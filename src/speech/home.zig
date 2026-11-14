//! The desktop's speech engine: stt.Home on the GPU, in-process
//! (docs/stt-sync-contract.md, "Desktop: stt.Home"), driven by one thread.
//!
//! That thread opens Home (loading the model takes a moment, so the window
//! never waits for it), then is the contract's one waiter: it sleeps in a
//! single WaitForMultipleObjects on
//!   * stop    the window is closing (Home.close confirms what is pending);
//!   * job     the window queued work (a recording to transcribe, a
//!             transcript's feedback);
//!   * rearm   Home's wakeup hook reported a new deadline (it may fire on
//!             the training thread: the hook only stores the deadline and
//!             sets this event, it never calls into Home);
//! with the timeout set to Home's latest deadline (none: infinite). At
//! the deadline it calls `tick()` and sleeps until tick's answer. Nothing
//! wakes on a fixed interval.
//!
//! Limits (limits.zig): one transcription at a time (queued or running;
//! another is refused with error.Busy), clips of 250 ms .. 120 s, at most
//! 10 transcriptions a minute (error.RateLimited; `retryAt` says when).
//! Feedback from the desk's own UI has its own bucket (burst 5, one every
//! 6 s): over it, refused, never queued; feedback for an id that isn't
//! waiting is refused cheaply (it still costs a token). Transcript and
//! feedback text at most 8 KiB; at most 16 feedback calls queued. A
//! transcription can be canceled (`cancel`: the user stopped, or its
//! timeout deadline passed): stt has no way to stop the GPU mid-way, so
//! it finishes, but its result is dropped and discarded in stt, and
//! nothing else runs meanwhile.
//!
//! Kept clips: at most `kept_clips_per_day` dictations a rolling day may
//! become training samples; past that each is discarded in stt right after
//! it is transcribed (feedback(id, _, false): no sample), and the result
//! says `not_kept`. Test clips are always discarded (nobody reviews them).
//!
//! One heavy job at a time, desktop-wide: transcription, bundle import
//! (Home.importBundle) and update export (Home.exportUpdate) run on this
//! one thread, at most one queued per kind (another is Busy); the desk's
//! own transcription goes first. Nothing here starts training: that stays
//! with stt's own schedule.
//!
//! Every limit is `limits.Config`, applied live by `setLimits`.
//!
//! Audio leaves Portal only as a WAV file in memory (encoded by ../Audio,
//! its header checked) handed to stt; Portal has no audio format code.

const std = @import("std");
const stt = @import("stt");
const Audio = @import("Audio");
const sys = @import("sys.zig");
const limits = @import("limits.zig");

/// What a transcript is for: the 🎤 (text into the input line), or the
/// Audio panel's Test (shown in the panel; its feedback is never asked).
pub const Purpose = enum { dictation, test_clip };

pub const Result = struct {
    purpose: Purpose,
    /// stt's transcript id (0: nothing heard, no feedback possible).
    id: u64 = 0,
    /// Owned (free with the engine's allocator), at most limits.max_text:
    /// the text, or why it failed.
    text: []u8,
    failed: bool = false,
    /// Past the day's kept-clips cap: transcribed, not kept for training.
    not_kept: bool = false,
};

/// A bundle import's or update export's outcome (`takeSync`).
pub const SyncResult = union(enum) {
    imported: struct { device: [limits.max_device_name]u8, device_len: usize, ok: bool },
    /// The update for a device (owned; null: it is current) or a failure.
    exported: struct { bytes: ?[]u8, ok: bool },
};

pub const State = enum {
    /// Opening Home (loading the model onto the GPU).
    loading,
    ready,
    /// Home could not open (no NVIDIA GPU, no model file, ...): `why`.
    failed,
};

pub const Status = struct {
    state: State = .loading,
    /// A transcription is queued or running (0 or 1).
    busy: u32 = 0,
    why_buf: [160]u8 = undefined,
    why_len: usize = 0,
    training: stt.schedule.Status = .{},

    pub fn why(s: *const Status) []const u8 {
        return s.why_buf[0..s.why_len];
    }
};

pub const Config = struct {
    model_path: []const u8,
    profile_dir: []const u8,
    /// The device name stt tags samples with.
    device: []const u8 = "desk",
};

pub const SubmitError = error{ TooShort, TooLong, Busy, RateLimited, SpeechUnavailable };
pub const SyncError = error{ Busy, TooLarge, SpeechUnavailable, OutOfMemory };
pub const FeedbackError = error{ RateLimited, UnknownId, TextTooLong, OutOfMemory };

const Clip = struct { purpose: Purpose, pcm: []i16, seq: u64 };
/// Who a queued feedback call is from: the desk's user, a paired device
/// (the future device routes, after gate.Gate), or Portal itself (its own
/// discards: canceled, not kept). Device entries never push out the desk's
/// or Portal's: they get at most half the queue.
const Source = enum { desk, device, portal };
const Feedback = struct { id: u64, text: []u8, ok: bool, source: Source = .desk };

pub const Engine = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    model_path: []u8,
    profile_dir: []u8,
    device: []u8,
    notify_ctx: ?*anyopaque = null,
    notify_fn: ?*const fn (ctx: *anyopaque) void = null,

    thread: ?std.Thread = null,
    stop_ev: sys.HANDLE = undefined,
    job_ev: sys.HANDLE = undefined,
    rearm_ev: sys.HANDLE = undefined,

    lock: sys.Lock = .{},
    // ---- under `lock`
    status: Status = .{},
    /// The one transcription waiting to start.
    queued: ?Clip = null,
    /// The in-flight transcription (queued or running), when it must be
    /// back (awake ms), and whether its result is to be dropped.
    seq: u64 = 0,
    inflight: ?u64 = null,
    inflight_deadline: ?i64 = null,
    canceled: bool = false,
    /// Transcriptions (10 a minute, 300 an hour, 2000 a day) and the desk
    /// UI's feedback (5 burst / one per 6 s, 120 an hour, 1000 a day).
    limiter: limits.Limiter = .transcriptions(),
    fb_limiter: limits.Limiter = .feedback(),
    /// The last refusal by either (which limit, when it frees up).
    last_limited: ?@FieldType(limits.Verdict, "limited") = null,
    /// Transcript ids that may still get feedback (newest overwrite the
    /// oldest; 0 = empty slot).
    cfg: limits.Config = .{},
    /// "Learn from my voice" (default on), and a change waiting for the
    /// engine's thread to pass to Home.
    learning: bool = true,
    learning_job: ?bool = null,
    /// Dictations kept as training samples (rolling day, boot clock).
    kept: limits.Rolling(24, 3_600_000) = .{},
    pending_ids: [limits.max_pending_ids]u64 = @splat(0),
    pending_at: usize = 0,
    feedbacks: std.ArrayList(Feedback) = .empty,
    result: ?Result = null,
    /// One bundle import and one update export waiting at most.
    import_job: ?struct { bytes: []u8, device: [limits.max_device_name]u8, device_len: usize } = null,
    export_job: ?u32 = null,
    sync_result: ?SyncResult = null,
    deadline: ?i64 = null,
    /// Ticks run, wakeups received, results / feedback dropped (tests, the log).
    ticks: u64 = 0,
    wakeups: u64 = 0,
    dropped: u64 = 0,

    /// Starts the engine thread; Home opens there.
    pub fn create(gpa: std.mem.Allocator, io: std.Io, cfg: Config) !*Engine {
        const e = try gpa.create(Engine);
        errdefer gpa.destroy(e);
        const model_path = try gpa.dupe(u8, cfg.model_path);
        errdefer gpa.free(model_path);
        const profile_dir = try gpa.dupe(u8, cfg.profile_dir);
        errdefer gpa.free(profile_dir);
        const device = try gpa.dupe(u8, cfg.device);
        errdefer gpa.free(device);
        e.* = .{ .gpa = gpa, .io = io, .model_path = model_path, .profile_dir = profile_dir, .device = device };
        try e.feedbacks.ensureTotalCapacityPrecise(gpa, limits.feedback_queue_ceiling);
        errdefer e.feedbacks.deinit(gpa);
        const stop_ev = try sys.autoEvent();
        errdefer _ = sys.CloseHandle(stop_ev);
        const job_ev = try sys.autoEvent();
        errdefer _ = sys.CloseHandle(job_ev);
        e.rearm_ev = try sys.autoEvent();
        e.stop_ev = stop_ev;
        e.job_ev = job_ev;
        return e;
    }

    pub fn start(e: *Engine) !void {
        e.thread = try std.Thread.spawn(.{}, run, .{e});
    }

    /// Stops the thread (Home confirms pending transcripts and closes) and
    /// frees everything, including an undelivered result.
    pub fn destroy(e: *Engine) void {
        if (e.thread) |t| {
            _ = sys.SetEvent(e.stop_ev);
            t.join();
        }
        for ([_]sys.HANDLE{ e.stop_ev, e.job_ev, e.rearm_ev }) |h| _ = sys.CloseHandle(h);
        if (e.queued) |c| e.gpa.free(c.pcm);
        for (e.feedbacks.items) |f| e.gpa.free(f.text);
        e.feedbacks.deinit(e.gpa);
        if (e.result) |r| e.gpa.free(r.text);
        if (e.import_job) |j| e.gpa.free(j.bytes);
        if (e.sync_result) |r| switch (r) {
            .exported => |x| if (x.bytes) |b| e.gpa.free(b),
            .imported => {},
        };
        e.gpa.free(e.model_path);
        e.gpa.free(e.profile_dir);
        e.gpa.free(e.device);
        e.gpa.destroy(e);
    }

    fn notify(e: *Engine) void {
        if (e.notify_fn) |f| f(e.notify_ctx.?);
    }

    fn awakeMs(e: *Engine) i64 {
        return std.Io.Clock.awake.now(e.io).toMilliseconds();
    }

    /// The rate limits' and day counts' clock: it keeps counting while the
    /// machine sleeps, so an hour or a day means wall time.
    fn bootMs(e: *Engine) i64 {
        return std.Io.Clock.boot.now(e.io).toMilliseconds();
    }

    // ------------------------------------------------------------ window side

    /// New limits, live (clamped): rates and caps apply to the next
    /// request; counts so far are kept.
    pub fn setLimits(e: *Engine, c: limits.Config) void {
        const cc = c.clamped();
        e.lock.lock();
        defer e.lock.unlock();
        e.cfg = cc;
        e.limiter.applyTranscriptions(cc);
        e.fb_limiter.applyFeedback(cc);
        while (e.feedbacks.items.len > cc.feedback_queue) {
            const old = e.feedbacks.orderedRemove(0);
            e.gpa.free(old.text);
            e.dropped += 1;
        }
    }

    /// Transcribes 16 kHz mono samples; takes ownership of `pcm` (also on
    /// error). Refused: shorter than 250 ms (TooShort, no stt call),
    /// longer than 120 s, another transcription in flight (Busy), more
    /// than 10 a minute (RateLimited: see `retryAt`).
    pub fn transcribe(e: *Engine, purpose: Purpose, pcm: []i16) SubmitError!void {
        var keep = false;
        defer if (!keep) e.gpa.free(pcm);
        const now = e.awakeMs();
        const boot = e.bootMs();
        e.lock.lock();
        defer e.lock.unlock();
        if (pcm.len < e.cfg.minSamples()) return error.TooShort;
        if (pcm.len > @min(e.cfg.maxSamples(), limits.max_samples)) return error.TooLong;
        if (e.status.state == .failed) return error.SpeechUnavailable;
        if (e.inflight != null) return error.Busy;
        switch (e.limiter.take(boot)) {
            .ok => {},
            .limited => |l| {
                e.last_limited = .{ .limit = l.limit, .at = l.at };
                return error.RateLimited;
            },
            .exceeds => |l| {
                e.last_limited = .{ .limit = l, .at = boot };
                return error.RateLimited;
            },
        }
        e.seq += 1;
        e.queued = .{ .purpose = purpose, .pcm = pcm, .seq = e.seq };
        keep = true;
        e.inflight = e.seq;
        e.inflight_deadline = now + @as(i64, e.cfg.job_timeout_s) * 1000;
        e.canceled = false;
        e.status.busy = 1;
        _ = sys.SetEvent(e.job_ev);
    }

    /// The last RateLimited refusal: which limit, and in how many ms it
    /// frees up.
    pub fn lastLimited(e: *Engine) ?struct { limit: limits.Limit, in_ms: i64 } {
        const now = e.bootMs();
        e.lock.lock();
        defer e.lock.unlock();
        const l = e.last_limited orelse return null;
        return .{ .limit = l.limit, .in_ms = @max(0, l.at -| now) };
    }

    /// "Learn from my voice" (the desk's switch): off, stt keeps no audio
    /// and every transcript is discarded at once; transcription goes on.
    /// Applied on the engine's thread (Home.setLearning), so the window
    /// never waits on it.
    pub fn setLearning(e: *Engine, on: bool) void {
        e.lock.lock();
        defer e.lock.unlock();
        e.learning = on;
        e.learning_job = on;
        _ = sys.SetEvent(e.job_ev);
    }

    /// The in-flight transcription's timeout (awake ms), if one is in
    /// flight and not yet canceled: the window cancels it then.
    pub fn jobDeadline(e: *Engine) ?i64 {
        e.lock.lock();
        defer e.lock.unlock();
        if (e.canceled) return null;
        return e.inflight_deadline;
    }

    /// Gives up the transcription in flight (the user stopped, or its
    /// deadline passed): not started yet, it is dropped; running, its
    /// result is dropped and discarded in stt when it comes. True if there
    /// was one.
    pub fn cancel(e: *Engine) bool {
        e.lock.lock();
        defer e.lock.unlock();
        if (e.inflight == null or e.canceled) return false;
        if (e.queued) |c| {
            e.gpa.free(c.pcm);
            e.queued = null;
            e.inflight = null;
            e.inflight_deadline = null;
            e.status.busy = 0;
            return true;
        }
        e.canceled = true;
        return true;
    }

    /// The desk user's answer for transcript `id`: the corrected text it
    /// was sent as (`ok` true), or a discard (`ok` false). Every call
    /// costs a token of the desk's feedback bucket (RateLimited when it is
    /// empty: refused, never queued); an id that isn't waiting for
    /// feedback is refused (UnknownId) without reaching stt; text over
    /// 8 KiB is refused.
    pub fn feedback(e: *Engine, id: u64, text: []const u8, ok: bool) FeedbackError!void {
        const now = e.bootMs();
        e.lock.lock();
        defer e.lock.unlock();
        switch (e.fb_limiter.take(now)) {
            .ok => {},
            .limited => |l| {
                e.last_limited = .{ .limit = l.limit, .at = l.at };
                return error.RateLimited;
            },
            .exceeds => |l| {
                e.last_limited = .{ .limit = l, .at = now };
                return error.RateLimited;
            },
        }
        if (text.len > e.cfg.text_max) return error.TextTooLong;
        if (!e.takePendingId(id)) return error.UnknownId;
        const t = try e.gpa.dupe(u8, text);
        e.pushFeedback(.{ .id = id, .text = t, .ok = ok });
        _ = sys.SetEvent(e.job_ev);
    }

    /// A paired device's correction (the future device routes call it
    /// after gate.Gate allowed it: rate limits, session, permission). The
    /// id must be one this engine handed out; its entries can't push the
    /// desk's corrections out of the queue.
    pub fn deviceFeedback(e: *Engine, id: u64, text: []const u8, ok: bool) FeedbackError!void {
        e.lock.lock();
        defer e.lock.unlock();
        if (text.len > e.cfg.text_max) return error.TextTooLong;
        if (!e.takePendingId(id)) return error.UnknownId;
        const t = try e.gpa.dupe(u8, text);
        e.pushFeedback(.{ .id = id, .text = t, .ok = ok, .source = .device });
        _ = sys.SetEvent(e.job_ev);
    }

    /// Caller holds `lock`.
    fn addPendingId(e: *Engine, id: u64) void {
        if (id == 0) return;
        e.pending_ids[e.pending_at] = id;
        e.pending_at = (e.pending_at + 1) % e.pending_ids.len;
    }

    /// Caller holds `lock`: true (and forgotten) if `id` waits for feedback.
    fn takePendingId(e: *Engine, id: u64) bool {
        if (id == 0) return false;
        for (&e.pending_ids) |*p| if (p.* == id) {
            p.* = 0;
            return true;
        };
        return false;
    }

    /// Caller holds `lock`; capacity is reserved, the oldest goes when full.
    fn pushFeedback(e: *Engine, f: Feedback) void {
        const cap = e.cfg.feedback_queue;
        var devices: usize = 0;
        for (e.feedbacks.items) |x| devices += @intFromBool(x.source == .device);
        // Devices get at most half the queue (at least one entry): their
        // oldest goes first.
        const device_cap = @max(1, cap / 2);
        const evict_device = (f.source == .device and devices >= device_cap) or
            (e.feedbacks.items.len >= cap and devices > 0);
        if (evict_device) {
            for (e.feedbacks.items, 0..) |x, i| if (x.source == .device) {
                e.gpa.free(e.feedbacks.orderedRemove(i).text);
                e.dropped += 1;
                break;
            };
        }
        if (e.feedbacks.items.len >= cap) {
            const old = e.feedbacks.orderedRemove(0);
            e.gpa.free(old.text);
            e.dropped += 1;
        }
        e.feedbacks.appendAssumeCapacity(f);
    }

    /// A device's training bundle (from the future POST /sync/bundle, after
    /// gate.Gate allowed it): imported on the heavy-job thread. One waits at
    /// most (another: Busy). Takes ownership of `bytes` (also on error).
    pub fn importBundle(e: *Engine, device: []const u8, bytes: []u8) SyncError!void {
        var keep = false;
        defer if (!keep) e.gpa.free(bytes);
        e.lock.lock();
        defer e.lock.unlock();
        if (bytes.len > @as(usize, e.cfg.bundle_max_kib) * 1024 or device.len > limits.max_device_name) return error.TooLarge;
        if (e.status.state == .failed) return error.SpeechUnavailable;
        if (e.import_job != null) return error.Busy;
        var j: @TypeOf(e.import_job.?) = .{ .bytes = bytes, .device = undefined, .device_len = device.len };
        @memcpy(j.device[0..device.len], device);
        e.import_job = j;
        keep = true;
        _ = sys.SetEvent(e.job_ev);
    }

    /// The adapter update for a device at `device_version` (the future GET
    /// /sync/update), exported on the heavy-job thread. One waits at most.
    pub fn exportUpdate(e: *Engine, device_version: u32) SyncError!void {
        e.lock.lock();
        defer e.lock.unlock();
        if (e.status.state == .failed) return error.SpeechUnavailable;
        if (e.export_job != null) return error.Busy;
        e.export_job = device_version;
        _ = sys.SetEvent(e.job_ev);
    }

    pub fn takeSync(e: *Engine) ?SyncResult {
        e.lock.lock();
        defer e.lock.unlock();
        const r = e.sync_result orelse return null;
        e.sync_result = null;
        return r;
    }

    /// The finished transcription, if any (free `text` with the engine's
    /// allocator).
    pub fn takeResult(e: *Engine) ?Result {
        e.lock.lock();
        defer e.lock.unlock();
        const r = e.result orelse return null;
        e.result = null;
        return r;
    }

    pub fn getStatus(e: *Engine) Status {
        e.lock.lock();
        defer e.lock.unlock();
        return e.status;
    }

    // ------------------------------------------------------------ thread

    fn setFailed(e: *Engine, comptime fmt: []const u8, args: anytype) void {
        e.lock.lock();
        defer e.lock.unlock();
        e.status.state = .failed;
        const s = std.fmt.bufPrint(&e.status.why_buf, fmt, args) catch e.status.why_buf[0..0];
        e.status.why_len = s.len;
        if (e.queued) |c| e.gpa.free(c.pcm);
        e.queued = null;
        e.inflight = null;
        e.inflight_deadline = null;
        e.status.busy = 0;
    }

    /// Home's wakeup hook (any thread, possibly the training thread):
    /// store the deadline, re-arm the waiter. Never calls into Home.
    fn onWakeup(ctx: *anyopaque, deadline_unix_ms: ?i64) void {
        const e: *Engine = @ptrCast(@alignCast(ctx));
        e.lock.lock();
        e.deadline = deadline_unix_ms;
        e.wakeups += 1;
        e.lock.unlock();
        _ = sys.SetEvent(e.rearm_ev);
    }

    /// Home's training events: the status for the window's banner.
    fn onTraining(ctx: *anyopaque, ev: stt.schedule.Event) void {
        const e: *Engine = @ptrCast(@alignCast(ctx));
        const st = switch (ev) {
            inline else => |s| s,
        };
        e.lock.lock();
        e.status.training = st;
        e.lock.unlock();
        e.notify();
    }

    fn nowMs(e: *Engine) i64 {
        return @intCast(@divFloor(std.Io.Clock.real.now(e.io).nanoseconds, std.time.ns_per_ms));
    }

    fn run(e: *Engine) void {
        const home = stt.Home.open(e.gpa, e.io, .{
            .model_path = e.model_path,
            .profile_dir = e.profile_dir,
            .service = .{ .max_seconds = limits.max_seconds, .feedback_window = limits.max_pending_ids },
        }) catch |err| {
            switch (err) {
                error.FileNotFound => e.setFailed("Speech model not found: {s}", .{e.model_path}),
                error.CudaUnavailable, error.CudaNoDevice => e.setFailed("Speech needs an NVIDIA GPU (driver not found)", .{}),
                else => e.setFailed("Speech could not start: {t}", .{err}),
            }
            e.notify();
            _ = sys.WaitForSingleObject(e.stop_ev, sys.INFINITE);
            return;
        };
        defer home.close();
        home.setListener(.{ .ctx = e, .onEvent = onTraining });
        home.setWakeup(.{ .ctx = e, .onWakeup = onWakeup });
        e.lock.lock();
        e.status.state = .ready;
        e.status.training = home.trainingStatus();
        e.lock.unlock();
        e.notify();

        while (true) {
            e.lock.lock();
            const deadline = e.deadline;
            e.lock.unlock();
            const hs = [_]sys.HANDLE{ e.stop_ev, e.job_ev, e.rearm_ev };
            const r = sys.WaitForMultipleObjects(hs.len, &hs, 0, sys.msUntil(deadline, e.nowMs()));
            switch (r) {
                0 => break,
                1 => e.drain(home),
                2 => {}, // the deadline moved: wait again with the new one
                sys.WAIT_TIMEOUT => {
                    const next = home.tick();
                    e.lock.lock();
                    e.deadline = next;
                    e.ticks += 1;
                    e.status.training = home.trainingStatus();
                    e.lock.unlock();
                },
                else => {
                    // The wait itself failed (should not happen): say so
                    // instead of staying Busy for ever.
                    e.setFailed("Speech stopped: waiting failed", .{});
                    e.notify();
                    break;
                },
            }
        }
    }

    fn drain(e: *Engine, home: *stt.Home) void {
        while (true) {
            e.lock.lock();
            var fb: ?Feedback = null;
            var clip: ?Clip = null;
            var imp: @TypeOf(e.import_job) = null;
            var exp: ?u32 = null;
            const learn = e.learning_job;
            e.learning_job = null;
            // Order: feedback (cheap), the desk's transcription, then
            // device sync work. One at a time.
            if (e.feedbacks.items.len > 0) {
                fb = e.feedbacks.orderedRemove(0);
            } else if (e.queued) |c| {
                clip = c;
                e.queued = null;
            } else if (e.import_job) |j| {
                imp = j;
                e.import_job = null;
            } else if (e.export_job) |v| {
                exp = v;
                e.export_job = null;
            }
            e.lock.unlock();
            if (learn) |on| {
                home.setLearning(on) catch {};
                continue;
            }
            if (imp) |j| {
                defer e.gpa.free(j.bytes);
                const ok = if (home.importBundle(e.gpa, j.bytes)) |_| true else |_| false;
                e.setSync(.{ .imported = .{ .device = j.device, .device_len = j.device_len, .ok = ok } });
                continue;
            }
            if (exp) |v| {
                const r = home.exportUpdate(e.gpa, v);
                e.setSync(.{ .exported = if (r) |b| .{ .bytes = b, .ok = true } else |_| .{ .bytes = null, .ok = false } });
                continue;
            }
            if (fb) |f| {
                defer e.gpa.free(f.text);
                _ = home.feedback(f.id, f.text, f.ok) catch {};
                continue;
            }
            const c = clip orelse return;
            defer e.gpa.free(c.pcm);
            var res = e.transcribeOne(home, c.purpose, c.pcm);
            e.lock.lock();
            e.inflight = null;
            e.inflight_deadline = null;
            e.status.busy = 0;
            if (e.canceled) {
                // Given up meanwhile: drop it, and tell stt it was wrong
                // so silence doesn't confirm it (Portal's own discard: no
                // token, it isn't the user's).
                e.canceled = false;
                if (res.id != 0) {
                    if (e.gpa.dupe(u8, "")) |t| e.pushFeedback(.{ .id = res.id, .text = t, .ok = false, .source = .portal }) else |_| {}
                }
                e.gpa.free(res.text);
                e.dropped += 1;
                e.lock.unlock();
                e.notify();
                continue;
            }
            if (e.result) |old| e.gpa.free(old.text);
            res.text = capOwned(e.gpa, res.text, e.cfg.text_max);
            if (res.id != 0) {
                const now = e.bootMs();
                // A Test's clip is never reviewed: not kept. With learning
                // off, nothing is. Past the day's cap, a dictation isn't
                // kept either. Discarding is the one way stt offers to not
                // keep a transcript's audio.
                const under_cap = e.kept.sum(now) < e.cfg.kept_clips_per_day;
                const keep = res.purpose == .dictation and e.learning and under_cap;
                if (keep) {
                    e.kept.add(now);
                    e.addPendingId(res.id);
                } else {
                    if (e.gpa.dupe(u8, "")) |t| e.pushFeedback(.{ .id = res.id, .text = t, .ok = false, .source = .portal }) else |_| {}
                    res.not_kept = res.purpose == .dictation and e.learning and !under_cap;
                    res.id = 0; // nothing left to give feedback on
                }
            }
            e.result = res;
            e.lock.unlock();
            e.notify();
        }
    }

    fn setSync(e: *Engine, r: SyncResult) void {
        e.lock.lock();
        if (e.sync_result) |old| switch (old) {
            .exported => |x| if (x.bytes) |b| e.gpa.free(b),
            .imported => {},
        };
        e.sync_result = r;
        e.lock.unlock();
        e.notify();
    }

    fn transcribeOne(e: *Engine, home: *stt.Home, purpose: Purpose, pcm: []const i16) Result {
        const failed = struct {
            fn f(gpa: std.mem.Allocator, p: Purpose, comptime fmt: []const u8, args: anytype) Result {
                const t: []u8 = std.fmt.allocPrint(gpa, fmt, args) catch &.{};
                return .{ .purpose = p, .text = t, .failed = true };
            }
        }.f;
        const wav = wavBytes(e.gpa, pcm) catch |err| return failed(e.gpa, purpose, "Could not prepare the audio: {t}", .{err});
        defer e.gpa.free(wav);
        // The header is checked before stt decodes anything.
        limits.checkWav(wav) catch |err| return failed(e.gpa, purpose, "Refused the audio: {t}", .{err});
        const r = home.transcribe(e.gpa, wav, e.device) catch |err| return failed(e.gpa, purpose, "Transcription failed: {t}", .{err});
        return .{ .purpose = purpose, .id = r.id, .text = r.text };
    }
};

/// `text` cut to `max` bytes (a UTF-8 boundary), still owned.
fn capOwned(gpa: std.mem.Allocator, text: []u8, max: usize) []u8 {
    const keep = limits.capText(text, max).len;
    if (keep == text.len) return text;
    return gpa.realloc(text, keep) catch text[0..keep];
}

/// 16 kHz mono s16le samples (at most 120 s) as a WAV file, by ../Audio's
/// encoder.
pub fn wavBytes(gpa: std.mem.Allocator, pcm: []const i16) ![]u8 {
    if (pcm.len > limits.max_samples) return error.AudioTooLong;
    // Audio's encoder reads the samples; it never frees or changes them.
    const a: Audio = .{ .sample_rate = limits.sample_rate, .channels = 1, .samples = .{ .i16 = @constCast(pcm) } };
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try a.encode(.wav, &out.writer, gpa);
    return out.toOwnedSlice();
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

/// An engine whose thread is never started: the window-side limits only.
fn bare() !*Engine {
    return Engine.create(testing.allocator, testing.io, .{ .model_path = "none", .profile_dir = "none" });
}

fn testClip(n: usize) ![]i16 {
    const p = try testing.allocator.alloc(i16, n);
    @memset(p, 0);
    return p;
}

test "engine limits: too short, too long, one in flight, cancel frees the slot" {
    const e = try bare();
    defer e.destroy();
    try testing.expectError(error.TooShort, e.transcribe(.dictation, try testClip(limits.min_samples - 1)));
    try testing.expectError(error.TooLong, e.transcribe(.dictation, try testClip(limits.max_samples + 1)));
    try e.transcribe(.dictation, try testClip(limits.min_samples));
    try testing.expectEqual(@as(u32, 1), e.getStatus().busy);
    try testing.expect(e.jobDeadline() != null);
    // A second while the first waits: refused, never queued.
    try testing.expectError(error.Busy, e.transcribe(.test_clip, try testClip(limits.min_samples)));
    // Canceled before it ran: gone, the slot free again.
    try testing.expect(e.cancel());
    try testing.expect(!e.cancel());
    try testing.expectEqual(@as(u32, 0), e.getStatus().busy);
    try testing.expect(e.jobDeadline() == null);
    try e.transcribe(.dictation, try testClip(limits.min_samples));
}

test "engine limits: 10 transcriptions a minute, then RateLimited until the bucket's deadline" {
    const e = try bare();
    defer e.destroy();
    for (0..limits.rate_burst) |_| {
        try e.transcribe(.dictation, try testClip(limits.min_samples));
        _ = e.cancel();
    }
    try testing.expectError(error.RateLimited, e.transcribe(.dictation, try testClip(limits.min_samples)));
    const l = e.lastLimited().?;
    try testing.expectEqual(limits.Limit.per_minute, l.limit);
    try testing.expect(l.in_ms > limits.rate_refill_ms - 1000);
}

test "engine limits: desk feedback has its own bucket; unknown ids cost a token; text capped; queue bounded" {
    const e = try bare();
    defer e.destroy();
    // Ids the engine produced (as drain does for dictations).
    for (1..limits.max_pending_ids + 1) |i| e.addPendingId(i);
    const long: [limits.max_text + 1]u8 = @splat('a');
    try testing.expectError(error.TextTooLong, e.feedback(1, &long, true)); // token 1
    try testing.expectError(error.UnknownId, e.feedback(999, "x", true)); // token 2
    try e.feedback(2, "fix", true); // 3
    try testing.expectError(error.UnknownId, e.feedback(2, "again", true)); // 4: answered already
    try e.feedback(3, "", false); // 5
    // The burst is spent: refused, not queued.
    try testing.expectError(error.RateLimited, e.feedback(4, "fix", true));
    try testing.expectEqual(@as(usize, 2), e.feedbacks.items.len);
    try testing.expect(e.lastLimited().?.in_ms > 0);
    // The transcription bucket is separate.
    try e.transcribe(.dictation, try testClip(limits.min_samples));
    // The queue keeps the newest 16 (Portal's own discards fill it too).
    e.lock.lock();
    for (0..limits.max_feedback_jobs + 4) |i| e.pushFeedback(.{ .id = i + 100, .text = try testing.allocator.dupe(u8, "d"), .ok = false });
    e.lock.unlock();
    try testing.expectEqual(@as(usize, limits.max_feedback_jobs), e.feedbacks.items.len);
    try testing.expectEqual(@as(usize, limits.feedback_queue_ceiling), e.feedbacks.capacity); // reserved once, never grown
}

test "engine limits apply live (clamped); sync jobs: one each, never training" {
    const e = try bare();
    defer e.destroy();
    e.setLimits(.{ .clip_min_ms = 1000, .transcribe_burst = 0, .feedback_queue = 2 });
    try testing.expectEqual(@as(u32, 1), e.cfg.transcribe_burst); // clamped: never zero
    try testing.expectError(error.TooShort, e.transcribe(.dictation, try testClip(limits.sample_rate / 2)));
    try e.transcribe(.dictation, try testClip(limits.sample_rate));
    _ = e.cancel();
    // A burst of 1 now: the next is refused.
    try testing.expectError(error.RateLimited, e.transcribe(.dictation, try testClip(limits.sample_rate)));
    e.lock.lock();
    for (0..5) |i| e.pushFeedback(.{ .id = i + 1, .text = try testing.allocator.dupe(u8, "d"), .ok = false });
    e.lock.unlock();
    try testing.expectEqual(@as(usize, 2), e.feedbacks.items.len);
    // Bundle import and update export: one waiting each.
    try e.importBundle("laptop", try testing.allocator.dupe(u8, "bundle"));
    try testing.expectError(error.Busy, e.importBundle("laptop", try testing.allocator.dupe(u8, "again")));
    const huge = try testing.allocator.alloc(u8, 5 * 1024 * 1024 + 1);
    try testing.expectError(error.TooLarge, e.importBundle("iphone", huge));
    try e.exportUpdate(3);
    try testing.expectError(error.Busy, e.exportUpdate(4));
}

test "device feedback can't push the desk's corrections out of the queue" {
    const e = try bare();
    defer e.destroy();
    e.setLimits(.{ .feedback_queue = 4 });
    for (1..20) |i| e.addPendingId(i);
    try e.feedback(1, "desk fix", true);
    for (2..12) |i| try e.deviceFeedback(i, "device fix", true);
    var desk: usize = 0;
    var dev: usize = 0;
    for (e.feedbacks.items) |f| switch (f.source) {
        .desk => desk += 1,
        .device => dev += 1,
        .portal => {},
    };
    try testing.expectEqual(@as(usize, 1), desk);
    try testing.expectEqual(@as(usize, 2), dev); // half of 4
    try testing.expectError(error.UnknownId, e.deviceFeedback(999, "x", true));
}

test "learning off: queued for the engine thread; the switch is remembered" {
    const e = try bare();
    defer e.destroy();
    try testing.expect(e.learning);
    e.setLearning(false);
    try testing.expect(!e.learning);
    try testing.expectEqual(@as(?bool, false), e.learning_job);
}

test "create: no leak when the allocator fails part-way" {
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        var fa: std.testing.FailingAllocator = .init(testing.allocator, .{ .fail_index = i });
        if (Engine.create(fa.allocator(), testing.io, .{ .model_path = "m", .profile_dir = "p" })) |e| {
            e.destroy();
        } else |_| {}
    }
}

test "capOwned and wavBytes bounds" {
    const t = try testing.allocator.alloc(u8, limits.max_text + 10);
    @memset(t, 'x');
    const c = capOwned(testing.allocator, t, limits.max_text);
    defer testing.allocator.free(c);
    try testing.expectEqual(@as(usize, limits.max_text), c.len);
    const big = try testClip(limits.max_samples + 1);
    defer testing.allocator.free(big);
    try testing.expectError(error.AudioTooLong, wavBytes(testing.allocator, big));
}
