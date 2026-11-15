//! Dictation on a Windows device (the Snapdragon X laptop, the Surface) in
//! `portal connect`: the shared input line's 🎤 (connect.Platform.speech ->
//! ui/shell.zig Dictation, the hooks the desk and the iPhone fill too),
//! recording with the desk's microphone thread (module "speech": WASAPI,
//! headset first, 16 kHz mono s16) and transcribing with stt-local on the
//! device's NPU (speech.local: the child process, protocol 1), from the
//! three packages its desk publishes and full sync installs:
//!
//!   stt-local    the program (executable: approved on the device), built
//!                by the desk for aarch64 Windows;
//!   stt-model    the base model, the desk's own file (model_pin.zig);
//!   stt-adapter  home's personal adapter: an update is swapped into the
//!                running program (import_update), a raw adapter is used
//!                from its next start (it restarts at the next idle moment).
//!
//! The stt profile (rules, vocabulary, samples, the compiled NPU graphs)
//! is the package's own data folder in this desktop's sync folder,
//! sync\desktops\<host>-<key>\data\stt-local (docs/sync-design.md). With
//! "learn from my voice" on (the default; the device setting
//! `speech_learning = off` turns it off) the samples stt keeps from your
//! corrections go home on each sync pass (shared/bulk.zig `put bundle`,
//! connect.sendSamples) and are deleted here only once the desk stored
//! them; with it off nothing is sent.
//!
//!   app thread    the 🎤 (start / stop / cancel / sent / cleared) and
//!                 `frame`: the recording to the worker, the transcript
//!                 into the line, the 🎤's state. Never blocks on stt.
//!   sync worker   connect.zig's, after every pass: the installed packages
//!                 (`installed`, then `checked`), and the samples home
//!                 (`nextBundle` / `sent`, which wait for the worker).
//!   speech worker one thread asleep on a condition until there is work or
//!                 a deadline: the only one that talks to stt-local.
//!
//! Energy: stt-local starts when a recording starts (the model loads while
//! you speak), or for a sync pass only when samples wait on disk. It stops
//! 60 s after the last dictation (once stt's own silence deadline has
//! passed too), a deadline the worker sleeps until; when Portal exits its
//! pipe closes and it stops by itself. A clip loses its leading and
//! trailing silence (speech.trim) before stt sees it.
//!
//! No engine for this machine (an x86_64 PC: the desk builds stt-local for
//! the Snapdragon only, so a delivered program is checked against this
//! machine's PE type before it runs): the 🎤 says speech is unavailable.

const std = @import("std");
const builtin = @import("builtin");
const client = @import("client");
const ui = @import("portal_ui");
const speech = @import("speech");

const capture = speech.capture;
const local = speech.local;
const sep = std.fs.path.sep_str;

pub const engine_package = "stt-local";
pub const model_package = "stt-model";
pub const adapter_package = "stt-adapter";
/// The packages the engine takes from full sync (connect.SpeechSync).
pub const packages: []const []const u8 = &.{ engine_package, model_package, adapter_package };
/// How long stt-local stays loaded after the last dictation.
pub const idle_release_ms: i64 = 60_000;
/// The largest training bundle sent home at once (the desk takes up to
/// its `speech.bundle_max_kib`, 5 MiB by default).
pub const bundle_bytes = 2 << 20;
/// Training samples carry this source name (the desk keys its limits on
/// the paired session's name, never on this).
const device_name = "laptop";
const max_feedback = 16;
const max_path = client.pin.max_path;

const Feedback = struct { id: u64, text: []u8, ok: bool };
const BundleReq = struct { gpa: std.mem.Allocator, answer: ?client.SpeechSync.Bundle = null, done: bool = false };

/// Whether speech can run here, from the last sync pass.
pub const Avail = enum { unknown, missing, wrong_machine, ready };

/// The installed packages' folders (sync worker -> speech worker).
const Pkgs = struct {
    engine: Path = .{},
    model: Path = .{},
    adapter: Path = .{},
    adapter_ver: Path = .{},

    const Path = struct {
        buf: [max_path]u8 = undefined,
        len: usize = 0,
        fn get(p: *const Path) []const u8 {
            return p.buf[0..p.len];
        }
        fn set(p: *Path, v: []const u8) void {
            const n = @min(v.len, p.buf.len);
            @memcpy(p.buf[0..n], v[0..n]);
            p.len = n;
        }
    };

    fn eql(a: *const Pkgs, b: *const Pkgs) bool {
        return std.mem.eql(u8, a.engine.get(), b.engine.get()) and std.mem.eql(u8, a.model.get(), b.model.get()) and
            std.mem.eql(u8, a.adapter.get(), b.adapter.get()) and std.mem.eql(u8, a.adapter_ver.get(), b.adapter_ver.get());
    }
};

const State = struct {
    io: std.Io = undefined,
    gpa: std.mem.Allocator = std.heap.page_allocator,

    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    /// The sync worker waits on this for its answers.
    answered: std.Io.Condition = .init,
    // ---- under `mutex`: work for the speech worker
    warm: bool = false,
    clip: ?[]i16 = null,
    /// Bumped by cancel: a result for an older clip is dropped.
    gen: u64 = 0,
    clip_gen: u64 = 0,
    busy: bool = false,
    feedback: [max_feedback]Feedback = undefined,
    n_feedback: usize = 0,
    learning: bool = true,
    learning_dirty: bool = false,
    pkgs: Pkgs = .{},
    pkgs_new: bool = false,
    bundle_req: ?*BundleReq = null,
    commit_req: ?u32 = null,
    commit_done: bool = true,
    /// Real-clock ms of the last dictation (the idle release counts from it).
    last_use_ms: i64 = 0,
    // ---- under `mutex`: what the speech worker reports
    result: ?local.Result = null,
    result_failed: bool = false,
    loading: bool = false,
    status_buf: [240]u8 = undefined,
    status_len: usize = 0,
    adapter_version: u32 = 0,
    avail: Avail = .unknown,

    // ---- app thread only
    thread: ?std.Thread = null,
    wasapi: speech.wasapi.Wasapi = .{},
    mic: capture.Mic = undefined,
    mic_ok: bool = false,
    snap: capture.Snapshot = .{},
    recording: bool = false,
    /// The recording asked for (capture.Recording.seq); 0: none awaited.
    rec_seq: u32 = 0,
    tracker: ui.dictation.Tracker = .{},
    insert_buf: [ui.dictation.max_text + 2]u8 = undefined,
    note_buf: [160]u8 = undefined,
    note_len: usize = 0,
    mic_buf: [speech.mics.max_name + 8]u8 = undefined,
    status_ui_buf: [240]u8 = undefined,

    // ---- sync worker only: this pass's packages, so far
    incoming: Pkgs = .{},

    // ---- speech worker only
    engine: local.Engine = undefined,
    applied: Pkgs = .{},
    /// The profile folder (from the engine package's place in the store).
    profile_buf: [max_path]u8 = undefined,
    profile_len: usize = 0,
    /// A raw adapter came while the program runs: it restarts when idle.
    reload_pending: bool = false,
    learning_sent: ?bool = null,
};

var state: State = .{};

/// Wires speech into the viewer (before connect.main). Windows only.
pub fn install(gpa: std.mem.Allocator, io: std.Io) void {
    const s = &state;
    s.gpa = gpa;
    s.io = io;
    s.engine = .init(gpa, io);
    var sb: [4096]u8 = undefined;
    s.learning = ui.convoview.parseOnOffSetting(client.pin.loadDeviceSettings(io, &sb), "speech_learning") orelse true;
    s.learning_dirty = true;
    s.mic = .{ .gpa = gpa, .backend = s.wasapi.backend(), .notify_ctx = s, .notify_fn = wake };
    s.mic_ok = if (s.mic.start()) |_| true else |_| false;
    s.thread = std.Thread.spawn(.{}, worker, .{s}) catch null;
    client.platform.speech = .{
        .dictation = .{ .ctx = s, .start = onStart, .stop = onStop, .cancel = onCancel, .sent = onSent, .cleared = onCleared },
        .frame = frame,
    };
    client.platform.speech_sync = .{ .ctx = s, .packages = packages, .installed = installed, .checked = checked, .next_bundle = nextBundle, .sent = sent };
}

fn wake(_: *anyopaque) void {
    client.redraw();
}

fn nowMs(io: std.Io) i64 {
    return std.Io.Clock.real.now(io).toMilliseconds();
}

fn setNote(s: *State, text: []const u8) void {
    const n = @min(text.len, s.note_buf.len);
    @memcpy(s.note_buf[0..n], text[0..n]);
    s.note_len = n;
}

// ------------------------------------------------------------ app thread

fn onStart(ctx: *anyopaque) bool {
    const s: *State = @ptrCast(@alignCast(ctx));
    s.note_len = 0;
    if (s.thread == null) {
        setNote(s, "Dictation could not start (no worker thread).");
        return false;
    }
    if (s.snap.active == null) return false;
    s.rec_seq = s.mic.startRecording();
    s.recording = true;
    s.mutex.lockUncancelable(s.io);
    s.warm = true;
    s.last_use_ms = nowMs(s.io);
    s.mutex.unlock(s.io);
    s.cond.signal(s.io);
    return true;
}

fn onStop(ctx: *anyopaque) void {
    const s: *State = @ptrCast(@alignCast(ctx));
    if (!s.recording) return;
    s.recording = false;
    // The recording arrives through takeRecording (frame).
    s.mic.stopRecording();
}

/// "Transcribing (cancel)": the clip on its way, or the transcription
/// running, is dropped (stt cannot stop mid-clip; its text is discarded).
fn onCancel(ctx: *anyopaque) void {
    const s: *State = @ptrCast(@alignCast(ctx));
    s.rec_seq = 0;
    s.mutex.lockUncancelable(s.io);
    defer s.mutex.unlock(s.io);
    s.gen +%= 1;
    if (s.clip) |c| s.gpa.free(c);
    s.clip = null;
    s.busy = false;
    if (s.result) |r| s.gpa.free(r.text);
    s.result = null;
}

fn onSent(ctx: *anyopaque, line: []const u8) void {
    const s: *State = @ptrCast(@alignCast(ctx));
    perform(s, s.tracker.sent(line));
}

fn onCleared(ctx: *anyopaque) void {
    const s: *State = @ptrCast(@alignCast(ctx));
    perform(s, s.tracker.cleared());
}

/// Queues a feedback decision for the worker (the oldest goes when full).
fn perform(s: *State, d: ui.dictation.Decision) void {
    const f: Feedback = switch (d) {
        .none => return,
        .learn => |l| .{ .id = l.id, .text = s.gpa.dupe(u8, l.text) catch return, .ok = true },
        .discard => |id| .{ .id = id, .text = &.{}, .ok = false },
    };
    s.mutex.lockUncancelable(s.io);
    if (s.n_feedback == max_feedback) {
        s.gpa.free(s.feedback[0].text);
        std.mem.copyForwards(Feedback, s.feedback[0 .. max_feedback - 1], s.feedback[1..]);
        s.n_feedback -= 1;
    }
    s.feedback[s.n_feedback] = f;
    s.n_feedback += 1;
    s.mutex.unlock(s.io);
    s.cond.signal(s.io);
}

fn headsetPresent(ctx: ?*anyopaque) bool {
    const s: *State = @ptrCast(@alignCast(ctx.?));
    return s.snap.list.anyHeadset();
}

/// Why the 🎤 can't work, for what the last pass found ("" if it can).
pub fn availText(a: Avail) []const u8 {
    const snapdragon = builtin.cpu.arch == .aarch64;
    return switch (a) {
        .ready => "",
        .unknown => "Speech starts once this device has checked its desktop's voice packages.",
        .missing => if (snapdragon)
            "Speech needs the voice packages from your desktop: install them in Packages (Ctrl+Shift+K)."
        else
            "Speech unavailable on this device (its speech engine is for Snapdragon X Windows devices).",
        .wrong_machine => "Speech unavailable on this device (the desktop's speech engine is built for another processor).",
    };
}

/// Each frame (app thread): the recording to the worker, a finished
/// transcript into the line, the 🎤's state.
fn frame(ctx: *anyopaque, sh: *ui.Shell) void {
    const s: *State = @ptrCast(@alignCast(ctx));
    if (s.mic_ok) s.mic.snapshot(&s.snap);
    sh.headset_mic = .{ .ctx = s, .present = headsetPresent };
    // The clip reached stt's limit: the 🎤 goes off.
    if (s.recording and s.snap.full) {
        sh.stopDictation();
        setNote(s, "Dictation stopped at 120 s (the most stt takes at once).");
    }
    if (s.mic_ok) if (s.mic.takeRecording()) |rec| {
        if (rec.seq != 0 and rec.seq == s.rec_seq) {
            s.rec_seq = 0;
            s.mutex.lockUncancelable(s.io);
            if (s.clip) |old| s.gpa.free(old);
            s.clip = rec.samples;
            s.clip_gen = s.gen;
            s.busy = true;
            s.mutex.unlock(s.io);
            s.cond.signal(s.io);
        } else s.gpa.free(rec.samples);
    };
    s.mutex.lockUncancelable(s.io);
    const result = s.result;
    const failed = s.result_failed;
    s.result = null;
    const busy = s.busy;
    const loading = s.loading;
    const adapter_version = s.adapter_version;
    const avail = s.avail;
    const status = s.status_ui_buf[0..s.status_len];
    @memcpy(status, s.status_buf[0..s.status_len]);
    s.mutex.unlock(s.io);
    // Stopped, the recording not handed over yet: transcribing already.
    sh.transcribing = busy or (!s.recording and s.rec_seq != 0);
    if (result) |r| {
        defer s.gpa.free(r.text);
        if (failed) setNote(s, r.text) else {
            var d: ui.dictation.Decision = .none;
            const add = s.tracker.added(r.id, r.text, sh.line.text(), &s.insert_buf, &d);
            perform(s, d);
            // Cut or changed on the way into the line: never learned as if
            // sent unchanged; discarded instead.
            if (!sh.dictated(add)) {
                perform(s, s.tracker.cleared());
                if (add.len > 0) setNote(s, "The transcript did not fit in the line.");
            }
        }
    }
    // While recording: the microphone. Otherwise the personal adapter in
    // use, once home has trained one.
    sh.mic_label = if (s.recording)
        if (s.snap.activeEndpoint()) |e| e.name.get() else ""
    else
        ui.dictation.voiceLabel(&s.mic_buf, adapter_version);
    const no_mic = !s.mic_ok or s.snap.active == null;
    sh.speech_off = if (avail != .ready)
        availText(avail)
    else if (no_mic)
        (if (s.snap.err().len > 0) s.snap.err() else "No microphone: plug in a headset or turn the microphone on.")
    else if (s.note_len > 0)
        s.note_buf[0..s.note_len]
    else if (status.len > 0)
        status
    else if (loading)
        "Loading the speech engine\u{2026}"
    else
        "";
    sh.setSpeechReady(avail == .ready and !no_mic);
}

// ------------------------------------------------------------ sync worker side

fn installed(ctx: *anyopaque, pkg: []const u8, dir: []const u8, version: []const u8) void {
    const s: *State = @ptrCast(@alignCast(ctx));
    if (std.mem.eql(u8, pkg, engine_package)) s.incoming.engine.set(dir);
    if (std.mem.eql(u8, pkg, model_package)) s.incoming.model.set(dir);
    if (std.mem.eql(u8, pkg, adapter_package)) {
        s.incoming.adapter.set(dir);
        s.incoming.adapter_ver.set(version);
    }
}

/// After a pass: the packages as they are now (a change reaches the worker).
fn checked(ctx: *anyopaque) void {
    const s: *State = @ptrCast(@alignCast(ctx));
    s.mutex.lockUncancelable(s.io);
    defer s.mutex.unlock(s.io);
    if (s.avail == .unknown or !Pkgs.eql(&s.pkgs, &s.incoming)) {
        s.pkgs = s.incoming;
        s.pkgs_new = true;
        s.cond.signal(s.io);
    }
    s.incoming = .{};
}

fn nextBundle(ctx: *anyopaque, gpa: std.mem.Allocator) ?client.SpeechSync.Bundle {
    const s: *State = @ptrCast(@alignCast(ctx));
    var req: BundleReq = .{ .gpa = gpa };
    s.mutex.lockUncancelable(s.io);
    defer s.mutex.unlock(s.io);
    if (s.thread == null or s.bundle_req != null) return null;
    s.bundle_req = &req;
    s.cond.signal(s.io);
    while (!req.done) s.answered.waitUncancelable(s.io, &s.mutex);
    return req.answer;
}

fn sent(ctx: *anyopaque, through: u32) void {
    const s: *State = @ptrCast(@alignCast(ctx));
    s.mutex.lockUncancelable(s.io);
    defer s.mutex.unlock(s.io);
    if (s.thread == null) return;
    s.commit_req = through;
    s.commit_done = false;
    s.cond.signal(s.io);
    while (!s.commit_done) s.answered.waitUncancelable(s.io, &s.mutex);
}

// ------------------------------------------------------------ speech worker

const Work = struct {
    warm: bool,
    clip: ?[]i16,
    gen: u64,
    feedback: [max_feedback]Feedback,
    n_feedback: usize,
    learning: ?bool,
    pkgs: ?Pkgs,
    bundle: ?*BundleReq,
    commit: ?u32,
    timed_out: bool,
};

fn hasWork(s: *const State) bool {
    return s.warm or s.clip != null or s.n_feedback > 0 or s.learning_dirty or s.pkgs_new or
        s.bundle_req != null or s.commit_req != null;
}

/// When the running program may go: 60 s after the last dictation, and
/// not before stt's own silence deadline (it confirms at close anyway).
fn releaseAt(s: *State) ?i64 {
    if (!s.engine.running()) return null;
    const idle = s.last_use_ms + idle_release_ms;
    return if (s.engine.sttDeadline()) |d| @max(d, idle) else idle;
}

/// Under `mutex`: sleeps until there is work or the release deadline,
/// and takes the work.
fn waitWork(s: *State) Work {
    var timed_out = false;
    while (!hasWork(s)) {
        const d = releaseAt(s) orelse {
            s.cond.waitUncancelable(s.io, &s.mutex);
            continue;
        };
        if (d <= nowMs(s.io)) {
            timed_out = true;
            break;
        }
        const ts: std.Io.Clock.Timestamp = .{ .raw = .fromNanoseconds(@as(i96, d) * std.time.ns_per_ms), .clock = .real };
        s.cond.waitTimeout(s.io, &s.mutex, .{ .deadline = ts }) catch {};
    }
    const w: Work = .{
        .warm = s.warm,
        .clip = s.clip,
        .gen = s.clip_gen,
        .feedback = s.feedback,
        .n_feedback = s.n_feedback,
        .learning = if (s.learning_dirty) s.learning else null,
        .pkgs = if (s.pkgs_new) s.pkgs else null,
        .bundle = s.bundle_req,
        .commit = s.commit_req,
        .timed_out = timed_out,
    };
    s.warm = false;
    s.clip = null;
    s.n_feedback = 0;
    s.learning_dirty = false;
    s.pkgs_new = false;
    s.commit_req = null;
    return w;
}

fn worker(s: *State) void {
    while (true) {
        s.mutex.lockUncancelable(s.io);
        const w = waitWork(s);
        s.mutex.unlock(s.io);

        if (w.pkgs) |p| applyPackages(s, &p, w.warm or w.clip != null);
        if (w.learning != null) syncLearning(s);
        for (w.feedback[0..w.n_feedback]) |f| giveFeedback(s, f);
        if (w.commit) |through| {
            commit(s, through);
            s.mutex.lockUncancelable(s.io);
            s.commit_done = true;
            s.mutex.unlock(s.io);
            s.answered.broadcast(s.io);
        }
        if (w.bundle) |req| {
            const b = exportBundle(s, req.gpa);
            s.mutex.lockUncancelable(s.io);
            req.answer = b;
            req.done = true;
            s.bundle_req = null;
            s.mutex.unlock(s.io);
            s.answered.broadcast(s.io);
        }
        if (w.timed_out) {
            // Idle long enough: the program goes (it starts again with the
            // next 🎤; what it held is confirmed as it closes).
            if (releaseAt(s)) |t| if (nowMs(s.io) >= t) s.engine.stop();
            continue;
        }
        if (w.warm or w.clip != null) load(s);
        const c = w.clip orelse continue;
        defer s.gpa.free(c);
        transcribe(s, c, w.gen);
        // A raw adapter came while busy: the program restarts now, between
        // dictations, and takes it.
        if (s.reload_pending) {
            s.reload_pending = false;
            s.engine.stop();
        }
        s.mutex.lockUncancelable(s.io);
        s.last_use_ms = nowMs(s.io);
        s.mutex.unlock(s.io);
    }
}

fn report(s: *State, avail: Avail, comptime fmt: []const u8, args: anytype) void {
    s.mutex.lockUncancelable(s.io);
    s.avail = avail;
    const t = std.fmt.bufPrint(&s.status_buf, fmt, args) catch s.status_buf[0..0];
    s.status_len = t.len;
    s.mutex.unlock(s.io);
    if (t.len > 0) std.log.warn("speech: {s}", .{t});
    client.redraw();
}

/// The packages of the last pass: the program's paths, and an adapter
/// swapped in when it can be. `busy`: a dictation is on its way.
fn applyPackages(s: *State, p: *const Pkgs, busy: bool) void {
    defer s.applied = p.*;
    if (p.engine.len == 0 or p.model.len == 0) {
        s.engine.stop();
        return report(s, .missing, "", .{});
    }
    var eb: [max_path]u8 = undefined;
    const exe = std.fmt.bufPrint(&eb, "{s}" ++ sep ++ local.exe_name, .{p.engine.get()}) catch return report(s, .missing, "", .{});
    if (!local.fitsThisMachine(s.io, exe)) {
        s.engine.stop();
        return report(s, .wrong_machine, "", .{});
    }
    var mb: [max_path]u8 = undefined;
    const model = std.fmt.bufPrint(&mb, "{s}" ++ sep ++ speech.model_pin.file_name, .{p.model.get()}) catch return report(s, .missing, "", .{});
    std.Io.Dir.cwd().access(s.io, model, .{}) catch {
        s.engine.stop();
        return report(s, .missing, "The stt-model package has no {s}: the desk must publish the pinned model.", .{speech.model_pin.file_name});
    };
    // packages\stt-local\<ver> -> the store's data\stt-local.
    const root = std.fs.path.dirname(std.fs.path.dirname(std.fs.path.dirname(p.engine.get()) orelse "") orelse "") orelse "";
    const profile = std.fmt.bufPrint(&s.profile_buf, "{s}" ++ sep ++ "data" ++ sep ++ engine_package, .{root}) catch return report(s, .missing, "", .{});
    s.profile_len = profile.len;
    std.Io.Dir.cwd().createDirPath(s.io, profile) catch |err| return report(s, .missing, "No place for the speech profile ({t}).", .{err});

    var ab: [max_path + 16]u8 = undefined;
    const adapter: ?[]const u8 = if (p.adapter.len > 0) speech.adapter_pkg.file(s.io, p.adapter.get(), &ab) else null;
    var head: [8]u8 = undefined;
    const is_update = if (adapter) |a| blk: {
        const got = std.Io.Dir.cwd().readFile(s.io, a, &head) catch break :blk false;
        break :blk speech.adapter_pkg.isUpdate(got);
    } else false;
    const raw_version: u32 = if (adapter != null and !is_update) speech.adapter_pkg.rawVersion(p.adapter_ver.get()) orelse 0 else 0;

    const program_changed = !std.mem.eql(u8, p.engine.get(), s.applied.engine.get()) or !std.mem.eql(u8, p.model.get(), s.applied.model.get());
    const adapter_changed = !std.mem.eql(u8, p.adapter.get(), s.applied.adapter.get());
    // A new program or model: the running one goes first (it confirms
    // what it holds), the next start takes the new paths.
    if (program_changed) s.engine.stop();
    s.engine.configure(.{
        .exe = exe,
        .model = model,
        .profile = profile,
        .adapter = adapter,
        .adapter_version = raw_version,
        .device_name = device_name,
    }) catch return report(s, .missing, "Out of memory.", .{});
    report(s, .ready, "", .{});
    if (!adapter_changed or program_changed or adapter == null) return;
    if (!s.engine.running()) return; // the next start passes it (imported if newer)
    if (is_update) {
        const bytes = std.Io.Dir.cwd().readFileAlloc(s.io, adapter.?, s.gpa, .limited(local.max_update_bytes)) catch |err| {
            std.log.warn("speech: stt-adapter {s}: {t}", .{ p.adapter_ver.get(), err });
            return;
        };
        defer s.gpa.free(bytes);
        const v = s.engine.importUpdate(bytes) catch |err| {
            std.log.warn("speech: adapter update {s}: {t}", .{ p.adapter_ver.get(), err });
            return;
        };
        std.log.info("speech: personal adapter v{d} (stt-adapter {s}), swapped in", .{ v, p.adapter_ver.get() });
        setAdapterVersion(s, v);
    } else if (raw_version > s.engine.adapterVersion()) {
        // A raw adapter is read at start: a restart at the next idle moment.
        if (busy) s.reload_pending = true else s.engine.stop();
    }
}

fn setAdapterVersion(s: *State, v: u32) void {
    s.mutex.lockUncancelable(s.io);
    s.adapter_version = v;
    s.mutex.unlock(s.io);
    client.redraw();
}

fn ready(s: *State) bool {
    s.mutex.lockUncancelable(s.io);
    defer s.mutex.unlock(s.io);
    return s.avail == .ready;
}

/// The program, if not running yet (the 🎤 went on, or a clip came).
fn load(s: *State) void {
    if (!ready(s) or s.engine.running()) return;
    s.engine.retry(); // pressed again after it gave up: one more try
    s.mutex.lockUncancelable(s.io);
    s.loading = true;
    s.status_len = 0;
    s.mutex.unlock(s.io);
    client.redraw();
    defer {
        s.mutex.lockUncancelable(s.io);
        s.loading = false;
        s.mutex.unlock(s.io);
        client.redraw();
    }
    s.engine.start() catch |err| return startFailed(s, err);
    s.learning_sent = null;
    syncLearning(s);
    setAdapterVersion(s, s.engine.adapterVersion());
}

fn startFailed(s: *State, err: local.Error) void {
    var lb: [200]u8 = undefined;
    const why = s.engine.lastError(&lb);
    switch (err) {
        error.ProtocolMismatch => report(s, .ready, "This speech engine speaks another protocol version: update Portal or the desk's stt-local.", .{}),
        error.Timeout => report(s, .ready, "The speech engine did not start in time.", .{}),
        error.GaveUp => report(s, .ready, "The speech engine keeps failing ({s}).", .{why}),
        else => report(s, .ready, "Speech could not start on this device ({s}).", .{if (why.len > 0) why else @errorName(err)}),
    }
}

/// Tells the program the learning switch once per start (stt keeps it in
/// the profile).
fn syncLearning(s: *State) void {
    s.mutex.lockUncancelable(s.io);
    const on = s.learning;
    s.mutex.unlock(s.io);
    if (s.learning_sent == on or !s.engine.running()) return;
    s.engine.setLearning(on) catch return;
    s.learning_sent = on;
}

fn transcribe(s: *State, clip: []const i16, gen: u64) void {
    var failed = false;
    // Silence off both ends first; nothing voiced is "nothing heard"
    // without stt.
    const voiced = speech.trim.voiced16(clip);
    const r: local.Result = if (voiced.len < speech.limits.min_samples)
        .{ .id = 0, .text = s.gpa.dupe(u8, "") catch &.{} }
    else if (!ready(s) or !s.engine.running()) blk: {
        failed = true;
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        const why = if (s.status_len > 0) s.status_buf[0..s.status_len] else availText(s.avail);
        break :blk .{ .id = 0, .text = s.gpa.dupe(u8, if (why.len > 0) why else "The speech engine is not running.") catch &.{} };
    } else s.engine.transcribe(s.gpa, voiced) catch |err| blk: {
        failed = true;
        const why: []const u8 = switch (err) {
            error.Crashed, error.BackendLost, error.BadReply => "The speech engine stopped; it starts again with the next dictation.",
            error.Timeout => "Transcription took too long and was dropped.",
            error.TooLong => "Too long to transcribe (over 120 s).",
            error.Busy => "Still transcribing the last one: try again when it is done.",
            else => "Transcription failed.",
        };
        break :blk .{ .id = 0, .text = s.gpa.dupe(u8, why) catch &.{} };
    };
    s.mutex.lockUncancelable(s.io);
    const current = gen == s.gen;
    if (current) {
        if (s.result) |old| s.gpa.free(old.text);
        s.result = r;
        s.result_failed = failed;
        s.busy = false;
    }
    s.mutex.unlock(s.io);
    if (!current) {
        // Canceled meanwhile: stt is told it was wrong, so silence does
        // not confirm it as a sample.
        if (r.id != 0) _ = s.engine.feedback(r.id, "", false) catch {};
        s.gpa.free(r.text);
    }
    client.redraw();
}

fn giveFeedback(s: *State, f: Feedback) void {
    defer s.gpa.free(f.text);
    // Released meanwhile: stt confirmed it as it closed.
    if (!s.engine.running()) return;
    const out = s.engine.feedback(f.id, f.text, f.ok) catch return;
    // A correction learned: a sample to send home, on a pass now.
    if (out == .learned) client.requestSync();
}

fn exportBundle(s: *State, gpa: std.mem.Allocator) ?client.SpeechSync.Bundle {
    s.mutex.lockUncancelable(s.io);
    const learning = s.learning;
    s.mutex.unlock(s.io);
    // Learning off: nothing leaves the device (Engine.nextBundle).
    if (!ready(s)) return null;
    const was_running = s.engine.running();
    const b = (s.engine.nextBundle(gpa, learning, bundle_bytes) catch |err| {
        std.log.warn("speech: export: {t}", .{err});
        return null;
    }) orelse return null;
    if (!was_running) {
        // Started for this pass: it goes again idle_release_ms from now.
        s.mutex.lockUncancelable(s.io);
        s.last_use_ms = nowMs(s.io);
        s.mutex.unlock(s.io);
        syncLearning(s);
    }
    return .{ .bytes = b.bytes, .through = b.through };
}

fn commit(s: *State, through: u32) void {
    s.engine.commitExport(through) catch |err| std.log.warn("speech: commit: {t}", .{err});
}

test "availText" {
    try std.testing.expectEqualStrings("", availText(.ready));
    try std.testing.expect(std.mem.indexOf(u8, availText(.wrong_machine), "unavailable on this device") != null);
}
