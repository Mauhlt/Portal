//! Speech input in the desk's window (docs/audio-design.md): the glue
//! between the shell's 🎤 (ui/shell.zig Dictation), the Audio panel
//! (ui/panels/audio.zig), the microphone thread (module "speech": WASAPI,
//! headset first) and stt.Home on the desktop GPU (speech.home.Engine).
//!
//!   🎤 on       the microphone thread records from the active endpoint
//!               (a visible "● Listening…" in the instruct panel);
//!   🎤 off      it hands the recording over; the engine transcribes it on
//!               its own thread; the text is appended to the instruction
//!               line for review;
//!   sent / Esc  ui/dictation.zig decides stt's feedback (learn the
//!               correction, discard, or nothing: silence confirms).
//!
//! Everything here runs on the window's thread. The microphone thread and
//! the engine wake the window through `notify`; `poll` (each frame) takes
//! what they produced. The only deadlines are real ones: a toast's end and
//! the Audio panel's 3-second Test (`deadlineMs`).

const std = @import("std");
const speech = @import("speech");
const ui = @import("portal_ui");
const settings = @import("settings.zig");

const capture = speech.capture;
const mics = speech.mics;
const audio_panel = ui.panels.audio;
const Engine = if (speech.has_home) speech.home.Engine else void;

/// Where the model is looked for when the settings name none.
pub fn defaultModel(gpa: std.mem.Allocator, data_dir: []const u8) ![]u8 {
    return std.fs.path.join(gpa, &.{ data_dir, "models", speech.model_pin.file_name });
}

const toast_ms: i64 = 4000;

pub const DeskSpeech = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    data_dir: []const u8,
    notify_ctx: *anyopaque,
    notify_fn: *const fn (ctx: *anyopaque) void,

    wasapi: speech.wasapi.Wasapi = .{},
    mic: capture.Mic,
    engine: ?*Engine = null,
    model_path: []u8 = &.{},

    tracker: ui.dictation.Tracker = .{},
    snap: capture.Snapshot = .{},
    /// What the recording in progress is for.
    recording_for: enum { none, dictation, test_clip } = .none,
    /// Test: when its 3 s are up (awake-clock ms).
    test_until: ?i64 = null,
    /// What the desk's Instruct button does (settings.txt `instruct_mode`).
    instruct_mode: ui.shell.InstructMode = .auto,
    /// The speech limits in force (settings.txt `speech.*`).
    limits: speech.limits.Config = .{},
    /// "Not kept for training" was said (once, until a clip is kept again).
    told_not_kept: bool = false,
    /// The number (capture.Recording.seq) of the recording asked for;
    /// any other one that arrives (a Test given up on) is dropped.
    recording_seq: u32 = 0,
    /// "Learn from my voice" (settings.txt speech_learning, default on).
    learning: bool = true,
    /// A model change: the old engine stops on a thread of its own (Home
    /// closing can take a moment), which wakes the window when done; the
    /// new one starts then. Meanwhile: "Stopping speech…".
    retire_thread: ?std.Thread = null,
    retiring: std.atomic.Value(bool) = .init(false),
    next_model: ?[]u8 = null,
    /// Where devices' training bundles come in (web.Config.speech_inbox):
    /// the engine is attached while it runs, detached before it stops.
    inbox: ?*speech.inbox.Inbox = null,

    panel: audio_panel.Ui = .{},
    bufs: audio_panel.Ui.Bufs = .{},
    rows: [audio_panel.max_rows]audio_panel.Row = undefined,
    kind_bufs: [audio_panel.max_rows][48]u8 = undefined,

    toast_buf: [160]u8 = undefined,
    toast_len: usize = 0,
    toast_until: ?i64 = null,
    mic_buf: [mics.max_name + 8]u8 = undefined,
    status_buf: [200]u8 = undefined,
    insert_buf: [ui.dictation.max_text + 2]u8 = undefined,
    /// The engine's state as of the last poll (redraw when it changes).
    last_state: u8 = 255,
    last_busy: u32 = 0,

    /// Starts the microphone thread and the engine (Home opens on its
    /// thread). Call before the window's loop; `self` must not move.
    pub fn start(s: *DeskSpeech, saved: *const settings.Settings) void {
        s.mic = .{ .gpa = s.gpa, .backend = s.wasapi.backend(), .notify_ctx = s.notify_ctx, .notify_fn = s.notify_fn };
        if (saved.mic.get()) |id| s.mic.manual_id.set(id);
        s.mic.automatic = saved.mic.get() == null;
        s.mic.start() catch {};
        s.mic.setLimits(saved.speech);
        s.limits = saved.speech;
        s.instruct_mode = saved.instruct_mode orelse .auto;
        s.learning = saved.speech_learning orelse true;
        if (s.inbox) |ib| ib.setLimits(s.limits);
        const model = saved.speech_model.get();
        s.startEngine(model);
    }

    fn startEngine(s: *DeskSpeech, model: ?[]const u8) void {
        if (s.model_path.len > 0) s.gpa.free(s.model_path);
        s.model_path = if (model) |m| s.gpa.dupe(u8, m) catch &.{} else defaultModel(s.gpa, s.data_dir) catch &.{};
        if (!speech.has_home) return;
        const profile = std.fs.path.join(s.gpa, &.{ s.data_dir, "stt-home" }) catch return;
        defer s.gpa.free(profile);
        const e = Engine.create(s.gpa, s.io, .{ .model_path = s.model_path, .profile_dir = profile }) catch return;
        e.notify_ctx = s.notify_ctx;
        e.notify_fn = s.notify_fn;
        e.setLimits(s.limits);
        if (!s.learning) e.setLearning(false);
        e.start() catch {
            e.destroy();
            return;
        };
        s.engine = e;
        if (s.inbox) |ib| ib.attach(e);
    }

    fn stopEngine(s: *DeskSpeech) void {
        if (!speech.has_home) return;
        if (s.inbox) |ib| ib.detach();
        if (s.engine) |e| e.destroy();
        s.engine = null;
        s.tracker = .{};
    }

    /// Stops the engine off the window's thread; `poll` starts
    /// `next_model` once it has gone (the reaper wakes the window).
    fn retireEngine(s: *DeskSpeech) void {
        if (!speech.has_home) return;
        const e = s.engine orelse return;
        s.engine = null;
        s.tracker = .{};
        // A Test waiting on this engine gets no result now: say so.
        if (s.panel.test_state == .transcribing) s.panel.testResult("Speech restarted (the model changed): try the Test again.", true);
        s.retiring.store(true, .release);
        s.retire_thread = std.Thread.spawn(.{}, reap, .{ s, e }) catch {
            // No thread: stop it here (the window waits this once).
            if (s.inbox) |ib| ib.detach();
            e.destroy();
            s.retiring.store(false, .release);
            return;
        };
    }

    fn reap(s: *DeskSpeech, e: *Engine) void {
        // Imports in flight on it finish first (off the window's thread).
        if (s.inbox) |ib| ib.detach();
        e.destroy();
        s.retiring.store(false, .release);
        s.notify_fn(s.notify_ctx);
    }

    pub fn deinit(s: *DeskSpeech) void {
        s.mic.deinit();
        if (s.retire_thread) |t| t.join();
        s.retire_thread = null;
        s.stopEngine();
        if (s.next_model) |m| s.gpa.free(m);
        if (s.model_path.len > 0) s.gpa.free(s.model_path);
    }

    fn nowMs(s: *const DeskSpeech) i64 {
        return std.Io.Clock.awake.now(s.io).toMilliseconds();
    }

    // ------------------------------------------------------------ the 🎤

    pub fn hooks(s: *DeskSpeech) ui.shell.Dictation {
        return .{ .ctx = s, .start = onStart, .stop = onStop, .sent = onSent, .cleared = onCleared, .cancel = onCancel };
    }

    fn of(ctx: *anyopaque) *DeskSpeech {
        return @ptrCast(@alignCast(ctx));
    }

    /// The 🎤 on: true if recording started (a Test keeps the
    /// microphone; without one there is nothing to record from).
    fn onStart(ctx: *anyopaque) bool {
        const s = of(ctx);
        if (s.recording_for == .test_clip) return false;
        if (s.snap.active == null) return false;
        s.recording_for = .dictation;
        s.recording_seq = s.mic.startRecording();
        return true;
    }

    fn onStop(ctx: *anyopaque) void {
        const s = of(ctx);
        if (s.recording_for != .dictation) return;
        s.mic.stopRecording();
    }

    /// The user gave up the transcription (or closed the panel on it).
    fn onCancel(ctx: *anyopaque) void {
        const s = of(ctx);
        if (!speech.has_home) return;
        if (s.engine) |e| _ = e.cancel();
    }

    fn onSent(ctx: *anyopaque, line: []const u8) void {
        const s = of(ctx);
        s.perform(s.tracker.sent(line));
    }

    fn onCleared(ctx: *anyopaque) void {
        const s = of(ctx);
        s.perform(s.tracker.cleared());
    }

    fn perform(s: *DeskSpeech, d: ui.dictation.Decision) void {
        if (!speech.has_home) return;
        const e = s.engine orelse return;
        const r = switch (d) {
            .none => return,
            .learn => |l| e.feedback(l.id, l.text, true),
            .discard => |id| e.feedback(id, "", false),
        };
        r catch |err| switch (err) {
            // Too many corrections in a row: this one is not learned.
            error.RateLimited => {
                var buf: [120]u8 = undefined;
                s.showToast(s.limitText(e, &buf, "corrections (this one was not learned)"));
            },
            error.TextTooLong => s.showToast("That correction is too long to learn from."),
            // Answered already, or too old: nothing to do.
            error.UnknownId, error.OutOfMemory => {},
        };
    }

    // ------------------------------------------------------------ each frame

    /// Takes what the threads produced since the last frame; updates the
    /// shell's 🎤 state. True if the window should redraw.
    pub fn poll(s: *DeskSpeech, sh: *ui.Shell) bool {
        var changed = false;
        const old_gen = s.snap.list_gen;
        const old_steps = capture.levelSteps(s.snap.level);
        const old_rec = s.snap.recording;
        const old_cap = s.snap.capturing;
        s.mic.snapshot(&s.snap);
        if (s.snap.list_gen != old_gen or capture.levelSteps(s.snap.level) != old_steps or s.snap.recording != old_rec or s.snap.capturing != old_cap) changed = true;

        var cb: [mics.max_name + 32]u8 = undefined;
        if (s.mic.takeChange(&cb)) |text| {
            s.showToast(text);
            changed = true;
        }
        const now = s.nowMs();
        if (s.toast_until) |t| if (now >= t) {
            s.toast_until = null;
            s.toast_len = 0;
            changed = true;
        };
        if (s.test_until) |t| if (now >= t) {
            s.test_until = null;
            s.mic.stopRecording();
        };
        // A transcription past its timeout: given up (its result dropped).
        if (speech.has_home) if (s.engine) |e| if (e.jobDeadline()) |t| if (now >= t) {
            if (e.cancel()) {
                s.showToast("Transcription took too long and was dropped.");
                if (s.panel.test_state == .transcribing) s.panel.testResult("Transcription took too long and was dropped.", true);
                changed = true;
            }
        };
        if (s.retire_thread != null and !s.retiring.load(.acquire)) {
            s.retire_thread.?.join();
            s.retire_thread = null;
            if (s.next_model) |m| {
                s.next_model = null;
                defer s.gpa.free(m);
                s.startEngine(m);
            }
            changed = true;
        }
        if (s.mic.takeRecording()) |rec| {
            changed = true;
            // Only the recording asked for counts (a Test given up on, or
            // one overtaken by a newer start, is dropped).
            var purpose = s.recording_for;
            if (rec.seq != s.recording_seq) {
                purpose = .none;
            } else {
                s.recording_for = .none;
                s.recording_seq = 0;
            }
            if (purpose == .test_clip) s.panel.testRecorded();
            if (rec.truncated) s.showToast("Dictation stopped at 120 s (the most stt takes at once).");
            s.transcribe(purpose, rec.samples);
        }
        // A recording that hit the 120 s cap: the 🎤 goes off.
        if (sh.dictating and s.recording_for == .dictation and s.snap.full) sh.stopDictation();
        if (speech.has_home) if (s.engine) |e| {
            while (e.takeResult()) |r| {
                defer s.gpa.free(r.text);
                changed = true;
                switch (r.purpose) {
                    .test_clip => s.panel.testResult(r.text, r.failed),
                    .dictation => if (r.failed) {
                        s.showToast(r.text);
                    } else {
                        if (r.not_kept and !s.told_not_kept) {
                            s.told_not_kept = true;
                            s.showToast("Today's limit of clips kept for training is reached: this one is transcribed but not kept.");
                        } else if (!r.not_kept) s.told_not_kept = false;
                        var d: ui.dictation.Decision = .none;
                        const add = s.tracker.added(r.id, r.text, sh.line.text(), &s.insert_buf, &d);
                        s.perform(d);
                        // Cut or changed on the way into the line (its
                        // limit, a line break, a tab): never learned as
                        // if sent unchanged; discarded instead.
                        if (!sh.dictated(add)) switch (s.tracker.cleared()) {
                            // Portal's discard: no token, no toast.
                            .discard => |id| if (speech.has_home) if (s.engine) |e2| {
                                e2.discard(id) catch {};
                            },
                            else => {},
                        };
                    },
                }
            }
            const st = e.getStatus();
            if (@backingInt(st.state) != s.last_state or st.busy != s.last_busy) changed = true;
            s.last_state = @backingInt(st.state);
            s.last_busy = st.busy;
        };
        s.updateShell(sh);
        // Record mode couldn't record: say why, once.
        if (sh.unavailable_notice) {
            sh.unavailable_notice = false;
            s.showToast(sh.speech_off);
            changed = true;
        }
        return changed;
    }

    fn transcribe(s: *DeskSpeech, purpose: @TypeOf(s.recording_for), samples: []i16) void {
        if (!speech.has_home or purpose == .none) {
            s.gpa.free(samples);
            return;
        }
        const e = s.engine orelse {
            s.gpa.free(samples);
            if (purpose == .test_clip) s.panel.testResult("Speech is not available.", true);
            return;
        };
        e.transcribe(if (purpose == .test_clip) .test_clip else .dictation, samples) catch |err| {
            var buf: [120]u8 = undefined;
            const why: []const u8 = switch (err) {
                error.TooShort => "Nothing to transcribe (under a quarter of a second).",
                error.TooLong => "Too long to transcribe (over 120 s).",
                error.Busy => "Still transcribing the last one: try again when it is done.",
                error.RateLimited => s.limitText(e, &buf, "transcriptions"),
                error.SpeechUnavailable => "Speech is not available.",
            };
            if (purpose == .test_clip) s.panel.testResult(why, true) else s.showToast(why);
        };
    }

    /// "Over the hourly limit for transcriptions: possible again in 4 min."
    fn limitText(_: *DeskSpeech, e: *Engine, buf: []u8, what: []const u8) []const u8 {
        const l = e.lastLimited() orelse return "Too many in a row.";
        const secs = @max(1, @divFloor(l.in_ms +| 999, 1000));
        const when = if (secs < 120)
            std.fmt.bufPrint(buf[60..], "{d} s", .{secs}) catch ""
        else if (secs < 7200)
            std.fmt.bufPrint(buf[60..], "{d} min", .{@divFloor(secs + 59, 60)}) catch ""
        else
            std.fmt.bufPrint(buf[60..], "{d} h", .{@divFloor(secs + 3599, 3600)}) catch "";
        var tmp: [64]u8 = undefined;
        @memcpy(tmp[0..when.len], when);
        return std.fmt.bufPrint(buf, "Over {s} for {s}: possible again in {s}.", .{ l.limit.label(), what, tmp[0..when.len] }) catch "Too many in a row.";
    }

    fn showToast(s: *DeskSpeech, text: []const u8) void {
        const n = @min(text.len, s.toast_buf.len);
        @memcpy(s.toast_buf[0..n], text[0..n]);
        s.toast_len = n;
        s.toast_until = s.nowMs() + toast_ms;
    }

    /// The toast to draw now, if any.
    pub fn toast(s: *const DeskSpeech) ?ui.frame.Toast {
        if (s.toast_len == 0) return null;
        return .{ .text = s.toast_buf[0..s.toast_len], .tone = .warn };
    }

    /// Milliseconds until the next deadline here (a toast ending, Test's
    /// 3 s), or null.
    pub fn deadlineMs(s: *const DeskSpeech) ?i64 {
        var best: ?i64 = null;
        const job: ?i64 = if (speech.has_home) (if (s.engine) |e| e.jobDeadline() else null) else null;
        for ([_]?i64{ s.toast_until, s.test_until, job }) |d| if (d) |t| {
            best = if (best) |b| @min(b, t) else t;
        };
        const b = best orelse return null;
        return @max(0, b - s.nowMs());
    }

    /// Why speech can't run now ("" if it can).
    fn speechState(s: *DeskSpeech, bad: *bool) []const u8 {
        bad.* = false;
        if (!speech.has_home) {
            bad.* = true;
            return "Speech on this device comes with stt-local (not delivered yet).";
        }
        if (s.retiring.load(.acquire) or s.next_model != null) return "Stopping speech\u{2026}";
        const e = s.engine orelse {
            bad.* = true;
            return "Speech could not start.";
        };
        const st = e.getStatus();
        return switch (st.state) {
            .ready => "",
            .loading => "Loading the speech model\u{2026}",
            .failed => blk: {
                bad.* = true;
                const w = st.why();
                const n = @min(w.len, s.status_buf.len);
                @memcpy(s.status_buf[0..n], w[0..n]);
                break :blk s.status_buf[0..n];
            },
        };
    }

    fn updateShell(s: *DeskSpeech, sh: *ui.Shell) void {
        sh.mic_label = if (s.snap.activeEndpoint()) |e| e.name.get() else "no microphone";
        sh.transcribing = if (speech.has_home) (if (s.engine) |e| e.getStatus().busy > 0 else false) else false;
        var bad = false;
        const state = s.speechState(&bad);
        sh.speech_off = if (s.snap.active == null) "No microphone found (Audio in the top bar)." else state;
        // Re-evaluated on every poll, so a device change (the microphone
        // thread's IMMNotificationClient wake) updates it at once.
        sh.setSpeechReady(s.snap.active != null and !bad and state.len == 0);
        sh.instruct_mode = s.instruct_mode;
    }

    // ------------------------------------------------------------ Audio panel

    pub fn openPanel(s: *DeskSpeech) void {
        s.panel.show(s.snap.automatic, s.model_path, s.instruct_mode);
        s.panel.learning = s.learning;
        // The meter runs exactly while the panel is open.
        s.mic.setMeter(true);
    }

    pub fn panelView(s: *DeskSpeech) audio_panel.View {
        const n = @min(s.snap.list.len, audio_panel.max_rows);
        for (s.snap.list.slice()[0..n], 0..) |*e, i| s.rows[i] = .{
            .name = e.name.get(),
            .kind = e.typeLabel(&s.kind_bufs[i]),
            .active = s.snap.active == i,
            .default = e.default_comms or e.default_console,
        };
        var bad = false;
        const state = s.speechState(&bad);
        return .{
            .rows = s.rows[0..n],
            .automatic = s.snap.automatic,
            .fell_back = s.snap.fell_back,
            .level = capture.levelSteps(s.snap.level),
            .capturing = s.snap.capturing,
            .speech = state,
            .speech_bad = bad,
            .mic_error = s.snap.err(),
        };
    }

    /// What an Audio panel action changes in the settings (the window
    /// saves them): the microphone choice or the model path.
    pub const Saved = union(enum) { none, mic: ?[]const u8, model: []const u8, reload, instruct_mode: ui.shell.InstructMode, learning: bool };

    /// New speech limits (settings.txt reloaded at the desk): applied live.
    pub fn setLimits(s: *DeskSpeech, c: speech.limits.Config) void {
        s.limits = c.clamped();
        s.mic.setLimits(s.limits);
        if (speech.has_home) if (s.engine) |e| e.setLimits(s.limits);
        if (s.inbox) |ib| ib.setLimits(s.limits);
    }

    pub fn act(s: *DeskSpeech, a: audio_panel.Action) Saved {
        switch (a) {
            .reload_limits => return .reload,
            .set_learning => |on| {
                s.learning = on;
                if (speech.has_home) if (s.engine) |e| e.setLearning(on);
                return .{ .learning = on };
            },
            .set_instruct_mode => |m| {
                s.instruct_mode = m;
                return .{ .instruct_mode = m };
            },
            .none, .paste => return .none,
            .closed => {
                s.mic.setMeter(false);
                // A Test still recording or transcribing goes with the panel.
                if (s.recording_for == .test_clip) {
                    s.test_until = null;
                    s.mic.stopRecording();
                    s.recording_for = .none;
                    s.recording_seq = 0; // its recording is dropped when it comes
                }
                if (s.panel.test_state == .transcribing) if (speech.has_home) if (s.engine) |e| {
                    _ = e.cancel();
                };
                return .none;
            },
            .set_auto => |on| {
                if (on) {
                    s.mic.setMode(.automatic);
                    return .{ .mic = null };
                }
                // Off: pin what is active now.
                const e = s.snap.activeEndpoint() orelse return .none;
                s.mic.setMode(.{ .manual = e.id.get() });
                return .{ .mic = e.id.get() };
            },
            .use => |i| {
                if (i >= s.snap.list.len) return .none;
                const id = s.snap.list.items[i].id.get();
                s.mic.setMode(.{ .manual = id });
                return .{ .mic = id };
            },
            .test_clip => {
                if (s.recording_for != .none) {
                    s.panel.testResult("The microphone is busy (dictation is on).", true);
                    return .none;
                }
                s.recording_for = .test_clip;
                s.test_until = s.nowMs() + audio_panel.test_ms;
                s.recording_seq = s.mic.startRecording();
                return .none;
            },
            .save_model => {
                const path = std.mem.trim(u8, s.panel.model.text(), " \"");
                if (path.len == 0) {
                    s.panel.setNote(.bad, "Enter the model file's path.", .{});
                    return .none;
                }
                if (s.next_model) |m| s.gpa.free(m);
                s.next_model = s.gpa.dupe(u8, path) catch null;
                if (s.engine != null) s.retireEngine();
                if (s.retire_thread == null) if (s.next_model) |m| {
                    s.next_model = null;
                    defer s.gpa.free(m);
                    s.startEngine(m);
                };
                s.panel.setNote(.good, "Switching to {s}\u{2026}", .{std.fs.path.basename(path)});
                return .{ .model = path };
            },
        }
    }
};

test "a model swap during a Test's transcription ends the Test with a message" {
    if (!speech.has_home) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const Nop = struct {
        fn f(_: *anyopaque) void {}
    };
    var dummy: u8 = 0;
    var s: DeskSpeech = .{ .gpa = gpa, .io = std.testing.io, .data_dir = ".", .notify_ctx = &dummy, .notify_fn = Nop.f, .mic = undefined };
    s.engine = try Engine.create(gpa, std.testing.io, .{ .model_path = "m", .profile_dir = "p" });
    s.panel.test_state = .transcribing;
    s.retireEngine();
    try std.testing.expectEqual(audio_panel.TestState.failed, s.panel.test_state);
    if (s.retire_thread) |t| t.join();
    try std.testing.expect(!s.retiring.load(.acquire));
}
