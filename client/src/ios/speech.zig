//! Dictation on the iPhone itself: the shared input line's 🎤
//! (connect.Platform.speech -> ui/shell.zig Dictation, the same hooks the
//! desk's engine fills) recording with mic.zig and transcribing with
//! stt.Local on its Core ML engine, on the bundled base model, the very
//! file the desk trains on (src/speech/model_pin.zig). The audio is
//! transcribed on the phone; with "learn from my voice" on (the default;
//! the device setting `speech_learning = off` turns it off), the samples
//! stt keeps from your corrections (and from silence: an unchanged
//! transcript is confirmed after 60 s) go to your own desk through the
//! tunnel, where the GPU trains the personal adapter, and that adapter
//! comes back: trained at home, better everywhere.
//!
//!   app thread    start / stop / cancel / sent / cleared (the shell's 🎤
//!                 and line) and `frame` (each frame: the transcript into
//!                 the line, the 🎤's state); never blocks on stt.
//!   sync worker   connect.zig's, on every pass (connect, the desk's
//!                 updates, a learned correction: connect.requestSync):
//!                 `installed` hands over the stt-adapter package it
//!                 verified (signed by the pinned release key, a newer
//!                 sequence, data only: sync.engine Options.allow);
//!                 `nextBundle` / `sent` move training samples home
//!                 (shared/bulk.zig `put bundle`; deleted here only once
//!                 the desk stored them). These wait for the speech
//!                 worker's answer.
//!   speech worker one thread, asleep on an Io.Condition until there is
//!                 work or a deadline: opens stt.Local (model + Core ML
//!                 programs, cached in Library/Caches/stt-coreml; the
//!                 first time takes seconds), transcribes, applies
//!                 feedback and adapter updates, packs bundles. The only
//!                 thread that touches the stt profile. Never the UIKit
//!                 main thread.
//!
//! Energy: recording starts the engine loading in parallel (`warm`); a
//! clip loses its leading and trailing silence (speech.trim) before stt
//! sees it. The engine is released 60 s after the last dictation (a
//! deadline the worker sleeps until, together with stt's own silence
//! confirm; no polling) and on suspend, when a recording is stopped and
//! dropped too: iOS reclaims memory from background apps.
//!
//! Adapter updates: an update file (update.bin, stt's STTUPD01) is
//! swapped into the open engine at once (stt.Local.importUpdate: only the
//! Core ML decoder is rebuilt, the model stays loaded) or imported into
//! the profile for the next load; a raw adapter (adapter.bin, its version
//! the package's version number) is used from the next load, the engine
//! closing at the next idle moment.
//!
//! Storage: the stt profile (samples, rules, vocabulary, the adapter) is
//! Library/Application Support/Portal/stt-local, the sync store
//! .../Portal/sync, the Core ML programs Library/Caches/stt-coreml, each
//! with iOS file protection Complete (readable only while the phone is
//! unlocked: the class of the device key's Keychain item, credstore.zig).

const std = @import("std");
const view = @import("view");
const stt = @import("stt");
const connect = @import("client");
const ui = connect.ui_mod;
const mic = @import("mic.zig");
const speech_mod = @import("speech");
const ios = view.Window.ios;
const objc = ios.objc;
const Object = objc.Object;
const msgSend = objc.msgSend;
const sel = objc.sel;

/// The model in Portal.app (build.zig: only iOS builds bundle it): the
/// desk's own base model (src/speech/model_pin.zig).
pub const model_name = "stt/" ++ speech_mod.model_pin.file_name;
/// The one package the phone takes from its desk.
pub const adapter_package = "stt-adapter";
/// The packages the phone accepts (connect.Platform.sync).
pub const sync_packages: []const []const u8 = &.{adapter_package};
/// How long the engine stays loaded after the last dictation.
pub const idle_release_ms: i64 = 60_000;
/// The largest training bundle sent home at once (the desk takes up to
/// its `speech.bundle_max_kib`, 5 MiB by default).
pub const bundle_bytes = 2 << 20;
/// Training samples carry this source name (the desk keys its limits on
/// the paired session's name, never on this).
const device_name = "iphone";
const max_feedback = 16;

const Feedback = struct { id: u64, text: []u8, ok: bool };
const BundleReq = struct { gpa: std.mem.Allocator, answer: ?connect.SpeechSync.Bundle = null, done: bool = false };

const State = struct {
    io: std.Io = undefined,
    gpa: std.mem.Allocator = std.heap.c_allocator,

    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    /// The sync worker waits on this for its answers.
    answered: std.Io.Condition = .init,
    // ---- under `mutex`: work for the speech worker
    warm: bool = false,
    release: bool = false,
    clip: ?[]f32 = null,
    /// Bumped by cancel / suspend: a result for an older one is dropped.
    gen: u64 = 0,
    clip_gen: u64 = 0,
    busy: bool = false,
    feedback: [max_feedback]Feedback = undefined,
    n_feedback: usize = 0,
    /// "Learn from my voice" (device settings), and a change to apply.
    learning: bool = true,
    learning_dirty: bool = false,
    /// An installed stt-adapter version folder not applied yet.
    adapter_dir_buf: [1024]u8 = undefined,
    adapter_dir_len: usize = 0,
    adapter_ver_buf: [64]u8 = undefined,
    adapter_ver_len: usize = 0,
    adapter_new: bool = false,
    bundle_req: ?*BundleReq = null,
    commit_req: ?u32 = null,
    commit_done: bool = true,
    /// Real-clock ms of the last dictation (the idle release counts from it).
    last_use_ms: i64 = 0,
    // ---- under `mutex`: what the speech worker reports
    result: ?stt.local.Result = null,
    result_failed: bool = false,
    loading: bool = false,
    status_buf: [160]u8 = undefined,
    status_len: usize = 0,
    /// The adapter version the engine uses (0: the base model alone).
    adapter_version: u32 = 0,

    // ---- app thread only
    thread: ?std.Thread = null,
    recording: bool = false,
    tracker: ui.dictation.Tracker = .{},
    insert_buf: [ui.dictation.max_text + 2]u8 = undefined,
    /// Why the last start or transcription failed ("" if not).
    note_buf: [160]u8 = undefined,
    note_len: usize = 0,
    mic_buf: [128]u8 = undefined,
    /// The worker's status, copied for the shell (it keeps the slice).
    status_ui_buf: [160]u8 = undefined,

    // ---- speech worker only
    local: ?*stt.Local = null,
    /// A raw adapter for the next load (path and version), and whether the
    /// open engine should close at the next idle moment to take it.
    raw_adapter_buf: [1100]u8 = undefined,
    raw_adapter_len: usize = 0,
    raw_adapter_version: u32 = 0,
    reload_pending: bool = false,
    applied_buf: [1024]u8 = undefined,
    applied_len: usize = 0,
};

var state: State = .{};

pub fn init(io: std.Io) void {
    state.io = io;
    mic.init(io, state.gpa);
    var sb: [4096]u8 = undefined;
    const text = connect.pin.loadDeviceSettings(io, &sb);
    state.learning = ui.convoview.parseOnOffSetting(text, "speech_learning") orelse true;
    state.learning_dirty = true;
    // The sync store (the adapter package lands there) is protected like
    // the profile.
    var rb: [connect.pin.max_path]u8 = undefined;
    if (connect.sync.keypin.syncRoot(&rb)) |root| protect(io, root) else |_| {}
    // The sync worker may ask for bundles before the first dictation.
    state.thread = std.Thread.spawn(.{}, worker, .{&state}) catch null;
}

pub fn hooks() connect.Speech {
    return .{
        .dictation = .{ .ctx = &state, .start = onStart, .stop = onStop, .cancel = onCancel, .sent = onSent, .cleared = onCleared },
        .frame = frame,
    };
}

/// The sync worker's side (connect.Platform.speech_sync).
pub fn syncHooks() connect.SpeechSync {
    return .{ .ctx = &state, .installed = installed, .next_bundle = nextBundle, .sent = sent };
}

fn setNote(s: *State, text: []const u8) void {
    const n = @min(text.len, s.note_buf.len);
    @memcpy(s.note_buf[0..n], text[0..n]);
    s.note_len = n;
}

/// What a failed start means for the user.
pub fn startNote(err: mic.StartError) []const u8 {
    return switch (err) {
        error.NotAllowed => "Portal may not use the microphone: allow it in Settings > Portal > Microphone.",
        error.AskedForAccess => "Allow the microphone, then tap Dictate again.",
        error.SessionFailed => "The microphone is busy (a call or another app).",
        error.NoInput => "No microphone is available.",
        error.EngineFailed => "The microphone could not start.",
        error.OutOfMemory => "Not enough memory to record.",
    };
}

fn nowMs(io: std.Io) i64 {
    return std.Io.Timestamp.now(io, .real).toMilliseconds();
}

/// The 🎤 on (app thread).
fn onStart(ctx: *anyopaque) bool {
    const s: *State = @ptrCast(@alignCast(ctx));
    s.note_len = 0;
    if (s.thread == null) s.thread = std.Thread.spawn(.{}, worker, .{s}) catch {
        setNote(s, "Dictation could not start (no worker thread).");
        return false;
    };
    mic.start() catch |err| {
        setNote(s, startNote(err));
        return false;
    };
    s.recording = true;
    s.mutex.lockUncancelable(s.io);
    s.warm = true;
    s.release = false;
    s.last_use_ms = nowMs(s.io);
    s.mutex.unlock(s.io);
    s.cond.signal(s.io);
    return true;
}

/// The 🎤 off: the clip goes to the worker.
fn onStop(ctx: *anyopaque) void {
    const s: *State = @ptrCast(@alignCast(ctx));
    if (!s.recording) return;
    s.recording = false;
    const clip = mic.stop() orelse return;
    s.mutex.lockUncancelable(s.io);
    if (s.clip) |old| s.gpa.free(old);
    s.clip = clip;
    s.clip_gen = s.gen;
    s.busy = true;
    s.mutex.unlock(s.io);
    s.cond.signal(s.io);
}

/// "Transcribing (cancel)": the running transcription's text is dropped
/// (stt cannot stop mid-clip; the worker finishes and discards it).
fn onCancel(ctx: *anyopaque) void {
    const s: *State = @ptrCast(@alignCast(ctx));
    s.mutex.lockUncancelable(s.io);
    defer s.mutex.unlock(s.io);
    s.gen +%= 1;
    if (s.clip) |c| s.gpa.free(c);
    s.clip = null;
    s.busy = false;
    if (s.result) |r| s.gpa.free(r.text);
    s.result = null;
}

/// The line was sent: stt learns the correction, if there was one
/// (ui/dictation.zig decides; unchanged: nothing, silence confirms it).
fn onSent(ctx: *anyopaque, line: []const u8) void {
    const s: *State = @ptrCast(@alignCast(ctx));
    perform(s, s.tracker.sent(line));
}

fn onCleared(ctx: *anyopaque) void {
    const s: *State = @ptrCast(@alignCast(ctx));
    perform(s, s.tracker.cleared());
}

/// Queues a feedback decision for the worker (app thread; the oldest goes
/// when the queue is full).
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

/// UI thread (device.onSuspend): off screen. The recording stops and is
/// dropped, and the worker releases the engine (stt confirms what is
/// pending first).
pub fn suspend_() void {
    const s = &state;
    if (s.recording) {
        s.recording = false;
        if (mic.stop()) |c| s.gpa.free(c);
    }
    onCancel(s);
    s.mutex.lockUncancelable(s.io);
    s.warm = false;
    s.release = true;
    s.mutex.unlock(s.io);
    s.cond.signal(s.io);
}

/// Each frame (UI thread): a finished transcript into the line, and the
/// 🎤's state.
fn frame(ctx: *anyopaque, sh: *ui.Shell) void {
    const s: *State = @ptrCast(@alignCast(ctx));
    // The clip reached stt's limit: the 🎤 goes off (sh.stopDictation
    // calls onStop, which hands it over).
    if (s.recording and mic.isFull()) {
        sh.stopDictation();
        setNote(s, "Dictation stopped at 120 s (the most stt takes at once).");
    }
    s.mutex.lockUncancelable(s.io);
    const result = s.result;
    const failed = s.result_failed;
    s.result = null;
    sh.transcribing = s.busy;
    const loading = s.loading;
    const adapter_version = s.adapter_version;
    const status = s.status_ui_buf[0..s.status_len];
    @memcpy(status, s.status_buf[0..s.status_len]);
    s.mutex.unlock(s.io);
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
    // use, once home has trained one (what to check after a training run).
    sh.mic_label = if (s.recording)
        mic.inputName(&s.mic_buf)
    else if (adapter_version > 0)
        std.fmt.bufPrint(&s.mic_buf, "your voice v{d}", .{adapter_version}) catch ""
    else
        "";
    const denied = mic.cachedPermission() == .denied;
    sh.speech_off = if (denied)
        startNote(error.NotAllowed)
    else if (s.note_len > 0)
        s.note_buf[0..s.note_len]
    else if (status.len > 0)
        status
    else if (loading)
        "Loading the speech model\u{2026}"
    else
        "";
    // A failed model load is not fatal: the next Dictate tries again.
    sh.setSpeechReady(!denied);
}

// ------------------------------------------------------------ sync worker side

/// Sync worker: the current stt-adapter version folder (every pass).
fn installed(ctx: *anyopaque, pkg: []const u8, dir: []const u8, version: []const u8) void {
    const s: *State = @ptrCast(@alignCast(ctx));
    if (!std.mem.eql(u8, pkg, adapter_package) or dir.len > s.adapter_dir_buf.len or version.len > s.adapter_ver_buf.len) return;
    s.mutex.lockUncancelable(s.io);
    defer s.mutex.unlock(s.io);
    if (std.mem.eql(u8, s.adapter_dir_buf[0..s.adapter_dir_len], dir)) return;
    @memcpy(s.adapter_dir_buf[0..dir.len], dir);
    s.adapter_dir_len = dir.len;
    @memcpy(s.adapter_ver_buf[0..version.len], version);
    s.adapter_ver_len = version.len;
    s.adapter_new = true;
    s.cond.signal(s.io);
}

/// Sync worker: the next bundle for home, packed by the speech worker.
fn nextBundle(ctx: *anyopaque, gpa: std.mem.Allocator) ?connect.SpeechSync.Bundle {
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

/// Sync worker: the desk stored the samples up to `through`.
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
    release: bool,
    clip: ?[]f32,
    gen: u64,
    feedback: [max_feedback]Feedback,
    n_feedback: usize,
    learning: ?bool,
    adapter: bool,
    bundle: ?*BundleReq,
    commit: ?u32,
    timed_out: bool,
    last_use_ms: i64,
};

fn hasWork(s: *const State) bool {
    return s.warm or s.release or s.clip != null or s.n_feedback > 0 or s.learning_dirty or
        s.adapter_new or s.bundle_req != null or s.commit_req != null;
}

/// The next deadline (real-clock ms) while the engine is loaded: stt's
/// silence confirm, and the idle release.
fn deadline(s: *const State) ?i64 {
    const l = s.local orelse return null;
    const idle = s.last_use_ms + idle_release_ms;
    return if (l.tick()) |c| @min(c, idle) else idle;
}

/// Under `mutex`: sleeps until there is work or the deadline passed, and
/// takes the work.
fn waitWork(s: *State) Work {
    var timed_out = false;
    while (!hasWork(s)) {
        const d = deadline(s) orelse {
            s.cond.waitUncancelable(s.io, &s.mutex);
            continue;
        };
        if (d <= nowMs(s.io)) {
            timed_out = true;
            break;
        }
        const ts: std.Io.Clock.Timestamp = .{ .raw = .fromNanoseconds(@as(i96, d) * std.time.ns_per_ms), .clock = .real };
        s.cond.waitTimeout(s.io, &s.mutex, .{ .deadline = ts }) catch |err| switch (err) {
            error.Timeout => {
                timed_out = !hasWork(s);
                break;
            },
            error.Canceled => {},
        };
    }
    const w: Work = .{
        .warm = s.warm,
        // A new clip after a suspend: keep the engine for it.
        .release = s.release and s.clip == null,
        .clip = s.clip,
        .gen = s.clip_gen,
        .feedback = s.feedback,
        .n_feedback = s.n_feedback,
        .learning = if (s.learning_dirty) s.learning else null,
        .adapter = s.adapter_new,
        .bundle = s.bundle_req,
        .commit = s.commit_req,
        .timed_out = timed_out,
        .last_use_ms = s.last_use_ms,
    };
    s.warm = false;
    s.release = false;
    s.clip = null;
    s.n_feedback = 0;
    s.learning_dirty = false;
    s.adapter_new = false;
    s.commit_req = null;
    return w;
}

fn worker(s: *State) void {
    while (true) {
        s.mutex.lockUncancelable(s.io);
        const w = waitWork(s);
        s.mutex.unlock(s.io);

        if (w.learning) |on| setLearning(s, on);
        if (w.adapter) applyAdapter(s, w.warm or w.clip != null);
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
        if (w.release) {
            unload(s);
            continue;
        }
        if (w.timed_out) {
            // Idle long enough and nothing waiting on stt's own clock: the
            // engine's memory goes back (it reloads on the next 🎤).
            if (s.local) |l| if (l.tick() == null and nowMs(s.io) >= w.last_use_ms + idle_release_ms) unload(s);
            continue;
        }
        if (w.warm or w.clip != null) load(s);
        const c = w.clip orelse continue;
        defer s.gpa.free(c);
        transcribe(s, c, w.gen);
        // A raw adapter came while busy: take it now, between dictations.
        if (s.reload_pending) unload(s);
        s.mutex.lockUncancelable(s.io);
        s.last_use_ms = nowMs(s.io);
        s.mutex.unlock(s.io);
    }
}

fn transcribe(s: *State, clip: []const f32, gen: u64) void {
    var failed = false;
    // Silence off both ends first; a clip with nothing voiced in it is
    // "nothing heard" without stt.
    const voiced = speech_mod.trim.voiced(clip);
    const r: stt.local.Result = if (voiced.len < speech_mod.limits.min_samples)
        .{ .id = 0, .text = s.gpa.dupe(u8, "") catch &.{} }
    else if (s.local) |l| l.transcribePcm(s.gpa, voiced) catch |err| blk: {
        failed = true;
        if (err == error.BackendLost) unload(s);
        break :blk .{ .id = 0, .text = std.fmt.allocPrint(s.gpa, "Transcription failed: {t}", .{err}) catch &.{} };
    } else blk: {
        failed = true;
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        break :blk .{ .id = 0, .text = s.gpa.dupe(u8, s.status_buf[0..s.status_len]) catch &.{} };
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
        if (r.id != 0) if (s.local) |l| {
            _ = l.feedback(r.id, "", false) catch {};
        };
        s.gpa.free(r.text);
    }
    ios.postEvent(.expose);
}

fn giveFeedback(s: *State, f: Feedback) void {
    defer s.gpa.free(f.text);
    const l = s.local orelse return; // released meanwhile: stt confirmed it already
    const out = l.feedback(f.id, f.text, f.ok) catch return;
    // A correction learned: a sample to send home, on a pass now.
    if (out == .learned) connect.requestSync();
}

fn setLearning(s: *State, on: bool) void {
    if (s.local) |l| {
        l.setLearning(on) catch {};
        return;
    }
    var p = openProfile(s) orelse return;
    defer p.deinit();
    p.setLearning(on) catch {};
}

/// The stt profile alone (no model, no engine): sync work while the
/// engine is released.
fn openProfile(s: *State) ?stt.Profile {
    var pb: [1024]u8 = undefined;
    const dir = profileDir(s.io, &pb) orelse return null;
    return stt.Profile.load(s.gpa, s.io, dir) catch |err| {
        std.log.err("speech: profile: {t}", .{err});
        return null;
    };
}

fn exportBundle(s: *State, gpa: std.mem.Allocator) ?connect.SpeechSync.Bundle {
    s.mutex.lockUncancelable(s.io);
    const learning = s.learning;
    s.mutex.unlock(s.io);
    // Learning off: nothing leaves the phone.
    if (!learning) return null;
    const b = if (s.local) |l|
        l.exportBundle(gpa, bundle_bytes) catch null
    else blk: {
        var p = openProfile(s) orelse return null;
        defer p.deinit();
        break :blk stt.sync.exportBundle(gpa, &p, device_name, bundle_bytes) catch null;
    };
    const got = b orelse return null;
    return .{ .bytes = got.bytes, .through = got.through };
}

fn commit(s: *State, through: u32) void {
    if (s.local) |l| {
        l.commitExport(through) catch |err| std.log.err("speech: commit: {t}", .{err});
        return;
    }
    var p = openProfile(s) orelse return;
    defer p.deinit();
    stt.sync.commitExport(&p, through) catch |err| std.log.err("speech: commit: {t}", .{err});
}

/// The verified stt-adapter package: an update swapped in (or imported for
/// the next load), a raw adapter kept for the next load. `busy`: a
/// dictation is on its way (a reload waits for it).
fn applyAdapter(s: *State, busy: bool) void {
    var db: [1024]u8 = undefined;
    var vb: [64]u8 = undefined;
    s.mutex.lockUncancelable(s.io);
    const dir = db[0..s.adapter_dir_len];
    @memcpy(dir, s.adapter_dir_buf[0..s.adapter_dir_len]);
    const ver = vb[0..s.adapter_ver_len];
    @memcpy(ver, s.adapter_ver_buf[0..s.adapter_ver_len]);
    s.mutex.unlock(s.io);
    if (std.mem.eql(u8, dir, s.applied_buf[0..s.applied_len])) return;
    var pb: [1100]u8 = undefined;
    const file = adapterFile(s.io, dir, &pb) orelse {
        std.log.err("speech: stt-adapter {s} has no update.bin or adapter.bin", .{ver});
        return;
    };
    const bytes = std.Io.Dir.cwd().readFileAlloc(s.io, file, s.gpa, .limited(256 << 20)) catch |err| {
        std.log.err("speech: stt-adapter {s}: {t}", .{ ver, err });
        return;
    };
    defer s.gpa.free(bytes);
    if (std.mem.startsWith(u8, bytes, "STTUPD01")) {
        const v = if (s.local) |l| l.importUpdate(s.gpa, bytes) catch |err| {
            std.log.err("speech: adapter update {s}: {t}", .{ ver, err });
            return;
        } else blk: {
            var p = openProfile(s) orelse return;
            defer p.deinit();
            break :blk stt.sync.importUpdate(s.gpa, &p, bytes) catch |err| {
                std.log.err("speech: adapter update {s}: {t}", .{ ver, err });
                return;
            };
        };
        std.log.info("speech: personal adapter v{d} (stt-adapter {s})", .{ v, ver });
        if (s.local) |l| setAdapterVersion(s, l.adapterVersion());
    } else {
        // A raw adapter: its version is the package's version number.
        const v = std.fmt.parseInt(u32, ver, 10) catch {
            std.log.err("speech: stt-adapter {s}: a raw adapter needs a numeric package version", .{ver});
            return;
        };
        @memcpy(s.raw_adapter_buf[0..file.len], file);
        s.raw_adapter_len = file.len;
        s.raw_adapter_version = v;
        if (s.local) |l| s.reload_pending = l.adapterVersion() < v;
        std.log.info("speech: personal adapter v{d} for the next load", .{v});
    }
    @memcpy(s.applied_buf[0..dir.len], dir);
    s.applied_len = dir.len;
    if (s.reload_pending and !busy) unload(s);
}

/// update.bin (an stt update) or adapter.bin in a package folder.
fn adapterFile(io: std.Io, dir: []const u8, buf: []u8) ?[]const u8 {
    for ([_][]const u8{ "update.bin", "adapter.bin" }) |name| {
        const p = std.fmt.bufPrint(buf, "{s}/{s}", .{ dir, name }) catch return null;
        std.Io.Dir.cwd().access(io, p, .{}) catch continue;
        return p;
    }
    return null;
}

fn setAdapterVersion(s: *State, v: u32) void {
    s.mutex.lockUncancelable(s.io);
    s.adapter_version = v;
    s.mutex.unlock(s.io);
    ios.postEvent(.expose);
}

/// Worker: stt.Local (model + Core ML), if not open yet.
fn load(s: *State) void {
    if (s.local != null) return;
    s.mutex.lockUncancelable(s.io);
    s.loading = true;
    s.status_len = 0;
    const learning = s.learning;
    s.mutex.unlock(s.io);
    ios.postEvent(.expose);
    defer {
        s.mutex.lockUncancelable(s.io);
        s.loading = false;
        s.mutex.unlock(s.io);
        ios.postEvent(.expose);
    }
    const pool = objc.AutoreleasePool.push();
    defer pool.pop();
    var mb: [1024]u8 = undefined;
    const model = std.fmt.bufPrint(&mb, "{s}/" ++ model_name, .{resourceDir()}) catch return fail(s, "Speech model path too long", .{});
    var cb: [1024]u8 = undefined;
    const cache = std.fmt.bufPrint(&cb, "{s}/stt-coreml", .{cachesDir()}) catch return fail(s, "Cache path too long", .{});
    protect(s.io, cache);
    var pb: [1024]u8 = undefined;
    const profile = profileDir(s.io, &pb) orelse return fail(s, "No place for the speech profile", .{});
    const raw = s.raw_adapter_buf[0..s.raw_adapter_len];
    const l = stt.Local.open(s.gpa, s.io, .{
        .model_path = model,
        .profile_dir = profile,
        .adapter_path = if (raw.len > 0) raw else null,
        .adapter_version = s.raw_adapter_version,
        .backend = .coreml,
        .coreml = .{ .cache_dir = cache, .compute_units = .cpu_and_neural_engine },
        .device_name = device_name,
        .service = .{ .max_seconds = speech_mod.limits.max_seconds, .feedback_window = speech_mod.limits.max_pending_ids },
    }) catch |err| return fail(s, "Speech could not start on this iPhone ({t})", .{err});
    l.setLearning(learning) catch {};
    s.local = l;
    s.reload_pending = false;
    setAdapterVersion(s, l.adapterVersion());
}

fn unload(s: *State) void {
    // Close confirms what is pending (silence = correct).
    if (s.local) |l| l.close();
    s.local = null;
    s.reload_pending = false;
}

fn fail(s: *State, comptime fmt: []const u8, args: anytype) void {
    s.mutex.lockUncancelable(s.io);
    defer s.mutex.unlock(s.io);
    const t = std.fmt.bufPrint(&s.status_buf, fmt, args) catch s.status_buf[0..0];
    s.status_len = t.len;
    std.log.err("dictation: {s}", .{t});
}

// Foundation.
extern fn NSSearchPathForDirectoriesInDomains(directory: objc.NSUInteger, domains: objc.NSUInteger, expand: objc.BOOL) ?*Object;
extern const NSFileProtectionKey: ?*Object;
extern const NSFileProtectionComplete: ?*Object;
const ns_caches_directory: objc.NSUInteger = 13;
const ns_user_domain_mask: objc.NSUInteger = 1;

/// Library/Caches (the system may empty it; the Core ML programs are
/// rebuilt then). Valid until the caller's autorelease pool drains.
fn cachesDir() []const u8 {
    const list = NSSearchPathForDirectoriesInDomains(ns_caches_directory, ns_user_domain_mask, objc.YES) orelse return "/tmp";
    if (msgSend(objc.NSUInteger, list, sel("count"), .{}) == 0) return "/tmp";
    return objc.stringBytes(msgSend(?*Object, list, sel("objectAtIndex:"), .{@as(objc.NSUInteger, 0)}));
}

/// Portal.app's resource folder (the bundle's root on iOS).
fn resourceDir() []const u8 {
    const b = msgSend(?*Object, objc.getClass("NSBundle"), sel("mainBundle"), .{});
    return objc.stringBytes(msgSend(?*Object, b, sel("resourcePath"), .{}));
}

/// The stt profile: Library/Application Support/Portal/stt-local (HOME is
/// the app container), created and protected.
fn profileDir(io: std.Io, buf: []u8) ?[]const u8 {
    const home = std.c.getenv("HOME") orelse return null;
    const p = std.fmt.bufPrint(buf, "{s}/Library/Application Support/Portal/stt-local", .{std.mem.span(home)}) catch return null;
    protect(io, p);
    return p;
}

/// Creates `dir` and gives it iOS file protection Complete; files created
/// in it afterwards inherit the class.
fn protect(io: std.Io, dir: []const u8) void {
    std.Io.Dir.cwd().createDirPath(io, dir) catch return;
    const pool = objc.AutoreleasePool.push();
    defer pool.pop();
    const path = objc.newString(dir) orelse return;
    defer objc.release(path);
    const attrs = msgSend(?*Object, objc.getClass("NSDictionary"), sel("dictionaryWithObject:forKey:"), .{ NSFileProtectionComplete, NSFileProtectionKey }) orelse return;
    const fm = msgSend(?*Object, objc.getClass("NSFileManager"), sel("defaultManager"), .{});
    var err: ?*Object = null;
    if (msgSend(objc.BOOL, fm, sel("setAttributes:ofItemAtPath:error:"), .{ attrs, path, &err }) == 0)
        std.log.warn("speech: no file protection on {s}", .{dir});
}
