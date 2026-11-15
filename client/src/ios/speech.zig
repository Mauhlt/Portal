//! Dictation on the iPhone itself: the shared input line's 🎤
//! (connect.Platform.speech -> ui/shell.zig Dictation, the same hooks the
//! desk's engine fills) recording with mic.zig and transcribing with stt's
//! Core ML engine (stt.Transcriber, backend .coreml) on the bundled
//! base.en model. Audio never leaves the phone.
//!
//!   app thread   start / stop / cancel (the shell's 🎤) and `frame`
//!                (each frame: the transcript into the line, the 🎤's
//!                state); never blocks on stt.
//!   worker       one thread, asleep on an Io.Condition until there is
//!                work: loads the model and builds the Core ML programs
//!                (cached in Library/Caches/stt-coreml; the first time
//!                takes seconds, later loads are fast), transcribes, and
//!                wakes the window with the result. Never the UIKit main
//!                thread.
//!
//! Recording starts the model loading in parallel (`warm`), so it is
//! usually ready when the user stops. Off screen (onSuspend) a recording
//! is stopped and dropped, a pending result is dropped, and the model and
//! the transcriber are released: iOS reclaims memory from background
//! apps, and the compiled programs reload from Caches next time.

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

const State = struct {
    io: std.Io = undefined,
    gpa: std.mem.Allocator = std.heap.c_allocator,

    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    // ---- under `mutex`: work for the worker
    warm: bool = false,
    release: bool = false,
    clip: ?[]f32 = null,
    /// Bumped by cancel / suspend: a result for an older one is dropped.
    gen: u64 = 0,
    clip_gen: u64 = 0,
    busy: bool = false,
    // ---- under `mutex`: what the worker reports
    result: ?[]u8 = null,
    result_failed: bool = false,
    ready: bool = false,
    loading: bool = false,
    status_buf: [160]u8 = undefined,
    status_len: usize = 0,

    // ---- app thread only
    thread: ?std.Thread = null,
    recording: bool = false,
    /// Why the last start or transcription failed ("" if not).
    note_buf: [160]u8 = undefined,
    note_len: usize = 0,
    mic_buf: [128]u8 = undefined,
    /// The worker's status, copied for the shell (it keeps the slice).
    status_ui_buf: [160]u8 = undefined,

    // ---- worker only
    model: ?stt.Model = null,
    tr: ?stt.Transcriber = null,
};

var state: State = .{};

pub fn init(io: std.Io) void {
    state.io = io;
    mic.init(io, state.gpa);
}

pub fn hooks() connect.Speech {
    return .{
        .dictation = .{ .ctx = &state, .start = onStart, .stop = onStop, .cancel = onCancel },
        .frame = frame,
    };
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
    if (s.result) |r| s.gpa.free(r);
    s.result = null;
}

/// UI thread (device.onSuspend): off screen. The recording stops and is
/// dropped, and the worker releases the engine.
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
    const status = s.status_ui_buf[0..s.status_len];
    @memcpy(status, s.status_buf[0..s.status_len]);
    s.mutex.unlock(s.io);
    if (result) |r| {
        defer s.gpa.free(r);
        if (failed) setNote(s, r) else if (!sh.dictated(r) and r.len > 0) setNote(s, "The transcript did not fit in the line.");
    }
    sh.mic_label = if (s.recording) mic.inputName(&s.mic_buf) else "";
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

// ------------------------------------------------------------ worker

fn worker(s: *State) void {
    while (true) {
        s.mutex.lockUncancelable(s.io);
        while (!s.warm and !s.release and s.clip == null) s.cond.waitUncancelable(s.io, &s.mutex);
        const release = s.release;
        s.release = false;
        const clip = s.clip;
        s.clip = null;
        const gen = s.clip_gen;
        s.mutex.unlock(s.io);

        if (release and clip == null) {
            unload(s);
            continue;
        }
        load(s);
        const c = clip orelse {
            s.mutex.lockUncancelable(s.io);
            s.warm = false;
            s.mutex.unlock(s.io);
            continue;
        };
        defer s.gpa.free(c);
        var failed = false;
        const text: []u8 = if (s.tr) |*tr| tr.transcribe(s.gpa, c) catch |err| blk: {
            failed = true;
            break :blk std.fmt.allocPrint(s.gpa, "Transcription failed: {t}", .{err}) catch &.{};
        } else blk: {
            failed = true;
            break :blk s.gpa.dupe(u8, s.status_buf[0..s.status_len]) catch &.{};
        };
        s.mutex.lockUncancelable(s.io);
        if (gen == s.gen) {
            if (s.result) |old| s.gpa.free(old);
            s.result = text;
            s.result_failed = failed;
            s.busy = false;
        } else s.gpa.free(text);
        s.mutex.unlock(s.io);
        ios.postEvent(.expose);
    }
}

/// Worker: the model and the Core ML transcriber, if not loaded yet.
fn load(s: *State) void {
    if (s.tr != null) return;
    s.mutex.lockUncancelable(s.io);
    s.loading = true;
    s.status_len = 0;
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
    var pb: [1024]u8 = undefined;
    const path = std.fmt.bufPrint(&pb, "{s}/" ++ model_name, .{resourceDir()}) catch return fail(s, "Speech model path too long", .{});
    if (s.model == null) s.model = stt.Model.load(s.gpa, s.io, path) catch |err| return fail(s, "The speech model could not be loaded ({t})", .{err});
    var cb: [1024]u8 = undefined;
    const cache = std.fmt.bufPrint(&cb, "{s}/stt-coreml", .{cachesDir()}) catch return fail(s, "Cache path too long", .{});
    s.tr = stt.Transcriber.init(s.gpa, &s.model.?, .{ .backend = .{ .coreml = .{ .cache_dir = cache, .compute_units = .cpu_and_neural_engine } } }) catch |err|
        return fail(s, "Speech could not start on this iPhone ({t})", .{err});
}

fn unload(s: *State) void {
    if (s.tr) |*tr| tr.deinit();
    s.tr = null;
    if (s.model) |*m| m.deinit();
    s.model = null;
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
