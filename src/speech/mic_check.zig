//! `zig build mic-check [-- <seconds> [model]]`: a manual check of the
//! real microphone path, outside the window: lists the capture endpoints
//! (WASAPI), says which one Automatic picks, records <seconds> (default 3)
//! from it, prints the peak level and the transcript from stt.Home.
//! Not part of `zig build test` (it opens the real microphone).

const std = @import("std");
const speech = @import("speech");
const options = @import("speech_options");

const sys = speech.sys;
const capture = speech.capture;

const Waker = struct {
    ev: sys.HANDLE,
    fn notify(ctx: *anyopaque) void {
        const w: *Waker = @ptrCast(@alignCast(ctx));
        _ = sys.SetEvent(w.ev);
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer args.deinit();
    _ = args.next();
    const seconds: u32 = if (args.next()) |a| std.fmt.parseInt(u32, a, 10) catch 3 else 3;
    const model_arg = args.next();

    var w: Waker = .{ .ev = try sys.autoEvent() };
    defer _ = sys.CloseHandle(w.ev);
    var wb: speech.wasapi.Wasapi = .{};
    var mic: capture.Mic = .{ .gpa = gpa, .backend = wb.backend(), .notify_ctx = &w, .notify_fn = Waker.notify };
    try mic.start();
    defer mic.deinit();
    var s: capture.Snapshot = .{};
    // The device list comes with the thread's first notification (10 s
    // at most, a real deadline).
    const list_end = std.Io.Clock.awake.now(io).toMilliseconds() + 10_000;
    while (true) {
        mic.snapshot(&s);
        if (s.list_gen > 0 or s.err().len > 0) break;
        const ms = sys.msUntil(list_end, std.Io.Clock.awake.now(io).toMilliseconds());
        if (ms == 0) break;
        _ = sys.WaitForSingleObject(w.ev, ms);
    }
    std.debug.print("capture endpoints ({d}):\n", .{s.list.len});
    for (s.list.slice(), 0..) |*e, i| {
        var tb: [64]u8 = undefined;
        std.debug.print("  {s} {s}  [{s}]{s}{s}\n", .{
            if (s.active == i) "*" else " ",
            e.name.get(),
            e.typeLabel(&tb),
            if (e.default_comms) " default-communications" else "",
            if (e.default_console) " default-console" else "",
        });
    }
    if (s.err().len > 0) std.debug.print("error: {s}\n", .{s.err()});
    if (s.active == null) return;

    std.debug.print("recording {d} s from the endpoint marked * ...\n", .{seconds});
    _ = mic.startRecording();
    // Wait out the seconds (a real deadline), then stop.
    const end = std.Io.Clock.awake.now(io).toMilliseconds() + @as(i64, seconds) * 1000;
    while (true) {
        const now = std.Io.Clock.awake.now(io).toMilliseconds();
        if (now >= end) break;
        _ = sys.WaitForSingleObject(w.ev, sys.msUntil(end, now));
    }
    mic.snapshot(&s);
    if (s.err().len > 0) std.debug.print("error: {s}\n", .{s.err()});
    mic.stopRecording();
    const rec_end = std.Io.Clock.awake.now(io).toMilliseconds() + 5_000;
    const rec = while (true) {
        if (mic.takeRecording()) |rr| break rr;
        const ms = sys.msUntil(rec_end, std.Io.Clock.awake.now(io).toMilliseconds());
        if (ms == 0) return error.Timeout;
        _ = sys.WaitForSingleObject(w.ev, ms);
    };
    std.debug.print("recorded {d} samples ({d:.2} s), peak level {d:.2}\n", .{ rec.samples.len, @as(f32, @floatFromInt(rec.samples.len)) / capture.sample_rate, capture.peakLevel(rec.samples) });
    if (!speech.has_home) {
        gpa.free(rec.samples);
        return;
    }
    const arena = init.arena.allocator();
    const model = model_arg orelse try std.fs.path.join(arena, &.{ options.stt_dir, "models", "ggml-base.en.bin" });
    // A throwaway profile under the system temp folder.
    const tmp = init.environ_map.get("TEMP") orelse ".";
    const prof = try std.fs.path.join(arena, &.{ tmp, "portal-mic-check-stt" });
    const e = try speech.home.Engine.create(gpa, io, .{ .model_path = model, .profile_dir = prof });
    defer e.destroy();
    e.notify_ctx = &w;
    e.notify_fn = Waker.notify;
    try e.start();
    try e.transcribe(.test_clip, rec.samples);
    while (true) {
        if (e.takeResult()) |r| {
            std.debug.print("transcript (id {d}{s}): \"{s}\"\n", .{ r.id, if (r.failed) ", FAILED" else "", r.text });
            gpa.free(r.text);
            break;
        }
        const st = e.getStatus();
        if (st.state == .failed) {
            std.debug.print("speech failed: {s}\n", .{st.why()});
            break;
        }
        _ = sys.WaitForSingleObject(w.ev, sys.INFINITE);
    }
}
