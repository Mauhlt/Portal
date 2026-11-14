//! End-to-end tests of the desktop speech path that need ../SpeechToText's
//! test recording and model and an NVIDIA GPU (skipped otherwise): a fake
//! microphone records testdata/hello.wav's samples, the engine
//! transcribes them through stt.Home, feedback goes back.

const std = @import("std");
const Audio = @import("Audio");
const options = @import("speech_options");
const sys = @import("sys.zig");
const mics = @import("mics.zig");
const capture = @import("capture.zig");
const home = @import("home.zig");

const testing = std.testing;

/// hello.wav as 16 kHz mono s16 samples (it is recorded that way).
fn helloSamples(gpa: std.mem.Allocator) ![]i16 {
    const path = try std.fs.path.join(gpa, &.{ options.stt_dir, "testdata", "hello.wav" });
    defer gpa.free(path);
    const bytes = std.Io.Dir.cwd().readFileAlloc(testing.io, path, gpa, .limited(16 << 20)) catch return error.SkipZigTest;
    defer gpa.free(bytes);
    const a = try Audio.decodeAny(gpa, bytes);
    defer a.deinit(gpa);
    try testing.expectEqual(@as(u32, capture.sample_rate), a.sample_rate);
    try testing.expectEqual(@as(u16, 1), a.channels);
    const c = try a.convert(.i16, gpa);
    return c.samples.i16;
}

test "wavBytes: ../Audio's WAV of the samples decodes back to them" {
    const gpa = testing.allocator;
    const pcm = [_]i16{ 0, 1, -1, 32767, -32768, 1234 };
    const wav = try home.wavBytes(gpa, &pcm);
    defer gpa.free(wav);
    const a = try Audio.decodeAny(gpa, wav);
    defer a.deinit(gpa);
    try testing.expectEqual(@as(u32, 16000), a.sample_rate);
    try testing.expectEqualSlices(i16, &pcm, a.samples.i16);
}

const Waker = struct {
    ev: sys.HANDLE,
    fn notify(ctx: *anyopaque) void {
        const w: *Waker = @ptrCast(@alignCast(ctx));
        _ = sys.SetEvent(w.ev);
    }
    /// Sleeps until a notification or the deadline (awake ms); false once
    /// the deadline has passed.
    fn wait(w: *Waker, end: i64) bool {
        const ms = sys.msUntil(end, nowMs());
        if (ms == 0) return false;
        _ = sys.WaitForSingleObject(w.ev, ms);
        return true;
    }
};

fn nowMs() i64 {
    return std.Io.Clock.awake.now(testing.io).toMilliseconds();
}

test "gpu: a fake microphone's recording of hello.wav, transcribed by stt.Home, with feedback" {
    const gpa = testing.allocator;
    const samples = try helloSamples(gpa);
    defer gpa.free(samples);
    const model = try std.fs.path.join(gpa, &.{ options.stt_dir, "models", "ggml-tiny.en.bin" });
    defer gpa.free(model);
    std.Io.Dir.cwd().access(testing.io, model, .{}) catch return error.SkipZigTest;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [1024]u8 = undefined;
    const profile = pbuf[0..try tmp.dir.realPath(testing.io, &pbuf)];

    var waker: Waker = .{ .ev = try sys.autoEvent() };
    defer _ = sys.CloseHandle(waker.ev);

    // The microphone: a fake endpoint fed the recording in 10 ms packets.
    var l: mics.List = .{};
    l.append(mics.testEndpoint("{fake}", "Test headset", .headset, .usb));
    var fake: capture.Fake = .{ .gpa = gpa, .list = l };
    defer fake.deinit();
    var mic: capture.Mic = .{ .gpa = gpa, .backend = fake.backend(), .notify_ctx = &waker, .notify_fn = Waker.notify };
    try mic.start();
    defer mic.deinit();
    _ = mic.startRecording();
    var end = nowMs() + 5000;
    while (true) {
        var s: capture.Snapshot = .{};
        mic.snapshot(&s);
        if (s.capturing) break;
        if (!waker.wait(end)) return error.TestTimeout;
    }
    var i: usize = 0;
    while (i < samples.len) : (i += 160) fake.feed(samples[i..@min(i + 160, samples.len)]);
    mic.stopRecording();
    end = nowMs() + 5000;
    const rec = while (true) {
        if (mic.takeRecording()) |r| break r;
        if (!waker.wait(end)) return error.TestTimeout;
    };
    try testing.expectEqual(samples.len, rec.samples.len);

    // The engine: Home opens on its thread, then transcribes.
    const e = try home.Engine.create(gpa, testing.io, .{ .model_path = model, .profile_dir = profile });
    defer e.destroy();
    e.notify_ctx = &waker;
    e.notify_fn = Waker.notify;
    try e.start();
    try e.transcribe(.dictation, rec.samples);
    end = nowMs() + 60_000;
    const r = while (true) {
        if (e.takeResult()) |r| break r;
        const st = e.getStatus();
        if (st.state == .failed) {
            // No NVIDIA GPU here: nothing to test.
            if (std.mem.indexOf(u8, st.why(), "GPU") != null) return error.SkipZigTest;
            std.debug.print("speech failed: {s}\n", .{st.why()});
            return error.TestUnexpectedResult;
        }
        if (!waker.wait(end)) return error.TestTimeout;
    };
    defer gpa.free(r.text);
    try testing.expect(!r.failed);
    try testing.expect(r.id != 0);
    // testdata/hello.wav: " Hello World. This is a test of speech
    // recognition written in Piersig." (SpeechToText NOTES.md).
    try testing.expect(std.ascii.findIgnoreCase(r.text, "hello") != null);
    try testing.expect(std.ascii.findIgnoreCase(r.text, "speech recognition") != null);

    // Home reported a deadline (the 60 s silence auto-confirm) through the
    // wakeup hook: the waiter sleeps until then, no ticks before it.
    e.lock.lock();
    const deadline = e.deadline;
    const ticks0 = e.ticks;
    e.lock.unlock();
    try testing.expect(deadline != null);
    try testing.expectEqual(@as(u64, 0), ticks0);

    // The user corrected it and sent: feedback(id, corrected, true).
    try e.feedback(r.id, "Hello world. This is a test of speech recognition written in pure Zig.", true);
    end = nowMs() + 10_000;
    while (true) {
        e.lock.lock();
        const w = e.wakeups;
        const busy = e.feedbacks.items.len;
        e.lock.unlock();
        // The feedback moved the deadline (nothing pending: null) → a wakeup.
        if (busy == 0 and w >= 3) break;
        if (!waker.wait(end)) return error.TestTimeout;
    }
    // A learned fix: the profile has its phrase rule.
    const rules_path = try std.fs.path.join(gpa, &.{ profile, "rules.txt" });
    defer gpa.free(rules_path);
    const rules = std.Io.Dir.cwd().readFileAlloc(testing.io, rules_path, gpa, .limited(1 << 20)) catch "";
    defer if (rules.len > 0) gpa.free(rules);
    try testing.expect(std.ascii.findIgnoreCase(rules, "pure zig") != null);
}
