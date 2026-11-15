//! Leading and trailing silence off a clip before it is transcribed (stt
//! has no voice-activity helper of its own): less audio for the encoder to
//! chew on, and a training sample without the dead air around the words.
//! Energy per 20 ms frame against the clip's own loudest frame, so a quiet
//! microphone is not cut away; 200 ms of margin is kept on each side so no
//! word loses its edges. Pure: 16 kHz mono, f32 (as stt.Local takes it,
//! the iPhone) or s16 (as WASAPI records it and stt-local takes it, the
//! laptop).

const std = @import("std");

pub const sample_rate = 16_000;
const frame = sample_rate / 50; // 20 ms
const margin = sample_rate / 5; // 200 ms
/// A frame is voiced above this fraction of the loudest frame's RMS...
const relative = 0.05;
/// ...and above this absolute RMS (full scale = 1.0): digital silence and
/// a hiss-only clip stay unvoiced.
const floor = 0.002;

fn rms(comptime T: type, s: []const T) f32 {
    var e: f32 = 0;
    for (s) |raw| {
        const x: f32 = if (T == i16) @as(f32, @floatFromInt(raw)) / 32768.0 else raw;
        e += x * x;
    }
    return @sqrt(e / @as(f32, @floatFromInt(s.len)));
}

/// The part of `samples` from the first to the last voiced frame, with
/// the margin; the whole clip when it is shorter than a frame; an empty
/// slice when nothing in it is voiced.
pub fn voiced(samples: []const f32) []const f32 {
    return voicedOf(f32, samples);
}

/// `voiced` for s16 samples.
pub fn voiced16(samples: []const i16) []const i16 {
    return voicedOf(i16, samples);
}

fn voicedOf(comptime T: type, samples: []const T) []const T {
    if (samples.len < frame) return samples;
    const n = samples.len / frame;
    var peak: f32 = 0;
    for (0..n) |i| peak = @max(peak, rms(T, samples[i * frame ..][0..frame]));
    const threshold = @max(peak * relative, floor);
    var first: ?usize = null;
    var last: usize = 0;
    for (0..n) |i| if (rms(T, samples[i * frame ..][0..frame]) > threshold) {
        if (first == null) first = i;
        last = i;
    };
    const f = first orelse return samples[0..0];
    const start = (f * frame) -| margin;
    const end = @min(samples.len, (last + 1) * frame + margin);
    return samples[start..end];
}

const testing = std.testing;

test "silence around a tone is cut, with the margin kept" {
    var buf: [sample_rate * 3]f32 = @splat(0);
    // A tone from 1.0 s to 2.0 s, a little hiss everywhere.
    for (&buf, 0..) |*x, i| {
        x.* = if (i % 7 == 0) 0.0005 else -0.0005;
        if (i >= sample_rate and i < 2 * sample_rate) x.* += 0.3 * @sin(@as(f32, @floatFromInt(i)) * 0.2);
    }
    const v = voiced(&buf);
    const start = @intFromPtr(v.ptr) - @intFromPtr(&buf);
    try testing.expectEqual(@as(usize, (sample_rate - margin) * @sizeOf(f32)), start);
    try testing.expectEqual(@as(usize, sample_rate + 2 * margin), v.len);
}

test "all quiet: nothing voiced; a quiet microphone is kept; short clips untouched" {
    var silent: [sample_rate]f32 = @splat(0);
    try testing.expectEqual(@as(usize, 0), voiced(&silent).len);
    var quiet: [sample_rate]f32 = undefined;
    for (&quiet, 0..) |*x, i| x.* = 0.01 * @sin(@as(f32, @floatFromInt(i)) * 0.3);
    try testing.expectEqual(quiet.len, voiced(&quiet).len);
    const short = [_]f32{ 0, 0, 0 };
    try testing.expectEqual(@as(usize, 3), voiced(&short).len);
}

test "s16 clips are cut the same way" {
    var buf: [sample_rate * 3]i16 = @splat(0);
    for (&buf, 0..) |*x, i| {
        if (i >= sample_rate and i < 2 * sample_rate) x.* = @intFromFloat(9000 * @sin(@as(f32, @floatFromInt(i)) * 0.2));
    }
    const v = voiced16(&buf);
    try testing.expectEqual(@as(usize, (sample_rate - margin) * @sizeOf(i16)), @intFromPtr(v.ptr) - @intFromPtr(&buf));
    try testing.expectEqual(@as(usize, sample_rate + 2 * margin), v.len);
    try testing.expectEqual(@as(usize, 0), voiced16(buf[0..sample_rate]).len);
}
