//! Speech input's limits (owner requirement, 2026-11-14: nothing can be
//! abused by too-long clips, rapid-fire clips or a flood of submissions),
//! in one place:
//!
//!   max_seconds            120 s per utterance (stt-local's too_long):
//!                          capture stops there; the capture buffer is
//!                          allocated once at that size and never grows
//!   min_ms                 250 ms: shorter clips are dropped, no stt call
//!   in flight              one transcription at a time; another request
//!                          while one runs or waits is refused (Busy)
//!   rate                   at most 10 transcriptions a minute (a token
//!                          bucket: burst 10, one back every 6 s); refusals
//!                          say when the next is allowed (a deadline, not
//!                          a poll)
//!   long windows           on top of the per-minute buckets, rolling caps
//!                          per source: transcriptions 300 an hour and
//!                          2000 a day; feedback 120 an hour and 1000 a
//!                          day. Counted in fixed slots (60 one-minute
//!                          slots for the hour, 24 one-hour slots for the
//!                          day; no timestamp per event), so the day's
//!                          window is exact to the hour. A refusal names
//!                          the limit hit and when it frees up.
//!   job_timeout_ms         60 s: a transcription not back by then is
//!                          given up (its result is dropped and
//!                          discarded); stt has no cancel yet, so the GPU
//!                          finishes it, but nothing else is queued
//!   max_text               8 KiB of transcript, feedback or correction
//!                          text (cut at a UTF-8 boundary / refused)
//!   max_feedback_jobs      16 queued feedback calls (the oldest dropped)
//!   feedback rate          corrections / discards: burst 5, one back every
//!                          6 s (about 10 a minute), per source: the desk's
//!                          own UI has one bucket (home.Engine), each paired
//!                          device another (DeviceBuckets, keyed on the
//!                          session's device name, kept for the life of
//!                          the process so re-pairing or reconnecting
//!                          doesn't reset it). Over the limit: refused,
//!                          never queued. Feedback for an id that isn't
//!                          waiting is refused cheaply and still counts.
//!   max_wav_bytes          the WAV handed to stt: header + 120 s of 16 kHz
//!                          mono s16; its header is checked (rate,
//!                          channels, bits, length) before stt decodes it
//!
//!   kept clips             at most 500 clips a rolling day become stt
//!                          training samples (per source); past that a
//!                          clip is still transcribed but Portal discards
//!                          it in stt at once (feedback(id, _, false)), and
//!                          the UI says so once
//!   bundles (future)       per device a rolling day: 50 training bundles,
//!                          100 MiB in all, each at most 5 MiB
//!
//! Every value above is a field of `Config` (defaults = these numbers),
//! loaded from the desk's settings.txt (`speech.<name> = <n>`, edited only
//! at the desk) and clamped to `Config.ranges`: never zero, and never
//! above what keeps memory bounded (the capture buffer is allocated once
//! for the 120 s ceiling, text buffers for 8 KiB, the feedback queue for
//! 64). Changes apply live (home.Engine.setLimits, capture.Mic.setLimits).
//!
//! Desk-local only: no device sends audio (there is no /stt/transcribe,
//! docs/stt-sync-contract.md).

const std = @import("std");
const Audio = @import("Audio");

pub const sample_rate = 16_000;
pub const max_seconds = 120;
pub const max_samples = sample_rate * max_seconds;
pub const min_ms = 250;
pub const min_samples = sample_rate * min_ms / 1000;
pub const rate_burst = 10;
/// One transcription comes back every this many ms (10 a minute).
pub const rate_refill_ms: i64 = 6_000;
pub const job_timeout_ms: i64 = 60_000;
pub const max_text = 8 * 1024;
/// Rolling caps per source, on top of the per-minute bucket.
pub const transcribe_per_hour = 300;
pub const transcribe_per_day = 2000;
pub const feedback_per_hour = 120;
pub const feedback_per_day = 1000;
/// Feedback (corrections, discards): burst and refill, per source.
pub const feedback_burst = 5;
pub const feedback_refill_ms: i64 = 6_000;
/// Transcript ids that can still get feedback (stt's own window is 64).
pub const max_pending_ids = 64;
/// Paired devices (src/devices.zig max_devices): the size of the
/// per-device feedback table.
pub const max_devices = 16;
pub const max_device_name = 64;
pub const max_feedback_jobs = 16;
/// The feedback queue's reserved capacity (Config.feedback_queue's ceiling).
pub const feedback_queue_ceiling = 64;
pub const job_timeout_s = 60;
pub const kept_clips_per_day = 500;
pub const bundles_per_day = 50;
pub const bundle_mib_per_day = 100;
pub const bundle_max_kib = 5 * 1024;
/// Desktop-wide, over all devices (gate.zig): devices doing speech
/// traffic at once (the desk's own mic never counts), and totals.
pub const concurrent_devices = 3;
pub const global_feedback_per_hour = 300;
pub const global_kept_clips_per_day = 1000;
pub const global_bundles_per_day = 100;
pub const global_bundle_mib_per_day = 250;
/// All device speech payloads in flight together (MiB), each request's
/// body read deadline, and malformed-data strikes before a device's
/// speech traffic is closed until it reconnects.
pub const payload_budget_mib = 16;
pub const read_timeout_s = 30;
pub const malformed_strikes = 3;
pub const malformed_window_min = 10;
/// A device's hold on one of the concurrent speech slots: at most this
/// long, released early after this long without speech traffic, and after
/// an expiry not taken again by the same device for this long while
/// another device is waiting (seconds).
pub const slot_max_hold_s = 300;
pub const slot_idle_s = 60;
pub const slot_cooldown_s = 30;
/// RIFF/fmt/data headers are 44 bytes for what Portal writes; a little room.
pub const max_wav_bytes = max_samples * 2 + 128;

/// A token bucket in whole tokens: `burst` at most, one more every
/// `refill_ms`. Pure (callers pass monotonic ms).
pub const Bucket = struct {
    burst: u32 = rate_burst,
    refill_ms: i64 = rate_refill_ms,
    tokens: u32 = rate_burst,
    /// When the next token is added (null: full).
    next_ms: ?i64 = null,

    fn refill(b: *Bucket, now: i64) void {
        while (b.next_ms) |t| {
            if (now < t) return;
            b.tokens += 1;
            b.next_ms = if (b.tokens >= b.burst) null else t + b.refill_ms;
        }
    }

    /// Takes a token if there is one.
    pub fn take(b: *Bucket, now: i64) bool {
        b.refill(now);
        if (b.tokens == 0) return false;
        b.tokens -= 1;
        if (b.next_ms == null) b.next_ms = now + b.refill_ms;
        return true;
    }

    /// When a token is next available (now if there is one).
    pub fn nextAllowed(b: *Bucket, now: i64) i64 {
        b.refill(now);
        if (b.tokens > 0) return now;
        return b.next_ms.?;
    }
};

/// A rolling count over the last `n` slots of `slot_ms` each, in fixed
/// memory (one counter per slot, no timestamp per event). Pure: callers
/// pass monotonic ms; old slots are cleared as time is seen to pass.
pub fn Rolling(comptime n: usize, comptime slot_ms: i64) type {
    return RollingOf(u32, n, slot_ms);
}

/// `Rolling` with a counter type (u64 for byte totals).
pub fn RollingOf(comptime T: type, comptime n: usize, comptime slot_ms: i64) type {
    return struct {
        const Self = @This();
        slots: [n]T = @splat(0),
        /// The absolute slot number (ms / slot_ms) of the newest slot.
        newest: ?i64 = null,

        fn advance(r: *Self, now: i64) i64 {
            const cur = @divFloor(now, slot_ms);
            if (r.newest) |old| {
                if (cur > old) {
                    const gap: usize = @intCast(@min(cur - old, n));
                    var k: usize = 0;
                    while (k < gap) : (k += 1) r.slots[@intCast(@mod(cur - @as(i64, @intCast(k)), n))] = 0;
                    r.newest = cur;
                }
                // A clock that went back counts into the newest slot.
            } else r.newest = cur;
            return r.newest.?;
        }

        pub fn sum(r: *Self, now: i64) T {
            _ = r.advance(now);
            var t: T = 0;
            for (r.slots) |c| t += c;
            return t;
        }

        /// The count of the newest `k` slots (k <= n).
        pub fn sumLast(r: *Self, now: i64, k: usize) T {
            const cur = r.advance(now);
            var t: T = 0;
            var i: usize = 0;
            while (i < @min(k, n)) : (i += 1) t += r.slots[@intCast(@mod(cur - @as(i64, @intCast(i)), n))];
            return t;
        }

        pub fn add(r: *Self, now: i64) void {
            r.addN(now, 1);
        }

        pub fn addN(r: *Self, now: i64, k: T) void {
            const cur = r.advance(now);
            r.slots[@intCast(@mod(cur, n))] += k;
        }

        /// When the count falls below `cap` again (now if it is below).
        pub fn freeAt(r: *Self, now: i64, cap: T) i64 {
            var t = r.sum(now);
            if (t < cap) return now;
            const cur = r.newest.?;
            var a = cur - @as(i64, n) + 1;
            while (a <= cur) : (a += 1) {
                t -= r.slots[@intCast(@mod(a, n))];
                if (t < cap) return (a + @as(i64, n)) * slot_ms;
            }
            return (cur + @as(i64, n)) * slot_ms;
        }
    };
}

pub const Limit = enum {
    per_minute,
    per_hour,
    per_day,
    bundle_size,
    bundle_bytes_per_day,
    global_per_hour,
    global_per_day,
    global_bytes_per_day,
    kept_per_day,

    pub fn label(l: Limit) []const u8 {
        return switch (l) {
            .per_minute => "the per-minute limit",
            .per_hour => "the hourly limit",
            .per_day => "the daily limit",
            .bundle_size => "the bundle size limit",
            .bundle_bytes_per_day => "the daily bundle bytes limit",
            .global_per_hour => "the desktop-wide hourly limit",
            .global_per_day => "the desktop-wide daily limit",
            .global_bytes_per_day => "the desktop-wide daily bundle bytes limit",
            .kept_per_day => "the daily limit of clips kept for training",
        };
    }
};

/// Every speech limit, tunable at the desk. Defaults: the constants above.
pub const Config = struct {
    clip_max_s: u32 = max_seconds,
    clip_min_ms: u32 = min_ms,
    transcribe_burst: u32 = rate_burst,
    transcribe_refill_ms: u32 = rate_refill_ms,
    transcribe_per_hour: u32 = transcribe_per_hour,
    transcribe_per_day: u32 = transcribe_per_day,
    job_timeout_s: u32 = job_timeout_s,
    feedback_burst: u32 = feedback_burst,
    feedback_refill_ms: u32 = feedback_refill_ms,
    feedback_per_hour: u32 = feedback_per_hour,
    feedback_per_day: u32 = feedback_per_day,
    text_max: u32 = max_text,
    feedback_queue: u32 = max_feedback_jobs,
    kept_clips_per_day: u32 = kept_clips_per_day,
    bundles_per_day: u32 = bundles_per_day,
    bundle_mib_per_day: u32 = bundle_mib_per_day,
    bundle_max_kib: u32 = bundle_max_kib,
    concurrent_devices: u32 = concurrent_devices,
    global_feedback_per_hour: u32 = global_feedback_per_hour,
    global_kept_clips_per_day: u32 = global_kept_clips_per_day,
    global_bundles_per_day: u32 = global_bundles_per_day,
    global_bundle_mib_per_day: u32 = global_bundle_mib_per_day,
    payload_budget_mib: u32 = payload_budget_mib,
    read_timeout_s: u32 = read_timeout_s,
    malformed_strikes: u32 = malformed_strikes,
    malformed_window_min: u32 = malformed_window_min,
    slot_max_hold_s: u32 = slot_max_hold_s,
    slot_idle_s: u32 = slot_idle_s,
    slot_cooldown_s: u32 = slot_cooldown_s,

    pub const Range = struct { name: []const u8, min: u32, max: u32, doc: []const u8 };

    /// Each field's bounds (and what it means), in field order.
    pub const ranges = [_]Range{
        .{ .name = "clip_max_s", .min = 1, .max = max_seconds, .doc = "longest utterance (s); the capture buffer is sized for the ceiling" },
        .{ .name = "clip_min_ms", .min = 50, .max = 5_000, .doc = "shorter clips are dropped without an stt call (ms)" },
        .{ .name = "transcribe_burst", .min = 1, .max = 100, .doc = "transcriptions at once (token bucket size)" },
        .{ .name = "transcribe_refill_ms", .min = 100, .max = 3_600_000, .doc = "one more transcription allowed every (ms)" },
        .{ .name = "transcribe_per_hour", .min = 1, .max = 100_000, .doc = "transcriptions per rolling hour" },
        .{ .name = "transcribe_per_day", .min = 1, .max = 1_000_000, .doc = "transcriptions per rolling day" },
        .{ .name = "job_timeout_s", .min = 5, .max = 600, .doc = "a transcription not back by then is given up (s)" },
        .{ .name = "feedback_burst", .min = 1, .max = 100, .doc = "corrections at once (token bucket size)" },
        .{ .name = "feedback_refill_ms", .min = 100, .max = 3_600_000, .doc = "one more correction allowed every (ms)" },
        .{ .name = "feedback_per_hour", .min = 1, .max = 100_000, .doc = "corrections per rolling hour" },
        .{ .name = "feedback_per_day", .min = 1, .max = 1_000_000, .doc = "corrections per rolling day" },
        .{ .name = "text_max", .min = 256, .max = max_text, .doc = "transcript / correction text (bytes)" },
        .{ .name = "feedback_queue", .min = 1, .max = feedback_queue_ceiling, .doc = "feedback calls queued (oldest dropped)" },
        .{ .name = "kept_clips_per_day", .min = 1, .max = 100_000, .doc = "clips kept as training samples per rolling day" },
        .{ .name = "bundles_per_day", .min = 1, .max = 10_000, .doc = "training bundles per device per rolling day" },
        .{ .name = "bundle_mib_per_day", .min = 1, .max = 10_240, .doc = "training bundle MiB per device per rolling day" },
        .{ .name = "bundle_max_kib", .min = 64, .max = 5 * 1024, .doc = "one training bundle (KiB; stt-local caps bundles at 5 MiB)" },
        .{ .name = "concurrent_devices", .min = 1, .max = max_devices, .doc = "devices doing speech traffic at once (the desk's mic not counted)" },
        .{ .name = "global_feedback_per_hour", .min = 1, .max = 100_000, .doc = "corrections per rolling hour, all devices together" },
        .{ .name = "global_kept_clips_per_day", .min = 1, .max = 1_000_000, .doc = "clips kept for training per rolling day, all devices" },
        .{ .name = "global_bundles_per_day", .min = 1, .max = 100_000, .doc = "training bundles per rolling day, all devices" },
        .{ .name = "global_bundle_mib_per_day", .min = 1, .max = 102_400, .doc = "training bundle MiB per rolling day, all devices" },
        .{ .name = "payload_budget_mib", .min = 1, .max = 64, .doc = "device speech payloads in flight together (MiB)" },
        .{ .name = "read_timeout_s", .min = 1, .max = 300, .doc = "a request body not read by then is dropped (s)" },
        .{ .name = "malformed_strikes", .min = 1, .max = 100, .doc = "malformed messages that close a device's speech traffic" },
        .{ .name = "malformed_window_min", .min = 1, .max = 60, .doc = "...within this many minutes" },
        .{ .name = "slot_max_hold_s", .min = 10, .max = 3600, .doc = "longest hold on a speech slot (s)" },
        .{ .name = "slot_idle_s", .min = 5, .max = 600, .doc = "a slot without speech traffic this long is released (s)" },
        .{ .name = "slot_cooldown_s", .min = 1, .max = 600, .doc = "after an expiry, the same device waits this long if others want a slot (s)" },
    };

    comptime {
        const fs = std.meta.fieldNames(Config);
        if (fs.len != ranges.len) @compileError("every speech limit needs a range");
        for (fs, ranges) |f, r| if (!std.mem.eql(u8, f, r.name)) @compileError("ranges out of order: " ++ f);
    }

    /// Every field within its range.
    pub fn clamped(c: Config) Config {
        var out = c;
        inline for (comptime std.meta.fieldNames(Config), ranges) |f, r| {
            @field(out, f) = std.math.clamp(@field(out, f), r.min, r.max);
        }
        return out;
    }

    /// `key = text` from the settings (key without "speech."): parsed and
    /// clamped. False if the key is unknown or the text isn't a number.
    pub fn set(c: *Config, key: []const u8, text: []const u8) bool {
        inline for (comptime std.meta.fieldNames(Config), ranges) |f, r| {
            if (std.mem.eql(u8, key, f)) {
                const v = std.fmt.parseInt(i64, std.mem.trim(u8, text, " \t"), 10) catch return false;
                @field(c, f) = @intCast(std.math.clamp(v, r.min, r.max));
                return true;
            }
        }
        return false;
    }

    /// The values that differ from the defaults, as settings lines.
    pub fn format(c: *const Config, out: *std.Io.Writer) !void {
        const d: Config = .{};
        inline for (comptime std.meta.fieldNames(Config)) |f| {
            if (@field(c, f) != @field(d, f)) try out.print("speech.{s} = {d}\r\n", .{ f, @field(c, f) });
        }
    }

    pub fn minSamples(c: Config) usize {
        return @as(usize, c.clip_min_ms) * sample_rate / 1000;
    }
    pub fn maxSamples(c: Config) usize {
        return @as(usize, c.clip_max_s) * sample_rate;
    }
};

pub const Verdict = union(enum) {
    ok,
    /// Refused by `limit`; allowed again at `at` (monotonic ms).
    limited: struct { limit: Limit, at: i64 },
};

/// One source's limits: a token bucket (the per-minute rate) and rolling
/// hour and day caps. A request is counted only if every one allows it.
pub const Limiter = struct {
    bucket: Bucket,
    hour: Rolling(60, 60_000) = .{},
    day: Rolling(24, 3_600_000) = .{},
    per_hour: u32,
    per_day: u32,

    pub fn transcriptions() Limiter {
        return .{ .bucket = .{}, .per_hour = transcribe_per_hour, .per_day = transcribe_per_day };
    }
    pub fn feedback() Limiter {
        return .{
            .bucket = .{ .burst = feedback_burst, .refill_ms = feedback_refill_ms, .tokens = feedback_burst },
            .per_hour = feedback_per_hour,
            .per_day = feedback_per_day,
        };
    }

    /// New values (live): caps, the bucket's size and refill; tokens over
    /// the new size are dropped.
    pub fn apply(l: *Limiter, burst: u32, refill_ms: u32, per_hour: u32, per_day: u32) void {
        l.bucket.burst = burst;
        l.bucket.refill_ms = refill_ms;
        l.bucket.tokens = @min(l.bucket.tokens, burst);
        if (l.bucket.tokens >= burst) l.bucket.next_ms = null;
        l.per_hour = per_hour;
        l.per_day = per_day;
    }

    pub fn applyTranscriptions(l: *Limiter, c: Config) void {
        l.apply(c.transcribe_burst, c.transcribe_refill_ms, c.transcribe_per_hour, c.transcribe_per_day);
    }
    pub fn applyFeedback(l: *Limiter, c: Config) void {
        l.apply(c.feedback_burst, c.feedback_refill_ms, c.feedback_per_hour, c.feedback_per_day);
    }

    /// Checks every limit; counts the request only if all allow it.
    pub fn take(l: *Limiter, now: i64) Verdict {
        if (l.day.sum(now) >= l.per_day) return .{ .limited = .{ .limit = .per_day, .at = l.day.freeAt(now, l.per_day) } };
        if (l.hour.sum(now) >= l.per_hour) return .{ .limited = .{ .limit = .per_hour, .at = l.hour.freeAt(now, l.per_hour) } };
        if (!l.bucket.take(now)) return .{ .limited = .{ .limit = .per_minute, .at = l.bucket.nextAllowed(now) } };
        l.hour.add(now);
        l.day.add(now);
        return .ok;
    }
};

/// A token bucket per paired device, keyed on the device name from the
/// session (never from the request). Entries live for the process, so a
/// reconnect or re-pairing finds its old bucket; the table holds at most
/// max_devices names, and a name beyond that is refused (paired devices
/// are at most that many, so this only happens if something is wrong).
pub const DeviceBuckets = struct {
    names: [max_devices][max_device_name]u8 = undefined,
    lens: [max_devices]u8 = @splat(0),
    limiters: [max_devices]Limiter = undefined,
    /// Training bundles per device (count and bytes, rolling day).
    bundles: [max_devices]Rolling(24, 3_600_000) = undefined,
    bundle_bytes: [max_devices]RollingOf(u64, 24, 3_600_000) = undefined,
    cfg: Config = .{},
    n: usize = 0,

    pub const DeviceVerdict = union(enum) {
        ok,
        /// Over a limit: refused (the caller answers 429 / a WS error
        /// naming the limit, with Retry-After from `at`).
        limited: @FieldType(Verdict, "limited"),
        /// No room for another device name (or an empty / too long one).
        refused,
    };

    /// New limits for every device (live; counts are kept).
    pub fn setLimits(t: *DeviceBuckets, c: Config) void {
        t.cfg = c.clamped();
        for (t.limiters[0..t.n]) |*l| l.applyFeedback(t.cfg);
    }

    /// A correction / discard from `device` (the session's device name).
    pub fn take(t: *DeviceBuckets, device: []const u8, now: i64) DeviceVerdict {
        const i = t.slot(device) orelse return .refused;
        return switch (t.limiters[i].take(now)) {
            .ok => .ok,
            .limited => |l| .{ .limited = l },
        };
    }

    /// A training bundle of `bytes` from `device` (future POST
    /// /sync/bundle): its size, the day's count and the day's bytes.
    pub fn takeBundle(t: *DeviceBuckets, device: []const u8, bytes: u64, now: i64) DeviceVerdict {
        const i = t.slot(device) orelse return .refused;
        const max_one = @as(u64, t.cfg.bundle_max_kib) * 1024;
        if (bytes > max_one) return .{ .limited = .{ .limit = .bundle_size, .at = std.math.maxInt(i64) } };
        if (t.bundles[i].sum(now) >= t.cfg.bundles_per_day) return .{ .limited = .{ .limit = .per_day, .at = t.bundles[i].freeAt(now, t.cfg.bundles_per_day) } };
        const cap = @as(u64, t.cfg.bundle_mib_per_day) * 1024 * 1024;
        if (bytes > cap) return .{ .limited = .{ .limit = .bundle_bytes_per_day, .at = std.math.maxInt(i64) } };
        if (t.bundle_bytes[i].sum(now) + bytes > cap) return .{ .limited = .{ .limit = .bundle_bytes_per_day, .at = t.bundle_bytes[i].freeAt(now, cap - bytes + 1) } };
        t.bundles[i].add(now);
        t.bundle_bytes[i].addN(now, bytes);
        return .ok;
    }

    /// The device's entry (registered on first use); null: no room or a bad name.
    pub fn slot(t: *DeviceBuckets, device: []const u8) ?usize {
        if (device.len == 0 or device.len > max_device_name) return null;
        const i = for (0..t.n) |k| {
            if (std.mem.eql(u8, t.names[k][0..t.lens[k]], device)) break k;
        } else blk: {
            if (t.n == max_devices) return null;
            const k = t.n;
            @memcpy(t.names[k][0..device.len], device);
            t.lens[k] = @intCast(device.len);
            t.limiters[k] = Limiter.feedback();
            t.limiters[k].applyFeedback(t.cfg);
            t.bundles[k] = .{};
            t.bundle_bytes[k] = .{};
            t.n += 1;
            break :blk k;
        };
        return i;
    }
};

/// `s` cut to at most `max` bytes at a UTF-8 boundary.
pub fn capText(s: []const u8, max: usize) []const u8 {
    if (s.len <= max) return s;
    var n = max;
    while (n > 0 and (s[n] & 0xC0) == 0x80) n -= 1;
    return s[0..n];
}

pub const AudioError = error{ AudioTooLarge, AudioTooLong, BadAudio };

/// Checks audio bytes before they reach stt's decoder: the size first,
/// then the header only (Audio.info parses headers, allocating nothing,
/// and clamps a claimed data length to the bytes present): 16 kHz, mono,
/// 16-bit PCM, at most max_seconds.
pub fn checkWav(bytes: []const u8) AudioError!void {
    if (bytes.len > max_wav_bytes) return error.AudioTooLarge;
    const inf = Audio.info(.wav, bytes) catch return error.BadAudio;
    if (inf.sample_rate != sample_rate or inf.channels != 1 or inf.tag != .i16) return error.BadAudio;
    const frames = inf.nSamples() catch return error.BadAudio;
    if (frames > max_samples) return error.AudioTooLong;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "bucket: 10 at once, then one every 6 s; the refusal says when" {
    var b: Bucket = .{};
    for (0..10) |_| try testing.expect(b.take(1000));
    try testing.expect(!b.take(1000));
    try testing.expectEqual(@as(i64, 7000), b.nextAllowed(1000));
    try testing.expect(!b.take(6999));
    try testing.expect(b.take(7000));
    try testing.expect(!b.take(7000));
    try testing.expectEqual(@as(i64, 13000), b.nextAllowed(7000));
    // A long pause refills it to the burst, never beyond.
    for (0..10) |_| try testing.expect(b.take(1_000_000));
    try testing.expect(!b.take(1_000_000));
}

test "device buckets: burst 5, refill every 6 s, per device, a reconnect doesn't reset" {
    var t: DeviceBuckets = .{};
    for (0..feedback_burst) |_| try testing.expect(t.take("laptop", 0) == .ok);
    const v = t.take("laptop", 0);
    try testing.expectEqual(@as(i64, feedback_refill_ms), v.limited.at);
    try testing.expectEqual(Limit.per_minute, v.limited.limit);
    // Another device has its own bucket.
    try testing.expect(t.take("iphone", 0) == .ok);
    // The laptop reconnects (a new session, same device): still limited.
    try testing.expect(t.take("laptop", 100) == .limited);
    try testing.expect(t.take("laptop", feedback_refill_ms) == .ok);
    try testing.expect(t.take("laptop", feedback_refill_ms) == .limited);
    // Bounded: 16 names, then refused; bad names refused.
    var names: [max_devices][8]u8 = undefined;
    for (2..max_devices) |i| {
        const nm = std.fmt.bufPrint(&names[i], "dev{d}", .{i}) catch unreachable;
        try testing.expect(t.take(nm, 0) == .ok);
    }
    try testing.expectEqual(@as(usize, max_devices), t.n);
    try testing.expect(t.take("one-too-many", 0) == .refused);
    try testing.expect(t.take("", 0) == .refused);
}

test "rolling windows: hour and day caps with a fake clock; under the minute limit but over the hour is refused" {
    // Transcriptions: one every 10 s never trips the per-minute bucket
    // (one back every 6 s), but 300 of them fill the hour.
    var l = Limiter.transcriptions();
    var now: i64 = 0;
    for (0..transcribe_per_hour) |_| {
        try testing.expect(l.take(now) == .ok);
        now += 10_000;
    }
    try testing.expect(l.bucket.nextAllowed(now) == now); // the bucket has tokens
    const v = l.take(now);
    try testing.expectEqual(Limit.per_hour, v.limited.limit);
    // The oldest minute's slot leaves the hour first: it frees then.
    try testing.expectEqual(@as(i64, 3_600_000), v.limited.at);
    try testing.expect(l.take(v.limited.at - 1) != .ok);
    try testing.expect(l.take(v.limited.at) == .ok);

    // Feedback: 120 an hour; and 1000 a day spread over hours.
    var f = Limiter.feedback();
    now = 0;
    for (0..feedback_per_hour) |_| {
        try testing.expect(f.take(now) == .ok);
        now += 20_000;
    }
    try testing.expectEqual(Limit.per_hour, f.take(now).limited.limit);
    var d = Limiter.feedback();
    now = 0;
    var taken: u32 = 0;
    while (taken < feedback_per_day) {
        if (d.take(now) == .ok) taken += 1;
        now += 31_000; // under 2 a minute: the hour cap (120) allows all
    }
    const dv = d.take(now);
    try testing.expectEqual(Limit.per_day, dv.limited.limit);
    try testing.expect(dv.limited.at > now and dv.limited.at <= now + 24 * 3_600_000);
    try testing.expect(d.take(dv.limited.at) == .ok);
}

test "rolling: slots clear as time passes, and a refused request counts nothing" {
    var r: Rolling(60, 60_000) = .{};
    r.add(0);
    r.add(59_999);
    r.add(60_000);
    try testing.expectEqual(@as(u32, 3), r.sum(60_000));
    try testing.expectEqual(@as(u32, 1), r.sum(3_600_000)); // the first minute left
    try testing.expectEqual(@as(u32, 0), r.sum(100 * 3_600_000));
    var l = Limiter.feedback();
    for (0..feedback_burst) |_| _ = l.take(0);
    try testing.expect(l.take(0) != .ok);
    try testing.expectEqual(@as(u32, feedback_burst), l.hour.sum(0));
}

test "config: clamping on load, unknown keys, defaults not written" {
    var c: Config = .{};
    try testing.expect(c.set("clip_max_s", "0"));
    try testing.expectEqual(@as(u32, 1), c.clip_max_s); // never zero
    try testing.expect(c.set("clip_max_s", "99999"));
    try testing.expectEqual(@as(u32, max_seconds), c.clip_max_s); // the buffer's ceiling
    try testing.expect(c.set("text_max", "-5"));
    try testing.expectEqual(@as(u32, 256), c.text_max);
    try testing.expect(c.set("feedback_queue", "1000000"));
    try testing.expectEqual(@as(u32, feedback_queue_ceiling), c.feedback_queue);
    try testing.expect(c.set("transcribe_per_hour", " 50 "));
    try testing.expectEqual(@as(u32, 50), c.transcribe_per_hour);
    try testing.expect(!c.set("nonsense", "1"));
    try testing.expect(!c.set("clip_min_ms", "lots"));
    // Out-of-range values set in code are clamped too.
    var raw: Config = .{ .feedback_burst = 0, .bundle_max_kib = 1 << 30 };
    raw = raw.clamped();
    try testing.expectEqual(@as(u32, 1), raw.feedback_burst);
    try testing.expectEqual(@as(u32, 5 * 1024), raw.bundle_max_kib);
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try c.format(&w);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "speech.transcribe_per_hour = 50") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "kept_clips") == null);
    try testing.expectEqual(@as(usize, 4000), (Config{}).minSamples());
    try testing.expectEqual(@as(usize, max_samples), (Config{}).maxSamples());
}

test "bundles: size, 50 a day, 100 MiB a day, per device; limits apply live" {
    var t: DeviceBuckets = .{};
    try testing.expectEqual(Limit.bundle_size, t.takeBundle("laptop", 5 * 1024 * 1024 + 1, 0).limited.limit);
    for (0..bundles_per_day) |_| try testing.expect(t.takeBundle("laptop", 1024, 0) == .ok);
    try testing.expectEqual(Limit.per_day, t.takeBundle("laptop", 1024, 0).limited.limit);
    try testing.expect(t.takeBundle("iphone", 1024, 0) == .ok);
    // Bytes: 20 bundles of 5 MiB fill the 100 MiB day.
    var u: DeviceBuckets = .{};
    for (0..20) |_| try testing.expect(u.takeBundle("laptop", 5 * 1024 * 1024, 0) == .ok);
    const v = u.takeBundle("laptop", 1, 0);
    try testing.expectEqual(Limit.bundle_bytes_per_day, v.limited.limit);
    try testing.expectEqual(@as(i64, 24 * 3_600_000), v.limited.at);
    // Live: a lower feedback burst applies to a device already known.
    _ = u.take("laptop", 0);
    u.setLimits(.{ .feedback_burst = 1 });
    try testing.expect(u.take("laptop", 0) == .ok); // at most 1 token left
    try testing.expect(u.take("laptop", 0) != .ok);
}

test "capText cuts at a code point boundary" {
    try testing.expectEqualStrings("ab", capText("ab", 8));
    try testing.expectEqualStrings("a", capText("a\u{00E9}", 2));
    try testing.expectEqual(@as(usize, max_text), capText(&(@as([max_text + 5]u8, @splat('x'))), max_text).len);
}

fn header(buf: *[44]u8, rate: u32, channels: u16, bits: u16, data_len: u32) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.writeAll("RIFF") catch unreachable;
    w.writeInt(u32, 36 +% data_len, .little) catch unreachable;
    w.writeAll("WAVEfmt ") catch unreachable;
    w.writeInt(u32, 16, .little) catch unreachable;
    w.writeInt(u16, 1, .little) catch unreachable;
    w.writeInt(u16, channels, .little) catch unreachable;
    w.writeInt(u32, rate, .little) catch unreachable;
    w.writeInt(u32, rate * channels * bits / 8, .little) catch unreachable;
    w.writeInt(u16, channels * bits / 8, .little) catch unreachable;
    w.writeInt(u16, bits, .little) catch unreachable;
    w.writeAll("data") catch unreachable;
    w.writeInt(u32, data_len, .little) catch unreachable;
    return w.buffered();
}

test "checkWav: size before parsing; a header claiming too much is refused without allocating" {
    // Too many bytes: refused on the length alone.
    const big = try testing.allocator.alloc(u8, max_wav_bytes + 1);
    defer testing.allocator.free(big);
    try testing.expectError(error.AudioTooLarge, checkWav(big));
    var buf: [44]u8 = undefined;
    // A header claiming 4 GiB of samples that aren't there: ../Audio
    // clamps the length to the bytes present (checked above), so the
    // claim can't make anything allocate more than those bytes.
    try checkWav(header(&buf, 16000, 1, 16, 0xFFFF_FFF0));
    const inf = try Audio.info(.wav, header(&buf, 16000, 1, 16, 0xFFFF_FFF0));
    try testing.expectEqual(@as(usize, 0), try inf.nSamples());
    // Wrong rate / channels / bits.
    try testing.expectError(error.BadAudio, checkWav(header(&buf, 48000, 1, 16, 0)));
    try testing.expectError(error.BadAudio, checkWav(header(&buf, 16000, 6, 16, 0)));
    try testing.expectError(error.BadAudio, checkWav(header(&buf, 16000, 1, 8, 0)));
    try testing.expectError(error.BadAudio, checkWav("RIFF"));
    // A good empty one passes the header check.
    try checkWav(header(&buf, 16000, 1, 16, 0));
}
