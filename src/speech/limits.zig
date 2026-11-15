//! Speech input's limits, in one place (trimmed 2026-11-14 for one person
//! with two desk-approved devices inside WireGuard):
//!
//!   clip length            at most 120 s per utterance (stt-local's
//!                          too_long; the capture buffer is allocated once
//!                          at that size), at least 250 ms (shorter: no
//!                          stt call)
//!   in flight              one transcription at a time (another: Busy)
//!   job timeout            60 s: a transcription not back by then is given
//!                          up (its result dropped and discarded in stt)
//!   rates, per source      transcriptions: a token bucket (burst 10, one
//!                          back every 6 s) and 2000 a rolling day;
//!                          corrections: burst 5, one every 6 s, and 1000
//!                          a rolling day. The desk has its own (home.Engine),
//!                          each paired device another (DeviceBuckets, keyed
//!                          on the session's device name). A refusal names
//!                          the limit and when it frees up.
//!   text                   8 KiB of transcript or correction
//!   feedback queue         16 calls (the oldest dropped; a device's never
//!                          push out the desk's)
//!   kept clips             500 a rolling day per source become training
//!                          samples; past that a clip is transcribed but
//!                          discarded in stt
//!   bundles (future)       each at most 5 MiB, 100 MiB a rolling day per
//!                          device
//!   devices (gate.zig)     at most 2 devices with speech requests in
//!                          flight at once (the desk's mic never counts),
//!                          2 requests per device, 16 MiB of payloads in
//!                          flight in all, 30 s to read a request body
//!   WAV to stt             size and header checked before stt decodes it
//!
//! Every tunable value is a field of `Config` (defaults: the constants),
//! loaded from the desk's settings.txt (`speech.<name> = <n>`, edited only
//! at the desk), clamped to `Config.ranges` (never zero, never above what
//! keeps memory bounded) and applied live. Unknown `speech.*` keys
//! (including removed ones) are ignored on load. Rolling days are 24
//! hourly slots (`Day`): no timestamp per event, exact to the hour.
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
pub const max_text = 8 * 1024;
pub const transcribe_per_day = 2000;
/// Feedback (corrections, discards): burst and refill, per source.
pub const feedback_burst = 5;
pub const feedback_refill_ms: i64 = 6_000;
pub const feedback_per_day = 1000;
/// Transcript ids that can still get feedback (stt's own window is 64).
pub const max_pending_ids = 64;
/// Paired devices (src/devices.zig max_devices): the size of the
/// per-device table.
pub const max_devices = 16;
pub const max_device_name = 64;
pub const max_feedback_jobs = 16;
/// The feedback queue's reserved capacity (Config.feedback_queue's ceiling).
pub const feedback_queue_ceiling = 64;
pub const job_timeout_s = 60;
pub const kept_clips_per_day = 500;
pub const bundle_mib_per_day = 100;
pub const bundle_max_kib = 5 * 1024;
/// Devices with speech requests in flight at once (the desk's own mic
/// never counts), requests per device, all device payloads in flight
/// together (MiB), and each request body's read deadline.
pub const concurrent_devices = 2;
pub const device_inflight = 2;
pub const payload_budget_mib = 16;
pub const read_timeout_s = 30;
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

/// A rolling 24-hour total in 24 hourly slots (a count or bytes): fixed
/// memory, no timestamp per event. Pure: callers pass monotonic ms; slots
/// are cleared as time is seen to pass.
pub const Day = struct {
    const n = 24;
    const slot_ms: i64 = 3_600_000;
    slots: [n]u64 = @splat(0),
    /// The absolute hour (ms / slot_ms) of the newest slot.
    newest: ?i64 = null,

    fn advance(d: *Day, now: i64) i64 {
        const cur = @divFloor(now, slot_ms);
        if (d.newest) |old| {
            if (cur > old) {
                var k: i64 = 0;
                while (k < @min(cur - old, n)) : (k += 1) d.slots[@intCast(@mod(cur - k, n))] = 0;
                d.newest = cur;
            }
            // A clock that went back counts into the newest slot.
        } else d.newest = cur;
        return d.newest.?;
    }

    pub fn sum(d: *Day, now: i64) u64 {
        _ = d.advance(now);
        var t: u64 = 0;
        for (d.slots) |c| t += c;
        return t;
    }

    pub fn add(d: *Day, now: i64, k: u64) void {
        const cur = d.advance(now);
        d.slots[@intCast(@mod(cur, n))] += k;
    }

    /// When adding `k` fits under `cap` again (now if it does); null if
    /// it never will (k alone is over the cap).
    pub fn fitsAt(d: *Day, now: i64, k: u64, cap: u64) ?i64 {
        if (k > cap) return null;
        var t = d.sum(now);
        if (t + k <= cap) return now;
        const cur = d.newest.?;
        var a = cur - n + 1;
        while (a <= cur) : (a += 1) {
            t -= d.slots[@intCast(@mod(a, n))];
            if (t + k <= cap) return (a + n) * slot_ms;
        }
        return (cur + n) * slot_ms;
    }
};

pub const Limit = enum {
    per_minute,
    per_day,
    bundle_size,
    bundle_bytes_per_day,
    kept_per_day,

    pub fn label(l: Limit) []const u8 {
        return switch (l) {
            .per_minute => "the per-minute limit",
            .per_day => "the daily limit",
            .bundle_size => "the bundle size limit",
            .bundle_bytes_per_day => "the daily bundle bytes limit",
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
    transcribe_per_day: u32 = transcribe_per_day,
    job_timeout_s: u32 = job_timeout_s,
    feedback_burst: u32 = feedback_burst,
    feedback_refill_ms: u32 = feedback_refill_ms,
    feedback_per_day: u32 = feedback_per_day,
    text_max: u32 = max_text,
    feedback_queue: u32 = max_feedback_jobs,
    kept_clips_per_day: u32 = kept_clips_per_day,
    bundle_mib_per_day: u32 = bundle_mib_per_day,
    bundle_max_kib: u32 = bundle_max_kib,
    concurrent_devices: u32 = concurrent_devices,
    device_inflight: u32 = device_inflight,
    payload_budget_mib: u32 = payload_budget_mib,
    read_timeout_s: u32 = read_timeout_s,

    pub const Range = struct { name: []const u8, min: u32, max: u32, doc: []const u8 };

    /// Each field's bounds (and what it means), in field order.
    pub const ranges = [_]Range{
        .{ .name = "clip_max_s", .min = 1, .max = max_seconds, .doc = "longest utterance (s); the capture buffer is sized for the ceiling" },
        .{ .name = "clip_min_ms", .min = 50, .max = 5_000, .doc = "shorter clips are dropped without an stt call (ms)" },
        .{ .name = "transcribe_burst", .min = 1, .max = 100, .doc = "transcriptions at once (token bucket size)" },
        .{ .name = "transcribe_refill_ms", .min = 100, .max = 3_600_000, .doc = "one more transcription allowed every (ms)" },
        .{ .name = "transcribe_per_day", .min = 1, .max = 1_000_000, .doc = "transcriptions per rolling day" },
        .{ .name = "job_timeout_s", .min = 5, .max = 600, .doc = "a transcription not back by then is given up (s)" },
        .{ .name = "feedback_burst", .min = 1, .max = 100, .doc = "corrections at once (token bucket size)" },
        .{ .name = "feedback_refill_ms", .min = 100, .max = 3_600_000, .doc = "one more correction allowed every (ms)" },
        .{ .name = "feedback_per_day", .min = 1, .max = 1_000_000, .doc = "corrections per rolling day" },
        .{ .name = "text_max", .min = 256, .max = max_text, .doc = "transcript / correction text (bytes)" },
        .{ .name = "feedback_queue", .min = 1, .max = feedback_queue_ceiling, .doc = "feedback calls queued (oldest dropped)" },
        .{ .name = "kept_clips_per_day", .min = 1, .max = 100_000, .doc = "clips kept as training samples per rolling day, per source" },
        .{ .name = "bundle_mib_per_day", .min = 1, .max = 10_240, .doc = "training bundle MiB per device per rolling day" },
        .{ .name = "bundle_max_kib", .min = 64, .max = 5 * 1024, .doc = "one training bundle (KiB; stt-local caps bundles at 5 MiB)" },
        .{ .name = "concurrent_devices", .min = 1, .max = max_devices, .doc = "devices with speech requests in flight at once (the desk's mic not counted)" },
        .{ .name = "device_inflight", .min = 1, .max = 16, .doc = "requests one device may have in flight at once" },
        .{ .name = "payload_budget_mib", .min = 1, .max = 64, .doc = "device speech payloads in flight together (MiB)" },
        .{ .name = "read_timeout_s", .min = 1, .max = 300, .doc = "a request body not read by then is dropped (s)" },
    };

    comptime {
        const fs = std.meta.fieldNames(Config);
        if (fs.len != ranges.len) @compileError("every speech limit needs a range");
        for (fs, ranges) |f, r| if (!std.mem.eql(u8, f, r.name)) @compileError("ranges out of order: " ++ f);
    }

    /// Every field within its range, and the shortest clip below the
    /// longest.
    pub fn clamped(c: Config) Config {
        var out = c;
        inline for (comptime std.meta.fieldNames(Config), ranges) |f, r| {
            @field(out, f) = std.math.clamp(@field(out, f), r.min, r.max);
        }
        out.clip_min_ms = @min(out.clip_min_ms, out.clip_max_s * 1000 - 1);
        return out;
    }

    /// `key = text` from the settings (key without "speech."): parsed and
    /// clamped. False if the key is unknown (or removed) or the text isn't
    /// a number.
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
    /// Never allowed as it is (larger than `limit` allows at all): no
    /// retry time.
    exceeds: Limit,
};

/// One source's rate: a token bucket (per minute) and a daily cap. A
/// request is counted only if both allow it.
pub const Limiter = struct {
    bucket: Bucket,
    day: Day = .{},
    per_day: u32,

    pub fn transcriptions() Limiter {
        return .{ .bucket = .{}, .per_day = transcribe_per_day };
    }
    pub fn feedback() Limiter {
        return .{ .bucket = .{ .burst = feedback_burst, .refill_ms = feedback_refill_ms, .tokens = feedback_burst }, .per_day = feedback_per_day };
    }

    /// New values (live): the cap, the bucket's size and refill; tokens
    /// over the new size are dropped.
    pub fn apply(l: *Limiter, burst: u32, refill_ms: u32, per_day: u32) void {
        l.bucket.burst = burst;
        l.bucket.refill_ms = refill_ms;
        l.bucket.tokens = @min(l.bucket.tokens, burst);
        if (l.bucket.tokens >= burst) l.bucket.next_ms = null;
        l.per_day = per_day;
    }

    pub fn applyTranscriptions(l: *Limiter, c: Config) void {
        l.apply(c.transcribe_burst, c.transcribe_refill_ms, c.transcribe_per_day);
    }
    pub fn applyFeedback(l: *Limiter, c: Config) void {
        l.apply(c.feedback_burst, c.feedback_refill_ms, c.feedback_per_day);
    }

    pub fn take(l: *Limiter, now: i64) Verdict {
        if (l.day.fitsAt(now, 1, l.per_day)) |at| if (at > now) return .{ .limited = .{ .limit = .per_day, .at = at } };
        if (!l.bucket.take(now)) return .{ .limited = .{ .limit = .per_minute, .at = l.bucket.nextAllowed(now) } };
        l.day.add(now, 1);
        return .ok;
    }
};

/// Per paired device, keyed on the device name from the session (never
/// from the request): its feedback rate, its bundle bytes and its kept
/// clips (rolling day). Entries live while the device stays paired, so a
/// reconnect finds its old counts; at most max_devices names (a name
/// beyond that is refused); `free` reuses an unpaired or replaced
/// device's entry (Gate.retain / Gate.drop, from the device store).
pub const DeviceBuckets = struct {
    names: [max_devices][max_device_name]u8 = undefined,
    lens: [max_devices]u8 = @splat(0),
    limiters: [max_devices]Limiter = undefined,
    bundle_bytes: [max_devices]Day = undefined,
    kept: [max_devices]Day = undefined,
    cfg: Config = .{},
    n: usize = 0,

    pub const DeviceVerdict = union(enum) {
        ok,
        /// Over a limit: refused (the caller answers 429 / a WS error
        /// naming the limit, with Retry-After from `at`).
        limited: @FieldType(Verdict, "limited"),
        /// Too large for that limit ever: 413 / a WS error, no retry.
        exceeds: Limit,
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
            .exceeds => |l| .{ .exceeds = l },
        };
    }

    /// A training bundle of `bytes` holding `clips` samples from `device`
    /// (future POST /sync/bundle): its size, the day's bytes, the day's
    /// kept clips.
    pub fn takeBundle(t: *DeviceBuckets, device: []const u8, bytes: u64, clips: u32, now: i64) DeviceVerdict {
        const i = t.slot(device) orelse return .refused;
        if (bytes > @as(u64, t.cfg.bundle_max_kib) * 1024) return .{ .exceeds = .bundle_size };
        const cap = @as(u64, t.cfg.bundle_mib_per_day) * 1024 * 1024;
        const b_at = t.bundle_bytes[i].fitsAt(now, bytes, cap) orelse return .{ .exceeds = .bundle_bytes_per_day };
        if (b_at > now) return .{ .limited = .{ .limit = .bundle_bytes_per_day, .at = b_at } };
        const k_at = t.kept[i].fitsAt(now, clips, t.cfg.kept_clips_per_day) orelse return .{ .exceeds = .kept_per_day };
        if (k_at > now) return .{ .limited = .{ .limit = .kept_per_day, .at = k_at } };
        t.bundle_bytes[i].add(now, bytes);
        t.kept[i].add(now, clips);
        return .ok;
    }

    /// The device's entry, if it has one (no registering).
    pub fn find(t: *const DeviceBuckets, device: []const u8) ?usize {
        if (device.len == 0) return null;
        for (0..t.n) |k| {
            if (t.lens[k] > 0 and std.mem.eql(u8, t.names[k][0..t.lens[k]], device)) return k;
        }
        return null;
    }

    /// Frees entry `k` for reuse (its device was unpaired: no longer in
    /// the device store; `Gate.retain`).
    pub fn free(t: *DeviceBuckets, k: usize) void {
        if (k < t.n) t.lens[k] = 0;
    }

    /// The device's entry (registered on first use, in a free entry if
    /// there is one); null: no room or a bad name.
    pub fn slot(t: *DeviceBuckets, device: []const u8) ?usize {
        if (device.len == 0 or device.len > max_device_name) return null;
        if (t.find(device)) |k| return k;
        const k = for (0..t.n) |j| {
            if (t.lens[j] == 0) break j;
        } else k: {
            if (t.n == max_devices) return null;
            t.n += 1;
            break :k t.n - 1;
        };
        @memcpy(t.names[k][0..device.len], device);
        t.lens[k] = @intCast(device.len);
        t.limiters[k] = Limiter.feedback();
        t.limiters[k].applyFeedback(t.cfg);
        t.bundle_bytes[k] = .{};
        t.kept[k] = .{};
        return k;
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

test "daily caps with a fake clock: under the minute rate but over the day is refused" {
    // One every 10 s never trips the bucket (one back every 6 s), but
    // the 2001st within 24 h is refused, and frees as the oldest hour leaves.
    var l = Limiter.transcriptions();
    var now: i64 = 0;
    for (0..transcribe_per_day) |_| {
        try testing.expect(l.take(now) == .ok);
        now += 10_000;
    }
    try testing.expect(l.bucket.nextAllowed(now) == now); // tokens left
    const v = l.take(now);
    try testing.expectEqual(Limit.per_day, v.limited.limit);
    try testing.expectEqual(@as(i64, 24 * 3_600_000), v.limited.at);
    try testing.expect(l.take(v.limited.at - 1) != .ok);
    try testing.expect(l.take(v.limited.at) == .ok);
    // Feedback: 1000 a day.
    var f = Limiter.feedback();
    now = 0;
    for (0..feedback_per_day) |_| {
        try testing.expect(f.take(now) == .ok);
        now += 31_000;
    }
    try testing.expectEqual(Limit.per_day, f.take(now).limited.limit);
}

test "day: slots clear as time passes; a refused request counts nothing; fitsAt" {
    var d: Day = .{};
    d.add(0, 1);
    d.add(3_599_999, 2);
    d.add(3_600_000, 4);
    try testing.expectEqual(@as(u64, 7), d.sum(3_600_000));
    try testing.expectEqual(@as(u64, 4), d.sum(24 * 3_600_000)); // the first hour left
    try testing.expectEqual(@as(u64, 0), d.sum(100 * 3_600_000));
    try testing.expect(d.fitsAt(0, 11, 10) == null); // never
    var l = Limiter.feedback();
    for (0..feedback_burst) |_| _ = l.take(0);
    try testing.expect(l.take(0) != .ok);
    try testing.expectEqual(@as(u64, feedback_burst), l.day.sum(0));
}

test "config: clamping on load, unknown and removed keys ignored, defaults not written" {
    var c: Config = .{};
    try testing.expect(c.set("clip_max_s", "0"));
    try testing.expectEqual(@as(u32, 1), c.clip_max_s); // never zero
    try testing.expect(c.set("clip_max_s", "99999"));
    try testing.expectEqual(@as(u32, max_seconds), c.clip_max_s); // the buffer's ceiling
    try testing.expect(c.set("text_max", "-5"));
    try testing.expectEqual(@as(u32, 256), c.text_max);
    try testing.expect(c.set("feedback_queue", "1000000"));
    try testing.expectEqual(@as(u32, feedback_queue_ceiling), c.feedback_queue);
    try testing.expect(c.set("transcribe_per_day", " 50 "));
    try testing.expectEqual(@as(u32, 50), c.transcribe_per_day);
    try testing.expect(!c.set("nonsense", "1"));
    try testing.expect(!c.set("clip_min_ms", "lots"));
    // Keys of limits that were removed: not known any more.
    for ([_][]const u8{ "transcribe_per_hour", "feedback_per_hour", "global_feedback_per_hour", "slot_max_hold_s", "malformed_strikes", "bundles_per_day" }) |k|
        try testing.expect(!c.set(k, "5"));
    var raw: Config = .{ .feedback_burst = 0, .bundle_max_kib = 1 << 30 };
    raw = raw.clamped();
    try testing.expectEqual(@as(u32, 1), raw.feedback_burst);
    try testing.expectEqual(@as(u32, 5 * 1024), raw.bundle_max_kib);
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try c.format(&w);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "speech.transcribe_per_day = 50") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "kept_clips") == null);
    try testing.expectEqual(@as(usize, 4000), (Config{}).minSamples());
    try testing.expectEqual(@as(usize, max_samples), (Config{}).maxSamples());
}

test "bundles: size, 100 MiB a day, kept clips a day, per device; limits apply live" {
    var t: DeviceBuckets = .{};
    try testing.expectEqual(Limit.bundle_size, t.takeBundle("laptop", 5 * 1024 * 1024 + 1, 1, 0).exceeds);
    // Bytes: 20 bundles of 5 MiB fill the 100 MiB day.
    for (0..20) |_| try testing.expect(t.takeBundle("laptop", 5 * 1024 * 1024, 1, 0) == .ok);
    const v = t.takeBundle("laptop", 1, 1, 0);
    try testing.expectEqual(Limit.bundle_bytes_per_day, v.limited.limit);
    try testing.expectEqual(@as(i64, 24 * 3_600_000), v.limited.at);
    try testing.expect(t.takeBundle("iphone", 1024, 1, 0) == .ok); // its own
    // Kept clips: 500 a day per device; more than that in one is never.
    var k: DeviceBuckets = .{};
    try testing.expect(k.takeBundle("laptop", 1024, 500, 0) == .ok);
    try testing.expectEqual(Limit.kept_per_day, k.takeBundle("laptop", 1024, 1, 0).limited.limit);
    try testing.expectEqual(Limit.kept_per_day, k.takeBundle("iphone", 1024, 501, 0).exceeds);
    var z: DeviceBuckets = .{};
    z.setLimits(.{ .bundle_mib_per_day = 1 });
    try testing.expectEqual(Limit.bundle_bytes_per_day, z.takeBundle("a", 2 * 1024 * 1024, 0, 0).exceeds);
    // Live: a lower feedback burst applies to a device already known.
    _ = t.take("laptop", 0);
    t.setLimits(.{ .feedback_burst = 1 });
    try testing.expect(t.take("laptop", 0) == .ok); // at most 1 token left
    try testing.expect(t.take("laptop", 0) != .ok);
}

test "config: the shortest clip stays below the longest" {
    const c = (Config{ .clip_max_s = 1, .clip_min_ms = 5000 }).clamped();
    try testing.expect(c.clip_min_ms < c.clip_max_s * 1000);
}

test "device table: an unpaired device's entry is reused" {
    var t: DeviceBuckets = .{};
    var names: [max_devices][8]u8 = undefined;
    for (0..max_devices) |i| _ = t.take(std.fmt.bufPrint(&names[i], "d{d}", .{i}) catch unreachable, 0);
    try testing.expect(t.take("new", 0) == .refused);
    t.free(t.find("d3").?);
    try testing.expect(t.take("new", 0) == .ok);
    try testing.expectEqual(@as(usize, max_devices), t.n);
    try testing.expect(t.find("d3") == null);
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
