//! The desktop's gate for speech traffic from paired devices (owner
//! requirement, 2026-11-14: protect the desktop from many devices at once,
//! e.g. several compromised). Nothing device-facing carries speech yet:
//! the future routes (POST /sync/bundle, GET /sync/update, a device's
//! correction message) must call it, in this order, with the device name
//! from the live paired session (never from the request) and after the
//! device's input permission check:
//!
//!   begin(device, declared_bytes, now)   before reading the body: the
//!       device isn't closed for malformed data, it holds (or gets) one of
//!       the `concurrent_devices` speech slots (others: Busy with a retry
//!       time, never queued), and the declared size fits the shared
//!       payload budget (16 MiB over every device). The ticket carries the
//!       body's read deadline (slow-loris: the server's read waits until
//!       then, as a deadline, never a poll).
//!   Slots: a device keeps its slot across requests, at most 5 minutes;
//!       it is released after 60 s without speech traffic, and at 5
//!       minutes even if busy (a request in flight finishes or is cut at
//!       its own read deadline; the device's next request is told
//!       `expired`, then may retry). After an expiry the same device can't
//!       take a slot for 30 s while another device is waiting. Only the
//!       speech slot is released: the device's Portal session, terminal
//!       and WebSocket are untouched (the gate knows nothing of them).
//!       `nextDeadline` is the one wakeup to arm (the earliest expiry or
//!       idle release); at it, call `expire`. No polling.
//!   feedback(device, now) / bundle(device, bytes, clips, now)
//!       the per-device limits (limits.DeviceBuckets) and the desktop-wide
//!       totals; whichever is hit first refuses, and a refused request
//!       counts against nothing.
//!   malformed(device, now)  a body that didn't parse: the third within 10
//!       minutes closes the device's speech traffic until `reconnected`
//!       (the caller logs it).
//!   end(ticket)             always, when the request is done.
//!
//! The desk's own microphone never goes through here (it has its own
//! limits in home.Engine and always has priority on the engine's worker).
//! Pure state: the caller holds one lock around it and passes monotonic ms.
//! Every limit hit is a value, never an assert or a panic.

const std = @import("std");
const limits = @import("limits.zig");

pub const Ticket = struct {
    device: u8,
    bytes: u64,
    /// The body must be read by then (monotonic ms).
    read_deadline: i64,
};

pub const Begin = union(enum) {
    ok: Ticket,
    /// Too many devices at once, or the payload budget is in use: try again
    /// at `retry_at` (monotonic ms). Never queued.
    busy: i64,
    /// The declared size alone is over the budget or a bundle's size cap.
    too_large,
    /// The device's speech slot expired (it held it the maximum time):
    /// told once; the next request may take a slot again.
    expired,
    /// Closed for malformed data until the device reconnects; or no room
    /// for its name (more than the paired-device count).
    refused,
};

/// How long a Busy device should wait before trying again.
pub const busy_retry_ms: i64 = 2_000;

pub const Gate = struct {
    cfg: limits.Config = .{},
    per_device: limits.DeviceBuckets = .{},
    // ---- desktop-wide totals
    feedback_hour: limits.Rolling(60, 60_000) = .{},
    kept_day: limits.Rolling(24, 3_600_000) = .{},
    bundles_day: limits.Rolling(24, 3_600_000) = .{},
    bytes_day: limits.RollingOf(u64, 24, 3_600_000) = .{},
    kept_dev: [limits.max_devices]limits.Rolling(24, 3_600_000) = @splat(.{}),
    // ---- in flight: requests and payload bytes per device, and the slots
    inflight: [limits.max_devices]u16 = @splat(0),
    payload: u64 = 0,
    held_since: [limits.max_devices]?i64 = @splat(null),
    last_traffic: [limits.max_devices]i64 = @splat(0),
    /// Expired: tell the device once; then it may not retake a slot
    /// before `cooldown_until` while another device is waiting.
    expired_notice: [limits.max_devices]bool = @splat(false),
    cooldown_until: [limits.max_devices]i64 = @splat(0),
    /// A device was refused a slot: it counts as waiting until then.
    waiting_until: [limits.max_devices]i64 = @splat(0),
    // ---- malformed data (strikes per minute over the last hour)
    strikes: [limits.max_devices]limits.Rolling(60, 60_000) = @splat(.{}),
    closed: [limits.max_devices]bool = @splat(false),

    /// New limits (live): counts and tickets are kept.
    pub fn setLimits(g: *Gate, c: limits.Config) void {
        g.cfg = c.clamped();
        g.per_device.setLimits(g.cfg);
    }

    fn slot(g: *Gate, device: []const u8) ?u8 {
        const k = g.per_device.slot(device) orelse return null;
        return @intCast(k);
    }

    /// Slots in use: held, or still serving a request after its slot
    /// expired (no overcommit past concurrent_devices meanwhile).
    fn heldSlots(g: *const Gate) u32 {
        var n: u32 = 0;
        for (g.held_since, g.inflight) |h, f| if (h != null or f > 0) {
            n += 1;
        };
        return n;
    }

    /// Frees the entries of devices the device store no longer has (call
    /// when it changes: unpairing). Entries with a request in flight stay
    /// until it ends; desktop-wide totals are untouched.
    pub fn retain(g: *Gate, paired: []const []const u8) void {
        const t = &g.per_device;
        for (0..t.n) |k| {
            if (t.lens[k] == 0) continue;
            const name = t.names[k][0..t.lens[k]];
            const still = for (paired) |p| {
                if (std.mem.eql(u8, p, name)) break true;
            } else false;
            if (still or g.inflight[k] > 0) continue;
            t.free(k);
            g.held_since[k] = null;
            g.last_traffic[k] = 0;
            g.expired_notice[k] = false;
            g.cooldown_until[k] = 0;
            g.waiting_until[k] = 0;
            g.kept_dev[k] = .{};
            g.strikes[k] = .{};
            g.closed[k] = false;
        }
    }

    fn ms(s: u32) i64 {
        return @as(i64, s) * 1000;
    }

    /// Releases slots whose time is up (call at `nextDeadline`, and it is
    /// called by every entry point). Returns how many were released.
    pub fn expire(g: *Gate, now: i64) u32 {
        var n: u32 = 0;
        for (&g.held_since, 0..) |*h, i| {
            const since = h.* orelse continue;
            if (now - since >= ms(g.cfg.slot_max_hold_s)) {
                h.* = null;
                g.expired_notice[i] = true;
                g.cooldown_until[i] = now + ms(g.cfg.slot_cooldown_s);
                n += 1;
            } else if (g.inflight[i] == 0 and now - g.last_traffic[i] >= ms(g.cfg.slot_idle_s)) {
                h.* = null;
                n += 1;
            }
        }
        return n;
    }

    /// The one wakeup to arm: the earliest slot expiry or idle release
    /// (monotonic ms), or null when no slot is held.
    pub fn nextDeadline(g: *const Gate) ?i64 {
        var best: ?i64 = null;
        for (g.held_since, 0..) |h, i| {
            const since = h orelse continue;
            var d = since + ms(g.cfg.slot_max_hold_s);
            if (g.inflight[i] == 0) d = @min(d, g.last_traffic[i] + ms(g.cfg.slot_idle_s));
            best = if (best) |b| @min(b, d) else d;
        }
        return best;
    }

    fn othersWaiting(g: *const Gate, me: usize, now: i64) bool {
        for (g.waiting_until, 0..) |w, i| if (i != me and g.held_since[i] == null and w > now) return true;
        return false;
    }

    pub fn holdsSlot(g: *const Gate, device: []const u8) bool {
        for (0..g.per_device.n) |k| {
            if (std.mem.eql(u8, g.per_device.names[k][0..g.per_device.lens[k]], device)) return g.held_since[k] != null;
        }
        return false;
    }

    fn budget(g: *const Gate) u64 {
        return @as(u64, g.cfg.payload_budget_mib) * 1024 * 1024;
    }

    pub fn begin(g: *Gate, device: []const u8, declared_bytes: u64, now: i64) Begin {
        const i = g.slot(device) orelse return .refused;
        if (g.closed[i]) return .refused;
        if (declared_bytes > g.budget()) return .too_large;
        _ = g.expire(now);
        if (g.expired_notice[i]) {
            g.expired_notice[i] = false;
            return .expired;
        }
        if (g.inflight[i] >= g.cfg.device_inflight) return .{ .busy = now + busy_retry_ms };
        if (g.held_since[i] == null) {
            // The same device right after an expiry waits while others want one.
            if (now < g.cooldown_until[i] and g.othersWaiting(i, now)) return .{ .busy = g.cooldown_until[i] };
            // Its own expired-but-open request isn't someone else's slot.
            const in_use = g.heldSlots() - @intFromBool(g.inflight[i] > 0);
            if (in_use >= g.cfg.concurrent_devices) {
                g.waiting_until[i] = now + ms(g.cfg.slot_cooldown_s);
                return .{ .busy = @min(now + busy_retry_ms, g.nextDeadline() orelse now + busy_retry_ms) };
            }
        }
        if (g.payload + declared_bytes > g.budget()) return .{ .busy = now + busy_retry_ms };
        if (g.held_since[i] == null) g.held_since[i] = now;
        g.waiting_until[i] = 0;
        g.last_traffic[i] = now;
        g.inflight[i] +|= 1;
        g.payload += declared_bytes;
        return .{ .ok = .{ .device = i, .bytes = declared_bytes, .read_deadline = now + @as(i64, g.cfg.read_timeout_s) * 1000 } };
    }

    /// The request is done (read, answered, or cut at its read deadline).
    pub fn end(g: *Gate, t: Ticket, now: i64) void {
        g.inflight[t.device] -|= 1;
        g.payload -|= t.bytes;
        g.last_traffic[t.device] = now;
    }

    /// A correction or discard from `device`.
    pub fn feedback(g: *Gate, device: []const u8, now: i64) limits.DeviceBuckets.DeviceVerdict {
        const i = g.slot(device) orelse return .refused;
        if (g.closed[i]) return .refused;
        // Desktop-wide first (checked, not yet counted), then the device's.
        if (g.feedback_hour.sum(now) >= g.cfg.global_feedback_per_hour)
            return .{ .limited = .{ .limit = .global_per_hour, .at = g.feedback_hour.freeAt(now, g.cfg.global_feedback_per_hour) } };
        const v = g.per_device.take(device, now);
        if (v == .ok) g.feedback_hour.add(now);
        return v;
    }

    /// A training bundle of `bytes` holding `clips` samples from `device`.
    pub fn bundle(g: *Gate, device: []const u8, bytes: u64, clips: u32, now: i64) limits.DeviceBuckets.DeviceVerdict {
        const i = g.slot(device) orelse return .refused;
        if (g.closed[i]) return .refused;
        const c = g.cfg;
        if (g.bundles_day.sum(now) >= c.global_bundles_per_day)
            return .{ .limited = .{ .limit = .global_per_day, .at = g.bundles_day.freeAt(now, c.global_bundles_per_day) } };
        const gcap = @as(u64, c.global_bundle_mib_per_day) * 1024 * 1024;
        if (bytes > gcap) return .{ .exceeds = .global_bytes_per_day };
        if (g.bytes_day.sum(now) + bytes > gcap)
            return .{ .limited = .{ .limit = .global_bytes_per_day, .at = g.bytes_day.freeAt(now, gcap - bytes + 1) } };
        if (clips > c.global_kept_clips_per_day or clips > c.kept_clips_per_day) return .{ .exceeds = .kept_per_day };
        if (g.kept_day.sum(now) + clips > c.global_kept_clips_per_day)
            return .{ .limited = .{ .limit = .kept_per_day, .at = g.kept_day.freeAt(now, c.global_kept_clips_per_day - clips + 1) } };
        if (g.kept_dev[i].sum(now) + clips > c.kept_clips_per_day)
            return .{ .limited = .{ .limit = .kept_per_day, .at = g.kept_dev[i].freeAt(now, c.kept_clips_per_day - clips + 1) } };
        const v = g.per_device.takeBundle(device, bytes, now);
        if (v == .ok) {
            g.bundles_day.add(now);
            g.bytes_day.addN(now, bytes);
            g.kept_day.addN(now, clips);
            g.kept_dev[i].addN(now, clips);
        }
        return v;
    }

    /// A body from `device` that didn't parse. True: this closed its
    /// speech traffic (the caller logs it) until `reconnected`.
    pub fn malformed(g: *Gate, device: []const u8, now: i64) bool {
        const i = g.slot(device) orelse return false;
        if (g.closed[i]) return false;
        g.strikes[i].add(now);
        if (g.strikes[i].sumLast(now, g.cfg.malformed_window_min) >= g.cfg.malformed_strikes) {
            g.closed[i] = true;
            return true;
        }
        return false;
    }

    /// The device's session started again: its speech traffic is open
    /// (its strikes and every count are kept).
    pub fn reconnected(g: *Gate, device: []const u8) void {
        const i = g.slot(device) orelse return;
        g.closed[i] = false;
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "concurrency: 3 devices at once, the 4th is busy (not queued); the budget is shared" {
    var g: Gate = .{};
    const names = [_][]const u8{ "laptop", "iphone", "surface", "tablet" };
    var t: [3]Ticket = undefined;
    for (names[0..3], 0..) |n, i| t[i] = g.begin(n, 1024, 0).ok;
    const b = g.begin(names[3], 1024, 0);
    try testing.expectEqual(@as(i64, busy_retry_ms), b.busy);
    // A device already in may send another request.
    const again = g.begin("laptop", 1024, 0).ok;
    g.end(again, 0);
    g.end(t[0], 0);
    // The laptop still holds its slot (idle for less than 60 s): busy.
    try testing.expect(g.begin(names[3], 1024, 1000) == .busy);
    // 60 s without traffic: released, the tablet gets it.
    try testing.expect(g.begin(names[3], 1024, 60_000) == .ok);
    try testing.expect(!g.holdsSlot("laptop"));
    // 16 MiB over all devices: a declared size that doesn't fit next to
    // the others is busy; one over the budget alone is too large.
    var h: Gate = .{};
    const big = h.begin("laptop", 10 * 1024 * 1024, 0).ok;
    try testing.expect(h.begin("iphone", 7 * 1024 * 1024, 0) == .busy);
    try testing.expect(h.begin("iphone", 17 * 1024 * 1024, 0) == .too_large);
    h.end(big, 0);
    const ok = h.begin("iphone", 7 * 1024 * 1024, 5).ok;
    try testing.expectEqual(@as(i64, 5 + read_timeout_ms), ok.read_deadline);
}

const read_timeout_ms = limits.read_timeout_s * 1000;

test "slots: expiry at 5 minutes even while busy, told once; the session is untouched" {
    var g: Gate = .{};
    const t0 = g.begin("laptop", 100, 0).ok;
    try testing.expectEqual(@as(?i64, 300_000), g.nextDeadline()); // busy: no idle release
    // Still busy at 5 minutes: the slot goes anyway.
    try testing.expectEqual(@as(u32, 1), g.expire(300_000));
    try testing.expect(!g.holdsSlot("laptop"));
    try testing.expect(g.nextDeadline() == null);
    // The request in flight ends on its own (its read deadline).
    g.end(t0, 301_000);
    // Its next request: "slot expired, retry" once, then it may go on
    // (nobody else waits), its feedback allowance as before: nothing of
    // the device's session was dropped.
    try testing.expect(g.begin("laptop", 100, 302_000) == .expired);
    const t1 = g.begin("laptop", 100, 302_000).ok;
    g.end(t1, 302_000);
    try testing.expect(g.feedback("laptop", 302_000) == .ok);
    try testing.expect(g.holdsSlot("laptop"));
}

test "slots: idle release after 60 s, one wakeup for the earliest deadline" {
    var g: Gate = .{};
    const a = g.begin("laptop", 1, 0).ok;
    g.end(a, 10_000);
    const b = g.begin("iphone", 1, 20_000).ok;
    g.end(b, 20_000);
    try testing.expectEqual(@as(?i64, 70_000), g.nextDeadline());
    try testing.expectEqual(@as(u32, 0), g.expire(69_999));
    try testing.expectEqual(@as(u32, 1), g.expire(70_000));
    try testing.expect(!g.holdsSlot("laptop") and g.holdsSlot("iphone"));
    try testing.expectEqual(@as(?i64, 80_000), g.nextDeadline());
}

test "slots: after an expiry the same device waits 30 s if another is waiting" {
    var g: Gate = .{};
    g.setLimits(.{ .concurrent_devices = 1 });
    const t0 = g.begin("laptop", 1, 0).ok; // holds the only slot (request open)
    try testing.expect(g.begin("iphone", 1, 1000) == .busy); // waiting
    try testing.expect(g.begin("iphone", 1, 298_000) == .busy); // still retrying
    _ = g.expire(300_000);
    // Its open request still uses the slot until it ends.
    try testing.expect(g.begin("iphone", 1, 300_000) == .busy);
    g.end(t0, 300_000);
    try testing.expect(g.begin("laptop", 1, 300_000) == .expired);
    // The iPhone waits: the laptop is held off until the cooldown ends.
    try testing.expectEqual(@as(i64, 330_000), g.begin("laptop", 1, 300_001).busy);
    try testing.expect(g.begin("iphone", 1, 300_002) == .ok);
    // Without anyone waiting, an expired device retakes at once.
    var h: Gate = .{};
    h.setLimits(.{ .concurrent_devices = 1 });
    const t = h.begin("laptop", 1, 0).ok;
    _ = h.expire(300_000);
    h.end(t, 300_000);
    try testing.expect(h.begin("laptop", 1, 300_000) == .expired);
    try testing.expect(h.begin("laptop", 1, 300_001) == .ok);
}

test "global totals override the per-device allowance" {
    var g: Gate = .{};
    g.setLimits(.{ .global_feedback_per_hour = 7 });
    // Two devices, each well within its own burst of 5 ...
    for (0..4) |_| try testing.expect(g.feedback("laptop", 0) == .ok);
    for (0..3) |_| try testing.expect(g.feedback("iphone", 0) == .ok);
    // ... but together at the desktop-wide hourly cap: both refused.
    try testing.expectEqual(limits.Limit.global_per_hour, g.feedback("laptop", 0).limited.limit);
    try testing.expectEqual(limits.Limit.global_per_hour, g.feedback("iphone", 0).limited.limit);
    try testing.expect(g.feedback("laptop", 3_600_000) == .ok);

    // Bundles: 100 a day desktop-wide, 50 per device; bytes 250 MiB.
    var b: Gate = .{};
    for (0..50) |_| try testing.expect(b.bundle("laptop", 1024, 1, 0) == .ok);
    try testing.expectEqual(limits.Limit.per_day, b.bundle("laptop", 1024, 1, 0).limited.limit);
    for (0..50) |_| try testing.expect(b.bundle("iphone", 1024, 1, 0) == .ok);
    try testing.expectEqual(limits.Limit.global_per_day, b.bundle("surface", 1024, 1, 0).limited.limit);
    var z: Gate = .{};
    z.setLimits(.{ .global_bundle_mib_per_day = 12 });
    try testing.expect(z.bundle("a", 5 * 1024 * 1024, 0, 0) == .ok);
    try testing.expect(z.bundle("b", 5 * 1024 * 1024, 0, 0) == .ok);
    try testing.expectEqual(limits.Limit.global_bytes_per_day, z.bundle("c", 5 * 1024 * 1024, 0, 0).limited.limit);
    // Kept clips: 1000 a day desktop-wide, 500 per device.
    var k: Gate = .{};
    try testing.expect(k.bundle("a", 1024, 500, 0) == .ok);
    try testing.expectEqual(limits.Limit.kept_per_day, k.bundle("a", 1024, 1, 0).limited.limit);
    try testing.expect(k.bundle("b", 1024, 500, 0) == .ok);
    try testing.expectEqual(limits.Limit.kept_per_day, k.bundle("c", 1024, 1, 0).limited.limit);
}

test "per-device in-flight cap; an expired slot still serving a request counts" {
    var g: Gate = .{};
    const a = g.begin("laptop", 1, 0).ok;
    const b = g.begin("laptop", 1, 0).ok;
    try testing.expect(g.begin("laptop", 1, 0) == .busy); // 2 at once at most
    g.end(a, 0);
    g.end(b, 0);
    var h: Gate = .{};
    h.setLimits(.{ .concurrent_devices = 1 });
    const t = h.begin("laptop", 1, 0).ok;
    _ = h.expire(300_000); // the slot goes, its request is still open
    try testing.expect(h.begin("iphone", 1, 300_000) == .busy);
    h.end(t, 300_100);
    try testing.expect(h.begin("iphone", 1, 300_100) == .ok);
}

test "permanent refusals carry no retry time" {
    var g: Gate = .{};
    try testing.expectEqual(limits.Limit.kept_per_day, g.bundle("laptop", 1024, 501, 0).exceeds);
    var z: Gate = .{};
    z.setLimits(.{ .global_bundle_mib_per_day = 1 });
    try testing.expectEqual(limits.Limit.global_bytes_per_day, z.bundle("a", 2 * 1024 * 1024, 0, 0).exceeds);
}

test "retain: unpaired devices' entries are reused, totals stay" {
    var g: Gate = .{};
    g.setLimits(.{ .global_feedback_per_hour = 3 });
    try testing.expect(g.feedback("old", 0) == .ok);
    try testing.expect(g.feedback("old", 0) == .ok);
    g.retain(&.{"laptop"});
    try testing.expect(g.per_device.find("old") == null);
    // The desktop-wide count still holds the old device's two.
    try testing.expect(g.feedback("laptop", 0) == .ok);
    try testing.expectEqual(limits.Limit.global_per_hour, g.feedback("laptop", 0).limited.limit);
}

test "malformed data: 3 in 10 minutes closes a device until it reconnects" {
    var g: Gate = .{};
    try testing.expect(!g.malformed("laptop", 0));
    try testing.expect(!g.malformed("laptop", 60_000));
    // Spread out: the first two have left the 10-minute window (minute
    // 1 is in it until minute 11's slot pushes it out).
    try testing.expect(!g.malformed("laptop", 11 * 60_000));
    try testing.expect(!g.malformed("laptop", 11 * 60_000 + 1));
    try testing.expect(g.malformed("laptop", 11 * 60_000 + 2));
    try testing.expect(g.begin("laptop", 10, 0) == .refused);
    try testing.expect(g.feedback("laptop", 0) == .refused);
    try testing.expect(g.feedback("iphone", 0) == .ok); // others unaffected
    g.reconnected("laptop");
    try testing.expect(g.begin("laptop", 10, 0) == .ok);
}

test "never more names than paired devices; bad names refused, no panic" {
    var g: Gate = .{};
    var buf: [limits.max_devices][8]u8 = undefined;
    for (0..limits.max_devices) |i| {
        const n = std.fmt.bufPrint(&buf[i], "d{d}", .{i}) catch unreachable;
        try testing.expect(g.feedback(n, 0) == .ok);
    }
    try testing.expect(g.feedback("seventeen", 0) == .refused);
    try testing.expect(g.begin("", 1, 0) == .refused);
    var long: [limits.max_device_name + 1]u8 = @splat('x');
    try testing.expect(g.bundle(&long, 1, 1, 0) == .refused);
    try testing.expect(!g.malformed("", 0));
}
