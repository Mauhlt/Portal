//! The desktop's gate for speech traffic from paired devices. Nothing
//! device-facing carries speech yet: the future routes (POST /sync/bundle,
//! GET /sync/update, a device's correction message) must call it, with the
//! device name from the live paired session (never from the request) and
//! after the device's input permission check:
//!
//!   begin(device, declared_bytes, now)   before reading the body: at most
//!       `concurrent_devices` devices have speech requests in flight
//!       (others: Busy with a retry time, never queued), at most
//!       `device_inflight` per device, and the declared size fits the
//!       shared payload budget (16 MiB over every device). The ticket
//!       carries the body's read deadline (a deadline, never a poll).
//!   feedback(device, now) / bundle(device, bytes, clips, now)
//!       the per-device limits (limits.DeviceBuckets).
//!   end(ticket)             always, when the request is done.
//!   retain(paired names) / drop(name)    when the device store changes:
//!       an unpaired (or replaced) device's entry is freed for reuse; one
//!       with a request in flight is marked stale (its requests refused,
//!       the name busy) and freed when the last one ends.
//!
//! The desk's own microphone never goes through here (it has its own
//! limits in home.Engine). Pure state: the caller holds one lock around it
//! and passes monotonic ms. Every limit hit is a value, never an assert or
//! a panic.

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
    /// Too many devices or requests at once, or the payload budget is in
    /// use: try again at `retry_at` (monotonic ms). Never queued.
    busy: i64,
    /// The declared size alone is over the budget.
    too_large,
    /// No room for its name (more than the paired-device count), or a bad
    /// name.
    refused,
};

/// How long a Busy device should wait before trying again.
pub const busy_retry_ms: i64 = 2_000;

pub const Gate = struct {
    cfg: limits.Config = .{},
    per_device: limits.DeviceBuckets = .{},
    /// Requests in flight per device, and payload bytes over all.
    inflight: [limits.max_devices]u16 = @splat(0),
    /// Unpaired or replaced while a request was in flight: freed when the
    /// last one ends.
    stale: [limits.max_devices]bool = @splat(false),
    payload: u64 = 0,

    /// New limits (live): counts and tickets are kept.
    pub fn setLimits(g: *Gate, c: limits.Config) void {
        g.cfg = c.clamped();
        g.per_device.setLimits(g.cfg);
    }

    fn slot(g: *Gate, device: []const u8) ?u8 {
        const k = g.per_device.slot(device) orelse return null;
        return @intCast(k);
    }

    /// Devices with a request in flight.
    fn busyDevices(g: *const Gate) u32 {
        var n: u32 = 0;
        for (g.inflight) |f| n += @intFromBool(f > 0);
        return n;
    }

    /// Frees the entries of devices the device store no longer has (call
    /// when it changes: unpairing). Entries with a request in flight are
    /// marked stale and freed when it ends.
    pub fn retain(g: *Gate, paired: []const []const u8) void {
        const t = &g.per_device;
        for (0..t.n) |k| {
            if (t.lens[k] == 0) continue;
            const name = t.names[k][0..t.lens[k]];
            const still = for (paired) |p| {
                if (std.mem.eql(u8, p, name)) break true;
            } else false;
            if (!still) g.dropSlot(k);
        }
    }

    /// `device`'s entry goes (it was unpaired, or replaced by a new
    /// pairing under the same name: the new device starts afresh).
    pub fn drop(g: *Gate, device: []const u8) void {
        if (g.per_device.find(device)) |k| g.dropSlot(k);
    }

    fn dropSlot(g: *Gate, k: usize) void {
        if (g.inflight[k] > 0) {
            g.stale[k] = true;
            return;
        }
        g.stale[k] = false;
        g.per_device.free(k);
    }

    /// The device's entry was dropped while its request was in flight:
    /// that request must not be stored.
    pub fn isStale(g: *const Gate, device: []const u8) bool {
        const k = g.per_device.find(device) orelse return false;
        return g.stale[k];
    }

    fn budget(g: *const Gate) u64 {
        return @as(u64, g.cfg.payload_budget_mib) * 1024 * 1024;
    }

    pub fn begin(g: *Gate, device: []const u8, declared_bytes: u64, now: i64) Begin {
        const i = g.slot(device) orelse return .refused;
        if (declared_bytes > g.budget()) return .too_large;
        // The name's previous device is still finishing a request.
        if (g.stale[i]) return .{ .busy = now + busy_retry_ms };
        if (g.inflight[i] >= g.cfg.device_inflight) return .{ .busy = now + busy_retry_ms };
        if (g.inflight[i] == 0 and g.busyDevices() >= g.cfg.concurrent_devices) return .{ .busy = now + busy_retry_ms };
        if (g.payload + declared_bytes > g.budget()) return .{ .busy = now + busy_retry_ms };
        g.inflight[i] +|= 1;
        g.payload += declared_bytes;
        return .{ .ok = .{ .device = i, .bytes = declared_bytes, .read_deadline = now + @as(i64, g.cfg.read_timeout_s) * 1000 } };
    }

    /// The request is done (read, answered, or cut at its read deadline).
    pub fn end(g: *Gate, t: Ticket) void {
        g.inflight[t.device] -|= 1;
        g.payload -|= t.bytes;
        if (g.stale[t.device] and g.inflight[t.device] == 0) g.dropSlot(t.device);
    }

    /// A correction or discard from `device`.
    pub fn feedback(g: *Gate, device: []const u8, now: i64) limits.DeviceBuckets.DeviceVerdict {
        return g.per_device.take(device, now);
    }

    /// A training bundle of `bytes` holding `clips` samples from `device`.
    pub fn bundle(g: *Gate, device: []const u8, bytes: u64, clips: u32, now: i64) limits.DeviceBuckets.DeviceVerdict {
        return g.per_device.takeBundle(device, bytes, clips, now);
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "concurrency: 2 devices at once, the 3rd is busy (not queued); the budget is shared" {
    var g: Gate = .{};
    const a = g.begin("laptop", 1024, 0).ok;
    const b = g.begin("iphone", 1024, 0).ok;
    try testing.expectEqual(@as(i64, busy_retry_ms), g.begin("surface", 1024, 0).busy);
    // A device already in may send another request.
    const again = g.begin("laptop", 1024, 0).ok;
    g.end(again);
    g.end(a);
    // The laptop has nothing in flight now: the Surface gets in.
    try testing.expect(g.begin("surface", 1024, 0) == .ok);
    g.end(b);
    // 16 MiB over all devices: a declared size that doesn't fit next to
    // the others is busy; one over the budget alone is too large.
    var h: Gate = .{};
    const big = h.begin("laptop", 10 * 1024 * 1024, 0).ok;
    try testing.expect(h.begin("iphone", 7 * 1024 * 1024, 0) == .busy);
    try testing.expect(h.begin("iphone", 17 * 1024 * 1024, 0) == .too_large);
    h.end(big);
    const ok = h.begin("iphone", 7 * 1024 * 1024, 5).ok;
    try testing.expectEqual(@as(i64, 5 + limits.read_timeout_s * 1000), ok.read_deadline);
}

test "per-device in-flight cap" {
    var g: Gate = .{};
    const a = g.begin("laptop", 1, 0).ok;
    const b = g.begin("laptop", 1, 0).ok;
    try testing.expect(g.begin("laptop", 1, 0) == .busy); // 2 at once at most
    g.end(a);
    try testing.expect(g.begin("laptop", 1, 0) == .ok);
    g.end(b);
}

test "feedback and bundles go to the per-device limits" {
    var g: Gate = .{};
    for (0..limits.feedback_burst) |_| try testing.expect(g.feedback("laptop", 0) == .ok);
    try testing.expectEqual(limits.Limit.per_minute, g.feedback("laptop", 0).limited.limit);
    try testing.expect(g.feedback("iphone", 0) == .ok);
    try testing.expectEqual(limits.Limit.kept_per_day, g.bundle("laptop", 1024, 501, 0).exceeds);
    try testing.expect(g.bundle("laptop", 1024, 10, 0) == .ok);
}

test "retain: unpaired devices' entries are reused; in flight is stale until it ends" {
    var g: Gate = .{};
    try testing.expect(g.feedback("old", 0) == .ok);
    const t = g.begin("busy", 1, 0).ok;
    g.retain(&.{"laptop"});
    try testing.expect(g.per_device.find("old") == null);
    try testing.expect(g.per_device.find("busy") != null);
    try testing.expect(g.isStale("busy"));
    // Its name is busy meanwhile (a new pairing under it waits).
    try testing.expect(g.begin("busy", 1, 0) == .busy);
    g.end(t);
    // Freed by the end itself, no further store change needed.
    try testing.expect(g.per_device.find("busy") == null);
    try testing.expect(!g.isStale("busy"));
    try testing.expect(g.begin("busy", 1, 0) == .ok);
}

test "drop: a replaced device starts afresh" {
    var g: Gate = .{};
    for (0..limits.feedback_burst) |_| try testing.expect(g.feedback("laptop", 0) == .ok);
    try testing.expect(g.feedback("laptop", 0) == .limited);
    g.drop("laptop");
    try testing.expect(g.feedback("laptop", 0) == .ok);
    g.drop("never-seen"); // nothing to do
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
}
