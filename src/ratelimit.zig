//! The one rate limiter for requests the desk counts per paired device or
//! per tab: at most `n` accepted in any `window_ms`, by timestamps only
//! (callers pass the awake clock's ms; nothing sleeps, no timer runs).
//!
//!   projects (projects_ws.zig)  3 starts and 3 stops a minute per device
//!   For you  (foryou_ws.zig)    30 `i:` / `r:` requests a minute per device
//!   recap    (foryou_desk.zig)  1 a minute per tab, from any device
//!
//! A sliding window, not a token bucket (src/bucket.zig, speech's
//! limits.Bucket): a bucket of burst n refilling over the window lets
//! nearly 2n through in the first window, so it would not keep these
//! budgets.

const std = @import("std");
const Io = std.Io;
const devices = @import("devices.zig");

/// At most `n` events in any `window_ms`: the last `n` accepted times, in
/// a ring (the oldest is the one replaced).
pub fn Window(comptime n: usize, comptime window_ms: i64) type {
    return struct {
        const Self = @This();
        const never = std.math.minInt(i64);
        times: [n]i64 = @splat(never),
        next: usize = 0,

        /// True (and counted) if fewer than `n` were accepted in the
        /// `window_ms` before `now_ms`.
        pub fn allow(w: *Self, now_ms: i64) bool {
            const oldest = w.times[w.next];
            if (oldest != never and now_ms -| oldest < window_ms) return false;
            w.times[w.next] = now_ms;
            w.next = (w.next + 1) % n;
            return true;
        }
    };
}

/// A `Window` per paired device and per `Lane` (an enum: the kinds of
/// request counted apart), shared by all of a device's connections, so
/// reconnecting doesn't reset it. A device not seen yet takes a free
/// slot, or the one unused longest (more devices than slots only happens
/// after a re-pairing). Any thread.
pub fn PerDevice(comptime Lane: type, comptime n: usize, comptime window_ms: i64) type {
    return struct {
        const Self = @This();
        pub const Win = Window(n, window_ms);

        mutex: Io.Mutex = .init,
        slots: [devices.max_devices]Slot = @splat(.{}),

        const Slot = struct {
            id: ?devices.DeviceId = null,
            last_ms: i64 = 0,
            wins: std.EnumArray(Lane, Win) = .initFill(.{}),
            /// Requests over the limit (callers log the first few only).
            over: u32 = 0,
        };

        pub const Check = struct { ok: bool, over: u32 = 0 };

        /// Counts one `lane` request of device `id` at `now_ms`.
        pub fn allow(l: *Self, io: Io, id: devices.DeviceId, lane: Lane, now_ms: i64) Check {
            l.mutex.lockUncancelable(io);
            defer l.mutex.unlock(io);
            const s = l.slotFor(id);
            s.last_ms = now_ms;
            if (s.wins.getPtr(lane).allow(now_ms)) return .{ .ok = true };
            s.over +|= 1;
            return .{ .ok = false, .over = s.over };
        }

        fn slotFor(l: *Self, id: devices.DeviceId) *Slot {
            for (&l.slots) |*s| if (s.id) |sid| if (std.mem.eql(u8, &sid, &id)) return s;
            var pick: *Slot = &l.slots[0];
            for (&l.slots) |*s| {
                if (s.id == null) {
                    pick = s;
                    break;
                }
                if (s.last_ms < pick.last_ms) pick = s;
            }
            pick.* = .{ .id = id };
            return pick;
        }
    };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "window: n per window, by timestamps" {
    var r: Window(3, 60_000) = .{};
    try testing.expect(r.allow(0));
    try testing.expect(r.allow(10));
    try testing.expect(r.allow(20));
    try testing.expect(!r.allow(30));
    try testing.expect(!r.allow(59_999));
    try testing.expect(r.allow(60_000)); // the first one aged out
    try testing.expect(!r.allow(60_005));
    try testing.expect(r.allow(60_010));
    // One per window: the recap's.
    var one: Window(1, 60_000) = .{};
    try testing.expect(one.allow(100));
    try testing.expect(!one.allow(100 + 59_999));
    try testing.expect(one.allow(100 + 60_000));
    // The first event at the clock's very start counts too.
    var z: Window(1, 60_000) = .{};
    try testing.expect(z.allow(std.math.minInt(i64) + 1));
}

test "per device: lanes apart, devices apart, overs counted" {
    const io = testing.io;
    var l: PerDevice(enum { a, b }, 2, 1000) = .{};
    const x: devices.DeviceId = @splat(1);
    const y: devices.DeviceId = @splat(2);
    try testing.expect(l.allow(io, x, .a, 0).ok);
    try testing.expect(l.allow(io, x, .a, 1).ok);
    const no = l.allow(io, x, .a, 2);
    try testing.expect(!no.ok and no.over == 1);
    try testing.expectEqual(@as(u32, 2), l.allow(io, x, .a, 3).over);
    try testing.expect(l.allow(io, x, .b, 3).ok);
    try testing.expect(l.allow(io, y, .a, 3).ok);
    try testing.expect(l.allow(io, x, .a, 1000).ok);
}

test "per device: more devices than slots reuse the one unused longest" {
    const io = testing.io;
    var l: PerDevice(enum { only }, 3, 60_000) = .{};
    for (0..devices.max_devices) |i| {
        const id: devices.DeviceId = @splat(@intCast(i + 1));
        try testing.expect(l.allow(io, id, .only, @intCast(i)).ok);
    }
    const first: devices.DeviceId = @splat(1);
    for (0..2) |_| try testing.expect(l.allow(io, first, .only, 100).ok);
    try testing.expect(!l.allow(io, first, .only, 101).ok);
    // A new device takes device 2's slot (unused longest), not device 1's.
    const new: devices.DeviceId = @splat(200);
    try testing.expect(l.allow(io, new, .only, 102).ok);
    try testing.expect(!l.allow(io, first, .only, 103).ok);
}
