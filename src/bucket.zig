//! Token bucket, in milli-units so slow rates refill smoothly: `rate`
//! units per second, holding at most `burst`. Used for per-WebSocket input
//! limits (web.zig) and the per-viewer image byte budget (web_images.zig).
//! Pure: callers pass the time (monotonic ms).

const std = @import("std");

pub const Bucket = struct {
    rate: i64,
    burst: i64,
    level_m: i64,
    last_ms: ?i64 = null,

    /// Starts full.
    pub fn init(rate: i64, burst: i64) Bucket {
        return .{ .rate = rate, .burst = burst, .level_m = burst *| 1000 };
    }

    pub fn refill(b: *Bucket, now_ms: i64) void {
        if (b.last_ms) |last| {
            // A clock that went back refills nothing; a long gap refills fully.
            const dt = std.math.clamp(now_ms -| last, 0, 3_600_000);
            b.level_m = @min(b.burst *| 1000, b.level_m +| dt *| b.rate);
        }
        b.last_ms = now_ms;
    }

    pub fn has(b: *const Bucket, n: i64) bool {
        return b.level_m >= n *| 1000;
    }

    /// Takes `n` units if they are there (call `refill` first).
    pub fn take(b: *Bucket, n: i64) bool {
        if (!b.has(n)) return false;
        b.level_m -= n *| 1000;
        return true;
    }

    /// Milliseconds after the last refill until `n` units are there (0 if
    /// they are now), or null if they never will be (more than `burst`,
    /// or no refill rate): the exact deadline to wait for, no polling.
    pub fn msUntil(b: *const Bucket, n: i64) ?i64 {
        if (n > b.burst or (b.rate <= 0 and !b.has(n))) return null;
        const missing = n *| 1000 -| b.level_m;
        if (missing <= 0) return 0;
        return std.math.divCeil(i64, missing, b.rate) catch null;
    }
};

const testing = std.testing;

test "refill, take, clock going back" {
    var b: Bucket = .init(10, 20); // 10/s, burst 20
    b.refill(0);
    try testing.expect(b.take(20));
    try testing.expect(!b.take(1));
    b.refill(100); // +1
    try testing.expect(b.take(1));
    try testing.expect(!b.has(1));
    b.refill(50); // back in time: nothing
    try testing.expect(!b.has(1));
    b.refill(10_000_000); // long gap: full, not more
    try testing.expect(b.take(20) and !b.has(1));
}

test "msUntil is the exact refill deadline" {
    var b: Bucket = .init(4, 8); // 4/s
    b.refill(0);
    try testing.expectEqual(@as(?i64, 0), b.msUntil(8));
    try testing.expect(b.take(8));
    try testing.expectEqual(@as(?i64, 250), b.msUntil(1));
    try testing.expectEqual(@as(?i64, 1000), b.msUntil(4));
    try testing.expectEqual(@as(?i64, null), b.msUntil(9)); // more than the burst
    b.refill(250);
    try testing.expect(b.has(1));
    try testing.expectEqual(@as(?i64, 750), b.msUntil(4));
}
