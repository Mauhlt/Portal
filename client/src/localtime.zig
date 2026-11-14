//! The local time zone's offset from UTC at a given time (seconds east),
//! for showing reset times in local time (ui/usage_strip.zig). Windows:
//! FileTimeToLocalFileTime; Apple: localtime_r's tm_gmtoff; elsewhere
//! UTC.

const std = @import("std");
const builtin = @import("builtin");

pub fn offsetAt(t: i64) i32 {
    if (t <= 0) return 0;
    switch (builtin.os.tag) {
        .windows => {
            const FILETIME = extern struct { lo: u32, hi: u32 };
            const k32 = struct {
                extern "kernel32" fn FileTimeToLocalFileTime(ft: *const FILETIME, local: *FILETIME) callconv(.winapi) c_int;
            };
            const v: u64 = (@as(u64, @intCast(t)) + 11644473600) * 10_000_000;
            const ft: FILETIME = .{ .lo = @truncate(v), .hi = @truncate(v >> 32) };
            var lt: FILETIME = undefined;
            if (k32.FileTimeToLocalFileTime(&ft, &lt) == 0) return 0;
            const l: u64 = (@as(u64, lt.hi) << 32) | lt.lo;
            const diff: i64 = @divFloor(@as(i64, @intCast(l)) - @as(i64, @intCast(v)), 10_000_000);
            return @intCast(std.math.clamp(diff, -14 * 3600, 14 * 3600));
        },
        .macos, .ios => {
            // Darwin's struct tm: nine ints, then tm_gmtoff and tm_zone.
            const Tm = extern struct {
                ints: [9]c_int,
                gmtoff: c_long,
                zone: ?[*:0]const u8,
            };
            const c = struct {
                extern "c" fn localtime_r(t: *const c_long, out: *Tm) ?*Tm;
            };
            const tt: c_long = @intCast(t);
            var tm: Tm = undefined;
            if (c.localtime_r(&tt, &tm) == null) return 0;
            return @intCast(std.math.clamp(tm.gmtoff, -14 * 3600, 14 * 3600));
        },
        else => return 0,
    }
}

test "offsetAt: within a day either way" {
    const o = offsetAt(1_794_819_600);
    try std.testing.expect(o >= -14 * 3600 and o <= 14 * 3600);
    try std.testing.expectEqual(@as(i32, 0), offsetAt(0));
}
