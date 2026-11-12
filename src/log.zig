//! Append-only audit log (logins, viewer connects, startup/shutdown).
//! Opened with FILE_APPEND_DATA only, so writes are atomic appends and the
//! handle cannot rewrite earlier entries.

const std = @import("std");
const Io = std.Io;
const w = @import("win32.zig");

pub const Log = struct {
    io: Io,
    handle: ?w.HANDLE,
    mutex: Io.Mutex = .init,

    pub fn open(gpa: std.mem.Allocator, io: Io, path: []const u8) Log {
        const wide = std.unicode.utf8ToUtf16LeAllocZ(gpa, path) catch return .{ .io = io, .handle = null };
        defer gpa.free(wide);
        const h = w.validHandle(w.CreateFileW(wide.ptr, w.FILE_APPEND_DATA, w.FILE_SHARE_READ, null, w.OPEN_ALWAYS, w.FILE_ATTRIBUTE_NORMAL, null));
        return .{ .io = io, .handle = h };
    }

    pub fn close(l: *Log) void {
        if (l.handle) |h| _ = w.CloseHandle(h);
        l.handle = null;
    }

    pub fn print(l: *Log, comptime fmt: []const u8, args: anytype) void {
        const h = l.handle orelse return;
        var buf: [1024]u8 = undefined;
        const ts = timestamp(l.io, buf[0..32]);
        const body = std.fmt.bufPrint(buf[ts.len..], " " ++ fmt ++ "\r\n", args) catch blk: {
            // Truncate rather than drop an audit entry.
            const tail = "...\r\n";
            @memcpy(buf[buf.len - tail.len ..], tail);
            break :blk buf[ts.len..];
        };
        const line = buf[0 .. ts.len + body.len];
        l.mutex.lockUncancelable(l.io);
        defer l.mutex.unlock(l.io);
        var n: w.DWORD = 0;
        _ = w.WriteFile(h, line.ptr, @intCast(line.len), &n, null);
    }
};

fn timestamp(io: Io, out: []u8) []const u8 {
    const now = Io.Timestamp.now(io, .real).toSeconds();
    const secs: u64 = if (now < 0) 0 else @intCast(now);
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(out, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,                   md.month.numeric(),      @as(u32, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch out[0..0];
}
