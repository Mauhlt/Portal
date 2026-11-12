//! Append-only audit log (logins, viewer connects, startup/shutdown).
//! Opened with FILE_APPEND_DATA only, so writes are atomic appends and the
//! handle cannot rewrite earlier entries.

const std = @import("std");
const Io = std.Io;
const w = @import("win32.zig");

/// portal.log is moved to portal.log.1 at startup once it exceeds this.
pub const rotate_bytes: i64 = 10 * 1024 * 1024;

pub fn needsRotation(size: i64) bool {
    return size > rotate_bytes;
}

pub const Log = struct {
    io: Io,
    handle: ?w.HANDLE,
    mutex: Io.Mutex = .init,

    /// Opens (creating if needed) the log for appending. Fails rather than
    /// returning a log that silently drops entries: callers that need an
    /// audit trail must refuse to run without one. If the existing file is
    /// over `rotate_bytes` it is first renamed to `<path>.1` (replacing any
    /// older one); a failed rename (e.g. another Portal has it open) just
    /// keeps appending to the current file.
    pub fn open(gpa: std.mem.Allocator, io: Io, path: []const u8) !Log {
        const wide = try std.unicode.utf8ToUtf16LeAllocZ(gpa, path);
        defer gpa.free(wide);
        var h = try openAppend(wide);
        var size: i64 = 0;
        var rotated = false;
        if (w.GetFileSizeEx(h, &size) != 0 and needsRotation(size)) {
            const old_path = try std.mem.concat(gpa, u8, &.{ path, ".1" });
            defer gpa.free(old_path);
            const wide_old = try std.unicode.utf8ToUtf16LeAllocZ(gpa, old_path);
            defer gpa.free(wide_old);
            _ = w.CloseHandle(h);
            rotated = w.MoveFileExW(wide.ptr, wide_old.ptr, w.MOVEFILE_REPLACE_EXISTING) != 0;
            h = try openAppend(wide);
        }
        var l: Log = .{ .io = io, .handle = h };
        if (rotated) l.print("log rotated: previous entries are in {s}.1", .{path});
        return l;
    }

    fn openAppend(wide: [:0]const u16) !w.HANDLE {
        // FILE_APPEND_DATA only: every write is an atomic append and this
        // handle cannot rewrite earlier entries. FILE_SHARE_WRITE lets a
        // second Portal instance (another port) log to the same file.
        return w.validHandle(w.CreateFileW(
            wide.ptr,
            w.FILE_APPEND_DATA,
            w.FILE_SHARE_READ | w.FILE_SHARE_WRITE,
            null,
            w.OPEN_ALWAYS,
            w.FILE_ATTRIBUTE_NORMAL,
            null,
        )) orelse error.LogOpenFailed;
    }

    pub fn close(l: *Log) void {
        if (l.handle) |h| _ = w.CloseHandle(h);
        l.handle = null;
    }

    pub fn print(l: *Log, comptime fmt: []const u8, args: anytype) void {
        const h = l.handle orelse return;
        var buf: [1024]u8 = undefined;
        const ts = timestamp(l.io, buf[0..32]);
        const line = formatLine(&buf, ts.len, fmt, args);
        l.mutex.lockUncancelable(l.io);
        defer l.mutex.unlock(l.io);
        var n: w.DWORD = 0;
        _ = w.WriteFile(h, line.ptr, @intCast(line.len), &n, null);
    }
};

/// `buf[0..prefix_len]` already holds the timestamp. Appends " <entry>\r\n",
/// truncating (with a "...") rather than dropping an over-long audit entry.
fn formatLine(buf: []u8, prefix_len: usize, comptime fmt: []const u8, args: anytype) []const u8 {
    const tail = "...\r\n";
    std.debug.assert(buf.len >= prefix_len + tail.len);
    const body = std.fmt.bufPrint(buf[prefix_len..], " " ++ fmt ++ "\r\n", args) catch {
        @memcpy(buf[buf.len - tail.len ..], tail);
        return buf;
    };
    return buf[0 .. prefix_len + body.len];
}

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

test "log rotation threshold" {
    try std.testing.expect(!needsRotation(0));
    try std.testing.expect(!needsRotation(rotate_bytes));
    try std.testing.expect(needsRotation(rotate_bytes + 1));
}

test "log line truncates instead of failing" {
    var buf: [64]u8 = undefined;
    @memcpy(buf[0..2], "TS");
    try std.testing.expectEqualStrings("TS hi 7\r\n", formatLine(&buf, 2, "hi {d}", .{7}));
    const big: [200]u8 = @splat('x');
    const long = formatLine(&buf, 2, "{s}", .{&big});
    try std.testing.expectEqual(@as(usize, 64), long.len);
    try std.testing.expect(std.mem.startsWith(u8, long, "TS x"));
    try std.testing.expect(std.mem.endsWith(u8, long, "...\r\n"));
}
