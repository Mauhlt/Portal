//! Append-only audit log (pairings, viewer connects, startup/shutdown).
//! Opened with FILE_APPEND_DATA only, so writes are atomic appends and the
//! handle cannot rewrite earlier entries.
//!
//! Size is bounded: when portal.log grows past `rotate_bytes` (checked at
//! startup and while running) it is renamed to portal.log.1, replacing any
//! older one, and a fresh file is started. Lines that a remote peer can
//! trigger are additionally rate limited by the callers
//! (web.zig `LogLimiter`), so a flood cannot rotate real entries away
//! quickly either.

const std = @import("std");
const Io = std.Io;
const w = @import("win32.zig");

/// portal.log is moved to portal.log.1 once it exceeds this.
pub const rotate_bytes: i64 = 10 * 1024 * 1024;

pub fn needsRotation(size: i64) bool {
    return size > rotate_bytes;
}

const max_path = 1024;

pub const Log = struct {
    io: Io,
    handle: ?w.HANDLE,
    mutex: Io.Mutex = .init,
    /// Rotation threshold (a field so tests can use a small one).
    limit: i64 = rotate_bytes,
    /// Bytes this process believes the file holds (re-read from the file
    /// before rotating: another Portal may share it).
    size: i64 = 0,
    path_w: [max_path:0]u16 = undefined,
    path_len: usize = 0,
    /// Times this handle rotated the file while running.
    rotations: u32 = 0,

    /// Opens (creating if needed) the log for appending. Fails rather than
    /// returning a log that silently drops entries: callers that need an
    /// audit trail must refuse to run without one. If the existing file is
    /// over the limit it is first renamed to `<path>.1`; a failed rename
    /// (e.g. another Portal has it open) just keeps appending.
    pub fn open(gpa: std.mem.Allocator, io: Io, path: []const u8) !Log {
        return openLimit(gpa, io, path, rotate_bytes);
    }

    pub fn openLimit(gpa: std.mem.Allocator, io: Io, path: []const u8, limit: i64) !Log {
        _ = gpa;
        var l: Log = .{ .io = io, .handle = null, .limit = limit };
        l.path_len = std.unicode.utf8ToUtf16Le(l.path_w[0..max_path], path) catch return error.LogOpenFailed;
        if (l.path_len >= max_path) return error.LogOpenFailed;
        l.path_w[l.path_len] = 0;
        l.handle = try openAppend(l.widePath());
        l.size = fileSize(l.handle.?);
        if (l.size > l.limit and l.rotate()) {
            l.print("log rotated: previous entries are in portal.log.1", .{});
        }
        return l;
    }

    fn widePath(l: *const Log) [:0]const u16 {
        return l.path_w[0..l.path_len :0];
    }

    fn fileSize(h: w.HANDLE) i64 {
        var size: i64 = 0;
        return if (w.GetFileSizeEx(h, &size) != 0) size else 0;
    }

    /// Renames the file to `<path>.1` and reopens a fresh one. Returns false
    /// (and keeps appending to the current file) if the rename failed.
    fn rotate(l: *Log) bool {
        var old: [max_path + 3:0]u16 = undefined;
        @memcpy(old[0..l.path_len], l.path_w[0..l.path_len]);
        old[l.path_len] = '.';
        old[l.path_len + 1] = '1';
        old[l.path_len + 2] = 0;
        const old_w = old[0 .. l.path_len + 2 :0];
        if (l.handle) |h| _ = w.CloseHandle(h);
        const moved = w.MoveFileExW(l.widePath().ptr, old_w.ptr, w.MOVEFILE_REPLACE_EXISTING) != 0;
        l.handle = openAppend(l.widePath()) catch null;
        l.size = if (l.handle) |h| fileSize(h) else 0;
        return moved;
    }

    fn openAppend(path: [:0]const u16) !w.HANDLE {
        // FILE_APPEND_DATA only: every write is an atomic append and this
        // handle cannot rewrite earlier entries. FILE_SHARE_WRITE lets a
        // second Portal instance (another port) log to the same file;
        // FILE_SHARE_DELETE lets either of them rotate it.
        return w.validHandle(w.CreateFileW(
            path.ptr,
            w.FILE_APPEND_DATA,
            w.FILE_SHARE_READ | w.FILE_SHARE_WRITE | FILE_SHARE_DELETE,
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
        var buf: [1024]u8 = undefined;
        const ts = timestamp(l.io, buf[0..32]);
        const line = formatLine(&buf, ts.len, fmt, args);
        l.mutex.lockUncancelable(l.io);
        defer l.mutex.unlock(l.io);
        if (l.handle == null) return;
        if (l.size +| @as(i64, @intCast(line.len)) > l.limit) {
            // Another process may have rotated it already: trust the file.
            l.size = fileSize(l.handle.?);
            if (l.size +| @as(i64, @intCast(line.len)) > l.limit and l.rotate()) {
                l.rotations +|= 1;
                var nbuf: [128]u8 = undefined;
                const ts2 = timestamp(l.io, nbuf[0..32]);
                const note = formatLine(&nbuf, ts2.len, "log rotated (over {d} bytes): previous entries are in portal.log.1", .{l.limit});
                l.write(note);
            }
        }
        l.write(line);
    }

    fn write(l: *Log, line: []const u8) void {
        const h = l.handle orelse return;
        var n: w.DWORD = 0;
        if (w.WriteFile(h, line.ptr, @intCast(line.len), &n, null) != 0) l.size +|= n;
    }
};

const FILE_SHARE_DELETE: w.DWORD = 0x4;

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
        yd.year,              md.month.numeric(),      @as(u32, md.day_index) + 1,
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

test "log rotates by size while running" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [512]u8 = undefined;
    const dir = try std.fmt.bufPrint(&pbuf, ".zig-cache\\tmp\\{s}", .{&tmp.sub_path});
    var fbuf: [600]u8 = undefined;
    const path = try std.fmt.bufPrint(&fbuf, "{s}\\portal.log", .{dir});
    var l = try Log.openLimit(std.testing.allocator, io, path, 400);
    defer l.close();
    for (0..40) |i| l.print("entry {d} padding padding padding", .{i});
    try std.testing.expect(l.rotations >= 2);
    const cur = try tmp.dir.readFileAlloc(io, "portal.log", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(cur);
    const old = try tmp.dir.readFileAlloc(io, "portal.log.1", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(old);
    try std.testing.expect(cur.len <= 400 + 128);
    try std.testing.expect(old.len <= 400 + 128);
    try std.testing.expect(std.mem.indexOf(u8, cur, "entry 39") != null);
    try std.testing.expect(std.mem.indexOf(u8, cur, "log rotated") != null);
}
