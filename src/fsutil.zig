//! File helpers shared by every store under %LOCALAPPDATA%\Portal (device
//! list, sync subscriptions and publish store, TLS files, settings):
//! path joining, WTF-16 conversion, atomic replace, and the cross-process
//! lock with the locked read-modify-write built on both.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const w = @import("win32.zig");

/// `parts` joined with `\` into `buf`.
pub fn join(buf: []u8, parts: []const []const u8) error{NameTooLong}![]const u8 {
    var wr: Io.Writer = .fixed(buf);
    for (parts, 0..) |p, i| {
        if (i > 0) wr.writeAll("\\") catch return error.NameTooLong;
        wr.writeAll(p) catch return error.NameTooLong;
    }
    return wr.buffered();
}

/// Portal's data directory (%LOCALAPPDATA%\Portal) and paths inside it.
pub const DataDir = struct {
    dir: []const u8,

    /// `dir\parts[0]\parts[1]...` into `buf`.
    pub fn join(d: DataDir, buf: []u8, parts: []const []const u8) error{NameTooLong}![]const u8 {
        var wr: Io.Writer = .fixed(buf);
        wr.writeAll(d.dir) catch return error.NameTooLong;
        for (parts) |p| {
            wr.writeAll("\\") catch return error.NameTooLong;
            wr.writeAll(p) catch return error.NameTooLong;
        }
        return wr.buffered();
    }
};

/// A WTF-8 path or string as NUL-terminated WTF-16, for the W APIs.
/// Caller frees.
pub fn wide(gpa: Allocator, s: []const u8) error{ OutOfMemory, InvalidWtf8 }![:0]u16 {
    return std.unicode.wtf8ToWtf16LeAllocZ(gpa, s);
}

/// Replaces `final` with `data` atomically: written to a fresh temporary
/// file next to it, flushed to disk, then renamed over it
/// (MoveFileEx REPLACE_EXISTING | WRITE_THROUGH), so a reader or a crash
/// never sees an empty or partial file. The temporary file is removed if
/// the rename fails (error.ReplaceFailed).
pub fn writeAtomic(gpa: Allocator, io: Io, final: []const u8, data: []const u8) !void {
    var tb: [1100]u8 = undefined;
    var rnd: [6]u8 = undefined;
    io.random(&rnd);
    const tmp = std.fmt.bufPrint(&tb, "{s}.{x}.tmp", .{ final, &rnd }) catch return error.NameTooLong;
    {
        const f = try Io.Dir.cwd().createFile(io, tmp, .{ .exclusive = true });
        defer f.close(io);
        errdefer Io.Dir.cwd().deleteFile(io, tmp) catch {};
        try f.writeStreamingAll(io, data);
        try f.sync(io);
    }
    const a = try wide(gpa, tmp);
    defer gpa.free(a);
    const b = try wide(gpa, final);
    defer gpa.free(b);
    if (w.MoveFileExW(a.ptr, b.ptr, w.MOVEFILE_REPLACE_EXISTING | w.MOVEFILE_WRITE_THROUGH) == 0) {
        Io.Dir.cwd().deleteFile(io, tmp) catch {};
        return error.ReplaceFailed;
    }
}

/// An exclusive lock on a lock file, shared by every Portal process (the
/// running server and the `portalctl` commands). Taking it blocks until
/// the holder releases it (or exits: Windows drops the lock with the
/// process); there is no retry loop and no timer.
///
/// Cancelation: the wait is an Io cancelation point. A cancel that lands
/// here is re-armed before error.Canceled is returned: callers in the web
/// server turn store errors into HTTP responses, so without re-arming the
/// request would be consumed and the connection's next read would block
/// forever, with the supervisor stuck in `worker.cancel` (a pre-auth DoS
/// that leaks the connection slot).
pub const FileLock = struct {
    file: Io.File,

    pub fn acquire(io: Io, path: []const u8) !FileLock {
        const f = Io.Dir.cwd().createFile(io, path, .{ .truncate = false }) catch |err| return switch (err) {
            // An older Portal opens lock files exclusively (no sharing).
            error.FileBusy => error.LockBusy,
            error.Canceled => rearm(io),
            else => err,
        };
        errdefer f.close(io);
        f.lock(io, .exclusive) catch |err| return switch (err) {
            error.Canceled => rearm(io),
            else => err,
        };
        return .{ .file = f };
    }

    pub fn release(l: FileLock, io: Io) void {
        l.file.unlock(io);
        l.file.close(io);
    }

    fn rearm(io: Io) error{Canceled} {
        io.recancel();
        return error.Canceled;
    }
};

/// Locked read-modify-write of the text file `path`, under the lock file
/// `lock_path`: `edit(ctx, old, out)` gets the current contents (null if
/// the file does not exist; at most `limit` bytes) and appends the new
/// contents to `out`, returning whether to replace the file with them
/// (atomically, see `writeAtomic`).
pub fn update(gpa: Allocator, io: Io, lock_path: []const u8, path: []const u8, limit: usize, ctx: anytype, comptime edit: anytype) !void {
    const lock = try FileLock.acquire(io, lock_path);
    defer lock.release(io);
    const old: ?[]u8 = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(limit)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (old) |o| gpa.free(o);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    if (!try edit(ctx, old, &out)) return;
    try writeAtomic(gpa, io, path, out.items);
}

/// A directory change notification (FindFirstChangeNotification): its
/// handle is signalled when a file (or, with `dirs`, a folder) in the
/// directory is created, renamed or deleted. Callers wait on `h` together
/// with their other events (win32.WaitForMultipleObjects), so watching
/// costs no wakeups. A watch that cannot be made or re-armed is an error
/// the caller reports; nobody falls back to polling.
pub const DirWatch = struct {
    h: w.HANDLE,

    pub const Options = struct {
        /// Watch the whole tree below the directory.
        subtree: bool = false,
        /// Also report folders created, renamed or deleted.
        dirs: bool = false,
    };

    pub fn open(gpa: Allocator, dir: []const u8, opts: Options) !DirWatch {
        const dir_w = try wide(gpa, dir);
        defer gpa.free(dir_w);
        const filter = w.FILE_NOTIFY_CHANGE_FILE_NAME | (if (opts.dirs) w.FILE_NOTIFY_CHANGE_DIR_NAME else 0);
        const h = w.validHandle(w.FindFirstChangeNotificationW(dir_w.ptr, @intFromBool(opts.subtree), filter)) orelse
            return error.WatchFailed;
        return .{ .h = h };
    }

    /// Re-arms after a wake. Call before re-reading what is watched, so a
    /// change made meanwhile signals again.
    pub fn rearm(d: *DirWatch) error{WatchFailed}!void {
        if (w.FindNextChangeNotification(d.h) == 0) return error.WatchFailed;
    }

    pub fn close(d: *DirWatch) void {
        _ = w.FindCloseChangeNotification(d.h);
    }
};

// -------------------------------------------------------------------- tests

const testing = std.testing;

fn tmpPath(tmp: *testing.TmpDir, buf: []u8, name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache\\tmp\\{s}\\{s}", .{ &tmp.sub_path, name });
}

test "join" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("a\\b\\c", try join(&buf, &.{ "a", "b", "c" }));
    try testing.expectEqualStrings("a", try join(&buf, &.{"a"}));
    var small: [3]u8 = undefined;
    try testing.expectError(error.NameTooLong, join(&small, &.{ "ab", "c" }));
}

test "writeAtomic replaces and leaves no temporary file" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var pb: [256]u8 = undefined;
    const p = try tmpPath(&tmp, &pb, "f.txt");
    try writeAtomic(testing.allocator, io, p, "one");
    try writeAtomic(testing.allocator, io, p, "two");
    var rb: [16]u8 = undefined;
    try testing.expectEqualStrings("two", try tmp.dir.readFile(io, "f.txt", &rb));
    var it = tmp.dir.iterate();
    while (try it.next(io)) |e| try testing.expect(!std.mem.endsWith(u8, e.name, ".tmp"));
}

test "update: read-modify-write under the lock" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var lb: [256]u8 = undefined;
    var pb: [256]u8 = undefined;
    const lock = try tmpPath(&tmp, &lb, "x.lock");
    const path = try tmpPath(&tmp, &pb, "x.txt");
    const Edit = struct {
        fn append(gpa: Allocator, old: ?[]const u8, out: *std.ArrayList(u8)) !bool {
            try out.appendSlice(gpa, old orelse "");
            try out.append(gpa, 'x');
            return true;
        }
    };
    try update(testing.allocator, io, lock, path, 1024, testing.allocator, Edit.append);
    try update(testing.allocator, io, lock, path, 1024, testing.allocator, Edit.append);
    var rb: [16]u8 = undefined;
    try testing.expectEqualStrings("xx", try tmp.dir.readFile(io, "x.txt", &rb));
}

test "DirWatch: a rename in the directory signals it" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db: [256]u8 = undefined;
    const dir = try std.fmt.bufPrint(&db, ".zig-cache\\tmp\\{s}", .{&tmp.sub_path});
    var dw = try DirWatch.open(testing.allocator, dir, .{});
    defer dw.close();
    try testing.expectEqual(w.WAIT_TIMEOUT, w.WaitForSingleObject(dw.h, 0));
    var pb: [256]u8 = undefined;
    try writeAtomic(testing.allocator, io, try join(&pb, &.{ dir, "a.txt" }), "x");
    try testing.expectEqual(w.WAIT_OBJECT_0, w.WaitForSingleObject(dw.h, 5000));
    try dw.rearm();
}

test "FileLock: waits for the holder, without polling" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var lb: [256]u8 = undefined;
    const path = try tmpPath(&tmp, &lb, "w.lock");
    const held = try FileLock.acquire(io, path);
    const Task = struct {
        fn run(t_io: Io, p: []const u8, got: *std.atomic.Value(bool)) !void {
            const l = try FileLock.acquire(t_io, p);
            got.store(true, .release);
            l.release(t_io);
        }
    };
    var got: std.atomic.Value(bool) = .init(false);
    var fut = io.concurrent(Task.run, .{ io, path, &got }) catch return error.SkipZigTest;
    try io.sleep(.fromMilliseconds(50), .awake);
    try testing.expect(!got.load(.acquire)); // still blocked on the held lock
    held.release(io);
    try fut.await(io);
    try testing.expect(got.load(.acquire));
}

test "FileLock: a cancel during the wait is returned and stays armed" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var lb: [256]u8 = undefined;
    const path = try tmpPath(&tmp, &lb, "c.lock");
    const held = try FileLock.acquire(io, path);
    defer held.release(io);

    const Task = struct {
        /// Like the web handlers: the lock error is turned into something
        /// else (a 500), then the task carries on to its next blocking call.
        fn run(t_io: Io, p: []const u8, started: *Io.Event) struct { lock: anyerror!void, next: Io.Cancelable!void } {
            started.set(t_io);
            const r: anyerror!void = if (FileLock.acquire(t_io, p)) |l| l.release(t_io) else |err| err;
            // The next cancelation point must still see the cancel.
            const next = t_io.sleep(.fromSeconds(30), .awake);
            return .{ .lock = r, .next = next };
        }
    };
    var started: Io.Event = .unset;
    var fut = io.concurrent(Task.run, .{ io, path, &started }) catch return error.SkipZigTest;
    try started.wait(io);
    try io.sleep(.fromMilliseconds(30), .awake); // let it block on the lock
    const res = fut.cancel(io);
    try testing.expectError(error.Canceled, res.lock);
    try testing.expectError(error.Canceled, res.next);
}
