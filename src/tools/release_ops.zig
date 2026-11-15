//! The release folder's file operations, shared by portal-release
//! (`zig build release | mark-good | rollback`) and portal-setup (the
//! installer): the pointer files, history, the lock, the launchers in
//! `bin` and pruning. One implementation, so a folder the installer wrote
//! is one `zig build release`, `rollback` and `mark-good` keep working on,
//! and the other way round. Pure logic lives in releases_lib.zig.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const lib = @import("releases_lib.zig");
const w = @import("win32");

pub const Ctx = struct {
    gpa: Allocator,
    io: Io,
    env: *const std.process.Environ.Map,
    releases: []const u8,
    /// PORTAL_RELEASES_DIR is in effect (testing): the real data folder is
    /// not touched (no voice packages published).
    testing_override: bool = false,
    /// Progress lines (release's console). Off in the installer, which is
    /// a GUI program with nowhere to print.
    quiet: bool = false,

    pub fn path(ctx: Ctx, name: []const u8) ![]u8 {
        return std.fs.path.join(ctx.gpa, &.{ ctx.releases, name });
    }

    pub fn say(ctx: Ctx, comptime fmt: []const u8, args: anytype) void {
        if (!ctx.quiet) std.debug.print(fmt, args);
    }

    pub fn warn(ctx: Ctx, comptime fmt: []const u8, args: anytype) void {
        ctx.say("release: warning: " ++ fmt ++ "\n", args);
    }
};

// --------------------------------------------------------------- pointers

/// Owned, validated id from a pointer file, or null if missing/invalid.
pub fn readPointer(ctx: Ctx, name: []const u8) ?[]u8 {
    const p = ctx.path(name) catch return null;
    defer ctx.gpa.free(p);
    const contents = Io.Dir.cwd().readFileAlloc(ctx.io, p, ctx.gpa, .limited(lib.max_pointer_bytes)) catch return null;
    defer ctx.gpa.free(contents);
    const id = lib.parsePointer(contents) orelse return null;
    return ctx.gpa.dupe(u8, id) catch null;
}

/// Like readPointer, but tells a missing file apart from one that exists
/// and cannot be read. Owned contents (unvalidated) on success.
pub fn readPointerRaw(ctx: Ctx, name: []const u8) lib.PointerRead {
    const p = ctx.path(name) catch return .unreadable;
    defer ctx.gpa.free(p);
    const contents = Io.Dir.cwd().readFileAlloc(ctx.io, p, ctx.gpa, .limited(lib.max_pointer_bytes)) catch |err| return switch (err) {
        error.FileNotFound => .missing,
        else => .unreadable,
    };
    return .{ .contents = contents };
}

/// Holds `<releases>\release.lock` open with no sharing (and delete-on-
/// close) until the process exits, so two commands that change the
/// pointers (`release`, `mark-good`, `rollback`, the installer) cannot
/// share _staging or race on current.txt / known-good.txt. error.Busy if
/// another holds it; nothing has been changed then.
pub fn lock(ctx: Ctx) error{ Busy, LockFailed, OutOfMemory }!void {
    const p = try ctx.path(lib.lock_file);
    defer ctx.gpa.free(p);
    const p_w = std.unicode.wtf8ToWtf16LeAllocZ(ctx.gpa, p) catch return error.OutOfMemory;
    defer ctx.gpa.free(p_w);
    const h = w.validHandle(w.CreateFileW(p_w.ptr, w.GENERIC_READ | w.GENERIC_WRITE, 0, null, w.OPEN_ALWAYS, w.FILE_ATTRIBUTE_NORMAL | w.FILE_FLAG_DELETE_ON_CLOSE, null));
    if (h == null) return if (w.GetLastError() == 32) error.Busy else error.LockFailed;
    // Never closed: the handle (and lock) lasts until the process exits.
}

/// Atomic pointer update: write and flush a temp file, then
/// MoveFileEx(REPLACE_EXISTING | WRITE_THROUGH) over the pointer.
pub fn writePointer(ctx: Ctx, name: []const u8, id: []const u8) !void {
    if (!lib.isValidId(id)) return error.InvalidReleaseId;
    const gpa = ctx.gpa;
    const dest = try ctx.path(name);
    defer gpa.free(dest);
    const tmp = try std.fmt.allocPrint(gpa, "{s}.tmp", .{dest});
    defer gpa.free(tmp);
    {
        const f = try Io.Dir.cwd().createFile(ctx.io, tmp, .{});
        defer f.close(ctx.io);
        try f.writeStreamingAll(ctx.io, id);
        try f.sync(ctx.io);
    }
    try moveReplace(gpa, tmp, dest);
}

pub fn moveReplace(gpa: Allocator, from: []const u8, to: []const u8) !void {
    const from_w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, from);
    defer gpa.free(from_w);
    const to_w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, to);
    defer gpa.free(to_w);
    if (w.MoveFileExW(from_w.ptr, to_w.ptr, w.MOVEFILE_REPLACE_EXISTING | w.MOVEFILE_WRITE_THROUGH) == 0) return error.MoveFailed;
}

/// Plain rename (MoveFileEx without REPLACE_EXISTING), like PowerShell's
/// Rename-Item. Unlike std's rename, this succeeds on a running exe, which
/// the launcher swap relies on.
pub fn moveNoReplace(gpa: Allocator, from: []const u8, to: []const u8) !void {
    const from_w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, from);
    defer gpa.free(from_w);
    const to_w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, to);
    defer gpa.free(to_w);
    if (w.MoveFileExW(from_w.ptr, to_w.ptr, 0) == 0) return switch (w.GetLastError()) {
        2, 3 => error.FileNotFound,
        5 => error.AccessDenied,
        32 => error.SharingViolation,
        80, 183 => error.PathAlreadyExists,
        else => error.MoveFailed,
    };
}

pub fn appendHistory(ctx: Ctx, id: []const u8) !void {
    if (!lib.isValidId(id)) return error.InvalidReleaseId;
    const p = try ctx.path(lib.history_file);
    defer ctx.gpa.free(p);
    const f = try Io.Dir.cwd().createFile(ctx.io, p, .{ .truncate = false });
    defer f.close(ctx.io);
    const end = try f.length(ctx.io);
    var line_buf: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&line_buf, "{s}\r\n", .{id});
    try f.writePositionalAll(ctx.io, line, end);
    try f.sync(ctx.io);
}

pub fn isFile(io: Io, p: []const u8) bool {
    const st = Io.Dir.cwd().statFile(io, p, .{}) catch return false;
    return st.kind == .file;
}

pub fn isDir(io: Io, p: []const u8) bool {
    const st = Io.Dir.cwd().statFile(io, p, .{}) catch return false;
    return st.kind == .directory;
}

pub fn releaseExe(ctx: Ctx, id: []const u8) ![]u8 {
    std.debug.assert(lib.isValidId(id));
    return std.fs.path.join(ctx.gpa, &.{ ctx.releases, id, "portal.exe" });
}

// ------------------------------------------------------------------- time

pub const Now = struct {
    stamp_buf: [15]u8 = undefined,
    iso_buf: [33]u8 = undefined,
    stamp: []const u8 = "",
    iso: []const u8 = "",

    pub fn get(n: *Now) void {
        var utc: w.FILETIME = undefined;
        w.GetSystemTimeAsFileTime(&utc);
        var local: w.FILETIME = undefined;
        if (w.FileTimeToLocalFileTime(&utc, &local) == 0) local = utc;
        const t = lib.fromFileTime(local.toU64());
        n.stamp = lib.formatStamp(&n.stamp_buf, t);
        n.iso = lib.formatIso(&n.iso_buf, t, lib.utcOffsetMinutes(utc.toU64(), local.toU64()));
    }
};

// --------------------------------------------------------------- launcher

/// Installs the launchers: stage\bin\portal-launcher.exe (GUI subsystem)
/// as <bin_dir>\portal.exe, stage\bin\portal-launcher-console.exe as
/// portalctl.exe and portal-show.exe. An old launcher may be running (it
/// waits for its child), so it is renamed aside first, which Windows allows
/// for a running exe, then deleted if possible. Leftover *.old files are
/// cleaned up when no longer in use. Returns how many failed (each is
/// warned about; the previous launcher of that name, if any, still works).
pub fn installLauncher(ctx: Ctx, stage: []const u8, bin_dir: []const u8, stamp: []const u8) usize {
    cleanup: {
        Io.Dir.cwd().createDirPath(ctx.io, bin_dir) catch break :cleanup;
        var bin = Io.Dir.cwd().openDir(ctx.io, bin_dir, .{ .iterate = true }) catch break :cleanup;
        defer bin.close(ctx.io);
        cleanOldLaunchers(ctx.gpa, ctx.io, bin);
    }
    var failed: usize = 0;
    for (lib.release_exes) |exe| {
        installLauncherInner(ctx, stage, bin_dir, stamp, lib.launcherFor(exe), exe) catch |err| {
            ctx.warn("could not install the launcher {s} into {s}: {t}. The previous one (if any) still works.", .{ exe, bin_dir, err });
            failed += 1;
        };
    }
    return failed;
}

fn installLauncherInner(ctx: Ctx, stage: []const u8, bin_dir: []const u8, stamp: []const u8, launcher: []const u8, exe: []const u8) !void {
    const gpa = ctx.gpa;
    const io = ctx.io;
    const cwd = Io.Dir.cwd();
    const src = try std.fs.path.join(gpa, &.{ stage, "bin", launcher });
    defer gpa.free(src);
    if (!isFile(io, src)) return error.LauncherNotBuilt;

    try cwd.createDirPath(io, bin_dir);
    var bin = try cwd.openDir(io, bin_dir, .{ .iterate = true });
    defer bin.close(io);

    const dest = try std.fs.path.join(gpa, &.{ bin_dir, exe });
    defer gpa.free(dest);
    const old = try std.fmt.allocPrint(gpa, "{s}.{s}.old", .{ dest, stamp });
    defer gpa.free(old);
    var renamed = false;
    if (isFile(io, dest)) {
        try moveNoReplace(gpa, dest, old);
        renamed = true;
    }

    cwd.copyFile(src, bin, exe, io, .{}) catch |err| {
        if (renamed) moveNoReplace(gpa, old, dest) catch {};
        return err;
    };
    if (renamed) Io.Dir.cwd().deleteFile(io, old) catch {
        ctx.say("release: previous launcher is running; left as {s} (removed by a later release)\n", .{old});
    };
    ctx.say("release: launcher installed: {s}\n", .{dest});
}

fn cleanOldLaunchers(gpa: Allocator, io: Io, bin: Io.Dir) void {
    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }

    var iter = bin.iterate();
    while (iter.next(io) catch null) |e| {
        if (e.kind == .file and lib.isOldLauncherName(e.name)) {
            const copy = gpa.dupe(u8, e.name) catch return;
            names.append(gpa, copy) catch {
                gpa.free(copy);
                return;
            };
        }
    }
    for (names.items) |n| bin.deleteFile(io, n) catch {};
}

// ------------------------------------------------------------------ prune

/// Prunes old releases, but only when the known-good release is certain:
/// if known-good.txt exists but cannot be read or validated, deleting old
/// releases could delete the very release it names. Never fails: anything
/// that cannot be removed is reported and skipped. Returns the known-good
/// id it went by (owned) or null.
pub fn pruneGuarded(ctx: Ctx, current: []const u8) ?[]u8 {
    const kg_read = readPointerRaw(ctx, lib.known_good_file);
    defer if (kg_read == .contents) ctx.gpa.free(kg_read.contents);
    switch (lib.pruneGuard(kg_read)) {
        .skip => {
            ctx.warn("{s} exists but could not be read or is invalid: pruning skipped", .{lib.known_good_file});
            return null;
        },
        .prune => |k| {
            prune(ctx, current, k);
            return if (k) |id| ctx.gpa.dupe(u8, id) catch null else null;
        },
    }
}

/// Never fails: anything that cannot be removed is reported and skipped.
pub fn prune(ctx: Ctx, current: []const u8, known_good: ?[]const u8) void {
    pruneInner(ctx, current, known_good) catch |err| ctx.warn("pruning skipped: {t}", .{err});
}

fn pruneInner(ctx: Ctx, current: []const u8, known_good: ?[]const u8) !void {
    const gpa = ctx.gpa;
    const io = ctx.io;
    var root = try Io.Dir.cwd().openDir(io, ctx.releases, .{ .iterate = true });
    defer root.close(io);

    var names: std.ArrayList([]const u8) = .empty;
    defer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }
    var leftovers: std.ArrayList([]const u8) = .empty;
    defer {
        for (leftovers.items) |n| gpa.free(n);
        leftovers.deinit(gpa);
    }
    var iter = root.iterate();
    while (try iter.next(io)) |e| {
        if (e.kind != .directory) continue;
        if (lib.isValidId(e.name)) {
            try names.append(gpa, try gpa.dupe(u8, e.name));
        } else if (std.mem.endsWith(u8, e.name, lib.deleting_suffix) and
            lib.isValidId(e.name[0 .. e.name.len - lib.deleting_suffix.len]))
        {
            try leftovers.append(gpa, try gpa.dupe(u8, e.name));
        }
    }

    // Folders a previous prune renamed but could not finish deleting.
    for (leftovers.items) |n| {
        root.deleteTree(io, n) catch |err| {
            ctx.warn("could not finish deleting {s} ({t}); skipping", .{ n, err });
            continue;
        };
        ctx.say("release: removed leftover {s}\n", .{n});
    }

    const victims = try lib.selectPrune(gpa, names.items, current, known_good, lib.default_keep);
    defer gpa.free(victims);
    for (victims) |n| {
        std.debug.assert(lib.isValidId(n));
        const from = try ctx.path(n);
        defer gpa.free(from);
        const tmp = try std.fmt.allocPrint(gpa, "{s}" ++ lib.deleting_suffix, .{from});
        defer gpa.free(tmp);
        // Rename first, so a half-deleted folder never looks like a release.
        // This fails if a file inside is open without sharing.
        moveNoReplace(gpa, from, tmp) catch |err| {
            ctx.say("release: could not prune {s} (in use? {t}); skipping\n", .{ n, err });
            continue;
        };
        // Windows lets a folder be renamed while its portal.exe is running,
        // but not the running exe be deleted: delete it first and, if that
        // fails, put the release back untouched.
        const exe = try std.fs.path.join(gpa, &.{ tmp, "portal.exe" });
        defer gpa.free(exe);
        Io.Dir.cwd().deleteFile(io, exe) catch |err| switch (err) {
            error.FileNotFound => {},
            else => {
                moveNoReplace(gpa, tmp, from) catch |err2|
                    ctx.warn("could not restore {s} from {s} ({t})", .{ n, tmp, err2 });
                ctx.say("release: could not prune {s} (portal.exe in use? {t}); skipping\n", .{ n, err });
                continue;
            },
        };
        root.deleteTree(io, tmp) catch |err| {
            ctx.warn("pruned {s} but could not delete all of {s} ({t}); will retry next release", .{ n, tmp, err });
            continue;
        };
        ctx.say("release: pruned {s}\n", .{n});
    }
}
