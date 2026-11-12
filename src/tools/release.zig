//! portal-release: build, test and promote Portal releases, keeping a
//! known-good fallback. Replaces the old scripts\*.ps1.
//!
//!   portal-release release [--zig PATH] [--repo DIR]
//!   portal-release mark-good
//!   portal-release rollback
//!   portal-release status
//!
//! Normally run through `zig build release|mark-good|rollback|release-status`,
//! which passes --zig (the compiler running the build) and --repo.
//!
//! Releases live OUTSIDE the repo (so `git clean` can't delete the safety copy):
//!     %LOCALAPPDATA%\Portal\releases\
//!         20261111-183000_zig-0.18.0-dev.4+5a23bf4b2\
//!             portal.exe, portal.pdb, BUILD-INFO.txt, source\
//!         current.txt     release the launcher runs
//!         known-good.txt  release you confirmed works (mark-good)
//!         history.txt     every promotion, newest last
//!     %LOCALAPPDATA%\Portal\bin\portal.exe   the launcher (put bin on PATH)
//!
//! PORTAL_RELEASES_DIR (absolute path) overrides the releases directory, for
//! testing; the launcher is then installed to its sibling `bin` directory.
//!
//! Only a build that passes `zig build test` (unit tests + full exe compile
//! in Debug and ReleaseSafe) is promoted. A running portal.exe is never
//! overwritten, pointer files are replaced atomically, and pruning never
//! fails a release.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const lib = @import("releases_lib.zig");
const w = @import("win32_tools.zig");

const usage =
    \\portal-release - build, test and promote Portal releases
    \\
    \\Usage:
    \\  portal-release release [--zig PATH] [--repo DIR]
    \\      Run `zig build test`, build ReleaseSafe, check `portal version`,
    \\      store it as a new release, make it current, install the launcher
    \\      (portal.exe in the `bin` folder next to the releases folder) and
    \\      prune old releases. On any failure before promotion, the current
    \\      release is left untouched.
    \\  portal-release mark-good
    \\      Record the current release as known-good (never pruned).
    \\  portal-release rollback
    \\      Point current back at known-good. Running it twice is harmless.
    \\  portal-release status
    \\      Show current, known-good, history and releases on disk.
    \\
    \\Releases: %LOCALAPPDATA%\Portal\releases, or PORTAL_RELEASES_DIR
    \\(absolute path; for testing only).
    \\
;

const Ctx = struct {
    gpa: Allocator,
    io: Io,
    env: *const std.process.Environ.Map,
    releases: []const u8,

    fn path(ctx: Ctx, name: []const u8) ![]u8 {
        return std.fs.path.join(ctx.gpa, &.{ ctx.releases, name });
    }
};

pub fn main(init: std.process.Init) !void {
    if (builtin.os.tag != .windows) @compileError("portal-release supports Windows only.");
    const gpa = init.gpa;
    const io = init.io;
    const env = init.environ_map;

    var args_list: std.ArrayList([]const u8) = .empty;
    defer args_list.deinit(gpa);
    var it: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |a| try args_list.append(gpa, a);
    const args = args_list.items;
    if (args.len == 0) {
        std.debug.print(usage, .{});
        std.process.exit(2);
    }
    const cmd = args[0];

    const override = env.get("PORTAL_RELEASES_DIR");
    const releases = lib.releasesRoot(gpa, override, env.get("LOCALAPPDATA")) catch |err| switch (err) {
        error.NoLocalAppData => fatal(cmd, "LOCALAPPDATA is not set", .{}),
        error.RelativeOverride => fatal(cmd, "PORTAL_RELEASES_DIR must be an absolute path", .{}),
        error.OutOfMemory => return err,
    };
    defer gpa.free(releases);
    if (override != null and override.?.len > 0)
        std.debug.print("{s}: note: PORTAL_RELEASES_DIR override in effect: {s}\n", .{ cmd, releases });
    Io.Dir.cwd().createDirPath(io, releases) catch |err|
        fatal(cmd, "cannot create {s}: {t}", .{ releases, err });

    const ctx: Ctx = .{ .gpa = gpa, .io = io, .env = env, .releases = releases };

    if (std.mem.eql(u8, cmd, "release")) {
        var zig_arg: ?[]const u8 = null;
        var repo_arg: ?[]const u8 = null;
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            const a = args[i];
            if (optValue(args, &i, a, "--zig")) |v| {
                zig_arg = v;
            } else if (optValue(args, &i, a, "--repo")) |v| {
                repo_arg = v;
            } else fatal(cmd, "unknown option '{s}'", .{a});
        }
        return cmdRelease(ctx, zig_arg, repo_arg);
    }
    if (args.len > 1) fatal(cmd, "unexpected argument '{s}'", .{args[1]});
    if (std.mem.eql(u8, cmd, "mark-good")) return cmdMarkGood(ctx);
    if (std.mem.eql(u8, cmd, "rollback")) return cmdRollback(ctx);
    if (std.mem.eql(u8, cmd, "status")) return cmdStatus(ctx);
    std.debug.print(usage, .{});
    std.process.exit(2);
}

/// Accepts `--name value` and `--name=value`.
fn optValue(args: []const []const u8, i: *usize, a: []const u8, comptime name: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, a, name ++ "=")) return a[name.len + 1 ..];
    if (!std.mem.eql(u8, a, name)) return null;
    if (i.* + 1 >= args.len) fatal("release", name ++ " needs a value", .{});
    i.* += 1;
    return args[i.*];
}

fn fatal(cmd: []const u8, comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("{s}: " ++ fmt ++ "\n", .{cmd} ++ args);
    std.process.exit(1);
}

/// Failure before promotion: current.txt has not been touched.
fn failRelease(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("release: " ++ fmt ++ "\n", args);
    std.debug.print("release: current release left untouched.\n", .{});
    std.process.exit(1);
}

fn warn(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("release: warning: " ++ fmt ++ "\n", args);
}

// --------------------------------------------------------------- pointers

/// Owned, validated id from a pointer file, or null if missing/invalid.
fn readPointer(ctx: Ctx, name: []const u8) ?[]u8 {
    const p = ctx.path(name) catch return null;
    defer ctx.gpa.free(p);
    const contents = Io.Dir.cwd().readFileAlloc(ctx.io, p, ctx.gpa, .limited(lib.max_pointer_bytes)) catch return null;
    defer ctx.gpa.free(contents);
    const id = lib.parsePointer(contents) orelse return null;
    return ctx.gpa.dupe(u8, id) catch null;
}

/// Atomic pointer update: write and flush a temp file, then
/// MoveFileEx(REPLACE_EXISTING | WRITE_THROUGH) over the pointer.
fn writePointer(ctx: Ctx, name: []const u8, id: []const u8) !void {
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

fn moveReplace(gpa: Allocator, from: []const u8, to: []const u8) !void {
    const from_w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, from);
    defer gpa.free(from_w);
    const to_w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, to);
    defer gpa.free(to_w);
    if (w.MoveFileExW(from_w.ptr, to_w.ptr, w.MOVEFILE_REPLACE_EXISTING | w.MOVEFILE_WRITE_THROUGH) == 0) {
        std.debug.print("MoveFileExW({s} -> {s}) failed, error {d}\n", .{ from, to, w.GetLastError() });
        return error.MoveFailed;
    }
}

/// Plain rename (MoveFileEx without REPLACE_EXISTING), like PowerShell's
/// Rename-Item. Unlike std's rename, this succeeds on a running exe, which
/// the launcher swap relies on.
fn moveNoReplace(gpa: Allocator, from: []const u8, to: []const u8) !void {
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

fn appendHistory(ctx: Ctx, id: []const u8) !void {
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

fn isFile(io: Io, p: []const u8) bool {
    const st = Io.Dir.cwd().statFile(io, p, .{}) catch return false;
    return st.kind == .file;
}

fn isDir(io: Io, p: []const u8) bool {
    const st = Io.Dir.cwd().statFile(io, p, .{}) catch return false;
    return st.kind == .directory;
}

fn releaseExe(ctx: Ctx, id: []const u8) ![]u8 {
    std.debug.assert(lib.isValidId(id));
    return std.fs.path.join(ctx.gpa, &.{ ctx.releases, id, "portal.exe" });
}

// ---------------------------------------------------------------- process

/// Searches PATH (absolute entries only; never the current directory).
fn findOnPath(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, exe_name: []const u8) ?[]u8 {
    const path_var = env.get("PATH") orelse return null;
    var parts = std.mem.splitScalar(u8, path_var, ';');
    while (parts.next()) |raw| {
        const dir = std.mem.trim(u8, raw, " \"");
        if (dir.len == 0 or !std.fs.path.isAbsolute(dir)) continue;
        const candidate = std.fs.path.join(gpa, &.{ dir, exe_name }) catch return null;
        if (isFile(io, candidate)) return candidate;
        gpa.free(candidate);
    }
    return null;
}

/// Waits for the child and returns its full 32-bit exit code (std's Term
/// truncates it to u8, which could turn 256 into "success").
fn waitExact(io: Io, child: *std.process.Child) !u32 {
    const h: w.HANDLE = @ptrCast(child.id.?);
    if (w.WaitForSingleObject(h, w.INFINITE) == w.WAIT_FAILED) return error.WaitFailed;
    var code: w.DWORD = 1;
    const ok = w.GetExitCodeProcess(h, &code) != 0;
    _ = try child.wait(io);
    if (!ok) return error.NoExitCode;
    return code;
}

fn runInherit(io: Io, argv: []const []const u8, cwd: []const u8) !u32 {
    var child = try std.process.spawn(io, .{ .argv = argv, .cwd = .{ .path = cwd } });
    errdefer child.kill(io);
    return waitExact(io, &child);
}

const Captured = struct {
    code: u32,
    stdout: []u8,
    stderr: []u8,

    fn deinit(c: Captured, gpa: Allocator) void {
        gpa.free(c.stdout);
        gpa.free(c.stderr);
    }
};

fn runCapture(gpa: Allocator, io: Io, argv: []const []const u8, cwd: []const u8) !Captured {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = .{ .path = cwd },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
        .create_no_window = true,
    });
    defer child.kill(io);

    var mr_buf: Io.File.MultiReader.Buffer(2) = undefined;
    var mr: Io.File.MultiReader = undefined;
    mr.init(gpa, io, mr_buf.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer mr.deinit();
    try mr.fillRemaining(.none);
    try mr.checkAnyError();
    const code = try waitExact(io, &child);
    const out = try mr.toOwnedSlice(0);
    errdefer gpa.free(out);
    const err_out = try mr.toOwnedSlice(1);
    return .{ .code = code, .stdout = out, .stderr = err_out };
}

// ------------------------------------------------------------------- time

const Now = struct {
    stamp_buf: [15]u8 = undefined,
    iso_buf: [33]u8 = undefined,
    stamp: []const u8 = "",
    iso: []const u8 = "",

    fn get(n: *Now) void {
        var utc: w.FILETIME = undefined;
        w.GetSystemTimeAsFileTime(&utc);
        var local: w.FILETIME = undefined;
        if (w.FileTimeToLocalFileTime(&utc, &local) == 0) local = utc;
        const t = lib.fromFileTime(local.toU64());
        n.stamp = lib.formatStamp(&n.stamp_buf, t);
        n.iso = lib.formatIso(&n.iso_buf, t, lib.utcOffsetMinutes(utc.toU64(), local.toU64()));
    }
};

// ---------------------------------------------------------------- release

fn cmdRelease(ctx: Ctx, zig_arg: ?[]const u8, repo_arg: ?[]const u8) !void {
    const gpa = ctx.gpa;
    const io = ctx.io;

    const repo = Io.Dir.cwd().realPathFileAlloc(io, repo_arg orelse ".", gpa) catch |err|
        failRelease("cannot resolve repo directory '{s}': {t}", .{ repo_arg orelse ".", err });
    defer gpa.free(repo);
    {
        const bz = try std.fs.path.join(gpa, &.{ repo, "build.zig" });
        defer gpa.free(bz);
        if (!isFile(io, bz)) failRelease("{s} is not the Portal repo (no build.zig); pass --repo", .{repo});
    }

    const zig_exe: []u8 = if (zig_arg) |z| blk: {
        if (!std.fs.path.isAbsolute(z) or !isFile(io, z)) failRelease("--zig '{s}' is not an absolute path to a file", .{z});
        break :blk try gpa.dupe(u8, z);
    } else findOnPath(gpa, io, ctx.env, "zig.exe") orelse failRelease("zig not found on PATH", .{});
    defer gpa.free(zig_exe);

    const zig_version = blk: {
        const r = runCapture(gpa, io, &.{ zig_exe, "version" }, repo) catch |err|
            failRelease("cannot run {s}: {t}", .{ zig_exe, err });
        defer r.deinit(gpa);
        if (r.code != 0) failRelease("`zig version` failed with exit code {d}", .{r.code});
        break :blk try gpa.dupe(u8, std.mem.trim(u8, r.stdout, " \t\r\n"));
    };
    defer gpa.free(zig_version);
    std.debug.print("release: using zig {s} ({s})\n", .{ zig_version, zig_exe });

    std.debug.print("release: running tests (unit tests + full compile)...\n", .{});
    {
        const code = runInherit(io, &.{ zig_exe, "build", "test", "--summary", "all" }, repo) catch |err|
            failRelease("cannot run zig build test: {t}", .{err});
        if (code != 0) failRelease("tests failed with zig {s} (exit code {d})", .{ zig_version, code });
    }

    var now: Now = .{};
    now.get();
    var id_buf: [256]u8 = undefined;
    const id = lib.makeId(&id_buf, now.stamp, zig_version) catch
        failRelease("unexpected release id '{s}_zig-{s}'", .{ now.stamp, zig_version });
    const dest = try ctx.path(id);
    defer gpa.free(dest);
    if (Io.Dir.cwd().statFile(io, dest, .{})) |_| {
        failRelease("release {s} already exists; wait a second and retry", .{id});
    } else |_| {}
    const stage = try ctx.path(lib.staging_dir);
    defer gpa.free(stage);
    Io.Dir.cwd().deleteTree(io, stage) catch |err| failRelease("cannot clear {s}: {t}", .{ stage, err });

    std.debug.print("release: building ReleaseSafe...\n", .{});
    {
        const code = runInherit(io, &.{ zig_exe, "build", "-Doptimize=ReleaseSafe", "--prefix", stage }, repo) catch |err|
            failRelease("cannot run zig build: {t}", .{err});
        if (code != 0) failRelease("build failed with zig {s} (exit code {d})", .{ zig_version, code });
    }

    const staged_exe = try std.fs.path.join(gpa, &.{ stage, "bin", "portal.exe" });
    defer gpa.free(staged_exe);
    const version_out = blk: {
        const r = runCapture(gpa, io, &.{ staged_exe, "version" }, repo) catch |err|
            failRelease("new binary does not run: {t}", .{err});
        defer r.deinit(gpa);
        // Same as `2>&1`: portal prints its version on stderr.
        const both = try std.mem.concat(gpa, u8, &.{ r.stdout, r.stderr });
        defer gpa.free(both);
        const trimmed = std.mem.trim(u8, both, " \t\r\n");
        if (r.code != 0) failRelease("new binary does not run (exit code {d}): {s}", .{ r.code, trimmed });
        break :blk try gpa.dupe(u8, trimmed);
    };
    defer gpa.free(version_out);

    const git_desc = try gitDescribe(ctx, repo);
    defer gpa.free(git_desc);

    populateRelease(ctx, repo, stage, dest, .{
        .portal = version_out,
        .zig_version = zig_version,
        .zig_path = zig_exe,
        .git = git_desc,
        .built = now.iso,
        .sha256_hex = "",
    }) catch |err| {
        Io.Dir.cwd().deleteTree(io, dest) catch {};
        failRelease("could not store release {s}: {t}", .{ id, err });
    };

    // ---- promotion: from here on the new release is live; later problems
    // are warnings, never a failed release.
    writePointer(ctx, lib.current_file, id) catch |err| {
        Io.Dir.cwd().deleteTree(io, dest) catch {};
        failRelease("could not update {s}: {t}", .{ lib.current_file, err });
    };
    appendHistory(ctx, id) catch |err| warn("could not append to {s}: {t}", .{ lib.history_file, err });

    const bin_dir = try lib.launcherBinDir(gpa, ctx.releases);
    defer gpa.free(bin_dir);
    installLauncher(ctx, stage, bin_dir, now.stamp);
    Io.Dir.cwd().deleteTree(io, stage) catch |err| warn("could not remove {s}: {t}", .{ stage, err });

    const kg = readPointer(ctx, lib.known_good_file);
    defer if (kg) |k| gpa.free(k);
    prune(ctx, id, kg);

    std.debug.print("release: promoted {s}\n", .{id});
    if (kg) |k| {
        std.debug.print("release: known-good fallback is {s}\n", .{k});
    } else {
        std.debug.print("release: no known-good release yet. After confirming this one works end to end, run `zig build mark-good`\n", .{});
    }
    if (!pathListContains(ctx.env.get("PATH") orelse "", bin_dir))
        std.debug.print("release: add {s} to your PATH to run `portal`.\n", .{bin_dir});
    std.debug.print("release: restart any running portal to pick it up.\n", .{});
}

fn pathListContains(path_var: []const u8, dir: []const u8) bool {
    var parts = std.mem.splitScalar(u8, path_var, ';');
    while (parts.next()) |raw| {
        const p = std.mem.trimEnd(u8, std.mem.trim(u8, raw, " \""), "\\/");
        if (std.ascii.eqlIgnoreCase(p, dir)) return true;
    }
    return false;
}

fn gitDescribe(ctx: Ctx, repo: []const u8) ![]u8 {
    const gpa = ctx.gpa;
    const git = findOnPath(gpa, ctx.io, ctx.env, "git.exe") orelse return lib.gitDescription(gpa, null, null);
    defer gpa.free(git);
    const head = runCapture(gpa, ctx.io, &.{ git, "-C", repo, "rev-parse", "HEAD" }, repo) catch
        return lib.gitDescription(gpa, null, null);
    defer head.deinit(gpa);
    if (head.code != 0) return lib.gitDescription(gpa, null, null);
    const status = runCapture(gpa, ctx.io, &.{ git, "-C", repo, "status", "--porcelain" }, repo) catch
        return lib.gitDescription(gpa, head.stdout, null);
    defer status.deinit(gpa);
    return lib.gitDescription(gpa, head.stdout, if (status.code == 0) status.stdout else null);
}

/// Creates `dest` with portal.exe, portal.pdb, source\ and BUILD-INFO.txt.
fn populateRelease(ctx: Ctx, repo: []const u8, stage: []const u8, dest: []const u8, info_in: lib.BuildInfo) !void {
    const gpa = ctx.gpa;
    const io = ctx.io;
    const cwd = Io.Dir.cwd();
    try cwd.createDir(io, dest, .default_dir);

    const stage_bin = try std.fs.path.join(gpa, &.{ stage, "bin" });
    defer gpa.free(stage_bin);
    var stage_dir = try cwd.openDir(io, stage_bin, .{});
    defer stage_dir.close(io);
    var dest_dir = try cwd.openDir(io, dest, .{});
    defer dest_dir.close(io);

    try stage_dir.copyFile("portal.exe", dest_dir, "portal.exe", io, .{});
    if (stage_dir.statFile(io, "portal.pdb", .{})) |_| {
        try stage_dir.copyFile("portal.pdb", dest_dir, "portal.pdb", io, .{});
    } else |_| {}

    var repo_dir = try cwd.openDir(io, repo, .{});
    defer repo_dir.close(io);
    try dest_dir.createDirPath(io, "source\\src");
    var src_dest = try dest_dir.openDir(io, "source", .{});
    defer src_dest.close(io);
    try copyTree(gpa, io, repo_dir, "src", src_dest, "src");
    try repo_dir.copyFile("build.zig", src_dest, "build.zig", io, .{});
    try repo_dir.copyFile("build.zig.zon", src_dest, "build.zig.zon", io, .{});

    const exe_bytes = try dest_dir.readFileAlloc(io, "portal.exe", gpa, .limited(1 << 30));
    defer gpa.free(exe_bytes);
    const hash = lib.sha256Hex(exe_bytes);
    var info = info_in;
    info.sha256_hex = &hash;
    const text = try lib.formatBuildInfo(gpa, info);
    defer gpa.free(text);
    try dest_dir.writeFile(io, .{ .sub_path = "BUILD-INFO.txt", .data = text });
}

fn copyTree(gpa: Allocator, io: Io, from_parent: Io.Dir, from_sub: []const u8, to_parent: Io.Dir, to_sub: []const u8) !void {
    var from = try from_parent.openDir(io, from_sub, .{ .iterate = true });
    defer from.close(io);
    try to_parent.createDirPath(io, to_sub);
    var to = try to_parent.openDir(io, to_sub, .{});
    defer to.close(io);
    var walker = try from.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |e| switch (e.kind) {
        .directory => try to.createDirPath(io, e.path),
        else => try from.copyFile(e.path, to, e.path, io, .{}),
    };
}

// --------------------------------------------------------------- launcher

/// Installs stage\bin\portal-launcher.exe as <bin_dir>\portal.exe. The old
/// launcher may be running (it waits for portal.exe), so it is renamed
/// aside first, which Windows allows for a running exe, then deleted if
/// possible. Leftover *.old files are cleaned up when no longer in use.
fn installLauncher(ctx: Ctx, stage: []const u8, bin_dir: []const u8, stamp: []const u8) void {
    installLauncherInner(ctx, stage, bin_dir, stamp) catch |err|
        warn("could not install the launcher into {s}: {t}. The previous launcher (if any) still works.", .{ bin_dir, err });
}

fn installLauncherInner(ctx: Ctx, stage: []const u8, bin_dir: []const u8, stamp: []const u8) !void {
    const gpa = ctx.gpa;
    const io = ctx.io;
    const cwd = Io.Dir.cwd();
    const src = try std.fs.path.join(gpa, &.{ stage, "bin", "portal-launcher.exe" });
    defer gpa.free(src);
    if (!isFile(io, src)) return error.LauncherNotBuilt;

    try cwd.createDirPath(io, bin_dir);
    var bin = try cwd.openDir(io, bin_dir, .{ .iterate = true });
    defer bin.close(io);
    cleanOldLaunchers(gpa, io, bin);

    const dest = try std.fs.path.join(gpa, &.{ bin_dir, "portal.exe" });
    defer gpa.free(dest);
    const old = try std.fmt.allocPrint(gpa, "{s}.{s}.old", .{ dest, stamp });
    defer gpa.free(old);
    var renamed = false;
    if (isFile(io, dest)) {
        try moveNoReplace(gpa, dest, old);
        renamed = true;
    }

    cwd.copyFile(src, bin, "portal.exe", io, .{}) catch |err| {
        if (renamed) moveNoReplace(gpa, old, dest) catch {};
        return err;
    };
    if (renamed) Io.Dir.cwd().deleteFile(io, old) catch {
        std.debug.print("release: previous launcher is running; left as {s} (removed by a later release)\n", .{old});
    };
    std.debug.print("release: launcher installed: {s}\n", .{dest});
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

/// Never fails: anything that cannot be removed is reported and skipped.
fn prune(ctx: Ctx, current: []const u8, known_good: ?[]const u8) void {
    pruneInner(ctx, current, known_good) catch |err| warn("pruning skipped: {t}", .{err});
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
            warn("could not finish deleting {s} ({t}); skipping", .{ n, err });
            continue;
        };
        std.debug.print("release: removed leftover {s}\n", .{n});
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
            std.debug.print("release: could not prune {s} (in use? {t}); skipping\n", .{ n, err });
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
                    warn("could not restore {s} from {s} ({t})", .{ n, tmp, err2 });
                std.debug.print("release: could not prune {s} (portal.exe in use? {t}); skipping\n", .{ n, err });
                continue;
            },
        };
        root.deleteTree(io, tmp) catch |err| {
            warn("pruned {s} but could not delete all of {s} ({t}); will retry next release", .{ n, tmp, err });
            continue;
        };
        std.debug.print("release: pruned {s}\n", .{n});
    }
}

fn cmdMarkGood(ctx: Ctx) !void {
    const cur = readPointer(ctx, lib.current_file) orelse fatal("mark-good", "no valid current release.", .{});
    defer ctx.gpa.free(cur);
    const exe = try releaseExe(ctx, cur);
    defer ctx.gpa.free(exe);
    if (!isFile(ctx.io, exe)) fatal("mark-good", "{s} has no portal.exe.", .{cur});
    writePointer(ctx, lib.known_good_file, cur) catch |err|
        fatal("mark-good", "could not write {s}: {t}", .{ lib.known_good_file, err });
    std.debug.print("mark-good: known-good is now {s}\n", .{cur});
}

fn cmdRollback(ctx: Ctx) !void {
    const kg = readPointer(ctx, lib.known_good_file) orelse
        fatal("rollback", "no known-good release recorded (run `zig build mark-good` on a working release).", .{});
    defer ctx.gpa.free(kg);
    const exe = try releaseExe(ctx, kg);
    defer ctx.gpa.free(exe);
    if (!isFile(ctx.io, exe)) fatal("rollback", "known-good {s} is missing its portal.exe.", .{kg});
    const cur = readPointer(ctx, lib.current_file);
    defer if (cur) |c| ctx.gpa.free(c);
    if (cur) |c| if (std.mem.eql(u8, c, kg)) {
        std.debug.print("rollback: already on known-good {s}.\n", .{kg});
        return;
    };
    writePointer(ctx, lib.current_file, kg) catch |err|
        fatal("rollback", "could not write {s}: {t}", .{ lib.current_file, err });
    std.debug.print("rollback: current is now known-good {s} (was {s}). Restart portal to use it.\n", .{ kg, cur orelse "none" });
}

fn cmdStatus(ctx: Ctx) !void {
    const gpa = ctx.gpa;
    const io = ctx.io;
    var buf: [4096]u8 = undefined;
    var fw = Io.File.stdout().writer(io, &buf);
    const out = &fw.interface;

    const cur = readPointer(ctx, lib.current_file);
    defer if (cur) |c| gpa.free(c);
    const kg = readPointer(ctx, lib.known_good_file);
    defer if (kg) |k| gpa.free(k);

    try out.print("releases:   {s}\n", .{ctx.releases});
    try printPointer(ctx, out, "current:   ", cur);
    try printPointer(ctx, out, "known-good:", kg);

    const bin_dir = try lib.launcherBinDir(gpa, ctx.releases);
    defer gpa.free(bin_dir);
    const launcher = try std.fs.path.join(gpa, &.{ bin_dir, "portal.exe" });
    defer gpa.free(launcher);
    try out.print("launcher:   {s}{s}\n", .{ launcher, if (isFile(io, launcher)) "" else "  (not installed)" });

    try out.print("\nhistory (oldest first):\n", .{});
    const hist_path = try ctx.path(lib.history_file);
    defer gpa.free(hist_path);
    if (Io.Dir.cwd().readFileAlloc(io, hist_path, gpa, .limited(16 << 20))) |hist| {
        defer gpa.free(hist);
        var lines = std.mem.splitScalar(u8, hist, '\n');
        var any = false;
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r\xEF\xBB\xBF");
            if (line.len == 0) continue;
            any = true;
            if (!lib.isValidId(line)) {
                try out.print("  (invalid entry, ignored)\n", .{});
                continue;
            }
            try printRelease(ctx, out, line, cur, kg);
        }
        if (!any) try out.print("  (empty)\n", .{});
    } else |_| try out.print("  (none)\n", .{});

    try out.print("\nreleases on disk (newest first):\n", .{});
    var names: std.ArrayList([]const u8) = .empty;
    defer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }
    var root = try Io.Dir.cwd().openDir(io, ctx.releases, .{ .iterate = true });
    defer root.close(io);
    var iter = root.iterate();
    while (try iter.next(io)) |e| {
        if (e.kind == .directory and lib.isValidId(e.name)) try names.append(gpa, try gpa.dupe(u8, e.name));
    }
    std.mem.sort([]const u8, names.items, {}, struct {
        fn f(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, b, a);
        }
    }.f);
    if (names.items.len == 0) try out.print("  (none)\n", .{});
    for (names.items) |n| try printRelease(ctx, out, n, cur, kg);
    try out.flush();
}

fn printPointer(ctx: Ctx, out: *Io.Writer, label: []const u8, id: ?[]const u8) !void {
    const v = id orelse return out.print("{s} (none or invalid)\n", .{label});
    const exe = try releaseExe(ctx, v);
    defer ctx.gpa.free(exe);
    try out.print("{s} {s}  (zig {s}){s}\n", .{ label, v, lib.zigVersionOf(v), if (isFile(ctx.io, exe)) "" else "  MISSING portal.exe" });
}

fn printRelease(ctx: Ctx, out: *Io.Writer, id: []const u8, cur: ?[]const u8, kg: ?[]const u8) !void {
    const exe = try releaseExe(ctx, id);
    defer ctx.gpa.free(exe);
    const dir = try ctx.path(id);
    defer ctx.gpa.free(dir);
    const is_cur = if (cur) |c| std.mem.eql(u8, c, id) else false;
    const is_kg = if (kg) |k| std.mem.eql(u8, k, id) else false;
    const state: []const u8 = if (!isDir(ctx.io, dir)) "  (pruned)" else if (!isFile(ctx.io, exe)) "  (no portal.exe)" else "";
    try out.print("  {s}  zig {s}{s}{s}{s}\n", .{
        id,                                lib.zigVersionOf(id),
        if (is_cur) "  [current]" else "", if (is_kg) "  [known-good]" else "",
        state,
    });
}

test "pathListContains" {
    try std.testing.expect(pathListContains("C:\\a;C:\\Users\\x\\Portal\\bin\\;C:\\b", "C:\\Users\\x\\Portal\\bin"));
    try std.testing.expect(pathListContains("\"c:\\users\\x\\portal\\bin\"", "C:\\Users\\x\\Portal\\bin"));
    try std.testing.expect(!pathListContains("C:\\a;C:\\b", "C:\\Users\\x\\Portal\\bin"));
}

test {
    _ = lib;
}
