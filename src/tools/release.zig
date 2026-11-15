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
//!         20261114-104043_zig-0.18.0-dev.1005+75d48dfff\
//!             portal.exe (the window, GUI subsystem), portalctl.exe (the
//!             console tool), portal-show.exe (images, runs in sessions),
//!             their .pdb files, BUILD-INFO.txt, source\
//!         current.txt     release the launcher runs
//!         known-good.txt  release you confirmed works (mark-good)
//!         history.txt     every promotion, newest last
//!     %LOCALAPPDATA%\Portal\bin\   launchers (put bin on PATH):
//!         portal.exe        GUI-subsystem launcher -> release's portal.exe
//!         portalctl.exe     console launcher -> release's portalctl.exe
//!         portal-show.exe   console launcher -> release's portal-show.exe
//!
//! PORTAL_RELEASES_DIR (absolute path) overrides the releases directory, for
//! testing, when PORTAL_TESTING=1 is also set; the launcher is then
//! installed to its sibling `bin` directory. `release` holds
//! <releases>\release.lock for its whole run (one release at a time).
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
const w = @import("win32");

const usage =
    \\portal-release - build, test and promote Portal releases
    \\
    \\Usage:
    \\  portal-release release [--zig PATH] [--repo DIR]
    \\      Run `zig build test`, build ReleaseSafe, check `portalctl version`,
    \\      store it as a new release, make it current, install the launchers
    \\      (portal.exe, portalctl.exe and portal-show.exe in the `bin` folder
    \\      next to the releases folder) and
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
    \\(absolute path; for testing only: honoured only with PORTAL_TESTING=1).
    \\
;

const ops = @import("release_ops.zig");
const Ctx = ops.Ctx;
const readPointer = ops.readPointer;
const readPointerRaw = ops.readPointerRaw;
const writePointer = ops.writePointer;
const moveReplace = ops.moveReplace;
const moveNoReplace = ops.moveNoReplace;
const appendHistory = ops.appendHistory;
const isFile = ops.isFile;
const isDir = ops.isDir;
const releaseExe = ops.releaseExe;
const Now = ops.Now;

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

    const override: ?[]const u8 = switch (lib.releasesOverride(env.get(lib.override_env), env.get(lib.testing_env))) {
        .none => null,
        .ignored => |o| blk: {
            std.debug.print("{s}: warning: ignoring PORTAL_RELEASES_DIR={s} (set PORTAL_TESTING=1 to use it)\n", .{ cmd, o });
            break :blk null;
        },
        .active => |o| o,
    };
    const releases = lib.releasesRoot(gpa, override, env.get("LOCALAPPDATA")) catch |err| switch (err) {
        error.NoLocalAppData => fatal(cmd, "LOCALAPPDATA is not set", .{}),
        error.RelativeOverride => fatal(cmd, "PORTAL_RELEASES_DIR must be an absolute path", .{}),
        error.OutOfMemory => return err,
    };
    defer gpa.free(releases);
    if (override != null)
        std.debug.print("{s}: warning: TESTING override PORTAL_RELEASES_DIR in effect: {s}\n", .{ cmd, releases });
    Io.Dir.cwd().createDirPath(io, releases) catch |err|
        fatal(cmd, "cannot create {s}: {t}", .{ releases, err });

    const ctx: Ctx = .{ .gpa = gpa, .io = io, .env = env, .releases = releases, .testing_override = override != null };

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

/// release.lock for the whole command (ops.lock); exits if it is taken.
fn lockReleases(ctx: Ctx, cmd: []const u8) void {
    ops.lock(ctx) catch |err| switch (err) {
        error.Busy => fatal(cmd, "another portal-release command (release, mark-good or rollback) or the installer is running ({s} in {s} is in use); nothing was changed", .{ lib.lock_file, ctx.releases }),
        else => fatal(cmd, "cannot create the lock file {s} in {s} ({t}); nothing was changed", .{ lib.lock_file, ctx.releases, err }),
    };
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

// ---------------------------------------------------------------- release

fn cmdRelease(ctx: Ctx, zig_arg: ?[]const u8, repo_arg: ?[]const u8) !void {
    const gpa = ctx.gpa;
    const io = ctx.io;
    lockReleases(ctx, "release");

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

    // portal.exe is a GUI program (message boxes, no stdout): the version
    // check runs the console tool built from the same code.
    const staged_exe = try std.fs.path.join(gpa, &.{ stage, "bin", "portalctl.exe" });
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
    _ = ops.installLauncher(ctx, stage, bin_dir, now.stamp);
    Io.Dir.cwd().deleteTree(io, stage) catch |err| warn("could not remove {s}: {t}", .{ stage, err });

    // The laptop speech engine and its model: published by the new
    // release's portalctl when they changed. Never fails the release.
    const voice = publishVoice(ctx, zig_exe, repo, dest);

    // Prune only when the known-good release is certain: if known-good.txt
    // exists but cannot be read or validated, deleting old releases could
    // delete the very release it names.
    const kg_read = readPointerRaw(ctx, lib.known_good_file);
    defer if (kg_read == .contents) gpa.free(kg_read.contents);
    const kg: ?[]const u8 = switch (lib.pruneGuard(kg_read)) {
        .skip => blk: {
            warn("{s} exists but could not be read or is invalid: pruning skipped", .{lib.known_good_file});
            break :blk null;
        },
        .prune => |k| blk: {
            ops.prune(ctx, id, k);
            break :blk k;
        },
    };

    std.debug.print("release: promoted {s}\n", .{id});
    if (kg) |k| {
        std.debug.print("release: known-good fallback is {s}\n", .{k});
    } else if (kg_read != .missing) {
        std.debug.print("release: check {s} (unreadable or invalid); `zig build mark-good` rewrites it\n", .{lib.known_good_file});
    } else {
        std.debug.print("release: no known-good release yet. After confirming this one works end to end, run `zig build mark-good`\n", .{});
    }
    if (!pathListContains(ctx.env.get("PATH") orelse "", bin_dir))
        std.debug.print("release: add {s} to your PATH to run `portal`.\n", .{bin_dir});
    std.debug.print("release: restart any running portal to pick it up.\n", .{});
    if (lib.voiceLine(voice)) |l| std.debug.print("release: {s}\n", .{l});
}

/// `zig build voice-packages` (the QAIRT SDK fetch and the aarch64 cross-
/// build of stt-local, and the pinned model) into <releases>\_voice, then
/// the new release's `portalctl voice-publish`, which publishes each
/// package only when it changed and records the result for the desk. A
/// failed build is recorded too (`--not-built`). Every failure is a
/// warning: the desk's release is promoted already.
fn publishVoice(ctx: Ctx, zig_exe: []const u8, repo: []const u8, dest: []const u8) lib.VoiceOutcome {
    const gpa = ctx.gpa;
    const io = ctx.io;
    if (ctx.testing_override) return lib.voiceOutcome(true, false, false);
    const ctl = std.fs.path.join(gpa, &.{ dest, "portalctl.exe" }) catch return .publish_failed;
    defer gpa.free(ctl);
    // The Audio panel's "Publish the laptop speech engine": off, nothing
    // is built (portalctl says so and records it for the desk).
    if (runInherit(io, &.{ ctl, "voice-publish", "--enabled" }, repo)) |code| {
        if (code == lib.voice_off_exit) return .off;
        if (code != 0) return .publish_failed;
    } else |err| {
        warn("cannot run {s}: {t}", .{ ctl, err });
        return .publish_failed;
    }
    const out = ctx.path(lib.voice_dir) catch return .build_failed;
    defer gpa.free(out);
    defer Io.Dir.cwd().deleteTree(io, out) catch {};
    Io.Dir.cwd().deleteTree(io, out) catch {};

    std.debug.print("release: building the laptop speech engine (zig build voice-packages)...\n", .{});
    var why_buf: [200]u8 = undefined;
    const why: ?[]const u8 = if (runInherit(io, &.{ zig_exe, "build", "voice-packages", "--prefix", out }, repo)) |code|
        (if (code == 0) null else lib.notBuiltReason(&why_buf, code, null))
    else |err|
        lib.notBuiltReason(&why_buf, null, @errorName(err));
    const folder = std.fs.path.join(gpa, &.{ out, "voice" }) catch return .build_failed;
    defer gpa.free(folder);
    const argv: []const []const u8 = if (why) |reason| &.{ ctl, "voice-publish", "--not-built", reason } else &.{ ctl, "voice-publish", folder };
    const published = if (runInherit(io, argv, repo)) |code| code == 0 else |err| blk: {
        warn("cannot run {s}: {t}", .{ ctl, err });
        break :blk false;
    };
    return lib.voiceOutcome(false, why == null, published);
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

    for (lib.release_exes) |exe| {
        try stage_dir.copyFile(exe, dest_dir, exe, io, .{});
        var pdb_buf: [64]u8 = undefined;
        const pdb = try std.fmt.bufPrint(&pdb_buf, "{s}.pdb", .{exe[0 .. exe.len - 4]});
        if (stage_dir.statFile(io, pdb, .{})) |_| {
            try stage_dir.copyFile(pdb, dest_dir, pdb, io, .{});
        } else |_| {}
    }

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

fn cmdMarkGood(ctx: Ctx) !void {
    lockReleases(ctx, "mark-good");
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
    lockReleases(ctx, "rollback");
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
