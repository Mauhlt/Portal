//! portal-setup's install of the program files: the payload (the Portal
//! exes and the launchers it carries) becomes a release in the releases
//! folder, exactly as `zig build release` stores one (release_ops.zig),
//! made current, with the launchers installed into `bin`.
//!
//! Idempotent: re-running the same installer finds the release it stored
//! before (by the SHA-256 of portal.exe recorded in BUILD-INFO.txt, checked
//! against the file) and only makes sure it is current and the launchers
//! are in place. A newer installer stores a new release next to the old
//! ones (an upgrade in place: Portal's data is never touched), and the old
//! release stays for `zig build rollback` until pruning.
//!
//! The caller holds release.lock (release_ops.lock) around it.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const lib = @import("releases_lib.zig");
const ops = @import("release_ops.zig");

pub const File = struct { name: []const u8, data: []const u8 };

pub const Payload = struct {
    /// portal.exe, portalctl.exe, portal-show.exe (lib.release_exes).
    exes: []const File,
    /// portal-launcher.exe and portal-launcher-console.exe.
    launchers: []const File,
    /// The release workflow's version (the tag) and commit.
    version: []const u8,
    commit: []const u8,
    /// The Zig that built it (release ids carry it).
    zig_version: []const u8,

    fn exe(p: Payload, name: []const u8) ?[]const u8 {
        for (p.exes) |f| if (std.ascii.eqlIgnoreCase(f.name, name)) return f.data;
        return null;
    }
};

/// Payload folder names under the releases root while installing.
pub const stage_dir = "_setup";

pub const Result = struct {
    /// The release now current (owned).
    id: []u8,
    /// It was there already (the same build): nothing new was stored.
    reused: bool,
    /// It was current already.
    was_current: bool,
    /// Launchers that could not be replaced (the old ones still work).
    launcher_failures: usize,
};

pub const Time = struct { stamp: []const u8, iso: []const u8 };

pub fn install(ctx: ops.Ctx, p: Payload, now: Time) !Result {
    const gpa = ctx.gpa;
    const io = ctx.io;
    const cwd = Io.Dir.cwd();
    for (lib.release_exes) |e| if (p.exe(e) == null) return error.PayloadIncomplete;
    try cwd.createDirPath(io, ctx.releases);
    const hash = lib.sha256Hex(p.exe("portal.exe").?);

    const current = ops.readPointer(ctx, lib.current_file);
    defer if (current) |c| gpa.free(c);

    var reused = true;
    const id: []u8 = (try findRelease(ctx, p, &hash, current)) orelse blk: {
        reused = false;
        var id_buf: [256]u8 = undefined;
        const new_id = try lib.makeId(&id_buf, now.stamp, p.zig_version);
        const dest = try ctx.path(new_id);
        defer gpa.free(dest);
        if (ops.isDir(io, dest)) return error.ReleaseExists;
        const stage = try ctx.path(stage_dir);
        defer gpa.free(stage);
        cwd.deleteTree(io, stage) catch {};
        const rel = try std.fs.path.join(gpa, &.{ stage, "release" });
        defer gpa.free(rel);
        try cwd.createDirPath(io, rel);
        var rd = try cwd.openDir(io, rel, .{});
        defer rd.close(io);
        for (p.exes) |f| try rd.writeFile(io, .{ .sub_path = f.name, .data = f.data });
        var version_buf: [160]u8 = undefined;
        const text = try lib.formatBuildInfo(gpa, .{
            .portal = std.fmt.bufPrint(&version_buf, "portal-setup {s}", .{p.version}) catch "portal-setup",
            .zig_version = p.zig_version,
            .zig_path = "(the release workflow's pinned Zig)",
            .git = p.commit,
            .built = now.iso,
            .sha256_hex = &hash,
        });
        defer gpa.free(text);
        try rd.writeFile(io, .{ .sub_path = "BUILD-INFO.txt", .data = text });
        // The finished folder appears under its id in one rename.
        try ops.moveNoReplace(gpa, rel, dest);
        break :blk try gpa.dupe(u8, new_id);
    };
    errdefer gpa.free(id);

    const was_current = if (current) |c| lib.sameId(c, id) else false;
    if (!was_current) {
        try ops.writePointer(ctx, lib.current_file, id);
        ops.appendHistory(ctx, id) catch |err| ctx.warn("could not append to {s}: {t}", .{ lib.history_file, err });
    }
    // A first install has nothing to roll back to: this release is it
    // (a CI-tested build). `zig build mark-good` moves it later.
    const kg = ops.readPointerRaw(ctx, lib.known_good_file);
    if (kg == .contents) gpa.free(kg.contents);
    if (kg == .missing)
        ops.writePointer(ctx, lib.known_good_file, id) catch |err| ctx.warn("could not write {s}: {t}", .{ lib.known_good_file, err });

    // The launchers, from <releases>\_setup\bin, the way release installs
    // them from its staging folder.
    const stage = try ctx.path(stage_dir);
    defer gpa.free(stage);
    const sbin = try std.fs.path.join(gpa, &.{ stage, "bin" });
    defer gpa.free(sbin);
    try cwd.createDirPath(io, sbin);
    {
        var bd = try cwd.openDir(io, sbin, .{});
        defer bd.close(io);
        for (p.launchers) |f| try bd.writeFile(io, .{ .sub_path = f.name, .data = f.data });
    }
    const bin_dir = try lib.launcherBinDir(gpa, ctx.releases);
    defer gpa.free(bin_dir);
    const failures = ops.installLauncher(ctx, stage, bin_dir, now.stamp);
    cwd.deleteTree(io, stage) catch {};

    if (ops.pruneGuarded(ctx, id)) |k| gpa.free(k);
    return .{ .id = id, .reused = reused, .was_current = was_current, .launcher_failures = failures };
}

/// A stored release holding exactly this payload's exes (current first),
/// or null. Owned.
fn findRelease(ctx: ops.Ctx, p: Payload, hash: []const u8, current: ?[]const u8) !?[]u8 {
    const gpa = ctx.gpa;
    if (current) |c| if (try sameRelease(ctx, p, hash, c)) return try gpa.dupe(u8, c);
    var root = Io.Dir.cwd().openDir(ctx.io, ctx.releases, .{ .iterate = true }) catch return null;
    defer root.close(ctx.io);
    var it = root.iterate();
    while (try it.next(ctx.io)) |e| {
        if (e.kind != .directory or !lib.isValidId(e.name)) continue;
        if (try sameRelease(ctx, p, hash, e.name)) return try gpa.dupe(u8, e.name);
    }
    return null;
}

fn sameRelease(ctx: ops.Ctx, p: Payload, hash: []const u8, id: []const u8) !bool {
    const gpa = ctx.gpa;
    const dir_path = try ctx.path(id);
    defer gpa.free(dir_path);
    var d = Io.Dir.cwd().openDir(ctx.io, dir_path, .{}) catch return false;
    defer d.close(ctx.io);
    const info = d.readFileAlloc(ctx.io, "BUILD-INFO.txt", gpa, .limited(64 << 10)) catch return false;
    defer gpa.free(info);
    const recorded = lib.buildInfoSha256(info) orelse return false;
    if (!std.ascii.eqlIgnoreCase(recorded, hash)) return false;
    // The files themselves, not just the record.
    for (p.exes) |f| {
        const have = d.readFileAlloc(ctx.io, f.name, gpa, .limited(1 << 30)) catch return false;
        defer gpa.free(have);
        if (!std.mem.eql(u8, have, f.data)) return false;
    }
    return true;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn fakePayload(comptime tag: []const u8) Payload {
    const E = struct {
        const e = [_]File{
            .{ .name = "portal.exe", .data = "portal.exe " ++ tag },
            .{ .name = "portalctl.exe", .data = "portalctl.exe " ++ tag },
            .{ .name = "portal-show.exe", .data = "portal-show.exe " ++ tag },
        };
        const l = [_]File{
            .{ .name = "portal-launcher.exe", .data = "gui launcher" },
            .{ .name = "portal-launcher-console.exe", .data = "console launcher" },
        };
    };
    return .{ .exes = &E.e, .launchers = &E.l, .version = "test", .commit = "abc", .zig_version = "0.18.0-dev.1" };
}

fn readText(io: Io, dir: Io.Dir, sub: []const u8, buf: []u8) ![]const u8 {
    return dir.readFile(io, sub, buf);
}

test "setup: installing twice reuses the release; a new build is an upgrade in place" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const base = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(base);
    const releases = try std.fs.path.join(testing.allocator, &.{ base, "Portal", "releases" });
    defer testing.allocator.free(releases);
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    const ctx: ops.Ctx = .{ .gpa = testing.allocator, .io = io, .env = &env, .releases = releases, .quiet = true };

    // Portal's data next to the program: never touched.
    try tmp.dir.createDirPath(io, "Portal");
    try tmp.dir.writeFile(io, .{ .sub_path = "Portal\\settings.txt", .data = "tunnel_port = 51999\r\n" });

    const p1 = fakePayload("one");
    const r1 = try install(ctx, p1, .{ .stamp = "20261115-100000", .iso = "t1" });
    defer testing.allocator.free(r1.id);
    try testing.expect(!r1.reused and !r1.was_current);
    try testing.expectEqualStrings("20261115-100000_zig-0.18.0-dev.1", r1.id);
    try testing.expectEqual(@as(usize, 0), r1.launcher_failures);

    var b: [4096]u8 = undefined;
    try testing.expectEqualStrings(r1.id, try readText(io, tmp.dir, "Portal\\releases\\current.txt", &b));
    try testing.expectEqualStrings(r1.id, try readText(io, tmp.dir, "Portal\\releases\\known-good.txt", &b));
    try testing.expectEqualStrings("gui launcher", try readText(io, tmp.dir, "Portal\\bin\\portal.exe", &b));
    try testing.expectEqualStrings("console launcher", try readText(io, tmp.dir, "Portal\\bin\\portalctl.exe", &b));
    try testing.expectEqualStrings("console launcher", try readText(io, tmp.dir, "Portal\\bin\\portal-show.exe", &b));
    // Exactly what `zig build release` stores (BUILD-INFO with the hash).
    const info = try readText(io, tmp.dir, "Portal\\releases\\20261115-100000_zig-0.18.0-dev.1\\BUILD-INFO.txt", &b);
    try testing.expectEqualStrings(&lib.sha256Hex(p1.exes[0].data), lib.buildInfoSha256(info).?);

    // Again, later: the same release, nothing new, history unchanged.
    const r2 = try install(ctx, p1, .{ .stamp = "20261115-110000", .iso = "t2" });
    defer testing.allocator.free(r2.id);
    try testing.expect(r2.reused and r2.was_current);
    try testing.expectEqualStrings(r1.id, r2.id);
    try testing.expectEqualStrings("20261115-100000_zig-0.18.0-dev.1\r\n", try readText(io, tmp.dir, "Portal\\releases\\history.txt", &b));
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "Portal\\releases\\20261115-110000_zig-0.18.0-dev.1", .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "Portal\\releases\\_setup", .{}));

    // A newer build: a new release, current moves, the old one stays
    // (known-good, for rollback), and the data is untouched.
    const p2 = fakePayload("two");
    const r3 = try install(ctx, p2, .{ .stamp = "20261116-090000", .iso = "t3" });
    defer testing.allocator.free(r3.id);
    try testing.expect(!r3.reused);
    try testing.expectEqualStrings(r3.id, try readText(io, tmp.dir, "Portal\\releases\\current.txt", &b));
    try testing.expectEqualStrings(r1.id, try readText(io, tmp.dir, "Portal\\releases\\known-good.txt", &b));
    _ = try tmp.dir.statFile(io, "Portal\\releases\\20261115-100000_zig-0.18.0-dev.1\\portal.exe", .{});
    try testing.expectEqualStrings("tunnel_port = 51999\r\n", try readText(io, tmp.dir, "Portal\\settings.txt", &b));

    // Re-running the older installer goes back to its stored release
    // (found by its hash) without storing a third.
    const r4 = try install(ctx, p1, .{ .stamp = "20261116-100000", .iso = "t4" });
    defer testing.allocator.free(r4.id);
    try testing.expect(r4.reused and !r4.was_current);
    try testing.expectEqualStrings(r1.id, r4.id);

    // A tampered file is not taken for the release.
    try tmp.dir.writeFile(io, .{ .sub_path = "Portal\\releases\\20261115-100000_zig-0.18.0-dev.1\\portalctl.exe", .data = "changed" });
    const r5 = try install(ctx, p1, .{ .stamp = "20261116-110000", .iso = "t5" });
    defer testing.allocator.free(r5.id);
    try testing.expect(!r5.reused);
}

test "setup: an incomplete payload is refused" {
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    const ctx: ops.Ctx = .{ .gpa = testing.allocator, .io = testing.io, .env = &env, .releases = "C:\\nowhere-portal-test", .quiet = true };
    var p = fakePayload("x");
    p.exes = p.exes[0..2];
    try testing.expectError(error.PayloadIncomplete, install(ctx, p, .{ .stamp = "20261115-100000", .iso = "" }));
}
