//! "Share voice improvements with devices" (the desk's Audio panel,
//! settings.txt `speech_share`, default on): each adapter version the
//! desk's training produces (speech/home.zig, stt.Home) becomes the next
//! signed `stt-adapter` data package, through sync.publish, the same code
//! `portalctl publish` runs (docs/sync-design.md, docs/stt-sync-contract.md).
//!
//!   update.bin   stt's update (STTUPD01: the adapter, phrase rules and
//!                vocabulary), what devices import (stt importUpdate)
//!   adapter.bin  the raw adapter alone, for anything that loads one
//!
//! The package version is the adapter's version number. Publishing ends in
//! a folder rename under publish\, which SyncWatch (main.zig) sees: every
//! subscribed device's index changes and its WebSocket gets
//! {"t":"updates"}, so connected devices fetch it at once. Versions beyond
//! the newest `keep_versions` are unpublished (sync.prune).
//!
//! Runs on the speech engine's thread (home.Engine.Publisher), never on
//! the window's.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const sync = @import("sync.zig");
const Log = @import("log.zig").Log;

pub const package = "stt-adapter";
/// Published versions kept (the newest); older ones are unpublished.
pub const keep_versions = 3;
pub const update_file = "update.bin";
pub const adapter_file = "adapter.bin";
const update_magic = "STTUPD01";

pub const Published = struct {
    version: u32,
    sequence: u64,
    /// Superseded versions unpublished by this publish.
    pruned: usize,
};

/// The newest published adapter's version number (0: none, or a version
/// name that is not a number, e.g. one published by hand).
pub fn latestVersion(gpa: Allocator, io: Io, paths: sync.Paths) u32 {
    var v = (sync.latest(gpa, io, paths, package) catch return 0) orelse return 0;
    defer v.deinit(gpa);
    return std.fmt.parseInt(u32, v.m.version, 10) catch 0;
}

pub const UpdateParts = struct { version: u32, adapter: []const u8 };

/// The version and the adapter of an stt update ("STTUPD01", u32 version,
/// u32 length + the adapter, then rules and vocabulary; little-endian), or
/// null if it is not one. stt checks the rest when a device imports it.
pub fn updateParts(bytes: []const u8) ?UpdateParts {
    if (bytes.len < 16 or !std.mem.eql(u8, bytes[0..8], update_magic)) return null;
    const version = std.mem.readInt(u32, bytes[8..12], .little);
    const n = std.mem.readInt(u32, bytes[12..16], .little);
    if (version == 0 or bytes.len - 16 < n) return null;
    return .{ .version = version, .adapter = bytes[16..][0..n] };
}

/// Publishes `update` as stt-adapter version <its version>, then prunes.
/// Null: that version (or a newer one) is published already.
pub fn publish(gpa: Allocator, io: Io, paths: sync.Paths, update: []const u8, now: i64) !?Published {
    const parts = updateParts(update) orelse return error.BadUpdate;
    if (latestVersion(gpa, io, paths) >= parts.version) return null;

    // The package's files, staged in a folder of their own (outside
    // publish\, so SyncWatch sees only the finished version).
    var rnd: [8]u8 = undefined;
    io.random(&rnd);
    var nb: [32]u8 = undefined;
    const hex = std.fmt.bytesToHex(rnd, .lower);
    var sb: [1024]u8 = undefined;
    const staging = try paths.join(&sb, &.{ "stt-share", try std.fmt.bufPrint(&nb, ".tmp-{s}", .{&hex}) });
    try Io.Dir.cwd().createDirPath(io, staging);
    defer Io.Dir.cwd().deleteTree(io, staging) catch {};
    var fb: [1100]u8 = undefined;
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.bufPrint(&fb, "{s}\\{s}", .{ staging, update_file }), .data = update });
    if (parts.adapter.len > 0)
        try Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.bufPrint(&fb, "{s}\\{s}", .{ staging, adapter_file }), .data = parts.adapter });

    var vb: [16]u8 = undefined;
    const ver = std.fmt.bufPrint(&vb, "{d}", .{parts.version}) catch unreachable;
    var problem: [300]u8 = undefined;
    const p = sync.publish(gpa, io, paths, .{ .package = package, .folder = staging, .kind = .data, .version = ver, .now = now }, &problem) catch |err| switch (err) {
        // Published before and unpublished since: names are never reused.
        error.VersionUsed => return null,
        else => return err,
    };
    const pruned = sync.prune(gpa, io, paths, package, keep_versions) catch 0;
    return .{ .version = parts.version, .sequence = p.sequence, .pruned = pruned };
}

/// The desk's publisher (home.Engine.Publisher): the data folder and the log.
pub const Share = struct {
    gpa: Allocator,
    io: Io,
    paths: sync.Paths,
    log: ?*Log = null,

    /// For home.Engine (only where it is linked).
    pub fn publisher(s: *Share, comptime Publisher: type) Publisher {
        return .{ .ctx = s, .published = published, .publish = publishThunk };
    }

    fn of(ctx: *anyopaque) *Share {
        return @ptrCast(@alignCast(ctx));
    }

    fn published(ctx: *anyopaque) u32 {
        const s = of(ctx);
        return latestVersion(s.gpa, s.io, s.paths);
    }

    fn publishThunk(ctx: *anyopaque, update: []const u8) anyerror!?u32 {
        const s = of(ctx);
        const now = Io.Timestamp.now(s.io, .real).toSeconds();
        const got = publish(s.gpa, s.io, s.paths, update, now) catch |err| {
            if (s.log) |l| l.print("ERROR: speech: the new voice adapter could not be published to devices ({t})", .{err});
            return err;
        };
        const p = got orelse return null;
        if (s.log) |l| l.print("speech: your voice v{d} published to devices ({s} sequence {d}; {d} superseded version(s) unpublished)", .{ p.version, package, p.sequence, p.pruned });
        return p.version;
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn tmpPaths(tmp: *testing.TmpDir, buf: []u8) !sync.Paths {
    var abs: [1024]u8 = undefined;
    const n = try Io.Dir.cwd().realPath(testing.io, &abs);
    return .{ .dir = try std.fmt.bufPrint(buf, "{s}\\.zig-cache\\tmp\\{s}", .{ abs[0..n], &tmp.sub_path }) };
}

/// An stt update of `version` with `adapter` (empty rules and vocabulary).
fn testUpdate(buf: []u8, version: u32, adapter: []const u8) []u8 {
    @memcpy(buf[0..8], update_magic);
    std.mem.writeInt(u32, buf[8..12], version, .little);
    std.mem.writeInt(u32, buf[12..16], @intCast(adapter.len), .little);
    @memcpy(buf[16..][0..adapter.len], adapter);
    @memset(buf[16 + adapter.len ..][0..8], 0);
    return buf[0 .. 24 + adapter.len];
}

test "update header: version and adapter, or not an update" {
    var b: [64]u8 = undefined;
    const u = testUpdate(&b, 7, "LORA");
    const p = updateParts(u).?;
    try testing.expectEqual(@as(u32, 7), p.version);
    try testing.expectEqualStrings("LORA", p.adapter);
    try testing.expect(updateParts(u[0..17]) == null); // adapter cut short
    try testing.expect(updateParts(testUpdate(&b, 0, "x")) == null);
    try testing.expect(updateParts("STTBUN01 a bundle, not an update") == null);
}

test "publish: a new version is signed and published with both files; the same one is not again; retention keeps 3" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const paths = try tmpPaths(&tmp, &pb);
    const pk = try sync.initKey(gpa, io, paths, false);
    try testing.expectEqual(@as(u32, 0), latestVersion(gpa, io, paths));

    var b: [64]u8 = undefined;
    const p1 = (try publish(gpa, io, paths, testUpdate(&b, 4, "v4"), 1)).?;
    try testing.expectEqual(@as(u32, 4), p1.version);
    try testing.expectEqual(@as(u32, 4), latestVersion(gpa, io, paths));
    {
        var v = try sync.readVersion(gpa, io, paths, package, "4");
        defer v.deinit(gpa);
        const manifest = @import("client").sync.manifest;
        try manifest.verify(v.manifest_bytes, manifest.parseHex(64, &v.sig_hex).?, pk);
        try testing.expectEqual(@as(usize, 2), v.m.files.len);
        try testing.expectEqual(.data, v.m.kind);
        try testing.expectEqualStrings(adapter_file, v.m.files[0].path);
        try testing.expectEqualStrings(update_file, v.m.files[1].path);
        var fb: [1024]u8 = undefined;
        var cb: [8]u8 = undefined;
        try testing.expectEqualStrings("v4", try Io.Dir.cwd().readFile(io, try sync.filePath(paths, &fb, package, "4", 0), &cb));
    }
    // Unchanged (or older): nothing published.
    try testing.expect((try publish(gpa, io, paths, testUpdate(&b, 4, "v4"), 2)) == null);
    try testing.expect((try publish(gpa, io, paths, testUpdate(&b, 3, "v3"), 2)) == null);
    try testing.expectError(error.BadUpdate, publish(gpa, io, paths, "junk", 2));
    // The staging folders are gone.
    var sb: [1024]u8 = undefined;
    var sd = try Io.Dir.cwd().openDir(io, try paths.join(&sb, &.{"stt-share"}), .{ .iterate = true });
    defer sd.close(io);
    var it = sd.iterate();
    try testing.expect((try it.next(io)) == null);

    // Retention: the newest 3 stay published.
    for ([_]u32{ 5, 6, 7 }) |n| _ = (try publish(gpa, io, paths, testUpdate(&b, n, "vx"), 3)).?;
    const last = (try publish(gpa, io, paths, testUpdate(&b, 8, "v8"), 4)).?;
    try testing.expectEqual(@as(usize, 1), last.pruned);
    try testing.expectError(error.NotPublished, sync.readVersion(gpa, io, paths, package, "4"));
    try testing.expectError(error.NotPublished, sync.readVersion(gpa, io, paths, package, "5"));
    for ([_][]const u8{ "6", "7", "8" }) |v| {
        var x = try sync.readVersion(gpa, io, paths, package, v);
        x.deinit(gpa);
    }
    try testing.expectEqual(@as(u32, 8), latestVersion(gpa, io, paths));
}

test "publish: with no release key nothing is published (an error the caller logs)" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const paths = try tmpPaths(&tmp, &pb);
    var b: [64]u8 = undefined;
    try testing.expectError(error.NoSyncKey, publish(gpa, testing.io, paths, testUpdate(&b, 2, "v2"), 1));
    try testing.expectEqual(@as(u32, 0), latestVersion(gpa, testing.io, paths));
}
