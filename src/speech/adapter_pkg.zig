//! What a device finds in the `stt-adapter` package the desk publishes
//! (one rule for the iPhone and the laptop): an update file from
//! stt.Home.exportUpdate (update.bin, swapped into a running engine at
//! once) or a raw adapter (adapter.bin, used from the next start, its
//! version the package's version number).

const std = @import("std");
const Io = std.Io;

/// The first bytes of an stt update file.
pub const update_magic = "STTUPD01";
/// Looked for in this order.
pub const file_names = [_][]const u8{ "update.bin", "adapter.bin" };

/// update.bin or adapter.bin in the package folder `dir`, into `buf`.
pub fn file(io: Io, dir: []const u8, buf: []u8) ?[]const u8 {
    for (file_names) |name| {
        const p = std.fmt.bufPrint(buf, "{s}" ++ std.fs.path.sep_str ++ "{s}", .{ dir, name }) catch return null;
        Io.Dir.cwd().access(io, p, .{}) catch continue;
        return p;
    }
    return null;
}

pub fn isUpdate(bytes: []const u8) bool {
    return std.mem.startsWith(u8, bytes, update_magic);
}

/// A raw adapter's version: the package version, a plain number.
pub fn rawVersion(package_version: []const u8) ?u32 {
    return std.fmt.parseInt(u32, package_version, 10) catch null;
}

test "the update file first, then the raw adapter; versions" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db: [1024]u8 = undefined;
    const dir = db[0..try tmp.dir.realPath(testing.io, &db)];
    var pb: [1100]u8 = undefined;
    try testing.expect(file(testing.io, dir, &pb) == null);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "adapter.bin", .data = "raw" });
    try testing.expect(std.mem.endsWith(u8, file(testing.io, dir, &pb).?, "adapter.bin"));
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "update.bin", .data = update_magic ++ "x" });
    try testing.expect(std.mem.endsWith(u8, file(testing.io, dir, &pb).?, "update.bin"));
    try testing.expect(isUpdate(update_magic ++ "x") and !isUpdate("raw"));
    try testing.expectEqual(@as(?u32, 7), rawVersion("7"));
    try testing.expectEqual(@as(?u32, null), rawVersion("7.1"));
}
