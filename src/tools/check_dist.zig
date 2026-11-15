//! portal-check-dist: fails if a published binary embeds a path or name of
//! the machine that built it (ported from ZVC's tools/check_dist.zig).
//!
//!   portal-check-dist <binary>...
//!
//! Needles: the usual home-folder prefixes, plus this machine's own: the
//! current folder (build.zig runs it from the repo), the home folder, the
//! Zig caches, the CI workspace and the user's name, from the
//! environment. Each is searched as bytes and as UTF-16LE (Windows
//! strings), ignoring ASCII case.

const std = @import("std");

/// Byte strings that only show up in a binary through an absolute build
/// path (Linux and macOS runners and homes, Windows profiles).
const forbidden = [_][]const u8{ "/home/runner", "/home/", "/Users/", "\\Users\\", "runneradmin" };

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer args.deinit();
    _ = args.next();

    var needles: std.ArrayList([]const u8) = .empty;
    defer needles.deinit(gpa);
    const cwd_path = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", gpa);
    defer gpa.free(cwd_path);
    try needles.append(gpa, cwd_path);
    for ([_][]const u8{ "USERPROFILE", "HOME", "LOCALAPPDATA", "ZIG_GLOBAL_CACHE_DIR", "ZIG_LOCAL_CACHE_DIR", "GITHUB_WORKSPACE", "RUNNER_TEMP" }) |name|
        if (init.environ_map.get(name)) |v| if (std.fs.path.isAbsolute(v)) try needles.append(gpa, v);
    for ([_][]const u8{ "USERNAME", "USER" }) |name|
        if (init.environ_map.get(name)) |v| if (v.len >= 4) try needles.append(gpa, v);

    var checked: usize = 0;
    var clean = true;
    while (args.next()) |path| {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(512 << 20));
        defer gpa.free(bytes);
        const name = std.fs.path.basename(path);
        if (try findForbidden(gpa, bytes, needles.items)) |hit| {
            std.log.err("{s}: contains \"{s}\" ({s}) at offset {d}", .{ name, hit.needle, if (hit.wide) "UTF-16" else "bytes", hit.offset });
            clean = false;
        }
        checked += 1;
    }
    if (checked == 0) return error.NoBinariesGiven;
    if (!clean) std.process.exit(1);
    std.debug.print("check-dist: {d} binaries contain no build-machine paths or names.\n", .{checked});
}

const Hit = struct { needle: []const u8, offset: usize, wide: bool };

fn findForbidden(gpa: std.mem.Allocator, bytes: []const u8, extra: []const []const u8) !?Hit {
    for ([2][]const []const u8{ &forbidden, extra }) |list| for (list) |needle| {
        if (needle.len == 0) continue;
        if (std.ascii.findIgnoreCase(bytes, needle)) |offset| return .{ .needle = needle, .offset = offset, .wide = false };
        const wide = try gpa.alloc(u8, needle.len * 2);
        defer gpa.free(wide);
        for (needle, 0..) |c, i| {
            wide[2 * i] = c;
            wide[2 * i + 1] = 0;
        }
        if (std.ascii.findIgnoreCase(bytes, wide)) |offset| return .{ .needle = needle, .offset = offset, .wide = true };
    };
    return null;
}

test findForbidden {
    const a = std.testing.allocator;
    try std.testing.expect(try findForbidden(a, "ok https://ziglang.org /usr/local/bin %LOCALAPPDATA%\\Portal", &.{}) == null);
    try std.testing.expect(try findForbidden(a, "/home/runner/work/x", &.{}) != null);
    try std.testing.expect(try findForbidden(a, "C:\\USERS\\me", &.{}) != null);
    try std.testing.expect(try findForbidden(a, "/Users/me", &.{}) != null);
    const h = (try findForbidden(a, "..D\x00:\x00\\\x00a\x00\\\x00P\x00", &.{"D:\\a\\P"})).?;
    try std.testing.expect(h.wide);
    try std.testing.expectEqual(@as(usize, 2), h.offset);
    try std.testing.expect(try findForbidden(a, "built by someone", &.{"someone"}) == null);
    try std.testing.expect(try findForbidden(a, "x SOMEONE y", &.{"someone"}) != null);
}
