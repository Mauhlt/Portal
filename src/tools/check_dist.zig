//! portal-check-dist: fails if a published file embeds a path or name of
//! the machine that built it (ported from ZVC's tools/check_dist.zig).
//!
//!   portal-check-dist <file>...
//!
//! Every asset a release publishes goes through it: the installers and
//! the exes they carry, the Mac's slices, Portal-mac.zip (stored, so its
//! files are scanned as they are), and the release notes.
//!
//! Needles, each searched as bytes and as UTF-16LE (Windows strings; a
//! non-ASCII needle is encoded properly), ignoring ASCII case:
//!   * the usual home-folder prefixes (`forbidden`);
//!   * this machine's folders: the current folder (build.zig runs it from
//!     the repo), the home folder, %LOCALAPPDATA%, the Zig caches, the CI
//!     workspace and temp folder, each with `\` and with `/`;
//!   * the user's and the computer's name (USERNAME, USER, COMPUTERNAME),
//!     from 2 characters, but only as a path component (`\name\`,
//!     `/name/`), so a short name does not match ordinary text.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Byte strings that only show up in a binary through an absolute build
/// path (Linux and macOS runners and homes, Windows profiles).
const forbidden = [_][]const u8{ "/home/runner", "/home/", "/Users/", "\\Users\\", "runneradmin" };

const path_vars = [_][]const u8{ "USERPROFILE", "HOME", "LOCALAPPDATA", "ZIG_GLOBAL_CACHE_DIR", "ZIG_LOCAL_CACHE_DIR", "GITHUB_WORKSPACE", "RUNNER_TEMP" };
const name_vars = [_][]const u8{ "USERNAME", "USER", "COMPUTERNAME" };

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var args: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer args.deinit();
    _ = args.next();

    var paths: std.ArrayList([]const u8) = .empty;
    try paths.append(a, try std.Io.Dir.cwd().realPathFileAlloc(io, ".", a));
    for (path_vars) |name| if (init.environ_map.get(name)) |v| try paths.append(a, v);
    var names: std.ArrayList([]const u8) = .empty;
    for (name_vars) |name| if (init.environ_map.get(name)) |v| try names.append(a, v);
    const needles = try needlesFor(a, &forbidden, paths.items, names.items);

    var checked: usize = 0;
    var clean = true;
    while (args.next()) |path| {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(512 << 20));
        defer gpa.free(bytes);
        const name = std.fs.path.basename(path);
        if (findForbidden(bytes, needles)) |hit| {
            std.log.err("{s}: contains \"{s}\" ({s}) at offset {d}", .{ name, hit.needle, if (hit.wide) "UTF-16" else "bytes", hit.offset });
            clean = false;
        }
        checked += 1;
    }
    if (checked == 0) return error.NoBinariesGiven;
    if (!clean) std.process.exit(1);
    std.debug.print("check-dist: {d} files contain no build-machine paths or names.\n", .{checked});
}

pub const Needle = struct {
    /// What is reported.
    text: []const u8,
    /// The bytes searched: the needle itself, and its UTF-16LE form.
    bytes: []const u8,
    wide: []const u8,
};

/// Every needle, in `a`. Absolute `paths` count with `\` and `/`; `names`
/// of 2+ characters only as a path component.
pub fn needlesFor(a: Allocator, fixed: []const []const u8, paths: []const []const u8, names: []const []const u8) ![]Needle {
    var list: std.ArrayList(Needle) = .empty;
    for (fixed) |f| try list.append(a, try needle(a, f, f));
    for (paths) |p| {
        if (!std.fs.path.isAbsolute(p) and !std.fs.path.isAbsolutePosix(p)) continue;
        const back = try a.dupe(u8, std.mem.trimEnd(u8, p, "\\/"));
        std.mem.replaceScalar(u8, back, '/', '\\');
        const fwd = try a.dupe(u8, back);
        std.mem.replaceScalar(u8, fwd, '\\', '/');
        try list.append(a, try needle(a, p, back));
        try list.append(a, try needle(a, p, fwd));
    }
    for (names) |n| {
        if (n.len < 2) continue;
        try list.append(a, try needle(a, n, try std.fmt.allocPrint(a, "\\{s}\\", .{n})));
        try list.append(a, try needle(a, n, try std.fmt.allocPrint(a, "/{s}/", .{n})));
    }
    return list.toOwnedSlice(a);
}

fn needle(a: Allocator, text: []const u8, bytes: []const u8) !Needle {
    const w16 = try std.unicode.wtf8ToWtf16LeAlloc(a, bytes);
    return .{ .text = text, .bytes = bytes, .wide = std.mem.sliceAsBytes(w16) };
}

pub const Hit = struct { needle: []const u8, offset: usize, wide: bool };

/// The first needle found, ASCII case ignored.
pub fn findForbidden(bytes: []const u8, needles: []const Needle) ?Hit {
    for (needles) |n| {
        if (std.ascii.findIgnoreCase(bytes, n.bytes)) |offset| return .{ .needle = n.text, .offset = offset, .wide = false };
        if (std.ascii.findIgnoreCase(bytes, n.wide)) |offset| return .{ .needle = n.text, .offset = offset, .wide = true };
    }
    return null;
}

const testing = std.testing;

fn check(bytes: []const u8, paths: []const []const u8, names: []const []const u8) !?Hit {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    return findForbidden(bytes, try needlesFor(arena.allocator(), &forbidden, paths, names));
}

test "check-dist: home prefixes" {
    try testing.expect(try check("ok https://ziglang.org /usr/local/bin %LOCALAPPDATA%\\Portal", &.{}, &.{}) == null);
    try testing.expect(try check("/home/runner/work/x", &.{}, &.{}) != null);
    try testing.expect(try check("C:\\USERS\\me", &.{}, &.{}) != null);
    try testing.expect(try check("/Users/me", &.{}, &.{}) != null);
}

test "check-dist: this machine's folders, with either slash and in UTF-16" {
    const repo = "D:\\a\\Portal\\Portal";
    try testing.expect(try check("x D:\\a\\Portal\\Portal\\src y", &.{repo}, &.{}) != null);
    const fwd = (try check("x D:/a/Portal/Portal/src y", &.{repo}, &.{})).?;
    try testing.expect(!fwd.wide);
    const h = (try check("..D\x00:\x00\\\x00a\x00\\\x00P\x00o\x00r\x00t\x00a\x00l\x00\\\x00P\x00o\x00r\x00t\x00a\x00l\x00", &.{repo}, &.{})).?;
    try testing.expect(h.wide);
    try testing.expectEqual(@as(usize, 2), h.offset);
    // Non-ASCII: the real UTF-16 code unit, not the UTF-8 bytes spread out.
    const p = "C:\\Profiles\\Jos\u{e9}";
    var w16: [32]u16 = undefined;
    const n = try std.unicode.utf8ToUtf16Le(&w16, p);
    try testing.expect(try check(std.mem.sliceAsBytes(w16[0..n]), &.{p}, &.{}) != null);
    try testing.expect(try check("relative\\path", &.{"relative"}, &.{}) == null);
}

test "check-dist: names, short ones too, only as a path component" {
    try testing.expect(try check("C:\\Users\\someone\\x", &.{}, &.{"someone"}) != null);
    try testing.expect(try check("built by someone", &.{}, &.{"someone"}) == null);
    try testing.expect(try check("x /home2/jo/y", &.{}, &.{"jo"}) != null);
    try testing.expect(try check("x\\JO\\y", &.{}, &.{"jo"}) != null);
    try testing.expect(try check("join the journey to jo", &.{}, &.{"jo"}) == null);
    try testing.expect(try check("\\\\DESKTOP-AB12\\share", &.{}, &.{"DESKTOP-AB12"}) != null);
    try testing.expect(try check("x\\j\\y", &.{}, &.{"j"}) == null); // 1 character: not a needle
}
