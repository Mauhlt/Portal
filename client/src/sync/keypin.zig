//! The release key pinned for each server, next to its pinned CA
//! (net/pin.zig), and where each desktop's sync store lives.
//!
//!   Windows  %APPDATA%\Portal\servers\<host>.sync-key
//!   macOS    ~/Library/Application Support/Portal/servers/<host>.sync-key
//!   Linux    $XDG_CONFIG_HOME/portal/servers/<host>.sync-key
//!
//! The file holds the desktop's Ed25519 release public key (public data,
//! not a secret):
//!
//!   portal-sync-key-v1\n<64 hex digits>\n
//!
//! It is written only when this device completes pairing, from the paired,
//! CA-pinned TLS session (docs/sync-design.md, "Trust"). A different key
//! from the server later is refused; only re-pairing replaces the pin.
//!
//! Every paired desktop syncs into its own folder, named after the pinned
//! host and the pinned key (`desktopRoot`):
//!
//!   <sync root>\desktops\<host stem>-<first 16 hex of the key's SHA-256>\
//!
//! e.g. desktops\10.8.0.1_8420-3f2a9c0d11b7e4a5\. Another desktop (another
//! host, or the same address with another release key) can never write
//! into, overwrite or block it.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const pin = @import("../net/pin.zig");
const manifest = @import("manifest.zig");
const store = @import("store.zig");

pub const header = "portal-sync-key-v1";
pub const Key = [manifest.public_key_len]u8;

pub fn pinPath(host: []const u8, out: *[pin.max_path]u8) ![]const u8 {
    var dir_buf: [pin.max_path]u8 = undefined;
    const dir = try pin.serversDir(&dir_buf);
    var stem_buf: [80]u8 = undefined;
    const stem = try pin.fileStem(host, &stem_buf);
    return std.fmt.bufPrint(out, "{s}" ++ std.fs.path.sep_str ++ "{s}.sync-key", .{ dir, stem }) catch error.PathTooLong;
}

/// The key text the server sends (GET /sync/key) and the pin file holds.
pub fn format(key: Key, out: *[header.len + 1 + 64 + 1]u8) []const u8 {
    @memcpy(out[0..header.len], header);
    out[header.len] = '\n';
    _ = manifest.hexLower(&key, out[header.len + 1 ..][0..64]);
    out[out.len - 1] = '\n';
    return out;
}

pub fn parse(text: []const u8) ?Key {
    const want = header.len + 1 + 64 + 1;
    if (text.len != want or !std.mem.startsWith(u8, text, header ++ "\n") or text[want - 1] != '\n') return null;
    const hex = text[header.len + 1 .. want - 1];
    for (hex) |c| switch (c) {
        '0'...'9', 'a'...'f' => {},
        else => return null,
    };
    return manifest.parseHex(manifest.public_key_len, hex);
}

pub fn load(io: Io, host: []const u8) !?Key {
    var pb: [pin.max_path]u8 = undefined;
    var buf: [256]u8 = undefined;
    const text = Io.Dir.cwd().readFile(io, try pinPath(host, &pb), &buf) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => |e| return e,
    };
    return parse(text) orelse error.BadKeyPin;
}

/// Pins `key` for `host`: a flushed temp file renamed over the old pin, so
/// a crash leaves the old pin or the new one, never a truncated file.
pub fn save(io: Io, host: []const u8, key: Key) !void {
    var pb: [pin.max_path]u8 = undefined;
    const p = try pinPath(host, &pb);
    if (std.fs.path.dirname(p)) |d| try Io.Dir.cwd().createDirPath(io, d);
    var tb: [header.len + 66]u8 = undefined;
    try store.writeAtomic(std.heap.page_allocator, io, p, format(key, &tb));
}

pub fn delete(io: Io, host: []const u8) !void {
    var pb: [pin.max_path]u8 = undefined;
    Io.Dir.cwd().deleteFile(io, try pinPath(host, &pb)) catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    };
}

/// The device's sync store folder (not created):
///   Windows  %LOCALAPPDATA%\Portal\sync
///   macOS    ~/Library/Application Support/Portal/sync
///   Linux    $XDG_DATA_HOME/portal/sync (~/.local/share/portal/sync)
pub fn syncRoot(out: *[pin.max_path]u8) ![]const u8 {
    var env_buf: [pin.max_path]u8 = undefined;
    const r = switch (builtin.os.tag) {
        .windows => blk: {
            const base = pin.envVar("LOCALAPPDATA", &env_buf) orelse return error.NoConfigDir;
            break :blk std.fmt.bufPrint(out, "{s}\\Portal\\sync", .{base});
        },
        // iOS: HOME is the app container; Library/Application Support
        // is private to the app and backed up (only public data here).
        .macos, .ios => blk: {
            const home = pin.envVar("HOME", &env_buf) orelse return error.NoConfigDir;
            break :blk std.fmt.bufPrint(out, "{s}/Library/Application Support/Portal/sync", .{home});
        },
        else => blk: {
            if (pin.envVar("XDG_DATA_HOME", &env_buf)) |x| if (std.fs.path.isAbsolute(x))
                break :blk std.fmt.bufPrint(out, "{s}/portal/sync", .{x});
            const home = pin.envVar("HOME", &env_buf) orelse return error.NoConfigDir;
            break :blk std.fmt.bufPrint(out, "{s}/.local/share/portal/sync", .{home});
        },
    };
    return r catch error.PathTooLong;
}

/// "10.8.0.1_8420-3f2a9c0d11b7e4a5": the folder name for one desktop.
pub fn desktopFolderName(host: []const u8, key: Key, out: *[96]u8) ![]const u8 {
    var stem_buf: [80]u8 = undefined;
    const stem = try pin.fileStem(host, &stem_buf);
    const fp = manifest.fingerprint(key);
    var hex: [64]u8 = undefined;
    return std.fmt.bufPrint(out, "{s}-{s}", .{ stem, manifest.hexLower(&fp, &hex)[0..16] }) catch error.PathTooLong;
}

/// The desktop's own sync folder (not created): everything Portal sync
/// keeps for `host` with release key `key` lives under it.
pub fn desktopRoot(host: []const u8, key: Key, out: *[pin.max_path]u8) ![]const u8 {
    var rb: [pin.max_path]u8 = undefined;
    const root = try syncRoot(&rb);
    var nb: [96]u8 = undefined;
    const name = try desktopFolderName(host, key, &nb);
    return std.fmt.bufPrint(out, "{s}" ++ std.fs.path.sep_str ++ "desktops" ++ std.fs.path.sep_str ++ "{s}", .{ root, name }) catch error.PathTooLong;
}

/// What the shared, un-namespaced store of earlier builds left directly
/// under the sync root. It is never read or written any more (its pointers
/// could have been written by any desktop), so it is deleted on start.
pub const legacy_entries = [_][]const u8{ "packages", "current", "previous" };

/// Deletes the shared store of earlier builds (`legacy_entries` under the
/// sync root), the same way `deleteDesktopFolders` deletes a desktop: each
/// entry is renamed to <sync root>\.trash-<random>, then deleted, so a
/// half-deleted one is never mistaken for a store. Anything still in use
/// (a running program) stays and is counted in `kept`; leftover .trash-*
/// entries from an earlier attempt are retried. Never touches desktops\.
pub fn removeLegacyStore(io: Io) !Dropped {
    var rb: [pin.max_path]u8 = undefined;
    return removeLegacyStoreAt(io, try syncRoot(&rb));
}

pub fn removeLegacyStoreAt(io: Io, root: []const u8) !Dropped {
    var r: Dropped = .{};
    var names: [16][96]u8 = undefined;
    var lens: [16]usize = undefined;
    var n: usize = 0;
    {
        var dir = Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return r,
            else => |e| return e,
        };
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            if (n == names.len) break;
            var legacy = std.mem.startsWith(u8, e.name, ".trash-");
            for (legacy_entries) |l| legacy = legacy or std.mem.eql(u8, e.name, l);
            if (!legacy or e.name.len > 96) continue;
            @memcpy(names[n][0..e.name.len], e.name);
            lens[n] = e.name.len;
            n += 1;
        }
    }
    for (names[0..n], lens[0..n]) |*name_buf, len| {
        const name = name_buf[0..len];
        var fb: [pin.max_path + 128]u8 = undefined;
        const full = std.fmt.bufPrint(&fb, "{s}" ++ std.fs.path.sep_str ++ "{s}", .{ root, name }) catch continue;
        var target = full;
        var tb: [pin.max_path + 128]u8 = undefined;
        const retry = std.mem.startsWith(u8, name, ".trash-");
        if (!retry) {
            var rnd: [8]u8 = undefined;
            io.random(&rnd);
            var hb: [16]u8 = undefined;
            const t = std.fmt.bufPrint(&tb, "{s}" ++ std.fs.path.sep_str ++ ".trash-{s}", .{ root, manifest.hexLower(&rnd, &hb) }) catch continue;
            if (Io.Dir.rename(Io.Dir.cwd(), full, Io.Dir.cwd(), t, io)) |_| {
                target = t;
            } else |_| {}
        }
        Io.Dir.cwd().deleteTree(io, target) catch {};
        if (Io.Dir.cwd().access(io, target, .{})) |_| {
            r.kept += 1;
        } else |_| {
            if (!retry) r.removed += 1;
        }
    }
    return r;
}

pub const Dropped = struct {
    /// Desktop folders deleted completely.
    removed: usize = 0,
    /// Folders (or parts) that stayed because something still uses them
    /// (a running program); moved aside as desktops\.trash-* when possible.
    kept: usize = 0,
};

/// Deletes every sync folder of `host` (any release key):
/// <sync root>\desktops\<host stem>-*. Each is first renamed to
/// desktops\.trash-<random> (so a half-deleted folder is never mistaken for
/// a store), then deleted.
pub fn deleteDesktopFolders(io: Io, host: []const u8) !Dropped {
    var r: Dropped = .{};
    var rb: [pin.max_path]u8 = undefined;
    const root = try syncRoot(&rb);
    var db: [pin.max_path + 16]u8 = undefined;
    const dir_path = std.fmt.bufPrint(&db, "{s}" ++ std.fs.path.sep_str ++ "desktops", .{root}) catch return error.PathTooLong;
    var stem_buf: [80]u8 = undefined;
    const stem = try pin.fileStem(host, &stem_buf);
    var names: [32][96]u8 = undefined;
    var lens: [32]usize = undefined;
    var n: usize = 0;
    {
        var dir = Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return r,
            else => |e| return e,
        };
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            if (n == names.len) break;
            const trash = std.mem.startsWith(u8, e.name, ".trash-");
            const mine = e.name.len == stem.len + 17 and std.mem.startsWith(u8, e.name, stem) and e.name[stem.len] == '-';
            if (e.kind != .directory or e.name.len > 96 or !(mine or trash)) continue;
            @memcpy(names[n][0..e.name.len], e.name);
            lens[n] = e.name.len;
            n += 1;
        }
    }
    for (names[0..n], lens[0..n]) |*name_buf, len| {
        const name = name_buf[0..len];
        var fb: [pin.max_path + 128]u8 = undefined;
        const full = std.fmt.bufPrint(&fb, "{s}" ++ std.fs.path.sep_str ++ "{s}", .{ dir_path, name }) catch continue;
        var target = full;
        var tb: [pin.max_path + 128]u8 = undefined;
        if (!std.mem.startsWith(u8, name, ".trash-")) {
            var rnd: [8]u8 = undefined;
            io.random(&rnd);
            var hb: [16]u8 = undefined;
            const t = std.fmt.bufPrint(&tb, "{s}" ++ std.fs.path.sep_str ++ ".trash-{s}", .{ dir_path, manifest.hexLower(&rnd, &hb) }) catch continue;
            if (Io.Dir.rename(Io.Dir.cwd(), full, Io.Dir.cwd(), t, io)) |_| {
                target = t;
            } else |_| {}
        }
        Io.Dir.cwd().deleteTree(io, target) catch {};
        if (Io.Dir.cwd().access(io, target, .{})) |_| {
            r.kept += 1;
        } else |_| {
            if (!std.mem.startsWith(u8, name, ".trash-")) r.removed += 1;
        }
    }
    return r;
}

test "desktop folder names: host stem and key fingerprint" {
    var b: [96]u8 = undefined;
    const k: Key = @splat(0xab);
    const name = try desktopFolderName("10.8.0.1:8420", k, &b);
    var hex: [64]u8 = undefined;
    const fp = manifest.fingerprint(k);
    try std.testing.expect(std.mem.startsWith(u8, name, "10.8.0.1_8420-"));
    try std.testing.expectEqualStrings(manifest.hexLower(&fp, &hex)[0..16], name["10.8.0.1_8420-".len..]);
    var b2: [96]u8 = undefined;
    try std.testing.expect(!std.mem.eql(u8, name, try desktopFolderName("10.8.0.2:8420", k, &b2)));
    try std.testing.expect(!std.mem.eql(u8, name, try desktopFolderName("10.8.0.1:8420", @splat(0xac), &b2)));
    try std.testing.expectEqualStrings("fd00--1_8420-", (try desktopFolderName("[fd00::1]:8420", k, &b2))[0..13]);
}

test "removeLegacyStoreAt deletes the old shared store, never desktops\\" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "packages" ++ std.fs.path.sep_str ++ "stt-model" ++ std.fs.path.sep_str ++ "1");
    try tmp.dir.writeFile(io, .{ .sub_path = "current", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "previous", .data = "y" });
    try tmp.dir.createDirPath(io, "desktops" ++ std.fs.path.sep_str ++ "10.8.0.1_8420-0011223344556677" ++ std.fs.path.sep_str ++ "packages");
    try tmp.dir.createDirPath(io, ".trash-0123456789abcdef");
    var rb: [256]u8 = undefined;
    const root = try std.fmt.bufPrint(&rb, ".zig-cache" ++ std.fs.path.sep_str ++ "tmp" ++ std.fs.path.sep_str ++ "{s}", .{&tmp.sub_path});
    const r = try removeLegacyStoreAt(io, root);
    try std.testing.expectEqual(@as(usize, 3), r.removed);
    try std.testing.expectEqual(@as(usize, 0), r.kept);
    for ([_][]const u8{ "packages", "current", "previous", ".trash-0123456789abcdef" }) |gone|
        try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, gone, .{}));
    try tmp.dir.access(io, "desktops" ++ std.fs.path.sep_str ++ "10.8.0.1_8420-0011223344556677" ++ std.fs.path.sep_str ++ "packages", .{});
    // Nothing left: a second run finds nothing.
    const again = try removeLegacyStoreAt(io, root);
    try std.testing.expectEqual(@as(usize, 0), again.removed + again.kept);
}

test "key text round trip and strictness" {
    const k: Key = @splat(0xab);
    var b: [header.len + 66]u8 = undefined;
    const t = format(k, &b);
    try std.testing.expectEqual(k, parse(t).?);
    try std.testing.expect(parse("portal-sync-key-v1\nAB\n") == null);
    var upper = b;
    upper[header.len + 1] = 'A';
    try std.testing.expect(parse(&upper) == null);
}
