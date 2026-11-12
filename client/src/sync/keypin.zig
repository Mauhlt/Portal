//! The release key pinned for each server, next to its pinned CA
//! (net/pin.zig), and where the device's sync store lives.
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

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const pin = @import("../net/pin.zig");
const manifest = @import("manifest.zig");

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

pub fn save(io: Io, host: []const u8, key: Key) !void {
    var pb: [pin.max_path]u8 = undefined;
    const p = try pinPath(host, &pb);
    if (std.fs.path.dirname(p)) |d| try Io.Dir.cwd().createDirPath(io, d);
    var tb: [header.len + 66]u8 = undefined;
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = format(key, &tb) });
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
        .macos => blk: {
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
