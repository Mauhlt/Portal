//! The Portal CA pinned for each server: a public certificate, stored in the
//! per-user config directory (not secret, so not in the credential store):
//!
//!   Windows  %APPDATA%\Portal\servers\<host>.pem
//!   macOS    ~/Library/Application Support/Portal/servers/<host>.pem
//!   Linux    $XDG_CONFIG_HOME/portal/servers/<host>.pem (~/.config/...)
//!
//! `<host>` is the canonical IP:PORT with ':' written as '_' (last one, the
//! port) and '-' (IPv6), e.g. 10.8.0.1_8420.pem, fd00--1_8420.pem.
//! A pin is only ever created by an explicit `--ca FILE` or a CA download
//! checked against `--ca-sha256`; nothing is trusted on first use.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const x509check = @import("x509check.zig");

pub const max_path = 1024;

pub const Error = error{ NoConfigDir, PathTooLong };

pub fn envVar(comptime name: []const u8, buf: []u8) ?[]const u8 {
    if (builtin.os.tag == .windows) {
        const env: std.process.Environ = .{ .block = .global };
        const w = env.getWindows(std.unicode.utf8ToUtf16LeStringLiteral(name)) orelse return null;
        if (w.len == 0) return null;
        const n = std.unicode.calcWtf8Len(w);
        if (n > buf.len) return null;
        return buf[0..std.unicode.wtf16LeToWtf8(buf, w)];
    } else {
        const v = std.c.getenv(std.fmt.comptimePrint("{s}", .{name})) orelse return null;
        const s = std.mem.sliceTo(v, 0);
        if (s.len == 0 or s.len > buf.len) return null;
        @memcpy(buf[0..s.len], s);
        return buf[0..s.len];
    }
}

/// The directory holding pinned CAs (not created).
pub fn serversDir(out: *[max_path]u8) Error![]const u8 {
    var env_buf: [max_path]u8 = undefined;
    const sep = std.fs.path.sep_str;
    const r = switch (builtin.os.tag) {
        .windows => blk: {
            const appdata = envVar("APPDATA", &env_buf) orelse return error.NoConfigDir;
            break :blk std.fmt.bufPrint(out, "{s}" ++ sep ++ "Portal" ++ sep ++ "servers", .{appdata});
        },
        // iOS: HOME is the app container; Library/Application Support
        // is private to the app and backed up (only public data here).
        .macos, .ios => blk: {
            const home = envVar("HOME", &env_buf) orelse return error.NoConfigDir;
            break :blk std.fmt.bufPrint(out, "{s}/Library/Application Support/Portal/servers", .{home});
        },
        else => blk: {
            if (envVar("XDG_CONFIG_HOME", &env_buf)) |x| if (std.fs.path.isAbsolute(x))
                break :blk std.fmt.bufPrint(out, "{s}/portal/servers", .{x});
            const home = envVar("HOME", &env_buf) orelse return error.NoConfigDir;
            break :blk std.fmt.bufPrint(out, "{s}/.config/portal/servers", .{home});
        },
    };
    return r catch error.PathTooLong;
}

/// The file remembering the last server connected to (next to the
/// servers directory): what `portal connect` with no --server uses.
pub fn lastServerPath(out: *[max_path]u8) Error![]const u8 {
    var dir_buf: [max_path]u8 = undefined;
    const sdir = try serversDir(&dir_buf);
    const parent = std.fs.path.dirname(sdir) orelse return error.NoConfigDir;
    return std.fmt.bufPrint(out, "{s}" ++ std.fs.path.sep_str ++ "last-server.txt", .{parent}) catch error.PathTooLong;
}

/// The device's settings (next to the servers directory), e.g.
/// `swipe = left-yes` (ui/convoview.zig parseSwipeSetting).
pub fn deviceSettingsPath(out: *[max_path]u8) Error![]const u8 {
    var dir_buf: [max_path]u8 = undefined;
    const sdir = try serversDir(&dir_buf);
    const parent = std.fs.path.dirname(sdir) orelse return error.NoConfigDir;
    return std.fmt.bufPrint(out, "{s}" ++ std.fs.path.sep_str ++ "settings.txt", .{parent}) catch error.PathTooLong;
}

/// The tabs this device hides from its tab bar (ui/hidden_tabs.zig), next
/// to the settings file: one name per line.
pub fn hiddenTabsPath(out: *[max_path]u8) Error![]const u8 {
    var dir_buf: [max_path]u8 = undefined;
    const sdir = try serversDir(&dir_buf);
    const parent = std.fs.path.dirname(sdir) orelse return error.NoConfigDir;
    return std.fmt.bufPrint(out, "{s}" ++ std.fs.path.sep_str ++ "hidden-tabs.txt", .{parent}) catch error.PathTooLong;
}

/// The hidden tabs file's text (empty if there is none), into `buf`.
pub fn loadHiddenTabs(io: Io, buf: []u8) []const u8 {
    var pbuf: [max_path]u8 = undefined;
    const p = hiddenTabsPath(&pbuf) catch return "";
    return Io.Dir.cwd().readFile(io, p, buf) catch "";
}

pub fn saveHiddenTabs(io: Io, text: []const u8) !void {
    var pbuf: [max_path]u8 = undefined;
    const p = try hiddenTabsPath(&pbuf);
    if (std.fs.path.dirname(p)) |d| try Io.Dir.cwd().createDirPath(io, d);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = text });
}

/// The device's settings text (empty if there is no file), into `buf`.
pub fn loadDeviceSettings(io: Io, buf: []u8) []const u8 {
    var pbuf: [max_path]u8 = undefined;
    const p = deviceSettingsPath(&pbuf) catch return "";
    return Io.Dir.cwd().readFile(io, p, buf) catch "";
}

/// The remembered server ("IP:PORT"), if any.
pub fn loadLastServer(io: Io, out: *[64]u8) ?[]const u8 {
    var pbuf: [max_path]u8 = undefined;
    const p = lastServerPath(&pbuf) catch return null;
    var fbuf: [128]u8 = undefined;
    const data = Io.Dir.cwd().readFile(io, p, &fbuf) catch return null;
    const t = std.mem.trim(u8, data, " \t\r\n");
    if (t.len == 0 or t.len > out.len) return null;
    @memcpy(out[0..t.len], t);
    return out[0..t.len];
}

pub fn saveLastServer(io: Io, host: []const u8) !void {
    var pbuf: [max_path]u8 = undefined;
    const p = try lastServerPath(&pbuf);
    if (std.fs.path.dirname(p)) |d| try Io.Dir.cwd().createDirPath(io, d);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = host });
}

/// Where the Portal window's "Export certificate" puts the CA by default
/// (<home>/Downloads/Portal-CA/portal-ca.pem), to prefill the first-run
/// screen when the file was copied over to the same place.
pub fn defaultCaFile(out: *[max_path]u8) ?[]const u8 {
    var env_buf: [max_path]u8 = undefined;
    const home = (if (builtin.os.tag == .windows) envVar("USERPROFILE", &env_buf) else envVar("HOME", &env_buf)) orelse return null;
    const sep = std.fs.path.sep_str;
    return std.fmt.bufPrint(out, "{s}" ++ sep ++ "Downloads" ++ sep ++ "Portal-CA" ++ sep ++ "portal-ca.pem", .{home}) catch null;
}

/// "10.8.0.1:8420" -> "10.8.0.1_8420", "[fd00::1]:8420" -> "fd00--1_8420".
pub fn fileStem(host: []const u8, out: []u8) Error![]const u8 {
    const last = std.mem.lastIndexOfScalar(u8, host, ':') orelse return error.PathTooLong;
    var n: usize = 0;
    for (host, 0..) |ch, i| {
        const o: u8 = switch (ch) {
            '[', ']' => continue,
            ':' => if (i == last) '_' else '-',
            '0'...'9', 'a'...'z', 'A'...'Z', '.' => ch,
            else => return error.PathTooLong, // canonical hosts never have these
        };
        if (n == out.len) return error.PathTooLong;
        out[n] = o;
        n += 1;
    }
    return out[0..n];
}

pub const Pin = struct {
    dir_buf: [max_path]u8 = undefined,
    dir_len: usize = 0,
    path_buf: [max_path]u8 = undefined,
    path_len: usize = 0,

    pub fn forHost(host: []const u8) Error!Pin {
        var p: Pin = .{};
        const sdir = try serversDir(&p.dir_buf);
        p.dir_len = sdir.len;
        var stem_buf: [80]u8 = undefined;
        const stem = try fileStem(host, &stem_buf);
        p.path_len = (std.fmt.bufPrint(&p.path_buf, "{s}" ++ std.fs.path.sep_str ++ "{s}.pem", .{ sdir, stem }) catch
            return error.PathTooLong).len;
        return p;
    }

    pub fn dir(p: *const Pin) []const u8 {
        return p.dir_buf[0..p.dir_len];
    }
    pub fn path(p: *const Pin) []const u8 {
        return p.path_buf[0..p.path_len];
    }

    /// The pinned CA (DER, in `out`), or null if none is pinned.
    pub fn load(p: *const Pin, io: Io, out: *[x509check.max_cert_len]u8) !?[]const u8 {
        var file_buf: [4 * x509check.max_cert_len]u8 = undefined;
        const data = Io.Dir.cwd().readFile(io, p.path(), &file_buf) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => |e| return e,
        };
        return try x509check.loadCertificate(data, out);
    }

    /// Pins `der` (replacing any previous pin).
    pub fn save(p: *const Pin, io: Io, der: []const u8) !void {
        try Io.Dir.cwd().createDirPath(io, p.dir());
        var pem_buf: [3 * x509check.max_cert_len]u8 = undefined;
        var w: Io.Writer = .fixed(&pem_buf);
        try x509check.writePem(&w, der);
        try Io.Dir.cwd().writeFile(io, .{ .sub_path = p.path(), .data = w.buffered() });
    }

    pub fn delete(p: *const Pin, io: Io) !void {
        Io.Dir.cwd().deleteFile(io, p.path()) catch |err| switch (err) {
            error.FileNotFound => {},
            else => |e| return e,
        };
    }
};

/// Reads a user-supplied CA file (.pem or .cer) into `out`.
pub fn readCaFile(io: Io, file_path: []const u8, out: *[x509check.max_cert_len]u8) ![]const u8 {
    var file_buf: [4 * x509check.max_cert_len]u8 = undefined;
    const data = try Io.Dir.cwd().readFile(io, file_path, &file_buf);
    return x509check.loadCertificate(data, out);
}

test "file names for hosts" {
    var buf: [80]u8 = undefined;
    try std.testing.expectEqualStrings("10.8.0.1_8420", try fileStem("10.8.0.1:8420", &buf));
    try std.testing.expectEqualStrings("fd00--1_8420", try fileStem("[fd00::1]:8420", &buf));
    try std.testing.expectError(error.PathTooLong, fileStem("..\\x:1", &buf));
}
