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

fn envVar(comptime name: []const u8, buf: []u8) ?[]const u8 {
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
        .macos => blk: {
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
