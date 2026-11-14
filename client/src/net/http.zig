//! The HTTP/1.1 the client still speaks: only the WebSocket upgrade
//! request (`GET /ws`, the interactive channel, and `GET /ws/bulk`, the
//! bulk one) and a strict parser for the response head. There are no
//! cookies: a device is its WireGuard key (src/devices.zig), and the
//! desktop knows which device is asking from the tunnel address alone.
//! Pure functions over byte slices; responses are untrusted and never
//! cause a panic.

const std = @import("std");
/// Header syntax shared with the server (shared/http.zig).
const syntax = @import("shared").http;

pub const max_head_bytes = 8 * 1024;
pub const max_headers = 64;

pub const Channel = enum {
    /// Keystrokes, screen, conversation, status (priority .interactive).
    interactive,
    /// Sync transfers (priority .bulk; shared/bulk.zig).
    bulk,

    pub fn path(ch: Channel) []const u8 {
        return switch (ch) {
            .interactive => "/ws",
            .bulk => "/ws/bulk",
        };
    }
};

pub fn writeUpgradeRequest(w: *std.Io.Writer, host: []const u8, channel: Channel, key: []const u8) !void {
    try w.print("GET {s} HTTP/1.1\r\nHost: {s}\r\n" ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n", .{ channel.path(), host, key });
}

/// "IP:PORT" (IPv4) or "[IPv6]:PORT", normalised. Only literal addresses are
/// accepted: the client talks to its tunnel peer and never resolves names.
pub fn canonicalHost(text: []const u8, out: []u8) ![]const u8 {
    if (text.len == 0 or text.len > 64) return error.BadServerAddress;
    const addr = std.Io.net.IpAddress.parseLiteral(text) catch return error.BadServerAddress;
    if (addr.getPort() == 0) return error.BadServerAddress;
    return std.fmt.bufPrint(out, "{f}", .{addr}) catch error.BadServerAddress;
}

pub const findHeadEnd = syntax.findHeadEnd;

pub const Response = struct {
    status: u16,
    upgrade_websocket: bool = false,
    connection_upgrade: bool = false,
    accept: ?[]const u8 = null,
};

pub const ParseError = error{ BadStatusLine, BadHeader, TooManyHeaders };

pub fn parseResponseHead(head: []const u8) ParseError!Response {
    if (head.len < 4 or !std.mem.endsWith(u8, head, "\r\n\r\n")) return error.BadStatusLine;
    var lines = std.mem.splitSequence(u8, head[0 .. head.len - 4], "\r\n");
    const status_line = lines.first();
    // "HTTP/1.1 101 Switching Protocols"
    if (status_line.len < 12 or !std.mem.startsWith(u8, status_line, "HTTP/1.")) return error.BadStatusLine;
    if (status_line[8] != ' ') return error.BadStatusLine;
    if (status_line.len > 12 and status_line[12] != ' ') return error.BadStatusLine;
    const status = std.fmt.parseInt(u16, status_line[9..12], 10) catch return error.BadStatusLine;
    if (status < 100 or status > 599) return error.BadStatusLine;
    var resp: Response = .{ .status = status };
    var count: usize = 0;
    while (lines.next()) |line| {
        count += 1;
        if (count > max_headers) return error.TooManyHeaders;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.BadHeader;
        const name = line[0..colon];
        if (!syntax.isToken(name)) return error.BadHeader;
        const val = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (!syntax.validValue(val)) return error.BadHeader;
        if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
            if (std.ascii.eqlIgnoreCase(val, "websocket")) resp.upgrade_websocket = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            var it = std.mem.splitScalar(u8, val, ',');
            while (it.next()) |tok| {
                if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, tok, " \t"), "upgrade")) resp.connection_upgrade = true;
            }
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-accept")) {
            resp.accept = val;
        }
    }
    return resp;
}

const testing = std.testing;

test "upgrade response and malformed heads" {
    const r = try parseResponseHead("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" ++
        "Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n");
    try testing.expect(r.upgrade_websocket and r.connection_upgrade);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", r.accept.?);
    try testing.expectError(error.BadStatusLine, parseResponseHead("HTTP/1.1 9x9 Nope\r\n\r\n"));
    try testing.expectError(error.BadStatusLine, parseResponseHead("garbage\r\n\r\n"));
    try testing.expectError(error.BadStatusLine, parseResponseHead("HTTP/1.1 200"));
    try testing.expectError(error.BadHeader, parseResponseHead("HTTP/1.1 200 OK\r\nNoColon\r\n\r\n"));
    try testing.expectError(error.BadHeader, parseResponseHead("HTTP/1.1 200 OK\r\nX: a\x00b\r\n\r\n"));
    const refused = try parseResponseHead("HTTP/1.1 403 Forbidden\r\n\r\n");
    try testing.expectEqual(@as(u16, 403), refused.status);
}

test "fuzz: response parser never panics" {
    var prng = std.Random.DefaultPrng.init(3);
    const rand = prng.random();
    var buf: [256]u8 = undefined;
    const alphabet = "HTTP/1. 0123456789:\r\nUpgrade Connection websocket Sec-WebSocket-Accept";
    for (0..50000) |_| {
        const n = rand.uintLessThan(usize, buf.len);
        for (buf[0..n]) |*b| b.* = if (rand.boolean()) alphabet[rand.uintLessThan(usize, alphabet.len)] else rand.int(u8);
        if (n >= 4) @memcpy(buf[n - 4 .. n], "\r\n\r\n");
        _ = parseResponseHead(buf[0..n]) catch {};
    }
}

test "upgrade requests carry no cookie, only the channel" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeUpgradeRequest(&w, "10.8.0.1:8420", .bulk, "dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expect(std.mem.startsWith(u8, w.buffered(), "GET /ws/bulk HTTP/1.1\r\nHost: 10.8.0.1:8420\r\n"));
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "ookie") == null);
}
