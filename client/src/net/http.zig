//! HTTP/1.1 pieces the client needs: device pairing (`POST /pair`), session
//! refresh (`POST /auth/refresh`), the WebSocket upgrade request, and a
//! strict parser for response heads (status, Location, Set-Cookie, upgrade
//! fields). Pure functions over byte slices; responses are untrusted and
//! never cause a panic.

const std = @import("std");

pub const max_head_bytes = 8 * 1024;
pub const max_headers = 64;
/// Device cookie values are "<name>.<43-char secret>"; session values are 43.
pub const max_cookie_value = 200;

pub const CookieKind = enum { session, device };

const CookieName = struct { name: []const u8, kind: CookieKind };
/// `__Host-` variants are used when the server runs with --https.
pub const cookie_names = [_]CookieName{
    .{ .name = "portal_session", .kind = .session },
    .{ .name = "__Host-portal", .kind = .session },
    .{ .name = "portal_device", .kind = .device },
    .{ .name = "__Host-portal_device", .kind = .device },
};

/// A cookie value. The session cookie lives in memory only; the device
/// cookie is persisted only through the OS credential store (credstore.zig).
pub const Cookie = struct {
    name_index: u8 = 0,
    value_buf: [max_cookie_value]u8 = undefined,
    value_len: u8 = 0,

    pub fn name(c: *const Cookie) []const u8 {
        return cookie_names[c.name_index].name;
    }
    pub fn kind(c: *const Cookie) CookieKind {
        return cookie_names[c.name_index].kind;
    }
    pub fn value(c: *const Cookie) []const u8 {
        return c.value_buf[0..c.value_len];
    }
    pub fn wipe(c: *Cookie) void {
        std.crypto.secureZero(u8, &c.value_buf);
        c.value_len = 0;
    }
    /// Builds a cookie from a stored value; null if the value is not valid.
    pub fn fromValue(k: CookieKind, v: []const u8) ?Cookie {
        if (!validValue(k, v)) return null;
        var c: Cookie = .{ .name_index = if (k == .session) 0 else 2, .value_len = @intCast(v.len) };
        @memcpy(c.value_buf[0..v.len], v);
        return c;
    }
};

fn validValue(k: CookieKind, v: []const u8) bool {
    if (v.len == 0 or v.len > max_cookie_value) return false;
    for (v) |c| {
        const ok = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or (k == .device and c == '.');
        if (!ok) return false;
    }
    return true;
}

/// Writes `POST /pair`. `host` must already be canonical (see canonicalHost).
pub fn writePairRequest(w: *std.Io.Writer, host: []const u8) !void {
    try w.print("POST /pair HTTP/1.1\r\nHost: {s}\r\nOrigin: http://{s}\r\n" ++
        "Content-Length: 0\r\nConnection: close\r\n\r\n", .{ host, host });
}

/// Writes `POST /auth/refresh` with the stored device cookie.
pub fn writeRefreshRequest(w: *std.Io.Writer, host: []const u8, device: *const Cookie) !void {
    try w.print("POST /auth/refresh HTTP/1.1\r\nHost: {s}\r\nOrigin: http://{s}\r\nCookie: {s}={s}\r\n" ++
        "Content-Length: 0\r\nConnection: close\r\n\r\n", .{ host, host, device.name(), device.value() });
}

pub fn writeUpgradeRequest(w: *std.Io.Writer, host: []const u8, session: *const Cookie, key: []const u8) !void {
    try w.print("GET /ws HTTP/1.1\r\nHost: {s}\r\nOrigin: http://{s}\r\nCookie: {s}={s}\r\n" ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n", .{ host, host, session.name(), session.value(), key });
}

/// "IP:PORT" (IPv4) or "[IPv6]:PORT", normalised. Only literal addresses are
/// accepted: the client talks to a WireGuard peer and never resolves names.
pub fn canonicalHost(text: []const u8, out: []u8) ![]const u8 {
    if (text.len == 0 or text.len > 64) return error.BadServerAddress;
    const addr = std.Io.net.IpAddress.parseLiteral(text) catch return error.BadServerAddress;
    if (addr.getPort() == 0) return error.BadServerAddress;
    return std.fmt.bufPrint(out, "{f}", .{addr}) catch error.BadServerAddress;
}

pub fn findHeadEnd(buf: []const u8) ?usize {
    const i = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse return null;
    return i + 4;
}

pub const Response = struct {
    status: u16,
    location: ?[]const u8 = null,
    session: ?Cookie = null,
    device: ?Cookie = null,
    /// A Set-Cookie that clears one of our cookies (Max-Age=0 or empty value).
    cookie_cleared: bool = false,
    upgrade_websocket: bool = false,
    connection_upgrade: bool = false,
    accept: ?[]const u8 = null,
};

pub const ParseError = error{ BadStatusLine, BadHeader, TooManyHeaders };

pub fn parseResponseHead(head: []const u8) ParseError!Response {
    if (head.len < 4 or !std.mem.endsWith(u8, head, "\r\n\r\n")) return error.BadStatusLine;
    var lines = std.mem.splitSequence(u8, head[0 .. head.len - 4], "\r\n");
    const status_line = lines.first();
    // "HTTP/1.1 303 See Other"
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
        if (name.len == 0 or std.mem.indexOfAny(u8, name, " \t") != null) return error.BadHeader;
        const val = std.mem.trim(u8, line[colon + 1 ..], " \t");
        for (val) |c| if ((c < 0x20 and c != '\t') or c == 0x7f) return error.BadHeader;
        if (std.ascii.eqlIgnoreCase(name, "location")) {
            resp.location = val;
        } else if (std.ascii.eqlIgnoreCase(name, "set-cookie")) {
            switch (parseSetCookie(val)) {
                .set => |c| switch (c.kind()) {
                    .session => resp.session = c,
                    .device => resp.device = c,
                },
                .cleared => resp.cookie_cleared = true,
                .other => {},
            }
        } else if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
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

pub const SetCookieResult = union(enum) { set: Cookie, cleared, other };

/// Parses a Set-Cookie value. Only Portal's cookie names are recognised;
/// values must be base64url (plus '.' for the device cookie), 1..200 bytes.
pub fn parseSetCookie(header: []const u8) SetCookieResult {
    var parts = std.mem.splitScalar(u8, header, ';');
    const pair = std.mem.trim(u8, parts.first(), " \t");
    const eq = std.mem.indexOfScalar(u8, pair, '=') orelse return .other;
    const name = std.mem.trim(u8, pair[0..eq], " \t");
    var v = std.mem.trim(u8, pair[eq + 1 ..], " \t");
    if (v.len >= 2 and v[0] == '"' and v[v.len - 1] == '"') v = v[1 .. v.len - 1];
    var idx: ?u8 = null;
    for (cookie_names, 0..) |n, i| {
        if (std.mem.eql(u8, name, n.name)) idx = @intCast(i);
    }
    const name_index = idx orelse return .other;
    while (parts.next()) |attr_raw| {
        const attr = std.mem.trim(u8, attr_raw, " \t");
        if (std.ascii.startsWithIgnoreCase(attr, "max-age=")) {
            const age = std.fmt.parseInt(i64, attr["max-age=".len..], 10) catch continue;
            if (age <= 0) return .cleared;
        }
    }
    if (v.len == 0) return .cleared;
    if (!validValue(cookie_names[name_index].kind, v)) return .other;
    var c: Cookie = .{ .name_index = name_index, .value_len = @intCast(v.len) };
    @memcpy(c.value_buf[0..v.len], v);
    return .{ .set = c };
}

pub const PairOutcome = enum { ok, closed, unexpected };

/// `POST /pair`: 303 with both cookies, or 303 to /pair?e=closed.
pub fn pairOutcome(r: *const Response) PairOutcome {
    if (r.status == 303 or r.status == 302) {
        if (r.device != null and r.session != null) return .ok;
        if (r.location) |loc| if (std.mem.startsWith(u8, loc, "/pair")) return .closed;
    }
    return .unexpected;
}

pub const RefreshOutcome = enum { ok, revoked, unexpected };

/// `POST /auth/refresh`: 204 with a rotated device cookie and a fresh session
/// cookie; 401 means the device is revoked or unknown.
pub fn refreshOutcome(r: *const Response) RefreshOutcome {
    if (r.status == 401) return .revoked;
    if ((r.status == 204 or r.status == 200) and r.device != null and r.session != null) return .ok;
    return .unexpected;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "set-cookie parsing" {
    const v43 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123-_6";
    const r = parseSetCookie("portal_session=" ++ v43 ++ "; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200");
    try testing.expectEqualStrings(v43, r.set.value());
    try testing.expectEqualStrings("portal_session", r.set.name());
    try testing.expectEqual(CookieKind.session, r.set.kind());
    const d = parseSetCookie("portal_device=laptop." ++ v43 ++ "; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000");
    try testing.expectEqual(CookieKind.device, d.set.kind());
    try testing.expectEqualStrings("laptop." ++ v43, d.set.value());
    // '.' is only allowed in device values.
    try testing.expect(parseSetCookie("portal_session=a.b") == .other);
    const s = parseSetCookie("__Host-portal=abc; Path=/; Secure; HttpOnly");
    try testing.expectEqualStrings("__Host-portal", s.set.name());
    try testing.expect(parseSetCookie("portal_session=; Path=/; Max-Age=0") == .cleared);
    try testing.expect(parseSetCookie("portal_device=x.y; Max-Age=0") == .cleared);
    try testing.expect(parseSetCookie("other=abc") == .other);
    try testing.expect(parseSetCookie("portal_session=a b") == .other);
    try testing.expect(parseSetCookie("portal_session=a\r\nX: y") == .other);
    try testing.expect(parseSetCookie("portal_session") == .other);
    try testing.expect(parseSetCookie("portal_device=" ++ &@as([201]u8, @splat('a'))) == .other);
    try testing.expect(parseSetCookie("") == .other);
    try testing.expect(Cookie.fromValue(.device, "dev.abc") != null);
    try testing.expect(Cookie.fromValue(.device, "dev abc") == null);
    try testing.expect(Cookie.fromValue(.device, "") == null);
}

test "pair and refresh responses" {
    const ok = try parseResponseHead("HTTP/1.1 303 See Other\r\nLocation: /\r\n" ++
        "Set-Cookie: portal_device=lap.abc; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000\r\n" ++
        "Set-Cookie: portal_session=xyz; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200\r\ncontent-length: 0\r\n\r\n");
    try testing.expectEqual(PairOutcome.ok, pairOutcome(&ok));
    try testing.expectEqualStrings("xyz", ok.session.?.value());
    try testing.expectEqualStrings("lap.abc", ok.device.?.value());
    const closed = try parseResponseHead("HTTP/1.1 303 See Other\r\nLocation: /pair?e=closed\r\n\r\n");
    try testing.expectEqual(PairOutcome.closed, pairOutcome(&closed));
    // A session cookie alone is not a successful pairing.
    const half = try parseResponseHead("HTTP/1.1 303 See Other\r\nLocation: /\r\nSet-Cookie: portal_session=xyz\r\n\r\n");
    try testing.expectEqual(PairOutcome.unexpected, pairOutcome(&half));

    const ref = try parseResponseHead("HTTP/1.1 204 No Content\r\n" ++
        "Set-Cookie: portal_device=lap.new; Path=/; HttpOnly; Max-Age=2592000\r\nSet-Cookie: portal_session=s2\r\n\r\n");
    try testing.expectEqual(RefreshOutcome.ok, refreshOutcome(&ref));
    try testing.expectEqualStrings("lap.new", ref.device.?.value());
    const revoked = try parseResponseHead("HTTP/1.1 401 Unauthorized\r\n\r\n");
    try testing.expectEqual(RefreshOutcome.revoked, refreshOutcome(&revoked));
    const odd = try parseResponseHead("HTTP/1.1 500 Internal Server Error\r\n\r\n");
    try testing.expectEqual(RefreshOutcome.unexpected, refreshOutcome(&odd));
}

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
    const unauth = try parseResponseHead("HTTP/1.1 401 Unauthorized\r\n\r\n");
    try testing.expectEqual(@as(u16, 401), unauth.status);
}

test "fuzz: response parser never panics" {
    var prng = std.Random.DefaultPrng.init(3);
    const rand = prng.random();
    var buf: [256]u8 = undefined;
    const alphabet = "HTTP/1. 0123456789:\r\nSet-Cookie;=portal_session portal_device Max-Age Location";
    for (0..50000) |_| {
        const n = rand.uintLessThan(usize, buf.len);
        for (buf[0..n]) |*b| b.* = if (rand.boolean()) alphabet[rand.uintLessThan(usize, alphabet.len)] else rand.int(u8);
        if (n >= 4) @memcpy(buf[n - 4 .. n], "\r\n\r\n");
        _ = parseResponseHead(buf[0..n]) catch {};
        _ = parseSetCookie(buf[0..n]);
    }
}

test "request building" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writePairRequest(&w, "10.8.0.1:8420");
    try testing.expectEqualStrings("POST /pair HTTP/1.1\r\nHost: 10.8.0.1:8420\r\nOrigin: http://10.8.0.1:8420\r\n" ++
        "Content-Length: 0\r\nConnection: close\r\n\r\n", w.buffered());
    w = .fixed(&buf);
    const dev = Cookie.fromValue(.device, "lap.secret").?;
    try writeRefreshRequest(&w, "10.8.0.1:8420", &dev);
    try testing.expect(std.mem.startsWith(u8, w.buffered(), "POST /auth/refresh HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\r\nCookie: portal_device=lap.secret\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\r\nOrigin: http://10.8.0.1:8420\r\n") != null);
    w = .fixed(&buf);
    const ses = Cookie.fromValue(.session, "sess").?;
    try writeUpgradeRequest(&w, "10.8.0.1:8420", &ses, "dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\r\nCookie: portal_session=sess\r\n") != null);

    var cbuf: [64]u8 = undefined;
    try testing.expectEqualStrings("10.8.0.1:8420", try canonicalHost("10.8.0.1:8420", &cbuf));
    try testing.expectEqualStrings("[::1]:8420", try canonicalHost("[::1]:8420", &cbuf));
    try testing.expectError(error.BadServerAddress, canonicalHost("10.8.0.1", &cbuf));
    try testing.expectError(error.BadServerAddress, canonicalHost("example.com:8420", &cbuf));
    try testing.expectError(error.BadServerAddress, canonicalHost("10.8.0.1:8420\r\nX: y", &cbuf));
}
