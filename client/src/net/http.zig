//! HTTP/1.1 pieces the client needs: device pairing (`POST /pair`, then
//! `GET /pair/wait` until the desk answers), session refresh (`POST
//! /auth/refresh`), the WebSocket upgrade request, and a strict parser for
//! response heads (status, Location, Set-Cookie, upgrade fields, the
//! pairing request code). Pure functions over byte slices; responses are
//! untrusted and never cause a panic.

const std = @import("std");
/// Header syntax and cookie names, shared with the server (shared/http.zig).
const syntax = @import("shared").http;

pub const max_head_bytes = 8 * 1024;
pub const max_headers = 64;
/// Device cookie values are "<name>.<43-char secret>"; session values are 43.
pub const max_cookie_value = 200;

pub const CookieKind = syntax.CookieKind;
/// `__Host-` variants are what the server uses over HTTPS (its default);
/// the plain names only with `portal run --no-tls`. The pairing request
/// token is HttpOnly for browsers and kept in memory only here.
pub const cookie_names = syntax.cookie_names;

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
    /// `secure` selects the `__Host-` name (HTTPS).
    pub fn fromValue(k: CookieKind, v: []const u8, secure: bool) ?Cookie {
        if (!validValue(k, v)) return null;
        var c: Cookie = .{ .name_index = nameIndex(k, secure), .value_len = @intCast(v.len) };
        @memcpy(c.value_buf[0..v.len], v);
        return c;
    }
};

const nameIndex = syntax.cookieIndex;

/// The name the server expects for `k`: `__Host-portal` /
/// `__Host-portal_device` over HTTPS, `portal_session` / `portal_device`
/// over plain HTTP.
pub const cookieName = syntax.cookieName;

fn scheme(secure: bool) []const u8 {
    return if (secure) "https" else "http";
}

fn validValue(k: CookieKind, v: []const u8) bool {
    if (v.len == 0 or v.len > max_cookie_value) return false;
    for (v) |c| {
        const ok = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or (k == .device and c == '.');
        if (!ok) return false;
    }
    return true;
}

/// Writes `POST /pair`. `host` must already be canonical (see canonicalHost);
/// `secure` is true over HTTPS (Origin scheme, cookie names).
pub fn writePairRequest(w: *std.Io.Writer, host: []const u8, secure: bool) !void {
    try w.print("POST /pair HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}://{s}\r\n" ++
        "Content-Length: 0\r\nConnection: close\r\n\r\n", .{ host, scheme(secure), host });
}

/// Writes `GET /pair/wait` with the request token from `POST /pair`.
pub fn writePairWaitRequest(w: *std.Io.Writer, host: []const u8, secure: bool, req: *const Cookie) !void {
    try w.print("GET /pair/wait HTTP/1.1\r\nHost: {s}\r\nCookie: {s}={s}\r\nConnection: close\r\n\r\n", .{ host, cookieName(.pairreq, secure), req.value() });
}

/// Writes `POST /auth/refresh` with the stored device cookie, under the
/// name for the scheme (whatever name it was received under).
pub fn writeRefreshRequest(w: *std.Io.Writer, host: []const u8, secure: bool, device: *const Cookie) !void {
    try w.print("POST /auth/refresh HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}://{s}\r\nCookie: {s}={s}\r\n" ++
        "Content-Length: 0\r\nConnection: close\r\n\r\n", .{ host, scheme(secure), host, cookieName(.device, secure), device.value() });
}

pub fn writeUpgradeRequest(w: *std.Io.Writer, host: []const u8, secure: bool, session: *const Cookie, key: []const u8) !void {
    try w.print("GET /ws HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}://{s}\r\nCookie: {s}={s}\r\n" ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n", .{ host, scheme(secure), host, cookieName(.session, secure), session.value(), key });
}

/// `GET /ca.cer` on the pairing-time certificate download listener (plain
/// HTTP, server port + 1). Only used together with an expected fingerprint.
pub fn writeCaRequest(w: *std.Io.Writer, host: []const u8) !void {
    try w.print("GET /ca.cer HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{host});
}

/// "IP:PORT" (IPv4) or "[IPv6]:PORT", normalised. Only literal addresses are
/// accepted: the client talks to a WireGuard peer and never resolves names.
pub fn canonicalHost(text: []const u8, out: []u8) ![]const u8 {
    if (text.len == 0 or text.len > 64) return error.BadServerAddress;
    const addr = std.Io.net.IpAddress.parseLiteral(text) catch return error.BadServerAddress;
    if (addr.getPort() == 0) return error.BadServerAddress;
    return std.fmt.bufPrint(out, "{f}", .{addr}) catch error.BadServerAddress;
}

pub const findHeadEnd = syntax.findHeadEnd;

pub const Response = struct {
    status: u16,
    location: ?[]const u8 = null,
    session: ?Cookie = null,
    device: ?Cookie = null,
    /// The pairing request token (`POST /pair`).
    pairreq: ?Cookie = null,
    /// `X-Portal-Request-Code` of the `/pair/wait` page: the code the desk
    /// shows next to this request.
    request_code: ?[4]u8 = null,
    /// A Set-Cookie that clears one of our cookies (Max-Age=0 or empty value).
    cookie_cleared: bool = false,
    upgrade_websocket: bool = false,
    connection_upgrade: bool = false,
    accept: ?[]const u8 = null,
    content_length: ?usize = null,
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
        if (!syntax.isToken(name)) return error.BadHeader;
        const val = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (!syntax.validValue(val)) return error.BadHeader;
        if (std.ascii.eqlIgnoreCase(name, "location")) {
            resp.location = val;
        } else if (std.ascii.eqlIgnoreCase(name, "set-cookie")) {
            switch (parseSetCookie(val)) {
                .set => |c| switch (c.kind()) {
                    .session => resp.session = c,
                    .device => resp.device = c,
                    .pairreq => resp.pairreq = c,
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
        } else if (std.ascii.eqlIgnoreCase(name, "x-portal-request-code")) {
            if (val.len == 4) {
                var code: [4]u8 = undefined;
                var ok = true;
                for (val, 0..) |ch, i| {
                    ok = ok and ((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'));
                    code[i] = ch;
                }
                if (ok) resp.request_code = code;
            }
        } else if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            if (resp.content_length != null) return error.BadHeader;
            resp.content_length = std.fmt.parseInt(usize, val, 10) catch return error.BadHeader;
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
    const name_index = syntax.findCookie(name) orelse return .other;
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

pub const PairStart = enum {
    /// Registered: `pairreq` holds the request token; poll /pair/wait.
    requested,
    /// No pairing window is open (or it already paired a device).
    closed,
    /// Too many requests are waiting at the desk.
    busy,
    /// The desk denied this address in this window.
    denied,
    unexpected,
};

/// `POST /pair` (docs/protocol.md section 1): 303 to /pair/wait with the
/// request cookie, or 303 to /pair?e=closed|busy|denied.
pub fn pairStartOutcome(r: *const Response) PairStart {
    if (r.status != 303 and r.status != 302) return .unexpected;
    const loc = r.location orelse return .unexpected;
    if (std.mem.eql(u8, loc, "/pair/wait")) return if (r.pairreq != null) .requested else .unexpected;
    if (std.mem.eql(u8, loc, "/pair?e=busy")) return .busy;
    if (std.mem.eql(u8, loc, "/pair?e=denied")) return .denied;
    if (std.mem.startsWith(u8, loc, "/pair")) return .closed;
    return .unexpected;
}

pub const PairWait = enum {
    /// 200: still waiting for the desk (`request_code` is the code).
    waiting,
    /// 303 to / with the device credential and a session: paired.
    paired,
    denied,
    /// Expired, unknown, used, from another address, or the window closed.
    expired,
    unexpected,
};

/// `GET /pair/wait`.
pub fn pairWaitOutcome(r: *const Response) PairWait {
    if (r.status == 200) return .waiting;
    if (r.status != 303 and r.status != 302) return .unexpected;
    const loc = r.location orelse return .unexpected;
    if (std.mem.eql(u8, loc, "/")) return if (r.device != null and r.session != null) .paired else .unexpected;
    if (std.mem.eql(u8, loc, "/pair?e=denied")) return .denied;
    if (std.mem.startsWith(u8, loc, "/pair")) return .expired;
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
    try testing.expect(Cookie.fromValue(.device, "dev.abc", true) != null);
    try testing.expect(Cookie.fromValue(.device, "dev abc", true) == null);
    try testing.expect(Cookie.fromValue(.device, "", false) == null);
    try testing.expectEqualStrings("__Host-portal_device", Cookie.fromValue(.device, "dev.abc", true).?.name());
    try testing.expectEqualStrings("portal_device", Cookie.fromValue(.device, "dev.abc", false).?.name());
    try testing.expectEqualStrings("__Host-portal", Cookie.fromValue(.session, "abc", true).?.name());
}

test "pair and refresh responses" {
    // POST /pair: the request is registered (token cookie), or refused.
    const req = try parseResponseHead("HTTP/1.1 303 See Other\r\nLocation: /pair/wait\r\n" ++
        "Set-Cookie: __Host-portal_pairreq=abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123-_6; Path=/; HttpOnly; SameSite=Strict; Max-Age=600; Secure\r\n\r\n");
    try testing.expectEqual(PairStart.requested, pairStartOutcome(&req));
    try testing.expectEqualStrings("__Host-portal_pairreq", req.pairreq.?.name());
    const no_tok = try parseResponseHead("HTTP/1.1 303 See Other\r\nLocation: /pair/wait\r\n\r\n");
    try testing.expectEqual(PairStart.unexpected, pairStartOutcome(&no_tok));
    const closed = try parseResponseHead("HTTP/1.1 303 See Other\r\nLocation: /pair?e=closed\r\n\r\n");
    try testing.expectEqual(PairStart.closed, pairStartOutcome(&closed));
    const busy = try parseResponseHead("HTTP/1.1 303 See Other\r\nLocation: /pair?e=busy\r\n\r\n");
    try testing.expectEqual(PairStart.busy, pairStartOutcome(&busy));
    const denied = try parseResponseHead("HTTP/1.1 303 See Other\r\nLocation: /pair?e=denied\r\n\r\n");
    try testing.expectEqual(PairStart.denied, pairStartOutcome(&denied));
    try testing.expectEqual(PairStart.unexpected, pairStartOutcome(&(try parseResponseHead("HTTP/1.1 200 OK\r\n\r\n"))));

    // GET /pair/wait.
    const waiting = try parseResponseHead("HTTP/1.1 200 OK\r\nX-Portal-Request-Code: 7f3a\r\nContent-Length: 10\r\n\r\n");
    try testing.expectEqual(PairWait.waiting, pairWaitOutcome(&waiting));
    try testing.expectEqualStrings("7f3a", &waiting.request_code.?);
    const bad_code = try parseResponseHead("HTTP/1.1 200 OK\r\nX-Portal-Request-Code: 7F3<\r\n\r\n");
    try testing.expect(bad_code.request_code == null);
    const ok = try parseResponseHead("HTTP/1.1 303 See Other\r\nLocation: /\r\n" ++
        "Set-Cookie: portal_device=lap.abc; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000\r\n" ++
        "Set-Cookie: portal_session=xyz; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200\r\n" ++
        "Set-Cookie: portal_pairreq=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0\r\ncontent-length: 0\r\n\r\n");
    try testing.expectEqual(PairWait.paired, pairWaitOutcome(&ok));
    try testing.expectEqualStrings("xyz", ok.session.?.value());
    try testing.expectEqualStrings("lap.abc", ok.device.?.value());
    try testing.expect(ok.cookie_cleared);
    const wdenied = try parseResponseHead("HTTP/1.1 303 See Other\r\nLocation: /pair?e=denied\r\n\r\n");
    try testing.expectEqual(PairWait.denied, pairWaitOutcome(&wdenied));
    const expired = try parseResponseHead("HTTP/1.1 303 See Other\r\nLocation: /pair?e=expired\r\n\r\n");
    try testing.expectEqual(PairWait.expired, pairWaitOutcome(&expired));
    // A session cookie alone is not a successful pairing.
    const half = try parseResponseHead("HTTP/1.1 303 See Other\r\nLocation: /\r\nSet-Cookie: portal_session=xyz\r\n\r\n");
    try testing.expectEqual(PairWait.unexpected, pairWaitOutcome(&half));

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
    try writePairRequest(&w, "10.8.0.1:8420", true);
    try testing.expectEqualStrings("POST /pair HTTP/1.1\r\nHost: 10.8.0.1:8420\r\nOrigin: https://10.8.0.1:8420\r\n" ++
        "Content-Length: 0\r\nConnection: close\r\n\r\n", w.buffered());
    w = .fixed(&buf);
    try writePairRequest(&w, "10.8.0.1:8420", false);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\r\nOrigin: http://10.8.0.1:8420\r\n") != null);
    const tok = Cookie.fromValue(.pairreq, "tok123", true).?;
    w = .fixed(&buf);
    try writePairWaitRequest(&w, "10.8.0.1:8420", true, &tok);
    try testing.expectEqualStrings("GET /pair/wait HTTP/1.1\r\nHost: 10.8.0.1:8420\r\nCookie: __Host-portal_pairreq=tok123\r\nConnection: close\r\n\r\n", w.buffered());
    w = .fixed(&buf);
    try writePairWaitRequest(&w, "10.8.0.1:8420", false, &tok);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\r\nCookie: portal_pairreq=tok123\r\n") != null);
    // A credential from before TLS (plain name) goes out under the
    // __Host- name over HTTPS.
    const dev = Cookie.fromValue(.device, "lap.secret", false).?;
    w = .fixed(&buf);
    try writeRefreshRequest(&w, "10.8.0.1:8420", true, &dev);
    try testing.expect(std.mem.startsWith(u8, w.buffered(), "POST /auth/refresh HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\r\nCookie: __Host-portal_device=lap.secret\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\r\nOrigin: https://10.8.0.1:8420\r\n") != null);
    w = .fixed(&buf);
    try writeRefreshRequest(&w, "10.8.0.1:8420", false, &dev);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\r\nCookie: portal_device=lap.secret\r\n") != null);
    w = .fixed(&buf);
    const ses = parseSetCookie("__Host-portal=sess; Path=/; Secure; HttpOnly").set;
    try writeUpgradeRequest(&w, "10.8.0.1:8420", true, &ses, "dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\r\nCookie: __Host-portal=sess\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\r\nOrigin: https://10.8.0.1:8420\r\n") != null);
    w = .fixed(&buf);
    try writeUpgradeRequest(&w, "10.8.0.1:8420", false, &ses, "dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\r\nCookie: portal_session=sess\r\n") != null);

    const cl = try parseResponseHead("HTTP/1.1 200 OK\r\nContent-Length: 485\r\n\r\n");
    try testing.expectEqual(@as(?usize, 485), cl.content_length);
    try testing.expectError(error.BadHeader, parseResponseHead("HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n"));
    try testing.expectError(error.BadHeader, parseResponseHead("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"));

    var cbuf: [64]u8 = undefined;
    try testing.expectEqualStrings("10.8.0.1:8420", try canonicalHost("10.8.0.1:8420", &cbuf));
    try testing.expectEqualStrings("[::1]:8420", try canonicalHost("[::1]:8420", &cbuf));
    try testing.expectError(error.BadServerAddress, canonicalHost("10.8.0.1", &cbuf));
    try testing.expectError(error.BadServerAddress, canonicalHost("example.com:8420", &cbuf));
    try testing.expectError(error.BadServerAddress, canonicalHost("10.8.0.1:8420\r\nX: y", &cbuf));
}
