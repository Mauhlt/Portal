//! Minimal, strict HTTP/1.1 server protocol code (and the 101 response of
//! the WebSocket handshake; framing is shared/ws.zig).
//!
//! Replaces std.http.Server, which had two remotely reachable panics
//! (an assert on body-less POSTs during keep-alive, and a null unwrap in
//! HeaderIterator on a head split across reads) and whose API churns between
//! Zig releases. Everything here is pure: it operates on byte slices, never
//! asserts on peer input, and rejects anything unusual instead of guessing.

const std = @import("std");
const syntax = @import("shared").http;

pub const max_head_bytes = 8 * 1024;
pub const max_headers = 64;
pub const max_target_bytes = 2048;

pub const Method = enum { GET, POST, other };

pub const ParseError = error{
    BadRequestLine,
    UnsupportedVersion,
    BadTarget,
    BadHeader,
    TooManyHeaders,
    DuplicateHeader,
    BadContentLength,
};

pub const Request = struct {
    method: Method,
    /// The target up to any `?` (no route takes a query).
    path: []const u8,
    host: ?[]const u8 = null,
    content_length: ?u64 = null,
    /// Any Transfer-Encoding header at all. Portal never accepts one.
    has_transfer_encoding: bool = false,
    has_expect: bool = false,
    connection_close: bool = false,
    connection_upgrade: bool = false,
    upgrade_websocket: bool = false,
    ws_key: ?[]const u8 = null,
    ws_version: ?[]const u8 = null,
    /// Header lines seen (at most max_headers).
    header_count: usize = 0,
};

pub const Header = struct { name: []const u8, value: []const u8 };

/// Returns the length of the head including the terminating CRLFCRLF, or
/// null if not yet complete.
pub const findHeadEnd = syntax.findHeadEnd;
const isToken = syntax.isToken;
const validValue = syntax.validValue;

fn listContainsToken(value: []const u8, token: []const u8) bool {
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |part| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, part, " \t"), token)) return true;
    }
    return false;
}

/// Parses a complete head (as delimited by `findHeadEnd`). Returned slices
/// point into `head`.
pub fn parseHead(head: []const u8) ParseError!Request {
    if (head.len < 4 or !std.mem.endsWith(u8, head, "\r\n\r\n")) return error.BadRequestLine;
    const body = head[0 .. head.len - 4]; // without final blank line
    var lines = std.mem.splitSequence(u8, body, "\r\n");

    // Request line: METHOD SP TARGET SP HTTP/1.1
    const line = lines.first();
    var parts = std.mem.splitScalar(u8, line, ' ');
    const m = parts.next() orelse return error.BadRequestLine;
    const target = parts.next() orelse return error.BadRequestLine;
    const version = parts.next() orelse return error.BadRequestLine;
    if (parts.next() != null) return error.BadRequestLine;
    if (!isToken(m)) return error.BadRequestLine;
    if (!std.mem.eql(u8, version, "HTTP/1.1")) return error.UnsupportedVersion;
    if (target.len == 0 or target.len > max_target_bytes or target[0] != '/') return error.BadTarget;
    for (target) |c| if (c <= 0x20 or c >= 0x7f) return error.BadTarget;

    const q = std.mem.indexOfScalar(u8, target, '?');
    var req: Request = .{
        .method = if (std.mem.eql(u8, m, "GET")) .GET else if (std.mem.eql(u8, m, "POST")) .POST else .other,
        .path = if (q) |i| target[0..i] else target,
    };

    while (lines.next()) |hl| {
        if (hl.len == 0) return error.BadHeader; // blank line before end: cannot happen with a valid head
        if (hl[0] == ' ' or hl[0] == '\t') return error.BadHeader; // obsolete line folding
        if (std.mem.indexOfAny(u8, hl, "\r\n") != null) return error.BadHeader; // bare CR / LF
        const colon = std.mem.indexOfScalar(u8, hl, ':') orelse return error.BadHeader;
        const name = hl[0..colon];
        if (!isToken(name)) return error.BadHeader;
        const value = std.mem.trim(u8, hl[colon + 1 ..], " \t");
        if (!validValue(value)) return error.BadHeader;
        if (req.header_count >= max_headers) return error.TooManyHeaders;
        req.header_count += 1;

        if (std.ascii.eqlIgnoreCase(name, "host")) {
            if (req.host != null) return error.DuplicateHeader;
            req.host = value;
        } else if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            if (req.content_length != null) return error.DuplicateHeader;
            if (value.len == 0 or value.len > 10) return error.BadContentLength;
            for (value) |c| if (c < '0' or c > '9') return error.BadContentLength;
            req.content_length = std.fmt.parseInt(u64, value, 10) catch return error.BadContentLength;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            req.has_transfer_encoding = true;
        } else if (std.ascii.eqlIgnoreCase(name, "expect")) {
            req.has_expect = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (listContainsToken(value, "close")) req.connection_close = true;
            if (listContainsToken(value, "upgrade")) req.connection_upgrade = true;
        } else if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
            if (listContainsToken(value, "websocket")) req.upgrade_websocket = true;
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-key")) {
            if (req.ws_key != null) return error.DuplicateHeader;
            req.ws_key = value;
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-version")) {
            if (req.ws_version != null) return error.DuplicateHeader;
            req.ws_version = value;
        }
    }
    return req;
}

// ------------------------------------------------------------- responses

pub const Status = enum(u16) {
    ok = 200,
    no_content = 204,
    switching_protocols = 101,
    see_other = 303,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    length_required = 411,
    payload_too_large = 413,
    unsupported_media_type = 415,
    expectation_failed = 417,
    misdirected_request = 421,
    header_fields_too_large = 431,
    internal_server_error = 500,

    pub fn phrase(s: Status) []const u8 {
        return switch (s) {
            .ok => "OK",
            .no_content => "No Content",
            .switching_protocols => "Switching Protocols",
            .see_other => "See Other",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .length_required => "Length Required",
            .payload_too_large => "Payload Too Large",
            .unsupported_media_type => "Unsupported Media Type",
            .expectation_failed => "Expectation Failed",
            .misdirected_request => "Misdirected Request",
            .header_fields_too_large => "Request Header Fields Too Large",
            .internal_server_error => "Internal Server Error",
        };
    }
};

/// Header values written by Portal are constants or base64url; this guards
/// against a future caller accidentally passing CR/LF (response splitting).
pub fn headerSafe(h: Header) bool {
    return isToken(h.name) and validValue(h.value);
}

pub fn writeResponse(
    w: *std.Io.Writer,
    status: Status,
    headers: []const Header,
    body: []const u8,
    keep_alive: bool,
) !void {
    try w.print("HTTP/1.1 {d} {s}\r\n", .{ @backingInt(status), status.phrase() });
    for (headers) |h| {
        if (!headerSafe(h)) return error.UnsafeHeader;
        try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    try w.print("content-length: {d}\r\nconnection: {s}\r\n\r\n", .{ body.len, if (keep_alive) "keep-alive" else "close" });
    try w.writeAll(body);
    try w.flush();
}

pub const Reject = struct { status: Status, msg: []const u8 };

/// Framing checks applied to every parsed head before routing. Any non-null
/// result must be answered with that status and the connection closed: after
/// a framing problem the position of the next request is unknown.
pub fn framingError(req: *const Request, max_body: u64) ?Reject {
    if (req.has_transfer_encoding) return .{ .status = .bad_request, .msg = "transfer-encoding not supported\n" };
    if (req.has_expect) return .{ .status = .expectation_failed, .msg = "expect not supported\n" };
    switch (req.method) {
        .other => return .{ .status = .method_not_allowed, .msg = "method not allowed\n" },
        .GET => if ((req.content_length orelse 0) != 0) return .{ .status = .bad_request, .msg = "unexpected body\n" },
        .POST => {
            const len = req.content_length orelse return .{ .status = .length_required, .msg = "content-length required\n" };
            if (len > max_body) return .{ .status = .payload_too_large, .msg = "too large\n" };
        },
    }
    return null;
}

/// The 101 response completing a WebSocket handshake.
pub fn writeUpgrade(w: *std.Io.Writer, accept: []const u8) !void {
    if (!validValue(accept)) return error.UnsafeHeader;
    try w.print("HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: {s}\r\n\r\n", .{accept});
    try w.flush();
}

// ----------------------------------------------------------------- tests

const testing = std.testing;

test "findHeadEnd" {
    try testing.expectEqual(@as(?usize, null), findHeadEnd("GET / HTTP/1.1\r\nA\r\n"));
    try testing.expectEqual(@as(?usize, 18), findHeadEnd("GET / HTTP/1.1\r\n\r\nrest"));
}

test "parse simple GET" {
    const r = try parseHead("GET /ws?e=1 HTTP/1.1\r\nHost: 10.8.0.1:8420\r\nX-A: 1\r\nX-A: 2\r\n\r\n");
    try testing.expectEqual(Method.GET, r.method);
    try testing.expectEqualStrings("/ws", r.path);
    try testing.expectEqualStrings("10.8.0.1:8420", r.host.?);
    try testing.expectEqual(@as(usize, 3), r.header_count);
}

test "reject the head shape that crashed std.http" {
    // "GET / HTTP/1.1\r\nA\r\n" never contains CRLFCRLF, so findHeadEnd keeps
    // waiting; and parseHead refuses it outright.
    try testing.expectError(error.BadRequestLine, parseHead("GET / HTTP/1.1\r\nA\r\n"));
    try testing.expectError(error.BadHeader, parseHead("GET / HTTP/1.1\r\nA\r\n\r\n"));
}

test "reject malformed request lines and headers" {
    try testing.expectError(error.UnsupportedVersion, parseHead("GET / HTTP/1.0\r\n\r\n"));
    try testing.expectError(error.BadRequestLine, parseHead("GET  / HTTP/1.1\r\n\r\n"));
    try testing.expectError(error.BadTarget, parseHead("GET http://x/ HTTP/1.1\r\n\r\n"));
    try testing.expectError(error.BadTarget, parseHead("GET /\x01 HTTP/1.1\r\n\r\n"));
    try testing.expectError(error.BadHeader, parseHead("GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n"));
    try testing.expectError(error.BadHeader, parseHead("GET / HTTP/1.1\r\nBad Name: a\r\n\r\n"));
    try testing.expectError(error.BadHeader, parseHead("GET / HTTP/1.1\r\nX: a\x00b\r\n\r\n"));
    try testing.expectError(error.BadHeader, parseHead("GET / HTTP/1.1\r\nX: a\rb\r\n\r\n"));
    try testing.expectError(error.DuplicateHeader, parseHead("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"));
    try testing.expectError(error.DuplicateHeader, parseHead("POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n"));
    try testing.expectError(error.BadContentLength, parseHead("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n"));
    try testing.expectError(error.BadContentLength, parseHead("POST / HTTP/1.1\r\nContent-Length: 1 2\r\n\r\n"));
    try testing.expectError(error.BadContentLength, parseHead("POST / HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n"));
}

test "too many headers" {
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll("GET / HTTP/1.1\r\n");
    for (0..max_headers + 1) |_| try w.writeAll("X: y\r\n");
    try w.writeAll("\r\n");
    try testing.expectError(error.TooManyHeaders, parseHead(w.buffered()));
}

test "websocket upgrade fields" {
    const r = try parseHead("GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nTransfer-Encoding: chunked\r\n\r\n");
    try testing.expect(r.upgrade_websocket and r.connection_upgrade and r.has_transfer_encoding);
    // RFC 6455 section 1.3 example.
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &try @import("shared").ws.accept(r.ws_key.?));
}

test "response refuses header injection" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.UnsafeHeader, writeResponse(&w, .ok, &.{.{ .name = "x", .value = "a\r\nSet-Cookie: evil" }}, "", false));
}

test "framing checks" {
    const ok_get = try parseHead("GET / HTTP/1.1\r\nHost: h\r\n\r\n");
    try testing.expect(framingError(&ok_get, 512) == null);
    const get_cl0 = try parseHead("GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
    try testing.expect(framingError(&get_cl0, 512) == null);
    const get_body = try parseHead("GET / HTTP/1.1\r\nContent-Length: 3\r\n\r\n");
    try testing.expectEqual(Status.bad_request, framingError(&get_body, 512).?.status);
    const put = try parseHead("PUT / HTTP/1.1\r\n\r\n");
    try testing.expectEqual(Status.method_not_allowed, framingError(&put, 512).?.status);
    const te = try parseHead("POST /ws HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n");
    try testing.expectEqual(Status.bad_request, framingError(&te, 512).?.status);
    const ex = try parseHead("POST /ws HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n");
    try testing.expectEqual(Status.expectation_failed, framingError(&ex, 512).?.status);
    const no_len = try parseHead("POST /ws HTTP/1.1\r\n\r\n");
    try testing.expectEqual(Status.length_required, framingError(&no_len, 512).?.status);
    const big = try parseHead("POST /ws HTTP/1.1\r\nContent-Length: 513\r\n\r\n");
    try testing.expectEqual(Status.payload_too_large, framingError(&big, 512).?.status);
    const post = try parseHead("POST /ws HTTP/1.1\r\nContent-Length: 512\r\n\r\n");
    try testing.expect(framingError(&post, 512) == null);
}

test "upgrade response" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeUpgrade(&w, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    try testing.expectEqualStrings("HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n" ++
        "sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n", w.buffered());
    var w2: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.UnsafeHeader, writeUpgrade(&w2, "a\r\nb"));
}
