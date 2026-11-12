//! A small HTTP/1.1 client over net.Socket. Requests are built byte-exact
//! (the harness decides every header); responses are parsed strictly enough
//! to notice a malformed server reply.

const std = @import("std");
const net = @import("net.zig");
const Allocator = std.mem.Allocator;

pub const Header = struct { name: []const u8, value: []const u8 };

pub const Response = struct {
    gpa: Allocator,
    /// Owns head + body bytes; slices below point into it.
    raw: []u8,
    status: u16,
    headers: std.ArrayList(Header) = .empty,
    body: []const u8,

    pub fn deinit(r: *Response) void {
        r.headers.deinit(r.gpa);
        r.gpa.free(r.raw);
    }

    pub fn header(r: *const Response, name: []const u8) ?[]const u8 {
        for (r.headers.items) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        return null;
    }

    pub fn location(r: *const Response) []const u8 {
        return r.header("location") orelse "";
    }

    pub fn setCookieCount(r: *const Response) usize {
        var n: usize = 0;
        for (r.headers.items) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "set-cookie")) n += 1;
        }
        return n;
    }

    /// Full Set-Cookie header value for cookie `name`.
    pub fn setCookieLine(r: *const Response, name: []const u8) ?[]const u8 {
        for (r.headers.items) |h| {
            if (!std.ascii.eqlIgnoreCase(h.name, "set-cookie")) continue;
            if (h.value.len > name.len and std.mem.startsWith(u8, h.value, name) and h.value[name.len] == '=') return h.value;
        }
        return null;
    }

    /// Value of cookie `name` from the Set-Cookie headers.
    pub fn cookie(r: *const Response, name: []const u8) ?[]const u8 {
        const line = r.setCookieLine(name) orelse return null;
        const rest = line[name.len + 1 ..];
        const end = std.mem.indexOfScalar(u8, rest, ';') orelse rest.len;
        return rest[0..end];
    }

    pub fn bodyContains(r: *const Response, needle: []const u8) bool {
        return std.mem.indexOf(u8, r.body, needle) != null;
    }
};

pub const Error = error{ BadResponse, Closed } || net.Error || Allocator.Error;

/// Reads one response from `sock`, which must carry a content-length (every
/// Portal response does; a 101 has no body). Bytes after it are discarded.
pub fn readResponse(gpa: Allocator, sock: *net.Socket, timeout_ms: u32) Error!Response {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    const deadline = net.now() + timeout_ms;
    var tmp: [16 * 1024]u8 = undefined;
    const head_len = while (true) {
        if (std.mem.indexOf(u8, buf.items, "\r\n\r\n")) |i| break i + 4;
        if (buf.items.len > 64 * 1024) return error.BadResponse;
        const t = net.now();
        if (t >= deadline) return error.Timeout;
        const n = try sock.recvSome(&tmp, @intCast(deadline - t));
        if (n == 0) return if (buf.items.len == 0) error.Closed else error.BadResponse;
        try buf.appendSlice(gpa, tmp[0..n]);
    };
    var status: u16 = 0;
    var cl: ?usize = null;
    {
        var lines = std.mem.splitSequence(u8, buf.items[0 .. head_len - 4], "\r\n");
        const sl = lines.first();
        if (!std.mem.startsWith(u8, sl, "HTTP/1.1 ") or sl.len < 12) return error.BadResponse;
        status = std.fmt.parseInt(u16, sl[9..12], 10) catch return error.BadResponse;
        while (lines.next()) |l| {
            const c = std.mem.indexOfScalar(u8, l, ':') orelse return error.BadResponse;
            if (c == 0) return error.BadResponse;
            if (std.ascii.eqlIgnoreCase(l[0..c], "content-length")) {
                if (cl != null) return error.BadResponse;
                cl = std.fmt.parseInt(usize, std.mem.trim(u8, l[c + 1 ..], " "), 10) catch return error.BadResponse;
            }
        }
    }
    const body_len: usize = if (status == 101) 0 else cl orelse return error.BadResponse;
    while (buf.items.len < head_len + body_len) {
        const t = net.now();
        if (t >= deadline) return error.Timeout;
        const n = try sock.recvSome(&tmp, @intCast(deadline - t));
        if (n == 0) return error.BadResponse;
        try buf.appendSlice(gpa, tmp[0..n]);
    }
    const raw = try gpa.dupe(u8, buf.items[0 .. head_len + body_len]);
    var r: Response = .{ .gpa = gpa, .raw = raw, .status = status, .body = raw[head_len..] };
    errdefer r.deinit();
    var lines = std.mem.splitSequence(u8, raw[0 .. head_len - 4], "\r\n");
    _ = lines.first();
    while (lines.next()) |l| {
        const c = std.mem.indexOfScalar(u8, l, ':').?;
        try r.headers.append(gpa, .{ .name = l[0..c], .value = std.mem.trim(u8, l[c + 1 ..], " ") });
    }
    return r;
}

/// Status codes of every "HTTP/1.1 NNN" status line in a raw byte stream
/// (for pipelining checks).
pub fn statusLines(data: []const u8, out: []u16) []u16 {
    var n: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, data, i, "HTTP/1.1 ")) |p| {
        if (p + 12 > data.len or n >= out.len) break;
        out[n] = std.fmt.parseInt(u16, data[p + 9 .. p + 12], 10) catch 0;
        n += 1;
        i = p + 12;
    }
    return out[0..n];
}

/// First status code in raw response bytes, or 0.
pub fn firstStatus(data: []const u8) u16 {
    if (data.len < 12 or !std.mem.startsWith(u8, data, "HTTP/1.1 ")) return 0;
    return std.fmt.parseInt(u16, data[9..12], 10) catch 0;
}

pub const Request = struct {
    method: []const u8 = "GET",
    path: []const u8 = "/",
    /// Host header value; null omits it.
    host: ?[]const u8,
    origin: ?[]const u8 = null,
    cookie: ?[]const u8 = null,
    /// Sent with a Content-Length when non-null.
    body: ?[]const u8 = null,
    extra: []const Header = &.{},
    source: ?[4]u8 = null,
};

pub fn format(gpa: Allocator, req: Request) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.print(gpa, "{s} {s} HTTP/1.1\r\n", .{ req.method, req.path });
    if (req.host) |h| try out.print(gpa, "Host: {s}\r\n", .{h});
    if (req.origin) |o| try out.print(gpa, "Origin: {s}\r\n", .{o});
    if (req.cookie) |c| try out.print(gpa, "Cookie: {s}\r\n", .{c});
    for (req.extra) |h| try out.print(gpa, "{s}: {s}\r\n", .{ h.name, h.value });
    if (req.body) |b| try out.print(gpa, "Content-Length: {d}\r\n", .{b.len});
    try out.appendSlice(gpa, "\r\n");
    if (req.body) |b| try out.appendSlice(gpa, b);
    return out.toOwnedSlice(gpa);
}

/// One request on a fresh connection.
pub fn request(gpa: Allocator, port: u16, req: Request) Error!Response {
    var sock = try net.Socket.connect(port, .{ .source = req.source });
    defer sock.close();
    const bytes = try format(gpa, req);
    defer gpa.free(bytes);
    try sock.sendAll(bytes);
    return readResponse(gpa, &sock, 10_000);
}

/// Sends raw bytes on a fresh connection and returns everything the server
/// sends back until it closes (or `timeout_ms`).
pub fn rawExchange(gpa: Allocator, port: u16, bytes: []const u8, timeout_ms: u32) ![]u8 {
    var sock = try net.Socket.connect(port, .{});
    defer sock.close();
    sock.sendAll(bytes) catch {}; // the server may close before reading it all
    const r = try sock.recvUntilClose(gpa, 1 << 20, timeout_ms);
    return r.data;
}
