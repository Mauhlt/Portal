//! WebSocket (RFC 6455) test client. Server frames are parsed with the
//! shared, strict parser (shared/ws.zig) every Portal program uses; client
//! frames are encoded here, so tests can also send malformed ones (no FIN,
//! RSV bits, unmasked, lying lengths) at the server.

const std = @import("std");
const shared_ws = @import("shared").ws;
const net = @import("net.zig");
const http = @import("http.zig");
const tlsnet = @import("tlsnet.zig");
const Allocator = std.mem.Allocator;

pub const Op = shared_ws.Opcode;

pub const Frame = struct {
    op: Op,
    /// Valid until the next call to `next`.
    payload: []const u8,
};

pub const ConnectOptions = struct {
    host: []const u8,
    origin: ?[]const u8,
    /// Full Cookie header value, e.g. "portal_session=...".
    cookie: ?[]const u8,
    version: []const u8 = "13",
    /// Defaults to a random valid key.
    key: ?[]const u8 = null,
    upgrade_headers: bool = true,
    rcvbuf: ?c_int = null,
    /// Bytes sent in the same write as the handshake (pipelined frames).
    trailing: []const u8 = "",
    /// WSS, trusting only this CA; null is plain ws://.
    tls: ?*tlsnet.Trust = null,
};

var seed_counter = std.atomic.Value(u64).init(0x9e3779b97f4a7c15);

fn newRng() std.Random.DefaultPrng {
    const s = seed_counter.fetchAdd(0x9e3779b97f4a7c15, .monotonic) ^ net.now();
    return std.Random.DefaultPrng.init(s);
}

pub const Client = struct {
    gpa: Allocator,
    sock: tlsnet.Stream,
    /// HTTP status of the handshake response.
    status: u16,
    buf: std.ArrayList(u8) = .empty,
    /// Start of unconsumed bytes in `buf`.
    pos: usize = 0,
    rng: std.Random.DefaultPrng,

    pub fn connect(gpa: Allocator, port: u16, o: ConnectOptions) !Client {
        var sock = try tlsnet.Stream.connect(gpa, port, .{ .rcvbuf = o.rcvbuf }, o.tls);
        errdefer sock.close();
        var rng = newRng();
        var key_buf: [24]u8 = undefined;
        const key = o.key orelse blk: {
            var raw: [16]u8 = undefined;
            rng.random().bytes(&raw);
            break :blk std.base64.standard.Encoder.encode(&key_buf, &raw);
        };
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(gpa);
        try req.print(gpa, "GET /ws HTTP/1.1\r\nHost: {s}\r\n", .{o.host});
        if (o.upgrade_headers) try req.appendSlice(gpa, "Upgrade: websocket\r\nConnection: Upgrade\r\n");
        try req.print(gpa, "Sec-WebSocket-Key: {s}\r\nSec-WebSocket-Version: {s}\r\n", .{ key, o.version });
        if (o.origin) |v| try req.print(gpa, "Origin: {s}\r\n", .{v});
        if (o.cookie) |v| try req.print(gpa, "Cookie: {s}\r\n", .{v});
        try req.appendSlice(gpa, "\r\n");
        try req.appendSlice(gpa, o.trailing);
        try sock.sendAll(req.items);

        var c: Client = .{ .gpa = gpa, .sock = sock, .status = 0, .rng = rng };
        errdefer c.buf.deinit(gpa);
        // Read exactly the response head; keep any frame bytes after it.
        const deadline = net.now() + 10_000;
        var tmp: [4096]u8 = undefined;
        const head_end = while (true) {
            if (std.mem.indexOf(u8, c.buf.items, "\r\n\r\n")) |i| break i + 4;
            const t = net.now();
            if (t >= deadline) return error.Timeout;
            const n = try c.sock.recvSome(&tmp, @intCast(deadline - t));
            if (n == 0) return error.Closed;
            try c.buf.appendSlice(gpa, tmp[0..n]);
        };
        c.status = http.firstStatus(c.buf.items);
        if (c.status == 101) {
            const head = c.buf.items[0..head_end];
            // Verify Sec-WebSocket-Accept.
            const expect = shared_ws.accept(key) catch return error.BadAccept;
            if (std.mem.indexOf(u8, head, &expect) == null) return error.BadAccept;
        }
        c.pos = head_end;
        return c;
    }

    pub fn close(c: *Client) void {
        c.sock.close();
        c.buf.deinit(c.gpa);
    }

    /// Encodes a masked client frame (fin and rsv as given) into `out`.
    pub fn encode(c: *Client, out: *std.ArrayList(u8), op: u8, payload: []const u8, o: struct { fin: bool = true, rsv: u8 = 0, masked: bool = true, len_override: ?u64 = null }) !void {
        const gpa = c.gpa;
        try out.append(gpa, (if (o.fin) @as(u8, 0x80) else 0) | (o.rsv << 4) | (op & 0x0f));
        const m: u8 = if (o.masked) 0x80 else 0;
        const len = o.len_override orelse payload.len;
        if (len < 126) {
            try out.append(gpa, m | @as(u8, @intCast(len)));
        } else if (len <= 0xffff) {
            try out.append(gpa, m | 126);
            var b: [2]u8 = undefined;
            std.mem.writeInt(u16, &b, @intCast(len), .big);
            try out.appendSlice(gpa, &b);
        } else {
            try out.append(gpa, m | 127);
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, len, .big);
            try out.appendSlice(gpa, &b);
        }
        var mask: [4]u8 = undefined;
        c.rng.random().bytes(&mask);
        if (o.masked) try out.appendSlice(gpa, &mask);
        const start = out.items.len;
        try out.appendSlice(gpa, payload);
        if (o.masked) for (out.items[start..], 0..) |*b, i| {
            b.* ^= mask[i & 3];
        };
    }

    pub fn send(c: *Client, op: Op, payload: []const u8) !void {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(c.gpa);
        try c.encode(&out, @backingInt(op), payload, .{});
        try c.sock.sendAll(out.items);
    }

    pub fn sendText(c: *Client, text: []const u8) !void {
        return c.send(.text, text);
    }

    pub fn sendRaw(c: *Client, bytes: []const u8) !void {
        return c.sock.sendAll(bytes);
    }

    fn compact(c: *Client) void {
        if (c.pos == 0) return;
        const rest = c.buf.items.len - c.pos;
        std.mem.copyForwards(u8, c.buf.items[0..rest], c.buf.items[c.pos..]);
        c.buf.shrinkRetainingCapacity(rest);
        c.pos = 0;
    }

    /// Next server frame. error.Timeout if none within `timeout_ms`,
    /// error.Closed on EOF/reset, error.BadFrame on a protocol violation.
    pub fn next(c: *Client, timeout_ms: u32) !Frame {
        const deadline = net.now() + timeout_ms;
        var tmp: [64 * 1024]u8 = undefined;
        while (true) {
            if (try c.parseOne()) |f| return f;
            c.compact();
            const t = net.now();
            if (t >= deadline) return error.Timeout;
            const n = c.sock.recvSome(&tmp, @intCast(deadline - t)) catch |err| switch (err) {
                error.Reset => return error.Closed,
                else => return err,
            };
            if (n == 0) return error.Closed;
            try c.buf.appendSlice(c.gpa, tmp[0..n]);
        }
    }

    fn parseOne(c: *Client) !?Frame {
        const f = (shared_ws.parseServerFrame(c.buf.items[c.pos..], 16 * 1024 * 1024) catch
            return error.BadFrame) orelse return null;
        c.pos += f.len;
        return .{ .op = f.opcode, .payload = f.payload };
    }

    /// Reads and discards everything until the peer closes; returns whether
    /// it closed within `timeout_ms`.
    pub fn waitClosed(c: *Client, timeout_ms: u32) bool {
        const deadline = net.now() + timeout_ms;
        var tmp: [64 * 1024]u8 = undefined;
        while (true) {
            const t = net.now();
            if (t >= deadline) return false;
            const n = c.sock.recvSome(&tmp, @intCast(deadline - t)) catch |err| switch (err) {
                error.Timeout => return false,
                else => return true,
            };
            if (n == 0) return true;
        }
    }
};
