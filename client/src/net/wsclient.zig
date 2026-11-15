//! A client WebSocket to the desktop over the in-process tunnel: the TLS
//! connection (tlsconn.zig, CA pinned), the upgrade to one of the two
//! channels (http.zig: interactive `/ws` or bulk `/ws/bulk`), then frames.
//! One implementation for the live stream (net/client.zig) and the sync
//! transfers (sync/engine.zig over shared/bulk.zig). On the interactive
//! channel, messages the desk sends in parts (shared/parts.zig) come out
//! of `next` / `buffered` whole.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const ws = @import("shared").ws;
const bulk = @import("shared").bulk;
const parts = @import("shared").parts;
const http = @import("http.zig");
const tlsconn = @import("tlsconn.zig");

pub const Channel = http.Channel;

pub const OpenError = error{
    /// The desktop answered the upgrade with 403: it does not have this
    /// device paired (any more).
    NotPaired,
    UpgradeRefused,
    BadUpgrade,
    ConnectionClosed,
    ResponseTooLarge,
    NoEntropy,
    OutOfMemory,
} || tlsconn.Conn.OpenError || error{ WriteFailed, ReadFailed, Canceled };

pub const Socket = struct {
    gpa: std.mem.Allocator,
    io: Io,
    conn: *tlsconn.Conn,
    /// Bytes read and not yet consumed (frames after the upgrade head).
    buf: std.ArrayList(u8) = .empty,
    /// The frame last returned by `next` (dropped by the next call).
    used: usize = 0,
    /// A bulk reply's signature, copied out of the frame buffer.
    sig_buf: [bulk.max_header]u8 = undefined,
    /// Reassembles messages in parts: the interactive channel only (the
    /// bulk channel has none, and its file chunks may start with 'M').
    assembler: ?parts.Assembler,

    /// Dials through `dialer` (its priority: the bulk channel dials as
    /// bulk), completes TLS and the upgrade to `channel`. `stop` is the
    /// watchdog's flag (tlsconn.Conn.openWatched).
    pub fn open(gpa: std.mem.Allocator, io: Io, dialer: tlsconn.transport.Dialer, addr: net.IpAddress, security: tlsconn.Security, host: []const u8, channel: Channel, stop: ?*const std.atomic.Value(bool)) OpenError!Socket {
        const d = if (channel == .bulk) dialer.bulk() else dialer;
        const conn = try tlsconn.Conn.openWatched(gpa, io, d, addr, security, stop);
        var s: Socket = .{ .gpa = gpa, .io = io, .conn = conn, .assembler = if (channel == .interactive) .{ .limit = 0 } else null };
        errdefer s.close();
        var rnd: [16]u8 = undefined;
        io.randomSecure(&rnd) catch return error.NoEntropy;
        const key = ws.makeKey(rnd);
        var req_buf: [256]u8 = undefined;
        var w: Io.Writer = .fixed(&req_buf);
        http.writeUpgradeRequest(&w, host, channel, &key) catch return error.BadUpgrade;
        try conn.writeAll(w.buffered());
        try s.buf.ensureTotalCapacity(gpa, 64 * 1024);
        const head_end = while (true) {
            if (http.findHeadEnd(s.buf.items)) |e| break e;
            if (s.buf.items.len >= http.max_head_bytes) return error.ResponseTooLarge;
            if (!try s.readMore()) return error.ConnectionClosed;
        };
        const resp = http.parseResponseHead(s.buf.items[0..head_end]) catch return error.BadUpgrade;
        if (resp.status == 403) return error.NotPaired;
        if (resp.status != 101) return error.UpgradeRefused;
        const expected = ws.accept(&key) catch return error.BadUpgrade;
        if (!resp.upgrade_websocket or !resp.connection_upgrade or resp.accept == null or
            !std.mem.eql(u8, resp.accept.?, &expected)) return error.BadUpgrade;
        // Keep any frame bytes that followed the head.
        std.mem.copyForwards(u8, s.buf.items[0 .. s.buf.items.len - head_end], s.buf.items[head_end..]);
        s.buf.shrinkRetainingCapacity(s.buf.items.len - head_end);
        return s;
    }

    pub fn close(s: *Socket) void {
        if (s.assembler) |*a| a.deinit(s.gpa);
        std.crypto.secureZero(u8, s.buf.allocatedSlice());
        s.buf.deinit(s.gpa);
        s.conn.close(s.gpa);
    }

    /// Reads more into `buf`; false at end of stream.
    pub fn readMore(s: *Socket) error{ OutOfMemory, ReadFailed, Canceled }!bool {
        try s.buf.ensureUnusedCapacity(s.gpa, 32 * 1024);
        const n = try s.conn.read(s.buf.unusedCapacitySlice());
        if (n == 0) return false;
        s.buf.items.len += n;
        return true;
    }

    /// Sends one masked client frame.
    pub fn send(s: *Socket, opcode: ws.Opcode, payload: []const u8) !void {
        var out: [ws.max_client_payload + 16]u8 = undefined;
        defer std.crypto.secureZero(u8, &out);
        var mask: [4]u8 = undefined;
        try s.io.randomSecure(&mask);
        try s.conn.writeAll(try ws.encodeClientFrame(&out, opcode, payload, mask));
    }

    /// The next server frame (its payload valid until the next call);
    /// null at end of stream.
    pub fn next(s: *Socket, max_payload: usize) !?ws.Frame {
        while (true) {
            if (try s.buffered(max_payload)) |f| return f;
            if (s.buf.items.len > max_payload + 16) return error.FrameTooLarge;
            if (!try s.readMore()) return null;
        }
    }

    /// The next message among the bytes already read (its payload valid
    /// until the next call), or null if more are needed. A message in
    /// parts is at most `max_payload` bytes in all, like one frame.
    pub fn buffered(s: *Socket, max_payload: usize) (ws.FrameError || parts.Assembler.Error)!?ws.Frame {
        s.drop();
        while (try ws.parseServerFrame(s.buf.items, max_payload)) |f| {
            s.used = f.len;
            const a = if (s.assembler) |*a| a else return f;
            a.limit = max_payload;
            if (try a.filter(s.gpa, f)) |m| return m;
            s.drop(); // a part: the message goes on
        }
        return null;
    }

    fn drop(s: *Socket) void {
        if (s.used == 0) return;
        const u = s.used;
        std.mem.copyForwards(u8, s.buf.items[0 .. s.buf.items.len - u], s.buf.items[u..]);
        s.buf.shrinkRetainingCapacity(s.buf.items.len - u);
        s.used = 0;
    }

    /// The next reply header (pings answered on the way).
    fn replyHeader(s: *Socket) !bulk.Reply {
        while (true) {
            const f = (try s.next(bulk.max_header)) orelse return error.ConnectionClosed;
            switch (f.opcode) {
                .text => return bulk.parseReply(f.payload) orelse error.BadReply,
                .ping => try s.send(.pong, f.payload),
                .pong => {},
                else => return error.BadReply,
            }
        }
    }

    /// One bulk upload (`put bundle`, shared/bulk.zig): the header, the
    /// server's go-ahead, `body` in binary messages, and the final reply.
    /// A refusal of the header comes back as is, with nothing sent.
    pub fn upload(s: *Socket, req: bulk.Request, body: []const u8) !bulk.Reply {
        var rb: [bulk.max_header]u8 = undefined;
        try s.send(.text, try bulk.formatRequest(&rb, req));
        const go = try s.replyHeader();
        switch (go) {
            .err => return go,
            .ok => |o| if (o.len != 0) return error.BadReply,
        }
        var rest = body;
        while (rest.len > 0) {
            const n = @min(rest.len, bulk.upload_chunk);
            try s.send(.binary, rest[0..n]);
            rest = rest[n..];
        }
        const done = try s.replyHeader();
        switch (done) {
            .err => {},
            .ok => |o| if (o.len != 0) return error.BadReply,
        }
        return done;
    }

    /// One bulk request (shared/bulk.zig): the reply header, then the body
    /// handed to `sink(ctx, chunk)` chunk by chunk (exactly `len` bytes),
    /// ping/pong answered on the way.
    pub fn request(s: *Socket, req: bulk.Request, ctx: anytype, comptime sink: fn (@TypeOf(ctx), []const u8) anyerror!void) !bulk.Reply {
        var rb: [bulk.max_header]u8 = undefined;
        try s.send(.text, try bulk.formatRequest(&rb, req));
        var header: bulk.Reply = while (true) {
            const f = (try s.next(bulk.max_header)) orelse return error.ConnectionClosed;
            switch (f.opcode) {
                .text => break bulk.parseReply(f.payload) orelse return error.BadReply,
                .ping => try s.send(.pong, f.payload),
                .pong => {},
                else => return error.BadReply,
            }
        };
        // The frame buffer moves on with the body: keep the signature.
        switch (header) {
            .ok => |*o| if (o.sig) |sig| {
                @memcpy(s.sig_buf[0..sig.len], sig);
                o.sig = s.sig_buf[0..sig.len];
            },
            .err => {},
        }
        const len = switch (header) {
            .ok => |o| o.len,
            .err => return header,
        };
        var got: u64 = 0;
        while (got < len) {
            const f = (try s.next(bulk.chunk)) orelse return error.ConnectionClosed;
            switch (f.opcode) {
                .binary => {
                    if (f.payload.len == 0 or f.payload.len > len - got) return error.BadReply;
                    try sink(ctx, f.payload);
                    got += f.payload.len;
                },
                .ping => try s.send(.pong, f.payload),
                .pong => {},
                else => return error.BadReply,
            }
        }
        return header;
    }
};
