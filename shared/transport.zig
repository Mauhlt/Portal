//! The stream seam: the one place Portal's HTTPS/WSS server and its native
//! client touch a connection. Everything above it (TLS 1.3, HTTP/1.1,
//! WebSocket, auth, pairing, sync) is one implementation, whichever
//! transport carries the bytes:
//!
//!   os    an OS socket (std.Io.net): loopback, the e2e tests, and anyone
//!         still on a real WireGuard adapter. Byte-for-byte what Portal
//!         did before the seam existed: std's own reader/writer, std's own
//!         cancelation.
//!   ext   anything else that moves a byte stream: the in-process tunnel's
//!         userspace TCP/IP stack (client/src/tunnel/netstack.zig) and the
//!         in-memory network the unit tests use (`MemNet` below).
//!
//! Contract for an `ext` implementation:
//!   * `read` blocks until at least one byte, end of stream (0) or an
//!     error; `write` blocks until at least one byte was accepted
//!     (backpressure). Both block ONLY in a cancelable std.Io wait (an
//!     Io.Condition or Io.Event), never in an OS wait std cannot cancel:
//!     Portal's connection supervisor ends a stuck worker by canceling it
//!     (web.zig) and the client's watchdog does the same (watchdog.zig).
//!   * `remote` is the peer's address as the transport authenticated it.
//!     Inside the tunnel that is the device's tunnel address (10.8.0.x,
//!     enforced by WireGuard's allowed-IPs source check): device
//!     credentials and session cookies are bound to it (auth.zig, M1).
//!   * `close` releases the stream once nothing is blocked on it.
//!
//! No polling anywhere: a waiting call sleeps in an Io wait until the
//! implementation signals readiness (see `Readiness`).

const std = @import("std");
const Io = std.Io;
const net = Io.net;

pub const ReadError = net.Stream.Reader.Error;
pub const WriteError = net.Stream.Writer.Error;
pub const AcceptError = net.Server.AcceptError;
pub const DialError = net.IpAddress.ConnectError;

/// How the transport schedules a stream's bytes against the others. The
/// live WebSocket (keystrokes, screen, conversation) is `interactive`;
/// sync packages and other large transfers go on their own `bulk`
/// connection, so a big download never delays a keystroke or its echo.
pub const Priority = enum { interactive, bulk };

/// A connection from an `ext` transport.
pub const Ext = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    remote: net.IpAddress,

    pub const VTable = struct {
        read: *const fn (ptr: *anyopaque, io: Io, dest: []u8) ReadError!usize,
        write: *const fn (ptr: *anyopaque, io: Io, data: []const u8) WriteError!usize,
        close: *const fn (ptr: *anyopaque, io: Io) void,
        /// null: the transport has a single class.
        set_priority: ?*const fn (ptr: *anyopaque, p: Priority) void = null,
    };
};

pub const Stream = union(enum) {
    os: net.Stream,
    ext: Ext,

    /// The peer's address (what M1 and the pairing checks bind to).
    pub fn remote(s: *const Stream) net.IpAddress {
        return switch (s.*) {
            .os => |o| o.socket.address,
            .ext => |e| e.remote,
        };
    }

    /// At least one byte, or 0 at end of stream.
    pub fn read(s: *const Stream, io: Io, dest: []u8) ReadError!usize {
        switch (s.*) {
            .os => |*o| {
                var iov = [_][]u8{dest};
                const r = try o.readWithControl(io, &iov, &.{});
                return r.data_len;
            },
            .ext => |e| return e.vtable.read(e.ptr, io, dest),
        }
    }

    pub fn close(s: *const Stream, io: Io) void {
        switch (s.*) {
            .os => |*o| o.close(io),
            .ext => |e| e.vtable.close(e.ptr, io),
        }
    }

    /// The server marks the bulk WebSocket after the upgrade (the client
    /// already dialed it as bulk). OS sockets (unit tests only) have one
    /// class.
    pub fn setPriority(s: *const Stream, p: Priority) void {
        switch (s.*) {
            .os => {},
            .ext => |e| if (e.vtable.set_priority) |f| f(e.ptr, p),
        }
    }

    pub fn reader(s: Stream, io: Io, buffer: []u8) Reader {
        return switch (s) {
            .os => |o| .{ .os = o.reader(io, buffer) },
            .ext => |e| .{ .ext = .init(e, io, buffer) },
        };
    }

    pub fn writer(s: Stream, io: Io, buffer: []u8) Writer {
        return switch (s) {
            .os => |o| .{ .os = o.writer(io, buffer) },
            .ext => |e| .{ .ext = .init(e, io, buffer) },
        };
    }
};

/// A std.Io.Reader over either kind of stream. Do not move it once
/// `interface()` has been taken (like std's own readers).
pub const Reader = union(enum) {
    os: net.Stream.Reader,
    ext: ExtReader,

    pub fn interface(r: *Reader) *Io.Reader {
        return switch (r.*) {
            .os => |*o| &o.interface,
            .ext => |*e| &e.interface,
        };
    }

    /// Why the interface returned error.ReadFailed (null: end of stream).
    pub fn err(r: *const Reader) ?ReadError {
        return switch (r.*) {
            .os => |*o| o.err,
            .ext => |*e| e.err,
        };
    }
};

pub const Writer = union(enum) {
    os: net.Stream.Writer,
    ext: ExtWriter,

    pub fn interface(w: *Writer) *Io.Writer {
        return switch (w.*) {
            .os => |*o| &o.interface,
            .ext => |*e| &e.interface,
        };
    }

    pub fn err(w: *const Writer) ?WriteError {
        return switch (w.*) {
            .os => |*o| o.err,
            .ext => |*e| e.err,
        };
    }
};

pub const ExtReader = struct {
    interface: Io.Reader,
    ext: Ext,
    io: Io,
    err: ?ReadError = null,

    fn init(e: Ext, io: Io, buffer: []u8) ExtReader {
        return .{
            .interface = .{ .vtable = &.{ .stream = streamImpl, .readVec = readVec }, .buffer = buffer, .seek = 0, .end = 0 },
            .ext = e,
            .io = io,
        };
    }

    fn streamImpl(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const dest = limit.slice(try io_w.writableSliceGreedy(1));
        var data: [1][]u8 = .{dest};
        const n = try readVec(io_r, &data);
        io_w.advance(n);
        return n;
    }

    fn readVec(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const r: *ExtReader = @alignCast(@fieldParentPtr("interface", io_r));
        var iov: [2][]u8 = undefined;
        const dest_n, const data_size = try io_r.writableVector(&iov, data);
        if (dest_n == 0 or iov[0].len == 0) return 0;
        const n = r.ext.vtable.read(r.ext.ptr, r.io, iov[0]) catch |e| {
            r.err = e;
            return error.ReadFailed;
        };
        if (n == 0) return error.EndOfStream;
        // Read into the reader's own buffer (nothing of `data` was given).
        if (n > data_size) {
            io_r.end += n - data_size;
            return data_size;
        }
        return n;
    }
};

pub const ExtWriter = struct {
    interface: Io.Writer,
    ext: Ext,
    io: Io,
    err: ?WriteError = null,

    fn init(e: Ext, io: Io, buffer: []u8) ExtWriter {
        return .{
            .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer },
            .ext = e,
            .io = io,
        };
    }

    fn some(w: *ExtWriter, bytes: []const u8) Io.Writer.Error!usize {
        return w.ext.vtable.write(w.ext.ptr, w.io, bytes) catch |e| {
            w.err = e;
            return error.WriteFailed;
        };
    }

    fn drain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const w: *ExtWriter = @alignCast(@fieldParentPtr("interface", io_w));
        // The buffered bytes first (nothing of `data` is consumed then).
        const buffered = io_w.buffered();
        if (buffered.len > 0) return io_w.consume(try w.some(buffered));
        for (data[0 .. data.len - 1]) |d| {
            if (d.len > 0) return w.some(d);
        }
        const pattern = data[data.len - 1];
        if (splat == 0 or pattern.len == 0) return 0;
        return w.some(pattern);
    }
};

/// A listener of either kind. The os one is created (and closed) by the
/// caller: on Windows Portal binds it exclusively (src/netlisten.zig).
pub const Listener = union(enum) {
    os: net.Server,
    ext: ExtListener,

    /// Blocks until a connection arrives (cancelable).
    pub fn accept(l: *Listener, io: Io) AcceptError!Stream {
        return switch (l.*) {
            .os => |*o| .{ .os = try o.accept(io) },
            .ext => |e| e.vtable.accept(e.ptr, io),
        };
    }
};

pub const ExtListener = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        accept: *const fn (ptr: *anyopaque, io: Io) AcceptError!Stream,
        close: *const fn (ptr: *anyopaque, io: Io) void,
    };

    pub fn close(l: ExtListener, io: Io) void {
        l.vtable.close(l.ptr, io);
    }
};

/// How a client reaches the server: a dial through the in-process tunnel
/// (`ext`; production) or an OS connect (`os`; in-process unit tests on
/// loopback only), with the priority its connections get from the first
/// byte.
pub const Dialer = struct {
    kind: Kind,
    priority: Priority = .interactive,

    pub const Kind = union(enum) {
        os,
        ext: ExtDialer,
    };

    pub const os: Dialer = .{ .kind = .os };

    pub fn ext(e: ExtDialer) Dialer {
        return .{ .kind = .{ .ext = e } };
    }

    /// The same dialer for bulk transfers.
    pub fn bulk(d: Dialer) Dialer {
        var b = d;
        b.priority = .bulk;
        return b;
    }

    pub fn dial(d: Dialer, io: Io, addr: net.IpAddress) DialError!Stream {
        return switch (d.kind) {
            .os => .{ .os = try addr.connect(io, .{ .mode = .stream }) },
            .ext => |e| e.vtable.dial(e.ptr, io, addr, d.priority),
        };
    }
};

pub const ExtDialer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        dial: *const fn (ptr: *anyopaque, io: Io, addr: net.IpAddress, priority: Priority) DialError!Stream,
    };
};

/// The wake-up an `ext` implementation's blocking calls sleep on: a
/// generation counter under an Io.Mutex with an Io.Condition. A blocking
/// call takes `begin()`, tries its non-blocking operation, and if that
/// would block calls `wait(gen)`, which returns once `signal()` ran after
/// `begin()` (or with error.Canceled). Signalling is cheap and may be
/// spurious; one Readiness may serve many streams (each just retries).
pub const Readiness = struct {
    mutex: Io.Mutex = .init,
    cond: Io.Condition = .init,
    gen: u64 = 0,

    pub fn begin(r: *Readiness, io: Io) u64 {
        r.mutex.lockUncancelable(io);
        defer r.mutex.unlock(io);
        return r.gen;
    }

    pub fn wait(r: *Readiness, io: Io, seen: u64) Io.Cancelable!void {
        r.mutex.lockUncancelable(io);
        defer r.mutex.unlock(io);
        while (r.gen == seen) try r.cond.wait(io, &r.mutex);
    }

    pub fn signal(r: *Readiness, io: Io) void {
        r.mutex.lockUncancelable(io);
        r.gen +%= 1;
        r.mutex.unlock(io);
        r.cond.broadcast(io);
    }
};

// ------------------------------------------------------- in-memory network

/// An in-memory network of `ext` streams, for tests: listeners on
/// (address, port), dials from a given source address. The accepting side
/// sees the dialer's source address as `remote`, exactly as the tunnel's
/// stack reports the device's tunnel address. Everything blocks only in
/// `Readiness` waits, so cancelation works as with the real stack.
pub const MemNet = struct {
    gpa: std.mem.Allocator,
    ready: Readiness = .{},
    mutex: Io.Mutex = .init,
    listeners: [8]?*MemListener = @splat(null),
    next_port: u16 = 40000,

    pub const capacity = 16 * 1024;

    const Pipe = struct {
        buf: [capacity]u8 = undefined,
        head: usize = 0,
        len: usize = 0,
        closed: bool = false,
    };

    /// Two pipes and two ends; freed when both ends are closed.
    const Conn = struct {
        net_: *MemNet,
        pipes: [2]Pipe = .{ .{}, .{} },
        open_ends: u8 = 2,
        ends: [2]End = undefined,
        /// What end side sees as its peer.
        remotes: [2]net.IpAddress = undefined,
    };

    const End = struct {
        conn: *Conn,
        /// Reads pipes[side], writes pipes[1 - side].
        side: u1,
    };

    const MemListener = struct {
        net_: *MemNet,
        addr: net.IpAddress,
        queue: [8]?*End = @splat(null),
        closed: bool = false,
    };

    pub fn listen(n: *MemNet, io: Io, addr: net.IpAddress) !Listener {
        n.mutex.lockUncancelable(io);
        defer n.mutex.unlock(io);
        for (n.listeners) |slot| if (slot) |l| if (!l.closed and l.addr.eql(&addr)) return error.AddressInUse;
        for (&n.listeners) |*slot| if (slot.* == null) {
            const l = try n.gpa.create(MemListener);
            l.* = .{ .net_ = n, .addr = addr };
            slot.* = l;
            return .{ .ext = .{ .ptr = l, .vtable = &listener_vtable } };
        };
        return error.SystemResources;
    }

    /// A dialer whose connections come from `source` (no port: one is
    /// picked per connection).
    pub fn dialer(n: *MemNet, source: *Source) Dialer {
        source.net_ = n;
        return .ext(.{ .ptr = source, .vtable = &dialer_vtable });
    }

    pub const Source = struct {
        addr: net.IpAddress,
        net_: *MemNet = undefined,
    };

    pub fn deinit(n: *MemNet) void {
        for (&n.listeners) |*slot| if (slot.*) |l| {
            n.gpa.destroy(l);
            slot.* = null;
        };
    }

    const listener_vtable: ExtListener.VTable = .{ .accept = accept, .close = closeListener };
    const dialer_vtable: ExtDialer.VTable = .{ .dial = dial };
    const stream_vtable: Ext.VTable = .{ .read = read, .write = write, .close = closeEnd };

    fn accept(ptr: *anyopaque, io: Io) AcceptError!Stream {
        const l: *MemListener = @ptrCast(@alignCast(ptr));
        const n = l.net_;
        while (true) {
            const seen = n.ready.begin(io);
            n.mutex.lockUncancelable(io);
            if (l.closed) {
                n.mutex.unlock(io);
                return error.SocketNotListening;
            }
            for (&l.queue) |*q| if (q.*) |e| {
                q.* = null;
                n.mutex.unlock(io);
                return .{ .ext = .{ .ptr = e, .vtable = &stream_vtable, .remote = e.conn.remotes[e.side] } };
            };
            n.mutex.unlock(io);
            try n.ready.wait(io, seen);
        }
    }

    fn closeListener(ptr: *anyopaque, io: Io) void {
        const l: *MemListener = @ptrCast(@alignCast(ptr));
        const n = l.net_;
        n.mutex.lockUncancelable(io);
        l.closed = true;
        n.mutex.unlock(io);
        n.ready.signal(io);
    }

    fn dial(ptr: *anyopaque, io: Io, addr: net.IpAddress, priority: Priority) DialError!Stream {
        _ = priority;
        const src: *Source = @ptrCast(@alignCast(ptr));
        const n = src.net_;
        n.mutex.lockUncancelable(io);
        defer n.mutex.unlock(io);
        const l = for (n.listeners) |slot| {
            if (slot) |l| if (!l.closed and l.addr.eql(&addr)) break l;
        } else return error.ConnectionRefused;
        const qi = for (l.queue, 0..) |q, i| {
            if (q == null) break i;
        } else return error.ConnectionRefused;
        const c = n.gpa.create(Conn) catch return error.SystemResources;
        c.* = .{ .net_ = n };
        c.ends = .{ .{ .conn = c, .side = 0 }, .{ .conn = c, .side = 1 } };
        var from = src.addr;
        from.setPort(n.next_port);
        n.next_port +%= 1;
        c.remotes = .{ addr, from };
        l.queue[qi] = &c.ends[1];
        n.ready.signal(io);
        return .{ .ext = .{ .ptr = &c.ends[0], .vtable = &stream_vtable, .remote = addr } };
    }

    fn read(ptr: *anyopaque, io: Io, dest: []u8) ReadError!usize {
        const e: *End = @ptrCast(@alignCast(ptr));
        const n = e.conn.net_;
        if (dest.len == 0) return 0;
        while (true) {
            const seen = n.ready.begin(io);
            n.mutex.lockUncancelable(io);
            const p = &e.conn.pipes[e.side];
            if (p.len > 0) {
                const k = @min(dest.len, p.len, capacity - p.head);
                @memcpy(dest[0..k], p.buf[p.head..][0..k]);
                p.head = (p.head + k) % capacity;
                p.len -= k;
                n.mutex.unlock(io);
                n.ready.signal(io);
                return k;
            }
            if (p.closed) {
                n.mutex.unlock(io);
                return 0;
            }
            n.mutex.unlock(io);
            try n.ready.wait(io, seen);
        }
    }

    fn write(ptr: *anyopaque, io: Io, data: []const u8) WriteError!usize {
        const e: *End = @ptrCast(@alignCast(ptr));
        const n = e.conn.net_;
        if (data.len == 0) return 0;
        while (true) {
            const seen = n.ready.begin(io);
            n.mutex.lockUncancelable(io);
            const p = &e.conn.pipes[1 - @as(usize, e.side)];
            if (p.closed) {
                n.mutex.unlock(io);
                return error.ConnectionResetByPeer;
            }
            if (p.len < capacity) {
                const tail = (p.head + p.len) % capacity;
                const k = @min(data.len, capacity - p.len, capacity - tail);
                @memcpy(p.buf[tail..][0..k], data[0..k]);
                p.len += k;
                n.mutex.unlock(io);
                n.ready.signal(io);
                return k;
            }
            n.mutex.unlock(io);
            try n.ready.wait(io, seen);
        }
    }

    fn closeEnd(ptr: *anyopaque, io: Io) void {
        const e: *End = @ptrCast(@alignCast(ptr));
        const c = e.conn;
        const n = c.net_;
        n.mutex.lockUncancelable(io);
        // Both directions end: the peer reads end of stream, its writes fail.
        c.pipes[0].closed = true;
        c.pipes[1].closed = true;
        c.open_ends -= 1;
        const free = c.open_ends == 0;
        n.mutex.unlock(io);
        n.ready.signal(io);
        if (free) n.gpa.destroy(c);
    }
};

// -------------------------------------------------------------------- tests

const testing = std.testing;

fn echoOnce(io: Io, l: *Listener, out_remote: *net.IpAddress) !void {
    var s = try l.accept(io);
    defer s.close(io);
    out_remote.* = s.remote();
    var rbuf: [64]u8 = undefined;
    var wbuf: [64]u8 = undefined;
    var r = s.reader(io, &rbuf);
    var w = s.writer(io, &wbuf);
    const line = try r.interface().takeDelimiterInclusive('\n');
    try w.interface().writeAll(line);
    try w.interface().flush();
}

test "ext streams: reader/writer interfaces, and the dialer's address is the remote" {
    const io = testing.io;
    var mn: MemNet = .{ .gpa = testing.allocator };
    defer mn.deinit();
    const desk = try net.IpAddress.parse("10.8.0.1", 8420);
    var l = try mn.listen(io, desk);
    var seen: net.IpAddress = undefined;
    var server = try io.concurrent(echoOnce, .{ io, &l, &seen });

    var src: MemNet.Source = .{ .addr = try net.IpAddress.parse("10.8.0.2", 0) };
    const d = mn.dialer(&src);
    var s = try d.dial(io, desk);
    try testing.expect(s.remote().eql(&desk));
    var wbuf: [8]u8 = undefined; // smaller than the line: drains mid-write
    var w = s.writer(io, &wbuf);
    try w.interface().writeAll("hello through the seam\n");
    try w.interface().flush();
    var got: [64]u8 = undefined;
    var n: usize = 0;
    while (n < 23) {
        const k = try s.read(io, got[n..]);
        if (k == 0) break;
        n += k;
    }
    try testing.expectEqualStrings("hello through the seam\n", got[0..n]);
    try server.await(io);
    // M1 depends on this: the accepting side sees the device's address.
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("10.8.0.2", (try std.fmt.bufPrint(&buf, "{f}", .{seen}))[0.."10.8.0.2".len]);
    try testing.expectEqual(@as(usize, 0), try s.read(io, &got)); // server closed
    s.close(io);
    l.ext.close(io);
}

fn blockedRead(io: Io, s: *const Stream) ReadError!usize {
    var b: [4]u8 = undefined;
    return s.read(io, &b);
}

test "ext streams: a blocked read is canceled like an OS socket's" {
    const io = testing.io;
    var mn: MemNet = .{ .gpa = testing.allocator };
    defer mn.deinit();
    const desk = try net.IpAddress.parse("10.8.0.1", 8420);
    var l = try mn.listen(io, desk);
    var src: MemNet.Source = .{ .addr = try net.IpAddress.parse("10.8.0.3", 0) };
    var s = try mn.dialer(&src).dial(io, desk);
    var peer = try l.accept(io);
    var f = try io.concurrent(blockedRead, .{ io, &s });
    try testing.expectError(error.Canceled, f.cancel(io));
    s.close(io);
    peer.close(io);
    l.ext.close(io);
}

test "ext dial without a listener is refused" {
    const io = testing.io;
    var mn: MemNet = .{ .gpa = testing.allocator };
    defer mn.deinit();
    var src: MemNet.Source = .{ .addr = try net.IpAddress.parse("10.8.0.2", 0) };
    try testing.expectError(error.ConnectionRefused, mn.dialer(&src).dial(io, try net.IpAddress.parse("10.8.0.1", 8421)));
}
