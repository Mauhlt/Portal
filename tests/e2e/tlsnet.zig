//! HTTPS/WSS transport for the harness: std.crypto.tls.Client over a
//! net.Socket, trusting only one Portal CA (exported with
//! `portal ca export`), plus `Stream`, the plain-or-TLS connection that
//! http.zig and ws.zig speak over.
//!
//! Trust: the Certificate.Bundle holds exactly the exported CA. On Windows
//! std's client does not stop there: when the bundle cannot verify a chain
//! it asks the OS chain engine (CertGetCertificateChain, current user) and,
//! if the OS accepts it, swaps the OS root store into our bundle
//! (tryDownloadRootCert). A server that only the OS trusts would then pass
//! silently. `connect` catches that: the bundle must still hold exactly the
//! one CA after the handshake, otherwise the connection is refused with
//! error.NotVerifiedByPortalCa and the bundle is reloaded from the PEM.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const tls = std.crypto.tls;
const Certificate = std.crypto.Certificate;
const net = @import("net.zig");

pub const Error = net.Error || Allocator.Error || error{ TlsHandshakeFailed, NotVerifiedByPortalCa };

/// The detailed reason for the last error.TlsHandshakeFailed on this thread.
pub threadlocal var last_handshake_error: ?anyerror = null;

/// A bundle holding exactly one CA certificate, loaded from a PEM file.
pub const Trust = struct {
    gpa: Allocator,
    io: Io,
    path: []const u8,
    bundle: Certificate.Bundle = .empty,
    lock: Io.RwLock = .init,
    mutex: @import("win.zig").Mutex = .{},

    pub fn load(gpa: Allocator, io: Io, pem_path: []const u8) !*Trust {
        const t = try gpa.create(Trust);
        errdefer gpa.destroy(t);
        t.* = .{ .gpa = gpa, .io = io, .path = try gpa.dupe(u8, pem_path) };
        try t.reload();
        return t;
    }

    fn reload(t: *Trust) !void {
        t.bundle.deinit(t.gpa);
        t.bundle = .empty;
        try t.bundle.addCertsFromFilePathAbsolute(t.gpa, t.io, Io.Timestamp.now(t.io, .real), t.path);
        if (t.bundle.map.count() != 1) return error.ExpectedOneCertificate;
    }

    pub fn deinit(t: *Trust) void {
        t.bundle.deinit(t.gpa);
        t.gpa.free(t.path);
        t.gpa.destroy(t);
    }
};

/// A TLS 1.3 (or 1.2, if the server offered it) client connection.
pub const TlsSocket = struct {
    gpa: Allocator,
    sock: net.Socket,
    /// Receive timeout for the current read.
    timeout_ms: u32 = 10_000,
    /// Socket-level failure behind the last error.ReadFailed/WriteFailed.
    sock_err: ?net.Error = null,
    raw_in: Io.Reader,
    raw_out: Io.Writer,
    client: tls.Client,
    in_buf: [tls.Client.min_buffer_len]u8,
    out_buf: [tls.max_ciphertext_record_len]u8,
    tls_read: [tls.max_ciphertext_record_len]u8,
    tls_write: [tls.max_ciphertext_record_len]u8,

    const in_vtable: Io.Reader.VTable = .{ .stream = streamFn, .readVec = readVecFn };
    const out_vtable: Io.Writer.VTable = .{ .drain = drainFn };

    pub const Options = struct {
        net: net.Options = .{},
        /// Name checked against the certificate (an IP SAN for Portal).
        host: []const u8 = "127.0.0.1",
    };

    pub fn connect(gpa: Allocator, port: u16, trust: *Trust, o: Options) Error!*TlsSocket {
        var sock = try net.Socket.connect(port, o.net);
        errdefer sock.close();
        const t = try gpa.create(TlsSocket);
        errdefer gpa.destroy(t);
        t.gpa = gpa;
        t.sock = sock;
        t.timeout_ms = 10_000;
        t.sock_err = null;
        t.raw_in = .{ .vtable = &in_vtable, .buffer = &t.in_buf, .seek = 0, .end = 0 };
        t.raw_out = .{ .vtable = &out_vtable, .buffer = &t.out_buf, .end = 0 };

        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        trust.io.random(&entropy);
        // One handshake at a time per trust: std may swap the bundle.
        trust.mutex.lock();
        defer trust.mutex.unlock();
        const before = trust.bundle.map.count();
        t.client = tls.Client.init(&t.raw_in, &t.raw_out, .{
            .host = .{ .explicit = o.host },
            .ca = .{ .bundle = .{ .gpa = trust.gpa, .io = trust.io, .lock = &trust.lock, .bundle = &trust.bundle } },
            .write_buffer = &t.tls_write,
            .read_buffer = &t.tls_read,
            .entropy = &entropy,
            .realtime_now = Io.Timestamp.now(trust.io, .real),
        }) catch |err| {
            last_handshake_error = if (err == error.ReadFailed) (t.sock_err orelse err) else err;
            if (trust.bundle.map.count() != before) trust.reload() catch {};
            return error.TlsHandshakeFailed;
        };
        if (trust.bundle.map.count() != before) {
            // Accepted by the OS root store, not by our CA.
            trust.reload() catch {};
            last_handshake_error = error.NotVerifiedByPortalCa;
            return error.NotVerifiedByPortalCa;
        }
        return t;
    }

    pub fn version(t: *const TlsSocket) tls.ProtocolVersion {
        return t.client.tls_version;
    }

    /// Sends close_notify (best effort) and closes the socket.
    pub fn close(t: *TlsSocket) void {
        if (t.client.end()) |_| {
            t.raw_out.flush() catch {};
        } else |_| {}
        t.sock.close();
        t.gpa.destroy(t);
    }

    pub fn sendAll(t: *TlsSocket, data: []const u8) net.Error!void {
        t.sock_err = null;
        t.client.writer.writeAll(data) catch return t.sock_err orelse error.SendFailed;
        t.client.writer.flush() catch return t.sock_err orelse error.SendFailed;
        t.raw_out.flush() catch return t.sock_err orelse error.SendFailed;
    }

    /// Like net.Socket.recvSome: 0 once the peer closed (close_notify, or
    /// TCP close without it).
    pub fn recvSome(t: *TlsSocket, buf: []u8, timeout_ms: u32) net.Error!usize {
        if (buf.len == 0) return 0;
        t.timeout_ms = timeout_ms;
        const r = &t.client.reader;
        while (r.bufferedLen() == 0) {
            t.sock_err = null;
            r.fillMore() catch |err| switch (err) {
                error.EndOfStream => return 0,
                error.ReadFailed => {
                    if (t.sock_err) |e| return e;
                    if (t.client.read_err) |e| {
                        if (e == error.TlsConnectionTruncated) return 0;
                        if (e == error.TlsAlert) return 0; // the server's alert ends the stream
                    }
                    return error.RecvFailed;
                },
            };
        }
        const n = @min(buf.len, r.bufferedLen());
        @memcpy(buf[0..n], r.buffered()[0..n]);
        r.toss(n);
        return n;
    }

    // ------------------------------------------- raw socket Reader/Writer

    fn streamFn(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        _ = w;
        _ = limit;
        try fill(r);
        return 0;
    }

    fn readVecFn(r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        _ = data;
        try fill(r);
        return 0;
    }

    /// Adds at least one socket byte to `r.buffer`.
    fn fill(r: *Io.Reader) Io.Reader.Error!void {
        const t: *TlsSocket = @alignCast(@fieldParentPtr("raw_in", r));
        if (r.seek == r.end) {
            r.seek = 0;
            r.end = 0;
        } else if (r.end == r.buffer.len) {
            const n = r.end - r.seek;
            std.mem.copyForwards(u8, r.buffer[0..n], r.buffer[r.seek..r.end]);
            r.seek = 0;
            r.end = n;
        }
        const space = r.buffer[r.end..];
        if (space.len == 0) return error.ReadFailed;
        const n = t.sock.recvSome(space, t.timeout_ms) catch |err| {
            t.sock_err = err;
            return error.ReadFailed;
        };
        if (n == 0) return error.EndOfStream;
        r.end += n;
    }

    fn drainFn(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const t: *TlsSocket = @alignCast(@fieldParentPtr("raw_out", w));
        t.sock.sendAll(w.buffered()) catch |err| {
            t.sock_err = err;
            return error.WriteFailed;
        };
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            t.sock.sendAll(d) catch |err| {
                t.sock_err = err;
                return error.WriteFailed;
            };
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            t.sock.sendAll(last) catch |err| {
                t.sock_err = err;
                return error.WriteFailed;
            };
            n += last.len;
        }
        return n;
    }
};

/// A plain or TLS connection with net.Socket's interface.
pub const Stream = union(enum) {
    plain: net.Socket,
    tls: *TlsSocket,

    /// TLS when `trust` is set, else plain TCP.
    pub fn connect(gpa: Allocator, port: u16, opts: net.Options, trust: ?*Trust) Error!Stream {
        if (trust) |t| return .{ .tls = try TlsSocket.connect(gpa, port, t, .{ .net = opts }) };
        return .{ .plain = try net.Socket.connect(port, opts) };
    }

    pub fn close(s: *Stream) void {
        switch (s.*) {
            .plain => |*p| p.close(),
            .tls => |t| t.close(),
        }
        s.* = .{ .plain = .{ .s = @import("win.zig").INVALID_SOCKET } };
    }

    pub fn sendAll(s: *Stream, data: []const u8) net.Error!void {
        return switch (s.*) {
            .plain => |*p| p.sendAll(data),
            .tls => |t| t.sendAll(data),
        };
    }

    pub fn recvSome(s: *Stream, buf: []u8, timeout_ms: u32) net.Error!usize {
        return switch (s.*) {
            .plain => |*p| p.recvSome(buf, timeout_ms),
            .tls => |t| t.recvSome(buf, timeout_ms),
        };
    }

    pub fn shutdownSend(s: *Stream) void {
        switch (s.*) {
            .plain => |*p| p.shutdownSend(),
            .tls => |t| t.sock.shutdownSend(),
        }
    }

    /// See net.Socket.recvUntilClose.
    pub fn recvUntilClose(s: *Stream, gpa: Allocator, max: usize, timeout_ms: u32) !net.Socket.Drained {
        switch (s.*) {
            .plain => |*p| return p.recvUntilClose(gpa, max, timeout_ms),
            .tls => {},
        }
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        const deadline = net.now() + timeout_ms;
        var buf: [16 * 1024]u8 = undefined;
        var closed = false;
        while (out.items.len < max) {
            const t = net.now();
            if (t >= deadline) break;
            const n = s.recvSome(&buf, @intCast(deadline - t)) catch |err| switch (err) {
                error.Timeout => break,
                error.Reset => {
                    closed = true;
                    break;
                },
                else => return err,
            };
            if (n == 0) {
                closed = true;
                break;
            }
            try out.appendSlice(gpa, buf[0..n]);
        }
        return .{ .data = try out.toOwnedSlice(gpa), .closed = closed };
    }
};
