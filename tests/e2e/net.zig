//! Raw TCP client sockets to 127.0.0.1 with explicit timeouts: the harness
//! must be able to send malformed bytes, dribble requests, stop reading, and
//! notice exactly when the server closes.

const std = @import("std");
const w = @import("win.zig");

pub const Error = error{ SocketFailed, ConnectFailed, SendFailed, RecvFailed, Timeout, Reset };

var started = std.atomic.Value(bool).init(false);

pub fn init() void {
    if (started.swap(true, .acq_rel)) return;
    var data: [1024]u8 align(8) = undefined;
    _ = w.WSAStartup(0x0202, &data);
}

pub fn now() u64 {
    return w.GetTickCount64();
}

pub fn sleep(ms: u32) void {
    w.Sleep(ms);
}

pub const Options = struct {
    /// Local source address (127.0.0.x), to look like a different peer.
    source: ?[4]u8 = null,
    /// SO_RCVBUF before connecting (a small one makes a stuck reader).
    rcvbuf: ?c_int = null,
};

pub const Socket = struct {
    s: w.SOCKET,
    /// Timeout of the last setsockopt, to avoid redundant calls.
    rcv_timeout: u32 = 0,

    pub fn connect(port: u16, opts: Options) Error!Socket {
        init();
        const s = w.WSASocketW(w.AF_INET, w.SOCK_STREAM, w.IPPROTO_TCP, null, 0, w.WSA_FLAG_OVERLAPPED | w.WSA_FLAG_NO_HANDLE_INHERIT); // SO_RCVTIMEO needs OVERLAPPED
        if (s == w.INVALID_SOCKET) return error.SocketFailed;
        errdefer _ = w.closesocket(s);
        if (opts.rcvbuf) |n| {
            var v: c_int = n;
            _ = w.setsockopt(s, w.SOL_SOCKET, w.SO_RCVBUF, &v, @sizeOf(c_int));
        }
        var one: c_int = 1;
        _ = w.setsockopt(s, w.IPPROTO_TCP, w.TCP_NODELAY, &one, @sizeOf(c_int));
        var snd: u32 = 15_000;
        _ = w.setsockopt(s, w.SOL_SOCKET, w.SO_SNDTIMEO, &snd, @sizeOf(u32));
        if (opts.source) |src| {
            const local: w.sockaddr_in = .{ .port_be = 0, .addr = src };
            if (w.bind(s, &local, @sizeOf(w.sockaddr_in)) != 0) return error.ConnectFailed;
        }
        const addr: w.sockaddr_in = .{ .port_be = std.mem.nativeToBig(u16, port), .addr = .{ 127, 0, 0, 1 } };
        if (w.connect(s, &addr, @sizeOf(w.sockaddr_in)) != 0) return error.ConnectFailed;
        return .{ .s = s };
    }

    pub fn close(sock: *Socket) void {
        if (sock.s != w.INVALID_SOCKET) _ = w.closesocket(sock.s);
        sock.s = w.INVALID_SOCKET;
    }

    pub fn shutdownSend(sock: *Socket) void {
        _ = w.shutdown(sock.s, w.SD_SEND);
    }

    pub fn sendAll(sock: *Socket, data: []const u8) Error!void {
        var off: usize = 0;
        while (off < data.len) {
            const chunk: c_int = @intCast(@min(data.len - off, 1 << 20));
            const n = w.send(sock.s, data[off..].ptr, chunk, 0);
            if (n <= 0) return error.SendFailed;
            off += @intCast(n);
        }
    }

    /// Returns 0 when the peer closed the connection.
    pub fn recvSome(sock: *Socket, buf: []u8, timeout_ms: u32) Error!usize {
        const t: u32 = @max(timeout_ms, 1);
        if (t != sock.rcv_timeout) {
            _ = w.setsockopt(sock.s, w.SOL_SOCKET, w.SO_RCVTIMEO, &t, @sizeOf(u32));
            sock.rcv_timeout = t;
        }
        const n = w.recv(sock.s, buf.ptr, @intCast(@min(buf.len, 1 << 30)), 0);
        if (n >= 0) return @intCast(n);
        return switch (w.WSAGetLastError()) {
            w.WSAETIMEDOUT => error.Timeout,
            w.WSAECONNRESET, w.WSAECONNABORTED => error.Reset,
            else => error.RecvFailed,
        };
    }

    pub const Drained = struct { data: []u8, closed: bool };

    /// Reads until the peer closes, `max` bytes arrive, or `timeout_ms`
    /// passes overall. `closed` reports whether EOF/reset was seen.
    pub fn recvUntilClose(sock: *Socket, gpa: std.mem.Allocator, max: usize, timeout_ms: u32) !Drained {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        const deadline = now() + timeout_ms;
        var buf: [16 * 1024]u8 = undefined;
        var closed = false;
        while (out.items.len < max) {
            const t = now();
            if (t >= deadline) break;
            const n = sock.recvSome(&buf, @intCast(deadline - t)) catch |err| switch (err) {
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
