//! Connection thread: pairing, session refresh, the WebSocket stream and
//! reconnects (docs/protocol.md).
//!
//!   no stored device credential -> wait for the user to press "Pair"
//!       -> POST /pair -> store the device cookie in the OS credential store
//!   stored credential -> POST /auth/refresh -> store the rotated value
//!       immediately (before anything else), keep the session in memory
//!   GET /ws with the session cookie -> 'G' frames into the shared grid
//!   401 on refresh -> delete the credential, back to "Pair this device"
//!   401 on /ws or a `logout` message -> refresh again
//!   network errors -> retry with backoff 1 s doubling to 15 s
//!
//! Every connection is HTTPS/WSS with the server certificate pinned to the
//! Portal CA imported for this server (tlsconn.zig), unless the user chose
//! `--insecure-plain-http`; nothing is sent before the TLS handshake has
//! authenticated the server.
//!
//! Liveness: each step runs under a watchdog (watchdog.zig): 15 s for
//! connect + TLS handshake, 15 s for each request/response, and on the
//! stream 60 s without any data from the server. A ping goes out after
//! 20 s of silence, so a live server always answers in time.
//!
//! Everything read from the network is bounded and parsed defensively.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const http = @import("http.zig");
const ws = @import("ws.zig");
const tlsconn = @import("tlsconn.zig");
const x509check = @import("x509check.zig");
const watchdog = @import("watchdog.zig");
const Grid = @import("view").grid.Grid;
const gframe = @import("../gframe.zig");
const keys = @import("../keys.zig");
const credstore = @import("../credstore.zig");

pub const max_frame_payload = 8 << 20;

pub const connect_timeout_ms = 15_000;
pub const request_timeout_ms = 15_000;
pub const idle_timeout_ms = 60_000;
pub const ping_interval_ms = 20_000;

pub const Status = enum {
    starting,
    need_pairing,
    pairing,
    pair_closed,
    refreshing,
    connecting,
    connected,
    retrying,
    session_ended,
    store_unavailable,
};

pub const Shared = struct {
    mutex: Io.Mutex = .init,
    grid: Grid = .{},
    mode: keys.Mode = .unknown,
    status: Status = .starting,
    detail_buf: [160]u8 = undefined,
    detail_len: usize = 0,
    retry_in_ms: i64 = 0,
    exit_code: ?i64 = null,
    /// Bumped on any change the UI should redraw for.
    version: std.atomic.Value(u64) = .init(0),
    pair_requested: std.atomic.Value(bool) = .init(false),
    wake_ctx: ?*anyopaque = null,
    wake_fn: ?*const fn (*anyopaque) void = null,

    pub fn detail(s: *const Shared) []const u8 {
        return s.detail_buf[0..s.detail_len];
    }
};

/// How to reach the server.
pub const Transport = union(enum) {
    /// HTTPS/WSS, server certificate signed by this CA (DER).
    tls: []const u8,
    /// `--insecure-plain-http` (servers run with --no-tls).
    insecure_plain_http,
};

/// Short user-facing reason for a connection error (no secrets).
pub fn describe(err: anyerror) []const u8 {
    return switch (err) {
        error.NotIssuedByPinnedCa => "server certificate is not from the pinned Portal CA",
        error.HostMismatch => "server certificate is not for this IP",
        error.CertificateExpired => "server certificate expired",
        error.CertificateNotYetValid => "server certificate not yet valid (check the clock)",
        error.CaExpired => "the pinned Portal CA expired",
        error.BadCertificate, error.UnsupportedCertificate => "server sent an unusable certificate",
        error.NotTls13, error.UnsupportedCipherSuite, error.HelloRetryRequest => "server TLS is not Portal's (TLS 1.3)",
        error.TlsHandshakeMalformed, error.TlsUnexpectedMessage, error.TlsDecodeError => "not a TLS server (a --no-tls server needs --insecure-plain-http)",
        error.TlsAlert => "server refused the TLS handshake",
        error.TlsConnectionTruncated => "connection closed during the TLS handshake (a --no-tls server needs --insecure-plain-http)",
        error.NoServerCertificate, error.NoHandshakeSecret, error.TlsHandshakeTooLarge => "TLS handshake failed",
        error.TimedOut, error.Canceled => "server not responding (timed out)",
        error.ConnectionRefused => "connection refused (is Portal running?)",
        error.ConnectionResetByPeer, error.ConnectionClosed => "connection closed by the server",
        error.NetworkUnreachable, error.HostUnreachable => "network unreachable (is the tunnel up?)",
        error.ResponseTooLarge => "response too large",
        else => @errorName(err),
    };
}

pub const Client = struct {
    gpa: std.mem.Allocator,
    io: Io,
    shared: *Shared,
    addr: net.IpAddress,
    host_buf: [64]u8 = undefined,
    host_len: usize = 0,
    ip_buf: [64]u8 = undefined,
    ip_len: usize = 0,
    target_buf: [credstore.max_target]u8 = undefined,
    target_len: usize = 0,
    plain: bool,
    ca_buf: [x509check.max_cert_len]u8 = undefined,
    ca_len: usize = 0,

    wd: watchdog.Watchdog,
    /// The open WebSocket connection; guarded by write_mutex.
    write_mutex: Io.Mutex = .init,
    conn: ?*tlsconn.Conn = null,
    last_rx_ms: std.atomic.Value(i64) = .init(0),
    last_ping_ms: std.atomic.Value(i64) = .init(0),
    /// Last connection error printed to stderr (printed once per change).
    last_logged: ?anyerror = null,

    pub fn init(gpa: std.mem.Allocator, io: Io, shared: *Shared, server: []const u8, transport: Transport) !Client {
        var c: Client = .{
            .gpa = gpa,
            .io = io,
            .shared = shared,
            .addr = undefined,
            .plain = transport == .insecure_plain_http,
            .wd = .{ .io = io },
        };
        const h = try http.canonicalHost(server, &c.host_buf);
        c.host_len = h.len;
        c.addr = net.IpAddress.parseLiteral(h) catch return error.BadServerAddress;
        const ip = bareIp(h);
        @memcpy(c.ip_buf[0..ip.len], ip);
        c.ip_len = ip.len;
        c.target_len = credstore.targetName(h, c.plain, &c.target_buf).len;
        switch (transport) {
            .tls => |ca| {
                if (ca.len > c.ca_buf.len) return error.BadCertificate;
                @memcpy(c.ca_buf[0..ca.len], ca);
                c.ca_len = ca.len;
            },
            .insecure_plain_http => {},
        }
        return c;
    }

    pub fn host(c: *const Client) []const u8 {
        return c.host_buf[0..c.host_len];
    }

    pub fn target(c: *const Client) []const u8 {
        return c.target_buf[0..c.target_len];
    }

    fn secure(c: *const Client) bool {
        return !c.plain;
    }

    fn security(c: *const Client) tlsconn.Security {
        if (c.plain) return .plain;
        return .{ .tls = .{ .ca_der = c.ca_buf[0..c.ca_len], .ip = c.ip_buf[0..c.ip_len] } };
    }

    // ------------------------------------------------------------ status

    fn setStatus(c: *Client, status: Status, comptime fmt: []const u8, args: anytype) void {
        const s = c.shared;
        s.mutex.lockUncancelable(c.io);
        s.status = status;
        const d = std.fmt.bufPrint(&s.detail_buf, fmt, args) catch s.detail_buf[0..0];
        s.detail_len = d.len;
        if (status != .connected) s.mode = if (status == .session_ended) s.mode else .unknown;
        s.mutex.unlock(c.io);
        c.notify();
    }

    fn notify(c: *Client) void {
        _ = c.shared.version.fetchAdd(1, .release);
        if (c.shared.wake_fn) |f| f(c.shared.wake_ctx.?);
    }

    fn sleepMs(c: *Client, ms: i64) void {
        c.io.sleep(.fromMilliseconds(ms), .awake) catch {};
    }

    /// Prints connection errors to stderr once per distinct error.
    fn logError(c: *Client, err: anyerror) void {
        if (c.last_logged) |l| if (l == err) return;
        c.last_logged = err;
        std.debug.print("portal connect: {s}: {s} ({t})\n", .{ c.host(), describe(err), err });
    }

    // ------------------------------------------------------------ main loop

    pub fn run(c: *Client) void {
        var backoff: i64 = 1000;
        var session: ?http.Cookie = null;
        defer if (session) |*s| s.wipe();
        while (true) {
            if (session == null) {
                session = c.authenticate(&backoff);
                if (session == null) continue;
            }
            c.setStatus(.connecting, "opening stream", .{});
            const result = c.runStream(&session.?, &backoff);
            switch (result) {
                .unauthorized, .logout => {
                    session.?.wipe();
                    session = null; // refresh (or re-pair) next
                },
                .exited => |code| {
                    c.shared.mutex.lockUncancelable(c.io);
                    c.shared.exit_code = code;
                    c.shared.mutex.unlock(c.io);
                    c.setStatus(.session_ended, "program exited (code {d}); waiting for a new session", .{code});
                    c.sleepMs(backoff);
                    backoff = @min(backoff * 2, 15000);
                },
                .failed => |why| {
                    c.retryWait(&backoff, why);
                },
            }
        }
    }

    fn retryWait(c: *Client, backoff: *i64, why: []const u8) void {
        var left = backoff.*;
        while (left > 0) : (left -= 250) {
            c.shared.mutex.lockUncancelable(c.io);
            c.shared.retry_in_ms = left;
            c.shared.mutex.unlock(c.io);
            c.setStatus(.retrying, "{s}; retrying in {d} s", .{ why, @divTrunc(left + 999, 1000) });
            c.sleepMs(@min(250, left));
        }
        backoff.* = @min(backoff.* * 2, 15000);
    }

    /// Returns a fresh session cookie, or null after showing why not.
    fn authenticate(c: *Client, backoff: *i64) ?http.Cookie {
        var buf: [credstore.max_secret]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        const stored = credstore.load(c.target(), &buf) catch |err| {
            c.setStatus(.store_unavailable, "OS credential store unavailable ({t}); cannot pair securely", .{err});
            c.sleepMs(5000);
            return null;
        };
        if (stored) |value| {
            var device = http.Cookie.fromValue(.device, value, c.secure()) orelse {
                credstore.delete(c.target()) catch {};
                return null;
            };
            defer device.wipe();
            c.setStatus(.refreshing, "signing in", .{});
            return c.refresh(&device, backoff);
        }
        // Not paired: wait for the user.
        c.shared.mutex.lockUncancelable(c.io);
        const already = c.shared.status == .need_pairing;
        c.shared.mutex.unlock(c.io);
        if (!already) c.setStatus(.need_pairing, "", .{}); // keep any "no longer paired" note
        while (!c.shared.pair_requested.swap(false, .acq_rel)) c.sleepMs(100);
        c.setStatus(.pairing, "pairing", .{});
        return c.pair();
    }

    fn pair(c: *Client) ?http.Cookie {
        var resp_buf: [http.max_head_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &resp_buf);
        var req_buf: [512]u8 = undefined;
        var w: Io.Writer = .fixed(&req_buf);
        http.writePairRequest(&w, c.host(), c.secure()) catch return null;
        var r = c.roundTrip(w.buffered(), &resp_buf) catch |err| {
            c.logError(err);
            c.setStatus(.pair_closed, "could not reach the server: {s}", .{describe(err)});
            return null;
        };
        defer if (r.device) |*d| d.wipe();
        switch (http.pairOutcome(&r)) {
            .ok => {
                credstore.save(c.target(), r.device.?.value()) catch |err| {
                    c.setStatus(.store_unavailable, "could not save the device credential ({t})", .{err});
                    return null;
                };
                return r.session.?;
            },
            .closed => c.setStatus(.pair_closed, "pairing window is closed", .{}),
            .unexpected => c.setStatus(.pair_closed, "unexpected pairing response (HTTP {d})", .{r.status}),
        }
        return null;
    }

    fn refresh(c: *Client, device: *const http.Cookie, backoff: *i64) ?http.Cookie {
        var resp_buf: [http.max_head_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &resp_buf);
        var req_buf: [768]u8 = undefined;
        defer std.crypto.secureZero(u8, &req_buf);
        var w: Io.Writer = .fixed(&req_buf);
        http.writeRefreshRequest(&w, c.host(), c.secure(), device) catch return null;
        var r = c.roundTrip(w.buffered(), &resp_buf) catch |err| {
            c.logError(err);
            c.retryWait(backoff, describe(err));
            return null;
        };
        defer if (r.device) |*d| d.wipe();
        switch (http.refreshOutcome(&r)) {
            .ok => {
                // Rotate first: the old value is only valid for 10 minutes.
                credstore.save(c.target(), r.device.?.value()) catch |err| {
                    c.setStatus(.store_unavailable, "could not save the rotated credential ({t})", .{err});
                    c.sleepMs(5000);
                    return null;
                };
                c.last_logged = null;
                return r.session.?;
            },
            .revoked => {
                credstore.delete(c.target()) catch {};
                c.setStatus(.need_pairing, "this device is no longer paired", .{});
                return null;
            },
            .unexpected => {
                var why: [48]u8 = undefined;
                c.retryWait(backoff, std.fmt.bufPrint(&why, "sign-in failed (HTTP {d})", .{r.status}) catch "sign-in failed");
                return null;
            },
        }
    }

    /// Sends a request on a fresh connection and parses the response head.
    /// Returned slices point into `buf`.
    fn roundTrip(c: *Client, request: []const u8, buf: *[http.max_head_bytes]u8) anyerror!http.Response {
        c.wd.extend(connect_timeout_ms);
        const r = c.wd.run(roundTripTask, .{ c, request, buf }, null);
        if (c.wd.expired.load(.acquire)) return error.TimedOut;
        return r;
    }

    fn roundTripTask(c: *Client, request: []const u8, buf: *[http.max_head_bytes]u8) anyerror!http.Response {
        const conn = try tlsconn.Conn.open(c.gpa, c.io, c.addr, c.security());
        defer conn.close(c.gpa);
        c.wd.extend(request_timeout_ms);
        try conn.writeAll(request);
        var len: usize = 0;
        while (true) {
            if (len == buf.len) return error.ResponseTooLarge;
            const n = try conn.read(buf[len..]);
            if (n == 0) return error.ConnectionClosed;
            len += n;
            if (http.findHeadEnd(buf[0..len])) |end| return http.parseResponseHead(buf[0..end]);
        }
    }

    // ------------------------------------------------------------ stream

    const StreamResult = union(enum) {
        unauthorized,
        logout,
        exited: i64,
        failed: []const u8,
    };

    fn runStream(c: *Client, session: *const http.Cookie, backoff: *i64) StreamResult {
        c.wd.extend(connect_timeout_ms);
        const r = c.wd.run(streamTask, .{ c, session, backoff }, .{ .ctx = c, .f = pingTick });
        if (c.wd.expired.load(.acquire)) {
            c.logError(error.TimedOut);
            return .{ .failed = describe(error.TimedOut) };
        }
        return r;
    }

    /// Runs on the network thread while the stream task runs: keeps an idle
    /// stream alive (the server answers pings with pongs).
    fn pingTick(ctx: *anyopaque) void {
        const c: *Client = @ptrCast(@alignCast(ctx));
        const now = watchdog.nowMs(c.io);
        if (now - c.last_rx_ms.load(.acquire) < ping_interval_ms) return;
        if (now - c.last_ping_ms.load(.acquire) < ping_interval_ms) return;
        c.last_ping_ms.store(now, .release);
        c.sendFrame(.ping, "") catch {};
    }

    fn streamTask(c: *Client, session: *const http.Cookie, backoff: *i64) StreamResult {
        const conn = tlsconn.Conn.open(c.gpa, c.io, c.addr, c.security()) catch |err| {
            c.logError(err);
            return .{ .failed = describe(err) };
        };
        defer conn.close(c.gpa);
        c.wd.extend(request_timeout_ms);

        var rnd: [16]u8 = undefined;
        c.io.randomSecure(&rnd) catch return .{ .failed = "no secure randomness" };
        const key = ws.makeKey(rnd);
        {
            var req_buf: [768]u8 = undefined;
            defer std.crypto.secureZero(u8, &req_buf);
            var w: Io.Writer = .fixed(&req_buf);
            http.writeUpgradeRequest(&w, c.host(), c.secure(), session, &key) catch return .{ .failed = "request too long" };
            conn.writeAll(w.buffered()) catch return .{ .failed = "write failed" };
        }

        // Buffer for the response head and then for frames; grows on demand.
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(c.gpa);
        buf.ensureTotalCapacity(c.gpa, 64 * 1024) catch return .{ .failed = "out of memory" };

        // Response head.
        var head_end: usize = 0;
        while (true) {
            if (buf.items.len >= http.max_head_bytes) return .{ .failed = "response head too large" };
            if (!c.readMore(conn, &buf)) return .{ .failed = "connection closed during upgrade" };
            if (http.findHeadEnd(buf.items)) |e| {
                if (e > http.max_head_bytes) return .{ .failed = "response head too large" };
                head_end = e;
                break;
            }
        }
        const resp = http.parseResponseHead(buf.items[0..head_end]) catch return .{ .failed = "bad upgrade response" };
        if (resp.status == 401) return .unauthorized;
        if (resp.status != 101) return .{ .failed = "upgrade refused" };
        const expected = ws.expectedAccept(&key);
        if (!resp.upgrade_websocket or !resp.connection_upgrade or resp.accept == null or
            !std.mem.eql(u8, resp.accept.?, &expected)) return .{ .failed = "bad websocket handshake" };
        // Drop the head; keep any frame bytes that followed it.
        std.mem.copyForwards(u8, buf.items[0 .. buf.items.len - head_end], buf.items[head_end..]);
        buf.shrinkRetainingCapacity(buf.items.len - head_end);

        c.last_rx_ms.store(watchdog.nowMs(c.io), .release);
        c.last_ping_ms.store(0, .release);
        c.wd.extend(idle_timeout_ms);
        c.write_mutex.lockUncancelable(c.io);
        c.conn = conn;
        c.write_mutex.unlock(c.io);
        defer {
            c.write_mutex.lockUncancelable(c.io);
            c.conn = null;
            c.write_mutex.unlock(c.io);
        }
        c.last_logged = null;
        c.setStatus(.connected, "", .{});
        c.shared.mutex.lockUncancelable(c.io);
        c.shared.exit_code = null;
        c.shared.mutex.unlock(c.io);

        while (true) {
            // Drain complete frames.
            while (true) {
                const frame = ws.parseServerFrame(buf.items, max_frame_payload) catch |err| {
                    return .{ .failed = @errorName(err) };
                } orelse break;
                if (c.handleFrame(frame, backoff)) |r| return r;
                const used = frame.len;
                std.mem.copyForwards(u8, buf.items[0 .. buf.items.len - used], buf.items[used..]);
                buf.shrinkRetainingCapacity(buf.items.len - used);
            }
            if (buf.items.len > max_frame_payload + 16) return .{ .failed = "frame too large" };
            if (!c.readMore(conn, &buf)) return .{ .failed = "connection lost" };
        }
    }

    /// Reads into `buf`; any data from the server moves the idle deadline.
    fn readMore(c: *Client, conn: *tlsconn.Conn, buf: *std.ArrayList(u8)) bool {
        buf.ensureUnusedCapacity(c.gpa, 32 * 1024) catch return false;
        const spare = buf.unusedCapacitySlice();
        const n = conn.read(spare) catch return false;
        if (n == 0) return false;
        buf.items.len += n;
        c.last_rx_ms.store(watchdog.nowMs(c.io), .release);
        c.wd.extend(idle_timeout_ms);
        return true;
    }

    const Msg = struct {
        t: []const u8 = "",
        input: ?[]const u8 = null,
        code: ?i64 = null,
    };

    fn handleFrame(c: *Client, frame: ws.Frame, backoff: *i64) ?StreamResult {
        switch (frame.opcode) {
            .binary => {
                if (frame.payload.len == 0 or frame.payload[0] != 'G') return null; // unknown: ignore
                c.shared.mutex.lockUncancelable(c.io);
                const r = gframe.apply(&c.shared.grid, c.gpa, frame.payload);
                c.shared.mutex.unlock(c.io);
                r catch |err| return .{ .failed = @errorName(err) }; // reconnect for a fresh snapshot
                c.notify();
            },
            .text => {
                if (frame.payload.len > 4096) return null;
                const parsed = std.json.parseFromSlice(Msg, c.gpa, frame.payload, .{ .ignore_unknown_fields = true }) catch return null;
                defer parsed.deinit();
                const m = parsed.value;
                if (std.mem.eql(u8, m.t, "hello")) {
                    c.shared.mutex.lockUncancelable(c.io);
                    c.shared.mode = keys.Mode.parse(m.input orelse "none");
                    c.shared.mutex.unlock(c.io);
                    backoff.* = 1000;
                    c.notify();
                } else if (std.mem.eql(u8, m.t, "exit")) {
                    return .{ .exited = m.code orelse 0 };
                } else if (std.mem.eql(u8, m.t, "logout")) {
                    return .logout;
                }
            },
            .ping => c.sendFrame(.pong, frame.payload) catch {},
            .close => {
                c.sendFrame(.close, "") catch {};
                return .{ .failed = "server closed the stream" };
            },
            else => {},
        }
        return null;
    }

    /// Callable from any thread. Inside the watchdog's task, a cancelation
    /// that lands here is re-armed so that the next read sees it.
    fn sendFrame(c: *Client, opcode: ws.Opcode, payload: []const u8) !void {
        if (payload.len > ws.max_client_payload) return error.TooLarge;
        var mask: [4]u8 = undefined;
        c.io.randomSecure(&mask) catch |err| {
            if (err == error.Canceled) c.io.recancel();
            return err;
        };
        var out: [ws.max_client_payload + 16]u8 = undefined;
        const frame = try ws.encodeClientFrame(&out, opcode, payload, mask);
        c.write_mutex.lockUncancelable(c.io);
        defer c.write_mutex.unlock(c.io);
        const conn = c.conn orelse return error.NotConnected;
        conn.writeAll(frame) catch |err| {
            if (err == error.Canceled) c.io.recancel();
            return err;
        };
    }

    /// Sends an input frame ("k:..." or "t:..."); callable from the UI thread.
    pub fn sendInput(c: *Client, text: []const u8) bool {
        c.sendFrame(.text, text) catch return false;
        return true;
    }

    pub fn requestPairing(c: *Client) void {
        c.shared.pair_requested.store(true, .release);
    }
};

/// "10.8.0.1:8420" -> "10.8.0.1", "[fd00::1]:8420" -> "fd00::1".
pub fn bareIp(canonical_host: []const u8) []const u8 {
    if (canonical_host.len > 0 and canonical_host[0] == '[') {
        const close = std.mem.indexOfScalar(u8, canonical_host, ']') orelse return canonical_host;
        return canonical_host[1..close];
    }
    const colon = std.mem.lastIndexOfScalar(u8, canonical_host, ':') orelse return canonical_host;
    return canonical_host[0..colon];
}

/// Downloads the CA certificate from the pairing-time download listener
/// (plain HTTP on the server port + 1, `/ca.cer`) into `out`. This channel
/// is not authenticated: the caller must compare the certificate's
/// fingerprint with one the user read on the desktop before trusting it.
pub fn fetchCaCertificate(gpa: std.mem.Allocator, io: Io, server: []const u8, out: *[x509check.max_cert_len]u8) anyerror![]const u8 {
    var host_buf: [64]u8 = undefined;
    const h = try http.canonicalHost(server, &host_buf);
    var addr = net.IpAddress.parseLiteral(h) catch return error.BadServerAddress;
    if (addr.getPort() == 65535) return error.BadServerAddress;
    addr.setPort(addr.getPort() + 1);
    var dl_host_buf: [64]u8 = undefined;
    const dl_host = std.fmt.bufPrint(&dl_host_buf, "{f}", .{addr}) catch return error.BadServerAddress;
    var wd: watchdog.Watchdog = .{ .io = io };
    wd.extend(connect_timeout_ms);
    const r = wd.run(fetchTask, .{ gpa, io, addr, dl_host, &wd, out }, null);
    if (wd.expired.load(.acquire)) return error.TimedOut;
    return r;
}

fn fetchTask(gpa: std.mem.Allocator, io: Io, addr: net.IpAddress, host_: []const u8, wd: *watchdog.Watchdog, out: *[x509check.max_cert_len]u8) anyerror![]const u8 {
    const conn = try tlsconn.Conn.open(gpa, io, addr, .plain);
    defer conn.close(gpa);
    wd.extend(request_timeout_ms);
    var req_buf: [256]u8 = undefined;
    var rw: Io.Writer = .fixed(&req_buf);
    try http.writeCaRequest(&rw, host_);
    try conn.writeAll(rw.buffered());
    var buf: [http.max_head_bytes + x509check.max_cert_len]u8 = undefined;
    var len: usize = 0;
    var head_end: ?usize = null;
    var want: usize = 0;
    while (true) {
        if (head_end) |e| if (len - e >= want) {
            @memcpy(out[0..want], buf[e..][0..want]);
            return out[0..want];
        };
        if (len == buf.len) return error.ResponseTooLarge;
        const n = try conn.read(buf[len..]);
        if (n == 0) return error.ConnectionClosed;
        len += n;
        if (head_end == null) if (http.findHeadEnd(buf[0..len])) |e| {
            const resp = try http.parseResponseHead(buf[0..e]);
            if (resp.status != 200) return error.CaDownloadRefused;
            want = resp.content_length orelse return error.CaDownloadRefused;
            if (want == 0 or want > out.len) return error.ResponseTooLarge;
            head_end = e;
        };
    }
}

test "bare IP" {
    try std.testing.expectEqualStrings("10.8.0.1", bareIp("10.8.0.1:8420"));
    try std.testing.expectEqualStrings("fd00::1", bareIp("[fd00::1]:8420"));
}
