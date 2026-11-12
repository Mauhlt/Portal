//! HTTP + WebSocket front end.
//!
//! Request pipeline (every request):
//!   1. Host header must be on the allowlist        (DNS rebinding)
//!   2. Framing checks (no Transfer-Encoding, Expect, GET bodies, unknown
//!      methods); any problem closes the connection
//!   3. Route; unknown paths/methods are rejected
//!   4. State-changing requests and the WebSocket upgrade require an
//!      allowed Origin                              (CSRF / CSWSH)
//!   5. Anything beyond the pairing page and static assets requires a live
//!      session cookie
//!
//! The web side can only (a) watch the session's output and (b) send
//! keystrokes that pass the input filter into that same session. There is no
//! route that starts a process, changes directory, or touches files.
//!
//! Connection model. Every accepted connection gets a supervisor thread and
//! a worker task (`io.concurrent`). The worker does all socket I/O; the
//! supervisor enforces deadlines (head/body read, keep-alive idle, stuck
//! sends), evictions and session revocation by cancelling the worker, which
//! makes a blocked recv/send return error.Canceled. Sockets are only closed
//! once nothing is blocked on them: on Windows, closing a socket another
//! thread is blocked on hits `unreachable` inside std, and shutdown() does
//! not unblock a pending recv.
//!
//! TLS. By default every connection is HTTPS: the worker first runs the
//! TLS 1.3 handshake (src/tls/server.zig), then speaks HTTP/1.1 and
//! WebSocket (wss) through the TLS connection. The handshake runs under the
//! same deadline as the first request head, and a cancelled read or write
//! in the middle of a record simply ends the connection.
//!
//! HTTP parsing is src/http1.zig, never std.http.Server (which had remotely
//! reachable panics). Any panic on any thread kills the user's live session,
//! so nothing here may assert, unwrap or overflow on peer-controlled data.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;

const auth = @import("auth.zig");
const guard = @import("guard.zig");
const http1 = @import("http1.zig");
const Session = @import("session.zig").Session;
const Log = @import("log.zig").Log;
const devices = @import("devices.zig");
const tls = @import("tls/server.zig");

const index_html = @embedFile("web/index.html");
const pair_html = @embedFile("web/pair.html");
const app_js = @embedFile("web/app.js");
const app_css = @embedFile("web/app.css");
/// The browser client (src/wasm), built by build.zig for wasm32-freestanding
/// with the bundled font inside it.
const app_wasm = @embedFile("app_wasm");

/// Hard cap on simultaneous connections (each costs a supervisor thread and
/// a worker thread, a WebSocket one more).
const max_connections = 32;
/// Connections that have not yet presented a live session cookie. The
/// difference to `max_connections` is reserved for signed-in browsers.
const max_pre_auth = 16;
const max_pre_auth_per_ip = 8;

const max_requests_per_connection = 200;
const max_body = 512;
const max_input_message = 4096;
/// 'i' prefix + up to max_input_message bytes of keystrokes.
const max_ws_payload = max_input_message + 1;
/// Largest client frame header: 2 + 8 (64-bit length) + 4 (mask).
const max_ws_header = 14;

/// Minimum gap between grid frames to one viewer (~30 per second).
const frame_interval_ms = 33;
const auth_recheck_ms = 5000;
/// A request head (and body) must arrive within this long of its first byte,
/// or of the connection being accepted.
const head_timeout_ms = 10_000;
/// Keep-alive connection waiting for its next request.
const idle_timeout_ms = 60_000;
/// Any single response or WebSocket message must be accepted by the peer
/// within this long.
const send_timeout_ms = 30_000;
/// After the supervisor sees a WebSocket's auth session gone, the writer has
/// this long to notice and say goodbye before the connection is cancelled.
const revoke_grace_ms = 10_000;
const supervise_tick_ms = 500;
const no_deadline = std.math.maxInt(i64);

pub const Config = struct {
    /// Exact Host header values accepted, e.g. "10.8.0.1:8420".
    allowed_hosts: []const []const u8,
    /// "https" with TLS (the default); "http" only with --no-tls.
    scheme: []const u8,
    /// Adds `Secure` and uses the `__Host-` cookie prefix. Only valid over HTTPS.
    secure_cookie: bool,
    /// Where the paired-device store lives (%LOCALAPPDATA%\Portal).
    devices: devices.Paths,
    /// Serve HTTPS with these credentials; null means plain HTTP.
    tls: ?*const tls.Credentials = null,
    /// Set only on the plain-HTTP listener that runs while a pairing window
    /// is open: it serves nothing but the CA certificate downloads.
    ca_download: ?*const CaDownload = null,
};

/// What the pairing-time certificate download listener serves.
pub const CaDownload = struct {
    cer: []const u8,
    mobileconfig: []const u8,
    /// "AB:CD:..." SHA-256 of the CA certificate.
    fingerprint: []const u8,
    /// Port of the HTTPS server, for the link to /pair.
    https_port: u16,
};

// ------------------------------------------------------------ pure helpers

/// Peer address without the port; IPv4 is stored v4-mapped.
pub const IpKey = [16]u8;

pub fn ipKey(addr: net.IpAddress) IpKey {
    var k: IpKey = @splat(0);
    switch (addr) {
        .ip4 => |a| {
            k[10] = 0xff;
            k[11] = 0xff;
            @memcpy(k[12..16], &a.bytes);
        },
        .ip6 => |a| k = a.bytes,
    }
    return k;
}

/// Connection slot bookkeeping. Pure: the caller holds a mutex and supplies
/// time. Pre-auth connections over their limits evict the oldest pre-auth
/// connection (from the same address first), so idle or slow connections
/// cannot lock a real user out; signed-in connections are never evicted.
pub const ConnTable = struct {
    pub const Entry = struct {
        used: bool = false,
        key: IpKey = @splat(0),
        authed: bool = false,
        evicted: bool = false,
        since_ms: i64 = 0,
    };

    pub const Admission = struct {
        /// Slot for the new connection, or null to refuse it.
        slot: ?usize,
        /// An existing connection that must now be torn down.
        victim: ?usize,
    };

    entries: [max_connections]Entry = @splat(.{}),
    max_pre_auth: usize = max_pre_auth,
    max_pre_auth_per_ip: usize = max_pre_auth_per_ip,

    fn isPreAuth(e: Entry) bool {
        return e.used and !e.authed and !e.evicted;
    }

    fn oldestPreAuth(t: *const ConnTable, key: ?IpKey) ?usize {
        var best: ?usize = null;
        var best_ms: i64 = no_deadline;
        for (t.entries, 0..) |e, i| {
            if (!isPreAuth(e)) continue;
            if (key) |k| if (!std.mem.eql(u8, &k, &e.key)) continue;
            if (best == null or e.since_ms < best_ms) {
                best = i;
                best_ms = e.since_ms;
            }
        }
        return best;
    }

    pub fn admit(t: *ConnTable, key: IpKey, now_ms: i64) Admission {
        var free: ?usize = null;
        var pre_total: usize = 0;
        var pre_ip: usize = 0;
        for (t.entries, 0..) |e, i| {
            if (!e.used) {
                if (free == null) free = i;
                continue;
            }
            if (isPreAuth(e)) {
                pre_total += 1;
                if (std.mem.eql(u8, &key, &e.key)) pre_ip += 1;
            }
        }
        var victim: ?usize = null;
        if (pre_ip >= t.max_pre_auth_per_ip) {
            victim = t.oldestPreAuth(key);
        } else if (pre_total >= t.max_pre_auth or free == null) {
            victim = t.oldestPreAuth(null);
        }
        if (victim) |v| t.entries[v].evicted = true;
        const slot = free orelse return .{ .slot = null, .victim = victim };
        t.entries[slot] = .{ .used = true, .key = key, .since_ms = now_ms };
        return .{ .slot = slot, .victim = victim };
    }

    pub fn promote(t: *ConnTable, slot: usize) void {
        if (slot < t.entries.len) t.entries[slot].authed = true;
    }

    pub fn release(t: *ConnTable, slot: usize) void {
        if (slot < t.entries.len) t.entries[slot] = .{};
    }
};

/// "Log at most once per interval, and say how many were suppressed."
pub const LogLimiter = struct {
    last_ms: i64 = std.math.minInt(i64),
    suppressed: u32 = 0,

    /// Returns the number of suppressed events if this one should be logged.
    pub fn check(l: *LogLimiter, now_ms: i64, interval_ms: i64) ?u32 {
        if (now_ms -| l.last_ms >= interval_ms) {
            const n = l.suppressed;
            l.suppressed = 0;
            l.last_ms = now_ms;
            return n;
        }
        l.suppressed +|= 1;
        return null;
    }
};

/// Exponential backoff for the accept loop: 100 ms doubling to 5 s.
pub const Backoff = struct {
    cur_ms: i64 = 0,
    pub const min_ms = 100;
    pub const max_ms = 5000;

    pub fn next(b: *Backoff) i64 {
        b.cur_ms = if (b.cur_ms <= 0) min_ms else @min(b.cur_ms *| 2, max_ms);
        return b.cur_ms;
    }

    pub fn reset(b: *Backoff) void {
        b.cur_ms = 0;
    }
};

// ------------------------------------------------------------------ server

/// Per-connection state shared by the supervisor thread and the worker task.
const Conn = struct {
    stream: net.Stream,
    slot: usize,
    peer_buf: [64]u8 = undefined,
    peer_len: usize = 0,
    /// Monotonic ms after which the supervisor cancels the worker.
    deadline_ms: std.atomic.Value(i64),
    done: std.atomic.Value(bool) = .init(false),
    /// Set (release) once `ws_cookie` is filled in, for revocation checks.
    ws_active: std.atomic.Value(bool) = .init(false),
    ws_cookie: [auth.encoded_len]u8 = undefined,
    /// Worker-only: already promoted to an authenticated slot.
    authed: bool = false,
    /// Set once the TLS handshake is done (HTTPS connections only).
    tls: ?*tls.Connection = null,

    fn peer(c: *const Conn) []const u8 {
        return c.peer_buf[0..c.peer_len];
    }

    fn setDeadline(c: *Conn, ms: i64) void {
        c.deadline_ms.store(ms, .release);
    }
};

pub const Server = struct {
    gpa: Allocator,
    io: Io,
    cfg: Config,
    session: *Session,
    log: *Log,
    listener: net.Server,

    auth_mutex: Io.Mutex = .init,
    sessions: auth.Sessions = .{},

    conn_mutex: Io.Mutex = .init,
    conns: ConnTable = .{},
    conn_wake: [max_connections]Io.Event = @splat(.unset),
    conn_evict: [max_connections]std.atomic.Value(bool) = @splat(.init(false)),

    note_mutex: Io.Mutex = .init,
    host_reject_log: LogLimiter = .{},
    tls_fail_log: LogLimiter = .{},

    /// Makes `run` return (the pairing-time download listener is stopped
    /// this way, together with cancelling its accept).
    stop: std.atomic.Value(bool) = .init(false),

    fn cookieName(srv: *const Server) []const u8 {
        return if (srv.cfg.secure_cookie) "__Host-portal" else "portal_session";
    }

    fn deviceCookieName(srv: *const Server) []const u8 {
        return if (srv.cfg.secure_cookie) "__Host-portal_device" else "portal_device";
    }

    fn nowUnix(srv: *const Server) i64 {
        return Io.Timestamp.now(srv.io, .real).toSeconds();
    }

    fn nowMs(srv: *const Server) i64 {
        return Io.Timestamp.now(srv.io, .awake).toMilliseconds();
    }

    pub fn sessionLive(srv: *Server, cookie: []const u8, refresh: bool) bool {
        srv.auth_mutex.lockUncancelable(srv.io);
        defer srv.auth_mutex.unlock(srv.io);
        const now = srv.nowMs();
        return if (refresh) srv.sessions.validate(cookie, now) else srv.sessions.isLive(cookie, now);
    }

    /// Accept loop. Runs on its own thread for the life of the process.
    pub fn run(srv: *Server) void {
        var backoff: Backoff = .{};
        var accept_log: LogLimiter = .{};
        var full_log: LogLimiter = .{};
        while (!srv.stop.load(.acquire)) {
            const stream = srv.listener.accept(srv.io) catch |err| {
                if (err == error.Canceled or srv.stop.load(.acquire)) return;
                if (accept_log.check(srv.nowMs(), std.time.ms_per_min)) |n|
                    srv.log.print("accept error: {t} ({d} more since last report)", .{ err, n });
                srv.io.sleep(.fromMilliseconds(backoff.next()), .awake) catch {};
                continue;
            };
            backoff.reset();
            srv.admit(stream, &full_log);
        }
    }

    fn admit(srv: *Server, stream: net.Stream, full_log: *LogLimiter) void {
        const io = srv.io;
        const now = srv.nowMs();
        srv.conn_mutex.lockUncancelable(io);
        const adm = srv.conns.admit(ipKey(stream.socket.address), now);
        if (adm.victim) |v| {
            srv.conn_evict[v].store(true, .release);
            srv.conn_wake[v].set(io);
        }
        if (adm.slot) |s| {
            // The previous occupant's supervisor has fully exited.
            srv.conn_evict[s].store(false, .release);
            srv.conn_wake[s].reset();
        }
        srv.conn_mutex.unlock(io);

        const slot = adm.slot orelse {
            if (full_log.check(now, 10_000)) |n|
                srv.log.print("connection refused: {d} connections open ({d} more refusals since last report)", .{ max_connections, n });
            stream.close(io); // nothing else has seen this socket
            return;
        };
        const t = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, supervise, .{ srv, stream, slot }) catch {
            srv.releaseSlot(slot);
            stream.close(io);
            return;
        };
        t.detach();
    }

    fn releaseSlot(srv: *Server, slot: usize) void {
        srv.conn_mutex.lockUncancelable(srv.io);
        srv.conns.release(slot);
        srv.conn_mutex.unlock(srv.io);
    }

    fn promote(srv: *Server, conn: *Conn) void {
        if (conn.authed) return;
        conn.authed = true;
        srv.conn_mutex.lockUncancelable(srv.io);
        srv.conns.promote(conn.slot);
        srv.conn_mutex.unlock(srv.io);
    }

    /// Supervisor thread: owns the socket, runs the worker, enforces deadlines.
    fn supervise(srv: *Server, stream: net.Stream, slot: usize) void {
        const io = srv.io;
        defer srv.releaseSlot(slot);
        // Safe: the worker has finished (cancel/await below) before this runs.
        defer stream.close(io);

        var conn: Conn = .{
            .stream = stream,
            .slot = slot,
            .deadline_ms = .init(srv.nowMs() +| head_timeout_ms),
        };
        const peer = std.fmt.bufPrint(&conn.peer_buf, "{f}", .{stream.socket.address}) catch blk: {
            conn.peer_buf[0] = '?';
            break :blk conn.peer_buf[0..1];
        };
        conn.peer_len = peer.len;

        var worker = io.concurrent(connMain, .{ srv, &conn }) catch {
            srv.log.print("connection from {s} dropped: no thread available", .{conn.peer()});
            return;
        };

        var reason: ?[]const u8 = null;
        var last_auth = srv.nowMs();
        var revoked_since: ?i64 = null;
        while (!conn.done.load(.acquire)) {
            srv.conn_wake[slot].waitTimeout(io, .{ .duration = .{
                .raw = .fromMilliseconds(supervise_tick_ms),
                .clock = .awake,
            } }) catch {};
            if (conn.done.load(.acquire)) break;
            if (srv.conn_evict[slot].load(.acquire)) {
                reason = "evicted (too many unauthenticated connections)";
                break;
            }
            const now = srv.nowMs();
            if (now >= conn.deadline_ms.load(.acquire)) {
                reason = "timed out";
                break;
            }
            if (conn.ws_active.load(.acquire) and now -| last_auth >= auth_recheck_ms) {
                last_auth = now;
                if (srv.sessionLive(&conn.ws_cookie, false)) {
                    revoked_since = null;
                } else if (revoked_since == null) {
                    revoked_since = now;
                }
            }
            if (revoked_since) |r| {
                if (now -| r >= revoke_grace_ms) {
                    reason = "signed out";
                    break;
                }
            }
        }
        // Interrupts any blocked recv/send in the worker (error.Canceled),
        // then waits for it to finish. A no-op wait if it already finished.
        worker.cancel(io);
        if (reason) |r| {
            if (conn.ws_active.load(.acquire)) srv.log.print("websocket from {s} cancelled: {s}", .{ conn.peer(), r });
        }
    }

    fn connMain(srv: *Server, conn: *Conn) void {
        defer {
            conn.done.store(true, .release);
            srv.conn_wake[conn.slot].set(srv.io);
        }
        if (srv.cfg.tls) |creds| return srv.serveTls(conn, creds);
        var send_buf: [16 * 1024]u8 = undefined;
        var sw = conn.stream.writer(srv.io, &send_buf);
        srv.serveHttp(conn, &sw.interface) catch {};
    }

    /// Socket buffers and state for one HTTPS connection (heap, ~100 KiB).
    const TlsConn = struct {
        tls: tls.Connection,
        in: [tls.min_input_buffer]u8,
        out: [tls.min_output_buffer]u8,
        plain_out: [16 * 1024]u8,
    };

    fn serveTls(srv: *Server, conn: *Conn, creds: *const tls.Credentials) void {
        const io = srv.io;
        const st = srv.gpa.create(TlsConn) catch return;
        defer srv.gpa.destroy(st);
        var sr = conn.stream.reader(io, &st.in);
        var sw = conn.stream.writer(io, &st.out);
        var entropy: [tls.entropy_len]u8 = undefined;
        io.randomSecure(&entropy) catch return;
        defer std.crypto.secureZero(u8, &entropy);
        defer st.tls.wipe();
        st.tls.handshake(&sr.interface, &sw.interface, .{
            .credentials = creds,
            .entropy = &entropy,
            .read_buffer = &.{},
            .write_buffer = &st.plain_out,
        }) catch |err| {
            srv.noteTlsFailure(conn, err, st.tls.diag, &sw.interface);
            return;
        };
        conn.tls = &st.tls;
        srv.serveHttp(conn, &st.tls.writer) catch return;
        // Clean end (peer closed, Connection: close, request limit): send
        // close_notify, bounded by a short deadline in case the peer stalls.
        conn.setDeadline(srv.nowMs() +| 5000);
        st.tls.close();
    }

    fn noteTlsFailure(srv: *Server, conn: *Conn, err: tls.Error, diag: tls.Diagnostics, raw: *Io.Writer) void {
        if (diag.http_on_tls) {
            // A browser asked for http:// on the HTTPS port: say so.
            conn.setDeadline(srv.nowMs() +| 5000);
            http1.writeResponse(raw, .bad_request, &.{
                .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
                .{ .name = "x-content-type-options", .value = "nosniff" },
            }, "This Portal port speaks HTTPS: use https:// in the address.\n", false) catch {};
            return;
        }
        switch (err) {
            // Peer went away, or the deadline cancelled us: not worth a line.
            error.EndOfStream, error.ReadFailed, error.WriteFailed => return,
            else => {},
        }
        srv.note_mutex.lockUncancelable(srv.io);
        const n = srv.tls_fail_log.check(srv.nowMs(), 10_000);
        srv.note_mutex.unlock(srv.io);
        const suppressed = n orelse return;
        var abuf: [64]u8 = undefined;
        // Never `{t}` a peer-supplied alert: it may have no name.
        const alert: []const u8 = if (diag.received_alert) |a|
            std.fmt.bufPrint(&abuf, ", client alert {s} ({d})", .{ tls.alertName(a), @backingInt(a) }) catch ""
        else if (diag.sent_alert) |a|
            std.fmt.bufPrint(&abuf, ", sent alert {s}", .{tls.alertName(a)}) catch ""
        else
            "";
        const hint: []const u8 = if (diag.received_alert) |a| switch (a) {
            .bad_certificate, .unknown_ca, .certificate_unknown, .access_denied => " - that device does not trust the Portal CA yet (see `portal ca export`)",
            else => "",
        } else "";
        srv.log.print("TLS handshake with {s} failed: {t}{s}{s} ({d} more since last report)", .{
            conn.peer(), err, alert, hint, suppressed,
        });
    }

    fn readSome(conn: *Conn, io: Io, dest: []u8) !usize {
        if (dest.len == 0) return error.NoBufferSpace;
        if (conn.tls) |t| return t.readSome(dest);
        var iov = [_][]u8{dest};
        const r = try conn.stream.readWithControl(io, &iov, &.{});
        return r.data_len;
    }

    fn serveHttp(srv: *Server, conn: *Conn, w: *Io.Writer) !void {
        const io = srv.io;
        // Head (up to max_head_bytes) plus a login body.
        var buf: [http1.max_head_bytes + max_body]u8 = undefined;
        var len: usize = 0;

        var n: u32 = 0;
        while (n < max_requests_per_connection) : (n += 1) {
            // First request on a connection, or bytes of the next one already
            // buffered (pipelining): head timeout. Otherwise keep-alive idle.
            if (n == 0 or len > 0) {
                if (n > 0) conn.setDeadline(srv.nowMs() +| head_timeout_ms);
            } else {
                conn.setDeadline(srv.nowMs() +| idle_timeout_ms);
            }

            const head_len: usize = while (true) {
                if (http1.findHeadEnd(buf[0..len])) |e| break e;
                if (len >= http1.max_head_bytes) {
                    _ = try srv.fail(conn, w, .header_fields_too_large, "headers too large\n");
                    return;
                }
                const was_empty = len == 0;
                const got = try readSome(conn, io, buf[len..http1.max_head_bytes]);
                if (got == 0) return; // peer closed
                if (was_empty and n > 0) conn.setDeadline(srv.nowMs() +| head_timeout_ms);
                len += got;
            };
            if (head_len > http1.max_head_bytes) {
                _ = try srv.fail(conn, w, .header_fields_too_large, "headers too large\n");
                return;
            }

            const req = http1.parseHead(buf[0..head_len]) catch {
                _ = try srv.fail(conn, w, .bad_request, "bad request\n");
                return;
            };

            var body: []const u8 = "";
            if (req.method == .POST) {
                if (req.has_transfer_encoding or req.has_expect) {
                    // Answered by framingError below, without reading a body.
                } else if (req.content_length) |cl_u64| {
                    if (cl_u64 <= max_body) {
                        const need = head_len + @as(usize, @intCast(cl_u64));
                        while (len < need) {
                            const got = try readSome(conn, io, buf[len..need]);
                            if (got == 0) return;
                            len += got;
                        }
                        body = buf[head_len..need];
                    }
                }
            }

            const keep = try srv.handleRequest(conn, w, &req, body, buf[head_len..len]);
            if (!keep or req.connection_close or req.method != .GET) return;

            // Keep any pipelined bytes of the next request.
            const rest = len - head_len;
            std.mem.copyForwards(u8, buf[0..rest], buf[head_len..len]);
            len = rest;
        }
    }

    const device_cookie_max = devices.max_name + 1 + auth.encoded_len;

    const Headers = struct {
        host: ?[]const u8 = null,
        origin: ?[]const u8 = null,
        cookie: ?[]const u8 = null,
        /// `<name>.<secret>` from the paired-device cookie.
        device: ?[]const u8 = null,
        content_type: ?[]const u8 = null,
    };

    fn collectHeaders(srv: *const Server, req: *const http1.Request, cookie_out: *[auth.encoded_len]u8, device_out: *[device_cookie_max]u8) Headers {
        var h: Headers = .{ .host = req.host, .origin = req.origin, .content_type = req.content_type };
        var dit = req.cookieHeaders();
        while (dit.next()) |value| {
            if (guard.getCookie(value, srv.deviceCookieName())) |v| {
                if (v.len > 0 and v.len <= device_cookie_max) {
                    @memcpy(device_out[0..v.len], v);
                    h.device = device_out[0..v.len];
                    break;
                }
            }
        }
        var it = req.cookieHeaders();
        while (it.next()) |value| {
            if (guard.getCookie(value, srv.cookieName())) |v| {
                if (v.len == auth.encoded_len) {
                    @memcpy(cookie_out, v);
                    h.cookie = cookie_out;
                    break;
                }
            }
        }
        return h;
    }

    fn noteHostRejected(srv: *Server, peer: []const u8, host: ?[]const u8) void {
        srv.note_mutex.lockUncancelable(srv.io);
        const n = srv.host_reject_log.check(srv.nowMs(), 10_000);
        srv.note_mutex.unlock(srv.io);
        const suppressed = n orelse return;
        const h = host orelse "(none)";
        srv.log.print("rejected request from {s}: Host '{s}' not allowed ({d} more since last report)", .{
            peer, h[0..@min(h.len, 80)], suppressed,
        });
    }

    /// Returns whether to keep the connection open for another request.
    fn handleRequest(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, body: []const u8, leftover: []const u8) !bool {
        _ = body; // no route reads a request body any more (pairing posts are empty)
        var cookie_buf: [auth.encoded_len]u8 = undefined;
        var device_buf: [device_cookie_max]u8 = undefined;
        const h = srv.collectHeaders(req, &cookie_buf, &device_buf);
        const peer = conn.peer();

        if (!guard.hostAllowed(h.host, srv.cfg.allowed_hosts)) {
            srv.noteHostRejected(peer, h.host);
            return srv.fail(conn, w, .misdirected_request, "unknown host\n");
        }
        if (http1.framingError(req, max_body)) |r| return srv.fail(conn, w, r.status, r.msg);
        if (srv.cfg.ca_download) |d| return srv.caDownload(conn, w, req, d);

        if (!conn.authed) {
            if (h.cookie) |c| {
                if (srv.sessionLive(c, false)) srv.promote(conn);
            }
        }

        const path = req.path;
        switch (req.method) {
            .GET => {
                if (std.mem.eql(u8, path, "/static/app.js")) return srv.asset(conn, w, req, app_js, "text/javascript; charset=utf-8");
                if (std.mem.eql(u8, path, "/static/app.css")) return srv.asset(conn, w, req, app_css, "text/css; charset=utf-8");
                if (std.mem.eql(u8, path, "/static/app.wasm")) return srv.asset(conn, w, req, app_wasm, "application/wasm");
                if (std.mem.eql(u8, path, "/pair")) return srv.pairPage(conn, w, req);
                if (std.mem.eql(u8, path, "/login")) return srv.redirect(conn, w, req, "/pair", &.{});
                if (std.mem.eql(u8, path, "/")) {
                    if (h.cookie) |c| if (srv.sessionLive(c, true)) return srv.asset(conn, w, req, index_html, "text/html; charset=utf-8");
                    // No live session (first visit, or Portal restarted): a
                    // paired device signs in silently with its credential.
                    if (h.device) |d| return srv.deviceSignIn(conn, w, req, d, .page);
                    return srv.redirect(conn, w, req, "/pair", &.{});
                }
                if (std.mem.eql(u8, path, "/ws")) {
                    try srv.webSocket(conn, w, req, h, leftover);
                    return false;
                }
            },
            .POST => {
                if (!guard.originAllowed(h.origin, srv.cfg.scheme, srv.cfg.allowed_hosts)) {
                    srv.log.print("rejected {s} from {s}: bad origin", .{ path[0..@min(path.len, 80)], peer });
                    return srv.fail(conn, w, .forbidden, "bad origin\n");
                }
                if (std.mem.eql(u8, path, "/pair")) return srv.pairDevice(conn, w, req);
                if (std.mem.eql(u8, path, "/auth/refresh")) {
                    const d = h.device orelse return srv.fail(conn, w, .unauthorized, "not paired\n");
                    return srv.deviceSignIn(conn, w, req, d, .api);
                }
                if (std.mem.eql(u8, path, "/logout")) return srv.logout(conn, w, req, h);
            },
            .other => return srv.fail(conn, w, .method_not_allowed, "method not allowed\n"),
        }
        return srv.fail(conn, w, .not_found, "not found\n");
    }

    // ---------------------------------------------------------- responses

    // 'wasm-unsafe-eval': with any CSP set, browsers (Safari, Chrome, Firefox)
    // refuse WebAssembly.instantiate unless script-src allows it. It permits
    // compiling WebAssembly only; it does not re-enable eval(), new Function()
    // or inline script, and scripts still load only from 'self'. The only
    // wasm the page ever loads is /static/app.wasm, compiled into this exe.
    const csp = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; " ++
        "connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; " ++
        "form-action 'self'; frame-ancestors 'none'";

    fn respond(srv: *Server, conn: *Conn, w: *Io.Writer, status: http1.Status, body: []const u8, content_type: []const u8, extra: []const http1.Header, keep_alive: bool) !void {
        var headers: [12]http1.Header = undefined;
        const common = [_]http1.Header{
            .{ .name = "content-type", .value = content_type },
            .{ .name = "content-security-policy", .value = csp },
            .{ .name = "x-content-type-options", .value = "nosniff" },
            .{ .name = "x-frame-options", .value = "DENY" },
            .{ .name = "referrer-policy", .value = "no-referrer" },
            .{ .name = "cross-origin-opener-policy", .value = "same-origin" },
            .{ .name = "cross-origin-resource-policy", .value = "same-origin" },
            .{ .name = "cache-control", .value = "no-store" },
        };
        if (common.len + extra.len > headers.len) return error.TooManyHeaders;
        @memcpy(headers[0..common.len], &common);
        @memcpy(headers[common.len..][0..extra.len], extra);
        conn.setDeadline(srv.nowMs() +| send_timeout_ms);
        try http1.writeResponse(w, status, headers[0 .. common.len + extra.len], body, keep_alive);
    }

    /// Error response; always closes the connection.
    fn fail(srv: *Server, conn: *Conn, w: *Io.Writer, status: http1.Status, body: []const u8) !bool {
        try srv.respond(conn, w, status, body, "text/plain; charset=utf-8", &.{}, false);
        return false;
    }

    fn asset(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, body: []const u8, content_type: []const u8) !bool {
        const keep = !req.connection_close;
        try srv.respond(conn, w, .ok, body, content_type, &.{}, keep);
        return keep;
    }

    fn redirect(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, location: []const u8, set_cookies: []const []const u8) !bool {
        var extra: [3]http1.Header = undefined;
        var n: usize = 0;
        extra[n] = .{ .name = "location", .value = location };
        n += 1;
        for (set_cookies[0..@min(set_cookies.len, 2)]) |c| {
            extra[n] = .{ .name = "set-cookie", .value = c };
            n += 1;
        }
        // Never reuse a connection after a POST.
        const keep = req.method == .GET and !req.connection_close;
        try srv.respond(conn, w, .see_other, "", "text/plain; charset=utf-8", extra[0..n], keep);
        return keep;
    }

    fn pairPage(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request) !bool {
        const q = req.query;
        var open_name: [devices.max_name]u8 = undefined;
        var open_len: usize = 0;
        const now = srv.nowUnix();
        const Ctx = struct { now: i64, name: *[devices.max_name]u8, len: *usize };
        devices.withStore(srv.gpa, srv.io, srv.cfg.devices, now, Ctx{ .now = now, .name = &open_name, .len = &open_len }, struct {
            fn op(c: Ctx, st: *devices.Store) !bool {
                if (st.pairingName(c.now)) |n| {
                    @memcpy(c.name[0..n.len], n);
                    c.len.* = n.len;
                }
                return false;
            }
        }.op) catch {};
        const msg: []const u8 = if (std.mem.eql(u8, q, "e=closed"))
            "<p class=\"error\">No pairing window is open. Run the command below at the desktop first.</p>"
        else if (std.mem.eql(u8, q, "e=revoked"))
            "<p class=\"error\">This device's credential was used from somewhere else, so it was revoked. Pair it again at the desktop.</p>"
        else if (std.mem.eql(u8, q, "e=address"))
            "<p class=\"error\">This device is paired from a different WireGuard address. Pair it again at the desktop.</p>"
        else if (std.mem.eql(u8, q, "bye"))
            "<p class=\"info\">This device was unpaired.</p>"
        else
            "";
        // The device name comes from the store and is [a-z0-9-] only
        // (devices.validName), so it is safe to place in HTML.
        var action_buf: [512]u8 = undefined;
        const action: []const u8 = if (open_len > 0)
            std.fmt.bufPrint(&action_buf, "<form method=\"post\" action=\"/pair\"><p>Pairing is open for <strong>{s}</strong>.</p>" ++
                "<button type=\"submit\">Pair this device</button></form>", .{open_name[0..open_len]}) catch ""
        else
            "<p>This device is not paired yet. At the desktop, run:</p><pre>portal pair &lt;name&gt;</pre>" ++
                "<p>then reload this page within 2 minutes.</p>";
        const marker_msg = "<!--MESSAGE-->";
        const marker_act = "<!--ACTION-->";
        const i_msg = comptime std.mem.indexOf(u8, pair_html, marker_msg).?;
        const i_act = comptime std.mem.indexOf(u8, pair_html, marker_act).?;
        comptime std.debug.assert(i_msg < i_act);
        const page = try std.mem.concat(srv.gpa, u8, &.{
            pair_html[0..i_msg],
            msg,
            pair_html[i_msg + marker_msg.len .. i_act],
            action,
            pair_html[i_act + marker_act.len ..],
        });
        defer srv.gpa.free(page);
        return srv.asset(conn, w, req, page, "text/html; charset=utf-8");
    }

    /// The pairing-time download listener (plain HTTP on port+1): the CA
    /// certificate as an Apple profile and as DER, plus a page linking them.
    fn caDownload(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, d: *const CaDownload) !bool {
        if (req.method != .GET) return srv.fail(conn, w, .method_not_allowed, "method not allowed\n");
        const path = req.path;
        if (std.mem.eql(u8, path, "/ca.mobileconfig") or std.mem.eql(u8, path, "/ca.cer")) {
            const profile = path[4] == 'm';
            srv.log.print("CA certificate downloaded by {s}: {s}", .{ conn.peer(), path });
            const extra = [_]http1.Header{.{
                .name = "content-disposition",
                .value = if (profile) "attachment; filename=\"portal-ca.mobileconfig\"" else "attachment; filename=\"portal-ca.cer\"",
            }};
            try srv.respond(conn, w, .ok, if (profile) d.mobileconfig else d.cer, if (profile) "application/x-apple-aspen-config" else "application/pkix-cert", &extra, false);
            return false;
        }
        if (!std.mem.eql(u8, path, "/")) return srv.fail(conn, w, .not_found, "not found\n");
        // Host passed the allowlist; keep only safe characters for the link.
        const host_full = req.host orelse "";
        const host = blk: {
            var end = host_full.len;
            if (std.mem.lastIndexOfScalar(u8, host_full, ':')) |c| {
                if (std.mem.indexOfScalar(u8, host_full[c..], ']') == null) end = c;
            }
            const h = host_full[0..end];
            for (h) |ch| switch (ch) {
                'a'...'z', 'A'...'Z', '0'...'9', '.', '-', ':', '[', ']' => {},
                else => break :blk "",
            };
            break :blk h;
        };
        var page_buf: [3072]u8 = undefined;
        const page = std.fmt.bufPrint(&page_buf,
            \\<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            \\<title>Portal certificate</title><style>body{{font-family:system-ui,sans-serif;max-width:36em;margin:2em auto;padding:0 1em;line-height:1.5}}a.b{{display:block;margin:1em 0;padding:.8em;border:1px solid #888;border-radius:.5em;text-align:center;text-decoration:none}}code{{word-break:break-all}}</style></head><body>
            \\<h1>Trust this desktop's Portal</h1>
            \\<p>Install the Portal certificate once per device, then continue to pairing over HTTPS.</p>
            \\<a class="b" href="/ca.mobileconfig">iPhone / iPad / Mac: install profile</a>
            \\<a class="b" href="/ca.cer">Other devices: certificate (.cer)</a>
            \\<p><b>iPhone / iPad:</b> after downloading, open Settings &gt; General &gt; VPN &amp; Device Management, install the "Portal Local CA" profile, then Settings &gt; General &gt; About &gt; Certificate Trust Settings and enable full trust for it.</p>
            \\<p>Check the fingerprint (SHA-256) matches what <code>portal ca export</code> prints on the desktop:<br><code>{s}</code></p>
            \\<a class="b" href="https://{s}:{d}/pair">Continue to pairing (HTTPS)</a>
            \\</body></html>
        , .{ d.fingerprint, host, d.https_port }) catch return srv.fail(conn, w, .internal_server_error, "page too large\n");
        try srv.respond(conn, w, .ok, page, "text/html; charset=utf-8", &.{}, false);
        return false;
    }

    fn newSecret(srv: *Server, out: *[auth.encoded_len]u8) !void {
        var raw: [auth.secret_bytes]u8 = undefined;
        try srv.io.randomSecure(&raw);
        _ = auth.encodeSecret(&raw, out);
        std.crypto.secureZero(u8, &raw);
    }

    const CookiePair = struct {
        device_buf: [256]u8 = undefined,
        session_buf: [192]u8 = undefined,
        device: []const u8 = "",
        session: []const u8 = "",
    };

    /// Builds Set-Cookie values for a device credential and a new session.
    fn issueCookies(srv: *Server, name: []const u8, device_secret: []const u8, out: *CookiePair) !void {
        var session_val: [auth.encoded_len]u8 = undefined;
        try srv.newSecret(&session_val);
        defer std.crypto.secureZero(u8, &session_val);
        srv.auth_mutex.lockUncancelable(srv.io);
        srv.sessions.createTagged(&session_val, srv.nowMs(), name);
        srv.auth_mutex.unlock(srv.io);
        const secure = if (srv.cfg.secure_cookie) "; Secure" else "";
        out.device = try std.fmt.bufPrint(&out.device_buf, "{s}={s}.{s}; Path=/; HttpOnly; SameSite=Strict; Max-Age={d}{s}", .{
            srv.deviceCookieName(), name, device_secret, devices.unused_expiry_s, secure,
        });
        out.session = try std.fmt.bufPrint(&out.session_buf, "{s}={s}; Path=/; HttpOnly; SameSite=Strict; Max-Age={d}{s}", .{
            srv.cookieName(), &session_val, @divTrunc(srv.sessions.absolute_timeout_ms, 1000), secure,
        });
    }

    fn clearCookies(srv: *Server, buf: *[2][128]u8) ![2][]const u8 {
        const secure = if (srv.cfg.secure_cookie) "; Secure" else "";
        return .{
            try std.fmt.bufPrint(&buf[0], "{s}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{s}", .{ srv.deviceCookieName(), secure }),
            try std.fmt.bufPrint(&buf[1], "{s}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{s}", .{ srv.cookieName(), secure }),
        };
    }

    /// POST /pair: consume an open pairing window for this device's address.
    fn pairDevice(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request) !bool {
        const peer = conn.peer();
        const ip = devices.ipOnly(peer);
        var secret: [auth.encoded_len]u8 = undefined;
        srv.newSecret(&secret) catch return srv.fail(conn, w, .internal_server_error, "no entropy\n");
        defer std.crypto.secureZero(u8, &secret);
        var name_buf: [devices.max_name]u8 = undefined;
        var name_len: usize = 0;
        const now = srv.nowUnix();
        const Ctx = struct { ip: []const u8, hash: auth.Hash, now: i64, name: *[devices.max_name]u8, len: *usize };
        devices.withStore(srv.gpa, srv.io, srv.cfg.devices, now, Ctx{
            .ip = ip,
            .hash = auth.hashSecret(&secret),
            .now = now,
            .name = &name_buf,
            .len = &name_len,
        }, struct {
            fn op(c: Ctx, st: *devices.Store) !bool {
                const n = st.completePair(c.ip, c.hash, c.now) catch return false;
                @memcpy(c.name[0..n.len], n);
                c.len.* = n.len;
                return true;
            }
        }.op) catch |err| {
            srv.log.print("pairing from {s} failed: {t}", .{ peer, err });
            return srv.fail(conn, w, .internal_server_error, "device store unavailable\n");
        };
        if (name_len == 0) {
            srv.log.print("pairing attempt from {s}: no window open", .{peer});
            return srv.redirect(conn, w, req, "/pair?e=closed", &.{});
        }
        const name = name_buf[0..name_len];
        srv.log.print("PAIRED device '{s}' at {s}", .{ name, ip });
        var cookies: CookiePair = .{};
        try srv.issueCookies(name, &secret, &cookies);
        return srv.redirect(conn, w, req, "/", &.{ cookies.device, cookies.session });
    }

    const SignInMode = enum { page, api };
    const SignInOutcome = enum { ok, wrong_address, revoked, unknown };

    /// A paired device presents its credential: verify it against the
    /// device's bound address, rotate it, and start a session. A stale or
    /// wrong secret revokes the device (see devices.zig).
    fn deviceSignIn(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, presented: []const u8, mode: SignInMode) !bool {
        const peer = conn.peer();
        const ip = devices.ipOnly(peer);
        var secret: [auth.encoded_len]u8 = undefined;
        srv.newSecret(&secret) catch return srv.fail(conn, w, .internal_server_error, "no entropy\n");
        defer std.crypto.secureZero(u8, &secret);

        var outcome: SignInOutcome = .unknown;
        var name_buf: [devices.max_name]u8 = undefined;
        var name_len: usize = 0;
        const now = srv.nowUnix();
        const Ctx = struct {
            presented: []const u8,
            ip: []const u8,
            hash: auth.Hash,
            now: i64,
            outcome: *SignInOutcome,
            name: *[devices.max_name]u8,
            len: *usize,
        };
        devices.withStore(srv.gpa, srv.io, srv.cfg.devices, now, Ctx{
            .presented = presented,
            .ip = ip,
            .hash = auth.hashSecret(&secret),
            .now = now,
            .outcome = &outcome,
            .name = &name_buf,
            .len = &name_len,
        }, struct {
            fn op(c: Ctx, st: *devices.Store) !bool {
                switch (st.authenticate(c.presented, c.ip, c.now)) {
                    .ok => |idx| {
                        const n = st.devices[idx].?.name.get();
                        @memcpy(c.name[0..n.len], n);
                        c.len.* = n.len;
                        st.rotate(idx, c.presented, c.hash, c.now);
                        c.outcome.* = .ok;
                        return true;
                    },
                    .revoked => |n| {
                        const m = @min(n.len, devices.max_name);
                        @memcpy(c.name[0..m], n[0..m]);
                        c.len.* = m;
                        c.outcome.* = .revoked;
                        return true;
                    },
                    .wrong_address => {
                        c.outcome.* = .wrong_address;
                        return false;
                    },
                    .unknown => return false,
                }
            }
        }.op) catch |err| {
            srv.log.print("device sign-in from {s} failed: {t}", .{ peer, err });
            return srv.fail(conn, w, .internal_server_error, "device store unavailable\n");
        };
        const name = name_buf[0..name_len];
        switch (outcome) {
            .ok => {
                var cookies: CookiePair = .{};
                try srv.issueCookies(name, &secret, &cookies);
                switch (mode) {
                    .page => return srv.redirect(conn, w, req, "/", &.{ cookies.device, cookies.session }),
                    .api => {
                        const extra = [_]http1.Header{
                            .{ .name = "set-cookie", .value = cookies.device },
                            .{ .name = "set-cookie", .value = cookies.session },
                        };
                        try srv.respond(conn, w, .no_content, "", "text/plain; charset=utf-8", &extra, false);
                        return false;
                    },
                }
            },
            .revoked => {
                srv.auth_mutex.lockUncancelable(srv.io);
                srv.sessions.revokeTag(name);
                srv.auth_mutex.unlock(srv.io);
                srv.log.print("DEVICE REVOKED '{s}': stale or wrong credential presented from {s} (copied credential?). Re-pair required.", .{ name, peer });
            },
            .wrong_address => srv.log.print("device credential presented from unexpected address {s}; rejected", .{peer}),
            .unknown => {},
        }
        var clear_buf: [2][128]u8 = undefined;
        const clear = try srv.clearCookies(&clear_buf);
        switch (mode) {
            .page => return srv.redirect(conn, w, req, switch (outcome) {
                .revoked => "/pair?e=revoked",
                .wrong_address => "/pair?e=address",
                else => "/pair",
            }, &clear),
            .api => return srv.fail(conn, w, .unauthorized, "not paired\n"),
        }
    }

    /// Whether device `name` is still in the store (it may have been unpaired
    /// by `portal unpair` from another process). Fails closed.
    fn devicePaired(srv: *Server, name: []const u8) bool {
        var found = false;
        const Ctx = struct { name: []const u8, found: *bool };
        devices.withStore(srv.gpa, srv.io, srv.cfg.devices, srv.nowUnix(), Ctx{ .name = name, .found = &found }, struct {
            fn op(c: Ctx, st: *devices.Store) !bool {
                c.found.* = st.find(c.name) != null;
                return false;
            }
        }.op) catch return false;
        return found;
    }

    /// POST /logout ("Unpair this device"): removes the device and its sessions.
    fn logout(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, h: Headers) !bool {
        var tag_buf: [auth.Sessions.max_tag]u8 = undefined;
        var name: []const u8 = "";
        if (h.cookie) |c| {
            srv.auth_mutex.lockUncancelable(srv.io);
            name = srv.sessions.liveTag(c, srv.nowMs(), false, &tag_buf) orelse "";
            srv.sessions.revoke(c);
            if (name.len > 0) srv.sessions.revokeTag(name);
            srv.auth_mutex.unlock(srv.io);
        }
        if (name.len > 0) {
            const Ctx = struct { name: []const u8 };
            devices.withStore(srv.gpa, srv.io, srv.cfg.devices, srv.nowUnix(), Ctx{ .name = name }, struct {
                fn op(c: Ctx, st: *devices.Store) !bool {
                    return st.remove(c.name);
                }
            }.op) catch {};
            srv.log.print("device '{s}' unpaired itself from {s}", .{ name, conn.peer() });
        }
        var clear_buf: [2][128]u8 = undefined;
        const clear = try srv.clearCookies(&clear_buf);
        return srv.redirect(conn, w, req, "/pair?bye", &clear);
    }

    // --------------------------------------------------------- websocket

    const WsConn = struct {
        conn: *Conn,
        w: *Io.Writer,
        write_mutex: Io.Mutex = .init,
        /// Guarded by write_mutex: a close frame went out, send nothing more.
        close_sent: bool = false,
        dead: std.atomic.Value(bool) = .init(false),
        cookie: [auth.encoded_len]u8,
        device: [auth.Sessions.max_tag]u8 = undefined,
        device_len: u8 = 0,

        /// Returns false if the connection should end. Cancelable: the
        /// supervisor can always tear down a sender stuck behind another.
        fn send(c: *WsConn, srv: *Server, data: []const u8, op: http1.Opcode) bool {
            c.write_mutex.lock(srv.io) catch return false;
            defer c.write_mutex.unlock(srv.io);
            if (c.close_sent) return false;
            if (op == .close) c.close_sent = true;
            c.conn.setDeadline(srv.nowMs() +| send_timeout_ms);
            http1.writeFrame(c.w, op, data) catch return false;
            c.conn.setDeadline(no_deadline);
            return true;
        }
    };

    fn webSocket(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, h: Headers, leftover: []const u8) !void {
        const peer = conn.peer();
        if (!guard.originAllowed(h.origin, srv.cfg.scheme, srv.cfg.allowed_hosts)) {
            srv.log.print("websocket rejected from {s}: bad origin", .{peer});
            _ = try srv.fail(conn, w, .forbidden, "bad origin\n");
            return;
        }
        const cookie = h.cookie orelse {
            _ = try srv.fail(conn, w, .unauthorized, "login required\n");
            return;
        };
        if (!srv.sessionLive(cookie, true)) {
            _ = try srv.fail(conn, w, .unauthorized, "login required\n");
            return;
        }
        if (!req.upgrade_websocket or !req.connection_upgrade) {
            _ = try srv.fail(conn, w, .bad_request, "expected websocket\n");
            return;
        }
        if (!std.mem.eql(u8, req.ws_version orelse "", "13")) {
            _ = try srv.fail(conn, w, .bad_request, "unsupported websocket version\n");
            return;
        }
        var accept_buf: [28]u8 = undefined;
        const accept = http1.wsAccept(req.ws_key orelse "", &accept_buf) catch {
            _ = try srv.fail(conn, w, .bad_request, "bad websocket key\n");
            return;
        };
        if (leftover.len > max_ws_header + max_ws_payload) return;

        conn.setDeadline(srv.nowMs() +| send_timeout_ms);
        try http1.writeUpgrade(w, accept);
        conn.setDeadline(no_deadline);

        var ws: WsConn = .{ .conn = conn, .w = w, .cookie = undefined };
        @memcpy(&ws.cookie, cookie);
        {
            srv.auth_mutex.lockUncancelable(srv.io);
            defer srv.auth_mutex.unlock(srv.io);
            const tag = srv.sessions.liveTag(cookie, srv.nowMs(), false, &ws.device) orelse "";
            ws.device_len = @intCast(tag.len);
        }
        @memcpy(&conn.ws_cookie, cookie);
        conn.ws_active.store(true, .release);

        const viewers = srv.session.viewerDelta(1);
        srv.log.print("viewer connected from {s} ({d} watching)", .{ peer, viewers });
        srv.updateTitle(viewers);
        defer {
            const left = srv.session.viewerDelta(-1);
            srv.log.print("viewer disconnected from {s} ({d} watching)", .{ peer, left });
            srv.updateTitle(left);
        }

        var reader = srv.io.concurrent(wsReadLoop, .{ srv, &ws, leftover }) catch return;
        srv.wsWriteLoop(&ws);
        ws.dead.store(true, .release);
        // Interrupts the reader if it is parked in a recv; never close a
        // socket another task is blocked on.
        reader.cancel(srv.io);
    }

    fn updateTitle(srv: *Server, viewers: u32) void {
        var buf: [96]u8 = undefined;
        const title = if (viewers == 0)
            "Portal - no remote viewers"
        else
            std.fmt.bufPrint(&buf, "Portal - {d} REMOTE VIEWER{s} CONNECTED", .{ viewers, if (viewers == 1) "" else "S" }) catch "Portal";
        srv.session.console.setTitle(title);
    }

    fn wsWriteLoop(srv: *Server, ws: *WsConn) void {
        const s = srv.session;
        var msg: [128]u8 = undefined;
        var frame: std.ArrayList(u8) = .empty;
        defer frame.deinit(srv.gpa);
        var rows: std.ArrayList(u16) = .empty;
        defer rows.deinit(srv.gpa);

        const hello = std.fmt.bufPrint(&msg, "{{\"t\":\"hello\",\"input\":\"{t}\"}}", .{s.policy}) catch return;
        if (!ws.send(srv, hello, .text)) return;

        // Generation of the emulator state last sent; 0 plus `full` forces a
        // complete snapshot first (docs/protocol.md section 3).
        var sent_gen: u64 = 0;
        var full = true;
        var sent_cols: u16 = 0;
        var sent_rows: u16 = 0;
        var last_auth = srv.nowMs();
        while (true) {
            s.mutex.lockUncancelable(srv.io);
            if (!s.closed and !full and s.term.gen == sent_gen and !ws.dead.load(.acquire)) {
                s.cond.waitTimeout(srv.io, &s.mutex, .{ .duration = .{
                    .raw = .fromMilliseconds(auth_recheck_ms),
                    .clock = .awake,
                } }) catch |err| switch (err) {
                    error.Timeout => {},
                    error.Canceled => {
                        // waitTimeout re-acquired the mutex before returning.
                        s.mutex.unlock(srv.io);
                        return;
                    },
                };
            }
            // Encode under the lock so the frame is a consistent snapshot.
            const t = &s.term;
            if (t.cols != sent_cols or t.rows != sent_rows) full = true;
            var encode_ok = true;
            const changed = full or t.gen != sent_gen;
            if (changed) {
                rows.clearRetainingCapacity();
                frame.clearRetainingCapacity();
                var r: u16 = 0;
                while (r < t.rows) : (r += 1) {
                    if (full or t.rowGen(r) > sent_gen) {
                        rows.append(srv.gpa, r) catch {
                            encode_ok = false;
                            break;
                        };
                    }
                }
                if (encode_ok) t.encodeRows(rows.items, &frame, srv.gpa) catch {
                    encode_ok = false;
                };
                if (encode_ok) {
                    sent_gen = t.gen;
                    sent_cols = t.cols;
                    sent_rows = t.rows;
                    full = false;
                }
            }
            const closed = s.closed;
            const exit_code = s.exit_code;
            s.mutex.unlock(srv.io);

            if (ws.dead.load(.acquire)) return;
            if (!encode_ok) return; // out of memory: drop this viewer, keep the session

            if (changed) {
                if (!ws.send(srv, frame.items, .binary)) return;
            } else if (closed) {
                const m = std.fmt.bufPrint(&msg, "{{\"t\":\"exit\",\"code\":{d}}}", .{exit_code}) catch return;
                _ = ws.send(srv, m, .text);
                return;
            }

            const now = srv.nowMs();
            if (now -| last_auth >= auth_recheck_ms) {
                last_auth = now;
                // Logout, expiry, or the device being unpaired (possibly by
                // `portal unpair` in another process) ends the stream.
                const dev = ws.device[0..ws.device_len];
                if (dev.len > 0 and !srv.devicePaired(dev)) {
                    srv.auth_mutex.lockUncancelable(srv.io);
                    srv.sessions.revokeTag(dev);
                    srv.auth_mutex.unlock(srv.io);
                }
                if (!srv.sessionLive(&ws.cookie, false)) {
                    _ = ws.send(srv, "{\"t\":\"logout\"}", .text);
                    return;
                }
            }
            // Coalesce bursts of output into at most ~30 frames per second.
            if (changed) srv.io.sleep(.fromMilliseconds(frame_interval_ms), .awake) catch return;
        }
    }

    fn wsReadLoop(srv: *Server, ws: *WsConn, leftover: []const u8) void {
        defer {
            ws.dead.store(true, .release);
            // Wake the writer so it notices promptly.
            srv.session.mutex.lockUncancelable(srv.io);
            srv.session.mutex.unlock(srv.io);
            srv.session.cond.broadcast(srv.io);
        }
        var buf: [max_ws_header + max_ws_payload]u8 = undefined;
        if (leftover.len > buf.len) return;
        @memcpy(buf[0..leftover.len], leftover);
        var len: usize = leftover.len;

        while (!ws.dead.load(.acquire)) {
            const parsed = http1.parseFrameHeader(buf[0..len], max_ws_payload) catch {
                _ = ws.send(srv, &.{ 0x03, 0xea }, .close); // 1002 protocol error
                return;
            };
            if (parsed) |f| {
                const total = f.header_len + f.payload_len;
                if (total <= len) {
                    const payload = buf[f.header_len..total];
                    http1.unmask(payload, f.mask);
                    if (!srv.wsHandleFrame(ws, f.opcode, payload)) return;
                    std.mem.copyForwards(u8, buf[0 .. len - total], buf[total..len]);
                    len -= total;
                    continue;
                }
            }
            if (len >= buf.len) return; // cannot happen: the largest frame fits
            const got = readSome(ws.conn, srv.io, buf[len..]) catch return;
            if (got == 0) return;
            len += got;
        }
    }

    /// Returns false to end the connection.
    fn wsHandleFrame(srv: *Server, ws: *WsConn, opcode: http1.Opcode, payload: []const u8) bool {
        switch (opcode) {
            .ping => return ws.send(srv, payload, .pong),
            .pong => return true,
            .close => {
                // Echo the status code (if any), then end.
                _ = ws.send(srv, if (payload.len >= 2) payload[0..2] else "", .close);
                return false;
            },
            .text, .binary => {
                if (payload.len == 0) return true;
                // "k:<name>" key press, "t:<text>" typing (docs/protocol.md section 4).
                if (payload.len < 2 or payload[1] != ':') return true;
                if (srv.session.policy == .none) return true;
                // Re-check on every input message, not just periodically.
                if (!srv.sessionLive(&ws.cookie, false)) return false;
                switch (payload[0]) {
                    'k' => srv.session.writeWebKey(payload[2..], srv.nowMs()),
                    't' => srv.session.writeWebText(payload[2..]),
                    'l' => srv.session.writeWebLine(payload[2..]) catch |err| {
                        // Error names are Portal's own (keymap.LineError), so
                        // {t} is safe here; nothing from the peer is echoed.
                        srv.log.print("instruction from {s} rejected: {t}", .{ ws.conn.peer(), err });
                        var msg: [96]u8 = undefined;
                        const m = std.fmt.bufPrint(&msg, "{{\"t\":\"rejected\",\"reason\":\"{t}\"}}", .{err}) catch return true;
                        return ws.send(srv, m, .text);
                    },
                    else => {},
                }
                return true;
            },
            else => return false,
        }
    }
};

// -------------------------------------------------------------------- tests

const testing = std.testing;

test {
    _ = http1;
}

fn testKey(last: u8) IpKey {
    var k: IpKey = @splat(0);
    k[15] = last;
    return k;
}

test "conn table: per-ip pre-auth cap evicts that address's oldest" {
    var t: ConnTable = .{ .max_pre_auth = 10, .max_pre_auth_per_ip = 2 };
    const a = t.admit(testKey(1), 0);
    const b = t.admit(testKey(1), 1);
    try testing.expect(a.slot != null and b.slot != null and a.victim == null and b.victim == null);
    const other = t.admit(testKey(2), 2);
    try testing.expect(other.victim == null);
    const c = t.admit(testKey(1), 3);
    try testing.expect(c.slot != null);
    try testing.expectEqual(a.slot, c.victim);
    // The victim no longer counts, so the next one evicts b.
    const d = t.admit(testKey(1), 4);
    try testing.expectEqual(b.slot, d.victim);
}

test "conn table: authenticated connections are never evicted" {
    var t: ConnTable = .{ .max_pre_auth = 10, .max_pre_auth_per_ip = 1 };
    const a = t.admit(testKey(1), 0);
    t.promote(a.slot.?);
    const b = t.admit(testKey(1), 1);
    try testing.expect(b.victim == null);
    const c = t.admit(testKey(1), 2);
    try testing.expectEqual(b.slot, c.victim);
}

test "conn table: global pre-auth cap and full table" {
    var t: ConnTable = .{ .max_pre_auth = 3, .max_pre_auth_per_ip = 100 };
    var slots: [max_connections]usize = undefined;
    for (0..3) |i| slots[i] = t.admit(testKey(@intCast(i)), @intCast(i)).slot.?;
    const d = t.admit(testKey(9), 10);
    try testing.expectEqual(@as(?usize, slots[0]), d.victim);

    // Fill every slot with authenticated connections: new ones are refused.
    var full: ConnTable = .{};
    for (0..max_connections) |i| {
        const s = full.admit(testKey(@intCast(i % 200)), @intCast(i)).slot.?;
        full.promote(s);
    }
    const r = full.admit(testKey(1), 100);
    try testing.expect(r.slot == null and r.victim == null);
    full.release(5);
    try testing.expectEqual(@as(?usize, 5), full.admit(testKey(1), 101).slot);
}

test "log limiter" {
    var l: LogLimiter = .{};
    try testing.expectEqual(@as(?u32, 0), l.check(0, 1000));
    try testing.expectEqual(@as(?u32, null), l.check(10, 1000));
    try testing.expectEqual(@as(?u32, null), l.check(999, 1000));
    try testing.expectEqual(@as(?u32, 2), l.check(1000, 1000));
    // Survives extreme clock values without overflow.
    var m: LogLimiter = .{};
    _ = m.check(std.math.minInt(i64), 1000);
    try testing.expect(m.check(std.math.maxInt(i64), 1000) != null);
    try testing.expect(m.check(std.math.minInt(i64), 1000) == null);
}

test "accept backoff" {
    var b: Backoff = .{};
    try testing.expectEqual(@as(i64, 100), b.next());
    try testing.expectEqual(@as(i64, 200), b.next());
    for (0..20) |_| _ = b.next();
    try testing.expectEqual(@as(i64, 5000), b.next());
    b.reset();
    try testing.expectEqual(@as(i64, 100), b.next());
}

test "ip key" {
    const a = try net.IpAddress.parse("10.8.0.2", 1);
    const b = try net.IpAddress.parse("10.8.0.2", 2);
    const c = try net.IpAddress.parse("10.8.0.3", 1);
    try testing.expectEqualSlices(u8, &ipKey(a), &ipKey(b));
    try testing.expect(!std.mem.eql(u8, &ipKey(a), &ipKey(c)));
}

// ------------------------------------------------------- browser client

/// Everything the bridge (src/web/app.js) provides to the wasm client.
const bridge_imports = [_][]const u8{
    "log",           "get_origin", "ws_open",       "ws_send",
    "ws_close",      "canvas_size", "present",      "request_frame",
    "set_timer",     "check_session", "navigate_pair", "set_text",
};
/// Every export the bridge calls.
const client_exports = [_][]const u8{
    "memory",     "init",     "in_alloc", "resize",   "frame",    "on_ws_open", "on_ws_close",
    "on_ws_message", "on_timer", "on_check", "on_key", "on_pointer", "on_wheel", "on_cmd",
};

const WasmReader = struct {
    b: []const u8,
    p: usize = 0,
    fn byte(r: *WasmReader) !u8 {
        if (r.p >= r.b.len) return error.Truncated;
        r.p += 1;
        return r.b[r.p - 1];
    }
    fn leb(r: *WasmReader) !u32 {
        var v: u32 = 0;
        var shift: u5 = 0;
        while (true) {
            const c = try r.byte();
            v |= @as(u32, c & 0x7f) << shift;
            if (c & 0x80 == 0) return v;
            if (shift >= 28) return error.BadLeb;
            shift += 7;
        }
    }
    fn name(r: *WasmReader) ![]const u8 {
        const n = try r.leb();
        if (n > r.b.len - r.p) return error.Truncated;
        r.p += n;
        return r.b[r.p - n .. r.p];
    }
    fn limits(r: *WasmReader) !void {
        const flags = try r.byte();
        _ = try r.leb();
        if (flags & 1 != 0) _ = try r.leb();
    }
};

fn inList(list: []const []const u8, s: []const u8) bool {
    for (list) |x| if (std.mem.eql(u8, x, s)) return true;
    return false;
}

test "app.wasm imports only the bridge's host functions and exports what it calls" {
    const b = app_wasm;
    try std.testing.expectEqualStrings("\x00asm\x01\x00\x00\x00", b[0..8]);
    var r: WasmReader = .{ .b = b, .p = 8 };
    var imports: usize = 0;
    var exports_found: usize = 0;
    while (r.p < b.len) {
        const id = try r.byte();
        const size = try r.leb();
        const end = r.p + size;
        try std.testing.expect(end <= b.len);
        if (id == 2) { // imports
            var n = try r.leb();
            while (n > 0) : (n -= 1) {
                const module = try r.name();
                const field = try r.name();
                const kind = try r.byte();
                // Only functions from "env": no WASI, no imported memory.
                try std.testing.expectEqualStrings("env", module);
                try std.testing.expectEqual(@as(u8, 0), kind);
                _ = try r.leb();
                if (!inList(&bridge_imports, field)) {
                    std.debug.print("unexpected wasm import: {s}\n", .{field});
                    return error.UnexpectedImport;
                }
                imports += 1;
            }
        } else if (id == 7) { // exports
            var n = try r.leb();
            while (n > 0) : (n -= 1) {
                const field = try r.name();
                _ = try r.byte();
                _ = try r.leb();
                if (inList(&client_exports, field)) exports_found += 1;
            }
        }
        r.p = end;
    }
    try std.testing.expectEqual(bridge_imports.len, imports);
    try std.testing.expectEqual(client_exports.len, exports_found);
    // The bridge defines each import and calls each export.
    for (bridge_imports) |f| {
        var buf: [64]u8 = undefined;
        const decl = try std.fmt.bufPrint(&buf, "\n    {s}: ", .{f});
        if (std.mem.indexOf(u8, app_js, decl) == null) {
            std.debug.print("app.js does not define host function {s}\n", .{f});
            return error.MissingHostFunction;
        }
    }
    for (client_exports[1..]) |f| {
        var buf: [64]u8 = undefined;
        const call = try std.fmt.bufPrint(&buf, "X.{s}(", .{f});
        try std.testing.expect(std.mem.indexOf(u8, app_js, call) != null);
    }
    // The bridge stays small: it is glue, not an application.
    try std.testing.expect(std.mem.count(u8, app_js, "\n") <= 90);
}

test "csp allows wasm compilation but no eval or inline script" {
    try std.testing.expect(std.mem.indexOf(u8, Server.csp, "script-src 'self' 'wasm-unsafe-eval';") != null);
    try std.testing.expect(std.mem.indexOf(u8, Server.csp, "'unsafe-eval'") == null);
}
