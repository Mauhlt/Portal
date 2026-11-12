//! HTTP + WebSocket front end.
//!
//! Request pipeline (every request):
//!   1. Host header must be on the allowlist        (DNS rebinding)
//!   2. Route; unknown paths/methods are rejected
//!   3. State-changing requests and the WebSocket upgrade require an
//!      allowed Origin                              (CSRF / CSWSH)
//!   4. Anything beyond the login page and static assets requires a live
//!      session cookie
//!
//! The web side can only (a) watch the session's output and (b) send
//! keystrokes that pass the input filter into that same session. There is no
//! route that starts a process, changes directory, or touches files.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const http = std.http;
const Allocator = std.mem.Allocator;

const auth = @import("auth.zig");
const guard = @import("guard.zig");
const Session = @import("session.zig").Session;
const Log = @import("log.zig").Log;

const index_html = @embedFile("web/index.html");
const login_html = @embedFile("web/login.html");
const app_js = @embedFile("web/app.js");
const app_css = @embedFile("web/app.css");
const xterm_js = @embedFile("web/vendor/xterm.js");
const xterm_css = @embedFile("web/vendor/xterm.css");

const max_connections = 16;
const max_requests_per_connection = 200;
const max_login_body = 512;
const max_input_message = 4096;
const auth_recheck_ms = 5000;

pub const Config = struct {
    /// Exact Host header values accepted, e.g. "10.8.0.1:8420".
    allowed_hosts: []const []const u8,
    /// "http" normally (WireGuard already encrypts); "https" behind a TLS proxy.
    scheme: []const u8,
    /// Adds `Secure` and uses the `__Host-` cookie prefix. Only valid over HTTPS.
    secure_cookie: bool,
    token_hash: auth.Hash,
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
    limiter: auth.RateLimiter = .{},
    active_conns: std.atomic.Value(u32) = .init(0),

    fn cookieName(srv: *const Server) []const u8 {
        return if (srv.cfg.secure_cookie) "__Host-portal" else "portal_session";
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
        while (true) {
            const stream = srv.listener.accept(srv.io) catch |err| {
                srv.log.print("accept error: {t}", .{err});
                srv.io.sleep(.fromMilliseconds(100), .awake) catch {};
                continue;
            };
            if (srv.active_conns.fetchAdd(1, .acq_rel) >= max_connections) {
                _ = srv.active_conns.fetchSub(1, .acq_rel);
                stream.close(srv.io);
                continue;
            }
            const t = std.Thread.spawn(.{}, handleConnection, .{ srv, stream }) catch {
                _ = srv.active_conns.fetchSub(1, .acq_rel);
                stream.close(srv.io);
                continue;
            };
            t.detach();
        }
    }

    fn handleConnection(srv: *Server, stream: net.Stream) void {
        defer _ = srv.active_conns.fetchSub(1, .acq_rel);
        defer stream.close(srv.io);

        var recv_buf: [16 * 1024]u8 = undefined;
        var send_buf: [16 * 1024]u8 = undefined;
        var sr = stream.reader(srv.io, &recv_buf);
        var sw = stream.writer(srv.io, &send_buf);
        var hs = http.Server.init(&sr.interface, &sw.interface);

        var peer_buf: [64]u8 = undefined;
        const peer = std.fmt.bufPrint(&peer_buf, "{f}", .{stream.socket.address}) catch "?";

        var n: u32 = 0;
        while (n < max_requests_per_connection) : (n += 1) {
            var req = hs.receiveHead() catch return;
            const keep = srv.handleRequest(&req, stream, peer) catch return;
            if (!keep) return;
        }
    }

    const Headers = struct {
        host: ?[]const u8 = null,
        origin: ?[]const u8 = null,
        cookie: ?[]const u8 = null,
        content_type: ?[]const u8 = null,
    };

    fn collectHeaders(srv: *const Server, req: *const http.Server.Request, cookie_out: *[auth.encoded_len]u8) Headers {
        var h: Headers = .{ .content_type = req.head.content_type };
        var it = req.iterateHeaders();
        while (it.next()) |hdr| {
            if (std.ascii.eqlIgnoreCase(hdr.name, "host")) {
                h.host = hdr.value;
            } else if (std.ascii.eqlIgnoreCase(hdr.name, "origin")) {
                h.origin = hdr.value;
            } else if (std.ascii.eqlIgnoreCase(hdr.name, "cookie")) {
                if (guard.getCookie(hdr.value, srv.cookieName())) |v| {
                    if (v.len == auth.encoded_len) {
                        @memcpy(cookie_out, v);
                        h.cookie = cookie_out;
                    }
                }
            }
        }
        return h;
    }

    /// Returns whether to keep the connection open for another request.
    fn handleRequest(srv: *Server, req: *http.Server.Request, stream: net.Stream, peer: []const u8) !bool {
        var cookie_buf: [auth.encoded_len]u8 = undefined;
        const h = srv.collectHeaders(req, &cookie_buf);

        if (!guard.hostAllowed(h.host, srv.cfg.allowed_hosts)) {
            try srv.plain(req, .misdirected_request, "unknown host\n");
            return false;
        }

        // std.http.Server asserts (panics, killing the whole process) when it
        // tries to reuse a connection after a body-bearing request that had
        // neither content-length nor transfer-encoding. Reject those, and any
        // chunked body (we never need one), before anything else.
        if (req.head.method != .GET and req.head.method != .POST) {
            try srv.plain(req, .method_not_allowed, "method not allowed\n"); // keep_alive=false: no body discard
            return false;
        }
        if (req.head.transfer_encoding != .none or
            (req.head.method.requestHasBody() and req.head.content_length == null))
        {
            try srv.plain(req, .length_required, "content-length required\n");
            return false;
        }

        const target = req.head.target;
        const path = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;
        const query = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[q + 1 ..] else "";
        const method = req.head.method;

        if (method == .GET) {
            if (std.mem.eql(u8, path, "/static/xterm.js")) return srv.asset(req, xterm_js, "text/javascript; charset=utf-8");
            if (std.mem.eql(u8, path, "/static/xterm.css")) return srv.asset(req, xterm_css, "text/css; charset=utf-8");
            if (std.mem.eql(u8, path, "/static/app.js")) return srv.asset(req, app_js, "text/javascript; charset=utf-8");
            if (std.mem.eql(u8, path, "/static/app.css")) return srv.asset(req, app_css, "text/css; charset=utf-8");
            if (std.mem.eql(u8, path, "/login")) return srv.loginPage(req, query);
            if (std.mem.eql(u8, path, "/")) {
                if (h.cookie) |c| if (srv.sessionLive(c, true)) return srv.asset(req, index_html, "text/html; charset=utf-8");
                return srv.redirect(req, "/login", null);
            }
            if (std.mem.eql(u8, path, "/ws")) {
                try srv.webSocket(req, h, stream, peer);
                return false;
            }
        } else if (method == .POST) {
            if (!guard.originAllowed(h.origin, srv.cfg.scheme, srv.cfg.allowed_hosts)) {
                srv.log.print("rejected {s} from {s}: bad origin", .{ path, peer });
                try srv.plain(req, .forbidden, "bad origin\n");
                return false;
            }
            if (std.mem.eql(u8, path, "/login")) return srv.login(req, h, peer);
            if (std.mem.eql(u8, path, "/logout")) return srv.logout(req, h, peer);
        } else {
            try srv.plain(req, .method_not_allowed, "method not allowed\n");
            return false;
        }
        try srv.plain(req, .not_found, "not found\n");
        return true;
    }

    // ---------------------------------------------------------- responses

    const csp = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " ++
        "connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; " ++
        "form-action 'self'; frame-ancestors 'none'";

    fn respond(req: *http.Server.Request, status: http.Status, body: []const u8, content_type: []const u8, extra: []const http.Header, keep_alive: bool) !void {
        var headers: [16]http.Header = undefined;
        const common = [_]http.Header{
            .{ .name = "content-type", .value = content_type },
            .{ .name = "content-security-policy", .value = csp },
            .{ .name = "x-content-type-options", .value = "nosniff" },
            .{ .name = "x-frame-options", .value = "DENY" },
            .{ .name = "referrer-policy", .value = "no-referrer" },
            .{ .name = "cross-origin-opener-policy", .value = "same-origin" },
            .{ .name = "cross-origin-resource-policy", .value = "same-origin" },
            .{ .name = "cache-control", .value = "no-store" },
        };
        @memcpy(headers[0..common.len], &common);
        std.debug.assert(common.len + extra.len <= headers.len);
        @memcpy(headers[common.len..][0..extra.len], extra);
        try req.respond(body, .{
            .status = status,
            .keep_alive = keep_alive,
            .extra_headers = headers[0 .. common.len + extra.len],
        });
    }

    fn plain(_: *Server, req: *http.Server.Request, status: http.Status, body: []const u8) !void {
        try respond(req, status, body, "text/plain; charset=utf-8", &.{}, false);
    }

    fn asset(_: *Server, req: *http.Server.Request, body: []const u8, content_type: []const u8) !bool {
        try respond(req, .ok, body, content_type, &.{}, true);
        return true;
    }

    fn redirect(_: *Server, req: *http.Server.Request, location: []const u8, set_cookie: ?[]const u8) !bool {
        var extra: [2]http.Header = undefined;
        var n: usize = 0;
        extra[n] = .{ .name = "location", .value = location };
        n += 1;
        if (set_cookie) |c| {
            extra[n] = .{ .name = "set-cookie", .value = c };
            n += 1;
        }
        // Never reuse a connection after a POST: avoids body-discard paths in
        // std.http entirely.
        const keep = req.head.method != .POST;
        try respond(req, .see_other, "", "text/plain; charset=utf-8", extra[0..n], keep);
        return keep;
    }

    fn loginPage(srv: *Server, req: *http.Server.Request, query: []const u8) !bool {
        const marker = "<!--MESSAGE-->";
        const msg: []const u8 = if (std.mem.eql(u8, query, "e=1"))
            "<p class=\"error\">That token was not accepted.</p>"
        else if (std.mem.eql(u8, query, "e=locked"))
            "<p class=\"error\">Too many failed attempts. Try again in 15 minutes.</p>"
        else if (std.mem.eql(u8, query, "bye"))
            "<p class=\"info\">Signed out.</p>"
        else
            "";
        const idx = comptime std.mem.indexOf(u8, login_html, marker).?;
        const page = try std.mem.concat(srv.gpa, u8, &.{ login_html[0..idx], msg, login_html[idx + marker.len ..] });
        defer srv.gpa.free(page);
        try respond(req, .ok, page, "text/html; charset=utf-8", &.{}, true);
        return true;
    }

    // -------------------------------------------------------------- auth

    fn login(srv: *Server, req: *http.Server.Request, h: Headers, peer: []const u8) !bool {
        const ct = h.content_type orelse "";
        if (!std.ascii.startsWithIgnoreCase(ct, "application/x-www-form-urlencoded")) {
            try srv.plain(req, .unsupported_media_type, "expected form\n");
            return false;
        }
        const len = req.head.content_length orelse {
            try srv.plain(req, .length_required, "length required\n");
            return false;
        };
        if (len > max_login_body) {
            try srv.plain(req, .payload_too_large, "too large\n");
            return false;
        }
        var body_buf: [max_login_body]u8 = undefined;
        const body_reader = try req.readerExpectContinue(&.{});
        const body = body_buf[0..@intCast(len)];
        body_reader.readSliceAll(body) catch return false;

        var token_buf: [256]u8 = undefined;
        const presented = guard.formValue(body, "token", &token_buf) orelse "";

        srv.auth_mutex.lockUncancelable(srv.io);
        const now = srv.nowMs();
        if (!srv.limiter.allowed(now)) {
            srv.auth_mutex.unlock(srv.io);
            srv.log.print("login refused from {s}: locked out", .{peer});
            return srv.redirect(req, "/login?e=locked", null);
        }
        if (!auth.verify(srv.cfg.token_hash, presented)) {
            srv.limiter.recordFailure(now);
            const locked = !srv.limiter.allowed(now);
            srv.auth_mutex.unlock(srv.io);
            srv.log.print("login FAILED from {s}{s}", .{ peer, if (locked) " (now locked out)" else "" });
            return srv.redirect(req, if (locked) "/login?e=locked" else "/login?e=1", null);
        }
        srv.limiter.recordSuccess();
        var raw: [auth.secret_bytes]u8 = undefined;
        srv.io.randomSecure(&raw) catch {
            srv.auth_mutex.unlock(srv.io);
            try srv.plain(req, .internal_server_error, "no entropy\n");
            return false;
        };
        var cookie_val: [auth.encoded_len]u8 = undefined;
        _ = auth.encodeSecret(&raw, &cookie_val);
        std.crypto.secureZero(u8, &raw);
        srv.sessions.create(&cookie_val, now);
        srv.auth_mutex.unlock(srv.io);

        srv.log.print("login ok from {s}", .{peer});
        var cookie_hdr: [192]u8 = undefined;
        const set_cookie = try std.fmt.bufPrint(&cookie_hdr, "{s}={s}; Path=/; HttpOnly; SameSite=Strict; Max-Age={d}{s}", .{
            srv.cookieName(),
            &cookie_val,
            @divTrunc(srv.sessions.absolute_timeout_ms, 1000),
            if (srv.cfg.secure_cookie) "; Secure" else "",
        });
        return srv.redirect(req, "/", set_cookie);
    }

    fn logout(srv: *Server, req: *http.Server.Request, h: Headers, peer: []const u8) !bool {
        if (h.cookie) |c| {
            srv.auth_mutex.lockUncancelable(srv.io);
            srv.sessions.revoke(c);
            srv.auth_mutex.unlock(srv.io);
            srv.log.print("logout from {s}", .{peer});
        }
        var cookie_hdr: [128]u8 = undefined;
        const clear = try std.fmt.bufPrint(&cookie_hdr, "{s}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{s}", .{
            srv.cookieName(),
            if (srv.cfg.secure_cookie) "; Secure" else "",
        });
        return srv.redirect(req, "/login?bye", clear);
    }

    // --------------------------------------------------------- websocket

    const WsConn = struct {
        ws: http.Server.WebSocket,
        stream: net.Stream,
        write_mutex: Io.Mutex = .init,
        dead: std.atomic.Value(bool) = .init(false),
        cookie: [auth.encoded_len]u8,

        fn send(c: *WsConn, io: Io, data: []const u8, op: http.Server.WebSocket.Opcode) bool {
            c.write_mutex.lockUncancelable(io);
            defer c.write_mutex.unlock(io);
            c.ws.writeMessage(data, op) catch return false;
            return true;
        }
    };

    fn webSocket(srv: *Server, req: *http.Server.Request, h: Headers, stream: net.Stream, peer: []const u8) !void {
        if (!guard.originAllowed(h.origin, srv.cfg.scheme, srv.cfg.allowed_hosts)) {
            srv.log.print("websocket rejected from {s}: bad origin", .{peer});
            return srv.plain(req, .forbidden, "bad origin\n");
        }
        const cookie = h.cookie orelse return srv.plain(req, .unauthorized, "login required\n");
        if (!srv.sessionLive(cookie, true)) return srv.plain(req, .unauthorized, "login required\n");
        const key = switch (req.upgradeRequested()) {
            .websocket => |k| k orelse return srv.plain(req, .bad_request, "missing key\n"),
            else => return srv.plain(req, .bad_request, "expected websocket\n"),
        };

        var conn: WsConn = .{
            .ws = try req.respondWebSocket(.{ .key = key }),
            .stream = stream,
            .cookie = undefined,
        };
        @memcpy(&conn.cookie, cookie);
        try conn.ws.flush();

        const viewers = srv.session.viewerDelta(1);
        srv.log.print("viewer connected from {s} ({d} watching)", .{ peer, viewers });
        srv.updateTitle(viewers);
        defer {
            const left = srv.session.viewerDelta(-1);
            srv.log.print("viewer disconnected from {s} ({d} watching)", .{ peer, left });
            srv.updateTitle(left);
        }

        const reader = std.Thread.spawn(.{}, wsReadLoop, .{ srv, &conn }) catch return;
        srv.wsWriteLoop(&conn);
        // Unblock the reader (it may be parked in a socket read), then wait.
        conn.dead.store(true, .release);
        conn.stream.shutdown(srv.io, .both) catch {};
        reader.join();
    }

    fn updateTitle(srv: *Server, viewers: u32) void {
        var buf: [96]u8 = undefined;
        const title = if (viewers == 0)
            "Portal - no remote viewers"
        else
            std.fmt.bufPrint(&buf, "Portal - {d} REMOTE VIEWER{s} CONNECTED", .{ viewers, if (viewers == 1) "" else "S" }) catch "Portal";
        srv.session.console.setTitle(title);
    }

    fn wsWriteLoop(srv: *Server, conn: *WsConn) void {
        const s = srv.session;
        var out: [32 * 1024]u8 = undefined;
        var msg: [128]u8 = undefined;

        s.mutex.lockUncancelable(srv.io);
        var pos = s.ring.oldest(); // replay scrollback on connect
        var sent_gen = s.size_gen -% 1; // force an initial size message
        s.mutex.unlock(srv.io);

        const hello = std.fmt.bufPrint(&msg, "{{\"t\":\"hello\",\"input\":\"{t}\"}}", .{s.policy}) catch unreachable;
        if (!conn.send(srv.io, hello, .text)) return;

        var last_auth = srv.nowMs();
        while (true) {
            s.mutex.lockUncancelable(srv.io);
            if (!s.closed and pos >= s.ring.total and sent_gen == s.size_gen and !conn.dead.load(.acquire)) {
                s.cond.waitTimeout(srv.io, &s.mutex, .{ .duration = .{
                    .raw = .fromMilliseconds(auth_recheck_ms),
                    .clock = .awake,
                } }) catch {};
            }
            const res = s.ring.readFrom(pos, &out);
            pos = res.next;
            const gen = s.size_gen;
            const size = s.size;
            const closed = s.closed;
            const exit_code = s.exit_code;
            s.mutex.unlock(srv.io);

            if (conn.dead.load(.acquire)) return;

            if (gen != sent_gen) {
                sent_gen = gen;
                const m = std.fmt.bufPrint(&msg, "{{\"t\":\"size\",\"cols\":{d},\"rows\":{d}}}", .{ size.cols, size.rows }) catch unreachable;
                if (!conn.send(srv.io, m, .text)) return;
            }
            if (res.n > 0) {
                if (!conn.send(srv.io, out[0..res.n], .binary)) return;
            } else if (closed) {
                const m = std.fmt.bufPrint(&msg, "{{\"t\":\"exit\",\"code\":{d}}}", .{exit_code}) catch unreachable;
                _ = conn.send(srv.io, m, .text);
                return;
            }

            const now = srv.nowMs();
            if (now - last_auth >= auth_recheck_ms) {
                last_auth = now;
                // Logout, expiry or restart of the auth state ends the stream.
                if (!srv.sessionLive(&conn.cookie, false)) {
                    _ = conn.send(srv.io, "{\"t\":\"logout\"}", .text);
                    return;
                }
            }
        }
    }

    fn wsReadLoop(srv: *Server, conn: *WsConn) void {
        defer {
            conn.dead.store(true, .release);
            // Wake the writer so it notices promptly.
            srv.session.mutex.lockUncancelable(srv.io);
            srv.session.mutex.unlock(srv.io);
            srv.session.cond.broadcast(srv.io);
        }
        while (!conn.dead.load(.acquire)) {
            const m = conn.ws.readSmallMessage() catch return;
            switch (m.opcode) {
                .ping => if (!conn.send(srv.io, m.data, .pong)) return,
                .text, .binary => {
                    if (m.data.len == 0 or m.data.len > max_input_message) continue;
                    switch (m.data[0]) {
                        'i' => {
                            if (srv.session.policy == .none) continue;
                            // Re-check on every keystroke batch, not just periodically.
                            if (!srv.sessionLive(&conn.cookie, false)) return;
                            srv.session.writeWebInput(m.data[1..], srv.nowMs());
                        },
                        'r' => srv.session.requestRedraw(srv.nowMs()),
                        else => {},
                    }
                },
                else => {},
            }
        }
    }
};
