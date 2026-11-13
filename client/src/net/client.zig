//! Connection thread: pairing, session refresh, the WebSocket stream and
//! reconnects (docs/protocol.md).
//!
//!   no stored device credential -> wait for the user to press "Pair"
//!       -> POST /pair (registers a request, returns its token)
//!       -> GET /pair/wait, showing the request code, until the desk
//!          approves (device + session cookies) or denies. The server
//!          holds each wait until the request changes (or ~25 s), and the
//!          next one goes out as soon as it answers: a long poll, no
//!          fixed sleep (only errors back off)
//!       -> store the device cookie in the OS credential store
//!   stored credential -> POST /auth/refresh -> store the rotated value
//!       immediately (before anything else), keep the session in memory
//!   GET /ws with the session cookie -> 'G' frames into the shared grid
//!   401 on refresh -> delete the credential, back to "Pair this device";
//!       with `X-Portal-Device: gone` (the desktop unpaired or forgot this
//!       device) also Shared.desktop_gone: the app forgets the desktop
//!   401 on /ws or a `logout` message -> refresh again; `logout` with
//!       reason "unpaired" -> desktop_gone at once
//!   network errors -> retry with backoff 1 s doubling to 15 s
//!
//! Every connection is HTTPS/WSS with the server certificate pinned to the
//! Portal CA imported for this server (tlsconn.zig), unless the user chose
//! `--insecure-plain-http`; nothing is sent before the TLS handshake has
//! authenticated the server.
//!
//! Liveness: each step runs under a watchdog (watchdog.zig): 15 s for
//! connect + TLS handshake, 15 s for each request/response (40 s for a
//! held /pair/wait), and on the stream 60 s without any data from the
//! server. A ping goes out after 20 s of silence, so a live server always
//! answers in time.
//!
//! On the stream one writer task owns every socket write: input frames
//! (queued by the UI thread, which never touches the socket), pings
//! (flagged by the watchdog, which never does I/O) and pongs. A server
//! that stops reading can block the writer, but never the UI thread or the
//! watchdog, so the idle timeout always fires; the watchdog then sets its
//! stop flag and cancels reader and writer, and a stopped connection never
//! blocks again even if a cancelation was swallowed.
//!
//! Everything read from the network is bounded and parsed defensively.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const http = @import("http.zig");
const ws = @import("shared").ws;
const tabs_wire = @import("shared").tabs;
const convo_wire = @import("shared").convo;
const tlsconn = @import("tlsconn.zig");
const x509check = @import("x509check.zig");
const watchdog = @import("watchdog.zig");
const ui = @import("portal_ui");
const Grid = ui.grid.Grid;
const gframe = @import("../gframe.zig");
const keys = @import("../keys.zig");
const credstore = @import("../credstore.zig");
const sync_engine = @import("../sync/engine.zig");
const keypin = @import("../sync/keypin.zig");
const sync_manifest = @import("../sync/manifest.zig");

pub const max_frame_payload = 8 << 20;
pub const http_Cookie = http.Cookie;
pub const TabList = tabs_wire.List;

pub const connect_timeout_ms = 15_000;
pub const request_timeout_ms = 15_000;
pub const idle_timeout_ms = 60_000;
pub const ping_interval_ms = 20_000;
/// One held `GET /pair/wait` (the server answers within ~25 s).
pub const pair_wait_timeout_ms = 40_000;
/// The server keeps a pairing request (its token cookie) for 10 minutes.
pub const pair_request_lifetime_ms = 600_000;

pub const Status = enum {
    starting,
    need_pairing,
    pairing,
    /// The request is registered; the desk has not answered yet
    /// (Shared.pair_code is the request code).
    pair_waiting,
    pair_closed,
    refreshing,
    connecting,
    connected,
    /// A failure that is neither of the two below (TLS, HTTP, a dropped
    /// stream); retried with backoff.
    retrying,
    /// The program on the desktop exited ({"t":"exit"}; Shared.exit_code).
    session_ended,
    /// The desktop does not answer (refused or timed out): Portal is not
    /// running there, or the machine is off. Retried with backoff; Portal
    /// starting again resumes the session (re-signing in as needed).
    desktop_offline,
    /// This side's network is down (no route to the desktop).
    network_error,
    store_unavailable,
};

/// What a failed connection attempt says about the desktop.
pub const Reach = enum { desktop_offline, network_error, other };

pub fn classify(err: anyerror) Reach {
    return switch (err) {
        // Nobody listening, or nothing answering at all: the desktop (or
        // Portal on it) is gone. A firewalled desktop without Portal
        // running drops the SYN, so a timeout means the same.
        error.ConnectionRefused, error.TimedOut, error.Timeout, error.Canceled => .desktop_offline,
        error.NetworkUnreachable, error.HostUnreachable, error.NetworkDown, error.AddressUnavailable => .network_error,
        else => .other,
    };
}

/// The user-facing sentences for the session-ended and offline states
/// (the shared UI's, which shows them too).
pub const endedText = ui.shell.endedText;
pub const offline_text = ui.shell.offline_text;

/// Errors that mean "this is not the Portal we trust" (or not Portal's
/// TLS at all), as opposed to the network being down.
pub fn isTrustError(err: anyerror) bool {
    const list = [_]anyerror{
        error.NotIssuedByPinnedCa,    error.HostMismatch,          error.CertificateExpired,
        error.CertificateNotYetValid, error.CaExpired,             error.BadCertificate,
        error.UnsupportedCertificate, error.NotTls13,              error.UnsupportedCipherSuite,
        error.HelloRetryRequest,      error.TlsHandshakeMalformed, error.TlsUnexpectedMessage,
        error.TlsDecodeError,         error.TlsAlert,              error.TlsConnectionTruncated,
        error.NoServerCertificate,
    };
    for (list) |e| if (e == err) return true;
    return false;
}

test "trust errors" {
    try std.testing.expect(isTrustError(error.HostMismatch));
    try std.testing.expect(!isTrustError(error.TimedOut));
}

pub const Shared = struct {
    mutex: Io.Mutex = .init,
    grid: Grid = .{},
    /// The conversation of the tab shown (convo / convo+ messages).
    convo: ui.convo.Conversation = .{},
    /// hello's `input` (null before hello and while disconnected).
    mode: ?keys.Policy = null,
    /// The desktop's open project tabs (hello, then `tabs`), the one shown
    /// (the server's `session`), and the one this device chose (kept
    /// across reconnects: the first hello after one switches back to it).
    /// Devices can only switch between open tabs (docs/protocol.md).
    tabs: tabs_wire.List = .{},
    current: ?tabs_wire.Id = null,
    chosen: ?tabs_wire.Id = null,
    /// The last {"t":"rejected"} reason (a LineError name) and a counter
    /// bumped with each one, for the UI thread's instruction field.
    rejected_buf: [32]u8 = undefined,
    rejected_len: usize = 0,
    rejected_gen: u64 = 0,
    status: Status = .starting,
    detail_buf: [160]u8 = undefined,
    detail_len: usize = 0,
    retry_in_ms: i64 = 0,
    exit_code: ?i64 = null,
    /// Bumped on any change the UI should redraw for.
    version: std.atomic.Value(u64) = .init(0),
    pair_requested: std.atomic.Value(bool) = .init(false),
    pair_cancel: std.atomic.Value(bool) = .init(false),
    /// Wakes the network thread when the user asks to pair or cancels.
    wake: Io.Event = .unset,
    /// While waiting for the desk: the request code it shows.
    pair_code: ?[4]u8 = null,
    /// The last connection error, until the next successful connection
    /// (the overlay explains certificate and pinning errors).
    last_error: ?anyerror = null,
    wake_ctx: ?*anyopaque = null,
    wake_fn: ?*const fn (*anyopaque) void = null,
    /// The live session (guarded by `mutex`), for the sync worker's
    /// requests; null while signed out. Memory only.
    session: ?http.Cookie = null,
    /// Bumped on every stream (re)connect and every {"t":"updates"}: the
    /// sync worker runs a pass when it changes (docs/sync-design.md).
    sync_gen: std.atomic.Value(u64) = .init(0),
    /// Set with sync_gen, for a worker waiting on it.
    sync_wake: Io.Event = .unset,
    /// Pairing just completed (the app offers voice packages then).
    just_paired: std.atomic.Value(bool) = .init(false),
    /// The desktop said, unambiguously, that it no longer has this device
    /// (`X-Portal-Device: gone`, or logout reason "unpaired"). The
    /// credential is already deleted; the app then forgets the desktop
    /// (connect.forgetDesktop) and says why. Never set by a transient
    /// error.
    desktop_gone: std.atomic.Value(bool) = .init(false),

    pub fn detail(s: *const Shared) []const u8 {
        return s.detail_buf[0..s.detail_len];
    }

    /// Caller holds `mutex`. The name of the tab shown, if known.
    pub fn project(s: *const Shared) ?[]const u8 {
        const id = s.current orelse return null;
        const i = s.tabs.find(id) orelse return null;
        return s.tabs.items[i].name();
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
    /// Frames for the stream's writer task (input from the UI thread,
    /// pongs from the reader).
    out: OutQueue = .{},
    /// Wakes the writer task: a frame was queued or a ping is due.
    write_wake: Io.Event = .unset,
    /// Set by the watchdog's tick (which never writes itself).
    ping_due: std.atomic.Value(bool) = .init(false),
    last_rx_ms: std.atomic.Value(i64) = .init(0),
    last_ping_ms: std.atomic.Value(i64) = .init(0),
    /// Stream liveness (tests shorten them).
    idle_ms: i64 = idle_timeout_ms,
    ping_ms: i64 = ping_interval_ms,
    /// Last connection error printed to stderr (printed once per change).
    last_logged: ?anyerror = null,
    /// First retry delay after a failed `GET /pair/wait` (doubles, up to
    /// 15 s). Successful waits are re-issued at once.
    pair_retry_ms: i64 = 1000,
    /// A /pair/wait that answers faster than this (a server that does not
    /// hold the request) is re-issued only this long after it was sent,
    /// so such a server is not hammered; a held one goes again at once.
    pair_min_interval_ms: i64 = 1000,
    reason_buf: [160]u8 = undefined,
    /// Tests: no connection errors on stderr.
    quiet: bool = false,

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
        if (status != .pair_waiting) s.pair_code = null;
        if (status == .connected) s.last_error = null;
        if (status != .connected) s.mode = if (status == .session_ended) s.mode else null;
        s.mutex.unlock(c.io);
        c.notify();
    }

    /// A `convo` / `convo+` message: parsed strictly (malformed: ignored)
    /// and kept in Shared.convo for the Conversation view.
    fn applyConvo(c: *Client, payload: []const u8) void {
        if (payload.len > convo_wire.max_message) return;
        const scratch = c.gpa.create(convo_wire.Scratch) catch return;
        defer c.gpa.destroy(scratch);
        scratch.text = c.gpa.alloc(u8, payload.len) catch return;
        defer c.gpa.free(scratch.text);
        const m = convo_wire.parse(payload, scratch) orelse return;
        c.shared.mutex.lockUncancelable(c.io);
        c.shared.convo.apply(c.gpa, m) catch {};
        c.shared.mutex.unlock(c.io);
        c.notify();
    }

    fn notify(c: *Client) void {
        _ = c.shared.version.fetchAdd(1, .release);
        if (c.shared.wake_fn) |f| f(c.shared.wake_ctx.?);
    }

    /// Only on the long-lived network thread (never inside a watchdog
    /// task): nothing cancels that thread, so there is no cancelation to
    /// swallow here.
    fn sleepMs(c: *Client, ms: i64) void {
        c.io.sleep(.fromMilliseconds(ms), .awake) catch {};
    }

    /// Prints connection errors to stderr once per distinct error.
    fn logError(c: *Client, err: anyerror) void {
        c.shared.mutex.lockUncancelable(c.io);
        c.shared.last_error = err;
        c.shared.mutex.unlock(c.io);
        if (c.last_logged) |l| if (l == err) return;
        c.last_logged = err;
        if (c.quiet) return;
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
                c.publishSession(&session.?);
            }
            // After an ended session, or while the desktop is unreachable,
            // keep saying so during the (possibly long) attempt instead of
            // a bare "connecting".
            if (!c.quietAttempt()) c.setStatus(.connecting, "opening stream", .{});
            const result = c.runStream(&session.?, &backoff);
            c.streamEnded(result, &session, &backoff);
        }
    }

    /// What follows a stream's end: sign in again, forget the desktop,
    /// show the ended session, or wait (a real deadline) before retrying.
    pub fn streamEnded(c: *Client, result: StreamResult, session: *?http.Cookie, backoff: *i64) void {
        switch (result) {
            .unauthorized, .logout => {
                session.*.?.wipe();
                session.* = null; // refresh (or re-pair) next
                c.publishSession(null);
            },
            .gone => {
                session.*.?.wipe();
                session.* = null;
                c.publishSession(null);
                c.desktopGone();
            },
            .exited => |code| {
                c.shared.mutex.lockUncancelable(c.io);
                c.shared.exit_code = code;
                c.shared.mutex.unlock(c.io);
                var b: [64]u8 = undefined;
                c.setStatus(.session_ended, "{s}", .{endedText(code, &b)});
                // The desktop closes the stream next (and, when this was
                // its only session, exits): look again after the backoff;
                // that attempt says whether it is still there.
                c.sleepMs(backoff.*);
                backoff.* = @min(backoff.* * 2, 15000);
            },
            .unreachable_err => |err| c.unreachableWait(backoff, err),
            .failed => |why| c.retryWait(backoff, why),
        }
    }

    /// Shares the session with the sync worker (or clears it).
    fn publishSession(c: *Client, session: ?*const http.Cookie) void {
        c.shared.mutex.lockUncancelable(c.io);
        defer c.shared.mutex.unlock(c.io);
        if (c.shared.session) |*old| old.wipe();
        c.shared.session = if (session) |x| x.* else null;
    }

    fn signalSync(c: *Client) void {
        _ = c.shared.sync_gen.fetchAdd(1, .release);
        c.shared.sync_wake.set(c.io);
    }

    /// How the sync engine reaches the server with `session`.
    pub fn syncRemote(c: *const Client, session: []const u8) sync_engine.Remote {
        return .{ .gpa = c.gpa, .io = c.io, .addr = c.addr, .security = c.security(), .host = c.host(), .session = session };
    }

    /// Right after pairing: asks the server, over this freshly paired and
    /// CA-pinned session, for its release key and pins it for this server
    /// (docs/sync-design.md, "Trust"). Replaces any earlier pin: pairing
    /// is the only way a pin changes.
    pub fn pinReleaseKey(c: *Client, session: *const http.Cookie) !keypin.Key {
        const remote = c.syncRemote(session.value());
        const key = try sync_engine.fetchKey(&remote);
        try keypin.save(c.io, c.host(), key);
        var fp: [95]u8 = undefined;
        std.debug.print("portal connect: release key for {s} pinned: SHA-256 {s}\n", .{ c.host(), sync_manifest.formatFingerprint(sync_manifest.fingerprint(key), &fp) });
        return key;
    }

    /// Signs in with the stored device credential (rotating it) and returns
    /// a session; for headless use (portalctl sync-device).
    pub fn signIn(c: *Client) !http.Cookie {
        var buf: [credstore.max_secret]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        const stored = (try credstore.load(c.target(), &buf)) orelse return error.NotPaired;
        var device = http.Cookie.fromValue(.device, stored, c.secure()) orelse return error.NotPaired;
        defer device.wipe();
        var resp_buf: [http.max_head_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &resp_buf);
        var req_buf: [768]u8 = undefined;
        defer std.crypto.secureZero(u8, &req_buf);
        var w: Io.Writer = .fixed(&req_buf);
        try http.writeRefreshRequest(&w, c.host(), c.secure(), &device);
        var r = try c.roundTrip(w.buffered(), &resp_buf, request_timeout_ms);
        defer r.wipe();
        switch (http.refreshOutcome(&r)) {
            .ok => {
                try credstore.save(c.target(), r.device.?.value());
                return r.session.?;
            },
            .gone => return error.DeviceGone,
            .revoked => return error.NotPaired,
            .unexpected => return error.SignInFailed,
        }
    }

    pub const ForgetRemote = enum {
        /// The desktop removed this device.
        forgotten,
        /// It no longer had it.
        already_gone,
        /// It could not be reached (or refused): it still lists the device.
        unreachable_desktop,
    };

    /// Asks the desktop to remove this device (POST /device/forget), with
    /// `session` or, without one, a fresh sign-in. Never deletes anything
    /// here: the caller then runs connect.forgetDesktop either way.
    pub fn forgetOnDesktop(c: *Client, session: ?*const http.Cookie) ForgetRemote {
        var own: ?http.Cookie = null;
        defer if (own) |*o| o.wipe();
        const sess: *const http.Cookie = session orelse blk: {
            own = c.signIn() catch |err| return if (err == error.DeviceGone) .already_gone else .unreachable_desktop;
            break :blk &own.?;
        };
        var resp_buf: [http.max_head_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &resp_buf);
        var req_buf: [768]u8 = undefined;
        defer std.crypto.secureZero(u8, &req_buf);
        var w: Io.Writer = .fixed(&req_buf);
        http.writeForgetRequest(&w, c.host(), c.secure(), sess) catch return .unreachable_desktop;
        var r = c.roundTrip(w.buffered(), &resp_buf, request_timeout_ms) catch return .unreachable_desktop;
        defer r.wipe();
        return switch (http.forgetOutcome(&r)) {
            .forgotten => .forgotten,
            .already_gone => .already_gone,
            // The given session ended meanwhile: sign in and ask again.
            .need_session => if (session != null) c.forgetOnDesktop(null) else .unreachable_desktop,
            .unexpected => .unreachable_desktop,
        };
    }

    /// The desktop no longer has this device: drop the credential now (so
    /// nothing signs in with it again) and let the app forget the rest.
    fn desktopGone(c: *Client) void {
        credstore.delete(c.target()) catch {};
        c.setStatus(.need_pairing, "this desktop no longer has this device paired (unpaired at the desk, or forgotten)", .{});
        c.shared.desktop_gone.store(true, .release);
        c.signalSync();
        c.notify();
    }

    /// Whether the current status already explains the next attempt.
    fn quietAttempt(c: *Client) bool {
        c.shared.mutex.lockUncancelable(c.io);
        defer c.shared.mutex.unlock(c.io);
        return switch (c.shared.status) {
            .session_ended, .desktop_offline, .network_error => true,
            else => false,
        };
    }

    /// A connection attempt failed with `err`: says whether the desktop
    /// is offline or this side's network is down (anything else goes to
    /// retryWait), then sleeps once until the retry: a real deadline.
    fn unreachableWait(c: *Client, backoff: *i64, err: anyerror) void {
        switch (classify(err)) {
            .other => return c.retryWait(backoff, describe(err)),
            .desktop_offline => c.setStatus(.desktop_offline, offline_text, .{}),
            .network_error => c.setStatus(.network_error, "Network error: {s} \u{2014} reconnects automatically", .{describe(err)}),
        }
        c.shared.mutex.lockUncancelable(c.io);
        c.shared.retry_in_ms = backoff.*;
        c.shared.mutex.unlock(c.io);
        c.sleepMs(backoff.*);
        backoff.* = @min(backoff.* * 2, 15000);
    }

    /// Shows why and sleeps once until the retry (no countdown ticks).
    fn retryWait(c: *Client, backoff: *i64, why: []const u8) void {
        const left = backoff.*;
        c.shared.mutex.lockUncancelable(c.io);
        c.shared.retry_in_ms = left;
        c.shared.mutex.unlock(c.io);
        c.setStatus(.retrying, "{s}; retrying in {d} s", .{ why, @divTrunc(left + 999, 1000) });
        c.sleepMs(left);
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
        // Not paired: wait for the user (event-driven: requestPairing wakes us).
        c.shared.mutex.lockUncancelable(c.io);
        const already = c.shared.status == .need_pairing or c.shared.status == .pair_closed;
        c.shared.mutex.unlock(c.io);
        if (!already) c.setStatus(.need_pairing, "", .{}); // keep any "no longer paired" note
        while (!c.shared.pair_requested.swap(false, .acq_rel)) {
            // Network thread, not a watchdog task: nothing cancels it.
            c.shared.wake.wait(c.io) catch {};
            c.shared.wake.reset();
        }
        _ = c.shared.pair_cancel.swap(false, .acq_rel);
        c.setStatus(.pairing, "asking the desk", .{});
        const r = c.pairFlow();
        switch (r) {
            .paired => |p| {
                var dev = p.device;
                defer dev.wipe();
                credstore.save(c.target(), dev.value()) catch |err| {
                    c.setStatus(.store_unavailable, "could not save the device credential ({t})", .{err});
                    return null;
                };
                if (!c.plain) _ = c.pinReleaseKey(&p.session) catch |err|
                    std.debug.print("portal connect: no release key pinned ({t}); sync stays off until this device is paired again\n", .{err});
                c.shared.just_paired.store(true, .release);
                return p.session;
            },
            .failed => |why| {
                c.setStatus(.pair_closed, "{s}", .{why});
                return null;
            },
            .cancelled => {
                c.setStatus(.need_pairing, "pairing cancelled", .{});
                return null;
            },
        }
    }

    pub const PairFlowResult = union(enum) {
        paired: struct { device: http.Cookie, session: http.Cookie },
        /// Why not (shown to the user).
        failed: []const u8,
        cancelled,
    };

    /// The desk-approved pairing (docs/protocol.md section 1): `POST /pair`
    /// registers a request and returns its token; then `GET /pair/wait`
    /// until the desk answers. While waiting the request code is shown
    /// (Shared.pair_code) so the user can match it with the desk's.
    ///
    /// Long poll: the server holds each wait until the request changes or
    /// about 25 s pass, and the next wait is sent as soon as one returns
    /// (no sleep between successful waits; see `pair_min_interval_ms` for
    /// servers that answer at once). A held wait is interrupted at once by
    /// cancelPairing (the watchdog's abort flag). Only failed waits back
    /// off, with real deadlines on Shared.wake. The whole wait ends when
    /// the request's 10-minute lifetime is over. Nothing is stored here.
    pub fn pairFlow(c: *Client) PairFlowResult {
        var resp_buf: [http.max_head_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &resp_buf);
        var req_buf: [512]u8 = undefined;
        defer std.crypto.secureZero(u8, &req_buf);
        var w: Io.Writer = .fixed(&req_buf);
        http.writePairRequest(&w, c.host(), c.secure()) catch return .{ .failed = "request too long" };
        var token: http.Cookie = blk: {
            var r = c.roundTrip(w.buffered(), &resp_buf, request_timeout_ms) catch |err| {
                c.logError(err);
                return .{ .failed = c.reason("could not reach the server: {s}", .{describe(err)}) };
            };
            defer r.wipe();
            switch (http.pairStartOutcome(&r)) {
                .requested => break :blk r.pairreq.?,
                .closed => return .{ .failed = "no pairing window is open at the desk (Pair a device in the Portal window, or portalctl pair <name>)" },
                .busy => return .{ .failed = "too many requests are waiting at the desk; answer them there, then try again" },
                .denied => return .{ .failed = "the desk denied this device in this pairing window" },
                .unexpected => return .{ .failed = c.reason("unexpected pairing response (HTTP {d})", .{r.status}) },
            }
        };
        defer token.wipe();

        const deadline = watchdog.nowMs(c.io) + pair_request_lifetime_ms;
        var failures: u32 = 0;
        while (true) {
            if (c.shared.pair_cancel.swap(false, .acq_rel)) return .cancelled;
            w = .fixed(&req_buf);
            http.writePairWaitRequest(&w, c.host(), c.secure(), &token) catch return .{ .failed = "request too long" };
            const sent = watchdog.nowMs(c.io);
            // The held request: cancelPairing aborts it through the watchdog.
            c.wd.abort = &c.shared.pair_cancel;
            const result = c.roundTrip(w.buffered(), &resp_buf, pair_wait_timeout_ms);
            c.wd.abort = null;
            var next_at: i64 = sent +| c.pair_min_interval_ms;
            if (result) |resp| {
                var r = resp;
                defer r.wipe();
                failures = 0;
                switch (http.pairWaitOutcome(&r)) {
                    .waiting => {
                        c.shared.mutex.lockUncancelable(c.io);
                        if (r.request_code) |code| c.shared.pair_code = code;
                        c.shared.mutex.unlock(c.io);
                        c.setStatus(.pair_waiting, "approve this device at the desk", .{});
                    },
                    .paired => {
                        const p: PairFlowResult = .{ .paired = .{ .device = r.device.?, .session = r.session.? } };
                        return p;
                    },
                    .denied => return .{ .failed = "the desk denied this request" },
                    .expired => return .{ .failed = "the request expired or the pairing window closed; pair again" },
                    .unexpected => return .{ .failed = c.reason("unexpected answer while waiting (HTTP {d})", .{r.status}) },
                }
            } else |err| {
                if (c.shared.pair_cancel.swap(false, .acq_rel)) return .cancelled;
                // A lost wait is retried (with backoff) until the deadline.
                c.logError(err);
                failures += 1;
                next_at = watchdog.nowMs(c.io) +| @min(c.pair_retry_ms * (@as(i64, 1) << @intCast(@min(failures - 1, 4))), 15_000);
                c.setStatus(.pair_waiting, "{s}; trying again", .{describe(err)});
            }
            const now = watchdog.nowMs(c.io);
            if (now >= deadline) return .{ .failed = "the pairing request expired; pair again" };
            if (now >= next_at) continue;
            // Until the retry (or the floor for a non-holding server), or
            // until the user cancels. Network thread: nothing cancels it.
            c.shared.wake.reset();
            if (c.shared.pair_cancel.load(.acquire)) continue;
            c.shared.wake.waitTimeout(c.io, .{ .duration = .{ .raw = .fromMilliseconds(@min(next_at, deadline) - now), .clock = .awake } }) catch {};
        }
    }

    /// Formats a failure reason into the client's buffer.
    fn reason(c: *Client, comptime fmt: []const u8, args: anytype) []const u8 {
        return std.fmt.bufPrint(&c.reason_buf, fmt, args) catch "pairing failed";
    }

    fn refresh(c: *Client, device: *const http.Cookie, backoff: *i64) ?http.Cookie {
        var resp_buf: [http.max_head_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &resp_buf);
        var req_buf: [768]u8 = undefined;
        defer std.crypto.secureZero(u8, &req_buf);
        var w: Io.Writer = .fixed(&req_buf);
        http.writeRefreshRequest(&w, c.host(), c.secure(), device) catch return null;
        var r = c.roundTrip(w.buffered(), &resp_buf, request_timeout_ms) catch |err| {
            c.logError(err);
            c.unreachableWait(backoff, err);
            return null;
        };
        defer r.wipe();
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
            .gone => {
                c.desktopGone();
                return null;
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

    /// Sends a request on a fresh connection and parses the response head
    /// (the server must answer within `answer_ms`). Returned slices point
    /// into `buf`.
    fn roundTrip(c: *Client, request: []const u8, buf: *[http.max_head_bytes]u8, answer_ms: i64) anyerror!http.Response {
        c.wd.extend(connect_timeout_ms);
        const r = c.wd.run(roundTripTask, .{ c, request, buf, answer_ms }, null);
        if (c.wd.expired.load(.acquire)) return error.TimedOut;
        return r;
    }

    fn roundTripTask(c: *Client, request: []const u8, buf: *[http.max_head_bytes]u8, answer_ms: i64) anyerror!http.Response {
        const conn = try tlsconn.Conn.openWatched(c.gpa, c.io, c.addr, c.security(), &c.wd.stopped);
        defer conn.close(c.gpa);
        c.wd.extend(answer_ms);
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

    pub const StreamResult = union(enum) {
        unauthorized,
        logout,
        /// {"t":"logout","reason":"unpaired"}: the record is gone.
        gone,
        exited: i64,
        /// Could not connect at all (see classify).
        unreachable_err: anyerror,
        failed: []const u8,
    };

    pub fn runStream(c: *Client, session: *const http.Cookie, backoff: *i64) StreamResult {
        c.wd.extend(connect_timeout_ms);
        const r = c.wd.run(streamTask, .{ c, session, backoff }, .{ .ctx = c, .f = pingTick });
        if (c.wd.expired.load(.acquire)) {
            c.logError(error.TimedOut);
            return .{ .unreachable_err = error.TimedOut };
        }
        return r;
    }

    /// Runs on the watchdog's thread while the stream task runs. It never
    /// writes (a blocked write would keep the watchdog from its deadline):
    /// it only flags a ping for the writer task after `ping_ms` of
    /// silence. Returns when it next needs to run (awake-clock ms).
    fn pingTick(ctx: *anyopaque) i64 {
        const c: *Client = @ptrCast(@alignCast(ctx));
        const now = watchdog.nowMs(c.io);
        const due = @max(c.last_rx_ms.load(.acquire), c.last_ping_ms.load(.acquire)) +| c.ping_ms;
        if (now < due) return due;
        c.last_ping_ms.store(now, .release);
        c.ping_due.store(true, .release);
        c.write_wake.set(c.io);
        return now +| c.ping_ms;
    }

    fn streamTask(c: *Client, session: *const http.Cookie, backoff: *i64) StreamResult {
        const conn = tlsconn.Conn.openWatched(c.gpa, c.io, c.addr, c.security(), &c.wd.stopped) catch |err| {
            c.logError(err);
            return .{ .unreachable_err = err };
        };
        defer conn.close(c.gpa);
        c.wd.extend(request_timeout_ms);

        var rnd: [16]u8 = undefined;
        c.io.randomSecure(&rnd) catch |err| {
            if (err == error.Canceled) c.io.recancel();
            return .{ .failed = "no secure randomness" };
        };
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
        const expected = ws.accept(&key) catch return .{ .failed = "bad websocket key" };
        if (!resp.upgrade_websocket or !resp.connection_upgrade or resp.accept == null or
            !std.mem.eql(u8, resp.accept.?, &expected)) return .{ .failed = "bad websocket handshake" };
        // Drop the head; keep any frame bytes that followed it.
        std.mem.copyForwards(u8, buf.items[0 .. buf.items.len - head_end], buf.items[head_end..]);
        buf.shrinkRetainingCapacity(buf.items.len - head_end);

        c.last_rx_ms.store(watchdog.nowMs(c.io), .release);
        c.last_ping_ms.store(0, .release);
        c.ping_due.store(false, .release);
        c.wd.extend(c.idle_ms);

        // The writer task owns every write from here on.
        c.write_wake.reset();
        c.out.open(c.io);
        var writer = c.io.concurrent(writerTask, .{ c, conn }) catch {
            c.out.close(c.io);
            return .{ .failed = "cannot start the writer" };
        };
        defer {
            // No more frames; the writer must not block again (a write
            // stuck on a server that stopped reading is canceled).
            c.out.close(c.io);
            conn.halt();
            c.write_wake.set(c.io);
            writer.cancel(c.io);
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

    /// The stream's only writer: due pings and queued frames, until the
    /// stream ends (halted connection, closed queue) or it is canceled.
    /// A failed write ends it and halts the connection, so the reader's
    /// next read fails too and the stream reconnects.
    fn writerTask(c: *Client, conn: *tlsconn.Conn) void {
        var item: OutQueue.Item = .{};
        defer std.crypto.secureZero(u8, &item.buf);
        var out: [ws.max_client_payload + 16]u8 = undefined;
        defer std.crypto.secureZero(u8, &out);
        while (!conn.stopped()) {
            if (c.ping_due.swap(false, .acq_rel)) {
                c.writeFrame(conn, .ping, "", &out) catch return conn.halt();
                continue;
            }
            if (c.out.take(c.io, &item)) {
                c.writeFrame(conn, item.opcode, item.buf[0..item.len], &out) catch return conn.halt();
                continue;
            }
            if (!c.out.isOpen(c.io)) return;
            c.write_wake.wait(c.io) catch return; // canceled: the stream is ending
            c.write_wake.reset(); // then look again: nothing queued before this is missed
        }
    }

    fn writeFrame(c: *Client, conn: *tlsconn.Conn, opcode: ws.Opcode, payload: []const u8, out: []u8) !void {
        var mask: [4]u8 = undefined;
        try c.io.randomSecure(&mask);
        const frame = try ws.encodeClientFrame(out, opcode, payload, mask);
        try conn.writeAll(frame);
    }

    /// Reads into `buf`; any data from the server moves the idle deadline.
    fn readMore(c: *Client, conn: *tlsconn.Conn, buf: *std.ArrayList(u8)) bool {
        buf.ensureUnusedCapacity(c.gpa, 32 * 1024) catch return false;
        const spare = buf.unusedCapacitySlice();
        const n = conn.read(spare) catch return false;
        if (n == 0) return false;
        buf.items.len += n;
        c.last_rx_ms.store(watchdog.nowMs(c.io), .release);
        c.wd.extend(c.idle_ms);
        return true;
    }

    const Msg = struct {
        t: []const u8 = "",
        input: ?[]const u8 = null,
        code: ?i64 = null,
        reason: ?[]const u8 = null,
    };

    fn handleFrame(c: *Client, frame: ws.Frame, backoff: *i64) ?StreamResult {
        switch (frame.opcode) {
            .binary => {
                if (frame.payload.len == 0) return null;
                switch (frame.payload[0]) {
                    'G' => {
                        c.shared.mutex.lockUncancelable(c.io);
                        const r = gframe.apply(&c.shared.grid, c.gpa, frame.payload);
                        c.shared.mutex.unlock(c.io);
                        r catch |err| return .{ .failed = @errorName(err) }; // reconnect for a fresh snapshot
                    },
                    // Inline images: a bad one is dropped, the stream goes on.
                    'I', 'P' => {
                        c.shared.mutex.lockUncancelable(c.io);
                        const r = if (frame.payload[0] == 'I')
                            gframe.applyBlob(&c.shared.grid, c.gpa, frame.payload)
                        else
                            gframe.applyPlacements(&c.shared.grid, c.gpa, frame.payload);
                        c.shared.mutex.unlock(c.io);
                        r catch return null;
                    },
                    else => return null, // unknown: ignore
                }
                c.notify();
            },
            .text => {
                // The conversation of the tab shown (larger than the
                // other messages; its own strict parser).
                if (std.mem.startsWith(u8, frame.payload, "{\"t\":\"convo")) {
                    c.applyConvo(frame.payload);
                    return null;
                }
                if (frame.payload.len > 8192) return null;
                const parsed = std.json.parseFromSlice(Msg, c.gpa, frame.payload, .{ .ignore_unknown_fields = true }) catch return null;
                defer parsed.deinit();
                const m = parsed.value;
                if (std.mem.eql(u8, m.t, "hello")) {
                    c.shared.mutex.lockUncancelable(c.io);
                    c.shared.mode = keys.parsePolicy(m.input orelse "none");
                    c.shared.tabs = tabs_wire.parseList(frame.payload) orelse .{};
                    c.shared.current = tabs_wire.idField(frame.payload, "session");
                    // Reconnected: back to the tab this device was on, if
                    // it is still open.
                    const back = c.shared.chosen;
                    c.shared.mutex.unlock(c.io);
                    if (back) |id| if (!sameId(c.shared.current, id)) c.sendTabIfOpen(id);
                    backoff.* = 1000;
                    c.notify();
                    c.signalSync(); // look for updates on every (re)connect
                } else if (std.mem.eql(u8, m.t, "tabs")) {
                    c.shared.mutex.lockUncancelable(c.io);
                    if (tabs_wire.parseList(frame.payload)) |l| c.shared.tabs = l;
                    c.shared.mutex.unlock(c.io);
                    c.notify();
                } else if (std.mem.eql(u8, m.t, "session")) {
                    // The server now shows this tab; its full screen
                    // follows. Images belong to the old tab: drop them.
                    c.shared.mutex.lockUncancelable(c.io);
                    c.shared.current = tabs_wire.idField(frame.payload, "id");
                    c.shared.grid.images.deinit(c.gpa);
                    c.shared.grid.images = .{};
                    c.shared.mutex.unlock(c.io);
                    c.notify();
                } else if (std.mem.eql(u8, m.t, "nosession") or std.mem.eql(u8, m.t, "ended")) {
                    // The tab asked for (or shown) is gone: input goes
                    // nowhere until another one is chosen. Choose the one
                    // shown if it is still open, else the first.
                    const gone = tabs_wire.idField(frame.payload, "id");
                    c.shared.mutex.lockUncancelable(c.io);
                    var pick: ?tabs_wire.Id = null;
                    if (c.shared.current) |cur| if (!sameId(gone, cur) and c.shared.tabs.find(cur) != null) {
                        pick = cur;
                    };
                    if (pick == null) for (c.shared.tabs.slice()) |e| if (!sameId(gone, e.id)) {
                        pick = e.id;
                        break;
                    };
                    const was_current = gone != null and sameId(c.shared.current, gone.?);
                    c.shared.mutex.unlock(c.io);
                    if (pick) |p| if (m.t[0] == 'n' or was_current) c.selectTab(p);
                    c.notify();
                } else if (std.mem.eql(u8, m.t, "rejected")) {
                    // An instruction line was refused (docs/protocol.md §4).
                    const why = m.reason orelse "";
                    c.shared.mutex.lockUncancelable(c.io);
                    const n = @min(why.len, c.shared.rejected_buf.len);
                    @memcpy(c.shared.rejected_buf[0..n], why[0..n]);
                    c.shared.rejected_len = n;
                    c.shared.rejected_gen +%= 1;
                    c.shared.mutex.unlock(c.io);
                    c.notify();
                } else if (std.mem.eql(u8, m.t, "updates")) {
                    c.signalSync();
                } else if (std.mem.eql(u8, m.t, "exit")) {
                    return .{ .exited = m.code orelse 0 };
                } else if (std.mem.eql(u8, m.t, "logout")) {
                    // "unpaired": the desktop removed this device. Anything
                    // else (expired, "replaced"): sign in again, whose
                    // answer says whether this device is still paired.
                    if (std.mem.eql(u8, m.reason orelse "", "unpaired")) return .gone;
                    return .logout;
                }
            },
            // Queued for the writer (dropped if its queue is full: the
            // server's next ping gets the next pong).
            .ping => _ = c.out.put(c.io, .pong, frame.payload),
            // The stream ends now; the closing handshake reply is not
            // waited for (the writer is stopped with the reader).
            .close => return .{ .failed = "server closed the stream" },
            else => {},
        }
        return null;
    }

    /// Shows tab `id` (one of Shared.tabs): "s:<id>". Remembered as this
    /// device's choice. Callable from any thread.
    pub fn selectTab(c: *Client, id: tabs_wire.Id) void {
        c.shared.mutex.lockUncancelable(c.io);
        c.shared.chosen = id;
        c.shared.mutex.unlock(c.io);
        const f = tabs_wire.subscribeFrame(id);
        _ = c.sendInput(&f);
    }

    fn sendTabIfOpen(c: *Client, id: tabs_wire.Id) void {
        c.shared.mutex.lockUncancelable(c.io);
        const open = c.shared.tabs.find(id) != null;
        c.shared.mutex.unlock(c.io);
        if (open) c.selectTab(id);
    }

    /// Queues an input frame ("k:...", "t:..." or "l:...") for the stream's writer;
    /// callable from the UI thread and never blocks on the socket. False
    /// when not connected, too long, or the queue is full (a server that
    /// stopped reading: the idle timeout will reconnect).
    pub fn sendInput(c: *Client, text: []const u8) bool {
        if (!c.out.put(c.io, .text, text)) return false;
        c.write_wake.set(c.io);
        return true;
    }

    pub fn requestPairing(c: *Client) void {
        c.shared.pair_requested.store(true, .release);
        c.shared.wake.set(c.io);
    }

    /// Stops waiting for the desk (the request stays at the desk until it
    /// expires; the device just stops asking).
    pub fn cancelPairing(c: *Client) void {
        c.shared.pair_cancel.store(true, .release);
        c.shared.wake.set(c.io);
        c.wd.poke(); // ends a held /pair/wait (the watchdog's abort flag)
    }
};

fn sameId(a: ?tabs_wire.Id, b: tabs_wire.Id) bool {
    const x = a orelse return false;
    return std.mem.eql(u8, &x, &b);
}

/// Frames waiting for the stream's writer task. Bounded: when the socket
/// is stuck, input is refused rather than piling up or blocking.
pub const OutQueue = struct {
    pub const cap = 16;
    pub const Item = struct {
        opcode: ws.Opcode = .text,
        len: u16 = 0,
        buf: [ws.max_client_payload]u8 = undefined,
    };

    mutex: Io.Mutex = .init,
    items: [cap]Item = undefined,
    head: usize = 0,
    len: usize = 0,
    /// True while a stream is connected (frames are accepted).
    is_open: bool = false,

    pub fn open(q: *OutQueue, io: Io) void {
        q.mutex.lockUncancelable(io);
        defer q.mutex.unlock(io);
        q.is_open = true;
        q.head = 0;
        q.len = 0;
    }

    /// Stops accepting and drops what is queued (wiped: it may be typed text).
    pub fn close(q: *OutQueue, io: Io) void {
        q.mutex.lockUncancelable(io);
        defer q.mutex.unlock(io);
        q.is_open = false;
        q.len = 0;
        q.head = 0;
        for (&q.items) |*it| std.crypto.secureZero(u8, &it.buf);
    }

    pub fn isOpen(q: *OutQueue, io: Io) bool {
        q.mutex.lockUncancelable(io);
        defer q.mutex.unlock(io);
        return q.is_open;
    }

    pub fn put(q: *OutQueue, io: Io, opcode: ws.Opcode, payload: []const u8) bool {
        if (payload.len > ws.max_client_payload) return false;
        q.mutex.lockUncancelable(io);
        defer q.mutex.unlock(io);
        if (!q.is_open or q.len == cap) return false;
        const it = &q.items[(q.head + q.len) % cap];
        it.opcode = opcode;
        it.len = @intCast(payload.len);
        @memcpy(it.buf[0..payload.len], payload);
        q.len += 1;
        return true;
    }

    pub fn take(q: *OutQueue, io: Io, out: *Item) bool {
        q.mutex.lockUncancelable(io);
        defer q.mutex.unlock(io);
        if (q.len == 0) return false;
        const it = &q.items[q.head];
        out.opcode = it.opcode;
        out.len = it.len;
        @memcpy(out.buf[0..it.len], it.buf[0..it.len]);
        std.crypto.secureZero(u8, it.buf[0..it.len]);
        q.head = (q.head + 1) % cap;
        q.len -= 1;
        return true;
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
    const conn = try tlsconn.Conn.openWatched(gpa, io, addr, .plain, &wd.stopped);
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

// ------------------------------------------------------------------ pairing against a scripted server

/// A local plain-HTTP server that answers one request per connection from
/// a script, like Portal's pairing routes, and records what it was asked.
const ScriptServer = struct {
    server: net.Server,
    replies: []const []const u8,
    /// Request heads, as received (first line + headers).
    seen: [8][512]u8 = undefined,
    seen_len: [8]usize = @splat(0),
    n: usize = 0,

    fn serve(s: *ScriptServer, io: Io) void {
        for (s.replies) |reply| {
            const conn = s.server.accept(io) catch return;
            defer conn.close(io);
            var len: usize = 0;
            const buf = &s.seen[s.n];
            while (len < buf.len) {
                var vec = [_][]u8{buf[len..]};
                const got = conn.readWithControl(io, &vec, &.{}) catch return;
                if (got.data_len == 0) return;
                len += got.data_len;
                if (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n") != null) break;
            }
            s.seen_len[s.n] = len;
            s.n += 1;
            if (reply.len == 0) {
                // Hold the request unanswered, as a long poll does.
                io.sleep(.fromSeconds(60), .awake) catch {};
                return;
            }
            var wb: [1024]u8 = undefined;
            var w = conn.writer(io, &wb);
            w.interface.writeAll(reply) catch return;
            w.interface.flush() catch return;
        }
    }

    fn request(s: *const ScriptServer, i: usize) []const u8 {
        return s.seen[i][0..s.seen_len[i]];
    }
};

const tok43 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123-_6";
const reply_requested = "HTTP/1.1 303 See Other\r\nLocation: /pair/wait\r\n" ++
    "Set-Cookie: portal_pairreq=" ++ tok43 ++ "; Path=/; HttpOnly; SameSite=Strict; Max-Age=600\r\nContent-Length: 0\r\n\r\n";
const reply_waiting = "HTTP/1.1 200 OK\r\nX-Portal-Request-Code: 7f3a\r\nContent-Type: text/html\r\nContent-Length: 4\r\n\r\nwait";

fn runScript(replies: []const []const u8, srv: *ScriptServer) !Client.PairFlowResult {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var addr: net.IpAddress = try .parseLiteral("127.0.0.1:0");
    srv.* = .{ .server = try addr.listen(io, .{}), .replies = replies };
    addr = srv.server.socket.address;
    var host_buf: [32]u8 = undefined;
    const host_text = try std.fmt.bufPrint(&host_buf, "{f}", .{addr});
    var fut = try io.concurrent(ScriptServer.serve, .{ srv, io });
    defer {
        fut.cancel(io);
        srv.server.deinit(io);
    }
    var shared: Shared = .{};
    var c = try Client.init(gpa, io, &shared, host_text, .insecure_plain_http);
    c.pair_min_interval_ms = 5;
    c.pair_retry_ms = 5;
    const r = c.pairFlow();
    if (r == .paired) {
        // The request code was shown while waiting (cleared on later
        // statuses, so check what the waiting status left behind).
        try std.testing.expect(shared.version.load(.acquire) > 0);
    }
    return r;
}

test "pairing: request, wait (code shown), approved at the desk" {
    var srv: ScriptServer = undefined;
    const approved = "HTTP/1.1 303 See Other\r\nLocation: /\r\n" ++
        "Set-Cookie: portal_device=laptop." ++ tok43 ++ "; Path=/; HttpOnly; SameSite=Strict; Max-Age=7776000\r\n" ++
        "Set-Cookie: portal_session=" ++ tok43 ++ "; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200\r\n" ++
        "Set-Cookie: portal_pairreq=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0\r\nContent-Length: 0\r\n\r\n";
    const r = try runScript(&.{ reply_requested, reply_waiting, reply_waiting, approved }, &srv);
    try std.testing.expect(r == .paired);
    try std.testing.expectEqualStrings("laptop." ++ tok43, r.paired.device.value());
    try std.testing.expectEqualStrings(tok43, r.paired.session.value());
    // POST /pair with Host and Origin, then the waits with the token.
    try std.testing.expectEqual(@as(usize, 4), srv.n);
    try std.testing.expect(std.mem.startsWith(u8, srv.request(0), "POST /pair HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, srv.request(0), "\r\nOrigin: http://127.0.0.1:") != null);
    for (1..4) |i| {
        try std.testing.expect(std.mem.startsWith(u8, srv.request(i), "GET /pair/wait HTTP/1.1\r\n"));
        try std.testing.expect(std.mem.indexOf(u8, srv.request(i), "\r\nCookie: portal_pairreq=" ++ tok43 ++ "\r\n") != null);
    }
}

test "pairing: denied, expired, refused, and the code is published" {
    var srv: ScriptServer = undefined;
    const denied = "HTTP/1.1 303 See Other\r\nLocation: /pair?e=denied\r\nContent-Length: 0\r\n\r\n";
    const r1 = try runScript(&.{ reply_requested, reply_waiting, denied }, &srv);
    try std.testing.expect(r1 == .failed);
    try std.testing.expect(std.mem.indexOf(u8, r1.failed, "denied") != null);

    const expired = "HTTP/1.1 303 See Other\r\nLocation: /pair?e=expired\r\nContent-Length: 0\r\n\r\n";
    const r2 = try runScript(&.{ reply_requested, expired }, &srv);
    try std.testing.expect(r2 == .failed);
    try std.testing.expect(std.mem.indexOf(u8, r2.failed, "expired") != null);

    const closed = "HTTP/1.1 303 See Other\r\nLocation: /pair?e=closed\r\nContent-Length: 0\r\n\r\n";
    const r3 = try runScript(&.{closed}, &srv);
    try std.testing.expect(r3 == .failed);
    try std.testing.expect(std.mem.indexOf(u8, r3.failed, "no pairing window") != null);

    // The waiting page's code reaches Shared for the overlay.
    const io = std.testing.io;
    var addr: net.IpAddress = try .parseLiteral("127.0.0.1:0");
    srv = .{ .server = try addr.listen(io, .{}), .replies = &.{ reply_requested, reply_waiting, denied } };
    addr = srv.server.socket.address;
    var host_buf: [32]u8 = undefined;
    const host_text = try std.fmt.bufPrint(&host_buf, "{f}", .{addr});
    var fut = try io.concurrent(ScriptServer.serve, .{ &srv, io });
    defer {
        fut.cancel(io);
        srv.server.deinit(io);
    }
    var shared: Shared = .{};
    var c = try Client.init(std.testing.allocator, io, &shared, host_text, .insecure_plain_http);
    c.pair_min_interval_ms = 5;
    c.pair_retry_ms = 5;
    var seen_code = false;
    // Watch the shared state from the UI side: wake_fn runs on every change.
    const Watch = struct {
        var flag: *bool = undefined;
        var sh: *Shared = undefined;
        fn f(_: *anyopaque) void {
            if (sh.pair_code) |code| if (std.mem.eql(u8, &code, "7f3a")) {
                flag.* = true;
            };
        }
    };
    Watch.flag = &seen_code;
    Watch.sh = &shared;
    shared.wake_ctx = &shared;
    shared.wake_fn = Watch.f;
    _ = c.pairFlow();
    try std.testing.expect(seen_code);
}

test "pairing: cancel stops the wait" {
    var srv: ScriptServer = undefined;
    const io = std.testing.io;
    var addr: net.IpAddress = try .parseLiteral("127.0.0.1:0");
    srv = .{ .server = try addr.listen(io, .{}), .replies = &.{ reply_requested, reply_waiting, reply_waiting, reply_waiting } };
    addr = srv.server.socket.address;
    var host_buf: [32]u8 = undefined;
    const host_text = try std.fmt.bufPrint(&host_buf, "{f}", .{addr});
    var fut = try io.concurrent(ScriptServer.serve, .{ &srv, io });
    defer {
        fut.cancel(io);
        srv.server.deinit(io);
    }
    var shared: Shared = .{};
    var c = try Client.init(std.testing.allocator, io, &shared, host_text, .insecure_plain_http);
    c.pair_min_interval_ms = 60_000; // only a cancel can end the wait in time
    const Cancel = struct {
        var client: *Client = undefined;
        fn f(_: *anyopaque) void {
            if (client.shared.status == .pair_waiting) client.cancelPairing();
        }
    };
    Cancel.client = &c;
    shared.wake_ctx = &shared;
    shared.wake_fn = Cancel.f;
    const t0 = watchdog.nowMs(io);
    try std.testing.expect(c.pairFlow() == .cancelled);
    try std.testing.expect(watchdog.nowMs(io) - t0 < 10_000);
}

test "pairing: waits are re-issued at once (long poll), and cancel ends a held wait" {
    var srv: ScriptServer = undefined;
    const io = std.testing.io;
    var addr: net.IpAddress = try .parseLiteral("127.0.0.1:0");
    // "" = hold the request without answering (the server's long poll).
    srv = .{ .server = try addr.listen(io, .{}), .replies = &.{ reply_requested, reply_waiting, reply_waiting, "" } };
    addr = srv.server.socket.address;
    var host_buf: [32]u8 = undefined;
    const host_text = try std.fmt.bufPrint(&host_buf, "{f}", .{addr});
    var fut = try io.concurrent(ScriptServer.serve, .{ &srv, io });
    defer {
        fut.cancel(io);
        srv.server.deinit(io);
    }
    var shared: Shared = .{};
    var c = try Client.init(std.testing.allocator, io, &shared, host_text, .insecure_plain_http);
    c.pair_min_interval_ms = 0; // a holding server: no floor
    const T = struct {
        fn cancelWhenHeld(cl: *Client, s: *ScriptServer, i: Io) void {
            // The fourth request (index 3) is the held one.
            while (s.n < 4) i.sleep(.fromMilliseconds(10), .awake) catch return;
            i.sleep(.fromMilliseconds(100), .awake) catch return;
            cl.cancelPairing();
        }
    };
    const t0 = watchdog.nowMs(io);
    var canceller = try io.concurrent(T.cancelWhenHeld, .{ &c, &srv, io });
    defer canceller.cancel(io);
    try std.testing.expect(c.pairFlow() == .cancelled);
    // Well before the 40 s request timeout: the cancel interrupted the held wait.
    try std.testing.expect(watchdog.nowMs(io) - t0 < 10_000);
    try std.testing.expectEqual(@as(usize, 4), srv.n);
}

/// A WebSocket server that completes the upgrade, then never reads or
/// writes again: the client's writes back up until the socket blocks.
const DeafServer = struct {
    server: net.Server,
    upgraded: Io.Event = .unset,

    fn serve(s: *DeafServer, io: Io) void {
        const conn = s.server.accept(io) catch return;
        defer conn.close(io);
        var buf: [2048]u8 = undefined;
        var len: usize = 0;
        while (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n") == null) {
            if (len == buf.len) return;
            var vec = [_][]u8{buf[len..]};
            const got = conn.readWithControl(io, &vec, &.{}) catch return;
            if (got.data_len == 0) return;
            len += got.data_len;
        }
        const head = buf[0..len];
        const name = "Sec-WebSocket-Key: ";
        const at = std.mem.indexOf(u8, head, name) orelse return;
        const rest = head[at + name.len ..];
        const key = rest[0 .. std.mem.indexOf(u8, rest, "\r\n") orelse return];
        const accept = ws.accept(key) catch return;
        var rb: [256]u8 = undefined;
        const reply = std.fmt.bufPrint(&rb, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{&accept}) catch return;
        var wb: [512]u8 = undefined;
        var w = conn.writer(io, &wb);
        w.interface.writeAll(reply) catch return;
        w.interface.flush() catch return;
        s.upgraded.set(io);
        io.sleep(.fromSeconds(60), .awake) catch {}; // deaf until the test ends
    }
};

test "stream: the idle timeout fires while a write is blocked, and input never blocks the caller" {
    const io = std.testing.io;
    var addr: net.IpAddress = try .parseLiteral("127.0.0.1:0");
    var srv: DeafServer = .{ .server = try addr.listen(io, .{}) };
    addr = srv.server.socket.address;
    var host_buf: [32]u8 = undefined;
    const host_text = try std.fmt.bufPrint(&host_buf, "{f}", .{addr});
    var fut = try io.concurrent(DeafServer.serve, .{ &srv, io });
    defer {
        fut.cancel(io);
        srv.server.deinit(io);
    }
    var shared: Shared = .{};
    const c = try std.testing.allocator.create(Client);
    defer std.testing.allocator.destroy(c);
    c.* = try Client.init(std.testing.allocator, io, &shared, host_text, .insecure_plain_http);
    c.idle_ms = 1500;
    c.ping_ms = 100; // pings fall due while the writer is stuck
    c.quiet = true; // the expected timeout stays off stderr
    var session = http.Cookie.fromValue(.session, tok43, false).?;
    const T = struct {
        fn stream(cl: *Client, sess: *const http.Cookie, done: *Io.Event, out: *Client.StreamResult) void {
            var backoff: i64 = 1000;
            out.* = cl.runStream(sess, &backoff);
            done.set(cl.io);
        }
    };
    var done: Io.Event = .unset;
    var result: Client.StreamResult = .unauthorized;
    const t0 = watchdog.nowMs(io);
    var st = try io.concurrent(T.stream, .{ c, &session, &done, &result });
    defer st.cancel(io);
    try srv.upgraded.wait(io);
    // Flood input from "the UI thread" until the stream gives up. Each
    // call must return at once (queued or refused), never wait on the socket.
    var payload: [ws.max_client_payload]u8 = undefined;
    @memset(&payload, 'x');
    var slowest: i64 = 0;
    var refused: usize = 0;
    while (!done.isSet()) {
        const a = watchdog.nowMs(io);
        if (!c.sendInput(&payload)) refused += 1;
        slowest = @max(slowest, watchdog.nowMs(io) - a);
        if (refused > 0) io.sleep(.fromMilliseconds(1), .awake) catch {};
        if (watchdog.nowMs(io) - t0 > 20_000) break;
    }
    try std.testing.expect(done.isSet());
    try std.testing.expect(result == .unreachable_err);
    try std.testing.expectEqual(error.TimedOut, result.unreachable_err);
    try std.testing.expect(watchdog.nowMs(io) - t0 < 10_000);
    try std.testing.expect(slowest < 500);
    try std.testing.expect(refused > 0); // the writer was stuck: the queue filled
    try std.testing.expect(!c.sendInput("k:enter")); // not connected any more
}

/// A WebSocket server whose program exits at once: hello, {"t":"exit"},
/// the closing handshake, then it waits for the client to close its end
/// (as Portal's wsGoodbye does).
const ExitServer = struct {
    server: net.Server,
    client_closed: Io.Event = .unset,

    fn serve(s: *ExitServer, io: Io) void {
        const conn = s.server.accept(io) catch return;
        defer conn.close(io);
        var buf: [2048]u8 = undefined;
        var len: usize = 0;
        while (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n") == null) {
            if (len == buf.len) return;
            var vec = [_][]u8{buf[len..]};
            const got = conn.readWithControl(io, &vec, &.{}) catch return;
            if (got.data_len == 0) return;
            len += got.data_len;
        }
        const head = buf[0..len];
        const name = "Sec-WebSocket-Key: ";
        const at = std.mem.indexOf(u8, head, name) orelse return;
        const rest = head[at + name.len ..];
        const key = rest[0 .. std.mem.indexOf(u8, rest, "\r\n") orelse return];
        const accept = ws.accept(key) catch return;
        var wb: [512]u8 = undefined;
        var w = conn.writer(io, &wb);
        w.interface.print("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{&accept}) catch return;
        ws.writeServerFrame(&w.interface, .text, "{\"t\":\"hello\",\"v\":1,\"input\":\"keys\"}") catch return;
        ws.writeServerFrame(&w.interface, .text, "{\"t\":\"exit\",\"code\":1}") catch return;
        ws.writeServerFrame(&w.interface, .close, "\x03\xe8session ended") catch return;
        w.interface.flush() catch return;
        // Until the client closes (EOF or a reset).
        while (true) {
            var vec = [_][]u8{&buf};
            const got = conn.readWithControl(io, &vec, &.{}) catch break;
            if (got.data_len == 0) break;
        }
        s.client_closed.set(io);
    }
};

test "stream: an exited program shows the ended session, then the desktop going away shows offline" {
    const io = std.testing.io;
    var addr: net.IpAddress = try .parseLiteral("127.0.0.1:0");
    var srv: ExitServer = .{ .server = try addr.listen(io, .{}) };
    addr = srv.server.socket.address;
    var host_buf: [32]u8 = undefined;
    const host_text = try std.fmt.bufPrint(&host_buf, "{f}", .{addr});
    var fut = try io.concurrent(ExitServer.serve, .{ &srv, io });
    var listening = true;
    defer {
        fut.cancel(io);
        if (listening) srv.server.deinit(io);
    }
    var shared: Shared = .{};
    const c = try std.testing.allocator.create(Client);
    defer std.testing.allocator.destroy(c);
    c.* = try Client.init(std.testing.allocator, io, &shared, host_text, .insecure_plain_http);
    c.quiet = true;
    var session: ?http.Cookie = http.Cookie.fromValue(.session, tok43, false).?;
    defer if (session) |*x| x.wipe();
    var backoff: i64 = 10;

    const r = c.runStream(&session.?, &backoff);
    try std.testing.expect(r == .exited);
    try std.testing.expectEqual(@as(i64, 1), r.exited);
    c.streamEnded(r, &session, &backoff);
    try std.testing.expectEqual(Status.session_ended, shared.status);
    try std.testing.expectEqualStrings("Session ended on the desktop (exit code 1)", shared.detail());
    try std.testing.expectEqual(@as(?i64, 1), shared.exit_code);
    try std.testing.expect(session != null); // kept: a restarted Portal answers 401, then sign-in
    // The client closed its end, so the server could close without a reset.
    try srv.client_closed.wait(io);
    // The next attempt does not flip the status to "connecting".
    try std.testing.expect(c.quietAttempt());

    // Portal exits: nothing listens any more.
    fut.await(io);
    srv.server.deinit(io);
    listening = false;
    const r2 = c.runStream(&session.?, &backoff);
    try std.testing.expect(r2 == .unreachable_err);
    c.streamEnded(r2, &session, &backoff);
    try std.testing.expectEqual(Status.desktop_offline, shared.status);
    try std.testing.expectEqualStrings(offline_text, shared.detail());
    try std.testing.expectEqual(@as(?i64, 1), shared.exit_code); // still says what ended
    try std.testing.expect(c.quietAttempt());
}

test "classify: desktop offline vs network error vs anything else" {
    try std.testing.expectEqual(Reach.desktop_offline, classify(error.ConnectionRefused));
    try std.testing.expectEqual(Reach.desktop_offline, classify(error.TimedOut));
    try std.testing.expectEqual(Reach.network_error, classify(error.NetworkUnreachable));
    try std.testing.expectEqual(Reach.network_error, classify(error.HostUnreachable));
    try std.testing.expectEqual(Reach.other, classify(error.NotIssuedByPinnedCa));
    try std.testing.expectEqual(Reach.other, classify(error.ConnectionResetByPeer));
    var b: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Session ended on the desktop (exit code -1)", endedText(-1, &b));
}
