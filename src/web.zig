//! HTTP + WebSocket front end.
//!
//! Request pipeline (every request):
//!   1. Host header must be on the allowlist        (DNS rebinding)
//!   2. Framing checks (no Transfer-Encoding, Expect, GET bodies, unknown
//!      methods); any problem closes the connection
//!   3. Route; unknown paths/methods are rejected
//!   4. State-changing requests and the WebSocket upgrade require an
//!      allowed Origin                              (CSRF / CSWSH)
//!   5. Anything beyond the pairing pages and static assets requires a live
//!      session cookie
//!
//! Pairing needs desk approval (devices.zig): POST /pair only registers a
//! request; the device's page (GET /pair/wait, a plain meta refresh) gets
//! its credential once the owner answers "y" in `portal pair`. Requests
//! before sign-in never touch the device file except to create or collect
//! a request: the pairing window is read from `pair_view`, which the
//! pairing watcher (main.zig) refreshes when the file changes. Every log
//! line a peer can cause before signing in is rate limited (`LogLimiter`).
//!
//! The web side can only (a) watch the session's output and (b) send
//! keystrokes that pass the input filter into that same session. There is no
//! route that starts a process, changes directory, or touches files.
//!
//! Connection model. Every accepted connection gets a supervisor thread and
//! a worker task (`io.concurrent`). The worker does all socket I/O; the
//! supervisor enforces deadlines (head/body read, keep-alive idle, stuck
//! sends), evictions and session revocation by cancelling the worker, which
//! makes a blocked recv/send return error.Canceled. The supervisor sleeps
//! until the earliest of those deadlines or until it is signalled (a
//! deadline moved earlier, eviction, a revocation, the worker finishing):
//! an idle connection costs no wakeups. Sockets are only closed
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
const web_images = @import("web_images.zig");

extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;

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
const no_deadline = std.math.maxInt(i64);
/// Pre-auth log lines: at most `burst` per this interval per kind.
const pre_auth_log_interval_ms = 10_000;
/// The waiting page re-asks for its outcome this often (meta refresh).
const pair_wait_refresh_s = 2;
/// Per-WebSocket input limits (messages and bytes per second, with bursts
/// twice that). Answering prompts needs a few per second; more is dropped.
pub const input_msgs_per_s = 40;
pub const input_bytes_per_s = 16 * 1024;

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
    /// "AB:CD:..." SHA-256 of the Portal CA, shown on the pairing pages
    /// while a window is open (null without TLS).
    ca_fingerprint: ?[]const u8 = null,
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

/// "Log at most `burst` lines per interval, and say how many were
/// suppressed."
pub const LogLimiter = struct {
    window_start: i64 = std.math.minInt(i64),
    count: u32 = 0,
    suppressed: u32 = 0,
    burst: u32 = 1,

    /// Returns the number of suppressed events if this one should be logged.
    pub fn check(l: *LogLimiter, now_ms: i64, interval_ms: i64) ?u32 {
        if (now_ms -| l.window_start >= interval_ms) {
            l.window_start = now_ms;
            l.count = 0;
        }
        if (l.count < l.burst) {
            l.count += 1;
            const n = l.suppressed;
            l.suppressed = 0;
            return n;
        }
        l.suppressed +|= 1;
        return null;
    }
};

/// Token bucket in milli-units: `rate` per second, holding at most `burst`.
pub const Bucket = struct {
    rate: i64,
    burst: i64,
    level_m: i64,
    last_ms: ?i64 = null,

    pub fn init(rate: i64, burst: i64) Bucket {
        return .{ .rate = rate, .burst = burst, .level_m = burst * 1000 };
    }

    fn refill(b: *Bucket, now_ms: i64) void {
        if (b.last_ms) |last| {
            // A clock that went back refills nothing; a long gap refills fully.
            const dt = std.math.clamp(now_ms -| last, 0, 3_600_000);
            b.level_m = @min(b.burst * 1000, b.level_m +| dt *| b.rate);
        }
        b.last_ms = now_ms;
    }

    fn has(b: *const Bucket, n: i64) bool {
        return b.level_m >= n *| 1000;
    }
};

/// Per-connection input limit: a message must fit both buckets.
pub const InputLimit = struct {
    msgs: Bucket = .init(input_msgs_per_s, 2 * input_msgs_per_s),
    bytes: Bucket = .init(input_bytes_per_s, 2 * input_bytes_per_s),

    pub fn allow(l: *InputLimit, now_ms: i64, len: usize) bool {
        l.msgs.refill(now_ms);
        l.bytes.refill(now_ms);
        const n: i64 = @intCast(len);
        if (!l.msgs.has(1) or !l.bytes.has(n)) return false;
        l.msgs.level_m -= 1000;
        l.bytes.level_m -= n * 1000;
        return true;
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
    /// The supervisor's wake event and when it next plans to wake: moving
    /// the deadline earlier than that signals it.
    wake: *Io.Event,
    io: Io,
    sup_until: std.atomic.Value(i64) = .init(no_deadline),
    /// Times the supervisor woke up (for the wakeup measurement in the log).
    sup_wakes: std.atomic.Value(u32) = .init(0),
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
        c.deadline_ms.store(ms, .seq_cst);
        if (ms < c.sup_until.load(.seq_cst)) c.wake.set(c.io);
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
    origin_log: LogLimiter = .{},
    pair_log: LogLimiter = .{ .burst = 8 },
    signin_log: LogLimiter = .{ .burst = 4 },
    ca_log: LogLimiter = .{ .burst = 4 },
    store_log: LogLimiter = .{},
    input_log: LogLimiter = .{},
    thread_log: LogLimiter = .{},

    /// The pairing window as last read from the device store, by the
    /// pairing watcher or by a handler that just changed it. Requests
    /// before sign-in read only this, never the file.
    pair_mutex: Io.Mutex = .init,
    pair_view: ?devices.Pairing = null,
    /// A window whose `portal pair` process has exited: treated as closed.
    pair_dead_nonce: ?u64 = null,
    /// Times the pairing watcher woke up (for the wakeup measurement).
    pairwatch_wakes: std.atomic.Value(u32) = .init(0),
    /// Optional hook, like Session.notify_fn: called whenever the pairing
    /// view may have changed (a window opened or closed, a request arrived
    /// or was answered), on the changing thread with no lock held. The
    /// Portal window uses it to redraw its approval UI. Set before any
    /// thread starts.
    pairing_notify_ctx: ?*anyopaque = null,
    pairing_notify_fn: ?*const fn (ctx: *anyopaque) void = null,

    /// Makes `run` return (the pairing-time download listener is stopped
    /// this way, together with cancelling its accept).
    stop: std.atomic.Value(bool) = .init(false),

    fn cookieName(srv: *const Server) []const u8 {
        return if (srv.cfg.secure_cookie) "__Host-portal" else "portal_session";
    }

    fn deviceCookieName(srv: *const Server) []const u8 {
        return if (srv.cfg.secure_cookie) "__Host-portal_device" else "portal_device";
    }

    fn pairReqCookieName(srv: *const Server) []const u8 {
        return if (srv.cfg.secure_cookie) "__Host-portal_pairreq" else "portal_pairreq";
    }

    fn nowUnix(srv: *const Server) i64 {
        return Io.Timestamp.now(srv.io, .real).toSeconds();
    }

    /// Monotonic ms: connection deadlines and rate limits.
    fn nowMs(srv: *const Server) i64 {
        return Io.Timestamp.now(srv.io, .awake).toMilliseconds();
    }

    /// Wall-clock ms: session lifetimes, so time the desktop spends asleep
    /// counts (auth.Sessions fails closed if this clock goes backwards).
    fn realMs(srv: *const Server) i64 {
        return Io.Timestamp.now(srv.io, .real).toMilliseconds();
    }

    pub fn sessionLive(srv: *Server, cookie: []const u8, refresh: bool) bool {
        srv.auth_mutex.lockUncancelable(srv.io);
        defer srv.auth_mutex.unlock(srv.io);
        const now = srv.realMs();
        return if (refresh) srv.sessions.validate(cookie, now) else srv.sessions.isLive(cookie, now);
    }

    /// Milliseconds until session `cookie` expires unless refreshed, or null
    /// if it is no longer live.
    fn sessionExpiresIn(srv: *Server, cookie: []const u8) ?i64 {
        srv.auth_mutex.lockUncancelable(srv.io);
        defer srv.auth_mutex.unlock(srv.io);
        const now = srv.realMs();
        const at = srv.sessions.expiresAt(cookie, now) orelse return null;
        return @max(at -| now, 0);
    }

    /// After any revocation: every WebSocket writer and supervisor re-checks
    /// its session now (they do not poll).
    fn wakeViewers(srv: *Server) void {
        const s = srv.session;
        s.mutex.lockUncancelable(srv.io);
        s.mutex.unlock(srv.io);
        s.cond.broadcast(srv.io);
        for (&srv.conn_wake) |*e| e.set(srv.io);
    }

    /// Logs a line a peer can cause before signing in, at most `lim.burst`
    /// per interval, noting how many were suppressed.
    fn notePreAuth(srv: *Server, lim: *LogLimiter, comptime fmt: []const u8, args: anytype) void {
        srv.note_mutex.lockUncancelable(srv.io);
        const n = lim.check(srv.nowMs(), pre_auth_log_interval_ms);
        srv.note_mutex.unlock(srv.io);
        const suppressed = n orelse return;
        if (suppressed == 0) {
            srv.log.print(fmt, args);
        } else {
            srv.log.print(fmt ++ " ({d} similar lines suppressed)", args ++ .{suppressed});
        }
    }

    // ------------------------------------------------- pairing window view

    /// Replaces the cached pairing window (called with the store's state
    /// right after reading or changing it).
    pub fn setPairing(srv: *Server, p: ?devices.Pairing) void {
        srv.pair_mutex.lockUncancelable(srv.io);
        srv.pair_view = p;
        srv.pair_mutex.unlock(srv.io);
        srv.notifyPairing();
    }

    fn notifyPairing(srv: *Server) void {
        if (srv.pairing_notify_fn) |f| if (srv.pairing_notify_ctx) |c| f(c);
    }

    /// The `portal pair` that owns window `nonce` has exited.
    pub fn pairingProcessGone(srv: *Server, nonce: u64) void {
        srv.pair_mutex.lockUncancelable(srv.io);
        srv.pair_dead_nonce = nonce;
        srv.pair_mutex.unlock(srv.io);
        srv.notifyPairing();
    }

    // ------------------------------------------- desk approval, in-process
    //
    // The same operations `portal pair` performs, for the Portal window:
    // open a window, list who asks, approve or deny, cancel. They change
    // the device store (devices.Desk) and refresh `pair_view` at once;
    // `pairing_notify_fn` reports every change, including requests that
    // devices make. Callable from any thread (e.g. the GUI thread); each
    // call is one short locked file update.

    fn desk(srv: *Server) devices.Desk {
        return .{ .gpa = srv.gpa, .io = srv.io, .paths = srv.cfg.devices };
    }

    fn refreshPairing(srv: *Server) void {
        var st: devices.Store = .{};
        devices.withStore(srv.gpa, srv.io, srv.cfg.devices, srv.nowUnix(), &st, struct {
            fn op(o: *devices.Store, s: *devices.Store) !bool {
                o.* = s.*;
                return false;
            }
        }.op) catch |err| return srv.noteStoreError(err);
        srv.setPairing(st.pairing);
    }

    /// Opens a pairing window for device `name` for `window_s` seconds
    /// (10..600), owned by this process. Returns the window's nonce.
    pub fn deskBegin(srv: *Server, name: []const u8, window_s: i64) !u64 {
        var b: [8]u8 = undefined;
        try srv.io.randomSecure(&b);
        const nonce = std.mem.readInt(u64, &b, .little) | 1;
        _ = try srv.desk().begin(name, window_s, nonce, GetCurrentProcessId());
        srv.log.print("pairing window opened for '{s}' ({d} s) from the Portal window", .{ name, window_s });
        srv.refreshPairing();
        return nonce;
    }

    /// The open window and its requests (codes, addresses, states, `created`
    /// times for the age), from memory; null if none is open.
    pub fn deskWindow(srv: *Server) ?devices.Pairing {
        return srv.pairingSnapshot(srv.nowUnix());
    }

    /// Approves (`approve`) or denies request `code` of the open window.
    /// Approving one denies the other pending requests.
    pub fn deskAnswer(srv: *Server, code: []const u8, approve: bool) !devices.AnswerResult {
        const p = srv.deskWindow() orelse return .window_gone;
        const r = try srv.desk().answer(p.nonce, code, approve);
        if (r == .approved or r == .denied) srv.log.print("pairing request {s} for '{s}' {s} at the desk", .{ code, p.name.get(), if (approve) "approved" else "denied" });
        srv.refreshPairing();
        return r;
    }

    /// Closes the open window, if any.
    pub fn deskCancel(srv: *Server) !void {
        const p = srv.deskWindow() orelse return;
        try srv.desk().cancel(p.nonce);
        srv.refreshPairing();
    }

    /// The open pairing window, if any (memory only).
    pub fn pairingSnapshot(srv: *Server, now_s: i64) ?devices.Pairing {
        srv.pair_mutex.lockUncancelable(srv.io);
        defer srv.pair_mutex.unlock(srv.io);
        const p = srv.pair_view orelse return null;
        if (now_s > p.expires) return null;
        if (srv.pair_dead_nonce) |d| if (d == p.nonce) return null;
        return p;
    }

    /// Called by the pairing watcher with a freshly read store: caches the
    /// window and ends the sessions of devices that are no longer paired
    /// (e.g. `portal unpair` in another process). Only a successful read
    /// gets here, so a store error never revokes anyone. `read_start_ms`
    /// (wall clock before the read) protects sessions created meanwhile.
    pub fn applyStore(srv: *Server, st: *const devices.Store, read_start_ms: i64) void {
        srv.setPairing(st.pairing);
        srv.auth_mutex.lockUncancelable(srv.io);
        const n = srv.sessions.revokeUnpaired(read_start_ms, st, struct {
            fn paired(s: *const devices.Store, tag: []const u8) bool {
                return s.find(tag) != null;
            }
        }.paired);
        srv.auth_mutex.unlock(srv.io);
        if (n > 0) {
            srv.log.print("ended {d} session(s) of devices that are no longer paired", .{n});
            srv.wakeViewers();
        }
    }

    pub fn realNowMs(srv: *const Server) i64 {
        return srv.realMs();
    }

    /// The pairing watcher could not read the store: say so (rate
    /// limited), revoke nothing, keep the last known window.
    pub fn noteStoreError(srv: *Server, err: anyerror) void {
        srv.notePreAuth(&srv.store_log, "device store unreadable ({t}): {s}", .{ err, devices.describeError(err) });
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
            .wake = &srv.conn_wake[slot],
            .io = io,
        };
        const peer = std.fmt.bufPrint(&conn.peer_buf, "{f}", .{stream.socket.address}) catch blk: {
            conn.peer_buf[0] = '?';
            break :blk conn.peer_buf[0..1];
        };
        conn.peer_len = peer.len;

        var worker = io.concurrent(connMain, .{ srv, &conn }) catch {
            srv.notePreAuth(&srv.thread_log, "connection from {s} dropped: no thread available", .{conn.peer()});
            return;
        };

        // Event-driven: sleeps until the earliest deadline (request/idle/
        // send watchdog, the WebSocket session's expiry, the revocation
        // grace), or until signalled: setDeadline moving the deadline
        // earlier, eviction, wakeViewers after a revocation, or the worker
        // finishing. Resetting the event before the checks, and checking
        // before waiting, means no signal is lost.
        var reason: ?[]const u8 = null;
        var revoked_since: ?i64 = null;
        while (true) {
            srv.conn_wake[slot].reset();
            if (conn.done.load(.acquire)) break;
            if (srv.conn_evict[slot].load(.acquire)) {
                reason = "evicted (too many unauthenticated connections)";
                break;
            }
            const now = srv.nowMs();
            const deadline = conn.deadline_ms.load(.seq_cst);
            if (now >= deadline) {
                reason = "timed out";
                break;
            }
            var until = deadline;
            if (conn.ws_active.load(.acquire)) {
                if (srv.sessionExpiresIn(&conn.ws_cookie)) |left| {
                    revoked_since = null;
                    until = @min(until, now +| @max(left, 1));
                } else if (revoked_since == null) {
                    revoked_since = now;
                }
            }
            if (revoked_since) |r| {
                if (now -| r >= revoke_grace_ms) {
                    reason = "signed out";
                    break;
                }
                until = @min(until, r +| revoke_grace_ms);
            }
            conn.sup_until.store(until, .seq_cst);
            // A deadline moved earlier between the load and the store above.
            if (conn.deadline_ms.load(.seq_cst) < until) continue;
            const timeout: Io.Timeout = if (until == no_deadline) .none else .{ .duration = .{
                .raw = .fromMilliseconds(@max(until -| now, 1)),
                .clock = .awake,
            } };
            srv.conn_wake[slot].waitTimeout(io, timeout) catch {};
            _ = conn.sup_wakes.fetchAdd(1, .monotonic);
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
        defer {
            // Plaintext buffers and traffic keys: wipe before the memory
            // goes back to the allocator.
            std.crypto.secureZero(u8, std.mem.asBytes(st));
            srv.gpa.destroy(st);
        }
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
            .bad_certificate, .unknown_ca, .certificate_unknown, .access_denied => " - that device does not trust the Portal CA yet (Export certificate in the Portal window, or `portalctl ca export`)",
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
        /// Pairing request token (only while a request is outstanding).
        pairreq: ?[]const u8 = null,
        content_type: ?[]const u8 = null,
    };

    fn collectHeaders(srv: *const Server, req: *const http1.Request, cookie_out: *[auth.encoded_len]u8, device_out: *[device_cookie_max]u8, pairreq_out: *[auth.encoded_len]u8) Headers {
        var h: Headers = .{ .host = req.host, .origin = req.origin, .content_type = req.content_type };
        var pit = req.cookieHeaders();
        while (pit.next()) |value| {
            if (guard.getCookie(value, srv.pairReqCookieName())) |v| {
                if (v.len == auth.encoded_len) {
                    @memcpy(pairreq_out, v);
                    h.pairreq = pairreq_out;
                    break;
                }
            }
        }
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
        var pairreq_buf: [auth.encoded_len]u8 = undefined;
        const h = srv.collectHeaders(req, &cookie_buf, &device_buf, &pairreq_buf);
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
                if (std.mem.eql(u8, path, "/pair/wait")) return srv.pairWait(conn, w, req, h);
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
                    srv.notePreAuth(&srv.origin_log, "rejected POST from {s}: bad origin", .{peer});
                    return srv.fail(conn, w, .forbidden, "bad origin\n");
                }
                if (std.mem.eql(u8, path, "/pair")) return srv.pairRequest(conn, w, req, h);
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
        var extra: [4]http1.Header = undefined;
        var n: usize = 0;
        extra[n] = .{ .name = "location", .value = location };
        n += 1;
        for (set_cookies[0..@min(set_cookies.len, 3)]) |c| {
            extra[n] = .{ .name = "set-cookie", .value = c };
            n += 1;
        }
        // Never reuse a connection after a POST.
        const keep = req.method == .GET and !req.connection_close;
        try srv.respond(conn, w, .see_other, "", "text/plain; charset=utf-8", extra[0..n], keep);
        return keep;
    }

    /// The pairing page around `head` (inside <head>), `msg` and `action`.
    fn renderPair(srv: *Server, head: []const u8, msg: []const u8, action: []const u8) ![]u8 {
        const marker_head = "<!--HEAD-->";
        const marker_msg = "<!--MESSAGE-->";
        const marker_act = "<!--ACTION-->";
        const i = comptime blk: {
            @setEvalBranchQuota(20_000);
            const a = std.mem.indexOf(u8, pair_html, marker_head).?;
            const b = std.mem.indexOf(u8, pair_html, marker_msg).?;
            const c = std.mem.indexOf(u8, pair_html, marker_act).?;
            std.debug.assert(a < b and b < c);
            break :blk .{ a, b, c };
        };
        const i_head = i[0];
        const i_msg = i[1];
        const i_act = i[2];
        return std.mem.concat(srv.gpa, u8, &.{
            pair_html[0..i_head],
            head,
            pair_html[i_head + marker_head.len .. i_msg],
            msg,
            pair_html[i_msg + marker_msg.len .. i_act],
            action,
            pair_html[i_act + marker_act.len ..],
        });
    }

    /// "Check the certificate" note for the pairing pages ("" without TLS).
    /// The fingerprint is Portal's own hex-and-colons text.
    fn fingerprintNote(srv: *const Server, buf: []u8) []const u8 {
        const fp = srv.cfg.ca_fingerprint orelse return "";
        return std.fmt.bufPrint(buf, "<p class=\"hint\">Portal CA SHA-256 (it must match what the desk shows while pairing):<br><code>{s}</code></p>", .{fp}) catch "";
    }

    fn pairPage(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request) !bool {
        const q = req.query;
        // Memory only: the pairing watcher keeps `pair_view` current.
        const view = srv.pairingSnapshot(srv.nowUnix());
        const msg: []const u8 = if (std.mem.eql(u8, q, "e=closed"))
            "<p class=\"error\">No pairing window is open. Open one at the desktop first (see below).</p>"
        else if (std.mem.eql(u8, q, "e=revoked"))
            "<p class=\"error\">This device's credential was used from somewhere else, so it was revoked. Pair it again at the desktop.</p>"
        else if (std.mem.eql(u8, q, "e=denied"))
            "<p class=\"error\">The desk did not approve this request. If that was a mistake, open <strong>Pair a device</strong> again in the Portal window at the desktop.</p>"
        else if (std.mem.eql(u8, q, "e=expired"))
            "<p class=\"error\">The pairing request expired, or the pairing window closed. Open <strong>Pair a device</strong> again in the Portal window at the desktop.</p>"
        else if (std.mem.eql(u8, q, "e=busy"))
            "<p class=\"error\">Too many pairing requests are waiting. Answer them at the desk, then try again.</p>"
        else if (std.mem.eql(u8, q, "bye"))
            "<p class=\"info\">This device was unpaired.</p>"
        else
            "";
        // The device name comes from the store and is [a-z0-9-] only
        // (devices.validName), so it is safe to place in HTML.
        var action_buf: [1024]u8 = undefined;
        var fp_buf: [256]u8 = undefined;
        const action: []const u8 = if (view != null and !view.?.decided())
            std.fmt.bufPrint(&action_buf, "<form method=\"post\" action=\"/pair\"><p>Pairing is open for <strong>{s}</strong>. " ++
                "After you tap the button, approve this device at the desk.</p>" ++
                "<button type=\"submit\">Pair this device</button></form>{s}", .{ view.?.name.get(), srv.fingerprintNote(&fp_buf) }) catch ""
        else
            "<p>This device is not paired yet. At the desktop, in the Portal window, choose <strong>Pair a device</strong> " ++
                "(Ctrl+Shift+P; in a terminal: <code>portalctl pair &lt;name&gt;</code>),</p>" ++
                "<p>then reload this page within 2 minutes.</p>";
        const page = try srv.renderPair("", msg, action);
        defer srv.gpa.free(page);
        return srv.asset(conn, w, req, page, "text/html; charset=utf-8");
    }

    /// The device's page while its request waits for the desk: shows the
    /// request code the desk sees and reloads itself (no script).
    fn pairWaitPage(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, view: *const devices.Pairing, r: *const devices.Request) !bool {
        var head_buf: [96]u8 = undefined;
        const head = try std.fmt.bufPrint(&head_buf, "<meta http-equiv=\"refresh\" content=\"{d}\">", .{pair_wait_refresh_s});
        var fp_buf: [256]u8 = undefined;
        var action_buf: [1024]u8 = undefined;
        // Name, address and code are validated by devices.zig ([a-z0-9-],
        // [0-9a-f.:%], [0-9a-f]): safe in HTML.
        const action = try std.fmt.bufPrint(&action_buf,
            \\<p>Waiting for approval at the desk.</p>
            \\<p>The desktop asks: <code>Pair '{s}' from {s} (request {s})?</code></p>
            \\<p class="code">Request code <strong>{s}</strong></p>
            \\<p>Approve it there only if the code matches. This page updates by itself.</p>{s}
        , .{ view.name.get(), r.ip.get(), &r.code, &r.code, srv.fingerprintNote(&fp_buf) });
        const page = try srv.renderPair(head, "", action);
        defer srv.gpa.free(page);
        // The code also as a header, for native clients (portal connect),
        // which read only the response head.
        const keep = !req.connection_close;
        try srv.respond(conn, w, .ok, page, "text/html; charset=utf-8", &.{.{ .name = "x-portal-request-code", .value = &r.code }}, keep);
        return keep;
    }

    /// The pairing-time download listener (plain HTTP on port+1): the CA
    /// certificate as an Apple profile and as DER, plus a page linking them.
    fn caDownload(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, d: *const CaDownload) !bool {
        if (req.method != .GET) return srv.fail(conn, w, .method_not_allowed, "method not allowed\n");
        const path = req.path;
        if (std.mem.eql(u8, path, "/ca.mobileconfig") or std.mem.eql(u8, path, "/ca.cer")) {
            const profile = path[4] == 'm';
            srv.notePreAuth(&srv.ca_log, "CA certificate downloaded by {s}: {s}", .{ conn.peer(), path });
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
            \\<p>Check the fingerprint (SHA-256) matches what the desk shows (Pair a device or Export certificate in the Portal window):<br><code>{s}</code></p>
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
        srv.sessions.createTagged(&session_val, srv.realMs(), name);
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

    fn clearPairReq(srv: *Server, buf: *[128]u8) ![]const u8 {
        const secure = if (srv.cfg.secure_cookie) "; Secure" else "";
        return std.fmt.bufPrint(buf, "{s}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{s}", .{ srv.pairReqCookieName(), secure });
    }

    fn noteStoreFailure(srv: *Server, what: []const u8, peer: []const u8, err: anyerror) void {
        srv.notePreAuth(&srv.store_log, "{s} from {s} failed: {t}: {s}", .{ what, peer, err, devices.describeError(err) });
    }

    /// POST /pair: registers a pairing request from this device's address,
    /// to be approved or denied at the desk (`portal pair`). Nothing is
    /// issued here; the device's page then waits at /pair/wait.
    fn pairRequest(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, h: Headers) !bool {
        const peer = conn.peer();
        const ip = devices.ipOnly(peer);
        const now = srv.nowUnix();
        const view = srv.pairingSnapshot(now) orelse {
            srv.notePreAuth(&srv.pair_log, "pairing attempt from {s}: no window open", .{peer});
            return srv.redirect(conn, w, req, "/pair?e=closed", &.{});
        };
        // Tapped again while waiting: keep the request it already has.
        if (h.pairreq) |tok| if (view.findToken(auth.hashSecret(tok))) |i| {
            const r = view.requests[i].?;
            if (r.state == .pending and std.mem.eql(u8, r.ip.get(), ip)) return srv.redirect(conn, w, req, "/pair/wait", &.{});
        };
        if (view.decided()) {
            srv.notePreAuth(&srv.pair_log, "pairing attempt from {s}: the window already approved a device", .{peer});
            return srv.redirect(conn, w, req, "/pair?e=closed", &.{});
        }

        var token: [auth.encoded_len]u8 = undefined;
        srv.newSecret(&token) catch return srv.fail(conn, w, .internal_server_error, "no entropy\n");
        defer std.crypto.secureZero(u8, &token);
        var code: [devices.code_len]u8 = undefined;
        var refused: ?devices.RequestError = null;
        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            var rnd: [2]u8 = undefined;
            srv.io.randomSecure(&rnd) catch return srv.fail(conn, w, .internal_server_error, "no entropy\n");
            _ = std.fmt.bufPrint(&code, "{x:0>4}", .{std.mem.readInt(u16, &rnd, .little)}) catch unreachable;
            refused = null;
            const Ctx = struct { srv: *Server, ip: []const u8, token: auth.Hash, code: [devices.code_len]u8, now: i64, refused: *?devices.RequestError };
            devices.withStore(srv.gpa, srv.io, srv.cfg.devices, now, Ctx{
                .srv = srv,
                .ip = ip,
                .token = auth.hashSecret(&token),
                .code = code,
                .now = now,
                .refused = &refused,
            }, struct {
                fn op(c: Ctx, st: *devices.Store) !bool {
                    defer c.srv.setPairing(st.pairing);
                    st.addRequest(c.ip, c.token, c.code, c.now) catch |e| {
                        c.refused.* = e;
                        return false;
                    };
                    return true;
                }
            }.op) catch |err| {
                srv.noteStoreFailure("pairing request", peer, err);
                return srv.fail(conn, w, .internal_server_error, "device store unavailable\n");
            };
            if (refused) |e| if (e == error.DuplicateCode and attempt < 3) continue;
            break;
        }
        if (refused) |e| {
            srv.notePreAuth(&srv.pair_log, "pairing request from {s} refused: {t}", .{ peer, e });
            return srv.redirect(conn, w, req, switch (e) {
                error.AddressDenied => "/pair?e=denied",
                error.TooManyRequests, error.TooManyFromAddress, error.DuplicateCode => "/pair?e=busy",
                error.NoPairingWindow, error.WindowDecided, error.BadAddress => "/pair?e=closed",
            }, &.{});
        }
        srv.notePreAuth(&srv.pair_log, "pairing request {s} for '{s}' from {s}: waiting for approval at the desk", .{ &code, view.name.get(), ip });
        var cbuf: [160]u8 = undefined;
        const secure = if (srv.cfg.secure_cookie) "; Secure" else "";
        const cookie = try std.fmt.bufPrint(&cbuf, "{s}={s}; Path=/; HttpOnly; SameSite=Strict; Max-Age={d}{s}", .{
            srv.pairReqCookieName(), &token, devices.max_pair_window_s, secure,
        });
        return srv.redirect(conn, w, req, "/pair/wait", &.{cookie});
    }

    /// GET /pair/wait: the requesting device asks for its outcome (its page
    /// reloads itself). Pending: the waiting page. Approved at the desk:
    /// the device credential and a session, once, to the same address and
    /// request token only. Denied or gone: back to /pair with the reason.
    fn pairWait(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, h: Headers) !bool {
        const peer = conn.peer();
        const ip = devices.ipOnly(peer);
        const now = srv.nowUnix();
        var clear_buf: [128]u8 = undefined;
        const clear = try srv.clearPairReq(&clear_buf);
        const tok = h.pairreq orelse return srv.redirect(conn, w, req, "/pair?e=expired", &.{});
        const tok_hash = auth.hashSecret(tok);
        const view = srv.pairingSnapshot(now) orelse return srv.redirect(conn, w, req, "/pair?e=expired", &.{clear});
        const i = view.findToken(tok_hash) orelse return srv.redirect(conn, w, req, "/pair?e=expired", &.{clear});
        const r = view.requests[i].?;
        if (!std.mem.eql(u8, r.ip.get(), ip)) return srv.redirect(conn, w, req, "/pair?e=expired", &.{clear});
        switch (r.state) {
            .pending => return srv.pairWaitPage(conn, w, req, &view, &r),
            .denied => return srv.redirect(conn, w, req, "/pair?e=denied", &.{clear}),
            .done => return srv.redirect(conn, w, req, "/pair?e=expired", &.{clear}),
            .approved => {},
        }

        // Approved at the desk: collect the credential.
        var secret: [auth.encoded_len]u8 = undefined;
        srv.newSecret(&secret) catch return srv.fail(conn, w, .internal_server_error, "no entropy\n");
        defer std.crypto.secureZero(u8, &secret);
        const Outcome = enum { pending, denied, unknown, paired };
        var outcome: Outcome = .unknown;
        var name_buf: [devices.max_name]u8 = undefined;
        var name_len: usize = 0;
        const Ctx = struct { srv: *Server, token: auth.Hash, ip: []const u8, hash: auth.Hash, now: i64, outcome: *Outcome, name: *[devices.max_name]u8, len: *usize };
        devices.withStore(srv.gpa, srv.io, srv.cfg.devices, now, Ctx{
            .srv = srv,
            .token = tok_hash,
            .ip = ip,
            .hash = auth.hashSecret(&secret),
            .now = now,
            .outcome = &outcome,
            .name = &name_buf,
            .len = &name_len,
        }, struct {
            fn op(c: Ctx, st: *devices.Store) !bool {
                defer c.srv.setPairing(st.pairing);
                switch (try st.claim(c.token, c.ip, c.hash, c.now)) {
                    .paired => |n| {
                        @memcpy(c.name[0..n.len], n);
                        c.len.* = n.len;
                        c.outcome.* = .paired;
                        return true;
                    },
                    .pending => c.outcome.* = .pending,
                    .denied => c.outcome.* = .denied,
                    .unknown => c.outcome.* = .unknown,
                }
                return false;
            }
        }.op) catch |err| {
            srv.noteStoreFailure("pairing", peer, err);
            return srv.fail(conn, w, .internal_server_error, if (err == error.TooManyDevices) "too many paired devices: unpair one at the desk\n" else "device store unavailable\n");
        };
        switch (outcome) {
            .paired => {},
            .pending => return srv.pairWaitPage(conn, w, req, &view, &r),
            .denied => return srv.redirect(conn, w, req, "/pair?e=denied", &.{clear}),
            .unknown => return srv.redirect(conn, w, req, "/pair?e=expired", &.{clear}),
        }
        const name = name_buf[0..name_len];
        srv.log.print("PAIRED device '{s}' at {s} (request {s}, approved at the desk)", .{ name, ip, &r.code });
        var cookies: CookiePair = .{};
        try srv.issueCookies(name, &secret, &cookies);
        return srv.redirect(conn, w, req, "/", &.{ cookies.device, cookies.session, clear });
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
                        st.rotate(idx, c.hash, c.now);
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
            srv.noteStoreFailure("device sign-in", peer, err);
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
                srv.wakeViewers();
                srv.log.print("DEVICE REVOKED '{s}': stale or wrong credential presented from {s} (copied credential?). Re-pair required.", .{ name, peer });
            },
            // Logged here only: the response is the same for both, so a
            // peer can't use it to learn which device names exist.
            .wrong_address => srv.notePreAuth(&srv.signin_log, "device credential presented from unexpected address {s}; rejected", .{peer}),
            .unknown => srv.notePreAuth(&srv.signin_log, "device credential from {s} matches no paired device; rejected", .{peer}),
        }
        var clear_buf: [2][128]u8 = undefined;
        const clear = try srv.clearCookies(&clear_buf);
        switch (mode) {
            .page => return srv.redirect(conn, w, req, if (outcome == .revoked) "/pair?e=revoked" else "/pair", &clear),
            .api => return srv.fail(conn, w, .unauthorized, "not paired\n"),
        }
    }

    /// POST /logout ("Unpair this device"): removes the device and its
    /// sessions. With an expired session, the device credential still
    /// identifies the device (checked like a sign-in, then removed).
    fn logout(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, h: Headers) !bool {
        const peer = conn.peer();
        var tag_buf: [auth.Sessions.max_tag]u8 = undefined;
        var name: []const u8 = "";
        if (h.cookie) |c| {
            srv.auth_mutex.lockUncancelable(srv.io);
            name = srv.sessions.liveTag(c, srv.realMs(), false, &tag_buf) orelse "";
            srv.sessions.revoke(c);
            srv.auth_mutex.unlock(srv.io);
        }
        const Outcome = enum { none, removed, revoked };
        var outcome: Outcome = .none;
        var name_buf: [devices.max_name]u8 = undefined;
        var name_len: usize = 0;
        const Ctx = struct { name: []const u8, device: ?[]const u8, ip: []const u8, now: i64, outcome: *Outcome, out: *[devices.max_name]u8, len: *usize };
        devices.withStore(srv.gpa, srv.io, srv.cfg.devices, srv.nowUnix(), Ctx{
            .name = name,
            .device = h.device,
            .ip = devices.ipOnly(peer),
            .now = srv.nowUnix(),
            .outcome = &outcome,
            .out = &name_buf,
            .len = &name_len,
        }, struct {
            fn op(c: Ctx, st: *devices.Store) !bool {
                if (c.name.len > 0) {
                    const n = @min(c.name.len, devices.max_name);
                    @memcpy(c.out[0..n], c.name[0..n]);
                    c.len.* = n;
                    _ = st.remove(c.name); // already gone counts as unpaired too
                    c.outcome.* = .removed;
                    return true;
                }
                const d = c.device orelse return false;
                switch (st.authenticate(d, c.ip, c.now)) {
                    .ok => |idx| {
                        const n = st.devices[idx].?.name.get();
                        @memcpy(c.out[0..n.len], n);
                        c.len.* = n.len;
                        st.devices[idx] = null;
                        c.outcome.* = .removed;
                        return true;
                    },
                    .revoked => |n| {
                        const m = @min(n.len, devices.max_name);
                        @memcpy(c.out[0..m], n[0..m]);
                        c.len.* = m;
                        c.outcome.* = .revoked;
                        return true;
                    },
                    .wrong_address, .unknown => return false,
                }
            }
        }.op) catch |err| {
            srv.noteStoreFailure("unpair", peer, err);
            return srv.fail(conn, w, .internal_server_error, "device store unavailable: the device was NOT unpaired\n");
        };
        const removed_name = name_buf[0..name_len];
        if (removed_name.len > 0) {
            srv.auth_mutex.lockUncancelable(srv.io);
            srv.sessions.revokeTag(removed_name);
            srv.auth_mutex.unlock(srv.io);
            srv.wakeViewers();
        }
        var clear_buf: [2][128]u8 = undefined;
        const clear = try srv.clearCookies(&clear_buf);
        switch (outcome) {
            .removed => {
                srv.log.print("device '{s}' unpaired itself from {s}", .{ removed_name, peer });
                return srv.redirect(conn, w, req, "/pair?bye", &clear);
            },
            .revoked => {
                srv.log.print("DEVICE REVOKED '{s}': stale or wrong credential presented from {s} (copied credential?). Re-pair required.", .{ removed_name, peer });
                return srv.redirect(conn, w, req, "/pair?e=revoked", &clear);
            },
            .none => return srv.redirect(conn, w, req, "/pair", &clear),
        }
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
        /// Reader only: per-connection input rate limit.
        limit: InputLimit = .{},
        /// Writer loop iterations (for the wakeup measurement in the log).
        writer_wakes: u32 = 0,

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
            srv.notePreAuth(&srv.origin_log, "websocket rejected from {s}: bad origin", .{peer});
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
            const tag = srv.sessions.liveTag(cookie, srv.realMs(), false, &ws.device) orelse "";
            ws.device_len = @intCast(tag.len);
        }
        @memcpy(&conn.ws_cookie, cookie);
        conn.ws_active.store(true, .release);
        conn.wake.set(srv.io); // the supervisor now also watches the session

        const viewers = srv.session.viewerDelta(1);
        srv.log.print("viewer connected from {s} ({d} watching)", .{ peer, viewers });
        srv.updateTitle(viewers);
        const pairwatch_before = srv.pairwatch_wakes.load(.monotonic);
        const sup_before = conn.sup_wakes.load(.monotonic);
        defer {
            const left = srv.session.viewerDelta(-1);
            // Wakeup counts make idle cost visible (and testable): an idle
            // viewer should cost no periodic wakeups at all.
            srv.log.print("viewer disconnected from {s} ({d} watching; wakeups while connected: supervisor {d}, writer {d}, pairing watcher {d})", .{
                peer,                                        left,
                conn.sup_wakes.load(.monotonic) -% sup_before, ws.writer_wakes,
                srv.pairwatch_wakes.load(.monotonic) -% pairwatch_before,
            });
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
        // Inline images: 'I' blobs and 'P' placements (web_images.zig).
        var images: web_images.Sender = .{ .last_ms = srv.nowMs() };
        defer images.deinit(srv.gpa);

        const hello = std.fmt.bufPrint(&msg, "{{\"t\":\"hello\",\"input\":\"{t}\"}}", .{s.policy}) catch return;
        if (!ws.send(srv, hello, .text)) return;

        // Generation of the emulator state last sent; 0 plus `full` forces a
        // complete snapshot first (docs/protocol.md section 3).
        var sent_gen: u64 = 0;
        var full = true;
        var sent_cols: u16 = 0;
        var sent_rows: u16 = 0;
        while (true) {
            ws.writer_wakes +|= 1;
            // Event-driven: wakes on output, resize, close, the reader
            // ending, or a revocation (wakeViewers); otherwise sleeps until
            // the session would expire. No periodic recheck.
            const expires_in = srv.sessionExpiresIn(&ws.cookie) orelse 0;
            s.mutex.lockUncancelable(srv.io);
            if (!s.closed and !full and s.term.gen == sent_gen and !ws.dead.load(.acquire) and expires_in > 0) {
                s.cond.waitTimeout(srv.io, &s.mutex, .{ .duration = .{
                    // Until the session expires, or sooner while an image
                    // blob is waiting for this viewer's byte budget.
                    .raw = .fromMilliseconds(if (images.pending) @min(expires_in, web_images.retry_ms) else expires_in),
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
            if (encode_ok) images.collect(srv.gpa, t, srv.nowMs()) catch {
                encode_ok = false;
            };
            const closed = s.closed;
            const exit_code = s.exit_code;
            s.mutex.unlock(srv.io);

            if (ws.dead.load(.acquire)) return;
            if (!encode_ok) return; // out of memory: drop this viewer, keep the session

            if (changed) {
                if (!ws.send(srv, frame.items, .binary)) return;
            }
            var image_frames = images.frames();
            while (image_frames.next()) |f| if (!ws.send(srv, f, .binary)) return;
            if (!changed and closed) {
                const m = std.fmt.bufPrint(&msg, "{{\"t\":\"exit\",\"code\":{d}}}", .{exit_code}) catch return;
                _ = ws.send(srv, m, .text);
                return;
            }

            // Logout, expiry, or the device being unpaired (possibly by
            // `portal unpair` in another process: the pairing watcher then
            // ends its sessions and wakes this loop) ends the stream.
            // Checked on every wake; memory only.
            if (!srv.sessionLive(&ws.cookie, false)) {
                _ = ws.send(srv, "{\"t\":\"logout\"}", .text);
                return;
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
            .ping, .text, .binary => if (!ws.limit.allow(srv.nowMs(), payload.len)) {
                // A paired device flooding input (or pings): drop the excess
                // rather than let it queue behind a slow PTY write.
                srv.notePreAuth(&srv.input_log, "input from {s} over the rate limit; dropped", .{ws.conn.peer()});
                return true;
            },
            else => {},
        }
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
    _ = web_images;
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

test "log limiter with a burst" {
    var l: LogLimiter = .{ .burst = 3 };
    try testing.expectEqual(@as(?u32, 0), l.check(0, 1000));
    try testing.expectEqual(@as(?u32, 0), l.check(1, 1000));
    try testing.expectEqual(@as(?u32, 0), l.check(2, 1000));
    try testing.expectEqual(@as(?u32, null), l.check(3, 1000));
    try testing.expectEqual(@as(?u32, null), l.check(4, 1000));
    try testing.expectEqual(@as(?u32, 2), l.check(1000, 1000));
    try testing.expectEqual(@as(?u32, 0), l.check(1001, 1000));
}

test "input limit: bursts pass, floods are cut to the rate" {
    var l: InputLimit = .{};
    var passed: usize = 0;
    // 1000 one-byte messages in one instant: only the burst passes.
    for (0..1000) |_| {
        if (l.allow(0, 1)) passed += 1;
    }
    try testing.expectEqual(@as(usize, 2 * input_msgs_per_s), passed);
    // One second later, one second's worth more.
    passed = 0;
    for (0..1000) |_| {
        if (l.allow(1000, 1)) passed += 1;
    }
    try testing.expectEqual(@as(usize, input_msgs_per_s), passed);
    // Bytes: large messages run out on the byte budget first.
    var b: InputLimit = .{};
    passed = 0;
    for (0..100) |_| {
        if (b.allow(0, 4096)) passed += 1;
    }
    try testing.expectEqual(@as(usize, 2 * input_bytes_per_s / 4096), passed);
    // A clock going backwards refills nothing (and does not crash).
    try testing.expect(!b.allow(-5000, 4096));
    try testing.expect(b.allow(std.math.maxInt(i64), 4096));
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

test "desk approval API is complete and compiles" {
    _ = &Server.deskBegin;
    _ = &Server.deskWindow;
    _ = &Server.deskAnswer;
    _ = &Server.deskCancel;
    _ = &Server.applyStore;
}
