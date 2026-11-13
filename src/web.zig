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
//! request; the device's page (GET /pair/wait, a long poll: see `pairWait`)
//! gets its credential once the owner answers "y" at the desk. Requests
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
const websocket = @import("shared").ws;
const http_names = @import("shared").http;
const tabs = @import("tabs.zig");
const tabs_wire = @import("shared").tabs;
const Log = @import("log.zig").Log;
const devices = @import("devices.zig");
const tls = @import("tls/server.zig");
const web_images = @import("web_images.zig");
const sync = @import("sync.zig");
const sync_manifest = @import("client").sync.manifest;
const sync_keypin = @import("client").sync.keypin;
const keymap = @import("keymap.zig");
const title = @import("title.zig");
const win32 = @import("win32.zig");
const activity_wire = @import("shared").activity;
const sysinfo = @import("shared").sysinfo;
const subtabs_wire = @import("shared").subtabs;
const sysmon = @import("sysmon.zig");


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
const max_ws_header = websocket.max_header_len;

/// Minimum gap between grid frames to one viewer (~30 per second).
const frame_interval_ms = 33;
/// After the exit notice, how long a viewer gets to close its end
/// (wsGoodbye). main.zig's viewer_goodbye_ms bounds the whole shutdown.
pub const goodbye_ms = 1500;
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
/// GET /pair/wait for a request still pending, whose waiting page this
/// device has already been shown, is held until the request's window
/// changes (or at most this long): a long poll, so neither the page nor a
/// native client needs a poll interval.
pub const pair_wait_hold_ms: i64 = 25_000;
/// The connection deadline while a /pair/wait is held: the hold plus
/// room to send the answer.
const pair_wait_slack_ms: i64 = 5_000;
/// Waiting pages remembered (by request token) for the long poll.
const pair_seen_slots = 2 * devices.max_requests;
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
    /// The sync release public key (docs/sync-design.md); null: the
    /// /sync routes answer 404.
    sync_key: ?[32]u8 = null,
};

/// What a device's GET /sync/index currently hashes to (main.zig's sync
/// watcher keeps these; a change sends that device {"t":"updates"}).
pub const SyncDigest = struct {
    device: devices.Text = .{},
    digest: [32]u8 = @splat(0),
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

const Bucket = @import("bucket.zig").Bucket;

/// Per-connection input limit: a message must fit both buckets.
pub const InputLimit = struct {
    msgs: Bucket = .init(input_msgs_per_s, 2 * input_msgs_per_s),
    bytes: Bucket = .init(input_bytes_per_s, 2 * input_bytes_per_s),

    pub fn allow(l: *InputLimit, now_ms: i64, len: usize) bool {
        l.msgs.refill(now_ms);
        l.bytes.refill(now_ms);
        const n: i64 = @intCast(len);
        if (!l.msgs.has(1) or !l.bytes.has(n)) return false;
        return l.msgs.take(1) and l.bytes.take(n);
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
    /// Set by the supervisor before it cancels the worker. A cancelation is
    /// delivered once; if some code path swallows it, `readSome` still
    /// refuses to block again, so the worker ends and `worker.cancel` returns.
    stop: std.atomic.Value(bool) = .init(false),
    /// Set (release) once `ws_cookie` is filled in, for revocation checks.
    ws_active: std.atomic.Value(bool) = .init(false),
    /// Worker-only (the supervisor reads it once the worker finished):
    /// counted in Session.viewer_sockets until the socket is closed.
    viewer_socket: bool = false,
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
    /// The open project tabs (tabs.zig); viewers watch one at a time.
    hub: *tabs.Hub,
    log: *Log,
    listener: net.Server,

    auth_mutex: Io.Mutex = .init,
    sessions: auth.Sessions = .{},
    /// Guarded by auth_mutex. Device records whose sessions were ended
    /// because the record itself went away, and why: what a WebSocket's
    /// {"t":"logout"} then says (`reason`). Memory only, oldest dropped.
    ended: [ended_slots]?Ended = @splat(null),
    ended_next: usize = 0,

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
    sync_log: LogLimiter = .{},
    sysmon_log: LogLimiter = .{},

    /// The optional system monitor (sysmon.zig; null: none). `y:on` from a
    /// viewer subscribes only while the desk's setting is on.
    sysmon: ?*sysmon.Monitor = null,

    /// The pairing window as last read from the device store, by the
    /// pairing watcher or by a handler that just changed it. Requests
    /// before sign-in read only this, never the file.
    pair_mutex: Io.Mutex = .init,
    pair_view: ?devices.Pairing = null,
    /// A window whose `portal pair` process has exited: treated as closed.
    pair_dead_nonce: ?u64 = null,
    /// Guarded by pair_mutex. Bumped whenever `pair_view` or
    /// `pair_dead_nonce` is set; `pair_cond` is broadcast then, which ends
    /// held GET /pair/wait long polls.
    pair_gen: u64 = 0,
    pair_cond: Io.Condition = .init,
    /// Guarded by pair_mutex. Request tokens (hashed) that were already
    /// answered "still waiting": their next GET /pair/wait is held.
    pair_seen: [pair_seen_slots]?auth.Hash = @splat(null),
    pair_seen_next: usize = 0,
    /// Times the pairing watcher woke up (for the wakeup measurement).
    pairwatch_wakes: std.atomic.Value(u32) = .init(0),
    /// Optional hook, like Session.notify_fn: called whenever the pairing
    /// view may have changed (a window opened or closed, a request arrived
    /// or was answered), on the changing thread with no lock held. The
    /// Portal window uses it to redraw its approval UI. Set before any
    /// thread starts.
    pairing_notify_ctx: ?*anyopaque = null,
    pairing_notify_fn: ?*const fn (ctx: *anyopaque) void = null,

    /// Per-device sync index digests, and a generation bumped whenever
    /// they are replaced (setSyncDigests).
    sync_mutex: Io.Mutex = .init,
    sync_digests: [devices.max_devices]SyncDigest = @splat(.{}),
    sync_n: usize = 0,
    sync_gen: std.atomic.Value(u64) = .init(0),

    /// Makes `run` return (the pairing-time download listener is stopped
    /// this way, together with cancelling its accept).
    stop: std.atomic.Value(bool) = .init(false),

    /// Why a device record's sessions ended (docs/protocol.md section 3,
    /// `logout`). `unpaired`: the record was removed (unpaired at the desk,
    /// forgotten by the device, revoked): the device should forget this
    /// desktop. `replaced`: another pairing under its name or address
    /// replaced it: the device signs in again and learns from that
    /// answer whether it is still paired.
    pub const EndReason = enum { unpaired, replaced };
    const Ended = struct { id: auth.DeviceId, reason: EndReason };
    const ended_slots = 32;

    /// Caller holds auth_mutex. The first reason recorded for `id` stays.
    fn noteEnded(srv: *Server, id: auth.DeviceId, reason: EndReason) void {
        if (srv.endedReason(id) != null) return;
        srv.ended[srv.ended_next] = .{ .id = id, .reason = reason };
        srv.ended_next = (srv.ended_next + 1) % ended_slots;
    }

    /// Caller holds auth_mutex.
    fn endedReason(srv: *const Server, id: auth.DeviceId) ?EndReason {
        for (srv.ended) |slot| if (slot) |e| if (std.mem.eql(u8, &e.id, &id)) return e.reason;
        return null;
    }

    fn cookieName(srv: *const Server) []const u8 {
        return http_names.cookieName(.session, srv.cfg.secure_cookie);
    }

    fn deviceCookieName(srv: *const Server) []const u8 {
        return http_names.cookieName(.device, srv.cfg.secure_cookie);
    }

    fn pairReqCookieName(srv: *const Server) []const u8 {
        return http_names.cookieName(.pairreq, srv.cfg.secure_cookie);
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
        srv.hub.mutex.lockUncancelable(srv.io);
        srv.hub.mutex.unlock(srv.io);
        srv.hub.cond.broadcast(srv.io);
        for (&srv.conn_wake) |*e| e.set(srv.io);
    }

    /// `lim.check` under `note_mutex`: the number of suppressed lines if
    /// this one should be logged, else null.
    fn limited(srv: *Server, lim: *LogLimiter, interval_ms: i64) ?u32 {
        srv.note_mutex.lockUncancelable(srv.io);
        defer srv.note_mutex.unlock(srv.io);
        return lim.check(srv.nowMs(), interval_ms);
    }

    /// Logs a line a peer can cause before signing in, at most `lim.burst`
    /// per interval, noting how many were suppressed.
    fn notePreAuth(srv: *Server, lim: *LogLimiter, comptime fmt: []const u8, args: anytype) void {
        const suppressed = srv.limited(lim, pre_auth_log_interval_ms) orelse return;
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
        srv.pair_gen +%= 1;
        srv.pair_mutex.unlock(srv.io);
        srv.notifyPairing();
    }

    /// The pairing view may have changed: held /pair/wait long polls
    /// re-check, and the Portal window's hook runs.
    fn notifyPairing(srv: *Server) void {
        srv.pair_cond.broadcast(srv.io);
        if (srv.pairing_notify_fn) |f| if (srv.pairing_notify_ctx) |c| f(c);
    }

    /// The `portal pair` that owns window `nonce` has exited.
    pub fn pairingProcessGone(srv: *Server, nonce: u64) void {
        srv.pair_mutex.lockUncancelable(srv.io);
        srv.pair_dead_nonce = nonce;
        srv.pair_gen +%= 1;
        srv.pair_mutex.unlock(srv.io);
        srv.notifyPairing();
    }

    const PairWaitView = struct {
        view: ?devices.Pairing,
        gen: u64,
        /// This request token was already answered "still waiting".
        seen: bool,
    };

    /// `pairingSnapshot` plus what a held /pair/wait needs, in one look.
    fn pairWaitView(srv: *Server, now_s: i64, token: auth.Hash) PairWaitView {
        const view = srv.pairingSnapshot(now_s);
        srv.pair_mutex.lockUncancelable(srv.io);
        defer srv.pair_mutex.unlock(srv.io);
        var seen = false;
        for (srv.pair_seen) |s| if (s) |h| {
            seen = seen or std.crypto.timing_safe.eql(auth.Hash, h, token);
        };
        return .{ .view = view, .gen = srv.pair_gen, .seen = seen };
    }

    fn markPairSeen(srv: *Server, token: auth.Hash) void {
        srv.pair_mutex.lockUncancelable(srv.io);
        defer srv.pair_mutex.unlock(srv.io);
        for (srv.pair_seen) |s| if (s) |h| if (std.crypto.timing_safe.eql(auth.Hash, h, token)) return;
        srv.pair_seen[srv.pair_seen_next] = token;
        srv.pair_seen_next = (srv.pair_seen_next + 1) % srv.pair_seen.len;
    }

    /// Blocks until the pairing view changes from generation `gen`, or
    /// `ms` pass. Cancelable: the connection's supervisor can always end
    /// it (error.Canceled is returned, never swallowed).
    fn waitPairChange(srv: *Server, gen: u64, ms: i64) Io.Cancelable!void {
        const timeout: Io.Timeout = (Io.Timeout{ .duration = .{ .raw = .fromMilliseconds(@max(ms, 1)), .clock = .awake } }).toDeadline(srv.io);
        srv.pair_mutex.lockUncancelable(srv.io);
        defer srv.pair_mutex.unlock(srv.io);
        while (srv.pair_gen == gen) {
            srv.pair_cond.waitTimeout(srv.io, &srv.pair_mutex, timeout) catch |err| switch (err) {
                error.Timeout => return,
                error.Canceled => return error.Canceled,
            };
        }
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
        _ = try srv.desk().begin(name, window_s, nonce, win32.GetCurrentProcessId());
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
        var ended: [auth.Sessions.max_sessions]auth.DeviceId = undefined;
        const n = srv.sessions.revokeUnpaired(read_start_ms, st, struct {
            fn paired(s: *const devices.Store, id: auth.DeviceId) bool {
                return s.findId(id) != null;
            }
        }.paired, &ended);
        for (ended[0..n]) |id| srv.noteEnded(id, .unpaired);
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

    // ------------------------------------------------------------ sync

    /// Replaces the per-device sync digests and wakes every WebSocket
    /// writer; each sends {"t":"updates"} if its device's digest changed.
    pub fn setSyncDigests(srv: *Server, list: []const SyncDigest) void {
        srv.sync_mutex.lockUncancelable(srv.io);
        const n = @min(list.len, srv.sync_digests.len);
        @memcpy(srv.sync_digests[0..n], list[0..n]);
        srv.sync_n = n;
        srv.sync_mutex.unlock(srv.io);
        _ = srv.sync_gen.fetchAdd(1, .release);
        srv.hub.mutex.lockUncancelable(srv.io);
        srv.hub.mutex.unlock(srv.io);
        srv.hub.cond.broadcast(srv.io);
    }

    fn syncDigestFor(srv: *Server, device: []const u8) [32]u8 {
        srv.sync_mutex.lockUncancelable(srv.io);
        defer srv.sync_mutex.unlock(srv.io);
        for (srv.sync_digests[0..srv.sync_n]) |d| if (std.mem.eql(u8, d.device.get(), device)) return d.digest;
        return @splat(0);
    }

    /// GET /sync/...: only with a live session, and only for the session's
    /// own device and its subscriptions. Unknown and unsubscribed packages
    /// look the same (404).
    fn syncRoute(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, h: Headers) !bool {
        // Only these exist; anything else under /sync/ is a plain 404.
        if (!std.mem.eql(u8, req.path, "/sync/key") and !std.mem.eql(u8, req.path, "/sync/index") and
            !std.mem.startsWith(u8, req.path, "/sync/pkg/")) return srv.fail(conn, w, .not_found, "not found\n");
        const cookie = h.cookie orelse return srv.fail(conn, w, .unauthorized, "login required\n");
        const who = srv.sessionOwner(cookie, true);
        const owner = switch (who) {
            .none => return srv.fail(conn, w, .unauthorized, "login required\n"),
            .anonymous => return srv.fail(conn, w, .forbidden, "not a paired device\n"),
            .device => |d| d,
        };
        const device = owner.name();
        if (!devices.validName(device)) return srv.fail(conn, w, .forbidden, "not a paired device\n");
        const key = srv.cfg.sync_key orelse return srv.fail(conn, w, .not_found, "not found\n");
        const paths: sync.Paths = .{ .dir = srv.cfg.devices.dir };
        const path = req.path;
        const keep = !req.connection_close;

        if (std.mem.eql(u8, path, "/sync/key")) {
            var kb: [sync_keypin.header.len + 66]u8 = undefined;
            var fp_buf: [95]u8 = undefined;
            const fp = sync_manifest.formatFingerprint(sync_manifest.fingerprint(key), &fp_buf);
            try srv.respond(conn, w, .ok, sync_keypin.format(key, &kb), "text/plain; charset=utf-8", &.{.{ .name = "x-portal-sync-key-fingerprint", .value = fp }}, keep);
            return keep;
        }
        if (std.mem.eql(u8, path, "/sync/index")) {
            const body = sync.buildIndex(srv.gpa, srv.io, paths, device) catch |err| {
                srv.log.print("sync: index for '{s}' failed: {t}", .{ device, err });
                return srv.fail(conn, w, .internal_server_error, "sync store unavailable\n");
            };
            defer srv.gpa.free(body);
            try srv.respond(conn, w, .ok, body, "text/plain; charset=utf-8", &.{}, keep);
            return keep;
        }
        const prefix = "/sync/pkg/";
        if (!std.mem.startsWith(u8, path, prefix)) return srv.fail(conn, w, .not_found, "not found\n");
        // <pkg>/<ver>/manifest  or  <pkg>/<ver>/file/<n>
        var it = std.mem.splitScalar(u8, path[prefix.len..], '/');
        const pkg = it.next() orelse "";
        const ver = it.next() orelse "";
        const what = it.next() orelse "";
        const arg = it.next();
        if (it.next() != null or !sync_manifest.validPackageId(pkg) or !sync_manifest.validVersion(ver))
            return srv.fail(conn, w, .not_found, "not found\n");
        const subs = sync.readSubs(srv.gpa, srv.io, paths) catch return srv.fail(conn, w, .internal_server_error, "sync store unavailable\n");
        if (!subs.has(device, pkg)) {
            srv.notePreAuth(&srv.sync_log, "sync: '{s}' asked for '{s}', which it is not subscribed to", .{ device, pkg });
            return srv.fail(conn, w, .not_found, "not found\n");
        }
        var v = sync.readVersion(srv.gpa, srv.io, paths, pkg, ver) catch return srv.fail(conn, w, .not_found, "not found\n");
        defer v.deinit(srv.gpa);
        if (std.mem.eql(u8, what, "manifest") and arg == null) {
            srv.log.print("sync: '{s}' fetched the manifest of {s} {s}", .{ device, pkg, ver });
            try srv.respond(conn, w, .ok, v.manifest_bytes, "text/plain; charset=utf-8", &.{.{ .name = "x-portal-signature", .value = &v.sig_hex }}, keep);
            return keep;
        }
        if (!std.mem.eql(u8, what, "file")) return srv.fail(conn, w, .not_found, "not found\n");
        const ntext = arg orelse return srv.fail(conn, w, .not_found, "not found\n");
        if (ntext.len == 0 or ntext.len > 4 or (ntext.len > 1 and ntext[0] == '0')) return srv.fail(conn, w, .not_found, "not found\n");
        const n = std.fmt.parseInt(usize, ntext, 10) catch return srv.fail(conn, w, .not_found, "not found\n");
        if (n >= v.m.files.len) return srv.fail(conn, w, .not_found, "not found\n");
        return srv.syncFile(conn, w, paths, pkg, ver, n, v.m.files[n].size, keep);
    }

    /// Streams stored file `n`: exactly the size its manifest promises,
    /// in bounded chunks, each under the send deadline.
    fn syncFile(srv: *Server, conn: *Conn, w: *Io.Writer, paths: sync.Paths, pkg: []const u8, ver: []const u8, n: usize, size: u64, keep: bool) !bool {
        var pb: [1024]u8 = undefined;
        const fpath = sync.filePath(paths, &pb, pkg, ver, n) catch return srv.fail(conn, w, .not_found, "not found\n");
        const f = Io.Dir.cwd().openFile(srv.io, fpath, .{}) catch return srv.fail(conn, w, .not_found, "not found\n");
        defer f.close(srv.io);
        const st = f.stat(srv.io) catch return srv.fail(conn, w, .internal_server_error, "sync store unavailable\n");
        if (st.size != size) {
            srv.log.print("sync: stored file {d} of {s} {s} has the wrong size; not served", .{ n, pkg, ver });
            return srv.fail(conn, w, .internal_server_error, "sync store damaged\n");
        }
        conn.setDeadline(srv.nowMs() +| send_timeout_ms);
        try w.print("HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\nx-content-type-options: nosniff\r\n" ++
            "cache-control: no-store\r\ncross-origin-resource-policy: same-origin\r\ncontent-length: {d}\r\nconnection: {s}\r\n\r\n", .{ size, if (keep) "keep-alive" else "close" });
        var buf: [32 * 1024]u8 = undefined;
        var sent: u64 = 0;
        while (sent < size) {
            const got = try f.readPositional(srv.io, &.{buf[0..@intCast(@min(buf.len, size - sent))]}, sent);
            if (got == 0) return error.SyncFileShrank; // ends the connection mid-body
            try w.writeAll(buf[0..got]);
            try w.flush();
            sent += got;
            conn.setDeadline(srv.nowMs() +| send_timeout_ms);
        }
        try w.flush();
        conn.setDeadline(no_deadline);
        return keep;
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

        var conn: Conn = .{
            .stream = stream,
            .slot = slot,
            .deadline_ms = .init(srv.nowMs() +| head_timeout_ms),
            .wake = &srv.conn_wake[slot],
            .io = io,
        };
        // Safe: the worker has finished (cancel/await below) before this
        // runs. A viewer's socket counts until it is closed here, so a
        // shutting-down Portal outlives every exit notice in flight.
        defer {
            stream.close(io);
            if (conn.viewer_socket) srv.hub.viewerSocketDelta(-1);
        }
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
        // `stop` first: should the worker swallow the one cancelation, its
        // next read fails instead of blocking with nobody left to cancel it.
        conn.stop.store(true, .seq_cst);
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
        const suppressed = srv.limited(&srv.tls_fail_log, 10_000) orelse return;
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
        if (conn.stop.load(.seq_cst)) return error.Canceled;
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
        const suppressed = srv.limited(&srv.host_reject_log, 10_000) orelse return;
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
                if (std.mem.startsWith(u8, path, "/sync/")) return srv.syncRoute(conn, w, req, h);
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
                if (std.mem.eql(u8, path, "/device/forget")) return srv.deviceForget(conn, w, h);
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
            // same-origin, not no-referrer: under no-referrer, browsers
            // (Fetch spec) send `Origin: null` with a form POST, which the
            // origin check rightly refuses ("bad origin" on Pair this
            // device and Unpair). Nothing is ever sent to another origin.
            .{ .name = "referrer-policy", .value = "same-origin" },
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
        else if (std.mem.eql(u8, q, "e=gone"))
            "<p class=\"error\">This device is no longer paired with this desktop (it was unpaired at the desk, or forgot this desktop). Pair it again at the desktop.</p>"
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
    /// request code the desk sees and reloads itself at once, with no
    /// script. That reload is a held GET /pair/wait (the long poll in
    /// `pairWait`), so the browser keeps showing this page until the desk
    /// answers; it is not a timer.
    fn pairWaitPage(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, view: *const devices.Pairing, r: *const devices.Request) !bool {
        srv.markPairSeen(r.token);
        const head = "<meta http-equiv=\"refresh\" content=\"0\">";
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

    /// Builds Set-Cookie values for a device credential and a new session
    /// of device record `device`.
    fn issueCookies(srv: *Server, device: auth.Device, device_secret: []const u8, out: *CookiePair) !void {
        var session_val: [auth.encoded_len]u8 = undefined;
        try srv.newSecret(&session_val);
        defer std.crypto.secureZero(u8, &session_val);
        srv.auth_mutex.lockUncancelable(srv.io);
        srv.sessions.createFor(&session_val, srv.realMs(), device);
        srv.auth_mutex.unlock(srv.io);
        const secure = if (srv.cfg.secure_cookie) "; Secure" else "";
        out.device = try std.fmt.bufPrint(&out.device_buf, "{s}={s}.{s}; Path=/; HttpOnly; SameSite=Strict; Max-Age={d}{s}", .{
            srv.deviceCookieName(), device.name(), device_secret, devices.unused_expiry_s, secure,
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

    /// Who session `cookie` belongs to (memory only).
    fn sessionOwner(srv: *Server, cookie: []const u8, refresh: bool) auth.Sessions.Live {
        srv.auth_mutex.lockUncancelable(srv.io);
        defer srv.auth_mutex.unlock(srv.io);
        return srv.sessions.live(cookie, srv.realMs(), refresh);
    }

    /// Ends every session of device record `id` (which the store no longer
    /// has, for `reason`) and wakes every viewer and supervisor so open
    /// WebSockets of it are told (`logout` with the reason) and close.
    /// Returns how many sessions ended.
    fn endDeviceSessions(srv: *Server, id: auth.DeviceId, reason: EndReason) usize {
        srv.auth_mutex.lockUncancelable(srv.io);
        const n = srv.sessions.revokeDevice(id);
        srv.noteEnded(id, reason);
        srv.auth_mutex.unlock(srv.io);
        srv.wakeViewers();
        return n;
    }

    /// The {"t":"logout"} message for a session that is no longer live.
    fn logoutMessage(srv: *Server, device: ?auth.Device) []const u8 {
        const d = device orelse return "{\"t\":\"logout\"}";
        srv.auth_mutex.lockUncancelable(srv.io);
        defer srv.auth_mutex.unlock(srv.io);
        return switch (srv.endedReason(d.id) orelse return "{\"t\":\"logout\"}") {
            .unpaired => "{\"t\":\"logout\",\"reason\":\"unpaired\"}",
            .replaced => "{\"t\":\"logout\",\"reason\":\"replaced\"}",
        };
    }

    /// A stale or wrong credential was presented: the store already
    /// removed the record; end its sessions and say so.
    fn deviceRevoked(srv: *Server, gone: auth.Device, peer: []const u8) void {
        const n = srv.endDeviceSessions(gone.id, .unpaired);
        srv.log.print("DEVICE REVOKED '{s}': stale or wrong credential presented from {s} (copied credential?); {d} session(s) ended. Re-pair required.", .{ gone.name(), peer, n });
    }

    const CredentialUse = enum { sign_in, unpair };

    const CredentialCheck = struct {
        outcome: SignInOutcome = .unknown,
        /// The record signed in to, removed (unpair) or revoked.
        device: ?auth.Device = null,
    };

    /// One locked store update for a presented `<name>.<secret>` device
    /// credential from `ip`: verified against the record's bound address;
    /// valid ones rotate to `new_hash` (sign-in) or remove the record
    /// (unpair); a stale or wrong secret revokes the record (see
    /// devices.zig). Callers report `.revoked` with `deviceRevoked`.
    fn checkCredential(srv: *Server, presented: []const u8, ip: []const u8, use: CredentialUse, new_hash: auth.Hash) !CredentialCheck {
        var res: CredentialCheck = .{};
        const now = srv.nowUnix();
        const Ctx = struct { presented: []const u8, ip: []const u8, use: CredentialUse, hash: auth.Hash, now: i64, res: *CredentialCheck };
        try devices.withStore(srv.gpa, srv.io, srv.cfg.devices, now, Ctx{
            .presented = presented,
            .ip = ip,
            .use = use,
            .hash = new_hash,
            .now = now,
            .res = &res,
        }, struct {
            fn op(c: Ctx, st: *devices.Store) !bool {
                switch (st.authenticate(c.presented, c.ip, c.now)) {
                    .ok => |idx| {
                        c.res.* = .{ .outcome = .ok, .device = st.devices[idx].?.ref() };
                        switch (c.use) {
                            .sign_in => st.rotate(idx, c.hash, c.now),
                            .unpair => st.devices[idx] = null,
                        }
                        return true;
                    },
                    .revoked => |d| {
                        c.res.* = .{ .outcome = .revoked, .device = d };
                        return true;
                    },
                    .wrong_address => {
                        c.res.outcome = .wrong_address;
                        return false;
                    },
                    .gone => {
                        c.res.outcome = .gone;
                        return false;
                    },
                    .unknown => return false,
                }
            }
        }.op);
        return res;
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

    /// GET /pair/wait: the requesting device asks for its outcome. A long
    /// poll (docs/protocol.md section 1):
    ///   * Pending, first ask with this request token: the waiting page at
    ///     once (it carries the request code, also as X-Portal-Request-Code).
    ///   * Pending, asked again: held until the pairing window changes
    ///     (a request answered, the window closed or replaced, its
    ///     `portalctl pair` gone, its expiry) or `pair_wait_hold_ms`
    ///     pass, then answered exactly like a fresh ask: the outcome
    ///     below, or the same waiting page if still pending. Clients
    ///     re-ask at once; there is no poll interval.
    ///   * Approved at the desk: the device credential and a session, once,
    ///     to the same address and request token only.
    ///   * Denied or gone: back to /pair with the reason.
    fn pairWait(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, h: Headers) !bool {
        const peer = conn.peer();
        const ip = devices.ipOnly(peer);
        var clear_buf: [128]u8 = undefined;
        const clear = try srv.clearPairReq(&clear_buf);
        const tok = h.pairreq orelse return srv.redirect(conn, w, req, "/pair?e=expired", &.{});
        const tok_hash = auth.hashSecret(tok);
        const hold_until = srv.nowMs() +| pair_wait_hold_ms;
        var now: i64 = undefined;
        var view: devices.Pairing = undefined;
        var r: devices.Request = undefined;
        while (true) {
            now = srv.nowUnix();
            const look = srv.pairWaitView(now, tok_hash);
            view = look.view orelse return srv.redirect(conn, w, req, "/pair?e=expired", &.{clear});
            const i = view.findToken(tok_hash) orelse return srv.redirect(conn, w, req, "/pair?e=expired", &.{clear});
            r = view.requests[i].?;
            if (!std.mem.eql(u8, r.ip.get(), ip)) return srv.redirect(conn, w, req, "/pair?e=expired", &.{clear});
            if (r.state != .pending) break;
            const left = @min(hold_until -| srv.nowMs(), (view.expires -| now +| 1) *| 1000);
            if (!look.seen or left <= 0) return srv.pairWaitPage(conn, w, req, &view, &r);
            // Hold. The window's expiry and every change to it bump the
            // generation (the pairing watcher re-reads the store at the
            // expiry), so this sleeps until something can have changed.
            conn.setDeadline(srv.nowMs() +| left +| pair_wait_slack_ms);
            try srv.waitPairChange(look.gen, left);
        }
        switch (r.state) {
            .pending => unreachable, // the loop above answers those
            .denied => return srv.redirect(conn, w, req, "/pair?e=denied", &.{clear}),
            .done => return srv.redirect(conn, w, req, "/pair?e=expired", &.{clear}),
            .approved => {},
        }

        // Approved at the desk: collect the credential, as a new device
        // record with a new random id.
        var secret: [auth.encoded_len]u8 = undefined;
        srv.newSecret(&secret) catch return srv.fail(conn, w, .internal_server_error, "no entropy\n");
        defer std.crypto.secureZero(u8, &secret);
        var new_id: auth.DeviceId = undefined;
        srv.io.randomSecure(&new_id) catch return srv.fail(conn, w, .internal_server_error, "no entropy\n");
        var result: devices.ClaimResult = .unknown;
        const Ctx = struct { srv: *Server, token: auth.Hash, ip: []const u8, id: auth.DeviceId, hash: auth.Hash, now: i64, result: *devices.ClaimResult };
        devices.withStore(srv.gpa, srv.io, srv.cfg.devices, now, Ctx{
            .srv = srv,
            .token = tok_hash,
            .ip = ip,
            .id = new_id,
            .hash = auth.hashSecret(&secret),
            .now = now,
            .result = &result,
        }, struct {
            fn op(c: Ctx, st: *devices.Store) !bool {
                defer c.srv.setPairing(st.pairing);
                c.result.* = try st.claim(c.token, c.ip, c.id, c.hash, c.now);
                return c.result.* == .paired;
            }
        }.op) catch |err| {
            srv.noteStoreFailure("pairing", peer, err);
            return srv.fail(conn, w, .internal_server_error, if (err == error.TooManyDevices) "too many paired devices: unpair one at the desk\n" else "device store unavailable\n");
        };
        const paired = switch (result) {
            .paired => |p| p,
            .pending => return srv.pairWaitPage(conn, w, req, &view, &r),
            .denied => return srv.redirect(conn, w, req, "/pair?e=denied", &.{clear}),
            .unknown => return srv.redirect(conn, w, req, "/pair?e=expired", &.{clear}),
        };
        // Re-pair: the records this one replaced are gone from the store;
        // end every one of their sessions (and so their WebSockets, input
        // and /sync access) before the new credential exists.
        for (paired.replaced.items()) |old| {
            const n = srv.endDeviceSessions(old.id, .replaced);
            srv.log.print("re-pair: previous device record '{s}' removed; {d} of its session(s) ended", .{ old.name(), n });
        }
        srv.log.print("PAIRED device '{s}' at {s} (request {s}, approved at the desk)", .{ paired.device.name(), ip, &r.code });
        var cookies: CookiePair = .{};
        try srv.issueCookies(paired.device, &secret, &cookies);
        return srv.redirect(conn, w, req, "/", &.{ cookies.device, cookies.session, clear });
    }

    const SignInMode = enum { page, api };
    const SignInOutcome = enum { ok, wrong_address, revoked, gone, unknown };

    /// On a refused native sign-in (`POST /auth/refresh`) and
    /// `POST /device/forget`: says, unambiguously, that this desktop no
    /// longer has the device (its record was removed, or its credential
    /// matches no record). A device that gets it forgets this desktop.
    /// Never sent for a store error (500) or a known device presented from
    /// another address.
    const device_gone_header: http1.Header = .{ .name = "x-portal-device", .value = "gone" };

    /// A paired device presents its credential: verify it against the
    /// device's bound address, rotate it, and start a session. A stale or
    /// wrong secret revokes the device (see devices.zig).
    fn deviceSignIn(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, presented: []const u8, mode: SignInMode) !bool {
        const peer = conn.peer();
        var secret: [auth.encoded_len]u8 = undefined;
        srv.newSecret(&secret) catch return srv.fail(conn, w, .internal_server_error, "no entropy\n");
        defer std.crypto.secureZero(u8, &secret);

        const res = srv.checkCredential(presented, devices.ipOnly(peer), .sign_in, auth.hashSecret(&secret)) catch |err| {
            srv.noteStoreFailure("device sign-in", peer, err);
            return srv.fail(conn, w, .internal_server_error, "device store unavailable\n");
        };
        const outcome = res.outcome;
        switch (outcome) {
            .ok => {
                var cookies: CookiePair = .{};
                try srv.issueCookies(res.device.?, &secret, &cookies);
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
            .revoked => srv.deviceRevoked(res.device.?, peer),
            // Logged here only: the response is the same for both, so a
            // peer can't use it to learn which device names exist.
            .wrong_address => srv.notePreAuth(&srv.signin_log, "device credential presented from unexpected address {s}; rejected", .{peer}),
            .gone => srv.notePreAuth(&srv.signin_log, "credential of a removed device presented from {s}; told it is no longer paired", .{peer}),
            .unknown => srv.notePreAuth(&srv.signin_log, "device credential from {s} matches no paired device; rejected", .{peer}),
        }
        var clear_buf: [2][128]u8 = undefined;
        const clear = try srv.clearCookies(&clear_buf);
        switch (mode) {
            .page => return srv.redirect(conn, w, req, switch (outcome) {
                .revoked => "/pair?e=revoked",
                .gone => "/pair?e=gone",
                else => "/pair",
            }, &clear),
            .api => {
                const gone = [_]http1.Header{device_gone_header};
                try srv.respond(conn, w, .unauthorized, "not paired\n", "text/plain; charset=utf-8", if (outcome == .wrong_address) &.{} else &gone, false);
                return false;
            },
        }
    }

    /// POST /device/forget: the device forgets this desktop ("Forget this
    /// desktop" in portal connect, `connect --forget`, `sync-device
    /// --forget`) and asks it to forget the device too. The device is the
    /// one its live session belongs to (never anything in the request):
    /// its record is removed (secrets kept as tombstones), all its
    /// sessions end (WebSockets get logout/unpaired), and the desk's
    /// Devices panel refreshes. 204 when done; 401 with
    /// `X-Portal-Device: gone` without a live device session.
    fn deviceForget(srv: *Server, conn: *Conn, w: *Io.Writer, h: Headers) !bool {
        const peer = conn.peer();
        const gone = [_]http1.Header{device_gone_header};
        const cookie = h.cookie orelse {
            try srv.respond(conn, w, .unauthorized, "login required\n", "text/plain; charset=utf-8", &.{}, false);
            return false;
        };
        const d = switch (srv.sessionOwner(cookie, false)) {
            .device => |d| d,
            .anonymous => return srv.fail(conn, w, .forbidden, "not a paired device\n"),
            .none => {
                // No live session: it may have ended because the device
                // is gone; the device signs in to find out.
                try srv.respond(conn, w, .unauthorized, "login required\n", "text/plain; charset=utf-8", &.{}, false);
                return false;
            },
        };
        var removed = false;
        const Ctx = struct { id: auth.DeviceId, removed: *bool };
        devices.withStore(srv.gpa, srv.io, srv.cfg.devices, srv.nowUnix(), Ctx{ .id = d.id, .removed = &removed }, struct {
            fn op(c: Ctx, st: *devices.Store) !bool {
                c.removed.* = st.removeId(c.id);
                return c.removed.*;
            }
        }.op) catch |err| {
            srv.noteStoreFailure("forget", peer, err);
            return srv.fail(conn, w, .internal_server_error, "device store unavailable: the device was NOT forgotten\n");
        };
        const n = srv.endDeviceSessions(d.id, .unpaired);
        srv.log.print("device '{s}' forgot this desktop from {s}: its record was removed{s}; {d} session(s) ended", .{
            d.name(), peer, if (removed) "" else " (already gone)", n,
        });
        srv.notifyPairing(); // the desk's Devices panel re-reads the list
        try srv.respond(conn, w, .no_content, "", "text/plain; charset=utf-8", &gone, false);
        return false;
    }

    /// POST /logout ("Unpair this device"): removes the device and its
    /// sessions. With an expired session, the device credential still
    /// identifies the device (checked like a sign-in, then removed).
    fn logout(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, h: Headers) !bool {
        const peer = conn.peer();
        // A live session names its device record exactly (by id): remove
        // that record only, so a newer pairing under the same name stays.
        var owner: ?auth.Device = null;
        if (h.cookie) |c| {
            srv.auth_mutex.lockUncancelable(srv.io);
            owner = srv.sessions.liveDevice(c, srv.realMs(), false);
            srv.sessions.revoke(c);
            srv.auth_mutex.unlock(srv.io);
        }
        var res: CredentialCheck = .{};
        if (owner) |d| {
            devices.withStore(srv.gpa, srv.io, srv.cfg.devices, srv.nowUnix(), d.id, struct {
                fn op(id: auth.DeviceId, st: *devices.Store) !bool {
                    return st.removeId(id); // already gone counts as unpaired too
                }
            }.op) catch |err| {
                srv.noteStoreFailure("unpair", peer, err);
                return srv.fail(conn, w, .internal_server_error, "device store unavailable: the device was NOT unpaired\n");
            };
            res = .{ .outcome = .ok, .device = d };
        } else if (h.device) |presented| {
            // No live session: the device credential identifies it
            // (checked like a sign-in, then removed).
            res = srv.checkCredential(presented, devices.ipOnly(peer), .unpair, undefined) catch |err| {
                srv.noteStoreFailure("unpair", peer, err);
                return srv.fail(conn, w, .internal_server_error, "device store unavailable: the device was NOT unpaired\n");
            };
        }
        var clear_buf: [2][128]u8 = undefined;
        const clear = try srv.clearCookies(&clear_buf);
        switch (res.outcome) {
            .ok => {
                const d = res.device.?;
                _ = srv.endDeviceSessions(d.id, .unpaired);
                srv.log.print("device '{s}' unpaired itself from {s}", .{ d.name(), peer });
                return srv.redirect(conn, w, req, "/pair?bye", &clear);
            },
            .revoked => {
                srv.deviceRevoked(res.device.?, peer);
                return srv.redirect(conn, w, req, "/pair?e=revoked", &clear);
            },
            .wrong_address, .gone, .unknown => return srv.redirect(conn, w, req, "/pair", &clear),
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
        /// The session's device record (null: an untagged session).
        device: ?auth.Device = null,
        /// Reader only: per-connection input rate limit.
        limit: InputLimit = .{},
        /// Reader only: the tab this viewer's input goes to, with a
        /// reference (null after asking for a session that is not open:
        /// input is then dropped until it picks an open one).
        sel: ?*tabs.Tab = null,
        /// Guarded by hub.mutex: a switch the reader asks the writer to
        /// show (`s:<id>`); the writer answers `session` or `nosession`.
        want: Want = .none,
        /// Reader only: unknown-session log lines (rate limited).
        unknown_ids: u32 = 0,
        /// Guarded by hub.mutex: the conversation the reader asks the
        /// writer to show (`a:<sub id>` / `a:`, section 3e).
        sub_want: SubWant = .none,
        /// Reader only: a sub-tab is shown, which takes no input (k:, t:
        /// and l: are dropped until `a:` or `s:`).
        sub_view: bool = false,
        /// The viewer's System panel is open (`y:on`) and the monitor
        /// accepted it: the writer sends `sys` after every sample.
        sys_on: std.atomic.Value(bool) = .init(false),
        /// Reader only: refused `y:on`s (log rate limit).
        sys_refused: u32 = 0,
        /// Writer loop iterations (for the wakeup measurement in the log).
        writer_wakes: u32 = 0,

        const Want = union(enum) { none, tab: *tabs.Tab, unknown };
        const SubWant = union(enum) { none, main, sub: tabs.Id };

        /// Returns false if the connection should end. Cancelable: the
        /// supervisor can always tear down a sender stuck behind another.
        fn send(c: *WsConn, srv: *Server, data: []const u8, op: websocket.Opcode) bool {
            c.write_mutex.lock(srv.io) catch return false;
            defer c.write_mutex.unlock(srv.io);
            if (c.close_sent) return false;
            if (op == .close) c.close_sent = true;
            c.conn.setDeadline(srv.nowMs() +| send_timeout_ms);
            websocket.writeServerFrame(c.w, op, data) catch return false;
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
        const accept = websocket.accept(req.ws_key orelse "") catch {
            _ = try srv.fail(conn, w, .bad_request, "bad websocket key\n");
            return;
        };
        if (leftover.len > max_ws_header + max_ws_payload) return;

        conn.setDeadline(srv.nowMs() +| send_timeout_ms);
        try http1.writeUpgrade(w, &accept);
        conn.setDeadline(no_deadline);

        var ws: WsConn = .{ .conn = conn, .w = w, .cookie = undefined };
        @memcpy(&ws.cookie, cookie);
        switch (srv.sessionOwner(cookie, false)) {
            .device => |d| ws.device = d,
            else => {},
        }
        @memcpy(&conn.ws_cookie, cookie);
        conn.ws_active.store(true, .release);
        conn.wake.set(srv.io); // the supervisor now also watches the session

        srv.hub.viewerSocketDelta(1);
        conn.viewer_socket = true;
        const viewers = srv.hub.viewerDelta(1);
        srv.log.print("viewer connected from {s} ({d} watching)", .{ peer, viewers });
        srv.updateTitle(viewers);
        const pairwatch_before = srv.pairwatch_wakes.load(.monotonic);
        const sup_before = conn.sup_wakes.load(.monotonic);
        defer {
            const left = srv.hub.viewerDelta(-1);
            // Wakeup counts make idle cost visible (and testable): an idle
            // viewer should cost no periodic wakeups at all.
            srv.log.print("viewer disconnected from {s} ({d} watching; wakeups while connected: supervisor {d}, writer {d}, pairing watcher {d})", .{
                peer,                                        left,
                conn.sup_wakes.load(.monotonic) -% sup_before, ws.writer_wakes,
                srv.pairwatch_wakes.load(.monotonic) -% pairwatch_before,
            });
            srv.updateTitle(left);
        }

        // The viewer starts on the desk's tab: the writer shows it and the
        // reader sends input to it, each with its own reference.
        const initial = srv.hub.acquireInitial();
        if (initial) |t| {
            t.acquire();
            ws.sel = t;
        }
        defer {
            // Both tasks have ended: their references go.
            if (ws.sel) |t| t.release();
            switch (ws.want) {
                .tab => |t| t.release(),
                else => {},
            }
        }
        var reader = srv.io.concurrent(wsReadLoop, .{ srv, &ws, leftover }) catch {
            if (initial) |t| t.release();
            return;
        };
        srv.wsWriteLoop(&ws, initial);
        ws.dead.store(true, .release);
        // Interrupts the reader if it is parked in a recv; never close a
        // socket another task is blocked on.
        reader.cancel(srv.io);
    }

    /// The console's title in `portalctl run --console` (a no-op in the
    /// window, which titles itself the same way): title.zig.
    fn updateTitle(srv: *Server, viewers: u32) void {
        var buf: [title.max_title_bytes]u8 = undefined;
        var nb: [tabs_wire.max_name]u8 = undefined;
        srv.hub.console.setTitle(title.windowTitle(srv.hub.deskName(&nb), viewers, &buf));
    }

    /// `s:<id>` from the viewer (reader task): watch another open tab. The
    /// reader resolves the id itself, so input sent after it goes to the
    /// new tab at once; the writer then switches what it shows and answers
    /// `session`. Anything that is not an open tab's id (closed, never
    /// existed, malformed) gets the same `nosession` and leaves the viewer
    /// with no input target until it picks an open tab (privacy rule 3:
    /// probing learns nothing). Rejected ids are logged locally, rate
    /// limited, never echoed (rule 7).
    fn subscribe(srv: *Server, ws: *WsConn, text: []const u8) void {
        const hub = srv.hub;
        const id = tabs_wire.parseId(text);
        hub.mutex.lockUncancelable(srv.io);
        const t: ?*tabs.Tab = if (id) |i| hub.acquireLocked(i) else null;
        switch (ws.want) {
            .tab => |old| old.release(),
            else => {},
        }
        if (t) |tt| {
            tt.acquire(); // the writer's
            ws.want = .{ .tab = tt };
        } else ws.want = .unknown;
        const old_sel = ws.sel;
        ws.sel = t;
        // A switch shows the new tab's own conversation.
        ws.sub_want = .none;
        ws.sub_view = false;
        hub.mutex.unlock(srv.io);
        hub.cond.broadcast(srv.io);
        if (old_sel) |o| o.release();
        if (t == null) {
            ws.unknown_ids +|= 1;
            if (ws.unknown_ids <= 3 or std.math.isPowerOfTwo(ws.unknown_ids))
                srv.notePreAuth(&srv.input_log, "viewer from {s} asked for a session that is not open ({d} so far)", .{ ws.conn.peer(), ws.unknown_ids });
        }
    }

    /// `a:<sub id>` from the viewer (reader task): show that sub-tab of the
    /// tab watched instead of the tab's own conversation; `a:` goes back.
    /// Anything that is not a current sub-tab of the tab watched (gone,
    /// another tab's, malformed) is the same as `a:` (nothing echoed or
    /// told apart). While a sub-tab is shown the viewer's input is dropped:
    /// sub-tabs are read-only.
    fn viewSub(srv: *Server, ws: *WsConn, text: []const u8) void {
        const hub = srv.hub;
        const id = tabs_wire.parseId(text);
        hub.mutex.lockUncancelable(srv.io);
        const ok = if (id) |i| (if (ws.sel) |t| t.subs.byId(i) != null else false) else false;
        ws.sub_want = if (ok) .{ .sub = id.? } else .main;
        ws.sub_view = ok;
        hub.mutex.unlock(srv.io);
        hub.cond.broadcast(srv.io);
    }

    /// `y:on` / `y:off`: the viewer's System panel opened or closed. Only
    /// while the desk's "Show system monitor" is on does `y:on` count (and
    /// start the sampler); otherwise it is ignored and logged here, rate
    /// limited, and the viewer gets nothing.
    fn sysPanel(srv: *Server, ws: *WsConn, arg: []const u8) void {
        const on = std.mem.eql(u8, arg, "on");
        if (!on and !std.mem.eql(u8, arg, "off")) return;
        if (!on) {
            if (ws.sys_on.swap(false, .acq_rel)) if (srv.sysmon) |m| m.unsubscribe();
            return;
        }
        if (ws.sys_on.load(.acquire)) return;
        const accepted = if (srv.sysmon) |m| m.subscribe() else false;
        if (!accepted) {
            ws.sys_refused +|= 1;
            if (ws.sys_refused <= 3 or std.math.isPowerOfTwo(ws.sys_refused))
                srv.notePreAuth(&srv.sysmon_log, "viewer from {s} asked for the system monitor, which is off in Settings ({d} so far)", .{ ws.conn.peer(), ws.sys_refused });
            return;
        }
        ws.sys_on.store(true, .release);
        srv.hub.broadcast();
    }

    const Shown = struct { convo: *@import("convo/model.zig").Convo, id: tabs.Id, gone: bool = false };

    /// The conversation a viewer of tab `c` sees: sub-tab `sub`'s, or (no
    /// sub-tab, or it went: `gone`) the tab's own. Hub lock held.
    fn shownConvo(c: *tabs.Tab, sub: ?tabs.Id) Shown {
        const id = sub orelse return .{ .convo = &c.convo, .id = c.id };
        const s = c.subs.byId(id) orelse return .{ .convo = &c.convo, .id = c.id, .gone = true };
        return .{ .convo = &s.convo, .id = s.id };
    }

    fn wsWriteLoop(srv: *Server, ws: *WsConn, initial: ?*tabs.Tab) void {
        const hub = srv.hub;
        // The tab shown, with this task's reference.
        var cur: ?*tabs.Tab = initial;
        defer if (cur) |t| t.release();
        var msg: [128]u8 = undefined;
        var frame: std.ArrayList(u8) = .empty;
        defer frame.deinit(srv.gpa);
        var rows: std.ArrayList(u16) = .empty;
        defer rows.deinit(srv.gpa);
        // Inline images: 'I' blobs and 'P' placements (web_images.zig),
        // of the tab shown (a switch starts over).
        var images: web_images.Sender = .{};
        defer images.deinit(srv.gpa);
        // The tab list: hello, then `tabs` whenever it changes.
        const text = srv.gpa.alloc(u8, tabs_wire.max_list_json + 256) catch return;
        defer srv.gpa.free(text);
        var list: tabs_wire.List = .{};

        hub.mutex.lockUncancelable(srv.io);
        hub.entriesLocked(&list);
        var seen_gen = hub.gen;
        var cur_entry: ?tabs_wire.Entry = null;
        if (cur) |c| if (list.find(c.id)) |i| {
            cur_entry = list.items[i];
        };
        hub.mutex.unlock(srv.io);
        const hello = helloMessage(text, hub.policy, cur_entry, list.slice()) catch return;
        if (!ws.send(srv, hello, .text)) return;
        // Sync announcements: {"t":"updates"} when this device's index
        // changes (devices also look on every connect).
        const ws_device: []const u8 = if (ws.device) |*d| d.name() else "";
        var sync_seen = srv.sync_gen.load(.acquire);
        var sync_digest = srv.syncDigestFor(ws_device);

        // Generation of the emulator state last sent; 0 plus `full` forces a
        // complete snapshot first (docs/protocol.md section 3).
        var sent_gen: u64 = 0;
        var full = true;
        var sent_cols: u16 = 0;
        var sent_rows: u16 = 0;
        // `ended` was sent for the tab shown (it closed while others run).
        var ended_sent = false;
        // The shown tab's conversation (docs/protocol.md section 3b): the
        // epoch and revision last sent; epoch 0 forces a `convo` snapshot.
        var convo_epoch: u32 = 0;
        var convo_rev: u64 = 0;
        var convo_out: std.Io.Writer.Allocating = .init(srv.gpa);
        defer convo_out.deinit();
        // The shown tab's sub-tabs (section 3e): the list's generation
        // last sent (0: send it), and the sub-tab whose conversation is
        // shown instead of the tab's (null: the tab's own).
        var subs_gen: u64 = 0;
        var sub_shown: ?tabs.Id = null;
        const subs_list = srv.gpa.create(subtabs_wire.List) catch return;
        defer srv.gpa.destroy(subs_list);
        var subs_out: std.Io.Writer.Allocating = .init(srv.gpa);
        defer subs_out.deinit();
        // Every tab's background tasks and usage (section 3c): after hello,
        // then whenever any of it (or the tab list) changes.
        var activity_seen: u64 = 0;
        const act = srv.gpa.create(activity_wire.Activity) catch return;
        defer srv.gpa.destroy(act);
        var act_out: std.Io.Writer.Allocating = .init(srv.gpa);
        defer act_out.deinit();
        // The system monitor's sample last sent (section 3d).
        var sys_seen: u64 = 0;
        while (true) {
            ws.writer_wakes +|= 1;
            // Event-driven: wakes on output, resize, a tab list change, a
            // switch the reader asked for, the reader ending, or a
            // revocation (wakeViewers); otherwise sleeps until the session
            // would expire. No periodic recheck.
            const expires_in = srv.sessionExpiresIn(&ws.cookie) orelse 0;
            hub.mutex.lockUncancelable(srv.io);
            const cur_closed = if (cur) |c| c.session.closed else false;
            const cur_gen = if (cur) |c| c.session.term.gen else sent_gen;
            const convo_changed = if (cur) |c| blk: {
                const cv = shownConvo(c, sub_shown).convo;
                break :blk cv.epoch != convo_epoch or cv.rev != convo_rev or c.subs.gen != subs_gen;
            } else false;
            const sys_due = if (srv.sysmon) |m| ws.sys_on.load(.acquire) and m.gen.load(.acquire) != sys_seen else false;
            if (!hub.finished and !full and cur_gen == sent_gen and !(cur_closed and !ended_sent) and !convo_changed and
                hub.activity_gen == activity_seen and !sys_due and
                ws.want == .none and ws.sub_want == .none and hub.gen == seen_gen and !ws.dead.load(.acquire) and expires_in > 0 and
                srv.sync_gen.load(.acquire) == sync_seen)
            {
                hub.cond.waitTimeout(srv.io, &hub.mutex, .{ .duration = .{
                    // Until the session expires, or sooner while an image
                    // blob waits for this viewer's byte budget: exactly
                    // when the budget will have refilled enough for it.
                    .raw = .fromMilliseconds(if (images.wait_ms) |ms| @min(expires_in, @max(ms, 1)) else expires_in),
                    .clock = .awake,
                } }) catch |err| switch (err) {
                    error.Timeout => {},
                    error.Canceled => {
                        // waitTimeout re-acquired the mutex before returning.
                        hub.mutex.unlock(srv.io);
                        return;
                    },
                };
            }
            // A switch the reader asked for.
            const Answer = enum { none, session, nosession };
            var answer: Answer = .none;
            switch (ws.want) {
                .none => {},
                .tab => |t| {
                    if (cur) |c| c.release(); // never takes the hub lock
                    cur = t;
                    full = true;
                    ended_sent = false;
                    convo_epoch = 0;
                    subs_gen = 0;
                    sub_shown = null;
                    images.deinit(srv.gpa);
                    images = .{};
                    answer = .session;
                },
                .unknown => answer = .nosession,
            }
            ws.want = .none;
            // The conversation the reader asked for (`a:`).
            switch (ws.sub_want) {
                .none => {},
                .main => {
                    sub_shown = null;
                    convo_epoch = 0;
                },
                .sub => |id| {
                    sub_shown = id;
                    convo_epoch = 0;
                },
            }
            ws.sub_want = .none;
            const list_changed = hub.gen != seen_gen;
            if (list_changed) {
                hub.entriesLocked(&list);
                seen_gen = hub.gen;
            }
            const finished = hub.finished;
            const last_code = hub.last_code;
            var ended: ?u32 = null;
            if (cur) |c| if (c.session.closed and !ended_sent and !finished) {
                ended = c.session.exit_code;
                ended_sent = true;
            };
            // Encode under the lock so the frame is a consistent snapshot.
            var encode_ok = true;
            var changed = false;
            if (cur) |c| {
                const t = &c.session.term;
                if (t.cols != sent_cols or t.rows != sent_rows) full = true;
                changed = full or t.gen != sent_gen;
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
                // The sub-tabs, when they changed (before the
                // conversation, which may be one of them).
                subs_out.clearRetainingCapacity();
                if (encode_ok and c.subs.gen != subs_gen) {
                    c.subs.entries(c.id, subs_list);
                    subtabs_wire.write(&subs_out.writer, c.id, subs_list.slice()) catch {
                        encode_ok = false;
                    };
                    subs_gen = c.subs.gen;
                }
                // The conversation: the whole of it after a switch or a
                // new start, else what changed. A sub-tab that went (the
                // tab's conversation started over) shows the tab's own.
                convo_out.clearRetainingCapacity();
                const shown = shownConvo(c, sub_shown);
                if (shown.gone) {
                    sub_shown = null;
                    convo_epoch = 0;
                }
                const cv = shown.convo;
                if (encode_ok and (cv.epoch != convo_epoch or cv.rev != convo_rev)) {
                    const cw = &convo_out.writer;
                    if (cv.epoch != convo_epoch) {
                        cv.writeSnapshot(cw, shown.id) catch {
                            encode_ok = false;
                        };
                    } else {
                        _ = cv.writeSince(cw, shown.id, convo_rev) catch {
                            encode_ok = false;
                        };
                    }
                    convo_epoch = cv.epoch;
                    convo_rev = cv.rev;
                }
            }
            act_out.clearRetainingCapacity();
            if (encode_ok and (hub.activity_gen != activity_seen or list_changed)) {
                hub.activityLocked(act);
                activity_wire.write(&act_out.writer, act) catch {
                    encode_ok = false;
                };
                activity_seen = hub.activity_gen;
            }
            const cur_id: ?tabs.Id = if (cur) |c| c.id else null;
            hub.mutex.unlock(srv.io);

            if (ws.dead.load(.acquire)) return;
            if (!encode_ok) return; // out of memory: drop this viewer, keep the session

            // In order: what is shown now, the list, a tab's end, then
            // that tab's screen.
            switch (answer) {
                .none => {},
                .session => if (cur_id) |id| {
                    const m = std.fmt.bufPrint(&msg, "{{\"t\":\"session\",\"id\":\"{s}\"}}", .{&tabs_wire.idHex(id)}) catch return;
                    if (!ws.send(srv, m, .text)) return;
                },
                .nosession => if (!ws.send(srv, "{\"t\":\"nosession\"}", .text)) return,
            }
            if (list_changed) {
                const m = tabsMessage(text, list.slice()) catch return;
                if (!ws.send(srv, m, .text)) return;
            }
            if (ended) |code| if (cur_id) |id| {
                const m = std.fmt.bufPrint(&msg, "{{\"t\":\"ended\",\"id\":\"{s}\",\"code\":{d}}}", .{ &tabs_wire.idHex(id), code }) catch return;
                if (!ws.send(srv, m, .text)) return;
            };
            if (changed) {
                if (!ws.send(srv, frame.items, .binary)) return;
            }
            var image_frames = images.frames();
            while (image_frames.next()) |f| if (!ws.send(srv, f, .binary)) return;
            if (subs_out.written().len > 0) {
                if (!ws.send(srv, subs_out.written(), .text)) return;
            }
            if (convo_out.written().len > 0) {
                if (!ws.send(srv, convo_out.written(), .text)) return;
            }
            if (act_out.written().len > 0) {
                if (!ws.send(srv, act_out.written(), .text)) return;
            }
            if (srv.sysmon) |m| if (ws.sys_on.load(.acquire) and m.gen.load(.acquire) != sys_seen) {
                var snap: sysinfo.Snapshot = undefined;
                sys_seen = m.latest(&snap);
                var sb: [sysinfo.max_message]u8 = undefined;
                var sw: std.Io.Writer = .fixed(&sb);
                sysinfo.write(&sw, &snap) catch return;
                if (!ws.send(srv, sw.buffered(), .text)) return;
            };
            const gen_now = srv.sync_gen.load(.acquire);
            if (gen_now != sync_seen) {
                sync_seen = gen_now;
                const d = srv.syncDigestFor(ws_device);
                if (!std.mem.eql(u8, &d, &sync_digest)) {
                    sync_digest = d;
                    if (!ws.send(srv, "{\"t\":\"updates\"}", .text)) return;
                }
            }
            // Every tab has ended: the last program's exit code, after
            // the final screen, then the closing handshake.
            if (!changed and finished) {
                const m = std.fmt.bufPrint(&msg, "{{\"t\":\"exit\",\"code\":{d}}}", .{last_code}) catch return;
                if (ws.send(srv, m, .text)) srv.wsGoodbye(ws);
                return;
            }

            // Logout, expiry, or the device being unpaired (possibly by
            // `portal unpair` in another process: the pairing watcher then
            // ends its sessions and wakes this loop) ends the stream.
            // Checked on every wake; memory only.
            if (!srv.sessionLive(&ws.cookie, false)) {
                _ = ws.send(srv, srv.logoutMessage(ws.device), .text);
                return;
            }
            // Coalesce bursts of output into at most ~30 frames per second.
            if (changed) srv.io.sleep(.fromMilliseconds(frame_interval_ms), .awake) catch return;
        }
    }

    /// After the exit notice: starts the closing handshake (1000, "session
    /// ended") and waits, at most `goodbye_ms`, for the viewer to close
    /// its end (its close frame or EOF ends the reader). Closing first
    /// with the viewer's frames unread would reset the connection, and a
    /// reset can discard the exit notice before the viewer has read it.
    /// Event-driven: the reader ending broadcasts `hub.cond`.
    fn wsGoodbye(srv: *Server, ws: *WsConn) void {
        _ = ws.send(srv, "\x03\xe8session ended", .close);
        const s = srv.hub;
        const deadline = srv.nowMs() +| goodbye_ms;
        s.mutex.lockUncancelable(srv.io);
        defer s.mutex.unlock(srv.io);
        while (!ws.dead.load(.acquire)) {
            const left = deadline -| srv.nowMs();
            if (left <= 0) return;
            s.cond.waitTimeout(srv.io, &s.mutex, .{ .duration = .{
                .raw = .fromMilliseconds(left),
                .clock = .awake,
            } }) catch |err| switch (err) {
                error.Timeout => {},
                // waitTimeout re-acquired the mutex before returning.
                error.Canceled => return,
            };
        }
    }

    fn wsReadLoop(srv: *Server, ws: *WsConn, leftover: []const u8) void {
        defer {
            // A System panel left open: it is closed now.
            if (ws.sys_on.swap(false, .acq_rel)) if (srv.sysmon) |m| m.unsubscribe();
            ws.dead.store(true, .release);
            // Wake the writer so it notices promptly.
            srv.hub.mutex.lockUncancelable(srv.io);
            srv.hub.mutex.unlock(srv.io);
            srv.hub.cond.broadcast(srv.io);
        }
        var buf: [max_ws_header + max_ws_payload]u8 = undefined;
        if (leftover.len > buf.len) return;
        @memcpy(buf[0..leftover.len], leftover);
        var len: usize = leftover.len;

        while (!ws.dead.load(.acquire)) {
            const parsed = websocket.parseHeader(buf[0..len], .client, max_ws_payload) catch {
                _ = ws.send(srv, &.{ 0x03, 0xea }, .close); // 1002 protocol error
                return;
            };
            if (parsed) |f| {
                const total = f.len + f.payload_len;
                if (total <= len) {
                    const payload = buf[f.len..total];
                    if (f.mask) |m| websocket.applyMask(payload, m);
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
    fn wsHandleFrame(srv: *Server, ws: *WsConn, opcode: websocket.Opcode, payload: []const u8) bool {
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
                // "k:<name>" key press, "t:<text>" typing, "l:<line>"
                // instruction, "s:<id>" watch another open tab
                // (docs/protocol.md section 4).
                if (payload.len < 2 or payload[1] != ':') return true;
                // Re-check on every input message, not just periodically.
                if (!srv.sessionLive(&ws.cookie, false)) return false;
                // Switching tabs is not input: also in view-only mode.
                if (payload[0] == 's') {
                    srv.subscribe(ws, payload[2..]);
                    return true;
                }
                // Showing a sub-tab (or the tab's own conversation again)
                // is not input either.
                if (payload[0] == 'a') {
                    srv.viewSub(ws, payload[2..]);
                    return true;
                }
                // A sub-tab is read-only: nothing typed while it is shown.
                if (ws.sub_view) return true;
                // The System panel (read-only, every mode): "y:on" / "y:off".
                if (payload[0] == 'y') {
                    srv.sysPanel(ws, payload[2..]);
                    return true;
                }
                if (srv.hub.policy == .none) return true;
                // Input goes to the tab this viewer last chose, and only
                // while it is open (a closed one drops it: input_open).
                const s = &(ws.sel orelse return true).session;
                switch (payload[0]) {
                    'k' => s.writeWebKey(payload[2..], srv.nowMs()) catch |err| {
                        // Up/Down in instruct mode while the program is not
                        // waiting (keymap.KeyError: Portal's own names).
                        srv.log.print("key from {s} rejected: {t}", .{ ws.conn.peer(), err });
                        var msg: [96]u8 = undefined;
                        const m = std.fmt.bufPrint(&msg, "{{\"t\":\"rejected\",\"reason\":\"{t}\"}}", .{err}) catch return true;
                        return ws.send(srv, m, .text);
                    },
                    't' => s.writeWebText(payload[2..]),
                    'l' => s.writeWebLine(payload[2..]) catch |err| {
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

/// Writes a JSON string body: `"` and `\` escaped (names are printable,
/// tabs_wire.validName).
fn writeEscaped(w: *std.Io.Writer, s: []const u8) !void {
    for (s) |c| {
        if (c == '"' or c == '\\') try w.writeByte('\\');
        try w.writeByte(c);
    }
}

/// `{"t":"hello","v":2,"input":...,"project":<name>,"session":<id>,
/// "sessions":[...]}` (docs/protocol.md section 3): the input mode, the
/// tab this viewer starts on (its name also as `project`, for clients
/// that predate tabs) and every open tab. No paths: names are
/// desk-assigned, ids random.
fn helloMessage(buf: []u8, policy: keymap.Policy, cur: ?tabs_wire.Entry, list: []const tabs_wire.Entry) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.print("{{\"t\":\"hello\",\"v\":2,\"input\":\"{t}\"", .{policy});
    if (cur) |c| {
        try w.writeAll(",\"project\":\"");
        try writeEscaped(&w, c.name());
        try w.print("\",\"session\":\"{s}\"", .{&tabs_wire.idHex(c.id)});
    }
    try w.writeByte(',');
    try tabs_wire.writeList(&w, list);
    try w.writeByte('}');
    return w.buffered();
}

/// `{"t":"tabs","sessions":[...]}`: the open tabs changed (opened,
/// closed, renamed, a program's state).
fn tabsMessage(buf: []u8, list: []const tabs_wire.Entry) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.writeAll("{\"t\":\"tabs\",");
    try tabs_wire.writeList(&w, list);
    try w.writeByte('}');
    return w.buffered();
}

test "hello and tabs messages" {
    var buf: [tabs_wire.max_list_json + 256]u8 = undefined;
    try testing.expectEqualStrings("{\"t\":\"hello\",\"v\":2,\"input\":\"instruct\",\"sessions\":[]}", try helloMessage(&buf, .instruct, null, &.{}));
    var e: tabs_wire.Entry = .{ .id = @splat(0xab), .color = 0x3366CC, .state = .waiting };
    e.setName("a \"b\" \\c");
    const h = try helloMessage(&buf, .keys, e, &.{e});
    try testing.expectEqualStrings("{\"t\":\"hello\",\"v\":2,\"input\":\"keys\",\"project\":\"a \\\"b\\\" \\\\c\",\"session\":\"abababababababababababababababab\"," ++
        "\"sessions\":[{\"id\":\"abababababababababababababababab\",\"name\":\"a \\\"b\\\" \\\\c\",\"color\":\"#3366cc\",\"state\":\"waiting\"}]}", h);
    // Clients parse it back with the shared parser.
    try testing.expectEqualStrings("a \"b\" \\c", tabs_wire.parseList(h).?.items[0].name());
    try testing.expectEqual(e.id, tabs_wire.idField(h, "session").?);
    // The longest list, every name fully escaped, still fits.
    var full: [tabs_wire.max_tabs]tabs_wire.Entry = undefined;
    const worst: [64]u8 = @splat('"');
    for (&full) |*x| {
        x.* = .{};
        x.setName(&worst);
    }
    _ = try helloMessage(&buf, .text, full[0], &full);
    try testing.expect(std.mem.startsWith(u8, try tabsMessage(&buf, &full), "{\"t\":\"tabs\",\"sessions\":[{"));
}

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
    "set_layout",    "set_class",     "box_read",      "box_write",
    "box_hint",      "set_tab",
};
/// Every export the bridge calls.
const client_exports = [_][]const u8{
    "memory",     "init",     "in_alloc", "resize",   "frame",    "on_ws_open", "on_ws_close",
    "on_ws_message", "on_timer", "on_check", "on_key", "on_pointer", "on_wheel", "on_cmd",
    "on_viewport",   "on_box_input", "on_box_key", "on_button", "on_ptab",
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
    try std.testing.expect(std.mem.count(u8, app_js, "\n") <= 110);
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
