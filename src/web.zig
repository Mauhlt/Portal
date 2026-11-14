//! The WebSocket front end, inside the in-process tunnel (client/src/tunnel).
//!
//! Who is connecting: a connection reaches this file only through the
//! tunnel, which lets in only the WireGuard keys of paired devices, each
//! only from its own address (devices.zig). So the stream's remote address
//! names exactly one paired device; a connection from any other address
//! (a record removed a moment ago) is closed at once. There is no sign-in,
//! cookie or credential: the device is its key.
//!
//! What a device can do, over TLS 1.3 (the pinned Portal CA proves the
//! desktop's identity on top of WireGuard) and HTTP/1.1 only far enough to
//! upgrade:
//!   GET /ws        the interactive WebSocket (priority .interactive):
//!                  watch the session's output, send keystrokes that pass
//!                  the input filter, switch tabs, Forget this desktop
//!   GET /ws/bulk   the bulk WebSocket (priority .bulk): request/reply
//!                  sync transfers (shared/bulk.zig), so a large download
//!                  never delays a keystroke
//! Anything else is answered 404 and the connection closed. There is no
//! route that starts a process, changes directory, or touches files.
//!
//! Request pipeline (every request):
//!   1. Host header must be on the allowlist        (10.8.0.1:8420)
//!   2. Framing checks (no Transfer-Encoding, Expect, bodies, unknown
//!      methods); any problem closes the connection
//!   3. Route; unknown paths/methods are rejected
//!
//! Connection model. Every accepted connection gets a supervisor thread and
//! a worker task (`io.concurrent`). The worker does all stream I/O; the
//! supervisor enforces deadlines (head read, keep-alive idle, stuck sends),
//! evictions and unpairing by canceling the worker, which makes a blocked
//! read/write return error.Canceled (the tunnel's streams wait in
//! cancelable Io waits, shared/transport.zig). The supervisor sleeps until
//! the earliest of those deadlines or until it is signalled: an idle
//! connection costs no wakeups.
//!
//! HTTP parsing is src/http1.zig, never std.http.Server (which had remotely
//! reachable panics). Any panic on any thread kills the user's live session,
//! so nothing here may assert, unwrap or overflow on peer-controlled data.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;

const guard = @import("guard.zig");
const http1 = @import("http1.zig");
const websocket = @import("shared").ws;
/// The stream seam: the tunnel's streams (shared/transport.zig).
const transport = @import("shared").transport;
const tunnelnet = @import("shared").tunnelnet;
const bulk = @import("shared").bulk;
const parts = @import("shared").parts;
const tabs = @import("tabs.zig");
const vt = @import("vt.zig");
const tabs_wire = @import("shared").tabs;
const planusage = @import("shared").planusage;
const usage_desk = @import("usage_desk.zig");
const Log = @import("log.zig").Log;
const devices = @import("devices.zig");
const tls = @import("tls/server.zig");
const web_images = @import("web_images.zig");
const sync = @import("sync.zig");
const sync_manifest = @import("client").sync.manifest;
const sync_keypin = @import("client").sync.keypin;
const keymap = @import("keymap.zig");
const title = @import("title.zig");
const activity_wire = @import("shared").activity;
const sysinfo = @import("shared").sysinfo;
const subtabs_wire = @import("shared").subtabs;
const sysmon = @import("sysmon.zig");
const frames = @import("shared").frames;
const foryou_ws = @import("foryou_ws.zig");
const projects_ws = @import("projects_ws.zig");
const ratelimit = @import("ratelimit.zig");

/// Hard cap on simultaneous connections (each costs a supervisor thread and
/// a worker thread, a WebSocket one more).
const max_connections = 32;
/// Connections not yet upgraded to a WebSocket. Every one comes from a
/// paired device's key; the cap only bounds what a misbehaving device can
/// hold open.
const max_pre_auth = 16;
const max_pre_auth_per_ip = 8;
/// Upgraded connections one device may hold per channel. A client keeps
/// one interactive WebSocket and opens a bulk one per sync request (one
/// at a time). Four interactive leave room for a second viewer on the
/// device and a reconnect overlapping a dying one; two bulk for a second
/// process of the same device (`portal sync`). A new one
/// over the cap ends that device's oldest on the same channel, so one
/// device can never hold every slot.
pub const max_upgraded_per_device: std.EnumArray(Channel, usize) = .init(.{ .interactive = 4, .bulk = 2 });

const max_requests_per_connection = 16;
const max_body = 0;
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
/// A request head must arrive within this long of its first byte, or of
/// the connection being accepted.
const head_timeout_ms = 10_000;
/// Keep-alive connection waiting for its next request.
const idle_timeout_ms = 60_000;
/// Any single response or WebSocket message must be accepted by the peer
/// within this long.
const send_timeout_ms = 30_000;
/// A bulk WebSocket waiting for its next request.
const bulk_idle_ms = 120_000;
/// After the supervisor sees a WebSocket's device unpaired, the writer has
/// this long to notice and say goodbye before the connection is canceled.
const revoke_grace_ms = 10_000;
const no_deadline = std.math.maxInt(i64);
/// Per-peer log lines: at most `burst` per this interval per kind.
const peer_log_interval_ms = 10_000;
/// Per-device input limits, shared by all of a device's WebSockets
/// (messages and bytes per second, with bursts twice that). Answering
/// prompts needs a few per second; more is dropped.
pub const input_msgs_per_s = 40;
pub const input_bytes_per_s = 16 * 1024;

pub const Config = struct {
    /// Exact Host header values accepted: "10.8.0.1:8420".
    allowed_hosts: []const []const u8,
    /// Where the paired-device store lives (%LOCALAPPDATA%\Portal).
    devices: devices.Paths,
    /// TLS 1.3, always (the leaf and the Portal CA, so a device can pin
    /// the CA from the fingerprint in its pairing code).
    tls: *const tls.Credentials,
    /// The sync release public key (docs/sync-design.md); null: every bulk
    /// request is answered 404.
    sync_key: ?[32]u8 = null,
};

/// What a device's sync index currently hashes to (main.zig's sync
/// watcher keeps these; a change sends that device {"t":"updates"}).
pub const SyncDigest = struct {
    device: devices.Text = .{},
    digest: [32]u8 = @splat(0),
};

/// A paired device as the server knows it (from the last store read).
pub const Peer = struct {
    ip: tunnelnet.Ip4,
    id: devices.DeviceId,
    name: devices.Text,
    /// Its address may still carry an older key in the tunnel (the store
    /// changed and the tunnel's peer table has not caught up,
    /// tunneldesk.Applier): nothing is admitted from it and no connection
    /// counts as this record's.
    refused: bool = false,
};

/// The two WebSockets (`GET /ws`, `GET /ws/bulk`).
pub const Channel = enum { interactive, bulk };

/// `peers` from store `st`, those at `refused` addresses marked refused.
fn setPeers(peers: *[devices.max_devices]?Peer, st: *const devices.Store, refused: []const tunnelnet.Ip4) void {
    for (peers, st.devices) |*p, d| p.* = if (d) |dev| .{
        .ip = dev.ip,
        .id = dev.id,
        .name = dev.name,
        .refused = for (refused) |ip| {
            if (std.mem.eql(u8, &ip, &dev.ip)) break true;
        } else false,
    } else null;
}

/// The record admitted from address `ip`: none if refused.
fn peerAt(peers: *const [devices.max_devices]?Peer, ip: tunnelnet.Ip4) ?Peer {
    for (peers) |slot| if (slot) |p| if (std.mem.eql(u8, &p.ip, &ip)) return if (p.refused) null else p;
    return null;
}

/// Null while record `p` is still the one at its address (and not
/// refused); else why its connections end: `replaced` if its name is
/// still paired (under another record), `unpaired` if not.
fn endReasonIn(peers: *const [devices.max_devices]?Peer, p: *const Peer) ?Server.EndReason {
    var replaced = false;
    for (peers) |slot| if (slot) |q| {
        if (std.mem.eql(u8, &q.id, &p.id) and std.mem.eql(u8, &q.ip, &p.ip) and !q.refused) return null;
        if (std.mem.eql(u8, q.name.get(), p.name.get())) replaced = true;
    };
    return if (replaced) .replaced else .unpaired;
}

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
/// cannot lock a real user out; upgraded connections are never evicted by
/// a pre-auth one, only by a newer upgrade of the same device and channel
/// over `max_upgraded_per_device` (`promote`).
pub const ConnTable = struct {
    pub const Entry = struct {
        used: bool = false,
        key: IpKey = @splat(0),
        authed: bool = false,
        evicted: bool = false,
        since_ms: i64 = 0,
        /// Set by `promote`.
        device: devices.DeviceId = @splat(0),
        channel: Channel = .interactive,
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
    max_upgraded: std.EnumArray(Channel, usize) = max_upgraded_per_device,

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

    /// Slot `slot` is now device `id`'s WebSocket on `ch`. Returns the
    /// connection to tear down if the device is now over its cap on `ch`
    /// (its oldest there), else null.
    pub fn promote(t: *ConnTable, slot: usize, id: devices.DeviceId, ch: Channel) ?usize {
        if (slot >= t.entries.len) return null;
        var n: usize = 0;
        var oldest: ?usize = null;
        for (t.entries, 0..) |e, i| {
            if (i == slot or !e.used or !e.authed or e.evicted or e.channel != ch) continue;
            if (!std.mem.eql(u8, &e.device, &id)) continue;
            n += 1;
            if (oldest == null or e.since_ms < t.entries[oldest.?].since_ms) oldest = i;
        }
        const s = &t.entries[slot];
        s.authed = true;
        s.device = id;
        s.channel = ch;
        if (n < t.max_upgraded.get(ch)) return null;
        const v = oldest orelse return null;
        t.entries[v].evicted = true;
        return v;
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

/// A device's input limit (Server.input_limits): a message must fit both
/// buckets.
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

/// A device's input limits, one per channel (Server.input_limits).
pub const DeviceInput = struct {
    interactive: InputLimit = .{},
    bulk: InputLimit = .{},

    pub fn forChannel(d: *DeviceInput, ch: Channel) *InputLimit {
        return switch (ch) {
            .interactive => &d.interactive,
            .bulk => &d.bulk,
        };
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
    stream: transport.Stream,
    slot: usize,
    /// The paired device this connection comes from (by its tunnel address).
    device: Peer,
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
    /// Set (release) once the connection is a WebSocket: the supervisor
    /// then also ends it when its device is unpaired.
    ws_active: std.atomic.Value(bool) = .init(false),
    /// Worker-only (the supervisor reads it once the worker finished):
    /// counted in Session.viewer_sockets until the socket is closed.
    viewer_socket: bool = false,
    /// Worker-only: already promoted to an upgraded slot.
    authed: bool = false,
    /// Set once the TLS handshake is done.
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
    /// Port 8420 inside the tunnel (client/src/tunnel).
    listener: transport.Listener,

    /// The paired devices, as last read from the store (applyStore):
    /// which tunnel address is which device.
    peer_mutex: Io.Mutex = .init,
    peers: [devices.max_devices]?Peer = @splat(null),

    conn_mutex: Io.Mutex = .init,
    /// Broadcast whenever a connection's slot is released (awaitGone).
    conn_cond: Io.Condition = .init,
    conns: ConnTable = .{},
    conn_wake: [max_connections]Io.Event = @splat(.unset),
    conn_evict: [max_connections]std.atomic.Value(bool) = @splat(.init(false)),

    note_mutex: Io.Mutex = .init,
    host_reject_log: LogLimiter = .{},
    tls_fail_log: LogLimiter = .{},
    unknown_log: LogLimiter = .{},
    input_log: LogLimiter = .{},
    thread_log: LogLimiter = .{},
    sync_log: LogLimiter = .{},
    sysmon_log: LogLimiter = .{},
    store_log: LogLimiter = .{},

    /// The optional system monitor (sysmon.zig; null: none). `y:on` from a
    /// viewer subscribes only while the desk's setting is on.
    sysmon: ?*sysmon.Monitor = null,

    /// For-you answers and recaps per device (foryou_ws.zig).
    fy_limits: foryou_ws.Limits = .{},

    /// Times the store watcher woke up (for the wakeup measurement).
    pairwatch_wakes: std.atomic.Value(u32) = .init(0),
    /// Optional hook, like Session.notify_fn: called whenever the paired
    /// devices may have changed, on the changing thread with no lock held.
    /// The Portal window uses it to refresh its Devices panel.
    store_notify_ctx: ?*anyopaque = null,
    store_notify_fn: ?*const fn (ctx: *anyopaque) void = null,

    /// Per-device sync index digests, and a generation bumped whenever
    /// they are replaced (setSyncDigests).
    sync_mutex: Io.Mutex = .init,
    sync_digests: [devices.max_devices]SyncDigest = @splat(.{}),
    sync_n: usize = 0,
    sync_gen: std.atomic.Value(u64) = .init(0),

    /// Each paired device's `p:start` / `p:stop` rate (projects_ws.zig).
    project_limits: projects_ws.Limits = .{},

    /// Each paired device's message budget per channel, over all its
    /// WebSockets (more sockets never mean more PTY input).
    input_mutex: Io.Mutex = .init,
    input_limits: ratelimit.Table(DeviceInput) = .{},

    /// Why a device's connections end (docs/protocol.md, `logout`).
    /// `unpaired`: its record was removed at the desk; the device forgets
    /// this desktop. `replaced`: the name was paired again (a new key); the
    /// old key is no longer let in either.
    pub const EndReason = enum { unpaired, replaced };

    fn nowUnix(srv: *const Server) i64 {
        return Io.Timestamp.now(srv.io, .real).toSeconds();
    }

    /// Monotonic ms: connection deadlines and rate limits.
    fn nowMs(srv: *const Server) i64 {
        return Io.Timestamp.now(srv.io, .awake).toMilliseconds();
    }

    // ------------------------------------------------------ paired devices

    /// The paired device at tunnel address `addr`, if any (and not
    /// refused). By address only: the stream does not carry the WireGuard
    /// key, so this relies on the tunnel letting each address in only
    /// with its record's key, which `refused` covers while the peer table
    /// catches up with the store.
    pub fn deviceAt(srv: *Server, addr: net.IpAddress) ?Peer {
        const ip: tunnelnet.Ip4 = switch (addr) {
            .ip4 => |a| a.bytes,
            .ip6 => return null,
        };
        srv.peer_mutex.lockUncancelable(srv.io);
        defer srv.peer_mutex.unlock(srv.io);
        return peerAt(&srv.peers, ip);
    }

    /// Null while record `p` is still paired at its address (and not
    /// refused); else why its connections end.
    pub fn endReason(srv: *Server, p: *const Peer) ?EndReason {
        srv.peer_mutex.lockUncancelable(srv.io);
        defer srv.peer_mutex.unlock(srv.io);
        return endReasonIn(&srv.peers, p);
    }

    /// Called by the store watcher (tunneldesk.Applier) with a freshly
    /// read store (only a successful read gets here, so a store error
    /// never ends anyone): refreshes the paired devices, marking those at
    /// `refused` addresses refused, then wakes every connection so those
    /// of removed, replaced or refused records say goodbye.
    pub fn applyStore(srv: *Server, st: *const devices.Store, refused: []const tunnelnet.Ip4) void {
        srv.peer_mutex.lockUncancelable(srv.io);
        setPeers(&srv.peers, st, refused);
        srv.peer_mutex.unlock(srv.io);
        srv.wakeViewers();
        srv.storeChanged();
    }

    /// Calls `store_notify_fn`: the paired devices, or how they are
    /// applied, may have changed.
    pub fn storeChanged(srv: *Server) void {
        if (srv.store_notify_fn) |f| if (srv.store_notify_ctx) |c| f(c);
    }

    /// The store watcher could not read the store: say so (rate limited),
    /// end nothing, keep the last known devices.
    pub fn noteStoreError(srv: *Server, err: anyerror) void {
        srv.notePeer(&srv.store_log, "device store unreadable ({t}): {s}", .{ err, devices.describeError(err) });
    }

    /// After any store change: every WebSocket writer and supervisor
    /// re-checks its device now (they do not poll).
    fn wakeViewers(srv: *Server) void {
        srv.hub.mutex.lockUncancelable(srv.io);
        srv.hub.mutex.unlock(srv.io);
        srv.hub.cond.broadcast(srv.io);
        for (&srv.conn_wake) |*e| e.set(srv.io);
    }

    fn logoutMessage(reason: EndReason) []const u8 {
        return switch (reason) {
            .unpaired => "{\"t\":\"logout\",\"reason\":\"unpaired\"}",
            .replaced => "{\"t\":\"logout\",\"reason\":\"replaced\"}",
        };
    }

    /// `lim.check` under `note_mutex`: the number of suppressed lines if
    /// this one should be logged, else null.
    fn limited(srv: *Server, lim: *LogLimiter, interval_ms: i64) ?u32 {
        srv.note_mutex.lockUncancelable(srv.io);
        defer srv.note_mutex.unlock(srv.io);
        return lim.check(srv.nowMs(), interval_ms);
    }

    /// Logs a line a peer can cause, at most `lim.burst` per interval,
    /// noting how many were suppressed.
    fn notePeer(srv: *Server, lim: *LogLimiter, comptime fmt: []const u8, args: anytype) void {
        const suppressed = srv.limited(lim, peer_log_interval_ms) orelse return;
        if (suppressed == 0) {
            srv.log.print(fmt, args);
        } else {
            srv.log.print(fmt ++ " ({d} similar lines suppressed)", args ++ .{suppressed});
        }
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

    /// Accept loop. Runs on its own thread for the life of the process.
    pub fn run(srv: *Server) void {
        var backoff: Backoff = .{};
        var accept_log: LogLimiter = .{};
        var full_log: LogLimiter = .{};
        while (true) {
            const stream = srv.listener.accept(srv.io) catch |err| {
                if (err == error.Canceled) return;
                if (accept_log.check(srv.nowMs(), std.time.ms_per_min)) |n|
                    srv.log.print("accept error: {t} ({d} more since last report)", .{ err, n });
                srv.io.sleep(.fromMilliseconds(backoff.next()), .awake) catch {};
                continue;
            };
            backoff.reset();
            srv.admit(stream, &full_log);
        }
    }

    fn admit(srv: *Server, stream: transport.Stream, full_log: *LogLimiter) void {
        const io = srv.io;
        const now = srv.nowMs();
        // Only paired devices' keys get through the tunnel; a record removed
        // a moment ago (its key not yet out of the peer table) gets nothing.
        const device = srv.deviceAt(stream.remote()) orelse {
            srv.notePeer(&srv.unknown_log, "connection from {f} refused: no paired device has that address", .{stream.remote()});
            stream.close(io);
            return;
        };
        srv.conn_mutex.lockUncancelable(io);
        const adm = srv.conns.admit(ipKey(stream.remote()), now);
        if (adm.victim) |v| srv.evictLocked(v);
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
        const t = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, supervise, .{ srv, stream, slot, device }) catch {
            srv.releaseSlot(slot);
            stream.close(io);
            return;
        };
        t.detach();
    }

    /// Tells slot `v`'s supervisor to end it (conn_mutex held).
    fn evictLocked(srv: *Server, v: usize) void {
        srv.conn_evict[v].store(true, .release);
        srv.conn_wake[v].set(srv.io);
    }

    fn releaseSlot(srv: *Server, slot: usize) void {
        srv.conn_mutex.lockUncancelable(srv.io);
        srv.conns.release(slot);
        srv.conn_mutex.unlock(srv.io);
        srv.conn_cond.broadcast(srv.io);
    }

    /// Waits (event-driven, at most `max_ms`) until no connection from
    /// these tunnel addresses is left: removed devices get their `logout`
    /// before their keys leave the tunnel (StoreWatch, main.zig).
    pub fn awaitGone(srv: *Server, ips: []const tunnelnet.Ip4, max_ms: i64) void {
        const deadline = srv.nowMs() +| max_ms;
        srv.conn_mutex.lockUncancelable(srv.io);
        defer srv.conn_mutex.unlock(srv.io);
        while (true) {
            var any = false;
            for (srv.conns.entries) |e| {
                if (!e.used) continue;
                for (ips) |ip| any = any or std.mem.eql(u8, e.key[12..16], &ip);
            }
            if (!any) return;
            const left = deadline -| srv.nowMs();
            if (left <= 0) return;
            srv.conn_cond.waitTimeout(srv.io, &srv.conn_mutex, .{ .duration = .{ .raw = .fromMilliseconds(left), .clock = .awake } }) catch return;
        }
    }

    fn promote(srv: *Server, conn: *Conn, ch: Channel) void {
        if (conn.authed) return;
        conn.authed = true;
        srv.conn_mutex.lockUncancelable(srv.io);
        if (srv.conns.promote(conn.slot, conn.device.id, ch)) |v| srv.evictLocked(v);
        srv.conn_mutex.unlock(srv.io);
    }

    /// Device `id` may send a `len`-byte message on `ch` now (its budget
    /// over all its WebSockets on that channel).
    fn inputAllowed(srv: *Server, id: devices.DeviceId, ch: Channel, len: usize) bool {
        const now = srv.nowMs();
        srv.input_mutex.lockUncancelable(srv.io);
        defer srv.input_mutex.unlock(srv.io);
        return srv.input_limits.get(id, now).forChannel(ch).allow(now, len);
    }

    /// Supervisor thread: owns the socket, runs the worker, enforces deadlines.
    fn supervise(srv: *Server, stream: transport.Stream, slot: usize, device: Peer) void {
        const io = srv.io;
        defer srv.releaseSlot(slot);

        var conn: Conn = .{
            .stream = stream,
            .slot = slot,
            .device = device,
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
        // The address the transport authenticated: inside the tunnel, the
        // device's tunnel address (sessions and credentials bind to it).
        const peer = std.fmt.bufPrint(&conn.peer_buf, "{f}", .{stream.remote()}) catch blk: {
            conn.peer_buf[0] = '?';
            break :blk conn.peer_buf[0..1];
        };
        conn.peer_len = peer.len;

        var worker = io.concurrent(connMain, .{ srv, &conn }) catch {
            srv.notePeer(&srv.thread_log, "connection from {s} dropped: no thread available", .{conn.peer()});
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
                reason = "evicted (over the connection limits)";
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
                if (srv.endReason(&conn.device) == null) {
                    revoked_since = null;
                } else if (revoked_since == null) {
                    revoked_since = now;
                }
            } else if (srv.endReason(&conn.device) != null) {
                // Not a WebSocket yet: there is no logout to deliver, so a
                // connection whose record went (or whose address is
                // refused) ends now, not at its head timeout.
                reason = "unpaired";
                break;
            }
            if (revoked_since) |r| {
                if (now -| r >= revoke_grace_ms) {
                    reason = "unpaired";
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
        srv.serveTls(conn, srv.cfg.tls);
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
        const raw_out = sw.interface();
        var entropy: [tls.entropy_len]u8 = undefined;
        io.randomSecure(&entropy) catch return;
        defer std.crypto.secureZero(u8, &entropy);
        defer st.tls.wipe();
        st.tls.handshake(sr.interface(), raw_out, .{
            .credentials = creds,
            .entropy = &entropy,
            .read_buffer = &.{},
            .write_buffer = &st.plain_out,
        }) catch |err| {
            srv.noteTlsFailure(conn, err, st.tls.diag, raw_out);
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
            .bad_certificate, .unknown_ca, .certificate_unknown, .access_denied => " - that device has another Portal CA pinned for this desktop (pair it again)",
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
        return conn.stream.read(io, dest);
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

            const keep = try srv.handleRequest(conn, w, &req, buf[head_len..len]);
            if (!keep or req.connection_close or req.method != .GET) return;

            // Keep any pipelined bytes of the next request.
            const rest = len - head_len;
            std.mem.copyForwards(u8, buf[0..rest], buf[head_len..len]);
            len = rest;
        }
    }

    fn noteHostRejected(srv: *Server, peer: []const u8, host: ?[]const u8) void {
        const suppressed = srv.limited(&srv.host_reject_log, 10_000) orelse return;
        const h = host orelse "(none)";
        srv.log.print("rejected request from {s}: Host '{s}' not allowed ({d} more since last report)", .{
            peer, h[0..@min(h.len, 80)], suppressed,
        });
    }

    /// The two WebSockets, nothing else. Returns whether to keep the
    /// connection open for another request (never: an upgrade keeps it,
    /// anything else is an error that closes it).
    fn handleRequest(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, leftover: []const u8) !bool {
        if (!guard.hostAllowed(req.host, srv.cfg.allowed_hosts)) {
            srv.noteHostRejected(conn.peer(), req.host);
            return srv.fail(conn, w, .misdirected_request, "unknown host\n");
        }
        if (http1.framingError(req, max_body)) |r| return srv.fail(conn, w, r.status, r.msg);
        if (req.method != .GET) return srv.fail(conn, w, .method_not_allowed, "method not allowed\n");
        const channel: Channel = if (std.mem.eql(u8, req.path, "/ws"))
            .interactive
        else if (std.mem.eql(u8, req.path, "/ws/bulk"))
            .bulk
        else
            return srv.fail(conn, w, .not_found, "not found\n");
        try srv.webSocket(conn, w, req, channel, leftover);
        return false;
    }

    // ---------------------------------------------------------- responses

    fn respond(srv: *Server, conn: *Conn, w: *Io.Writer, status: http1.Status, body: []const u8) !void {
        conn.setDeadline(srv.nowMs() +| send_timeout_ms);
        try http1.writeResponse(w, status, &.{
            .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
            .{ .name = "x-content-type-options", .value = "nosniff" },
            .{ .name = "cache-control", .value = "no-store" },
        }, body, false);
    }

    /// Error response; always closes the connection.
    fn fail(srv: *Server, conn: *Conn, w: *Io.Writer, status: http1.Status, body: []const u8) !bool {
        try srv.respond(conn, w, status, body);
        return false;
    }

    // --------------------------------------------------------- websocket

    const WsConn = struct {
        conn: *Conn,
        w: *Io.Writer,
        write_mutex: Io.Mutex = .init,
        /// Guarded by write_mutex: a close frame went out, send nothing more.
        close_sent: bool = false,
        dead: std.atomic.Value(bool) = .init(false),
        /// The paired device on the other end.
        device: Peer,
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

        /// One frame. Returns false if the connection should end.
        /// Cancelable: the supervisor can always tear down a sender stuck
        /// behind another. Only the writer task sends messages over
        /// parts.max_part, with sendMessage (the reader's answers are
        /// smaller: the assert below).
        fn send(c: *WsConn, srv: *Server, data: []const u8, op: websocket.Opcode) bool {
            return c.sendFrame(srv, op, &.{data});
        }

        comptime {
            std.debug.assert(frames.max_answer <= parts.max_part);
        }

        fn sendFrame(c: *WsConn, srv: *Server, op: websocket.Opcode, pieces: []const []const u8) bool {
            c.write_mutex.lock(srv.io) catch return false;
            defer c.write_mutex.unlock(srv.io);
            if (c.close_sent) return false;
            if (op == .close) c.close_sent = true;
            c.conn.setDeadline(srv.nowMs() +| send_timeout_ms);
            websocket.writeServerFrameOf(c.w, op, pieces) catch return false;
            c.conn.setDeadline(no_deadline);
            return true;
        }

        /// One message from the writer task: one frame if it fits in a
        /// part, else in 'M' parts (shared/parts.zig) with `screen` (the
        /// screen update, ScreenOut.Between) run after every part but the
        /// last, so a screen change waits for one part at most.
        fn sendMessage(c: *WsConn, srv: *Server, data: []const u8, op: websocket.Opcode, screen: ?*ScreenOut.Between) bool {
            if (!parts.inParts(data.len)) return c.send(srv, data, op);
            const Ctx = struct {
                c: *WsConn,
                srv: *Server,
                screen: ?*ScreenOut.Between,
                pub fn frame(x: @This(), header: []const u8, d: []const u8) bool {
                    return x.c.sendFrame(x.srv, .binary, &.{ header, d });
                }
                pub fn between(x: @This()) bool {
                    return if (x.screen) |b| b.run() else true;
                }
            };
            return parts.send(data, op, Ctx{ .c = c, .srv = srv, .screen = screen });
        }
    };

    /// The screen a viewer was last sent ('G' frames) and the frame being
    /// built: the writer's encode step, and the updates it sends between
    /// two parts of a large message. 'G' frames always go whole: they are
    /// what a keystroke waits for.
    const ScreenOut = struct {
        frame: std.ArrayList(u8) = .empty,
        rows: std.ArrayList(u16) = .empty,
        /// Generation of the emulator state last encoded; 0 plus `full`
        /// forces a complete snapshot (docs/protocol.md section 3).
        sent_gen: u64 = 0,
        full: bool = true,
        sent_cols: u16 = 0,
        sent_rows: u16 = 0,

        fn deinit(so: *ScreenOut, gpa: Allocator) void {
            so.frame.deinit(gpa);
            so.rows.deinit(gpa);
        }

        /// Encodes into `frame` what changed in `t` since the last frame
        /// (hub lock held: a consistent snapshot). False: nothing did.
        fn encodeLocked(so: *ScreenOut, gpa: Allocator, t: *const vt.Terminal) Allocator.Error!bool {
            if (t.cols != so.sent_cols or t.rows != so.sent_rows) so.full = true;
            if (!so.full and t.gen == so.sent_gen) return false;
            so.rows.clearRetainingCapacity();
            so.frame.clearRetainingCapacity();
            var r: u16 = 0;
            while (r < t.rows) : (r += 1) {
                if (so.full or t.rowGen(r) > so.sent_gen) try so.rows.append(gpa, r);
            }
            try t.encodeRows(so.rows.items, &so.frame, gpa);
            so.sent_gen = t.gen;
            so.sent_cols = t.cols;
            so.sent_rows = t.rows;
            so.full = false;
            return true;
        }

        /// Between two parts: the shown tab's screen, if it changed.
        const Between = struct {
            so: *ScreenOut,
            srv: *Server,
            ws: *WsConn,
            tab: *tabs.Tab,

            fn run(b: *Between) bool {
                const hub = b.srv.hub;
                hub.mutex.lockUncancelable(b.srv.io);
                const changed = b.so.encodeLocked(b.srv.gpa, &b.tab.session.term) catch {
                    hub.mutex.unlock(b.srv.io);
                    return false; // out of memory: drop this viewer
                };
                hub.mutex.unlock(b.srv.io);
                if (!changed) return true;
                return b.ws.send(b.srv, b.so.frame.items, .binary);
            }
        };
    };

    fn webSocket(srv: *Server, conn: *Conn, w: *Io.Writer, req: *const http1.Request, channel: Channel, leftover: []const u8) !void {
        const peer = conn.peer();
        if (srv.endReason(&conn.device) != null) {
            _ = try srv.fail(conn, w, .forbidden, "not paired\n");
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

        var ws: WsConn = .{ .conn = conn, .w = w, .device = conn.device };
        srv.promote(conn, channel);
        conn.ws_active.store(true, .release);
        conn.wake.set(srv.io); // the supervisor now also watches the pairing
        // A connection a day marks the device as in use (devices unused for
        // 90 days are forgotten); at most one store write an hour.
        const desk: devices.Desk = .{ .gpa = srv.gpa, .io = srv.io, .paths = srv.cfg.devices };
        desk.markSeen(conn.device.id) catch {};

        if (channel == .bulk) {
            conn.stream.setPriority(.bulk);
            srv.log.print("bulk channel from {s} ('{s}') opened", .{ peer, conn.device.name.get() });
            srv.bulkLoop(&ws, leftover);
            return;
        }
        conn.stream.setPriority(.interactive);

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
                peer,                                                     left,
                conn.sup_wakes.load(.monotonic) -% sup_before,            ws.writer_wakes,
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
                srv.notePeer(&srv.input_log, "viewer from {s} asked for a session that is not open ({d} so far)", .{ ws.conn.peer(), ws.unknown_ids });
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
                srv.notePeer(&srv.sysmon_log, "viewer from {s} asked for the system monitor, which is off in Settings ({d} so far)", .{ ws.conn.peer(), ws.sys_refused });
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
        var screen: ScreenOut = .{};
        defer screen.deinit(srv.gpa);
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
        const ws_device: []const u8 = ws.device.name.get();
        var sync_seen = srv.sync_gen.load(.acquire);
        var sync_digest = srv.syncDigestFor(ws_device);

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
        // Every tab's For-you cards (section 3g): after hello, then each
        // tab whose cards changed.
        var fy = foryou_ws.Outbox.init(srv.gpa);
        defer fy.deinit();
        // Every tab's background tasks and usage (section 3c): after hello,
        // then whenever any of it (or the tab list) changes.
        var activity_seen: u64 = 0;
        const act = srv.gpa.create(activity_wire.Activity) catch return;
        defer srv.gpa.destroy(act);
        var act_out: std.Io.Writer.Allocating = .init(srv.gpa);
        defer act_out.deinit();
        // The system monitor's sample last sent (section 3d).
        var sys_seen: u64 = 0;
        // The plan-usage bar (section 3h): after hello, then at most once
        // per 5 minutes, at once on a threshold (usage_desk.Throttle). Its
        // one deadline is part of this loop's wait.
        var usage_t: usage_desk.Throttle = .{};
        // The startable projects (section 3f): after hello, then whenever
        // the list or a project's running state changes.
        const proj = srv.gpa.create(projects_ws.Feed) catch return;
        defer srv.gpa.destroy(proj);
        proj.* = .{};
        while (true) {
            ws.writer_wakes +|= 1;
            // Event-driven: wakes on output, resize, a tab list change, a
            // switch the reader asked for, the reader ending, or a store
            // change (wakeViewers). No periodic recheck.
            const gone = srv.endReason(&ws.device) != null;
            hub.mutex.lockUncancelable(srv.io);
            const cur_closed = if (cur) |c| c.session.closed else false;
            const cur_gen = if (cur) |c| c.session.term.gen else screen.sent_gen;
            const convo_changed = if (cur) |c| blk: {
                const cv = shownConvo(c, sub_shown).convo;
                break :blk cv.epoch != convo_epoch or cv.rev != convo_rev or c.subs.gen != subs_gen;
            } else false;
            const sys_due = if (srv.sysmon) |m| ws.sys_on.load(.acquire) and m.gen.load(.acquire) != sys_seen else false;
            const usage_next = usage_t.decide(hub.usage.latest, srv.nowMs());
            if (usage_next != .now and !hub.finished and !screen.full and cur_gen == screen.sent_gen and !(cur_closed and !ended_sent) and !convo_changed and
                hub.activity_gen == activity_seen and !sys_due and !fy.due(hub) and !proj.dueLocked(hub) and
                ws.want == .none and ws.sub_want == .none and hub.gen == seen_gen and !ws.dead.load(.acquire) and !gone and
                srv.sync_gen.load(.acquire) == sync_seen)
            {
                // Forever, or while an image blob waits for this viewer's
                // byte budget: exactly until the budget has refilled
                // enough for it.
                // ... or until the usage message held back is due.
                var wait_ms: ?i64 = images.wait_ms;
                if (usage_next == .at) {
                    const left = usage_next.at -| srv.nowMs();
                    wait_ms = if (wait_ms) |ms| @min(ms, left) else left;
                }
                const timeout: Io.Timeout = if (wait_ms) |ms| .{ .duration = .{ .raw = .fromMilliseconds(@max(ms, 1)), .clock = .awake } } else .none;
                hub.cond.waitTimeout(srv.io, &hub.mutex, timeout) catch |err| switch (err) {
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
                    screen.full = true;
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
                changed = screen.encodeLocked(srv.gpa, t) catch blk: {
                    encode_ok = false;
                    break :blk false;
                };
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
            // The usage message, if it is due now.
            var usage_buf: [planusage.max_message]u8 = undefined;
            var usage_msg: []const u8 = "";
            const now_ms = srv.nowMs();
            if (usage_t.decide(hub.usage.latest, now_ms) == .now) {
                var uw: std.Io.Writer = .fixed(&usage_buf);
                if (planusage.write(&uw, hub.usage.latest)) {
                    usage_msg = uw.buffered();
                    usage_t.markSent(hub.usage.latest, now_ms);
                } else |_| {}
            }
            if (encode_ok) fy.fill(hub) catch {
                encode_ok = false;
            };
            const proj_msg = proj.collectLocked(hub);
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
            if (proj_msg) |m| if (!ws.send(srv, m, .text)) return;
            if (ended) |code| if (cur_id) |id| {
                const m = std.fmt.bufPrint(&msg, "{{\"t\":\"ended\",\"id\":\"{s}\",\"code\":{d}}}", .{ &tabs_wire.idHex(id), code }) catch return;
                if (!ws.send(srv, m, .text)) return;
            };
            if (changed) {
                if (!ws.send(srv, screen.frame.items, .binary)) return;
            }
            // From here on a large message goes in parts with the screen
            // between them (never before the frame above: newer rows would
            // arrive ahead of older ones).
            var between_buf: ScreenOut.Between = undefined;
            const between: ?*ScreenOut.Between = if (cur) |c| blk: {
                between_buf = .{ .so = &screen, .srv = srv, .ws = ws, .tab = c };
                break :blk &between_buf;
            } else null;
            var image_frames = images.frames();
            while (image_frames.next()) |f| if (!ws.sendMessage(srv, f, .binary, between)) return;
            if (subs_out.written().len > 0) {
                if (!ws.sendMessage(srv, subs_out.written(), .text, between)) return;
            }
            if (convo_out.written().len > 0) {
                if (!ws.sendMessage(srv, convo_out.written(), .text, between)) return;
            }
            if (act_out.written().len > 0) {
                if (!ws.sendMessage(srv, act_out.written(), .text, between)) return;
            }
            if (usage_msg.len > 0) {
                if (!ws.send(srv, usage_msg, .text)) return;
            }
            var fy_msgs = fy.messages();
            while (fy_msgs.next()) |m| if (!ws.sendMessage(srv, m, .text, between)) return;
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

            // The device being unpaired or paired again (possibly by
            // `portalctl unpair` in another process: the store watcher then
            // wakes this loop) ends the stream. Checked on every wake.
            if (srv.endReason(&ws.device)) |r| {
                _ = ws.send(srv, logoutMessage(r), .text);
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
        var fr: FrameReader = .{};
        if (!fr.init(leftover)) return;
        while (!ws.dead.load(.acquire)) {
            const f = (fr.next(ws.conn, srv.io) catch {
                _ = ws.send(srv, &.{ 0x03, 0xea }, .close); // 1002 protocol error
                return;
            }) orelse return;
            if (!srv.wsHandleFrame(ws, f.opcode, f.payload)) return;
        }
    }

    /// Returns false to end the connection.
    fn wsHandleFrame(srv: *Server, ws: *WsConn, opcode: websocket.Opcode, payload: []const u8) bool {
        switch (opcode) {
            .ping, .text, .binary => if (!srv.inputAllowed(ws.device.id, .interactive, payload.len)) {
                // A paired device flooding input (or pings): drop the excess
                // rather than let it queue behind a slow PTY write.
                srv.notePeer(&srv.input_log, "input from {s} over the rate limit; dropped", .{ws.conn.peer()});
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
                // Re-check on every input message, not just on wakes.
                if (srv.endReason(&ws.device) != null) return false;
                const known = frames.classify(payload);
                // "f:" this device forgets this desktop (mutual Forget):
                // its record goes, which ends all its connections. Exactly
                // "f:" (frames.classify): "f:" with anything after it is
                // an unknown frame, never Forget.
                if (known) |k| if (k.prefix == .forget) return srv.forgotten(ws);
                // A startable project (projects_ws.zig): a request, not
                // typing, answered in every input mode.
                if (known) |k| if (k.prefix == .project) return srv.projectRequest(ws, k.rest);
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
                // For-you answers and recaps name their card or tab, so a
                // shown sub-tab doesn't block them; foryou_ws checks the
                // input mode per request (dismissing is allowed in every
                // mode).
                if (known) |fr| if (fr.prefix == .item or fr.prefix == .recap) {
                    var ab: [frames.max_answer]u8 = undefined;
                    return ws.send(srv, foryou_ws.handle(srv.fyCtx(ws), fr, &ab), .text);
                };
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
                    // The line `recap`: a recap of the tab watched.
                    'l' => if (foryou_ws.isRecapLine(payload[2..])) {
                        var ab: [frames.max_answer]u8 = undefined;
                        return ws.send(srv, foryou_ws.recapTab(srv.fyCtx(ws), ws.sel, &ab), .text);
                    } else s.writeWebLine(payload[2..]) catch |err| {
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
    fn fyCtx(srv: *Server, ws: *const WsConn) foryou_ws.Ctx {
        return .{ .hub = srv.hub, .log = srv.log, .from = .{ .device = .{ .limits = &srv.fy_limits, .id = ws.device.id, .name = ws.device.name.get() } }, .now_ms = srv.nowMs() };
    }

    /// `p:start <name>` / `p:stop <name>` (projects_ws.handle): the answer,
    /// and on a start (or an already running one) this viewer then shows
    /// that tab, exactly as after `s:<id>`.
    fn projectRequest(srv: *Server, ws: *WsConn, rest: []const u8) bool {
        var buf: [frames.max_answer]u8 = undefined;
        const dev: projects_ws.Device = .{ .id = ws.device.id, .name = ws.device.name.get() };
        const out = projects_ws.handle(srv.hub, &srv.project_limits, dev, srv.nowMs(), rest, &buf) orelse return true;
        if (!ws.send(srv, out.answer, .text)) return false;
        if (out.show) |id| srv.subscribe(ws, &tabs_wire.idHex(id));
        return true;
    }

    /// "f:" from the device: remove its record (this one only: a newer
    /// pairing under the name stays), say so, end the connection.
    fn forgotten(srv: *Server, ws: *WsConn) bool {
        const desk: devices.Desk = .{ .gpa = srv.gpa, .io = srv.io, .paths = srv.cfg.devices };
        const removed = desk.forget(ws.device.id) catch |err| {
            srv.log.print("device '{s}' asked to be forgotten, but the device list could not be changed: {s}", .{ ws.device.name.get(), devices.describeError(err) });
            return ws.send(srv, "{\"t\":\"rejected\",\"reason\":\"StoreUnavailable\"}", .text);
        };
        if (removed) srv.log.print("device '{s}' ({s}) forgot this desktop: unpaired", .{ ws.device.name.get(), ws.conn.peer() });
        _ = ws.send(srv, "{\"t\":\"forgotten\"}", .text);
        return false;
    }

    // ------------------------------------------------------- frame reader

    /// Client frames from the connection, one at a time, for both
    /// WebSockets: at most one maximal frame buffered, masks applied.
    const FrameReader = struct {
        buf: [max_ws_header + max_ws_payload]u8 = undefined,
        len: usize = 0,
        /// Bytes of the frame last returned (dropped by the next call).
        used: usize = 0,

        const Frame = struct { opcode: websocket.Opcode, payload: []u8 };

        fn init(fr: *FrameReader, leftover: []const u8) bool {
            if (leftover.len > fr.buf.len) return false;
            @memcpy(fr.buf[0..leftover.len], leftover);
            fr.len = leftover.len;
            fr.used = 0;
            return true;
        }

        /// The next frame; null at end of stream (or a read error);
        /// error.Protocol for a malformed one.
        fn next(fr: *FrameReader, conn: *Conn, io: Io) error{Protocol}!?Frame {
            if (fr.used > 0) {
                std.mem.copyForwards(u8, fr.buf[0 .. fr.len - fr.used], fr.buf[fr.used..fr.len]);
                fr.len -= fr.used;
                fr.used = 0;
            }
            while (true) {
                const parsed = websocket.parseHeader(fr.buf[0..fr.len], .client, max_ws_payload) catch return error.Protocol;
                if (parsed) |f| {
                    const total = f.len + f.payload_len;
                    if (total <= fr.len) {
                        const payload = fr.buf[f.len..total];
                        if (f.mask) |m| websocket.applyMask(payload, m);
                        fr.used = total;
                        return .{ .opcode = f.opcode, .payload = payload };
                    }
                }
                if (fr.len >= fr.buf.len) return null; // cannot happen: the largest frame fits
                const got = readSome(conn, io, fr.buf[fr.len..]) catch return null;
                if (got == 0) return null;
                fr.len += got;
            }
        }
    };

    // ---------------------------------------------------------- bulk channel

    /// The bulk WebSocket (shared/bulk.zig): one request at a time, each
    /// answered in full (a header message, then the body in chunks of at
    /// most bulk.chunk bytes), only for this device and its subscriptions.
    /// Ends when the device is unpaired, idles too long, or misbehaves.
    fn bulkLoop(srv: *Server, ws: *WsConn, leftover: []const u8) void {
        var fr: FrameReader = .{};
        if (!fr.init(leftover)) return;
        while (true) {
            ws.conn.setDeadline(srv.nowMs() +| bulk_idle_ms);
            const f = (fr.next(ws.conn, srv.io) catch {
                _ = ws.send(srv, &.{ 0x03, 0xea }, .close); // 1002 protocol error
                return;
            }) orelse return;
            ws.conn.setDeadline(no_deadline);
            if (srv.endReason(&ws.device)) |r| {
                _ = ws.send(srv, logoutMessage(r), .text);
                return;
            }
            if (!srv.inputAllowed(ws.device.id, .bulk, f.payload.len)) {
                srv.notePeer(&srv.input_log, "bulk requests from {s} over the rate limit; dropped", .{ws.conn.peer()});
                continue;
            }
            switch (f.opcode) {
                .ping => if (!ws.send(srv, f.payload, .pong)) return,
                .pong => {},
                .close => {
                    _ = ws.send(srv, if (f.payload.len >= 2) f.payload[0..2] else "", .close);
                    return;
                },
                .text => if (!srv.bulkRequest(ws, f.payload)) return,
                else => return,
            }
        }
    }

    fn bulkErr(srv: *Server, ws: *WsConn, code: u16) bool {
        var b: [bulk.max_header]u8 = undefined;
        return ws.send(srv, bulk.formatReply(&b, .{ .err = code }) catch return false, .text);
    }

    /// "ok <len> [sig]" then `body` in chunks.
    fn bulkBody(srv: *Server, ws: *WsConn, body: []const u8, sig: ?[]const u8) bool {
        var b: [bulk.max_header]u8 = undefined;
        if (!ws.send(srv, bulk.formatReply(&b, .{ .ok = .{ .len = body.len, .sig = sig } }) catch return false, .text)) return false;
        var rest = body;
        while (rest.len > 0) {
            const n = @min(rest.len, bulk.chunk);
            if (!ws.send(srv, rest[0..n], .binary)) return false;
            rest = rest[n..];
        }
        return true;
    }

    /// Returns false to end the connection.
    fn bulkRequest(srv: *Server, ws: *WsConn, text: []const u8) bool {
        const r = bulk.parseRequest(text) orelse return srv.bulkErr(ws, 400);
        const key = srv.cfg.sync_key orelse return srv.bulkErr(ws, 404);
        const device = ws.device.name.get();
        if (!devices.validName(device)) return srv.bulkErr(ws, 404);
        const paths: sync.Paths = .{ .dir = srv.cfg.devices.dir };
        switch (r) {
            .key => {
                var kb: [sync_keypin.header.len + 66]u8 = undefined;
                return srv.bulkBody(ws, sync_keypin.format(key, &kb), null);
            },
            .index => {
                const body = sync.buildIndex(srv.gpa, srv.io, paths, device) catch |err| {
                    srv.log.print("sync: index for '{s}' failed: {t}", .{ device, err });
                    return srv.bulkErr(ws, 500);
                };
                defer srv.gpa.free(body);
                return srv.bulkBody(ws, body, null);
            },
            .manifest, .file => {},
        }
        const pkg = switch (r) {
            .manifest => |m| m,
            .file => |f| f.pkg,
            else => unreachable,
        };
        // Unknown and unsubscribed packages look the same (404).
        if (!sync_manifest.validPackageId(pkg.id) or !sync_manifest.validVersion(pkg.version)) return srv.bulkErr(ws, 404);
        const subs = sync.readSubs(srv.gpa, srv.io, paths) catch return srv.bulkErr(ws, 500);
        if (!subs.has(device, pkg.id)) {
            srv.notePeer(&srv.sync_log, "sync: '{s}' asked for '{s}', which it is not subscribed to", .{ device, pkg.id });
            return srv.bulkErr(ws, 404);
        }
        var v = sync.readVersion(srv.gpa, srv.io, paths, pkg.id, pkg.version) catch return srv.bulkErr(ws, 404);
        defer v.deinit(srv.gpa);
        switch (r) {
            .manifest => {
                srv.log.print("sync: '{s}' fetched the manifest of {s} {s}", .{ device, pkg.id, pkg.version });
                return srv.bulkBody(ws, v.manifest_bytes, &v.sig_hex);
            },
            .file => |f| {
                if (f.n >= v.m.files.len) return srv.bulkErr(ws, 404);
                return srv.bulkFile(ws, paths, pkg.id, pkg.version, f.n, v.m.files[f.n].size);
            },
            else => unreachable,
        }
    }

    /// Streams stored file `n`: exactly the size its manifest promises, in
    /// chunks, each under the send deadline.
    fn bulkFile(srv: *Server, ws: *WsConn, paths: sync.Paths, pkg: []const u8, ver: []const u8, n: usize, size: u64) bool {
        var pb: [1024]u8 = undefined;
        const fpath = sync.filePath(paths, &pb, pkg, ver, n) catch return srv.bulkErr(ws, 404);
        const f = Io.Dir.cwd().openFile(srv.io, fpath, .{}) catch return srv.bulkErr(ws, 404);
        defer f.close(srv.io);
        const st = f.stat(srv.io) catch return srv.bulkErr(ws, 500);
        if (st.size != size) {
            srv.log.print("sync: stored file {d} of {s} {s} has the wrong size; not served", .{ n, pkg, ver });
            return srv.bulkErr(ws, 500);
        }
        var hb: [bulk.max_header]u8 = undefined;
        if (!ws.send(srv, bulk.formatReply(&hb, .{ .ok = .{ .len = size } }) catch return false, .text)) return false;
        var buf: [bulk.chunk]u8 = undefined;
        var sent: u64 = 0;
        while (sent < size) {
            const got = f.readPositional(srv.io, &.{buf[0..@intCast(@min(buf.len, size - sent))]}, sent) catch return false;
            if (got == 0) return false; // the file shrank: end the connection mid-body
            if (!ws.send(srv, buf[0..got], .binary)) return false;
            sent += got;
        }
        return true;
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
    _ = t.promote(a.slot.?, @splat(1), .interactive);
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
        // Every connection its own device: no per-device cap applies.
        var id: devices.DeviceId = @splat(0);
        id[0] = @intCast(i);
        try testing.expect(full.promote(s, id, .interactive) == null);
    }
    const r = full.admit(testKey(1), 100);
    try testing.expect(r.slot == null and r.victim == null);
    full.release(5);
    try testing.expectEqual(@as(?usize, 5), full.admit(testKey(1), 101).slot);
}

test "conn table: a device over its upgraded cap loses its oldest on that channel" {
    var t: ConnTable = .{};
    const dev: devices.DeviceId = @splat(1);
    const other: devices.DeviceId = @splat(2);
    const cap = max_upgraded_per_device.get(.interactive);
    var first: ?usize = null;
    for (0..cap) |i| {
        const s = t.admit(testKey(1), @intCast(i)).slot.?;
        if (first == null) first = s;
        try testing.expect(t.promote(s, dev, .interactive) == null);
    }
    // Another device and the other channel count apart.
    try testing.expect(t.promote(t.admit(testKey(2), 50).slot.?, other, .interactive) == null);
    try testing.expect(t.promote(t.admit(testKey(1), 51).slot.?, dev, .bulk) == null);
    // One more interactive from the same device: its oldest goes.
    const s = t.admit(testKey(1), 100).slot.?;
    try testing.expectEqual(first, t.promote(s, dev, .interactive));
    try testing.expect(t.entries[first.?].evicted);
    // The evicted one no longer counts: the next evicts the second oldest.
    const s2 = t.admit(testKey(1), 101).slot.?;
    const v2 = t.promote(s2, dev, .interactive).?;
    try testing.expect(v2 != first.? and v2 != s);
    // However many it opens, the device holds at most `cap` live ones.
    var live: usize = 0;
    for (t.entries) |e| {
        if (e.used and e.authed and !e.evicted and e.channel == .interactive and std.mem.eql(u8, &e.device, &dev)) live += 1;
    }
    try testing.expectEqual(cap, live);
}

test "input limit is per device: more sockets do not add budget" {
    var t: ratelimit.Table(DeviceInput) = .{};
    const dev: devices.DeviceId = @splat(1);
    var passed: usize = 0;
    // Two "sockets" of the same device draw on one budget.
    for (0..1000) |_| {
        if (t.get(dev, 0).forChannel(.interactive).allow(0, 1)) passed += 1;
        if (t.get(dev, 0).forChannel(.interactive).allow(0, 1)) passed += 1;
    }
    try testing.expectEqual(@as(usize, 2 * input_msgs_per_s), passed);
    // The bulk channel and another device have their own.
    try testing.expect(t.get(dev, 0).forChannel(.bulk).allow(0, 1));
    try testing.expect(t.get(@splat(2), 0).forChannel(.interactive).allow(0, 1));
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

test "peers: a refused address admits nothing, and a record replaced at its address ends" {
    var st: devices.Store = .{};
    var k1: devices.Key = @splat(7);
    k1[0] = 1;
    var k2: devices.Key = @splat(8);
    k2[0] = 1;
    const old = (try st.pair("phone", k1, @splat(9), @splat(1), 0)).device;
    var peers: [devices.max_devices]?Peer = @splat(null);
    setPeers(&peers, &st, &.{});
    const admitted = peerAt(&peers, old.ip).?;
    try testing.expect(endReasonIn(&peers, &admitted) == null);

    // Re-paired: the same name and address, a new record. While the
    // tunnel may still have the old key the address is refused.
    const new = (try st.pair("phone", k2, @splat(9), @splat(2), 0)).device;
    try testing.expectEqual(old.ip, new.ip);
    setPeers(&peers, &st, &.{new.ip});
    try testing.expect(peerAt(&peers, new.ip) == null);
    try testing.expectEqual(Server.EndReason.replaced, endReasonIn(&peers, &admitted).?);
    // A connection admitted as the new record during the refusal could
    // not exist (peerAt refused it); after it, the new record is let in.
    setPeers(&peers, &st, &.{});
    const now_admitted = peerAt(&peers, new.ip).?;
    try testing.expect(endReasonIn(&peers, &now_admitted) == null);
    try testing.expectEqual(Server.EndReason.replaced, endReasonIn(&peers, &admitted).?);
    // A record id found at another address is not this connection's.
    var moved = now_admitted;
    moved.ip = .{ 10, 8, 0, 99 };
    try testing.expect(endReasonIn(&peers, &moved) != null);
    // Unpaired: nothing of that name is left.
    _ = st.remove("phone");
    setPeers(&peers, &st, &.{});
    try testing.expectEqual(Server.EndReason.unpaired, endReasonIn(&peers, &now_admitted).?);
}

test "screen out: a full snapshot first, then only what changed, nothing when nothing did" {
    var t = try vt.Terminal.init(testing.allocator, 10, 5);
    defer t.deinit();
    var so: Server.ScreenOut = .{};
    defer so.deinit(testing.allocator);
    try testing.expect(try so.encodeLocked(testing.allocator, &t));
    try testing.expectEqual(@as(usize, 5), so.rows.items.len);
    try testing.expect(!try so.encodeLocked(testing.allocator, &t));
    t.feed("x");
    try testing.expect(try so.encodeLocked(testing.allocator, &t));
    try testing.expectEqual(@as(usize, 1), so.rows.items.len);
    // A forced snapshot (a switch to another tab) has every row again.
    so.full = true;
    try testing.expect(try so.encodeLocked(testing.allocator, &t));
    try testing.expectEqual(@as(usize, 5), so.rows.items.len);
}
