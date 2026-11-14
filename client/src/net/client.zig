//! Connection thread: the interactive WebSocket and reconnects
//! (docs/protocol.md). Everything goes through the in-process WireGuard
//! tunnel (client/src/tunnel; `dialer`): the device IS its WireGuard key,
//! so there is no sign-in, cookie or credential here.
//!
//!   GET /ws (interactive channel) -> 'G' frames into the shared grid
//!   403 on the upgrade, or a `logout` message -> the desktop no longer has
//!       this device (unpaired at the desk, or paired again under a new
//!       key): Shared.desktop_gone, the app forgets the desktop
//!   network errors -> retry with backoff 1 s doubling to 15 s
//!
//! Every connection is TLS 1.3 with the server certificate pinned to the
//! Portal CA (tlsconn.zig): the one pinned for this desktop, or on the
//! first connection after pairing the one whose SHA-256 the pairing code
//! carried. Nothing is sent before the TLS handshake has authenticated the
//! server.
//!
//! Liveness: each step runs under a watchdog (watchdog.zig): 15 s for
//! connect + TLS handshake + upgrade, and on the stream 60 s without any
//! data from the server. A ping goes out after 20 s of silence, so a live
//! server always answers in time.
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
const builtin = @import("builtin");
const Io = std.Io;
const net = Io.net;
const http = @import("http.zig");
const ws = @import("shared").ws;
const tabs_wire = @import("shared").tabs;
const convo_wire = @import("shared").convo;
const subtabs_wire = @import("shared").subtabs;
const activity_wire = @import("shared").activity;
const planusage = @import("shared").planusage;
const projects_wire = @import("shared").projects;
const sysinfo = @import("shared").sysinfo;
const tlsconn = @import("tlsconn.zig");
const x509check = @import("x509check.zig");
const watchdog = @import("watchdog.zig");
const ui = @import("portal_ui");
const Grid = ui.grid.Grid;
const gframe = @import("../gframe.zig");
const keys = @import("../keys.zig");
const wsclient = @import("wsclient.zig");
const sync_engine = @import("../sync/engine.zig");
const keypin = @import("../sync/keypin.zig");
const sync_manifest = @import("../sync/manifest.zig");

pub const max_frame_payload = 8 << 20;
pub const TabList = tabs_wire.List;
pub const SubList = subtabs_wire.List;

pub const connect_timeout_ms = 15_000;
pub const request_timeout_ms = 15_000;
pub const idle_timeout_ms = 60_000;
pub const ping_interval_ms = 20_000;

pub const Status = enum {
    starting,
    /// The desktop no longer has this device (the app forgets it).
    need_pairing,
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
    /// The app is off screen (iOS background): the connection is dropped
    /// until it comes back (Client.setPaused).
    paused,
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

pub const Activity = activity_wire.Activity;
pub const ProjectList = projects_wire.List;
pub const ProjectAnswer = projects_wire.Answer;
pub const SysSnapshot = sysinfo.Snapshot;

pub const Shared = struct {
    mutex: Io.Mutex = .init,
    grid: Grid = .{},
    /// The conversation of the tab shown (convo / convo+ messages), or of
    /// its sub-tab `sub_shown`.
    convo: ui.convo.Conversation = .{},
    /// The shown tab's subagent sub-tabs (`subtabs`, section 3e) and the
    /// one whose conversation is shown (null: the tab's own). Read-only.
    subs: subtabs_wire.List = .{},
    sub_shown: ?subtabs_wire.Id = null,
    /// Every tab's background tasks and usage (`activity`), once known.
    activity: activity_wire.Activity = .{},
    has_activity: bool = false,
    /// Every open tab's For-you cards (`foryou`) and the last answer to an
    /// `i:` / `r:` request (`item`, `recap`): docs/protocol.md 3g, 4b.
    foryou: ui.foryou.Store = .{},
    /// The projects the desk lets this device start (`projects`, section
    /// 3f), once known; the desk's latest answer to a `p:` request and a
    /// count bumped with each one.
    projects: projects_wire.List = .{},
    has_projects: bool = false,
    project_answer: ?projects_wire.Answer = null,
    project_answer_gen: u64 = 0,
    /// The latest system monitor sample (`sys`), while the System panel
    /// is open.
    sys: sysinfo.Snapshot = .{},
    has_sys: bool = false,
    /// The plan's usage (`usage`, section 3h), once the desk sent it.
    usage: planusage.Usage = .{},
    has_usage: bool = false,
    /// The System panel is open: `y:on` was sent (and is sent again after
    /// a reconnect).
    sys_wanted: std.atomic.Value(bool) = .init(false),
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
    /// The last connection error, until the next successful connection
    /// (the overlay explains certificate and pinning errors).
    last_error: ?anyerror = null,
    wake_ctx: ?*anyopaque = null,
    wake_fn: ?*const fn (*anyopaque) void = null,
    /// Bumped on every stream (re)connect and every {"t":"updates"}: the
    /// sync worker runs a pass when it changes (docs/sync-design.md).
    sync_gen: std.atomic.Value(u64) = .init(0),
    /// Set with sync_gen, for a worker waiting on it.
    sync_wake: Io.Event = .unset,
    /// Pairing just completed (the app offers voice packages then).
    just_paired: std.atomic.Value(bool) = .init(false),
    /// The desktop said, unambiguously, that it no longer has this device
    /// (403 on the upgrade, or a `logout` message). The app then forgets
    /// the desktop (connect.forgetDesktop) and says why. Never set by a
    /// transient error.
    desktop_gone: std.atomic.Value(bool) = .init(false),
    /// The app is off screen: no connection (Client.setPaused). Also the
    /// stream's abort flag, so pausing drops a live stream at once.
    paused: std.atomic.Value(bool) = .init(false),
    /// Set when the pause ends: wakes the paused loop and cuts a backoff
    /// sleep short, so a returning app reconnects at once.
    resume_wake: Io.Event = .unset,

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

/// How the desktop's certificate is checked.
pub const Trust = union(enum) {
    /// Signed by this CA (DER), pinned earlier.
    pinned: []const u8,
    /// First connection after pairing: the CA the desktop sends must have
    /// this SHA-256 (from the pairing code); the caller pins it then.
    fingerprint: [32]u8,
    /// Unit tests over the in-memory network only: no TLS.
    plain_for_tests,
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
        error.TlsHandshakeMalformed, error.TlsUnexpectedMessage, error.TlsDecodeError => "not Portal's TLS server",
        error.TlsAlert => "server refused the TLS handshake",
        error.TlsConnectionTruncated => "connection closed during the TLS handshake",
        error.NoServerCertificate, error.NoHandshakeSecret, error.TlsHandshakeTooLarge => "TLS handshake failed",
        error.TimedOut, error.Canceled => "server not responding (timed out)",
        error.ConnectionRefused => "connection refused (is Portal running?)",
        error.ConnectionResetByPeer, error.ConnectionClosed => "connection closed by the server",
        error.NetworkUnreachable, error.HostUnreachable => "network unreachable",
        error.ResponseTooLarge => "response too large",
        else => @errorName(err),
    };
}

/// iOS: what to tell the user when a connection to `host` (IP:PORT)
/// failed with `err`, if it looks like iOS's Local Network privacy: while
/// Portal is not allowed Local Network access, connecting to a local
/// address fails with EHOSTUNREACH / ENETUNREACH. Null elsewhere and for
/// other errors or public addresses.
pub fn localNetworkHint(err: anyerror, host: []const u8) ?[]const u8 {
    return localNetworkHintFor(builtin.os.tag == .ios, err, host);
}

pub const local_network_text = "If iOS asked whether Portal may find devices on your local network, allow it: Settings > Privacy & Security > Local Network > Portal (on), then try again.";

fn localNetworkHintFor(ios: bool, err: anyerror, host: []const u8) ?[]const u8 {
    if (!ios) return null;
    if (err != error.HostUnreachable and err != error.NetworkUnreachable) return null;
    const addr = net.IpAddress.parseLiteral(host) catch return null;
    return if (isLocalAddress(addr)) local_network_text else null;
}

/// Private, link-local and unique-local addresses: what iOS counts as the
/// local network (the WireGuard tunnel's 10.x addresses included: without
/// the tunnel up they are looked for on the Wi-Fi).
fn isLocalAddress(addr: net.IpAddress) bool {
    return switch (addr) {
        .ip4 => |a| a.bytes[0] == 10 or
            (a.bytes[0] == 172 and a.bytes[1] & 0xF0 == 16) or
            (a.bytes[0] == 192 and a.bytes[1] == 168) or
            (a.bytes[0] == 169 and a.bytes[1] == 254),
        .ip6 => |a| (a.bytes[0] & 0xFE) == 0xFC or (a.bytes[0] == 0xFE and (a.bytes[1] & 0xC0) == 0x80),
    };
}

test "local network hint: iOS, unreachable, local address only" {
    try std.testing.expect(localNetworkHintFor(true, error.HostUnreachable, "192.168.1.20:8420") != null);
    try std.testing.expect(localNetworkHintFor(true, error.NetworkUnreachable, "10.8.0.1:8420") != null);
    try std.testing.expect(localNetworkHintFor(true, error.HostUnreachable, "172.20.0.5:8420") != null);
    try std.testing.expect(localNetworkHintFor(true, error.HostUnreachable, "[fe80::1]:8420") != null);
    try std.testing.expect(localNetworkHintFor(true, error.HostUnreachable, "[fd00::5]:8420") != null);
    try std.testing.expect(localNetworkHintFor(true, error.HostUnreachable, "172.32.0.5:8420") == null);
    try std.testing.expect(localNetworkHintFor(true, error.HostUnreachable, "203.0.113.7:8420") == null);
    try std.testing.expect(localNetworkHintFor(true, error.ConnectionRefused, "192.168.1.20:8420") == null);
    try std.testing.expect(localNetworkHintFor(false, error.HostUnreachable, "192.168.1.20:8420") == null);
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
    /// Through the in-process tunnel (connect.zig starts it).
    dialer: tlsconn.transport.Dialer,
    trust: TrustKind,
    ca_buf: [x509check.max_cert_len]u8 = undefined,
    ca_len: usize = 0,
    ca_sha256: [32]u8 = undefined,

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
    /// Tests: no connection errors on stderr.
    quiet: bool = false,
    /// Called (network thread) when a first connection pinned the CA
    /// found by its fingerprint: the app saves it (connect.zig).
    on_pinned: ?*const fn (ctx: *anyopaque, ca_der: []const u8) void = null,
    on_pinned_ctx: ?*anyopaque = null,

    pub const TrustKind = enum { pinned, fingerprint, plain };

    /// `server` is the desktop's address inside the tunnel (10.8.0.1:8420).
    pub fn init(gpa: std.mem.Allocator, io: Io, shared: *Shared, server: []const u8, dialer: tlsconn.transport.Dialer, trust: Trust) !Client {
        var c: Client = .{
            .gpa = gpa,
            .io = io,
            .shared = shared,
            .addr = undefined,
            .dialer = dialer,
            .trust = switch (trust) {
                .pinned => .pinned,
                .fingerprint => .fingerprint,
                .plain_for_tests => .plain,
            },
            .wd = .{ .io = io },
        };
        const h = try http.canonicalHost(server, &c.host_buf);
        c.host_len = h.len;
        c.addr = net.IpAddress.parseLiteral(h) catch return error.BadServerAddress;
        const ip = bareIp(h);
        @memcpy(c.ip_buf[0..ip.len], ip);
        c.ip_len = ip.len;
        switch (trust) {
            .pinned => |ca| {
                if (ca.len > c.ca_buf.len) return error.BadCertificate;
                @memcpy(c.ca_buf[0..ca.len], ca);
                c.ca_len = ca.len;
            },
            .fingerprint => |fp| c.ca_sha256 = fp,
            .plain_for_tests => {},
        }
        return c;
    }

    pub fn host(c: *const Client) []const u8 {
        return c.host_buf[0..c.host_len];
    }

    pub fn security(c: *const Client) tlsconn.Security {
        return switch (c.trust) {
            .plain => .plain,
            .pinned => .{ .tls = .{ .ca_der = c.ca_buf[0..c.ca_len], .ip = c.ip_buf[0..c.ip_len] } },
            .fingerprint => .{ .tls = .{ .ca_der = "", .ip = c.ip_buf[0..c.ip_len], .ca_sha256 = c.ca_sha256 } },
        };
    }

    /// A first connection checked the CA by its fingerprint: from now on
    /// it is pinned (and the app saves it).
    pub fn pinFound(c: *Client, ca_der: []const u8) void {
        if (c.trust != .fingerprint or ca_der.len == 0 or ca_der.len > c.ca_buf.len) return;
        @memcpy(c.ca_buf[0..ca_der.len], ca_der);
        c.ca_len = ca_der.len;
        c.trust = .pinned;
        if (c.on_pinned) |f| f(c.on_pinned_ctx.?, ca_der);
    }

    // ------------------------------------------------------------ status

    fn setStatus(c: *Client, status: Status, comptime fmt: []const u8, args: anytype) void {
        const s = c.shared;
        s.mutex.lockUncancelable(c.io);
        s.status = status;
        const d = std.fmt.bufPrint(&s.detail_buf, fmt, args) catch s.detail_buf[0..0];
        s.detail_len = d.len;
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
        // The tab's own conversation again: the sub-tab shown went.
        if (m.snapshot and sameId(c.shared.current, m.id)) c.shared.sub_shown = null;
        c.shared.convo.apply(c.gpa, m) catch {};
        c.shared.mutex.unlock(c.io);
        c.notify();
    }

    /// A `subtabs` message (section 3e): the shown tab's sub-tabs. If the
    /// one shown went, back to the tab's own conversation.
    fn applySubtabs(c: *Client, payload: []const u8) void {
        const l = subtabs_wire.parse(payload) orelse return;
        c.shared.mutex.lockUncancelable(c.io);
        if (!sameId(c.shared.current, l.tab)) {
            c.shared.mutex.unlock(c.io);
            return;
        }
        c.shared.subs = l;
        var back = false;
        if (c.shared.sub_shown) |s| if (l.find(s) == null) {
            c.shared.sub_shown = null;
            back = true;
        };
        c.shared.mutex.unlock(c.io);
        if (back) _ = c.sendInput("a:");
        c.notify();
    }

    /// Shows sub-tab `id` of the tab shown (read-only), or (null) the
    /// tab's own conversation: "a:<id>" / "a:". Callable from any thread.
    pub fn showSub(c: *Client, id: ?subtabs_wire.Id) void {
        c.shared.mutex.lockUncancelable(c.io);
        c.shared.sub_shown = id;
        c.shared.mutex.unlock(c.io);
        var b: [34]u8 = undefined;
        _ = c.sendInput(subtabs_wire.viewFrame(id, &b));
        c.notify();
    }

    /// A `foryou` message (section 3g): that tab's cards, parsed strictly
    /// (malformed: ignored).
    fn applyForYou(c: *Client, payload: []const u8) void {
        c.shared.mutex.lockUncancelable(c.io);
        const changed = c.shared.foryou.apply(c.gpa, payload);
        c.shared.mutex.unlock(c.io);
        if (changed) c.notify();
    }

    /// An `item` or `recap` answer: what the panel says next.
    fn applyForYouResult(c: *Client, payload: []const u8) void {
        c.shared.mutex.lockUncancelable(c.io);
        const changed = c.shared.foryou.applyResult(payload);
        c.shared.mutex.unlock(c.io);
        if (changed) c.notify();
    }

    /// An `activity` message (section 3c): parsed strictly, kept whole.
    fn applyActivity(c: *Client, payload: []const u8) void {
        const a = c.gpa.create(activity_wire.Activity) catch return;
        defer c.gpa.destroy(a);
        if (!activity_wire.parse(payload, a)) return;
        c.shared.mutex.lockUncancelable(c.io);
        c.shared.activity = a.*;
        c.shared.has_activity = true;
        c.shared.mutex.unlock(c.io);
        c.notify();
    }

    /// A `usage` message (section 3h): parsed strictly, each replaces the last.
    fn applyUsage(c: *Client, payload: []const u8) void {
        const u = planusage.parse(payload) orelse return;
        c.shared.mutex.lockUncancelable(c.io);
        c.shared.usage = u;
        c.shared.has_usage = true;
        c.shared.mutex.unlock(c.io);
        c.notify();
    }

    /// A `projects` message or a `project` answer (section 3f), parsed
    /// strictly (malformed: ignored).
    fn applyProjects(c: *Client, payload: []const u8) void {
        const list = projects_wire.parse(payload);
        const answer = if (list == null) projects_wire.parseResult(payload) else null;
        if (list == null and answer == null) return;
        c.shared.mutex.lockUncancelable(c.io);
        if (list) |l| {
            c.shared.projects = l;
            c.shared.has_projects = true;
        }
        if (answer) |a| {
            c.shared.project_answer = a;
            c.shared.project_answer_gen +%= 1;
        }
        c.shared.mutex.unlock(c.io);
        c.notify();
    }

    /// A `sys` message (section 3d), kept only while the panel is open.
    fn applySys(c: *Client, payload: []const u8) void {
        var s: sysinfo.Snapshot = undefined;
        if (!sysinfo.parse(payload, &s)) return;
        if (!c.shared.sys_wanted.load(.acquire)) return;
        c.shared.mutex.lockUncancelable(c.io);
        c.shared.sys = s;
        c.shared.has_sys = true;
        c.shared.mutex.unlock(c.io);
        c.notify();
    }

    /// The System panel opened or closed: `y:on` / `y:off` (the desktop
    /// samples only while some panel is open). Any thread.
    pub fn setSysPanel(c: *Client, on: bool) void {
        c.shared.sys_wanted.store(on, .release);
        if (!on) {
            c.shared.mutex.lockUncancelable(c.io);
            c.shared.has_sys = false;
            c.shared.mutex.unlock(c.io);
        }
        _ = c.sendInput(if (on) "y:on" else "y:off");
    }

    fn notify(c: *Client) void {
        _ = c.shared.version.fetchAdd(1, .release);
        if (c.shared.wake_fn) |f| f(c.shared.wake_ctx.?);
    }

    /// Only on the long-lived network thread (never inside a watchdog
    /// task): nothing cancels that thread, so there is no cancelation to
    /// swallow here.
    fn sleepMs(c: *Client, ms: i64) void {
        if (ms <= 0) return;
        // A resume (setPaused(false)) ends the wait early.
        c.shared.resume_wake.reset();
        if (c.shared.paused.load(.acquire)) return;
        c.shared.resume_wake.waitTimeout(c.io, .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } }) catch {};
    }

    /// Any thread. Paused: drop the stream now and make no connection
    /// until resumed (the UI is off screen: iOS background). The session
    /// stays in memory; resuming reconnects at once (signing in again if
    /// the desktop asks).
    pub fn setPaused(c: *Client, paused: bool) void {
        if (c.shared.paused.swap(paused, .acq_rel) == paused) return;
        if (paused) c.wd.poke(); // the stream's watchdog aborts on `paused`
        c.shared.resume_wake.set(c.io);
    }

    /// Network thread: sleeps (event-driven) while paused.
    fn waitWhilePaused(c: *Client) void {
        if (!c.shared.paused.load(.acquire)) return;
        c.setStatus(.paused, "paused while Portal is in the background", .{});
        while (c.shared.paused.load(.acquire)) {
            c.shared.resume_wake.wait(c.io) catch {};
            c.shared.resume_wake.reset();
        }
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
        while (true) {
            c.waitWhilePaused();
            if (c.shared.desktop_gone.load(.acquire)) {
                // Nothing to connect to until the app has forgotten it.
                c.sleepMs(std.math.maxInt(i32));
                continue;
            }
            // After an ended session, or while the desktop is unreachable,
            // keep saying so during the (possibly long) attempt instead of
            // a bare "connecting".
            if (!c.quietAttempt()) c.setStatus(.connecting, "opening stream", .{});
            const result = c.runStream(&backoff);
            // Dropped because the app left the screen: not an error.
            if (c.shared.paused.load(.acquire)) continue;
            c.streamEnded(result, &backoff);
        }
    }

    /// What follows a stream's end: forget the desktop, show the ended
    /// session, or wait (a real deadline) before retrying.
    pub fn streamEnded(c: *Client, result: StreamResult, backoff: *i64) void {
        switch (result) {
            .gone => c.desktopGone(),
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

    fn signalSync(c: *Client) void {
        _ = c.shared.sync_gen.fetchAdd(1, .release);
        c.shared.sync_wake.set(c.io);
    }

    /// How the sync engine reaches the desktop: the bulk channel.
    pub fn syncRemote(c: *const Client) sync_engine.Remote {
        return .{ .gpa = c.gpa, .io = c.io, .dialer = c.dialer, .addr = c.addr, .security = c.security(), .host = c.host() };
    }

    /// After pairing: asks the desktop, over the tunnel and the freshly
    /// pinned CA, for its release key and pins it for this desktop
    /// (docs/sync-design.md, "Trust"). Replaces any earlier pin: pairing
    /// is the only way a pin changes.
    pub fn pinReleaseKey(c: *Client) !keypin.Key {
        const remote = c.syncRemote();
        const key = try sync_engine.fetchKey(&remote);
        try keypin.save(c.io, c.host(), key);
        var fp: [95]u8 = undefined;
        if (!c.quiet) std.debug.print("portal connect: release key for {s} pinned: SHA-256 {s}\n", .{ c.host(), sync_manifest.formatFingerprint(sync_manifest.fingerprint(key), &fp) });
        return key;
    }

    pub const ForgetRemote = enum {
        /// The desktop removed this device.
        forgotten,
        /// It could not be reached (or refused): it still lists the device.
        unreachable_desktop,
    };

    /// Asks the desktop to remove this device ("f:" on its own interactive
    /// WebSocket, answered {"t":"forgotten"}). Never deletes anything
    /// here: the caller then runs connect.forgetDesktop either way.
    pub fn forgetOnDesktop(c: *Client) ForgetRemote {
        c.wd.extend(connect_timeout_ms);
        const r = c.wd.run(forgetTask, .{c}, null);
        if (c.wd.expired.load(.acquire)) return .unreachable_desktop;
        return r;
    }

    fn forgetTask(c: *Client) ForgetRemote {
        var sock = wsclient.Socket.open(c.gpa, c.io, c.dialer, c.addr, c.security(), c.host(), .interactive, &c.wd.stopped) catch return .unreachable_desktop;
        defer sock.close();
        c.wd.extend(request_timeout_ms);
        sock.send(.text, "f:") catch return .unreachable_desktop;
        while (true) {
            const f = (sock.next(max_frame_payload) catch return .unreachable_desktop) orelse return .unreachable_desktop;
            if (f.opcode == .text and std.mem.eql(u8, f.payload, "{\"t\":\"forgotten\"}")) return .forgotten;
        }
    }

    /// The desktop no longer has this device: let the app forget it.
    fn desktopGone(c: *Client) void {
        c.setStatus(.need_pairing, "this desktop no longer has this device paired (unpaired at the desk, or paired again)", .{});
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

    // ------------------------------------------------------------ stream

    pub const StreamResult = union(enum) {
        /// 403 on the upgrade, or {"t":"logout"}: the record is gone.
        gone,
        exited: i64,
        /// Could not connect at all (see classify).
        unreachable_err: anyerror,
        failed: []const u8,
    };

    pub fn runStream(c: *Client, backoff: *i64) StreamResult {
        c.wd.extend(connect_timeout_ms);
        // setPaused(true) ends the stream through the watchdog.
        c.wd.abort = &c.shared.paused;
        defer c.wd.abort = null;
        const r = c.wd.run(streamTask, .{ c, backoff }, .{ .ctx = c, .f = pingTick });
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

    fn streamTask(c: *Client, backoff: *i64) StreamResult {
        var sock = wsclient.Socket.open(c.gpa, c.io, c.dialer, c.addr, c.security(), c.host(), .interactive, &c.wd.stopped) catch |err| switch (err) {
            error.NotPaired => return .gone,
            error.UpgradeRefused => return .{ .failed = "upgrade refused" },
            error.BadUpgrade => return .{ .failed = "bad websocket handshake" },
            else => {
                c.logError(err);
                return .{ .unreachable_err = err };
            },
        };
        defer sock.close();
        if (c.trust == .fingerprint) c.pinFound(sock.conn.caDer());
        const conn = sock.conn;
        // The buffer holds any frame bytes that followed the upgrade head.
        const buf = &sock.buf;

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
            // Drain complete messages (parts reassembled: shared/parts.zig).
            while (sock.buffered(max_frame_payload) catch |err| return .{ .failed = @errorName(err) }) |frame| {
                if (c.handleFrame(frame, backoff)) |r| return r;
            }
            if (buf.items.len > max_frame_payload + 16) return .{ .failed = "frame too large" };
            if (!c.readMore(conn, buf)) return .{ .failed = "connection lost" };
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
                if (std.mem.startsWith(u8, frame.payload, "{\"t\":\"subtabs\"")) {
                    c.applySubtabs(frame.payload);
                    return null;
                }
                if (std.mem.startsWith(u8, frame.payload, "{\"t\":\"activity\"")) {
                    c.applyActivity(frame.payload);
                    return null;
                }
                // `projects` and `project` (the answer to a p: request).
                if (std.mem.startsWith(u8, frame.payload, "{\"t\":\"project")) {
                    c.applyProjects(frame.payload);
                    return null;
                }
                if (std.mem.startsWith(u8, frame.payload, "{\"t\":\"sys\"")) {
                    c.applySys(frame.payload);
                    return null;
                }
                if (std.mem.startsWith(u8, frame.payload, "{\"t\":\"usage\"")) {
                    c.applyUsage(frame.payload);
                    return null;
                }
                // For you (larger than the generic parser takes).
                if (std.mem.startsWith(u8, frame.payload, "{\"t\":\"foryou\"")) {
                    c.applyForYou(frame.payload);
                    return null;
                }
                if (std.mem.startsWith(u8, frame.payload, "{\"t\":\"item\"") or std.mem.startsWith(u8, frame.payload, "{\"t\":\"recap\"")) {
                    c.applyForYouResult(frame.payload);
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
                    c.shared.foryou.retain(c.shared.tabs.slice());
                    c.shared.current = tabs_wire.idField(frame.payload, "session");
                    c.shared.subs = .{};
                    c.shared.sub_shown = null;
                    // The desk sends its projects again after hello.
                    c.shared.has_projects = false;
                    // Reconnected: back to the tab this device was on, if
                    // it is still open.
                    const back = c.shared.chosen;
                    c.shared.mutex.unlock(c.io);
                    if (back) |id| if (!sameId(c.shared.current, id)) c.sendTabIfOpen(id);
                    // A System panel still open: subscribe again.
                    if (c.shared.sys_wanted.load(.acquire)) _ = c.sendInput("y:on");
                    backoff.* = 1000;
                    c.notify();
                    c.signalSync(); // look for updates on every (re)connect
                } else if (std.mem.eql(u8, m.t, "tabs")) {
                    c.shared.mutex.lockUncancelable(c.io);
                    if (tabs_wire.parseList(frame.payload)) |l| c.shared.tabs = l;
                    // A tab gone takes its For-you cards with it.
                    c.shared.foryou.retain(c.shared.tabs.slice());
                    c.shared.mutex.unlock(c.io);
                    c.notify();
                } else if (std.mem.eql(u8, m.t, "session")) {
                    // The server now shows this tab; its full screen
                    // follows. Images belong to the old tab: drop them.
                    c.shared.mutex.lockUncancelable(c.io);
                    c.shared.current = tabs_wire.idField(frame.payload, "id");
                    c.shared.subs = .{};
                    c.shared.sub_shown = null;
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
                    // "unpaired" or "replaced": the desktop no longer lets
                    // this key in.
                    return .gone;
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

test "bare IP" {
    try std.testing.expectEqualStrings("10.8.0.1", bareIp("10.8.0.1:8420"));
    try std.testing.expectEqualStrings("fd00::1", bareIp("[fd00::1]:8420"));
}

// ------------------------------------------------------------------ stream tests

/// A WebSocket server that completes the upgrade, then never reads or
/// writes again: the client's writes back up until the socket blocks.
const DeafServer = struct {
    server: tlsconn.transport.Listener,
    upgraded: Io.Event = .unset,

    fn serve(s: *DeafServer, io: Io) void {
        const conn = s.server.accept(io) catch return;
        defer conn.close(io);
        var buf: [2048]u8 = undefined;
        var len: usize = 0;
        while (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n") == null) {
            if (len == buf.len) return;
            const got = conn.read(io, buf[len..]) catch return;
            if (got == 0) return;
            len += got;
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
        w.interface().writeAll(reply) catch return;
        w.interface().flush() catch return;
        s.upgraded.set(io);
        io.sleep(.fromSeconds(60), .awake) catch {}; // deaf until the test ends
    }
};

/// The in-memory network (shared/transport.zig MemNet) as the tunnel: the
/// desk at 10.8.0.1:8420, this device at 10.8.0.2.
const TestNet = struct {
    mn: tlsconn.transport.MemNet,
    src: tlsconn.transport.MemNet.Source,

    fn init(t: *TestNet) void {
        t.* = .{ .mn = .{ .gpa = std.testing.allocator }, .src = .{ .addr = net.IpAddress.parse("10.8.0.2", 0) catch unreachable } };
    }
    fn listen(t: *TestNet, io: Io) !tlsconn.transport.Listener {
        return t.mn.listen(io, try net.IpAddress.parse("10.8.0.1", 8420));
    }
    fn client(t: *TestNet, io: Io, shared: *Shared) !Client {
        return Client.init(std.testing.allocator, io, shared, "10.8.0.1:8420", t.mn.dialer(&t.src), .plain_for_tests);
    }
};

test "stream: the idle timeout fires while a write is blocked, and input never blocks the caller" {
    const io = std.testing.io;
    var tn: TestNet = undefined;
    tn.init();
    defer tn.mn.deinit();
    var srv: DeafServer = .{ .server = try tn.listen(io) };
    var fut = try io.concurrent(DeafServer.serve, .{ &srv, io });
    defer {
        fut.cancel(io);
        srv.server.ext.close(io);
    }
    var shared: Shared = .{};
    const c = try std.testing.allocator.create(Client);
    defer std.testing.allocator.destroy(c);
    c.* = try tn.client(io, &shared);
    c.idle_ms = 1500;
    c.ping_ms = 100; // pings fall due while the writer is stuck
    c.quiet = true; // the expected timeout stays off stderr
    const T = struct {
        fn stream(cl: *Client, done: *Io.Event, out: *Client.StreamResult) void {
            var backoff: i64 = 1000;
            out.* = cl.runStream(&backoff);
            done.set(cl.io);
        }
    };
    var done: Io.Event = .unset;
    var result: Client.StreamResult = .gone;
    const t0 = watchdog.nowMs(io);
    var st = try io.concurrent(T.stream, .{ c, &done, &result });
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
    server: tlsconn.transport.Listener,
    client_closed: Io.Event = .unset,

    fn serve(s: *ExitServer, io: Io) void {
        const conn = s.server.accept(io) catch return;
        defer conn.close(io);
        var buf: [2048]u8 = undefined;
        var len: usize = 0;
        while (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n") == null) {
            if (len == buf.len) return;
            const got = conn.read(io, buf[len..]) catch return;
            if (got == 0) return;
            len += got;
        }
        const head = buf[0..len];
        const name = "Sec-WebSocket-Key: ";
        const at = std.mem.indexOf(u8, head, name) orelse return;
        const rest = head[at + name.len ..];
        const key = rest[0 .. std.mem.indexOf(u8, rest, "\r\n") orelse return];
        const accept = ws.accept(key) catch return;
        var wb: [512]u8 = undefined;
        var w = conn.writer(io, &wb);
        w.interface().print("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{&accept}) catch return;
        ws.writeServerFrame(w.interface(), .text, "{\"t\":\"hello\",\"v\":1,\"input\":\"keys\"}") catch return;
        ws.writeServerFrame(w.interface(), .text, "{\"t\":\"exit\",\"code\":1}") catch return;
        ws.writeServerFrame(w.interface(), .close, "\x03\xe8session ended") catch return;
        w.interface().flush() catch return;
        // Until the client closes (EOF or a reset).
        while (true) {
            const got = conn.read(io, &buf) catch break;
            if (got == 0) break;
        }
        s.client_closed.set(io);
    }
};

test "stream: an exited program shows the ended session, then the desktop going away shows offline" {
    const io = std.testing.io;
    var tn: TestNet = undefined;
    tn.init();
    defer tn.mn.deinit();
    var srv: ExitServer = .{ .server = try tn.listen(io) };
    var fut = try io.concurrent(ExitServer.serve, .{ &srv, io });
    var listening = true;
    defer {
        fut.cancel(io);
        if (listening) srv.server.ext.close(io);
    }
    var shared: Shared = .{};
    const c = try std.testing.allocator.create(Client);
    defer std.testing.allocator.destroy(c);
    c.* = try tn.client(io, &shared);
    c.quiet = true;
    var backoff: i64 = 10;

    const r = c.runStream(&backoff);
    try std.testing.expect(r == .exited);
    try std.testing.expectEqual(@as(i64, 1), r.exited);
    c.streamEnded(r, &backoff);
    try std.testing.expectEqual(Status.session_ended, shared.status);
    try std.testing.expectEqualStrings("Session ended on the desktop (exit code 1)", shared.detail());
    try std.testing.expectEqual(@as(?i64, 1), shared.exit_code);
    // The client closed its end, so the server could close without a reset.
    try srv.client_closed.wait(io);
    // The next attempt does not flip the status to "connecting".
    try std.testing.expect(c.quietAttempt());

    // Portal exits: nothing listens any more.
    fut.await(io);
    srv.server.ext.close(io);
    listening = false;
    const r2 = c.runStream(&backoff);
    try std.testing.expect(r2 == .unreachable_err);
    c.streamEnded(r2, &backoff);
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

test "convo: the client keeps the shown tab's items from convo / convo+ (malformed ignored)" {
    const io = std.testing.io;
    var shared: Shared = .{};
    defer shared.convo.deinit(std.testing.allocator);
    const c = try std.testing.allocator.create(Client);
    defer std.testing.allocator.destroy(c);
    c.* = try Client.init(std.testing.allocator, io, &shared, "127.0.0.1:1", .os, .plain_for_tests);
    c.quiet = true;
    const id = "0102030405060708090a0b0c0d0e0f10";
    c.applyConvo("{\"t\":\"convo\",\"id\":\"" ++ id ++ "\",\"on\":true,\"items\":[{\"n\":1,\"k\":\"user\",\"text\":\"fix it\"},{\"n\":2,\"k\":\"question\",\"text\":\"Run tests?\",\"open\":true,\"options\":[{\"label\":\"Yes\",\"key\":\"1\"},{\"label\":\"No\",\"key\":\"esc\"}]}]}");
    try std.testing.expect(shared.convo.on);
    try std.testing.expectEqual(@as(usize, 2), shared.convo.items.items.len);
    try std.testing.expectEqualStrings("esc", shared.convo.items.items[1].options[1].key);
    const gen = shared.convo.generation;
    c.applyConvo("{\"t\":\"convo+\",\"id\":\"" ++ id ++ "\",\"items\":[{\"n\":2,\"k\":\"question\",\"text\":\"Run tests?\",\"open\":false}]}");
    try std.testing.expect(!shared.convo.items.items[1].open);
    try std.testing.expect(shared.convo.generation != gen);
    // A key outside the answer keys: the whole message is refused.
    c.applyConvo("{\"t\":\"convo+\",\"id\":\"" ++ id ++ "\",\"items\":[{\"n\":3,\"k\":\"question\",\"text\":\"x\",\"open\":true,\"options\":[{\"label\":\"rm\",\"key\":\"t:rm -rf\"}]}]}");
    try std.testing.expectEqual(@as(usize, 2), shared.convo.items.items.len);
}

test "projects: the list and the answers, strictly" {
    const io = std.testing.io;
    var shared: Shared = .{};
    defer shared.convo.deinit(std.testing.allocator);
    const c = try std.testing.allocator.create(Client);
    defer std.testing.allocator.destroy(c);
    c.* = try Client.init(std.testing.allocator, io, &shared, "127.0.0.1:1", .os, .plain_for_tests);
    c.quiet = true;
    c.applyProjects("{\"t\":\"projects\",\"list\":[{\"name\":\"acme\",\"color\":\"#112233\",\"mode\":\"plan\",\"running\":false,\"stoppable\":false}]}");
    try std.testing.expect(shared.has_projects);
    try std.testing.expectEqualStrings("acme", shared.projects.items[0].name());
    // A malformed list (a path for a name) changes nothing.
    c.applyProjects("{\"t\":\"projects\",\"list\":[{\"name\":\"C:\\\\x\",\"mode\":\"ask\"}]}");
    try std.testing.expectEqual(@as(usize, 1), shared.projects.len);
    try std.testing.expectEqual(@as(u64, 0), shared.project_answer_gen);
    c.applyProjects("{\"t\":\"project\",\"op\":\"start\",\"result\":\"started\",\"name\":\"acme\"}");
    try std.testing.expectEqual(@as(u64, 1), shared.project_answer_gen);
    try std.testing.expectEqual(projects_wire.Result.started, shared.project_answer.?.result);
    c.applyProjects("{\"t\":\"project\",\"op\":\"start\",\"result\":\"maybe\"}");
    try std.testing.expectEqual(@as(u64, 1), shared.project_answer_gen);
}

test "subtabs: kept for the tab shown only; the sub-tab shown going (or the tab's own snapshot) ends showing it" {
    const io = std.testing.io;
    var shared: Shared = .{};
    defer shared.convo.deinit(std.testing.allocator);
    const c = try std.testing.allocator.create(Client);
    defer std.testing.allocator.destroy(c);
    c.* = try Client.init(std.testing.allocator, io, &shared, "127.0.0.1:1", .os, .plain_for_tests);
    c.quiet = true;
    const tab = "0102030405060708090a0b0c0d0e0f10";
    const sub = "abababababababababababababababab";
    shared.current = tabs_wire.parseId(tab);
    c.applySubtabs("{\"t\":\"subtabs\",\"id\":\"" ++ tab ++ "\",\"subs\":[{\"id\":\"" ++ sub ++ "\",\"name\":\"Find tests\",\"done\":false}]}");
    try std.testing.expectEqual(@as(usize, 1), shared.subs.len);
    try std.testing.expectEqualStrings("Find tests", shared.subs.items[0].name());
    // Another tab's list is ignored; a malformed one too.
    c.applySubtabs("{\"t\":\"subtabs\",\"id\":\"ffffffffffffffffffffffffffffffff\",\"subs\":[]}");
    c.applySubtabs("{\"t\":\"subtabs\",\"id\":\"" ++ tab ++ "\",\"subs\":[{\"id\":\"x\"}]}");
    try std.testing.expectEqual(@as(usize, 1), shared.subs.len);
    // Shown, then the tab's own snapshot arrives: back to the tab.
    shared.sub_shown = subtabs_wire.parse("{\"t\":\"subtabs\",\"id\":\"" ++ tab ++ "\",\"subs\":[{\"id\":\"" ++ sub ++ "\",\"name\":\"x\"}]}").?.items[0].id;
    c.applyConvo("{\"t\":\"convo\",\"id\":\"" ++ sub ++ "\",\"on\":true,\"items\":[]}");
    try std.testing.expect(shared.sub_shown != null);
    c.applyConvo("{\"t\":\"convo\",\"id\":\"" ++ tab ++ "\",\"on\":true,\"items\":[]}");
    try std.testing.expect(shared.sub_shown == null);
    // Shown, then it leaves the list.
    shared.sub_shown = shared.subs.items[0].id;
    c.applySubtabs("{\"t\":\"subtabs\",\"id\":\"" ++ tab ++ "\",\"subs\":[]}");
    try std.testing.expect(shared.sub_shown == null);
    try std.testing.expectEqual(@as(usize, 0), shared.subs.len);
}

test "foryou: every tab's cards kept (malformed ignored), answers' texts, closed tabs drop theirs" {
    const io = std.testing.io;
    var shared: Shared = .{};
    defer shared.foryou.deinit(std.testing.allocator);
    const c = try std.testing.allocator.create(Client);
    defer std.testing.allocator.destroy(c);
    c.* = try Client.init(std.testing.allocator, io, &shared, "127.0.0.1:1", .os, .plain_for_tests);
    c.quiet = true;
    const tab = "0102030405060708090a0b0c0d0e0f10";
    c.applyForYou("{\"t\":\"foryou\",\"id\":\"" ++ tab ++ "\",\"items\":[{\"id\":\"11111111111111111111111111111111\",\"k\":\"suggest_run\",\"text\":\"zig build\",\"cmd\":\"zig build\"}]}");
    const id = tabs_wire.parseId(tab).?;
    try std.testing.expectEqual(@as(usize, 1), shared.foryou.get(id).?.len);
    c.applyForYou("{\"t\":\"foryou\",\"id\":\"" ++ tab ++ "\",\"items\":[{\"id\":\"11111111111111111111111111111111\",\"k\":\"suggest_run\",\"text\":\"x\",\"cmd\":\"a`b\"}]}");
    try std.testing.expectEqualStrings("zig build", shared.foryou.get(id).?.items[0].cmd());
    c.applyForYouResult("{\"t\":\"item\",\"op\":\"yes\",\"result\":\"sent\",\"id\":\"11111111111111111111111111111111\"}");
    try std.testing.expectEqualStrings("Sent.", shared.foryou.result());
    shared.foryou.retain(&.{});
    try std.testing.expect(shared.foryou.get(id) == null);
}
