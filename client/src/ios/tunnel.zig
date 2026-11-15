//! The app's own WireGuard tunnel (iPhone section, optional).
//!
//! Owner decision: Portal owns a per-app tunnel through a Network
//! Extension: PortalTunnel.appex (client/src/ios/tunnel_ext), an
//! NEPacketTunnelProvider written in Zig that runs the owner's pure-Zig
//! WireGuard behind one `TunnelBackend` seam. This file is the app side:
//!
//!   configure  connect.Platform.system_tunnel, on the app thread once the
//!              pairing code is known (after pairing and on every later
//!              launch, from the stored code): the wg-quick text
//!              (devicelink.wgQuick) minus its private key goes to the VPN
//!              configuration, the key to the Keychain (keyref.zig); the
//!              NETunnelProviderManager is saved only when that changed
//!              (tunnel_note.needsSave), then started. True: the viewer
//!              dials the desk through OS sockets, which iOS routes into
//!              the tunnel.
//!   start      Portal came on screen (Platform.on_resume).
//!   stop       Portal went to the background (Platform.on_suspend).
//!
//! Everything NetworkExtension does is asynchronous: completion handlers
//! and NEVPNStatusDidChangeNotification on the main queue set the status
//! line (`note`, connect.Platform.note) and wake the window. No polling.
//!
//! Built only with `-Dios-tunnel=true` (needs a paid Apple Developer
//! account: the Network Extension entitlement, packet-tunnel-provider).
//! Without it `configure` returns false and the app runs the same tunnel
//! in its own process (client/src/tunnel), as `portal connect` does.

const std = @import("std");
const build_options = @import("ios_options");
const view = @import("view");
const credstore = @import("client").credstore_mod;
const keyref = @import("tunnel_ext/keyref.zig");
const tn = @import("tunnel_note.zig");
const ios = view.Window.ios;
const objc = ios.objc;
const Object = objc.Object;
const msgSend = objc.msgSend;
const sel = objc.sel;

pub const enabled = build_options.tunnel;
/// The tunnel extension's bundle id: the app's + ".tunnel".
pub const provider_bundle_id = build_options.bundle_id ++ ".tunnel";

var io: std.Io = undefined;

/// What Portal wants (on screen: up), applied by the completion handlers.
var want_up: std.atomic.Value(bool) = .init(false);
/// configure() handed the tunnel to the system: start/stop act.
var active: std.atomic.Value(bool) = .init(false);

/// A configuration to install (configure -> the main thread), or none.
/// Handed over whole: configure fills a fresh one and publishes it here;
/// the main thread takes it (swap) and frees it, so neither thread ever
/// touches a buffer the other one is using.
const Pending = struct {
    buf: [keyref.max_config]u8 = undefined,
    len: usize = 0,

    fn text(p: *const Pending) []const u8 {
        return p.buf[0..p.len];
    }
};
var pending: std.atomic.Value(?*Pending) = .init(null);
const pending_alloc = std.heap.c_allocator;

/// The status line (under `note_mutex`).
var note_mutex: std.Io.Mutex = .init;
var note_buf: [160]u8 = undefined;
var note_len: usize = 0;

pub fn init(the_io: std.Io) void {
    io = the_io;
}

/// UI thread (connect.Platform.note): the tunnel's status line.
pub fn note(buf: []u8) []const u8 {
    note_mutex.lockUncancelable(io);
    defer note_mutex.unlock(io);
    const n = @min(buf.len, note_len);
    @memcpy(buf[0..n], note_buf[0..n]);
    return buf[0..n];
}

/// Any thread: sets the status line and wakes the window if it changed.
fn setNote(text: []const u8) void {
    note_mutex.lockUncancelable(io);
    const n = @min(text.len, note_buf.len);
    const changed = n != note_len or !std.mem.eql(u8, note_buf[0..n], text[0..n]);
    @memcpy(note_buf[0..n], text[0..n]);
    note_len = n;
    note_mutex.unlock(io);
    if (!changed) return;
    if (n > 0) std.log.warn("{s}", .{text[0..n]});
    ios.postEvent(.expose);
}

fn setErrorNote(op: tn.Op, err: ?*Object) void {
    var b: [160]u8 = undefined;
    const pool = objc.AutoreleasePool.push();
    defer pool.pop();
    const domain = msgSend(?*Object, err, sel("domain"), .{});
    const want = objc.newString("NEVPNErrorDomain");
    defer if (want) |w| objc.release(w);
    const code = msgSend(objc.NSInteger, err, sel("code"), .{});
    const why = objc.stringBytes(msgSend(?*Object, err, sel("localizedDescription"), .{}));
    setNote(tn.errorNote(&b, op, objc.isEqualString(domain, want), code, why));
}

/// Any thread: Portal is on screen, bring the tunnel up.
pub fn start() void {
    if (!enabled or !active.load(.acquire)) return;
    want_up.store(true, .release);
    objc.onMainAsync(null, load);
}

/// Any thread: Portal left the screen, take the tunnel down.
pub fn stop() void {
    if (!enabled or !active.load(.acquire)) return;
    want_up.store(false, .release);
    objc.onMainAsync(null, load);
}

/// App thread (connect.Platform.system_tunnel): hand the tunnel to the
/// packet tunnel extension. False (the viewer starts the in-process
/// tunnel instead): built without -Dios-tunnel, or the key could not be
/// put in the Keychain (said in the status line).
///
/// The private key never goes into the VPN configuration (system
/// preferences, which can reach backups and diagnostics): it goes to the
/// Keychain, this device only, readable by the extension without Face ID
/// (keyref.zig), and the configuration names that item.
pub fn configure(wg_quick: []const u8) bool {
    // Comptime: without -Dios-tunnel nothing of NetworkExtension is
    // referenced (it is not linked then).
    return if (enabled) configureEnabled(wg_quick) else false;
}

fn configureEnabled(wg_quick: []const u8) bool {
    configureOrFail(wg_quick) catch |err| {
        var b: [160]u8 = undefined;
        setNote(std.fmt.bufPrint(&b, "Background tunnel unavailable ({t}): using the in-app tunnel", .{err}) catch "Background tunnel unavailable: using the in-app tunnel");
        return false;
    };
    return true;
}

fn configureOrFail(wg_quick: []const u8) (keyref.Error || credstore.Error || error{OutOfMemory})!void {
    const p = try pending_alloc.create(Pending);
    p.* = .{};
    errdefer pending_alloc.destroy(p);
    const parts = try keyref.split(wg_quick, &p.buf);
    try credstore.saveUnattended(keyref.keychain_target, parts.key);
    p.len = parts.public.len;
    observe();
    active.store(true, .release);
    // Configured while on screen: up as soon as it is saved.
    want_up.store(true, .release);
    if (pending.swap(p, .acq_rel)) |old| pending_alloc.destroy(old);
    setNote(tn.statusNote(.connecting, true));
    objc.onMainAsync(null, load);
}

fn load(_: ?*anyopaque) callconv(.c) void {
    const cls = objc.lookUpClass("NETunnelProviderManager") orelse return setNote("Background tunnel: NetworkExtension is missing from this build");
    msgSend(void, cls, sel("loadAllFromPreferencesWithCompletionHandler:"), .{&loaded_block});
}

var loaded_block: objc.Block = objc.Block.global(@ptrCast(&loaded));
var saved_block: objc.Block = objc.Block.global(@ptrCast(&saved));

/// loadAllFromPreferences' completion (main queue): our manager is the
/// one whose provider is our extension.
fn loaded(_: *const objc.Block, managers: ?*Object, err: ?*Object) callconv(.c) void {
    if (err != null) return setErrorNote(.load, err);
    const mgr = find(managers);
    if (pending.swap(null, .acq_rel)) |p| {
        defer pending_alloc.destroy(p);
        if (tn.needsSave(existing(mgr), p.text(), keyref.keychain_target)) return install(mgr, p.text());
    }
    const m = mgr orelse return setNote(tn.statusNote(.invalid, want_up.load(.acquire)));
    const conn = msgSend(?*Object, m, sel("connection"), .{}) orelse return;
    if (want_up.load(.acquire)) {
        var e: ?*Object = null;
        if (msgSend(objc.BOOL, conn, sel("startVPNTunnelAndReturnError:"), .{&e}) == 0) return setErrorNote(.start, e);
    } else {
        msgSend(void, conn, sel("stopVPNTunnel"), .{});
    }
    statusChanged(conn);
}

fn find(managers: ?*Object) ?*Object {
    const want = objc.newString(provider_bundle_id) orelse return null;
    defer objc.release(want);
    const n = msgSend(objc.NSUInteger, managers, sel("count"), .{});
    var i: objc.NSUInteger = 0;
    while (i < n) : (i += 1) {
        const m = msgSend(?*Object, managers, sel("objectAtIndex:"), .{i});
        if (isOurs(m)) return m;
    }
    return null;
}

/// `mgr`'s provider is our extension.
fn isOurs(mgr: ?*Object) bool {
    const proto = msgSend(?*Object, mgr orelse return false, sel("protocolConfiguration"), .{});
    const id = msgSend(?*Object, proto, sel("providerBundleIdentifier"), .{});
    const want = objc.newString(provider_bundle_id) orelse return false;
    defer objc.release(want);
    return objc.isEqualString(id, want);
}

/// What `m` holds now (valid until the main queue's pool drains).
fn existing(m: ?*Object) ?tn.Existing {
    const mgr = m orelse return null;
    const proto = msgSend(?*Object, mgr, sel("protocolConfiguration"), .{});
    const dict = msgSend(?*Object, proto, sel("providerConfiguration"), .{});
    return .{
        .config = dictString(dict, keyref.config_key),
        .key_ref = dictString(dict, keyref.key_ref_key),
        .enabled = msgSend(objc.BOOL, mgr, sel("isEnabled"), .{}) != 0,
    };
}

fn dictString(dict: ?*Object, key: []const u8) []const u8 {
    const d = dict orelse return "";
    const k = objc.newString(key) orelse return "";
    defer objc.release(k);
    return objc.stringBytes(msgSend(?*Object, d, sel("objectForKey:"), .{k}));
}

/// Creates or updates the manager with `config` (the wg-quick text
/// without its private key) in providerConfiguration["wgQuickConfig"]
/// (WireGuardKit's convention) and the key's Keychain item name in
/// providerConfiguration["privateKeyRef"] (keyref.zig). iOS asks the
/// user once to allow a new VPN configuration.
fn install(existing_mgr: ?*Object, config: []const u8) void {
    const pool = objc.AutoreleasePool.push();
    defer pool.pop();
    const m = existing_mgr orelse (msgSend(?*Object, objc.getClass("NETunnelProviderManager"), sel("new"), .{}) orelse return);
    // A new manager (from `new`) is +1; saving keeps the system's own copy.
    defer if (existing_mgr == null) objc.release(m);
    const proto = msgSend(?*Object, objc.getClass("NETunnelProviderProtocol"), sel("new"), .{}) orelse return;
    defer objc.release(proto);
    const bid = objc.newString(provider_bundle_id);
    defer if (bid) |x| objc.release(x);
    msgSend(void, proto, sel("setProviderBundleIdentifier:"), .{bid});
    const server = objc.newString("Portal desktop");
    defer if (server) |x| objc.release(x);
    msgSend(void, proto, sel("setServerAddress:"), .{server});
    const dict = msgSend(?*Object, objc.getClass("NSMutableDictionary"), sel("dictionary"), .{}) orelse return;
    for ([_][2][]const u8{ .{ keyref.config_key, config }, .{ keyref.key_ref_key, keyref.keychain_target } }) |kv| {
        const k = objc.newString(kv[0]) orelse return;
        defer objc.release(k);
        const v = objc.newString(kv[1]) orelse return;
        defer objc.release(v);
        msgSend(void, dict, sel("setObject:forKey:"), .{ v, k });
    }
    msgSend(void, proto, sel("setProviderConfiguration:"), .{dict});
    msgSend(void, m, sel("setProtocolConfiguration:"), .{proto});
    const desc = objc.newString("Portal");
    defer if (desc) |x| objc.release(x);
    msgSend(void, m, sel("setLocalizedDescription:"), .{desc});
    msgSend(void, m, sel("setEnabled:"), .{objc.YES});
    msgSend(void, m, sel("saveToPreferencesWithCompletionHandler:"), .{&saved_block});
}

/// saveToPreferences' completion: load again (a saved manager is
/// reloaded before it starts) and apply the wanted state.
fn saved(_: *const objc.Block, err: ?*Object) callconv(.c) void {
    if (err != null) return setErrorNote(.save, err);
    objc.onMainAsync(null, load);
}

// ---------------------------------------------------------- status

/// NetworkExtension (linked only with -Dios-tunnel; referenced only then).
extern const NEVPNStatusDidChangeNotification: ?*Object;
var observing: bool = false;

/// Registers for NEVPNStatusDidChangeNotification once (any thread; the
/// registration itself runs on the main queue).
fn observe() void {
    objc.onMainAsync(null, struct {
        fn f(_: ?*anyopaque) callconv(.c) void {
            if (observing) return;
            observing = true;
            const cls = observerClass() orelse return;
            const obs = msgSend(?*Object, cls, sel("new"), .{}) orelse return; // kept for the process
            const center = msgSend(?*Object, objc.getClass("NSNotificationCenter"), sel("defaultCenter"), .{});
            msgSend(void, center, sel("addObserver:selector:name:object:"), .{ obs, sel("vpnStatusChanged:"), NEVPNStatusDidChangeNotification, @as(?*Object, null) });
        }
    }.f);
}

fn observerClass() ?*objc.Class {
    const name = "PortalTunnelObserver";
    if (objc.lookUpClass(name)) |c| return c;
    const b = objc.ClassBuilder.begin(objc.getClass("NSObject"), name) orelse return objc.lookUpClass(name);
    b.addMethod("vpnStatusChanged:", &Observer.changed, "v@:@");
    return b.register();
}

const Observer = struct {
    /// The notification's object is the NEVPNConnection that changed.
    fn changed(_: *Object, _: *objc.Selector, notification: ?*Object) callconv(.c) void {
        statusChanged(msgSend(?*Object, notification, sel("object"), .{}));
    }
};

/// The status line from `conn`'s state (main queue). The notification is
/// for any VPN on the phone: only our own manager's connection counts.
fn statusChanged(conn: ?*Object) void {
    const c = conn orelse return;
    // NETunnelProviderSession.manager -> its protocol's provider.
    if (!isOurs(msgSend(?*Object, c, sel("manager"), .{}))) return;
    const st: tn.Status = @enumFromInt(msgSend(objc.NSInteger, c, sel("status"), .{}));
    setNote(tn.statusNote(st, want_up.load(.acquire)));
}

comptime {
    _ = &configure;
}
