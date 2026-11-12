//! The app's own WireGuard tunnel (iPhone section, optional).
//!
//! Owner decision: Portal owns a per-app tunnel through a Network
//! Extension: PortalTunnel.appex (client/src/ios/tunnel_ext), an
//! NEPacketTunnelProvider written in Zig that runs the owner's pure-Zig
//! WireGuard (../WireGuard) behind one `TunnelBackend` seam. This file is
//! the app side: it turns that tunnel on when Portal comes on screen and
//! off when it goes to the background, from the lifecycle hooks (no
//! polling), through NETunnelProviderManager.
//!
//! Built only with `-Dios-tunnel=true` (needs a paid Apple Developer
//! account: the Network Extension entitlement, packet-tunnel-provider).
//! Without it every function here is a no-op and the phone uses the
//! WireGuard app (the pairing page's Shortcuts automations), exactly as
//! before. With it, `zig build ios` also builds the extension into
//! Portal.app/PlugIns.

const std = @import("std");
const build_options = @import("ios_options");
const view = @import("view");
const ios = view.Window.ios;
const objc = ios.objc;
const Object = objc.Object;
const msgSend = objc.msgSend;
const sel = objc.sel;

pub const enabled = build_options.tunnel;
/// The tunnel extension's bundle id: the app's + ".tunnel".
pub const provider_bundle_id = build_options.bundle_id ++ ".tunnel";

/// What the last start/stop asked for (the completion handler applies it).
var want_up: std.atomic.Value(bool) = .init(false);
/// A wg-quick configuration to install (configure), or none.
var config_buf: [4096]u8 = undefined;
var config_len: usize = 0;
var config_pending: std.atomic.Value(bool) = .init(false);

/// Any thread: Portal is on screen, bring the tunnel up.
pub fn start() void {
    if (!enabled) return;
    want_up.store(true, .release);
    objc.onMainAsync(null, load);
}

/// Any thread: Portal left the screen, take the tunnel down.
pub fn stop() void {
    if (!enabled) return;
    want_up.store(false, .release);
    objc.onMainAsync(null, load);
}

/// App thread: install (or replace) the tunnel's configuration, in
/// wg-quick format (this phone's private key, the desk as the only peer,
/// AllowedIPs = the desk's tunnel address). iOS asks the user once to
/// allow the VPN configuration. Called after the desk confirmed this
/// phone's public key (docs/ios-native.md: not wired yet).
pub fn configure(wg_quick: []const u8) error{TooLong}!void {
    if (!enabled) return;
    if (wg_quick.len > config_buf.len) return error.TooLong;
    @memcpy(config_buf[0..wg_quick.len], wg_quick);
    config_len = wg_quick.len;
    config_pending.store(true, .release);
    objc.onMainAsync(null, load);
}

fn load(_: ?*anyopaque) callconv(.c) void {
    const cls = objc.lookUpClass("NETunnelProviderManager") orelse return; // framework not linked
    msgSend(void, cls, sel("loadAllFromPreferencesWithCompletionHandler:"), .{&loaded_block});
}

var loaded_block: objc.Block = objc.Block.global(@ptrCast(&loaded));
var saved_block: objc.Block = objc.Block.global(@ptrCast(&saved));

/// loadAllFromPreferences' completion (main queue): our manager is the
/// one whose provider is our extension.
fn loaded(_: *const objc.Block, managers: ?*Object, err: ?*Object) callconv(.c) void {
    if (err != null) return;
    const mgr = find(managers);
    if (config_pending.swap(false, .acq_rel)) return install(mgr);
    const m = mgr orelse return; // never configured: nothing to start
    const conn = msgSend(?*Object, m, sel("connection"), .{}) orelse return;
    if (want_up.load(.acquire)) {
        _ = msgSend(objc.BOOL, conn, sel("startVPNTunnelAndReturnError:"), .{@as(?*?*Object, null)});
    } else {
        msgSend(void, conn, sel("stopVPNTunnel"), .{});
    }
}

fn find(managers: ?*Object) ?*Object {
    const want = objc.newString(provider_bundle_id) orelse return null;
    defer objc.release(want);
    const n = msgSend(objc.NSUInteger, managers, sel("count"), .{});
    var i: objc.NSUInteger = 0;
    while (i < n) : (i += 1) {
        const m = msgSend(?*Object, managers, sel("objectAtIndex:"), .{i});
        const proto = msgSend(?*Object, m, sel("protocolConfiguration"), .{});
        const id = msgSend(?*Object, proto, sel("providerBundleIdentifier"), .{});
        if (objc.isEqualString(id, want)) return m;
    }
    return null;
}

/// Creates or updates the manager with the pending configuration
/// (WireGuardKit's convention: providerConfiguration["wgQuickConfig"]).
fn install(existing: ?*Object) void {
    const pool = objc.AutoreleasePool.push();
    defer pool.pop();
    const m = existing orelse (msgSend(?*Object, objc.getClass("NETunnelProviderManager"), sel("new"), .{}) orelse return);
    const proto = msgSend(?*Object, objc.getClass("NETunnelProviderProtocol"), sel("new"), .{}) orelse return;
    defer objc.release(proto);
    const bid = objc.newString(provider_bundle_id);
    defer if (bid) |x| objc.release(x);
    msgSend(void, proto, sel("setProviderBundleIdentifier:"), .{bid});
    const server = objc.newString("Portal desktop");
    defer if (server) |x| objc.release(x);
    msgSend(void, proto, sel("setServerAddress:"), .{server});
    const cfg = objc.newString(config_buf[0..config_len]);
    defer if (cfg) |x| objc.release(x);
    const key = objc.newString("wgQuickConfig");
    defer if (key) |x| objc.release(x);
    const dict = msgSend(?*Object, objc.getClass("NSDictionary"), sel("dictionaryWithObject:forKey:"), .{ cfg, key });
    msgSend(void, proto, sel("setProviderConfiguration:"), .{dict});
    msgSend(void, m, sel("setProtocolConfiguration:"), .{proto});
    const desc = objc.newString("Portal");
    defer if (desc) |x| objc.release(x);
    msgSend(void, m, sel("setLocalizedDescription:"), .{desc});
    msgSend(void, m, sel("setEnabled:"), .{objc.YES});
    msgSend(void, m, sel("saveToPreferencesWithCompletionHandler:"), .{&saved_block});
}

/// saveToPreferences' completion: apply the wanted state.
fn saved(_: *const objc.Block, err: ?*Object) callconv(.c) void {
    if (err != null) return;
    objc.onMainAsync(null, load);
}

comptime {
    _ = &configure;
}
