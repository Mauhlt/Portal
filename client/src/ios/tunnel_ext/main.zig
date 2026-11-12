//! Portal's packet tunnel extension (PortalTunnel.appex inside Portal.app),
//! in Zig: an NEPacketTunnelProvider subclass registered at runtime, the
//! WireGuard implementation behind backend.zig's `TunnelBackend` seam (the
//! owner's pure-Zig WireGuard, ../WireGuard).
//!
//!   main             registers PortalPacketTunnelProvider, NSExtensionMain
//!   startTunnel      providerConfiguration["wgQuickConfig"] (the app wrote
//!                    it, tunnel.zig) -> backend.configure -> network
//!                    settings (addresses, routes, MTU) -> backend.start ->
//!                    read packets
//!   packets in       packetFlow.readPackets completion -> backend.deliver,
//!                    re-armed from the completion (no polling)
//!   packets out      backend Output -> packetFlow.writePackets
//!   stopTunnel       backend.stop
//!
//! Needs the Network Extension entitlement (packet-tunnel-provider) on both
//! the app and this extension: a paid Apple Developer account. STATUS:
//! compile-checked for aarch64-ios only (`zig build ios-check`).

const std = @import("std");
const objc = @import("IosObjC");
const backend_mod = @import("backend.zig");
const Object = objc.Object;
const Selector = objc.Selector;
const msgSend = objc.msgSend;
const sel = objc.sel;

// Foundation (an app extension's main hands over to it).
extern fn NSExtensionMain(argc: c_int, argv: ?[*]?[*:0]u8) c_int;
extern "c" fn _NSGetArgc() *c_int;
extern "c" fn _NSGetArgv() *?[*]?[*:0]u8;
extern "c" fn _Block_copy(block: *const anyopaque) ?*anyopaque;
extern "c" fn _Block_release(block: *const anyopaque) void;

const class_name = "PortalPacketTunnelProvider";

var zig_backend: backend_mod.ZigBackend = undefined;
var backend: backend_mod.TunnelBackend = undefined;
/// The provider instance (one per extension process).
var provider: ?*Object = null;
/// startTunnel's completion handler (copied), until settings are applied.
var start_done: ?*objc.Block = null;
var stopping: std.atomic.Value(bool) = .init(false);
var settings: backend_mod.NetSettings = .{};

pub fn main(init: std.process.Init) void {
    // The one backend compiled in (see backend.zig for adding a fallback).
    zig_backend = backend_mod.ZigBackend.init(init.gpa, init.io);
    backend = zig_backend.backend();
    _ = providerClass();
    _ = NSExtensionMain(_NSGetArgc().*, _NSGetArgv().*);
}

const Provider = struct {
    /// startTunnelWithOptions:completionHandler:
    fn startTunnel(self: *Object, _: *Selector, _: ?*Object, done: ?*objc.Block) callconv(.c) void {
        provider = self;
        stopping.store(false, .release);
        const pool = objc.AutoreleasePool.push();
        defer pool.pop();
        const copied: ?*objc.Block = if (done) |d| @ptrCast(@alignCast(_Block_copy(d))) else null;
        const text = configText(self) orelse return finish(copied, "no tunnel configuration (pair this iPhone again)");
        backend.configure(text, &settings) catch return finish(copied, "the tunnel configuration is invalid");
        const ns = networkSettings(&settings) orelse return finish(copied, "cannot build the network settings");
        start_done = copied;
        msgSend(void, self, sel("setTunnelNetworkSettings:completionHandler:"), .{ ns, &applied_block });
    }

    /// stopTunnelWithReason:completionHandler:
    fn stopTunnel(_: *Object, _: *Selector, _: objc.NSInteger, done: ?*objc.Block) callconv(.c) void {
        stopping.store(true, .release);
        backend.stop();
        if (done) |d| {
            const f: *const fn (*objc.Block) callconv(.c) void = @ptrCast(@alignCast(d.invoke));
            f(d);
        }
    }
};

/// Calls the start completion with nil (ok) or an NSError carrying `why`.
fn finish(done: ?*objc.Block, why: ?[]const u8) void {
    const d = done orelse return;
    defer _Block_release(d);
    var err: ?*Object = null;
    if (why) |w| {
        std.log.err("tunnel: {s}", .{w});
        const domain = objc.newString("Portal.tunnel");
        defer if (domain) |x| objc.release(x);
        err = msgSend(?*Object, objc.getClass("NSError"), sel("errorWithDomain:code:userInfo:"), .{ domain, @as(objc.NSInteger, 1), @as(?*Object, null) });
    }
    const f: *const fn (*objc.Block, ?*Object) callconv(.c) void = @ptrCast(@alignCast(d.invoke));
    f(d, err);
}

fn configText(self: *Object) ?[]const u8 {
    const proto = msgSend(?*Object, self, sel("protocolConfiguration"), .{}) orelse return null;
    const cfg = msgSend(?*Object, proto, sel("providerConfiguration"), .{}) orelse return null;
    const key = objc.newString("wgQuickConfig") orelse return null;
    defer objc.release(key);
    const v = msgSend(?*Object, cfg, sel("objectForKey:"), .{key}) orelse return null;
    const s = objc.stringBytes(v);
    return if (s.len == 0) null else s;
}

fn nsString(text: []const u8) ?*Object {
    const s = objc.newString(text) orelse return null;
    return msgSend(?*Object, s, sel("autorelease"), .{});
}

fn ip4(a: [4]u8, buf: *[16]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ a[0], a[1], a[2], a[3] }) catch "0.0.0.0";
}

/// NEPacketTunnelNetworkSettings from the parsed configuration (autoreleased).
fn networkSettings(s: *const backend_mod.NetSettings) ?*Object {
    const arr = objc.getClass("NSMutableArray");
    const addrs = msgSend(?*Object, arr, sel("array"), .{}) orelse return null;
    const masks = msgSend(?*Object, arr, sel("array"), .{}) orelse return null;
    var b1: [16]u8 = undefined;
    var b2: [16]u8 = undefined;
    for (s.addrs[0..s.n_addrs]) |a| {
        msgSend(void, addrs, sel("addObject:"), .{nsString(ip4(a.addr, &b1))});
        msgSend(void, masks, sel("addObject:"), .{nsString(backend_mod.mask(a.prefix, &b2))});
    }
    const routes = msgSend(?*Object, arr, sel("array"), .{}) orelse return null;
    for (s.routes[0..s.n_routes]) |r| {
        const ra = msgSend(?*Object, objc.getClass("NEIPv4Route"), sel("alloc"), .{}) orelse continue;
        const route = msgSend(?*Object, ra, sel("initWithDestinationAddress:subnetMask:"), .{ nsString(ip4(r.addr, &b1)), nsString(backend_mod.mask(r.prefix, &b2)) }) orelse continue;
        msgSend(void, routes, sel("addObject:"), .{route});
        objc.release(route);
    }
    const v4a = msgSend(?*Object, objc.getClass("NEIPv4Settings"), sel("alloc"), .{}) orelse return null;
    const v4 = msgSend(?*Object, v4a, sel("initWithAddresses:subnetMasks:"), .{ addrs, masks }) orelse return null;
    defer objc.release(v4);
    msgSend(void, v4, sel("setIncludedRoutes:"), .{routes});
    const na = msgSend(?*Object, objc.getClass("NEPacketTunnelNetworkSettings"), sel("alloc"), .{}) orelse return null;
    const ns = msgSend(?*Object, na, sel("initWithTunnelRemoteAddress:"), .{nsString(s.remote())}) orelse return null;
    msgSend(void, ns, sel("setIPv4Settings:"), .{v4});
    msgSend(void, ns, sel("setMTU:"), .{msgSend(?*Object, objc.getClass("NSNumber"), sel("numberWithUnsignedShort:"), .{s.mtu})});
    return msgSend(?*Object, ns, sel("autorelease"), .{});
}

var applied_block: objc.Block = objc.Block.global(@ptrCast(&applied));

/// setTunnelNetworkSettings' completion: start WireGuard and the reads.
fn applied(_: *const objc.Block, err: ?*Object) callconv(.c) void {
    const done = start_done;
    start_done = null;
    if (err != null) return finish(done, "iOS refused the tunnel settings");
    backend.start(.{ .ctx = null, .f = writeOut }) catch return finish(done, "WireGuard did not start");
    readMore();
    finish(done, null);
}

var read_block: objc.Block = objc.Block.global(@ptrCast(&readDone));

fn readMore() void {
    if (stopping.load(.acquire)) return;
    const p = provider orelse return;
    const flow = msgSend(?*Object, p, sel("packetFlow"), .{}) orelse return;
    msgSend(void, flow, sel("readPacketsWithCompletionHandler:"), .{&read_block});
}

/// readPackets' completion: hand each packet to WireGuard, then re-arm.
fn readDone(_: *const objc.Block, packets: ?*Object, _: ?*Object) callconv(.c) void {
    const n = msgSend(objc.NSUInteger, packets, sel("count"), .{});
    var i: objc.NSUInteger = 0;
    while (i < n) : (i += 1) {
        const d = msgSend(?*Object, packets, sel("objectAtIndex:"), .{i}) orelse continue;
        const len = msgSend(objc.NSUInteger, d, sel("length"), .{});
        const bytes = msgSend(?[*]const u8, d, sel("bytes"), .{}) orelse continue;
        backend.deliver(bytes[0..len]);
    }
    readMore();
}

/// WireGuard's decrypted packets -> the packet flow (device thread).
fn writeOut(_: ?*anyopaque, packet: []const u8, family: u8) void {
    const p = provider orelse return;
    const pool = objc.AutoreleasePool.push();
    defer pool.pop();
    const flow = msgSend(?*Object, p, sel("packetFlow"), .{}) orelse return;
    const data = msgSend(?*Object, objc.getClass("NSData"), sel("dataWithBytes:length:"), .{ @as([*]const u8, packet.ptr), @as(objc.NSUInteger, packet.len) });
    const proto = msgSend(?*Object, objc.getClass("NSNumber"), sel("numberWithInt:"), .{@as(c_int, family)});
    const pkts = msgSend(?*Object, objc.getClass("NSArray"), sel("arrayWithObject:"), .{data});
    const protos = msgSend(?*Object, objc.getClass("NSArray"), sel("arrayWithObject:"), .{proto});
    _ = msgSend(objc.BOOL, flow, sel("writePackets:withProtocols:"), .{ pkts, protos });
}

fn providerClass() *objc.Class {
    if (objc.lookUpClass(class_name)) |c| return c;
    const b = objc.ClassBuilder.begin(objc.getClass("NEPacketTunnelProvider"), class_name) orelse return objc.lookUpClass(class_name).?;
    b.addMethod("startTunnelWithOptions:completionHandler:", &Provider.startTunnel, "v@:@@?");
    b.addMethod("stopTunnelWithReason:completionHandler:", &Provider.stopTunnel, "v@:q@?");
    return b.register();
}

comptime {
    _ = &main; // analysed in the object-only compile check
}

test {
    _ = backend_mod;
}
