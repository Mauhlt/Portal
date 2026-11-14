//! The in-process WireGuard tunnel: the owner's Zig WireGuard (module
//! "WireGuard": the device, its UDP socket and its userspace TCP/IPv4
//! stack, `netstack`) running inside Portal, with no adapter, no driver
//! and no administrator rights. It is Portal's only network path:
//!
//!   desk     UDP <tunnel port> <-> zwg device <-> netstack at 10.8.0.1
//!            -> listeners on 8420 inside the tunnel -> web.zig (TLS 1.3,
//!            WebSocket): one peer per paired device, derived from the
//!            device store (devices.zig), nothing else gets in
//!   device   zwg device with the desk as its only peer <-> netstack at
//!            the device's 10.8.0.x -> dial 10.8.0.1:8420 -> the same TLS
//!            and WebSocket client code as before (client/src/net)
//!
//! Above the stream nothing knows about the tunnel: the netstack's streams
//! are handed out as `transport.Stream`s (shared/transport.zig), and the
//! address a stream reports as its peer is the device's tunnel address,
//! which WireGuard's allowed-IPs source check binds to the device's key.
//!
//! Threads (no polling, no fixed ticks):
//!   * the zwg device loop (Device.run): UDP, crypto, its timers;
//!   * the netstack's own thread (Stack.start): TCP input, timers, output.
//! Portal's own threads call the netstack's non-blocking stream calls; when
//! one would block they sleep in a cancelable Io wait (`transport.
//! Readiness`) that the stack's ready callback signals, then retry. So
//! Portal's connection supervisors and watchdogs cancel them like any
//! socket call.
//!
//! Keys: the caller passes the private key in; it is copied into the
//! device and this object, and wiped from both when they go (and from the
//! temporary Options after each device start), per zwg's convention.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const net = Io.net;
const wg = @import("WireGuard");
const options = @import("tunnel_options");
const shared = @import("shared");
const transport = shared.transport;
const tunnelnet = shared.tunnelnet;

pub const keys = @import("keys.zig");

/// Whether this build has a working userspace TCP/IP stack. The netstack's
/// API is final but its bodies may still be stubs (`-Dnetstack-ready`);
/// without it every start fails with error.NetstackNotReady instead of
/// reaching a stub.
pub const ready = options.netstack_ready and @hasDecl(wg, "netstack");

const ns = if (@hasDecl(wg, "netstack")) wg.netstack else struct {};
const Device = wg.device.Device;
const Clock = wg.device.device.Clock;

pub const Key = wg.device.keys.Key;

/// One WireGuard peer of this tunnel.
pub const Peer = struct {
    public_key: Key,
    /// The one address this peer may use inside the tunnel (a /32): a
    /// device's 10.8.0.x on the desk, 10.8.0.1 on a device.
    address: tunnelnet.Ip4,
    /// "host:port" (a DNS name is looked up again while the peer is
    /// silent); null on the desk: devices roam, the desk learns where
    /// they are from their authenticated packets.
    endpoint: ?[]const u8 = null,
    persistent_keepalive: u16 = 0,
};

pub const Options = struct {
    private_key: Key,
    /// This side's tunnel address (10.8.0.1 on the desk).
    address: tunnelnet.Ip4,
    /// UDP port; null or 0: any free port (devices).
    udp_port: ?u16 = null,
    /// Bind the UDP socket to loopback only (tests: never reachable from
    /// the network, and no firewall prompt).
    loopback_only: bool = false,
    peers: []const Peer = &.{},
};

pub const StartError = error{ NetstackNotReady, OutOfMemory, SystemResources, InvalidEndpoint, ThreadSpawnFailed } || Device.InitError;

pub const Tunnel = struct {
    gpa: std.mem.Allocator,
    io: Io,
    clock: Clock,
    private_key: Key,
    address: tunnelnet.Ip4,
    udp_port: ?u16,
    loopback_only: bool,
    stack: *StackT,
    /// Guarded by `mutex`: the device and its thread (replaced when the
    /// peer list changes, see `setPeers`).
    mutex: Io.Mutex = .init,
    device: ?*Device = null,
    device_thread: ?std.Thread = null,
    /// The peers the running device has (owned copies).
    peers: std.ArrayList(OwnedPeer) = .empty,
    readiness: transport.Readiness = .{},

    const StackT = if (@hasDecl(wg, "netstack")) ns.Stack else opaque {};

    const OwnedPeer = struct {
        peer: Peer,
        endpoint_buf: [shared.pairqr.max_endpoint]u8 = undefined,
    };

    pub fn start(gpa: std.mem.Allocator, io: Io, o: Options) StartError!*Tunnel {
        if (!ready) return error.NetstackNotReady;
        const t = try gpa.create(Tunnel);
        errdefer gpa.destroy(t);
        t.* = .{
            .gpa = gpa,
            .io = io,
            .clock = .{ .io = io },
            .private_key = o.private_key,
            .address = o.address,
            .udp_port = o.udp_port,
            .loopback_only = o.loopback_only,
            .stack = undefined,
        };
        errdefer std.crypto.secureZero(u8, &t.private_key);
        t.stack = ns.Stack.create(gpa, &t.clock, .{ .address = .{ .v4 = o.address } }) catch |err| return switch (err) {
            error.InvalidLimits, error.InvalidMtu, error.AddressFamilyUnsupported => error.SystemResources,
            else => |e| e,
        };
        errdefer t.stack.destroy();
        t.stack.setReadyCallback(t, onReady);
        t.stack.start() catch return error.SystemResources;
        errdefer t.stack.stop();
        try t.setPeersLocked(o.peers);
        return t;
    }

    /// Called by the stack (any thread, its lock released) whenever a
    /// stream or listener may have become ready: wakes the waiters.
    fn onReady(ctx: ?*anyopaque) void {
        const t: *Tunnel = @ptrCast(@alignCast(ctx.?));
        t.readiness.signal(t.io);
    }

    /// Resets every connection (blocked calls return), stops everything
    /// and wipes the keys. Threads using this tunnel's streams must have
    /// ended (or be ending on the reset) before the memory goes.
    pub fn abortAll(t: *Tunnel) void {
        t.stack.abortAll();
        t.readiness.signal(t.io);
    }

    pub fn destroy(t: *Tunnel) void {
        t.abortAll();
        t.stopDevice();
        t.stack.setReadyCallback(null, null);
        t.stack.destroy();
        t.peers.deinit(t.gpa);
        std.crypto.secureZero(u8, &t.private_key);
        t.gpa.destroy(t);
    }

    /// Replaces the peer list (the desk: whenever the device store
    /// changes). A no-op if it is the same. zwg's Device.setPeers applies
    /// it on the running device: peers that stay keep their sessions,
    /// removed ones are wiped. (A WireGuard without it gets the device
    /// restarted on the same stack instead; TCP survives either way.)
    pub fn setPeers(t: *Tunnel, peers: []const Peer) !void {
        t.mutex.lockUncancelable(t.io);
        defer t.mutex.unlock(t.io);
        if (samePeers(t.peers.items, peers) and t.device != null) return;
        if (comptime @hasDecl(Device, "setPeers")) if (t.device) |d| {
            var b: PeerConfigs = .{};
            defer b.deinit(t.gpa);
            try t.ownPeers(peers, &b);
            return d.setPeers(b.configs);
        };
        t.stopDeviceLocked();
        try t.setPeersLocked(peers);
    }

    fn samePeers(have: []const OwnedPeer, want: []const Peer) bool {
        if (have.len != want.len) return false;
        for (have, want) |*h, *w| {
            if (!std.mem.eql(u8, &h.peer.public_key, &w.public_key) or !std.mem.eql(u8, &h.peer.address, &w.address) or
                h.peer.persistent_keepalive != w.persistent_keepalive) return false;
            const he = h.peer.endpoint orelse "";
            if (!std.mem.eql(u8, he, w.endpoint orelse "")) return false;
        }
        return true;
    }

    /// zwg peer configs for `peers` (their slices point into `t.peers`
    /// and `b`).
    const PeerConfigs = struct {
        cidrs: []wg.device.ip.Cidr = &.{},
        configs: []wg.device.device.PeerConfig = &.{},

        fn deinit(b: *PeerConfigs, gpa: std.mem.Allocator) void {
            gpa.free(b.cidrs);
            gpa.free(b.configs);
        }
    };

    /// Copies `peers` into `t.peers` and builds their zwg configs.
    fn ownPeers(t: *Tunnel, peers: []const Peer, b: *PeerConfigs) StartError!void {
        t.peers.clearRetainingCapacity();
        try t.peers.ensureTotalCapacity(t.gpa, peers.len);
        b.cidrs = try t.gpa.alloc(wg.device.ip.Cidr, peers.len);
        b.configs = try t.gpa.alloc(wg.device.device.PeerConfig, peers.len);
        const cidrs = b.cidrs;
        const configs = b.configs;
        for (peers, 0..) |p, i| {
            t.peers.appendAssumeCapacity(.{ .peer = p });
            // The copy of the endpoint lives in the list's own element.
            const op = &t.peers.items[t.peers.items.len - 1];
            if (p.endpoint) |e| {
                if (e.len > op.endpoint_buf.len) return error.InvalidEndpoint;
                @memcpy(op.endpoint_buf[0..e.len], e);
                op.peer.endpoint = op.endpoint_buf[0..e.len];
            }
            cidrs[i] = .{ .addr = .{ .v4 = p.address }, .prefix = 32 };
        }
        for (t.peers.items, 0..) |*op, i| {
            // zwg's own path from a [Peer] to the device's peer config
            // (literal endpoints as they are, names looked up now and
            // again later while the peer is silent).
            const cp: wg.device.config.Peer = .{
                .public_key = op.peer.public_key,
                .allowed_ips = cidrs[i .. i + 1],
                .endpoint = if (op.peer.endpoint) |e| (wg.device.config.Endpoint.parse(e) catch return error.InvalidEndpoint) else null,
                .persistent_keepalive = op.peer.persistent_keepalive,
            };
            configs[i] = wg.device.device.PeerConfig.fromConfig(t.io, &cp).peer;
        }
    }

    /// Starts a device with `peers` (the mutex is held, or not yet shared).
    fn setPeersLocked(t: *Tunnel, peers: []const Peer) StartError!void {
        var b: PeerConfigs = .{};
        defer b.deinit(t.gpa);
        try t.ownPeers(peers, &b);
        var dopts: wg.device.device.Options = .{
            .private_key = t.private_key,
            .listen_port = t.udp_port,
            .loopback_only = t.loopback_only,
            .peers = b.configs,
        };
        defer std.crypto.secureZero(u8, &dopts.private_key);
        const d = try Device.create(t.gpa, &t.clock, t.stack.tun(), dopts);
        // The same port on every restart (the first start may have picked one).
        t.udp_port = d.listen_port;
        t.device = d;
        t.device_thread = std.Thread.spawn(.{}, runDevice, .{d}) catch {
            d.destroy();
            t.device = null;
            return error.ThreadSpawnFailed;
        };
    }

    fn runDevice(d: *Device) void {
        d.run() catch |err| std.log.err("tunnel: device stopped: {t}", .{err});
    }

    fn stopDevice(t: *Tunnel) void {
        t.mutex.lockUncancelable(t.io);
        defer t.mutex.unlock(t.io);
        t.stopDeviceLocked();
    }

    fn stopDeviceLocked(t: *Tunnel) void {
        const d = t.device orelse return;
        d.stop();
        if (t.device_thread) |th| th.join();
        t.device_thread = null;
        d.destroy(); // wipes its copy of the key
        t.device = null;
    }

    /// The UDP port the device listens on.
    pub fn udpPort(t: *Tunnel) u16 {
        t.mutex.lockUncancelable(t.io);
        defer t.mutex.unlock(t.io);
        return t.udp_port orelse 0;
    }


    // ---------------------------------------------------------- streams

    /// A listener on this side's tunnel address, `port`.
    pub fn listen(t: *Tunnel, port: u16) !transport.Listener {
        const l = try t.gpa.create(NsListener);
        errdefer t.gpa.destroy(l);
        l.* = .{ .t = t, .l = try t.stack.listen(port) };
        return .{ .ext = .{ .ptr = l, .vtable = &NsListener.vtable } };
    }

    /// Dials through the tunnel (the device side: 10.8.0.1:8420).
    pub fn dialer(t: *Tunnel) transport.Dialer {
        return .ext(.{ .ptr = t, .vtable = &dialer_vtable });
    }

    const dialer_vtable: transport.ExtDialer.VTable = .{ .dial = dial };

    fn nsPriority(p: transport.Priority) ns.Priority {
        return switch (p) {
            .interactive => .interactive,
            .bulk => .bulk,
        };
    }

    fn dial(ptr: *anyopaque, io: Io, addr: net.IpAddress, priority: transport.Priority) transport.DialError!transport.Stream {
        const t: *Tunnel = @ptrCast(@alignCast(ptr));
        const to: ns.Endpoint = .{ .addr = wg.device.ip.Addr.fromIpAddress(addr), .port = addr.getPort() };
        const s = t.stack.dialWith(to, nsPriority(priority)) catch |err| return switch (err) {
            error.TooManyConnections, error.NoPortsAvailable => error.SystemResources,
            error.AddressFamilyUnsupported => error.AddressFamilyUnsupported,
            error.Closed => error.NetworkDown,
        };
        // Wait (cancelably) until connected or refused.
        while (true) {
            const seen = t.readiness.begin(io);
            const st = s.status();
            switch (st.state) {
                .established, .close_wait => break,
                .syn_sent => {},
                else => {
                    s.abort();
                    return error.ConnectionRefused;
                },
            }
            t.readiness.wait(io, seen) catch {
                s.abort();
                return error.Canceled;
            };
        }
        return wrap(t, s) catch {
            s.abort();
            return error.SystemResources;
        };
    }

    fn wrap(t: *Tunnel, s: ns.Stream) !transport.Stream {
        const c = try t.gpa.create(NsStream);
        c.* = .{ .t = t, .s = s };
        const r = s.remote();
        const remote: net.IpAddress = switch (r.addr) {
            .v4 => |b| .{ .ip4 = .{ .bytes = b, .port = r.port } },
            .v6 => |b| .{ .ip6 = .{ .bytes = b, .port = r.port } },
        };
        return .{ .ext = .{ .ptr = c, .vtable = &NsStream.vtable, .remote = remote } };
    }

    const NsListener = struct {
        t: *Tunnel,
        l: ns.Listener,

        const vtable: transport.ExtListener.VTable = .{ .accept = accept, .close = close };

        fn accept(ptr: *anyopaque, io: Io) transport.AcceptError!transport.Stream {
            const self: *NsListener = @ptrCast(@alignCast(ptr));
            const t = self.t;
            while (true) {
                const seen = t.readiness.begin(io);
                if (self.l.accept()) |s| {
                    return wrap(t, s) catch {
                        s.abort();
                        return error.SystemResources;
                    };
                } else |err| switch (err) {
                    error.WouldBlock, error.Timeout => {},
                    error.Closed => return error.SocketNotListening,
                }
                try t.readiness.wait(io, seen);
            }
        }

        fn close(ptr: *anyopaque, io: Io) void {
            _ = io;
            const self: *NsListener = @ptrCast(@alignCast(ptr));
            self.l.close();
            self.t.gpa.destroy(self);
        }
    };

    const NsStream = struct {
        t: *Tunnel,
        s: ns.Stream,

        const vtable: transport.Ext.VTable = .{ .read = read, .write = write, .close = close, .set_priority = setPriority };

        fn read(ptr: *anyopaque, io: Io, dest: []u8) transport.ReadError!usize {
            const self: *NsStream = @ptrCast(@alignCast(ptr));
            while (true) {
                const seen = self.t.readiness.begin(io);
                if (self.s.read(dest)) |n| return n else |err| switch (err) {
                    error.WouldBlock, error.Timeout => {},
                    error.Closed => return error.SocketUnconnected,
                    error.ConnectionRefused, error.ConnectionReset => return error.ConnectionResetByPeer,
                    error.ConnectionTimedOut => return error.ConnectionTimedOut,
                }
                try self.t.readiness.wait(io, seen);
            }
        }

        fn write(ptr: *anyopaque, io: Io, data: []const u8) transport.WriteError!usize {
            const self: *NsStream = @ptrCast(@alignCast(ptr));
            while (true) {
                const seen = self.t.readiness.begin(io);
                if (self.s.write(data)) |n| return n else |err| switch (err) {
                    error.WouldBlock, error.Timeout => {},
                    error.Closed, error.BrokenPipe => return error.SocketUnconnected,
                    error.ConnectionRefused, error.ConnectionReset => return error.ConnectionResetByPeer,
                    error.ConnectionTimedOut => return error.NetworkUnreachable,
                }
                try self.t.readiness.wait(io, seen);
            }
        }

        fn close(ptr: *anyopaque, io: Io) void {
            _ = io;
            const self: *NsStream = @ptrCast(@alignCast(ptr));
            self.s.close();
            self.t.gpa.destroy(self);
        }

        fn setPriority(ptr: *anyopaque, p: transport.Priority) void {
            const self: *NsStream = @ptrCast(@alignCast(ptr));
            self.s.setPriority(nsPriority(p));
        }
    };
};

test {
    _ = keys;
}

test "without a working netstack the tunnel refuses to start (no stub is ever reached)" {
    if (ready) return error.SkipZigTest;
    var k: Key = @splat(1);
    try std.testing.expectError(error.NetstackNotReady, Tunnel.start(std.testing.allocator, std.testing.io, .{ .private_key = k, .address = tunnelnet.desk_ip }));
    std.crypto.secureZero(u8, &k);
}
