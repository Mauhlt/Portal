//! The tunnel extension's one seam: `TunnelBackend`, the WireGuard
//! implementation behind Portal's per-app tunnel.
//!
//! Primary (and today the only compiled-in) backend: `ZigBackend`, the
//! owner's pure-Zig WireGuard (../WireGuard, module "WireGuard": config
//! parser, device.Device event loop, tun.PacketFlowTun for the
//! NEPacketTunnelProvider packet flow). It is under security review and
//! live interop testing; if that gate fails, a fallback backend can be
//! compiled in instead WITHOUT touching the extension's provider code
//! (main.zig) or the app:
//!
//!   * implement the four calls below over the fallback library (for
//!     wireguard-go: WireGuardKit's C entry points `wgTurnOn(settings,
//!     tun_fd)` / `wgTurnOff(handle)`, with its own packet flow
//!     handling), in a sibling file `backend_<name>.zig`;
//!   * select it with a build option (`-Dios-tunnel-backend=<name>`) in
//!     `zig build ios`, linking the library only then.
//!
//! Nothing of wireguard-go/WireGuardKit is in the repository now.
//!
//! Contract: configure() parses the wg-quick text the app stored in the
//! VPN configuration and returns the network settings iOS must apply
//! (addresses, routes, MTU, the peer's address); start() brings the device
//! up; deliver() hands it one packet read from the packet flow; packets
//! for the flow come back through `Output`; stop() tears everything down.
//! The four calls come from different queues (the provider's, the packet
//! flow's): a backend serialises them itself; deliver() after (or
//! during) stop() drops the packet, never touches freed state, and a
//! start() after stop() does nothing until the next configure(). IPv4 only for now (Portal's tunnel
//! addresses are IPv4; IPv6 settings are a TODO in docs/ios-native.md).

const std = @import("std");
const wg = @import("WireGuard");

/// Where decrypted packets go (the provider writes them to the packet
/// flow). `family` is AF_INET (2) or AF_INET6 (30).
pub const Output = struct {
    ctx: ?*anyopaque,
    f: *const fn (ctx: ?*anyopaque, packet: []const u8, family: u8) void,
};

pub const max_addrs = 8;
pub const max_routes = 64;

pub const Cidr4 = struct { addr: [4]u8, prefix: u8 };

/// What NEPacketTunnelNetworkSettings needs.
pub const NetSettings = struct {
    /// The peer's (the desk's) endpoint address as text, e.g. "192.168.1.10".
    remote_buf: [64]u8 = undefined,
    remote_len: usize = 0,
    addrs: [max_addrs]Cidr4 = undefined,
    n_addrs: usize = 0,
    routes: [max_routes]Cidr4 = undefined,
    n_routes: usize = 0,
    mtu: u16 = 1420,

    pub fn remote(s: *const NetSettings) []const u8 {
        return s.remote_buf[0..s.remote_len];
    }
};

pub const TunnelBackend = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        configure: *const fn (ptr: *anyopaque, wg_quick: []const u8, out: *NetSettings) anyerror!void,
        start: *const fn (ptr: *anyopaque, output: Output) anyerror!void,
        deliver: *const fn (ptr: *anyopaque, packet: []const u8) void,
        stop: *const fn (ptr: *anyopaque) void,
    };

    pub fn configure(b: TunnelBackend, wg_quick: []const u8, out: *NetSettings) !void {
        return b.vtable.configure(b.ptr, wg_quick, out);
    }
    pub fn start(b: TunnelBackend, output: Output) !void {
        return b.vtable.start(b.ptr, output);
    }
    pub fn deliver(b: TunnelBackend, packet: []const u8) void {
        b.vtable.deliver(b.ptr, packet);
    }
    pub fn stop(b: TunnelBackend) void {
        b.vtable.stop(b.ptr);
    }
};

/// The owner's Zig WireGuard.
pub const ZigBackend = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    config: ?wg.device.config.Config = null,
    tun: ?wg.tun.PacketFlowTun = null,
    clock: wg.device.device.Clock,
    device: ?*wg.device.Device = null,
    thread: ?std.Thread = null,
    output: Output = undefined,
    /// Held by every call: deliver (packet flow queue) never runs during
    /// stop (provider queue), so it never sees a freed tun.
    mutex: std.Io.Mutex = .init,
    /// Set by stop, cleared by configure (the next startTunnel): a start
    /// that lost the race with stop does nothing.
    stopped: bool = false,

    pub fn init(gpa: std.mem.Allocator, io: std.Io) ZigBackend {
        return .{ .gpa = gpa, .io = io, .clock = .{ .io = io } };
    }

    pub fn backend(z: *ZigBackend) TunnelBackend {
        return .{ .ptr = z, .vtable = &vtable };
    }

    const vtable: TunnelBackend.VTable = .{ .configure = configure, .start = start, .deliver = deliver, .stop = stop };

    fn self(p: *anyopaque) *ZigBackend {
        return @ptrCast(@alignCast(p));
    }

    fn configure(p: *anyopaque, text: []const u8, out: *NetSettings) anyerror!void {
        const z = self(p);
        z.mutex.lockUncancelable(z.io);
        defer z.mutex.unlock(z.io);
        z.stopped = false;
        var diag: wg.device.config.Diagnostic = .{};
        if (z.config) |*c| c.deinit();
        z.config = null;
        const cfg = wg.device.config.parse(z.gpa, text, &diag) catch |err| {
            std.log.err("tunnel: bad configuration: {s}", .{diag.message()});
            return err;
        };
        z.config = cfg;
        try settingsFrom(&z.config.?, out);
    }

    fn start(p: *anyopaque, output: Output) anyerror!void {
        const z = self(p);
        z.mutex.lockUncancelable(z.io);
        defer z.mutex.unlock(z.io);
        if (z.stopped) return error.Stopped;
        if (z.device != null) return error.AlreadyStarted;
        const c = &(z.config orelse return error.NotConfigured);
        z.output = output;
        const mtu = c.interface.mtu orelse wg.tun.default_mtu;
        z.tun = try wg.tun.PacketFlowTun.init(z.gpa, .{ .mtu = mtu, .write_fn = writeOut, .write_ctx = z });
        errdefer z.teardown();
        const peers = try z.gpa.alloc(wg.device.device.PeerConfig, c.peers.len);
        defer z.gpa.free(peers);
        for (c.peers, peers) |*pc_in, *pc| pc.* = .{
            .public_key = pc_in.public_key,
            .preshared_key = pc_in.preshared_key,
            .allowed_ips = pc_in.allowed_ips,
            .persistent_keepalive = pc_in.persistent_keepalive,
            // Literal addresses only: the app writes the desk's IP.
            .endpoint = if (pc_in.endpoint) |e| e.literal() else null,
        };
        z.device = try wg.device.Device.create(z.gpa, &z.clock, z.tun.?.tun(), .{
            .private_key = c.interface.private_key,
            .listen_port = c.interface.listen_port,
            .peers = peers,
        });
        z.thread = try std.Thread.spawn(.{}, runDevice, .{z.device.?});
    }

    fn runDevice(d: *wg.device.Device) void {
        d.run() catch |err| std.log.err("tunnel: device stopped: {t}", .{err});
    }

    fn writeOut(ctx: ?*anyopaque, packet: [*]const u8, len: usize, family: u8) callconv(.c) void {
        const z: *ZigBackend = @ptrCast(@alignCast(ctx.?));
        z.output.f(z.output.ctx, packet[0..len], family);
    }

    fn deliver(p: *anyopaque, packet: []const u8) void {
        const z = self(p);
        z.mutex.lockUncancelable(z.io);
        defer z.mutex.unlock(z.io);
        if (z.tun) |*t| t.deliver(packet);
    }

    fn stop(p: *anyopaque) void {
        const z = self(p);
        z.mutex.lockUncancelable(z.io);
        defer z.mutex.unlock(z.io);
        z.stopped = true;
        z.teardown();
    }

    /// Under `mutex`. The device thread never takes it (it only writes
    /// packets out), so joining it here cannot deadlock.
    fn teardown(z: *ZigBackend) void {
        if (z.device) |d| d.stop();
        if (z.thread) |t| t.join();
        z.thread = null;
        if (z.device) |d| d.destroy();
        z.device = null;
        if (z.tun) |*t| t.deinit();
        z.tun = null;
        if (z.config) |*c| c.deinit();
        z.config = null;
    }
};

/// IPv4 interface addresses, the peers' IPv4 AllowedIPs as routes, the
/// first peer's literal endpoint as the remote address, the MTU.
pub fn settingsFrom(c: *const wg.device.config.Config, out: *NetSettings) !void {
    out.* = .{};
    out.mtu = c.interface.mtu orelse wg.tun.default_mtu;
    for (c.interface.addresses) |a| switch (a.addr) {
        .v4 => |b| if (out.n_addrs < max_addrs) {
            out.addrs[out.n_addrs] = .{ .addr = b, .prefix = a.prefix };
            out.n_addrs += 1;
        },
        .v6 => {},
    };
    for (c.peers) |p| {
        for (p.allowed_ips) |a| switch (a.addr) {
            .v4 => |b| if (out.n_routes < max_routes) {
                out.routes[out.n_routes] = .{ .addr = b, .prefix = a.prefix };
                out.n_routes += 1;
            },
            .v6 => {},
        };
        if (out.remote_len == 0) if (p.endpoint) |e| {
            const n = @min(e.host.len, out.remote_buf.len);
            @memcpy(out.remote_buf[0..n], e.host[0..n]);
            out.remote_len = n;
        };
    }
    if (out.n_addrs == 0) return error.NoIpv4Address;
    if (out.remote_len == 0) return error.NoEndpoint;
}

/// "255.255.255.0" for /24 (NEIPv4Settings wants masks).
pub fn mask(prefix: u8, buf: *[16]u8) []const u8 {
    const p: u6 = @intCast(@min(prefix, 32));
    const m: u32 = if (p == 0) 0 else ~@as(u32, 0) << @intCast(32 - @as(u7, p));
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ m >> 24, (m >> 16) & 0xff, (m >> 8) & 0xff, m & 0xff }) catch "255.255.255.255";
}

test {
    _ = @import("keyref.zig");
}

test "deliver before start and after stop drops the packet" {
    var z = ZigBackend.init(std.testing.allocator, std.testing.io);
    const b = z.backend();
    b.deliver(&.{ 0x45, 0x00 });
    b.stop();
    b.deliver(&.{ 0x45, 0x00 });
    b.stop(); // idempotent
    try std.testing.expect(z.tun == null and z.device == null);
    // A start that comes after the stop (lost the race) does nothing.
    try std.testing.expectError(error.Stopped, b.start(.{ .ctx = null, .f = undefined }));
}

test "settings from a wg-quick config, masks" {
    const text =
        \\[Interface]
        \\PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
        \\Address = 10.8.0.3/32
        \\
        \\[Peer]
        \\PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
        \\Endpoint = 192.168.1.10:51820
        \\AllowedIPs = 10.8.0.1/32
        \\
    ;
    var diag: wg.device.config.Diagnostic = .{};
    var c = try wg.device.config.parse(std.testing.allocator, text, &diag);
    defer c.deinit();
    var s: NetSettings = .{};
    try settingsFrom(&c, &s);
    try std.testing.expectEqualStrings("192.168.1.10", s.remote());
    try std.testing.expectEqual(@as(usize, 1), s.n_addrs);
    try std.testing.expectEqual([4]u8{ 10, 8, 0, 3 }, s.addrs[0].addr);
    try std.testing.expectEqual(@as(usize, 1), s.n_routes);
    var b: [16]u8 = undefined;
    try std.testing.expectEqualStrings("255.255.255.0", mask(24, &b));
    try std.testing.expectEqualStrings("255.255.255.255", mask(32, &b));
    try std.testing.expectEqualStrings("0.0.0.0", mask(0, &b));
}
