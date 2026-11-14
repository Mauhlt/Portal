//! A paired test device inside the e2e process: its own WireGuard key, its
//! own in-process tunnel to the desk under test (the very code `portal
//! connect` runs: client.devicelink / client.tunnel, over UDP on
//! 127.0.0.1), and a forwarder on 127.0.0.1 that carries each TCP
//! connection the harness makes into that tunnel, to 10.8.0.1:8420. So the
//! harness' existing HTTP/WebSocket/TLS helpers (http.zig, ws.zig,
//! tlsnet.zig) talk to Portal exactly as a device does: through the
//! tunnel, from the device's tunnel address, over TLS. There is no other
//! way into Portal.
//!
//! Only loopback is ever bound (the forwarder's TCP port, the tunnel's UDP
//! socket).

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const client = @import("client");
const transport = @import("shared").transport;
const tunnelnet = @import("shared").tunnelnet;

pub const Link = struct {
    gpa: Allocator,
    io: Io,
    name: []const u8,
    tun: *client.tunnel.Tunnel,
    server: net.Server,
    /// The forwarder's port on 127.0.0.1.
    port: u16,
    code: client.devicelink.Code,
    key_text: [44]u8,
    accept_task: ?Io.Future(void) = null,
    stopped: bool = false,

    /// A new device key; `pairingCode` is what `portalctl pair` printed.
    pub fn start(gpa: Allocator, io: Io, name: []const u8, key: *client.tunnel.keys.KeyPair, code_text: []const u8) !*Link {
        const code = try client.devicelink.parse(code_text);
        const l = try gpa.create(Link);
        errdefer gpa.destroy(l);
        const tun = try client.devicelink.startTunnel(gpa, io, &code, key);
        errdefer tun.destroy();
        var addr: net.IpAddress = try .parseLiteral("127.0.0.1:0");
        const server = try addr.listen(io, .{});
        l.* = .{
            .gpa = gpa,
            .io = io,
            .name = try gpa.dupe(u8, name),
            .tun = tun,
            .server = server,
            .port = server.socket.address.getPort(),
            .code = code,
            .key_text = key.publicText(),
        };
        l.accept_task = try io.concurrent(acceptLoop, .{l});
        return l;
    }

    /// Stops forwarding and tears the tunnel down.
    pub fn stop(l: *Link) void {
        if (l.stopped) return;
        l.stopped = true;
        if (l.accept_task) |*t| t.cancel(l.io);
        l.accept_task = null;
        l.server.deinit(l.io);
        l.tun.destroy();
    }

    fn acceptLoop(l: *Link) void {
        while (true) {
            const s = l.server.accept(l.io) catch return;
            const t = std.Thread.spawn(.{}, forward, .{ l, s }) catch {
                s.close(l.io);
                continue;
            };
            t.detach();
        }
    }

    /// One harness connection: dial the desk through the tunnel and copy
    /// both ways until either side ends; then cancel the other copy (never
    /// close a socket something is blocked on) and close both.
    fn forward(l: *Link, local: net.Stream) void {
        const io = l.io;
        const a: transport.Stream = .{ .os = local };
        const desk = net.IpAddress{ .ip4 = .{ .bytes = tunnelnet.desk_ip, .port = tunnelnet.https_port } };
        const b = l.tun.dialer().dial(io, desk) catch {
            a.close(io);
            return;
        };
        var done: Io.Event = .unset;
        var up = io.concurrent(pump, .{ io, a, b, &done }) catch {
            a.close(io);
            b.close(io);
            return;
        };
        var down = io.concurrent(pump, .{ io, b, a, &done }) catch {
            up.cancel(io);
            a.close(io);
            b.close(io);
            return;
        };
        done.waitUncancelable(io);
        up.cancel(io);
        down.cancel(io);
        a.close(io);
        b.close(io);
    }

    fn pump(io: Io, from: transport.Stream, to: transport.Stream, done: *Io.Event) void {
        defer done.set(io);
        var buf: [16 * 1024]u8 = undefined;
        var wbuf: [256]u8 = undefined;
        var w = to.writer(io, &wbuf);
        while (true) {
            const n = from.read(io, &buf) catch return;
            if (n == 0) return;
            w.interface().writeAll(buf[0..n]) catch return;
            w.interface().flush() catch return;
        }
    }
};
