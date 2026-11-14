//! The desk's side of the in-process tunnel (client/src/tunnel): its
//! WireGuard key, its peer table and the pairing code it shows.
//!
//!  * Key: generated on first use, kept like Portal's other private keys
//!    (DPAPI, current user, purpose-bound: tls/dpapi.zig writeSealedFile)
//!    in %LOCALAPPDATA%\Portal\tunnel\desk.key; its public half in
//!    desk.pub (so the window can show it without decrypting). Decrypted
//!    only to start the tunnel, then wiped.
//!  * Peers: derived from the device store and nothing else (one source of
//!    truth): every paired device's key, allowed only its own 10.8.0.x/32.
//!  * UDP: the tunnel port (settings `tunnel_port`, default 51820) on all
//!    interfaces, or on 127.0.0.1 only for tests (`--tunnel-loopback`).
//!    Inbound UDP on that port needs one firewall rule the owner adds once
//!    (docs/wireguard.md); Portal never touches the firewall.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const dpapi = @import("tls/dpapi.zig");
const fsutil = @import("fsutil.zig");
const devices = @import("devices.zig");
const shared = @import("shared");
const tunnelnet = shared.tunnelnet;
const pairqr = shared.pairqr;
pub const tunnel = @import("client").tunnel;
const wgkeys = @import("WireGuard").device.keys;

pub const Key = wgkeys.Key;

const key_magic = "PORTAL-WIREGUARD-KEY-V1\n";
const key_purpose = "Portal desk WireGuard private key v1";

pub const KeyPair = tunnel.keys.KeyPair;

fn keyPath(paths: devices.Paths, buf: []u8, name: []const u8) ![]const u8 {
    return paths.join(buf, &.{ "tunnel", name });
}

/// The desk's public key, if it has one (never decrypts).
pub fn loadPublic(io: Io, paths: devices.Paths) !?Key {
    var pb: [1024]u8 = undefined;
    var buf: [128]u8 = undefined;
    const text = Io.Dir.cwd().readFile(io, try keyPath(paths, &pb, "desk.pub"), &buf) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    return wgkeys.decode(std.mem.trim(u8, text, " \r\n")) catch error.BadTunnelKey;
}

/// The desk's key pair, created on first use. Caller wipes it.
pub fn loadOrCreate(gpa: Allocator, io: Io, paths: devices.Paths) !KeyPair {
    var pb: [1024]u8 = undefined;
    if (try loadPublic(io, paths)) |public| {
        const plain = try dpapi.readSealedFile(gpa, io, try keyPath(paths, &pb, "desk.key"), key_magic, key_purpose);
        defer {
            std.crypto.secureZero(u8, plain);
            gpa.free(plain);
        }
        if (plain.len != wgkeys.key_len) return error.BadTunnelKey;
        var kp = KeyPair.fromPrivate(plain[0..wgkeys.key_len].*);
        // The public half on disk must be this key's (fail closed).
        if (!std.mem.eql(u8, &kp.public, &public)) {
            kp.wipe();
            return error.TunnelKeyMismatch;
        }
        return kp;
    }
    try Io.Dir.cwd().createDirPath(io, try paths.join(&pb, &.{"tunnel"}));
    var kp = KeyPair.generate(io);
    errdefer kp.wipe();
    // The key first, then its public half: a crash in between leaves no
    // public key, and the next start makes a new pair.
    try dpapi.writeSealedFile(gpa, io, try keyPath(paths, &pb, "desk.key"), key_magic, &kp.private, key_purpose);
    const text = kp.publicText() ++ "\n".*;
    try fsutil.writeAtomic(gpa, io, try keyPath(paths, &pb, "desk.pub"), &text);
    return kp;
}

/// The tunnel's peer table: every paired device, its key allowed only its
/// own address. `out` must hold devices.max_devices entries.
pub fn peersFrom(st: *const devices.Store, out: []tunnel.Peer) []tunnel.Peer {
    var n: usize = 0;
    for (st.devices) |slot| if (slot) |d| {
        out[n] = .{ .public_key = d.key, .address = d.ip };
        n += 1;
    };
    return out[0..n];
}

pub const Options = struct {
    udp_port: u16 = tunnelnet.default_udp_port,
    /// Tests: bind the UDP socket to 127.0.0.1 only.
    loopback_only: bool = false,
};

/// Starts the desk's tunnel with the paired devices as peers.
pub fn start(gpa: Allocator, io: Io, paths: devices.Paths, o: Options, st: *const devices.Store) !*tunnel.Tunnel {
    var kp = try loadOrCreate(gpa, io, paths);
    defer kp.wipe();
    var peers: [devices.max_devices]tunnel.Peer = undefined;
    return tunnel.Tunnel.start(gpa, io, .{
        .private_key = kp.private,
        .address = tunnelnet.desk_ip,
        .udp_port = o.udp_port,
        .loopback_only = o.loopback_only,
        .peers = peersFrom(st, &peers),
    });
}

/// The pairing code for device `d` (shared/pairqr.zig, version 2): what
/// the desk shows after approving it, as text and QR.
pub fn pairingCode(buf: []u8, desk_public: *const Key, endpoint: []const u8, ca_sha256: [32]u8, d: *const devices.Device) ![]const u8 {
    const key_text = wgkeys.encode(desk_public);
    var ib: [tunnelnet.max_ip_text]u8 = undefined;
    return pairqr.formatTunnel(buf, tunnelnet.desk_server, ca_sha256, .{ .endpoint = endpoint, .desk_key = &key_text, .device_ip = d.ipText(&ib) });
}

test "peers come from the device store only" {
    var st: devices.Store = .{};
    var k: Key = @splat(7);
    k[0] = 1;
    _ = try st.pair("laptop", k, @splat(9), @splat(1), 0);
    var out: [devices.max_devices]tunnel.Peer = undefined;
    const p = peersFrom(&st, &out);
    try std.testing.expectEqual(@as(usize, 1), p.len);
    try std.testing.expectEqual(tunnelnet.Ip4{ 10, 8, 0, 2 }, p[0].address);
    try std.testing.expectEqualSlices(u8, &k, &p[0].public_key);
    try std.testing.expect(p[0].endpoint == null);
}

test "pairing code carries the desk key, endpoint, CA and the device address" {
    var st: devices.Store = .{};
    var k: Key = @splat(7);
    k[0] = 1;
    const paired = try st.pair("laptop", k, @splat(9), @splat(1), 0);
    const desk: Key = @splat(3);
    var buf: [pairqr.max_len_tunnel]u8 = undefined;
    const t = try pairingCode(&buf, &desk, "home.example.org:51820", @splat(0xab), &paired.device);
    const p = try pairqr.parse(t);
    try std.testing.expectEqualStrings(tunnelnet.desk_server, p.server);
    try std.testing.expectEqualStrings("10.8.0.2", p.tunnel.?.device_ip);
    try std.testing.expectEqualSlices(u8, &desk, &(try wgkeys.decode(p.tunnel.?.desk_key)));
}

test "the desk key is sealed with DPAPI, survives a reload, and a swapped public half is refused" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db: [1024]u8 = undefined;
    const dir = db[0..try tmp.dir.realPath(io, &db)];
    const paths: devices.Paths = .{ .dir = dir };
    var a = try loadOrCreate(gpa, io, paths);
    defer a.wipe();
    var b = try loadOrCreate(gpa, io, paths);
    defer b.wipe();
    try std.testing.expectEqualSlices(u8, &a.private, &b.private);
    try std.testing.expectEqualSlices(u8, &a.public, &(try loadPublic(io, paths)).?);
    // The private key is not in the file in the clear.
    var pb: [1024]u8 = undefined;
    const sealed = try Io.Dir.cwd().readFileAlloc(io, try keyPath(paths, &pb, "desk.key"), gpa, .limited(64 * 1024));
    defer gpa.free(sealed);
    try std.testing.expect(std.mem.indexOf(u8, sealed, &a.private) == null);
    var other = KeyPair.generate(io);
    defer other.wipe();
    const text = other.publicText() ++ "\n".*;
    try fsutil.writeAtomic(gpa, io, try keyPath(paths, &pb, "desk.pub"), &text);
    try std.testing.expectError(error.TunnelKeyMismatch, loadOrCreate(gpa, io, paths));
}
