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
//!    A store change reaches the server and the tunnel in the order
//!    `Applier` keeps (an address is refused while an old key may still
//!    use it).
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
///
/// Under the device store's lock (devices.lockPath), so a Portal starting
/// and a `portalctl pair` cannot each make a pair. The key is written
/// first, then its public half: a crash in between leaves desk.key alone,
/// and the public half is derived from it next time (a new key would
/// lock out every paired device). A public half without its key is an
/// error, never a silent new key.
pub fn loadOrCreate(gpa: Allocator, io: Io, paths: devices.Paths) !KeyPair {
    var lb: [1024]u8 = undefined;
    const lock = fsutil.FileLock.acquire(io, try devices.lockPath(paths, &lb)) catch |err| return switch (err) {
        error.LockBusy => error.DeviceStoreBusy,
        else => err,
    };
    defer lock.release(io);
    var pb: [1024]u8 = undefined;
    const public = try loadPublic(io, paths);
    const plain = dpapi.readSealedFile(gpa, io, try keyPath(paths, &pb, "desk.key"), key_magic, key_purpose) catch |err| switch (err) {
        error.FileNotFound => {
            if (public != null) return error.TunnelKeyMissing;
            return create(gpa, io, paths);
        },
        else => return err,
    };
    defer {
        std.crypto.secureZero(u8, plain);
        gpa.free(plain);
    }
    if (plain.len != wgkeys.key_len) return error.BadTunnelKey;
    var kp = KeyPair.fromPrivate(plain[0..wgkeys.key_len].*);
    errdefer kp.wipe();
    if (public) |p| {
        // The public half on disk must be this key's (fail closed).
        if (!std.mem.eql(u8, &kp.public, &p)) return error.TunnelKeyMismatch;
    } else try writePublic(gpa, io, paths, &kp);
    return kp;
}

/// A new pair (the lock is held, neither file exists).
fn create(gpa: Allocator, io: Io, paths: devices.Paths) !KeyPair {
    var pb: [1024]u8 = undefined;
    try Io.Dir.cwd().createDirPath(io, try paths.join(&pb, &.{"tunnel"}));
    var kp = KeyPair.generate(io);
    errdefer kp.wipe();
    try dpapi.writeSealedFile(gpa, io, try keyPath(paths, &pb, "desk.key"), key_magic, &kp.private, key_purpose);
    try writePublic(gpa, io, paths, &kp);
    return kp;
}

fn writePublic(gpa: Allocator, io: Io, paths: devices.Paths, kp: *const KeyPair) !void {
    var pb: [1024]u8 = undefined;
    const text = kp.publicText() ++ "\n".*;
    try fsutil.writeAtomic(gpa, io, try keyPath(paths, &pb, "desk.pub"), &text);
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

/// How long the connections of a device that went (or whose address now
/// has another key) get to read their `logout` before the key leaves the
/// tunnel.
pub const logout_wait_ms = 3000;

/// Brings a new device store to the server (web.Server) and the tunnel
/// (tunnel.Tunnel), in an order that never lets an address name one record
/// at the server while another key may still use it in the tunnel (a
/// re-paired name keeps its address):
///   1. the server gets the new list with every address whose key in the
///      tunnel is not the store's refused: nothing more is admitted from
///      it, and its connections end with their `logout`;
///   2. they get `logout_wait_ms` to go;
///   3. the tunnel gets the new peer table;
///   4. only once it took it does the server get the full list.
/// If the tunnel refuses the table, those addresses stay refused and the
/// error is returned; `in_tunnel` is unchanged, so every later apply
/// refuses them again until a table goes through (fail closed).
/// Not thread-safe: the caller serializes applies.
pub const Applier = struct {
    /// The store the tunnel's peer table was last made from.
    in_tunnel: devices.Store = .{},

    pub fn apply(a: *Applier, srv: anytype, tun: anytype, st: *const devices.Store) !void {
        var buf: [devices.max_devices]tunnelnet.Ip4 = undefined;
        const refused = staleAddresses(&a.in_tunnel, st, &buf);
        srv.applyStore(st, refused);
        if (refused.len > 0) srv.awaitGone(refused, logout_wait_ms);
        var peers: [devices.max_devices]tunnel.Peer = undefined;
        try tun.setPeers(peersFrom(st, &peers));
        a.in_tunnel = st.*;
        if (refused.len > 0) srv.applyStore(st, &.{});
    }
};

/// The addresses whose key in `have` (the tunnel's) is not the one `want`
/// has there, or that `want` no longer has. `out` holds max_devices.
pub fn staleAddresses(have: *const devices.Store, want: *const devices.Store, out: []tunnelnet.Ip4) []tunnelnet.Ip4 {
    var n: usize = 0;
    for (have.devices) |slot| if (slot) |d| {
        const same = if (want.findIp(d.ip)) |i| std.mem.eql(u8, &want.devices[i].?.key, &d.key) else false;
        if (!same) {
            out[n] = d.ip;
            n += 1;
        }
    };
    return out[0..n];
}

/// TCP keepalive on the desk's stack: a device that vanished (sleep,
/// network gone) frees its connection slots after about this plus the
/// netstack's probes, not only at the next application timeout.
pub const keepalive_idle_ns: u64 = 30 * std.time.ns_per_s;

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
        .tcp_keepalive_idle_ns = keepalive_idle_ns,
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

test "a lost desk.pub is derived from desk.key, not replaced by a new pair" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db: [1024]u8 = undefined;
    const dir = db[0..try tmp.dir.realPath(io, &db)];
    const paths: devices.Paths = .{ .dir = dir };
    var a = try loadOrCreate(gpa, io, paths);
    defer a.wipe();
    var pb: [1024]u8 = undefined;
    try Io.Dir.cwd().deleteFile(io, try keyPath(paths, &pb, "desk.pub"));
    try std.testing.expect((try loadPublic(io, paths)) == null);
    var b = try loadOrCreate(gpa, io, paths);
    defer b.wipe();
    try std.testing.expectEqualSlices(u8, &a.private, &b.private);
    try std.testing.expectEqualSlices(u8, &a.public, &(try loadPublic(io, paths)).?);
    // A public half whose key is gone is an error, not a new key.
    try Io.Dir.cwd().deleteFile(io, try keyPath(paths, &pb, "desk.key"));
    try std.testing.expectError(error.TunnelKeyMissing, loadOrCreate(gpa, io, paths));
}

/// Records what the Applier does, in order.
const FakeDesk = struct {
    const Step = union(enum) {
        server: struct { n_peers: usize, refused: [devices.max_devices]tunnelnet.Ip4, n_refused: usize },
        await_gone: usize,
        set_peers: usize,
    };
    steps: [16]Step = undefined,
    n: usize = 0,
    fail_set_peers: bool = false,

    fn add(f: *FakeDesk, s: Step) void {
        f.steps[f.n] = s;
        f.n += 1;
    }
    pub fn applyStore(f: *FakeDesk, st: *const devices.Store, refused: []const tunnelnet.Ip4) void {
        var s: Step = .{ .server = .{ .n_peers = st.count(), .refused = undefined, .n_refused = refused.len } };
        @memcpy(s.server.refused[0..refused.len], refused);
        f.add(s);
    }
    pub fn awaitGone(f: *FakeDesk, ips: []const tunnelnet.Ip4, max_ms: i64) void {
        std.debug.assert(max_ms == logout_wait_ms);
        f.add(.{ .await_gone = ips.len });
    }
    pub fn setPeers(f: *FakeDesk, peers: []const tunnel.Peer) !void {
        f.add(.{ .set_peers = peers.len });
        if (f.fail_set_peers) return error.OutOfMemory;
    }
};

test "store apply: a re-paired address is refused until the tunnel dropped the old key" {
    var old: devices.Store = .{};
    var k1: Key = @splat(7);
    k1[0] = 1;
    var k2: Key = @splat(8);
    k2[0] = 1;
    const first = try old.pair("phone", k1, @splat(9), @splat(1), 0);
    var new = old;
    const second = try new.pair("phone", k2, @splat(9), @splat(2), 0);
    // The name keeps its address: only the key in the tunnel tells them apart.
    try std.testing.expectEqual(first.device.ip, second.device.ip);

    var a: Applier = .{ .in_tunnel = old };
    var f: FakeDesk = .{};
    try a.apply(&f, &f, &new);
    try std.testing.expectEqual(@as(usize, 4), f.n);
    const s0 = f.steps[0].server;
    try std.testing.expectEqual(@as(usize, 1), s0.n_refused);
    try std.testing.expectEqual(first.device.ip, s0.refused[0]);
    try std.testing.expectEqual(@as(usize, 1), f.steps[1].await_gone);
    try std.testing.expectEqual(@as(usize, 1), f.steps[2].set_peers);
    try std.testing.expectEqual(@as(usize, 0), f.steps[3].server.n_refused);

    // Nothing changed: no refusal, no wait.
    f = .{};
    try a.apply(&f, &f, &new);
    try std.testing.expectEqual(@as(usize, 2), f.n);
    try std.testing.expectEqual(@as(usize, 0), f.steps[0].server.n_refused);
    try std.testing.expectEqual(@as(usize, 1), f.steps[1].set_peers);
}

test "store apply: a failed peer table keeps the address refused, also on the next apply" {
    var old: devices.Store = .{};
    var k1: Key = @splat(7);
    k1[0] = 1;
    _ = try old.pair("phone", k1, @splat(9), @splat(1), 0);
    var gone = old;
    _ = gone.remove("phone");
    var a: Applier = .{ .in_tunnel = old };
    var f: FakeDesk = .{ .fail_set_peers = true };
    try std.testing.expectError(error.OutOfMemory, a.apply(&f, &f, &gone));
    // Refused, waited, the table refused: no full list was published.
    try std.testing.expectEqual(@as(usize, 3), f.n);
    try std.testing.expectEqual(@as(usize, 1), f.steps[0].server.n_refused);
    try std.testing.expect(f.steps[2] == .set_peers);
    // The same store again (a retry): still refused until it goes through.
    f = .{ .fail_set_peers = true };
    try std.testing.expectError(error.OutOfMemory, a.apply(&f, &f, &gone));
    try std.testing.expectEqual(@as(usize, 1), f.steps[0].server.n_refused);
    f = .{};
    try a.apply(&f, &f, &gone);
    try std.testing.expectEqual(@as(usize, 4), f.n);
    try std.testing.expectEqual(@as(usize, 0), f.steps[3].server.n_refused);
    // Now the tunnel has it: nothing is refused any more.
    f = .{};
    try a.apply(&f, &f, &gone);
    try std.testing.expectEqual(@as(usize, 0), f.steps[0].server.n_refused);
}
