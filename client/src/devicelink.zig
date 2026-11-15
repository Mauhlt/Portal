//! A device's link to its desktop: the pairing code the desk showed
//! (shared/pairqr.zig, version 2), kept on this device, and from it the
//! in-process tunnel (tunnel/root.zig) and the client's dialer and trust.
//! Shared by `portal connect` (connect.zig) and the headless
//! `portalctl sync-device` (src/sync_cli.zig).
//!
//! The code is public data (the desk's public key and where to reach it,
//! the CA's SHA-256, this device's tunnel address): it is kept next to the
//! pinned CA (net/pin.zig) as `tunnel.txt`. Its authenticity is the owner
//! carrying it from the desk's screen (QR or typing) and comparing the
//! desk key's check code on both screens; the device's own key never
//! leaves this machine (tunnel/keys.zig).

const std = @import("std");
const Io = std.Io;
const shared = @import("shared");
const pairqr = shared.pairqr;
const tunnelnet = shared.tunnelnet;
const wg = @import("WireGuard");
const tunnel = @import("tunnel/root.zig");
const pin_mod = @import("net/pin.zig");
const x509check = @import("net/x509check.zig");
const client_mod = @import("net/client.zig");

/// The desktop's address inside the tunnel: the same for every desk.
pub const server = tunnelnet.desk_server;

pub const Code = struct {
    text_buf: [pairqr.max_len_tunnel]u8 = undefined,
    text_len: usize = 0,
    desk_key: tunnel.Key,
    ca_sha256: [32]u8,
    device_ip: tunnelnet.Ip4,
    /// "host:port": where in text_buf (the struct is copied by value, so no
    /// slice into itself).
    endpoint_at: usize = 0,
    endpoint_len: usize = 0,

    pub fn endpoint(c: *const Code) []const u8 {
        return c.text_buf[c.endpoint_at..][0..c.endpoint_len];
    }

    pub fn text(c: *const Code) []const u8 {
        return c.text_buf[0..c.text_len];
    }

    /// The desk key's check code, for the owner to compare with the desk.
    pub fn deskCheck(c: *const Code) [tunnelnet.check_code_len]u8 {
        return tunnelnet.checkCode(&c.desk_key);
    }

    /// The endpoint is on this machine (tests): bind the UDP socket to
    /// loopback only.
    pub fn loopback(c: *const Code) bool {
        const e = wg.device.config.Endpoint.parse(c.endpoint()) catch return false;
        return std.mem.eql(u8, e.host, "127.0.0.1") or std.mem.eql(u8, e.host, "::1");
    }
};

pub const ParseError = error{ NotPortal, UnsupportedVersion, Malformed, NoTunnel, BadDeskKey, BadEndpoint, BadAddress, BadFingerprint, WrongServer };

/// Parses and checks a pairing code as typed, pasted or scanned. The
/// fixed start ("portal-pair 2 10.8.0.1:8420") may be left out when typing.
pub fn parse(input: []const u8) ParseError!Code {
    var c: Code = .{ .desk_key = undefined, .ca_sha256 = undefined, .device_ip = undefined };
    const t = std.mem.trim(u8, input, " \t\r\n");
    const full = if (std.mem.startsWith(u8, t, pairqr.prefix))
        std.fmt.bufPrint(&c.text_buf, "{s}", .{t})
    else
        std.fmt.bufPrint(&c.text_buf, pairqr.prefix ++ " " ++ pairqr.version_tunnel ++ " " ++ server ++ " {s}", .{t});
    c.text_len = (full catch return error.Malformed).len;
    const p = try pairqr.parse(c.text());
    const tn = p.tunnel orelse return error.NoTunnel;
    if (!std.mem.eql(u8, p.server, server)) return error.WrongServer;
    c.ca_sha256 = pairqr.parseFingerprint(p.ca_sha256) orelse return error.BadFingerprint;
    c.desk_key = wg.device.keys.decode(tn.desk_key) catch return error.BadDeskKey;
    _ = wg.device.config.Endpoint.parse(tn.endpoint) catch return error.BadEndpoint;
    c.endpoint_at = @intFromPtr(tn.endpoint.ptr) - @intFromPtr(&c.text_buf);
    c.endpoint_len = tn.endpoint.len;
    c.device_ip = tunnelnet.parseIp(tn.device_ip) orelse return error.BadAddress;
    if (!tunnelnet.isDeviceIp(c.device_ip)) return error.BadAddress;
    return c;
}

pub fn describe(err: ParseError) []const u8 {
    return switch (err) {
        error.NotPortal, error.Malformed => "That is not a Portal pairing code. Enter the code Pair a device shows at the desk.",
        error.UnsupportedVersion, error.NoTunnel => "That pairing code is for another Portal version: pair again at the desk.",
        error.BadDeskKey => "The desktop's key in the code is damaged: check it against the desk.",
        error.BadEndpoint => "The desktop's endpoint in the code is not HOST:PORT: set it in the desk's Settings and pair again.",
        error.BadAddress => "This device's tunnel address in the code is damaged.",
        error.BadFingerprint => "The certificate's SHA-256 in the code is damaged.",
        error.WrongServer => "That code is not for Portal's tunnel address.",
    };
}

fn path(buf: *[pin_mod.max_path]u8) ![]const u8 {
    var dir_buf: [pin_mod.max_path]u8 = undefined;
    const sdir = try pin_mod.serversDir(&dir_buf);
    return std.fmt.bufPrint(buf, "{s}" ++ std.fs.path.sep_str ++ "tunnel.txt", .{sdir}) catch error.PathTooLong;
}

/// The saved pairing code, if this device is paired.
pub fn load(io: Io) ?Code {
    var pb: [pin_mod.max_path]u8 = undefined;
    const p = path(&pb) catch return null;
    var buf: [pairqr.max_len_tunnel + 8]u8 = undefined;
    const data = Io.Dir.cwd().readFile(io, p, &buf) catch return null;
    return parse(data) catch null;
}

pub fn save(io: Io, c: *const Code) !void {
    var pb: [pin_mod.max_path]u8 = undefined;
    const p = try path(&pb);
    if (std.fs.path.dirname(p)) |d| try Io.Dir.cwd().createDirPath(io, d);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = c.text() });
}

pub fn delete(io: Io) !void {
    var pb: [pin_mod.max_path]u8 = undefined;
    const p = try path(&pb);
    Io.Dir.cwd().deleteFile(io, p) catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    };
}

/// Starts this device's tunnel for `c` with `key` (copied in; the caller
/// wipes its own copy): the desk as its only peer, allowed only 10.8.0.1,
/// a keepalive so NAT mappings stay open.
pub fn startTunnel(gpa: std.mem.Allocator, io: Io, c: *const Code, key: *const tunnel.keys.KeyPair) !*tunnel.Tunnel {
    return tunnel.Tunnel.start(gpa, io, .{
        .private_key = key.private,
        .address = c.device_ip,
        .loopback_only = c.loopback(),
        .peers = &.{.{
            .public_key = c.desk_key,
            .address = tunnelnet.desk_ip,
            .endpoint = c.endpoint(),
            .persistent_keepalive = tunnelnet.persistent_keepalive_s,
        }},
    });
}

/// The longest `wgQuick` text (the longest endpoint and the fixed parts).
pub const max_wg_quick = 640;

/// The same tunnel as `startTunnel`, as a wg-quick configuration for a
/// tunnel the OS runs (the iPhone's packet tunnel extension): this device
/// at its tunnel address, the desk as the one peer, allowed only
/// 10.8.0.1, with the keepalive. It holds the private key: the caller
/// wipes `buf` (the iPhone app moves the key to the Keychain first,
/// ios/tunnel_ext/keyref.zig).
pub fn wgQuick(c: *const Code, key: *const tunnel.keys.KeyPair, buf: []u8) error{NoSpaceLeft}![]const u8 {
    var private = wg.device.keys.encode(&key.private);
    defer std.crypto.secureZero(u8, &private);
    const desk = wg.device.keys.encode(&c.desk_key);
    var ib: [tunnelnet.max_ip_text]u8 = undefined;
    var db: [tunnelnet.max_ip_text]u8 = undefined;
    return std.fmt.bufPrint(buf,
        \\[Interface]
        \\PrivateKey = {s}
        \\Address = {s}/32
        \\
        \\[Peer]
        \\PublicKey = {s}
        \\Endpoint = {s}
        \\AllowedIPs = {s}/32
        \\PersistentKeepalive = {d}
        \\
    , .{ &private, tunnelnet.formatIp(c.device_ip, &ib), &desk, c.endpoint(), tunnelnet.formatIp(tunnelnet.desk_ip, &db), tunnelnet.persistent_keepalive_s });
}

/// How the client checks the desktop's certificate: the CA pinned for it,
/// or (first connection after pairing) the SHA-256 from the code. `buf`
/// holds the pinned DER.
pub fn trust(io: Io, c: *const Code, buf: *[x509check.max_cert_len]u8) client_mod.Trust {
    if (pin_mod.Pin.forHost(server)) |p| {
        if (p.load(io, buf) catch null) |der| {
            // A pin for another CA (an earlier pairing): the code wins.
            if (std.mem.eql(u8, &x509check.fingerprint(der), &c.ca_sha256)) return .{ .pinned = der };
        }
    } else |_| {}
    return .{ .fingerprint = c.ca_sha256 };
}

/// Saves the CA a first connection checked by its fingerprint
/// (Client.on_pinned).
pub fn savePin(ctx: *anyopaque, ca_der: []const u8) void {
    const io: *const Io = @ptrCast(@alignCast(ctx));
    const p = pin_mod.Pin.forHost(server) catch return;
    p.save(io.*, ca_der) catch |err| std.debug.print("portal connect: cannot save the pinned CA to {s}: {t}\n", .{ p.path(), err });
}

const testing = std.testing;

test "pairing codes: full, typed without the fixed start, and refused ones" {
    const key = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
    const fp = "00070E151C232A31383F464D545B626970777E858C939AA1A8AFB6BDC4CBD2D9";
    const c = try parse("portal-pair 2 10.8.0.1:8420 " ++ fp ++ " home.example.org:51820 " ++ key ++ " 10.8.0.2\r\n");
    try testing.expectEqual(tunnelnet.Ip4{ 10, 8, 0, 2 }, c.device_ip);
    try testing.expectEqualStrings("home.example.org:51820", c.endpoint());
    try testing.expect(!c.loopback());
    const short = try parse(fp ++ " 127.0.0.1:51999 " ++ key ++ " 10.8.0.3");
    try testing.expect(short.loopback());
    try testing.expectEqualSlices(u8, &c.desk_key, &short.desk_key);
    try testing.expectError(error.NoTunnel, parse("portal-pair 1 10.8.0.1:8420 " ++ fp));
    try testing.expectError(error.BadAddress, parse(fp ++ " h:1 " ++ key ++ " 10.8.0.1"));
    try testing.expectError(error.BadEndpoint, parse(fp ++ " h " ++ key ++ " 10.8.0.2"));
    try testing.expectError(error.WrongServer, parse("portal-pair 2 10.8.0.9:8420 " ++ fp ++ " h:1 " ++ key ++ " 10.8.0.2"));
    try testing.expectEqualSlices(u8, &tunnelnet.checkCode(&c.desk_key), &c.deskCheck());
}

test "wg-quick text for an OS-run tunnel: parses back to the in-process tunnel's settings" {
    const desk = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
    const fp = "00070E151C232A31383F464D545B626970777E858C939AA1A8AFB6BDC4CBD2D9";
    const c = try parse(fp ++ " home.example.org:51820 " ++ desk ++ " 10.8.0.3");
    var priv: tunnel.Key = undefined;
    _ = try std.fmt.hexToBytes(&priv, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const kp = tunnel.keys.KeyPair.fromPrivate(priv);
    var buf: [max_wg_quick]u8 = undefined;
    const text = try wgQuick(&c, &kp, &buf);
    var diag: wg.device.config.Diagnostic = .{};
    var cfg = try wg.device.config.parse(testing.allocator, text, &diag);
    defer cfg.deinit();
    try testing.expectEqualSlices(u8, &priv, &cfg.interface.private_key);
    try testing.expectEqual(@as(usize, 1), cfg.interface.addresses.len);
    try testing.expectEqual(@as(u8, 32), cfg.interface.addresses[0].prefix);
    try testing.expectEqual(@as(usize, 1), cfg.peers.len);
    const p = cfg.peers[0];
    try testing.expectEqualSlices(u8, &c.desk_key, &p.public_key);
    try testing.expectEqualStrings("home.example.org", p.endpoint.?.host);
    try testing.expectEqual(@as(u16, 51820), p.endpoint.?.port);
    try testing.expectEqual(tunnelnet.persistent_keepalive_s, p.persistent_keepalive);
    try testing.expectEqual(@as(usize, 1), p.allowed_ips.len);
    try testing.expect(std.mem.indexOf(u8, text, "Address = 10.8.0.3/32\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "AllowedIPs = 10.8.0.1/32\n") != null);
    // The longest endpoint a pairing code carries still fits.
    try testing.expect(max_wg_quick >= text.len - c.endpoint().len + pairqr.max_endpoint);
    var small: [16]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, wgQuick(&c, &kp, &small));
}
