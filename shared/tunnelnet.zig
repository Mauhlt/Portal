//! The in-process tunnel's addressing and ports: the ONE place they are
//! defined. The desk, `portal connect`, the settings, the pairing QR code,
//! the device store and the tests all use these.
//!
//!   10.8.0.0/24     the tunnel network
//!   10.8.0.1        the desk (hub); Portal listens on 8420 (HTTPS/WSS)
//!                   and, while a pairing window is open, 8421 (the plain
//!                   HTTP certificate download), both inside the tunnel only
//!   10.8.0.2..254   devices, one /32 each, assigned at pairing (lowest
//!                   free first: the owner's laptop .2, iPhone .3, Surface .4
//!                   when paired in that order)
//!   UDP 51820       the desk's WireGuard port (configurable)
//!   keepalive 25 s  devices keep NAT mappings open toward the desk

const std = @import("std");

pub const Ip4 = [4]u8;

pub const network: Ip4 = .{ 10, 8, 0, 0 };
pub const prefix_len: u8 = 24;
pub const desk_ip: Ip4 = .{ 10, 8, 0, 1 };
pub const first_device: u8 = 2;
pub const last_device: u8 = 254;

pub const https_port: u16 = 8420;
/// The pairing-time certificate download: always the HTTPS port + 1.
pub const ca_port: u16 = https_port + 1;
pub const default_udp_port: u16 = 51820;
pub const persistent_keepalive_s: u16 = 25;

/// "10.8.0.1:8420": what devices dial through the tunnel and the desk's
/// Host allowlist and certificate name.
pub const desk_server = "10.8.0.1:8420";

pub fn deviceIp(host: u8) Ip4 {
    return .{ network[0], network[1], network[2], host };
}

/// A device address inside the tunnel network (not the desk's, not the
/// network or broadcast address).
pub fn isDeviceIp(ip: Ip4) bool {
    return std.mem.eql(u8, ip[0..3], network[0..3]) and ip[3] >= first_device and ip[3] <= last_device;
}

/// Strict dotted quad ("10.8.0.2"); null for anything else.
pub fn parseIp(text: []const u8) ?Ip4 {
    var out: Ip4 = undefined;
    var it = std.mem.splitScalar(u8, text, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i == 4 or part.len == 0 or part.len > 3) return null;
        for (part) |c| if (c < '0' or c > '9') return null;
        if (part.len > 1 and part[0] == '0') return null;
        out[i] = std.fmt.parseInt(u8, part, 10) catch return null;
    }
    return if (i == 4) out else null;
}

pub const max_ip_text = 15;

pub fn formatIp(ip: Ip4, buf: *[max_ip_text]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch unreachable;
}

/// The address for a new device: `prefer` if it is a free device address
/// (a re-pair keeps its address), else the lowest free one; null when all
/// are taken. `used` are the addresses of the other paired devices.
pub fn assign(used: []const Ip4, prefer: ?Ip4) ?Ip4 {
    const taken = struct {
        fn f(u: []const Ip4, ip: Ip4) bool {
            for (u) |x| if (std.mem.eql(u8, &x, &ip)) return true;
            return false;
        }
    }.f;
    if (prefer) |p| if (isDeviceIp(p) and !taken(used, p)) return p;
    var h: u16 = first_device;
    while (h <= last_device) : (h += 1) {
        const ip = deviceIp(@intCast(h));
        if (!taken(used, ip)) return ip;
    }
    return null;
}

/// "ABCDE-FGHJK": the check code of a WireGuard public key, shown next to
/// the key wherever the owner carries it between machines (the device's
/// key typed at the desk; the desk's key in the pairing code entered on the
/// device) and compared on both screens before approving. 50 bits of
/// SHA-256 over the key (domain-separated), in Crockford base32 (no I, L,
/// O, U): grinding a different key with the same code takes about 2^50
/// tries, so a key swapped in transit (a chat, an email, a synced
/// clipboard) is caught by the comparison.
pub const check_code_len = 11;

pub fn checkCode(public_key: *const [32]u8) [check_code_len]u8 {
    const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    var h: [32]u8 = undefined;
    var s = std.crypto.hash.sha2.Sha256.init(.{});
    s.update("portal-wireguard-check-code-v1:");
    s.update(public_key);
    s.final(&h);
    const bits = std.mem.readInt(u64, h[0..8], .big) >> 14; // the top 50 bits
    var out: [check_code_len]u8 = undefined;
    var j: usize = 0;
    for (0..10) |i| {
        if (i == 5) {
            out[j] = '-';
            j += 1;
        }
        const shift: u6 = @intCast(45 - 5 * i);
        out[j] = alphabet[@intCast((bits >> shift) & 31)];
        j += 1;
    }
    return out;
}

const testing = std.testing;

test "check codes: 50 bits, grouped, stable, key-dependent" {
    const a: [32]u8 = @splat(0);
    var b: [32]u8 = @splat(0);
    b[31] = 1;
    const ca = checkCode(&a);
    try testing.expectEqual(@as(u8, '-'), ca[5]);
    for (ca, 0..) |c, i| if (i != 5) try testing.expect(std.mem.indexOfScalar(u8, "0123456789ABCDEFGHJKMNPQRSTVWXYZ", c) != null);
    try testing.expectEqualSlices(u8, &ca, &checkCode(&a));
    try testing.expect(!std.mem.eql(u8, &ca, &checkCode(&b)));
}

test "addresses and ports are defined once and agree" {
    var b: [max_ip_text]u8 = undefined;
    try testing.expectEqualStrings("10.8.0.1", formatIp(desk_ip, &b));
    var sb: [32]u8 = undefined;
    try testing.expectEqualStrings(desk_server, try std.fmt.bufPrint(&sb, "{s}:{d}", .{ formatIp(desk_ip, &b), https_port }));
    try testing.expectEqual(@as(u16, 8421), ca_port);
    try testing.expect(!isDeviceIp(desk_ip));
    try testing.expect(isDeviceIp(.{ 10, 8, 0, 2 }));
    try testing.expect(!isDeviceIp(.{ 10, 8, 0, 255 }));
    try testing.expect(!isDeviceIp(.{ 10, 8, 1, 2 }));
}

test "parseIp is strict" {
    try testing.expectEqual(@as(?Ip4, .{ 10, 8, 0, 2 }), parseIp("10.8.0.2"));
    for ([_][]const u8{ "", "10.8.0", "10.8.0.2.1", "10.8.0.256", "10.08.0.2", "10.8.0.x", " 10.8.0.2", "10..0.2" }) |t|
        try testing.expectEqual(@as(?Ip4, null), parseIp(t));
}

test "assign: lowest free, a re-pair keeps its address, full is null" {
    try testing.expectEqual(@as(?Ip4, .{ 10, 8, 0, 2 }), assign(&.{}, null));
    try testing.expectEqual(@as(?Ip4, .{ 10, 8, 0, 4 }), assign(&.{ .{ 10, 8, 0, 2 }, .{ 10, 8, 0, 3 } }, null));
    try testing.expectEqual(@as(?Ip4, .{ 10, 8, 0, 3 }), assign(&.{ .{ 10, 8, 0, 2 }, .{ 10, 8, 0, 4 } }, null));
    try testing.expectEqual(@as(?Ip4, .{ 10, 8, 0, 9 }), assign(&.{.{ 10, 8, 0, 2 }}, .{ 10, 8, 0, 9 }));
    // A preferred address that is taken, or not a device address: lowest free.
    try testing.expectEqual(@as(?Ip4, .{ 10, 8, 0, 3 }), assign(&.{.{ 10, 8, 0, 2 }}, .{ 10, 8, 0, 2 }));
    try testing.expectEqual(@as(?Ip4, .{ 10, 8, 0, 2 }), assign(&.{}, desk_ip));
    var all: [253]Ip4 = undefined;
    for (&all, 0..) |*a, i| a.* = deviceIp(@intCast(i + 2));
    try testing.expectEqual(@as(?Ip4, null), assign(&all, null));
}
