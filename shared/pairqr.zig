//! The pairing QR code's text: what the desk's "Pair a device" panel shows
//! and the iPhone app scans on first launch.
//!
//!     portal-pair 1 <IP:PORT> <SHA-256 of the Portal CA, 64 hex digits>
//!
//! With the in-process tunnel (version 2) it also carries what the device
//! needs to bring the tunnel up, all public:
//!
//!     portal-pair 2 <IP:PORT> <CA SHA-256> <ENDPOINT> <DESK KEY> <DEVICE IP>
//!
//! ENDPOINT is where the desk's WireGuard listens as the device reaches it
//! (a public IP or DNS name, ":51820"), DESK KEY the desk's WireGuard
//! public key (44 base64 characters), DEVICE IP the tunnel address the desk
//! assigned to this device (10.8.0.x). Authenticity comes from the owner
//! carrying it from the desk's screen to the device (QR or typing), as for
//! the CA fingerprint; the desk only lets the device's own key in (typed at
//! the desk), and the request code is still approved at the desk.
//!
//! Example: `portal-pair 1 10.8.0.1:8420 3A5F...`. Both values are public:
//! the address is the desk's listen address and the fingerprint is that of
//! the CA certificate the desk shows anyway. The QR grants nothing by
//! itself: the app downloads the CA from the pairing-time page, keeps it
//! only if its SHA-256 matches, pins it, then asks to pair, and the owner
//! still approves the request code at the desk. No nonce is needed for
//! that reason (the request code is already the per-request check).

const std = @import("std");

pub const prefix = "portal-pair";
pub const version = "1";
pub const version_tunnel = "2";
/// Longest endpoint text ("host:port", a DNS name up to 253 + ":65535").
pub const max_endpoint = 259;
pub const key_len = 44;
/// Longest text `format` writes (bracketed IPv6 with port, plus fixed parts).
pub const max_len = prefix.len + 1 + version.len + 1 + 47 + 1 + 64;
/// Longest text `formatTunnel` writes.
pub const max_len_tunnel = max_len + 1 + max_endpoint + 1 + key_len + 1 + 15;

pub const Payload = struct {
    /// "IP:PORT" as written (the caller validates it).
    server: []const u8,
    /// 64 hex digits.
    ca_sha256: []const u8,
    /// Version 2 only: the in-process tunnel (each value is checked by the
    /// caller: the endpoint and key with WireGuard's own parsers).
    tunnel: ?Tunnel = null,
};

pub const Tunnel = struct {
    endpoint: []const u8,
    desk_key: []const u8,
    device_ip: []const u8,
};

pub const Error = error{ NotPortal, UnsupportedVersion, Malformed };

/// The QR text for `server` ("IP:PORT") and the CA fingerprint as 32
/// bytes.
pub fn format(buf: []u8, server: []const u8, ca_sha256: [32]u8) ![]const u8 {
    const hex = std.fmt.bytesToHex(ca_sha256, .upper);
    return std.fmt.bufPrint(buf, prefix ++ " " ++ version ++ " {s} {s}", .{ server, &hex });
}

/// Version 2: `format` plus the tunnel.
pub fn formatTunnel(buf: []u8, server: []const u8, ca_sha256: [32]u8, t: Tunnel) ![]const u8 {
    const hex = std.fmt.bytesToHex(ca_sha256, .upper);
    return std.fmt.bufPrint(buf, prefix ++ " " ++ version_tunnel ++ " {s} {s} {s} {s} {s}", .{ server, &hex, t.endpoint, t.desk_key, t.device_ip });
}

/// The fingerprint as "AB:CD:..." (95 chars) or plain hex (64) -> 32 bytes.
pub fn parseFingerprint(text: []const u8) ?[32]u8 {
    var hex: [64]u8 = undefined;
    var n: usize = 0;
    for (text) |c| {
        if (c == ':' or c == ' ') continue;
        if (n == hex.len) return null;
        hex[n] = c;
        n += 1;
    }
    if (n != 64) return null;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, &hex) catch return null;
    return out;
}

/// Splits a scanned text. Never trusts it: the caller checks the address
/// and verifies the downloaded CA against the fingerprint.
pub fn parse(text: []const u8) Error!Payload {
    const t = std.mem.trim(u8, text, " \r\n\t");
    var it = std.mem.tokenizeScalar(u8, t, ' ');
    if (!std.mem.eql(u8, it.next() orelse return error.NotPortal, prefix)) return error.NotPortal;
    const v = it.next() orelse return error.Malformed;
    const tunnel = std.mem.eql(u8, v, version_tunnel);
    if (!tunnel and !std.mem.eql(u8, v, version)) return error.UnsupportedVersion;
    const server = it.next() orelse return error.Malformed;
    const fp = it.next() orelse return error.Malformed;
    var p: Payload = .{ .server = server, .ca_sha256 = fp };
    if (tunnel) {
        const tu: Tunnel = .{
            .endpoint = it.next() orelse return error.Malformed,
            .desk_key = it.next() orelse return error.Malformed,
            .device_ip = it.next() orelse return error.Malformed,
        };
        if (tu.endpoint.len > max_endpoint or tu.desk_key.len != key_len or tu.device_ip.len > 15) return error.Malformed;
        p.tunnel = tu;
    }
    if (it.next() != null) return error.Malformed;
    if (server.len > 47) return error.Malformed;
    if (fp.len != 64 or parseFingerprint(fp) == null) return error.Malformed;
    return p;
}

test "pairing QR text with the tunnel (version 2)" {
    var fp: [32]u8 = undefined;
    for (&fp, 0..) |*b, i| b.* = @intCast(i * 7);
    var buf: [max_len_tunnel]u8 = undefined;
    const key = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
    const t = try formatTunnel(&buf, "10.8.0.1:8420", fp, .{ .endpoint = "home.example.org:51820", .desk_key = key, .device_ip = "10.8.0.2" });
    const p = try parse(t);
    try std.testing.expectEqualStrings("10.8.0.1:8420", p.server);
    try std.testing.expectEqualStrings("home.example.org:51820", p.tunnel.?.endpoint);
    try std.testing.expectEqualStrings(key, p.tunnel.?.desk_key);
    try std.testing.expectEqualStrings("10.8.0.2", p.tunnel.?.device_ip);
    var long_host: [253]u8 = @splat('a');
    var eb: [max_endpoint]u8 = undefined;
    const ep = try std.fmt.bufPrint(&eb, "{s}:65535", .{&long_host});
    try std.testing.expect((try formatTunnel(&buf, "[fd00:1234:5678:9abc:def0:1234:5678:9abc]:65535", fp, .{ .endpoint = ep, .desk_key = key, .device_ip = "10.8.0.254" })).len <= max_len_tunnel);
    // A version 1 code has no tunnel; a version 2 one must have all of it.
    try std.testing.expect((try parse("portal-pair 1 10.8.0.1:8420 " ++ "0000000000000000000000000000000000000000000000000000000000000000")).tunnel == null);
    try std.testing.expectError(error.Malformed, parse("portal-pair 2 10.8.0.1:8420 " ++ "0000000000000000000000000000000000000000000000000000000000000000" ++ " h:1 " ++ key));
    try std.testing.expectError(error.Malformed, parse("portal-pair 2 10.8.0.1:8420 " ++ "0000000000000000000000000000000000000000000000000000000000000000" ++ " h:1 short 10.8.0.2"));
}

test "pairing QR text round trip and rejects" {
    var fp: [32]u8 = undefined;
    for (&fp, 0..) |*b, i| b.* = @intCast(i * 7);
    var buf: [max_len]u8 = undefined;
    const t = try format(&buf, "10.8.0.1:8420", fp);
    try std.testing.expect(std.mem.startsWith(u8, t, "portal-pair 1 10.8.0.1:8420 00070E15"));
    const p = try parse(t);
    try std.testing.expectEqualStrings("10.8.0.1:8420", p.server);
    try std.testing.expectEqual(fp, parseFingerprint(p.ca_sha256).?);
    try std.testing.expectEqual(fp, parseFingerprint("00:07:0E:15:1C:23:2A:31:38:3F:46:4D:54:5B:62:69:70:77:7E:85:8C:93:9A:A1:A8:AF:B6:BD:C4:CB:D2:D9").?);
    const long = try format(&buf, "[fd00:1234:5678:9abc:def0:1234:5678:9abc]:65535", fp);
    try std.testing.expect(long.len <= max_len);
    try std.testing.expectError(error.NotPortal, parse("https://example.com"));
    try std.testing.expectError(error.UnsupportedVersion, parse("portal-pair 3 10.8.0.1:8420 00"));
    try std.testing.expectError(error.Malformed, parse("portal-pair 1 10.8.0.1:8420"));
    try std.testing.expectError(error.Malformed, parse("portal-pair 1 10.8.0.1:8420 XYZ"));
    try std.testing.expectError(error.Malformed, parse("portal-pair 1 a b c"));
}
