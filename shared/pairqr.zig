//! The pairing QR code's text: what the desk's "Pair a device" panel shows
//! and the iPhone app scans on first launch.
//!
//!     portal-pair 1 <IP:PORT> <SHA-256 of the Portal CA, 64 hex digits>
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
/// Longest text `format` writes (bracketed IPv6 with port, plus fixed parts).
pub const max_len = prefix.len + 1 + version.len + 1 + 47 + 1 + 64;

pub const Payload = struct {
    /// "IP:PORT" as written (the caller validates it).
    server: []const u8,
    /// 64 hex digits.
    ca_sha256: []const u8,
};

pub const Error = error{ NotPortal, UnsupportedVersion, Malformed };

/// The QR text for `server` ("IP:PORT") and the CA fingerprint as 32
/// bytes.
pub fn format(buf: []u8, server: []const u8, ca_sha256: [32]u8) ![]const u8 {
    const hex = std.fmt.bytesToHex(ca_sha256, .upper);
    return std.fmt.bufPrint(buf, prefix ++ " " ++ version ++ " {s} {s}", .{ server, &hex });
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
    if (!std.mem.eql(u8, it.next() orelse return error.Malformed, version)) return error.UnsupportedVersion;
    const server = it.next() orelse return error.Malformed;
    const fp = it.next() orelse return error.Malformed;
    if (it.next() != null) return error.Malformed;
    if (server.len > 47) return error.Malformed;
    if (fp.len != 64 or parseFingerprint(fp) == null) return error.Malformed;
    return .{ .server = server, .ca_sha256 = fp };
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
    try std.testing.expectError(error.UnsupportedVersion, parse("portal-pair 2 10.8.0.1:8420 00"));
    try std.testing.expectError(error.Malformed, parse("portal-pair 1 10.8.0.1:8420"));
    try std.testing.expectError(error.Malformed, parse("portal-pair 1 10.8.0.1:8420 XYZ"));
    try std.testing.expectError(error.Malformed, parse("portal-pair 1 a b c"));
}
