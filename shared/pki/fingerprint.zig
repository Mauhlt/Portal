//! SHA-256 fingerprints as people compare them: "AB:CD:..." (95
//! characters), the form the desk, `portal ca export`, `portal connect`
//! and the Portal sync release-key pins all print.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const text_len = 32 * 3 - 1;

/// SHA-256 of `bytes` (a DER certificate, a public key).
pub fn sha256(bytes: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(bytes, &out, .{});
    return out;
}

/// "AB:CD:..." form of a fingerprint.
pub fn format(fp: [32]u8, out: *[text_len]u8) []const u8 {
    const hex = "0123456789ABCDEF";
    for (fp, 0..) |b, i| {
        out[i * 3] = hex[b >> 4];
        out[i * 3 + 1] = hex[b & 0xf];
        if (i < 31) out[i * 3 + 2] = ':';
    }
    return out;
}

/// Accepts 64 hex digits, optionally separated by ':', '-' or spaces, any
/// case.
pub fn parse(text: []const u8) error{BadFingerprint}![32]u8 {
    var out: [32]u8 = undefined;
    var n: usize = 0;
    var hi: ?u4 = null;
    for (text) |ch| {
        if (ch == ':' or ch == ' ' or ch == '-') continue;
        const v: u4 = @intCast(std.fmt.charToDigit(ch, 16) catch return error.BadFingerprint);
        if (hi) |h| {
            if (n == 32) return error.BadFingerprint;
            out[n] = (@as(u8, h) << 4) | v;
            n += 1;
            hi = null;
        } else hi = v;
    }
    if (n != 32 or hi != null) return error.BadFingerprint;
    return out;
}

const testing = std.testing;

test "format and parse" {
    const fp = sha256("abc");
    var buf: [text_len]u8 = undefined;
    const text = format(fp, &buf);
    try testing.expectEqualStrings("BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD", text);
    try testing.expectEqual(fp, try parse(text));
    var lower: [text_len]u8 = undefined;
    try testing.expectEqual(fp, try parse(std.ascii.lowerString(&lower, text)));
    var bare: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&bare, "{x}", .{fp}) catch unreachable;
    try testing.expectEqual(fp, try parse(&bare));
    try testing.expectError(error.BadFingerprint, parse(bare[0..63]));
    try testing.expectError(error.BadFingerprint, parse(bare ++ "00"));
    try testing.expectError(error.BadFingerprint, parse("zz"));
    try testing.expectError(error.BadFingerprint, parse(""));
}
