//! The phone's own WireGuard key pair, for the per-app tunnel (tunnel.zig).
//! Pure Zig (std X25519 and base64), no OS calls, so it is tested on every
//! host.
//!
//! The private key is generated on the phone and never leaves it; only the
//! public key goes to the desk, during pairing, over the already-trusted
//! (CA-pinned, desk-approved) HTTPS connection. The desk adds it as a
//! WireGuard peer only after the owner confirms at the desk (see
//! docs/ios-native.md, "Per-app tunnel").

const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const b64 = std.base64.standard.Encoder;

pub const key_b64_len = 44;

pub const KeyPair = struct {
    secret: [32]u8,
    public: [32]u8,

    pub fn generate(io: std.Io) KeyPair {
        const kp = X25519.KeyPair.generate(io);
        return .{ .secret = kp.secret_key, .public = kp.public_key };
    }

    pub fn fromSecret(secret: [32]u8) KeyPair {
        return .{ .secret = secret, .public = X25519.recoverPublicKey(secret) };
    }

    pub fn wipe(k: *KeyPair) void {
        std.crypto.secureZero(u8, &k.secret);
    }
};

/// WireGuard's text form of a key (base64, 44 chars).
pub fn encodeKey(key: [32]u8, out: *[key_b64_len]u8) []const u8 {
    return b64.encode(out, &key);
}

/// The tunnel's configuration in wg-quick format: this phone as the
/// interface (`address`, e.g. "10.8.0.3/32"), the desk as the one peer,
/// routing only the desk's tunnel address through it.
pub fn wgQuick(buf: []u8, k: KeyPair, address: []const u8, desk_public: [32]u8, endpoint: []const u8, desk_tunnel_ip: []const u8) ![]const u8 {
    var sk: [key_b64_len]u8 = undefined;
    var pk: [key_b64_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &sk);
    return std.fmt.bufPrint(buf,
        \\[Interface]
        \\PrivateKey = {s}
        \\Address = {s}
        \\
        \\[Peer]
        \\PublicKey = {s}
        \\Endpoint = {s}
        \\AllowedIPs = {s}/32
        \\PersistentKeepalive = 25
        \\
    , .{ encodeKey(k.secret, &sk), address, encodeKey(desk_public, &pk), endpoint, desk_tunnel_ip });
}

test "X25519 key pair, base64 form and wg-quick text" {
    // RFC 7748 section 6.1: Alice's keys.
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    var k = KeyPair.fromSecret(secret);
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    try std.testing.expectEqual(want, k.public);
    var b: [key_b64_len]u8 = undefined;
    try std.testing.expectEqualStrings("hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=", encodeKey(k.public, &b));
    var buf: [512]u8 = undefined;
    const t = try wgQuick(&buf, k, "10.8.0.3/32", want, "192.168.1.10:51820", "10.8.0.1");
    try std.testing.expect(std.mem.indexOf(u8, t, "AllowedIPs = 10.8.0.1/32") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "PublicKey = hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=") != null);
    k.wipe();
    try std.testing.expect(std.mem.allEqual(u8, &k.secret, 0));
}
