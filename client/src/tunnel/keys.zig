//! A device's WireGuard key pair (`portal connect` on Windows, Linux and
//! macOS). The private key is generated here, never leaves this machine,
//! and is kept only in the OS credential store (credstore.zig: Windows
//! Credential Manager, the macOS Keychain, on Linux a 0600 file in a 0700
//! directory checked on every load). In memory it lives in a `KeyPair`
//! that the caller wipes; the text form goes through zwg's constant-time
//! key codec (WireGuard.device.keys), the same one `wg` and zwg use.
//!
//! One key per device (not per desktop): it is the device's identity at
//! every desk it pairs with; "Forget this desktop" leaves it.

const std = @import("std");
const wg = @import("WireGuard");
const credstore = @import("../credstore.zig");
const tunnelnet = @import("shared").tunnelnet;

const codec = wg.device.keys;
pub const Key = codec.Key;
pub const text_len = codec.base64_len;

/// The credential store entry.
pub const store_target = "Portal-tunnel/device-key";

pub const KeyPair = struct {
    private: Key,
    public: Key,

    pub fn generate(io: std.Io) KeyPair {
        var k = codec.generatePrivate(io);
        defer std.crypto.secureZero(u8, &k);
        return fromPrivate(k);
    }

    pub fn fromPrivate(private: Key) KeyPair {
        return .{ .private = private, .public = codec.publicFromPrivate(&private) };
    }

    pub fn wipe(k: *KeyPair) void {
        std.crypto.secureZero(u8, &k.private);
    }

    /// The public key as WireGuard writes it (44 base64 characters).
    pub fn publicText(k: *const KeyPair) [text_len]u8 {
        return codec.encode(&k.public);
    }

    /// The check code the desk shows for this key ("ABCDE-FGHJK").
    pub fn checkCode(k: *const KeyPair) [tunnelnet.check_code_len]u8 {
        return tunnelnet.checkCode(&k.public);
    }
};

/// This device's key pair: the stored one, or a new one stored now.
/// Caller wipes it.
pub fn loadOrCreate(io: std.Io) (credstore.Error || error{BadStoredKey})!KeyPair {
    var buf: [credstore.max_secret]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    if (try credstore.load(store_target, &buf)) |text| {
        var k = codec.decode(text) catch return error.BadStoredKey;
        defer std.crypto.secureZero(u8, &k);
        if (codec.isZero(&k)) return error.BadStoredKey;
        return KeyPair.fromPrivate(k);
    }
    var kp = KeyPair.generate(io);
    errdefer kp.wipe();
    var text = codec.encode(&kp.private);
    defer std.crypto.secureZero(u8, &text);
    try credstore.save(store_target, &text);
    return kp;
}

/// Parses a public key someone typed or pasted (spaces and line breaks
/// around it are ignored).
pub fn parsePublic(text: []const u8) ?Key {
    return codec.decode(std.mem.trim(u8, text, " \t\r\n")) catch null;
}

test "key pair, text form and check code" {
    var priv: Key = undefined;
    _ = try std.fmt.hexToBytes(&priv, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    var k = KeyPair.fromPrivate(priv);
    try std.testing.expectEqualStrings("hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=", &k.publicText());
    try std.testing.expectEqualSlices(u8, &k.public, &parsePublic(" hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=\r\n").?);
    try std.testing.expect(parsePublic("hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo") == null);
    try std.testing.expectEqualSlices(u8, &tunnelnet.checkCode(&k.public), &k.checkCode());
    k.wipe();
    try std.testing.expect(std.mem.allEqual(u8, &k.private, 0));
}
