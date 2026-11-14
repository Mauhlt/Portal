//! How the app hands the tunnel's configuration to the packet tunnel
//! extension without putting the phone's WireGuard private key in the VPN
//! configuration (NETunnelProviderProtocol.providerConfiguration lives in
//! the system's VPN preferences, which can reach backups and diagnostics).
//!
//!   app        split(): the wg-quick text without its PrivateKey line goes
//!              to providerConfiguration[config_key], the key itself to the
//!              Keychain (credstore.saveUnattended, item `keychain_target`:
//!              this device only, no Face ID, in the Keychain group the app
//!              and the extension share), and the item's name to
//!              providerConfiguration[key_ref_key]
//!   extension  reads the item named there (only `keychain_target` is
//!              accepted) and join()s the key back in before parsing
//!
//! Imported by the app (client/src/ios/tunnel.zig) and the extension
//! (main.zig): one definition of the names and the format.

const std = @import("std");

/// The Keychain item holding the phone's tunnel private key (base64).
pub const keychain_target = "Portal-tunnel/packet-tunnel-key";
/// providerConfiguration keys.
pub const config_key = "wgQuickConfig";
pub const key_ref_key = "privateKeyRef";

pub const max_config = 4096;
/// The base64 text of a WireGuard key.
pub const key_text_len = 44;

pub const Error = error{ TooLong, NoPrivateKey, Unsupported };

pub const Split = struct {
    /// The PrivateKey value (a slice of the input).
    key: []const u8,
    /// The configuration without the PrivateKey line (in the caller's buffer).
    public: []const u8,
};

fn keyName(line: []const u8) []const u8 {
    const eq = std.mem.indexOfScalar(u8, line, '=') orelse return "";
    return std.mem.trim(u8, line[0..eq], " \t");
}

/// Takes the one PrivateKey line out of `text` (in [Interface], the first
/// section). A PresharedKey (also secret) is refused: Portal's
/// configuration has none.
pub fn split(text: []const u8, out: []u8) Error!Split {
    if (text.len > out.len) return error.TooLong;
    var key: ?[]const u8 = null;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    var first = true;
    while (it.next()) |line| {
        const name = keyName(line);
        if (std.ascii.eqlIgnoreCase(name, "PresharedKey")) return error.Unsupported;
        if (std.ascii.eqlIgnoreCase(name, "PrivateKey")) {
            if (key != null) return error.Unsupported;
            const eq = std.mem.indexOfScalar(u8, line, '=').?;
            key = std.mem.trim(u8, line[eq + 1 ..], " \t\r");
            continue;
        }
        if (!first) {
            out[n] = '\n';
            n += 1;
        }
        first = false;
        @memcpy(out[n..][0..line.len], line);
        n += line.len;
    }
    const k = key orelse return error.NoPrivateKey;
    if (k.len != key_text_len) return error.NoPrivateKey;
    if (!std.mem.startsWith(u8, std.mem.trimStart(u8, out[0..n], " \t\r\n"), "[Interface]")) return error.Unsupported;
    return .{ .key = k, .public = out[0..n] };
}

/// `public` (from split) with "PrivateKey = <key>" back under its first
/// line ("[Interface]"). The caller wipes `out`.
pub fn join(public: []const u8, key: []const u8, out: []u8) Error![]const u8 {
    if (key.len != key_text_len) return error.NoPrivateKey;
    const t = std.mem.trimStart(u8, public, " \t\r\n");
    if (!std.mem.startsWith(u8, t, "[Interface]")) return error.Unsupported;
    const nl = std.mem.indexOfScalar(u8, t, '\n') orelse t.len;
    const head = t[0..nl];
    const rest = t[nl..];
    const line_prefix = "\nPrivateKey = ";
    const len = head.len + line_prefix.len + key.len + rest.len;
    if (len > out.len) return error.TooLong;
    var n: usize = 0;
    for ([_][]const u8{ head, line_prefix, key, rest }) |part| {
        @memcpy(out[n..][0..part.len], part);
        n += part.len;
    }
    return out[0..len];
}

test "split takes the private key out, join puts it back" {
    const key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const text = "[Interface]\nPrivateKey = " ++ key ++ "\nAddress = 10.8.0.3/32\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = 192.168.1.10:51820\nAllowedIPs = 10.8.0.1/32\n";
    var a: [max_config]u8 = undefined;
    const s = try split(text, &a);
    try std.testing.expectEqualStrings(key, s.key);
    try std.testing.expect(std.mem.indexOf(u8, s.public, "PrivateKey") == null);
    try std.testing.expect(std.mem.indexOf(u8, s.public, key) == null);
    var b: [max_config]u8 = undefined;
    try std.testing.expectEqualStrings(text, try join(s.public, s.key, &b));
}

test "split refuses what it cannot keep secret" {
    var a: [max_config]u8 = undefined;
    const key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    try std.testing.expectError(error.NoPrivateKey, split("[Interface]\nAddress = 10.8.0.3/32\n", &a));
    try std.testing.expectError(error.Unsupported, split("[Interface]\nPrivateKey = " ++ key ++ "\nprivatekey = " ++ key ++ "\n", &a));
    try std.testing.expectError(error.Unsupported, split("[Interface]\nPrivateKey = " ++ key ++ "\n[Peer]\nPresharedKey = " ++ key ++ "\n", &a));
    try std.testing.expectError(error.Unsupported, split("[Peer]\nPrivateKey = " ++ key ++ "\n", &a));
    try std.testing.expectError(error.Unsupported, join("Address = x\n", key, &a));
    try std.testing.expectError(error.TooLong, split(&@as([max_config + 1]u8, @splat('a')), &a));
}
