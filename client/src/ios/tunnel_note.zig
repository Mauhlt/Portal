//! The background tunnel's decisions and its status line, without any
//! OS call, so they are tested on every host (client/src/tests.zig).
//! tunnel.zig (the app side of the packet tunnel extension) applies them.

const std = @import("std");

/// NEVPNStatus.
pub const Status = enum(isize) {
    invalid = 0,
    disconnected = 1,
    connecting = 2,
    connected = 3,
    reasserting = 4,
    disconnecting = 5,
    _,
};

/// NEVPNErrorDomain codes.
pub const vpn_configuration_invalid = 1;
pub const vpn_configuration_disabled = 2;
pub const vpn_connection_failed = 3;
pub const vpn_configuration_stale = 4;
pub const vpn_configuration_read_write_failed = 5;
pub const vpn_configuration_unknown = 6;

/// What the VPN configuration iOS has for our extension looks like.
pub const Existing = struct {
    /// providerConfiguration["wgQuickConfig"] (keyref.config_key).
    config: []const u8,
    /// providerConfiguration["privateKeyRef"] (keyref.key_ref_key).
    key_ref: []const u8,
    enabled: bool,
};

/// Whether `config` must be saved: no configuration yet, or a different
/// one, or disabled (another VPN was turned on since). Saving the same
/// configuration again on every launch would rewrite the system's VPN
/// preferences for nothing.
pub fn needsSave(existing: ?Existing, config: []const u8, key_ref: []const u8) bool {
    const e = existing orelse return true;
    return !e.enabled or !std.mem.eql(u8, e.config, config) or !std.mem.eql(u8, e.key_ref, key_ref);
}

/// The status line for the tunnel's state while Portal wants it up
/// ("" when it is up, or while Portal is in the background).
pub fn statusNote(status: Status, want_up: bool) []const u8 {
    if (!want_up) return "";
    return switch (status) {
        .connected => "",
        .connecting, .reasserting => "Background tunnel: connecting",
        .disconnecting => "Background tunnel: stopping",
        .disconnected => "Background tunnel: off (Settings > VPN shows Portal)",
        .invalid => "Background tunnel: not set up (reopen Portal and allow the VPN configuration)",
        _ => "Background tunnel: unknown state",
    };
}

pub const Op = enum { load, save, start };

/// The status line after a NetworkExtension call failed. `vpn_domain`:
/// the NSError is in NEVPNErrorDomain (`code` is one of the codes above).
/// `why` is the system's own description, kept short by the caller.
pub fn errorNote(buf: []u8, op: Op, vpn_domain: bool, code: isize, why: []const u8) []const u8 {
    const what = if (vpn_domain) switch (code) {
        vpn_configuration_read_write_failed => if (op == .save)
            "the VPN configuration was not allowed: reopen Portal and tap Allow"
        else
            "the system's VPN settings could not be read",
        vpn_configuration_disabled => "turned off: another VPN is on (Settings > VPN)",
        vpn_configuration_invalid, vpn_configuration_unknown, vpn_configuration_stale => "the VPN configuration is damaged: reopen Portal",
        vpn_connection_failed => "the tunnel extension did not start (Console: process PortalTunnel)",
        else => "",
    } else "";
    const verb = switch (op) {
        .load => "cannot read the VPN settings",
        .save => "cannot save the VPN configuration",
        .start => "cannot start",
    };
    if (what.len > 0) return std.fmt.bufPrint(buf, "Background tunnel: {s}", .{what}) catch buf[0..0];
    return std.fmt.bufPrint(buf, "Background tunnel: {s} ({s})", .{ verb, why[0..@min(why.len, 80)] }) catch buf[0..0];
}

const testing = std.testing;

test "save only what changed" {
    const cfg = "[Interface]\nAddress = 10.8.0.3/32\n";
    try testing.expect(needsSave(null, cfg, "k"));
    try testing.expect(!needsSave(.{ .config = cfg, .key_ref = "k", .enabled = true }, cfg, "k"));
    try testing.expect(needsSave(.{ .config = cfg, .key_ref = "k", .enabled = false }, cfg, "k"));
    try testing.expect(needsSave(.{ .config = "[Interface]\nAddress = 10.8.0.4/32\n", .key_ref = "k", .enabled = true }, cfg, "k"));
    try testing.expect(needsSave(.{ .config = cfg, .key_ref = "other", .enabled = true }, cfg, "k"));
}

test "status line: nothing while up or in the background" {
    try testing.expectEqualStrings("", statusNote(.connected, true));
    try testing.expectEqualStrings("", statusNote(.disconnected, false));
    try testing.expect(statusNote(.connecting, true).len > 0);
    try testing.expect(std.mem.indexOf(u8, statusNote(.invalid, true), "allow") != null);
    try testing.expect(statusNote(@enumFromInt(42), true).len > 0);
}

test "error notes name the fix, or the system's reason" {
    var b: [160]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, errorNote(&b, .save, true, vpn_configuration_read_write_failed, "permission denied"), "tap Allow") != null);
    try testing.expect(std.mem.indexOf(u8, errorNote(&b, .start, true, vpn_configuration_disabled, ""), "another VPN") != null);
    try testing.expectEqualStrings("Background tunnel: cannot start (no network)", errorNote(&b, .start, false, 0, "no network"));
    const long: [200]u8 = @splat('x');
    try testing.expect(errorNote(&b, .load, false, 0, &long).len < b.len);
}
