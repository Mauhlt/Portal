//! Request-level checks. Pure functions, unit tested.

const std = @import("std");

/// Exact, case-insensitive match of the Host header against the allowlist.
/// Rejecting unknown Host values defeats DNS-rebinding attacks, where a
/// malicious web page points its own hostname at Portal's address.
pub fn hostAllowed(host: ?[]const u8, allowed: []const []const u8) bool {
    const h = host orelse return false;
    if (h.len == 0) return false;
    for (allowed) |a| {
        if (std.ascii.eqlIgnoreCase(h, a)) return true;
    }
    return false;
}

const testing = std.testing;

test "host allowlist" {
    const allowed = [_][]const u8{ "10.8.0.1:8420", "desktop.lan:8420" };
    try testing.expect(hostAllowed("10.8.0.1:8420", &allowed));
    try testing.expect(hostAllowed("DESKTOP.lan:8420", &allowed));
    try testing.expect(!hostAllowed("evil.com:8420", &allowed));
    try testing.expect(!hostAllowed("10.8.0.1", &allowed));
    try testing.expect(!hostAllowed(null, &allowed));
    try testing.expect(!hostAllowed("", &allowed));
}
