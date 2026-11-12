//! Request-level checks: listen-address policy, Host/Origin allowlists,
//! cookie and form parsing. Pure functions, unit tested.

const std = @import("std");
const IpAddress = std.Io.net.IpAddress;

// ------------------------------------------------------------ listen policy

pub const ListenError = error{
    /// 0.0.0.0 / :: would expose Portal on every interface, including any
    /// public one. Always refused.
    WildcardAddress,
    /// Not loopback / private / VPN range.
    PublicAddress,
};

/// Portal may only listen on loopback, RFC 1918 private ranges (where a
/// WireGuard interface address lives, e.g. 10.8.0.1), 100.64.0.0/10
/// (Tailscale / CGNAT) or IPv6 unique-local fc00::/7.
pub fn checkListenAddress(addr: IpAddress) ListenError!void {
    switch (addr) {
        .ip4 => |a| {
            const b = a.bytes;
            if (std.mem.eql(u8, &b, &.{ 0, 0, 0, 0 })) return error.WildcardAddress;
            if (b[0] == 127) return; // loopback
            if (b[0] == 10) return; // 10.0.0.0/8
            if (b[0] == 172 and b[1] >= 16 and b[1] <= 31) return; // 172.16.0.0/12
            if (b[0] == 192 and b[1] == 168) return; // 192.168.0.0/16
            if (b[0] == 100 and b[1] >= 64 and b[1] <= 127) return; // 100.64.0.0/10
            return error.PublicAddress;
        },
        .ip6 => |a| {
            const b = a.bytes;
            const zero: [16]u8 = @splat(0);
            if (std.mem.eql(u8, &b, &zero)) return error.WildcardAddress;
            var loop = zero;
            loop[15] = 1;
            if (std.mem.eql(u8, &b, &loop)) return; // ::1
            if (b[0] & 0xfe == 0xfc) return; // fc00::/7 unique local
            return error.PublicAddress;
        },
    }
}

// ----------------------------------------------------------- host / origin

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

/// Origin must be present and equal `scheme://host` for an allowed host.
/// Required on every state-changing request and on WebSocket upgrades
/// (browsers do not apply CORS to WebSockets, so this check is the defence
/// against cross-site WebSocket hijacking).
pub fn originAllowed(origin: ?[]const u8, scheme: []const u8, allowed_hosts: []const []const u8) bool {
    const o = origin orelse return false;
    if (!std.ascii.startsWithIgnoreCase(o, scheme)) return false;
    const rest = o[scheme.len..];
    if (!std.mem.startsWith(u8, rest, "://")) return false;
    return hostAllowed(rest[3..], allowed_hosts);
}

// ------------------------------------------------------------------ cookies

/// Finds `name` in a Cookie header value ("a=1; b=2").
pub fn getCookie(header: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, header, ';');
    while (it.next()) |part_raw| {
        const part = std.mem.trim(u8, part_raw, " \t");
        const eq = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        if (std.mem.eql(u8, part[0..eq], name)) return part[eq + 1 ..];
    }
    return null;
}

// --------------------------------------------------------------------- form

/// Looks up `key` in an application/x-www-form-urlencoded body and
/// percent-decodes it into `out`. Returns null if missing or malformed.
pub fn formValue(body: []const u8, key: []const u8, out: []u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, body, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (!std.mem.eql(u8, pair[0..eq], key)) continue;
        return percentDecode(pair[eq + 1 ..], out);
    }
    return null;
}

fn percentDecode(in: []const u8, out: []u8) ?[]const u8 {
    var o: usize = 0;
    var i: usize = 0;
    while (i < in.len) {
        if (o >= out.len) return null;
        switch (in[i]) {
            '+' => {
                out[o] = ' ';
                i += 1;
            },
            '%' => {
                if (i + 3 > in.len) return null;
                const hi = std.fmt.charToDigit(in[i + 1], 16) catch return null;
                const lo = std.fmt.charToDigit(in[i + 2], 16) catch return null;
                out[o] = hi * 16 + lo;
                i += 3;
            },
            else => |c| {
                out[o] = c;
                i += 1;
            },
        }
        o += 1;
    }
    return out[0..o];
}

// -------------------------------------------------------------------- tests

const testing = std.testing;

fn ip(text: []const u8) IpAddress {
    return IpAddress.parse(text, 8420) catch unreachable;
}

test "listen policy" {
    try testing.expectError(error.WildcardAddress, checkListenAddress(ip("0.0.0.0")));
    try testing.expectError(error.WildcardAddress, checkListenAddress(ip("::")));
    try checkListenAddress(ip("127.0.0.1"));
    try checkListenAddress(ip("::1"));
    try checkListenAddress(ip("10.8.0.1"));
    try checkListenAddress(ip("192.168.1.20"));
    try checkListenAddress(ip("172.20.0.1"));
    try checkListenAddress(ip("100.101.102.103"));
    try checkListenAddress(ip("fd7a:115c:a1e0::1"));
    try testing.expectError(error.PublicAddress, checkListenAddress(ip("8.8.8.8")));
    try testing.expectError(error.PublicAddress, checkListenAddress(ip("172.32.0.1")));
    try testing.expectError(error.PublicAddress, checkListenAddress(ip("100.128.0.1")));
    try testing.expectError(error.PublicAddress, checkListenAddress(ip("2001:db8::1")));
}

test "host allowlist" {
    const allowed = [_][]const u8{ "10.8.0.1:8420", "desktop.lan:8420" };
    try testing.expect(hostAllowed("10.8.0.1:8420", &allowed));
    try testing.expect(hostAllowed("DESKTOP.lan:8420", &allowed));
    try testing.expect(!hostAllowed("evil.com:8420", &allowed));
    try testing.expect(!hostAllowed("10.8.0.1", &allowed));
    try testing.expect(!hostAllowed(null, &allowed));
    try testing.expect(!hostAllowed("", &allowed));
}

test "origin check" {
    const allowed = [_][]const u8{"10.8.0.1:8420"};
    try testing.expect(originAllowed("http://10.8.0.1:8420", "http", &allowed));
    try testing.expect(!originAllowed("https://10.8.0.1:8420", "http", &allowed));
    try testing.expect(!originAllowed("http://evil.com", "http", &allowed));
    try testing.expect(!originAllowed("http://10.8.0.1:8420.evil.com", "http", &allowed));
    try testing.expect(!originAllowed("null", "http", &allowed));
    try testing.expect(!originAllowed(null, "http", &allowed));
}

test "cookie parsing" {
    try testing.expectEqualStrings("abc", getCookie("x=1; portal_session=abc; y=2", "portal_session").?);
    try testing.expectEqualStrings("abc", getCookie("portal_session=abc", "portal_session").?);
    try testing.expect(getCookie("xportal_session=abc", "portal_session") == null);
    try testing.expect(getCookie("", "portal_session") == null);
}

test "form parsing" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("a-b_c", formValue("token=a-b_c", "token", &buf).?);
    try testing.expectEqualStrings("a b/", formValue("x=1&token=a+b%2F", "token", &buf).?);
    try testing.expect(formValue("token=%2", "token", &buf) == null);
    try testing.expect(formValue("token=%zz", "token", &buf) == null);
    try testing.expect(formValue("other=1", "token", &buf) == null);
    var tiny: [2]u8 = undefined;
    try testing.expect(formValue("token=abc", "token", &tiny) == null);
}
