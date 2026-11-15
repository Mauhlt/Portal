//! Who holds a UDP port on this desktop, and the plain message the desk
//! shows when Portal's tunnel port is taken (docs/wireguard.md, "Port
//! clash").
//!
//! Windows tells the owning process of each UDP socket
//! (GetExtendedUdpTable, UDP_TABLE_OWNER_PID); the process's executable
//! name comes from QueryFullProcessImageNameW. The name is shown at the
//! desk and written to the desk's log only; it is never sent to a device.

const std = @import("std");
const builtin = @import("builtin");
const w = @import("win32.zig");

/// Longest name kept (an executable's base name).
pub const max_name = 128;

pub const Holder = struct {
    pid: u32,
    name_buf: [max_name]u8 = undefined,
    name_len: usize = 0,

    pub fn name(h: *const Holder) []const u8 {
        return h.name_buf[0..h.name_len];
    }
};

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const UDP_TABLE_OWNER_PID: c_int = 1;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

const Row4 = extern struct { local_addr: u32, local_port: u32, pid: u32 };
const Row6 = extern struct { local_addr: [16]u8, scope_id: u32, local_port: u32, pid: u32 };

extern "iphlpapi" fn GetExtendedUdpTable(table: ?*anyopaque, size: *u32, sort: w.BOOL, af: u32, class: c_int, reserved: u32) callconv(.winapi) u32;
extern "kernel32" fn QueryFullProcessImageNameW(h: w.HANDLE, flags: u32, name: [*]u16, size: *u32) callconv(.winapi) w.BOOL;

/// The process holding UDP `port` (IPv4 first, then IPv6), if Windows can
/// tell. Never fails: null means "unknown".
pub fn find(gpa: std.mem.Allocator, port: u16) ?Holder {
    if (builtin.os.tag != .windows) return null;
    const pid = ownerPid(gpa, AF_INET, port) orelse ownerPid(gpa, AF_INET6, port) orelse return null;
    var h: Holder = .{ .pid = pid };
    const n = processName(pid, &h.name_buf);
    h.name_len = n.len;
    return h;
}

fn ownerPid(gpa: std.mem.Allocator, af: u32, port: u16) ?u32 {
    var size: u32 = 0;
    _ = GetExtendedUdpTable(null, &size, 0, af, UDP_TABLE_OWNER_PID, 0);
    if (size < 4 or size > 16 << 20) return null;
    // Room for a few more rows appearing in between.
    size += 1024;
    const buf = gpa.alignedAlloc(u8, .of(u32), size) catch return null;
    defer gpa.free(buf);
    if (GetExtendedUdpTable(buf.ptr, &size, 0, af, UDP_TABLE_OWNER_PID, 0) != 0) return null;
    const count = std.mem.readInt(u32, buf[0..4], .little);
    const want = std.mem.nativeToBig(u16, port);
    if (af == AF_INET) {
        const rows = std.mem.bytesAsSlice(Row4, buf[4..][0 .. @min(count, (buf.len - 4) / @sizeOf(Row4)) * @sizeOf(Row4)]);
        for (rows) |r| if (@as(u16, @truncate(r.local_port)) == want) return r.pid;
    } else {
        const rows = std.mem.bytesAsSlice(Row6, buf[4..][0 .. @min(count, (buf.len - 4) / @sizeOf(Row6)) * @sizeOf(Row6)]);
        for (rows) |r| if (@as(u16, @truncate(r.local_port)) == want) return r.pid;
    }
    return null;
}

/// The executable's base name ("wireguard.exe"); "System" for the kernel
/// (a driver's socket), "" when it can't be read (another user's process).
fn processName(pid: u32, out: *[max_name]u8) []const u8 {
    if (pid == 4) return copy(out, "System");
    if (pid == 0) return out[0..0];
    const h = w.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) orelse return out[0..0];
    defer _ = w.CloseHandle(h);
    var wide: [1024]u16 = undefined;
    var n: u32 = wide.len;
    if (QueryFullProcessImageNameW(h, 0, &wide, &n) == 0 or n == 0) return out[0..0];
    const full = wide[0..n];
    const base_at = if (std.mem.lastIndexOfScalar(u16, full, '\\')) |i| i + 1 else 0;
    var u8buf: [max_name * 3]u8 = undefined;
    const len = std.unicode.wtf16LeToWtf8(&u8buf, full[base_at..][0..@min(full.len - base_at, max_name)]);
    return copy(out, u8buf[0..@min(len, max_name)]);
}

fn copy(out: *[max_name]u8, s: []const u8) []const u8 {
    const n = @min(s.len, out.len);
    @memcpy(out[0..n], s[0..n]);
    return out[0..n];
}

/// The official WireGuard client's own port (also Portal's default).
pub const wireguard_port: u16 = 51820;

fn looksLikeWireGuard(name: []const u8) bool {
    return containsIgnoreCase(name, "wireguard") or std.ascii.eqlIgnoreCase(name, "System");
}

fn containsIgnoreCase(hay: []const u8, needle: []const u8) bool {
    if (needle.len > hay.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(hay[i..][0..needle.len], needle)) return true;
    }
    return false;
}

/// What the desk says when the tunnel's UDP port is taken: the port, the
/// program holding it when known, and what to do. No automatic fix: the
/// owner chooses another port and forwards it on the router.
pub fn busyMessage(buf: []u8, port: u16, holder: ?*const Holder) []const u8 {
    var wr: std.Io.Writer = .fixed(buf);
    wr.print("Portal's tunnel could not start: UDP port {d} is already in use", .{port}) catch return buf[0..wr.end];
    if (holder) |h| {
        if (h.name().len > 0) {
            wr.print(" by {s} (process {d})", .{ h.name(), h.pid }) catch {};
        } else wr.print(" by process {d}", .{h.pid}) catch {};
    }
    wr.writeAll(". Devices cannot connect until it can listen; this window keeps working for local sessions.") catch {};
    const wg_named = if (holder) |h| looksLikeWireGuard(h.name()) else false;
    if (wg_named or port == wireguard_port)
        wr.writeAll(" The official WireGuard client often uses 51820 (its tunnels can show up as \"System\"); give one of them another port.") catch {};
    wr.writeAll(" Choose another port in Settings \u{2192} Tunnel UDP port, and forward it on your router.") catch {};
    return wr.buffered();
}

test "busy port message: the port, the holder, what to do" {
    var buf: [600]u8 = undefined;
    var h: Holder = .{ .pid = 4242 };
    h.name_len = copy(&h.name_buf, "wireguard.exe").len;
    const m = busyMessage(&buf, 51820, &h);
    try std.testing.expect(std.mem.indexOf(u8, m, "UDP port 51820 is already in use by wireguard.exe (process 4242)") != null);
    try std.testing.expect(std.mem.indexOf(u8, m, "official WireGuard client often uses 51820") != null);
    try std.testing.expect(std.mem.indexOf(u8, m, "Choose another port in Settings \u{2192} Tunnel UDP port, and forward it on your router.") != null);
    // Unknown holder on another port: no WireGuard note, still the advice.
    const u = busyMessage(&buf, 51999, null);
    try std.testing.expect(std.mem.indexOf(u8, u, "UDP port 51999 is already in use.") != null);
    try std.testing.expect(std.mem.indexOf(u8, u, "WireGuard") == null);
    try std.testing.expect(std.mem.indexOf(u8, u, "Tunnel UDP port") != null);
    const nameless: Holder = .{ .pid = 77 };
    try std.testing.expect(std.mem.indexOf(u8, busyMessage(&buf, 51999, &nameless), "by process 77.") != null);
}

test "the holder of a UDP port this process binds is this process" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    const os = @import("WireGuard").device.os;
    var u = try os.Udp.openScoped(.v4, 0, .loopback);
    defer u.close();
    const h = find(std.testing.allocator, u.localPort()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(w.GetCurrentProcessId(), h.pid);
    try std.testing.expect(std.mem.endsWith(u8, h.name(), ".exe"));
}
