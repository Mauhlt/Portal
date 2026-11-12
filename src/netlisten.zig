//! Listening sockets that no other program can share.
//!
//! On Windows, std's `IpAddress.listen` binds in a sharing mode: a second
//! socket (another Portal, or any local program) can bind the very same
//! address and port without error and receive Portal's connections. Portal's
//! listeners are created through Winsock with SO_EXCLUSIVEADDRUSE instead,
//! then handed to std (`net.Server`) for accepting, which works on the same
//! AFD endpoint handle.
//!
//! Every socket from `listenExclusive` must be released with `close` (not
//! `Server.deinit`): it calls `closesocket` and drops the Winsock reference
//! taken when it was opened.

const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;
const Io = std.Io;

comptime {
    if (builtin.os.tag != .windows) @compileError("netlisten is Windows-only");
}

const SOCKET = std.os.windows.HANDLE;
const invalid_socket: usize = std.math.maxInt(usize);

const WSADATA = extern struct { opaque_: [512]u8 };
extern "ws2_32" fn WSAStartup(version: u16, data: *WSADATA) callconv(.winapi) i32;
extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;
extern "ws2_32" fn WSASocketW(af: i32, kind: i32, protocol: i32, info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
extern "ws2_32" fn setsockopt(s: SOCKET, level: i32, name: i32, value: [*]const u8, len: i32) callconv(.winapi) i32;
extern "ws2_32" fn bind(s: SOCKET, addr: *const anyopaque, len: i32) callconv(.winapi) i32;
extern "ws2_32" fn listen(s: SOCKET, backlog: i32) callconv(.winapi) i32;
extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) i32;
extern "ws2_32" fn WSAGetLastError() callconv(.winapi) i32;

const AF_INET = 2;
const AF_INET6 = 23;
const SOCK_STREAM = 1;
const IPPROTO_TCP = 6;
const SOL_SOCKET = 0xffff;
const SO_EXCLUSIVEADDRUSE = ~@as(i32, 4); // ~SO_REUSEADDR
const WSA_FLAG_OVERLAPPED = 0x01; // std drives the handle asynchronously
const WSA_FLAG_NO_HANDLE_INHERIT = 0x80; // never leaks into the session child
const backlog = 128;

const WSAEACCES = 10013;
const WSAEADDRINUSE = 10048;
const WSAEADDRNOTAVAIL = 10049;
const WSAEAFNOSUPPORT = 10047;
const WSAENETDOWN = 10050;
const WSAENOBUFS = 10055;
const WSAEMFILE = 10024;

const SockaddrIn = extern struct {
    family: u16 = AF_INET,
    port: u16, // big endian
    addr: [4]u8,
    zero: [8]u8 = @splat(0),
};
const SockaddrIn6 = extern struct {
    family: u16 = AF_INET6,
    port: u16, // big endian
    flowinfo: u32,
    addr: [16]u8,
    scope_id: u32,
};

pub const Error = error{
    AccessDenied,
    AddressInUse,
    AddressUnavailable,
    AddressFamilyUnsupported,
    NetworkDown,
    SystemResources,
    ProcessFdQuotaExceeded,
    Unexpected,
};

fn lastError() Error {
    return switch (WSAGetLastError()) {
        // Another socket holds the address (exclusively or not).
        WSAEADDRINUSE, WSAEACCES => error.AddressInUse,
        WSAEADDRNOTAVAIL => error.AddressUnavailable,
        WSAEAFNOSUPPORT => error.AddressFamilyUnsupported,
        WSAENETDOWN => error.NetworkDown,
        WSAENOBUFS => error.SystemResources,
        WSAEMFILE => error.ProcessFdQuotaExceeded,
        else => error.Unexpected,
    };
}

/// A TCP listener on `addr` that no other socket can bind while it is open.
/// Release it with `close`.
pub fn listenExclusive(addr: net.IpAddress) Error!net.Server {
    var data: WSADATA = undefined;
    if (WSAStartup(0x0202, &data) != 0) return error.NetworkDown;
    errdefer _ = WSACleanup();

    const family: i32 = switch (addr) {
        .ip4 => AF_INET,
        .ip6 => AF_INET6,
    };
    const raw = WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, null, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (raw == invalid_socket) return lastError();
    const s: SOCKET = @ptrFromInt(raw);
    errdefer _ = closesocket(s);

    const one: i32 = 1;
    if (setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, @ptrCast(&one), @sizeOf(i32)) != 0) return lastError();

    const rc = switch (addr) {
        .ip4 => |a| bind(s, &SockaddrIn{ .port = std.mem.nativeToBig(u16, a.port), .addr = a.bytes }, @sizeOf(SockaddrIn)),
        .ip6 => |a| bind(s, &SockaddrIn6{
            .port = std.mem.nativeToBig(u16, a.port),
            .flowinfo = a.flow,
            .addr = a.bytes,
            .scope_id = a.interface.index,
        }, @sizeOf(SockaddrIn6)),
    };
    if (rc != 0) return lastError();
    if (listen(s, backlog) != 0) return lastError();

    return .{
        .socket = .{ .handle = s, .address = addr },
        .options = .{ .mode = .stream, .protocol = .tcp },
    };
}

/// Closes a listener from `listenExclusive`. Any accept blocked on it must
/// have been cancelled and finished first.
pub fn close(server: *net.Server) void {
    _ = closesocket(server.socket.handle);
    _ = WSACleanup();
    server.* = undefined;
}

/// Test helper: what any other program would do, a plain Winsock bind of
/// `addr` with or without SO_REUSEADDR. True if the bind succeeded.
fn otherProgramCanBind(addr: net.IpAddress, reuse: bool) bool {
    var data: WSADATA = undefined;
    if (WSAStartup(0x0202, &data) != 0) return false;
    defer _ = WSACleanup();
    const raw = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, null, 0, WSA_FLAG_NO_HANDLE_INHERIT);
    if (raw == invalid_socket) return false;
    const s: SOCKET = @ptrFromInt(raw);
    defer _ = closesocket(s);
    const one: i32 = 1;
    if (reuse) _ = setsockopt(s, SOL_SOCKET, 4, @ptrCast(&one), @sizeOf(i32)); // SO_REUSEADDR
    return bind(s, &SockaddrIn{ .port = std.mem.nativeToBig(u16, addr.ip4.port), .addr = addr.ip4.bytes }, @sizeOf(SockaddrIn)) == 0;
}

test "a second socket cannot bind an exclusive listener's address" {
    const io = std.testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 18397);
    var srv = try listenExclusive(addr);
    defer close(&srv);

    // Another program's bind, with and without SO_REUSEADDR, is refused,
    // and so is a second exclusive listener.
    try std.testing.expect(!otherProgramCanBind(addr, false));
    try std.testing.expect(!otherProgramCanBind(addr, true));
    try std.testing.expectError(error.AddressInUse, listenExclusive(addr));

    // std accepts on it.
    var client = try addr.connect(io, .{ .mode = .stream });
    defer client.close(io);
    var conn = try srv.accept(io);
    defer conn.close(io);
    var wbuf: [8]u8 = undefined;
    var w = client.writer(io, &wbuf);
    try w.interface.writeAll("ok");
    try w.interface.flush();
    var rbuf: [8]u8 = undefined;
    var r = conn.reader(io, &rbuf);
    try std.testing.expectEqualStrings("ok", try r.interface.takeArray(2));
}

test "a closed exclusive listener releases its address" {
    const addr = try net.IpAddress.parse("127.0.0.1", 18398);
    var srv = try listenExclusive(addr);
    close(&srv);
    try std.testing.expect(otherProgramCanBind(addr, false));
    var again = try listenExclusive(addr);
    close(&again);
}

test "restart: rebinding works while a closed connection is in TIME_WAIT" {
    // Portal closes viewer connections first when it exits, which leaves
    // them in TIME_WAIT on its port; a restart must still be able to bind.
    const io = std.testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 18399);
    var srv = try listenExclusive(addr);
    var client = try addr.connect(io, .{ .mode = .stream });
    var conn = try srv.accept(io);
    conn.close(io); // server side closes first: it holds the TIME_WAIT
    client.close(io);
    close(&srv);
    var again = try listenExclusive(addr);
    close(&again);
}
