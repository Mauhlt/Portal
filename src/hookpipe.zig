//! The local channel between `portalctl hook` (run by the agent for each
//! hook event, hookmsg.zig) and the running Portal: a named pipe only the
//! current user can open, never reachable from the network or a device.
//!
//!   * Name: `\\.\pipe\portal-hook-<hash>` (hookmsg.pipeName: the user's
//!     SID and Portal's data directory).
//!   * Security: an explicit security descriptor, owner the current user,
//!     DACL with exactly one ACE (allow the current user's SID read and
//!     write); no one else, not even administrators or SYSTEM, is granted
//!     anything. PIPE_REJECT_REMOTE_CLIENTS: no SMB clients (so nothing
//!     from another machine, and nothing a paired device could reach; the
//!     devices only ever talk HTTP/WebSocket to web.zig). The first
//!     instance is created with FILE_FLAG_FIRST_PIPE_INSTANCE: if anyone
//!     (another user, another Portal on the same data directory) holds the
//!     name already, Portal says so in its log and listens to no hooks.
//!   * The client checks the other way round: the process serving the
//!     pipe must run as the same user (GetNamedPipeServerProcessId, its
//!     token's user SID) at an integrity level no lower than the client's
//!     (so a low-integrity process of the same user that grabbed the name
//!     hears nothing from the agent), and it opens the pipe with
//!     SECURITY_IDENTIFICATION so the server could never impersonate it.
//!   * If another instance cannot be created, the server says so (once)
//!     and keeps serving on the instance it has, trying again at the next
//!     client; it only stops if that instance fails too.
//!   * Event-driven: the server thread blocks in an overlapped
//!     ConnectNamedPipe (and a bounded read) next to a stop event. No
//!     polling, no timers besides the read deadline.
//!   * The client never waits long: opening the pipe does not block; only
//!     when every instance is busy does it wait, at most
//!     `connect_timeout_ms`. It writes its few bytes and closes; there is
//!     no answer to wait for.

const std = @import("std");
const builtin = @import("builtin");
const w = @import("win32.zig");
const hookmsg = @import("hookmsg.zig");
const statusline = @import("statusline.zig");
const elevation = @import("elevation.zig");
const settings = @import("settings.zig");
const json_text = @import("shared").convo;

pub const connect_timeout_ms = 200;
/// How long the server waits for a connected client's message.
pub const read_timeout_ms = 500;

// ------------------------------------------------------------ Win32

const SECURITY_ATTRIBUTES = extern struct {
    nLength: w.DWORD = @sizeOf(SECURITY_ATTRIBUTES),
    lpSecurityDescriptor: ?*anyopaque = null,
    bInheritHandle: w.BOOL = 0,
};
const SID_AND_ATTRIBUTES = extern struct { Sid: *anyopaque, Attributes: w.DWORD };

const TOKEN_QUERY: u32 = 0x0008;
const TokenUser: u32 = 1;
const TokenIntegrityLevel: u32 = 25;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const ACL_REVISION: u32 = 2;
const PIPE_ACCESS_INBOUND: u32 = 0x00000001;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x00080000;
const PIPE_TYPE_BYTE: u32 = 0;
const PIPE_READMODE_BYTE: u32 = 0;
const PIPE_WAIT: u32 = 0;
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x00000008;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const SECURITY_SQOS_PRESENT: u32 = 0x00100000;
const SECURITY_IDENTIFICATION: u32 = 0x00010000;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const ERROR_PIPE_BUSY: u32 = 231;
const ERROR_PIPE_CONNECTED: u32 = 535;
const ERROR_BROKEN_PIPE: u32 = 109;
const ERROR_NO_DATA: u32 = 232;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_OPERATION_ABORTED: u32 = 995;
const FILE_TYPE_DISK: u32 = 1;
const FILE_TYPE_PIPE: u32 = 3;

extern "advapi32" fn OpenProcessToken(process: w.HANDLE, access: u32, token: *?w.HANDLE) callconv(.winapi) w.BOOL;
extern "advapi32" fn GetTokenInformation(token: w.HANDLE, class: u32, info: ?*anyopaque, len: u32, ret_len: *u32) callconv(.winapi) w.BOOL;
extern "advapi32" fn ConvertSidToStringSidW(sid: *anyopaque, out: *?[*:0]u16) callconv(.winapi) w.BOOL;
extern "advapi32" fn InitializeSecurityDescriptor(sd: *anyopaque, rev: u32) callconv(.winapi) w.BOOL;
extern "advapi32" fn SetSecurityDescriptorDacl(sd: *anyopaque, present: w.BOOL, dacl: ?*anyopaque, defaulted: w.BOOL) callconv(.winapi) w.BOOL;
extern "advapi32" fn SetSecurityDescriptorOwner(sd: *anyopaque, owner: ?*anyopaque, defaulted: w.BOOL) callconv(.winapi) w.BOOL;
extern "advapi32" fn InitializeAcl(acl: *anyopaque, len: u32, rev: u32) callconv(.winapi) w.BOOL;
extern "advapi32" fn AddAccessAllowedAce(acl: *anyopaque, rev: u32, mask: u32, sid: *anyopaque) callconv(.winapi) w.BOOL;
extern "advapi32" fn GetLengthSid(sid: *anyopaque) callconv(.winapi) u32;
extern "advapi32" fn EqualSid(a: *anyopaque, b: *anyopaque) callconv(.winapi) w.BOOL;
extern "advapi32" fn GetSidSubAuthorityCount(sid: *anyopaque) callconv(.winapi) *u8;
extern "advapi32" fn GetSidSubAuthority(sid: *anyopaque, n: u32) callconv(.winapi) *u32;
extern "kernel32" fn LocalFree(p: ?*anyopaque) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn CreateNamedPipeW(name: [*:0]const u16, open_mode: u32, pipe_mode: u32, max: u32, out_size: u32, in_size: u32, timeout: u32, sa: ?*SECURITY_ATTRIBUTES) callconv(.winapi) ?w.HANDLE;
extern "kernel32" fn ConnectNamedPipe(h: w.HANDLE, ov: ?*w.OVERLAPPED) callconv(.winapi) w.BOOL;
extern "kernel32" fn DisconnectNamedPipe(h: w.HANDLE) callconv(.winapi) w.BOOL;
extern "kernel32" fn WaitNamedPipeW(name: [*:0]const u16, ms: u32) callconv(.winapi) w.BOOL;
extern "kernel32" fn GetNamedPipeServerProcessId(h: w.HANDLE, pid: *u32) callconv(.winapi) w.BOOL;
extern "kernel32" fn GetFileType(h: w.HANDLE) callconv(.winapi) u32;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) w.HANDLE;

/// A user SID (TOKEN_USER buffer).
pub const UserSid = struct {
    buf: [256]u8 align(8) = undefined,

    fn sid(u: *UserSid) *anyopaque {
        const tu: *SID_AND_ATTRIBUTES = @ptrCast(&u.buf);
        return tu.Sid;
    }

    /// The token's user.
    fn ofToken(u: *UserSid, token: w.HANDLE) bool {
        var len: u32 = 0;
        return GetTokenInformation(token, TokenUser, &u.buf, u.buf.len, &len) != 0;
    }

    pub fn ofProcess(u: *UserSid, process: w.HANDLE) bool {
        var token: ?w.HANDLE = null;
        if (OpenProcessToken(process, TOKEN_QUERY, &token) == 0) return false;
        const t = token orelse return false;
        defer _ = w.CloseHandle(t);
        return u.ofToken(t);
    }

    pub fn current(u: *UserSid) bool {
        return u.ofProcess(GetCurrentProcess());
    }

    /// `S-1-5-21-...` as ASCII.
    pub fn text(u: *UserSid, out: *[184]u8) ?[]const u8 {
        var s: ?[*:0]u16 = null;
        if (ConvertSidToStringSidW(u.sid(), &s) == 0) return null;
        const p = s orelse return null;
        defer _ = LocalFree(p);
        const wide = std.mem.sliceTo(p, 0);
        if (wide.len > out.len) return null;
        for (wide, 0..) |c, i| {
            if (c > 0x7f) return null;
            out[i] = @intCast(c);
        }
        return out[0..wide.len];
    }

    pub fn eql(a: *UserSid, b: *UserSid) bool {
        return EqualSid(a.sid(), b.sid()) != 0;
    }
};

/// The mandatory integrity level of `process` (its label SID's last
/// sub-authority: 0x1000 low, 0x2000 medium, 0x3000 high, 0x4000 system).
pub fn integrityOf(process: w.HANDLE) ?u32 {
    var token: ?w.HANDLE = null;
    if (OpenProcessToken(process, TOKEN_QUERY, &token) == 0) return null;
    const t = token orelse return null;
    defer _ = w.CloseHandle(t);
    var buf: [128]u8 align(8) = undefined;
    var len: u32 = 0;
    if (GetTokenInformation(t, TokenIntegrityLevel, &buf, buf.len, &len) == 0) return null;
    const label: *SID_AND_ATTRIBUTES = @ptrCast(&buf);
    const n = GetSidSubAuthorityCount(label.Sid).*;
    if (n == 0) return null;
    return GetSidSubAuthority(label.Sid, n - 1).*;
}

/// This user's pipe for the data directory `data_dir`, as WTF-16.
pub fn pipeNameW(buf: *[80:0]u16, data_dir: []const u8) ?[:0]const u16 {
    var me: UserSid = .{};
    if (!me.current()) return null;
    var sb: [184]u8 = undefined;
    const sid = me.text(&sb) orelse return null;
    var nb: [64]u8 = undefined;
    const name = hookmsg.pipeName(&nb, sid, data_dir);
    for (name, 0..) |c, i| buf[i] = c;
    buf[name.len] = 0;
    return buf[0..name.len :0];
}

/// The security descriptor: owner and the only ACE are the current user.
const Security = struct {
    me: UserSid = .{},
    sd: [64]u8 align(8) = undefined,
    acl: [256]u8 align(8) = undefined,
    sa: SECURITY_ATTRIBUTES = .{},

    fn init(s: *Security) bool {
        if (!s.me.current()) return false;
        const sid = s.me.sid();
        if (InitializeSecurityDescriptor(&s.sd, SECURITY_DESCRIPTOR_REVISION) == 0) return false;
        const acl_len: u32 = 8 + 8 + GetLengthSid(sid); // ACL + ACCESS_ALLOWED_ACE header and mask + SID
        if (acl_len > s.acl.len) return false;
        if (InitializeAcl(&s.acl, acl_len, ACL_REVISION) == 0) return false;
        if (AddAccessAllowedAce(&s.acl, ACL_REVISION, w.GENERIC_READ | w.GENERIC_WRITE, sid) == 0) return false;
        if (SetSecurityDescriptorDacl(&s.sd, 1, &s.acl, 0) == 0) return false;
        if (SetSecurityDescriptorOwner(&s.sd, sid, 0) == 0) return false;
        s.sa = .{ .lpSecurityDescriptor = &s.sd };
        return true;
    }
};

// ------------------------------------------------------------ server

pub const Server = struct {
    name: [80:0]u16 = undefined,
    name_len: usize = 0,
    sec: Security = .{},
    /// The listening instance (always one, so the name never vanishes
    /// between two clients).
    cur: ?w.HANDLE = null,
    stop: w.HANDLE,
    conn_ev: w.HANDLE,
    read_ev: w.HANDLE,
    ctx: *anyopaque,
    /// Called on the server thread with each well-formed message.
    on_message: *const fn (ctx: *anyopaque, m: *const hookmsg.Message) void,
    /// Called on the server thread with each well-formed status line
    /// report (`portalctl statusline`, statusline.zig); null: dropped.
    on_usage: ?*const fn (ctx: *anyopaque, r: *const statusline.Report) void = null,
    /// Messages that did not parse: counted, never echoed or logged as
    /// received.
    rejected: std.atomic.Value(u32) = .init(0),
    /// Called on the server thread with a problem worth logging (once per
    /// change: degraded, recovered, stopped).
    on_problem: ?*const fn (ctx: *anyopaque, what: []const u8) void = null,
    /// Another instance could not be created: serving on the current one.
    degraded: bool = false,
    /// Tests: this many next instances fail to be created.
    test_fail_instances: u32 = 0,

    pub const InitError = error{ NoSecurity, NameTaken, CreateFailed, NoEvent };

    /// Creates the pipe (first instance). Fails with NameTaken when anyone
    /// already holds the name.
    pub fn init(s: *Server, name: [:0]const u16) InitError!void {
        @memcpy(s.name[0..name.len], name);
        s.name[name.len] = 0;
        s.name_len = name.len;
        if (!s.sec.init()) return error.NoSecurity;
        s.cur = try s.instance(true);
    }

    fn nameZ(s: *const Server) [*:0]const u16 {
        return s.name[0..s.name_len :0].ptr;
    }

    fn instance(s: *Server, first: bool) InitError!w.HANDLE {
        if (builtin.is_test and !first and s.test_fail_instances > 0) {
            s.test_fail_instances -= 1;
            return error.CreateFailed;
        }
        const mode = PIPE_ACCESS_INBOUND | w.FILE_FLAG_OVERLAPPED | (if (first) FILE_FLAG_FIRST_PIPE_INSTANCE else 0);
        const h = w.validHandle(CreateNamedPipeW(s.nameZ(), mode, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES, 0, hookmsg.max_message * 4, 0, &s.sec.sa));
        return h orelse {
            const e = w.GetLastError();
            // ERROR_ACCESS_DENIED (5) or ERROR_PIPE_BUSY: someone has it.
            return if (first and (e == 5 or e == ERROR_PIPE_BUSY)) error.NameTaken else error.CreateFailed;
        };
    }

    /// Creates the events. Call before init's thread runs.
    pub fn events() InitError!struct { w.HANDLE, w.HANDLE, w.HANDLE } {
        const a = w.validHandle(w.CreateEventW(null, 1, 0, null)) orelse return error.NoEvent;
        const b = w.validHandle(w.CreateEventW(null, 1, 0, null)) orelse return error.NoEvent;
        const c = w.validHandle(w.CreateEventW(null, 1, 0, null)) orelse return error.NoEvent;
        return .{ a, b, c };
    }

    /// Ends `run` (tests; Portal itself just exits).
    pub fn requestStop(s: *Server) void {
        _ = w.SetEvent(s.stop);
    }

    /// The server thread: one client at a time, in connection order.
    pub fn run(s: *Server) void {
        while (true) {
            const cur = s.cur orelse return;
            var ov: w.OVERLAPPED = .{ .hEvent = s.conn_ev };
            _ = w.ResetEvent(s.conn_ev);
            var connected = false;
            if (ConnectNamedPipe(cur, &ov) != 0) {
                connected = true;
            } else switch (w.GetLastError()) {
                // Connected meanwhile; or connected, wrote and closed
                // already (its bytes are still there to read).
                ERROR_PIPE_CONNECTED, ERROR_NO_DATA => connected = true,
                w.ERROR_IO_PENDING => {
                    const hs = [_]w.HANDLE{ s.conn_ev, s.stop };
                    const r = w.WaitForMultipleObjects(2, &hs, 0, w.INFINITE);
                    if (r != w.WAIT_OBJECT_0) {
                        _ = w.CancelIoEx(cur, &ov);
                        var n: w.DWORD = 0;
                        _ = w.GetOverlappedResult(cur, &ov, &n, 1);
                        _ = w.CloseHandle(cur);
                        s.cur = null;
                        return;
                    }
                    var n: w.DWORD = 0;
                    connected = w.GetOverlappedResult(cur, &ov, &n, 0) != 0;
                },
                else => {},
            }
            // Keep the name alive before handling this client.
            const next = s.instance(false) catch null;
            if (next == null and !s.degraded) {
                s.degraded = true;
                s.problem("cannot create another hook pipe instance; serving on the current one and trying again at the next hook");
            } else if (next != null and s.degraded) {
                s.degraded = false;
                s.problem("hook pipe instances can be created again");
            }
            if (connected) {
                var buf: [hookmsg.max_message + 1]u8 = undefined;
                const got = s.readAll(cur, &buf);
                if (got) |text| {
                    if (hookmsg.parse(text)) |m| {
                        s.on_message(s.ctx, &m);
                    } else if (statusline.parse(text)) |r| {
                        if (s.on_usage) |f| f(s.ctx, &r);
                    } else _ = s.rejected.fetchAdd(1, .monotonic);
                }
            }
            if (next) |n| {
                _ = DisconnectNamedPipe(cur);
                _ = w.CloseHandle(cur);
                s.cur = n;
            } else if (connected) {
                // Reuse this instance: disconnected, it can be connected
                // to the next client (the name stays alive meanwhile).
                _ = DisconnectNamedPipe(cur);
            } else {
                // This instance failed and no new one could be made:
                // nothing is left to wait on.
                _ = w.CloseHandle(cur);
                s.cur = null;
                s.problem("the hook pipe failed and no new instance could be created; Claude Code hooks are no longer listened to");
                return;
            }
            if (w.WaitForSingleObject(s.stop, 0) == w.WAIT_OBJECT_0) {
                if (s.cur) |h| _ = w.CloseHandle(h);
                s.cur = null;
                return;
            }
        }
    }

    fn problem(s: *Server, what: []const u8) void {
        if (s.on_problem) |f| f(s.ctx, what);
    }

    /// The client's bytes until it closes, at most max_message (more is
    /// malformed), within read_timeout_ms.
    fn readAll(s: *Server, h: w.HANDLE, buf: []u8) ?[]const u8 {
        var n: usize = 0;
        const deadline = w.GetTickCount64() + read_timeout_ms;
        while (n < buf.len) {
            var ov: w.OVERLAPPED = .{ .hEvent = s.read_ev };
            _ = w.ResetEvent(s.read_ev);
            var got: w.DWORD = 0;
            if (w.ReadFile(h, buf[n..].ptr, @intCast(buf.len - n), null, &ov) == 0) {
                const e = w.GetLastError();
                if (e == ERROR_BROKEN_PIPE) break;
                if (e != w.ERROR_IO_PENDING and e != ERROR_MORE_DATA) return null;
                const now = w.GetTickCount64();
                const left: u32 = if (now >= deadline) 0 else @intCast(deadline - now);
                const hs = [_]w.HANDLE{ s.read_ev, s.stop };
                const r = w.WaitForMultipleObjects(2, &hs, 0, left);
                if (r != w.WAIT_OBJECT_0) {
                    _ = w.CancelIoEx(h, &ov);
                    _ = w.GetOverlappedResult(h, &ov, &got, 1);
                    return null;
                }
            }
            if (w.GetOverlappedResult(h, &ov, &got, 0) == 0) {
                if (w.GetLastError() == ERROR_BROKEN_PIPE) break;
                return null;
            }
            if (got == 0) break;
            n += got;
        }
        if (n > hookmsg.max_message) return null;
        return buf[0..n];
    }
};

// ------------------------------------------------------------ client

pub const SendError = error{ NoPortal, Busy, NotOurs, WriteFailed };

/// Sends one message to the Portal listening on `name`. Never waits
/// longer than connect_timeout_ms (and only when every instance is busy).
pub fn send(name: [:0]const u16, bytes: []const u8) SendError!void {
    const access = w.GENERIC_WRITE | FILE_READ_ATTRIBUTES;
    const flags = SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION;
    var h = w.validHandle(w.CreateFileW(name.ptr, access, 0, null, w.OPEN_EXISTING, flags, null));
    if (h == null) {
        if (w.GetLastError() != ERROR_PIPE_BUSY) return error.NoPortal;
        if (WaitNamedPipeW(name.ptr, connect_timeout_ms) == 0) return error.Busy;
        h = w.validHandle(w.CreateFileW(name.ptr, access, 0, null, w.OPEN_EXISTING, flags, null));
    }
    const p = h orelse return error.Busy;
    defer _ = w.CloseHandle(p);
    if (!servedByMe(p)) return error.NotOurs;
    var off: usize = 0;
    while (off < bytes.len) {
        var wrote: w.DWORD = 0;
        if (w.WriteFile(p, bytes[off..].ptr, @intCast(bytes.len - off), &wrote, null) == 0) return error.WriteFailed;
        off += wrote;
    }
}

/// The process serving the pipe runs as this user, at an integrity level
/// no lower than this process's.
fn servedByMe(pipe: w.HANDLE) bool {
    var pid: u32 = 0;
    if (GetNamedPipeServerProcessId(pipe, &pid) == 0) return false;
    const proc = w.validHandle(w.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)) orelse return false;
    defer _ = w.CloseHandle(proc);
    var them: UserSid = .{};
    var me: UserSid = .{};
    if (!them.ofProcess(proc) or !me.current()) return false;
    if (!them.eql(&me)) return false;
    const their_level = integrityOf(proc) orelse return false;
    const my_level = integrityOf(GetCurrentProcess()) orelse return false;
    return trustedLevel(their_level, my_level);
}

/// A server at `server` integrity may receive from a client at `client`.
fn trustedLevel(server: u32, client: u32) bool {
    return server >= client;
}

// ------------------------------------------------------------ `portalctl hook`

/// Largest hook input read (the agent's JSON on stdin); the rest is
/// drained and the input counts as unparsable.
pub const max_input = 1 << 20;

/// `portalctl hook`: always exits 0 (the caller exits), and does nothing
/// at all outside a Portal tab (no PORTAL_TAB). It prints nothing, except
/// the one decision of the admin-prompt guard: a PreToolUse shell command
/// that asks for elevation (elevation.zig) in a session a device started
/// (`guard` = PORTAL_GUARD, `device`), or in any session while the desk's
/// `block_elevation_desk` is on, is denied with the hook's documented
/// output (`hookSpecificOutput.permissionDecision = "deny"` and a reason
/// for the agent). Otherwise the command runs and Portal is told
/// (`guard=marked`: a "needs desk" card). The command never travels.
pub fn hookCommand(io: std.Io, tab: ?[]const u8, data_dir: ?[]const u8, guard: ?[]const u8) void {
    const in = stdinHandle();
    const key = hookmsg.parseKey(tab orelse return drain(in)) orelse return drain(in);
    const buf = std.heap.page_allocator.alloc(u8, max_input) catch return drain(in);
    defer std.heap.page_allocator.free(buf);
    const n = readInput(in, buf);
    drain(in);
    const json = buf[0 .. n orelse return];
    var scratch: [16 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    // Large inputs (a long prompt) need more than the scratch: fall back.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const parsed = hookmsg.parseHook(fba.allocator(), key, json) orelse
        (hookmsg.parseHook(arena.allocator(), key, json) orelse return);
    var m = parsed.msg;
    if (m.event == .PreToolUse) {
        const device = if (guard) |g| std.mem.eql(u8, g, "device") else false;
        switch (guardDecision(parsed, device, if (device) false else deskBlocks(io, data_dir))) {
            .none => {},
            .marked => m.guard = .marked,
            .denied => |r| {
                m.guard = .denied;
                printDecision(r.reason());
            },
        }
    }
    var nb: [80:0]u16 = undefined;
    const name = pipeNameW(&nb, data_dir orelse return) orelse return;
    var mb: [hookmsg.max_message]u8 = undefined;
    send(name, m.format(&mb)) catch {};
}

pub const Decision = union(hookmsg.Guard) {
    none,
    marked,
    denied: Reason,

    pub const Reason = struct {
        buf: [600]u8 = undefined,
        len: usize = 0,
        pub fn reason(r: *const Reason) []const u8 {
            return r.buf[0..r.len];
        }
    };
};

/// The admin-prompt guard's decision for a PreToolUse (pure, tested):
/// only the shell tools' commands count; an elevating one is denied in a
/// device-started session (`device`) or when the desk blocks it
/// (`desk_blocks`), else marked.
pub fn guardDecision(p: hookmsg.Parsed, device: bool, desk_blocks: bool) Decision {
    if (p.msg.event != .PreToolUse) return .none;
    const t = p.msg.tool();
    if (!std.mem.eql(u8, t, "Bash") and !std.mem.eql(u8, t, "PowerShell")) return .none;
    const match = elevation.check(p.command orelse return .none) orelse return .none;
    if (!device and !desk_blocks) return .marked;
    var r: Decision.Reason = .{};
    const text = if (device) elevation.denyReason(match, &r.buf) else elevation.deskDenyReason(match, &r.buf);
    if (@intFromPtr(text.ptr) != @intFromPtr(&r.buf)) {
        @memcpy(r.buf[0..text.len], text);
    }
    r.len = text.len;
    return .{ .denied = r };
}

/// The desk's `block_elevation_desk` (settings.txt in the data folder);
/// read only when an elevating command was found.
fn deskBlocks(io: std.Io, data_dir: ?[]const u8) bool {
    const dir = data_dir orelse return false;
    return settings.load(std.heap.page_allocator, io, dir).block_elevation_desk orelse false;
}

/// The PreToolUse deny decision on stdout (the agent's documented hook
/// output; exit code 0).
pub fn decisionJson(reason: []const u8, out: *std.Io.Writer) !void {
    try out.writeAll("{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":");
    try json_text.writeString(out, reason);
    try out.writeAll("}}\n");
}

fn printDecision(reason: []const u8) void {
    var buf: [1024]u8 = undefined;
    var wr: std.Io.Writer = .fixed(&buf);
    decisionJson(reason, &wr) catch return;
    const h = w.validHandle(w.GetStdHandle(w.STD_OUTPUT_HANDLE)) orelse return;
    var done: usize = 0;
    const bytes = wr.buffered();
    while (done < bytes.len) {
        var n: w.DWORD = 0;
        if (w.WriteFile(h, bytes[done..].ptr, @intCast(bytes.len - done), &n, null) == 0 or n == 0) return;
        done += n;
    }
}

pub fn stdinHandle() ?w.HANDLE {
    const h = w.validHandle(w.GetStdHandle(w.STD_INPUT_HANDLE)) orelse return null;
    // Only a pipe or a file: never wait on a console someone types into.
    const t = GetFileType(h);
    return if (t == FILE_TYPE_PIPE or t == FILE_TYPE_DISK) h else null;
}

/// Reads all of stdin into buf; null if it does not fit.
pub fn readInput(in: ?w.HANDLE, buf: []u8) ?usize {
    const h = in orelse return null;
    var n: usize = 0;
    while (true) {
        if (n == buf.len) return null;
        var r: w.DWORD = 0;
        if (w.ReadFile(h, buf[n..].ptr, @intCast(buf.len - n), &r, null) == 0 or r == 0) return n;
        n += r;
    }
}

/// Reads stdin to its end (bounded), so the writer never sees a broken
/// pipe.
pub fn drain(in: ?w.HANDLE) void {
    const h = in orelse return;
    var buf: [16 * 1024]u8 = undefined;
    var total: usize = 0;
    while (total < 64 << 20) {
        var r: w.DWORD = 0;
        if (w.ReadFile(h, &buf, buf.len, &r, null) == 0 or r == 0) return;
        total += r;
    }
}

// ------------------------------------------------------------ tests

const testing = std.testing;

const Got = struct {
    n: std.atomic.Value(usize) = .init(0),
    last: hookmsg.Event = .SessionEnd,
    fn on(ctx: *anyopaque, m: *const hookmsg.Message) void {
        const g: *Got = @ptrCast(@alignCast(ctx));
        g.last = m.event;
        _ = g.n.fetchAdd(1, .release);
    }
    fn waitFor(g: *Got, n: usize) bool {
        var tries: usize = 0;
        while (g.n.load(.acquire) < n) : (tries += 1) {
            if (tries > 1000) return false;
            w.Sleep(5);
        }
        return true;
    }
};

fn testName(buf: *[80:0]u16) [:0]const u16 {
    var rnd: [8]u8 = undefined;
    testing.io.random(&rnd);
    const hex = std.fmt.bytesToHex(rnd, .lower);
    var nb: [64]u8 = undefined;
    const s = std.fmt.bufPrint(&nb, "\\\\.\\pipe\\portal-hook-test-{s}", .{&hex}) catch unreachable;
    for (s, 0..) |c, i| buf[i] = c;
    buf[s.len] = 0;
    return buf[0..s.len :0];
}

test "server: messages in order, malformed ones dropped, the name can't be taken twice" {
    var nb: [80:0]u16 = undefined;
    const name = testName(&nb);
    var got: Got = .{};
    const ev = try Server.events();
    var s: Server = .{ .stop = ev[0], .conn_ev = ev[1], .read_ev = ev[2], .ctx = &got, .on_message = Got.on };
    defer inline for (0..3) |k| {
        _ = w.CloseHandle(ev[k]);
    };
    try s.init(name);
    // A second server for the same name is refused.
    var dup: Server = .{ .stop = ev[0], .conn_ev = ev[1], .read_ev = ev[2], .ctx = &got, .on_message = Got.on };
    try testing.expectError(error.NameTaken, dup.init(name));
    const th = try std.Thread.spawn(.{}, Server.run, .{&s});
    var mb: [hookmsg.max_message]u8 = undefined;
    for ([_]hookmsg.Event{ .UserPromptSubmit, .PermissionRequest, .Stop }) |e| {
        const m: hookmsg.Message = .{ .key = @splat(7), .event = e };
        try send(name, m.format(&mb));
    }
    try send(name, "garbage\n");
    try testing.expect(got.waitFor(3));
    try testing.expectEqual(hookmsg.Event.Stop, got.last);
    // The garbage was read after the three and dropped.
    var tries: usize = 0;
    while (s.rejected.load(.monotonic) == 0 and tries < 200) : (tries += 1) w.Sleep(5);
    try testing.expectEqual(@as(u32, 1), s.rejected.load(.monotonic));
    try testing.expectEqual(@as(usize, 3), got.n.load(.acquire));
    // No such pipe: the client gives up at once.
    var ob: [80:0]u16 = undefined;
    try testing.expectError(error.NoPortal, send(testName(&ob), "x"));
    // Remote (SMB) clients are rejected, even from this machine.
    var rb: [96:0]u16 = undefined;
    const prefix = "\\\\127.0.0.1\\pipe\\";
    const local = name["\\\\.\\pipe\\".len..];
    for (prefix, 0..) |c, i| rb[i] = c;
    @memcpy(rb[prefix.len..][0..local.len], local);
    rb[prefix.len + local.len] = 0;
    const remote = w.validHandle(w.CreateFileW(rb[0 .. prefix.len + local.len :0].ptr, w.GENERIC_WRITE, 0, null, w.OPEN_EXISTING, 0, null));
    if (remote) |r| _ = w.CloseHandle(r);
    try testing.expect(remote == null);
    s.requestStop();
    th.join();
}

test "server: keeps serving on its instance when no new one can be created" {
    var nb: [80:0]u16 = undefined;
    const name = testName(&nb);
    var got: Got = .{};
    const ev = try Server.events();
    defer inline for (0..3) |k| {
        _ = w.CloseHandle(ev[k]);
    };
    const Problems = struct {
        var n: std.atomic.Value(u32) = .init(0);
        fn on(_: *anyopaque, _: []const u8) void {
            _ = n.fetchAdd(1, .release);
        }
    };
    var s: Server = .{ .stop = ev[0], .conn_ev = ev[1], .read_ev = ev[2], .ctx = &got, .on_message = Got.on, .on_problem = Problems.on, .test_fail_instances = 2 };
    try s.init(name);
    const th = try std.Thread.spawn(.{}, Server.run, .{&s});
    var mb: [hookmsg.max_message]u8 = undefined;
    for (0..4) |i| {
        const m: hookmsg.Message = .{ .key = @splat(7), .event = .Stop };
        try send(name, m.format(&mb));
        try testing.expect(got.waitFor(i + 1));
    }
    // Degraded once (two failures), recovered once.
    try testing.expectEqual(@as(u32, 2), Problems.n.load(.acquire));
    s.requestStop();
    th.join();
}

test "integrity: this process has a level, and a lower server is not trusted" {
    const mine = integrityOf(GetCurrentProcess()).?;
    try testing.expect(mine >= 0x1000);
    try testing.expect(trustedLevel(mine, mine));
    try testing.expect(trustedLevel(0x3000, 0x2000));
    try testing.expect(!trustedLevel(0x1000, 0x2000));
}

test "the admin-prompt guard: shell tools only; device sessions denied, desk ones marked unless blocked" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key: hookmsg.Key = @splat(4);
    const elev = hookmsg.parseHook(a, key, "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"gsudo winget install X\"}}").?;
    const plain = hookmsg.parseHook(a, key, "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"PowerShell\",\"tool_input\":{\"command\":\"zig build test\"}}").?;
    const other = hookmsg.parseHook(a, key, "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Write\",\"tool_input\":{\"command\":\"sudo x\"}}").?;
    try testing.expect(guardDecision(plain, true, true) == .none);
    try testing.expect(guardDecision(other, true, true) == .none);
    try testing.expect(guardDecision(elev, false, false) == .marked);
    const d = guardDecision(elev, true, false);
    try testing.expect(d == .denied);
    try testing.expect(std.mem.indexOf(u8, d.denied.reason(), "only run at the desk") != null);
    try testing.expect(std.mem.indexOf(u8, d.denied.reason(), "winget") == null);
    const b = guardDecision(elev, false, true);
    try testing.expect(std.mem.indexOf(u8, b.denied.reason(), "block_elevation_desk") != null);
    // The documented output, as JSON the agent parses.
    var buf: [1024]u8 = undefined;
    var wr: std.Io.Writer = .fixed(&buf);
    try decisionJson(d.denied.reason(), &wr);
    const v = try std.json.parseFromSlice(std.json.Value, testing.allocator, wr.buffered(), .{});
    defer v.deinit();
    const o = v.value.object.get("hookSpecificOutput").?.object;
    try testing.expectEqualStrings("PreToolUse", o.get("hookEventName").?.string);
    try testing.expectEqualStrings("deny", o.get("permissionDecision").?.string);
    try testing.expect(o.get("permissionDecisionReason").?.string.len > 20);
}

test "pipeNameW: this user's name for a data directory" {
    var a: [80:0]u16 = undefined;
    const n = pipeNameW(&a, "C:\\x\\Portal").?;
    try testing.expect(std.mem.startsWith(u16, n, std.unicode.utf8ToUtf16LeStringLiteral("\\\\.\\pipe\\portal-hook-")));
}
