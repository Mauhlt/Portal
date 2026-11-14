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
const transcript = @import("convo/transcript.zig");
const json_text = @import("shared").convo;
const Mode = @import("shared").projects.Mode;

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

/// `portalctl hook [--device ask|plan]`: always exits 0 (the caller
/// exits). Two ways it is run:
///
///   * Plain (`hook`, the user's hooks install, agenthooks.zig): nothing
///     at all outside a Portal tab (no PORTAL_TAB); otherwise it tells
///     Portal the event. Its one decision is the admin-prompt guard's: a
///     PreToolUse shell command that asks for elevation (elevation.zig) in
///     a session a device started (`guard` = PORTAL_GUARD, `device`), or
///     in any session while the desk's `block_elevation_desk` is on, is
///     denied with the hook's documented output
///     (`hookSpecificOutput.permissionDecision = "deny"` and a reason for
///     the agent). Otherwise the command runs and Portal is told
///     (`guard=marked`: a "needs desk" card). The command never travels.
///   * The device guard (`hook --device <mode>`, Portal's own settings
///     layer for a device start, agentsettings.zig; every tool's
///     PreToolUse): the mode is the desk's, from the hook's own arguments,
///     not from anything the session can set. The admin-prompt guard as
///     above, then modeDecision: in Plan only read-only tools run, in Ask
///     every other tool asks (over any allow rule or mode). It tells
///     Portal about shell commands that may run; in such a session the
///     plain hook leaves that to it, so nothing reaches Portal twice.
///
/// Input it can't read or parse (over max_input, not JSON) is denied in
/// the device guard, and in the plain hook for a PreToolUse in a device
/// start or while the desk blocks elevation: the guard fails closed.
pub fn hookCommand(io: std.Io, tab: ?[]const u8, data_dir: ?[]const u8, guard: ?[]const u8, args: []const []const u8) void {
    const in = stdinHandle();
    const device_mode = deviceArg(args);
    const env_device = if (guard) |g| std.mem.eql(u8, g, "device") else false;
    const key: ?hookmsg.Key = if (tab) |t| hookmsg.parseKey(t) else null;
    if (key == null and device_mode == null) return drain(in);
    const buf = std.heap.page_allocator.alloc(u8, max_input) catch {
        drain(in);
        if (device_mode != null) printDecision(.deny, unreadable_reason);
        return;
    };
    defer std.heap.page_allocator.free(buf);
    const n = readInput(in, buf);
    drain(in);
    // Cut off (null): the first max_input bytes; no stdin at all: none.
    const seen = if (in == null) buf[0..0] else buf[0 .. n orelse buf.len];
    var scratch: [16 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    // Large inputs (a long prompt) need more than the scratch: fall back.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const k = key orelse @as(hookmsg.Key, @splat(0));
    const got: ?hookmsg.Parsed = if (n == null) null else hookmsg.parseHook(fba.allocator(), k, seen) orelse
        hookmsg.parseHook(arena.allocator(), k, seen);
    const parsed = got orelse {
        if (failClosed(device_mode != null, env_device, seen, io, data_dir)) printDecision(.deny, unreadable_reason);
        return;
    };
    var m = parsed.msg;
    // The plain hook tells Portal, except a device start's PreToolUse,
    // which the device guard tells.
    var tell = if (device_mode != null) m.event == .PreToolUse else !(env_device and m.event == .PreToolUse);
    if (m.event == .PreToolUse) {
        const device = device_mode != null or env_device;
        switch (guardDecision(parsed, device, if (device) false else deskBlocks(io, data_dir))) {
            .none => {},
            .marked => m.guard = .marked,
            .denied => |r| {
                m.guard = .denied;
                printDecision(.deny, r.reason());
            },
        }
        if (m.guard != .denied) if (device_mode) |mode| switch (modeDecision(m.tool(), mode)) {
            .none => {},
            .ask => printDecision(.ask, ask_reason),
            .deny => {
                printDecision(.deny, plan_reason);
                tell = false; // it never runs
            },
        };
        // Portal only follows shell commands (the long-running deadline).
        if (!shellTool(m.tool())) tell = false;
    }
    if (!tell or key == null) return;
    var nb: [80:0]u16 = undefined;
    const name = pipeNameW(&nb, data_dir orelse return) orelse return;
    var mb: [hookmsg.max_message]u8 = undefined;
    send(name, m.format(&mb)) catch {};
}

/// `--device <mode>` in the hook's arguments (agentsettings.zig): the
/// desk's mode. Any other value is Plan, the stricter one; null: the
/// plain hook.
pub fn deviceArg(args: []const []const u8) ?Mode {
    for (args, 0..) |a, i| if (std.mem.eql(u8, a, hookmsg.device_flag)) {
        if (i + 1 < args.len and std.mem.eql(u8, args[i + 1], "ask")) return .ask;
        return .plan;
    };
    return null;
}

fn shellTool(t: []const u8) bool {
    return std.mem.eql(u8, t, "Bash") or std.mem.eql(u8, t, "PowerShell");
}

/// Tools that only read, look up, plan or ask (transcript.category: read,
/// search, the todo list, a question, a subagent, whose own tool calls
/// pass this hook too). Everything else, including web access, MCP tools,
/// ExitPlanMode and any tool Portal does not know, is not.
pub fn readOnlyTool(t: []const u8) bool {
    if (t.len == 0) return false;
    return switch (transcript.category(t)) {
        .read, .search, .todo, .question, .agent => true,
        else => false,
    };
}

pub const ModeVerdict = enum { none, ask, deny };

/// What the desk's mode for a device start says about tool `t` (pure,
/// tested): read-only tools take the normal way; otherwise Plan denies
/// and Ask asks.
pub fn modeDecision(t: []const u8, mode: Mode) ModeVerdict {
    if (readOnlyTool(t)) return .none;
    return switch (mode) {
        .plan => .deny,
        .ask => .ask,
    };
}

pub const plan_reason = "Portal blocked this tool: this session was started from a paired device in Plan mode, which only reads and plans. Nothing may be changed or run in it, and its plan can't be approved here. Present the plan as text and stop; the user can carry it out in a session at the desk.";
pub const ask_reason = "This session was started from a paired device in Ask mode: Portal asks before every edit, command and tool, whatever rules or mode would allow it.";
pub const unreadable_reason = "Portal blocked this tool call because its hook could not read the call (too large or malformed), and calls in this session must be checked. Try again with a smaller call.";

/// Unreadable or unparsable input is denied by the device guard (it only
/// runs for PreToolUse), and by the plain hook for what looks like a
/// PreToolUse (`hook_event_name` among the bytes read) in a device start
/// or while the desk blocks elevation. Other events stay untouched.
fn failClosed(device_guard: bool, env_device: bool, seen: []const u8, io: std.Io, data_dir: ?[]const u8) bool {
    if (device_guard) return true;
    if (!looksLikePreToolUse(seen)) return false;
    return env_device or deskBlocks(io, data_dir);
}

/// `"hook_event_name"`, `:` and `"PreToolUse"` (whitespace allowed)
/// somewhere in `s`: no parser needed, so a cut-off input counts too.
pub fn looksLikePreToolUse(s: []const u8) bool {
    const k = "\"hook_event_name\"";
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, s, from, k)) |i| {
        from = i + k.len;
        var j = from;
        while (j < s.len and std.ascii.isWhitespace(s[j])) j += 1;
        if (j >= s.len or s[j] != ':') continue;
        j += 1;
        while (j < s.len and std.ascii.isWhitespace(s[j])) j += 1;
        if (std.mem.startsWith(u8, s[j..], "\"PreToolUse\"")) return true;
    }
    return false;
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

test "block_elevation_desk: the Settings panel's merged save is what the hook reads next" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [1024]u8 = undefined;
    const dir = path_buf[0..try tmp.dir.realPath(io, &path_buf)];
    try testing.expect(!deskBlocks(io, dir)); // no file: off
    try tmp.dir.writeFile(io, .{ .sub_path = settings.file_name, .data = "program = agent\r\nsystem_monitor = on\r\n" });
    try testing.expect(!deskBlocks(io, dir)); // not set: off
    // As gui.saveSettings does: load, merge the toggle, save.
    var s = settings.loadOrNull(gpa, io, dir).?;
    s.block_elevation_desk = true;
    try settings.save(gpa, io, dir, &s);
    try testing.expect(deskBlocks(io, dir));
    const back = settings.load(gpa, io, dir);
    try testing.expectEqualStrings("agent", back.program.get().?);
    try testing.expect(back.system_monitor.?);
    s.block_elevation_desk = false;
    try settings.save(gpa, io, dir, &s);
    try testing.expect(!deskBlocks(io, dir));
    try testing.expect(!deskBlocks(io, null));
}

pub const Verdict = enum { deny, ask };

/// A PreToolUse decision on stdout (the agent's documented hook output;
/// exit code 0). At most one per hook run.
pub fn decisionJson(verdict: Verdict, reason: []const u8, out: *std.Io.Writer) !void {
    try out.print("{{\"hookSpecificOutput\":{{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"{t}\",\"permissionDecisionReason\":", .{verdict});
    try json_text.writeString(out, reason);
    try out.writeAll("}}\n");
}

fn printDecision(verdict: Verdict, reason: []const u8) void {
    var buf: [1024]u8 = undefined;
    var wr: std.Io.Writer = .fixed(&buf);
    decisionJson(verdict, reason, &wr) catch return;
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
    try decisionJson(.deny, d.denied.reason(), &wr);
    const v = try std.json.parseFromSlice(std.json.Value, testing.allocator, wr.buffered(), .{});
    defer v.deinit();
    const o = v.value.object.get("hookSpecificOutput").?.object;
    try testing.expectEqualStrings("PreToolUse", o.get("hookEventName").?.string);
    try testing.expectEqualStrings("deny", o.get("permissionDecision").?.string);
    try testing.expect(o.get("permissionDecisionReason").?.string.len > 20);
}

test "the device guard: the desk's mode from the hook's arguments; Plan denies, Ask asks, reading runs" {
    try testing.expect(deviceArg(&.{}) == null);
    try testing.expectEqual(Mode.ask, deviceArg(&.{ hookmsg.device_flag, "ask" }).?);
    try testing.expectEqual(Mode.plan, deviceArg(&.{ hookmsg.device_flag, "plan" }).?);
    // Anything else is the stricter mode.
    try testing.expectEqual(Mode.plan, deviceArg(&.{ hookmsg.device_flag, "acceptEdits" }).?);
    try testing.expectEqual(Mode.plan, deviceArg(&.{hookmsg.device_flag}).?);
    for ([_][]const u8{ "Read", "Glob", "Grep", "LS", "TodoWrite", "AskUserQuestion", "Agent", "Task" }) |t| {
        try testing.expectEqual(ModeVerdict.none, modeDecision(t, .plan));
        try testing.expectEqual(ModeVerdict.none, modeDecision(t, .ask));
    }
    for ([_][]const u8{ "ExitPlanMode", "Edit", "Write", "MultiEdit", "NotebookEdit", "Bash", "PowerShell", "WebFetch", "WebSearch", "mcp__x__y", "SomethingNew", "" }) |t| {
        try testing.expectEqual(ModeVerdict.deny, modeDecision(t, .plan));
        try testing.expectEqual(ModeVerdict.ask, modeDecision(t, .ask));
    }
    // The ask decision, as JSON the agent parses.
    var buf: [1024]u8 = undefined;
    var wr: std.Io.Writer = .fixed(&buf);
    try decisionJson(.ask, ask_reason, &wr);
    const v = try std.json.parseFromSlice(std.json.Value, testing.allocator, wr.buffered(), .{});
    defer v.deinit();
    try testing.expectEqualStrings("ask", v.value.object.get("hookSpecificOutput").?.object.get("permissionDecision").?.string);
}

test "failing closed: a PreToolUse the hook can't read is recognised from its bytes" {
    try testing.expect(looksLikePreToolUse("{\"session_id\":\"x\",\"hook_event_name\" : \"PreToolUse\",\"tool_input\":{\"command\":\"aaaa"));
    try testing.expect(!looksLikePreToolUse("{\"hook_event_name\":\"UserPromptSubmit\",\"prompt\":\"\\\"hook_event_name\\\": PreToolUse\"}"));
    try testing.expect(!looksLikePreToolUse(""));
    try testing.expect(!looksLikePreToolUse("\"hook_event_name\""));
    // The device guard always fails closed; the plain hook only in a
    // device start (or with the desk's block on) and only for PreToolUse.
    try testing.expect(failClosed(true, false, "", testing.io, null));
    try testing.expect(failClosed(false, true, "{\"hook_event_name\":\"PreToolUse\"", testing.io, null));
    try testing.expect(!failClosed(false, true, "{\"hook_event_name\":\"Stop\"", testing.io, null));
    try testing.expect(!failClosed(false, false, "{\"hook_event_name\":\"PreToolUse\"", testing.io, null));
}

test "pipeNameW: this user's name for a data directory" {
    var a: [80:0]u16 = undefined;
    const n = pipeNameW(&a, "C:\\x\\Portal").?;
    try testing.expect(std.mem.startsWith(u16, n, std.unicode.utf8ToUtf16LeStringLiteral("\\\\.\\pipe\\portal-hook-")));
}
