//! The desk's one Windows Firewall rule (docs/wireguard.md, "Firewall"):
//! inbound UDP on the tunnel port, any profile, any address, any
//! interface, no edge traversal, allow, not tied to a program, named
//! "Portal tunnel (WireGuard)".
//!
//! Module "firewall", used by portalctl (`portalctl firewall status | add |
//! remove`), the desk's Settings ("Windows Firewall") and portal-setup (the
//! installer). Self-contained (std and its own Win32/COM declarations), so
//! the release tools and the main program can both import it; it also
//! lends them its small COM helpers (`com`).
//!
//! * Reading the rule (`status`) needs no administrator: the Windows
//!   Firewall COM API (INetFwPolicy2) lets any user read rules.
//! * Changing it runs exactly one program as administrator:
//!   `<System32>\netsh.exe` (GetSystemDirectoryW, never a path from the
//!   environment), through ShellExecuteEx "runas", with arguments built
//!   here from a validated port and nothing else (`netshArgs`). Nothing a
//!   user can write (no Portal program, nothing from %LOCALAPPDATA%, no
//!   settings file) ever runs elevated.
//! * `change` reads the rule first (unelevated) and plans: nothing to do,
//!   `add rule`, or (a rule of that name that differs) `set rule ... new`,
//!   which rewrites it in the same one prompt. Only a rule tied to a
//!   program needs `delete rule` then `add rule`: two prompts, since netsh
//!   cannot clear a rule's program. Afterwards it waits for netsh, reads
//!   the rule again (unelevated) and reports what Windows now has.
//!   Declining the prompt changes nothing; the caller shows how to do it
//!   by hand (`manualAdd`).
//!
//! The spec, the port rules, the plan, netsh's arguments and the texts are
//! pure and unit tested; the COM read has a read-only test.

const std = @import("std");
const builtin = @import("builtin");

pub const rule_name = "Portal tunnel (WireGuard)";

/// NET_FW_IP_PROTOCOL_UDP, NET_FW_RULE_DIR_IN, NET_FW_ACTION_ALLOW,
/// NET_FW_PROFILE2_ALL (netfw.h).
pub const protocol_udp: i32 = 17;
pub const direction_in: i32 = 1;
pub const action_allow: i32 = 1;
pub const profiles_all: i32 = 0x7fffffff;

// ----------------------------------------------------------------- ports

/// Ports the tunnel may not use: below 1024 (system services), and these
/// well-known ones a desktop already has open or that its network stack
/// uses. One list for the firewall rule and the Settings / first-run /
/// `portalctl tunnel-port` checks.
pub const reserved_ports = [_]struct { port: u16, what: []const u8 }{
    .{ .port = 1701, .what = "L2TP" },
    .{ .port = 1900, .what = "SSDP (UPnP discovery)" },
    .{ .port = 3389, .what = "Remote Desktop" },
    .{ .port = 3544, .what = "Teredo" },
    .{ .port = 3702, .what = "WS-Discovery" },
    .{ .port = 4500, .what = "IPsec NAT traversal" },
    .{ .port = 5353, .what = "mDNS" },
    .{ .port = 5355, .what = "LLMNR" },
};

pub const min_port: u16 = 1024;

/// Why `port` cannot be the tunnel's port, or null if it can.
pub fn portRefusal(buf: []u8, port: u16) ?[]const u8 {
    if (port < min_port) return std.fmt.bufPrint(buf, "UDP {d} is a system port: choose 1024-65535.", .{port}) catch "Choose a port of 1024-65535.";
    for (reserved_ports) |r| if (r.port == port)
        return std.fmt.bufPrint(buf, "UDP {d} belongs to {s}: choose another port (1024-65535).", .{ port, r.what }) catch "That port belongs to a Windows service.";
    return null;
}

pub fn validPort(port: u16) bool {
    var b: [120]u8 = undefined;
    return portRefusal(&b, port) == null;
}

// ------------------------------------------------------------- the rule

/// A rule of that name as Windows reports it (COM strings: "*" is any
/// address, "All" every interface type).
pub const Observed = struct {
    protocol: i32,
    /// "51820", or a list / range ("51820,51821", "51820-51830", "*").
    local_ports: []const u8,
    direction: i32,
    action: i32,
    profiles: i32,
    enabled: bool,
    local_addresses: []const u8 = "*",
    remote_addresses: []const u8 = "*",
    interface_types: []const u8 = "All",
    edge_traversal: bool = false,
    /// Tied to a program (ApplicationName set).
    has_application: bool = false,
};

/// The single port in `local_ports`, or null for a list, range or "*".
pub fn portOf(o: Observed) ?u16 {
    return std.fmt.parseInt(u16, std.mem.trim(u8, o.local_ports, " "), 10) catch null;
}

/// The rule is exactly Portal's for `port`: every field that decides
/// what gets in.
pub fn matches(o: Observed, port: u16) bool {
    return o.protocol == protocol_udp and portOf(o) == port and o.direction == direction_in and
        o.action == action_allow and (o.profiles & profiles_all) == profiles_all and o.enabled and
        anyAddress(o.local_addresses) and anyAddress(o.remote_addresses) and
        std.ascii.eqlIgnoreCase(std.mem.trim(u8, o.interface_types, " "), "All") and
        !o.edge_traversal and !o.has_application;
}

fn anyAddress(s: []const u8) bool {
    const t = std.mem.trim(u8, s, " ");
    return std.mem.eql(u8, t, "*") or std.ascii.eqlIgnoreCase(t, "any");
}

pub const Plan = enum {
    /// The rule is there and right: nothing to change.
    already,
    /// No rule of that name: `add rule`.
    add,
    /// A rule of that name differs: `set rule ... new` (one prompt).
    set,
    /// It differs and is tied to a program, which netsh cannot clear:
    /// `delete rule`, then `add rule` (two prompts).
    delete_add,
};

/// What `change(.add)` does, given the first rule of that name (null: none).
pub fn plan(first: ?Observed, port: u16) Plan {
    const o = first orelse return .add;
    if (matches(o, port)) return .already;
    return if (o.has_application) .delete_add else .set;
}

pub const Status = union(enum) {
    /// The rule allows UDP <port> as Portal adds it.
    present,
    /// No rule of that name.
    missing,
    /// The rule is right but for another single port (the tunnel moved).
    other_port: u16,
    /// A rule of that name exists but differs in another way (disabled,
    /// a block rule, another protocol, addresses, edge traversal, ...).
    differs,
    /// The firewall could not be read (service stopped, not Windows).
    unavailable,
};

pub fn statusOf(first: ?Observed, port: u16) Status {
    const o = first orelse return .missing;
    if (matches(o, port)) return .present;
    if (portOf(o)) |p| if (p != port and matches(o, p)) return .{ .other_port = p };
    return .differs;
}

/// One line for the desk's Settings (it names the port).
pub fn describe(st: Status, port: u16, buf: []u8) []const u8 {
    return switch (st) {
        .present => std.fmt.bufPrint(buf, "Allows UDP {d} (rule \"" ++ rule_name ++ "\")", .{port}) catch "Present",
        .missing => std.fmt.bufPrint(buf, "No rule for UDP {d}: [Add rule for UDP {d}] (one administrator prompt)", .{ port, port }) catch "Missing",
        .other_port => |p| std.fmt.bufPrint(buf, "The rule allows UDP {d}, the tunnel uses {d}: [Replace it with UDP {d}] (one administrator prompt)", .{ p, port, port }) catch "Another port",
        .differs => std.fmt.bufPrint(buf, "A rule named \"" ++ rule_name ++ "\" does not allow UDP {d} as Portal needs: [Replace it] (one administrator prompt)", .{port}) catch "Differs",
        .unavailable => "Windows Firewall could not be read",
    };
}

/// The administrator PowerShell line that adds the rule by hand (the
/// fallback when the prompt was declined; README, docs/wireguard.md).
pub fn manualAdd(buf: []u8, port: u16) []const u8 {
    return std.fmt.bufPrint(buf, "New-NetFirewallRule -DisplayName \"" ++ rule_name ++ "\" -Direction Inbound -Protocol UDP -LocalPort {d} -Profile Any -Action Allow", .{port}) catch "";
}

pub const manual_remove = "Remove-NetFirewallRule -DisplayName \"" ++ rule_name ++ "\"";

// -------------------------------------------------------------- netsh

pub const NetshStep = enum { add, set, delete };

/// netsh's whole command line after `netsh.exe`: fixed text, the rule name
/// and a validated port, nothing else. error.BadPort for a port Portal
/// refuses.
pub fn netshArgs(buf: []u8, step: NetshStep, port: u16) ![]const u8 {
    const name = "name=\"" ++ rule_name ++ "\"";
    if (step != .delete and !validPort(port)) return error.BadPort;
    return switch (step) {
        .add => std.fmt.bufPrint(buf, "advfirewall firewall add rule " ++ name ++ " dir=in action=allow protocol=UDP localport={d} profile=any", .{port}),
        .set => std.fmt.bufPrint(buf, "advfirewall firewall set rule " ++ name ++ " new dir=in action=allow protocol=UDP localport={d} profile=any localip=any remoteip=any interfacetype=any edge=no enable=yes", .{port}),
        .delete => std.fmt.bufPrint(buf, "advfirewall firewall delete rule " ++ name, .{}),
    };
}

/// `<dir>\netsh.exe` for the System32 folder `dir`.
pub fn netshIn(buf: []u8, system_dir: []const u8) ?[]const u8 {
    if (!std.fs.path.isAbsolute(system_dir)) return null;
    return std.fmt.bufPrint(buf, "{s}\\netsh.exe", .{std.mem.trimEnd(u8, system_dir, "\\")}) catch null;
}

pub const Op = enum { add, remove };

pub const Outcome = union(enum) {
    /// Nothing needed changing (the rule was right, or already gone).
    nothing,
    /// netsh ran; Windows' rule as read afterwards.
    changed: Status,
    /// The administrator prompt was declined: nothing changed.
    declined,
    /// netsh failed (its exit code) or could not be started (a Win32
    /// error, flagged by `started == false`).
    failed: struct { code: u32, started: bool },
    /// The port is not one Portal uses (portRefusal).
    bad_port,
    /// The firewall could not be read.
    unavailable,
};

/// Adds (or rewrites) the rule for `port`, or removes it: reads it,
/// runs netsh as administrator only if something must change (one prompt;
/// two only for a program-bound rule), waits, and reads it again. Blocks
/// (on the prompt and netsh's process, no polling): call it off the UI
/// thread. `hwnd` (optional) owns the prompt.
pub fn change(op: Op, port: u16, hwnd: ?*anyopaque) Outcome {
    if (!windows) return .unavailable;
    if (op == .add and !validPort(port)) return .bad_port;
    var r: Reading = .{};
    const first = r.read() catch return .unavailable;
    const steps: []const NetshStep = switch (op) {
        .remove => if (first == null) return .nothing else &.{.delete},
        .add => switch (plan(first, port)) {
            .already => return .nothing,
            .add => &.{.add},
            .set => &.{.set},
            .delete_add => &.{ .delete, .add },
        },
    };
    var sys: [600]u8 = undefined;
    var nb: [640]u8 = undefined;
    const netsh = netshIn(&nb, systemDir(&sys) orelse return .{ .failed = .{ .code = 0, .started = false } }) orelse
        return .{ .failed = .{ .code = 0, .started = false } };
    for (steps) |step| {
        var ab: [400]u8 = undefined;
        const args = netshArgs(&ab, step, port) catch return .bad_port;
        switch (runElevated(netsh, args, hwnd)) {
            .exited => |code| if (code != 0) return .{ .failed = .{ .code = code, .started = true } },
            .declined => return .declined,
            .failed => |e| return .{ .failed = .{ .code = e, .started = false } },
        }
    }
    return .{ .changed = status(port) };
}

/// Exit codes of `portalctl firewall ...` (the installer reads them).
pub const exit = struct {
    pub const ok: u8 = 0;
    pub const failed: u8 = 1;
    pub const usage: u8 = 2;
    /// status: no rule (or another port, or a differing rule).
    pub const missing: u8 = 3;
    /// add / remove: the administrator prompt was declined.
    pub const declined: u8 = 5;
    /// status: the firewall could not be read.
    pub const unavailable: u8 = 6;
    /// add: the port is one Portal refuses.
    pub const bad_port: u8 = 7;
};

pub const Args = struct {
    sub: enum { status, add, remove },
    port: ?u16 = null,
};

pub fn parseArgs(args: []const []const u8) ?Args {
    if (args.len == 0) return null;
    var a: Args = .{ .sub = std.meta.stringToEnum(@FieldType(Args, "sub"), args[0]) orelse return null };
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--port") and i + 1 < args.len) {
            i += 1;
            a.port = std.fmt.parseInt(u16, args[i], 10) catch return null;
        } else return null;
    }
    return a;
}

pub const usage_text =
    \\usage: portalctl firewall status | add | remove [--port N]
    \\  status   whether the rule "Portal tunnel (WireGuard)" allows the tunnel's
    \\           UDP port (default: the saved one); no administrator needed
    \\  add      add the rule, or rewrite it after a port move (idempotent);
    \\           Windows' netsh asks for an administrator once (UAC)
    \\  remove   remove it; netsh asks for an administrator once (UAC)
    \\
;

/// `portalctl firewall ...` (never elevated itself): `saved_port` is
/// settings.txt's tunnel port. Prints to stderr; returns the exit code.
pub fn command(args: []const []const u8, saved_port: u16) u8 {
    const a = parseArgs(args) orelse {
        std.debug.print("{s}", .{usage_text});
        return exit.usage;
    };
    const port = a.port orelse saved_port;
    var mb: [400]u8 = undefined;
    switch (a.sub) {
        .status => {
            const st = status(port);
            std.debug.print("firewall: {s}\n", .{describe(st, port, &mb)});
            return switch (st) {
                .present => exit.ok,
                .unavailable => exit.unavailable,
                else => exit.missing,
            };
        },
        .add, .remove => {
            const op: Op = if (a.sub == .add) .add else .remove;
            const o = change(op, port, null);
            std.debug.print("firewall: {s}\n", .{outcomeText(o, op, port, &mb)});
            return switch (o) {
                .nothing => exit.ok,
                .changed => |st| if ((op == .add and st == .present) or (op == .remove and st == .missing)) exit.ok else exit.failed,
                .declined => exit.declined,
                .bad_port => exit.bad_port,
                .failed, .unavailable => exit.failed,
            };
        },
    }
}

/// What happened, in a line (portalctl, Settings).
pub fn outcomeText(o: Outcome, op: Op, port: u16, buf: []u8) []const u8 {
    var pb: [200]u8 = undefined;
    return switch (o) {
        .nothing => if (op == .add) std.fmt.bufPrint(buf, "the rule already allows UDP {d}", .{port}) catch "" else "there is no rule to remove",
        .changed => |st| if (op == .remove)
            (if (st == .missing) "rule removed" else "netsh ran, but the rule is still there")
        else if (st == .present)
            std.fmt.bufPrint(buf, "Windows Firewall now allows UDP {d}", .{port}) catch ""
        else
            std.fmt.bufPrint(buf, "netsh ran, but the rule does not allow UDP {d} as expected", .{port}) catch "",
        .declined => std.fmt.bufPrint(buf, "the administrator prompt was declined; nothing changed. By hand, in an administrator PowerShell: {s}", .{if (op == .add) manualAdd(&pb, port) else manual_remove}) catch "",
        .failed => |f| if (f.started)
            std.fmt.bufPrint(buf, "netsh failed (exit code {d}); nothing may have changed", .{f.code}) catch ""
        else
            std.fmt.bufPrint(buf, "could not start netsh as administrator (error {d})", .{f.code}) catch "",
        .bad_port => portRefusal(buf, port) orelse "bad port",
        .unavailable => "Windows Firewall could not be read",
    };
}

// =================================================================== Windows

const windows = builtin.os.tag == .windows;

/// Small COM helpers, shared with portal-setup (setup_win.zig).
pub const com = struct {
    pub const HRESULT = i32;
    pub const GUID = extern struct { a: u32, b: u16, c: u16, d: [8]u8 };

    pub fn guid(comptime s: []const u8) GUID {
        // "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        @setEvalBranchQuota(10_000);
        const hex = struct {
            fn n(t: []const u8) u64 {
                return std.fmt.parseInt(u64, t, 16) catch unreachable;
            }
        }.n;
        var g: GUID = .{ .a = @intCast(hex(s[0..8])), .b = @intCast(hex(s[9..13])), .c = @intCast(hex(s[14..18])), .d = undefined };
        g.d[0] = @intCast(hex(s[19..21]));
        g.d[1] = @intCast(hex(s[21..23]));
        inline for (0..6) |i| g.d[2 + i] = @intCast(hex(s[24 + 2 * i .. 26 + 2 * i]));
        return g;
    }

    /// The method at vtable `index` of COM object `obj`, as `F`.
    pub fn method(comptime F: type, obj: *anyopaque, index: usize) F {
        const vtbl: *const [*]const *const anyopaque = @ptrCast(@alignCast(obj));
        return @ptrCast(@alignCast(vtbl.*[index]));
    }

    pub fn release(obj: *anyopaque) void {
        _ = method(*const fn (*anyopaque) callconv(.winapi) u32, obj, 2)(obj);
    }

    /// COM on this thread (apartment threaded), undone by `deinit` only if
    /// this call started it.
    pub const Scope = struct {
        owned: bool,

        pub fn init() ?Scope {
            const hr = w.CoInitializeEx(null, 0x2);
            if (hr == @as(HRESULT, @bitCast(@as(u32, 0x80010106)))) return .{ .owned = false }; // RPC_E_CHANGED_MODE
            if (hr < 0) return null;
            return .{ .owned = true };
        }

        pub fn deinit(s: Scope) void {
            if (s.owned) w.CoUninitialize();
        }
    };

    pub extern "ole32" fn CoCreateInstance(clsid: *const GUID, outer: ?*anyopaque, ctx: u32, iid: *const GUID, out: *?*anyopaque) callconv(.winapi) HRESULT;
};

const Hr = com.HRESULT;
const BSTR = ?[*:0]u16;
const comMethod = com.method;
const comRelease = com.release;

const CLSID_NetFwPolicy2 = com.guid("e2b3c97f-6ae1-41ac-817a-f6f92166d7dd");
const IID_INetFwPolicy2 = com.guid("98325047-c671-4174-8d81-defcd3f03186");

const w = if (windows) struct {
    extern "ole32" fn CoInitializeEx(reserved: ?*anyopaque, coinit: u32) callconv(.winapi) Hr;
    extern "ole32" fn CoUninitialize() callconv(.winapi) void;
    extern "oleaut32" fn SysAllocStringLen(s: ?[*]const u16, len: u32) callconv(.winapi) BSTR;
    extern "oleaut32" fn SysFreeString(s: BSTR) callconv(.winapi) void;
    extern "oleaut32" fn SysStringLen(s: BSTR) callconv(.winapi) u32;
    extern "kernel32" fn CloseHandle(h: *anyopaque) callconv(.winapi) i32;
    extern "kernel32" fn GetLastError() callconv(.winapi) u32;
    extern "kernel32" fn WaitForSingleObject(h: *anyopaque, ms: u32) callconv(.winapi) u32;
    extern "kernel32" fn GetExitCodeProcess(h: *anyopaque, code: *u32) callconv(.winapi) i32;
    extern "kernel32" fn GetModuleFileNameW(module: ?*anyopaque, buf: [*]u16, size: u32) callconv(.winapi) u32;
    extern "kernel32" fn GetSystemDirectoryW(buf: [*]u16, size: u32) callconv(.winapi) u32;
    extern "shell32" fn ShellExecuteExW(info: *SHELLEXECUTEINFOW) callconv(.winapi) i32;
} else struct {};

const SHELLEXECUTEINFOW = extern struct {
    cbSize: u32 = @sizeOf(SHELLEXECUTEINFOW),
    fMask: u32 = 0,
    hwnd: ?*anyopaque = null,
    lpVerb: ?[*:0]const u16 = null,
    lpFile: ?[*:0]const u16 = null,
    lpParameters: ?[*:0]const u16 = null,
    lpDirectory: ?[*:0]const u16 = null,
    nShow: i32 = 0,
    hInstApp: ?*anyopaque = null,
    lpIDList: ?*anyopaque = null,
    lpClass: ?[*:0]const u16 = null,
    hkeyClass: ?*anyopaque = null,
    dwHotKey: u32 = 0,
    hIcon: ?*anyopaque = null,
    hProcess: ?*anyopaque = null,
};

comptime {
    if (@sizeOf(usize) == 8 and @sizeOf(SHELLEXECUTEINFOW) != 112) @compileError("SHELLEXECUTEINFOW layout");
}

/// The System32 folder (WTF-8), from GetSystemDirectoryW.
pub fn systemDir(buf: []u8) ?[]const u8 {
    if (!windows) return null;
    var wb: [300]u16 = undefined;
    const n = w.GetSystemDirectoryW(&wb, wb.len);
    if (n == 0 or n >= wb.len) return null;
    if (std.unicode.calcWtf8Len(wb[0..n]) > buf.len) return null;
    return buf[0..std.unicode.wtf16LeToWtf8(buf, wb[0..n])];
}

// INetFwPolicy2 (IDispatch: 7 methods first).
const policy_get_rules = 18;
// INetFwRules.
const rules_item = 10;
// INetFwRule getters.
const rule_get_application = 11;
const rule_get_protocol = 15;
const rule_get_local_ports = 17;
const rule_get_local_addresses = 21;
const rule_get_remote_addresses = 23;
const rule_get_direction = 27;
const rule_get_interface_types = 31;
const rule_get_enabled = 33;
const rule_get_profiles = 37;
const rule_get_edge_traversal = 39;
const rule_get_action = 41;

const GetI32 = *const fn (*anyopaque, *i32) callconv(.winapi) Hr;
const GetBool = *const fn (*anyopaque, *i16) callconv(.winapi) Hr;
const GetStr = *const fn (*anyopaque, *BSTR) callconv(.winapi) Hr;
const GetObj = *const fn (*anyopaque, *?*anyopaque) callconv(.winapi) Hr;

/// One read of the first rule named `rule_name`; its strings live here.
const Reading = struct {
    bufs: [4][160]u8 = undefined,

    /// The rule, null if there is none. error.Unavailable if the firewall
    /// cannot be read.
    fn read(r: *Reading) error{Unavailable}!?Observed {
        const scope = com.Scope.init() orelse return error.Unavailable;
        defer scope.deinit();
        var pol: ?*anyopaque = null;
        if (com.CoCreateInstance(&CLSID_NetFwPolicy2, null, 1, &IID_INetFwPolicy2, &pol) < 0) return error.Unavailable;
        const p = pol orelse return error.Unavailable;
        defer comRelease(p);
        var rules_opt: ?*anyopaque = null;
        if (comMethod(GetObj, p, policy_get_rules)(p, &rules_opt) < 0) return error.Unavailable;
        const rules = rules_opt orelse return error.Unavailable;
        defer comRelease(rules);

        const lit = std.unicode.utf8ToUtf16LeStringLiteral(rule_name);
        const name = w.SysAllocStringLen(lit, lit.len);
        defer w.SysFreeString(name);
        var rule_opt: ?*anyopaque = null;
        const hr = comMethod(*const fn (*anyopaque, BSTR, *?*anyopaque) callconv(.winapi) Hr, rules, rules_item)(rules, name, &rule_opt);
        // HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND): no such rule.
        if (hr == @as(Hr, @bitCast(@as(u32, 0x80070002)))) return null;
        if (hr < 0) return error.Unavailable;
        const rule = rule_opt orelse return null;
        defer comRelease(rule);

        var o: Observed = .{ .protocol = 0, .local_ports = "", .direction = 0, .action = 0, .profiles = 0, .enabled = false };
        if (comMethod(GetI32, rule, rule_get_protocol)(rule, &o.protocol) < 0) return error.Unavailable;
        if (comMethod(GetI32, rule, rule_get_direction)(rule, &o.direction) < 0) return error.Unavailable;
        if (comMethod(GetI32, rule, rule_get_action)(rule, &o.action) < 0) return error.Unavailable;
        if (comMethod(GetI32, rule, rule_get_profiles)(rule, &o.profiles) < 0) return error.Unavailable;
        o.enabled = try getBool(rule, rule_get_enabled);
        o.edge_traversal = try getBool(rule, rule_get_edge_traversal);
        o.local_ports = getStr(rule, rule_get_local_ports, &r.bufs[0]);
        o.local_addresses = getStr(rule, rule_get_local_addresses, &r.bufs[1]);
        o.remote_addresses = getStr(rule, rule_get_remote_addresses, &r.bufs[2]);
        o.interface_types = getStr(rule, rule_get_interface_types, &r.bufs[3]);
        var app_buf: [8]u8 = undefined;
        o.has_application = getStr(rule, rule_get_application, &app_buf).len > 0;
        return o;
    }

    fn getBool(rule: *anyopaque, index: usize) error{Unavailable}!bool {
        var v: i16 = 0;
        if (comMethod(GetBool, rule, index)(rule, &v) < 0) return error.Unavailable;
        return v != 0;
    }

    /// The string (cut to `buf`), "" if unset.
    fn getStr(rule: *anyopaque, index: usize, buf: []u8) []const u8 {
        var s: BSTR = null;
        if (comMethod(GetStr, rule, index)(rule, &s) < 0) return "";
        defer w.SysFreeString(s);
        const p = s orelse return "";
        const n = @min(w.SysStringLen(s), buf.len / 3);
        return buf[0..std.unicode.wtf16LeToWtf8(buf, p[0..n])];
    }
};

/// Whether the rule allows UDP `port` (read-only, no administrator).
pub fn status(port: u16) Status {
    if (!windows) return .unavailable;
    var r: Reading = .{};
    const first = r.read() catch return .unavailable;
    return statusOf(first, port);
}

const Elevated = union(enum) {
    exited: u32,
    declined,
    failed: u32,
};

/// Runs `netsh` (always the System32 one: `change` builds the path) as
/// administrator through ShellExecuteEx "runas", hidden, and waits for it
/// (a wait on its process handle).
fn runElevated(netsh: []const u8, params: []const u8, hwnd: ?*anyopaque) Elevated {
    var exe_w: [700:0]u16 = undefined;
    var par_w: [512:0]u16 = undefined;
    const ne = std.unicode.wtf8ToWtf16Le(exe_w[0..699], netsh) catch return .{ .failed = 87 };
    exe_w[ne] = 0;
    const np = std.unicode.wtf8ToWtf16Le(par_w[0..511], params) catch return .{ .failed = 87 };
    par_w[np] = 0;
    const scope = com.Scope.init();
    defer if (scope) |s| s.deinit();
    var info: SHELLEXECUTEINFOW = .{
        .fMask = 0x40 | 0x100 | 0x400, // NOCLOSEPROCESS | NOASYNC | FLAG_NO_UI
        .hwnd = hwnd,
        .lpVerb = std.unicode.utf8ToUtf16LeStringLiteral("runas"),
        .lpFile = exe_w[0..ne :0].ptr,
        .lpParameters = par_w[0..np :0].ptr,
        .nShow = 0, // SW_HIDE
    };
    if (w.ShellExecuteExW(&info) == 0) {
        const e = w.GetLastError();
        return if (e == 1223) .declined else .{ .failed = e }; // ERROR_CANCELLED
    }
    const h = info.hProcess orelse return .{ .failed = 0 };
    defer _ = w.CloseHandle(h);
    _ = w.WaitForSingleObject(h, 0xFFFFFFFF);
    var code: u32 = 1;
    if (w.GetExitCodeProcess(h, &code) == 0) return .{ .failed = w.GetLastError() };
    return .{ .exited = code };
}

/// This program's own path (WTF-8).
pub fn selfExe(buf: []u8) ?[]const u8 {
    if (!windows) return null;
    var wb: [1024]u16 = undefined;
    const n = w.GetModuleFileNameW(null, &wb, wb.len);
    if (n == 0 or n >= wb.len) return null;
    if (std.unicode.calcWtf8Len(wb[0..n]) > buf.len) return null;
    return buf[0..std.unicode.wtf16LeToWtf8(buf, wb[0..n])];
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn obs(port: []const u8) Observed {
    return .{ .protocol = protocol_udp, .local_ports = port, .direction = direction_in, .action = action_allow, .profiles = profiles_all, .enabled = true };
}

test "firewall: the manual command is the documented rule" {
    var b: [200]u8 = undefined;
    try testing.expectEqualStrings(
        "New-NetFirewallRule -DisplayName \"Portal tunnel (WireGuard)\" -Direction Inbound -Protocol UDP -LocalPort 51820 -Profile Any -Action Allow",
        manualAdd(&b, 51820),
    );
}

test "firewall: ports below 1024 and known service ports are refused" {
    var b: [120]u8 = undefined;
    try testing.expect(portRefusal(&b, 51820) == null);
    try testing.expect(portRefusal(&b, 1024) == null);
    try testing.expect(portRefusal(&b, 65535) == null);
    for ([_]u16{ 0, 53, 500, 1023 }) |p| try testing.expect(std.mem.indexOf(u8, portRefusal(&b, p).?, "1024-65535") != null);
    for ([_]u16{ 1900, 3389, 3702, 4500, 5353, 5355 }) |p| {
        const why = portRefusal(&b, p).?;
        var pb: [8]u8 = undefined;
        try testing.expect(std.mem.indexOf(u8, why, try std.fmt.bufPrint(&pb, "{d}", .{p})) != null);
        try testing.expect(!validPort(p));
    }
}

test "firewall: netsh's arguments are fixed text, the name and a validated port" {
    var b: [400]u8 = undefined;
    try testing.expectEqualStrings(
        "advfirewall firewall add rule name=\"Portal tunnel (WireGuard)\" dir=in action=allow protocol=UDP localport=51820 profile=any",
        try netshArgs(&b, .add, 51820),
    );
    try testing.expectEqualStrings(
        "advfirewall firewall delete rule name=\"Portal tunnel (WireGuard)\"",
        try netshArgs(&b, .delete, 0),
    );
    const set = try netshArgs(&b, .set, 51999);
    try testing.expect(std.mem.startsWith(u8, set, "advfirewall firewall set rule name=\"Portal tunnel (WireGuard)\" new "));
    for ([_][]const u8{ "dir=in", "action=allow", "protocol=UDP", "localport=51999", "profile=any", "localip=any", "remoteip=any", "interfacetype=any", "edge=no", "enable=yes" }) |part|
        try testing.expect(std.mem.indexOf(u8, set, part) != null);
    try testing.expectError(error.BadPort, netshArgs(&b, .add, 3389));
    try testing.expectError(error.BadPort, netshArgs(&b, .set, 80));
    // Only System32's netsh, never a relative or environment path.
    var nb: [100]u8 = undefined;
    try testing.expectEqualStrings("C:\\Windows\\system32\\netsh.exe", netshIn(&nb, "C:\\Windows\\system32").?);
    try testing.expectEqualStrings("C:\\Windows\\system32\\netsh.exe", netshIn(&nb, "C:\\Windows\\system32\\").?);
    try testing.expect(netshIn(&nb, "system32") == null);
    if (windows) {
        var sb: [600]u8 = undefined;
        const sys = systemDir(&sb).?;
        try testing.expect(std.ascii.endsWithIgnoreCase(netshIn(&nb, sys).?, "\\system32\\netsh.exe"));
    }
}

test "firewall: matches checks every field; the plan follows" {
    try testing.expect(matches(obs("51820"), 51820));
    try testing.expect(matches(obs(" 51820 "), 51820));
    const Case = struct { o: Observed, why: []const u8 };
    var cases: [12]Case = undefined;
    var n: usize = 0;
    const add = struct {
        fn f(c: []Case, k: *usize, o: Observed, why: []const u8) void {
            c[k.*] = .{ .o = o, .why = why };
            k.* += 1;
        }
    }.f;
    var o = obs("51821");
    add(&cases, &n, o, "port");
    o = obs("51820-51830");
    add(&cases, &n, o, "range");
    o = obs("51820");
    o.enabled = false;
    add(&cases, &n, o, "disabled");
    o = obs("51820");
    o.action = 0;
    add(&cases, &n, o, "block");
    o = obs("51820");
    o.protocol = 6;
    add(&cases, &n, o, "TCP");
    o = obs("51820");
    o.profiles = 0x4;
    add(&cases, &n, o, "public only");
    o = obs("51820");
    o.direction = 2;
    add(&cases, &n, o, "outbound");
    o = obs("51820");
    o.remote_addresses = "192.168.1.0/24";
    add(&cases, &n, o, "remote addresses");
    o = obs("51820");
    o.local_addresses = "10.0.0.5";
    add(&cases, &n, o, "local addresses");
    o = obs("51820");
    o.interface_types = "Wireless";
    add(&cases, &n, o, "interface types");
    o = obs("51820");
    o.edge_traversal = true;
    add(&cases, &n, o, "edge traversal");
    o = obs("51820");
    o.has_application = true;
    add(&cases, &n, o, "program");
    for (cases[0..n]) |c| {
        if (matches(c.o, 51820)) {
            std.debug.print("matched despite {s}\n", .{c.why});
            return error.TestUnexpectedResult;
        }
        const p = plan(c.o, 51820);
        try testing.expectEqual(if (c.o.has_application) Plan.delete_add else Plan.set, p);
    }
    try testing.expectEqual(Plan.add, plan(null, 51820));
    try testing.expectEqual(Plan.already, plan(obs("51820"), 51820));
    o = obs("51820");
    o.local_addresses = "Any";
    o.interface_types = "all";
    try testing.expect(matches(o, 51820));
}

test "firewall: status after a port move names the old port" {
    try testing.expectEqual(Status.present, statusOf(obs("51820"), 51820));
    try testing.expectEqual(Status.missing, statusOf(null, 51820));
    try testing.expectEqual(@as(u16, 51820), statusOf(obs("51820"), 51821).other_port);
    var o = obs("51820");
    o.enabled = false;
    try testing.expectEqual(Status.differs, statusOf(o, 51821));
    var b: [200]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, describe(.{ .other_port = 51820 }, 51821, &b), "Replace it with UDP 51821") != null);
    try testing.expect(std.mem.indexOf(u8, describe(.missing, 51821, &b), "Add rule for UDP 51821") != null);
    // The declined text names the real port.
    var ob: [400]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, outcomeText(.declined, .add, 51999, &ob), "-LocalPort 51999") != null);
}

test "firewall: arguments" {
    const a = parseArgs(&.{ "add", "--port", "51999" }).?;
    try testing.expect(a.sub == .add and a.port.? == 51999);
    try testing.expect(parseArgs(&.{"remove"}).?.sub == .remove);
    try testing.expect(parseArgs(&.{}) == null);
    try testing.expect(parseArgs(&.{"open"}) == null);
    try testing.expect(parseArgs(&.{ "add", "--no-elevate" }) == null);
    try testing.expect(parseArgs(&.{ "add", "--port", "70000" }) == null);
    try testing.expect(parseArgs(&.{ "add", "--port" }) == null);
}

test "firewall: guid" {
    const g = com.guid("98325047-c671-4174-8d81-defcd3f03186");
    try testing.expectEqual(@as(u32, 0x98325047), g.a);
    try testing.expectEqual(@as(u16, 0xc671), g.b);
    try testing.expectEqual(@as(u16, 0x4174), g.c);
    try testing.expectEqualSlices(u8, &.{ 0x8d, 0x81, 0xde, 0xfc, 0xd3, 0xf0, 0x31, 0x86 }, &g.d);
}

test "firewall: reading the real rule works without an administrator (read-only)" {
    if (!windows) return error.SkipZigTest;
    // Any answer is fine (this machine may or may not have the rule); the
    // point is that the COM calls and their vtable slots are right. It
    // never adds, changes or removes a rule.
    var r: Reading = .{};
    const first = r.read() catch return error.SkipZigTest; // firewall service off
    if (first) |o| _ = statusOf(o, 51820);
}
