//! The desk's one Windows Firewall rule (docs/wireguard.md, "Firewall"):
//! inbound UDP on the tunnel port, any profile, allow, not tied to a
//! program, named "Portal tunnel (WireGuard)".
//!
//! Module "firewall", used by portalctl (`portalctl firewall status | add |
//! remove`), the desk's Settings ("Windows Firewall") and portal-setup (the
//! installer). Self-contained (std and its own Win32/COM declarations), so
//! the release tools and the main program can both import it.
//!
//! * Reading the rule (`status`) needs no administrator: the Windows
//!   Firewall COM API (INetFwPolicy2) lets any user read rules.
//! * Changing it (`apply`, `removeAll`) needs one: `portalctl firewall add`
//!   started without one relaunches itself through ShellExecuteEx "runas"
//!   (`runElevated`, ONE UAC prompt) with `--no-elevate`, and waits for it.
//!   Declining the prompt is not an error: the caller shows how to add the
//!   rule later (`manualAdd`).
//! * `apply` is idempotent: a rule of that name that already matches the
//!   spec is left alone; one that differs (another port after a port move,
//!   disabled, a block rule) is replaced; none is added.
//!
//! The spec, the plan and the texts are pure and unit tested; the COM
//! calls only run for real (a read-only test exercises `status`).

const std = @import("std");
const builtin = @import("builtin");

pub const rule_name = "Portal tunnel (WireGuard)";
pub const rule_description = "Portal's own WireGuard (inbound UDP on the tunnel port). Added through Portal with an administrator's approval.";
pub const rule_grouping = "Portal";

/// NET_FW_IP_PROTOCOL_UDP, NET_FW_RULE_DIR_IN, NET_FW_ACTION_ALLOW,
/// NET_FW_PROFILE2_ALL (netfw.h).
pub const protocol_udp: i32 = 17;
pub const direction_in: i32 = 1;
pub const action_allow: i32 = 1;
pub const profiles_all: i32 = 0x7fffffff;

/// The rule Portal adds, for `port`.
pub const Spec = struct {
    name: []const u8 = rule_name,
    description: []const u8 = rule_description,
    grouping: []const u8 = rule_grouping,
    protocol: i32 = protocol_udp,
    local_port: u16,
    direction: i32 = direction_in,
    action: i32 = action_allow,
    profiles: i32 = profiles_all,
    enabled: bool = true,
};

pub fn spec(port: u16) Spec {
    return .{ .local_port = port };
}

/// A rule of that name as Windows reports it.
pub const Observed = struct {
    protocol: i32,
    /// "51820", or a list / range ("51820,51821", "51820-51830", "*").
    local_ports: []const u8,
    direction: i32,
    action: i32,
    profiles: i32,
    enabled: bool,
    /// Tied to a program (ApplicationName set): not Portal's rule shape.
    has_application: bool = false,
};

/// The single port in `local_ports`, or null for a list, range or "*".
pub fn portOf(o: Observed) ?u16 {
    const t = std.mem.trim(u8, o.local_ports, " ");
    return std.fmt.parseInt(u16, t, 10) catch null;
}

/// The observed rule is exactly the spec's (the parts that decide what
/// gets in; the description and grouping do not).
pub fn matches(s: Spec, o: Observed) bool {
    return o.protocol == s.protocol and portOf(o) == s.local_port and o.direction == s.direction and
        o.action == s.action and (o.profiles & s.profiles) == s.profiles and o.enabled == s.enabled and !o.has_application;
}

pub const Plan = enum {
    /// The rule is there and right: nothing to change.
    already,
    /// No rule of that name: add it.
    add,
    /// A rule of that name differs (another port, disabled, ...): remove
    /// every rule of that name and add it.
    replace,
};

/// What `apply` does, given the first rule of that name (null: none).
pub fn plan(first: ?Observed, s: Spec) Plan {
    const o = first orelse return .add;
    return if (matches(s, o)) .already else .replace;
}

pub const Status = union(enum) {
    /// The rule allows UDP <port>, inbound, every profile.
    present,
    /// No rule of that name.
    missing,
    /// The rule is for another single port (the tunnel moved).
    other_port: u16,
    /// A rule of that name exists but does not allow the port as Portal
    /// would (disabled, a block rule, another protocol, a range).
    differs,
    /// The firewall could not be read (service stopped, not Windows).
    unavailable,
};

pub fn statusOf(first: ?Observed, port: u16) Status {
    const o = first orelse return .missing;
    const s = spec(port);
    if (matches(s, o)) return .present;
    // Right in every way but the port: the tunnel moved since.
    if (portOf(o)) |p| if (p != port and matches(spec(p), o)) return .{ .other_port = p };
    return .differs;
}

/// One line for the desk's Settings.
pub fn describe(st: Status, port: u16, buf: []u8) []const u8 {
    return switch (st) {
        .present => std.fmt.bufPrint(buf, "Allows UDP {d} (rule \"" ++ rule_name ++ "\")", .{port}) catch "Present",
        .missing => std.fmt.bufPrint(buf, "No rule for UDP {d}: [Add rule] (one administrator prompt)", .{port}) catch "Missing",
        .other_port => |p| std.fmt.bufPrint(buf, "The rule allows UDP {d}, the tunnel uses {d}: [Replace rule] (one administrator prompt)", .{ p, port }) catch "Another port",
        .differs => std.fmt.bufPrint(buf, "A rule named \"" ++ rule_name ++ "\" does not allow UDP {d}: [Replace rule] (one administrator prompt)", .{port}) catch "Differs",
        .unavailable => "Windows Firewall could not be read",
    };
}

/// Exit codes of `portalctl firewall ...` (the installer and Settings read
/// them).
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
};

/// The administrator PowerShell line that adds the rule by hand (the
/// fallback when the prompt was declined; README, docs/wireguard.md).
pub fn manualAdd(buf: []u8, port: u16) []const u8 {
    return std.fmt.bufPrint(buf, "New-NetFirewallRule -DisplayName \"" ++ rule_name ++ "\" -Direction Inbound -Protocol UDP -LocalPort {d} -Profile Any -Action Allow", .{port}) catch "";
}

pub const manual_remove = "Remove-NetFirewallRule -DisplayName \"" ++ rule_name ++ "\"";

pub const Op = enum { add, remove };

/// The elevated child's command line after `portalctl`:
/// `firewall add --port 51820 --no-elevate` (`--no-elevate`: it never asks
/// again; without the rights it fails).
pub fn elevatedParams(buf: []u8, op: Op, port: u16) []const u8 {
    return switch (op) {
        .add => std.fmt.bufPrint(buf, "firewall add --port {d} --no-elevate", .{port}) catch "",
        .remove => "firewall remove --no-elevate",
    };
}

pub const Args = struct {
    sub: enum { status, add, remove },
    port: ?u16 = null,
    no_elevate: bool = false,
};

pub fn parseArgs(args: []const []const u8) ?Args {
    if (args.len == 0) return null;
    var a: Args = .{ .sub = if (std.mem.eql(u8, args[0], "status"))
        .status
    else if (std.mem.eql(u8, args[0], "add"))
        .add
    else if (std.mem.eql(u8, args[0], "remove"))
        .remove
    else
        return null };
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--port") and i + 1 < args.len) {
            i += 1;
            const p = std.fmt.parseInt(u16, args[i], 10) catch return null;
            if (p == 0) return null;
            a.port = p;
        } else if (std.mem.eql(u8, args[i], "--no-elevate")) {
            a.no_elevate = true;
        } else return null;
    }
    return a;
}

pub const usage_text =
    \\usage: portalctl firewall status | add | remove [--port N]
    \\  status   whether the rule "Portal tunnel (WireGuard)" allows the tunnel's
    \\           UDP port (default: the saved one); no administrator needed
    \\  add      add the rule, or replace it after a port move (idempotent);
    \\           asks for an administrator once (UAC)
    \\  remove   remove it; asks for an administrator once (UAC)
    \\
;

/// `portalctl firewall ...`: `saved_port` is settings.txt's tunnel port.
/// Prints to stderr; returns the exit code (`exit`).
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
            if (!isElevated()) {
                if (a.no_elevate) {
                    std.debug.print("firewall: this needs an administrator\n", .{});
                    return exit.failed;
                }
                var pb: [64]u8 = undefined;
                var self_buf: [1024]u8 = undefined;
                const self = selfExe(&self_buf) orelse {
                    std.debug.print("firewall: cannot find portalctl.exe itself\n", .{});
                    return exit.failed;
                };
                return switch (runElevated(self, elevatedParams(&pb, op, port), null)) {
                    .exited => |code| blk: {
                        const c: u8 = if (code > 255) exit.failed else @intCast(code);
                        if (c == exit.ok) {
                            std.debug.print("firewall: {s}\n", .{if (op == .add) describe(status(port), port, &mb) else "rule removed"});
                        } else std.debug.print("firewall: the administrator step failed (exit code {d})\n", .{code});
                        break :blk c;
                    },
                    .declined => blk: {
                        std.debug.print("firewall: the administrator prompt was declined; nothing changed. To do it later, in an administrator PowerShell:\n  {s}\n", .{if (op == .add) manualAdd(&mb, port) else manual_remove});
                        break :blk exit.declined;
                    },
                    .failed => |e| blk: {
                        std.debug.print("firewall: could not ask for an administrator (error {d})\n", .{e});
                        break :blk exit.failed;
                    },
                };
            }
            switch (op) {
                .add => {
                    const p = apply(port) catch |err| {
                        std.debug.print("firewall: could not add the rule: {t}\n", .{err});
                        return exit.failed;
                    };
                    std.debug.print("firewall: {s}\n", .{switch (p) {
                        .already => "the rule was already there",
                        .add => "rule added",
                        .replace => "rule replaced",
                    }});
                },
                .remove => {
                    const n = removeAll() catch |err| {
                        std.debug.print("firewall: could not remove the rule: {t}\n", .{err});
                        return exit.failed;
                    };
                    std.debug.print("firewall: {d} rule(s) removed\n", .{n});
                },
            }
            return exit.ok;
        },
    }
}

// =================================================================== Windows

const windows = builtin.os.tag == .windows;

const HRESULT = i32;
const GUID = extern struct { a: u32, b: u16, c: u16, d: [8]u8 };
const BSTR = ?[*:0]u16;

fn guid(comptime s: []const u8) GUID {
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

const CLSID_NetFwPolicy2 = guid("e2b3c97f-6ae1-41ac-817a-f6f92166d7dd");
const IID_INetFwPolicy2 = guid("98325047-c671-4174-8d81-defcd3f03186");
const CLSID_NetFwRule = guid("2c5bc43e-3369-4c33-ab0c-be9469677af4");
const IID_INetFwRule = guid("af230d27-baba-4e42-aced-f524f22cfce2");

const CLSCTX_INPROC_SERVER: u32 = 0x1;
const COINIT_APARTMENTTHREADED: u32 = 0x2;
const RPC_E_CHANGED_MODE: HRESULT = @bitCast(@as(u32, 0x80010106));

const w = if (windows) struct {
    extern "ole32" fn CoInitializeEx(reserved: ?*anyopaque, coinit: u32) callconv(.winapi) HRESULT;
    extern "ole32" fn CoUninitialize() callconv(.winapi) void;
    extern "ole32" fn CoCreateInstance(clsid: *const GUID, outer: ?*anyopaque, ctx: u32, iid: *const GUID, out: *?*anyopaque) callconv(.winapi) HRESULT;
    extern "oleaut32" fn SysAllocStringLen(s: ?[*]const u16, len: u32) callconv(.winapi) BSTR;
    extern "oleaut32" fn SysFreeString(s: BSTR) callconv(.winapi) void;
    extern "oleaut32" fn SysStringLen(s: BSTR) callconv(.winapi) u32;
    extern "kernel32" fn GetCurrentProcess() callconv(.winapi) *anyopaque;
    extern "kernel32" fn CloseHandle(h: *anyopaque) callconv(.winapi) i32;
    extern "kernel32" fn GetLastError() callconv(.winapi) u32;
    extern "kernel32" fn WaitForSingleObject(h: *anyopaque, ms: u32) callconv(.winapi) u32;
    extern "kernel32" fn GetExitCodeProcess(h: *anyopaque, code: *u32) callconv(.winapi) i32;
    extern "kernel32" fn GetModuleFileNameW(module: ?*anyopaque, buf: [*]u16, size: u32) callconv(.winapi) u32;
    extern "advapi32" fn OpenProcessToken(process: *anyopaque, access: u32, token: *?*anyopaque) callconv(.winapi) i32;
    extern "advapi32" fn GetTokenInformation(token: *anyopaque, class: u32, info: *anyopaque, len: u32, ret: *u32) callconv(.winapi) i32;
    extern "shell32" fn ShellExecuteExW(info: *SHELLEXECUTEINFOW) callconv(.winapi) i32;
} else struct {};

pub const SHELLEXECUTEINFOW = extern struct {
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

const SEE_MASK_NOCLOSEPROCESS: u32 = 0x40;
const SEE_MASK_NOASYNC: u32 = 0x100;
const SEE_MASK_FLAG_NO_UI: u32 = 0x400;
const ERROR_CANCELLED: u32 = 1223;
const INFINITE: u32 = 0xFFFFFFFF;

/// COM for this thread, undone by `deinit` only if this call started it.
const ComScope = struct {
    owned: bool,

    fn init() ?ComScope {
        const hr = w.CoInitializeEx(null, COINIT_APARTMENTTHREADED);
        if (hr == RPC_E_CHANGED_MODE) return .{ .owned = false }; // the thread has COM already
        if (hr < 0) return null;
        return .{ .owned = true };
    }

    fn deinit(s: ComScope) void {
        if (s.owned) w.CoUninitialize();
    }
};

/// The method at vtable `index` of COM object `obj`, as `F`.
fn method(comptime F: type, obj: *anyopaque, index: usize) F {
    const vtbl: *const [*]const *const anyopaque = @ptrCast(@alignCast(obj));
    return @ptrCast(@alignCast(vtbl.*[index]));
}

fn release(obj: *anyopaque) void {
    _ = method(*const fn (*anyopaque) callconv(.winapi) u32, obj, 2)(obj);
}

// INetFwPolicy2 (IDispatch: 7 methods first).
const policy_get_rules = 18;
// INetFwRules.
const rules_add = 8;
const rules_remove = 9;
const rules_item = 10;
// INetFwRule.
const rule_put_name = 8;
const rule_put_description = 10;
const rule_get_application = 11;
const rule_get_protocol = 15;
const rule_put_protocol = 16;
const rule_get_local_ports = 17;
const rule_put_local_ports = 18;
const rule_get_direction = 27;
const rule_put_direction = 28;
const rule_get_enabled = 33;
const rule_put_enabled = 34;
const rule_put_grouping = 36;
const rule_get_profiles = 37;
const rule_put_profiles = 38;
const rule_get_action = 41;
const rule_put_action = 42;

const GetI32 = *const fn (*anyopaque, *i32) callconv(.winapi) HRESULT;
const PutI32 = *const fn (*anyopaque, i32) callconv(.winapi) HRESULT;
const GetBool = *const fn (*anyopaque, *i16) callconv(.winapi) HRESULT;
const PutBool = *const fn (*anyopaque, i16) callconv(.winapi) HRESULT;
const GetStr = *const fn (*anyopaque, *BSTR) callconv(.winapi) HRESULT;
const PutStr = *const fn (*anyopaque, BSTR) callconv(.winapi) HRESULT;
const GetObj = *const fn (*anyopaque, *?*anyopaque) callconv(.winapi) HRESULT;

fn bstr(comptime s: []const u8) BSTR {
    const lit = std.unicode.utf8ToUtf16LeStringLiteral(s);
    return w.SysAllocStringLen(lit, lit.len);
}

fn bstrFmt(comptime fmt: []const u8, args: anytype) BSTR {
    var b: [64]u8 = undefined;
    const s = std.fmt.bufPrint(&b, fmt, args) catch return null;
    var u: [64]u16 = undefined;
    const n = std.unicode.utf8ToUtf16Le(&u, s) catch return null;
    return w.SysAllocStringLen(&u, @intCast(n));
}

/// INetFwPolicy2.Rules (released by the caller).
fn openRules() ?*anyopaque {
    var pol: ?*anyopaque = null;
    if (w.CoCreateInstance(&CLSID_NetFwPolicy2, null, CLSCTX_INPROC_SERVER, &IID_INetFwPolicy2, &pol) < 0) return null;
    const p = pol orelse return null;
    defer release(p);
    var rules: ?*anyopaque = null;
    if (method(GetObj, p, policy_get_rules)(p, &rules) < 0) return null;
    return rules;
}

const ItemError = error{ NotFound, Failed };

/// INetFwRules.Item(rule_name) (released by the caller).
fn item(rules: *anyopaque) ItemError!*anyopaque {
    const name = bstr(rule_name);
    defer w.SysFreeString(name);
    var r: ?*anyopaque = null;
    const hr = method(*const fn (*anyopaque, BSTR, *?*anyopaque) callconv(.winapi) HRESULT, rules, rules_item)(rules, name, &r);
    // HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
    if (hr == @as(HRESULT, @bitCast(@as(u32, 0x80070002)))) return error.NotFound;
    if (hr < 0) return error.Failed;
    return r orelse error.NotFound;
}

/// Reads a rule into `o`; `ports_buf` holds its local ports text.
fn observe(rule: *anyopaque, ports_buf: []u8) ?Observed {
    var o: Observed = .{ .protocol = 0, .local_ports = "", .direction = 0, .action = 0, .profiles = 0, .enabled = false };
    if (method(GetI32, rule, rule_get_protocol)(rule, &o.protocol) < 0) return null;
    if (method(GetI32, rule, rule_get_direction)(rule, &o.direction) < 0) return null;
    if (method(GetI32, rule, rule_get_action)(rule, &o.action) < 0) return null;
    if (method(GetI32, rule, rule_get_profiles)(rule, &o.profiles) < 0) return null;
    var en: i16 = 0;
    if (method(GetBool, rule, rule_get_enabled)(rule, &en) < 0) return null;
    o.enabled = en != 0;
    var ports: BSTR = null;
    if (method(GetStr, rule, rule_get_local_ports)(rule, &ports) >= 0) {
        defer w.SysFreeString(ports);
        if (ports) |p| {
            const n = w.SysStringLen(ports);
            const len = std.unicode.wtf16LeToWtf8(ports_buf[0..@min(ports_buf.len, n * 3)], p[0..@min(n, ports_buf.len / 3)]);
            o.local_ports = ports_buf[0..len];
        }
    }
    var app: BSTR = null;
    if (method(GetStr, rule, rule_get_application)(rule, &app) >= 0) {
        defer w.SysFreeString(app);
        o.has_application = app != null and w.SysStringLen(app) > 0;
    }
    return o;
}

/// Whether the rule allows UDP `port` (read-only, no administrator).
pub fn status(port: u16) Status {
    if (!windows) return .unavailable;
    const com = ComScope.init() orelse return .unavailable;
    defer com.deinit();
    const rules = openRules() orelse return .unavailable;
    defer release(rules);
    const r = item(rules) catch |err| return switch (err) {
        error.NotFound => .missing,
        error.Failed => .unavailable,
    };
    defer release(r);
    var pb: [96]u8 = undefined;
    const o = observe(r, &pb) orelse return .unavailable;
    return statusOf(o, port);
}

/// Adds the rule for `port`, or replaces a differing one (administrator
/// only). Idempotent.
pub fn apply(port: u16) !Plan {
    if (!windows) return error.Unsupported;
    const com = ComScope.init() orelse return error.ComInit;
    defer com.deinit();
    const rules = openRules() orelse return error.FirewallUnavailable;
    defer release(rules);
    const s = spec(port);
    const p: Plan = blk: {
        const r = item(rules) catch |err| switch (err) {
            error.NotFound => break :blk .add,
            error.Failed => return error.FirewallUnavailable,
        };
        defer release(r);
        var pb: [96]u8 = undefined;
        break :blk plan(observe(r, &pb) orelse return error.FirewallUnavailable, s);
    };
    switch (p) {
        .already => return p,
        .replace => _ = try removeFrom(rules),
        .add => {},
    }
    var nr: ?*anyopaque = null;
    if (w.CoCreateInstance(&CLSID_NetFwRule, null, CLSCTX_INPROC_SERVER, &IID_INetFwRule, &nr) < 0) return error.RuleCreate;
    const rule = nr orelse return error.RuleCreate;
    defer release(rule);
    const name = bstr(rule_name);
    defer w.SysFreeString(name);
    const desc = bstr(rule_description);
    defer w.SysFreeString(desc);
    const group = bstr(rule_grouping);
    defer w.SysFreeString(group);
    const ports = bstrFmt("{d}", .{s.local_port});
    defer w.SysFreeString(ports);
    if (method(PutStr, rule, rule_put_name)(rule, name) < 0) return error.RuleSet;
    if (method(PutStr, rule, rule_put_description)(rule, desc) < 0) return error.RuleSet;
    // The protocol first: ports are only valid for TCP and UDP rules.
    if (method(PutI32, rule, rule_put_protocol)(rule, s.protocol) < 0) return error.RuleSet;
    if (method(PutStr, rule, rule_put_local_ports)(rule, ports) < 0) return error.RuleSet;
    if (method(PutI32, rule, rule_put_direction)(rule, s.direction) < 0) return error.RuleSet;
    if (method(PutI32, rule, rule_put_profiles)(rule, s.profiles) < 0) return error.RuleSet;
    if (method(PutI32, rule, rule_put_action)(rule, s.action) < 0) return error.RuleSet;
    if (method(PutStr, rule, rule_put_grouping)(rule, group) < 0) return error.RuleSet;
    if (method(PutBool, rule, rule_put_enabled)(rule, -1) < 0) return error.RuleSet; // VARIANT_TRUE
    if (method(*const fn (*anyopaque, *anyopaque) callconv(.winapi) HRESULT, rules, rules_add)(rules, rule) < 0) return error.RuleAdd;
    return p;
}

/// Removes every rule of that name (administrator only). Returns how many.
pub fn removeAll() !usize {
    if (!windows) return error.Unsupported;
    const com = ComScope.init() orelse return error.ComInit;
    defer com.deinit();
    const rules = openRules() orelse return error.FirewallUnavailable;
    defer release(rules);
    return removeFrom(rules);
}

fn removeFrom(rules: *anyopaque) !usize {
    const name = bstr(rule_name);
    defer w.SysFreeString(name);
    var n: usize = 0;
    // Remove takes one rule of that name per call; bounded, in case a
    // rule cannot be removed (it would be found again).
    while (n < 64) : (n += 1) {
        const r = item(rules) catch |err| switch (err) {
            error.NotFound => return n,
            error.Failed => return error.FirewallUnavailable,
        };
        release(r);
        if (method(PutStr, rules, rules_remove)(rules, name) < 0) return error.RuleRemove;
    }
    return error.RuleRemove;
}

/// This process runs with an administrator's (elevated) token.
pub fn isElevated() bool {
    if (!windows) return false;
    var tok: ?*anyopaque = null;
    if (w.OpenProcessToken(w.GetCurrentProcess(), 0x0008, &tok) == 0) return false; // TOKEN_QUERY
    const t = tok orelse return false;
    defer _ = w.CloseHandle(t);
    var elevated: u32 = 0;
    var len: u32 = 0;
    if (w.GetTokenInformation(t, 20, &elevated, @sizeOf(u32), &len) == 0) return false; // TokenElevation
    return elevated != 0;
}

pub const Elevated = union(enum) {
    /// It ran; its exit code.
    exited: u32,
    /// The administrator prompt was declined (or closed).
    declined,
    /// It could not be started (Win32 error).
    failed: u32,
};

/// Runs `exe params` as administrator through ShellExecuteEx "runas":
/// Windows shows ONE administrator prompt (UAC). Blocks until the program
/// exits (a wait on its process handle, no polling): call it off the UI
/// thread. `hwnd` (optional) owns the prompt. The program runs hidden.
pub fn runElevated(exe: []const u8, params: []const u8, hwnd: ?*anyopaque) Elevated {
    if (!windows) return .{ .failed = 50 }; // ERROR_NOT_SUPPORTED
    var exe_w: [1024:0]u16 = undefined;
    var par_w: [512:0]u16 = undefined;
    const ne = std.unicode.wtf8ToWtf16Le(exe_w[0..1023], exe) catch return .{ .failed = 87 };
    exe_w[ne] = 0;
    const np = std.unicode.wtf8ToWtf16Le(par_w[0..511], params) catch return .{ .failed = 87 };
    par_w[np] = 0;
    const com = ComScope.init();
    defer if (com) |c| c.deinit();
    var info: SHELLEXECUTEINFOW = .{
        .fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        .hwnd = hwnd,
        .lpVerb = std.unicode.utf8ToUtf16LeStringLiteral("runas"),
        .lpFile = exe_w[0..ne :0].ptr,
        .lpParameters = par_w[0..np :0].ptr,
        .nShow = 0, // SW_HIDE
    };
    if (w.ShellExecuteExW(&info) == 0) {
        const e = w.GetLastError();
        return if (e == ERROR_CANCELLED) .declined else .{ .failed = e };
    }
    const h = info.hProcess orelse return .{ .exited = 0 };
    defer _ = w.CloseHandle(h);
    _ = w.WaitForSingleObject(h, INFINITE);
    var code: u32 = 1;
    if (w.GetExitCodeProcess(h, &code) == 0) return .{ .failed = w.GetLastError() };
    return .{ .exited = code };
}

/// This program's own path (WTF-8), for relaunching it.
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

test "firewall: the spec is the documented rule" {
    const s = spec(51820);
    try testing.expectEqualStrings("Portal tunnel (WireGuard)", s.name);
    try testing.expectEqual(@as(i32, 17), s.protocol);
    try testing.expectEqual(@as(u16, 51820), s.local_port);
    try testing.expectEqual(@as(i32, 1), s.direction);
    try testing.expectEqual(@as(i32, 1), s.action);
    try testing.expectEqual(@as(i32, 0x7fffffff), s.profiles);
    try testing.expect(s.enabled);
    var b: [200]u8 = undefined;
    // The same line README and docs/wireguard.md give.
    try testing.expectEqualStrings(
        "New-NetFirewallRule -DisplayName \"Portal tunnel (WireGuard)\" -Direction Inbound -Protocol UDP -LocalPort 51820 -Profile Any -Action Allow",
        manualAdd(&b, 51820),
    );
}

test "firewall: plan is idempotent (already, add, replace)" {
    const s = spec(51820);
    try testing.expectEqual(Plan.add, plan(null, s));
    try testing.expectEqual(Plan.already, plan(obs("51820"), s));
    try testing.expectEqual(Plan.already, plan(obs(" 51820 "), s));
    try testing.expectEqual(Plan.replace, plan(obs("51821"), s));
    try testing.expectEqual(Plan.replace, plan(obs("51820-51830"), s));
    try testing.expectEqual(Plan.replace, plan(obs("*"), s));
    var o = obs("51820");
    o.enabled = false;
    try testing.expectEqual(Plan.replace, plan(o, s));
    o = obs("51820");
    o.action = 0; // block
    try testing.expectEqual(Plan.replace, plan(o, s));
    o = obs("51820");
    o.protocol = 6; // TCP
    try testing.expectEqual(Plan.replace, plan(o, s));
    o = obs("51820");
    o.profiles = 0x4; // public only
    try testing.expectEqual(Plan.replace, plan(o, s));
    o = obs("51820");
    o.has_application = true;
    try testing.expectEqual(Plan.replace, plan(o, s));
    o = obs("51820");
    o.direction = 2; // outbound
    try testing.expectEqual(Plan.replace, plan(o, s));
}

test "firewall: status after a port move names the old port" {
    try testing.expectEqual(Status.present, statusOf(obs("51820"), 51820));
    try testing.expectEqual(Status.missing, statusOf(null, 51820));
    try testing.expectEqual(@as(u16, 51820), statusOf(obs("51820"), 51821).other_port);
    var o = obs("51820");
    o.enabled = false;
    try testing.expectEqual(Status.differs, statusOf(o, 51820));
    try testing.expectEqual(Status.differs, statusOf(o, 51821));
    var b: [200]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, describe(.{ .other_port = 51820 }, 51821, &b), "Replace") != null);
    try testing.expect(std.mem.indexOf(u8, describe(.missing, 51821, &b), "UDP 51821") != null);
}

test "firewall: the elevated child's arguments parse back" {
    var b: [64]u8 = undefined;
    const add = elevatedParams(&b, .add, 51999);
    try testing.expectEqualStrings("firewall add --port 51999 --no-elevate", add);
    var it = std.mem.tokenizeScalar(u8, add, ' ');
    var parts: [8][]const u8 = undefined;
    var n: usize = 0;
    while (it.next()) |t| : (n += 1) parts[n] = t;
    const a = parseArgs(parts[1..n]).?;
    try testing.expect(a.sub == .add and a.port.? == 51999 and a.no_elevate);
    const r = parseArgs(&.{ "remove", "--no-elevate" }).?;
    try testing.expect(r.sub == .remove and r.no_elevate and r.port == null);
    try testing.expect(parseArgs(&.{}) == null);
    try testing.expect(parseArgs(&.{"open"}) == null);
    try testing.expect(parseArgs(&.{ "add", "--port", "0" }) == null);
    try testing.expect(parseArgs(&.{ "add", "--port", "70000" }) == null);
    try testing.expect(parseArgs(&.{ "add", "--port" }) == null);
    try testing.expect(parseArgs(&.{ "status", "--force" }) == null);
}

test "firewall: guid" {
    const g = guid("98325047-c671-4174-8d81-defcd3f03186");
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
    const st = status(51820);
    _ = st;
    _ = isElevated();
}
