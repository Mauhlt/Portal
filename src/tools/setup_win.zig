//! portal-setup's Windows calls: HKCU registry (the real setup_lib.Registry),
//! the Start-menu shortcut (IShellLinkW), the PATH change broadcast, the
//! native-architecture check, the dialogs (TaskDialogIndirect, loaded at
//! run time so a program without the comctl32 v6 manifest still starts,
//! falling back to MessageBoxW) and starting programs. Declared here, not
//! in src/win32.zig, because only the installer uses them.

const std = @import("std");
const Allocator = std.mem.Allocator;
const setup_lib = @import("setup_lib.zig");
const w = @import("win32");

const HRESULT = i32;
const HKEY = *anyopaque;
const GUID = extern struct { a: u32, b: u16, c: u16, d: [8]u8 };

extern "advapi32" fn RegCreateKeyExW(key: HKEY, sub: [*:0]const u16, reserved: u32, class: ?[*:0]const u16, options: u32, sam: u32, sa: ?*anyopaque, result: *?HKEY, disposition: ?*u32) callconv(.winapi) i32;
extern "advapi32" fn RegOpenKeyExW(key: HKEY, sub: [*:0]const u16, options: u32, sam: u32, result: *?HKEY) callconv(.winapi) i32;
extern "advapi32" fn RegQueryValueExW(key: HKEY, name: [*:0]const u16, reserved: ?*u32, kind: ?*u32, data: ?[*]u8, size: ?*u32) callconv(.winapi) i32;
extern "advapi32" fn RegSetValueExW(key: HKEY, name: [*:0]const u16, reserved: u32, kind: u32, data: [*]const u8, size: u32) callconv(.winapi) i32;
extern "advapi32" fn RegDeleteValueW(key: HKEY, name: [*:0]const u16) callconv(.winapi) i32;
extern "advapi32" fn RegDeleteTreeW(key: HKEY, sub: ?[*:0]const u16) callconv(.winapi) i32;
extern "advapi32" fn RegCloseKey(key: HKEY) callconv(.winapi) i32;
extern "user32" fn SendMessageTimeoutW(hwnd: ?*anyopaque, msg: u32, wparam: usize, lparam: isize, flags: u32, timeout: u32, result: ?*usize) callconv(.winapi) isize;
extern "kernel32" fn IsWow64Process2(process: *anyopaque, process_machine: *u16, native_machine: *u16) callconv(.winapi) i32;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) *anyopaque;
extern "kernel32" fn LoadLibraryW(name: [*:0]const u16) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn GetProcAddress(module: *anyopaque, name: [*:0]const u8) callconv(.winapi) ?*const anyopaque;
extern "ole32" fn CoCreateInstance(clsid: *const GUID, outer: ?*anyopaque, ctx: u32, iid: *const GUID, out: *?*anyopaque) callconv(.winapi) HRESULT;

/// HKEY_CURRENT_USER: (HKEY)(ULONG_PTR)(LONG)0x80000001, sign-extended.
fn hkcu() HKEY {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, @as(i32, @bitCast(@as(u32, 0x80000001)))))));
}

const KEY_READ: u32 = 0x20019;
const KEY_WRITE: u32 = 0x20006;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const ERROR_FILE_NOT_FOUND: i32 = 2;

fn wide(gpa: Allocator, s: []const u8) ![:0]u16 {
    return std.unicode.wtf8ToWtf16LeAllocZ(gpa, s);
}

// ---------------------------------------------------------------- registry

/// The real HKEY_CURRENT_USER.
pub fn registry() setup_lib.Registry {
    const S = struct {
        var dummy: u8 = 0;
    };
    return .{ .ctx = &S.dummy, .vtable = &.{ .get = regGet, .set = regSet, .deleteValue = regDeleteValue, .deleteKey = regDeleteKey } };
}

fn regGet(_: *anyopaque, gpa: Allocator, key: []const u8, name: []const u8) anyerror!?setup_lib.Value {
    const k = try wide(gpa, key);
    defer gpa.free(k);
    const n = try wide(gpa, name);
    defer gpa.free(n);
    var h: ?HKEY = null;
    const r = RegOpenKeyExW(hkcu(), k, 0, KEY_READ, &h);
    if (r == ERROR_FILE_NOT_FOUND) return null;
    if (r != 0) return error.RegistryOpen;
    defer _ = RegCloseKey(h.?);
    var kind: u32 = 0;
    var size: u32 = 0;
    const q = RegQueryValueExW(h.?, n, null, &kind, null, &size);
    if (q == ERROR_FILE_NOT_FOUND) return null;
    if (q != 0) return error.RegistryRead;
    if (kind == REG_DWORD) {
        var v: u32 = 0;
        size = 4;
        if (RegQueryValueExW(h.?, n, null, null, @ptrCast(&v), &size) != 0) return error.RegistryRead;
        return .{ .dword = v };
    }
    if (kind != REG_SZ and kind != REG_EXPAND_SZ) return error.RegistryType;
    const buf = try gpa.alloc(u16, size / 2 + 1);
    defer gpa.free(buf);
    var got: u32 = @intCast(buf.len * 2);
    if (RegQueryValueExW(h.?, n, null, null, @ptrCast(buf.ptr), &got) != 0) return error.RegistryRead;
    var len: usize = got / 2;
    while (len > 0 and buf[len - 1] == 0) len -= 1;
    const text = try std.unicode.wtf16LeToWtf8Alloc(gpa, buf[0..len]);
    return if (kind == REG_SZ) .{ .sz = text } else .{ .expand_sz = text };
}

fn regSet(_: *anyopaque, key: []const u8, name: []const u8, v: setup_lib.Value) anyerror!void {
    const gpa = std.heap.page_allocator;
    const k = try wide(gpa, key);
    defer gpa.free(k);
    const n = try wide(gpa, name);
    defer gpa.free(n);
    var h: ?HKEY = null;
    if (RegCreateKeyExW(hkcu(), k, 0, null, 0, KEY_WRITE, null, &h, null) != 0) return error.RegistryCreate;
    defer _ = RegCloseKey(h.?);
    switch (v) {
        .dword => |d| if (RegSetValueExW(h.?, n, 0, REG_DWORD, @ptrCast(&d), 4) != 0) return error.RegistryWrite,
        .sz, .expand_sz => |s| {
            const data = try wide(gpa, s);
            defer gpa.free(data);
            const bytes: u32 = @intCast((data.len + 1) * 2);
            if (RegSetValueExW(h.?, n, 0, if (v == .sz) REG_SZ else REG_EXPAND_SZ, @ptrCast(data.ptr), bytes) != 0) return error.RegistryWrite;
        },
    }
}

fn regDeleteValue(_: *anyopaque, key: []const u8, name: []const u8) anyerror!void {
    const gpa = std.heap.page_allocator;
    const k = try wide(gpa, key);
    defer gpa.free(k);
    const n = try wide(gpa, name);
    defer gpa.free(n);
    var h: ?HKEY = null;
    const r = RegOpenKeyExW(hkcu(), k, 0, KEY_WRITE, &h);
    if (r == ERROR_FILE_NOT_FOUND) return;
    if (r != 0) return error.RegistryOpen;
    defer _ = RegCloseKey(h.?);
    const d = RegDeleteValueW(h.?, n);
    if (d != 0 and d != ERROR_FILE_NOT_FOUND) return error.RegistryWrite;
}

fn regDeleteKey(_: *anyopaque, key: []const u8) anyerror!void {
    const gpa = std.heap.page_allocator;
    const k = try wide(gpa, key);
    defer gpa.free(k);
    const r = RegDeleteTreeW(hkcu(), k);
    if (r != 0 and r != ERROR_FILE_NOT_FOUND) return error.RegistryWrite;
}

/// Tells running programs (Explorer, new terminals) that the user's
/// environment changed. Bounded: each window gets at most 5 s.
pub fn broadcastEnvironment() void {
    const HWND_BROADCAST: usize = 0xffff;
    const WM_SETTINGCHANGE: u32 = 0x001A;
    const SMTO_ABORTIFHUNG: u32 = 0x2;
    const env = std.unicode.utf8ToUtf16LeStringLiteral("Environment");
    var result: usize = 0;
    _ = SendMessageTimeoutW(@ptrFromInt(HWND_BROADCAST), WM_SETTINGCHANGE, 0, @bitCast(@intFromPtr(env)), SMTO_ABORTIFHUNG, 5000, &result);
}

// ------------------------------------------------------------ architecture

/// This PC's native processor (an x64 build running under ARM64
/// emulation still sees ARM64).
pub fn nativeArch() setup_lib.Arch {
    var p: u16 = 0;
    var n: u16 = 0;
    if (IsWow64Process2(GetCurrentProcess(), &p, &n) == 0) return .other;
    return setup_lib.archOfMachine(n);
}

// ---------------------------------------------------------------- shortcut

const CLSID_ShellLink: GUID = .{ .a = 0x00021401, .b = 0, .c = 0, .d = .{ 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
const IID_IShellLinkW: GUID = .{ .a = 0x000214F9, .b = 0, .c = 0, .d = .{ 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
const IID_IPersistFile: GUID = .{ .a = 0x0000010b, .b = 0, .c = 0, .d = .{ 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };

fn method(comptime F: type, obj: *anyopaque, index: usize) F {
    const vtbl: *const [*]const *const anyopaque = @ptrCast(@alignCast(obj));
    return @ptrCast(@alignCast(vtbl.*[index]));
}

fn release(obj: *anyopaque) void {
    _ = method(*const fn (*anyopaque) callconv(.winapi) u32, obj, 2)(obj);
}

const SetW = *const fn (*anyopaque, [*:0]const u16) callconv(.winapi) HRESULT;

/// Writes the shortcut `lnk` to `target args` (IShellLinkW + IPersistFile;
/// replaces an existing one). COM must be initialized on this thread.
pub fn writeShortcut(gpa: Allocator, lnk: []const u8, target: []const u8, args: []const u8, desc: []const u8, workdir: []const u8) !void {
    var obj: ?*anyopaque = null;
    if (CoCreateInstance(&CLSID_ShellLink, null, 1, &IID_IShellLinkW, &obj) < 0) return error.ShellLink;
    const sl = obj.?;
    defer release(sl);
    const t = try wide(gpa, target);
    defer gpa.free(t);
    const a = try wide(gpa, args);
    defer gpa.free(a);
    const d = try wide(gpa, desc);
    defer gpa.free(d);
    const wd = try wide(gpa, workdir);
    defer gpa.free(wd);
    if (method(SetW, sl, 20)(sl, t) < 0) return error.ShellLink; // SetPath
    if (method(SetW, sl, 11)(sl, a) < 0) return error.ShellLink; // SetArguments
    if (method(SetW, sl, 7)(sl, d) < 0) return error.ShellLink; // SetDescription
    if (method(SetW, sl, 9)(sl, wd) < 0) return error.ShellLink; // SetWorkingDirectory
    if (method(*const fn (*anyopaque, [*:0]const u16, i32) callconv(.winapi) HRESULT, sl, 17)(sl, t, 0) < 0) return error.ShellLink; // SetIconLocation
    var pf: ?*anyopaque = null;
    if (method(*const fn (*anyopaque, *const GUID, *?*anyopaque) callconv(.winapi) HRESULT, sl, 0)(sl, &IID_IPersistFile, &pf) < 0) return error.ShellLink;
    defer release(pf.?);
    const l = try wide(gpa, lnk);
    defer gpa.free(l);
    if (method(*const fn (*anyopaque, [*:0]const u16, i32) callconv(.winapi) HRESULT, pf.?, 6)(pf.?, l, 1) < 0) return error.ShortcutSave; // Save
}

pub fn coInit() void {
    _ = w.CoInitializeEx(null, 0x2); // apartment threaded
}

// ----------------------------------------------------------------- dialogs

const TASKDIALOG_BUTTON = extern struct {
    nButtonID: i32 align(1),
    pszButtonText: [*:0]const u16 align(1),
};

/// commctrl.h declares it inside #include <pshpack1.h>: byte packed.
const TASKDIALOGCONFIG = extern struct {
    cbSize: u32 align(1) = @sizeOf(TASKDIALOGCONFIG),
    hwndParent: ?*anyopaque align(1) = null,
    hInstance: ?*anyopaque align(1) = null,
    dwFlags: i32 align(1) = 0,
    dwCommonButtons: i32 align(1) = 0,
    pszWindowTitle: ?[*:0]const u16 align(1) = null,
    pszMainIcon: usize align(1) = 0,
    pszMainInstruction: ?[*:0]const u16 align(1) = null,
    pszContent: ?[*:0]const u16 align(1) = null,
    cButtons: u32 align(1) = 0,
    pButtons: ?[*]const TASKDIALOG_BUTTON align(1) = null,
    nDefaultButton: i32 align(1) = 0,
    cRadioButtons: u32 align(1) = 0,
    pRadioButtons: ?*const anyopaque align(1) = null,
    nDefaultRadioButton: i32 align(1) = 0,
    pszVerificationText: ?[*:0]const u16 align(1) = null,
    pszExpandedInformation: ?[*:0]const u16 align(1) = null,
    pszExpandedControlText: ?[*:0]const u16 align(1) = null,
    pszCollapsedControlText: ?[*:0]const u16 align(1) = null,
    pszFooterIcon: usize align(1) = 0,
    pszFooter: ?[*:0]const u16 align(1) = null,
    pfCallback: ?*const anyopaque align(1) = null,
    lpCallbackData: isize align(1) = 0,
    cxWidth: u32 align(1) = 0,
};

comptime {
    if (@sizeOf(usize) == 8 and @sizeOf(TASKDIALOGCONFIG) != 160) @compileError("TASKDIALOGCONFIG layout");
}

const TaskDialogIndirectFn = *const fn (*const TASKDIALOGCONFIG, ?*i32, ?*i32, ?*i32) callconv(.winapi) HRESULT;

fn taskDialogFn() ?TaskDialogIndirectFn {
    const S = struct {
        var looked: bool = false;
        var f: ?TaskDialogIndirectFn = null;
    };
    if (!S.looked) {
        S.looked = true;
        if (LoadLibraryW(std.unicode.utf8ToUtf16LeStringLiteral("comctl32.dll"))) |m|
            if (GetProcAddress(m, "TaskDialogIndirect")) |p| {
                S.f = @ptrCast(@alignCast(p));
            };
    }
    return S.f;
}

pub const Icon = enum { info, warn, err, shield };

fn iconId(i: Icon) usize {
    return switch (i) {
        .warn => 0xFFFF, // TD_WARNING_ICON (MAKEINTRESOURCE(-1))
        .err => 0xFFFE,
        .info => 0xFFFD,
        .shield => 0xFFFC,
    };
}

pub const Button = struct { id: i32, text: []const u8 };

pub const Dialog = struct {
    title: []const u8 = "Portal setup",
    heading: []const u8,
    body: []const u8 = "",
    icon: Icon = .info,
    /// Command links (big buttons with a second line after "\n").
    links: []const Button = &.{},
    /// Plain OK (and Cancel with `cancel`) when there are no links.
    cancel: bool = false,
    default: i32 = 0,
    /// A check box under the buttons; its state is returned in `checked`.
    check: ?[]const u8 = null,
    check_default: bool = false,
    footer: []const u8 = "",
};

pub const Answer = struct {
    /// The link's id, 1 (OK), 2 (Cancel / closed) or 6 / 7 (Yes / No).
    button: i32,
    checked: bool = false,
};

pub const id_ok: i32 = 1;
pub const id_cancel: i32 = 2;

/// Shows `d` and waits for the answer (TaskDialogIndirect; MessageBoxW if
/// comctl32 v6 is not available, where links become Yes / No / Cancel in
/// order).
pub fn show(gpa: Allocator, d: Dialog) Answer {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const W = struct {
        fn z(al: Allocator, s: []const u8) ?[*:0]const u16 {
            if (s.len == 0) return null;
            return (std.unicode.wtf8ToWtf16LeAllocZ(al, s) catch return null).ptr;
        }
    };
    if (taskDialogFn()) |td| {
        var btns: [8]TASKDIALOG_BUTTON = undefined;
        const n = @min(d.links.len, btns.len);
        for (d.links[0..n], 0..) |b, i| btns[i] = .{ .nButtonID = b.id, .pszButtonText = W.z(a, b.text) orelse std.unicode.utf8ToUtf16LeStringLiteral("?") };
        const TDF_ALLOW_DIALOG_CANCELLATION: i32 = 0x8;
        const TDF_USE_COMMAND_LINKS: i32 = 0x10;
        const TDF_VERIFICATION_FLAG_CHECKED: i32 = 0x100;
        const TDCBF_OK_BUTTON: i32 = 0x1;
        const TDCBF_CANCEL_BUTTON: i32 = 0x8;
        var flags: i32 = TDF_ALLOW_DIALOG_CANCELLATION;
        if (n > 0) flags |= TDF_USE_COMMAND_LINKS;
        if (d.check_default) flags |= TDF_VERIFICATION_FLAG_CHECKED;
        var common: i32 = 0;
        if (n == 0) common |= TDCBF_OK_BUTTON;
        if (d.cancel) common |= TDCBF_CANCEL_BUTTON;
        const cfg: TASKDIALOGCONFIG = .{
            .dwFlags = flags,
            .dwCommonButtons = common,
            .pszWindowTitle = W.z(a, d.title),
            .pszMainIcon = iconId(d.icon),
            .pszMainInstruction = W.z(a, d.heading),
            .pszContent = W.z(a, d.body),
            .cButtons = @intCast(n),
            .pButtons = if (n > 0) &btns else null,
            .nDefaultButton = d.default,
            .pszVerificationText = if (d.check) |c| W.z(a, c) else null,
            .pszFooter = W.z(a, d.footer),
        };
        var pressed: i32 = id_cancel;
        var checked: i32 = 0;
        if (td(&cfg, &pressed, null, &checked) >= 0) return .{ .button = pressed, .checked = checked != 0 };
    }
    // Fallback: a message box.
    const text = std.fmt.allocPrint(a, "{s}\n\n{s}{s}{s}", .{ d.heading, d.body, if (d.footer.len > 0) "\n\n" else "", d.footer }) catch d.heading;
    var flags: u32 = switch (d.icon) {
        .warn, .shield => 0x30,
        .err => 0x10,
        .info => 0x40,
    };
    if (d.links.len >= 3) flags |= 0x3 else if (d.links.len == 2) flags |= 0x4 else if (d.cancel) flags |= 0x1;
    const r = w.MessageBoxW(null, W.z(a, text) orelse std.unicode.utf8ToUtf16LeStringLiteral("Portal setup"), W.z(a, d.title) orelse std.unicode.utf8ToUtf16LeStringLiteral("Portal setup"), flags);
    if (d.links.len >= 2) return .{ .button = switch (r) {
        6 => d.links[0].id,
        7 => d.links[1].id,
        else => id_cancel,
    }, .checked = d.check_default };
    return .{ .button = r, .checked = d.check_default };
}

// -------------------------------------------------------- starting programs

/// Starts `exe args` on its own (not waited for, no console); the window
/// of a GUI program comes up in front.
pub fn startDetached(gpa: Allocator, exe: []const u8, args: []const u8, cwd: []const u8) !void {
    const line = try std.fmt.allocPrint(gpa, "\"{s}\"{s}{s}", .{ exe, if (args.len > 0) " " else "", args });
    defer gpa.free(line);
    const line_w = try wide(gpa, line);
    defer gpa.free(line_w);
    const exe_w = try wide(gpa, exe);
    defer gpa.free(exe_w);
    const cwd_w = try wide(gpa, cwd);
    defer gpa.free(cwd_w);
    var si: w.STARTUPINFOW = .{ .cb = @sizeOf(w.STARTUPINFOW) };
    var pi: w.PROCESS_INFORMATION = undefined;
    if (w.CreateProcessW(exe_w, line_w, null, null, 0, 0, null, cwd_w, &si, &pi) == 0) return error.StartFailed;
    _ = w.CloseHandle(pi.hThread);
    _ = w.CloseHandle(pi.hProcess);
}

/// Runs `argv` hidden (no console window) and waits for it: its exit code.
pub fn runHidden(io: std.Io, argv: []const []const u8) !u32 {
    var child = try std.process.spawn(io, .{ .argv = argv, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore, .create_no_window = true });
    errdefer child.kill(io);
    const h: w.HANDLE = @ptrCast(child.id.?);
    _ = w.WaitForSingleObject(h, w.INFINITE);
    var code: w.DWORD = 1;
    const ok = w.GetExitCodeProcess(h, &code) != 0;
    _ = try child.wait(io);
    if (!ok) return error.NoExitCode;
    return code;
}

/// Waits for process `pid` to end (the uninstaller's copy waits for the
/// one that started it, so the folder can be removed). A blocking wait on
/// its handle, no polling.
pub fn waitForPid(pid: u32) void {
    const h = w.OpenProcess(w.SYNCHRONIZE, 0, pid) orelse return;
    _ = w.WaitForSingleObject(h, w.INFINITE);
    _ = w.CloseHandle(h);
}
