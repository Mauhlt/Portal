//! The OS side of touch input for the shared UI on Windows (a Surface
//! tablet running `portal connect`, or the desk on a touch screen): what
//! the device offers (`query`, the shell's Touch parameter) and the
//! on-screen touch keyboard (`setVisible`). The iPhone always has a touch
//! screen (`query` says so, for finger-sized targets) and brings its own
//! keyboard (a UITextView over the input slot), so there `setVisible` is a
//! no-op; elsewhere both are.
//!
//! Taps already arrive as clicks: Windows promotes touch to mouse messages
//! for windows that do not register for touch, and the Window module turns
//! those into mouse_down / mouse_up like any click.
//!
//! The keyboard: ITipInvocation::Toggle (CLSID_UIHostNoLaunch) toggles the
//! touch keyboard of the running text input host, and
//! IFrameworkInputPane::Location says whether it is showing, so show and
//! hide only toggle when needed. If the input host is not running
//! (CoCreateInstance fails), TabTip.exe is started, which shows it. All on
//! the UI thread (an STA), only on a focus change: no polling.

const std = @import("std");
const builtin = @import("builtin");
const ui = @import("portal_ui");

const is_windows = builtin.os.tag == .windows;
const is_ios = builtin.os.tag == .ios;

/// What this device offers right now: touch input, and whether no hardware
/// keyboard is attached (a convertible in slate / tablet posture), so the
/// UI offers the on-screen one. Cheap (two GetSystemMetrics): the glue
/// calls it per frame.
pub fn query() ui.shell.Touch {
    // The system keyboard comes with the native text field (the Presenter).
    if (is_ios) return .{ .enabled = true };
    if (!is_windows) return .{};
    const touches = w.GetSystemMetrics(SM_MAXIMUMTOUCHES);
    if (touches <= 0) return .{};
    // 0: slate (no keyboard attached); 1: laptop posture.
    const slate = w.GetSystemMetrics(SM_CONVERTIBLESLATEMODE) == 0;
    return .{ .enabled = true, .on_screen_keyboard = slate };
}

/// Shows or hides the touch keyboard for window `hwnd`.
pub fn setVisible(hwnd: ?*anyopaque, show: bool) void {
    if (!is_windows) return;
    _ = w.CoInitializeEx(null, COINIT_APARTMENTTHREADED);
    if (visible() == show) return;
    var tip: ?*ITipInvocation = null;
    const hr = w.CoCreateInstance(&CLSID_UIHostNoLaunch, null, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER, &IID_ITipInvocation, @ptrCast(&tip));
    if (hr < 0 or tip == null) {
        // No input host yet: starting TabTip shows the keyboard.
        if (show) launchTabTip();
        return;
    }
    const t = tip.?;
    _ = t.vtable.Toggle(t, hwnd);
    _ = t.vtable.Release(t);
}

/// True if the touch keyboard is on screen (false when it can't be told).
fn visible() bool {
    var pane: ?*IFrameworkInputPane = null;
    const hr = w.CoCreateInstance(&CLSID_FrameworkInputPane, null, CLSCTX_INPROC_SERVER, &IID_IFrameworkInputPane, @ptrCast(&pane));
    if (hr < 0 or pane == null) return false;
    const p = pane.?;
    defer _ = p.vtable.Release(p);
    var r: RECT = .{};
    if (p.vtable.Location(p, &r) < 0) return false;
    return r.right > r.left and r.bottom > r.top;
}

fn launchTabTip() void {
    const path = std.unicode.utf8ToUtf16LeStringLiteral("C:\\Program Files\\Common Files\\microsoft shared\\ink\\TabTip.exe");
    _ = w.ShellExecuteW(null, std.unicode.utf8ToUtf16LeStringLiteral("open"), path, null, null, 1);
}

// ------------------------------------------------------------ Win32 / COM

const SM_MAXIMUMTOUCHES = 95;
const SM_CONVERTIBLESLATEMODE = 0x2003;
const COINIT_APARTMENTTHREADED = 0x2;
const CLSCTX_INPROC_SERVER = 0x1;
const CLSCTX_LOCAL_SERVER = 0x4;

const GUID = extern struct { a: u32, b: u16, c: u16, d: [8]u8 };
const RECT = extern struct { left: i32 = 0, top: i32 = 0, right: i32 = 0, bottom: i32 = 0 };
const HRESULT = i32;

const CLSID_UIHostNoLaunch: GUID = .{ .a = 0x4CE576FA, .b = 0x83DC, .c = 0x4F88, .d = .{ 0x95, 0x1C, 0x9D, 0x07, 0x82, 0xB4, 0xE3, 0x76 } };
const IID_ITipInvocation: GUID = .{ .a = 0x37C994E7, .b = 0x432B, .c = 0x4834, .d = .{ 0xA2, 0xF7, 0xDC, 0xE1, 0xF1, 0x3B, 0x83, 0x4B } };
const CLSID_FrameworkInputPane: GUID = .{ .a = 0xD5120AA3, .b = 0x46BA, .c = 0x44C5, .d = .{ 0x82, 0x2D, 0xCA, 0x80, 0x92, 0xC1, 0xFC, 0x72 } };
const IID_IFrameworkInputPane: GUID = .{ .a = 0x5752238B, .b = 0x24F0, .c = 0x495A, .d = .{ 0x82, 0xF1, 0x2F, 0xD5, 0x93, 0x05, 0x67, 0x96 } };

const call: std.builtin.CallingConvention = if (is_windows) .winapi else .c;

const ITipInvocation = extern struct {
    vtable: *const extern struct {
        QueryInterface: *const fn (*ITipInvocation, *const GUID, *?*anyopaque) callconv(call) HRESULT,
        AddRef: *const fn (*ITipInvocation) callconv(call) u32,
        Release: *const fn (*ITipInvocation) callconv(call) u32,
        Toggle: *const fn (*ITipInvocation, ?*anyopaque) callconv(call) HRESULT,
    },
};

const IFrameworkInputPane = extern struct {
    vtable: *const extern struct {
        QueryInterface: *const fn (*IFrameworkInputPane, *const GUID, *?*anyopaque) callconv(call) HRESULT,
        AddRef: *const fn (*IFrameworkInputPane) callconv(call) u32,
        Release: *const fn (*IFrameworkInputPane) callconv(call) u32,
        Advise: *const fn (*IFrameworkInputPane, ?*anyopaque, ?*anyopaque, *u32) callconv(call) HRESULT,
        AdviseWithHWND: *const fn (*IFrameworkInputPane, ?*anyopaque, ?*anyopaque, *u32) callconv(call) HRESULT,
        Unadvise: *const fn (*IFrameworkInputPane, u32) callconv(call) HRESULT,
        Location: *const fn (*IFrameworkInputPane, *RECT) callconv(call) HRESULT,
    },
};

const w = if (is_windows) struct {
    extern "user32" fn GetSystemMetrics(index: i32) callconv(.winapi) i32;
    extern "ole32" fn CoInitializeEx(reserved: ?*anyopaque, flags: u32) callconv(.winapi) HRESULT;
    extern "ole32" fn CoCreateInstance(clsid: *const GUID, outer: ?*anyopaque, ctx: u32, iid: *const GUID, out: *?*anyopaque) callconv(.winapi) HRESULT;
    extern "shell32" fn ShellExecuteW(hwnd: ?*anyopaque, op: ?[*:0]const u16, file: [*:0]const u16, params: ?[*:0]const u16, dir: ?[*:0]const u16, show: i32) callconv(.winapi) ?*anyopaque;
} else struct {};

test "query: touch on iOS (its own keyboard), none off Windows, no keyboard without touch" {
    const t = query();
    if (is_ios) try std.testing.expect(t.enabled and !t.on_screen_keyboard);
    if (!is_windows and !is_ios) try std.testing.expect(!t.enabled);
    if (!t.enabled) try std.testing.expect(!t.on_screen_keyboard);
}
