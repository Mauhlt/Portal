//! Win32 window backend. Declares its own minimal user32/kernel32 bindings.

const std = @import("std");
const platform = @import("platform.zig");
const input = @import("../input.zig");
const Renderer = @import("Renderer");

const WINAPI: std.builtin.CallingConvention = .winapi;
const HWND = *opaque {};
const HINSTANCE = *opaque {};
const HCURSOR = *opaque {};
const WPARAM = usize;
const LPARAM = isize;
const LRESULT = isize;
const BOOL = i32;
const UINT = u32;
const DWORD = u32;
const ATOM = u16;

const WNDPROC = *const fn (HWND, UINT, WPARAM, LPARAM) callconv(WINAPI) LRESULT;

const WNDCLASSEXW = extern struct {
    cbSize: UINT = @sizeOf(WNDCLASSEXW),
    style: UINT = 0,
    lpfnWndProc: WNDPROC,
    cbClsExtra: i32 = 0,
    cbWndExtra: i32 = 0,
    hInstance: ?HINSTANCE = null,
    hIcon: ?*anyopaque = null,
    hCursor: ?HCURSOR = null,
    hbrBackground: ?*anyopaque = null,
    lpszMenuName: ?[*:0]const u16 = null,
    lpszClassName: [*:0]const u16,
    hIconSm: ?*anyopaque = null,
};
const POINT = extern struct { x: i32, y: i32 };
const MSG = extern struct {
    hwnd: ?HWND,
    message: UINT,
    wParam: WPARAM,
    lParam: LPARAM,
    time: DWORD,
    pt: POINT,
    lPrivate: DWORD,
};
const RECT = extern struct { left: i32, top: i32, right: i32, bottom: i32 };
const CREATESTRUCTW = extern struct {
    lpCreateParams: ?*anyopaque,
    hInstance: ?HINSTANCE,
    hMenu: ?*anyopaque,
    hwndParent: ?HWND,
    cy: i32,
    cx: i32,
    y: i32,
    x: i32,
    style: i32,
    lpszName: ?[*:0]const u16,
    lpszClass: ?[*:0]const u16,
    dwExStyle: DWORD,
};

extern "user32" fn RegisterClassExW(*const WNDCLASSEXW) callconv(WINAPI) ATOM;
extern "user32" fn CreateWindowExW(DWORD, [*:0]const u16, [*:0]const u16, DWORD, i32, i32, i32, i32, ?HWND, ?*anyopaque, ?HINSTANCE, ?*anyopaque) callconv(WINAPI) ?HWND;
extern "user32" fn DestroyWindow(HWND) callconv(WINAPI) BOOL;
extern "user32" fn DefWindowProcW(HWND, UINT, WPARAM, LPARAM) callconv(WINAPI) LRESULT;
extern "user32" fn ShowWindow(HWND, i32) callconv(WINAPI) BOOL;
extern "user32" fn PeekMessageW(*MSG, ?HWND, UINT, UINT, UINT) callconv(WINAPI) BOOL;
extern "user32" fn TranslateMessage(*const MSG) callconv(WINAPI) BOOL;
extern "user32" fn DispatchMessageW(*const MSG) callconv(WINAPI) LRESULT;
extern "user32" fn PostMessageW(HWND, UINT, WPARAM, LPARAM) callconv(WINAPI) BOOL;
extern "user32" fn GetClientRect(HWND, *RECT) callconv(WINAPI) BOOL;
extern "user32" fn SetWindowLongPtrW(HWND, i32, isize) callconv(WINAPI) isize;
extern "user32" fn GetWindowLongPtrW(HWND, i32) callconv(WINAPI) isize;
extern "user32" fn LoadCursorW(?HINSTANCE, usize) callconv(WINAPI) ?HCURSOR;
extern "user32" fn MsgWaitForMultipleObjectsEx(DWORD, ?*const anyopaque, DWORD, DWORD, DWORD) callconv(WINAPI) DWORD;
extern "user32" fn GetKeyState(i32) callconv(WINAPI) i16;
extern "user32" fn SetWindowPos(HWND, ?HWND, i32, i32, i32, i32, UINT) callconv(WINAPI) BOOL;
extern "user32" fn SetTimer(HWND, usize, UINT, ?*anyopaque) callconv(WINAPI) usize;
extern "user32" fn KillTimer(HWND, usize) callconv(WINAPI) BOOL;
extern "user32" fn SetWindowTextW(HWND, [*:0]const u16) callconv(WINAPI) BOOL;
extern "user32" fn AdjustWindowRectEx(*RECT, DWORD, BOOL, DWORD) callconv(WINAPI) BOOL;
extern "kernel32" fn GetModuleHandleW(?[*:0]const u16) callconv(WINAPI) ?HINSTANCE;
extern "kernel32" fn GetProcAddress(*anyopaque, [*:0]const u8) callconv(WINAPI) ?*anyopaque;
extern "kernel32" fn LoadLibraryA([*:0]const u8) callconv(WINAPI) ?*anyopaque;

const WM_CREATE = 0x0001;
const WM_DESTROY = 0x0002;
const WM_SIZE = 0x0005;
const WM_PAINT = 0x000F;
const WM_CLOSE = 0x0010;
const WM_ERASEBKGND = 0x0014;
const WM_NCCREATE = 0x0081;
const WM_KEYDOWN = 0x0100;
const WM_CHAR = 0x0102;
const WM_SYSKEYDOWN = 0x0104;
const WM_SYSCHAR = 0x0106;
const WM_TIMER = 0x0113;
const WM_MOUSEMOVE = 0x0200;
const WM_LBUTTONDOWN = 0x0201;
const WM_LBUTTONUP = 0x0202;
const WM_RBUTTONDOWN = 0x0204;
const WM_MBUTTONDOWN = 0x0207;
const MK_LBUTTON = 0x0001;
const WM_ENTERSIZEMOVE = 0x0231;
const WM_EXITSIZEMOVE = 0x0232;
const WM_DPICHANGED = 0x02E0;
const WM_APP = 0x8000;
const WS_OVERLAPPEDWINDOW: DWORD = 0x00CF0000;
const CW_USEDEFAULT: i32 = @bitCast(@as(u32, 0x80000000));
const GWLP_USERDATA = -21;
const PM_REMOVE = 1;
const QS_ALLINPUT = 0x04FF;
const MWMO_INPUTAVAILABLE = 0x0004;
const IDC_ARROW: usize = 32512;
const CS_HREDRAW = 0x2;
const CS_VREDRAW = 0x1;
const SWP_NOZORDER = 0x0004;
const SWP_NOACTIVATE = 0x0010;
const VK_SHIFT = 0x10;
const VK_CONTROL = 0x11;
const VK_MENU = 0x12;

const class_name = std.unicode.utf8ToUtf16LeStringLiteral("PortalClientWindow");
var class_registered = false;

pub const Window = struct {
    gpa: std.mem.Allocator,
    hwnd: HWND = undefined,
    hinstance: HINSTANCE = undefined,
    queue: platform.Queue = .{},
    dpi: u32 = 96,
    pending_high: ?u16 = null,
    live_ctx: ?*anyopaque = null,
    live_fn: ?platform.LiveFn = null,
    in_size_move: bool = false,
    closed: bool = false,

    pub fn init(gpa: std.mem.Allocator, title: []const u8, width: u32, height: u32) !*Window {
        enableDpiAwareness();
        const self = try gpa.create(Window);
        errdefer gpa.destroy(self);
        self.* = .{ .gpa = gpa };
        self.hinstance = GetModuleHandleW(null) orelse return error.NoModuleHandle;
        if (!class_registered) {
            const wc: WNDCLASSEXW = .{
                .style = CS_HREDRAW | CS_VREDRAW,
                .lpfnWndProc = wndProc,
                .hInstance = self.hinstance,
                .hCursor = LoadCursorW(null, IDC_ARROW),
                .lpszClassName = class_name,
            };
            if (RegisterClassExW(&wc) == 0) return error.RegisterClassFailed;
            class_registered = true;
        }
        var wtitle: [256:0]u16 = undefined;
        utf16Title(title, &wtitle);
        const hwnd = CreateWindowExW(0, class_name, &wtitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, @intCast(width), @intCast(height), null, null, self.hinstance, self) orelse
            return error.CreateWindowFailed;
        self.hwnd = hwnd;
        self.dpi = windowDpi(hwnd);
        // Resize to the requested logical client size at this monitor's DPI.
        var rect: RECT = .{ .left = 0, .top = 0, .right = @intCast(width * self.dpi / 96), .bottom = @intCast(height * self.dpi / 96) };
        _ = AdjustWindowRectEx(&rect, WS_OVERLAPPEDWINDOW, 0, 0);
        _ = SetWindowPos(hwnd, null, 0, 0, rect.right - rect.left, rect.bottom - rect.top, 0x0002 | SWP_NOZORDER | SWP_NOACTIVATE); // SWP_NOMOVE
        _ = ShowWindow(hwnd, 1);
        return self;
    }

    pub fn deinit(self: *Window) void {
        if (!self.closed) _ = DestroyWindow(self.hwnd);
        self.gpa.destroy(self);
    }

    pub fn setLiveCallback(self: *Window, ctx: *anyopaque, f: platform.LiveFn) void {
        self.live_ctx = ctx;
        self.live_fn = f;
    }

    pub fn pollEvent(self: *Window) ?platform.Event {
        if (self.queue.pop()) |e| return e;
        var msg: MSG = undefined;
        while (PeekMessageW(&msg, null, 0, 0, PM_REMOVE) != 0) {
            _ = TranslateMessage(&msg);
            _ = DispatchMessageW(&msg);
            if (self.queue.pending()) break;
        }
        return self.queue.pop();
    }

    /// Events already queued, without pumping the OS (safe inside callbacks).
    pub fn pollQueued(self: *Window) ?platform.Event {
        return self.queue.pop();
    }

    /// `platform.forever` (= INFINITE) waits with no timeout; wake()'s
    /// posted WM_APP (QS_POSTMESSAGE, part of QS_ALLINPUT) still ends it,
    /// and MWMO_INPUTAVAILABLE makes a message posted before the call
    /// count too, so a wake cannot be lost between pollEvent and here.
    pub fn waitEvents(self: *Window, timeout_ms: u32) void {
        if (self.queue.pending()) return;
        _ = MsgWaitForMultipleObjectsEx(0, null, timeout_ms, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
    }

    /// Safe to call from any thread.
    pub fn wake(self: *Window) void {
        _ = PostMessageW(self.hwnd, WM_APP, 0, 0);
    }

    pub fn framebufferSize(self: *const Window) [2]u32 {
        var r: RECT = undefined;
        if (GetClientRect(self.hwnd, &r) == 0) return .{ 0, 0 };
        return .{ @intCast(@max(0, r.right - r.left)), @intCast(@max(0, r.bottom - r.top)) };
    }

    pub fn scale(self: *const Window) f32 {
        return @as(f32, @floatFromInt(self.dpi)) / 96.0;
    }

    pub fn surfaceSource(self: *const Window) Renderer.Instanced2D.SurfaceSource {
        return .{ .win32 = .{ .hinstance = self.hinstance, .hwnd = self.hwnd } };
    }

    pub fn setTitle(self: *Window, title: []const u8) void {
        var wtitle: [256:0]u16 = undefined;
        utf16Title(title, &wtitle);
        _ = SetWindowTextW(self.hwnd, &wtitle);
    }

    fn handle(self: *Window, hwnd: HWND, msg: UINT, wp: WPARAM, lp: LPARAM) ?LRESULT {
        switch (msg) {
            WM_CLOSE => {
                self.queue.push(.close);
                return 0;
            },
            WM_DESTROY => {
                self.closed = true;
                return 0;
            },
            WM_ERASEBKGND => return 1,
            WM_SIZE => {
                const w: u32 = @intCast(lp & 0xffff);
                const h: u32 = @intCast((lp >> 16) & 0xffff);
                self.queue.push(.{ .resize = .{ .width = w, .height = h } });
                if (self.in_size_move) self.runLive();
                return 0;
            },
            WM_PAINT => {
                // Validate so Windows stops sending WM_PAINT; we redraw ourselves.
                var r: RECT = undefined;
                _ = GetClientRect(hwnd, &r);
                _ = ValidateRect(hwnd, &r);
                self.queue.push(.expose);
                return 0;
            },
            WM_ENTERSIZEMOVE => {
                self.in_size_move = true;
                _ = SetTimer(hwnd, 1, 16, null);
                return 0;
            },
            WM_EXITSIZEMOVE => {
                self.in_size_move = false;
                _ = KillTimer(hwnd, 1);
                return 0;
            },
            WM_TIMER => {
                if (self.in_size_move) self.runLive();
                return 0;
            },
            WM_DPICHANGED => {
                self.dpi = @intCast(wp & 0xffff);
                if (lp != 0) {
                    const r: *const RECT = @ptrFromInt(@as(usize, @bitCast(lp)));
                    _ = SetWindowPos(hwnd, null, r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOZORDER | SWP_NOACTIVATE);
                }
                self.queue.push(.{ .scale = self.scale() });
                return 0;
            },
            WM_LBUTTONDOWN, WM_RBUTTONDOWN, WM_MBUTTONDOWN => {
                const p = mousePos(lp);
                const button: input.MouseButton = switch (msg) {
                    WM_LBUTTONDOWN => .left,
                    WM_RBUTTONDOWN => .right,
                    else => .middle,
                };
                // Keep receiving moves (and the up) while dragging outside.
                if (button == .left) _ = SetCapture(hwnd);
                self.queue.push(.{ .mouse_down = .{ .x = p[0], .y = p[1], .button = button, .mods = currentMods() } });
                return 0;
            },
            WM_LBUTTONUP => {
                const p = mousePos(lp);
                _ = ReleaseCapture();
                self.queue.push(.{ .mouse_up = .{ .x = p[0], .y = p[1] } });
                return 0;
            },
            WM_MOUSEMOVE => {
                // Only drags matter to hosts; plain hovering is not queued.
                if (wp & MK_LBUTTON == 0) return 0;
                const p = mousePos(lp);
                self.queue.push(.{ .mouse_move = .{ .x = p[0], .y = p[1], .left_held = true } });
                return 0;
            },
            WM_SYSCHAR => {
                // Alt+character: deliver it (hosts send ESC + char) instead
                // of letting DefWindowProc beep. Alt+Space still opens the
                // system menu.
                const unit: u16 = @truncate(wp);
                if (unit < 0x20 or unit == ' ' or unit == 0x7f or (unit >= 0xD800 and unit <= 0xDFFF)) return null;
                self.queue.push(.{ .char = .{ .cp = unit, .mods = .{ .alt = true } } });
                return 0;
            },
            WM_KEYDOWN, WM_SYSKEYDOWN => {
                const mods = currentMods();
                if (self.keyDown(@truncate(wp), mods)) return 0;
                return null; // let DefWindowProc handle Alt+F4 etc.
            },
            WM_CHAR => {
                const unit: u16 = @truncate(wp);
                if (unit >= 0xD800 and unit <= 0xDBFF) {
                    self.pending_high = unit;
                    return 0;
                }
                var cp: u21 = unit;
                if (unit >= 0xDC00 and unit <= 0xDFFF) {
                    const hi = self.pending_high orelse return 0;
                    cp = 0x10000 + ((@as(u21, hi) - 0xD800) << 10) + (unit - 0xDC00);
                }
                self.pending_high = null;
                if (cp >= 0x20 and cp != 0x7f) self.queue.push(.{ .char = .{ .cp = cp } });
                return 0;
            },
            WM_APP => return 0,
            else => return null,
        }
    }

    fn runLive(self: *Window) void {
        if (self.live_fn) |f| f(self.live_ctx.?);
    }

    /// Returns true if the key was consumed.
    fn keyDown(self: *Window, vk: u8, mods: input.Mods) bool {
        const key: ?input.Key = switch (vk) {
            0x0D => .enter,
            0x1B => .escape,
            0x08 => .backspace,
            0x09 => .tab,
            0x26 => .up,
            0x28 => .down,
            0x25 => .left,
            0x27 => .right,
            0x24 => .home,
            0x23 => .end,
            0x21 => .page_up,
            0x22 => .page_down,
            0x2E => .delete,
            0x2D => .insert,
            0x70 => .f1,
            0x71 => .f2,
            0x72 => .f3,
            0x73 => .f4,
            0x74 => .f5,
            0x75 => .f6,
            0x76 => .f7,
            0x77 => .f8,
            0x78 => .f9,
            0x79 => .f10,
            0x7A => .f11,
            0x7B => .f12,
            else => null,
        };
        if (key) |k| {
            // Alt+F4 stays with DefWindowProc (closes the window).
            if (k == .f4 and mods.alt) return false;
            self.queue.push(.{ .key = .{ .key = k, .mods = mods } });
            // F-keys are consumed (F10 would otherwise enter menu mode);
            // the others are still translated (their WM_CHAR is filtered).
            return @backingInt(k) >= @backingInt(input.Key.f1);
        }
        if (mods.ctrl and !mods.alt) {
            switch (vk) {
                0xBB, 0x6B => self.queue.push(.{ .zoom = .in }), // '=' / numpad +
                0xBD, 0x6D => self.queue.push(.{ .zoom = .out }),
                0x30, 0x60 => self.queue.push(.{ .zoom = .reset }),
                'A'...'Z' => self.queue.push(.{ .char = .{ .cp = vk + 32, .mods = mods } }),
                // Ctrl+[ \ ] Space / (US layout positions): ESC, FS, GS, NUL, US.
                0xDB => self.queue.push(.{ .char = .{ .cp = '[', .mods = mods } }),
                0xDC => self.queue.push(.{ .char = .{ .cp = '\\', .mods = mods } }),
                0xDD => self.queue.push(.{ .char = .{ .cp = ']', .mods = mods } }),
                0x20 => self.queue.push(.{ .char = .{ .cp = ' ', .mods = mods } }),
                0xBF => self.queue.push(.{ .char = .{ .cp = '/', .mods = mods } }),
                else => return false,
            }
            return true;
        }
        return false;
    }

    // ------------------------------------------------------------ clipboard

    /// Puts UTF-8 text on the clipboard as CF_UNICODETEXT. False on failure
    /// (invalid UTF-8, clipboard busy, out of memory).
    pub fn setClipboardText(self: *Window, utf8: []const u8) bool {
        const units = std.unicode.calcUtf16LeLen(utf8) catch return false;
        const mem = GlobalAlloc(GMEM_MOVEABLE, (units + 1) * 2) orelse return false;
        var handed_over = false;
        defer if (!handed_over) {
            _ = GlobalFree(mem);
        };
        {
            const p = GlobalLock(mem) orelse return false;
            defer _ = GlobalUnlock(mem);
            const dst: [*]align(1) u16 = @ptrCast(p);
            var i: usize = 0;
            var it = (std.unicode.Utf8View.init(utf8) catch return false).iterator();
            while (it.nextCodepoint()) |cp| {
                if (cp >= 0x10000) {
                    if (i + 2 > units) break;
                    const v = cp - 0x10000;
                    dst[i] = @intCast(0xD800 + (v >> 10));
                    dst[i + 1] = @intCast(0xDC00 + (v & 0x3FF));
                    i += 2;
                } else {
                    if (i + 1 > units) break;
                    dst[i] = @intCast(cp);
                    i += 1;
                }
            }
            dst[i] = 0;
        }
        if (OpenClipboard(self.hwnd) == 0) return false;
        defer _ = CloseClipboard();
        if (EmptyClipboard() == 0) return false;
        if (SetClipboardData(CF_UNICODETEXT, mem) == null) return false;
        handed_over = true; // the clipboard owns it now
        return true;
    }

    /// Clipboard text as UTF-8 (unpaired surrogates become U+FFFD), at most
    /// `max_units` UTF-16 units. Caller frees. Null if there is none.
    pub fn clipboardText(self: *Window, gpa: std.mem.Allocator, max_units: usize) ?[]u8 {
        if (OpenClipboard(self.hwnd) == 0) return null;
        defer _ = CloseClipboard();
        const h = GetClipboardData(CF_UNICODETEXT) orelse return null;
        const p = GlobalLock(h) orelse return null;
        defer _ = GlobalUnlock(h);
        const src: [*]align(1) const u16 = @ptrCast(p);
        const cap = @min(GlobalSize(h) / 2, max_units);
        var n: usize = 0;
        while (n < cap and src[n] != 0) n += 1;
        const out = gpa.alloc(u8, n * 3) catch return null;
        var o: usize = 0;
        var i: usize = 0;
        while (i < n) {
            var cp: u21 = 0xFFFD;
            const u = src[i];
            if (u >= 0xD800 and u <= 0xDBFF and i + 1 < n and src[i + 1] >= 0xDC00 and src[i + 1] <= 0xDFFF) {
                cp = 0x10000 + ((@as(u21, u) - 0xD800) << 10) + (src[i + 1] - 0xDC00);
                i += 2;
            } else {
                if (u < 0xD800 or u > 0xDFFF) cp = u;
                i += 1;
            }
            // A 4-byte sequence always comes from 2 units (6 bytes reserved).
            o += std.unicode.utf8Encode(cp, out[o..]) catch 0;
        }
        return gpa.realloc(out, o) catch out[0..o];
    }
};

fn mousePos(lp: LPARAM) [2]f32 {
    const x: i16 = @bitCast(@as(u16, @truncate(@as(usize, @bitCast(lp)))));
    const y: i16 = @bitCast(@as(u16, @truncate(@as(usize, @bitCast(lp)) >> 16)));
    return .{ @floatFromInt(x), @floatFromInt(y) };
}

extern "user32" fn SetCapture(HWND) callconv(WINAPI) ?HWND;
extern "user32" fn ReleaseCapture() callconv(WINAPI) BOOL;
extern "user32" fn OpenClipboard(?HWND) callconv(WINAPI) BOOL;
extern "user32" fn CloseClipboard() callconv(WINAPI) BOOL;
extern "user32" fn EmptyClipboard() callconv(WINAPI) BOOL;
extern "user32" fn SetClipboardData(UINT, ?*anyopaque) callconv(WINAPI) ?*anyopaque;
extern "user32" fn GetClipboardData(UINT) callconv(WINAPI) ?*anyopaque;
extern "kernel32" fn GlobalAlloc(UINT, usize) callconv(WINAPI) ?*anyopaque;
extern "kernel32" fn GlobalLock(*anyopaque) callconv(WINAPI) ?*anyopaque;
extern "kernel32" fn GlobalUnlock(*anyopaque) callconv(WINAPI) BOOL;
extern "kernel32" fn GlobalFree(*anyopaque) callconv(WINAPI) ?*anyopaque;
extern "kernel32" fn GlobalSize(*anyopaque) callconv(WINAPI) usize;
const CF_UNICODETEXT: UINT = 13;
const GMEM_MOVEABLE: UINT = 0x0002;

extern "user32" fn ValidateRect(HWND, ?*const RECT) callconv(WINAPI) BOOL;

fn currentMods() input.Mods {
    return .{
        .ctrl = GetKeyState(VK_CONTROL) < 0,
        .shift = GetKeyState(VK_SHIFT) < 0,
        .alt = GetKeyState(VK_MENU) < 0,
    };
}

fn wndProc(hwnd: HWND, msg: UINT, wp: WPARAM, lp: LPARAM) callconv(WINAPI) LRESULT {
    if (msg == WM_NCCREATE) {
        const cs: *const CREATESTRUCTW = @ptrFromInt(@as(usize, @bitCast(lp)));
        _ = SetWindowLongPtrW(hwnd, GWLP_USERDATA, @bitCast(@intFromPtr(cs.lpCreateParams)));
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
    const ud = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (ud != 0) {
        const self: *Window = @ptrFromInt(@as(usize, @bitCast(ud)));
        if (self.handle(hwnd, msg, wp, lp)) |r| return r;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/// Encodes `title` into `out`, NUL-terminated, truncating at the buffer
/// limit on a code point boundary (a BMP code point takes one unit, an
/// astral one two; a pair never splits). Invalid UTF-8 yields an empty
/// title. The program in the terminal controls the title (OSC 0/2), so this
/// must never write past `out` whatever its length (std's utf8ToUtf16Le
/// does not bounds-check the destination).
pub fn utf16Title(title: []const u8, out: *[256:0]u16) void {
    const cap: usize = out.len; // 256 units; out[256] is the sentinel slot
    var n: usize = 0;
    defer out[n] = 0;
    const v = std.unicode.Utf8View.init(title) catch return;
    var it = v.iterator();
    while (it.nextCodepoint()) |cp| {
        if (cp < 0x10000) {
            if (n + 1 > cap) return;
            out[n] = std.mem.nativeToLittle(u16, @intCast(cp));
            n += 1;
        } else {
            if (n + 2 > cap) return;
            const u = cp - 0x10000;
            out[n] = std.mem.nativeToLittle(u16, @intCast(0xD800 + (u >> 10)));
            out[n + 1] = std.mem.nativeToLittle(u16, @intCast(0xDC00 + (u & 0x3FF)));
            n += 2;
        }
    }
}

test "utf16Title truncates long titles inside the buffer" {
    var title: [600]u8 = undefined;
    @memset(&title, 'A');
    var out: [256:0]u16 = undefined;
    @memset(&out, 0xBEEF);
    utf16Title(&title, &out);
    const n = std.mem.len(@as([*:0]const u16, &out));
    try std.testing.expectEqual(@as(usize, 256), n);
    for (out[0..n]) |u| try std.testing.expectEqual(@as(u16, 'A'), u);
    try std.testing.expectEqual(@as(u16, 0), out[256]);
}

test "utf16Title keeps surrogate pairs whole" {
    // 300 x U+1F600 (4 bytes, 2 units each): 128 fit exactly.
    var title: [300 * 4]u8 = undefined;
    var i: usize = 0;
    while (i < title.len) : (i += 4) _ = try std.unicode.utf8Encode(0x1F600, title[i..][0..4]);
    var out: [256:0]u16 = undefined;
    utf16Title(&title, &out);
    try std.testing.expectEqual(@as(usize, 256), std.mem.len(@as([*:0]const u16, &out)));
    try std.testing.expectEqual(@as(u16, 0xD83D), out[254]);
    try std.testing.expectEqual(@as(u16, 0xDE00), out[255]);

    // One ASCII unit first: the 128th emoji no longer fits and is dropped
    // whole rather than leaving a lone high surrogate.
    var mixed: [1 + 300 * 4]u8 = undefined;
    mixed[0] = 'x';
    @memcpy(mixed[1..], &title);
    utf16Title(&mixed, &out);
    const n = std.mem.len(@as([*:0]const u16, &out));
    try std.testing.expectEqual(@as(usize, 255), n);
    try std.testing.expectEqual(@as(u16, 0xDE00), out[254]);
    const back = try std.unicode.utf16LeToUtf8Alloc(std.testing.allocator, out[0..n]);
    defer std.testing.allocator.free(back);
    try std.testing.expectEqual(@as(usize, 1 + 127 * 4), back.len);
}

test "utf16Title: short, empty and invalid input" {
    var out: [256:0]u16 = undefined;
    utf16Title("h\u{e9}", &out);
    try std.testing.expectEqualSlices(u16, &.{ 'h', 0xE9, 0 }, out[0..3]);
    utf16Title("", &out);
    try std.testing.expectEqual(@as(u16, 0), out[0]);
    utf16Title("ok\xff", &out);
    try std.testing.expectEqual(@as(u16, 0), out[0]);
}

fn enableDpiAwareness() void {
    const user32 = LoadLibraryA("user32.dll") orelse return;
    if (GetProcAddress(user32, "SetProcessDpiAwarenessContext")) |p| {
        const f: *const fn (isize) callconv(WINAPI) BOOL = @ptrCast(p);
        if (f(-4) != 0) return; // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
    }
    if (GetProcAddress(user32, "SetProcessDPIAware")) |p| {
        const f: *const fn () callconv(WINAPI) BOOL = @ptrCast(p);
        _ = f();
    }
}

fn windowDpi(hwnd: HWND) u32 {
    const user32 = LoadLibraryA("user32.dll") orelse return 96;
    const p = GetProcAddress(user32, "GetDpiForWindow") orelse return 96;
    const f: *const fn (HWND) callconv(WINAPI) UINT = @ptrCast(p);
    const d = f(hwnd);
    return if (d == 0) 96 else d;
}
