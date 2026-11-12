//! X11 window backend (Linux/BSD). Xlib is loaded at runtime with dlopen
//! (libX11.so.6), so building needs no X11 headers or libraries.
//! Surface: VK_KHR_xlib_surface. Keyboard: XLookupString keysyms, mapped to
//! Unicode for Latin-1 and the 0x01000000+ Unicode keysym range (no input
//! method support yet). HiDPI: Xft.dpi from the resource database.
//!
//! STATUS: compile-checked by cross-compilation only; never run.

const std = @import("std");
const platform = @import("platform.zig");
const input = @import("../input.zig");
const Renderer = @import("Renderer");

const Display = opaque {};
const XWindow = c_ulong;
const Atom = c_ulong;
const KeySym = c_ulong;

const XKeyEvent = extern struct {
    type: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: ?*Display,
    window: XWindow,
    root: XWindow,
    subwindow: XWindow,
    time: c_ulong,
    x: c_int,
    y: c_int,
    x_root: c_int,
    y_root: c_int,
    state: c_uint,
    keycode: c_uint,
    same_screen: c_int,
};
const XButtonEvent = XKeyEvent; // identical layout; `keycode` is `button`
const XConfigureEvent = extern struct {
    type: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: ?*Display,
    event: XWindow,
    window: XWindow,
    x: c_int,
    y: c_int,
    width: c_int,
    height: c_int,
    border_width: c_int,
    above: XWindow,
    override_redirect: c_int,
};
const XClientMessageEvent = extern struct {
    type: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: ?*Display,
    window: XWindow,
    message_type: Atom,
    format: c_int,
    data: [5]c_long,
};
const XEvent = extern union {
    type: c_int,
    key: XKeyEvent,
    button: XButtonEvent,
    configure: XConfigureEvent,
    client: XClientMessageEvent,
    pad: [24]c_long,
};

const KeyPress = 2;
const ButtonPress = 4;
const Expose = 12;
const ConfigureNotify = 22;
const ClientMessage = 33;
const KeyPressMask = 1 << 0;
const ButtonPressMask = 1 << 2;
const ExposureMask = 1 << 15;
const StructureNotifyMask = 1 << 17;
const ShiftMask = 1 << 0;
const ControlMask = 1 << 2;
const Mod1Mask = 1 << 3;
const Mod4Mask = 1 << 6;

const Xlib = struct {
    XOpenDisplay: *const fn (?[*:0]const u8) callconv(.c) ?*Display,
    XCloseDisplay: *const fn (*Display) callconv(.c) c_int,
    XDefaultScreen: *const fn (*Display) callconv(.c) c_int,
    XRootWindow: *const fn (*Display, c_int) callconv(.c) XWindow,
    XBlackPixel: *const fn (*Display, c_int) callconv(.c) c_ulong,
    XCreateSimpleWindow: *const fn (*Display, XWindow, c_int, c_int, c_uint, c_uint, c_uint, c_ulong, c_ulong) callconv(.c) XWindow,
    XDestroyWindow: *const fn (*Display, XWindow) callconv(.c) c_int,
    XSelectInput: *const fn (*Display, XWindow, c_long) callconv(.c) c_int,
    XMapWindow: *const fn (*Display, XWindow) callconv(.c) c_int,
    XStoreName: *const fn (*Display, XWindow, [*:0]const u8) callconv(.c) c_int,
    XInternAtom: *const fn (*Display, [*:0]const u8, c_int) callconv(.c) Atom,
    XSetWMProtocols: *const fn (*Display, XWindow, [*]Atom, c_int) callconv(.c) c_int,
    XPending: *const fn (*Display) callconv(.c) c_int,
    XNextEvent: *const fn (*Display, *XEvent) callconv(.c) c_int,
    XLookupString: *const fn (*XKeyEvent, ?[*]u8, c_int, ?*KeySym, ?*anyopaque) callconv(.c) c_int,
    XConnectionNumber: *const fn (*Display) callconv(.c) c_int,
    XFlush: *const fn (*Display) callconv(.c) c_int,
    XResourceManagerString: *const fn (*Display) callconv(.c) ?[*:0]const u8,
};

var xlib: Xlib = undefined;
var xlib_loaded = false;
var xlib_handle: ?std.DynLib = null;

fn loadXlib() !void {
    if (xlib_loaded) return;
    var lib = std.DynLib.open("libX11.so.6") catch std.DynLib.open("libX11.so") catch return error.X11NotFound;
    inline for (@typeInfo(Xlib).@"struct".field_names, @typeInfo(Xlib).@"struct".field_types) |f_name, f_type| {
        @field(xlib, f_name) = lib.lookup(f_type, f_name) orelse return error.X11SymbolMissing;
    }
    xlib_handle = lib;
    xlib_loaded = true;
}

pub const Window = struct {
    gpa: std.mem.Allocator,
    display: *Display,
    window: XWindow,
    wm_delete: Atom,
    queue: platform.Queue = .{},
    width: u32,
    height: u32,
    dpi_scale: f32 = 1,
    wake_pipe: [2]std.c.fd_t = .{ -1, -1 },
    live_ctx: ?*anyopaque = null,
    live_fn: ?platform.LiveFn = null,

    pub fn init(gpa: std.mem.Allocator, title: []const u8, width: u32, height: u32) !*Window {
        try loadXlib();
        const d = xlib.XOpenDisplay(null) orelse return error.CannotOpenDisplay;
        errdefer _ = xlib.XCloseDisplay(d);
        const screen = xlib.XDefaultScreen(d);
        const sc = xftScale(d);
        const w: u32 = @intFromFloat(@as(f32, @floatFromInt(width)) * sc);
        const h: u32 = @intFromFloat(@as(f32, @floatFromInt(height)) * sc);
        const win = xlib.XCreateSimpleWindow(d, xlib.XRootWindow(d, screen), 0, 0, w, h, 0, xlib.XBlackPixel(d, screen), xlib.XBlackPixel(d, screen));
        if (win == 0) return error.CreateWindowFailed;
        _ = xlib.XSelectInput(d, win, KeyPressMask | ButtonPressMask | ExposureMask | StructureNotifyMask);
        var wm_delete = xlib.XInternAtom(d, "WM_DELETE_WINDOW", 0);
        _ = xlib.XSetWMProtocols(d, win, @ptrCast(&wm_delete), 1);
        const self = try gpa.create(Window);
        self.* = .{ .gpa = gpa, .display = d, .window = win, .wm_delete = wm_delete, .width = w, .height = h, .dpi_scale = sc };
        self.setTitle(title);
        _ = xlib.XMapWindow(d, win);
        _ = xlib.XFlush(d);
        var fds: [2]std.c.fd_t = undefined;
        if (std.c.pipe(&fds) == 0) self.wake_pipe = fds;
        return self;
    }

    pub fn deinit(self: *Window) void {
        _ = xlib.XDestroyWindow(self.display, self.window);
        _ = xlib.XCloseDisplay(self.display);
        for (self.wake_pipe) |fd| {
            if (fd >= 0) _ = std.c.close(fd);
        }
        self.gpa.destroy(self);
    }

    pub fn setLiveCallback(self: *Window, ctx: *anyopaque, f: platform.LiveFn) void {
        self.live_ctx = ctx;
        self.live_fn = f;
    }

    pub fn pollQueued(self: *Window) ?platform.Event {
        return self.queue.pop();
    }

    pub fn pollEvent(self: *Window) ?platform.Event {
        if (self.queue.pop()) |e| return e;
        while (xlib.XPending(self.display) > 0) {
            var ev: XEvent = undefined;
            _ = xlib.XNextEvent(self.display, &ev);
            self.translate(&ev);
            if (self.queue.len > 0) break;
        }
        return self.queue.pop();
    }

    pub fn waitEvents(self: *Window, timeout_ms: u32) void {
        if (self.queue.len > 0 or xlib.XPending(self.display) > 0) return;
        var fds = [_]std.c.pollfd{
            .{ .fd = xlib.XConnectionNumber(self.display), .events = std.c.POLL.IN, .revents = 0 },
            .{ .fd = self.wake_pipe[0], .events = std.c.POLL.IN, .revents = 0 },
        };
        const n: usize = if (self.wake_pipe[0] >= 0) 2 else 1;
        _ = std.c.poll(&fds, @intCast(n), @intCast(@min(timeout_ms, std.math.maxInt(i32))));
        if (n == 2 and fds[1].revents != 0) {
            var buf: [64]u8 = undefined;
            _ = std.c.read(self.wake_pipe[0], &buf, buf.len);
        }
    }

    /// Thread-safe.
    pub fn wake(self: *Window) void {
        if (self.wake_pipe[1] >= 0) _ = std.c.write(self.wake_pipe[1], "w", 1);
    }

    pub fn framebufferSize(self: *const Window) [2]u32 {
        return .{ self.width, self.height };
    }

    pub fn scale(self: *const Window) f32 {
        return self.dpi_scale;
    }

    pub fn surfaceSource(self: *const Window) Renderer.Instanced2D.SurfaceSource {
        return .{ .xlib = .{ .display = self.display, .window = self.window } };
    }

    pub fn setTitle(self: *Window, title: []const u8) void {
        var buf: [256]u8 = undefined;
        // XStoreName is Latin-1; keep it to ASCII.
        var n: usize = 0;
        for (title) |c| {
            if (n == buf.len - 1) break;
            buf[n] = if (c >= 0x20 and c < 0x7f) c else '-';
            n += 1;
        }
        buf[n] = 0;
        _ = xlib.XStoreName(self.display, self.window, buf[0..n :0]);
    }

    fn translate(self: *Window, ev: *XEvent) void {
        switch (ev.type) {
            ClientMessage => if (@as(Atom, @bitCast(ev.client.data[0])) == self.wm_delete) self.queue.push(.close),
            ConfigureNotify => {
                const w: u32 = @intCast(@max(0, ev.configure.width));
                const h: u32 = @intCast(@max(0, ev.configure.height));
                if (w != self.width or h != self.height) {
                    self.width = w;
                    self.height = h;
                    self.queue.push(.{ .resize = .{ .width = w, .height = h } });
                }
            },
            Expose => self.queue.push(.expose),
            ButtonPress => if (ev.button.keycode == 1) self.queue.push(.{ .mouse_down = .{
                .x = @floatFromInt(ev.button.x),
                .y = @floatFromInt(ev.button.y),
            } }),
            KeyPress => self.keyPress(&ev.key),
            else => {},
        }
    }

    fn keyPress(self: *Window, k: *XKeyEvent) void {
        var buf: [32]u8 = undefined;
        var sym: KeySym = 0;
        _ = xlib.XLookupString(k, &buf, buf.len, &sym, null);
        const mods: input.Mods = .{
            .ctrl = k.state & ControlMask != 0,
            .shift = k.state & ShiftMask != 0,
            .alt = k.state & Mod1Mask != 0,
            .super = k.state & Mod4Mask != 0,
        };
        const key: ?input.Key = switch (sym) {
            0xff0d, 0xff8d => .enter,
            0xff1b => .escape,
            0xff08 => .backspace,
            0xff09, 0xfe20 => .tab,
            0xff52 => .up,
            0xff54 => .down,
            0xff51 => .left,
            0xff53 => .right,
            0xff50 => .home,
            0xff57 => .end,
            0xff55 => .page_up,
            0xff56 => .page_down,
            0xffff => .delete,
            else => null,
        };
        if (key) |kk| {
            var m = mods;
            if (sym == 0xfe20) m.shift = true; // ISO_Left_Tab
            return self.queue.push(.{ .key = .{ .key = kk, .mods = m } });
        }
        if (mods.ctrl and !mods.alt) {
            switch (sym) {
                '=', '+', 0xffab => self.queue.push(.{ .zoom = .in }),
                '-', 0xffad => self.queue.push(.{ .zoom = .out }),
                '0' => self.queue.push(.{ .zoom = .reset }),
                'a'...'z' => self.queue.push(.{ .char = .{ .cp = @intCast(sym), .mods = mods } }),
                'A'...'Z' => self.queue.push(.{ .char = .{ .cp = @intCast(sym + 32), .mods = mods } }),
                else => {},
            }
            return;
        }
        const cp: ?u21 = if ((sym >= 0x20 and sym <= 0x7e) or (sym >= 0xa0 and sym <= 0xff))
            @intCast(sym)
        else if (sym >= 0x01000100 and sym <= 0x0110ffff)
            @intCast(sym - 0x01000000)
        else
            null;
        if (cp) |c| self.queue.push(.{ .char = .{ .cp = c } });
    }
};

/// Scale from the Xft.dpi resource (what desktop environments set for HiDPI).
fn xftScale(d: *Display) f32 {
    const rms = xlib.XResourceManagerString(d) orelse return 1;
    const s = std.mem.span(rms);
    const key = "Xft.dpi:";
    const i = std.mem.indexOf(u8, s, key) orelse return 1;
    const rest = s[i + key.len ..];
    const end = std.mem.indexOfAny(u8, rest, "\n\r") orelse rest.len;
    const v = std.mem.trim(u8, rest[0..end], " \t");
    const dpi = std.fmt.parseFloat(f32, v) catch return 1;
    if (dpi < 48 or dpi > 960) return 1;
    return dpi / 96.0;
}
