//! macOS window backend through the Objective-C runtime. libobjc, AppKit,
//! QuartzCore and Foundation are opened with dlopen and every message is
//! sent through a typed cast of objc_msgSend, so building needs no SDK.
//! Surface: a CAMetalLayer on the content view, for VK_EXT_metal_surface
//! (MoltenVK through the Vulkan loader, or libMoltenVK.dylib directly).
//!
//! No delegate classes are registered: close and resize are detected by
//! polling the window each frame. wake() is a no-op; waitEvents caps its
//! sleep at 50 ms so network updates still appear promptly.
//!
//! STATUS: compile-checked by cross-compilation (aarch64-macos) only; never
//! run. x86_64 macOS would need objc_msgSend_stret for NSRect returns.

const std = @import("std");
const builtin = @import("builtin");
const platform = @import("platform.zig");
const input = @import("../input.zig");
const Renderer = @import("Renderer");

const id = ?*anyopaque;
const SEL = ?*anyopaque;
const NSRect = extern struct { x: f64, y: f64, w: f64, h: f64 };
const NSPoint = extern struct { x: f64, y: f64 };

const Rt = struct {
    objc_getClass: *const fn ([*:0]const u8) callconv(.c) id,
    sel_registerName: *const fn ([*:0]const u8) callconv(.c) SEL,
    objc_msgSend: *const fn () callconv(.c) void,
    objc_autoreleasePoolPush: *const fn () callconv(.c) ?*anyopaque,
    objc_autoreleasePoolPop: *const fn (?*anyopaque) callconv(.c) void,
};

var rt: Rt = undefined;
var rt_loaded = false;
var default_mode: id = null;

fn load() !void {
    if (rt_loaded) return;
    var objc = std.DynLib.open("/usr/lib/libobjc.A.dylib") catch return error.ObjcRuntimeNotFound;
    // Loading the frameworks registers their classes with the runtime.
    _ = std.DynLib.open("/System/Library/Frameworks/AppKit.framework/AppKit") catch return error.AppKitNotFound;
    _ = std.DynLib.open("/System/Library/Frameworks/QuartzCore.framework/QuartzCore") catch return error.QuartzCoreNotFound;
    var foundation = std.DynLib.open("/System/Library/Frameworks/Foundation.framework/Foundation") catch return error.FoundationNotFound;
    inline for (@typeInfo(Rt).@"struct".field_names, @typeInfo(Rt).@"struct".field_types) |f_name, f_type| {
        @field(rt, f_name) = objc.lookup(f_type, f_name) orelse return error.ObjcSymbolMissing;
    }
    const mode_ptr = foundation.lookup(*const id, "NSDefaultRunLoopMode") orelse return error.ObjcSymbolMissing;
    default_mode = mode_ptr.*;
    rt_loaded = true;
}

fn cls(name: [*:0]const u8) id {
    return rt.objc_getClass(name);
}

fn sel(name: [*:0]const u8) SEL {
    return rt.sel_registerName(name);
}

/// objc_msgSend cast to the exact C signature of the method being called.
fn send(comptime Ret: type, target: id, name: [*:0]const u8, args: anytype) Ret {
    const Args = @TypeOf(args);
    const fields = @typeInfo(Args).@"struct".field_types;
    const F = switch (fields.len) {
        0 => *const fn (id, SEL) callconv(.c) Ret,
        1 => *const fn (id, SEL, fields[0]) callconv(.c) Ret,
        2 => *const fn (id, SEL, fields[0], fields[1]) callconv(.c) Ret,
        3 => *const fn (id, SEL, fields[0], fields[1], fields[2]) callconv(.c) Ret,
        4 => *const fn (id, SEL, fields[0], fields[1], fields[2], fields[3]) callconv(.c) Ret,
        else => @compileError("too many arguments"),
    };
    const f: F = @ptrCast(rt.objc_msgSend);
    return @call(.auto, f, .{ target, sel(name) } ++ args);
}

fn nsString(s: []const u8) id {
    var buf: [512]u8 = undefined;
    const z = std.fmt.bufPrintSentinel(&buf, "{s}", .{s}, 0) catch return null;
    return send(id, cls("NSString"), "stringWithUTF8String:", .{@as([*:0]const u8, z.ptr)});
}

const NSEventTypeLeftMouseDown = 1;
const NSEventTypeKeyDown = 10;
const flag_shift: u64 = 1 << 17;
const flag_control: u64 = 1 << 18;
const flag_option: u64 = 1 << 19;
const flag_command: u64 = 1 << 20;

pub const Window = struct {
    gpa: std.mem.Allocator,
    app: id,
    window: id,
    view: id,
    layer: id,
    queue: platform.Queue = .{},
    width: u32 = 0,
    height: u32 = 0,
    backing: f64 = 1,
    closed: bool = false,
    live_ctx: ?*anyopaque = null,
    live_fn: ?platform.LiveFn = null,

    pub fn init(gpa: std.mem.Allocator, title: []const u8, width: u32, height: u32) !*Window {
        if (builtin.cpu.arch != .aarch64) return error.UnsupportedArchitecture;
        try load();
        const pool = rt.objc_autoreleasePoolPush();
        defer rt.objc_autoreleasePoolPop(pool);
        const app = send(id, cls("NSApplication"), "sharedApplication", .{});
        _ = send(bool, app, "setActivationPolicy:", .{@as(i64, 0)}); // regular app
        const rect: NSRect = .{ .x = 200, .y = 200, .w = @floatFromInt(width), .h = @floatFromInt(height) };
        const style: u64 = 1 | 2 | 4 | 8; // titled, closable, miniaturizable, resizable
        const alloc = send(id, cls("NSWindow"), "alloc", .{});
        const window = send(id, alloc, "initWithContentRect:styleMask:backing:defer:", .{ rect, style, @as(u64, 2), false });
        if (window == null) return error.CreateWindowFailed;
        send(void, window, "setReleasedWhenClosed:", .{false});
        send(void, window, "setTitle:", .{nsString(title)});
        const view = send(id, window, "contentView", .{});
        const layer = send(id, cls("CAMetalLayer"), "layer", .{});
        if (layer == null) return error.NoMetalLayer;
        _ = send(id, layer, "retain", .{});
        send(void, view, "setWantsLayer:", .{true});
        send(void, view, "setLayer:", .{layer});
        const backing = send(f64, window, "backingScaleFactor", .{});
        send(void, layer, "setContentsScale:", .{backing});
        send(void, window, "makeKeyAndOrderFront:", .{@as(id, null)});
        send(void, app, "activateIgnoringOtherApps:", .{true});
        send(void, app, "finishLaunching", .{});

        const self = try gpa.create(Window);
        self.* = .{ .gpa = gpa, .app = app, .window = window, .view = view, .layer = layer, .backing = backing };
        self.updateSize(false);
        return self;
    }

    pub fn deinit(self: *Window) void {
        if (!self.closed) send(void, self.window, "close", .{});
        send(void, self.layer, "release", .{});
        send(void, self.window, "release", .{});
        self.gpa.destroy(self);
    }

    pub fn setLiveCallback(self: *Window, ctx: *anyopaque, f: platform.LiveFn) void {
        self.live_ctx = ctx;
        self.live_fn = f;
    }

    pub fn pollQueued(self: *Window) ?platform.Event {
        return self.queue.pop();
    }

    fn updateSize(self: *Window, emit: bool) void {
        const frame = send(NSRect, self.view, "frame", .{});
        const backing = send(f64, self.window, "backingScaleFactor", .{});
        if (backing != self.backing) {
            self.backing = backing;
            send(void, self.layer, "setContentsScale:", .{backing});
            if (emit) self.queue.push(.{ .scale = @floatCast(backing) });
        }
        const w: u32 = @intFromFloat(@max(0, frame.w * backing));
        const h: u32 = @intFromFloat(@max(0, frame.h * backing));
        if (w != self.width or h != self.height) {
            self.width = w;
            self.height = h;
            if (emit) self.queue.push(.{ .resize = .{ .width = w, .height = h } });
        }
    }

    fn pump(self: *Window, wait_s: f64) void {
        const pool = rt.objc_autoreleasePoolPush();
        defer rt.objc_autoreleasePoolPop(pool);
        var until = send(id, cls("NSDate"), "dateWithTimeIntervalSinceNow:", .{wait_s});
        while (true) {
            const ev = send(id, self.app, "nextEventMatchingMask:untilDate:inMode:dequeue:", .{ ~@as(u64, 0), until, default_mode, true });
            if (ev == null) break;
            until = send(id, cls("NSDate"), "distantPast", .{});
            if (!self.translate(ev)) send(void, self.app, "sendEvent:", .{ev});
        }
        send(void, self.app, "updateWindows", .{});
        if (!self.closed and !send(bool, self.window, "isVisible", .{})) {
            self.closed = true;
            self.queue.push(.close);
        }
        self.updateSize(true);
    }

    pub fn pollEvent(self: *Window) ?platform.Event {
        if (self.queue.pop()) |e| return e;
        self.pump(0);
        return self.queue.pop();
    }

    pub fn waitEvents(self: *Window, timeout_ms: u32) void {
        if (self.queue.pending()) return;
        self.pump(@as(f64, @floatFromInt(@min(timeout_ms, 50))) / 1000.0);
    }

    pub fn wake(self: *Window) void {
        _ = self; // see file comment: waitEvents never sleeps longer than 50 ms
    }

    pub fn framebufferSize(self: *const Window) [2]u32 {
        return .{ self.width, self.height };
    }

    pub fn scale(self: *const Window) f32 {
        return @floatCast(self.backing);
    }

    pub fn surfaceSource(self: *const Window) Renderer.Instanced2D.SurfaceSource {
        return .{ .metal = .{ .layer = self.layer.? } };
    }

    pub fn setTitle(self: *Window, title: []const u8) void {
        const pool = rt.objc_autoreleasePoolPush();
        defer rt.objc_autoreleasePoolPop(pool);
        send(void, self.window, "setTitle:", .{nsString(title)});
    }

    /// Returns true if the event was consumed (not forwarded to AppKit).
    fn translate(self: *Window, ev: id) bool {
        const t = send(u64, ev, "type", .{});
        switch (t) {
            NSEventTypeLeftMouseDown => {
                if (send(id, ev, "window", .{}) != self.window) return false;
                const p = send(NSPoint, ev, "locationInWindow", .{});
                const frame = send(NSRect, self.view, "frame", .{});
                self.queue.push(.{ .mouse_down = .{
                    .x = @floatCast(p.x * self.backing),
                    .y = @floatCast((frame.h - p.y) * self.backing),
                } });
                return false;
            },
            NSEventTypeKeyDown => {
                self.keyDown(ev);
                return true;
            },
            else => return false,
        }
    }

    fn keyDown(self: *Window, ev: id) void {
        const flags = send(u64, ev, "modifierFlags", .{});
        const code = send(u16, ev, "keyCode", .{});
        const mods: input.Mods = .{
            .ctrl = flags & flag_control != 0,
            .shift = flags & flag_shift != 0,
            .alt = flags & flag_option != 0,
            .super = flags & flag_command != 0,
        };
        const key: ?input.Key = switch (code) {
            36, 76 => .enter,
            53 => .escape,
            51 => .backspace,
            48 => .tab,
            117 => .delete,
            123 => .left,
            124 => .right,
            125 => .down,
            126 => .up,
            115 => .home,
            119 => .end,
            116 => .page_up,
            121 => .page_down,
            else => null,
        };
        if (key) |k| return self.queue.push(.{ .key = .{ .key = k, .mods = mods } });

        const plain_str = send(id, ev, "charactersIgnoringModifiers", .{});
        const plain: []const u8 = if (plain_str != null) std.mem.span(send([*:0]const u8, plain_str, "UTF8String", .{})) else "";
        if (mods.super or mods.ctrl) {
            if (plain.len == 1) switch (plain[0]) {
                '=', '+' => return self.queue.push(.{ .zoom = .in }),
                '-' => return self.queue.push(.{ .zoom = .out }),
                '0' => return self.queue.push(.{ .zoom = .reset }),
                'q' => if (mods.super) return self.queue.push(.close) else if (mods.ctrl) return self.queue.push(.{ .char = .{ .cp = 'q', .mods = mods } }),
                'a'...'p', 'r'...'z' => if (mods.ctrl) return self.queue.push(.{ .char = .{ .cp = plain[0], .mods = mods } }),
                else => {},
            };
            return;
        }
        const str = send(id, ev, "characters", .{});
        if (str == null) return;
        const text = std.mem.span(send([*:0]const u8, str, "UTF8String", .{}));
        var it = (std.unicode.Utf8View.init(text) catch return).iterator();
        while (it.nextCodepoint()) |cp| {
            if (cp < 0x20 or cp == 0x7f or (cp >= 0xF700 and cp <= 0xF8FF)) continue; // function-key PUA
            self.queue.push(.{ .char = .{ .cp = cp } });
        }
    }
};
