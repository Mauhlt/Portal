//! Platform layer interface. Each backend provides a `Window` with:
//!
//!   init(gpa, title, width, height) !*Window   logical size, scaled by DPI
//!   deinit()
//!   pollEvent() ?Event                         non-blocking
//!   waitEvents(timeout_ms)                     sleep until input, wake() or timeout
//!   wake()                                     thread-safe; ends a waitEvents
//!   framebufferSize() [2]u32                   pixels
//!   scale() f32                                1.0 = 96 dpi
//!   surfaceSource() Renderer.Instanced2D.SurfaceSource
//!   setTitle(utf8)
//!   setLiveCallback(ctx, fn)                   redraw hook while the OS runs a
//!                                              modal resize loop (Win32)
//!
//! Backends: Win32 (tested), X11 via dlopen'ed Xlib, Cocoa via the
//! Objective-C runtime (both compile-checked only).

const std = @import("std");
const builtin = @import("builtin");
const input = @import("../input.zig");

pub const Event = input.Event;

pub const LiveFn = *const fn (ctx: *anyopaque) void;

pub const Window = switch (builtin.os.tag) {
    .windows => @import("win32.zig").Window,
    .linux, .freebsd, .openbsd, .netbsd => @import("x11.zig").Window,
    .macos => @import("cocoa.zig").Window,
    else => @compileError("unsupported OS"),
};

/// Simple fixed-size event queue shared by the backends.
pub const Queue = struct {
    items: [256]Event = undefined,
    head: usize = 0,
    len: usize = 0,

    pub fn push(q: *Queue, e: Event) void {
        if (q.len == q.items.len) return; // drop on overflow
        q.items[(q.head + q.len) % q.items.len] = e;
        q.len += 1;
    }
    pub fn pop(q: *Queue) ?Event {
        if (q.len == 0) return null;
        const e = q.items[q.head];
        q.head = (q.head + 1) % q.items.len;
        q.len -= 1;
        return e;
    }
};
