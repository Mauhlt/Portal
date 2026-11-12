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

/// waitEvents timeout meaning "no timeout": sleep until input or wake()
/// (equals Win32 INFINITE).
pub const forever: u32 = std.math.maxInt(u32);

pub const Window = switch (builtin.os.tag) {
    .windows => @import("win32.zig").Window,
    .linux, .freebsd, .openbsd, .netbsd => @import("x11.zig").Window,
    .macos => @import("cocoa.zig").Window,
    else => @compileError("unsupported OS"),
};

test {
    if (builtin.os.tag == .windows) _ = @import("win32.zig");
}

/// Simple fixed-size event queue shared by the backends. Other events are
/// dropped on overflow, but `.close` never is: it is kept as a sticky flag
/// and delivered once the queue has drained (so a flood of input cannot
/// make the window unclosable).
pub const Queue = struct {
    items: [256]Event = undefined,
    head: usize = 0,
    len: usize = 0,
    close_pending: bool = false,

    pub fn push(q: *Queue, e: Event) void {
        if (e == .close) {
            q.close_pending = true;
            return;
        }
        if (q.len == q.items.len) return; // drop on overflow
        q.items[(q.head + q.len) % q.items.len] = e;
        q.len += 1;
    }
    pub fn pop(q: *Queue) ?Event {
        if (q.len == 0) {
            if (!q.close_pending) return null;
            q.close_pending = false;
            return .close;
        }
        const e = q.items[q.head];
        q.head = (q.head + 1) % q.items.len;
        q.len -= 1;
        return e;
    }
    /// True if pop() would return an event.
    pub fn pending(q: *const Queue) bool {
        return q.len > 0 or q.close_pending;
    }
};

test "Queue never drops close" {
    var q: Queue = .{};
    var i: usize = 0;
    while (i < 300) : (i += 1) q.push(.expose);
    q.push(.close);
    q.push(.expose);
    try std.testing.expect(q.pending());
    var n: usize = 0;
    var saw_close = false;
    while (q.pop()) |e| {
        if (e == .close) {
            saw_close = true;
        } else n += 1;
    }
    try std.testing.expect(saw_close);
    try std.testing.expectEqual(@as(usize, 256), n);
    try std.testing.expect(!q.pending());
}
