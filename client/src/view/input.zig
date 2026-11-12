//! Input types shared by the platform backends, TermView and hosts.
//!
//! Platform code produces `Event`s; TermView handles view-local ones (zoom,
//! close, resize, button clicks) and forwards keyboard input to an
//! `InputSink`. The sink decides what a key means: the remote client turns
//! it into protocol key names ("k:enter", "t:x"); a local terminal host
//! would encode VT bytes for its PTY.

const std = @import("std");

pub const Key = enum {
    enter,
    escape,
    backspace,
    tab,
    up,
    down,
    left,
    right,
    home,
    end,
    page_up,
    page_down,
    delete,
    insert,
    f1,
    f2,
    f3,
    f4,
    f5,
    f6,
    f7,
    f8,
    f9,
    f10,
    f11,
    f12,
};

pub const MouseButton = enum { left, right, middle };

/// Mouse input in grid cells, for hosts (selection, paste). `col`/`row` are
/// clamped to the grid; `inside` is false when the pointer is outside it.
pub const Mouse = struct {
    action: enum { down, move, up },
    button: MouseButton,
    col: u16,
    row: u16,
    inside: bool,
    mods: Mods = .{},
};

pub const Mods = packed struct(u8) {
    ctrl: bool = false,
    shift: bool = false,
    alt: bool = false,
    super: bool = false,
    _: u4 = 0,
};

pub const Event = union(enum) {
    close,
    resize: struct { width: u32, height: u32 },
    /// Device scale changed (moved to another monitor).
    scale: f32,
    expose,
    key: struct { key: Key, mods: Mods },
    /// Typed text. Control characters are never delivered here; Ctrl+letter
    /// arrives as the lowercase letter with `mods.ctrl`.
    char: struct { cp: u21, mods: Mods = .{} },
    mouse_down: struct { x: f32, y: f32, button: MouseButton = .left, mods: Mods = .{} },
    /// Pointer moved; `left_held` while dragging with the left button.
    mouse_move: struct { x: f32, y: f32, left_held: bool = false },
    mouse_up: struct { x: f32, y: f32, button: MouseButton = .left },
    zoom: enum { in, out, reset },
};

/// On-screen answer buttons. `key` uses the protocol key names
/// (docs/protocol.md section 4): digits, "y", "n", "enter", "esc".
pub const Answer = struct { label: []const u8, key: []const u8 };
/// The same buttons, in the same order, as the browser's button row: the
/// shared list in Portal's src/inputrules/send.zig (`answer_buttons`; the
/// view module has no imports, so client/src/keys.zig tests that the two
/// agree).
pub const answers = [_]Answer{
    .{ .label = "Yes", .key = "y" },
    .{ .label = "No", .key = "n" },
    .{ .label = "1", .key = "1" },
    .{ .label = "2", .key = "2" },
    .{ .label = "3", .key = "3" },
    .{ .label = "Esc", .key = "esc" },
    .{ .label = "Enter", .key = "enter" },
};

/// Where TermView sends input. All callbacks run on the UI thread.
pub const InputSink = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        key: *const fn (ctx: *anyopaque, key: Key, mods: Mods) void,
        char: *const fn (ctx: *anyopaque, cp: u21, mods: Mods) void,
        /// An answer-bar button (`Answer.key`).
        answer: *const fn (ctx: *anyopaque, key: []const u8) void,
        /// A message-screen button (`Overlay.button_id`).
        button: *const fn (ctx: *anyopaque, id: u32) void,
        /// The drawable area changed. `cols`/`rows` is how many cells fit at
        /// the current font size, for hosts that size a PTY to the window.
        resized: *const fn (ctx: *anyopaque, width_px: u32, height_px: u32, cols: u16, rows: u16) void,
        /// Mouse input over the grid (optional; the remote client ignores
        /// it). Left-button downs that hit a TermView button are not sent.
        mouse: ?*const fn (ctx: *anyopaque, m: Mouse) void = null,
    };

    pub fn key(s: InputSink, k: Key, m: Mods) void {
        s.vtable.key(s.ctx, k, m);
    }
    pub fn char(s: InputSink, cp: u21, m: Mods) void {
        s.vtable.char(s.ctx, cp, m);
    }
    pub fn answer(s: InputSink, k: []const u8) void {
        s.vtable.answer(s.ctx, k);
    }
    pub fn button(s: InputSink, id: u32) void {
        s.vtable.button(s.ctx, id);
    }
    pub fn resized(s: InputSink, w: u32, h: u32, cols: u16, rows: u16) void {
        s.vtable.resized(s.ctx, w, h, cols, rows);
    }
    pub fn mouse(s: InputSink, m: Mouse) void {
        if (s.vtable.mouse) |f| f(s.ctx, m);
    }
};
