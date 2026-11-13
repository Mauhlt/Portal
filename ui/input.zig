//! Input as the shared UI sees it: keys, characters, pointer and wheel
//! events in window pixels. The device's window layer (the view module's
//! Presenter on desk and laptop, a UIKit backend on the iPhone) converts
//! its OS events into these; nothing here depends on a window system.

const std = @import("std");
const rules = @import("inputrules");

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

pub const Mods = packed struct(u8) {
    ctrl: bool = false,
    shift: bool = false,
    alt: bool = false,
    super: bool = false,
    _: u4 = 0,
};

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

/// A press, move or release over a content view (window pixels; `scale`:
/// device pixels per logical pixel), for scrolling and swiping.
pub const Drag = struct {
    phase: enum { down, move, up },
    x: f32,
    y: f32,
    scale: f32 = 1,
};

/// Input that is neither a key nor a pointer: what a device's buttons or
/// shortcuts mean (the shell decides when each applies).
pub const Action = enum {
    /// Start / stop dictation into the instruction line.
    toggle_dictation,
    /// A media play / pause button (a headset's): dictation, only with a
    /// headset microphone attached (Shell.headsetMicPresent).
    media_play_pause,
};

/// On-screen answer buttons: the shared list (module "inputrules"), the
/// same buttons in the same order on every device. `key` is a protocol
/// key name (docs/protocol.md section 4).
pub const Answer = rules.AnswerButton;
pub const answers = rules.answer_buttons;

/// Where the frame's hit-testing sends input. All callbacks run on the UI
/// thread.
pub const InputSink = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        key: *const fn (ctx: *anyopaque, key: Key, mods: Mods) void,
        char: *const fn (ctx: *anyopaque, cp: u21, mods: Mods) void,
        /// An answer-bar button (`Answer.key`).
        answer: *const fn (ctx: *anyopaque, key: []const u8) void,
        /// A button, tab or field, by id.
        button: *const fn (ctx: *anyopaque, id: u32) void,
        /// The drawable area changed. `cols`/`rows` is how many cells fit at
        /// the current font size, for hosts that size a PTY to the window.
        resized: *const fn (ctx: *anyopaque, width_px: u32, height_px: u32, cols: u16, rows: u16) void,
        /// Mouse input over the grid (optional). Left-button downs that hit
        /// a button are not sent.
        mouse: ?*const fn (ctx: *anyopaque, m: Mouse) void = null,
        /// Scroll a content view by `dy` pixels (> 0: towards older content
        /// at the top): the wheel or a drag over it (optional).
        scroll: ?*const fn (ctx: *anyopaque, dy: f32) void = null,
        /// A press over a content view, its moves and its release (optional).
        drag: ?*const fn (ctx: *anyopaque, d: Drag) void = null,
        /// A device action (optional).
        action: ?*const fn (ctx: *anyopaque, a: Action) void = null,
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
    pub fn scroll(s: InputSink, dy: f32) void {
        if (s.vtable.scroll) |f| f(s.ctx, dy);
    }
    pub fn drag(s: InputSink, d: Drag) void {
        if (s.vtable.drag) |f| f(s.ctx, d);
    }
    pub fn action(s: InputSink, a: Action) void {
        if (s.vtable.action) |f| f(s.ctx, a);
    }
};
