//! The draw list: what one frame of the shared UI looks like, as plain
//! data for a renderer. Commands are drawn in order (later ones on top):
//!
//!   rect    a filled rectangle (colour with alpha)
//!   glyph   one character cell's glyph (terminal cells: style, cell span)
//!   text    a run of UTF-8 text in one font and colour, laid out on the
//!           cell grid of its font (wcwidth), spaces and controls skipped
//!   image   an inline image from an image store, scaled to `disp_w x
//!           disp_h` pixels and clipped to `clip`; when it can't be decoded
//!           the renderer draws a box with its size instead
//!
//! Positions are window pixels (origin top left). Fonts are referenced by
//! index into `fonts` (sizes in device pixels). Text bytes are copied into
//! the list, so it does not borrow from the caller's buffers; image commands
//! point at their store, which must stay valid until the list is drawn.
//! The view module (Presenter) draws it with the Renderer's Instanced2D.

const std = @import("std");
const Font = @import("Font");
const grid = @import("grid.zig");

pub const Metrics = Font.fontset.Metrics;
pub const Style = Font.fontset.Style;
pub const Rgba = [4]u8;

pub fn rgba(c: [3]u8, a: u8) Rgba {
    return .{ c[0], c[1], c[2], a };
}

pub const Rect = struct { x: f32, y: f32, w: f32, h: f32, color: Rgba };

pub const Glyph = struct {
    x: f32,
    y: f32,
    cp: u21,
    /// 1 or 2 cells wide.
    cells: u8 = 1,
    style: Style = .{},
    font: u8,
    color: Rgba,
};

pub const Text = struct {
    x: f32,
    y: f32,
    /// Bytes in DrawList.bytes.
    start: u32,
    len: u32,
    font: u8,
    bold: bool = false,
    color: Rgba,
};

pub const Image = struct {
    store: *const grid.Images,
    id: u32,
    /// Where the whole image goes (before clipping).
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    /// Pixel size to decode and scale to.
    disp_w: u32,
    disp_h: u32,
    /// Visible part: x0, y0, x1, y1.
    clip: [4]f32,
    /// For the placeholder box and its label.
    font: u8,
    placeholder: Rgba,
};

pub const Cmd = union(enum) {
    rect: Rect,
    glyph: Glyph,
    text: Text,
    image: Image,
};

pub const max_fonts = 8;

pub const DrawList = struct {
    cmds: std.ArrayList(Cmd) = .empty,
    bytes: std.ArrayList(u8) = .empty,
    fonts: [max_fonts]Metrics = undefined,
    n_fonts: u8 = 0,
    /// The window's background.
    clear: [3]u8 = .{ 0, 0, 0 },

    pub fn deinit(dl: *DrawList, gpa: std.mem.Allocator) void {
        dl.cmds.deinit(gpa);
        dl.bytes.deinit(gpa);
        dl.* = .{};
    }

    pub fn reset(dl: *DrawList) void {
        dl.cmds.clearRetainingCapacity();
        dl.bytes.clearRetainingCapacity();
        dl.n_fonts = 0;
    }

    /// The index of font metrics `m` (by size), added if new. When the
    /// table is full the last entry is reused (never happens: a frame uses
    /// four sizes).
    pub fn font(dl: *DrawList, m: Metrics) u8 {
        for (dl.fonts[0..dl.n_fonts], 0..) |f, i| if (f.em == m.em) return @intCast(i);
        if (dl.n_fonts == max_fonts) return max_fonts - 1;
        dl.fonts[dl.n_fonts] = m;
        dl.n_fonts += 1;
        return dl.n_fonts - 1;
    }

    pub fn textOf(dl: *const DrawList, t: Text) []const u8 {
        return dl.bytes.items[t.start..][0..t.len];
    }

    pub fn push(dl: *DrawList, gpa: std.mem.Allocator, c: Cmd) void {
        dl.cmds.append(gpa, c) catch {};
    }

    pub fn pushText(dl: *DrawList, gpa: std.mem.Allocator, x: f32, y: f32, s: []const u8, font_i: u8, bold: bool, color: Rgba) void {
        if (s.len == 0) return;
        const start = dl.bytes.items.len;
        dl.bytes.appendSlice(gpa, s) catch return;
        dl.push(gpa, .{ .text = .{ .x = x, .y = y, .start = @intCast(start), .len = @intCast(s.len), .font = font_i, .bold = bold, .color = color } });
    }
};

test "draw list: fonts deduplicated, text copied" {
    const gpa = std.testing.allocator;
    var dl: DrawList = .{};
    defer dl.deinit(gpa);
    const m: Metrics = .{ .em = 13, .cell_w = 8, .cell_h = 16, .baseline = 12, .underline_y = 14, .stroke = 1 };
    const a = dl.font(m);
    try std.testing.expectEqual(a, dl.font(m));
    var buf = "hello".*;
    dl.pushText(gpa, 1, 2, &buf, a, false, .{ 1, 2, 3, 255 });
    buf[0] = 'j';
    try std.testing.expectEqualStrings("hello", dl.textOf(dl.cmds.items[0].text));
}
