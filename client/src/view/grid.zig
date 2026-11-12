//! Grid snapshot: the plain cell model TermView draws. Filled either from
//! remote 'G' frames (../gframe.zig) or from Portal's local src/vt.zig
//! Terminal (src/localgrid.zig). The model mirrors vt.zig: `Kind` = vt `Wide`
//! (narrow/lead/cont), `Attrs` = vt's wire attrs (bold 1, dim 2, italic 4,
//! underline 8, strikethrough 16) with inverse already applied, and colours
//! are 0x00RRGGBB or the vt.zig sentinels below.

const std = @import("std");

pub const max_cols = 1000;
pub const max_rows = 1000;

pub const color_default: u32 = 0xFF000000;
/// Default background used as a foreground (inverse video).
pub const color_default_bg_as_fg: u32 = 0xFF000002;
/// Default foreground used as a background (inverse video).
pub const color_default_fg_as_bg: u32 = 0xFF000003;

pub const Attrs = packed struct(u8) {
    bold: bool = false,
    dim: bool = false,
    italic: bool = false,
    underline: bool = false,
    strike: bool = false,
    _: u3 = 0,
};

pub const Kind = enum(u2) { normal, wide, continuation };

pub const Cell = struct {
    cp: u21 = ' ',
    kind: Kind = .normal,
    attrs: Attrs = .{},
    fg: u32 = color_default,
    bg: u32 = color_default,
};

pub const Grid = struct {
    cols: u16 = 0,
    rows: u16 = 0,
    cells: []Cell = &.{},
    cursor_x: u16 = 0,
    cursor_y: u16 = 0,
    cursor_visible: bool = false,
    /// Bump on every change, for redraw detection.
    generation: u64 = 0,
    /// True once every row has been filled for the current size.
    complete: bool = false,

    pub fn deinit(g: *Grid, gpa: std.mem.Allocator) void {
        gpa.free(g.cells);
        g.* = .{};
    }

    pub fn cell(g: *const Grid, x: usize, y: usize) Cell {
        if (x >= g.cols or y >= g.rows) return .{};
        return g.cells[y * g.cols + x];
    }

    pub fn row(g: *const Grid, y: usize) []const Cell {
        if (y >= g.rows) return &.{};
        return g.cells[y * g.cols ..][0..g.cols];
    }

    pub fn rowMut(g: *Grid, y: usize) []Cell {
        if (y >= g.rows) return &.{};
        return g.cells[y * g.cols ..][0..g.cols];
    }

    /// Reallocates to cols x rows (all blank). Sizes are capped.
    pub fn resize(g: *Grid, gpa: std.mem.Allocator, cols: u16, rows: u16) error{ OutOfMemory, TooLarge }!void {
        if (cols > max_cols or rows > max_rows) return error.TooLarge;
        const n = @as(usize, cols) * rows;
        const cells = try gpa.alloc(Cell, n);
        @memset(cells, .{});
        gpa.free(g.cells);
        g.cells = cells;
        g.cols = cols;
        g.rows = rows;
        g.complete = false;
    }
};

// ------------------------------------------------------------------ theme

pub const Rgb = [3]u8;

pub const Theme = struct {
    fg: Rgb = .{ 0xD8, 0xDC, 0xE2 },
    bg: Rgb = .{ 0x16, 0x18, 0x1D },
    cursor: Rgb = .{ 0xE8, 0xB0, 0x4C },
    /// Background of selected cells.
    selection: Rgb = .{ 0x2F, 0x4B, 0x78 },

    fn rgb(v: u32) Rgb {
        return .{ @truncate(v >> 16), @truncate(v >> 8), @truncate(v) };
    }

    pub fn resolveFg(t: Theme, v: u32) Rgb {
        if (v == color_default_bg_as_fg) return t.bg;
        if (v >> 24 != 0) return t.fg; // default, or an unknown sentinel
        return rgb(v);
    }

    pub fn resolveBg(t: Theme, v: u32) Rgb {
        if (v == color_default_fg_as_bg) return t.fg;
        if (v >> 24 != 0) return t.bg;
        return rgb(v);
    }
};


const testing = std.testing;

test "theme resolves sentinels" {
    const t: Theme = .{};
    try testing.expectEqual(t.fg, t.resolveFg(color_default));
    try testing.expectEqual(t.bg, t.resolveBg(color_default));
    try testing.expectEqual(t.bg, t.resolveFg(color_default_bg_as_fg));
    try testing.expectEqual(t.fg, t.resolveBg(color_default_fg_as_bg));
    try testing.expectEqual(Rgb{ 0x12, 0x34, 0x56 }, t.resolveFg(0x00123456));
    try testing.expectEqual(t.fg, t.resolveFg(0xFF000005));
}
