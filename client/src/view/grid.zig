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

/// An image placed on the grid, in cells (docs/protocol.md 'P' frames).
/// `row` is negative when the image has partly scrolled off the top.
pub const Placement = struct {
    id: u32,
    col: u16,
    row: i16,
    cols: u16,
    rows: u16,
};

pub const max_blob_bytes: usize = 6 << 20;
pub const max_blobs: usize = 64;
pub const max_placements: usize = 256;

/// The images of the visible screen: PNG bytes by id (untrusted; decoded
/// by TermView through imgdec) and their placements. Bounded: at most
/// `max_blobs` blobs of `max_blob_bytes`, `max_placements` placements.
pub const Images = struct {
    blobs: std.ArrayList(Blob) = .empty,
    placements: std.ArrayList(Placement) = .empty,
    /// Bumped on every change.
    generation: u64 = 0,

    pub const Blob = struct { id: u32, png: []u8 };

    pub fn deinit(im: *Images, gpa: std.mem.Allocator) void {
        for (im.blobs.items) |b| gpa.free(b.png);
        im.blobs.deinit(gpa);
        im.placements.deinit(gpa);
        im.* = .{};
    }

    pub fn blob(im: *const Images, id: u32) ?[]const u8 {
        for (im.blobs.items) |b| if (b.id == id) return b.png;
        return null;
    }

    /// Stores a copy of `png` under `id` (replacing an older one). Oversized
    /// blobs are refused; when full, the oldest blob goes.
    pub fn putBlob(im: *Images, gpa: std.mem.Allocator, id: u32, png: []const u8) error{ OutOfMemory, TooLarge }!void {
        if (png.len > max_blob_bytes) return error.TooLarge;
        const copy = try gpa.dupe(u8, png);
        errdefer gpa.free(copy);
        im.drop(gpa, id);
        if (im.blobs.items.len >= max_blobs) {
            gpa.free(im.blobs.items[0].png);
            _ = im.blobs.orderedRemove(0);
        }
        try im.blobs.append(gpa, .{ .id = id, .png = copy });
        im.generation +%= 1;
    }

    fn drop(im: *Images, gpa: std.mem.Allocator, id: u32) void {
        for (im.blobs.items, 0..) |b, k| if (b.id == id) {
            gpa.free(b.png);
            _ = im.blobs.orderedRemove(k);
            return;
        };
    }

    /// Replaces the placement list (capped) and, per the protocol's cache
    /// rule, drops every blob it doesn't reference.
    pub fn setPlacements(im: *Images, gpa: std.mem.Allocator, list: []const Placement) error{OutOfMemory}!void {
        const n = @min(list.len, max_placements);
        try im.placements.ensureTotalCapacity(gpa, n);
        im.placements.clearRetainingCapacity();
        im.placements.appendSliceAssumeCapacity(list[0..n]);
        var k: usize = 0;
        while (k < im.blobs.items.len) {
            const id = im.blobs.items[k].id;
            var used = false;
            for (im.placements.items) |p| {
                if (p.id == id) used = true;
            }
            if (used) k += 1 else {
                gpa.free(im.blobs.items[k].png);
                _ = im.blobs.orderedRemove(k);
            }
        }
        im.generation +%= 1;
    }
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
    /// Inline images of the visible screen.
    images: Images = .{},

    pub fn deinit(g: *Grid, gpa: std.mem.Allocator) void {
        gpa.free(g.cells);
        g.images.deinit(gpa);
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

test "images: blobs bounded, dropped when no placement references them" {
    const gpa = testing.allocator;
    var im: Images = .{};
    defer im.deinit(gpa);
    try im.putBlob(gpa, 1, "one");
    try im.putBlob(gpa, 2, "two");
    try im.putBlob(gpa, 1, "uno");
    try testing.expectEqualStrings("uno", im.blob(1).?);
    const big = try gpa.alloc(u8, max_blob_bytes + 1);
    defer gpa.free(big);
    try testing.expectError(error.TooLarge, im.putBlob(gpa, 3, big));
    for (0..max_blobs + 5) |i| try im.putBlob(gpa, @intCast(100 + i), "x");
    try testing.expectEqual(max_blobs, im.blobs.items.len);
    try im.setPlacements(gpa, &.{.{ .id = 110, .col = 0, .row = -1, .cols = 2, .rows = 2 }});
    try testing.expectEqual(@as(usize, 1), im.blobs.items.len);
    try testing.expect(im.blob(110) != null);
    var many: [max_placements + 10]Placement = undefined;
    for (&many) |*p| p.* = .{ .id = 110, .col = 0, .row = 0, .cols = 1, .rows = 1 };
    try im.setPlacements(gpa, &many);
    try testing.expectEqual(max_placements, im.placements.items.len);
}

test "theme resolves sentinels" {
    const t: Theme = .{};
    try testing.expectEqual(t.fg, t.resolveFg(color_default));
    try testing.expectEqual(t.bg, t.resolveBg(color_default));
    try testing.expectEqual(t.bg, t.resolveFg(color_default_bg_as_fg));
    try testing.expectEqual(t.fg, t.resolveBg(color_default_fg_as_bg));
    try testing.expectEqual(Rgb{ 0x12, 0x34, 0x56 }, t.resolveFg(0x00123456));
    try testing.expectEqual(t.fg, t.resolveFg(0xFF000005));
}
