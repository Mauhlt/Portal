//! Grid snapshot: the plain cell model the shared UI draws in its
//! terminal view. Filled either from
//! remote 'G' frames (../gframe.zig) or from Portal's local src/vt.zig
//! Terminal (src/localgrid.zig). The model mirrors vt.zig: `Kind` = vt `Wide`
//! (narrow/lead/cont), `Attrs` = vt's wire attrs (bold 1, dim 2, italic 4,
//! underline 8, strikethrough 16) with inverse already applied, and colours
//! are 0x00RRGGBB or the vt.zig sentinels below.

const std = @import("std");
/// The wire format's limits (shared/screen.zig), which every client uses.
const screen = @import("shared").screen;
const theme = @import("shared").theme;

pub const max_cols = screen.max_dim;
pub const max_rows = screen.max_dim;

pub const color_default = theme.color_default;
/// Default background used as a foreground (inverse video).
pub const color_default_bg_as_fg = theme.color_default_bg_as_fg;
/// Default foreground used as a background (inverse video).
pub const color_default_fg_as_bg = theme.color_default_fg_as_bg;

pub const Attrs = bitpack struct(u8) {
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
pub const Placement = screen.Placement;

pub const max_blob_bytes = screen.max_blob_bytes;
pub const max_blobs = screen.max_blobs;
pub const max_blob_total_bytes = screen.max_blob_total_bytes;
pub const max_placements = screen.max_placements;

/// The images of the visible screen: PNG bytes by id (untrusted; decoded
/// by the view module through imgdec) and their placements. Bounded: at most
/// `max_blobs` blobs of `max_blob_bytes`, `max_blob_total_bytes` in all,
/// `max_placements` placements.
pub const Images = struct {
    blobs: std.ArrayList(Blob) = .empty,
    placements: std.ArrayList(Placement) = .empty,
    /// Sum of the blobs' sizes.
    total_bytes: usize = 0,
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

    /// Whether a blob is stored under `id` (for screen.parsePlacements).
    pub fn has(im: *const Images, id: u32) bool {
        return im.blob(id) != null;
    }

    /// Stores a copy of `png` under `id` (replacing an older one). Oversized
    /// blobs are refused; when full (count or bytes), the oldest blobs go.
    pub fn putBlob(im: *Images, gpa: std.mem.Allocator, id: u32, png: []const u8) error{ OutOfMemory, TooLarge }!void {
        if (png.len > max_blob_bytes) return error.TooLarge;
        const copy = try gpa.dupe(u8, png);
        errdefer gpa.free(copy);
        for (im.blobs.items, 0..) |b, k| if (b.id == id) {
            im.remove(gpa, k);
            break;
        };
        while (screen.mustEvict(im.blobs.items.len, im.total_bytes, copy.len)) im.remove(gpa, 0);
        try im.blobs.append(gpa, .{ .id = id, .png = copy });
        im.total_bytes += copy.len;
        im.generation +%= 1;
    }

    fn remove(im: *Images, gpa: std.mem.Allocator, k: usize) void {
        im.total_bytes -= im.blobs.items[k].png.len;
        gpa.free(im.blobs.items[k].png);
        _ = im.blobs.orderedRemove(k);
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
            if (used) k += 1 else im.remove(gpa, k);
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

/// Colours are resolved with the theme (shared/theme.zig).
pub const Rgb = theme.Rgb;

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
    try testing.expectEqual(@as(usize, max_blobs), im.total_bytes);
    try im.setPlacements(gpa, &.{.{ .id = 110, .col = 0, .row = -1, .cols = 2, .rows = 2 }});
    try testing.expectEqual(@as(usize, 1), im.blobs.items.len);
    try testing.expect(im.blob(110) != null);
    var many: [max_placements + 10]Placement = undefined;
    for (&many) |*p| p.* = .{ .id = 110, .col = 0, .row = 0, .cols = 1, .rows = 1 };
    try im.setPlacements(gpa, &many);
    try testing.expectEqual(max_placements, im.placements.items.len);
    // The byte budget: eleven 6 MiB blobs do not fit in 64 MiB.
    const six = try gpa.alloc(u8, max_blob_bytes);
    defer gpa.free(six);
    for (0..11) |i| try im.putBlob(gpa, @intCast(1000 + i), six);
    try testing.expect(im.total_bytes <= max_blob_total_bytes);
    try testing.expectEqual(@as(usize, 10), im.blobs.items.len);
    try testing.expect(im.blob(1000) == null and im.blob(1010) != null);
}
