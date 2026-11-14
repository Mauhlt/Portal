//! Local copy of the remote terminal grid, updated from 'G', 'I' and 'P'
//! frames (docs/protocol.md section 3).
//!
//! Decoding is shared/screen.zig, the same decoder the e2e tests use: it
//! validates a whole frame before anything here touches the grid, so a
//! malformed frame changes nothing and returns an error. This file only
//! writes what the decoder yields into the UI's Grid.

const std = @import("std");
const ui = @import("portal_ui");
const screen = @import("shared").screen;
const wcwidth = @import("view").wcwidth;
const grid_mod = ui.grid;
const Grid = grid_mod.Grid;
const Cell = grid_mod.Cell;
const Attrs = grid_mod.Attrs;
const Kind = grid_mod.Kind;
const color_default = grid_mod.color_default;

pub const Error = screen.Error || error{OutOfMemory};

/// Applies one binary 'G' frame payload to `g`.
pub fn apply(g: *Grid, gpa: std.mem.Allocator, payload: []const u8) Error!void {
    const f = try screen.GridFrame.parse(payload);
    const h = f.header;
    if (h.cols != g.cols or h.rows != g.rows) try g.resize(gpa, h.cols, h.rows);
    var rows = f.rows(wcwidth.of);
    while (rows.next()) |row| {
        const cells = g.rowMut(row.index);
        @memset(cells, .{});
        var it = row.cells();
        while (it.next()) |c| {
            const attrs: Attrs = @bitCast(c.attrs);
            if (c.width == 2) {
                cells[c.col] = .{ .cp = c.cp, .kind = .wide, .fg = c.fg, .bg = c.bg, .attrs = attrs };
                cells[c.col + 1] = .{ .cp = ' ', .kind = .continuation, .fg = c.fg, .bg = c.bg, .attrs = attrs };
            } else {
                cells[c.col] = .{ .cp = c.cp, .fg = c.fg, .bg = c.bg, .attrs = attrs };
            }
        }
    }
    g.cursor_x = h.cursor_x;
    g.cursor_y = h.cursor_y;
    g.cursor_visible = h.cursor_visible;
    if (f.complete()) g.complete = true;
    g.generation +%= 1;
}

/// Applies an 'I' frame (an image blob). The bytes are only stored here
/// (bounded); the view validates and decodes them with a bounded allocator.
pub fn applyBlob(g: *Grid, gpa: std.mem.Allocator, p: []const u8) Error!void {
    const b = try screen.parseBlob(p);
    try g.images.putBlob(gpa, b.id, b.png);
    g.generation +%= 1;
}

/// Applies a 'P' frame (the visible screen's placements). Ids without a
/// blob are skipped; blobs no longer listed are dropped (the cache rule).
pub fn applyPlacements(g: *Grid, gpa: std.mem.Allocator, p: []const u8) Error!void {
    var list: [screen.max_placements]screen.Placement = undefined;
    try g.images.setPlacements(gpa, try screen.parsePlacements(p, &list, &g.images));
    g.generation +%= 1;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "image frames: blobs, placements, cache rule, malformed input" {
    const gpa = testing.allocator;
    var g: Grid = .{};
    defer g.deinit(gpa);
    try applyBlob(&g, gpa, "I\x07\x00\x00\x00\x03\x00\x00\x00abc");
    try testing.expectEqualStrings("abc", g.images.blob(7).?);
    // id 7 at (1, -1) 3x2; id 9 has no blob: skipped; zero size: skipped.
    const pf = "P\x03\x00" ++
        "\x07\x00\x00\x00\x01\x00\xff\xff\x03\x00\x02\x00\x00\x00" ++
        "\x09\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00" ++
        "\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00";
    try applyPlacements(&g, gpa, pf);
    try testing.expectEqual(@as(usize, 1), g.images.placements.items.len);
    const p0 = g.images.placements.items[0];
    try testing.expectEqual(@as(i16, -1), p0.row);
    try testing.expectEqual(@as(u16, 3), p0.cols);
    // Empty 'P': the blob is dropped.
    try applyPlacements(&g, gpa, "P\x00\x00");
    try testing.expect(g.images.blob(7) == null);

    // Malformed: wrong lengths, truncations at every point, trailing bytes.
    try testing.expectError(error.Malformed, applyBlob(&g, gpa, "I\x01\x00\x00\x00\x05\x00\x00\x00abc"));
    try testing.expectError(error.Malformed, applyBlob(&g, gpa, "I\x01\x00\x00\x00\x01\x00\x00\x00abc"));
    try testing.expectError(error.Malformed, applyBlob(&g, gpa, "I\x01"));
    for (0..pf.len) |n| try testing.expect(std.meta.isError(applyPlacements(&g, gpa, pf[0..n])));
    try testing.expectError(error.Malformed, applyPlacements(&g, gpa, pf ++ "x"));
}

test "fuzz: random image frames never panic and stay bounded" {
    const gpa = testing.allocator;
    var g: Grid = .{};
    defer g.deinit(gpa);
    var prng: std.Random.DefaultPrng = .init(0x1717);
    const rand = prng.random();
    var buf: [600]u8 = undefined;
    for (0..20000) |_| {
        const n = rand.uintAtMost(usize, buf.len);
        rand.bytes(buf[0..n]);
        if (n > 0) buf[0] = if (rand.boolean()) 'I' else 'P';
        if (n >= 9 and buf[0] == 'I' and rand.boolean()) std.mem.writeInt(u32, buf[5..9], @intCast(n - 9), .little);
        if (n >= 3 and buf[0] == 'P' and rand.boolean()) {
            const k: u16 = @intCast((n - 3) / screen.placement_len);
            std.mem.writeInt(u16, buf[1..3], k, .little);
            _ = applyPlacements(&g, gpa, buf[0 .. 3 + @as(usize, k) * screen.placement_len]) catch {};
            continue;
        }
        if (n >= 5 and rand.uintLessThan(u8, 4) == 0) std.mem.writeInt(u32, buf[1..5], rand.uintAtMost(u32, 8), .little);
        _ = (if (buf[0] == 'I') applyBlob(&g, gpa, buf[0..n]) else applyPlacements(&g, gpa, buf[0..n])) catch {};
        try testing.expect(g.images.blobs.items.len <= grid_mod.max_blobs);
        try testing.expect(g.images.placements.items.len <= grid_mod.max_placements);
    }
}

const FrameBuilder = screen.FrameBuilder;

test "snapshot then diff" {
    const gpa = testing.allocator;
    var g: Grid = .{};
    defer g.deinit(gpa);

    var b: FrameBuilder = .{ .gpa = gpa };
    defer b.deinit();
    try b.header(10, 3, 2, 1, true, 3);
    try b.rowStart(0, 2);
    try b.run(color_default, color_default, 0, "ab");
    try b.run(0x00FF0000, 0x000000FF, 1 | 8, "cd");
    try b.rowStart(1, 1);
    try b.run(color_default, color_default, 0, "\xE4\xB8\xADx"); // 中x
    try b.rowStart(2, 0);
    try apply(&g, gpa, b.buf.items);

    try testing.expectEqual(@as(u16, 10), g.cols);
    try testing.expect(g.complete and g.cursor_visible);
    try testing.expectEqual(@as(u21, 'c'), g.cell(2, 0).cp);
    try testing.expect(g.cell(2, 0).attrs.bold and g.cell(2, 0).attrs.underline);
    try testing.expectEqual(@as(u32, 0x00FF0000), g.cell(3, 0).fg);
    try testing.expectEqual(@as(u21, ' '), g.cell(4, 0).cp);
    try testing.expectEqual(Kind.wide, g.cell(0, 1).kind);
    try testing.expectEqual(Kind.continuation, g.cell(1, 1).kind);
    try testing.expectEqual(@as(u21, 'x'), g.cell(2, 1).cp);

    // Diff: only row 0 changes; row 1 must be preserved.
    b.buf.clearRetainingCapacity();
    try b.header(10, 3, 0, 0, false, 1);
    try b.rowStart(0, 1);
    try b.run(color_default, color_default, 0, "zz");
    const gen = g.generation;
    try apply(&g, gpa, b.buf.items);
    try testing.expectEqual(@as(u21, 'z'), g.cell(1, 0).cp);
    try testing.expectEqual(@as(u21, ' '), g.cell(2, 0).cp); // rest of row cleared
    try testing.expectEqual(@as(u21, 'x'), g.cell(2, 1).cp);
    try testing.expect(!g.cursor_visible and g.generation == gen + 1);

    // Resize.
    b.buf.clearRetainingCapacity();
    try b.header(20, 5, 0, 0, true, 1);
    try b.rowStart(4, 0);
    try apply(&g, gpa, b.buf.items);
    try testing.expectEqual(@as(u16, 20), g.cols);
    try testing.expect(!g.complete);
}

test "overlong runs are clipped, invalid utf8 becomes U+FFFD" {
    const gpa = testing.allocator;
    var g: Grid = .{};
    defer g.deinit(gpa);
    var b: FrameBuilder = .{ .gpa = gpa };
    defer b.deinit();
    try b.header(4, 1, 0, 0, false, 1);
    try b.rowStart(0, 1);
    try b.run(color_default, color_default, 0, "a\xFFbcdefgh\xE4\xB8");
    try apply(&g, gpa, b.buf.items);
    try testing.expectEqual(@as(u21, 'a'), g.cell(0, 0).cp);
    try testing.expectEqual(@as(u21, 0xFFFD), g.cell(1, 0).cp);
    try testing.expectEqual(@as(u21, 'c'), g.cell(3, 0).cp);
}

test "malformed frames are rejected without changing the grid" {
    const gpa = testing.allocator;
    var g: Grid = .{};
    defer g.deinit(gpa);
    var b: FrameBuilder = .{ .gpa = gpa };
    defer b.deinit();
    try b.header(4, 2, 0, 0, false, 1);
    try b.rowStart(0, 1);
    try b.run(color_default, color_default, 0, "ok");
    try apply(&g, gpa, b.buf.items);
    const good = try gpa.dupe(u8, b.buf.items);
    defer gpa.free(good);

    // Every truncation must fail cleanly and leave the grid alone.
    for (0..good.len) |n| {
        try testing.expect(std.meta.isError(apply(&g, gpa, good[0..n])));
        try testing.expectEqual(@as(u21, 'o'), g.cell(0, 0).cp);
    }
    // Row index out of range.
    b.buf.clearRetainingCapacity();
    try b.header(4, 2, 0, 0, false, 1);
    try b.rowStart(2, 0);
    try testing.expectError(error.Malformed, apply(&g, gpa, b.buf.items));
    // Too large.
    b.buf.clearRetainingCapacity();
    try b.header(60000, 60000, 0, 0, false, 0);
    try testing.expectError(error.TooLarge, apply(&g, gpa, b.buf.items));
    // Zero size, trailing garbage, bad cursor flag.
    b.buf.clearRetainingCapacity();
    try b.header(0, 2, 0, 0, false, 0);
    try testing.expectError(error.Malformed, apply(&g, gpa, b.buf.items));
    var extra = try gpa.alloc(u8, good.len + 1);
    defer gpa.free(extra);
    @memcpy(extra[0..good.len], good);
    extra[good.len] = 0;
    try testing.expectError(error.Malformed, apply(&g, gpa, extra));
    extra[9] = 7;
    try testing.expectError(error.Malformed, apply(&g, gpa, extra[0..good.len]));
}

test "fuzz: random frames never panic" {
    const gpa = testing.allocator;
    var g: Grid = .{};
    defer g.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(7);
    const rand = prng.random();
    var buf: [600]u8 = undefined;
    for (0..20000) |_| {
        const n = rand.uintLessThan(usize, buf.len);
        rand.bytes(buf[0..n]);
        if (n > 0) buf[0] = 'G';
        if (n > 12) {
            // Plausible small header so the row walker gets exercised.
            std.mem.writeInt(u16, buf[1..3], rand.intRangeAtMost(u16, 1, 50), .little);
            std.mem.writeInt(u16, buf[3..5], rand.intRangeAtMost(u16, 1, 10), .little);
            buf[9] = rand.uintLessThan(u8, 2);
            std.mem.writeInt(u16, buf[10..12], rand.uintLessThan(u16, 4), .little);
        }
        apply(&g, gpa, buf[0..n]) catch {};
    }
}

