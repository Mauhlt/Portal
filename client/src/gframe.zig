//! Local copy of the remote terminal grid, updated from 'G' frames
//! (docs/protocol.md section 3).
//!
//! Frames come from the network and are untrusted: `apply` validates the
//! whole frame before touching the grid, caps sizes, and returns an error
//! for anything malformed. It never panics on input.


const std = @import("std");
const view = @import("view");
const wcwidth = view.wcwidth;
const grid_mod = view.grid;
const Grid = grid_mod.Grid;
const Cell = grid_mod.Cell;
const Attrs = grid_mod.Attrs;
const Kind = grid_mod.Kind;
const color_default = grid_mod.color_default;

pub const Error = error{ Malformed, TooLarge, OutOfMemory };

/// Applies one binary 'G' frame payload to `g`.
pub fn apply(g: *Grid, gpa: std.mem.Allocator, payload: []const u8) Error!void {
    const hdr = try parseHeader(payload);
    // Pass 1: validate structure without side effects.
    try walk(payload, hdr, null);
    // Pass 2: apply.
    if (hdr.cols != g.cols or hdr.rows != g.rows) try g.resize(gpa, hdr.cols, hdr.rows);
    try walk(payload, hdr, g);
    g.cursor_x = hdr.cursor_x;
    g.cursor_y = hdr.cursor_y;
    g.cursor_visible = hdr.cursor_visible;
    if (hdr.n_rows == hdr.rows) g.complete = true;
    g.generation +%= 1;
}

const Header = struct {
    cols: u16,
    rows: u16,
    cursor_x: u16,
    cursor_y: u16,
    cursor_visible: bool,
    n_rows: u16,
};

const header_len = 1 + 2 * 4 + 1 + 2;

fn rd16(p: []const u8, off: usize) Error!u16 {
    if (off + 2 > p.len) return error.Malformed;
    return std.mem.readInt(u16, p[off..][0..2], .little);
}

fn rd32(p: []const u8, off: usize) Error!u32 {
    if (off + 4 > p.len) return error.Malformed;
    return std.mem.readInt(u32, p[off..][0..4], .little);
}

fn parseHeader(p: []const u8) Error!Header {
    if (p.len < header_len or p[0] != 'G') return error.Malformed;
    const h: Header = .{
        .cols = try rd16(p, 1),
        .rows = try rd16(p, 3),
        .cursor_x = try rd16(p, 5),
        .cursor_y = try rd16(p, 7),
        .cursor_visible = p[9] == 1,
        .n_rows = try rd16(p, 10),
    };
    if (p[9] > 1) return error.Malformed;
    if (h.cols == 0 or h.rows == 0) return error.Malformed;
    if (h.cols > grid_mod.max_cols or h.rows > grid_mod.max_rows) return error.TooLarge;
    if (h.n_rows > h.rows) return error.Malformed;
    return h;
}

/// Walks the rows of a frame. With `grid == null` it only validates.
fn walk(p: []const u8, h: Header, grid: ?*Grid) Error!void {
    var off: usize = header_len;
    var r: usize = 0;
    while (r < h.n_rows) : (r += 1) {
        const row_index = try rd16(p, off);
        const n_runs = try rd16(p, off + 2);
        off += 4;
        if (row_index >= h.rows) return error.Malformed;
        var cells: []Cell = &.{};
        if (grid) |g| {
            cells = g.cells[@as(usize, row_index) * g.cols ..][0..g.cols];
            @memset(cells, .{});
        }
        var col: usize = 0;
        var k: usize = 0;
        while (k < n_runs) : (k += 1) {
            const fg = try rd32(p, off);
            const bg = try rd32(p, off + 4);
            if (off + 8 >= p.len) return error.Malformed;
            const attrs: Attrs = @bitCast(p[off + 8] & 0x1f);
            const text_len = try rd16(p, off + 9);
            off += 11;
            if (off + text_len > p.len) return error.Malformed;
            const text = p[off..][0..text_len];
            off += text_len;
            if (grid == null) continue;
            var i: usize = 0;
            while (i < text.len) {
                const n = std.unicode.utf8ByteSequenceLength(text[i]) catch 0;
                var cp: u21 = 0xFFFD;
                if (n != 0 and i + n <= text.len) {
                    if (std.unicode.utf8Decode(text[i..][0..n])) |c| {
                        cp = c;
                        i += n;
                    } else |_| i += 1;
                } else {
                    i += 1;
                }
                if (cp < 0x20 or (cp >= 0x7f and cp < 0xa0)) cp = 0xFFFD; // no controls
                const w = wcwidth.of(cp);
                if (w == 0) continue; // combining marks: not rendered separately
                if (col >= cells.len) break;
                if (w == 2) {
                    if (col + 1 >= cells.len) {
                        // A wide char in the last column cannot fit; show a blank.
                        cells[col] = .{ .fg = fg, .bg = bg, .attrs = attrs };
                        col += 1;
                        continue;
                    }
                    cells[col] = .{ .cp = cp, .kind = .wide, .fg = fg, .bg = bg, .attrs = attrs };
                    cells[col + 1] = .{ .cp = ' ', .kind = .continuation, .fg = fg, .bg = bg, .attrs = attrs };
                    col += 2;
                } else {
                    cells[col] = .{ .cp = cp, .fg = fg, .bg = bg, .attrs = attrs };
                    col += 1;
                }
            }
        }
    }
    if (off != p.len) return error.Malformed; // trailing bytes
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

/// Test helper that builds frames.
pub const FrameBuilder = struct {
    buf: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,

    pub fn header(b: *FrameBuilder, cols: u16, rows: u16, cx: u16, cy: u16, vis: bool, n_rows: u16) !void {
        try b.buf.append(b.gpa, 'G');
        for ([_]u16{ cols, rows, cx, cy }) |v| try b.int(u16, v);
        try b.buf.append(b.gpa, @intFromBool(vis));
        try b.int(u16, n_rows);
    }
    pub fn rowStart(b: *FrameBuilder, index: u16, n_runs: u16) !void {
        try b.int(u16, index);
        try b.int(u16, n_runs);
    }
    pub fn run(b: *FrameBuilder, fg: u32, bg: u32, attrs: u8, text: []const u8) !void {
        try b.int(u32, fg);
        try b.int(u32, bg);
        try b.buf.append(b.gpa, attrs);
        try b.int(u16, @intCast(text.len));
        try b.buf.appendSlice(b.gpa, text);
    }
    fn int(b: *FrameBuilder, comptime T: type, v: T) !void {
        var tmp: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &tmp, v, .little);
        try b.buf.appendSlice(b.gpa, &tmp);
    }
    pub fn deinit(b: *FrameBuilder) void {
        b.buf.deinit(b.gpa);
    }
};

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

