//! Decoder for the server's binary screen frames (docs/protocol.md section
//! 3), shared by both clients: the native viewer (client/src/gframe.zig)
//! and the browser (src/wasm/proto.zig). Each client only writes what this
//! yields into its own grid; the encoder is src/vt.zig `encodeRows` and
//! src/vt_gfx.zig.
//!
//!   'G'  grid rows      `GridFrame.parse` validates the whole frame, then
//!                       `rows()` / `Row.cells()` iterate it cell by cell
//!   'I'  image blob     `parseBlob`
//!   'P'  placements     `parsePlacements`
//!
//! Frames come from the network and are untrusted. Nothing here panics,
//! overflows or reads out of bounds on any input (a trap in wasm kills the
//! page). The rules are strict, and the same in every client:
//!
//!   * A malformed frame is rejected whole, before anything is applied: a
//!     truncation, trailing bytes, a row index outside the grid, a size of
//!     zero or over `max_dim`, a cursor flag other than 0 or 1.
//!   * Text is decoded leniently: an invalid or truncated UTF-8 sequence
//!     becomes one U+FFFD; so do C0/C1 control characters (the server never
//!     sends them; a client must never pass one to a renderer).
//!   * Zero-width code points are skipped; a wide character that does not
//!     fit in the last column becomes a blank; text past the last column is
//!     clipped.
//!   * Placements with a zero or oversized size, or naming an image the
//!     client holds no blob for, are skipped; at most `max_placements` are
//!     kept.
//!
//! Client-side image limits (`max_blob_bytes`, `max_blobs`,
//! `max_blob_total_bytes`, `mustEvict`) are the server's own, so a client
//! never needs more than the server keeps.

const std = @import("std");

/// The server clamps its terminal to this (src/vt.zig `max_dim`), so any
/// bigger size is bogus.
pub const max_dim: u16 = 1000;
/// Bits of the `attrs` byte the protocol defines (bold, dim, italic,
/// underline, strikethrough). Others are ignored.
pub const attr_mask: u8 = 0x1f;
pub const attr_bold: u8 = 1;
pub const attr_dim: u8 = 2;
pub const attr_italic: u8 = 4;
pub const attr_underline: u8 = 8;
pub const attr_strike: u8 = 16;

/// Largest blob ('I' frame) a client stores: the server's limit too
/// (client/src/image/imgcheck.zig `max_file_bytes`).
pub const max_blob_bytes: usize = 6 << 20;
/// Most blobs, and most bytes in all, a client keeps: what the server holds
/// (src/vt_gfx.zig `max_images`, `max_total_bytes`).
pub const max_blobs: usize = 64;
pub const max_blob_total_bytes: usize = 64 << 20;
/// Most placements kept from one 'P' frame (src/vt_gfx.zig
/// `max_placements`: the server never sends more).
pub const max_placements: usize = 256;

pub const Error = error{
    /// Not a well-formed frame of its type.
    Malformed,
    /// Well-formed but over a limit (grid size, blob size).
    TooLarge,
};

pub const Kind = enum { grid, blob, placements, unknown };

/// The type of a binary frame. Clients must ignore unknown types (new ones
/// may be added); an empty frame is unknown too.
pub fn kind(frame: []const u8) Kind {
    if (frame.len == 0) return .unknown;
    return switch (frame[0]) {
        'G' => .grid,
        'I' => .blob,
        'P' => .placements,
        else => .unknown,
    };
}

// ------------------------------------------------------------------ 'G'

pub const Header = struct {
    cols: u16,
    rows: u16,
    /// Clamped into the grid.
    cursor_x: u16,
    cursor_y: u16,
    cursor_visible: bool,
    /// Rows included in this frame.
    n_rows: u16,
};

pub const header_len = 1 + 2 * 4 + 1 + 2;
const row_header_len = 4;
const run_header_len = 4 + 4 + 1 + 2;

/// A validated 'G' frame.
pub const GridFrame = struct {
    header: Header,
    /// The rows after the header.
    body: []const u8,

    /// Validates the whole frame. Nothing is applied by parsing, so a
    /// client that parses first never applies part of a bad frame.
    pub fn parse(frame: []const u8) Error!GridFrame {
        var r: Reader = .{ .b = frame };
        if (try r.int(u8) != 'G') return error.Malformed;
        const grid_cols = try r.int(u16);
        const grid_rows = try r.int(u16);
        const cx = try r.int(u16);
        const cy = try r.int(u16);
        const visible = try r.int(u8);
        const n_rows = try r.int(u16);
        if (visible > 1) return error.Malformed;
        if (grid_cols == 0 or grid_rows == 0) return error.Malformed;
        if (grid_cols > max_dim or grid_rows > max_dim) return error.TooLarge;
        if (n_rows > grid_rows) return error.Malformed;
        const body = frame[header_len..];
        for (0..n_rows) |_| {
            if (try r.int(u16) >= grid_rows) return error.Malformed;
            const n_runs = try r.int(u16);
            for (0..n_runs) |_| {
                _ = try r.bytes(run_header_len - 2);
                _ = try r.bytes(try r.int(u16));
            }
        }
        if (!r.done()) return error.Malformed; // trailing bytes
        return .{
            .header = .{
                .cols = grid_cols,
                .rows = grid_rows,
                .cursor_x = @min(cx, grid_cols - 1),
                .cursor_y = @min(cy, grid_rows - 1),
                .cursor_visible = visible == 1,
                .n_rows = n_rows,
            },
            .body = body,
        };
    }

    /// True when the frame carries every row: a full snapshot (rows are
    /// never repeated by the server).
    pub fn complete(f: *const GridFrame) bool {
        return f.header.n_rows == f.header.rows;
    }

    /// The frame's rows, in order. `width` gives a code point's cell width
    /// (0, 1 or 2); both clients use a copy of the server's table
    /// (src/vt_width.zig).
    pub fn rows(f: *const GridFrame, width: *const fn (u21) u2) RowIterator {
        return .{ .r = .{ .b = f.body }, .left = f.header.n_rows, .cols = f.header.cols, .width = width };
    }
};

pub const RowIterator = struct {
    r: Reader,
    left: u16,
    cols: u16,
    width: *const fn (u21) u2,

    pub fn next(it: *RowIterator) ?Row {
        if (it.left == 0) return null;
        it.left -= 1;
        // The frame was validated, so these reads cannot fail; if they did
        // anyway, iteration just stops.
        const index = it.r.int(u16) catch return null;
        const n_runs = it.r.int(u16) catch return null;
        const start = it.r.i;
        for (0..n_runs) |_| {
            _ = it.r.bytes(run_header_len - 2) catch return null;
            _ = it.r.bytes(it.r.int(u16) catch return null) catch return null;
        }
        return .{ .index = index, .runs = it.r.b[start..it.r.i], .n_runs = n_runs, .cols = it.cols, .width = it.width };
    }
};

/// One row of a frame: it replaces the whole grid row; cells not yielded
/// by `cells()` are blank with default colours.
pub const Row = struct {
    index: u16,
    runs: []const u8,
    n_runs: u16,
    cols: u16,
    width: *const fn (u21) u2,

    pub fn cells(row: Row) CellIterator {
        return .{ .r = .{ .b = row.runs }, .runs_left = row.n_runs, .cols = row.cols, .width = row.width };
    }
};

/// One cell to write. A `width` 2 cell also covers column `col + 1` (the
/// continuation half), which is always inside the row.
pub const Cell = struct {
    col: u16,
    cp: u21,
    width: u2,
    fg: u32,
    bg: u32,
    attrs: u8,
};

pub const CellIterator = struct {
    r: Reader,
    runs_left: u16,
    cols: u16,
    width: *const fn (u21) u2,
    col: u16 = 0,
    text: Utf8Iterator = .{ .s = "" },
    fg: u32 = 0,
    bg: u32 = 0,
    attrs: u8 = 0,

    pub fn next(it: *CellIterator) ?Cell {
        while (it.col < it.cols) {
            const cp0 = it.text.next() orelse {
                if (!it.nextRun()) return null;
                continue;
            };
            // No control characters reach a renderer.
            const cp: u21 = if (cp0 < 0x20 or (cp0 >= 0x7f and cp0 < 0xa0)) 0xFFFD else cp0;
            const w = it.width(cp);
            if (w == 0) continue; // combining marks: the server drops them too
            const cell: Cell = .{ .col = it.col, .cp = cp, .width = 1, .fg = it.fg, .bg = it.bg, .attrs = it.attrs };
            if (w == 2 and it.cols - it.col >= 2) {
                it.col += 2;
                var wide = cell;
                wide.width = 2;
                return wide;
            }
            it.col += 1;
            if (w == 2) {
                // A wide character in the last column cannot fit: a blank,
                // never half a glyph.
                var blank = cell;
                blank.cp = ' ';
                return blank;
            }
            return cell;
        }
        return null; // clipped: the rest of the row's text is dropped
    }

    fn nextRun(it: *CellIterator) bool {
        if (it.runs_left == 0) return false;
        it.runs_left -= 1;
        it.fg = it.r.int(u32) catch return false;
        it.bg = it.r.int(u32) catch return false;
        it.attrs = (it.r.int(u8) catch return false) & attr_mask;
        const n = it.r.int(u16) catch return false;
        it.text = .{ .s = it.r.bytes(n) catch return false };
        return true;
    }
};

/// Lenient UTF-8 decoding: every invalid or truncated sequence yields one
/// U+FFFD and advances by one byte, so decoding always terminates.
pub const Utf8Iterator = struct {
    s: []const u8,
    i: usize = 0,

    pub fn next(it: *Utf8Iterator) ?u21 {
        if (it.i >= it.s.len) return null;
        const n = std.unicode.utf8ByteSequenceLength(it.s[it.i]) catch {
            it.i += 1;
            return 0xFFFD;
        };
        if (n > it.s.len - it.i) {
            it.i += 1;
            return 0xFFFD;
        }
        const cp = std.unicode.utf8Decode(it.s[it.i..][0..n]) catch {
            it.i += 1;
            return 0xFFFD;
        };
        it.i += n;
        return cp;
    }

    /// The code point if `s` is exactly one valid one, else null.
    pub fn single(s: []const u8) ?u21 {
        var it: Utf8Iterator = .{ .s = s };
        const cp = it.next() orelse return null;
        if (it.next() != null) return null;
        if (cp == 0xFFFD and !std.mem.eql(u8, s, "\u{FFFD}")) return null;
        return cp;
    }
};

// ------------------------------------------------------------- 'I' / 'P'

pub const Blob = struct {
    id: u32,
    /// The PNG bytes (unvalidated: clients check and decode them bounded).
    png: []const u8,
};

/// Parses an 'I' frame: u8 'I', u32 id, u32 len, len PNG bytes.
pub fn parseBlob(frame: []const u8) Error!Blob {
    var r: Reader = .{ .b = frame };
    if (try r.int(u8) != 'I') return error.Malformed;
    const id = try r.int(u32);
    const len = try r.int(u32);
    if (len != frame.len - r.i) return error.Malformed;
    if (len > max_blob_bytes) return error.TooLarge;
    return .{ .id = id, .png = frame[r.i..] };
}

/// Whether a blob store with `count` blobs of `total` bytes must drop its
/// oldest blob before storing one of `incoming` bytes (at most
/// `max_blob_bytes`). Call in a loop: an empty store always has room.
pub fn mustEvict(count: usize, total: usize, incoming: usize) bool {
    return count > 0 and (count >= max_blobs or total + incoming > max_blob_total_bytes);
}

pub const Placement = struct {
    id: u32,
    /// Left column.
    col: u16,
    /// Top row; negative when the image has partly scrolled off the top.
    row: i16,
    /// Size in cells (never 0, at most `max_dim`).
    cols: u16,
    rows: u16,
};

pub const placement_len = 14;

/// Parses a 'P' frame (the visible screen's complete placement list): u8
/// 'P', u16 n, n x { u32 id, u16 col, i16 row, u16 cols, u16 rows, u16
/// reserved }. Validated whole first. Returns the usable placements, in
/// order, in `out`: entries with a zero or oversized size, or whose id
/// `blobs.has(id)` does not know, are skipped; at most `max_placements`.
/// `blobs` is any value with a `fn has(self, u32) bool`.
pub fn parsePlacements(frame: []const u8, out: *[max_placements]Placement, blobs: anytype) Error![]Placement {
    var r: Reader = .{ .b = frame };
    if (try r.int(u8) != 'P') return error.Malformed;
    const n = try r.int(u16);
    const body = try r.bytes(@as(usize, n) * placement_len);
    if (!r.done()) return error.Malformed;
    var k: usize = 0;
    for (0..n) |i| {
        if (k == out.len) break;
        const e = body[i * placement_len ..][0..placement_len];
        const p: Placement = .{
            .id = std.mem.readInt(u32, e[0..4], .little),
            .col = std.mem.readInt(u16, e[4..6], .little),
            .row = std.mem.readInt(i16, e[6..8], .little),
            .cols = std.mem.readInt(u16, e[8..10], .little),
            .rows = std.mem.readInt(u16, e[10..12], .little),
        };
        if (p.cols == 0 or p.rows == 0 or p.cols > max_dim or p.rows > max_dim) continue;
        if (!blobs.has(p.id)) continue;
        out[k] = p;
        k += 1;
    }
    return out[0..k];
}

// ---------------------------------------------------------------- reading

/// Bounds-checked little-endian reader.
const Reader = struct {
    b: []const u8,
    i: usize = 0,

    fn done(r: *const Reader) bool {
        return r.i == r.b.len;
    }
    fn bytes(r: *Reader, n: usize) Error![]const u8 {
        if (n > r.b.len - r.i) return error.Malformed;
        defer r.i += n;
        return r.b[r.i..][0..n];
    }
    fn int(r: *Reader, comptime T: type) Error!T {
        const s = try r.bytes(@sizeOf(T));
        return std.mem.readInt(T, s[0..@sizeOf(T)], .little);
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

/// Test helper that builds frames (both clients' tests use it).
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
    pub fn int(b: *FrameBuilder, comptime T: type, v: T) !void {
        var tmp: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &tmp, v, .little);
        try b.buf.appendSlice(b.gpa, &tmp);
    }
    pub fn deinit(b: *FrameBuilder) void {
        b.buf.deinit(b.gpa);
    }
};

/// A tiny width table for tests: CJK and emoji are wide, U+0300.. zero.
fn testWidth(cp: u21) u2 {
    if (cp >= 0x300 and cp < 0x370) return 0;
    if ((cp >= 0x4e00 and cp < 0xa000) or cp >= 0x1f300) return 2;
    return 1;
}

const Collected = struct { cells: [64]Cell = undefined, n: usize = 0 };

fn collect(row: Row) Collected {
    var c: Collected = .{};
    var it = row.cells();
    while (it.next()) |cell| {
        c.cells[c.n] = cell;
        c.n += 1;
    }
    return c;
}

test "grid frame: rows, runs, wide chars, clipping, controls" {
    var b: FrameBuilder = .{ .gpa = testing.allocator };
    defer b.deinit();
    try b.header(7, 3, 99, 1, true, 2);
    try b.rowStart(2, 2);
    try b.run(1, 2, 0xff, "a\x01\xc2\x9b中"); // attrs masked, C0 and C1 -> U+FFFD
    try b.run(3, 4, 0, "\u{301}x中yz"); // combining mark skipped; wide in the last column
    try b.rowStart(0, 0);
    const f = try GridFrame.parse(b.buf.items);
    try testing.expectEqual(@as(u16, 6), f.header.cursor_x); // clamped
    try testing.expect(f.header.cursor_visible and !f.complete());
    var rows = f.rows(testWidth);
    const r0 = rows.next().?;
    try testing.expectEqual(@as(u16, 2), r0.index);
    const c = collect(r0);
    try testing.expectEqual(@as(usize, 6), c.n);
    try testing.expectEqual(@as(u21, 'a'), c.cells[0].cp);
    try testing.expectEqual(@as(u8, 0x1f), c.cells[0].attrs);
    try testing.expectEqual(@as(u21, 0xFFFD), c.cells[1].cp);
    try testing.expectEqual(@as(u21, 0xFFFD), c.cells[2].cp);
    try testing.expectEqual(@as(u2, 2), c.cells[3].width);
    try testing.expectEqual(@as(u16, 3), c.cells[3].col);
    try testing.expectEqual(@as(u21, 'x'), c.cells[4].cp);
    try testing.expectEqual(@as(u32, 3), c.cells[4].fg);
    try testing.expectEqual(@as(u16, 6), c.cells[5].col);
    try testing.expectEqual(@as(u21, ' '), c.cells[5].cp); // wide did not fit
    try testing.expectEqual(@as(u2, 1), c.cells[5].width);
    const r1 = rows.next().?;
    try testing.expectEqual(@as(u16, 0), r1.index);
    try testing.expectEqual(@as(usize, 0), collect(r1).n);
    try testing.expect(rows.next() == null);
}

test "grid frame: invalid utf-8 becomes U+FFFD" {
    var b: FrameBuilder = .{ .gpa = testing.allocator };
    defer b.deinit();
    try b.header(4, 1, 0, 0, false, 1);
    try b.rowStart(0, 1);
    try b.run(0, 0, 0, "a\xFFbcdefgh\xE4\xB8");
    const f = try GridFrame.parse(b.buf.items);
    var rows = f.rows(testWidth);
    const c = collect(rows.next().?);
    try testing.expectEqual(@as(usize, 4), c.n);
    try testing.expectEqual(@as(u21, 0xFFFD), c.cells[1].cp);
    try testing.expectEqual(@as(u21, 'c'), c.cells[3].cp);
}

test "grid frame: malformed frames are rejected whole" {
    const gpa = testing.allocator;
    var b: FrameBuilder = .{ .gpa = gpa };
    defer b.deinit();
    try b.header(4, 2, 0, 0, false, 2);
    try b.rowStart(0, 1);
    try b.run(0, 0, 0, "ok");
    try b.rowStart(1, 0);
    const good = try gpa.dupe(u8, b.buf.items);
    defer gpa.free(good);
    _ = try GridFrame.parse(good);
    for (0..good.len) |n| try testing.expectError(error.Malformed, GridFrame.parse(good[0..n]));
    const extra = try std.mem.concat(gpa, u8, &.{ good, "x" });
    defer gpa.free(extra);
    try testing.expectError(error.Malformed, GridFrame.parse(extra));
    // Row index out of range, even after a good row.
    b.buf.clearRetainingCapacity();
    try b.header(4, 2, 0, 0, false, 2);
    try b.rowStart(0, 0);
    try b.rowStart(2, 0);
    try testing.expectError(error.Malformed, GridFrame.parse(b.buf.items));
    // Sizes, cursor flag, more rows than the grid has.
    b.buf.clearRetainingCapacity();
    try b.header(1001, 2, 0, 0, false, 0);
    try testing.expectError(error.TooLarge, GridFrame.parse(b.buf.items));
    b.buf.clearRetainingCapacity();
    try b.header(0, 2, 0, 0, false, 0);
    try testing.expectError(error.Malformed, GridFrame.parse(b.buf.items));
    b.buf.clearRetainingCapacity();
    try b.header(4, 2, 0, 0, false, 3);
    try testing.expectError(error.Malformed, GridFrame.parse(b.buf.items));
    b.buf.items[9] = 2;
    b.buf.items[10] = 0;
    try testing.expectError(error.Malformed, GridFrame.parse(b.buf.items));
    try testing.expectError(error.Malformed, GridFrame.parse("X12345678901"));
    try testing.expectEqual(Kind.unknown, kind(""));
}

test "fuzz: random grid frames never panic and cells stay inside the row" {
    var prng: std.Random.DefaultPrng = .init(7);
    const rand = prng.random();
    var buf: [600]u8 = undefined;
    for (0..30000) |_| {
        const n = rand.uintLessThan(usize, buf.len);
        rand.bytes(buf[0..n]);
        if (n > 0) buf[0] = 'G';
        if (n > 12) {
            std.mem.writeInt(u16, buf[1..3], rand.intRangeAtMost(u16, 1, 50), .little);
            std.mem.writeInt(u16, buf[3..5], rand.intRangeAtMost(u16, 1, 10), .little);
            buf[9] = rand.uintLessThan(u8, 2);
            std.mem.writeInt(u16, buf[10..12], rand.uintLessThan(u16, 4), .little);
        }
        const f = GridFrame.parse(buf[0..n]) catch continue;
        var rows = f.rows(testWidth);
        while (rows.next()) |row| {
            try testing.expect(row.index < f.header.rows);
            var it = row.cells();
            while (it.next()) |c| try testing.expect(@as(usize, c.col) + c.width <= f.header.cols);
        }
    }
}

const SomeBlobs = struct {
    ids: []const u32,
    fn has(s: SomeBlobs, id: u32) bool {
        return std.mem.indexOfScalar(u32, s.ids, id) != null;
    }
};

test "image frames: blobs and placements" {
    const blob = try parseBlob("I\x07\x00\x00\x00\x03\x00\x00\x00abc");
    try testing.expectEqual(@as(u32, 7), blob.id);
    try testing.expectEqualStrings("abc", blob.png);
    try testing.expectError(error.Malformed, parseBlob("I\x01\x00\x00\x00\x05\x00\x00\x00abc"));
    try testing.expectError(error.Malformed, parseBlob("I\x01\x00\x00\x00\x01\x00\x00\x00abc"));
    try testing.expectError(error.Malformed, parseBlob("I\x01"));
    var big: [9]u8 = .{ 'I', 1, 0, 0, 0, 0, 0, 0x70, 0 };
    try testing.expectError(error.Malformed, parseBlob(&big)); // claims more than present
    std.mem.writeInt(u32, big[5..9], max_blob_bytes + 1, .little);
    const huge = try testing.allocator.alloc(u8, 9 + max_blob_bytes + 1);
    defer testing.allocator.free(huge);
    @memcpy(huge[0..9], &big);
    try testing.expectError(error.TooLarge, parseBlob(huge));

    // id 7 at (1, -1) 3x2; id 9 has no blob: skipped; zero size: skipped.
    const pf = "P\x03\x00" ++
        "\x07\x00\x00\x00\x01\x00\xff\xff\x03\x00\x02\x00\x00\x00" ++
        "\x09\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00" ++
        "\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00";
    var out: [max_placements]Placement = undefined;
    const have: SomeBlobs = .{ .ids = &.{7} };
    const list = try parsePlacements(pf, &out, have);
    try testing.expectEqual(@as(usize, 1), list.len);
    try testing.expectEqual(@as(i16, -1), list[0].row);
    try testing.expectEqual(@as(u16, 3), list[0].cols);
    try testing.expectEqual(@as(usize, 0), (try parsePlacements("P\x00\x00", &out, have)).len);
    for (0..pf.len) |n| try testing.expectError(error.Malformed, parsePlacements(pf[0..n], &out, have));
    try testing.expectError(error.Malformed, parsePlacements(pf ++ "x", &out, have));
    try testing.expectError(error.Malformed, parsePlacements("P\xff\xff", &out, have));

    // More than the cap: the first max_placements are kept.
    const many = try testing.allocator.alloc(u8, 3 + 300 * placement_len);
    defer testing.allocator.free(many);
    @memset(many, 0);
    many[0] = 'P';
    std.mem.writeInt(u16, many[1..3], 300, .little);
    for (0..300) |i| {
        const e = many[3 + i * placement_len ..][0..placement_len];
        std.mem.writeInt(u32, e[0..4], 7, .little);
        std.mem.writeInt(u16, e[4..6], @intCast(i), .little);
        std.mem.writeInt(u16, e[8..10], 1, .little);
        std.mem.writeInt(u16, e[10..12], 1, .little);
    }
    const capped = try parsePlacements(many, &out, have);
    try testing.expectEqual(max_placements, capped.len);
    try testing.expectEqual(@as(u16, max_placements - 1), capped[max_placements - 1].col);
}

test "blob eviction" {
    try testing.expect(!mustEvict(0, 0, max_blob_bytes));
    try testing.expect(!mustEvict(max_blobs - 1, 0, 1));
    try testing.expect(mustEvict(max_blobs, 0, 1));
    try testing.expect(mustEvict(2, max_blob_total_bytes - 10, 11));
    try testing.expect(!mustEvict(2, max_blob_total_bytes - 10, 10));
}

test "fuzz: random image frames never panic" {
    var prng: std.Random.DefaultPrng = .init(0x1717);
    const rand = prng.random();
    var buf: [600]u8 = undefined;
    var out: [max_placements]Placement = undefined;
    const all: SomeBlobs = .{ .ids = &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8 } };
    for (0..20000) |_| {
        const n = rand.uintAtMost(usize, buf.len);
        rand.bytes(buf[0..n]);
        if (n > 0) buf[0] = if (rand.boolean()) 'I' else 'P';
        if (n >= 9 and buf[0] == 'I' and rand.boolean()) std.mem.writeInt(u32, buf[5..9], @intCast(n - 9), .little);
        if (n >= 3 and buf[0] == 'P' and rand.boolean()) {
            const k: u16 = @intCast((n - 3) / placement_len);
            std.mem.writeInt(u16, buf[1..3], k, .little);
            if (parsePlacements(buf[0 .. 3 + @as(usize, k) * placement_len], &out, all)) |l| {
                for (l) |p| try testing.expect(p.cols > 0 and p.rows > 0 and all.has(p.id));
            } else |_| {}
            continue;
        }
        if (buf[0] == 'I') {
            if (parseBlob(buf[0..n])) |bl| try testing.expect(bl.png.len == n - 9) else |_| {}
        } else _ = parsePlacements(buf[0..n], &out, all) catch {};
    }
}

test "utf8 single" {
    try testing.expectEqual(@as(?u21, 'a'), Utf8Iterator.single("a"));
    try testing.expectEqual(@as(?u21, 'é'), Utf8Iterator.single("é"));
    try testing.expectEqual(@as(?u21, 0xFFFD), Utf8Iterator.single("\u{FFFD}"));
    try testing.expectEqual(@as(?u21, null), Utf8Iterator.single("ab"));
    try testing.expectEqual(@as(?u21, null), Utf8Iterator.single(""));
    try testing.expectEqual(@as(?u21, null), Utf8Iterator.single("\xff"));
}
