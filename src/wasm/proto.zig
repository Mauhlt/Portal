//! Client side of the Portal protocol (docs/protocol.md): the grid model,
//! the 'G' binary frame decoder and the small JSON control messages.
//!
//! Everything here reads bytes from the network. A trap in wasm kills the
//! page, so nothing may panic, assert, overflow or index out of bounds on
//! peer data: every read is bounds-checked and malformed input is reported
//! as an error (or ignored) after applying whatever decoded cleanly.

const std = @import("std");
const vt = @import("vt");

pub const color_default = vt.color_default;
pub const color_default_bg_as_fg = vt.color_default_bg_as_fg;
pub const color_default_fg_as_bg = vt.color_default_fg_as_bg;

pub const attr_bold = vt.attr_bold;
pub const attr_dim = vt.attr_dim;
pub const attr_italic = vt.attr_italic;
pub const attr_underline = vt.attr_underline;
pub const attr_strike = vt.attr_strike;

/// The server clamps its terminal to this, so anything bigger is bogus.
pub const max_dim: u16 = vt.max_dim;

pub const Wide = enum(u2) { narrow, lead, cont };

pub const Cell = struct {
    cp: u21 = ' ',
    wide: Wide = .narrow,
    attrs: u8 = 0,
    fg: u32 = color_default,
    bg: u32 = color_default,
};

pub const Grid = struct {
    cols: u16 = 0,
    rows: u16 = 0,
    cells: []Cell = &.{},
    /// Rows changed since the renderer last drew them.
    dirty: []bool = &.{},
    cursor_x: u16 = 0,
    cursor_y: u16 = 0,
    cursor_visible: bool = false,

    pub fn deinit(g: *Grid, gpa: std.mem.Allocator) void {
        gpa.free(g.cells);
        gpa.free(g.dirty);
        g.* = .{};
    }

    pub fn row(g: *const Grid, y: u16) []Cell {
        const start = @as(usize, y) * g.cols;
        return g.cells[start..][0..g.cols];
    }

    pub fn at(g: *const Grid, x: u16, y: u16) Cell {
        if (x >= g.cols or y >= g.rows) return .{};
        return g.cells[@as(usize, y) * g.cols + x];
    }

    fn resize(g: *Grid, gpa: std.mem.Allocator, cols: u16, rows: u16) error{OutOfMemory}!void {
        const n = @as(usize, cols) * rows;
        const cells = try gpa.alloc(Cell, n);
        errdefer gpa.free(cells);
        const dirty = try gpa.alloc(bool, rows);
        gpa.free(g.cells);
        gpa.free(g.dirty);
        @memset(cells, .{});
        @memset(dirty, true);
        g.cells = cells;
        g.dirty = dirty;
        g.cols = cols;
        g.rows = rows;
    }

    pub fn markAllDirty(g: *Grid) void {
        @memset(g.dirty, true);
    }
};

pub const FrameError = error{ NotGrid, Truncated, BadSize, OutOfMemory };

pub const FrameResult = struct {
    /// The grid was reallocated (cols/rows changed): relayout.
    resized: bool = false,
};

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn bytes(r: *Reader, n: usize) FrameError![]const u8 {
        if (n > r.buf.len - r.pos) return error.Truncated;
        const s = r.buf[r.pos..][0..n];
        r.pos += n;
        return s;
    }
    fn int(r: *Reader, comptime T: type) FrameError!T {
        const s = try r.bytes(@sizeOf(T));
        return std.mem.readInt(T, s[0..@sizeOf(T)], .little);
    }
};

/// Applies one binary 'G' frame to `g`. On error the rows decoded before
/// the problem stay applied (and dirty); the grid is always consistent.
pub fn applyFrame(g: *Grid, gpa: std.mem.Allocator, frame: []const u8) FrameError!FrameResult {
    var r: Reader = .{ .buf = frame };
    if ((try r.int(u8)) != 'G') return error.NotGrid;
    const cols = try r.int(u16);
    const rows = try r.int(u16);
    const cx = try r.int(u16);
    const cy = try r.int(u16);
    const visible = (try r.int(u8)) == 1;
    const n_rows = try r.int(u16);
    if (cols == 0 or rows == 0 or cols > max_dim or rows > max_dim) return error.BadSize;

    var result: FrameResult = .{};
    if (cols != g.cols or rows != g.rows) {
        try g.resize(gpa, cols, rows);
        result.resized = true;
    }
    g.cursor_x = @min(cx, cols - 1);
    g.cursor_y = @min(cy, rows - 1);
    g.cursor_visible = visible;

    var i: usize = 0;
    while (i < n_rows) : (i += 1) {
        const y = try r.int(u16);
        const n_runs = try r.int(u16);
        const target: ?[]Cell = if (y < rows) g.row(y) else null;
        if (target) |cells| {
            @memset(cells, .{});
            g.dirty[y] = true;
        }
        var x: usize = 0;
        var k: usize = 0;
        while (k < n_runs) : (k += 1) {
            const fg = try r.int(u32);
            const bg = try r.int(u32);
            const attrs = try r.int(u8);
            const len = try r.int(u16);
            const text = try r.bytes(len);
            const cells = target orelse continue;
            var it: Utf8Iter = .{ .s = text };
            while (it.next()) |cp| {
                if (x >= cells.len) break;
                const w = vt.cellWidth(cp);
                if (w == 0) continue; // combining marks: the server drops them too
                const base: Cell = .{ .cp = cp, .attrs = attrs, .fg = fg, .bg = bg };
                if (w == 2 and x + 1 < cells.len) {
                    cells[x] = base;
                    cells[x].wide = .lead;
                    cells[x + 1] = .{ .cp = ' ', .wide = .cont, .attrs = attrs, .fg = fg, .bg = bg };
                    x += 2;
                } else {
                    cells[x] = base;
                    if (w == 2) cells[x].cp = ' '; // does not fit: never half a glyph
                    x += 1;
                }
            }
        }
    }
    return result;
}

/// Lenient UTF-8 decoding: every invalid or truncated sequence yields one
/// U+FFFD and advances by one byte, so decoding always terminates.
pub const Utf8Iter = struct {
    s: []const u8,
    i: usize = 0,

    pub fn next(it: *Utf8Iter) ?u21 {
        if (it.i >= it.s.len) return null;
        const b0 = it.s[it.i];
        const n: usize = if (b0 < 0x80) 1 else if (b0 & 0xE0 == 0xC0) 2 else if (b0 & 0xF0 == 0xE0) 3 else if (b0 & 0xF8 == 0xF0) 4 else 0;
        if (n == 0 or n > it.s.len - it.i) {
            it.i += 1;
            return 0xFFFD;
        }
        const seq = it.s[it.i..][0..n];
        const cp = std.unicode.utf8Decode(seq) catch {
            it.i += 1;
            return 0xFFFD;
        };
        it.i += n;
        return cp;
    }

    /// Number of code points, or null if `s` is not exactly one.
    pub fn single(s: []const u8) ?u21 {
        var it: Utf8Iter = .{ .s = s };
        const cp = it.next() orelse return null;
        if (it.next() != null) return null;
        if (cp == 0xFFFD and !std.mem.eql(u8, s, "\u{FFFD}")) return null;
        return cp;
    }
};

// ------------------------------------------------------------ JSON control

pub const Policy = enum { none, keys, text };

pub const Control = union(enum) {
    hello: Policy,
    exit: i64,
    logout,
    unknown,
};

/// Parses the server's one-object JSON text frames ({"t":"hello",...}).
/// Only the handful of fields Portal sends are understood; anything else,
/// including malformed JSON, is `unknown`.
pub fn parseControl(text: []const u8) Control {
    const t = stringField(text, "t") orelse return .unknown;
    if (std.mem.eql(u8, t, "hello")) {
        const input = stringField(text, "input") orelse "none";
        if (std.mem.eql(u8, input, "keys")) return .{ .hello = .keys };
        if (std.mem.eql(u8, input, "text")) return .{ .hello = .text };
        return .{ .hello = .none };
    }
    if (std.mem.eql(u8, t, "exit")) return .{ .exit = intField(text, "code") orelse 0 };
    if (std.mem.eql(u8, t, "logout")) return .logout;
    return .unknown;
}

/// Position just after `"name"` followed by optional spaces and a colon.
fn fieldValue(text: []const u8, name: []const u8) ?usize {
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, text, from, name)) |at| {
        from = at + 1;
        if (at == 0 or text[at - 1] != '"') continue;
        var p = at + name.len;
        if (p >= text.len or text[p] != '"') continue;
        p += 1;
        while (p < text.len and text[p] == ' ') p += 1;
        if (p >= text.len or text[p] != ':') continue;
        p += 1;
        while (p < text.len and text[p] == ' ') p += 1;
        return p;
    }
    return null;
}

/// A simple string value (no escapes are ever needed for Portal's values).
fn stringField(text: []const u8, name: []const u8) ?[]const u8 {
    const p = fieldValue(text, name) orelse return null;
    if (p >= text.len or text[p] != '"') return null;
    const end = std.mem.indexOfScalarPos(u8, text, p + 1, '"') orelse return null;
    return text[p + 1 .. end];
}

fn intField(text: []const u8, name: []const u8) ?i64 {
    var p = fieldValue(text, name) orelse return null;
    const start = p;
    if (p < text.len and text[p] == '-') p += 1;
    while (p < text.len and p - start < 19 and text[p] >= '0' and text[p] <= '9') p += 1;
    return std.fmt.parseInt(i64, text[start..p], 10) catch null;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

const Builder = struct {
    list: std.ArrayList(u8) = .empty,
    fn u8_(b: *Builder, v: u8) void {
        b.list.append(testing.allocator, v) catch unreachable;
    }
    fn u16_(b: *Builder, v: u16) void {
        var t: [2]u8 = undefined;
        std.mem.writeInt(u16, &t, v, .little);
        b.list.appendSlice(testing.allocator, &t) catch unreachable;
    }
    fn u32_(b: *Builder, v: u32) void {
        var t: [4]u8 = undefined;
        std.mem.writeInt(u32, &t, v, .little);
        b.list.appendSlice(testing.allocator, &t) catch unreachable;
    }
    fn header(b: *Builder, cols: u16, rows: u16, cx: u16, cy: u16, vis: u8, n: u16) void {
        b.u8_('G');
        b.u16_(cols);
        b.u16_(rows);
        b.u16_(cx);
        b.u16_(cy);
        b.u8_(vis);
        b.u16_(n);
    }
    fn run(b: *Builder, fg: u32, bg: u32, attrs: u8, text: []const u8) void {
        b.u32_(fg);
        b.u32_(bg);
        b.u8_(attrs);
        b.u16_(@intCast(text.len));
        b.list.appendSlice(testing.allocator, text) catch unreachable;
    }
    fn deinit(b: *Builder) void {
        b.list.deinit(testing.allocator);
    }
};

test "decode a full frame, wide chars and colours" {
    var b: Builder = .{};
    defer b.deinit();
    b.header(6, 2, 3, 1, 1, 2);
    b.u16_(0);
    b.u16_(2);
    b.run(color_default, color_default, 0, "ab");
    b.run(0xCD0000, 0x0000EE, attr_bold, "中x");
    b.u16_(1);
    b.u16_(0);
    var g: Grid = .{};
    defer g.deinit(testing.allocator);
    const res = try applyFrame(&g, testing.allocator, b.list.items);
    try testing.expect(res.resized);
    try testing.expectEqual(@as(u16, 6), g.cols);
    try testing.expectEqual(@as(u16, 3), g.cursor_x);
    try testing.expect(g.cursor_visible);
    try testing.expectEqual(@as(u21, 'a'), g.at(0, 0).cp);
    try testing.expectEqual(@as(u21, '中'), g.at(2, 0).cp);
    try testing.expectEqual(Wide.lead, g.at(2, 0).wide);
    try testing.expectEqual(Wide.cont, g.at(3, 0).wide);
    try testing.expectEqual(@as(u21, 'x'), g.at(4, 0).cp);
    try testing.expectEqual(@as(u32, 0xCD0000), g.at(4, 0).fg);
    try testing.expectEqual(attr_bold, g.at(4, 0).attrs);
    try testing.expectEqual(@as(u21, ' '), g.at(5, 0).cp); // uncovered: blank
    try testing.expectEqual(color_default, g.at(5, 0).bg);
    try testing.expect(g.dirty[0] and g.dirty[1]);

    // An update to one row replaces just that row; same size, no resize.
    @memset(g.dirty, false);
    var b2: Builder = .{};
    defer b2.deinit();
    b2.header(6, 2, 0, 0, 0, 1);
    b2.u16_(1);
    b2.u16_(1);
    b2.run(color_default, color_default, 0, "zz");
    const res2 = try applyFrame(&g, testing.allocator, b2.list.items);
    try testing.expect(!res2.resized);
    try testing.expect(!g.dirty[0] and g.dirty[1]);
    try testing.expectEqual(@as(u21, 'a'), g.at(0, 0).cp);
    try testing.expectEqual(@as(u21, 'z'), g.at(1, 1).cp);
    try testing.expect(!g.cursor_visible);
}

test "wide char at the right edge and overlong rows never overflow" {
    var b: Builder = .{};
    defer b.deinit();
    b.header(3, 1, 99, 99, 1, 3);
    b.u16_(0);
    b.u16_(1);
    b.run(color_default, color_default, 0, "ab中中中 and lots more text than fits");
    b.u16_(500); // out-of-range row: consumed and skipped
    b.u16_(1);
    b.run(1, 2, 3, "ignored");
    b.u16_(0);
    b.u16_(0); // an empty repeat of row 0 blanks it
    var g: Grid = .{};
    defer g.deinit(testing.allocator);
    _ = try applyFrame(&g, testing.allocator, b.list.items);
    try testing.expectEqual(@as(u16, 2), g.cursor_x); // clamped
    try testing.expectEqual(@as(u16, 0), g.cursor_y);
    try testing.expectEqual(@as(u21, ' '), g.at(0, 0).cp);

    var b2: Builder = .{};
    defer b2.deinit();
    b2.header(3, 1, 0, 0, 1, 1);
    b2.u16_(0);
    b2.u16_(1);
    b2.run(color_default, color_default, 0, "ab中");
    _ = try applyFrame(&g, testing.allocator, b2.list.items);
    try testing.expectEqual(@as(u21, 'b'), g.at(1, 0).cp);
    try testing.expectEqual(@as(u21, ' '), g.at(2, 0).cp); // wide did not fit
    try testing.expectEqual(Wide.narrow, g.at(2, 0).wide);
}

test "malformed frames are rejected without panicking" {
    var g: Grid = .{};
    defer g.deinit(testing.allocator);
    try testing.expectError(error.Truncated, applyFrame(&g, testing.allocator, ""));
    try testing.expectError(error.NotGrid, applyFrame(&g, testing.allocator, "X123456789012"));
    try testing.expectError(error.Truncated, applyFrame(&g, testing.allocator, "G\x01"));
    var b: Builder = .{};
    defer b.deinit();
    b.header(0, 5, 0, 0, 0, 0);
    try testing.expectError(error.BadSize, applyFrame(&g, testing.allocator, b.list.items));
    b.list.clearRetainingCapacity();
    b.header(5000, 5, 0, 0, 0, 0);
    try testing.expectError(error.BadSize, applyFrame(&g, testing.allocator, b.list.items));
    try testing.expectEqual(@as(u16, 0), g.cols); // grid untouched
    // n_rows promises more than is present.
    b.list.clearRetainingCapacity();
    b.header(4, 2, 0, 0, 0, 9);
    b.u16_(0);
    b.u16_(1);
    b.run(color_default, color_default, 0, "hi");
    try testing.expectError(error.Truncated, applyFrame(&g, testing.allocator, b.list.items));
    try testing.expectEqual(@as(u21, 'h'), g.at(0, 0).cp); // the good row applied
    // Invalid UTF-8 becomes U+FFFD.
    b.list.clearRetainingCapacity();
    b.header(4, 2, 0, 0, 0, 1);
    b.u16_(1);
    b.u16_(1);
    b.run(color_default, color_default, 0, "\xff\xe4\xb8");
    _ = try applyFrame(&g, testing.allocator, b.list.items);
    try testing.expectEqual(@as(u21, 0xFFFD), g.at(0, 1).cp);
    try testing.expectEqual(@as(u21, 0xFFFD), g.at(2, 1).cp);
}

test "every truncation and random corruption of a frame is safe" {
    var b: Builder = .{};
    defer b.deinit();
    b.header(20, 4, 3, 2, 1, 4);
    for (0..4) |y| {
        b.u16_(@intCast(y));
        b.u16_(3);
        b.run(color_default, color_default_fg_as_bg, 0, "héllo ");
        b.run(0x112233, color_default, attr_underline | attr_dim, "中文😀");
        b.run(color_default_bg_as_fg, 0x445566, attr_italic, "─│╭╮");
    }
    const frame = b.list.items;
    var g: Grid = .{};
    defer g.deinit(testing.allocator);
    for (0..frame.len + 1) |n| _ = applyFrame(&g, testing.allocator, frame[0..n]) catch {};
    const copy = try testing.allocator.dupe(u8, frame);
    defer testing.allocator.free(copy);
    var prng = std.Random.DefaultPrng.init(0xF7A3E);
    const rand = prng.random();
    for (0..3000) |_| {
        @memcpy(copy, frame);
        for (0..rand.uintLessThan(usize, 6) + 1) |_| copy[rand.uintLessThan(usize, copy.len)] = rand.int(u8);
        copy[0] = 'G';
        const n = rand.uintAtMost(usize, copy.len);
        _ = applyFrame(&g, testing.allocator, copy[0..n]) catch {};
        // Invariants: dimensions sane, cursor inside, wide pairs intact.
        try testing.expect(g.cols <= max_dim and g.rows <= max_dim);
        try testing.expect(g.cols == 0 or (g.cursor_x < g.cols and g.cursor_y < g.rows));
        for (0..g.rows) |y| {
            const cells = g.row(@intCast(y));
            for (cells, 0..) |c, x| switch (c.wide) {
                .narrow => {},
                .lead => try testing.expect(x + 1 < cells.len and cells[x + 1].wide == .cont),
                .cont => try testing.expect(x > 0 and cells[x - 1].wide == .lead),
            };
        }
    }
    // Fully random buffers.
    var buf: [256]u8 = undefined;
    for (0..3000) |_| {
        rand.bytes(&buf);
        buf[0] = 'G';
        std.mem.writeInt(u16, buf[1..3], rand.uintAtMost(u16, 40), .little);
        std.mem.writeInt(u16, buf[3..5], rand.uintAtMost(u16, 40), .little);
        _ = applyFrame(&g, testing.allocator, buf[0..rand.uintAtMost(usize, buf.len)]) catch {};
    }
}

test "frames produced by the server's own emulator decode identically" {
    var t = try vt.Terminal.init(testing.allocator, 16, 3);
    defer t.deinit();
    t.feed("ab\x1b[1;31mcd\x1b[m \x1b[44mx\x1b[m\r\n\x1b[7mI\x1b[27m中Z\r\n\x1b[4munder");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try t.encodeRows(&.{ 0, 1, 2 }, &out, testing.allocator);
    var g: Grid = .{};
    defer g.deinit(testing.allocator);
    _ = try applyFrame(&g, testing.allocator, out.items);
    try testing.expectEqual(@as(u16, 16), g.cols);
    try testing.expectEqual(@as(u21, 'c'), g.at(2, 0).cp);
    try testing.expectEqual(attr_bold, g.at(2, 0).attrs);
    try testing.expectEqual(color_default_bg_as_fg, g.at(0, 1).fg);
    try testing.expectEqual(color_default_fg_as_bg, g.at(0, 1).bg);
    try testing.expectEqual(Wide.lead, g.at(1, 1).wide);
    try testing.expectEqual(@as(u21, 'Z'), g.at(3, 1).cp);
    try testing.expectEqual(attr_underline, g.at(0, 2).attrs);
    try testing.expectEqual(@as(u16, 5), g.cursor_x);
    try testing.expectEqual(@as(u16, 2), g.cursor_y);
}

test "control messages" {
    try testing.expectEqual(Control{ .hello = .keys }, parseControl("{\"t\":\"hello\",\"input\":\"keys\"}"));
    try testing.expectEqual(Control{ .hello = .text }, parseControl("{\"t\": \"hello\", \"input\": \"text\"}"));
    try testing.expectEqual(Control{ .hello = .none }, parseControl("{\"t\":\"hello\",\"input\":\"none\"}"));
    try testing.expectEqual(Control{ .hello = .none }, parseControl("{\"t\":\"hello\",\"input\":\"bogus\"}"));
    try testing.expectEqual(Control{ .exit = 3 }, parseControl("{\"t\":\"exit\",\"code\":3}"));
    try testing.expectEqual(Control{ .exit = -1073741510 }, parseControl("{\"t\":\"exit\",\"code\":-1073741510}"));
    try testing.expectEqual(Control{ .exit = 0 }, parseControl("{\"t\":\"exit\",\"code\":99999999999999999999999}"));
    try testing.expectEqual(Control.logout, parseControl("{\"t\":\"logout\"}"));
    try testing.expectEqual(Control.unknown, parseControl("{\"t\":\"other\"}"));
    try testing.expectEqual(Control.unknown, parseControl("garbage"));
    try testing.expectEqual(Control.unknown, parseControl("{\"t\":\"hel"));
    try testing.expectEqual(Control.unknown, parseControl("\"t"));
    try testing.expectEqual(Control.unknown, parseControl(""));
    // A key that merely ends in "t" is not "t".
    try testing.expectEqual(Control.unknown, parseControl("{\"input\":\"keys\",\"at\":\"hello\"}"));
}

test "utf8 single" {
    try testing.expectEqual(@as(?u21, 'a'), Utf8Iter.single("a"));
    try testing.expectEqual(@as(?u21, 'é'), Utf8Iter.single("é"));
    try testing.expectEqual(@as(?u21, null), Utf8Iter.single("ab"));
    try testing.expectEqual(@as(?u21, null), Utf8Iter.single(""));
    try testing.expectEqual(@as(?u21, null), Utf8Iter.single("\xff"));
}
