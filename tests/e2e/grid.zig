//! Strict decoder for Portal's binary grid frames (docs/protocol.md §3) and
//! a client-side screen model that applies snapshots and diffs.
//!
//! Anything the protocol does not allow is an error: wrong magic, sizes out
//! of range, rows out of order or repeated, unknown colour sentinels or
//! attribute bits, empty or unmerged runs, invalid UTF-8, control
//! characters, more characters than columns, trailing bytes.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const color_default: u32 = 0xFF000000;
pub const color_default_bg_as_fg: u32 = 0xFF000002;
pub const color_default_fg_as_bg: u32 = 0xFF000003;
pub const attr_mask: u8 = 1 | 2 | 4 | 8 | 16;

pub const DecodeError = error{
    BadMagic,
    Truncated,
    TrailingBytes,
    BadSize,
    BadCursor,
    BadRowIndex,
    RowsOutOfOrder,
    TooManyRows,
    BadColor,
    BadAttrs,
    EmptyRun,
    UnmergedRuns,
    BadUtf8,
    ControlChar,
    RowTooWide,
    NotFullSnapshot,
    OutOfMemory,
};

const Reader = struct {
    d: []const u8,
    p: usize = 0,

    fn bytes(r: *Reader, n: usize) DecodeError![]const u8 {
        if (r.d.len - r.p < n) return error.Truncated;
        const s = r.d[r.p..][0..n];
        r.p += n;
        return s;
    }
    fn int(r: *Reader, comptime T: type) DecodeError!T {
        const s = try r.bytes(@sizeOf(T));
        return std.mem.readInt(T, s[0..@sizeOf(T)], .little);
    }
};

fn validFg(c: u32) bool {
    return c <= 0x00FFFFFF or c == color_default or c == color_default_bg_as_fg;
}

fn validBg(c: u32) bool {
    return c <= 0x00FFFFFF or c == color_default or c == color_default_fg_as_bg;
}

/// Number of codepoints, after checking UTF-8 and control characters.
fn checkText(t: []const u8) DecodeError!usize {
    const view = std.unicode.Utf8View.init(t) catch return error.BadUtf8;
    var it = view.iterator();
    var n: usize = 0;
    while (it.nextCodepoint()) |cp| {
        if (cp < 0x20 or cp == 0x7f or (cp >= 0x80 and cp <= 0x9f)) return error.ControlChar;
        n += 1;
    }
    return n;
}

pub const Row = struct {
    /// Concatenated text of all runs.
    text: std.ArrayList(u8) = .empty,
    /// Encoded runs exactly as received (colours and attributes included),
    /// for comparing two screens byte for byte.
    runs: std.ArrayList(u8) = .empty,
    n_runs: u16 = 0,
    /// Any run with a non-default fg or bg, or attributes.
    styled: bool = false,

    fn deinit(r: *Row, gpa: Allocator) void {
        r.text.deinit(gpa);
        r.runs.deinit(gpa);
    }
};

pub const Applied = struct { n_rows: u16, full: bool };

pub const Grid = struct {
    gpa: Allocator,
    cols: u16 = 0,
    rows: u16 = 0,
    cursor_x: u16 = 0,
    cursor_y: u16 = 0,
    cursor_visible: bool = false,
    lines: std.ArrayList(Row) = .empty,
    frames: usize = 0,
    full_frames: usize = 0,
    diff_frames: usize = 0,

    pub fn init(gpa: Allocator) Grid {
        return .{ .gpa = gpa };
    }

    pub fn deinit(g: *Grid) void {
        for (g.lines.items) |*r| r.deinit(g.gpa);
        g.lines.deinit(g.gpa);
    }

    /// Decodes and applies one frame. The first frame, and any frame that
    /// changes the size, must be a full snapshot.
    pub fn apply(g: *Grid, d: []const u8) DecodeError!Applied {
        var r: Reader = .{ .d = d };
        const magic = try r.bytes(1);
        if (magic[0] != 'G') return error.BadMagic;
        const cols = try r.int(u16);
        const rows = try r.int(u16);
        const cx = try r.int(u16);
        const cy = try r.int(u16);
        const vis = (try r.bytes(1))[0];
        const n_rows = try r.int(u16);
        if (cols == 0 or rows == 0) return error.BadSize;
        if (cy >= rows or cx > cols or vis > 1) return error.BadCursor;
        if (n_rows > rows) return error.TooManyRows;
        const resized = cols != g.cols or rows != g.rows;
        const full = n_rows == rows;
        if ((g.frames == 0 or resized) and !full) return error.NotFullSnapshot;

        // Decode into fresh rows first so a bad frame leaves the grid intact.
        var new_rows: std.ArrayList(struct { idx: u16, row: Row }) = .empty;
        defer {
            for (new_rows.items) |*nr| nr.row.deinit(g.gpa);
            new_rows.deinit(g.gpa);
        }
        var prev_idx: i32 = -1;
        for (0..n_rows) |_| {
            const idx = try r.int(u16);
            if (idx >= rows) return error.BadRowIndex;
            if (@as(i32, idx) <= prev_idx) return error.RowsOutOfOrder;
            prev_idx = idx;
            const n_runs = try r.int(u16);
            var row: Row = .{ .n_runs = n_runs };
            errdefer row.deinit(g.gpa);
            const runs_start = r.p;
            var width: usize = 0;
            var last: ?struct { fg: u32, bg: u32, attrs: u8 } = null;
            for (0..n_runs) |_| {
                const fg = try r.int(u32);
                const bg = try r.int(u32);
                const attrs = (try r.bytes(1))[0];
                const len = try r.int(u16);
                if (!validFg(fg) or !validBg(bg)) return error.BadColor;
                if (attrs & ~attr_mask != 0) return error.BadAttrs;
                if (len == 0) return error.EmptyRun;
                if (last) |l| if (l.fg == fg and l.bg == bg and l.attrs == attrs) return error.UnmergedRuns;
                last = .{ .fg = fg, .bg = bg, .attrs = attrs };
                const text = try r.bytes(len);
                width += try checkText(text);
                try row.text.appendSlice(g.gpa, text);
                if (fg != color_default or bg != color_default or attrs != 0) row.styled = true;
            }
            // Every codepoint takes at least one cell.
            if (width > cols) return error.RowTooWide;
            try row.runs.appendSlice(g.gpa, d[runs_start..r.p]);
            try new_rows.append(g.gpa, .{ .idx = idx, .row = row });
        }
        if (r.p != d.len) return error.TrailingBytes;

        // Commit.
        if (resized) {
            for (g.lines.items) |*row| row.deinit(g.gpa);
            g.lines.clearRetainingCapacity();
            try g.lines.appendNTimes(g.gpa, .{}, rows);
            g.cols = cols;
            g.rows = rows;
        }
        for (new_rows.items) |*nr| {
            g.lines.items[nr.idx].deinit(g.gpa);
            g.lines.items[nr.idx] = nr.row;
            nr.row = .{};
        }
        g.cursor_x = cx;
        g.cursor_y = cy;
        g.cursor_visible = vis == 1;
        g.frames += 1;
        if (full) g.full_frames += 1 else g.diff_frames += 1;
        return .{ .n_rows = n_rows, .full = full };
    }

    pub fn rowText(g: *const Grid, y: usize) []const u8 {
        if (y >= g.lines.items.len) return "";
        return g.lines.items[y].text.items;
    }

    /// Index of the first row containing `needle`.
    pub fn find(g: *const Grid, needle: []const u8) ?usize {
        for (g.lines.items, 0..) |row, i| {
            if (std.mem.indexOf(u8, row.text.items, needle) != null) return i;
        }
        return null;
    }

    pub fn count(g: *const Grid, needle: []const u8) usize {
        var n: usize = 0;
        for (g.lines.items) |row| n += std.mem.count(u8, row.text.items, needle);
        return n;
    }

    /// Whether two screens are identical (size, cursor and every run).
    pub fn sameAs(a: *const Grid, b: *const Grid) bool {
        if (a.cols != b.cols or a.rows != b.rows) return false;
        if (a.cursor_x != b.cursor_x or a.cursor_y != b.cursor_y or a.cursor_visible != b.cursor_visible) return false;
        for (a.lines.items, b.lines.items) |ra, rb| {
            if (ra.n_runs != rb.n_runs or !std.mem.eql(u8, ra.runs.items, rb.runs.items)) return false;
        }
        return true;
    }

    /// Describes the first difference between two screens (for failures).
    pub fn diffReason(a: *const Grid, b: *const Grid, buf: []u8) []const u8 {
        if (a.cols != b.cols or a.rows != b.rows)
            return std.fmt.bufPrint(buf, "size {d}x{d} vs {d}x{d}", .{ a.cols, a.rows, b.cols, b.rows }) catch "size";
        if (a.cursor_x != b.cursor_x or a.cursor_y != b.cursor_y or a.cursor_visible != b.cursor_visible)
            return std.fmt.bufPrint(buf, "cursor {d},{d},{} vs {d},{d},{}", .{ a.cursor_x, a.cursor_y, a.cursor_visible, b.cursor_x, b.cursor_y, b.cursor_visible }) catch "cursor";
        for (a.lines.items, b.lines.items, 0..) |ra, rb, i| {
            if (ra.n_runs != rb.n_runs or !std.mem.eql(u8, ra.runs.items, rb.runs.items))
                return std.fmt.bufPrint(buf, "row {d}: '{s}' ({d} runs) vs '{s}' ({d} runs)", .{ i, ra.text.items, ra.n_runs, rb.text.items, rb.n_runs }) catch "row";
        }
        return "identical";
    }

    /// The cursor row's text (e.g. a shell prompt being typed into).
    pub fn cursorRow(g: *const Grid) []const u8 {
        return g.rowText(g.cursor_y);
    }

    /// Non-empty rows joined with " | ", for failure details.
    pub fn dump(g: *const Grid, buf: []u8) []const u8 {
        var n: usize = 0;
        for (g.lines.items) |row| {
            const t = std.mem.trimEnd(u8, row.text.items, " ");
            if (t.len == 0) continue;
            const s = std.fmt.bufPrint(buf[n..], "{s} | ", .{t}) catch break;
            n += s.len;
        }
        return buf[0..n];
    }
};

// Decoder self-tests (run with `zig test tests/e2e/grid.zig`).

fn put16(l: *std.ArrayList(u8), gpa: Allocator, v: u16) !void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .little);
    try l.appendSlice(gpa, &b);
}

fn put32(l: *std.ArrayList(u8), gpa: Allocator, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try l.appendSlice(gpa, &b);
}

test "decode snapshot then diff; reject malformed" {
    const gpa = std.testing.allocator;
    var f: std.ArrayList(u8) = .empty;
    defer f.deinit(gpa);
    try f.append(gpa, 'G');
    try put16(&f, gpa, 10);
    try put16(&f, gpa, 2);
    try put16(&f, gpa, 3);
    try put16(&f, gpa, 0);
    try f.append(gpa, 1);
    try put16(&f, gpa, 2);
    try put16(&f, gpa, 0);
    try put16(&f, gpa, 1);
    try put32(&f, gpa, color_default);
    try put32(&f, gpa, color_default);
    try f.append(gpa, 0);
    try put16(&f, gpa, 3);
    try f.appendSlice(gpa, "abc");
    try put16(&f, gpa, 1);
    try put16(&f, gpa, 0);
    var g = Grid.init(gpa);
    defer g.deinit();
    const a = try g.apply(f.items);
    try std.testing.expect(a.full);
    try std.testing.expectEqualStrings("abc", g.rowText(0));
    // Trailing byte.
    try f.append(gpa, 0);
    try std.testing.expectError(error.TrailingBytes, g.apply(f.items));
    _ = f.pop();
    // Control character.
    f.items[f.items.len - 5] = 0x1b;
    try std.testing.expectError(error.ControlChar, g.apply(f.items));
    try std.testing.expectEqualStrings("abc", g.rowText(0));
}
