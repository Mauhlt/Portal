//! Fills the view's Grid snapshot from the session's vt.Terminal, copying
//! only rows whose generation changed. Call `sync` with the session mutex
//! held; the Grid is then the GUI thread's own copy, read without the lock
//! (selection text, drawing).

const std = @import("std");
const vt = @import("vt.zig");
const grid = @import("portal_ui").grid;

pub const Sync = struct {
    /// rowGen of each row when it was last copied.
    row_gens: []u64 = &.{},
    /// Scratch row buffer (max_dim cells).
    row_buf: [vt.max_dim]vt.Terminal.VisibleCell = undefined,
    /// Last copied title, NUL-free UTF-8.
    title_buf: [vt.max_title_bytes]u8 = undefined,
    title_len: usize = 0,
    /// term.imagesGen() when images were last copied.
    images_gen: ?u64 = null,
    place_buf: std.ArrayList(grid.Placement) = .empty,

    pub fn deinit(s: *Sync, gpa: std.mem.Allocator) void {
        gpa.free(s.row_gens);
        s.row_gens = &.{};
        s.place_buf.deinit(gpa);
    }

    /// Copies the visible screen's placements, and the PNG bytes of any
    /// image the grid doesn't have yet (decoding happens later, in the
    /// view, outside the session lock). Returns false on allocation
    /// failure (retried next time).
    fn syncImages(s: *Sync, gpa: std.mem.Allocator, g: *grid.Grid, term: *const vt.Terminal) bool {
        s.place_buf.clearRetainingCapacity();
        for (term.placements()) |p| {
            if (p.row < std.math.minInt(i16) or p.row > std.math.maxInt(i16)) continue;
            s.place_buf.append(gpa, .{ .id = p.image, .col = p.col, .row = @intCast(p.row), .cols = p.cols, .rows = p.rows }) catch return false;
            if (g.images.blob(p.image) == null) {
                const png = term.imagePng(p.image) orelse continue;
                g.images.putBlob(gpa, p.image, png) catch |e| switch (e) {
                    error.OutOfMemory => return false,
                    error.TooLarge => {},
                };
            }
        }
        g.images.setPlacements(gpa, s.place_buf.items) catch return false;
        return true;
    }

    pub fn title(s: *const Sync) []const u8 {
        return s.title_buf[0..s.title_len];
    }

    /// Brings `g` up to date with `term`. Returns true if anything visible
    /// changed (cells, cursor, size or title). On allocation failure the
    /// grid keeps its previous contents and false is returned; the next
    /// call retries.
    pub fn sync(s: *Sync, gpa: std.mem.Allocator, g: *grid.Grid, term: *const vt.Terminal) bool {
        var changed = false;
        if (g.cols != term.cols or g.rows != term.rows or s.row_gens.len != term.rows) {
            const gens = gpa.alloc(u64, term.rows) catch return false;
            g.resize(gpa, term.cols, term.rows) catch {
                gpa.free(gens);
                return false;
            };
            gpa.free(s.row_gens);
            s.row_gens = gens;
            // Force every row to be copied below.
            for (gens, 0..) |*v, y| v.* = term.rowGen(@intCast(y)) +% 1;
            changed = true;
        }
        for (s.row_gens, 0..) |*seen, yi| {
            const y: u16 = @intCast(yi);
            const gen = term.rowGen(y);
            if (gen == seen.*) continue;
            seen.* = gen;
            changed = true;
            const n = term.visibleRow(y, &s.row_buf);
            const dst = g.rowMut(y);
            for (dst[0..@min(n, dst.len)], s.row_buf[0..@min(n, dst.len)]) |*d, c| d.* = convert(c);
        }
        g.complete = true;
        const cur = term.cursor();
        if (cur.x != g.cursor_x or cur.y != g.cursor_y or cur.visible != g.cursor_visible) {
            g.cursor_x = cur.x;
            g.cursor_y = cur.y;
            g.cursor_visible = cur.visible;
            changed = true;
        }
        const ig = term.imagesGen();
        if (s.images_gen == null or s.images_gen.? != ig) {
            if (s.syncImages(gpa, g, term)) s.images_gen = ig;
            changed = true;
        }
        const t = term.title();
        if (!std.mem.eql(u8, t, s.title())) {
            const n = @min(t.len, s.title_buf.len);
            @memcpy(s.title_buf[0..n], t[0..n]);
            s.title_len = n;
            changed = true;
        }
        if (changed) g.generation +%= 1;
        return changed;
    }
};

fn convert(c: vt.Terminal.VisibleCell) grid.Cell {
    return .{
        .cp = c.cp,
        .kind = switch (c.wide) {
            .narrow => .normal,
            .lead => .wide,
            .cont => .continuation,
        },
        .attrs = @bitCast(c.attrs & 0x1F),
        .fg = c.fg,
        .bg = c.bg,
    };
}

comptime {
    // The view's model mirrors vt.zig's wire format.
    std.debug.assert(grid.color_default == vt.color_default);
    std.debug.assert(grid.color_default_bg_as_fg == vt.color_default_bg_as_fg);
    std.debug.assert(grid.color_default_fg_as_bg == vt.color_default_fg_as_bg);
    std.debug.assert(@as(u8, @bitCast(grid.Attrs{ .bold = true })) == vt.attr_bold);
    std.debug.assert(@as(u8, @bitCast(grid.Attrs{ .dim = true })) == vt.attr_dim);
    std.debug.assert(@as(u8, @bitCast(grid.Attrs{ .italic = true })) == vt.attr_italic);
    std.debug.assert(@as(u8, @bitCast(grid.Attrs{ .underline = true })) == vt.attr_underline);
    std.debug.assert(@as(u8, @bitCast(grid.Attrs{ .strike = true })) == vt.attr_strike);
    std.debug.assert(grid.max_cols >= vt.max_dim and grid.max_rows >= vt.max_dim);
}

/// Text of the selected cells (reading order, inclusive), rows joined with
/// CRLF and trailing blanks trimmed per row. Caller frees.
pub fn selectionText(gpa: std.mem.Allocator, g: *const grid.Grid, sel: anytype) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    if (g.rows == 0 or g.cols == 0) return out.toOwnedSlice(gpa);
    const last_row = @min(sel.end_row, g.rows - 1);
    var y: usize = sel.start_row;
    while (y <= last_row) : (y += 1) {
        const row = g.row(y);
        const from: usize = if (y == sel.start_row) @min(sel.start_col, row.len) else 0;
        const to: usize = if (y == sel.end_row) @min(@as(usize, sel.end_col) + 1, row.len) else row.len;
        const line_start = out.items.len;
        if (from < to) for (row[from..to]) |c| {
            if (c.kind == .continuation) continue;
            var buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(c.cp, &buf) catch continue;
            try out.appendSlice(gpa, buf[0..n]);
        };
        // Trim trailing spaces of this row.
        while (out.items.len > line_start and out.items[out.items.len - 1] == ' ') out.items.len -= 1;
        if (y < last_row) try out.appendSlice(gpa, "\r\n");
    }
    return out.toOwnedSlice(gpa);
}

const testing = std.testing;

test "sync copies dirty rows, cursor, title and follows resizes" {
    const gpa = testing.allocator;
    var term = try vt.Terminal.init(gpa, 10, 3);
    defer term.deinit();
    var g: grid.Grid = .{};
    defer g.deinit(gpa);
    var s: Sync = .{};
    defer s.deinit(gpa);

    term.feed("hi\x1b[1;31mX\x1b[m\x1b]0;my title\x07");
    try testing.expect(s.sync(gpa, &g, &term));
    try testing.expectEqual(@as(u16, 10), g.cols);
    try testing.expectEqual(@as(u21, 'h'), g.cell(0, 0).cp);
    try testing.expectEqual(@as(u21, 'X'), g.cell(2, 0).cp);
    try testing.expect(g.cell(2, 0).attrs.bold);
    try testing.expectEqual(@import("shared").theme.ansi16[1], g.cell(2, 0).fg);
    try testing.expectEqual(@as(u16, 3), g.cursor_x);
    try testing.expectEqualStrings("my title", s.title());

    // Nothing changed: no work reported.
    try testing.expect(!s.sync(gpa, &g, &term));

    // Only row 1 is dirty; row 0 is left alone (poke it to prove it).
    g.rowMut(0)[0].cp = 'Q';
    term.feed("\r\n\u{4E2D}");
    try testing.expect(s.sync(gpa, &g, &term));
    try testing.expectEqual(@as(u21, 'Q'), g.cell(0, 0).cp);
    try testing.expectEqual(grid.Kind.wide, g.cell(0, 1).kind);
    try testing.expectEqual(grid.Kind.continuation, g.cell(1, 1).kind);

    try term.resize(20, 5);
    try testing.expect(s.sync(gpa, &g, &term));
    try testing.expectEqual(@as(u16, 20), g.cols);
    try testing.expectEqual(@as(u16, 5), g.rows);
    try testing.expectEqual(@as(u21, 'h'), g.cell(0, 0).cp);
}

test "sync copies image placements and blobs" {
    const gpa = testing.allocator;
    var term = try vt.Terminal.init(gpa, 20, 5);
    defer term.deinit();
    var g: grid.Grid = .{};
    defer g.deinit(gpa);
    var s: Sync = .{};
    defer s.deinit(gpa);
    _ = s.sync(gpa, &g, &term);
    try testing.expectEqual(@as(usize, 0), g.images.placements.items.len);

    const png = try @import("imgcheck").testImage(gpa, 20, 20);
    defer gpa.free(png);
    const b64 = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(png.len));
    defer gpa.free(b64);
    _ = std.base64.standard.Encoder.encode(b64, png);
    var seq: std.ArrayList(u8) = .empty;
    defer seq.deinit(gpa);
    try seq.print(gpa, "\x1b[2;3H\x1b_Ga=T,f=100,c=4,r=2,C=1;{s}\x1b\\", .{b64});
    term.feed(seq.items);
    try testing.expect(s.sync(gpa, &g, &term));
    try testing.expectEqual(@as(usize, 1), g.images.placements.items.len);
    const p = g.images.placements.items[0];
    try testing.expectEqual(@as(u16, 2), p.col);
    try testing.expectEqual(@as(i16, 1), p.row);
    try testing.expectEqualSlices(u8, png, g.images.blob(p.id).?);
    // Erased: placement and blob go.
    term.feed("\x1b[2J");
    try testing.expect(s.sync(gpa, &g, &term));
    try testing.expectEqual(@as(usize, 0), g.images.placements.items.len);
    try testing.expectEqual(@as(usize, 0), g.images.blobs.items.len);
}

test "selection text" {
    const gpa = testing.allocator;
    var term = try vt.Terminal.init(gpa, 8, 3);
    defer term.deinit();
    var g: grid.Grid = .{};
    defer g.deinit(gpa);
    var s: Sync = .{};
    defer s.deinit(gpa);
    term.feed("abc  \r\n\u{4E2D}de\r\nxyz");
    _ = s.sync(gpa, &g, &term);
    const Sel = struct { start_col: u16, start_row: u16, end_col: u16, end_row: u16 };
    const t1 = try selectionText(gpa, &g, Sel{ .start_col = 1, .start_row = 0, .end_col = 1, .end_row = 2 });
    defer gpa.free(t1);
    try testing.expectEqualStrings("bc\r\n\u{4E2D}de\r\nxy", t1);
    const t2 = try selectionText(gpa, &g, Sel{ .start_col = 7, .start_row = 2, .end_col = 900, .end_row = 900 });
    defer gpa.free(t2);
    try testing.expectEqualStrings("", t2);
}
