//! Client side of the Portal protocol (docs/protocol.md): the grid model
//! the binary frames are written into, and the small JSON control messages.
//!
//! The binary frames ('G', 'I', 'P') are decoded by shared/screen.zig, the
//! same decoder the native client uses: a frame is validated whole before
//! anything here changes, so a malformed one changes nothing and is
//! reported as an error. Everything here reads bytes from the network; a
//! trap in wasm kills the page, so nothing may panic, assert, overflow or
//! index out of bounds on peer data.

const std = @import("std");
const vt = @import("vt");
const imgdec = @import("imgdec");
const imgcheck = @import("imgcheck");
const screen = @import("shared").screen;

pub const color_default = vt.color_default;
pub const color_default_bg_as_fg = vt.color_default_bg_as_fg;
pub const color_default_fg_as_bg = vt.color_default_fg_as_bg;

pub const attr_bold = vt.attr_bold;
pub const attr_dim = vt.attr_dim;
pub const attr_italic = vt.attr_italic;
pub const attr_underline = vt.attr_underline;
pub const attr_strike = vt.attr_strike;

/// The server clamps its terminal to this, so anything bigger is bogus.
pub const max_dim: u16 = screen.max_dim;

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
    /// Inline images ('I' / 'P' frames).
    images: Images = .{},

    pub fn deinit(g: *Grid, gpa: std.mem.Allocator) void {
        gpa.free(g.cells);
        gpa.free(g.dirty);
        g.images.deinit(gpa);
        g.* = .{};
    }

    /// Marks the grid rows a placement covers as dirty.
    pub fn markPlacement(g: *Grid, p: Placement) void {
        const r0: i64 = @max(0, @as(i64, p.row));
        const r1: i64 = @min(@as(i64, g.rows), @as(i64, p.row) + p.rows);
        var y = r0;
        while (y < r1) : (y += 1) g.dirty[@intCast(y)] = true;
    }

    /// Marks the rows of every placement showing image `id`.
    pub fn markImage(g: *Grid, id: u32) void {
        for (g.images.places.items) |p| if (p.id == id) g.markPlacement(p);
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

pub const FrameError = screen.Error || error{OutOfMemory};

pub const FrameResult = struct {
    /// The grid was reallocated (cols/rows changed): relayout.
    resized: bool = false,
    /// An 'I' or 'P' frame was applied.
    images: bool = false,
};

// ------------------------------------------------------------ images

/// Most blobs (and bytes) kept, and most placements: the server's own
/// limits (shared/screen.zig), only a guard against a bad peer.
pub const max_blobs = screen.max_blobs;
pub const max_blob_total_bytes = screen.max_blob_total_bytes;
pub const max_placements = screen.max_placements;
/// Decode limits for the browser: wasm memory only grows, so keep a single
/// decode modest. Bigger images draw as a placeholder box.
pub const decode_budget: usize = 96 << 20;
pub const decode_max_side: u32 = 1024;
/// Image's PNG decoder compiles for 32-bit targets since image-check
/// (inflate indexes its tables with usize), so the browser decodes too.
/// False would draw a placeholder box with the image's size instead.
pub const decoder_available = true;

pub const Placement = screen.Placement;

pub const Blob = struct {
    id: u32,
    png: []u8,
    /// IHDR size (0 if the header is unreadable), for the placeholder.
    w: u32 = 0,
    h: u32 = 0,
    rgba: ?imgdec.Rgba = null,
    /// Could not (or may not) be decoded: draw a placeholder.
    failed: bool = false,

    fn deinit(b: *Blob, gpa: std.mem.Allocator) void {
        gpa.free(b.png);
        if (b.rgba) |*r| r.deinit(gpa);
    }
};

pub const Images = struct {
    blobs: std.ArrayList(Blob) = .empty,
    places: std.ArrayList(Placement) = .empty,
    /// Sum of the blobs' PNG sizes.
    total_bytes: usize = 0,

    pub fn deinit(im: *Images, gpa: std.mem.Allocator) void {
        for (im.blobs.items) |*b| b.deinit(gpa);
        im.blobs.deinit(gpa);
        im.places.deinit(gpa);
        im.* = .{};
    }

    pub fn find(im: *const Images, id: u32) ?*Blob {
        for (im.blobs.items) |*b| if (b.id == id) return b;
        return null;
    }

    /// Whether a blob is stored under `id` (for screen.parsePlacements).
    pub fn has(im: *const Images, id: u32) bool {
        return im.find(id) != null;
    }

    fn referenced(im: *const Images, id: u32) bool {
        for (im.places.items) |p| if (p.id == id) return true;
        return false;
    }

    fn remove(im: *Images, gpa: std.mem.Allocator, i: usize) void {
        im.total_bytes -= im.blobs.items[i].png.len;
        im.blobs.items[i].deinit(gpa);
        _ = im.blobs.orderedRemove(i);
    }

    /// A placed blob that still needs decoding, if any.
    pub fn nextToDecode(im: *const Images) ?*Blob {
        for (im.places.items) |p| {
            const b = im.find(p.id) orelse continue;
            if (b.rgba == null and !b.failed) return b;
        }
        return null;
    }

    /// Decodes one pending blob. Returns its id, or null if none was left.
    pub fn decodeOne(im: *Images, gpa: std.mem.Allocator) ?u32 {
        const b = im.nextToDecode() orelse return null;
        if (comptime !decoder_available) {
            b.failed = true;
            return b.id;
        }
        if (imgdec.decode(gpa, b.png, .{ .budget = decode_budget, .max_side = decode_max_side })) |r| {
            b.rgba = r;
        } else |_| b.failed = true;
        return b.id;
    }
};

fn applyBlob(g: *Grid, gpa: std.mem.Allocator, frame: []const u8) FrameError!void {
    const b = try screen.parseBlob(frame);
    const im = &g.images;
    const owned = try gpa.dupe(u8, b.png);
    errdefer gpa.free(owned);
    var blob: Blob = .{ .id = b.id, .png = owned };
    if (imgcheck.header(owned)) |info| {
        blob.w = info.width;
        blob.h = info.height;
    } else |_| blob.failed = true;
    for (im.blobs.items, 0..) |old, i| if (old.id == b.id) {
        im.remove(gpa, i);
        break;
    };
    while (screen.mustEvict(im.blobs.items.len, im.total_bytes, owned.len)) im.remove(gpa, 0);
    try im.blobs.append(gpa, blob);
    im.total_bytes += owned.len;
    g.markImage(b.id);
}

fn applyPlacements(g: *Grid, gpa: std.mem.Allocator, frame: []const u8) FrameError!void {
    const im = &g.images;
    var list: [max_placements]Placement = undefined;
    const fresh = try screen.parsePlacements(frame, &list, im);
    try im.places.ensureTotalCapacity(gpa, fresh.len);
    for (im.places.items) |p| g.markPlacement(p);
    im.places.clearRetainingCapacity();
    im.places.appendSliceAssumeCapacity(fresh);
    for (im.places.items) |p| g.markPlacement(p);
    // Cache rule: blobs this frame doesn't list may go.
    var i: usize = 0;
    while (i < im.blobs.items.len) {
        if (im.referenced(im.blobs.items[i].id)) i += 1 else im.remove(gpa, i);
    }
}

/// Applies any binary frame: 'G' grid, 'I' image blob, 'P' placements.
/// Frames of unknown types are ignored (protocol: new types may appear).
/// On error nothing changed.
pub fn applyBinary(g: *Grid, gpa: std.mem.Allocator, frame: []const u8) FrameError!FrameResult {
    switch (screen.kind(frame)) {
        .grid => return applyFrame(g, gpa, frame),
        .blob => {
            try applyBlob(g, gpa, frame);
            return .{ .images = true };
        },
        .placements => {
            try applyPlacements(g, gpa, frame);
            return .{ .images = true };
        },
        .unknown => return .{},
    }
}

/// Applies one binary 'G' frame to `g`. A malformed frame is rejected
/// whole: the grid is unchanged.
pub fn applyFrame(g: *Grid, gpa: std.mem.Allocator, frame: []const u8) FrameError!FrameResult {
    const f = try screen.GridFrame.parse(frame);
    const h = f.header;
    var result: FrameResult = .{};
    if (h.cols != g.cols or h.rows != g.rows) {
        try g.resize(gpa, h.cols, h.rows);
        result.resized = true;
    }
    g.cursor_x = h.cursor_x;
    g.cursor_y = h.cursor_y;
    g.cursor_visible = h.cursor_visible;
    var rows = f.rows(vt.cellWidth);
    while (rows.next()) |row| {
        const cells = g.row(row.index);
        @memset(cells, .{});
        g.dirty[row.index] = true;
        var it = row.cells();
        while (it.next()) |c| {
            cells[c.col] = .{ .cp = c.cp, .attrs = c.attrs, .fg = c.fg, .bg = c.bg };
            if (c.width == 2) {
                cells[c.col].wide = .lead;
                cells[c.col + 1] = .{ .cp = ' ', .wide = .cont, .attrs = c.attrs, .fg = c.fg, .bg = c.bg };
            }
        }
    }
    return result;
}

/// Lenient UTF-8 decoding (shared with the frame decoder).
pub const Utf8Iter = screen.Utf8Iterator;

// ------------------------------------------------------------ JSON control

pub const Policy = @import("inputbox.zig").Policy;

/// Longest project name the server sends (gui.max_project_bytes).
pub const max_project = 64;

pub const tabs = @import("shared").tabs;

pub const Hello = struct {
    policy: Policy,
    /// Protocol v2: the open tabs and the one shown (empty / null from a
    /// desktop that predates tabs).
    list: tabs.List = .{},
    session: ?tabs.Id = null,
    /// `portal run --project NAME`, if given.
    project_buf: [max_project]u8 = undefined,
    project_len: u8 = 0,

    pub fn project(h: *const Hello) []const u8 {
        return h.project_buf[0..h.project_len];
    }
};

/// What the session program is doing (planned: from its OSC 7501 status,
/// sent as {"t":"state","state":...}; docs/protocol.md §3).
pub const SessionState = enum { unknown, working, waiting, done };

pub const Control = union(enum) {
    hello: Hello,
    /// The open tabs changed.
    tabs: tabs.List,
    /// The server now shows this tab (its full screen follows).
    session: tabs.Id,
    /// The tab asked for is not open.
    nosession,
    /// The tab shown ended while others go on.
    ended: tabs.Id,
    exit: i64,
    logout,
    /// An `l:` line was refused; the reason (a keymap.LineError name)
    /// points into the message.
    rejected: []const u8,
    state: SessionState,
    unknown,
};

/// Parses the server's one-object JSON text frames ({"t":"hello",...}).
/// Only the handful of fields Portal sends are understood; anything else,
/// including malformed JSON, is `unknown`.
pub fn parseControl(text: []const u8) Control {
    const t = stringField(text, "t") orelse return .unknown;
    if (std.mem.eql(u8, t, "hello")) {
        const input = stringField(text, "input") orelse "none";
        var h: Hello = .{ .policy = std.meta.stringToEnum(Policy, input) orelse .none };
        if (escapedField(text, "project", &h.project_buf)) |p| h.project_len = @intCast(p.len);
        if (tabs.parseList(text)) |l| h.list = l;
        h.session = tabs.idField(text, "session");
        return .{ .hello = h };
    }
    if (std.mem.eql(u8, t, "tabs")) return .{ .tabs = tabs.parseList(text) orelse return .unknown };
    if (std.mem.eql(u8, t, "session")) return .{ .session = tabs.idField(text, "id") orelse return .unknown };
    if (std.mem.eql(u8, t, "nosession")) return .nosession;
    if (std.mem.eql(u8, t, "ended")) return .{ .ended = tabs.idField(text, "id") orelse return .unknown };
    if (std.mem.eql(u8, t, "exit")) return .{ .exit = intField(text, "code") orelse 0 };
    if (std.mem.eql(u8, t, "logout")) return .logout;
    if (std.mem.eql(u8, t, "rejected")) return .{ .rejected = stringField(text, "reason") orelse "" };
    if (std.mem.eql(u8, t, "state")) {
        const v = stringField(text, "state") orelse "";
        return .{ .state = std.meta.stringToEnum(SessionState, v) orelse .unknown };
    }
    return .unknown;
}

/// A string value that may contain `\"` and `\\` (the only escapes the
/// server writes), unescaped into `out`. Null if absent, malformed, using
/// another escape, longer than `out`, or not valid UTF-8.
fn escapedField(text: []const u8, name: []const u8, out: []u8) ?[]const u8 {
    var p = fieldValue(text, name) orelse return null;
    if (p >= text.len or text[p] != '"') return null;
    p += 1;
    var n: usize = 0;
    while (p < text.len) : (p += 1) {
        var c = text[p];
        if (c == '"') {
            if (!std.unicode.utf8ValidateSlice(out[0..n])) return null;
            return out[0..n];
        }
        if (c == '\\') {
            p += 1;
            if (p >= text.len) return null;
            c = text[p];
            if (c != '"' and c != '\\') return null;
        }
        if (n >= out.len) return null;
        out[n] = c;
        n += 1;
    }
    return null;
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
    b.header(3, 1, 99, 99, 1, 2);
    b.u16_(0);
    b.u16_(1);
    b.run(color_default, color_default, 0, "ab中中中 and lots more text than fits");
    b.u16_(500); // out-of-range row: the whole frame is rejected
    b.u16_(1);
    b.run(1, 2, 3, "ignored");
    var g: Grid = .{};
    defer g.deinit(testing.allocator);
    try testing.expectError(error.Malformed, applyFrame(&g, testing.allocator, b.list.items));
    try testing.expectEqual(@as(u16, 0), g.cols); // nothing applied
    b.list.shrinkRetainingCapacity(b.list.items.len - (2 + 2 + 11 + "ignored".len));
    b.list.items[10] = 1; // n_rows: without the bad row
    _ = try applyFrame(&g, testing.allocator, b.list.items);
    try testing.expectEqual(@as(u16, 2), g.cursor_x); // clamped
    try testing.expectEqual(@as(u16, 0), g.cursor_y);
    try testing.expectEqual(@as(u21, 'b'), g.at(1, 0).cp);
    try testing.expectEqual(@as(u21, ' '), g.at(2, 0).cp); // wide did not fit

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
    try testing.expectError(error.Malformed, applyFrame(&g, testing.allocator, ""));
    try testing.expectError(error.Malformed, applyFrame(&g, testing.allocator, "X123456789012"));
    try testing.expectError(error.Malformed, applyFrame(&g, testing.allocator, "G\x01"));
    var b: Builder = .{};
    defer b.deinit();
    b.header(0, 5, 0, 0, 0, 0);
    try testing.expectError(error.Malformed, applyFrame(&g, testing.allocator, b.list.items));
    b.list.clearRetainingCapacity();
    b.header(5000, 5, 0, 0, 0, 0);
    try testing.expectError(error.TooLarge, applyFrame(&g, testing.allocator, b.list.items));
    try testing.expectEqual(@as(u16, 0), g.cols); // grid untouched
    // n_rows promises more than is present: rejected whole, even the good row.
    b.list.clearRetainingCapacity();
    b.header(4, 2, 0, 0, 0, 2);
    b.u16_(0);
    b.u16_(1);
    b.run(color_default, color_default, 0, "hi");
    try testing.expectError(error.Malformed, applyFrame(&g, testing.allocator, b.list.items));
    try testing.expectEqual(@as(u16, 0), g.cols);
    b.list.items[10] = 1;
    _ = try applyFrame(&g, testing.allocator, b.list.items);
    try testing.expectEqual(@as(u21, 'h'), g.at(0, 0).cp);
    // Control characters become U+FFFD too.
    b.list.clearRetainingCapacity();
    b.header(4, 2, 0, 0, 0, 1);
    b.u16_(0);
    b.u16_(1);
    b.run(color_default, color_default, 0, "\x1b[\xc2\x9b");
    _ = try applyFrame(&g, testing.allocator, b.list.items);
    try testing.expectEqual(@as(u21, 0xFFFD), g.at(0, 0).cp);
    try testing.expectEqual(@as(u21, '['), g.at(1, 0).cp);
    try testing.expectEqual(@as(u21, 0xFFFD), g.at(2, 0).cp);
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

fn blobFrame(id: u32, png: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try vt.gfx.appendBlobFrame(&out, testing.allocator, id, png);
    return out.toOwnedSlice(testing.allocator);
}

fn placeFrame(list: []const vt.gfx.Placement) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    const All = struct {
        fn f(_: void, _: u32) bool {
            return true;
        }
    };
    try vt.gfx.appendPlacementFrame(&out, testing.allocator, list, {}, All.f);
    return out.toOwnedSlice(testing.allocator);
}

fn gp(id: u32, col: u16, row: i32, cols: u16, rows: u16) vt.gfx.Placement {
    return .{ .image = id, .client_id = 0, .pid = 0, .col = col, .row = row, .cols = cols, .rows = rows };
}

test "image frames: blobs, placements, cache rule, unknown types" {
    const gpa = testing.allocator;
    var g: Grid = .{};
    defer g.deinit(gpa);
    // A grid first, so dirty marking has rows.
    var b: Builder = .{};
    defer b.deinit();
    b.header(10, 5, 0, 0, 1, 0);
    _ = try applyFrame(&g, gpa, b.list.items);

    const png = try imgcheck.testImage(gpa, 8, 6);
    defer gpa.free(png);
    const f1 = try blobFrame(7, png);
    defer gpa.free(f1);
    const res = try applyBinary(&g, gpa, f1);
    try testing.expect(res.images);
    try testing.expectEqual(@as(usize, 1), g.images.blobs.items.len);
    try testing.expectEqual(@as(u32, 8), g.images.find(7).?.w);

    @memset(g.dirty, false);
    const p1 = try placeFrame(&.{ gp(7, 1, -1, 3, 2), gp(99, 0, 0, 2, 2) });
    defer gpa.free(p1);
    _ = try applyBinary(&g, gpa, p1);
    // Unknown id 99 (no blob) is skipped.
    try testing.expectEqual(@as(usize, 1), g.images.places.items.len);
    try testing.expect(g.dirty[0] and !g.dirty[1]);
    try testing.expectEqual(@as(i16, -1), g.images.places.items[0].row);

    // One decode per call.
    try testing.expectEqual(@as(?u32, 7), g.images.decodeOne(gpa));
    try testing.expect(g.images.find(7).?.rgba != null);
    try testing.expectEqual(@as(?u32, null), g.images.decodeOne(gpa));

    // A 'P' without id 7 drops its blob (and pixels).
    const p2 = try placeFrame(&.{});
    defer gpa.free(p2);
    @memset(g.dirty, false);
    _ = try applyBinary(&g, gpa, p2);
    try testing.expectEqual(@as(usize, 0), g.images.blobs.items.len);
    try testing.expect(g.dirty[0]); // old placement area redraws

    // Unknown frame types and empty frames are ignored, grid untouched.
    const before = g.cols;
    _ = try applyBinary(&g, gpa, "Zwhatever");
    _ = try applyBinary(&g, gpa, "");
    try testing.expectEqual(before, g.cols);

    // An invalid PNG is kept but marked failed (placeholder).
    const f3 = try blobFrame(3, "not a png");
    defer gpa.free(f3);
    _ = try applyBinary(&g, gpa, f3);
    try testing.expect(g.images.find(3).?.failed);

    // Oversized length, lying lengths, trailing bytes.
    var big: [9]u8 = .{ 'I', 1, 0, 0, 0, 0, 1, 0, 0 }; // 256 bytes claimed, none present
    try testing.expectError(error.Malformed, applyBinary(&g, gpa, &big));
    try testing.expectError(error.Malformed, applyBinary(&g, gpa, "I\x01\x00\x00\x00\x00\x00\x00\x00X"));
    try testing.expectError(error.Malformed, applyBinary(&g, gpa, "P\x05\x00"));
    try testing.expectError(error.Malformed, applyBinary(&g, gpa, "P\xff\xff"));
    try testing.expectError(error.Malformed, applyBinary(&g, gpa, "P\x00\x00X"));

    // The blob cache is capped.
    for (0..max_blobs + 10) |k| {
        const f = try blobFrame(@intCast(1000 + k), "x");
        defer gpa.free(f);
        _ = try applyBinary(&g, gpa, f);
    }
    try testing.expectEqual(@as(usize, max_blobs), g.images.blobs.items.len);
    try testing.expectEqual(@as(usize, max_blobs), g.images.total_bytes);
}

test "image limits are the server's" {
    try testing.expectEqual(vt.max_dim, max_dim);
    try testing.expectEqual(vt.gfx.max_images, max_blobs);
    try testing.expectEqual(vt.gfx.max_total_bytes, max_blob_total_bytes);
    try testing.expectEqual(vt.gfx.max_placements, max_placements);
    try testing.expectEqual(imgcheck.max_file_bytes, screen.max_blob_bytes);
}

test "image frames: every truncation and random bytes are safe" {
    const gpa = testing.allocator;
    var g: Grid = .{};
    defer g.deinit(gpa);
    const png = try imgcheck.testImage(gpa, 4, 4);
    defer gpa.free(png);
    const f1 = try blobFrame(1, png);
    defer gpa.free(f1);
    const p1 = try placeFrame(&.{ gp(1, 0, 0, 2, 2), gp(1, 900, -30000, 65535, 65535) });
    defer gpa.free(p1);
    for ([_][]const u8{ f1, p1 }) |f| {
        for (0..f.len) |n| _ = applyBinary(&g, gpa, f[0..n]) catch {};
    }
    var prng = std.Random.DefaultPrng.init(0x1AA6E);
    const rand = prng.random();
    var buf: [300]u8 = undefined;
    for (0..20000) |_| {
        rand.bytes(&buf);
        buf[0] = "IPG"[rand.uintLessThan(usize, 3)];
        if (buf[0] == 'I') std.mem.writeInt(u32, buf[5..9], rand.uintAtMost(u32, 400), .little);
        if (buf[0] == 'P') std.mem.writeInt(u16, buf[1..3], rand.uintAtMost(u16, 25), .little);
        _ = applyBinary(&g, gpa, buf[0..rand.uintAtMost(usize, buf.len)]) catch {};
        _ = g.images.decodeOne(gpa);
        try testing.expect(g.images.blobs.items.len <= max_blobs);
        try testing.expect(g.images.total_bytes <= max_blob_total_bytes);
        try testing.expect(g.images.places.items.len <= max_placements);
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
    try testing.expectEqual(Policy.keys, parseControl("{\"t\":\"hello\",\"input\":\"keys\"}").hello.policy);
    try testing.expectEqual(Policy.text, parseControl("{\"t\": \"hello\", \"input\": \"text\"}").hello.policy);
    try testing.expectEqual(Policy.none, parseControl("{\"t\":\"hello\",\"input\":\"none\"}").hello.policy);
    try testing.expectEqual(Policy.none, parseControl("{\"t\":\"hello\",\"input\":\"bogus\"}").hello.policy);
    try testing.expectEqual(Policy.instruct, parseControl("{\"t\":\"hello\",\"input\":\"instruct\"}").hello.policy);
    // Unknown extra fields are ignored.
    try testing.expectEqual(Policy.keys, parseControl("{\"t\":\"hello\",\"input\":\"keys\",\"x\":1}").hello.policy);
    // Project names, with the escapes the server writes.
    try testing.expectEqualStrings("", parseControl("{\"t\":\"hello\",\"input\":\"keys\"}").hello.project());
    try testing.expectEqualStrings("Portal", parseControl("{\"t\":\"hello\",\"input\":\"keys\",\"project\":\"Portal\"}").hello.project());
    try testing.expectEqualStrings("a \"b\" \\c 中", parseControl("{\"t\":\"hello\",\"input\":\"keys\",\"project\":\"a \\\"b\\\" \\\\c 中\"}").hello.project());
    for ([_][]const u8{ "\"x\\n\"", "\"unterminated", "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"", "\"bad\xff\"", "7" }) |v| {
        var buf: [160]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "{{\"t\":\"hello\",\"input\":\"text\",\"project\":{s}}}", .{v});
        const h = parseControl(msg).hello;
        try testing.expectEqual(Policy.text, h.policy);
        try testing.expectEqualStrings("", h.project());
    }
    // Session state (planned server message).
    try testing.expectEqual(Control{ .state = .working }, parseControl("{\"t\":\"state\",\"state\":\"working\"}"));
    try testing.expectEqual(Control{ .state = .waiting }, parseControl("{\"t\":\"state\",\"state\":\"waiting\"}"));
    try testing.expectEqual(Control{ .state = .done }, parseControl("{\"t\":\"state\",\"state\":\"done\"}"));
    try testing.expectEqual(Control{ .state = .unknown }, parseControl("{\"t\":\"state\",\"state\":\"dancing\"}"));
    switch (parseControl("{\"t\":\"rejected\",\"reason\":\"ShellEscape\"}")) {
        .rejected => |r| try testing.expectEqualStrings("ShellEscape", r),
        else => return error.TestUnexpectedResult,
    }
    switch (parseControl("{\"t\":\"rejected\"}")) {
        .rejected => |r| try testing.expectEqualStrings("", r),
        else => return error.TestUnexpectedResult,
    }
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
    // Protocol v2: tabs.
    const h2 = parseControl("{\"t\":\"hello\",\"v\":2,\"input\":\"keys\",\"project\":\"A\",\"session\":\"000102030405060708090a0b0c0d0eff\"," ++
        "\"sessions\":[{\"id\":\"000102030405060708090a0b0c0d0eff\",\"name\":\"A\",\"color\":\"#3366cc\",\"state\":\"waiting\"}]}").hello;
    try testing.expectEqual(@as(usize, 1), h2.list.len);
    try testing.expect(h2.session != null);
    try testing.expectEqual(@as(usize, 0), parseControl("{\"t\":\"tabs\",\"sessions\":[]}").tabs.len);
    try testing.expectEqual(Control.unknown, parseControl("{\"t\":\"tabs\",\"sessions\":[{}]}"));
    try testing.expectEqual(@as(u8, 0xff), parseControl("{\"t\":\"session\",\"id\":\"000102030405060708090a0b0c0d0eff\"}").session[15]);
    try testing.expectEqual(Control.nosession, parseControl("{\"t\":\"nosession\"}"));
    try testing.expectEqual(Control.unknown, parseControl("{\"t\":\"ended\",\"id\":\"zz\"}"));
}

test "utf8 single" {
    try testing.expectEqual(@as(?u21, 'a'), Utf8Iter.single("a"));
    try testing.expectEqual(@as(?u21, 'é'), Utf8Iter.single("é"));
    try testing.expectEqual(@as(?u21, null), Utf8Iter.single("ab"));
    try testing.expectEqual(@as(?u21, null), Utf8Iter.single(""));
    try testing.expectEqual(@as(?u21, null), Utf8Iter.single("\xff"));
}
