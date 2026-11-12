//! TermView: a terminal grid view in its own window, drawn with the
//! Renderer's Instanced2D. Owns the window/surface, fonts, glyph atlas,
//! theme, fit/zoom, cursor, selection highlight, top bar, answer bar and
//! status line. Knows nothing about networking or PTYs: hosts feed it a
//! `Grid` snapshot plus an `Overlay` describing the chrome, and receive
//! input through an `InputSink`.
//!
//! Layout, top to bottom: top bar (optional, `Overlay.top_bar`), grid,
//! answer bar (optional), status line.
//!
//!     var tv = try TermView.init(gpa, io, .{ .title = "Portal" });
//!     defer tv.deinit();
//!     while (tv.pollEvents(sink)) {
//!         lock(); tv.build(&grid, overlay); unlock();   // CPU work only
//!         tv.present();                                  // GPU submit + vsync
//!         tv.waitEvents(250);
//!     }

const std = @import("std");
const Renderer = @import("Renderer");
const Instanced2D = Renderer.Instanced2D;
const platform = @import("platform/platform.zig");
const input = @import("input.zig");
const grid_mod = @import("grid.zig");
const wcwidth = @import("wcwidth.zig");
const fontset = @import("font/fontset.zig");
const Atlas = @import("font/atlas.zig").Atlas;
const images = @import("images.zig");

/// The texture: glyph atlas in rows 0..2047, inline images below it.
const tex_w: u32 = 2048;
const tex_h: u32 = images.region_y + images.region_h;

const TermView = @This();
const Rgb = grid_mod.Rgb;
const Grid = grid_mod.Grid;

pub const Tone = enum { normal, muted, good, warn, bad };

pub const Message = struct {
    title: []const u8,
    title_tone: Tone = .normal,
    lines: []const []const u8 = &.{},
    button: ?struct { label: []const u8, id: u32 } = null,
    detail: []const u8 = "",
    detail_tone: Tone = .muted,
};

pub const StatusLine = struct {
    tone: Tone = .muted,
    label: []const u8 = "",
    extra: []const u8 = "",
    extra_tone: Tone = .muted,
    right: []const u8 = "",
};

/// The strip above the grid. Today it shows one session's title and the
/// remote-viewer badge; it is the reserved slot for a tab strip (one tab per
/// session, coloured per project), which would replace `drawTopBar`.
pub const TopBar = struct {
    title: []const u8 = "",
    /// Coloured strip at the left edge (a per-project colour later).
    accent: ?Rgb = null,
    right: []const u8 = "",
    right_tone: Tone = .muted,
    /// Draw `right` as a filled, high-contrast badge (someone is watching).
    right_badge: bool = false,
};

/// A linear (reading-order) cell selection, inclusive, start <= end.
pub const Selection = struct {
    start_col: u16,
    start_row: u16,
    end_col: u16,
    end_row: u16,

    pub fn contains(s: Selection, col: usize, row: usize) bool {
        if (row < s.start_row or row > s.end_row) return false;
        if (row == s.start_row and col < s.start_col) return false;
        if (row == s.end_row and col > s.end_col) return false;
        return true;
    }
};

pub const Overlay = struct {
    /// `.grid` draws the grid (if it has cells); `.message` a centred notice.
    screen: union(enum) { grid, message: Message } = .grid,
    top_bar: ?TopBar = null,
    selection: ?Selection = null,
    show_answers: bool = false,
    status: StatusLine = .{},
};

pub const Sizing = union(enum) {
    /// Scale the font so the host's cols x rows fit the window (remote view).
    fit_grid,
    /// Fixed font size in logical pixels; the window decides cols x rows
    /// (reported through InputSink.resized; local terminal hosts).
    fixed_em: f32,
};

pub const Options = struct {
    title: []const u8 = "Portal",
    width: u32 = 1000,
    height: u32 = 640,
    sizing: Sizing = .fit_grid,
    theme: grid_mod.Theme = .{},
};

const Button = struct { x: f32, y: f32, w: f32, h: f32, action: union(enum) { answer: []const u8, button: u32 } };

const ui_bg: Rgb = .{ 0x20, 0x23, 0x29 };
const button_bg: Rgb = .{ 0x31, 0x36, 0x3F };
const button_fg: Rgb = .{ 0xE6, 0xE9, 0xED };

fn toneColor(t: Tone) Rgb {
    return switch (t) {
        .normal => button_fg,
        .muted => .{ 0x9A, 0xA3, 0xAD },
        .good => .{ 0x6C, 0xC0, 0x70 },
        .warn => .{ 0xE8, 0xB0, 0x4C },
        .bad => .{ 0xE0, 0x6C, 0x6C },
    };
}

gpa: std.mem.Allocator,
window: *platform.Window,
renderer: *Instanced2D,
fonts: fontset.FontSet,
atlas: Atlas,
theme: grid_mod.Theme,
sizing: Sizing,
instances: std.ArrayList(Instanced2D.Instance) = .empty,
buttons: [16]Button = undefined,
n_buttons: usize = 0,
zoom_steps: i32 = 0,
atlas_full: bool = false,
dirty: bool = true,
/// Cells that fit the window at the current font size (fixed_em sizing).
capacity: [2]u16 = .{ 0, 0 },
reported_capacity: [2]u16 = .{ 0, 0 },
/// Where the last built grid was drawn (pixels), for mouse -> cell.
layout: struct { ox: f32 = 0, oy: f32 = 0, cw: f32 = 1, ch: f32 = 1, cols: u16 = 0, rows: u16 = 0 } = .{},
live_ctx: ?*anyopaque = null,
live_fn: ?platform.LiveFn = null,
/// Inline images (decode, scale, pack into the texture's image region).
img: images.Layer,

pub fn init(gpa: std.mem.Allocator, io: std.Io, options: Options) !*TermView {
    const self = try gpa.create(TermView);
    errdefer gpa.destroy(self);
    var fonts = try fontset.FontSet.load(gpa, io);
    errdefer fonts.deinit();
    const window = try platform.Window.init(gpa, options.title, options.width, options.height);
    errdefer window.deinit();
    const fb = window.framebufferSize();
    const renderer = try Instanced2D.init(gpa, window.surfaceSource(), fb[0], fb[1], .{
        .app_name = "Portal",
        .texture_width = tex_w,
        .texture_height = tex_h,
    });
    errdefer renderer.deinit();
    var atlas = try Atlas.init(gpa, tex_w, 2048);
    atlas.tex_h = tex_h;
    self.* = .{
        .gpa = gpa,
        .window = window,
        .renderer = renderer,
        .fonts = fonts,
        .atlas = atlas,
        .theme = options.theme,
        .sizing = options.sizing,
        .img = .init(gpa),
    };
    window.setLiveCallback(self, liveThunk);
    return self;
}

pub fn deinit(tv: *TermView) void {
    tv.renderer.deinit();
    tv.window.deinit();
    tv.atlas.deinit();
    tv.img.deinit();
    tv.fonts.deinit();
    tv.instances.deinit(tv.gpa);
    tv.gpa.destroy(tv);
}

/// Called while the OS runs a modal resize loop (Win32); the host should
/// build + present from its current state.
pub fn setLiveRedraw(tv: *TermView, ctx: *anyopaque, f: platform.LiveFn) void {
    tv.live_ctx = ctx;
    tv.live_fn = f;
}

fn liveThunk(ctx: *anyopaque) void {
    const tv: *TermView = @ptrCast(@alignCast(ctx));
    while (tv.window.pollQueued()) |e| tv.handleViewEvent(e);
    if (tv.live_fn) |f| f(tv.live_ctx.?);
}

/// Thread-safe: wakes a waitEvents (e.g. after new data arrived).
pub fn wake(tv: *TermView) void {
    tv.window.wake();
}

pub fn waitEvents(tv: *TermView, timeout_ms: u32) void {
    tv.window.waitEvents(if (tv.dirty) 0 else timeout_ms);
}

pub fn setTitle(tv: *TermView, title: []const u8) void {
    tv.window.setTitle(title);
}

/// True if the view itself needs a redraw (input, resize, zoom).
pub fn needsRedraw(tv: *const TermView) bool {
    return tv.dirty;
}

/// Pumps window events. Returns false once the user closed the window.
pub fn pollEvents(tv: *TermView, sink: input.InputSink) bool {
    var open = true;
    while (tv.window.pollEvent()) |e| {
        switch (e) {
            .close => open = false,
            .key => |k| sink.key(k.key, k.mods),
            .char => |c| sink.char(c.cp, c.mods),
            .mouse_down => |m| {
                var hit = false;
                if (m.button == .left) for (tv.buttons[0..tv.n_buttons]) |b| {
                    if (m.x >= b.x and m.x < b.x + b.w and m.y >= b.y and m.y < b.y + b.h) {
                        switch (b.action) {
                            .answer => |a| sink.answer(a),
                            .button => |id| sink.button(id),
                        }
                        hit = true;
                        break;
                    }
                };
                if (!hit) sink.mouse(tv.mouseAt(.down, m.button, m.x, m.y, m.mods));
            },
            .mouse_move => |m| sink.mouse(tv.mouseAt(.move, .left, m.x, m.y, .{})),
            .mouse_up => |m| sink.mouse(tv.mouseAt(.up, m.button, m.x, m.y, .{})),
            else => tv.handleViewEvent(e),
        }
        tv.dirty = true;
    }
    tv.reportCapacity(sink);
    return open;
}

/// Tells the sink if the cells that fit the window changed since the last
/// report. pollEvents calls it; hosts may also call it from a live redraw
/// (during a modal resize) so the PTY follows the drag.
pub fn reportCapacity(tv: *TermView, sink: input.InputSink) void {
    if (tv.capacity[0] == 0 or tv.capacity[1] == 0) return;
    if (tv.capacity[0] != tv.reported_capacity[0] or tv.capacity[1] != tv.reported_capacity[1]) {
        tv.reported_capacity = tv.capacity;
        const fb = tv.window.framebufferSize();
        sink.resized(fb[0], fb[1], tv.capacity[0], tv.capacity[1]);
    }
}

/// Maps a window pixel to a grid cell of the last built frame.
fn mouseAt(tv: *const TermView, action: @FieldType(input.Mouse, "action"), button: input.MouseButton, x: f32, y: f32, mods: input.Mods) input.Mouse {
    const l = tv.layout;
    const fx = (x - l.ox) / l.cw;
    const fy = (y - l.oy) / l.ch;
    const inside = l.cols > 0 and l.rows > 0 and fx >= 0 and fy >= 0 and
        fx < @as(f32, @floatFromInt(l.cols)) and fy < @as(f32, @floatFromInt(l.rows));
    return .{
        .action = action,
        .button = button,
        .col = clampCell(fx, l.cols),
        .row = clampCell(fy, l.rows),
        .inside = inside,
        .mods = mods,
    };
}

fn clampCell(f: f32, n: u16) u16 {
    if (n == 0 or !(f > 0)) return 0; // also catches NaN
    const max: f32 = @floatFromInt(n - 1);
    return @intFromFloat(@min(@floor(f), max));
}

/// How many cells of `cell_w` x `cell_h` pixels fit in `w` x `h` pixels
/// with `pad` pixels on every side. At least 1 x 1, at most 1000 x 1000.
pub fn fitCells(w: f32, h: f32, cell_w: u32, cell_h: u32, pad: f32) [2]u16 {
    const cw: f32 = @floatFromInt(@max(cell_w, 1));
    const ch: f32 = @floatFromInt(@max(cell_h, 1));
    return .{ fitCount((w - 2 * pad) / cw), fitCount((h - 2 * pad) / ch) };
}

fn fitCount(f: f32) u16 {
    if (!(f >= 1)) return 1; // also NaN
    if (f >= 1000) return 1000;
    return @intFromFloat(@floor(f));
}

test "fitCells" {
    try std.testing.expectEqual([2]u16{ 80, 24 }, fitCells(808, 488, 10, 20, 4));
    try std.testing.expectEqual([2]u16{ 79, 23 }, fitCells(807, 487, 10, 20, 4));
    try std.testing.expectEqual([2]u16{ 1, 1 }, fitCells(0, 0, 10, 20, 4));
    try std.testing.expectEqual([2]u16{ 1, 1 }, fitCells(-50, std.math.nan(f32), 10, 20, 4));
    try std.testing.expectEqual([2]u16{ 1000, 1000 }, fitCells(1e9, 1e9, 1, 1, 0));
    try std.testing.expectEqual([2]u16{ 100, 50 }, fitCells(100, 50, 0, 0, 0));
}

test "selection contains" {
    const s: Selection = .{ .start_col = 5, .start_row = 1, .end_col = 2, .end_row = 3 };
    try std.testing.expect(!s.contains(4, 1));
    try std.testing.expect(s.contains(5, 1));
    try std.testing.expect(s.contains(0, 2));
    try std.testing.expect(s.contains(2, 3));
    try std.testing.expect(!s.contains(3, 3));
    try std.testing.expect(!s.contains(0, 0));
}

fn handleViewEvent(tv: *TermView, e: input.Event) void {
    tv.dirty = true;
    switch (e) {
        .resize => |r| tv.renderer.resize(r.width, r.height),
        .zoom => |z| tv.zoom_steps = switch (z) {
            .in => @min(tv.zoom_steps + 1, 20),
            .out => @max(tv.zoom_steps - 1, -10),
            .reset => 0,
        },
        else => {},
    }
}

// ------------------------------------------------------------ drawing

fn push(tv: *TermView, x: f32, y: f32, w: f32, h: f32, uv: [4]f32, c: Rgb) void {
    tv.pushA(x, y, w, h, uv, c, 255);
}

fn pushA(tv: *TermView, x: f32, y: f32, w: f32, h: f32, uv: [4]f32, c: Rgb, a: u8) void {
    tv.instances.append(tv.gpa, .{ .rect = .{ x, y, w, h }, .uv = uv, .color = .{ c[0], c[1], c[2], a } }) catch {};
}

fn rect(tv: *TermView, x: f32, y: f32, w: f32, h: f32, c: Rgb) void {
    tv.push(x, y, w, h, tv.atlas.whiteUv(), c);
}

fn glyph(tv: *TermView, cp: u21, style: fontset.Style, m: fontset.Metrics, cells: u32, x: f32, y: f32, c: Rgb) void {
    const slot = tv.atlas.get(&tv.fonts, cp, style, m, cells) orelse {
        tv.atlas_full = true;
        return;
    };
    tv.push(x, y, @floatFromInt(slot.w), @floatFromInt(slot.h), tv.atlas.uv(slot), c);
}

fn textWidth(m: fontset.Metrics, s: []const u8) f32 {
    var n: u32 = 0;
    var it = (std.unicode.Utf8View.init(s) catch return 0).iterator();
    while (it.nextCodepoint()) |cp| n += wcwidth.of(cp);
    return @floatFromInt(n * m.cell_w);
}

fn text(tv: *TermView, m: fontset.Metrics, x0: f32, y: f32, s: []const u8, c: Rgb, bold: bool) f32 {
    var x = x0;
    var it = (std.unicode.Utf8View.init(s) catch return x).iterator();
    while (it.nextCodepoint()) |cp| {
        const w = wcwidth.of(cp);
        if (w == 0) continue;
        if (cp != ' ' and cp >= 0x20) tv.glyph(cp, .{ .bold = bold }, m, w, x, y, c);
        x += @floatFromInt(w * m.cell_w);
    }
    return x;
}

fn addButton(tv: *TermView, m: fontset.Metrics, x: f32, y: f32, h: f32, label: []const u8, b: Button) f32 {
    const pad: f32 = @floatFromInt(m.cell_w);
    const w = textWidth(m, label) + 2 * pad;
    tv.rect(x, y, w, h, button_bg);
    _ = tv.text(m, x + pad, y + (h - @as(f32, @floatFromInt(m.cell_h))) / 2, label, button_fg, true);
    if (tv.n_buttons < tv.buttons.len) {
        var bb = b;
        bb.x = x;
        bb.y = y;
        bb.w = w;
        bb.h = h;
        tv.buttons[tv.n_buttons] = bb;
        tv.n_buttons += 1;
    }
    return w;
}

/// Builds the frame from `grid` and `overlay` (CPU only: hold the host's
/// lock around this, not around present()).
pub fn build(tv: *TermView, grid: *const Grid, overlay: Overlay) void {
    tv.buildOnce(grid, overlay);
    if (tv.atlas_full or tv.img.full) {
        // Out of atlas / image space: start over with only what is on
        // screen now.
        if (tv.atlas_full) tv.atlas.wipe();
        if (tv.img.full) tv.img.wipe();
        tv.buildOnce(grid, overlay);
    }
    // Images still waiting to be decoded: come back next frame.
    if (tv.img.needs_more) tv.dirty = true;
}

/// Uploads new glyphs and presents the last built frame.
pub fn present(tv: *TermView) void {
    if (tv.atlas.takeDirty()) |d| {
        tv.renderer.updateTexture(d.x, d.y, d.w, d.h, d.bytes) catch |err| std.log.warn("atlas upload failed: {t}", .{err});
    }
    for (tv.img.uploads.items) |u| {
        tv.renderer.updateTexture(u.x, images.region_y + u.y, u.w, u.h, u.px) catch |err| std.log.warn("image upload failed: {t}", .{err});
    }
    tv.img.clearUploads();
    const bg = tv.theme.bg;
    tv.renderer.drawFrame(.{
        @as(f32, @floatFromInt(bg[0])) / 255,
        @as(f32, @floatFromInt(bg[1])) / 255,
        @as(f32, @floatFromInt(bg[2])) / 255,
        1,
    }, tv.instances.items) catch |err| std.log.warn("draw failed: {t}", .{err});
    tv.dirty = false;
}

pub fn draw(tv: *TermView, grid: *const Grid, overlay: Overlay) void {
    tv.build(grid, overlay);
    tv.present();
}

fn buildOnce(tv: *TermView, grid: *const Grid, overlay: Overlay) void {
    tv.atlas_full = false;
    tv.instances.clearRetainingCapacity();
    tv.n_buttons = 0;
    const size = tv.window.framebufferSize();
    const W: f32 = @floatFromInt(size[0]);
    const H: f32 = @floatFromInt(size[1]);
    if (W < 1 or H < 1) return;
    const s = tv.window.scale();
    const ui = tv.fonts.metrics(@round(13 * s));
    const status_h: f32 = @round(@as(f32, @floatFromInt(ui.cell_h)) * 1.6);
    const bar_h: f32 = if (overlay.show_answers) @round(@as(f32, @floatFromInt(ui.cell_h)) * 2.4) else 0;
    const top_h: f32 = if (overlay.top_bar != null) topBarHeight(ui) else 0;
    const grid_h = @max(0, H - status_h - bar_h - top_h);

    tv.layout.cols = 0;
    tv.layout.rows = 0;
    switch (overlay.screen) {
        .grid => {
            const m = tv.cellMetrics(grid, W, grid_h, s);
            tv.capacity = fitCells(W, grid_h, m.cell_w, m.cell_h, 4 * s);
            if (grid.cols > 0 and grid.rows > 0) tv.drawGrid(grid, overlay.selection, m, W, top_h, grid_h, s);
        },
        .message => |msg| tv.drawMessage(ui, msg, W, top_h, grid_h, s),
    }
    if (overlay.top_bar) |tb| tv.drawTopBar(ui, tb, W, top_h, s);
    if (overlay.show_answers) tv.drawAnswerBar(ui, top_h + grid_h, W, bar_h, s);
    tv.drawStatus(ui, overlay.status, H - status_h, W, status_h, s);
}

fn topBarHeight(ui: fontset.Metrics) f32 {
    return @round(@as(f32, @floatFromInt(ui.cell_h)) * 1.8);
}

/// The top bar (see `TopBar`): the hook a tab strip would replace.
fn drawTopBar(tv: *TermView, ui: fontset.Metrics, tb: TopBar, W: f32, h: f32, s: f32) void {
    tv.rect(0, 0, W, h, ui_bg);
    const pad = @round(8 * s);
    var x: f32 = pad;
    if (tb.accent) |a| {
        tv.rect(0, 0, @round(4 * s), h, a);
        x += @round(4 * s);
    }
    const ty = @round((h - @as(f32, @floatFromInt(ui.cell_h))) / 2);
    var right_w: f32 = 0;
    if (tb.right.len > 0) {
        const tw = textWidth(ui, tb.right);
        if (tb.right_badge) {
            const bw = tw + 2 * pad;
            const bh = @round(h * 0.8);
            const bx = W - pad - bw;
            const color = toneColor(tb.right_tone);
            tv.rect(bx, @round((h - bh) / 2), bw, bh, color);
            _ = tv.text(ui, bx + pad, ty, tb.right, ui_bg, true);
            right_w = bw + pad;
        } else {
            _ = tv.text(ui, W - pad - tw, ty, tb.right, toneColor(tb.right_tone), false);
            right_w = tw + pad;
        }
    }
    // Title, cut to the space left of the right-hand text.
    const avail = W - x - right_w - 2 * pad;
    var cut: usize = 0;
    var used: f32 = 0;
    var it = (std.unicode.Utf8View.init(tb.title) catch return).iterator();
    while (it.nextCodepointSlice()) |cs| {
        const cp = std.unicode.utf8Decode(cs) catch break;
        const cw: f32 = @floatFromInt(wcwidth.of(cp) * ui.cell_w);
        if (used + cw > avail) break;
        used += cw;
        cut = it.i;
    }
    _ = tv.text(ui, x, ty, tb.title[0..cut], button_fg, true);
}

fn zoomed(tv: *const TermView, em: f32) f32 {
    if (tv.zoom_steps == 0) return em;
    const z = std.math.pow(f32, 1.1, @floatFromInt(tv.zoom_steps));
    return std.math.clamp(@round(em * z * 2) / 2, 5, 120);
}

/// Font metrics for the grid: fitted to cols x rows, or the fixed size.
fn cellMetrics(tv: *TermView, grid: *const Grid, w: f32, h: f32, s: f32) fontset.Metrics {
    switch (tv.sizing) {
        .fixed_em => |em| return tv.fonts.metrics(tv.zoomed(@round(em * s * 2) / 2)),
        .fit_grid => {},
    }
    const cols = @max(grid.cols, 1);
    const rows = @max(grid.rows, 1);
    const asp = tv.fonts.aspect();
    const pad = 4 * s;
    const aw = @max(1, w - 2 * pad);
    const ah = @max(1, h - 2 * pad);
    var em = @min(aw / (@as(f32, @floatFromInt(cols)) * asp.w_per_em), ah / (@as(f32, @floatFromInt(rows)) * asp.h_per_em));
    em = std.math.clamp(@floor(em * 2) / 2, 5, 40 * s);
    var m = tv.fonts.metrics(em);
    while (em > 5 and (@as(f32, @floatFromInt(m.cell_w * cols)) > aw or @as(f32, @floatFromInt(m.cell_h * rows)) > ah)) {
        em -= 0.5;
        m = tv.fonts.metrics(em);
    }
    if (tv.zoom_steps != 0) m = tv.fonts.metrics(tv.zoomed(em));
    return m;
}

fn drawGrid(tv: *TermView, g: *const Grid, sel: ?Selection, m: fontset.Metrics, W: f32, y0: f32, area_h: f32, s: f32) void {
    const cw: f32 = @floatFromInt(m.cell_w);
    const ch: f32 = @floatFromInt(m.cell_h);
    const gw = cw * @as(f32, @floatFromInt(g.cols));
    const gh = ch * @as(f32, @floatFromInt(g.rows));
    // Centre when it fits; pin to the top-left when zoomed past the window.
    const ox = @round(@max(4 * s, (W - gw) / 2));
    const oy = y0 + @round(@max(4 * s, (area_h - gh) / 2));
    const H = y0 + area_h;
    tv.layout = .{ .ox = ox, .oy = oy, .cw = cw, .ch = ch, .cols = g.cols, .rows = g.rows };
    const t = tv.theme;
    // Pass 1: cell backgrounds (cursor and selection come later, over images).
    for (0..g.rows) |y| {
        const py = oy + ch * @as(f32, @floatFromInt(y));
        if (py >= H) break;
        for (g.row(y), 0..) |c, x| {
            if (c.kind == .continuation) continue;
            const px = ox + cw * @as(f32, @floatFromInt(x));
            if (px >= W) break;
            const cells: u32 = if (c.kind == .wide) 2 else 1;
            const bg = t.resolveBg(c.bg);
            const hpx = @min(ch, H - py);
            if (!std.mem.eql(u8, &bg, &t.bg)) tv.rect(px, py, cw * @as(f32, @floatFromInt(cells)), hpx, bg);
        }
    }
    // Pass 2: inline images, clipped to the grid and the window.
    const n_inst = tv.instances.items.len;
    tv.drawImages(g, m, ox, oy, @min(ox + gw, W), @min(oy + gh, H));
    const has_images = tv.instances.items.len > n_inst;
    // Pass 3: cursor, selection, glyphs and decorations.
    for (0..g.rows) |y| {
        const py = oy + ch * @as(f32, @floatFromInt(y));
        if (py >= H) break;
        for (g.row(y), 0..) |c, x| {
            if (c.kind == .continuation) continue;
            const px = ox + cw * @as(f32, @floatFromInt(x));
            if (px >= W) break;
            const cells: u32 = if (c.kind == .wide) 2 else 1;
            var fg = t.resolveFg(c.fg);
            var bg = t.resolveBg(c.bg);
            var over: ?u8 = null; // alpha of a cursor / selection fill
            if (g.cursor_visible and x == g.cursor_x and y == g.cursor_y) {
                fg = t.bg;
                bg = t.cursor;
                over = 255;
            } else if (sel) |sl| if (sl.contains(x, y)) {
                bg = t.selection;
                // Translucent where images could be under it.
                over = if (has_images) 170 else 255;
            };
            if (c.attrs.dim) fg = mix(fg, bg);
            const wpx = cw * @as(f32, @floatFromInt(cells));
            // Clip the last row/column to the grid area (zoomed past the window).
            const hpx = @min(ch, H - py);
            if (over) |a| tv.pushA(px, py, wpx, hpx, tv.atlas.whiteUv(), bg, a);
            if (c.cp != ' ') tv.glyph(c.cp, .{ .bold = c.attrs.bold, .italic = c.attrs.italic }, m, cells, px, py, fg);
            const stroke: f32 = @floatFromInt(m.stroke);
            if (c.attrs.underline) tv.rect(px, py + @as(f32, @floatFromInt(m.underline_y)), wpx, stroke, fg);
            if (c.attrs.strike) tv.rect(px, py + @round(m.baseline * 0.62), wpx, stroke, fg);
        }
    }
}

/// Pushes the grid's image placements (above backgrounds, below text).
fn drawImages(tv: *TermView, g: *const Grid, m: fontset.Metrics, ox: f32, oy: f32, clip_x1: f32, clip_y1: f32) void {
    tv.img.begin();
    defer tv.img.end();
    const cw: f32 = @floatFromInt(m.cell_w);
    const ch: f32 = @floatFromInt(m.cell_h);
    for (g.images.placements.items) |p| {
        const x = ox + cw * @as(f32, @floatFromInt(p.col));
        const y = oy + ch * @as(f32, @floatFromInt(p.row));
        const w = cw * @as(f32, @floatFromInt(p.cols));
        const h = ch * @as(f32, @floatFromInt(p.rows));
        if (x >= clip_x1 or y >= clip_y1 or x + w <= ox or y + h <= oy) continue;
        const dw: u32 = @intCast(@min(@as(u64, m.cell_w) * p.cols, 1 << 16));
        const dh: u32 = @intCast(@min(@as(u64, m.cell_h) * p.rows, 1 << 16));
        switch (tv.img.prepare(&g.images, p.id, dw, dh, tex_w, tex_h)) {
            .image => |uv| if (images.clip(x, y, w, h, uv, ox, oy, clip_x1, clip_y1)) |c| {
                tv.pushA(c.rect[0], c.rect[1], c.rect[2], c.rect[3], c.uv, .{ 255, 255, 255 }, 255);
            },
            .placeholder => |dims| tv.placeholder(m, x, y, w, h, dims, ox, oy, clip_x1, clip_y1),
            .none => {},
        }
    }
}

/// A box with the image's pixel size, for images that can't be decoded.
fn placeholder(tv: *TermView, m: fontset.Metrics, x: f32, y: f32, w: f32, h: f32, dims: [2]u32, cx0: f32, cy0: f32, cx1: f32, cy1: f32) void {
    const c = toneColor(.muted);
    const s: f32 = @floatFromInt(@max(m.stroke, 1));
    const white = tv.atlas.whiteUv();
    const edges = [_][4]f32{ .{ x, y, w, s }, .{ x, y + h - s, w, s }, .{ x, y, s, h }, .{ x + w - s, y, s, h } };
    for (edges) |e| if (images.clip(e[0], e[1], e[2], e[3], white, cx0, cy0, cx1, cy1)) |r| {
        tv.push(r.rect[0], r.rect[1], r.rect[2], r.rect[3], r.uv, c);
    };
    var buf: [48]u8 = undefined;
    const label = if (dims[0] > 0)
        std.fmt.bufPrint(&buf, "image {d}\u{00D7}{d}", .{ dims[0], dims[1] }) catch "image"
    else
        "image";
    const lw = textWidth(m, label);
    const ch: f32 = @floatFromInt(m.cell_h);
    if (lw + 2 * s <= w and h >= ch and y >= cy0 and y + ch <= cy1 and x + lw < cx1) {
        _ = tv.text(m, x + @round((w - lw) / 2), y + @round((h - ch) / 2), label, c, false);
    }
}

fn mix(a: Rgb, b: Rgb) Rgb {
    return .{
        @intCast((@as(u16, a[0]) + b[0]) / 2),
        @intCast((@as(u16, a[1]) + b[1]) / 2),
        @intCast((@as(u16, a[2]) + b[2]) / 2),
    };
}

fn centreX(w: f32, tw: f32) f32 {
    return @round(@max(0, (w - tw) / 2));
}

fn drawMessage(tv: *TermView, ui: fontset.Metrics, msg: Message, W: f32, y0: f32, H: f32, s: f32) void {
    const big = tv.fonts.metrics(@round(20 * s));
    const lh: f32 = @floatFromInt(ui.cell_h);
    var y = y0 + @round(H * 0.28);
    _ = tv.text(big, centreX(W, textWidth(big, msg.title)), y, msg.title, toneColor(msg.title_tone), true);
    y += @as(f32, @floatFromInt(big.cell_h)) + lh;
    for (msg.lines) |l| {
        _ = tv.text(ui, centreX(W, textWidth(ui, l)), y, l, toneColor(.muted), false);
        y += lh * 1.4;
    }
    if (msg.button) |b| {
        y += lh;
        const bh = @round(lh * 2.2);
        const bw = textWidth(ui, b.label) + 2 * @as(f32, @floatFromInt(ui.cell_w));
        _ = tv.addButton(ui, centreX(W, bw), y, bh, b.label, .{ .x = 0, .y = 0, .w = 0, .h = 0, .action = .{ .button = b.id } });
        y += bh + lh;
    }
    if (msg.detail.len > 0) _ = tv.text(ui, centreX(W, textWidth(ui, msg.detail)), y, msg.detail, toneColor(msg.detail_tone), false);
}

fn drawAnswerBar(tv: *TermView, ui: fontset.Metrics, y: f32, W: f32, h: f32, s: f32) void {
    tv.rect(0, y, W, h, ui_bg);
    const gap = @round(6 * s);
    const bh = @round(h * 0.72);
    const by = y + @round((h - bh) / 2);
    var total: f32 = 0;
    for (input.answers) |a| total += textWidth(ui, a.label) + 2 * @as(f32, @floatFromInt(ui.cell_w)) + gap;
    var x = @round(@max(gap, (W - total + gap) / 2));
    for (input.answers) |a| {
        x += tv.addButton(ui, x, by, bh, a.label, .{ .x = 0, .y = 0, .w = 0, .h = 0, .action = .{ .answer = a.key } }) + gap;
    }
}

fn drawStatus(tv: *TermView, ui: fontset.Metrics, st: StatusLine, y: f32, W: f32, h: f32, s: f32) void {
    tv.rect(0, y, W, h, ui_bg);
    const ty = y + @round((h - @as(f32, @floatFromInt(ui.cell_h))) / 2);
    const pad = @round(8 * s);
    const dot = @round(@as(f32, @floatFromInt(ui.cell_h)) * 0.45);
    tv.rect(pad, y + @round((h - dot) / 2), dot, dot, toneColor(st.tone));
    var x = pad + dot + pad;
    x = tv.text(ui, x, ty, st.label, button_fg, true);
    if (st.extra.len > 0) {
        x = tv.text(ui, x, ty, "  \u{00B7}  ", toneColor(.muted), false);
        x = tv.text(ui, x, ty, st.extra, toneColor(st.extra_tone), false);
    }
    if (st.right.len > 0) _ = tv.text(ui, W - pad - textWidth(ui, st.right), ty, st.right, toneColor(.muted), false);
}
