//! TermView: a terminal grid view in its own window, drawn with the
//! Renderer's Instanced2D. Owns the window/surface, fonts, glyph atlas,
//! theme, fit/zoom, cursor, answer bar and status line. Knows nothing about
//! networking: hosts feed it a `Grid` snapshot plus an `Overlay` describing
//! the chrome, and receive input through an `InputSink`.
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

pub const Overlay = struct {
    /// `.grid` draws the grid (if it has cells); `.message` a centred notice.
    screen: union(enum) { grid, message: Message } = .grid,
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
live_ctx: ?*anyopaque = null,
live_fn: ?platform.LiveFn = null,

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
        .texture_width = 2048,
        .texture_height = 2048,
    });
    errdefer renderer.deinit();
    self.* = .{
        .gpa = gpa,
        .window = window,
        .renderer = renderer,
        .fonts = fonts,
        .atlas = try Atlas.init(gpa, 2048, 2048),
        .theme = options.theme,
        .sizing = options.sizing,
    };
    window.setLiveCallback(self, liveThunk);
    return self;
}

pub fn deinit(tv: *TermView) void {
    tv.renderer.deinit();
    tv.window.deinit();
    tv.atlas.deinit();
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
            .mouse_down => |m| for (tv.buttons[0..tv.n_buttons]) |b| {
                if (m.x >= b.x and m.x < b.x + b.w and m.y >= b.y and m.y < b.y + b.h) {
                    switch (b.action) {
                        .answer => |a| sink.answer(a),
                        .button => |id| sink.button(id),
                    }
                    break;
                }
            },
            else => tv.handleViewEvent(e),
        }
        tv.dirty = true;
    }
    if (tv.capacity[0] != tv.reported_capacity[0] or tv.capacity[1] != tv.reported_capacity[1]) {
        tv.reported_capacity = tv.capacity;
        const fb = tv.window.framebufferSize();
        sink.resized(fb[0], fb[1], tv.capacity[0], tv.capacity[1]);
    }
    return open;
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
    tv.instances.append(tv.gpa, .{ .rect = .{ x, y, w, h }, .uv = uv, .color = .{ c[0], c[1], c[2], 255 } }) catch {};
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
    if (tv.atlas_full) {
        // Out of atlas space: start over with only what is on screen now.
        tv.atlas.wipe();
        tv.buildOnce(grid, overlay);
    }
}

/// Uploads new glyphs and presents the last built frame.
pub fn present(tv: *TermView) void {
    if (tv.atlas.takeDirty()) |d| {
        tv.renderer.updateTexture(d.x, d.y, d.w, d.h, d.bytes) catch |err| std.log.warn("atlas upload failed: {t}", .{err});
    }
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
    const grid_h = @max(0, H - status_h - bar_h);

    switch (overlay.screen) {
        .grid => {
            const m = tv.cellMetrics(grid, W, grid_h, s);
            const pad = 4 * s;
            tv.capacity = .{
                @intFromFloat(@max(1, @floor((W - 2 * pad) / @as(f32, @floatFromInt(m.cell_w))))),
                @intFromFloat(@max(1, @floor((grid_h - 2 * pad) / @as(f32, @floatFromInt(m.cell_h))))),
            };
            if (grid.cols > 0 and grid.rows > 0) tv.drawGrid(grid, m, W, grid_h, s);
        },
        .message => |msg| tv.drawMessage(ui, msg, W, grid_h, s),
    }
    if (overlay.show_answers) tv.drawAnswerBar(ui, grid_h, W, bar_h, s);
    tv.drawStatus(ui, overlay.status, H - status_h, W, status_h, s);
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

fn drawGrid(tv: *TermView, g: *const Grid, m: fontset.Metrics, W: f32, H: f32, s: f32) void {
    const cw: f32 = @floatFromInt(m.cell_w);
    const ch: f32 = @floatFromInt(m.cell_h);
    const gw = cw * @as(f32, @floatFromInt(g.cols));
    const gh = ch * @as(f32, @floatFromInt(g.rows));
    // Centre when it fits; pin to the top-left when zoomed past the window.
    const ox = @round(@max(4 * s, (W - gw) / 2));
    const oy = @round(@max(4 * s, (H - gh) / 2));
    const t = tv.theme;
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
            if (g.cursor_visible and x == g.cursor_x and y == g.cursor_y) {
                fg = t.bg;
                bg = t.cursor;
            }
            if (c.attrs.dim) fg = mix(fg, bg);
            const wpx = cw * @as(f32, @floatFromInt(cells));
            // Clip the last row/column to the grid area (zoomed past the window).
            const hpx = @min(ch, H - py);
            if (!std.mem.eql(u8, &bg, &t.bg)) tv.rect(px, py, wpx, hpx, bg);
            if (c.cp != ' ') tv.glyph(c.cp, .{ .bold = c.attrs.bold, .italic = c.attrs.italic }, m, cells, px, py, fg);
            const stroke: f32 = @floatFromInt(m.stroke);
            if (c.attrs.underline) tv.rect(px, py + @as(f32, @floatFromInt(m.underline_y)), wpx, stroke, fg);
            if (c.attrs.strike) tv.rect(px, py + @round(m.baseline * 0.62), wpx, stroke, fg);
        }
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

fn drawMessage(tv: *TermView, ui: fontset.Metrics, msg: Message, W: f32, H: f32, s: f32) void {
    const big = tv.fonts.metrics(@round(20 * s));
    const lh: f32 = @floatFromInt(ui.cell_h);
    var y = @round(H * 0.28);
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
