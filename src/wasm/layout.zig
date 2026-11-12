//! Terminal canvas layout in device pixels: canvas size, cell size
//! (fit or a manual zoom) and pan limits. Pure math, no state beyond its
//! inputs. The page around the canvas (header, Data slice, input box,
//! buttons) is slices.zig.
//!
//! Fit, the same rule as the native viewer (TermView.fitEm): the cell size
//! at which the columns fill the canvas width, made smaller to show every
//! row too, but not below `Zoom.readable_px`; rows that still do not fit
//! are panned to follow the cursor (`followPan`).
//!
//! All inputs come from the browser (via the bridge) and are sanitised
//! here: NaN, negative or absurd sizes must not reach an @intFromFloat.

const std = @import("std");

/// Font proportions in ems, from the bundled font's tables.
pub const FontMetrics = struct {
    adv_em: f32 = 0.602,
    line_em: f32 = 1.164,
};

pub const Rect = struct {
    x: i32 = 0,
    y: i32 = 0,
    w: i32 = 0,
    h: i32 = 0,

    pub fn contains(r: Rect, px: i32, py: i32) bool {
        return px >= r.x and py >= r.y and px < r.x + r.w and py < r.y + r.h;
    }
    pub fn bottom(r: Rect) i32 {
        return r.y + r.h;
    }
    pub fn right(r: Rect) i32 {
        return r.x + r.w;
    }
};

pub const Zoom = struct {
    fit: bool = true,
    /// CSS pixels; used when not fitting.
    font_px: f32 = 14,

    pub const min_px: f32 = 4;
    pub const max_px: f32 = 40;
    /// Fit shrinks for the rows' sake down to this size (CSS px), no further.
    pub const readable_px: f32 = 12;
};

pub const max_side: u32 = 8192;
pub const max_pixels: u64 = 16 << 20;

pub const Input = struct {
    css_w: f64,
    css_h: f64,
    dpr: f64,
    cols: u16,
    rows: u16,
    zoom: Zoom,
    m: FontMetrics = .{},
};

pub const Layout = struct {
    /// Canvas size in device pixels.
    w: u32 = 1,
    h: u32 = 1,
    dpr: f32 = 1,
    term: Rect = .{},
    /// Cell size in device pixels, and the glyph em that matches it.
    cw: u32 = 8,
    ch: u32 = 16,
    em: f32 = 14,
    /// Inner padding around the grid.
    pad: i32 = 4,
    content_w: i32 = 0,
    content_h: i32 = 0,

    pub fn panMax(l: Layout) [2]i32 {
        return .{ @max(0, l.content_w - l.term.w), @max(0, l.content_h - l.term.h) };
    }

    pub fn clampPan(l: Layout, pan: [2]i32) [2]i32 {
        const m = l.panMax();
        return .{ std.math.clamp(pan[0], 0, m[0]), std.math.clamp(pan[1], 0, m[1]) };
    }
};

/// Finite, clamped float, so later float→int conversions are defined.
pub fn sane(v: f64, lo: f64, hi: f64) f64 {
    if (!std.math.isFinite(v)) return lo;
    return std.math.clamp(v, lo, hi);
}

pub fn toInt(v: f64) i32 {
    return @intFromFloat(@round(sane(v, -1e9, 1e9)));
}

fn dev(css: f64, dpr: f64) i32 {
    return toInt(css * dpr);
}

pub fn compute(in: Input) Layout {
    var l: Layout = .{};
    var dpr = sane(in.dpr, 0.5, 4);
    const cw_css = sane(in.css_w, 1, max_side);
    const ch_css = sane(in.css_h, 1, max_side);
    // Keep the framebuffer within limits by lowering the effective dpr.
    while (dpr > 0.5 and (cw_css * dpr > max_side or ch_css * dpr > max_side or
        cw_css * dpr * ch_css * dpr > @as(f64, @floatFromInt(max_pixels)))) dpr -= 0.25;
    dpr = @max(dpr, 0.5);
    l.dpr = @floatCast(dpr);
    l.w = @intCast(std.math.clamp(dev(cw_css, dpr), 1, max_side));
    l.h = @intCast(std.math.clamp(dev(ch_css, dpr), 1, max_side));
    const W: i32 = @intCast(l.w);
    const H: i32 = @intCast(l.h);

    l.term = .{ .x = 0, .y = 0, .w = W, .h = H };

    // Cell size. Fit: the widest cell that shows every column; otherwise
    // the zoom's font size. Either way the em is derived back from the
    // integer cell width so glyph advances land exactly on cell edges.
    l.pad = dev(4, dpr);
    const adv: f64 = sane(in.m.adv_em, 0.1, 2);
    const line: f64 = sane(in.m.line_em, 0.5, 4);
    const min_em = Zoom.min_px * dpr;
    const max_em = Zoom.max_px * dpr;
    var em: f64 = undefined;
    if (in.zoom.fit and in.cols > 0) {
        const avail: f64 = @floatFromInt(@max(1, l.term.w - 2 * l.pad));
        const cw_fit = @floor(avail / @as(f64, @floatFromInt(in.cols)));
        const by_w = cw_fit / adv;
        // Every row too, if that stays readable.
        const avail_h: f64 = @floatFromInt(@max(1, l.term.h - 2 * l.pad));
        const by_h = if (in.rows > 0) avail_h / (@as(f64, @floatFromInt(in.rows)) * line) else by_w;
        const readable = @as(f64, Zoom.readable_px) * dpr;
        em = std.math.clamp(@min(by_w, @max(by_h, readable)), min_em, max_em);
    } else {
        em = sane(in.zoom.font_px, Zoom.min_px, Zoom.max_px) * dpr;
    }
    var cw = @max(1, @round(em * adv));
    if (in.zoom.fit and in.cols > 0) {
        // Rounding must never push a fitted grid past the edge (unless the
        // minimum font size itself does not fit: then the view pans).
        const avail: f64 = @floatFromInt(@max(1, l.term.w - 2 * l.pad));
        const cw_fit = @floor(avail / @as(f64, @floatFromInt(in.cols)));
        if (cw > cw_fit and cw_fit >= @round(min_em * adv)) cw = @max(1, cw_fit);
    }
    l.cw = @intFromFloat(sane(cw, 1, 1000));
    l.em = @floatCast(@as(f64, @floatFromInt(l.cw)) / adv);
    l.ch = @intFromFloat(sane(@round(@as(f64, l.em) * line), 1, 2000));
    l.content_w = @as(i32, in.cols) * @as(i32, @intCast(l.cw)) + 2 * l.pad;
    l.content_h = @as(i32, in.rows) * @as(i32, @intCast(l.ch)) + 2 * l.pad;
    return l;
}

/// The first grid row to show when only `visible` of `rows` fit: the
/// lowest rows with content (`last`: the last non-blank row), keeping the
/// cursor in view; 0 when everything fits (TermView.followTop).
pub fn followTop(rows: u16, visible: u16, cursor: u16, last: u16) u16 {
    if (visible == 0 or visible >= rows) return 0;
    const bottom = @max(cursor, last);
    var first = (bottom + 1) -| visible;
    first = @min(first, rows - visible);
    return @min(first, cursor);
}

/// The vertical pan (device px) that shows the rows `followTop` picks.
pub fn followPan(l: Layout, rows: u16, cursor: u16, last: u16) i32 {
    const ch: i32 = @intCast(@max(1, l.ch));
    const visible: u16 = @intCast(std.math.clamp(@divFloor(l.term.h - 2 * l.pad, ch), 1, @max(1, @as(i32, rows))));
    const first = followTop(rows, visible, cursor, last);
    return l.clampPan(.{ 0, @as(i32, first) * ch })[1];
}

/// A− / A+: leaves fit mode at the current size, then steps by one CSS px.
pub fn zoomStep(z: Zoom, l: Layout, dir: i32) Zoom {
    var px_css: f32 = if (z.fit) l.em / l.dpr else z.font_px;
    if (!std.math.isFinite(px_css)) px_css = 14;
    px_css = @round(px_css) + @as(f32, @floatFromInt(std.math.clamp(dir, -1, 1)));
    return .{ .fit = false, .font_px = std.math.clamp(px_css, Zoom.min_px, Zoom.max_px) };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn base() Input {
    return .{ .css_w = 390, .css_h = 664, .dpr = 3, .cols = 120, .rows = 30, .zoom = .{} };
}

test "fit to width on an iPhone" {
    const l = compute(base());
    try testing.expectEqual(@as(u32, 1170), l.w);
    try testing.expectEqual(@as(u32, 1992), l.h);
    // 120 columns + padding fit exactly in the width.
    try testing.expect(@as(i32, 120) * @as(i32, @intCast(l.cw)) + 2 * l.pad <= l.term.w);
    try testing.expectEqual(@as(u32, 9), l.cw);
    try testing.expectEqual(@as(i32, 0), l.panMax()[0]);
    // The canvas is all terminal (the buttons are HTML, panes.zig).
    try testing.expectEqual(@as(i32, @intCast(l.h)), l.term.h);
}

test "fit never overflows across many sizes" {
    var w: f64 = 200;
    while (w < 3000) : (w += 37) {
        for ([_]u16{ 20, 80, 120, 200, 400 }) |cols| {
            for ([_]f64{ 1, 1.25, 2, 3 }) |dpr| {
                var in = base();
                in.css_w = w;
                in.cols = cols;
                in.dpr = dpr;
                const l = compute(in);
                const min_cw = @round(Zoom.min_px * l.dpr * 0.602);
                if (@as(f32, @floatFromInt(l.cw)) > min_cw)
                    try testing.expect(@as(i32, cols) * @as(i32, @intCast(l.cw)) + 2 * l.pad <= l.term.w);
                try testing.expect(l.cw >= 1 and l.ch >= 1);
            }
        }
    }
}

test "very wide terminal clamps to minimum font and pans" {
    var in = base();
    in.cols = 400;
    const l = compute(in);
    const m = l.panMax();
    try testing.expect(m[0] > 0);
    try testing.expectEqual([2]i32{ m[0], 0 }, l.clampPan(.{ 99999, -5 }));
}

test "manual zoom and pan" {
    var in = base();
    in.zoom = .{ .fit = false, .font_px = 20 };
    const l = compute(in);
    try testing.expectEqual(@as(u32, 36), l.cw); // 20 * 3 * 0.602
    try testing.expect(l.panMax()[0] > 0 and l.panMax()[1] > 0);
    // A+ from fit starts from the fitted size.
    const fitted = compute(base());
    const z = zoomStep(.{}, fitted, 1);
    try testing.expect(!z.fit);
    try testing.expectEqual(@round(fitted.em / fitted.dpr) + 1, z.font_px);
    try testing.expectEqual(Zoom.max_px, zoomStep(.{ .fit = false, .font_px = 40 }, l, 1).font_px);
    try testing.expectEqual(Zoom.min_px, zoomStep(.{ .fit = false, .font_px = 4 }, l, -1).font_px);
}

test "hostile sizes from the browser" {
    const bad = [_]f64{ std.math.nan(f64), std.math.inf(f64), -std.math.inf(f64), -5, 0, 1e300 };
    for (bad) |x| {
        var in = base();
        in.css_w = x;
        in.css_h = x;
        in.dpr = x;
        in.zoom = .{ .fit = false, .font_px = @floatCast(x) };
        const l = compute(in);
        try testing.expect(l.w >= 1 and l.w <= max_side and l.h >= 1 and l.h <= max_side);
        try testing.expect(@as(u64, l.w) * l.h <= max_pixels);
        try testing.expect(l.cw >= 1 and l.ch >= 1);
    }
    var in = base();
    in.cols = 0;
    in.rows = 0;
    _ = compute(in);
}

test "fit: rows too if readable, else the rows follow the cursor" {
    // A laptop browser: 120 x 40 in 1000 x 500 CSS px at dpr 1. The width
    // allows a 8 px cell (13.3 px font); every row would need 10.7 px:
    // below readable, so 12 px and the rows pan.
    var in: Input = .{ .css_w = 1000, .css_h = 500, .dpr = 1, .cols = 120, .rows = 40, .zoom = .{} };
    const l = compute(in);
    try testing.expectEqual(@as(u32, 7), l.cw); // 12 px * 0.602
    try testing.expect(l.panMax()[1] > 0 and l.panMax()[0] == 0);
    // Taller window: the width decides, everything fits.
    in.css_h = 2000;
    const t = compute(in);
    try testing.expectEqual(@as(u32, 8), t.cw);
    try testing.expectEqual(@as(i32, 0), t.panMax()[1]);
    // Following: the cursor's region, clamped to the content.
    try testing.expectEqual(@as(i32, 0), followPan(l, 40, 2, 2));
    try testing.expectEqual(l.panMax()[1], followPan(l, 40, 39, 39));
    try testing.expectEqual(@as(i32, 0), followPan(t, 40, 39, 39));
    try testing.expectEqual(@as(u16, 15), followTop(40, 25, 30, 39));
    try testing.expectEqual(@as(u16, 10), followTop(40, 5, 10, 39));
}
