//! Screen layout in device pixels: canvas size, terminal viewport, cell
//! size (fit-to-width or a manual zoom), pan limits, the answer bar and
//! hit testing for taps. Pure math, no state beyond its inputs.
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
};

pub const max_side: u32 = 8192;
pub const max_pixels: u64 = 16 << 20;
pub const button_count = 8;

pub const Input = struct {
    css_w: f64,
    css_h: f64,
    dpr: f64,
    touch: bool,
    show_bar: bool,
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
    bar: Rect = .{},
    buttons: [button_count]Rect = @splat(.{}),
    /// Answer bar label size in device pixels (em).
    label_em: f32 = 14,
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

    /// Index of the answer button under a device-pixel point.
    pub fn hitButton(l: Layout, px: i32, py: i32) ?usize {
        if (l.bar.h == 0 or !l.bar.contains(px, py)) return null;
        for (l.buttons, 0..) |b, i| if (b.contains(px, py)) return i;
        return null;
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

    // Answer bar along the bottom: big two-row grid on touch screens,
    // one compact row with a pointer.
    if (in.show_bar) {
        const pad = dev(if (in.touch) 8 else 4, dpr);
        const gap = pad;
        const bh = dev(if (in.touch) 48 else 28, dpr);
        const per_row: i32 = if (in.touch) 4 else 8;
        const n_rows: i32 = @divExact(button_count, per_row);
        l.bar = .{ .x = 0, .w = W, .h = @min(H, pad * 2 + n_rows * bh + (n_rows - 1) * gap) };
        l.bar.y = H - l.bar.h;
        const max_bw = if (in.touch) W else dev(72, dpr);
        const bw = std.math.clamp(@divFloor(W - pad * 2 - gap * (per_row - 1), per_row), 1, @max(1, max_bw));
        for (&l.buttons, 0..) |*b, i| {
            const col: i32 = @intCast(i % @as(usize, @intCast(per_row)));
            const row: i32 = @intCast(i / @as(usize, @intCast(per_row)));
            b.* = .{ .x = pad + col * (bw + gap), .y = l.bar.y + pad + row * (bh + gap), .w = bw, .h = bh };
        }
        l.label_em = @floatCast(sane(@as(f64, @floatFromInt(dev(if (in.touch) 18 else 13, dpr))), 4, 400));
    }
    l.term = .{ .x = 0, .y = 0, .w = W, .h = @max(0, H - l.bar.h) };

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
        em = std.math.clamp(cw_fit / adv, min_em, max_em);
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
    return .{ .css_w = 390, .css_h = 664, .dpr = 3, .touch = true, .show_bar = true, .cols = 120, .rows = 30, .zoom = .{} };
}

test "fit to width on an iPhone" {
    const l = compute(base());
    try testing.expectEqual(@as(u32, 1170), l.w);
    try testing.expectEqual(@as(u32, 1992), l.h);
    // 120 columns + padding fit exactly in the width.
    try testing.expect(@as(i32, 120) * @as(i32, @intCast(l.cw)) + 2 * l.pad <= l.term.w);
    try testing.expectEqual(@as(u32, 9), l.cw);
    try testing.expectEqual(@as(i32, 0), l.panMax()[0]);
    // Bar: 2 rows of 48 css px + 3 gaps of 8, at the bottom.
    try testing.expectEqual(@as(i32, (8 * 3 + 48 * 2) * 3), l.bar.h);
    try testing.expectEqual(@as(i32, @intCast(l.h)), l.bar.bottom());
    try testing.expectEqual(l.bar.y, l.term.h);
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

test "hit testing the answer bar" {
    const l = compute(base());
    for (l.buttons, 0..) |b, i| {
        try testing.expectEqual(@as(?usize, i), l.hitButton(b.x + 1, b.y + 1));
        try testing.expectEqual(@as(?usize, i), l.hitButton(b.x + b.w - 1, b.y + b.h - 1));
    }
    // Gaps and the terminal area hit nothing.
    try testing.expectEqual(@as(?usize, null), l.hitButton(l.buttons[0].right(), l.buttons[0].y + 2));
    try testing.expectEqual(@as(?usize, null), l.hitButton(10, 10));
    try testing.expectEqual(@as(?usize, null), l.hitButton(-1, -1));
    // Touch: 4 per row, top row 1 2 3 4, bottom Yes No Enter Esc.
    try testing.expectEqual(l.buttons[0].y, l.buttons[3].y);
    try testing.expect(l.buttons[4].y > l.buttons[0].y);
    // Desktop: one compact row.
    var in = base();
    in.touch = false;
    in.css_w = 1200;
    in.dpr = 1;
    const d = compute(in);
    try testing.expectEqual(d.buttons[0].y, d.buttons[7].y);
    try testing.expect(d.buttons[0].w <= 72);
    // No bar in view-only mode.
    in.show_bar = false;
    const v = compute(in);
    try testing.expectEqual(@as(i32, 0), v.bar.h);
    try testing.expectEqual(@as(?usize, null), v.hitButton(5, @as(i32, @intCast(v.h)) - 2));
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
