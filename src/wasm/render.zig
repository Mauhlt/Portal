//! Draws the grid, cursor and answer bar into an RGBA framebuffer that the
//! bridge copies to the <canvas> with putImageData.
//!
//! Only rows marked dirty are redrawn (glyphs come from the cache), and the
//! renderer reports the band of pixel rows it touched so the bridge uploads
//! just that band.

const std = @import("std");
const proto = @import("proto.zig");
const layout = @import("layout.zig");
const glyphs = @import("glyphs.zig");
const keys = @import("keys.zig");

const Rect = layout.Rect;

pub const Theme = struct {
    fg: u32 = 0xd4d4d4,
    bg: u32 = 0x0c0c0c,
    panel: u32 = 0x1f1f1d,
    border: u32 = 0x34342f,
    button: u32 = 0x2a2a27,
    label: u32 = 0xececea,
    pressed: u32 = 0x7aa2ff,
    pressed_label: u32 = 0x10131a,
    cursor: u32 = 0xd4d4d4,
    cursor_alpha: u8 = 140, // ≈ 0.55, as the old viewer
};

/// 0x00RRGGBB → little-endian RGBA bytes as a u32 (what ImageData wants).
pub fn pixel(rgb: u32) u32 {
    const r = (rgb >> 16) & 0xff;
    const g = (rgb >> 8) & 0xff;
    const b = rgb & 0xff;
    return 0xff000000 | (b << 16) | (g << 8) | r;
}

fn mixRgb(a: u32, b: u32, t255: u32) u32 {
    var out: u32 = 0;
    inline for (.{ 16, 8, 0 }) |sh| {
        const ca = (a >> sh) & 0xff;
        const cb = (b >> sh) & 0xff;
        out |= ((ca * (255 - t255) + cb * t255 + 127) / 255) << sh;
    }
    return out;
}

pub fn fgColor(t: Theme, v: u32) u32 {
    if (v == proto.color_default_bg_as_fg) return t.bg;
    if (v >> 24 != 0) return t.fg; // default, or any unknown sentinel
    return v;
}

pub fn bgColor(t: Theme, v: u32) u32 {
    if (v == proto.color_default_fg_as_bg) return t.fg;
    if (v >> 24 != 0) return t.bg;
    return v;
}

pub const Framebuffer = struct {
    pixels: []u32 = &.{},
    w: u32 = 0,
    h: u32 = 0,

    pub fn resize(fb: *Framebuffer, gpa: std.mem.Allocator, w: u32, h: u32) !void {
        const n = @as(usize, w) * h;
        if (n != fb.pixels.len) {
            const p = try gpa.alloc(u32, n);
            gpa.free(fb.pixels);
            fb.pixels = p;
        }
        fb.w = w;
        fb.h = h;
    }

    pub fn deinit(fb: *Framebuffer, gpa: std.mem.Allocator) void {
        gpa.free(fb.pixels);
        fb.* = .{};
    }

    fn bounds(fb: *const Framebuffer) Rect {
        return .{ .w = @intCast(fb.w), .h = @intCast(fb.h) };
    }

    /// Intersection of r, clip and the framebuffer, as usize bounds.
    fn span(fb: *const Framebuffer, r: Rect, clip: Rect) ?[4]usize {
        const b = fb.bounds();
        const x0 = @max(r.x, clip.x, b.x);
        const y0 = @max(r.y, clip.y, b.y);
        const x1 = @min(r.right(), clip.right(), b.right());
        const y1 = @min(r.bottom(), clip.bottom(), b.bottom());
        if (x1 <= x0 or y1 <= y0) return null;
        return .{ @intCast(x0), @intCast(y0), @intCast(x1), @intCast(y1) };
    }

    pub fn fill(fb: *Framebuffer, r: Rect, clip: Rect, rgb: u32) void {
        const s = fb.span(r, clip) orelse return;
        const p = pixel(rgb);
        for (s[1]..s[3]) |y| @memset(fb.pixels[y * fb.w + s[0] .. y * fb.w + s[2]], p);
    }

    /// Blends a solid colour over r with constant alpha.
    pub fn tint(fb: *Framebuffer, r: Rect, clip: Rect, rgb: u32, alpha: u8) void {
        const s = fb.span(r, clip) orelse return;
        for (s[1]..s[3]) |y| for (s[0]..s[2]) |x| {
            const i = y * fb.w + x;
            fb.pixels[i] = blendPixel(fb.pixels[i], rgb, alpha);
        };
    }

    /// Draws a coverage bitmap (cw x ch) at (x, y) in colour `rgb`.
    pub fn glyph(fb: *Framebuffer, x: i32, y: i32, cov: []const u8, gw: u32, gh: u32, clip: Rect, rgb: u32) void {
        if (cov.len < @as(usize, gw) * gh) return;
        const r: Rect = .{ .x = x, .y = y, .w = @intCast(gw), .h = @intCast(gh) };
        const s = fb.span(r, clip) orelse return;
        for (s[1]..s[3]) |py| {
            // span() clipped to r, so these offsets are within the bitmap.
            const gy: usize = @intCast(@as(i64, @intCast(py)) - y);
            for (s[0]..s[2]) |px| {
                const gx: usize = @intCast(@as(i64, @intCast(px)) - x);
                const a = cov[gy * gw + gx];
                if (a == 0) continue;
                const i = py * fb.w + px;
                fb.pixels[i] = if (a == 255) pixel(rgb) else blendPixel(fb.pixels[i], rgb, a);
            }
        }
    }
};

fn blendPixel(dst: u32, rgb: u32, a: u32) u32 {
    // dst is RGBA little-endian; convert to 0xRRGGBB to reuse mixRgb.
    const d = ((dst & 0xff) << 16) | (dst & 0xff00) | ((dst >> 16) & 0xff);
    return pixel(mixRgb(d, rgb, a));
}

pub const Renderer = struct {
    fb: Framebuffer = .{},
    theme: Theme = .{},
    /// Band of pixel rows touched since the last present.
    dirty_y0: u32 = std.math.maxInt(u32),
    dirty_y1: u32 = 0,

    fn touch(r: *Renderer, y0: i32, y1: i32) void {
        const a: u32 = @intCast(std.math.clamp(y0, 0, @as(i32, @intCast(r.fb.h))));
        const b: u32 = @intCast(std.math.clamp(y1, 0, @as(i32, @intCast(r.fb.h))));
        if (b <= a) return;
        r.dirty_y0 = @min(r.dirty_y0, a);
        r.dirty_y1 = @max(r.dirty_y1, b);
    }

    /// Takes the dirty band, or null when nothing changed.
    pub fn takeDirty(r: *Renderer) ?[2]u32 {
        if (r.dirty_y1 <= r.dirty_y0) return null;
        const band = [2]u32{ r.dirty_y0, r.dirty_y1 };
        r.dirty_y0 = std.math.maxInt(u32);
        r.dirty_y1 = 0;
        return band;
    }

    pub const View = struct {
        l: layout.Layout,
        pan: [2]i32,
        show_cursor: bool,
    };

    /// Clears the terminal area (padding included) to the background.
    pub fn clearTerm(r: *Renderer, l: layout.Layout) void {
        r.fb.fill(l.term, l.term, r.theme.bg);
        r.touch(l.term.y, l.term.bottom());
    }

    /// Redraws grid row `y` (if visible) and clears its dirty flag.
    pub fn drawRow(r: *Renderer, g: *proto.Grid, gl: *glyphs.Glyphs, v: View, y: u16) void {
        if (y >= g.rows) return;
        g.dirty[y] = false;
        const l = v.l;
        const cw: i32 = @intCast(l.cw);
        const ch: i32 = @intCast(l.ch);
        const top = l.term.y + l.pad + @as(i32, y) * ch - v.pan[1];
        const band: Rect = .{ .x = l.term.x, .y = top, .w = l.term.w, .h = ch };
        if (band.bottom() <= l.term.y or band.y >= l.term.bottom()) return;
        const clip = l.term;
        r.fb.fill(band, clip, r.theme.bg);
        r.touch(@max(band.y, clip.y), @min(band.bottom(), clip.bottom()));

        const left = l.term.x + l.pad - v.pan[0];
        const cells = g.row(y);
        // Cells beyond the visible area are skipped wholesale.
        const first: usize = @intCast(std.math.clamp(@divFloor(clip.x - left, cw) - 1, 0, @as(i32, g.cols)));
        const last: usize = @intCast(std.math.clamp(@divFloor(clip.right() - left, cw) + 1, 0, @as(i32, g.cols)));
        var x = first;
        while (x < last) : (x += 1) {
            const c = cells[x];
            if (c.wide == .cont) continue;
            const n: u2 = if (c.wide == .lead) 2 else 1;
            const cell: Rect = .{ .x = left + @as(i32, @intCast(x)) * cw, .y = top, .w = cw * n, .h = ch };
            const bg = bgColor(r.theme, c.bg);
            var fg = fgColor(r.theme, c.fg);
            if (c.attrs & proto.attr_dim != 0) fg = mixRgb(fg, bg, 102); // 60% opacity
            if (bg != r.theme.bg) r.fb.fill(cell, clip, bg);
            const style: glyphs.Style = .{ .bold = c.attrs & proto.attr_bold != 0, .italic = c.attrs & proto.attr_italic != 0 };
            const cov = gl.get(c.cp, style, n);
            r.fb.glyph(cell.x, cell.y, cov, l.cw * n, l.ch, clip, fg);
            const stroke: i32 = @intCast(gl.stroke);
            const base: i32 = @intFromFloat(gl.baseline);
            if (c.attrs & proto.attr_underline != 0)
                r.fb.fill(.{ .x = cell.x, .y = top + @min(ch - stroke, base + stroke), .w = cell.w, .h = stroke }, clip, fg);
            if (c.attrs & proto.attr_strike != 0)
                r.fb.fill(.{ .x = cell.x, .y = top + @max(0, base - @divFloor(ch * 3, 10)), .w = cell.w, .h = stroke }, clip, fg);
        }
        if (v.show_cursor and g.cursor_visible and g.cursor_y == y and g.cols > 0) {
            const cx = @min(g.cursor_x, g.cols - 1);
            const wide = cells[cx].wide == .lead;
            const cur: Rect = .{ .x = left + @as(i32, cx) * cw, .y = top, .w = cw * @as(i32, if (wide) 2 else 1), .h = ch };
            r.fb.tint(cur, clip, r.theme.cursor, r.theme.cursor_alpha);
        }
    }

    /// The answer bar: buttons with centred labels; `pressed` highlighted.
    pub fn drawBar(r: *Renderer, ui: *glyphs.Glyphs, l: layout.Layout, pressed: ?usize) void {
        if (l.bar.h == 0) return;
        const all = l.bar;
        r.fb.fill(all, all, r.theme.panel);
        const line = @max(1, @as(i32, @intFromFloat(@round(l.dpr))));
        r.fb.fill(.{ .x = all.x, .y = all.y, .w = all.w, .h = line }, all, r.theme.border);
        for (l.buttons, keys.answer_bar, 0..) |b, k, i| {
            const down = pressed != null and pressed.? == i;
            r.fb.fill(b, all, if (down) r.theme.pressed else r.theme.border);
            const inner: Rect = .{ .x = b.x + line, .y = b.y + line, .w = b.w - 2 * line, .h = b.h - 2 * line };
            if (!down) r.fb.fill(inner, all, r.theme.button);
            const lw: i32 = @intCast(ui.cw);
            const lh: i32 = @intCast(ui.ch);
            const text_w = lw * @as(i32, @intCast(k.label.len));
            var x = b.x + @divFloor(b.w - text_w, 2);
            const y = b.y + @divFloor(b.h - lh, 2);
            for (k.label) |c| {
                const cov = ui.get(c, .{ .bold = true }, 1);
                r.fb.glyph(x, y, cov, ui.cw, ui.ch, b, if (down) r.theme.pressed_label else r.theme.label);
                x += lw;
            }
        }
        r.touch(all.y, all.bottom());
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "colour sentinels" {
    const t: Theme = .{};
    try testing.expectEqual(t.fg, fgColor(t, proto.color_default));
    try testing.expectEqual(t.bg, fgColor(t, proto.color_default_bg_as_fg));
    try testing.expectEqual(t.bg, bgColor(t, proto.color_default));
    try testing.expectEqual(t.fg, bgColor(t, proto.color_default_fg_as_bg));
    try testing.expectEqual(@as(u32, 0x123456), fgColor(t, 0x123456));
    try testing.expectEqual(t.fg, fgColor(t, 0xFF000007)); // unknown sentinel
    try testing.expectEqual(@as(u32, 0xff563412), pixel(0x123456));
    try testing.expectEqual(@as(u32, 0xffffff), mixRgb(0x000000, 0xffffff, 255));
    try testing.expectEqual(@as(u32, 0x204060), mixRgb(0x204060, 0xffffff, 0));
    try testing.expectEqual(@as(u32, 0x808080), mixRgb(0x000000, 0xffffff, 128));
}

test "draw a frame end to end and clip at every pan offset" {
    const gpa = testing.allocator;
    var gl = try glyphs.Glyphs.init(gpa, @embedFile("font_regular"), @embedFile("font_bold"));
    defer gl.deinit();
    var ui = try glyphs.Glyphs.init(gpa, @embedFile("font_regular"), @embedFile("font_bold"));
    defer ui.deinit();
    var g: proto.Grid = .{};
    defer g.deinit(gpa);
    // Build a 10x3 grid through the real decoder.
    var t = try @import("vt").Terminal.init(gpa, 10, 3);
    defer t.deinit();
    t.feed("\x1b[41mA\x1b[m\x1b[4mb\x1b[9mc\x1b[m中\x1b[2mx\r\n\x1b[1;3mBold\r\n─│");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try t.encodeRows(&.{ 0, 1, 2 }, &out, gpa);
    _ = try proto.applyFrame(&g, gpa, out.items);

    var r: Renderer = .{};
    defer r.fb.deinit(gpa);
    const in: layout.Input = .{ .css_w = 120, .css_h = 300, .dpr = 1, .touch = true, .show_bar = true, .cols = 10, .rows = 3, .zoom = .{}, .m = gl.metrics() };
    const l = layout.compute(in);
    try r.fb.resize(gpa, l.w, l.h);
    gl.setSize(l.cw, l.ch, l.em);
    ui.setEm(l.label_em);
    r.clearTerm(l);
    for (0..3) |y| r.drawRow(&g, &gl, .{ .l = l, .pan = .{ 0, 0 }, .show_cursor = true }, @intCast(y));
    r.drawBar(&ui, l, 2);
    try testing.expect(!g.dirty[0]);
    const band = r.takeDirty().?;
    try testing.expectEqual(@as(u32, 0), band[0]);
    try testing.expectEqual(l.h, band[1]);
    try testing.expectEqual(@as(?[2]u32, null), r.takeDirty());
    // The red background of 'A' is there.
    const ax: usize = @intCast(l.pad + 1);
    const ay: usize = @intCast(l.pad + 1);
    try testing.expectEqual(pixel(0xCD0000), r.fb.pixels[ay * l.w + ax]);

    // Pans and zooms far outside the content must clip, never index out.
    const zl = layout.compute(.{ .css_w = 50, .css_h = 60, .dpr = 2, .touch = false, .show_bar = true, .cols = 10, .rows = 3, .zoom = .{ .fit = false, .font_px = 30 }, .m = gl.metrics() });
    try r.fb.resize(gpa, zl.w, zl.h);
    gl.setSize(zl.cw, zl.ch, zl.em);
    const pans = [_][2]i32{ .{ -5000, -5000 }, .{ 0, 0 }, .{ 37, 11 }, .{ 5000, 5000 }, zl.panMax() };
    for (pans) |p| {
        r.clearTerm(zl);
        for (0..3) |y| r.drawRow(&g, &gl, .{ .l = zl, .pan = p, .show_cursor = true }, @intCast(y));
        r.drawBar(&ui, zl, null);
    }
}
