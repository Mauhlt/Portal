//! Draws the grid and cursor into an RGBA framebuffer that the
//! bridge copies to the <canvas> with putImageData.
//!
//! Only rows marked dirty are redrawn (glyphs come from the cache), and the
//! renderer reports the band of pixel rows it touched so the bridge uploads
//! just that band.

const std = @import("std");
const proto = @import("proto.zig");
const layout = @import("layout.zig");
const glyphs = @import("glyphs.zig");

const Rect = layout.Rect;

pub const Theme = struct {
    fg: u32 = 0xd4d4d4,
    bg: u32 = 0x0c0c0c,
    cursor: u32 = 0xd4d4d4,
    cursor_alpha: u8 = 140, // ≈ 0.55, as the old viewer
    /// Outline and label of an image that can't be shown.
    placeholder: u32 = 0x8a8a80,
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
        // Pass 1: cell backgrounds.
        var x = first;
        while (x < last) : (x += 1) {
            const c = cells[x];
            if (c.wide == .cont) continue;
            const n: u2 = if (c.wide == .lead) 2 else 1;
            const cell: Rect = .{ .x = left + @as(i32, @intCast(x)) * cw, .y = top, .w = cw * n, .h = ch };
            const bg = bgColor(r.theme, c.bg);
            if (bg != r.theme.bg) r.fb.fill(cell, clip, bg);
        }
        // Pass 2: images, above backgrounds and below text and cursor.
        const grid_top = l.term.y + l.pad - v.pan[1];
        for (g.images.places.items) |p| r.drawImageSlice(g, gl, p, left, grid_top, cw, ch, band, clip, y);
        // Pass 3: glyphs and decorations.
        x = first;
        while (x < last) : (x += 1) {
            const c = cells[x];
            if (c.wide == .cont) continue;
            const n: u2 = if (c.wide == .lead) 2 else 1;
            const cell: Rect = .{ .x = left + @as(i32, @intCast(x)) * cw, .y = top, .w = cw * n, .h = ch };
            const bg = bgColor(r.theme, c.bg);
            var fg = fgColor(r.theme, c.fg);
            if (c.attrs & proto.attr_dim != 0) fg = mixRgb(fg, bg, 102); // 60% opacity
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

    /// Draws the part of placement `p` inside grid row `y`'s pixel band:
    /// the decoded image scaled (nearest) to its cells with alpha blending,
    /// or, if it can't be shown, an outlined box labelled with its size.
    /// Every coordinate comes from the peer: computed in i64 and clipped
    /// to the band, the terminal clip and the framebuffer before indexing.
    fn drawImageSlice(r: *Renderer, g: *const proto.Grid, gl: *glyphs.Glyphs, p: proto.Placement, left: i32, grid_top: i32, cw: i32, ch: i32, band: Rect, clip: Rect, y: u16) void {
        if (@as(i64, p.row) > y or @as(i64, p.row) + p.rows <= y) return;
        const blob = g.images.find(p.id) orelse return;
        const x0: i64 = @as(i64, left) + @as(i64, p.col) * cw;
        const y0: i64 = @as(i64, grid_top) + @as(i64, p.row) * ch;
        const w: i64 = @as(i64, p.cols) * cw;
        const h: i64 = @as(i64, p.rows) * ch;
        if (w <= 0 or h <= 0) return;
        const fb_w: i64 = r.fb.w;
        const fb_h: i64 = r.fb.h;
        const cx0 = @max(x0, clip.x, 0);
        const cx1 = @min(x0 + w, @as(i64, clip.x) + clip.w, fb_w);
        const cy0 = @max(y0, band.y, clip.y, 0);
        const cy1 = @min(y0 + h, @as(i64, band.y) + band.h, @as(i64, clip.y) + clip.h, fb_h);
        if (cx1 <= cx0 or cy1 <= cy0) return;
        if (blob.rgba) |img| {
            if (img.w == 0 or img.h == 0 or img.px.len < @as(usize, img.w) * img.h * 4) return;
            var py = cy0;
            while (py < cy1) : (py += 1) {
                const sy: usize = @intCast(@min(@as(i64, img.h) - 1, @divFloor((py - y0) * img.h, h)));
                const dst_row: usize = @intCast(py * fb_w);
                var px = cx0;
                while (px < cx1) : (px += 1) {
                    const sx: usize = @intCast(@min(@as(i64, img.w) - 1, @divFloor((px - x0) * img.w, w)));
                    const s = img.px[(sy * img.w + sx) * 4 ..][0..4];
                    if (s[3] == 0) continue;
                    const rgb = (@as(u32, s[0]) << 16) | (@as(u32, s[1]) << 8) | s[2];
                    const i = dst_row + @as(usize, @intCast(px));
                    r.fb.pixels[i] = if (s[3] == 255) pixel(rgb) else blendPixel(r.fb.pixels[i], rgb, s[3]);
                }
            }
            return;
        }
        if (!blob.failed) return; // not decoded yet: drawn once it is
        // Placeholder: a 1-device-pixel-ish outline.
        const t: i64 = @max(1, @divFloor(@min(cw, ch), 8));
        const col = pixel(r.theme.placeholder);
        var py = cy0;
        while (py < cy1) : (py += 1) {
            const edge_row = py < y0 + t or py >= y0 + h - t;
            const dst_row: usize = @intCast(py * fb_w);
            var px = cx0;
            while (px < cx1) : (px += 1) {
                if (edge_row or px < x0 + t or px >= x0 + w - t) r.fb.pixels[dst_row + @as(usize, @intCast(px))] = col;
            }
        }
        // Label "W×H" on the middle row, if it fits inside the box.
        if (blob.w == 0 or blob.h == 0) return;
        const mid: i64 = @as(i64, p.row) + @divFloor(@as(i64, p.rows), 2);
        if (mid != y) return;
        var buf: [32]u8 = undefined;
        const label = std.fmt.bufPrint(&buf, "{d}\u{00D7}{d}", .{ blob.w, blob.h }) catch return;
        var n_cells: i64 = 0;
        var it: proto.Utf8Iter = .{ .s = label };
        while (it.next()) |_| n_cells += 1;
        if (n_cells + 2 > p.cols) return;
        const lx0: i64 = x0 + @divFloor(@as(i64, p.cols) - n_cells, 2) * cw;
        const ly: i64 = @as(i64, grid_top) + @as(i64, y) * ch;
        if (lx0 < std.math.minInt(i32) / 2 or lx0 > std.math.maxInt(i32) / 2 or ly < std.math.minInt(i32) / 2 or ly > std.math.maxInt(i32) / 2) return;
        it = .{ .s = label };
        var k: i64 = 0;
        while (it.next()) |cp| : (k += 1) {
            const gx = lx0 + k * cw;
            if (gx > std.math.maxInt(i32) / 2) break;
            const cov = gl.get(cp, .{}, 1);
            r.fb.glyph(@intCast(gx), @intCast(ly), cov, @intCast(cw), @intCast(ch), clip, r.theme.placeholder);
        }
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

fn imageGrid(gpa: std.mem.Allocator, g: *proto.Grid, png: []const u8, places: []const @import("vt").gfx.Placement) !void {
    var t = try @import("vt").Terminal.init(gpa, 10, 4);
    defer t.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try t.encodeRows(&.{ 0, 1, 2, 3 }, &out, gpa);
    _ = try proto.applyFrame(g, gpa, out.items);
    out.clearRetainingCapacity();
    const gfx = @import("vt").gfx;
    try gfx.appendBlobFrame(&out, gpa, 5, png);
    _ = try proto.applyBinary(g, gpa, out.items);
    out.clearRetainingCapacity();
    const All = struct {
        fn f(_: void, _: u32) bool {
            return true;
        }
    };
    try gfx.appendPlacementFrame(&out, gpa, places, {}, All.f);
    _ = try proto.applyBinary(g, gpa, out.items);
    while (g.images.decodeOne(gpa)) |_| {}
}

fn pl(col: u16, row: i32, cols: u16, rows: u16) @import("vt").gfx.Placement {
    return .{ .image = 5, .client_id = 0, .pid = 0, .col = col, .row = row, .cols = cols, .rows = rows };
}

test "images land on their cells; placeholders for bad blobs; clipping" {
    const gpa = testing.allocator;
    var gl = try glyphs.Glyphs.init(gpa, @embedFile("font_regular"), @embedFile("font_bold"));
    defer gl.deinit();
    const in: layout.Input = .{ .css_w = 200, .css_h = 200, .dpr = 1, .cols = 10, .rows = 4, .zoom = .{}, .m = gl.metrics() };
    const l = layout.compute(in);
    gl.setSize(l.cw, l.ch, l.em);
    var r: Renderer = .{};
    defer r.fb.deinit(gpa);
    try r.fb.resize(gpa, l.w, l.h);

    // A solid red 4x4 PNG placed at cells (2,1)-(4,2).
    var px: [4 * 4 * 4]u8 = undefined;
    for (0..16) |i| px[i * 4 ..][0..4].* = .{ 255, 0, 0, 255 };
    const png = try @import("imgcheck").encodeStored(gpa, 4, 4, &px);
    defer gpa.free(png);
    var g: proto.Grid = .{};
    defer g.deinit(gpa);
    try imageGrid(gpa, &g, png, &.{pl(2, 1, 3, 2)});
    try testing.expect(g.images.find(5).?.rgba != null);
    const v: Renderer.View = .{ .l = l, .pan = .{ 0, 0 }, .show_cursor = false };
    r.clearTerm(l);
    for (0..4) |y| r.drawRow(&g, &gl, v, @intCast(y));
    const cw: usize = l.cw;
    const ch: usize = l.ch;
    const ox: usize = @intCast(l.term.x + l.pad);
    const oy: usize = @intCast(l.term.y + l.pad);
    const at = struct {
        fn f(rr: *const Renderer, x: usize, y: usize) u32 {
            return rr.fb.pixels[y * rr.fb.w + x];
        }
    }.f;
    try testing.expectEqual(pixel(0xff0000), at(&r, ox + 2 * cw + 1, oy + ch + 1)); // top-left cell
    try testing.expectEqual(pixel(0xff0000), at(&r, ox + 5 * cw - 1, oy + 3 * ch - 1)); // bottom-right
    try testing.expectEqual(pixel(r.theme.bg), at(&r, ox + 5 * cw + 1, oy + ch + 1)); // right of it
    try testing.expectEqual(pixel(r.theme.bg), at(&r, ox + 2 * cw + 1, oy + 3 * ch + 1)); // below it

    // An undecodable blob draws an outlined placeholder.
    var g2: proto.Grid = .{};
    defer g2.deinit(gpa);
    const bad = try gpa.dupe(u8, png);
    defer gpa.free(bad);
    bad[bad.len - 20] ^= 0xff; // IDAT CRC no longer matches
    try imageGrid(gpa, &g2, bad, &.{pl(0, 0, 10, 3)});
    try testing.expect(g2.images.find(5).?.failed);
    r.clearTerm(l);
    for (0..4) |y| r.drawRow(&g2, &gl, v, @intCast(y));
    try testing.expectEqual(pixel(r.theme.placeholder), at(&r, ox, oy));
    try testing.expectEqual(pixel(r.theme.bg), at(&r, ox + 5 * cw, oy + ch / 2));

    // Partly off-grid placements (negative row, beyond the right edge),
    // at extreme pans and zooms: clipped, never out of bounds.
    var g3: proto.Grid = .{};
    defer g3.deinit(gpa);
    try imageGrid(gpa, &g3, png, &.{ pl(8, -1, 500, 3), pl(0, -30000, 65535, 65535), pl(65535, 3, 65535, 1) });
    var g4: proto.Grid = .{};
    defer g4.deinit(gpa);
    try imageGrid(gpa, &g4, bad, &.{ pl(8, -1, 500, 3), pl(0, -30000, 65535, 65535), pl(3, 1, 7, 3) });
    const zooms = [_]layout.Zoom{ .{}, .{ .fit = false, .font_px = 60 }, .{ .fit = false, .font_px = 6 } };
    const pans = [_][2]i32{ .{ -5000, -5000 }, .{ 0, 0 }, .{ 37, 11 }, .{ 5000, 5000 } };
    for (zooms) |z| {
        var zin = in;
        zin.zoom = z;
        zin.dpr = 2;
        const zl = layout.compute(zin);
        try r.fb.resize(gpa, zl.w, zl.h);
        gl.setSize(zl.cw, zl.ch, zl.em);
        for (pans ++ [_][2]i32{zl.panMax()}) |p| for ([_]*proto.Grid{ &g3, &g4 }) |gg| {
            r.clearTerm(zl);
            for (0..4) |y| r.drawRow(gg, &gl, .{ .l = zl, .pan = p, .show_cursor = true }, @intCast(y));
        };
    }
}

test "draw a frame end to end and clip at every pan offset" {
    const gpa = testing.allocator;
    var gl = try glyphs.Glyphs.init(gpa, @embedFile("font_regular"), @embedFile("font_bold"));
    defer gl.deinit();
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
    const in: layout.Input = .{ .css_w = 120, .css_h = 300, .dpr = 1, .cols = 10, .rows = 3, .zoom = .{}, .m = gl.metrics() };
    const l = layout.compute(in);
    try r.fb.resize(gpa, l.w, l.h);
    gl.setSize(l.cw, l.ch, l.em);
    r.clearTerm(l);
    for (0..3) |y| r.drawRow(&g, &gl, .{ .l = l, .pan = .{ 0, 0 }, .show_cursor = true }, @intCast(y));
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
    const zl = layout.compute(.{ .css_w = 50, .css_h = 60, .dpr = 2, .cols = 10, .rows = 3, .zoom = .{ .fit = false, .font_px = 30 }, .m = gl.metrics() });
    try r.fb.resize(gpa, zl.w, zl.h);
    gl.setSize(zl.cw, zl.ch, zl.em);
    const pans = [_][2]i32{ .{ -5000, -5000 }, .{ 0, 0 }, .{ 37, 11 }, .{ 5000, 5000 }, zl.panMax() };
    for (pans) |p| {
        r.clearTerm(zl);
        for (0..3) |y| r.drawRow(&g, &gl, .{ .l = zl, .pan = p, .show_cursor = true }, @intCast(y));
    }
}
