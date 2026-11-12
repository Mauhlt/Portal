//! Cell-sized glyph coverage bitmaps from the bundled DejaVu Sans Mono,
//! cached per (code point, bold, italic, width) for the current cell size.
//!
//! Rasterising follows the native client's fontset.zig
//! (Portal-wt-client/client/src/font/fontset.zig): same baseline and
//! centring rules, same procedural box-drawing / block characters (so lines
//! join across cells whatever the font metrics), same replacement box for
//! missing glyphs. Unlike the native client there are no system fallback
//! fonts: a phone page cannot read them, so CJK and emoji become boxes.

const std = @import("std");
const ttf = @import("font/ttf.zig");
const raster = @import("font/raster.zig");
const layout = @import("layout.zig");

pub const Style = struct { bold: bool = false, italic: bool = false };

const Entry = struct { off: u32, len: u32 };

/// Cache memory cap; past this the cache is simply cleared.
const max_store = 24 << 20;

pub const Glyphs = struct {
    gpa: std.mem.Allocator,
    regular: ttf.Font,
    bold: ?ttf.Font,
    /// Cell size in pixels and the em that produces it.
    cw: u32 = 0,
    ch: u32 = 0,
    em: f32 = 0,
    baseline: f32 = 0,
    stroke: u32 = 1,
    map: std.AutoHashMapUnmanaged(u32, Entry) = .empty,
    store: std.ArrayList(u8) = .empty,
    outline: ttf.Outline = .{},
    acc: std.ArrayList(f32) = .empty,

    pub fn init(gpa: std.mem.Allocator, regular: []const u8, bold: []const u8) ttf.Error!Glyphs {
        const r = try ttf.Font.init(regular, 0);
        if (r.glyphIndex('M') == 0) return error.Unsupported;
        const b: ?ttf.Font = ttf.Font.init(bold, 0) catch null;
        return .{ .gpa = gpa, .regular = r, .bold = b };
    }

    pub fn deinit(g: *Glyphs) void {
        g.map.deinit(g.gpa);
        g.store.deinit(g.gpa);
        g.outline.deinit(g.gpa);
        g.acc.deinit(g.gpa);
    }

    pub fn metrics(g: *const Glyphs) layout.FontMetrics {
        const f = &g.regular;
        const upem: f32 = @floatFromInt(f.units_per_em);
        const adv: f32 = @floatFromInt(f.advance(f.glyphIndex('M')));
        const lh: f32 = @floatFromInt(@as(i32, f.ascender) - f.descender + @max(f.line_gap, 0));
        return .{ .adv_em = if (adv > 0) adv / upem else 0.6, .line_em = if (lh > 0) lh / upem else 1.2 };
    }

    /// Sets the cell size; clears the cache when it changes.
    pub fn setSize(g: *Glyphs, cw: u32, ch: u32, em: f32) void {
        if (cw == g.cw and ch == g.ch and em == g.em) return;
        g.cw = @max(1, cw);
        g.ch = @max(1, ch);
        g.em = if (std.math.isFinite(em) and em > 0) em else 1;
        g.clear();
        const f = &g.regular;
        const scale = g.em / @as(f32, @floatFromInt(f.units_per_em));
        const asc: f32 = @floatFromInt(f.ascender);
        const desc: f32 = @floatFromInt(f.descender);
        const hf: f32 = @floatFromInt(g.ch);
        g.baseline = std.math.clamp(@round(asc * scale + (hf - (asc - desc) * scale) / 2), 0, hf);
        g.stroke = @max(1, @as(u32, @intFromFloat(std.math.clamp(@round(g.em / 14), 0, 64))));
    }

    /// Sets the size from an em alone (cell = the font's own proportions);
    /// used for the answer-bar labels.
    pub fn setEm(g: *Glyphs, em_in: f32) void {
        const em = if (std.math.isFinite(em_in)) std.math.clamp(em_in, 1, 1000) else 14;
        const m = g.metrics();
        const cw: u32 = @intFromFloat(@max(1, @round(em * m.adv_em)));
        const ch: u32 = @intFromFloat(@max(1, @round(em * m.line_em)));
        g.setSize(cw, ch, em);
    }

    fn clear(g: *Glyphs) void {
        g.map.clearRetainingCapacity();
        g.store.clearRetainingCapacity();
    }

    /// Coverage for `cp` spanning `cells` (1 or 2) cells: (cw*cells) x ch
    /// bytes, row-major. Never fails: out of memory gives an empty slice.
    pub fn get(g: *Glyphs, cp: u21, style: Style, cells: u2) []const u8 {
        const n: u32 = if (cells == 2) 2 else 1;
        const key: u32 = @as(u32, cp) | (@as(u32, @intFromBool(style.bold)) << 21) |
            (@as(u32, @intFromBool(style.italic)) << 22) | ((n - 1) << 23);
        if (g.map.get(key)) |e| return g.store.items[e.off..][0..e.len];
        const w = g.cw * n;
        const len: usize = @as(usize, w) * g.ch;
        if (g.store.items.len + len > max_store) g.clear();
        g.map.ensureUnusedCapacity(g.gpa, 1) catch return &.{};
        const off = g.store.items.len;
        g.store.appendNTimes(g.gpa, 0, len) catch return &.{};
        const cov = g.store.items[off..][0..len];
        g.render(cp, style, n, w, cov);
        g.map.putAssumeCapacity(key, .{ .off = @intCast(off), .len = @intCast(len) });
        return cov;
    }

    fn render(g: *Glyphs, cp: u21, style: Style, cells: u32, w: u32, cov: []u8) void {
        const h = g.ch;
        if (cp == ' ' or cp == 0xA0) return;
        if (cells == 1 and drawBoxChar(cp, w, h, g.stroke, cov)) return;
        var font = &g.regular;
        if (style.bold) if (g.bold) |*b| if (b.glyphIndex(cp) != 0) {
            font = b;
        };
        const gid = font.glyphIndex(cp);
        if (gid == 0) return drawReplacementBox(w, h, g.stroke, cov);
        g.outline.clear();
        font.glyphOutline(g.gpa, gid, &g.outline) catch return drawReplacementBox(w, h, g.stroke, cov);

        const n_acc = @as(usize, w) * h + 4;
        g.acc.resize(g.gpa, n_acc) catch return;
        @memset(g.acc.items, 0);
        var canvas: raster.Canvas = .{ .w = w, .h = h, .acc = g.acc.items };
        const upem: f32 = @floatFromInt(font.units_per_em);
        const scale = g.em / upem;
        const wf: f32 = @floatFromInt(w);
        const hf: f32 = @floatFromInt(h);
        const adv = @as(f32, @floatFromInt(font.advance(gid))) * scale;
        var origin_x: f32 = 0;
        if (cells == 2 and adv < wf * 0.75) origin_x = (wf - adv) / 2;
        const skew: f32 = if (style.italic) 0.18 else 0;
        if (style.italic) origin_x -= skew * (hf - g.baseline) * 0.5;
        raster.fillOutline(&canvas, &g.outline, .{ .scale = scale, .origin_x = origin_x, .baseline_y = g.baseline, .skew = skew });
        canvas.finish(cov);
        // Synthetic bold if the bold face is missing.
        if (style.bold and font == &g.regular) embolden(cov, w, h);
    }
};

fn embolden(cov: []u8, w: u32, h: u32) void {
    for (0..h) |y| {
        const row = cov[y * w ..][0..w];
        var x: usize = w;
        while (x > 1) {
            x -= 1;
            row[x] = @max(row[x], row[x - 1]);
        }
    }
}

fn fillRect(cov: []u8, w: u32, h: u32, x0: i64, y0: i64, x1: i64, y1: i64, value: u8) void {
    const ax: usize = @intCast(std.math.clamp(x0, 0, w));
    const bx: usize = @intCast(std.math.clamp(x1, 0, w));
    const ay: usize = @intCast(std.math.clamp(y0, 0, h));
    const by: usize = @intCast(std.math.clamp(y1, 0, h));
    var y = ay;
    while (y < by) : (y += 1) {
        var x = ax;
        while (x < bx) : (x += 1) cov[y * w + x] = @max(cov[y * w + x], value);
    }
}

fn clearRect(cov: []u8, w: u32, h: u32, x0: i64, y0: i64, x1: i64, y1: i64) void {
    const ax: usize = @intCast(std.math.clamp(x0, 0, w));
    const bx: usize = @intCast(std.math.clamp(x1, 0, w));
    const ay: usize = @intCast(std.math.clamp(y0, 0, h));
    const by: usize = @intCast(std.math.clamp(y1, 0, h));
    var y = ay;
    while (y < by) : (y += 1) {
        if (bx > ax) @memset(cov[y * w + ax .. y * w + bx], 0);
    }
}

fn drawReplacementBox(w: u32, h: u32, stroke: u32, cov: []u8) void {
    const s: i64 = stroke;
    const x0: i64 = @intCast(w / 8 + 1);
    const x1: i64 = @as(i64, w) - x0;
    const y0: i64 = @intCast(h / 6);
    const y1: i64 = @as(i64, h) - y0;
    fillRect(cov, w, h, x0, y0, x1, y0 + s, 200);
    fillRect(cov, w, h, x0, y1 - s, x1, y1, 200);
    fillRect(cov, w, h, x0, y0, x0 + s, y1, 200);
    fillRect(cov, w, h, x1 - s, y0, x1, y1, 200);
}

/// Line weights for U+2500..U+257F: up, right, down, left
/// (0 none, 1 light, 2 heavy, 3 double). Rounded corners draw square.
fn boxSpec(cp: u21) ?[4]u2 {
    return switch (cp) {
        0x2500, 0x2504, 0x2508, 0x254C => .{ 0, 1, 0, 1 },
        0x2501, 0x2505, 0x2509, 0x254D => .{ 0, 2, 0, 2 },
        0x2502, 0x2506, 0x250A, 0x254E => .{ 1, 0, 1, 0 },
        0x2503, 0x2507, 0x250B, 0x254F => .{ 2, 0, 2, 0 },
        0x250C, 0x256D => .{ 0, 1, 1, 0 },
        0x250F => .{ 0, 2, 2, 0 },
        0x2510, 0x256E => .{ 0, 0, 1, 1 },
        0x2513 => .{ 0, 0, 2, 2 },
        0x2514, 0x2570 => .{ 1, 1, 0, 0 },
        0x2517 => .{ 2, 2, 0, 0 },
        0x2518, 0x256F => .{ 1, 0, 0, 1 },
        0x251B => .{ 2, 0, 0, 2 },
        0x251C => .{ 1, 1, 1, 0 },
        0x2523 => .{ 2, 2, 2, 0 },
        0x2524 => .{ 1, 0, 1, 1 },
        0x252B => .{ 2, 0, 2, 2 },
        0x252C => .{ 0, 1, 1, 1 },
        0x2533 => .{ 0, 2, 2, 2 },
        0x2534 => .{ 1, 1, 0, 1 },
        0x253B => .{ 2, 2, 0, 2 },
        0x253C => .{ 1, 1, 1, 1 },
        0x254B => .{ 2, 2, 2, 2 },
        0x2550 => .{ 0, 3, 0, 3 },
        0x2551 => .{ 3, 0, 3, 0 },
        0x2554 => .{ 0, 3, 3, 0 },
        0x2557 => .{ 0, 0, 3, 3 },
        0x255A => .{ 3, 3, 0, 0 },
        0x255D => .{ 3, 0, 0, 3 },
        0x2560 => .{ 3, 3, 3, 0 },
        0x2563 => .{ 3, 0, 3, 3 },
        0x2566 => .{ 0, 3, 3, 3 },
        0x2569 => .{ 3, 3, 0, 3 },
        0x256C => .{ 3, 3, 3, 3 },
        0x2574 => .{ 0, 0, 0, 1 },
        0x2575 => .{ 1, 0, 0, 0 },
        0x2576 => .{ 0, 1, 0, 0 },
        0x2577 => .{ 0, 0, 1, 0 },
        else => null,
    };
}

fn drawBoxChar(cp: u21, w: u32, h: u32, stroke: u32, cov: []u8) bool {
    const W: i64 = w;
    const H: i64 = h;
    if (boxSpec(cp)) |spec| {
        const light: i64 = stroke;
        const cx = @divFloor(W - light, 2);
        const cy = @divFloor(H - light, 2);
        const dashed = (cp >= 0x2504 and cp <= 0x250B) or (cp >= 0x254C and cp <= 0x254F);
        for (spec, 0..) |weight, dir| {
            if (weight == 0) continue;
            const t: i64 = if (weight == 2) light * 2 else light;
            const off: i64 = if (weight == 2) @divFloor(light, 2) else 0;
            const gap: i64 = light + 1;
            const lines: []const i64 = if (weight == 3) &.{ -gap, gap } else &.{0};
            for (lines) |d| switch (dir) {
                0 => fillRect(cov, w, h, cx - off + d, 0, cx - off + d + t, cy + t, 255),
                1 => fillRect(cov, w, h, cx, cy - off + d, W, cy - off + d + t, 255),
                2 => fillRect(cov, w, h, cx - off + d, cy, cx - off + d + t, H, 255),
                else => fillRect(cov, w, h, 0, cy - off + d, cx + t, cy - off + d + t, 255),
            };
        }
        if (dashed) {
            const horizontal = spec[1] != 0;
            const n: i64 = if (horizontal) W else H;
            const seg = @max(2, @divFloor(n, 4));
            var i: i64 = 0;
            while (i < n) : (i += seg) {
                const g0 = i + seg - @max(1, @divFloor(seg, 3));
                const g1 = i + seg;
                if (horizontal) clearRect(cov, w, h, g0, 0, g1, H) else clearRect(cov, w, h, 0, g0, W, g1);
            }
        }
        return true;
    }
    switch (cp) {
        0x2588 => fillRect(cov, w, h, 0, 0, W, H, 255),
        0x2580 => fillRect(cov, w, h, 0, 0, W, @divFloor(H, 2), 255),
        0x2581...0x2587 => {
            const eighths: i64 = @as(i64, cp - 0x2580);
            fillRect(cov, w, h, 0, H - @divFloor(H * eighths, 8), W, H, 255);
        },
        0x2589...0x258F => {
            const eighths: i64 = 8 - @as(i64, cp - 0x2588);
            fillRect(cov, w, h, 0, 0, @divFloor(W * eighths, 8), H, 255);
        },
        0x2590 => fillRect(cov, w, h, @divFloor(W, 2), 0, W, H, 255),
        0x2591 => fillRect(cov, w, h, 0, 0, W, H, 64),
        0x2592 => fillRect(cov, w, h, 0, 0, W, H, 128),
        0x2593 => fillRect(cov, w, h, 0, 0, W, H, 192),
        0x2594 => fillRect(cov, w, h, 0, 0, W, @max(1, @divFloor(H, 8)), 255),
        0x2595 => fillRect(cov, w, h, W - @max(1, @divFloor(W, 8)), 0, W, H, 255),
        else => return false,
    }
    return true;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;
const font_regular = @embedFile("font_regular");
const font_bold = @embedFile("font_bold");

fn inked(cov: []const u8) usize {
    var n: usize = 0;
    for (cov) |v| n += @intFromBool(v > 128);
    return n;
}

test "bundled fonts: metrics, glyphs, boxes, replacement" {
    var g = try Glyphs.init(testing.allocator, font_regular, font_bold);
    defer g.deinit();
    try testing.expect(g.bold != null);
    const m = g.metrics();
    try testing.expectApproxEqAbs(@as(f32, 0.602), m.adv_em, 0.01);
    try testing.expect(m.line_em > 1.1 and m.line_em < 1.3);
    g.setSize(12, 23, 20);
    const a = g.get('A', .{}, 1);
    try testing.expectEqual(@as(usize, 12 * 23), a.len);
    try testing.expect(inked(a) > 10);
    // Cached: same memory.
    try testing.expectEqual(a.ptr, g.get('A', .{}, 1).ptr);
    // Bold has more ink than regular.
    try testing.expect(inked(g.get('W', .{ .bold = true }, 1)) > inked(g.get('W', .{}, 1)));
    _ = g.get('W', .{ .italic = true, .bold = true }, 1);
    // Space is empty; the full block is solid; a horizontal line spans the cell.
    try testing.expectEqual(@as(usize, 0), inked(g.get(' ', .{}, 1)));
    try testing.expectEqual(@as(usize, 12 * 23), inked(g.get(0x2588, .{}, 1)));
    const line = g.get(0x2500, .{}, 1);
    const cy = (23 - 1) / 2;
    for (0..12) |x| try testing.expectEqual(@as(u8, 255), line[cy * 12 + x]);
    // CJK is not in DejaVu Sans Mono: a two-cell replacement box.
    const cjk = g.get(0x4E2D, .{}, 2);
    try testing.expectEqual(@as(usize, 24 * 23), cjk.len);
    try testing.expect(inked(cjk) > 20);
    // Resizing clears the cache and rerenders at the new size.
    g.setSize(24, 46, 40);
    try testing.expectEqual(@as(usize, 24 * 46), g.get('A', .{}, 1).len);
}

test "glyph rendering survives every code point class and tiny cells" {
    var g = try Glyphs.init(testing.allocator, font_regular, font_bold);
    defer g.deinit();
    for ([_][3]u32{ .{ 1, 1, 1 }, .{ 2, 3, 3 }, .{ 9, 18, 15 }, .{ 40, 80, 66 } }) |s| {
        g.setSize(s[0], s[1], @floatFromInt(s[2]));
        var cp: u21 = 0;
        while (cp < 0x3000) : (cp += 7) {
            _ = g.get(cp, .{}, 1);
            _ = g.get(cp, .{ .bold = true, .italic = true }, 2);
        }
        _ = g.get(0x10FFFF, .{}, 1);
        _ = g.get(0x1F600, .{}, 2);
    }
}

test "a corrupt font is rejected, never trusted" {
    const bad = [_][]const u8{ "", "garbage", font_regular[0..1000] };
    for (bad) |d| try testing.expect(std.meta.isError(Glyphs.init(testing.allocator, d, d)));
    // A broken bold face falls back to synthetic bold.
    var g = try Glyphs.init(testing.allocator, font_regular, font_bold[0..500]);
    defer g.deinit();
    try testing.expect(g.bold == null);
    g.setSize(10, 20, 16);
    try testing.expect(inked(g.get('H', .{ .bold = true }, 1)) > 0);
}
