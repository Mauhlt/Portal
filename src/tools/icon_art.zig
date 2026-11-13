//! Portal's app icon, drawn as code: the simplified logo of
//! docs/brand/portal-icon.svg (same geometry, same colours), rasterised by
//! a tiny supersampling "shader" (circles, bands, gradients, a few
//! polygons and line segments). Used by the brand tool (docs/brand PNGs
//! and the Windows .ico) and by `zig build ios` (the bundle's icons).
//!
//! Coordinates are the SVG's: a 600 x 600 canvas, centre (300, 300).
//!
//! Level of detail follows the pixel size, so the icon reads at 16 px as
//! well as at 1024 px: below ~64 px the ring and the orb grow and the
//! constellation, the mountains and the thin outer ring are left out
//! (`Detail`).

const std = @import("std");

pub const Rgba = [4]f32; // premultiplied, 0..1

const cx: f32 = 300;
const cy: f32 = 300;

/// Shape parameters for one pixel size.
pub const Detail = struct {
    /// Pixels per canvas unit.
    px: f32,
    ring_out: f32,
    ring_w: f32,
    orb_r: f32,
    halo_alpha: f32,
    stars: bool,
    lines: bool,
    mountains: bool,
    fine_ring: bool,

    pub fn of(size: u32) Detail {
        const s: f32 = @floatFromInt(size);
        // 0 at 16 px, 1 from 256 px up (log scale).
        const t = std.math.clamp((std.math.log2(s) - 4) / 4, 0, 1);
        return .{
            .px = s / 600,
            .ring_out = 262,
            .ring_w = lerp(78, 30, t),
            .orb_r = lerp(104, 60, t),
            .halo_alpha = lerp(0.35, 0.55, t),
            .stars = size >= 48,
            .lines = size >= 96,
            .mountains = size >= 48,
            .fine_ring = size >= 128,
        };
    }
};

fn lerp(a: f32, b: f32, t: f32) f32 {
    return a + (b - a) * t;
}

fn rgb(comptime v: u24) [3]f32 {
    return .{
        @as(f32, @floatFromInt((v >> 16) & 0xff)) / 255,
        @as(f32, @floatFromInt((v >> 8) & 0xff)) / 255,
        @as(f32, @floatFromInt(v & 0xff)) / 255,
    };
}

const Stop = struct { at: f32, c: [3]f32 };

fn grad(stops: []const Stop, t: f32) [3]f32 {
    if (t <= stops[0].at) return stops[0].c;
    for (stops[1..], 1..) |s, i| {
        if (t <= s.at) {
            const p = stops[i - 1];
            const k = (t - p.at) / (s.at - p.at);
            return .{ lerp(p.c[0], s.c[0], k), lerp(p.c[1], s.c[1], k), lerp(p.c[2], s.c[2], k) };
        }
    }
    return stops[stops.len - 1].c;
}

// The palette (docs/brand/README.md lists it).
pub const ring_stops = [_]Stop{
    .{ .at = 0, .c = rgb(0x1028D8) },
    .{ .at = 0.3, .c = rgb(0x0066FF) },
    .{ .at = 0.55, .c = rgb(0x00C8FF) },
    .{ .at = 0.78, .c = rgb(0x00FFC2) },
    .{ .at = 1, .c = rgb(0x7DFF5C) },
};
const night_stops = [_]Stop{
    .{ .at = 0, .c = rgb(0x02040F) },
    .{ .at = 0.55, .c = rgb(0x071640) },
    .{ .at = 1, .c = rgb(0x123274) },
};
const sky_stops = [_]Stop{
    .{ .at = 0, .c = rgb(0x1E90FF) },
    .{ .at = 0.55, .c = rgb(0x4FB8FF) },
    .{ .at = 1, .c = rgb(0xBDEBFF) },
};
const grass_stops = [_]Stop{
    .{ .at = 0, .c = rgb(0xA3E635) },
    .{ .at = 0.35, .c = rgb(0x4ADE80) },
    .{ .at = 1, .c = rgb(0x15803D) },
};
const moon_stops = [_]Stop{
    .{ .at = 0, .c = rgb(0xF4FAFF) },
    .{ .at = 0.45, .c = rgb(0xC4E3FF) },
    .{ .at = 0.8, .c = rgb(0x7DB9FF) },
    .{ .at = 1, .c = rgb(0x3A7DEB) },
};
const sun_stops = [_]Stop{
    .{ .at = 0, .c = rgb(0xFFF6D0) },
    .{ .at = 0.4, .c = rgb(0xFFE27A) },
    .{ .at = 0.75, .c = rgb(0xFFA733) },
    .{ .at = 1, .c = rgb(0xE5341B) },
};
/// The halo's bands, outside to inside: cool over the night, a rainbow
/// under the horizon.
const cool_band = [_]Stop{
    .{ .at = 0, .c = rgb(0xC4B5FD) },
    .{ .at = 0.17, .c = rgb(0xA5B4FC) },
    .{ .at = 0.33, .c = rgb(0x818CF8) },
    .{ .at = 0.5, .c = rgb(0x60A5FA) },
    .{ .at = 0.67, .c = rgb(0x22D3EE) },
    .{ .at = 0.83, .c = rgb(0x2DD4BF) },
    .{ .at = 1, .c = rgb(0xCFFAFE) },
};
const rainbow_band = [_]Stop{
    .{ .at = 0, .c = rgb(0xFF3B30) },
    .{ .at = 0.17, .c = rgb(0xFF9500) },
    .{ .at = 0.33, .c = rgb(0xFFD60A) },
    .{ .at = 0.5, .c = rgb(0x34C759) },
    .{ .at = 0.67, .c = rgb(0x0A84FF) },
    .{ .at = 0.83, .c = rgb(0x5856D6) },
    .{ .at = 1, .c = rgb(0xAF52DE) },
};
const bg_stops = [_]Stop{
    .{ .at = 0, .c = rgb(0x0B1A4A) },
    .{ .at = 1, .c = rgb(0x02040F) },
};

/// The brain constellation: its outline and two inner paths (from the
/// reference drawing, placed by translate(300 156) scale(0.8)
/// translate(-303 -188)).
const brain_outline = [_][2]f32{
    .{ 196, 214 }, .{ 182, 188 }, .{ 184, 160 }, .{ 198, 134 }, .{ 222, 114 }, .{ 252, 102 },
    .{ 286, 98 },  .{ 318, 100 }, .{ 348, 108 }, .{ 376, 122 }, .{ 398, 142 }, .{ 410, 166 },
    .{ 412, 190 }, .{ 404, 208 }, .{ 418, 222 }, .{ 414, 240 }, .{ 394, 248 }, .{ 370, 244 },
    .{ 352, 232 }, .{ 330, 216 }, .{ 300, 218 }, .{ 270, 214 }, .{ 244, 220 }, .{ 220, 222 },
};
const brain_inner = [_][]const [2]f32{
    &.{ .{ 318, 100 }, .{ 306, 132 }, .{ 312, 160 }, .{ 300, 188 }, .{ 304, 216 } },
    &.{ .{ 210, 196 }, .{ 240, 186 }, .{ 272, 180 }, .{ 300, 188 }, .{ 330, 186 }, .{ 354, 196 } },
    &.{ .{ 252, 102 }, .{ 262, 136 }, .{ 250, 160 }, .{ 272, 180 } },
    &.{ .{ 348, 108 }, .{ 344, 140 }, .{ 366, 162 }, .{ 398, 170 } },
};
/// The bright nodes (drawn even when the lines are not).
const brain_stars = [_][2]f32{
    .{ 198, 134 }, .{ 252, 102 }, .{ 318, 100 }, .{ 376, 122 }, .{ 410, 178 }, .{ 300, 188 },
    .{ 184, 174 }, .{ 414, 240 }, .{ 300, 218 }, .{ 244, 220 }, .{ 352, 232 },
};

pub fn brainPoint(p: [2]f32) [2]f32 {
    return .{ 300 + 0.8 * (p[0] - 303), 156 + 0.8 * (p[1] - 188) };
}

/// Two snowy peaks either side of the sun (simplified from the hero).
pub const left_peak = [_][2]f32{ .{ 60, 446 }, .{ 60, 362 }, .{ 100, 328 }, .{ 122, 342 }, .{ 158, 304 }, .{ 204, 356 }, .{ 244, 404 }, .{ 274, 446 } };
pub const right_peak = blk: {
    var out: [left_peak.len][2]f32 = undefined;
    for (left_peak, 0..) |p, i| out[i] = .{ 600 - p[0], p[1] };
    break :blk out;
};

fn inPolygon(poly: []const [2]f32, x: f32, y: f32) bool {
    var inside = false;
    var j = poly.len - 1;
    for (poly, 0..) |a, i| {
        const b = poly[j];
        if ((a[1] > y) != (b[1] > y) and x < (b[0] - a[0]) * (y - a[1]) / (b[1] - a[1]) + a[0]) inside = !inside;
        j = i;
    }
    return inside;
}

fn segDist(x: f32, y: f32, a: [2]f32, b: [2]f32) f32 {
    const dx = b[0] - a[0];
    const dy = b[1] - a[1];
    const t = std.math.clamp(((x - a[0]) * dx + (y - a[1]) * dy) / (dx * dx + dy * dy), 0, 1);
    const ex = x - (a[0] + t * dx);
    const ey = y - (a[1] + t * dy);
    return @sqrt(ex * ex + ey * ey);
}

fn over(dst: Rgba, c: [3]f32, a: f32) Rgba {
    const k = 1 - a;
    return .{ c[0] * a + dst[0] * k, c[1] * a + dst[1] * k, c[2] * a + dst[2] * k, a + dst[3] * k };
}

fn smooth(e0: f32, e1: f32, x: f32) f32 {
    const t = std.math.clamp((x - e0) / (e1 - e0), 0, 1);
    return t * t * (3 - 2 * t);
}

/// The colour at canvas point (x, y), premultiplied.
pub fn sample(d: Detail, x: f32, y: f32, opaque_bg: bool) Rgba {
    const dx = x - cx;
    const dy = y - cy;
    const r = @sqrt(dx * dx + dy * dy);
    var c: Rgba = .{ 0, 0, 0, 0 };
    if (opaque_bg) {
        const t = std.math.clamp(r / 424, 0, 1);
        const b = grad(&bg_stops, t);
        c = .{ b[0], b[1], b[2], 1 };
    }
    const ring_in = d.ring_out - d.ring_w;
    const ring_mid = d.ring_out - d.ring_w / 2;
    const ring_col = grad(&ring_stops, (y - (cy - d.ring_out)) / (2 * d.ring_out));

    // Neon glow around the ring (outside; the disc covers the inside).
    {
        const sigma = d.ring_w / 2 + 20;
        const g = (r - ring_mid) / sigma;
        c = over(c, ring_col, 0.55 * @exp(-g * g));
    }

    if (r < ring_in + 1) {
        // The disc.
        var bgc: [3]f32 = undefined;
        if (y < cy) {
            bgc = grad(&night_stops, (y - 60) / 240);
        } else {
            bgc = grad(&sky_stops, (y - 300) / 140);
        }
        c = over(c, bgc, 1);
        const orb = d.orb_r;
        // Moon glow above, sun glow below.
        {
            const gr = orb * 2.9;
            const t = r / gr;
            if (t < 1) {
                if (y < cy) {
                    const a = if (t < 0.35) lerp(0.85, 0.35, t / 0.35) else lerp(0.35, 0, (t - 0.35) / 0.65);
                    c = over(c, rgb(0x5AAEFF), a * 0.7);
                } else {
                    const a = if (t < 0.35) lerp(0.95, 0.5, t / 0.35) else if (t < 0.7) lerp(0.5, 0.16, (t - 0.35) / 0.35) else lerp(0.16, 0, (t - 0.7) / 0.3);
                    c = over(c, rgb(0xFFC23A), a * 0.8);
                }
            }
        }
        if (d.mountains and y > cy) {
            if (inPolygon(&left_peak, x, y) or inPolygon(&right_peak, x, y)) {
                const snow = y < 334;
                const m = if (snow) rgb(0xEAF4FF) else grad(&.{ .{ .at = 0, .c = rgb(0x9CC2EE) }, .{ .at = 1, .c = rgb(0x4A6CB0) } }, (y - 330) / 116);
                c = over(c, m, 1);
            }
        }
        // The meadow.
        {
            const edge = 440 + 6 * @sin((x - 60) / 480 * std.math.pi * 2);
            if (y > edge) c = over(c, grad(&grass_stops, (y - 430) / 120), 1);
        }
        // The halo: soft bands between orb + 22 and orb + 50.
        {
            const h0 = orb + 22;
            const h1 = orb + 50;
            if (r > h0 - 6 and r < h1 + 6) {
                const t = std.math.clamp((h1 - r) / (h1 - h0), 0, 1);
                const band = if (y < cy) grad(&cool_band, t) else grad(&rainbow_band, t);
                const a = d.halo_alpha * smooth(h0 - 6, h0 + 2, r) * (1 - smooth(h1 - 2, h1 + 6, r));
                c = over(c, band, a);
            }
        }
        // The constellation.
        if (d.lines or d.stars) {
            const lw = @max(1.1, 0.55 / d.px);
            if (d.lines) {
                var best: f32 = 1e9;
                for (brain_outline, 0..) |p, i| {
                    const q = brain_outline[(i + 1) % brain_outline.len];
                    best = @min(best, segDist(x, y, brainPoint(p), brainPoint(q)));
                }
                for (brain_inner) |path| for (path[0 .. path.len - 1], path[1..]) |p, q| {
                    best = @min(best, segDist(x, y, brainPoint(p), brainPoint(q)));
                };
                if (best < lw) c = over(c, rgb(0xB8E0FF), 0.75);
            }
            const sr = @max(3.6, 1.1 / d.px);
            for (brain_stars) |s0| {
                const s = brainPoint(s0);
                const ex = x - s[0];
                const ey = y - s[1];
                const sd = @sqrt(ex * ex + ey * ey);
                if (sd < sr * 3) c = over(c, rgb(0xD6EEFF), 0.45 * (1 - sd / (sr * 3)));
                if (sd < sr) c = over(c, rgb(0xFFFFFF), 1);
            }
        }
        // The orb: moon above, sun below, a rim and a horizon glint.
        if (r < orb) {
            const t = r / orb;
            c = over(c, if (y < cy) grad(&moon_stops, t) else grad(&sun_stops, t), 1);
            const rim = @max(3, 0.7 / d.px);
            if (r > orb - rim) c = over(c, if (y < cy) rgb(0xD6EEFF) else rgb(0xFFE7A3), 0.9);
        }
        {
            const gl = @max(2.5, 0.6 / d.px);
            const half = orb * 1.7;
            if (@abs(dy) < gl and @abs(dx) < half) {
                const k = 1 - @abs(dx) / half;
                c = over(c, rgb(0xFFFFFF), 0.9 * k * (1 - @abs(dy) / gl));
            }
        }
    }

    // The ring, its white core, and the fine rings either side.
    if (r >= ring_in and r <= d.ring_out) c = over(c, ring_col, 1);
    {
        const core = d.ring_w * 0.16;
        if (@abs(r - ring_mid) < core) c = over(c, rgb(0xFFFFFF), 0.45);
    }
    if (d.fine_ring) {
        const fw = @max(1.2, 0.6 / d.px);
        if (@abs(r - (d.ring_out + 16)) < fw) c = over(c, ring_col, 0.5);
        if (@abs(r - (ring_in - 12)) < fw) c = over(c, ring_col, 0.8);
    }
    return c;
}

/// Renders the icon at `size x size` (RGBA8, straight alpha). With
/// `opaque_bg` the square is filled (iOS: no alpha); otherwise the
/// outside of the ring's glow is transparent (Windows).
pub fn render(gpa: std.mem.Allocator, size: u32, opaque_bg: bool) ![]u8 {
    const d = Detail.of(size);
    const out = try gpa.alloc(u8, @as(usize, size) * size * 4);
    const ss: u32 = if (size <= 64) 8 else 4;
    const inv: f32 = 1 / @as(f32, @floatFromInt(ss * ss));
    const unit = 600 / @as(f32, @floatFromInt(size));
    for (0..size) |py| for (0..size) |px| {
        var acc: Rgba = .{ 0, 0, 0, 0 };
        for (0..ss) |sy| for (0..ss) |sx| {
            const fx = (@as(f32, @floatFromInt(px)) + (@as(f32, @floatFromInt(sx)) + 0.5) / @as(f32, @floatFromInt(ss))) * unit;
            const fy = (@as(f32, @floatFromInt(py)) + (@as(f32, @floatFromInt(sy)) + 0.5) / @as(f32, @floatFromInt(ss))) * unit;
            const s = sample(d, fx, fy, opaque_bg);
            for (0..4) |k| acc[k] += s[k];
        };
        const o = out[(py * size + px) * 4 ..][0..4];
        const a = acc[3] * inv;
        for (0..3) |k| {
            const v = if (a > 0) acc[k] * inv / a else 0;
            o[k] = @intFromFloat(std.math.clamp(v * 255 + 0.5, 0, 255));
        }
        o[3] = if (opaque_bg) 255 else @intFromFloat(std.math.clamp(a * 255 + 0.5, 0, 255));
    };
    return out;
}

test "icon: opaque fills, transparent corners, ring colours" {
    const gpa = std.testing.allocator;
    const a = try render(gpa, 32, false);
    defer gpa.free(a);
    try std.testing.expectEqual(@as(u8, 0), a[3]); // corner
    const b = try render(gpa, 32, true);
    defer gpa.free(b);
    for (0..32 * 32) |i| try std.testing.expectEqual(@as(u8, 255), b[i * 4 + 3]);
    // Top of the ring is blue, bottom green.
    const top = b[(2 * 32 + 16) * 4 ..][0..3];
    const bottom = b[(29 * 32 + 16) * 4 ..][0..3];
    try std.testing.expect(top[2] > top[1]);
    try std.testing.expect(bottom[1] > bottom[2]);
}
