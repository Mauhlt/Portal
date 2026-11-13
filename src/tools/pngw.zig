//! A small PNG writer for the brand tools (src/tools/brand.zig, the iOS
//! icon step): 8-bit RGB or RGBA, adaptive per-row filters, zlib through
//! std.compress.flate at its best level. Tooling only: nothing in Portal's
//! programs writes PNGs.

const std = @import("std");
const flate = std.compress.flate;

pub const Channels = enum(u8) { rgb = 3, rgba = 4 };

/// Encodes `w x h` pixels (`px` is RGBA8, straight alpha). With `.rgb`
/// the alpha channel is dropped (the caller makes the pixels opaque).
pub fn encode(gpa: std.mem.Allocator, px: []const u8, w: u32, h: u32, ch: Channels) ![]u8 {
    std.debug.assert(px.len == @as(usize, w) * h * 4);
    const bpp: usize = @intFromEnum(ch);
    const stride = bpp * w;
    // Filtered scanlines: one filter byte + the row.
    const raw = try gpa.alloc(u8, (1 + stride) * h);
    defer gpa.free(raw);
    const cur = try gpa.alloc(u8, stride);
    defer gpa.free(cur);
    const prev = try gpa.alloc(u8, stride);
    defer gpa.free(prev);
    const trial = try gpa.alloc(u8, stride);
    defer gpa.free(trial);
    @memset(prev, 0);
    for (0..h) |y| {
        for (0..w) |x| {
            const s = px[(y * w + x) * 4 ..][0..4];
            @memcpy(cur[x * bpp ..][0..bpp], s[0..bpp]);
        }
        // Pick the filter with the smallest sum of absolute values (the
        // usual heuristic).
        var best: u8 = 0;
        var best_cost: u64 = std.math.maxInt(u64);
        const out = raw[y * (1 + stride) ..][0 .. 1 + stride];
        for (0..5) |f| {
            filterRow(@intCast(f), cur, prev, bpp, trial);
            var cost: u64 = 0;
            for (trial) |b| cost += @abs(@as(i8, @bitCast(b)));
            if (cost < best_cost) {
                best_cost = cost;
                best = @intCast(f);
                out[0] = best;
                @memcpy(out[1..], trial);
            }
        }
        @memcpy(prev, cur);
    }

    var z: std.Io.Writer.Allocating = try .initCapacity(gpa, 1 << 16);
    defer z.deinit();
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    var c: flate.Compress = try .init(&z.writer, window, .zlib, .best);
    try c.writer.writeAll(raw);
    try c.finish();

    var png: std.ArrayList(u8) = .empty;
    errdefer png.deinit(gpa);
    try png.appendSlice(gpa, "\x89PNG\r\n\x1a\n");
    var ihdr: [13]u8 = undefined;
    std.mem.writeInt(u32, ihdr[0..4], w, .big);
    std.mem.writeInt(u32, ihdr[4..8], h, .big);
    ihdr[8] = 8;
    ihdr[9] = if (ch == .rgb) 2 else 6;
    ihdr[10] = 0;
    ihdr[11] = 0;
    ihdr[12] = 0;
    try chunk(gpa, &png, "IHDR", &ihdr);
    try chunk(gpa, &png, "IDAT", z.written());
    try chunk(gpa, &png, "IEND", "");
    return png.toOwnedSlice(gpa);
}

fn filterRow(f: u8, cur: []const u8, prev: []const u8, bpp: usize, out: []u8) void {
    for (cur, 0..) |v, i| {
        const a: u8 = if (i >= bpp) cur[i - bpp] else 0;
        const b: u8 = prev[i];
        const cc: u8 = if (i >= bpp) prev[i - bpp] else 0;
        out[i] = switch (f) {
            0 => v,
            1 => v -% a,
            2 => v -% b,
            3 => v -% @as(u8, @intCast((@as(u16, a) + b) / 2)),
            else => v -% paeth(a, b, cc),
        };
    }
}

fn paeth(a: u8, b: u8, c: u8) u8 {
    const p: i16 = @as(i16, a) + b - c;
    const pa = @abs(p - a);
    const pb = @abs(p - b);
    const pc = @abs(p - c);
    if (pa <= pb and pa <= pc) return a;
    if (pb <= pc) return b;
    return c;
}

fn chunk(gpa: std.mem.Allocator, out: *std.ArrayList(u8), kind: *const [4]u8, data: []const u8) !void {
    var len: [4]u8 = undefined;
    std.mem.writeInt(u32, &len, @intCast(data.len), .big);
    try out.appendSlice(gpa, &len);
    try out.appendSlice(gpa, kind);
    try out.appendSlice(gpa, data);
    var crc = std.hash.Crc32.init();
    crc.update(kind);
    crc.update(data);
    var c: [4]u8 = undefined;
    std.mem.writeInt(u32, &c, crc.final(), .big);
    try out.appendSlice(gpa, &c);
}

test "round trip through std's inflate" {
    const gpa = std.testing.allocator;
    var px: [8 * 5 * 4]u8 = undefined;
    for (&px, 0..) |*b, i| b.* = @truncate(i *% 37);
    const png = try encode(gpa, &px, 8, 5, .rgba);
    defer gpa.free(png);
    try std.testing.expectEqualStrings("\x89PNG\r\n\x1a\n", png[0..8]);
    const idat_len = std.mem.readInt(u32, png[33..37], .big);
    try std.testing.expectEqualStrings("IDAT", png[37..41]);
    var in: std.Io.Reader = .fixed(png[41..][0..idat_len]);
    var buf: [flate.max_window_len]u8 = undefined;
    var d: flate.Decompress = .init(&in, .zlib, &buf);
    var raw: [5 * (1 + 8 * 4)]u8 = undefined;
    try d.reader.readSliceAll(&raw);
    // Undo the filters and compare.
    var prev: [32]u8 = @splat(0);
    for (0..5) |y| {
        const row = raw[y * 33 ..][0..33];
        var cur: [32]u8 = undefined;
        for (0..32) |i| {
            const a: u8 = if (i >= 4) cur[i - 4] else 0;
            const b = prev[i];
            const c: u8 = if (i >= 4) prev[i - 4] else 0;
            cur[i] = row[1 + i] +% switch (row[0]) {
                0 => 0,
                1 => a,
                2 => b,
                3 => @as(u8, @intCast((@as(u16, a) + b) / 2)),
                else => paeth(a, b, c),
            };
        }
        try std.testing.expectEqualSlices(u8, px[y * 32 ..][0..32], &cur);
        prev = cur;
    }
}
