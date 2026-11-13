//! QR code encoder (ISO/IEC 18004), just enough for the desk's pairing
//! code: byte mode, error correction level M, versions 1 to 10 (up to 213
//! bytes), automatic mask choice. No allocation: a `Code` holds up to a
//! version 10 symbol (57 x 57 modules).
//!
//! Structure after Project Nayuki's QR Code generator (MIT): the function
//! patterns, the zig-zag data placement, Reed-Solomon over GF(2^8) with
//! 0x11D, and the four mask penalty rules.
//!
//!     var code: qr.Code = undefined;
//!     try code.encode("portal-pair 1 10.8.0.1:8420 3A5F...");
//!     code.size, code.get(x, y)    // true = dark

const std = @import("std");

pub const max_version = 10;
pub const max_size = 17 + 4 * max_version;

/// Level M per version (index 1..10): ECC codewords per block, blocks.
const ecc_per_block = [_]u8{ 0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26 };
const num_blocks = [_]u8{ 0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5 };
/// Format bits for level M.
const ecl_bits: u32 = 0;

pub const Error = error{TooLong};

pub const Code = struct {
    version: u8 = 1,
    size: u8 = 21,
    /// The mask pattern chosen (0..7).
    mask: u3 = 0,
    modules: [max_size][max_size]bool = undefined,
    function: [max_size][max_size]bool = undefined,

    /// Dark module at column x, row y.
    pub fn get(c: *const Code, x: usize, y: usize) bool {
        return c.modules[y][x];
    }

    /// Encodes `data` in byte mode at level M, the smallest version that fits.
    pub fn encode(c: *Code, data: []const u8) Error!void {
        var ver: u8 = 1;
        while (true) : (ver += 1) {
            if (ver > max_version) return error.TooLong;
            const cc_bits: usize = if (ver <= 9) 8 else 16;
            if (data.len < (@as(usize, 1) << @intCast(cc_bits)) and 4 + cc_bits + data.len * 8 <= dataCodewords(ver) * 8) break;
        }
        c.version = ver;
        c.size = 17 + 4 * ver;

        // Bit stream: mode 0100, count, bytes, terminator, pad.
        var buf: [rawCodewords(max_version)]u8 = @splat(0);
        const cap = dataCodewords(ver);
        var bits: usize = 0;
        const B = struct {
            fn put(b: []u8, at: *usize, val: u32, n: u5) void {
                var i: u5 = n;
                while (i > 0) {
                    i -= 1;
                    if ((val >> i) & 1 != 0) b[at.* >> 3] |= @as(u8, 0x80) >> @intCast(at.* & 7);
                    at.* += 1;
                }
            }
        };
        B.put(&buf, &bits, 0b0100, 4);
        B.put(&buf, &bits, @intCast(data.len), if (ver <= 9) 8 else 16);
        for (data) |d| B.put(&buf, &bits, d, 8);
        B.put(&buf, &bits, 0, @intCast(@min(4, cap * 8 - bits)));
        bits = (bits + 7) / 8 * 8;
        var pad: u8 = 0xEC;
        while (bits < cap * 8) : (bits += 8) {
            buf[bits / 8] = pad;
            pad ^= 0xEC ^ 0x11;
        }

        var all: [rawCodewords(max_version)]u8 = undefined;
        const n = interleave(ver, buf[0..cap], &all);

        c.drawFunctionPatterns();
        c.drawCodewords(all[0..n]);
        // Mask with the lowest penalty.
        var best: u3 = 0;
        var best_penalty: u32 = std.math.maxInt(u32);
        var m: u4 = 0;
        while (m < 8) : (m += 1) {
            const mask: u3 = @intCast(m);
            c.applyMask(mask);
            c.drawFormatBits(mask);
            const p = c.penalty();
            if (p < best_penalty) {
                best = mask;
                best_penalty = p;
            }
            c.applyMask(mask); // XOR again: undo
        }
        c.applyMask(best);
        c.drawFormatBits(best);
        c.mask = best;
    }

    fn set(c: *Code, x: usize, y: usize, dark: bool) void {
        c.modules[y][x] = dark;
        c.function[y][x] = true;
    }

    fn drawFunctionPatterns(c: *Code) void {
        const s = c.size;
        for (0..s) |y| for (0..s) |x| {
            c.modules[y][x] = false;
            c.function[y][x] = false;
        };
        for (0..s) |i| {
            c.set(6, i, i % 2 == 0);
            c.set(i, 6, i % 2 == 0);
        }
        c.finder(3, 3);
        c.finder(s - 4, 3);
        c.finder(3, s - 4);
        var pos: [7]u8 = undefined;
        const align_pos = alignmentPositions(c.version, &pos);
        for (align_pos, 0..) |ay, i| for (align_pos, 0..) |ax, j| {
            const corner = (i == 0 and j == 0) or (i == 0 and j == align_pos.len - 1) or (i == align_pos.len - 1 and j == 0);
            if (!corner) c.alignment(ax, ay);
        };
        c.drawFormatBits(0); // reserve; overwritten after masking
        c.drawVersion();
    }

    fn finder(c: *Code, cx: usize, cy: usize) void {
        var dy: i32 = -4;
        while (dy <= 4) : (dy += 1) {
            var dx: i32 = -4;
            while (dx <= 4) : (dx += 1) {
                const x = @as(i32, @intCast(cx)) + dx;
                const y = @as(i32, @intCast(cy)) + dy;
                if (x < 0 or y < 0 or x >= c.size or y >= c.size) continue;
                const d = @max(@abs(dx), @abs(dy));
                c.set(@intCast(x), @intCast(y), d != 2 and d != 4);
            }
        }
    }

    fn alignment(c: *Code, cx: usize, cy: usize) void {
        var dy: i32 = -2;
        while (dy <= 2) : (dy += 1) {
            var dx: i32 = -2;
            while (dx <= 2) : (dx += 1) {
                const x: usize = @intCast(@as(i32, @intCast(cx)) + dx);
                const y: usize = @intCast(@as(i32, @intCast(cy)) + dy);
                c.set(x, y, @max(@abs(dx), @abs(dy)) != 1);
            }
        }
    }

    fn drawFormatBits(c: *Code, mask: u3) void {
        const bits = formatBits(mask);
        const s: usize = c.size;
        const bit = struct {
            fn f(v: u32, i: u5) bool {
                return (v >> i) & 1 != 0;
            }
        }.f;
        for (0..6) |i| c.set(8, i, bit(bits, @intCast(i)));
        c.set(8, 7, bit(bits, 6));
        c.set(8, 8, bit(bits, 7));
        c.set(7, 8, bit(bits, 8));
        for (9..15) |i| c.set(14 - i, 8, bit(bits, @intCast(i)));
        for (0..8) |i| c.set(s - 1 - i, 8, bit(bits, @intCast(i)));
        for (8..15) |i| c.set(8, s - 15 + i, bit(bits, @intCast(i)));
        c.set(8, s - 8, true); // the dark module
    }

    fn drawVersion(c: *Code) void {
        if (c.version < 7) return;
        var rem: u32 = c.version;
        for (0..12) |_| rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
        const bits = (@as(u32, c.version) << 12) | rem;
        for (0..18) |i| {
            const dark = (bits >> @intCast(i)) & 1 != 0;
            const a = c.size - 11 + i % 3;
            const b = i / 3;
            c.set(a, b, dark);
            c.set(b, a, dark);
        }
    }

    fn drawCodewords(c: *Code, data: []const u8) void {
        const s: usize = c.size;
        var i: usize = 0;
        var right: isize = @intCast(s - 1);
        while (right >= 1) : (right -= 2) {
            if (right == 6) right = 5;
            const r: usize = @intCast(right);
            for (0..s) |vert| for (0..2) |j| {
                const x = r - j;
                const upward = ((r + 1) & 2) == 0;
                const y = if (upward) s - 1 - vert else vert;
                if (!c.function[y][x] and i < data.len * 8) {
                    c.modules[y][x] = (data[i >> 3] >> @intCast(7 - (i & 7))) & 1 != 0;
                    i += 1;
                }
            };
        }
    }

    fn applyMask(c: *Code, mask: u3) void {
        const s: usize = c.size;
        for (0..s) |y| for (0..s) |x| {
            if (c.function[y][x]) continue;
            const inv = switch (mask) {
                0 => (x + y) % 2 == 0,
                1 => y % 2 == 0,
                2 => x % 3 == 0,
                3 => (x + y) % 3 == 0,
                4 => (x / 3 + y / 2) % 2 == 0,
                5 => x * y % 2 + x * y % 3 == 0,
                6 => (x * y % 2 + x * y % 3) % 2 == 0,
                7 => ((x + y) % 2 + x * y % 3) % 2 == 0,
            };
            if (inv) c.modules[y][x] = !c.modules[y][x];
        };
    }

    /// The four penalty rules of the standard (lower is better).
    fn penalty(c: *const Code) u32 {
        const s: usize = c.size;
        var total: u32 = 0;
        // Rule 1: runs of 5+ same-colour modules in rows and columns.
        // Rule 3: 1:1:3:1:1 finder-like patterns with 4 light modules on
        // one side.
        for (0..2) |dir| for (0..s) |a| {
            var run: u32 = 0;
            var prev = false;
            for (0..s) |b| {
                const v = if (dir == 0) c.modules[a][b] else c.modules[b][a];
                if (b > 0 and v == prev) {
                    run += 1;
                    if (run == 5) total += 3 else if (run > 5) total += 1;
                } else run = 1;
                prev = v;
                if (b + 1 >= 11) {
                    const start = b + 1 - 11;
                    var pat: u11 = 0;
                    for (0..11) |k| {
                        const m = if (dir == 0) c.modules[a][start + k] else c.modules[start + k][a];
                        pat = (pat << 1) | @intFromBool(m);
                    }
                    if (pat == 0b00001011101 or pat == 0b10111010000) total += 40;
                }
            }
        };
        // Rule 2: 2x2 blocks of one colour.
        for (0..s - 1) |y| for (0..s - 1) |x| {
            const v = c.modules[y][x];
            if (v == c.modules[y][x + 1] and v == c.modules[y + 1][x] and v == c.modules[y + 1][x + 1]) total += 3;
        };
        // Rule 4: dark proportion away from 50%.
        var dark: u32 = 0;
        for (0..s) |y| for (0..s) |x| {
            if (c.modules[y][x]) dark += 1;
        };
        const n: u32 = @intCast(s * s);
        const k = (@max(dark * 20, n * 10) - @min(dark * 20, n * 10) + n - 1) / n; // ceil(|20d - 10n| / n)
        total += (k -| 1) * 10;
        return total;
    }
};

pub fn formatBits(mask: u3) u32 {
    const data: u32 = (ecl_bits << 3) | mask;
    var rem = data;
    for (0..10) |_| rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    return ((data << 10) | rem) ^ 0x5412;
}

/// Modules available for data and ECC, in whole codewords.
pub fn rawCodewords(ver: u8) usize {
    const v: usize = ver;
    var r = (16 * v + 128) * v + 64;
    if (v >= 2) {
        const n = v / 7 + 2;
        r -= (25 * n - 10) * n - 55;
        if (v >= 7) r -= 36;
    }
    return r / 8;
}

pub fn dataCodewords(ver: u8) usize {
    return rawCodewords(ver) - @as(usize, ecc_per_block[ver]) * num_blocks[ver];
}

fn alignmentPositions(ver: u8, out: *[7]u8) []const u8 {
    if (ver == 1) return out[0..0];
    const n: usize = ver / 7 + 2;
    const step: usize = (@as(usize, ver) * 8 + n * 3 + 5) / (n * 4 - 4) * 2;
    out[0] = 6;
    var p: usize = 17 + 4 * @as(usize, ver) - 7;
    var i = n - 1;
    while (i >= 1) : (i -= 1) {
        out[i] = @intCast(p);
        p -= step;
    }
    return out[0..n];
}

/// Splits `data` into blocks, appends each block's ECC and interleaves.
fn interleave(ver: u8, data: []const u8, out: []u8) usize {
    const nb: usize = num_blocks[ver];
    const ecc: usize = ecc_per_block[ver];
    const raw = rawCodewords(ver);
    const short_count = nb - raw % nb;
    const short_len = raw / nb; // data + ecc of a short block
    var blocks: [5][rawCodewords(max_version)]u8 = undefined;
    var lens: [5]usize = undefined;
    var div: [30]u8 = undefined;
    rsDivisor(div[0..ecc]);
    var k: usize = 0;
    for (0..nb) |i| {
        const dlen = short_len - ecc + @intFromBool(i >= short_count);
        @memcpy(blocks[i][0..dlen], data[k..][0..dlen]);
        k += dlen;
        var rem: [30]u8 = undefined;
        rsRemainder(data[k - dlen .. k], div[0..ecc], rem[0..ecc]);
        // Short blocks get a gap so the columns line up.
        var len = dlen;
        if (i < short_count) {
            blocks[i][len] = 0;
            len += 1;
        }
        @memcpy(blocks[i][len..][0..ecc], rem[0..ecc]);
        lens[i] = len + ecc;
    }
    var n: usize = 0;
    for (0..lens[0]) |col| for (0..nb) |j| {
        if (col != short_len - ecc or j >= short_count) {
            out[n] = blocks[j][col];
            n += 1;
        }
    };
    return n;
}

fn gfMul(x: u8, y: u8) u8 {
    var z: u16 = 0;
    var i: u4 = 8;
    while (i > 0) {
        i -= 1;
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        if ((y >> @intCast(i)) & 1 != 0) z ^= x;
    }
    return @intCast(z & 0xFF);
}

fn rsDivisor(out: []u8) void {
    @memset(out, 0);
    out[out.len - 1] = 1;
    var root: u8 = 1;
    for (0..out.len) |_| {
        for (0..out.len) |j| {
            out[j] = gfMul(out[j], root);
            if (j + 1 < out.len) out[j] ^= out[j + 1];
        }
        root = gfMul(root, 2);
    }
}

fn rsRemainder(data: []const u8, div: []const u8, out: []u8) void {
    @memset(out, 0);
    for (data) |b| {
        const factor = b ^ out[0];
        std.mem.copyForwards(u8, out[0 .. out.len - 1], out[1..]);
        out[out.len - 1] = 0;
        for (out, div) |*o, d| o.* ^= gfMul(d, factor);
    }
}

test "Reed-Solomon: HELLO WORLD 1-M (the classic worked example)" {
    const data = [_]u8{ 32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17 };
    var div: [10]u8 = undefined;
    rsDivisor(&div);
    var ecc: [10]u8 = undefined;
    rsRemainder(&data, &div, &ecc);
    try std.testing.expectEqualSlices(u8, &.{ 196, 35, 39, 119, 235, 215, 231, 226, 93, 23 }, &ecc);
}

test "format bits and capacities match the standard's tables" {
    // Level M, mask 0: 101010000010010.
    try std.testing.expectEqual(@as(u32, 0b101010000010010), formatBits(0));
    // Level M, mask 5: 100000011001110; mask 7: 100101010100000.
    try std.testing.expectEqual(@as(u32, 0b100000011001110), formatBits(5));
    try std.testing.expectEqual(@as(u32, 0b100101010100000), formatBits(7));
    // Data codewords at level M for versions 1..10.
    const want = [_]usize{ 16, 28, 44, 64, 86, 108, 124, 154, 182, 216 };
    for (want, 1..) |w, v| try std.testing.expectEqual(w, dataCodewords(@intCast(v)));
    var pos: [7]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &.{ 6, 18 }, alignmentPositions(2, &pos));
    try std.testing.expectEqualSlices(u8, &.{ 6, 22, 38 }, alignmentPositions(7, &pos));
    try std.testing.expectEqualSlices(u8, &.{ 6, 28, 50 }, alignmentPositions(10, &pos));
}

test "encode: fixed patterns, version choice and format copies agree" {
    var c: Code = undefined;
    try c.encode("portal-pair 1 10.8.0.1:8420 00070E151C232A31383F464D545B626970777E858C939AA1A8AFB6BDC4CBD2D9");
    // 92 bytes need version 6 at level M (version 5 holds 84).
    try std.testing.expectEqual(@as(u8, 6), c.version);
    try std.testing.expectEqual(@as(u8, 41), c.size);
    // Finder centres dark, ring light, timing alternates, dark module.
    try std.testing.expect(c.get(3, 3) and c.get(c.size - 4, 3) and c.get(3, c.size - 4));
    try std.testing.expect(!c.get(1, 1) and c.get(0, 0));
    for (8..c.size - 8) |i| try std.testing.expectEqual(i % 2 == 0, c.get(i, 6));
    try std.testing.expect(c.get(8, c.size - 8));
    // The two copies of the format information carry the same 15 bits.
    var a: u32 = 0;
    var b: u32 = 0;
    const s: usize = c.size;
    var i: usize = 15;
    while (i > 0) {
        i -= 1;
        const first = if (i < 6) c.get(8, i) else if (i == 6) c.get(8, 7) else if (i == 7) c.get(8, 8) else if (i == 8) c.get(7, 8) else c.get(14 - i, 8);
        const second = if (i < 8) c.get(s - 1 - i, 8) else c.get(8, s - 15 + i);
        a = (a << 1) | @intFromBool(first);
        b = (b << 1) | @intFromBool(second);
    }
    try std.testing.expectEqual(a, b);
    var found = false;
    for (0..8) |m| {
        if (formatBits(@intCast(m)) == a) found = true;
    }
    try std.testing.expect(found);
    const big: [300]u8 = @splat('x');
    try std.testing.expectError(error.TooLong, c.encode(&big));
    try c.encode("hi");
    try std.testing.expectEqual(@as(u8, 1), c.version);
}
