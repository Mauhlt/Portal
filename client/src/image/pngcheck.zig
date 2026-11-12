//! Module "pngcheck": strict, allocation-free structural validation of PNG
//! files, and the size limits Portal enforces on inline images.
//!
//! Used on both sides of the wire, always BEFORE any decoding:
//!   * src/vt.zig, when a program in the session finishes transmitting an
//!     image (kitty graphics), so nothing malformed or oversized is stored
//!     or forwarded to viewers;
//!   * imgdec.zig, before handing bytes to the PNG decoder (the owner's
//!     Image package), so the decoder only ever sees well-formed chunk
//!     structure with a sane IHDR and a decode cost within budget.
//!
//! Also has `encodeStored`, a tiny PNG writer (stored deflate blocks, no
//! compression) for tests and test fixtures. Pure std, no allocation in the
//! checker, never panics on any input.

const std = @import("std");

/// Largest width or height accepted.
pub const max_side: u32 = 8192;
/// Largest width * height accepted.
pub const max_pixels: u64 = 32 * 1024 * 1024;
/// Largest PNG file accepted. The base64 payload of one image is capped at
/// 8 MiB, which decodes to 6 MiB.
pub const max_file_bytes: usize = 6 * 1024 * 1024;
/// Most chunks a file may have (a file of a million empty chunks is
/// structurally valid but only good for burning CPU).
pub const max_chunks: usize = 4096;

pub const signature = [8]u8{ 137, 80, 78, 71, 13, 10, 26, 10 };

pub const Error = error{
    NotPng,
    TooLarge,
    BadIhdr,
    BadChunk,
    BadCrc,
    BadOrder,
    MissingIdat,
    MissingIend,
    UnsupportedCritical,
    TooManyChunks,
};

pub const Info = struct {
    width: u32,
    height: u32,
    bit_depth: u8,
    color_type: u8,
    interlaced: bool,

    /// Bits per pixel in the filtered stream.
    pub fn bitsPerPixel(i: Info) u32 {
        const ch: u32 = switch (i.color_type) {
            0, 3 => 1,
            4 => 2,
            2 => 3,
            else => 4,
        };
        return ch * i.bit_depth;
    }

    /// Exact size of the inflated, filtered image data (all Adam7 passes
    /// for interlaced images): what a decoder must allocate for it.
    pub fn rawBytes(i: Info) u64 {
        const bpp: u64 = i.bitsPerPixel();
        if (!i.interlaced) return @as(u64, i.height) * ((@as(u64, i.width) * bpp + 7) / 8 + 1);
        const passes = [7][4]u8{
            .{ 0, 0, 8, 8 }, .{ 4, 0, 8, 8 }, .{ 0, 4, 4, 8 }, .{ 2, 0, 4, 4 },
            .{ 0, 2, 2, 4 }, .{ 1, 0, 2, 2 }, .{ 0, 1, 1, 2 },
        };
        var total: u64 = 0;
        for (passes) |p| {
            const pw: u64 = if (i.width > p[0]) (i.width - p[0] + p[2] - 1) / p[2] else 0;
            const ph: u64 = if (i.height > p[1]) (i.height - p[1] + p[3] - 1) / p[3] else 0;
            if (pw == 0) continue;
            total += ph * ((pw * bpp + 7) / 8 + 1);
        }
        return total;
    }

    pub fn pixels(i: Info) u64 {
        return @as(u64, i.width) * i.height;
    }
};

fn be32(b: []const u8) u32 {
    return std.mem.readInt(u32, b[0..4], .big);
}

fn crcOf(tag_and_data: []const u8) u32 {
    return std.hash.Crc32.hash(tag_and_data);
}

/// Signature and IHDR only (CRC checked, limits enforced).
pub fn header(data: []const u8) Error!Info {
    if (data.len < 8 or !std.mem.eql(u8, data[0..8], &signature)) return error.NotPng;
    if (data.len < 8 + 8 + 13 + 4) return error.BadIhdr;
    if (be32(data[8..12]) != 13 or !std.mem.eql(u8, data[12..16], "IHDR")) return error.BadIhdr;
    const d = data[16..29];
    if (crcOf(data[12..29]) != be32(data[29..33])) return error.BadCrc;
    const info: Info = .{
        .width = be32(d[0..4]),
        .height = be32(d[4..8]),
        .bit_depth = d[8],
        .color_type = d[9],
        .interlaced = d[12] == 1,
    };
    if (info.width == 0 or info.height == 0) return error.BadIhdr;
    if (d[10] != 0 or d[11] != 0 or d[12] > 1) return error.BadIhdr;
    const depth_ok = switch (info.color_type) {
        0 => switch (info.bit_depth) {
            1, 2, 4, 8, 16 => true,
            else => false,
        },
        3 => switch (info.bit_depth) {
            1, 2, 4, 8 => true,
            else => false,
        },
        2, 4, 6 => info.bit_depth == 8 or info.bit_depth == 16,
        else => false,
    };
    if (!depth_ok) return error.BadIhdr;
    if (info.width > max_side or info.height > max_side or info.pixels() > max_pixels) return error.TooLarge;
    return info;
}

/// Whole-file structure: IHDR first, every chunk inside the file with a
/// valid CRC and an alphabetic tag, PLTE (required for palette images)
/// before the IDATs, IDATs consecutive, IEND present; unknown critical
/// chunks rejected. Bytes after IEND are ignored, as decoders do.
pub fn validate(data: []const u8) Error!Info {
    if (data.len > max_file_bytes) return error.TooLarge;
    const info = try header(data);
    var i: usize = 33;
    var n: usize = 1;
    var plte = false;
    const Idat = enum { before, inside, after };
    var idat: Idat = .before;
    while (true) {
        if (data.len - i < 12) return error.MissingIend;
        n += 1;
        if (n > max_chunks) return error.TooManyChunks;
        const len = be32(data[i..][0..4]);
        if (len > data.len - i - 12) return error.BadChunk;
        const tag = data[i + 4 ..][0..4];
        if (crcOf(data[i + 4 ..][0 .. 4 + len]) != be32(data[i + 8 + len ..][0..4])) return error.BadCrc;
        for (tag) |c| if (!std.ascii.isAlphabetic(c)) return error.BadChunk;
        i += 12 + len;
        const is_idat = std.mem.eql(u8, tag, "IDAT");
        if (idat == .inside and !is_idat) idat = .after;
        if (is_idat) {
            if (idat == .after) return error.BadOrder;
            if (info.color_type == 3 and !plte) return error.BadOrder;
            idat = .inside;
        } else if (std.mem.eql(u8, tag, "IEND")) {
            if (idat == .before) return error.MissingIdat;
            return info;
        } else if (std.mem.eql(u8, tag, "PLTE")) {
            if (plte or idat != .before) return error.BadOrder;
            if (len == 0 or len % 3 != 0 or len > 768) return error.BadChunk;
            if (info.color_type == 0 or info.color_type == 4) return error.BadChunk;
            plte = true;
        } else if (std.mem.eql(u8, tag, "IHDR")) {
            return error.BadOrder;
        } else if (tag[0] & 0x20 == 0) {
            // Uppercase first letter: critical, and not one we know.
            return error.UnsupportedCritical;
        }
    }
}

// ---------------------------------------------------------------- encoder

fn putChunk(out: *std.ArrayList(u8), gpa: std.mem.Allocator, tag: *const [4]u8, body: []const u8) !void {
    var len: [4]u8 = undefined;
    std.mem.writeInt(u32, &len, @intCast(body.len), .big);
    try out.appendSlice(gpa, &len);
    const start = out.items.len;
    try out.appendSlice(gpa, tag);
    try out.appendSlice(gpa, body);
    var crc: [4]u8 = undefined;
    std.mem.writeInt(u32, &crc, crcOf(out.items[start..]), .big);
    try out.appendSlice(gpa, &crc);
}

/// Writes an 8-bit RGBA (color type 6) PNG with filter-0 rows and stored
/// (uncompressed) deflate blocks: valid, simple, no compressor needed.
/// `rgba.len` must be w * h * 4. Caller frees.
pub fn encodeStored(gpa: std.mem.Allocator, w: u32, h: u32, rgba: []const u8) ![]u8 {
    if (rgba.len != @as(usize, w) * h * 4) return error.BadLength;
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(gpa);
    const stride = @as(usize, w) * 4;
    for (0..h) |y| {
        try raw.append(gpa, 0);
        try raw.appendSlice(gpa, rgba[y * stride ..][0..stride]);
    }
    var z: std.ArrayList(u8) = .empty;
    defer z.deinit(gpa);
    try z.appendSlice(gpa, &.{ 0x78, 0x01 });
    var rest: []const u8 = raw.items;
    while (true) {
        const n = @min(rest.len, 65535);
        const last = n == rest.len;
        try z.append(gpa, @intFromBool(last));
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u16, hdr[0..2], @intCast(n), .little);
        std.mem.writeInt(u16, hdr[2..4], ~@as(u16, @intCast(n)), .little);
        try z.appendSlice(gpa, &hdr);
        try z.appendSlice(gpa, rest[0..n]);
        rest = rest[n..];
        if (last) break;
    }
    var adler: [4]u8 = undefined;
    std.mem.writeInt(u32, &adler, std.hash.Adler32.hash(raw.items), .big);
    try z.appendSlice(gpa, &adler);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, &signature);
    var ihdr: [13]u8 = undefined;
    std.mem.writeInt(u32, ihdr[0..4], w, .big);
    std.mem.writeInt(u32, ihdr[4..8], h, .big);
    ihdr[8..13].* = .{ 8, 6, 0, 0, 0 };
    try putChunk(&out, gpa, "IHDR", &ihdr);
    try putChunk(&out, gpa, "IDAT", z.items);
    try putChunk(&out, gpa, "IEND", "");
    return out.toOwnedSlice(gpa);
}

/// Test helper: a w x h gradient PNG (red across, green down, blue 0x80).
pub fn testImage(gpa: std.mem.Allocator, w: u32, h: u32) ![]u8 {
    const px = try gpa.alloc(u8, @as(usize, w) * h * 4);
    defer gpa.free(px);
    for (0..h) |y| for (0..w) |x| {
        const p = px[(y * w + x) * 4 ..][0..4];
        p.* = .{ @truncate(x * 255 / @max(w - 1, 1)), @truncate(y * 255 / @max(h - 1, 1)), 0x80, 0xFF };
    };
    return encodeStored(gpa, w, h, px);
}

/// Recomputes every chunk's CRC in place (tests: mutate, then make the CRCs
/// right so the mutation reaches the decoder).
pub fn fixCrcs(data: []u8) void {
    if (data.len < 8) return;
    var i: usize = 8;
    while (data.len - i >= 12) {
        const len = be32(data[i..][0..4]);
        if (len > data.len - i - 12) return;
        const crc = crcOf(data[i + 4 ..][0 .. 4 + len]);
        std.mem.writeInt(u32, data[i + 8 + len ..][0..4], crc, .big);
        i += 12 + len;
    }
}

const testing = std.testing;

test "encodeStored output validates" {
    const png = try testImage(testing.allocator, 13, 7);
    defer testing.allocator.free(png);
    const info = try validate(png);
    try testing.expectEqual(@as(u32, 13), info.width);
    try testing.expectEqual(@as(u32, 7), info.height);
    try testing.expectEqual(@as(u64, 7 * (13 * 4 + 1)), info.rawBytes());
}

test "header and structure rejections" {
    const gpa = testing.allocator;
    const png = try testImage(gpa, 4, 4);
    defer gpa.free(png);
    try testing.expectError(error.NotPng, validate("GIF89a"));
    try testing.expectError(error.NotPng, validate(""));
    try testing.expectError(error.BadIhdr, validate(png[0..20]));
    // Every truncation fails cleanly.
    for (0..png.len) |n| try testing.expect(std.meta.isError(validate(png[0..n])));

    const m = try gpa.dupe(u8, png);
    defer gpa.free(m);
    // Bad CRC.
    m[20] ^= 1;
    try testing.expectError(error.BadCrc, validate(m));
    // Huge IHDR, CRC fixed: rejected by limits before anything else.
    @memcpy(m, png);
    std.mem.writeInt(u32, m[16..20], 100000, .big);
    fixCrcs(m);
    try testing.expectError(error.TooLarge, validate(m));
    std.mem.writeInt(u32, m[16..20], 8192, .big);
    std.mem.writeInt(u32, m[20..24], 8192, .big); // 64 Mpx > 32 Mpx
    fixCrcs(m);
    try testing.expectError(error.TooLarge, validate(m));
    // Zero width.
    std.mem.writeInt(u32, m[16..20], 0, .big);
    fixCrcs(m);
    try testing.expectError(error.BadIhdr, validate(m));
    // Bad depth for the colour type.
    @memcpy(m, png);
    m[24] = 4; // RGBA at 4 bits
    fixCrcs(m);
    try testing.expectError(error.BadIhdr, validate(m));
    // Chunk length pointing past the end.
    @memcpy(m, png);
    std.mem.writeInt(u32, m[33..37], 0x7FFFFFFF, .big);
    try testing.expectError(error.BadChunk, validate(m));
}

test "random bytes never panic" {
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const rand = prng.random();
    var buf: [512]u8 = undefined;
    const gpa = testing.allocator;
    const png = try testImage(gpa, 9, 5);
    defer gpa.free(png);
    for (0..20000) |_| {
        const n = rand.uintAtMost(usize, buf.len);
        if (rand.boolean() and png.len <= buf.len) {
            @memcpy(buf[0..png.len], png);
            for (0..rand.uintAtMost(usize, 4)) |_| buf[rand.uintLessThan(usize, png.len)] = rand.int(u8);
            if (rand.boolean()) fixCrcs(buf[0..png.len]);
            _ = validate(buf[0..@min(n, png.len)]) catch {};
        } else {
            rand.bytes(buf[0..n]);
            if (n >= 8) @memcpy(buf[0..8], &signature);
            _ = validate(buf[0..n]) catch {};
        }
    }
}
