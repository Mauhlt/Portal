//! Module "imgdec": PNG bytes -> RGBA8 pixels for drawing inline images,
//! in every client (the local window, `portal connect` and the iPhone app
//! via the view module).
//!
//! The decoder is the owner's Image package (module "Image"; see
//! build.zig.zon), used read-only. It is wrapped defensively:
//!   1. `imgcheck.validate` first (Image.check with Portal's limits):
//!      signature, IHDR limits (8192 per side,
//!      32 Mpx), every chunk's bounds and CRC, chunk order, IEND.
//!   2. The decode's memory cost is computed from the IHDR and checked
//!      against the caller's budget before anything is allocated.
//!   3. The decoder runs on a `Bounded` allocator capped at that budget, so
//!      even a wrong estimate can't make it allocate more.
//! Inflate output is bounded by construction (the decoder inflates into a
//! buffer sized from the IHDR), so a zlib bomb costs at most that buffer.
//!
//! The result is converted to straight-alpha RGBA8 and box-downscaled so
//! neither side exceeds `Options.max_side`.

const std = @import("std");
const Image = @import("Image");
/// The checks imgdec runs first, for callers that want header info.
pub const imgcheck = @import("imgcheck");

pub const Error = error{ Invalid, TooLarge, OutOfMemory };

pub const Rgba = struct {
    w: u32,
    h: u32,
    /// w * h * 4 bytes, straight (not premultiplied) alpha.
    px: []u8,

    pub fn deinit(r: *Rgba, gpa: std.mem.Allocator) void {
        gpa.free(r.px);
        r.* = .{ .w = 0, .h = 0, .px = &.{} };
    }
};

pub const Options = struct {
    /// Most bytes the whole decode may allocate (decoder scratch, its
    /// output, and our RGBA copy).
    budget: usize = 288 << 20,
    /// The result is downscaled to fit max_side x max_side.
    max_side: u32 = 2048,
};

/// An allocator that refuses to go past `limit` bytes outstanding.
pub const Bounded = struct {
    child: std.mem.Allocator,
    limit: usize,
    used: usize = 0,
    peak: usize = 0,

    pub fn allocator(b: *Bounded) std.mem.Allocator {
        return .{ .ptr = b, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };
    const Alignment = std.mem.Alignment;

    fn fits(b: *Bounded, extra: usize) bool {
        return extra <= b.limit - b.used;
    }

    fn note(b: *Bounded) void {
        b.peak = @max(b.peak, b.used);
    }

    fn alloc(ctx: *anyopaque, len: usize, a: Alignment, ra: usize) ?[*]u8 {
        const b: *Bounded = @ptrCast(@alignCast(ctx));
        if (!b.fits(len)) return null;
        const p = b.child.rawAlloc(len, a, ra) orelse return null;
        b.used += len;
        b.note();
        return p;
    }

    fn resize(ctx: *anyopaque, mem: []u8, a: Alignment, new_len: usize, ra: usize) bool {
        const b: *Bounded = @ptrCast(@alignCast(ctx));
        if (new_len > mem.len and !b.fits(new_len - mem.len)) return false;
        if (!b.child.rawResize(mem, a, new_len, ra)) return false;
        b.used = b.used - mem.len + new_len;
        b.note();
        return true;
    }

    fn remap(ctx: *anyopaque, mem: []u8, a: Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const b: *Bounded = @ptrCast(@alignCast(ctx));
        if (new_len > mem.len and !b.fits(new_len - mem.len)) return null;
        const p = b.child.rawRemap(mem, a, new_len, ra) orelse return null;
        b.used = b.used - mem.len + new_len;
        b.note();
        return p;
    }

    fn free(ctx: *anyopaque, mem: []u8, a: Alignment, ra: usize) void {
        const b: *Bounded = @ptrCast(@alignCast(ctx));
        b.child.rawFree(mem, a, ra);
        b.used -|= mem.len;
    }
};

/// Output size for a w x h image fitted into max_side x max_side.
pub fn fitted(w: u32, h: u32, max_side: u32) [2]u32 {
    const m = @max(max_side, 1);
    if (w <= m and h <= m) return .{ @max(w, 1), @max(h, 1) };
    if (w >= h) return .{ m, @intCast(@max(1, (@as(u64, h) * m + w / 2) / w)) };
    return .{ @intCast(@max(1, (@as(u64, w) * m + h / 2) / h)), m };
}

/// Upper bound of what `decode` allocates for an image `info` describes.
pub fn cost(info: imgcheck.Info, max_side: u32) u64 {
    const out_wh = fitted(info.width, info.height, max_side);
    const rgba = @as(u64, out_wh[0]) * out_wh[1] * 4;
    const sums = @as(u64, out_wh[0]) * 4 * 8; // one row of box-filter accumulators
    // The decoder's own (Image.check's bound: inflated rows, concatenated
    // IDATs, a zero row, its output) + our RGBA + accumulators + slack.
    return info.decode_bytes + rgba + sums + (64 << 10);
}

/// Decodes `png` to RGBA8 (caller frees `px` with `gpa`). Never panics on
/// any input; returns Invalid for anything the checker or decoder rejects.
pub fn decode(gpa: std.mem.Allocator, png: []const u8, opts: Options) Error!Rgba {
    const info = imgcheck.validate(png) catch |e| return if (imgcheck.tooLarge(e)) error.TooLarge else error.Invalid;
    if (cost(info, opts.max_side) > opts.budget) return error.TooLarge;
    var bounded: Bounded = .{ .child = gpa, .limit = opts.budget };
    const ba = bounded.allocator();

    const inf = Image.PNG.info(png) catch return error.Invalid;
    if (inf.width != info.width or inf.height != info.height) return error.Invalid;
    const bpp: usize = switch (inf.tag) {
        .g => 1,
        .ga, .g16 => 2,
        .rgb => 3,
        .rgba => 4,
        else => return error.Invalid, // never produced by PNG
    };
    const decoded = ba.alloc(u8, @as(usize, inf.width) * inf.height * bpp) catch return error.OutOfMemory;
    defer ba.free(decoded);
    {
        var arena: std.heap.ArenaAllocator = .init(ba);
        defer arena.deinit();
        Image.PNG.decodeInto(arena.allocator(), png, inf, decoded) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Invalid,
        };
    }
    const src: Src = .{ .w = inf.width, .h = inf.height, .bpp = bpp, .wide = inf.tag == .g16, .data = decoded };
    const wh = fitted(inf.width, inf.height, opts.max_side);
    const out = ba.alloc(u8, @as(usize, wh[0]) * wh[1] * 4) catch return error.OutOfMemory;
    // `out` is returned to the caller, who frees it with `gpa`: it must
    // come from `gpa` itself. Bounded only counts; the memory is gpa's.
    boxScale(src, out, wh[0], wh[1], ba) catch {
        ba.free(out);
        return error.OutOfMemory;
    };
    return .{ .w = wh[0], .h = wh[1], .px = out };
}

/// A decoded image in one of the decoder's layouts.
const Src = struct {
    w: u32,
    h: u32,
    bpp: usize,
    /// .g16: one native-endian u16 per pixel.
    wide: bool,
    data: []const u8,

    fn get(s: Src, x: usize, y: usize) [4]u8 {
        const p = s.data[(y * s.w + x) * s.bpp ..][0..s.bpp];
        if (s.wide) {
            const v = std.mem.readInt(u16, p[0..2], @import("builtin").cpu.arch.endian());
            const g: u8 = @intCast(v >> 8);
            return .{ g, g, g, 255 };
        }
        return switch (s.bpp) {
            1 => .{ p[0], p[0], p[0], 255 },
            2 => .{ p[0], p[0], p[0], p[1] },
            3 => .{ p[0], p[1], p[2], 255 },
            else => .{ p[0], p[1], p[2], p[3] },
        };
    }
};

/// Area-average (box filter) scaling into an `ow x oh` RGBA8 buffer, with
/// colour weighted by alpha so transparent pixels don't darken edges.
/// Upscaling degenerates to nearest neighbour.
fn boxScale(s: Src, out: []u8, ow: u32, oh: u32, scratch: std.mem.Allocator) !void {
    const sums = try scratch.alloc(u64, @as(usize, ow) * 4);
    defer scratch.free(sums);
    for (0..oh) |oy| {
        const y0 = oy * s.h / oh;
        const y1 = @max(y0 + 1, (oy + 1) * s.h / oh);
        @memset(sums, 0);
        for (0..ow) |ox| {
            const x0 = ox * s.w / ow;
            const x1 = @max(x0 + 1, (ox + 1) * s.w / ow);
            const acc = sums[ox * 4 ..][0..4];
            for (y0..y1) |y| for (x0..x1) |x| {
                const p = s.get(x, y);
                const a: u64 = p[3];
                acc[0] += @as(u64, p[0]) * a;
                acc[1] += @as(u64, p[1]) * a;
                acc[2] += @as(u64, p[2]) * a;
                acc[3] += a;
            };
            const n: u64 = (y1 - y0) * (x1 - x0);
            const o = out[(oy * ow + ox) * 4 ..][0..4];
            if (acc[3] == 0) {
                o.* = .{ 0, 0, 0, 0 };
            } else {
                o.* = .{
                    @intCast(acc[0] / acc[3]),
                    @intCast(acc[1] / acc[3]),
                    @intCast(acc[2] / acc[3]),
                    @intCast(acc[3] / n),
                };
            }
        }
    }
}

/// Scales an RGBA8 image to exactly `w x h` (display size). Caller frees.
pub fn scale(gpa: std.mem.Allocator, src: Rgba, w: u32, h: u32) error{OutOfMemory}!Rgba {
    const ow = @max(w, 1);
    const oh = @max(h, 1);
    const out = try gpa.alloc(u8, @as(usize, ow) * oh * 4);
    errdefer gpa.free(out);
    if (src.w == 0 or src.h == 0 or src.px.len < @as(usize, src.w) * src.h * 4) {
        @memset(out, 0);
    } else {
        try boxScale(.{ .w = src.w, .h = src.h, .bpp = 4, .wide = false, .data = src.px }, out, ow, oh, gpa);
    }
    return .{ .w = ow, .h = oh, .px = out };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "decode a stored PNG exactly" {
    const gpa = testing.allocator;
    const png = try imgcheck.testImage(gpa, 31, 17);
    defer gpa.free(png);
    var img = try decode(gpa, png, .{});
    defer img.deinit(gpa);
    try testing.expectEqual(@as(u32, 31), img.w);
    try testing.expectEqual(@as(u32, 17), img.h);
    // Pixel (30, 16): red 255, green 255, blue 0x80.
    const p = img.px[(16 * 31 + 30) * 4 ..][0..4];
    try testing.expectEqualSlices(u8, &.{ 255, 255, 0x80, 255 }, p);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0x80, 255 }, img.px[0..4]);
}

test "downscale to max_side and scale()" {
    const gpa = testing.allocator;
    const png = try imgcheck.testImage(gpa, 300, 100);
    defer gpa.free(png);
    var img = try decode(gpa, png, .{ .max_side = 60 });
    defer img.deinit(gpa);
    try testing.expectEqual(@as(u32, 60), img.w);
    try testing.expectEqual(@as(u32, 20), img.h);
    var s = try scale(gpa, img, 7, 3);
    defer s.deinit(gpa);
    try testing.expectEqual(@as(usize, 7 * 3 * 4), s.px.len);
    var up = try scale(gpa, img, 120, 40);
    defer up.deinit(gpa);
}

test "decoder output matches the Image package's own encoder" {
    const gpa = testing.allocator;
    // Encode with the owner's PNG encoder (adaptive filters, real deflate),
    // decode through our wrapper.
    const w = 23;
    const h = 11;
    var px: [w * h * 4]u8 = undefined;
    for (0..w * h) |i| px[i * 4 ..][0..4].* = .{ @truncate(i * 7), @truncate(i * 13), @truncate(i), 255 };
    const owned = try gpa.dupe(u8, &px);
    const img: Image = .{ .width = w, .height = h, .pixels = .fromBytes(.rgba, owned), .fmt = .r8g8b8a8_srgb };
    defer img.deinit(gpa);
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try img.encode(.png, &aw.writer, gpa);
    var out = try decode(gpa, aw.written(), .{});
    defer out.deinit(gpa);
    try testing.expectEqualSlices(u8, &px, out.px);
}

test "budget and limits refuse before decoding" {
    const gpa = testing.allocator;
    const png = try imgcheck.testImage(gpa, 64, 64);
    defer gpa.free(png);
    try testing.expectError(error.TooLarge, decode(gpa, png, .{ .budget = 1000 }));
    // Huge IHDR with fixed CRC: refused by imgcheck's limits.
    const m = try gpa.dupe(u8, png);
    defer gpa.free(m);
    std.mem.writeInt(u32, m[16..20], 8192, .big);
    std.mem.writeInt(u32, m[20..24], 8192, .big);
    imgcheck.fixCrcs(m);
    try testing.expectError(error.TooLarge, decode(gpa, m, .{}));
    // Large-but-legal IHDR (4096 x 4096) with a tiny IDAT: the cost check
    // refuses it under a small budget without allocating.
    std.mem.writeInt(u32, m[16..20], 4096, .big);
    std.mem.writeInt(u32, m[20..24], 4096, .big);
    imgcheck.fixCrcs(m);
    try testing.expectError(error.TooLarge, decode(gpa, m, .{ .budget = 64 << 20 }));
}

/// Builds a zlib stream of `n` zero bytes (fixed Huffman, long matches):
/// a few hundred bytes that inflate to megabytes.
fn zlibZeros(gpa: std.mem.Allocator, n: usize) ![]u8 {
    var aw: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer aw.deinit();
    const hist = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(hist);
    var c: std.compress.flate.Compress = try .init(&aw.writer, hist, .zlib, .best);
    var zeros: [4096]u8 = @splat(0);
    var left = n;
    while (left > 0) {
        const k = @min(left, zeros.len);
        try c.writer.writeAll(zeros[0..k]);
        left -= k;
    }
    try c.finish();
    _ = &zeros;
    return aw.toOwnedSlice();
}

fn pngWith(gpa: std.mem.Allocator, w: u32, h: u32, depth: u8, ctype: u8, interlace: u8, idat: []const u8, plte: ?[]const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, &imgcheck.signature);
    var ihdr: [13]u8 = undefined;
    std.mem.writeInt(u32, ihdr[0..4], w, .big);
    std.mem.writeInt(u32, ihdr[4..8], h, .big);
    ihdr[8..13].* = .{ depth, ctype, 0, 0, interlace };
    const chunks = [_]struct { t: *const [4]u8, d: ?[]const u8 }{
        .{ .t = "IHDR", .d = &ihdr }, .{ .t = "PLTE", .d = plte }, .{ .t = "IDAT", .d = idat }, .{ .t = "IEND", .d = "" },
    };
    for (chunks) |c| {
        const d = c.d orelse continue;
        var len: [4]u8 = undefined;
        std.mem.writeInt(u32, &len, @intCast(d.len), .big);
        try out.appendSlice(gpa, &len);
        try out.appendSlice(gpa, c.t);
        try out.appendSlice(gpa, d);
        try out.appendSlice(gpa, &[4]u8{ 0, 0, 0, 0 });
    }
    const s = try out.toOwnedSlice(gpa);
    imgcheck.fixCrcs(s);
    return s;
}

test "zlib bomb: output bounded by the IHDR, decode stays in budget" {
    const gpa = testing.allocator;
    // 2048 x 2048 RGBA = 16 MiB of pixels from ~16 KiB of IDAT, but claims to
    // contain 4x more data than the image needs: inflate must stop at the
    // image size.
    const w = 2048;
    const h = 2048;
    const z = try zlibZeros(gpa, @as(usize, h) * (w * 4 + 1) * 4);
    defer gpa.free(z);
    const png = try pngWith(gpa, w, h, 8, 6, 0, z, null);
    defer gpa.free(png);
    const budget: usize = @intCast(cost(try imgcheck.validate(png), 2048));
    var img = decode(gpa, png, .{ .budget = budget }) catch |e| {
        // Either outcome is fine as long as it is bounded and clean.
        try testing.expect(e == error.Invalid or e == error.TooLarge);
        return;
    };
    defer img.deinit(gpa);
    try testing.expectEqual(@as(u32, 2048), img.w);
}

test "fuzz: mutated, truncated, split and odd-format PNGs never panic" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x1a2b3c);
    const rand = prng.random();

    // Seeds: our stored encoder, the Image encoder (real deflate, filters),
    // palette / gray / 16-bit / interlaced headers over random IDAT data.
    var seeds: std.ArrayList([]u8) = .empty;
    defer {
        for (seeds.items) |s| gpa.free(s);
        seeds.deinit(gpa);
    }
    try seeds.append(gpa, try imgcheck.testImage(gpa, 17, 9));
    {
        var px: [40 * 20 * 4]u8 = undefined;
        rand.bytes(&px);
        const img: Image = .{ .width = 40, .height = 20, .pixels = .fromBytes(.rgba, try gpa.dupe(u8, &px)), .fmt = .r8g8b8a8_srgb };
        defer img.deinit(gpa);
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        try img.encode(.png, &aw.writer, gpa);
        try seeds.append(gpa, try aw.toOwnedSlice());
    }
    const layouts = [_][3]u8{
        .{ 1, 0, 0 }, .{ 2, 0, 1 }, .{ 4, 3, 0 }, .{ 8, 3, 1 }, .{ 16, 0, 0 }, .{ 16, 2, 1 },
        .{ 8, 4, 0 }, .{ 16, 6, 1 }, .{ 8, 2, 0 }, .{ 1, 3, 1 },
    };
    for (layouts) |l| {
        const w = rand.intRangeAtMost(u32, 1, 33);
        const h = rand.intRangeAtMost(u32, 1, 33);
        const bpp: usize = @as(usize, switch (l[1]) {
            0, 3 => 1,
            4 => 2,
            2 => 3,
            else => 4,
        }) * l[0];
        const raw_len = h * ((w * bpp + 7) / 8 + 1) + 64;
        const raw = try gpa.alloc(u8, raw_len);
        defer gpa.free(raw);
        rand.bytes(raw);
        var aw: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
        defer aw.deinit();
        const hist = try gpa.alloc(u8, std.compress.flate.max_window_len);
        defer gpa.free(hist);
        var c: std.compress.flate.Compress = try .init(&aw.writer, hist, .zlib, .default);
        try c.writer.writeAll(raw);
        try c.finish();
        var plte: [48]u8 = undefined;
        rand.bytes(&plte);
        try seeds.append(gpa, try pngWith(gpa, w, h, l[0], l[1], l[2], aw.written(), if (l[1] == 3) plte[0 .. 3 * rand.intRangeAtMost(usize, 1, 16)] else null));
    }

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    var decoded_ok: usize = 0;
    for (0..3000) |round| {
        const seed = seeds.items[round % seeds.items.len];
        buf.clearRetainingCapacity();
        try buf.appendSlice(gpa, seed);
        switch (rand.uintLessThan(u8, 6)) {
            0 => {}, // as is
            1 => for (0..rand.intRangeAtMost(usize, 1, 8)) |_| {
                buf.items[rand.intRangeLessThan(usize, 8, buf.items.len)] = rand.int(u8);
            },
            2 => buf.shrinkRetainingCapacity(rand.uintLessThan(usize, buf.items.len)),
            3 => { // flip bits in the IDAT payload only
                const at = 33 + 8 + rand.uintLessThan(usize, @max(1, buf.items.len - 33 - 8 - 12));
                if (at < buf.items.len) buf.items[at] ^= @as(u8, 1) << rand.int(u3);
            },
            4 => { // rewrite IHDR dims / depth / type within legal-looking ranges
                std.mem.writeInt(u32, buf.items[16..20], rand.intRangeAtMost(u32, 1, 70), .big);
                std.mem.writeInt(u32, buf.items[20..24], rand.intRangeAtMost(u32, 1, 70), .big);
                if (rand.boolean()) buf.items[24] = ([_]u8{ 1, 2, 4, 8, 16 })[rand.uintLessThan(usize, 5)];
                if (rand.boolean()) buf.items[25] = ([_]u8{ 0, 2, 3, 4, 6 })[rand.uintLessThan(usize, 5)];
                if (rand.boolean()) buf.items[28] = rand.uintAtMost(u8, 1);
            },
            else => { // split the IDAT into many small chunks
                if (try splitIdat(gpa, buf.items, rand.intRangeAtMost(usize, 1, 50))) |split| {
                    defer gpa.free(split);
                    buf.clearRetainingCapacity();
                    try buf.appendSlice(gpa, split);
                }
            },
        }
        if (rand.uintLessThan(u8, 4) != 0) imgcheck.fixCrcs(buf.items);
        var img = decode(gpa, buf.items, .{ .budget = 8 << 20, .max_side = 64 }) catch continue;
        decoded_ok += 1;
        try testing.expect(img.w <= 64 and img.h <= 64);
        img.deinit(gpa);
    }
    try testing.expect(decoded_ok > 100);
}

/// Re-chunks the (single) IDAT of `png` into pieces of `n` bytes.
fn splitIdat(gpa: std.mem.Allocator, png: []const u8, n: usize) !?[]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    if (png.len < 8) return null;
    try out.appendSlice(gpa, png[0..8]);
    var i: usize = 8;
    while (png.len - i >= 12) {
        const len = std.mem.readInt(u32, png[i..][0..4], .big);
        if (len > png.len - i - 12) {
            out.deinit(gpa);
            return null;
        }
        const tag = png[i + 4 ..][0..4];
        const body = png[i + 8 ..][0..len];
        if (std.mem.eql(u8, tag, "IDAT")) {
            var rest = body;
            while (rest.len > 0) {
                const k = @min(n, rest.len);
                var l: [4]u8 = undefined;
                std.mem.writeInt(u32, &l, @intCast(k), .big);
                try out.appendSlice(gpa, &l);
                try out.appendSlice(gpa, "IDAT");
                try out.appendSlice(gpa, rest[0..k]);
                try out.appendSlice(gpa, &[4]u8{ 0, 0, 0, 0 });
                rest = rest[k..];
            }
        } else try out.appendSlice(gpa, png[i..][0 .. 12 + len]);
        i += 12 + len;
    }
    const s = try out.toOwnedSlice(gpa);
    imgcheck.fixCrcs(s);
    return s;
}

test "Bounded allocator refuses past its limit" {
    var b: Bounded = .{ .child = testing.allocator, .limit = 100 };
    const a = b.allocator();
    const x = try a.alloc(u8, 60);
    try testing.expectError(error.OutOfMemory, a.alloc(u8, 41));
    const y = try a.alloc(u8, 40);
    a.free(x);
    a.free(y);
    try testing.expectEqual(@as(usize, 0), b.used);
}
