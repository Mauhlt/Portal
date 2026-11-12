//! Build helper for `zig build ios`: the placeholder app icon, drawn in
//! Zig (no image files in the repo): a dark rounded square with a light
//! "doorway" bar, written as an 8-bit RGB PNG (zlib stored blocks, so no
//! compressor is needed).
//!
//!   ios-icon <size in pixels> <out.png>

const std = @import("std");
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    var args: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer args.deinit();
    _ = args.next();
    const size = try std.fmt.parseInt(u32, args.next() orelse return error.Usage, 10);
    const out_path = args.next() orelse return error.Usage;
    const png = try encode(gpa, size);
    defer gpa.free(png);
    try Io.Dir.cwd().writeFile(init.io, .{ .sub_path = out_path, .data = png });
}

/// Pixel colour of the placeholder at (x, y).
fn pixel(size: u32, x: u32, y: u32) [3]u8 {
    const bg: [3]u8 = .{ 0x20, 0x23, 0x29 };
    const fg: [3]u8 = .{ 0x6C, 0xA8, 0xE8 };
    const s: f32 = @floatFromInt(size);
    const fx = @as(f32, @floatFromInt(x)) / s;
    const fy = @as(f32, @floatFromInt(y)) / s;
    // A door: an outlined portal in the middle third.
    const in_outer = fx > 0.30 and fx < 0.70 and fy > 0.20 and fy < 0.82;
    const in_inner = fx > 0.38 and fx < 0.62 and fy > 0.28 and fy < 0.82;
    return if (in_outer and !in_inner) fg else bg;
}

pub fn encode(gpa: std.mem.Allocator, size: u32) ![]u8 {
    // Raw scanlines: filter byte 0 + RGB.
    const row = 1 + 3 * @as(usize, size);
    const raw = try gpa.alloc(u8, row * size);
    defer gpa.free(raw);
    for (0..size) |y| {
        raw[y * row] = 0;
        for (0..size) |x| {
            const c = pixel(size, @intCast(x), @intCast(y));
            @memcpy(raw[y * row + 1 + 3 * x ..][0..3], &c);
        }
    }
    // zlib: header, stored blocks of at most 65535 bytes, Adler-32.
    var z: std.ArrayList(u8) = .empty;
    defer z.deinit(gpa);
    try z.appendSlice(gpa, &.{ 0x78, 0x01 });
    var off: usize = 0;
    while (true) {
        const n = @min(raw.len - off, 65535);
        const last = off + n == raw.len;
        try z.append(gpa, @intFromBool(last));
        const len: u16 = @intCast(n);
        try z.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToLittle(u16, len)));
        try z.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToLittle(u16, ~len)));
        try z.appendSlice(gpa, raw[off..][0..n]);
        off += n;
        if (last) break;
    }
    try z.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToBig(u32, std.hash.Adler32.hash(raw))));

    var png: std.ArrayList(u8) = .empty;
    errdefer png.deinit(gpa);
    try png.appendSlice(gpa, "\x89PNG\r\n\x1a\n");
    var ihdr: [13]u8 = undefined;
    std.mem.writeInt(u32, ihdr[0..4], size, .big);
    std.mem.writeInt(u32, ihdr[4..8], size, .big);
    ihdr[8] = 8; // bit depth
    ihdr[9] = 2; // RGB
    ihdr[10] = 0;
    ihdr[11] = 0;
    ihdr[12] = 0;
    try chunk(gpa, &png, "IHDR", &ihdr);
    try chunk(gpa, &png, "IDAT", z.items);
    try chunk(gpa, &png, "IEND", "");
    return png.toOwnedSlice(gpa);
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

test "placeholder icon is a well-formed PNG" {
    const png = try encode(std.testing.allocator, 120);
    defer std.testing.allocator.free(png);
    try std.testing.expectEqualStrings("\x89PNG\r\n\x1a\n", png[0..8]);
    try std.testing.expectEqualStrings("IHDR", png[12..16]);
    try std.testing.expectEqual(@as(u32, 120), std.mem.readInt(u32, png[16..20], .big));
    try std.testing.expectEqualStrings("IEND", png[png.len - 8 .. png.len - 4]);
}
