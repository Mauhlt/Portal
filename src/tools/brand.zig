//! portal-brand: regenerates the raster brand assets in docs/brand from
//! their sources (run by `zig build brand`; the outputs are committed, so
//! a normal build never runs it).
//!
//!   portal-brand icons <dir>
//!       portal-icon-1024.png   iOS App Store / marketing icon (opaque RGB)
//!       portal-icon-256.png, portal-icon-32.png, portal-icon-16.png
//!                              previews with transparency
//!       portal.ico             Windows icon: 16, 24, 32, 48, 64, 128
//!                              (32-bit BMP) and 256 (PNG)
//!   portal-brand hero <in.jpg> <out.png> <side>
//!       the hero art as a PNG of <side> x <side> (box filtered), the one
//!       Portal embeds for its splash and About art (the apps decode PNG).
//!
//! The icon is drawn by icon_art.zig (the code version of
//! docs/brand/portal-icon.svg); PNGs are written by pngw.zig; the JPEG is
//! decoded by the owner's Image package.

const std = @import("std");
const Io = std.Io;
const Image = @import("Image");
const icon_art = @import("icon_art.zig");
const pngw = @import("pngw.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer args.deinit();
    _ = args.next();
    const cmd = args.next() orelse return error.Usage;
    if (std.mem.eql(u8, cmd, "icons")) {
        const dir_path = args.next() orelse return error.Usage;
        var dir = try Io.Dir.cwd().createDirPathOpen(io, dir_path, .{});
        defer dir.close(io);
        try icons(gpa, io, dir);
    } else if (std.mem.eql(u8, cmd, "hero")) {
        const in_path = args.next() orelse return error.Usage;
        const out_path = args.next() orelse return error.Usage;
        const side = try std.fmt.parseInt(u32, args.next() orelse return error.Usage, 10);
        try hero(gpa, io, in_path, out_path, side);
    } else return error.Usage;
}

fn writePng(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, name: []const u8, size: u32, opaque_bg: bool) !void {
    const px = try icon_art.render(gpa, size, opaque_bg);
    defer gpa.free(px);
    const png = try pngw.encode(gpa, px, size, size, if (opaque_bg) .rgb else .rgba);
    defer gpa.free(png);
    try dir.writeFile(io, .{ .sub_path = name, .data = png });
}

fn icons(gpa: std.mem.Allocator, io: Io, dir: Io.Dir) !void {
    try writePng(gpa, io, dir, "portal-icon-1024.png", 1024, true);
    try writePng(gpa, io, dir, "portal-icon-256.png", 256, false);
    try writePng(gpa, io, dir, "portal-icon-32.png", 32, false);
    try writePng(gpa, io, dir, "portal-icon-16.png", 16, false);
    const ico = try buildIco(gpa, &.{ 16, 24, 32, 48, 64, 128, 256 });
    defer gpa.free(ico);
    try dir.writeFile(io, .{ .sub_path = "portal.ico", .data = ico });
}

/// An .ico with one image per size: 32-bit BMP (with an AND mask) below
/// 256, PNG at 256 (what Windows expects since Vista).
pub fn buildIco(gpa: std.mem.Allocator, sizes: []const u32) ![]u8 {
    var images: std.ArrayList([]u8) = .empty;
    defer {
        for (images.items) |b| gpa.free(b);
        images.deinit(gpa);
    }
    for (sizes) |s| {
        const px = try icon_art.render(gpa, s, false);
        defer gpa.free(px);
        try images.append(gpa, if (s >= 256) try pngw.encode(gpa, px, s, s, .rgba) else try dib(gpa, px, s));
    }
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const w = struct {
        fn u16le(o: *std.ArrayList(u8), g: std.mem.Allocator, v: u16) !void {
            try o.appendSlice(g, &std.mem.toBytes(std.mem.nativeToLittle(u16, v)));
        }
        fn u32le(o: *std.ArrayList(u8), g: std.mem.Allocator, v: u32) !void {
            try o.appendSlice(g, &std.mem.toBytes(std.mem.nativeToLittle(u32, v)));
        }
    };
    try w.u16le(&out, gpa, 0);
    try w.u16le(&out, gpa, 1);
    try w.u16le(&out, gpa, @intCast(sizes.len));
    var offset: u32 = @intCast(6 + 16 * sizes.len);
    for (sizes, images.items) |s, img| {
        try out.append(gpa, if (s >= 256) 0 else @intCast(s));
        try out.append(gpa, if (s >= 256) 0 else @intCast(s));
        try out.append(gpa, 0); // colour count
        try out.append(gpa, 0);
        try w.u16le(&out, gpa, 1); // planes
        try w.u16le(&out, gpa, 32); // bits per pixel
        try w.u32le(&out, gpa, @intCast(img.len));
        try w.u32le(&out, gpa, offset);
        offset += @intCast(img.len);
    }
    for (images.items) |img| try out.appendSlice(gpa, img);
    return out.toOwnedSlice(gpa);
}

/// BITMAPINFOHEADER + bottom-up BGRA + a 1-bit AND mask (set where fully
/// transparent, for old consumers).
fn dib(gpa: std.mem.Allocator, px: []const u8, s: u32) ![]u8 {
    const mask_stride = ((s + 31) / 32) * 4;
    const len = 40 + s * s * 4 + mask_stride * s;
    const out = try gpa.alloc(u8, len);
    @memset(out, 0);
    std.mem.writeInt(u32, out[0..4], 40, .little);
    std.mem.writeInt(i32, out[4..8], @intCast(s), .little);
    std.mem.writeInt(i32, out[8..12], @intCast(s * 2), .little);
    std.mem.writeInt(u16, out[12..14], 1, .little);
    std.mem.writeInt(u16, out[14..16], 32, .little);
    std.mem.writeInt(u32, out[20..24], s * s * 4 + mask_stride * s, .little);
    const pix = out[40..];
    const mask = out[40 + s * s * 4 ..];
    for (0..s) |y| {
        const row = s - 1 - y; // bottom-up
        for (0..s) |x| {
            const p = px[(y * s + x) * 4 ..][0..4];
            const o = pix[(row * s + x) * 4 ..][0..4];
            o.* = .{ p[2], p[1], p[0], p[3] };
            if (p[3] == 0) mask[row * mask_stride + x / 8] |= @as(u8, 0x80) >> @intCast(x % 8);
        }
    }
    return out;
}

fn hero(gpa: std.mem.Allocator, io: Io, in_path: []const u8, out_path: []const u8, side: u32) !void {
    const jpg = try Io.Dir.cwd().readFileAlloc(io, in_path, gpa, .limited(64 << 20));
    defer gpa.free(jpg);
    const img = try Image.decode(.jpg, gpa, jpg);
    defer img.deinit(gpa);
    const rgba = try img.convert(.rgba, gpa);
    defer rgba.deinit(gpa);
    const src = std.mem.sliceAsBytes(rgba.pixels.rgba);
    const sw = rgba.width;
    const sh = rgba.height;
    const out = try gpa.alloc(u8, @as(usize, side) * side * 4);
    defer gpa.free(out);
    // Box filter (area average), aspect kept by fitting into side x side
    // (the hero is square).
    for (0..side) |oy| {
        const y0 = oy * sh / side;
        const y1 = @max(y0 + 1, (oy + 1) * sh / side);
        for (0..side) |ox| {
            const x0 = ox * sw / side;
            const x1 = @max(x0 + 1, (ox + 1) * sw / side);
            var acc: [4]u64 = @splat(0);
            for (y0..y1) |y| for (x0..x1) |x| {
                const p = src[(y * sw + x) * 4 ..][0..4];
                for (0..4) |k| acc[k] += p[k];
            };
            const n: u64 = (y1 - y0) * (x1 - x0);
            const o = out[(oy * side + ox) * 4 ..][0..4];
            for (0..4) |k| o[k] = @intCast((acc[k] + n / 2) / n);
            o[3] = 255;
        }
    }
    const png = try pngw.encode(gpa, out, side, side, .rgb);
    defer gpa.free(png);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = png });
}

test {
    _ = pngw;
    _ = icon_art;
}

test "ico: directory and entries" {
    const gpa = std.testing.allocator;
    const ico = try buildIco(gpa, &.{ 16, 256 });
    defer gpa.free(ico);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, ico[2..4], .little));
    try std.testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, ico[4..6], .little));
    try std.testing.expectEqual(@as(u8, 16), ico[6]);
    try std.testing.expectEqual(@as(u8, 0), ico[22]); // 256 -> 0
    const off2 = std.mem.readInt(u32, ico[22 + 12 ..][0..4], .little);
    try std.testing.expectEqualStrings("\x89PNG", ico[off2..][0..4]);
    const off1 = std.mem.readInt(u32, ico[6 + 12 ..][0..4], .little);
    try std.testing.expectEqual(@as(u32, 40), std.mem.readInt(u32, ico[off1..][0..4], .little));
}
