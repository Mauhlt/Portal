//! Build helper for `zig build ios`: the app icon at one pixel size, drawn
//! in Zig by icon_art.zig (the code version of docs/brand/portal-icon.svg)
//! and written as an opaque 8-bit RGB PNG (Apple wants no alpha).
//!
//!   ios-icon <size in pixels> <out.png>

const std = @import("std");
const Io = std.Io;
const icon_art = @import("icon_art.zig");
const pngw = @import("pngw.zig");

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

pub fn encode(gpa: std.mem.Allocator, size: u32) ![]u8 {
    const px = try icon_art.render(gpa, size, true);
    defer gpa.free(px);
    return pngw.encode(gpa, px, size, size, .rgb);
}

test "app icon is a well-formed opaque PNG" {
    const png = try encode(std.testing.allocator, 120);
    defer std.testing.allocator.free(png);
    try std.testing.expectEqualStrings("\x89PNG\r\n\x1a\n", png[0..8]);
    try std.testing.expectEqualStrings("IHDR", png[12..16]);
    try std.testing.expectEqual(@as(u32, 120), std.mem.readInt(u32, png[16..20], .big));
    try std.testing.expectEqual(@as(u8, 2), png[25]); // RGB, no alpha
    try std.testing.expectEqualStrings("IEND", png[png.len - 8 .. png.len - 4]);
}

test {
    _ = icon_art;
    _ = pngw;
}
