//! The data slice: a feed of the data the session pushed, newest first,
//! drawn into its own framebuffer (a second canvas). Separate from the
//! terminal's decode/draw path so new kinds (CSV/JSON tables, charts) can
//! be added as further `Kind`s with their own card renderer.
//!
//! Today the only kind is an image: every inline image blob the session
//! sends ('I' frames, docs/protocol.md §3) becomes a card. The terminal may
//! drop a blob once it scrolls off; the feed keeps its own bounded copy of
//! what it needs (size, and pixels when they were decoded).

//!
//! The model (items, arrival order, the badge, memory bounds) is shared with
//! the native client: module "datafeed" (src/datafeed). This file keeps the
//! browser's payload (decoded pixels) and drawing.

const std = @import("std");
const datafeed = @import("datafeed");
const proto = @import("proto.zig");
const layout = @import("layout.zig");
const glyphs = @import("glyphs.zig");
const render = @import("render.zig");
const Rect = layout.Rect;

pub const Kind = datafeed.Kind;
pub const max_items = datafeed.max_items;
/// Pixels kept for previews, in bytes (older previews are dropped first).
pub const max_pixel_bytes: usize = 32 << 20;

/// A decoded image (RGBA, straight alpha), owned.
pub const Pixels = struct {
    px: []u8,
    pub fn bytes(p: Pixels) usize {
        return p.px.len;
    }
    pub fn deinit(p: Pixels, gpa: std.mem.Allocator) void {
        gpa.free(p.px);
    }
};

pub const Feed = datafeed.Feed(Pixels);
pub const Item = Feed.Item;

/// An image blob arrived. `visible`: the data slice is on screen (no
/// badge). A blob id seen again (re-sent after a cache drop) is not new.
pub fn addImage(f: *Feed, gpa: std.mem.Allocator, id: u32, w: u32, h: u32, visible: bool) !void {
    _ = try f.add(gpa, .image, id, w, h, visible);
}

/// Pixels for image `id` were decoded: keep a copy for the preview.
pub fn imageDecoded(f: *Feed, gpa: std.mem.Allocator, id: u32, rgba: @import("imgdec").Rgba) void {
    const it = f.find(.image, id) orelse return;
    if (it.data != null) return;
    const n = @as(usize, rgba.w) * rgba.h * 4;
    if (n == 0 or rgba.px.len < n) return;
    const copy = gpa.dupe(u8, rgba.px[0..n]) catch return;
    if (f.attach(gpa, .image, id, .{ .px = copy }, max_pixel_bytes)) {
        it.w = rgba.w;
        it.h = rgba.h;
    }
}

/// Height (CSS px) the feed would like under the Data slice's header in a
/// page `w` CSS px wide (0: nothing to show): a caption line and the
/// tallest image at up to 1 image pixel per CSS px, at least a few lines.
/// slices.compute caps it (datafeed.sliceHeight).
pub fn wantedHeight(f: *const Feed, w: f64) f64 {
    if (f.items.items.len == 0) return 0;
    const pad = 10;
    const line = 18;
    const inner = @max(1, w - 2 * pad);
    var tallest: f64 = line * 3;
    for (f.items.items) |it| {
        if (it.w == 0 or it.h == 0) {
            tallest = @max(tallest, line * 6);
            continue;
        }
        const k = @min(1, inner / @as(f64, @floatFromInt(it.w)));
        tallest = @max(tallest, @round(@as(f64, @floatFromInt(it.h)) * k));
    }
    return pad + line + tallest + pad;
}

/// Redraws the whole feed into `fb` (device pixels; `dpr` scales the
/// padding and text): the items left to right, newest first, each a
/// caption over its image fitted to the canvas height. `ui` must be sized
/// for captions already.
pub fn draw(f: *Feed, fb: *render.Framebuffer, ui: *glyphs.Glyphs, theme: render.Theme, dpr: f32) void {
    f.dirty = false;
    const all: Rect = .{ .w = @intCast(fb.w), .h = @intCast(fb.h) };
    fb.fill(all, all, theme.bg);
    const pad: i32 = @intFromFloat(@max(1, @round(10 * dpr)));
    const line: i32 = @intCast(@max(1, ui.ch));
    if (f.items.items.len == 0) {
        text(fb, ui, "No data yet", @divFloor(all.w - textWidth(ui, "No data yet"), 2), @divFloor(all.h - line, 2), all, theme.placeholder);
        return;
    }
    const img_y = pad + line + @divFloor(pad, 2);
    const img_h = @max(line, all.h - img_y - pad);
    var x: i32 = pad;
    var i = f.items.items.len;
    while (i > 0 and x < all.w - line * 4) {
        i -= 1;
        const it = f.items.items[i];
        var buf: [64]u8 = undefined;
        const cap = switch (it.kind) {
            .image => if (it.w > 0)
                std.fmt.bufPrint(&buf, "image {d}\u{00D7}{d}", .{ it.w, it.h }) catch "image"
            else
                "image",
        };
        const room = all.w - pad - x;
        const box_w = @min(room, @max(line * 4, @divFloor(all.w * 3, 5)));
        const used = switch (it.kind) {
            .image => drawImage(fb, ui, it, .{ .x = x, .y = img_y, .w = box_w, .h = img_h }, all, theme, dpr),
        };
        const cap_w = @min(room, @max(used, @min(textWidth(ui, cap), line * 12)));
        text(fb, ui, cap, x, pad, .{ .x = x, .y = 0, .w = cap_w, .h = all.h }, theme.fg);
        x += @max(used, cap_w) + pad * 2;
    }
}

/// Draws an image card fitted into `box` (keeping its aspect ratio);
/// returns the width used.
fn drawImage(fb: *render.Framebuffer, ui: *glyphs.Glyphs, it: Item, box: Rect, clip: Rect, theme: render.Theme, dpr: f32) i32 {
    var w = box.w;
    var h = box.h;
    if (it.w > 0 and it.h > 0) {
        // Fit, never upscale beyond 2 device pixels per image pixel.
        const max_w: i64 = @min(@as(i64, box.w), @as(i64, it.w) * 2);
        const max_h: i64 = @min(@as(i64, box.h), @as(i64, it.h) * 2);
        const by_w_h = @divFloor(max_w * it.h, it.w);
        if (by_w_h <= max_h) {
            w = @intCast(@max(1, max_w));
            h = @intCast(@max(1, by_w_h));
        } else {
            w = @intCast(@max(1, @divFloor(max_h * it.w, it.h)));
            h = @intCast(@max(1, max_h));
        }
    } else h = @min(h, @as(i32, @intCast(@max(1, ui.ch))) * 4);
    const r: Rect = .{ .x = box.x, .y = box.y, .w = w, .h = h };
    if (it.data) |d| {
        blit(fb, r, clip, d.px, it.w, it.h);
    } else {
        // Not decoded (the browser build has no PNG decoder yet): an
        // outlined card with the size, like the terminal's placeholder.
        const t: i32 = @intFromFloat(@max(1, @round(dpr)));
        fb.fill(r, clip, theme.placeholder);
        fb.fill(.{ .x = r.x + t, .y = r.y + t, .w = r.w - 2 * t, .h = r.h - 2 * t }, clip, theme.bg);
        const label = "preview not available";
        const lw = textWidth(ui, label);
        if (lw + 2 * t < r.w and @as(i32, @intCast(ui.ch)) < r.h)
            text(fb, ui, label, r.x + @divFloor(r.w - lw, 2), r.y + @divFloor(r.h - @as(i32, @intCast(ui.ch)), 2), clip, theme.placeholder);
    }
    return w;
}

/// Nearest-neighbour scale of a w x h RGBA image into `r`.
fn blit(fb: *render.Framebuffer, r: Rect, clip: Rect, px: []const u8, w: u32, h: u32) void {
    if (w == 0 or h == 0 or px.len < @as(usize, w) * h * 4 or r.w <= 0 or r.h <= 0) return;
    const fb_w: i32 = @intCast(fb.w);
    const fb_h: i32 = @intCast(fb.h);
    const x0 = @max(r.x, clip.x, 0);
    const x1 = @min(r.right(), clip.right(), fb_w);
    const y0 = @max(r.y, clip.y, 0);
    const y1 = @min(r.bottom(), clip.bottom(), fb_h);
    var y = y0;
    while (y < y1) : (y += 1) {
        const sy: usize = @intCast(@min(@as(i64, h) - 1, @divFloor(@as(i64, y - r.y) * h, r.h)));
        var x = x0;
        while (x < x1) : (x += 1) {
            const sx: usize = @intCast(@min(@as(i64, w) - 1, @divFloor(@as(i64, x - r.x) * w, r.w)));
            const s = px[(sy * w + sx) * 4 ..][0..4];
            if (s[3] == 0) continue;
            const rgb = (@as(u32, s[0]) << 16) | (@as(u32, s[1]) << 8) | s[2];
            const cell: Rect = .{ .x = x, .y = y, .w = 1, .h = 1 };
            if (s[3] == 255) fb.fill(cell, clip, rgb) else fb.tint(cell, clip, rgb, s[3]);
        }
    }
}

fn textWidth(ui: *const glyphs.Glyphs, s: []const u8) i32 {
    var n: i32 = 0;
    var it: proto.Utf8Iter = .{ .s = s };
    while (it.next()) |_| n += 1;
    return n * @as(i32, @intCast(ui.cw));
}

fn text(fb: *render.Framebuffer, ui: *glyphs.Glyphs, s: []const u8, x0: i32, y: i32, clip: Rect, rgb: u32) void {
    var x = x0;
    var it: proto.Utf8Iter = .{ .s = s };
    while (it.next()) |cp| {
        const cov = ui.get(cp, .{}, 1);
        fb.glyph(x, y, cov, ui.cw, ui.ch, clip, rgb);
        x += @intCast(ui.cw);
    }
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "feed: new images, badge, duplicates, eviction" {
    const gpa = testing.allocator;
    var f: Feed = .{};
    defer f.deinit(gpa);
    try addImage(&f, gpa, 7, 40, 20, false);
    try addImage(&f, gpa, 7, 40, 20, false); // re-sent blob: not new
    try testing.expectEqual(@as(usize, 1), f.items.items.len);
    try testing.expectEqual(@as(u32, 1), f.unseen);
    f.seen();
    try addImage(&f, gpa, 8, 1, 1, true); // visible: no badge
    try testing.expectEqual(@as(u32, 0), f.unseen);
    for (0..max_items + 3) |i| try addImage(&f, gpa, 100 + @as(u32, @intCast(i)), 2, 2, false);
    try testing.expectEqual(@as(usize, max_items), f.items.items.len);
    try testing.expectEqual(@as(u32, 100 + max_items + 2), f.items.items[max_items - 1].id);
}

test "feed: decoded pixels are copied and bounded" {
    const gpa = testing.allocator;
    var f: Feed = .{};
    defer f.deinit(gpa);
    try addImage(&f, gpa, 1, 2, 2, true);
    var px: [16]u8 = @splat(200);
    imageDecoded(&f, gpa, 1, .{ .w = 2, .h = 2, .px = &px });
    try testing.expect(f.items.items[0].data != null);
    px[0] = 1; // the feed owns its copy
    try testing.expectEqual(@as(u8, 200), f.items.items[0].data.?.px[0]);
    imageDecoded(&f, gpa, 99, .{ .w = 2, .h = 2, .px = &px }); // unknown id: ignored
    imageDecoded(&f, gpa, 1, .{ .w = 9, .h = 9, .px = &px }); // short buffer: ignored
}

test "draw: empty feed, decoded image and placeholder, any size" {
    const gpa = testing.allocator;
    var ui = try glyphs.Glyphs.init(gpa, @embedFile("font_regular"), @embedFile("font_bold"));
    defer ui.deinit();
    ui.setEm(13);
    var fb: render.Framebuffer = .{};
    defer fb.deinit(gpa);
    const theme: render.Theme = .{};
    var f: Feed = .{};
    defer f.deinit(gpa);
    try fb.resize(gpa, 300, 400);
    draw(&f, &fb, &ui, theme, 1);
    // "No data yet" is drawn somewhere around the middle.
    var lit: usize = 0;
    for (fb.pixels) |p| {
        if (p != render.pixel(theme.bg)) lit += 1;
    }
    try testing.expect(lit > 0);
    // A red 4x2 image, decoded, fills its card with red.
    try addImage(&f, gpa, 1, 4, 2, true);
    var px: [4 * 2 * 4]u8 = undefined;
    for (0..8) |i| px[i * 4 ..][0..4].* = .{ 255, 0, 0, 255 };
    imageDecoded(&f, gpa, 1, .{ .w = 4, .h = 2, .px = &px });
    try addImage(&f, gpa, 2, 640, 480, true); // never decoded: placeholder
    draw(&f, &fb, &ui, theme, 1);
    var red: usize = 0;
    for (fb.pixels) |p| {
        if (p == render.pixel(0xff0000)) red += 1;
    }
    try testing.expectEqual(@as(usize, 8 * 4), red); // 4x2 at 2x upscale
    try testing.expect(!f.dirty);
    // What the slice would like: a caption and the tallest image.
    try testing.expect(wantedHeight(&f, 1000) >= 480 + 18);
    try testing.expect(wantedHeight(&f, 330) < 480); // scaled to the width
    var e: Feed = .{};
    try testing.expectEqual(@as(f64, 0), wantedHeight(&e, 1000));
    // Tiny and odd framebuffers never index out of bounds.
    for ([_][2]u32{ .{ 1, 1 }, .{ 3, 500 }, .{ 500, 3 }, .{ 37, 41 } }) |sz| {
        try fb.resize(gpa, sz[0], sz[1]);
        draw(&f, &fb, &ui, theme, 2);
    }
}
