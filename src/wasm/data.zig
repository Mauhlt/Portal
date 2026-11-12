//! The data slice: a feed of the data the session pushed, newest first,
//! drawn into its own framebuffer (a second canvas). Separate from the
//! terminal's decode/draw path so new kinds (CSV/JSON tables, charts) can
//! be added as further `Kind`s with their own card renderer.
//!
//! Today the only kind is an image: every inline image blob the session
//! sends ('I' frames, docs/protocol.md §3) becomes a card. The terminal may
//! drop a blob once it scrolls off; the feed keeps its own bounded copy of
//! what it needs (size, and pixels when they were decoded).

const std = @import("std");
const proto = @import("proto.zig");
const layout = @import("layout.zig");
const glyphs = @import("glyphs.zig");
const render = @import("render.zig");
const Rect = layout.Rect;

pub const Kind = enum { image };

pub const Item = struct {
    kind: Kind,
    /// Server id (images: the blob id).
    id: u32,
    /// Arrival order, for "N new".
    seq: u32,
    /// Image size in pixels (0 if unknown).
    w: u32 = 0,
    h: u32 = 0,
    /// Decoded RGBA (straight alpha), owned; null until/unless decoded.
    px: ?[]u8 = null,
};

pub const max_items = 8;
/// Pixels kept for previews, in bytes (older previews are dropped first).
pub const max_pixel_bytes: usize = 32 << 20;

pub const Feed = struct {
    /// Oldest first.
    items: std.ArrayList(Item) = .empty,
    next_seq: u32 = 1,
    /// Items that arrived while the data slice was not visible (badge).
    unseen: u32 = 0,
    /// Needs a redraw.
    dirty: bool = true,

    pub fn deinit(f: *Feed, gpa: std.mem.Allocator) void {
        for (f.items.items) |it| if (it.px) |p| gpa.free(p);
        f.items.deinit(gpa);
        f.* = .{};
    }

    fn find(f: *Feed, kind: Kind, id: u32) ?*Item {
        for (f.items.items) |*it| if (it.kind == kind and it.id == id) return it;
        return null;
    }

    fn pixelBytes(f: *const Feed) usize {
        var n: usize = 0;
        for (f.items.items) |it| if (it.px) |p| {
            n += p.len;
        };
        return n;
    }

    /// An image blob arrived. `visible`: the data slice is on screen (no
    /// badge). A blob id seen again (re-sent after a cache drop) is not new.
    pub fn addImage(f: *Feed, gpa: std.mem.Allocator, id: u32, w: u32, h: u32, visible: bool) !void {
        if (f.find(.image, id) != null) return;
        if (f.items.items.len >= max_items) {
            const old = f.items.orderedRemove(0);
            if (old.px) |p| gpa.free(p);
        }
        try f.items.append(gpa, .{ .kind = .image, .id = id, .seq = f.next_seq, .w = w, .h = h });
        f.next_seq +%= 1;
        if (!visible) f.unseen +|= 1;
        f.dirty = true;
    }

    /// Pixels for image `id` were decoded: keep a copy for the preview.
    pub fn imageDecoded(f: *Feed, gpa: std.mem.Allocator, id: u32, rgba: @import("imgdec").Rgba) void {
        const it = f.find(.image, id) orelse return;
        if (it.px != null) return;
        const n = @as(usize, rgba.w) * rgba.h * 4;
        if (n == 0 or rgba.px.len < n) return;
        // Make room by dropping the oldest previews (their cards remain).
        var i: usize = 0;
        while (f.pixelBytes() + n > max_pixel_bytes and i < f.items.items.len) : (i += 1) {
            if (f.items.items[i].px) |p| {
                gpa.free(p);
                f.items.items[i].px = null;
            }
        }
        if (f.pixelBytes() + n > max_pixel_bytes) return;
        it.px = gpa.dupe(u8, rgba.px[0..n]) catch return;
        it.w = rgba.w;
        it.h = rgba.h;
        f.dirty = true;
    }

    /// The data slice became visible: clear the badge.
    pub fn seen(f: *Feed) void {
        f.unseen = 0;
    }

    /// Redraws the whole feed into `fb` (device pixels; `dpr` scales the
    /// padding and text). `ui` must be sized for captions already.
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
        var y: i32 = pad;
        var i = f.items.items.len;
        while (i > 0 and y < all.h) {
            i -= 1;
            const it = f.items.items[i];
            var buf: [64]u8 = undefined;
            const cap = switch (it.kind) {
                .image => if (it.w > 0)
                    std.fmt.bufPrint(&buf, "image {d}\u{00D7}{d}", .{ it.w, it.h }) catch "image"
                else
                    "image",
            };
            text(fb, ui, cap, pad, y, all, theme.fg);
            y += line + @divFloor(pad, 2);
            const card_w = @max(1, all.w - 2 * pad);
            switch (it.kind) {
                .image => y += drawImage(fb, ui, it, .{ .x = pad, .y = y, .w = card_w, .h = @max(line * 3, @divFloor(all.h * 3, 5)) }, all, theme, dpr),
            }
            y += pad * 2;
        }
    }
};

/// Draws an image card fitted into `box` (keeping its aspect ratio);
/// returns the height used.
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
    if (it.px) |px| {
        blit(fb, r, clip, px, it.w, it.h);
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
    return h;
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
    try f.addImage(gpa, 7, 40, 20, false);
    try f.addImage(gpa, 7, 40, 20, false); // re-sent blob: not new
    try testing.expectEqual(@as(usize, 1), f.items.items.len);
    try testing.expectEqual(@as(u32, 1), f.unseen);
    f.seen();
    try f.addImage(gpa, 8, 1, 1, true); // visible: no badge
    try testing.expectEqual(@as(u32, 0), f.unseen);
    for (0..max_items + 3) |i| try f.addImage(gpa, 100 + @as(u32, @intCast(i)), 2, 2, false);
    try testing.expectEqual(@as(usize, max_items), f.items.items.len);
    try testing.expectEqual(@as(u32, 100 + max_items + 2), f.items.items[max_items - 1].id);
}

test "feed: decoded pixels are copied and bounded" {
    const gpa = testing.allocator;
    var f: Feed = .{};
    defer f.deinit(gpa);
    try f.addImage(gpa, 1, 2, 2, true);
    var px: [16]u8 = @splat(200);
    f.imageDecoded(gpa, 1, .{ .w = 2, .h = 2, .px = &px });
    try testing.expect(f.items.items[0].px != null);
    px[0] = 1; // the feed owns its copy
    try testing.expectEqual(@as(u8, 200), f.items.items[0].px.?[0]);
    f.imageDecoded(gpa, 99, .{ .w = 2, .h = 2, .px = &px }); // unknown id: ignored
    f.imageDecoded(gpa, 1, .{ .w = 9, .h = 9, .px = &px }); // short buffer: ignored
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
    f.draw(&fb, &ui, theme, 1);
    // "No data yet" is drawn somewhere around the middle.
    var lit: usize = 0;
    for (fb.pixels) |p| {
        if (p != render.pixel(theme.bg)) lit += 1;
    }
    try testing.expect(lit > 0);
    // A red 4x2 image, decoded, fills its card with red.
    try f.addImage(gpa, 1, 4, 2, true);
    var px: [4 * 2 * 4]u8 = undefined;
    for (0..8) |i| px[i * 4 ..][0..4].* = .{ 255, 0, 0, 255 };
    f.imageDecoded(gpa, 1, .{ .w = 4, .h = 2, .px = &px });
    try f.addImage(gpa, 2, 640, 480, true); // never decoded: placeholder
    f.draw(&fb, &ui, theme, 1);
    var red: usize = 0;
    for (fb.pixels) |p| {
        if (p == render.pixel(0xff0000)) red += 1;
    }
    try testing.expectEqual(@as(usize, 8 * 4), red); // 4x2 at 2x upscale
    try testing.expect(!f.dirty);
    // Tiny and odd framebuffers never index out of bounds.
    for ([_][2]u32{ .{ 1, 1 }, .{ 3, 500 }, .{ 500, 3 }, .{ 37, 41 } }) |sz| {
        try fb.resize(gpa, sz[0], sz[1]);
        f.draw(&fb, &ui, theme, 2);
    }
}
