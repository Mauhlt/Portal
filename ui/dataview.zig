//! The Data slice's state (docs/layout-design.md): the images the session
//! pushed, newest first, in a strip under the main slice (frame.DataSlice)
//! on every device. The model is module "datafeed" (bounded history, a
//! badge for what arrived while
//! collapsed, the slice's size rule); here the payload is the PNG bytes,
//! which the view module decodes and scales like the terminal's inline images.
//!
//! Feeding: the UI thread calls `sync` with the grid's image store under
//! the shared lock whenever it draws; every blob not seen before becomes an
//! item. (A blob the server sends and drops again between two frames is
//! missed; the terminal never showed it either.)
//!
//! The slice is a thin header strip while empty ("Data · nothing yet") and
//! grows when items arrive (frame.dataHeight). F2 or its Hide button
//! collapses it to the strip, which then counts what is new; Clear empties
//! it.

const std = @import("std");
const datafeed = @import("datafeed");
const frame = @import("frame.zig");
const Images = @import("grid.zig").Images;

/// PNG bytes kept for the column, all items together.
pub const max_png_bytes: usize = 24 << 20;

/// Ids in `store` carry this bit, so the renderer's decoded entries for the
/// column never collide with the terminal's (they are drawn at other sizes).
const store_tag: u32 = 1 << 31;

const Png = struct {
    png: []u8,
    pub fn bytes(p: Png) usize {
        return p.png.len;
    }
    pub fn deinit(p: Png, gpa: std.mem.Allocator) void {
        gpa.free(p.png);
    }
};

/// Width and height from a PNG's IHDR (0 x 0 if it isn't one).
pub fn pngSize(png: []const u8) [2]u32 {
    const sig = "\x89PNG\r\n\x1a\n";
    if (png.len < 24 or !std.mem.eql(u8, png[0..8], sig) or !std.mem.eql(u8, png[12..16], "IHDR")) return .{ 0, 0 };
    return .{ std.mem.readInt(u32, png[16..20], .big), std.mem.readInt(u32, png[20..24], .big) };
}

pub const DataView = struct {
    feed: datafeed.Feed(Png) = .{},
    /// The slice's image store for the renderer: non-owning views of the
    /// feed's PNG bytes under tagged ids (rebuilt when the feed changes;
    /// only `blobs.deinit` is ever called on it).
    store: Images = .{},
    /// The user's choice (F2 / Hide / Show).
    shown: bool = true,
    seen_gen: u64 = std.math.maxInt(u64),
    /// Blob ids of the terminal's store already taken (a Clear must not
    /// bring them back on the next sync).
    taken: [datafeed.max_items * 2]u32 = undefined,
    n_taken: usize = 0,
    captions: [datafeed.max_items][48]u8 = undefined,
    items: [datafeed.max_items]frame.DataItem = undefined,
    summary_buf: [48]u8 = undefined,

    pub fn deinit(d: *DataView, gpa: std.mem.Allocator) void {
        d.store.blobs.deinit(gpa);
        d.feed.deinit(gpa);
    }

    pub fn visible(d: *const DataView) bool {
        return d.shown;
    }

    fn wasTaken(d: *const DataView, id: u32) bool {
        for (d.taken[0..d.n_taken]) |t| if (t == id) return true;
        return false;
    }

    fn take(d: *DataView, id: u32) void {
        if (d.n_taken == d.taken.len) {
            std.mem.copyForwards(u32, d.taken[0 .. d.taken.len - 1], d.taken[1..]);
            d.n_taken -= 1;
        }
        d.taken[d.n_taken] = id;
        d.n_taken += 1;
    }

    /// Picks up new blobs from the terminal's store. Under the lock that
    /// guards `grid`. True if the feed changed.
    pub fn sync(d: *DataView, gpa: std.mem.Allocator, grid: *const Images) bool {
        if (grid.generation == d.seen_gen) return false;
        d.seen_gen = grid.generation;
        var changed = false;
        for (grid.blobs.items) |b| {
            if (d.feed.find(.image, b.id) != null or d.wasTaken(b.id)) continue;
            d.take(b.id);
            const size = pngSize(b.png);
            _ = d.feed.add(gpa, .image, b.id, size[0], size[1], d.visible()) catch continue;
            changed = true;
            const copy = gpa.dupe(u8, b.png) catch continue;
            _ = d.feed.attach(gpa, .image, b.id, .{ .png = copy }, max_png_bytes);
        }
        if (changed) d.rebuildStore(gpa);
        return changed;
    }

    fn rebuildStore(d: *DataView, gpa: std.mem.Allocator) void {
        d.store.blobs.clearRetainingCapacity();
        for (d.feed.items.items) |it| if (it.data) |p| {
            d.store.blobs.append(gpa, .{ .id = it.seq | store_tag, .png = p.png }) catch {};
        };
        d.store.generation +%= 1;
    }

    /// F2 / the header's Hide and Show.
    pub fn toggle(d: *DataView) void {
        d.shown = !d.shown;
        if (d.visible()) d.feed.seen();
    }

    /// The header's Clear: the slice shrinks back to its strip.
    pub fn clear(d: *DataView, gpa: std.mem.Allocator) void {
        d.feed.clear(gpa);
        d.rebuildStore(gpa);
    }

    /// The slice for the frame. Slices point into `d`. `toggle_id` and
    /// `clear_id`: the header buttons' ids for InputSink.button.
    pub fn slice(d: *DataView, toggle_id: u32, clear_id: u32) frame.DataSlice {
        const all = d.feed.items.items;
        var out: frame.DataSlice = .{
            .collapsed = !d.shown,
            .toggle = .{ .label = if (d.shown) "Hide (F2)" else "Show (F2)", .id = toggle_id },
            .clear = if (all.len > 0) .{ .label = "Clear", .id = clear_id } else null,
            .images = &d.store,
        };
        if (all.len == 0) {
            out.summary = "\u{00B7} nothing yet";
            return out;
        }
        if (!d.shown and d.feed.unseen > 0) {
            out.summary = std.fmt.bufPrint(&d.summary_buf, "\u{00B7} {d} new", .{d.feed.unseen}) catch "";
            out.summary_tone = .warn;
        } else {
            out.summary = std.fmt.bufPrint(&d.summary_buf, "\u{00B7} {d} image{s}", .{ all.len, if (all.len == 1) "" else "s" }) catch "";
        }
        if (!d.shown) return out;
        var n: usize = 0;
        var i = all.len;
        while (i > 0 and n < d.items.len) {
            i -= 1;
            const it = all[i];
            const cap = if (it.w > 0)
                std.fmt.bufPrint(&d.captions[n], "image {d}\u{00D7}{d}", .{ it.w, it.h }) catch "image"
            else
                "image";
            d.items[n] = .{ .caption = cap, .image = if (it.data != null) it.seq | store_tag else null, .w = it.w, .h = it.h };
            n += 1;
        }
        out.items = d.items[0..n];
        return out;
    }

};

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn testPng(w: u32, h: u32, buf: *[33]u8) []const u8 {
    @memcpy(buf[0..8], "\x89PNG\r\n\x1a\n");
    std.mem.writeInt(u32, buf[8..12], 13, .big);
    @memcpy(buf[12..16], "IHDR");
    std.mem.writeInt(u32, buf[16..20], w, .big);
    std.mem.writeInt(u32, buf[20..24], h, .big);
    @memset(buf[24..], 0);
    return buf;
}

test "blobs from the terminal become items, newest first, tagged in the store" {
    const gpa = testing.allocator;
    var d: DataView = .{};
    defer d.deinit(gpa);
    var grid: Images = .{};
    defer grid.deinit(gpa);
    var b1: [33]u8 = undefined;
    var b2: [33]u8 = undefined;
    // Empty: the header strip says so.
    var sl = d.slice(1, 2);
    try testing.expectEqual(@as(usize, 0), sl.items.len);
    try testing.expectEqualStrings("\u{00B7} nothing yet", sl.summary);
    try testing.expect(sl.clear == null);
    try grid.putBlob(gpa, 5, testPng(64, 32, &b1));
    try testing.expect(d.sync(gpa, &grid));
    try testing.expect(!d.sync(gpa, &grid)); // nothing new
    try grid.putBlob(gpa, 9, testPng(10, 20, &b2));
    try testing.expect(d.sync(gpa, &grid));
    // The terminal dropping a blob (cache rule) does not remove the item.
    try grid.setPlacements(gpa, &.{});
    _ = d.sync(gpa, &grid);
    sl = d.slice(1, 2);
    try testing.expectEqual(@as(usize, 2), sl.items.len);
    try testing.expectEqualStrings("\u{00B7} 2 images", sl.summary);
    try testing.expectEqualStrings("image 10\u{00D7}20", sl.items[0].caption);
    try testing.expectEqualStrings("image 64\u{00D7}32", sl.items[1].caption);
    try testing.expectEqual(@as(u32, 2), sl.clear.?.id);
    const id = sl.items[0].image.?;
    try testing.expect(id & store_tag != 0);
    try testing.expect(sl.images.?.blob(id) != null);
    try testing.expect(sl.images.?.blob(9) == null); // never the terminal's id
    // Clear: back to the strip, and the same blobs do not come back.
    d.clear(gpa);
    grid.generation +%= 1;
    _ = d.sync(gpa, &grid);
    sl = d.slice(1, 2);
    try testing.expectEqual(@as(usize, 0), sl.items.len);
    try testing.expect(sl.images.?.blob(id) == null);
}

test "collapsed: the strip counts new items; F2 shows and clears the count" {
    const gpa = testing.allocator;
    var d: DataView = .{};
    defer d.deinit(gpa);
    var grid: Images = .{};
    defer grid.deinit(gpa);
    d.toggle(); // hide
    var b: [33]u8 = undefined;
    try grid.putBlob(gpa, 1, testPng(2, 2, &b));
    _ = d.sync(gpa, &grid);
    var sl = d.slice(1, 2);
    try testing.expect(sl.collapsed);
    try testing.expectEqual(@as(usize, 0), sl.items.len);
    try testing.expectEqualStrings("\u{00B7} 1 new", sl.summary);
    try testing.expectEqualStrings("Show (F2)", sl.toggle.?.label);
    d.toggle();
    sl = d.slice(1, 2);
    try testing.expect(!sl.collapsed);
    try testing.expectEqualStrings("\u{00B7} 1 image", sl.summary);
    try testing.expectEqual([2]u32{ 0, 0 }, pngSize("not a png at all, really not one"));
}
