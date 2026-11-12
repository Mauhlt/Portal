//! The native client's Data slice (docs/layout-design.md ③): the images
//! the session pushed, newest first, in a column at the right of the
//! window (TermView.DataColumn). The model is the browser's (module
//! "datafeed": bounded history, a badge for what arrived while hidden);
//! here the payload is the PNG bytes, which TermView decodes and scales
//! like the terminal's inline images.
//!
//! Feeding: the UI thread calls `sync` with the grid's image store under
//! the shared lock whenever it draws; every blob not seen before becomes an
//! item. (A blob the server sends and drops again between two frames is
//! missed; the terminal never showed it either.)
//!
//! F2 shows or hides the column. It is drawn only when the window is wide
//! enough (TermView.data_min_window_w); while hidden, new items are counted
//! for the status line.

const std = @import("std");
const datafeed = @import("datafeed");
const view = @import("view");
const TermView = view.TermView;
const Images = view.grid.Images;

/// PNG bytes kept for the column, all items together.
pub const max_png_bytes: usize = 24 << 20;

/// Ids in `store` carry this bit, so TermView's decoded entries for the
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
    /// The column's image store for TermView: non-owning views of the
    /// feed's PNG bytes under tagged ids (rebuilt when the feed changes;
    /// only `blobs.deinit` is ever called on it).
    store: Images = .{},
    /// The user's choice (F2).
    shown: bool = true,
    /// Whether the last frame could draw the column (window wide enough).
    fits: bool = true,
    seen_gen: u64 = std.math.maxInt(u64),
    captions: [datafeed.max_items][48]u8 = undefined,
    items: [datafeed.max_items]TermView.DataItem = undefined,
    hint_buf: [48]u8 = undefined,

    pub fn deinit(d: *DataView, gpa: std.mem.Allocator) void {
        d.store.blobs.deinit(gpa);
        d.feed.deinit(gpa);
    }

    pub fn visible(d: *const DataView) bool {
        return d.shown and d.fits;
    }

    /// Picks up new blobs from the terminal's store. Under the lock that
    /// guards `grid`. True if the feed changed.
    pub fn sync(d: *DataView, gpa: std.mem.Allocator, grid: *const Images) bool {
        if (grid.generation == d.seen_gen) return false;
        d.seen_gen = grid.generation;
        var changed = false;
        for (grid.blobs.items) |b| {
            if (d.feed.find(.image, b.id) != null) continue;
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

    /// F2.
    pub fn toggle(d: *DataView) void {
        d.shown = !d.shown;
        if (d.visible()) d.feed.seen();
    }

    /// The window width decided whether the column fits.
    pub fn setFits(d: *DataView, fits: bool) void {
        d.fits = fits;
        if (d.visible()) d.feed.seen();
    }

    /// The column for TermView (null while hidden). Slices point into `d`.
    pub fn column(d: *DataView) ?TermView.DataColumn {
        if (!d.shown) return null;
        const all = d.feed.items.items;
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
        return .{ .hint = "F2 hides", .items = d.items[0..n], .images = &d.store };
    }

    /// Status-line note while hidden with new items ("" otherwise).
    pub fn badge(d: *DataView) []const u8 {
        if (d.visible() or d.feed.unseen == 0) return "";
        return std.fmt.bufPrint(&d.hint_buf, "{d} new in Data{s}", .{ d.feed.unseen, if (d.shown) " (window too narrow)" else " (F2)" }) catch "";
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
    try grid.putBlob(gpa, 5, testPng(64, 32, &b1));
    try testing.expect(d.sync(gpa, &grid));
    try testing.expect(!d.sync(gpa, &grid)); // nothing new
    try grid.putBlob(gpa, 9, testPng(10, 20, &b2));
    try testing.expect(d.sync(gpa, &grid));
    // The terminal dropping a blob (cache rule) does not remove the item.
    try grid.setPlacements(gpa, &.{});
    _ = d.sync(gpa, &grid);
    const col = d.column().?;
    try testing.expectEqual(@as(usize, 2), col.items.len);
    try testing.expectEqualStrings("image 10\u{00D7}20", col.items[0].caption);
    try testing.expectEqualStrings("image 64\u{00D7}32", col.items[1].caption);
    const id = col.items[0].image.?;
    try testing.expect(id & store_tag != 0);
    try testing.expect(col.images.?.blob(id) != null);
    try testing.expect(col.images.?.blob(9) == null); // never the terminal's id
}

test "hidden: badge counts new items; F2 shows and clears it" {
    const gpa = testing.allocator;
    var d: DataView = .{};
    defer d.deinit(gpa);
    var grid: Images = .{};
    defer grid.deinit(gpa);
    d.toggle(); // hide
    try testing.expect(d.column() == null);
    var b: [33]u8 = undefined;
    try grid.putBlob(gpa, 1, testPng(2, 2, &b));
    _ = d.sync(gpa, &grid);
    try testing.expectEqualStrings("1 new in Data (F2)", d.badge());
    d.toggle();
    try testing.expectEqualStrings("", d.badge());
    d.setFits(false);
    try grid.putBlob(gpa, 2, testPng(2, 2, &b));
    _ = d.sync(gpa, &grid);
    try testing.expectEqualStrings("1 new in Data (window too narrow)", d.badge());
    try testing.expectEqual([2]u32{ 0, 0 }, pngSize("not a png at all, really not one"));
}
