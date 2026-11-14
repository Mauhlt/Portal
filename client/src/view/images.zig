//! The Presenter's inline images: PNG blobs from `grid.Images` are decoded
//! (imgdec: pre-validated, bounded allocator), scaled on the CPU to the
//! exact pixel size they are drawn at, and packed into the image region of
//! the renderer's texture (rows `region_y ..` below the glyph atlas), so
//! the nearest-neighbour sampler draws them 1:1 and the Renderer needs no
//! new code path.
//!
//! Memory: decoded pixels live only until they are uploaded (a zoom or
//! resize decodes again), so CPU memory is transient and GPU memory is the
//! fixed region. At most one decode per frame keeps the UI responsive; the
//! view asks for another frame while decodes are pending. Entries for
//! images no longer placed are dropped every frame.
//!
//! Space: slots are packed into shelves and only reclaimed by a wipe. A
//! wipe is asked for (`full`) only when the region holds stale slots
//! (images no longer drawn, or drawn at another size); when what is on
//! screen does not fit even then, the images left over are drawn as
//! placeholders instead of wiping and decoding again every frame.

const std = @import("std");
const imgdec = @import("imgdec");
const grid_mod = @import("portal_ui").grid;

pub const region_w: u32 = 2048;
pub const region_h: u32 = 2048;
/// The region starts below the 2048-row glyph atlas.
pub const region_y: u32 = 2048;
/// Budget for one decode (decoder scratch + output).
pub const decode_budget: usize = 288 << 20;

const Slot = struct { x: u32, y: u32, w: u32, h: u32 };
const Shelf = struct { y: u32, h: u32, x: u32 };

const Entry = struct {
    id: u32,
    failed: bool = false,
    /// Pixel size from the PNG header (for placeholders).
    dims: [2]u32 = .{ 0, 0 },
    slot: ?Slot = null,
    seen: bool = true,
    /// Did not fit in a region without stale slots: a placeholder until
    /// space may have been freed (`Layer.stale`).
    no_room: bool = false,
};

pub const Upload = struct { x: u32, y: u32, w: u32, h: u32, px: []u8 };

pub const Prepared = union(enum) {
    /// Draw with these texture coordinates.
    image: [4]f32,
    /// Couldn't decode: draw a box (PNG size, 0 x 0 if unknown).
    placeholder: [2]u32,
    /// Not ready yet (decode pending or no blob): draw nothing this frame.
    none,
};

pub const Layer = struct {
    gpa: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    shelves: std.ArrayList(Shelf) = .empty,
    next_y: u32 = 0,
    uploads: std.ArrayList(Upload) = .empty,
    /// The region ran out of space this frame, and a wipe would free
    /// some: wipe and rebuild.
    full: bool = false,
    /// The region holds slots no entry uses any more (since the last
    /// wipe).
    stale: bool = false,
    /// A decode was deferred: another frame is needed.
    needs_more: bool = false,
    decodes_left: u32 = 1,

    pub fn init(gpa: std.mem.Allocator) Layer {
        return .{ .gpa = gpa };
    }

    pub fn deinit(l: *Layer) void {
        l.clearUploads();
        l.uploads.deinit(l.gpa);
        l.entries.deinit(l.gpa);
        l.shelves.deinit(l.gpa);
    }

    pub fn clearUploads(l: *Layer) void {
        for (l.uploads.items) |u| l.gpa.free(u.px);
        l.uploads.clearRetainingCapacity();
    }

    /// Forgets every slot (the region's pixels are stale afterwards).
    pub fn wipe(l: *Layer) void {
        l.clearUploads();
        l.shelves.clearRetainingCapacity();
        l.next_y = 0;
        l.stale = false;
        for (l.entries.items) |*e| {
            e.slot = null;
            e.no_room = false;
        }
    }

    pub fn begin(l: *Layer) void {
        for (l.entries.items) |*e| e.seen = false;
        l.decodes_left = 1;
        l.needs_more = false;
        l.full = false;
    }

    /// Drops entries not drawn this frame. Their region space is reclaimed
    /// at the next wipe.
    pub fn end(l: *Layer) void {
        var k: usize = 0;
        while (k < l.entries.items.len) {
            if (l.entries.items[k].seen) {
                k += 1;
            } else {
                if (l.entries.items[k].slot != null) l.stale = true;
                _ = l.entries.swapRemove(k);
            }
        }
    }

    fn entry(l: *Layer, id: u32) ?*Entry {
        for (l.entries.items) |*e| if (e.id == id) return e;
        l.entries.append(l.gpa, .{ .id = id }) catch return null;
        return &l.entries.items[l.entries.items.len - 1];
    }

    fn alloc(l: *Layer, w: u32, h: u32) ?Slot {
        if (w > region_w or h > region_h) return null;
        for (l.shelves.items) |*s| {
            if (h <= s.h and h * 4 >= s.h * 3 and s.x + w <= region_w) {
                const slot: Slot = .{ .x = s.x, .y = s.y, .w = w, .h = h };
                s.x += w + 1;
                return slot;
            }
        }
        if (l.next_y + h > region_h) return null;
        l.shelves.append(l.gpa, .{ .y = l.next_y, .h = h, .x = w + 1 }) catch return null;
        const slot: Slot = .{ .x = 0, .y = l.next_y, .w = w, .h = h };
        l.next_y += h + 1;
        return slot;
    }

    /// Readies image `id` to be drawn `disp_w x disp_h` pixels, in a
    /// texture of `tex_w x tex_h`.
    pub fn prepare(l: *Layer, images: *const grid_mod.Images, id: u32, disp_w: u32, disp_h: u32, tex_w: u32, tex_h: u32) Prepared {
        const png = images.blob(id) orelse return .none;
        const e = l.entry(id) orelse return .none;
        e.seen = true;
        if (e.failed) return .{ .placeholder = e.dims };
        // Drawn at most region-sized; the GPU stretches the rest.
        var tw = @max(disp_w, 1);
        var th = @max(disp_h, 1);
        if (tw > region_w or th > region_h) {
            const f = @min(@as(f32, @floatFromInt(region_w)) / @as(f32, @floatFromInt(tw)), @as(f32, @floatFromInt(region_h)) / @as(f32, @floatFromInt(th)));
            tw = std.math.clamp(@as(u32, @intFromFloat(@as(f32, @floatFromInt(tw)) * f)), 1, region_w);
            th = std.math.clamp(@as(u32, @intFromFloat(@as(f32, @floatFromInt(th)) * f)), 1, region_h);
        }
        const have = if (e.slot) |s| s.w == tw and s.h == th else false;
        if (!have) {
            // Nothing was freed since it last did not fit.
            if (e.no_room and !l.stale) return .{ .placeholder = e.dims };
            if (l.decodes_left == 0) {
                l.needs_more = true;
                return .none;
            }
            l.decodes_left -= 1;
            var src = imgdec.decode(l.gpa, png, .{ .budget = decode_budget, .max_side = 2048 }) catch {
                e.failed = true;
                if (imgdec.imgcheck.header(png)) |info| {
                    e.dims = .{ info.width, info.height };
                } else |_| {}
                return .{ .placeholder = e.dims };
            };
            defer src.deinit(l.gpa);
            e.dims = .{ src.w, src.h };
            const slot = l.alloc(tw, th) orelse {
                if (l.stale) {
                    // A wipe frees space: ask for one.
                    l.full = true;
                    return .none;
                }
                // Does not fit even in a clean region: a box, and no
                // decoding it again every frame.
                e.no_room = true;
                return .{ .placeholder = e.dims };
            };
            // The old slot (another size) is stale from now on.
            if (e.slot != null) l.stale = true;
            e.no_room = false;
            const scaled = imgdec.scale(l.gpa, src, tw, th) catch return .none;
            l.uploads.append(l.gpa, .{ .x = slot.x, .y = slot.y, .w = tw, .h = th, .px = scaled.px }) catch {
                l.gpa.free(scaled.px);
                return .none;
            };
            e.slot = slot;
        }
        const s = e.slot.?;
        const fw: f32 = @floatFromInt(@max(tex_w, 1));
        const fh: f32 = @floatFromInt(@max(tex_h, 1));
        return .{ .image = .{
            @as(f32, @floatFromInt(s.x)) / fw,
            @as(f32, @floatFromInt(region_y + s.y)) / fh,
            @as(f32, @floatFromInt(s.x + s.w)) / fw,
            @as(f32, @floatFromInt(region_y + s.y + s.h)) / fh,
        } };
    }
};

/// Clips the rectangle (x, y, w, h) with texture coords `uv` to the box
/// [cx0, cx1) x [cy0, cy1); null if nothing is left.
pub fn clip(x: f32, y: f32, w: f32, h: f32, uv: [4]f32, cx0: f32, cy0: f32, cx1: f32, cy1: f32) ?struct { rect: [4]f32, uv: [4]f32 } {
    if (!(w > 0 and h > 0)) return null;
    const x0 = @max(x, cx0);
    const y0 = @max(y, cy0);
    const x1 = @min(x + w, cx1);
    const y1 = @min(y + h, cy1);
    if (!(x1 > x0 and y1 > y0)) return null;
    const du = uv[2] - uv[0];
    const dv = uv[3] - uv[1];
    return .{
        .rect = .{ x0, y0, x1 - x0, y1 - y0 },
        .uv = .{
            uv[0] + du * (x0 - x) / w,
            uv[1] + dv * (y0 - y) / h,
            uv[0] + du * (x1 - x) / w,
            uv[1] + dv * (y1 - y) / h,
        },
    };
}

const testing = std.testing;

test "prepare decodes once per frame, uploads, drops unplaced, placeholders" {
    const gpa = testing.allocator;
    var im: grid_mod.Images = .{};
    defer im.deinit(gpa);
    const a = try imgdec.imgcheck.testImage(gpa, 30, 20);
    defer gpa.free(a);
    try im.putBlob(gpa, 1, a);
    try im.putBlob(gpa, 2, a);
    var bad = try gpa.dupe(u8, a);
    defer gpa.free(bad);
    bad[40] ^= 0xff; // CRC now wrong
    try im.putBlob(gpa, 3, bad);

    var l: Layer = .init(gpa);
    defer l.deinit();
    l.begin();
    try testing.expect(l.prepare(&im, 1, 60, 40, 2048, 4096) == .image);
    try testing.expect(l.prepare(&im, 2, 60, 40, 2048, 4096) == .none); // one decode per frame
    try testing.expect(l.needs_more);
    l.end();
    try testing.expectEqual(@as(usize, 1), l.uploads.items.len);
    try testing.expectEqual(@as(u32, 60), l.uploads.items[0].w);
    l.clearUploads();

    l.begin();
    try testing.expect(l.prepare(&im, 1, 60, 40, 2048, 4096) == .image); // cached
    try testing.expect(l.prepare(&im, 2, 60, 40, 2048, 4096) == .image);
    l.end();
    l.begin();
    const p = l.prepare(&im, 3, 10, 10, 2048, 4096);
    try testing.expect(p == .placeholder);
    try testing.expectEqual([2]u32{ 30, 20 }, p.placeholder);
    try testing.expect(l.prepare(&im, 99, 10, 10, 2048, 4096) == .none); // no blob
    l.end();
    try testing.expectEqual(@as(usize, 1), l.entries.items.len); // 1 and 2 not drawn: dropped

    // Huge display sizes are capped to the region. Two images that do not
    // fit together: one is drawn, the other is a placeholder, and nothing
    // is wiped or decoded again frame after frame.
    l.wipe();
    var f: Frames = .{ .l = &l, .im = &im };
    for (0..8) |_| try f.frame(5000, 3000);
    try testing.expectEqual(@as(usize, 0), f.wipes);
    try testing.expect(f.last2 == .placeholder);
    try testing.expectEqual([2]u32{ 30, 20 }, f.last2.placeholder);
    try testing.expect(!l.needs_more);
    const decodes = f.decodes;
    try f.frame(5000, 3000);
    try testing.expectEqual(decodes, f.decodes); // settled: no decoding
    // The first image drawn at another size leaves its old slot stale:
    // one wipe, then settled again.
    for (0..8) |_| try f.frame(1000, 600);
    try testing.expectEqual(@as(usize, 1), f.wipes);
    try testing.expect(f.last1 == .image);
    try testing.expect(f.last2 == .placeholder);
    try testing.expect(!l.needs_more);
}

/// Frames as the Presenter builds them: prepare, and on `full` wipe and
/// prepare again.
const Frames = struct {
    l: *Layer,
    im: *const grid_mod.Images,
    wipes: usize = 0,
    decodes: usize = 0,
    last1: Prepared = .none,
    last2: Prepared = .none,

    fn frame(f: *Frames, w1: u32, h1: u32) !void {
        f.pass(w1, h1);
        if (f.l.full) {
            f.wipes += 1;
            f.l.wipe();
            f.pass(w1, h1);
        }
        f.l.clearUploads();
    }

    fn pass(f: *Frames, w1: u32, h1: u32) void {
        f.l.begin();
        f.last1 = f.l.prepare(f.im, 1, w1, h1, 2048, 4096);
        f.last2 = f.l.prepare(f.im, 2, 1500, 1500, 2048, 4096);
        f.decodes += 1 - f.l.decodes_left;
        f.l.end();
    }
};

test "clip" {
    const r = clip(-10, 0, 20, 10, .{ 0, 0, 1, 1 }, 0, 0, 100, 5).?;
    try testing.expectEqual([4]f32{ 0, 0, 10, 5 }, r.rect);
    try testing.expectEqual([4]f32{ 0.5, 0, 1, 0.5 }, r.uv);
    try testing.expect(clip(200, 0, 20, 10, .{ 0, 0, 1, 1 }, 0, 0, 100, 5) == null);
    try testing.expect(clip(0, 0, std.math.nan(f32), 10, .{ 0, 0, 1, 1 }, 0, 0, 100, 5) == null);
}
