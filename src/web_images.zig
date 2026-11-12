//! Per-viewer inline-image stream (docs/protocol.md, 'I' and 'P' frames).
//!
//! Each viewer connection owns one `Sender`. Under the session lock, right
//! after the grid frame is encoded, `collect` looks at the visible screen's
//! placements and queues:
//!   * an 'I' frame (the PNG bytes) for every placed image this viewer
//!     doesn't hold yet, within a per-viewer byte budget (token bucket), so
//!     a flood of images can't starve grid updates;
//!   * a 'P' frame listing the placements whose image the viewer holds,
//!     whenever that list changes.
//! A client may discard every blob not referenced by the latest 'P' frame,
//! and the server assumes it did: `have` is exactly the ids of the last
//! 'P' sent, so a blob needed again later (e.g. after leaving the
//! alternate screen) is simply sent again.
//!
//! Only images a program in the session emitted exist here, and they only
//! go to authenticated viewers of that session; there is no request a
//! client can make for an image (or anything else from disk).

const std = @import("std");
const Allocator = std.mem.Allocator;
const vt = @import("vt.zig");
const gfx = vt.gfx;

const Bucket = @import("bucket.zig").Bucket;

/// Token bucket: up to `burst` bytes at once (one maximum-size image),
/// refilled at `rate_per_s`.
pub const burst: i64 = 8 << 20;
pub const rate_per_s: i64 = 4 << 20;

pub const Sender = struct {
    /// Ids the viewer holds: those listed in the last 'P' frame.
    have: std.ArrayList(u32) = .empty,
    last_p: std.ArrayList(u8) = .empty,
    sent_gen: ?u64 = null,
    budget: Bucket = .init(rate_per_s, burst),
    /// Frames queued by `collect`, back to back; `ends` marks each one.
    out: std.ArrayList(u8) = .empty,
    ends: std.ArrayList(usize) = .empty,
    /// Some placed image still has to be sent (budget): call again soon.
    pending: bool = false,
    /// While `pending`: milliseconds (from the last `collect`) until the
    /// budget allows the smallest waiting blob. The writer sleeps exactly
    /// that long instead of re-checking on a timer. Null when nothing
    /// waits.
    wait_ms: ?i64 = null,
    scratch: std.ArrayList(u32) = .empty,

    pub fn deinit(s: *Sender, gpa: Allocator) void {
        s.have.deinit(gpa);
        s.last_p.deinit(gpa);
        s.out.deinit(gpa);
        s.ends.deinit(gpa);
        s.scratch.deinit(gpa);
    }

    /// The queued frames, in order.
    pub fn frames(s: *const Sender) FrameIter {
        return .{ .s = s };
    }

    pub const FrameIter = struct {
        s: *const Sender,
        i: usize = 0,
        pub fn next(it: *FrameIter) ?[]const u8 {
            if (it.i >= it.s.ends.items.len) return null;
            const start = if (it.i == 0) 0 else it.s.ends.items[it.i - 1];
            const end = it.s.ends.items[it.i];
            it.i += 1;
            return it.s.out.items[start..end];
        }
    };

    fn holds(list: []const u32, id: u32) bool {
        return std.mem.indexOfScalar(u32, list, id) != null;
    }

    /// Call with the session lock held. Fills `frames()` (possibly empty).
    pub fn collect(s: *Sender, gpa: Allocator, term: *const vt.Terminal, now_ms: i64) !void {
        s.out.clearRetainingCapacity();
        s.ends.clearRetainingCapacity();
        s.budget.refill(now_ms);

        const gen = term.imagesGen();
        if (!s.pending and s.sent_gen != null and s.sent_gen.? == gen) return;
        s.sent_gen = gen;
        s.pending = false;
        s.wait_ms = null;

        // Ids the next 'P' may reference: already held, or sent now.
        s.scratch.clearRetainingCapacity();
        const list = term.placements();
        for (list) |p| {
            if (holds(s.scratch.items, p.image)) continue;
            if (holds(s.have.items, p.image)) {
                try s.scratch.append(gpa, p.image);
                continue;
            }
            const png = term.imagePng(p.image) orelse continue;
            const size: i64 = @intCast(png.len);
            if (!s.budget.has(size)) {
                // Never sendable (larger than the whole budget): skip it.
                const ms = s.budget.msUntil(size) orelse continue;
                s.pending = true;
                s.wait_ms = @min(s.wait_ms orelse ms, ms);
                continue;
            }
            try gfx.appendBlobFrame(&s.out, gpa, p.image, png);
            try s.ends.append(gpa, s.out.items.len);
            _ = s.budget.take(size);
            try s.scratch.append(gpa, p.image);
        }

        const p_start = s.out.items.len;
        try gfx.appendPlacementFrame(&s.out, gpa, list, @as([]const u32, s.scratch.items), holds);
        const p_frame = s.out.items[p_start..];
        const new_blobs = s.ends.items.len > 0;
        const none_yet = s.last_p.items.len == 0 and p_frame.len == 3; // viewers start with no placements
        if (!new_blobs and (none_yet or std.mem.eql(u8, p_frame, s.last_p.items))) {
            s.out.shrinkRetainingCapacity(p_start); // nothing new to say
        } else {
            try s.ends.append(gpa, s.out.items.len);
            s.last_p.clearRetainingCapacity();
            try s.last_p.appendSlice(gpa, p_frame);
        }
        // The viewer now holds exactly what the last 'P' lists.
        s.have.clearRetainingCapacity();
        for (list) |p| {
            if (holds(s.scratch.items, p.image) and !holds(s.have.items, p.image)) try s.have.append(gpa, p.image);
        }
    }
};

const testing = std.testing;
const imgcheck = @import("imgcheck");

fn showImage(t: *vt.Terminal, w: u32, h: u32, keys: []const u8) !void {
    const gpa = testing.allocator;
    const png = try imgcheck.testImage(gpa, w, h);
    defer gpa.free(png);
    const b64 = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(png.len));
    defer gpa.free(b64);
    _ = std.base64.standard.Encoder.encode(b64, png);
    var seq: std.ArrayList(u8) = .empty;
    defer seq.deinit(gpa);
    try seq.print(gpa, "\x1b_G{s};{s}\x1b\\", .{ keys, b64 });
    t.feed(seq.items);
}

fn countFrames(s: *const Sender, kind: u8) usize {
    var it = s.frames();
    var n: usize = 0;
    while (it.next()) |f| {
        if (f[0] == kind) n += 1;
    }
    return n;
}

test "blobs once per viewer, placements on change, resend after drop" {
    const gpa = testing.allocator;
    var t = try vt.Terminal.init(gpa, 40, 10);
    defer t.deinit();
    var s: Sender = .{};
    defer s.deinit(gpa);
    try s.collect(gpa, &t, 0);
    try testing.expectEqual(@as(usize, 0), s.ends.items.len); // no images: no frames
    try s.collect(gpa, &t, 10);
    try testing.expectEqual(@as(usize, 0), s.ends.items.len);

    try showImage(&t, 20, 20, "a=T,f=100,i=1,C=1");
    try s.collect(gpa, &t, 20);
    try testing.expectEqual(@as(usize, 1), countFrames(&s, 'I'));
    try testing.expectEqual(@as(usize, 1), countFrames(&s, 'P'));
    // Same image placed again: a new 'P', no new blob.
    t.feed("\x1b[5;5H\x1b_Ga=p,i=1,C=1\x1b\\");
    try s.collect(gpa, &t, 30);
    try testing.expectEqual(@as(usize, 0), countFrames(&s, 'I'));
    try testing.expectEqual(@as(usize, 1), countFrames(&s, 'P'));
    // Unchanged: nothing.
    try s.collect(gpa, &t, 40);
    try testing.expectEqual(@as(usize, 0), s.ends.items.len);
    // Alt screen: empty 'P' (the viewer may drop the blob) ...
    t.feed("\x1b[?1049h");
    try s.collect(gpa, &t, 50);
    try testing.expectEqual(@as(usize, 1), countFrames(&s, 'P'));
    try testing.expectEqual(@as(usize, 0), s.have.items.len);
    // ... so coming back sends the blob again.
    t.feed("\x1b[?1049l");
    try s.collect(gpa, &t, 60);
    try testing.expectEqual(@as(usize, 1), countFrames(&s, 'I'));
}

test "byte budget defers blobs instead of starving the grid" {
    const gpa = testing.allocator;
    var t = try vt.Terminal.init(gpa, 40, 10);
    defer t.deinit();
    var s: Sender = .{};
    defer s.deinit(gpa);
    s.budget.level_m = 100 * 1000; // almost nothing left
    s.budget.last_ms = 0;
    try showImage(&t, 50, 50, "a=T,f=100,C=1");
    try s.collect(gpa, &t, 0);
    try testing.expectEqual(@as(usize, 0), countFrames(&s, 'I'));
    try testing.expect(s.pending);
    // The writer's wake-up is the exact refill deadline for that blob.
    const png_len: i64 = @intCast(t.imagePng(t.placements()[0].image).?.len);
    try testing.expectEqual(s.budget.msUntil(png_len), s.wait_ms);
    try testing.expect(s.wait_ms.? > 0 and s.wait_ms.? < 1000);
    // Its placement is not announced before its blob.
    var it = s.frames();
    while (it.next()) |f| if (f[0] == 'P') try testing.expectEqual(@as(u8, 0), f[1]);
    // A second later the budget allows it.
    try s.collect(gpa, &t, s.wait_ms.?);
    try testing.expectEqual(@as(usize, 1), countFrames(&s, 'I'));
    try testing.expect(!s.pending);
    try testing.expect(s.wait_ms == null);
}
