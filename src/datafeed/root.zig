//! Module "datafeed": the Data slice's model (docs/layout-design.md ③),
//! used by the native clients (ui/dataview.zig). A small history of the
//! data the session
//! pushed, newest last, with bounded memory and a badge count for items
//! that arrived while the slice was hidden. Each client keeps what it needs
//! to draw an item as its `Payload` (PNG bytes) and draws it its own way.
//! Pure logic, std only.
//!
//! Today the only kind is an image: every inline image blob the session
//! sends ('I' frames, docs/protocol.md §3) becomes an item. Tables and
//! charts (CSV/JSON) would be further `Kind`s.

const std = @import("std");

pub const Kind = enum { image };

/// Items kept (older ones are dropped first).
pub const max_items = 8;

/// `Payload` must have `fn bytes(Payload) usize` and
/// `fn deinit(Payload, std.mem.Allocator) void`.
pub fn Feed(comptime Payload: type) type {
    return struct {
        const Self = @This();

        pub const Item = struct {
            kind: Kind,
            /// Server id (images: the blob id).
            id: u32,
            /// Arrival order (1, 2, ...).
            seq: u32,
            /// Image size in pixels (0 if unknown).
            w: u32 = 0,
            h: u32 = 0,
            /// What the client draws it from; null until/unless it has it.
            data: ?Payload = null,
        };

        /// Oldest first.
        items: std.ArrayList(Item) = .empty,
        next_seq: u32 = 1,
        /// Items that arrived while the slice was not visible (badge).
        unseen: u32 = 0,
        /// Changed since the client last drew it.
        dirty: bool = true,

        pub fn deinit(f: *Self, gpa: std.mem.Allocator) void {
            for (f.items.items) |it| if (it.data) |d| d.deinit(gpa);
            f.items.deinit(gpa);
            f.* = .{};
        }

        pub fn find(f: *Self, kind: Kind, id: u32) ?*Item {
            for (f.items.items) |*it| if (it.kind == kind and it.id == id) return it;
            return null;
        }

        /// Bytes held by payloads.
        pub fn payloadBytes(f: *const Self) usize {
            var n: usize = 0;
            for (f.items.items) |it| if (it.data) |d| {
                n += d.bytes();
            };
            return n;
        }

        /// Something arrived. `visible`: the slice is on screen (no badge).
        /// An id seen again (a blob re-sent after a cache drop) is not new.
        /// Returns the item, or null if it was already there.
        pub fn add(f: *Self, gpa: std.mem.Allocator, kind: Kind, id: u32, w: u32, h: u32, visible: bool) !?*Item {
            if (f.find(kind, id) != null) return null;
            if (f.items.items.len >= max_items) {
                const old = f.items.orderedRemove(0);
                if (old.data) |d| d.deinit(gpa);
            }
            try f.items.append(gpa, .{ .kind = kind, .id = id, .seq = f.next_seq, .w = w, .h = h });
            f.next_seq +%= 1;
            if (!visible) f.unseen +|= 1;
            f.dirty = true;
            return &f.items.items[f.items.items.len - 1];
        }

        /// Gives item `id` its payload, if it fits in `budget` bytes of
        /// payloads altogether: the oldest payloads are dropped to make
        /// room (their items stay, drawn as placeholders). Takes ownership
        /// of `data` (freed if it is not kept). False if not kept.
        pub fn attach(f: *Self, gpa: std.mem.Allocator, kind: Kind, id: u32, data: Payload, budget: usize) bool {
            const it = f.find(kind, id) orelse {
                data.deinit(gpa);
                return false;
            };
            if (it.data) |old| old.deinit(gpa);
            it.data = null;
            const n = data.bytes();
            var i: usize = 0;
            while (f.payloadBytes() + n > budget and i < f.items.items.len) : (i += 1) {
                if (f.items.items[i].data) |d| {
                    d.deinit(gpa);
                    f.items.items[i].data = null;
                }
            }
            if (f.payloadBytes() + n > budget) {
                data.deinit(gpa);
                return false;
            }
            it.data = data;
            f.dirty = true;
            return true;
        }

        /// The slice became visible: clear the badge.
        pub fn seen(f: *Self) void {
            if (f.unseen != 0) f.dirty = true;
            f.unseen = 0;
        }

        /// The user cleared the slice (its Clear button): every item goes,
        /// and the slice shrinks back to its header strip.
        pub fn clear(f: *Self, gpa: std.mem.Allocator) void {
            for (f.items.items) |it| if (it.data) |d| d.deinit(gpa);
            f.items.clearRetainingCapacity();
            f.unseen = 0;
            f.dirty = true;
        }
    };
}

// ------------------------------------------------------------ slice size

/// Most of the height between the top bar and the interaction slice that
/// an open Data slice takes (the terminal keeps the rest).
pub const max_share: f64 = 0.38;

/// The Data slice's height on every device (docs/layout-design.md): it
/// sits under the terminal as a thin header strip ("Data · nothing yet")
/// and grows when there is something to show, to what its newest items
/// want (`content`, under the header) but at most `max_share` of `avail`
/// (the height the terminal and the Data slice share). Collapsed by the
/// user (F2 / its Hide button) or empty: the header strip only. Units are
/// the caller's (logical or CSS pixels); the result is whole.
pub fn sliceHeight(avail: f64, header: f64, content: f64, collapsed: bool) f64 {
    const room = if (std.math.isFinite(avail)) @max(0, avail) else 0;
    const head = @min(@round(if (std.math.isFinite(header)) @max(0, header) else 0), room);
    if (collapsed or !(content > 0)) return head;
    const cap = @max(head, @floor(room * max_share));
    return @min(@round(head + @min(content, room)), cap);
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

const Bytes = struct {
    b: []u8,
    pub fn bytes(p: Bytes) usize {
        return p.b.len;
    }
    pub fn deinit(p: Bytes, gpa: std.mem.Allocator) void {
        gpa.free(p.b);
    }
};

fn bytesOf(gpa: std.mem.Allocator, n: usize) !Bytes {
    const b = try gpa.alloc(u8, n);
    @memset(b, 1);
    return .{ .b = b };
}

test "new items, badge, duplicates, eviction" {
    const gpa = testing.allocator;
    var f: Feed(Bytes) = .{};
    defer f.deinit(gpa);
    try testing.expect(try f.add(gpa, .image, 7, 40, 20, false) != null);
    try testing.expect(try f.add(gpa, .image, 7, 40, 20, false) == null); // re-sent blob: not new
    try testing.expectEqual(@as(usize, 1), f.items.items.len);
    try testing.expectEqual(@as(u32, 1), f.unseen);
    f.seen();
    _ = try f.add(gpa, .image, 8, 1, 1, true); // visible: no badge
    try testing.expectEqual(@as(u32, 0), f.unseen);
    try testing.expect(f.attach(gpa, .image, 8, try bytesOf(gpa, 4), 100));
    for (0..max_items + 3) |i| _ = try f.add(gpa, .image, 100 + @as(u32, @intCast(i)), 2, 2, false);
    try testing.expectEqual(@as(usize, max_items), f.items.items.len);
    try testing.expectEqual(@as(u32, 100 + max_items + 2), f.items.items[max_items - 1].id);
    try testing.expectEqual(@as(usize, 0), f.payloadBytes()); // evicted with its item
}

test "payloads are bounded, oldest dropped first" {
    const gpa = testing.allocator;
    var f: Feed(Bytes) = .{};
    defer f.deinit(gpa);
    for (1..4) |i| _ = try f.add(gpa, .image, @intCast(i), 1, 1, true);
    try testing.expect(f.attach(gpa, .image, 1, try bytesOf(gpa, 40), 100));
    try testing.expect(f.attach(gpa, .image, 2, try bytesOf(gpa, 40), 100));
    try testing.expect(f.attach(gpa, .image, 3, try bytesOf(gpa, 40), 100)); // drops 1's
    try testing.expect(f.items.items[0].data == null);
    try testing.expect(f.items.items[1].data != null);
    try testing.expect(!f.attach(gpa, .image, 3, try bytesOf(gpa, 200), 100)); // never fits
    try testing.expect(!f.attach(gpa, .image, 99, try bytesOf(gpa, 1), 100)); // unknown id: freed
    try testing.expect(f.payloadBytes() <= 100);
}

test "clear empties the feed and its payloads" {
    const gpa = testing.allocator;
    var f: Feed(Bytes) = .{};
    defer f.deinit(gpa);
    _ = try f.add(gpa, .image, 1, 1, 1, false);
    try testing.expect(f.attach(gpa, .image, 1, try bytesOf(gpa, 8), 100));
    f.dirty = false;
    f.clear(gpa);
    try testing.expectEqual(@as(usize, 0), f.items.items.len);
    try testing.expectEqual(@as(u32, 0), f.unseen);
    try testing.expect(f.dirty);
    // Ids seen before the clear count as new again.
    try testing.expect(try f.add(gpa, .image, 1, 1, 1, true) != null);
}

test "slice height: a header strip, growing with content up to its share" {
    // Empty or collapsed: the header strip only.
    try testing.expectEqual(@as(f64, 28), sliceHeight(600, 28, 0, false));
    try testing.expectEqual(@as(f64, 28), sliceHeight(600, 28, 400, true));
    // A small item: just what it needs.
    try testing.expectEqual(@as(f64, 28 + 90), sliceHeight(600, 28, 90, false));
    // A big one: capped at the share of the room.
    try testing.expectEqual(@floor(600 * max_share), sliceHeight(600, 28, 2000, false));
    // A tiny window never gets less than the header (if it fits at all).
    try testing.expectEqual(@as(f64, 28), sliceHeight(40, 28, 500, false));
    try testing.expectEqual(@as(f64, 10), sliceHeight(10, 28, 500, false));
    // Hostile input stays finite and in range.
    for ([_]f64{ std.math.nan(f64), std.math.inf(f64), -5 }) |x| {
        const h = sliceHeight(x, x, x, false);
        try testing.expect(std.math.isFinite(h) and h >= 0);
    }
}
