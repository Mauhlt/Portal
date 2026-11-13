//! The conversation a device shows (shared/convo.zig on the wire): the
//! items of the tab shown, kept by the client from `convo` snapshots and
//! `convo+` updates, for the main slice's Conversation view (drawn by a
//! follow-up as a frame.ContentView). Owns copies of everything it keeps;
//! bounded by the protocol's limits.

const std = @import("std");
const wire = @import("shared").convo;

pub const Item = wire.Item;
pub const Kind = wire.Kind;

pub const Conversation = struct {
    /// The tab these items belong to (null: none yet).
    id: ?wire.Id = null,
    /// The tab has a transcript (snapshot `on`).
    on: bool = false,
    items: std.ArrayList(Item) = .empty,
    /// Bumped on every change (redraw detection).
    generation: u64 = 0,

    pub fn deinit(c: *Conversation, gpa: std.mem.Allocator) void {
        c.clear(gpa);
        c.items.deinit(gpa);
        c.* = .{};
    }

    fn clear(c: *Conversation, gpa: std.mem.Allocator) void {
        for (c.items.items) |it| freeItem(gpa, it);
        c.items.clearRetainingCapacity();
    }

    fn freeItem(gpa: std.mem.Allocator, it: Item) void {
        gpa.free(it.text);
        for (it.options) |o| {
            gpa.free(o.label);
            gpa.free(o.key);
        }
        gpa.free(it.options);
    }

    fn copyItem(gpa: std.mem.Allocator, it: Item) !Item {
        const text = try gpa.dupe(u8, it.text);
        errdefer gpa.free(text);
        const opts = try gpa.alloc(wire.Option, it.options.len);
        var n: usize = 0;
        errdefer {
            for (opts[0..n]) |o| {
                gpa.free(o.label);
                gpa.free(o.key);
            }
            gpa.free(opts);
        }
        for (it.options) |o| {
            const label = try gpa.dupe(u8, o.label);
            errdefer gpa.free(label);
            opts[n] = .{ .label = label, .key = try gpa.dupe(u8, o.key) };
            n += 1;
        }
        var out = it;
        out.text = text;
        out.options = opts;
        return out;
    }

    /// Applies a parsed `convo` / `convo+` message (strings are copied).
    /// An update for another tab than the snapshot's is ignored.
    pub fn apply(c: *Conversation, gpa: std.mem.Allocator, m: wire.Message) !void {
        if (m.snapshot) {
            c.clear(gpa);
            c.id = m.id;
            c.on = m.on;
        } else {
            const id = c.id orelse return;
            if (!std.mem.eql(u8, &id, &m.id)) return;
        }
        c.generation +%= 1;
        for (m.items) |it| {
            const at: ?usize = for (c.items.items, 0..) |have, i| {
                if (have.n == it.n) break i;
            } else null;
            if (it.text.len == 0) {
                // A note taken back.
                if (at) |i| freeItem(gpa, c.items.orderedRemove(i));
                continue;
            }
            const copy = try copyItem(gpa, it);
            if (at) |i| {
                freeItem(gpa, c.items.items[i]);
                c.items.items[i] = copy;
                continue;
            }
            if (c.items.items.len >= wire.max_items) freeItem(gpa, c.items.orderedRemove(0));
            c.items.append(gpa, copy) catch |err| {
                freeItem(gpa, copy);
                return err;
            };
        }
    }
};

test "snapshot, update, replace, take back, other tab ignored" {
    const gpa = std.testing.allocator;
    var c: Conversation = .{};
    defer c.deinit(gpa);
    const a: wire.Id = @splat(1);
    var items = [_]Item{
        .{ .n = 1, .kind = .user, .text = "fix the tests" },
        .{ .n = 2, .kind = .question, .text = "Proceed?", .open = true, .options = &.{.{ .label = "Yes", .key = "y" }} },
    };
    try c.apply(gpa, .{ .snapshot = true, .id = a, .items = &items });
    try std.testing.expectEqual(@as(usize, 2), c.items.items.len);
    var upd = [_]Item{
        .{ .n = 2, .kind = .question, .text = "Proceed?", .open = false },
        .{ .n = 3, .kind = .assistant, .text = "Done." },
        .{ .n = 1, .kind = .user, .text = "" },
    };
    try c.apply(gpa, .{ .snapshot = false, .id = a, .items = &upd });
    try std.testing.expectEqual(@as(usize, 2), c.items.items.len);
    try std.testing.expect(!c.items.items[0].open);
    try std.testing.expectEqualStrings("Done.", c.items.items[1].text);
    try c.apply(gpa, .{ .snapshot = false, .id = @splat(2), .items = &upd });
    try std.testing.expectEqual(@as(usize, 2), c.items.items.len);
}
