//! Keyboard input at the terminal → protocol frames (docs/protocol.md §4).
//!
//! Translation only: the browser's `KeyboardEvent.key` string becomes a
//! protocol key name or a character, and the shared rule (module
//! "inputrules", src/inputrules/keys.zig, the same one the native client and
//! the server use) decides what the policy allows. `keys` and `instruct`
//! mode never produce a `t:` frame (instruction lines come from the input
//! box, inputbox.zig). The server filters again.

const std = @import("std");
const rules = @import("inputrules");
const proto = @import("proto.zig");
pub const Policy = rules.Policy;
pub const Action = rules.Action;
pub const Mods = rules.Mods;
pub const frame = rules.frame;

/// Bit layout used by the bridge: 1 shift, 2 ctrl, 4 alt, 8 meta.
pub fn modsFromBits(bits: u32) Mods {
    return .{ .shift = bits & 1 != 0, .ctrl = bits & 2 != 0, .alt = bits & 4 != 0, .meta = bits & 8 != 0 };
}

/// `KeyboardEvent.key` values of the non-character keys, by protocol name.
const dom_keys = [_]struct { dom: []const u8, name: []const u8 }{
    .{ .dom = "Enter", .name = "enter" },
    .{ .dom = "Escape", .name = "esc" },
    .{ .dom = "Backspace", .name = "backspace" },
    .{ .dom = "Tab", .name = "tab" },
    .{ .dom = "ArrowUp", .name = "up" },
    .{ .dom = "ArrowDown", .name = "down" },
    .{ .dom = "ArrowLeft", .name = "left" },
    .{ .dom = "ArrowRight", .name = "right" },
    .{ .dom = "Home", .name = "home" },
    .{ .dom = "End", .name = "end" },
    .{ .dom = "PageUp", .name = "pageup" },
    .{ .dom = "PageDown", .name = "pagedown" },
    .{ .dom = "Delete", .name = "delete" },
};

/// Maps a keydown. Returned slices point into static tables or `buf`.
pub fn fromKeyboard(policy: Policy, key: []const u8, mods: Mods, buf: *[4]u8) Action {
    for (dom_keys) |k| if (std.mem.eql(u8, key, k.dom)) return rules.special(policy, k.name, mods);
    // A character key is one code point ("a", "é"); named keys ("Shift",
    // "F5", "Unidentified") are longer and map to nothing.
    const cp = proto.Utf8Iter.single(key) orelse return .none;
    return rules.char(policy, cp, mods, buf);
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn expectKey(expected: []const u8, a: Action) !void {
    switch (a) {
        .key => |k| try testing.expectEqualStrings(expected, k),
        else => return error.TestExpectedEqual,
    }
}

test "keys mode: answers only, never text" {
    var b: [4]u8 = undefined;
    const m: Mods = .{};
    try expectKey("enter", fromKeyboard(.keys, "Enter", m, &b));
    try expectKey("esc", fromKeyboard(.keys, "Escape", m, &b));
    try expectKey("3", fromKeyboard(.keys, "3", m, &b));
    try expectKey("y", fromKeyboard(.keys, "Y", .{ .shift = true }, &b));
    try expectKey("n", fromKeyboard(.keys, "n", m, &b));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "a", m, &b));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "ArrowUp", m, &b));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "Backspace", m, &b));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "c", .{ .ctrl = true }, &b));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "1", .{ .ctrl = true }, &b));
    // The same rule as the native client: Ctrl+Enter / Ctrl+Esc are not keys.
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "Enter", .{ .ctrl = true }, &b));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "Escape", .{ .ctrl = true }, &b));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "Enter", .{ .alt = true }, &b));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "y", .{ .meta = true }, &b));
    // No input whatsoever produces text in keys mode.
    var prng = std.Random.DefaultPrng.init(7);
    var buf: [6]u8 = undefined;
    for (0..5000) |_| {
        const n = prng.random().uintAtMost(usize, buf.len);
        prng.random().bytes(buf[0..n]);
        const a = fromKeyboard(.keys, buf[0..n], modsFromBits(prng.random().int(u4)), &b);
        try testing.expect(a != .text);
    }
}

test "text mode" {
    var b: [4]u8 = undefined;
    const m: Mods = .{};
    try expectKey("ctrl-c", fromKeyboard(.text, "c", .{ .ctrl = true }, &b));
    try expectKey("ctrl-c", fromKeyboard(.text, "C", .{ .ctrl = true, .shift = true }, &b));
    try expectKey("shift-tab", fromKeyboard(.text, "Tab", .{ .shift = true }, &b));
    try expectKey("tab", fromKeyboard(.text, "Tab", m, &b));
    try expectKey("up", fromKeyboard(.text, "ArrowUp", m, &b));
    try expectKey("pagedown", fromKeyboard(.text, "PageDown", m, &b));
    try expectKey("delete", fromKeyboard(.text, "Delete", m, &b));
    try expectKey("enter", fromKeyboard(.text, "Enter", m, &b));
    try testing.expectEqualStrings("a", fromKeyboard(.text, "a", m, &b).text);
    try testing.expectEqualStrings("\u{e9}", fromKeyboard(.text, "\u{e9}", m, &b).text);
    try testing.expectEqualStrings(" ", fromKeyboard(.text, " ", m, &b).text);
    // Outside the BMP too, as on the native client.
    try testing.expectEqualStrings("\u{1F600}", fromKeyboard(.text, "\u{1F600}", m, &b).text);
    try testing.expectEqual(Action.none, fromKeyboard(.text, "x", .{ .ctrl = true }, &b));
    try testing.expectEqual(Action.none, fromKeyboard(.text, "Enter", .{ .ctrl = true }, &b));
    try testing.expectEqual(Action.none, fromKeyboard(.text, "Shift", m, &b));
    try testing.expectEqual(Action.none, fromKeyboard(.text, "F5", m, &b));
}

test "instruct mode: the terminal takes answer keys only" {
    var b: [4]u8 = undefined;
    try expectKey("y", fromKeyboard(.instruct, "y", .{}, &b));
    try expectKey("enter", fromKeyboard(.instruct, "Enter", .{}, &b));
    try testing.expectEqual(Action.none, fromKeyboard(.instruct, "a", .{}, &b));
    try testing.expectEqual(Action.none, fromKeyboard(.instruct, "ArrowUp", .{}, &b));
}

test "view only sends nothing" {
    var b: [4]u8 = undefined;
    try testing.expectEqual(Action.none, fromKeyboard(.none, "Enter", .{}, &b));
    try testing.expectEqual(Action.none, fromKeyboard(.none, "1", .{}, &b));
}
