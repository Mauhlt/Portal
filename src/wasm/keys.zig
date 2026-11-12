//! Keyboard and answer-bar input → protocol frames (docs/protocol.md §4).
//!
//! Mirrors what the old app.js did, exactly: the browser's `KeyboardEvent.key`
//! string plus modifier bits come in, and a key *name* (`k:<name>`) or, only
//! in `text` mode, typed text (`t:<utf8>`) comes out. `keys` mode can never
//! produce a `t:` frame. The server filters again; this is just so the
//! client never offers what the mode does not accept.

const std = @import("std");
const proto = @import("proto.zig");
pub const Policy = proto.Policy;

pub const Mods = struct {
    shift: bool = false,
    ctrl: bool = false,
    alt: bool = false,
    meta: bool = false,

    /// Bit layout used by the bridge: 1 shift, 2 ctrl, 4 alt, 8 meta.
    pub fn fromBits(bits: u32) Mods {
        return .{ .shift = bits & 1 != 0, .ctrl = bits & 2 != 0, .alt = bits & 4 != 0, .meta = bits & 8 != 0 };
    }
};

pub const Action = union(enum) {
    none,
    /// Send `k:<name>`.
    key: []const u8,
    /// Send `t:<text>` (text mode only).
    text: []const u8,
};

const answer_keys = [_][]const u8{ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "y", "n" };

const text_keys = [_]struct { dom: []const u8, name: []const u8 }{
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

/// Maps a keydown. The returned slices point into static tables or `key`.
pub fn fromKeyboard(policy: Policy, key: []const u8, mods: Mods) Action {
    if (policy == .none or mods.alt or mods.meta) return .none;
    if (std.mem.eql(u8, key, "Enter")) return .{ .key = "enter" };
    if (std.mem.eql(u8, key, "Escape")) return .{ .key = "esc" };
    switch (policy) {
        .none => return .none,
        .text => {
            if (mods.ctrl and (std.mem.eql(u8, key, "c") or std.mem.eql(u8, key, "C"))) return .{ .key = "ctrl-c" };
            if (std.mem.eql(u8, key, "Tab") and mods.shift) return .{ .key = "shift-tab" };
            for (text_keys) |k| if (std.mem.eql(u8, key, k.dom)) return .{ .key = k.name };
            // JS `key.length === 1`: one UTF-16 unit, i.e. a single BMP code point.
            if (!mods.ctrl) if (proto.Utf8Iter.single(key)) |cp| {
                if (cp <= 0xFFFF) return .{ .text = key };
            };
            return .none;
        },
        .keys => {
            if (mods.ctrl or key.len != 1) return .none;
            const lower = std.ascii.toLower(key[0]);
            for (answer_keys) |name| if (name[0] == lower) return .{ .key = name };
            return .none;
        },
    }
}

/// The answer bar, in display order: label and key name.
pub const Button = struct { label: []const u8, name: []const u8 };
pub const answer_bar = [_]Button{
    .{ .label = "1", .name = "1" },
    .{ .label = "2", .name = "2" },
    .{ .label = "3", .name = "3" },
    .{ .label = "4", .name = "4" },
    .{ .label = "Yes", .name = "y" },
    .{ .label = "No", .name = "n" },
    .{ .label = "Enter", .name = "enter" },
    .{ .label = "Esc", .name = "esc" },
};

/// Formats a frame into `buf`; null if it would not fit.
pub fn frame(buf: []u8, action: Action) ?[]const u8 {
    const prefix: []const u8, const body: []const u8 = switch (action) {
        .none => return null,
        .key => |k| .{ "k:", k },
        .text => |t| .{ "t:", t },
    };
    if (prefix.len + body.len > buf.len) return null;
    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..][0..body.len], body);
    return buf[0 .. prefix.len + body.len];
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
    const m: Mods = .{};
    try expectKey("enter", fromKeyboard(.keys, "Enter", m));
    try expectKey("esc", fromKeyboard(.keys, "Escape", m));
    try expectKey("3", fromKeyboard(.keys, "3", m));
    try expectKey("y", fromKeyboard(.keys, "Y", .{ .shift = true }));
    try expectKey("n", fromKeyboard(.keys, "n", m));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "a", m));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "ArrowUp", m));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "Backspace", m));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "c", .{ .ctrl = true }));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "1", .{ .ctrl = true }));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "Enter", .{ .alt = true }));
    try testing.expectEqual(Action.none, fromKeyboard(.keys, "y", .{ .meta = true }));
    // No input whatsoever produces text in keys mode.
    var prng = std.Random.DefaultPrng.init(7);
    var buf: [6]u8 = undefined;
    for (0..5000) |_| {
        const n = prng.random().uintAtMost(usize, buf.len);
        prng.random().bytes(buf[0..n]);
        const a = fromKeyboard(.keys, buf[0..n], Mods.fromBits(prng.random().int(u4)));
        try testing.expect(a != .text);
    }
}

test "text mode" {
    const m: Mods = .{};
    try expectKey("ctrl-c", fromKeyboard(.text, "c", .{ .ctrl = true }));
    try expectKey("ctrl-c", fromKeyboard(.text, "C", .{ .ctrl = true, .shift = true }));
    try expectKey("shift-tab", fromKeyboard(.text, "Tab", .{ .shift = true }));
    try expectKey("tab", fromKeyboard(.text, "Tab", m));
    try expectKey("up", fromKeyboard(.text, "ArrowUp", m));
    try expectKey("pagedown", fromKeyboard(.text, "PageDown", m));
    try expectKey("delete", fromKeyboard(.text, "Delete", m));
    try expectKey("enter", fromKeyboard(.text, "Enter", m));
    try testing.expectEqualStrings("a", fromKeyboard(.text, "a", m).text);
    try testing.expectEqualStrings("é", fromKeyboard(.text, "é", m).text);
    try testing.expectEqualStrings(" ", fromKeyboard(.text, " ", m).text);
    try testing.expectEqual(Action.none, fromKeyboard(.text, "😀", m)); // two UTF-16 units
    try testing.expectEqual(Action.none, fromKeyboard(.text, "x", .{ .ctrl = true }));
    try testing.expectEqual(Action.none, fromKeyboard(.text, "Shift", m));
    try testing.expectEqual(Action.none, fromKeyboard(.text, "F5", m));
}

test "view only sends nothing" {
    try testing.expectEqual(Action.none, fromKeyboard(.none, "Enter", .{}));
    try testing.expectEqual(Action.none, fromKeyboard(.none, "1", .{}));
}

test "frame formatting" {
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("k:enter", frame(&buf, .{ .key = "enter" }).?);
    try testing.expectEqualStrings("t:ab", frame(&buf, .{ .text = "ab" }).?);
    try testing.expectEqual(@as(?[]const u8, null), frame(&buf, .{ .text = "toolongtext" }));
    try testing.expectEqual(@as(?[]const u8, null), frame(&buf, .none));
}
