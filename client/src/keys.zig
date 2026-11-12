//! Maps local key presses to protocol input frames (docs/protocol.md
//! section 4), filtered by the server's `hello.input` mode. The server
//! filters again; this keeps the client honest and the UI accurate.

const std = @import("std");

pub const Mode = enum {
    /// Before hello, or after the stream ended.
    unknown,
    none,
    keys,
    text,

    pub fn parse(s: []const u8) Mode {
        if (std.mem.eql(u8, s, "none")) return .none;
        if (std.mem.eql(u8, s, "keys")) return .keys;
        if (std.mem.eql(u8, s, "text")) return .text;
        return .none; // unknown value: safest interpretation
    }

    pub fn label(m: Mode) []const u8 {
        return switch (m) {
            .unknown => "",
            .none => "view only",
            .keys => "answer keys",
            .text => "typing allowed",
        };
    }

    pub fn acceptsAnswers(m: Mode) bool {
        return m == .keys or m == .text;
    }
};

const input = @import("view").input;
pub const Key = input.Key;
pub const Mods = input.Mods;


/// Frame for a special (non-text) key, or null if not allowed / not mapped.
pub fn keyFrame(mode: Mode, key: Key, mods: Mods) ?[]const u8 {
    if (mods.alt or mods.super) return null;
    switch (mode) {
        .unknown, .none => return null,
        .keys => return switch (key) {
            .enter => if (mods.ctrl) null else "k:enter",
            .escape => if (mods.ctrl) null else "k:esc",
            else => null,
        },
        .text => {
            if (mods.ctrl) return null;
            return switch (key) {
                .enter => "k:enter",
                .escape => "k:esc",
                .backspace => "k:backspace",
                .tab => if (mods.shift) "k:shift-tab" else "k:tab",
                .up => "k:up",
                .down => "k:down",
                .left => "k:left",
                .right => "k:right",
                .home => "k:home",
                .end => "k:end",
                .page_up => "k:pageup",
                .page_down => "k:pagedown",
                .delete => "k:delete",
            };
        },
    }
}

/// Frame for a typed character. `ctrl` is true when Ctrl was held (only
/// Ctrl+C is meaningful, and only in text mode). `buf` must hold >= 8 bytes.
pub fn charFrame(mode: Mode, cp: u21, mods: Mods, buf: []u8) ?[]const u8 {
    if (mods.alt or mods.super) return null;
    if (mods.ctrl) {
        if (mode == .text and (cp == 'c' or cp == 'C' or cp == 3)) return "k:ctrl-c";
        return null;
    }
    if (cp < 0x20 or cp == 0x7f or (cp >= 0x80 and cp < 0xa0)) return null;
    if (cp >= 0xD800 and cp <= 0xDFFF) return null;
    switch (mode) {
        .unknown, .none => return null,
        .keys => return switch (cp) {
            '0'...'9' => digitFrames[cp - '0'],
            'y', 'Y' => "k:y",
            'n', 'N' => "k:n",
            else => null,
        },
        .text => {
            if (buf.len < 6) return null;
            buf[0] = 't';
            buf[1] = ':';
            const n = std.unicode.utf8Encode(cp, buf[2..]) catch return null;
            return buf[0 .. 2 + n];
        },
    }
}

const digitFrames = [_][]const u8{ "k:0", "k:1", "k:2", "k:3", "k:4", "k:5", "k:6", "k:7", "k:8", "k:9" };

/// Frame for an answer-bar button (`view.input.answers[i].key`), if the
/// mode accepts it.
pub fn answerFrame(mode: Mode, key: []const u8) ?[]const u8 {
    if (!mode.acceptsAnswers()) return null;
    const table = [_][]const u8{ "k:0", "k:1", "k:2", "k:3", "k:4", "k:5", "k:6", "k:7", "k:8", "k:9", "k:y", "k:n", "k:enter", "k:esc" };
    for (table) |f| if (std.mem.eql(u8, f[2..], key)) return f;
    return null;
}

const testing = std.testing;

test "keys mode allows only answers" {
    var b: [8]u8 = undefined;
    try testing.expectEqualStrings("k:1", charFrame(.keys, '1', .{}, &b).?);
    try testing.expectEqualStrings("k:y", charFrame(.keys, 'Y', .{}, &b).?);
    try testing.expectEqualStrings("k:n", charFrame(.keys, 'n', .{}, &b).?);
    try testing.expect(charFrame(.keys, 'a', .{}, &b) == null);
    try testing.expect(charFrame(.keys, 'c', .{ .ctrl = true }, &b) == null);
    try testing.expectEqualStrings("k:enter", keyFrame(.keys, .enter, .{}).?);
    try testing.expectEqualStrings("k:esc", keyFrame(.keys, .escape, .{}).?);
    try testing.expect(keyFrame(.keys, .up, .{}) == null);
    try testing.expect(keyFrame(.keys, .backspace, .{}) == null);
}

test "text mode" {
    var b: [8]u8 = undefined;
    try testing.expectEqualStrings("t:a", charFrame(.text, 'a', .{}, &b).?);
    try testing.expectEqualStrings("t:\xE4\xB8\xAD", charFrame(.text, 0x4E2D, .{}, &b).?);
    try testing.expectEqualStrings("k:ctrl-c", charFrame(.text, 'c', .{ .ctrl = true }, &b).?);
    try testing.expect(charFrame(.text, 0x08, .{}, &b) == null);
    try testing.expect(charFrame(.text, 0x1b, .{}, &b) == null);
    try testing.expectEqualStrings("k:shift-tab", keyFrame(.text, .tab, .{ .shift = true }).?);
    try testing.expectEqualStrings("k:pagedown", keyFrame(.text, .page_down, .{}).?);
}

test "view only and unknown send nothing" {
    var b: [8]u8 = undefined;
    for ([_]Mode{ .none, .unknown }) |m| {
        try testing.expect(charFrame(m, '1', .{}, &b) == null);
        try testing.expect(keyFrame(m, .enter, .{}) == null);
    }
    try testing.expectEqual(Mode.none, Mode.parse("bogus"));
}

test "answer buttons" {
    try testing.expectEqualStrings("k:y", answerFrame(.keys, "y").?);
    try testing.expectEqualStrings("k:enter", answerFrame(.text, "enter").?);
    try testing.expect(answerFrame(.none, "1") == null);
    try testing.expect(answerFrame(.keys, "rm -rf") == null);
    for (input.answers) |a| try testing.expect(answerFrame(.keys, a.key) != null);
}
