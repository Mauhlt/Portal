//! Maps local key presses to protocol input frames (docs/protocol.md
//! section 4) under the server's `hello.input` policy. Translation only:
//! which keys are allowed in which mode is the shared rule (module
//! "inputrules", the same tables the server and the browser client use).
//! The server filters again; this keeps the client honest and the UI
//! accurate.

const std = @import("std");
const rules = @import("inputrules");
const input = @import("portal_ui").input;
pub const Policy = rules.Policy;
pub const Key = input.Key;
pub const Mods = input.Mods;

/// The policy from hello's `input`; an unknown value is the safest one.
pub fn parsePolicy(s: []const u8) Policy {
    return Policy.parse(s) orelse .none;
}

/// Status-line text for a policy (null: before hello).
pub fn label(p: ?Policy) []const u8 {
    return if (p) |q| q.label() else "";
}

fn mods(m: Mods) rules.Mods {
    return .{ .shift = m.shift, .ctrl = m.ctrl, .alt = m.alt, .meta = m.super };
}

/// The protocol name of a special key (null: not in the protocol).
pub fn keyName(key: Key) ?[]const u8 {
    return switch (key) {
        .enter => "enter",
        .escape => "esc",
        .backspace => "backspace",
        .tab => "tab",
        .up => "up",
        .down => "down",
        .left => "left",
        .right => "right",
        .home => "home",
        .end => "end",
        .page_up => "pageup",
        .page_down => "pagedown",
        .delete => "delete",
        .insert, .f1, .f2, .f3, .f4, .f5, .f6, .f7, .f8, .f9, .f10, .f11, .f12 => null,
    };
}

/// Frame for a special key at the terminal, or null if not allowed.
/// `buf` must hold >= 16 bytes.
pub fn keyFrame(policy: ?Policy, key: Key, m: Mods, buf: []u8) ?[]const u8 {
    return keyFrameAt(policy, false, key, m, buf);
}

/// `keyFrame`, knowing whether the shown tab's program waits for an
/// answer (Shell.waiting): instruct mode then sends Up/Down too.
pub fn keyFrameAt(policy: ?Policy, waiting: bool, key: Key, m: Mods, buf: []u8) ?[]const u8 {
    const p = policy orelse return null;
    const name = keyName(key) orelse return null;
    return rules.frame(buf, rules.specialAt(p, waiting, name, mods(m)));
}

/// Frame for a typed character at the terminal, or null. `buf` must hold
/// >= 8 bytes.
pub fn charFrame(policy: ?Policy, cp: u21, m: Mods, buf: []u8) ?[]const u8 {
    const p = policy orelse return null;
    var enc: [4]u8 = undefined;
    return rules.frame(buf, rules.char(p, cp, mods(m), &enc));
}

/// Frame for an answer button (`rules.answer_buttons[i].key`), if the
/// policy accepts it.
pub fn answerFrame(policy: ?Policy, key: []const u8, buf: []u8) ?[]const u8 {
    return answerFrameAt(policy, false, key, buf);
}

/// `answerFrame`, knowing whether the shown tab's program waits for an
/// answer: the Up/Down buttons (`rules.menu_buttons`) then send too, in
/// instruct mode.
pub fn answerFrameAt(policy: ?Policy, waiting: bool, key: []const u8, buf: []u8) ?[]const u8 {
    const p = policy orelse return null;
    if (!p.acceptsAnswers()) return null;
    for (&rules.answer_keys) |*k| if (std.mem.eql(u8, k.name, key)) return rules.frame(buf, .{ .key = k.name });
    if (rules.showMenuButtons(p, waiting)) for (&rules.menu_keys) |*k| if (std.mem.eql(u8, k.name, key)) return rules.frame(buf, .{ .key = k.name });
    return null;
}

const testing = std.testing;

test "keys mode allows only answers" {
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings("k:1", charFrame(.keys, '1', .{}, &b).?);
    try testing.expectEqualStrings("k:y", charFrame(.keys, 'Y', .{}, &b).?);
    try testing.expectEqualStrings("k:n", charFrame(.keys, 'n', .{}, &b).?);
    try testing.expect(charFrame(.keys, 'a', .{}, &b) == null);
    try testing.expect(charFrame(.keys, 'c', .{ .ctrl = true }, &b) == null);
    try testing.expectEqualStrings("k:enter", keyFrame(.keys, .enter, .{}, &b).?);
    try testing.expectEqualStrings("k:esc", keyFrame(.keys, .escape, .{}, &b).?);
    try testing.expect(keyFrame(.keys, .enter, .{ .ctrl = true }, &b) == null);
    try testing.expect(keyFrame(.keys, .up, .{}, &b) == null);
    try testing.expect(keyFrame(.keys, .backspace, .{}, &b) == null);
}

test "text mode" {
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings("t:a", charFrame(.text, 'a', .{}, &b).?);
    try testing.expectEqualStrings("t:\xE4\xB8\xAD", charFrame(.text, 0x4E2D, .{}, &b).?);
    try testing.expectEqualStrings("k:ctrl-c", charFrame(.text, 'c', .{ .ctrl = true }, &b).?);
    try testing.expect(charFrame(.text, 0x08, .{}, &b) == null);
    try testing.expect(charFrame(.text, 0x1b, .{}, &b) == null);
    try testing.expectEqualStrings("k:shift-tab", keyFrame(.text, .tab, .{ .shift = true }, &b).?);
    try testing.expectEqualStrings("k:pagedown", keyFrame(.text, .page_down, .{}, &b).?);
    try testing.expect(keyFrame(.text, .f5, .{}, &b) == null);
    try testing.expect(keyFrame(.text, .insert, .{}, &b) == null);
}

test "instruct: the answer keys work (the field takes typing, remote.zig)" {
    var b: [16]u8 = undefined;
    try testing.expectEqual(Policy.instruct, parsePolicy("instruct"));
    try testing.expectEqualStrings("instructions", label(.instruct));
    try testing.expectEqualStrings("k:enter", keyFrame(.instruct, .enter, .{}, &b).?);
    try testing.expectEqualStrings("k:2", charFrame(.instruct, '2', .{}, &b).?);
    try testing.expectEqualStrings("k:y", answerFrame(.instruct, "y", &b).?);
    try testing.expect(keyFrame(.instruct, .up, .{}, &b) == null);
}

test "instruct: Up/Down only while the shown tab waits" {
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings("k:up", keyFrameAt(.instruct, true, .up, .{}, &b).?);
    try testing.expectEqualStrings("k:down", keyFrameAt(.instruct, true, .down, .{}, &b).?);
    try testing.expect(keyFrameAt(.instruct, false, .up, .{}, &b) == null);
    try testing.expect(keyFrameAt(.instruct, true, .left, .{}, &b) == null);
    try testing.expect(keyFrameAt(.keys, true, .up, .{}, &b) == null);
    try testing.expectEqualStrings("k:up", answerFrameAt(.instruct, true, "up", &b).?);
    try testing.expect(answerFrameAt(.instruct, false, "up", &b) == null);
    try testing.expect(answerFrameAt(.keys, true, "down", &b) == null);
    try testing.expect(answerFrameAt(.none, true, "up", &b) == null);
}

test "view only and unknown send nothing" {
    var b: [16]u8 = undefined;
    for ([_]?Policy{ .none, null }) |m| {
        try testing.expect(charFrame(m, '1', .{}, &b) == null);
        try testing.expect(keyFrame(m, .enter, .{}, &b) == null);
        try testing.expect(answerFrame(m, "1", &b) == null);
    }
    try testing.expectEqual(Policy.none, parsePolicy("bogus"));
}

test "answer buttons: the shared list, accepted in every mode with input" {
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings("k:y", answerFrame(.keys, "y", &b).?);
    try testing.expectEqualStrings("k:enter", answerFrame(.text, "enter", &b).?);
    try testing.expect(answerFrame(.keys, "rm -rf", &b) == null);
    try testing.expect(answerFrame(.text, "backspace", &b) == null);
    // The UI draws input.answers: the same buttons as the browser.
    try testing.expectEqual(rules.answer_buttons.len, input.answers.len);
    for (rules.answer_buttons, input.answers) |r, v| {
        try testing.expectEqualStrings(r.label, v.label);
        try testing.expectEqualStrings(r.key, v.key);
        for ([_]Policy{ .keys, .instruct, .text }) |p| try testing.expect(answerFrame(p, v.key, &b) != null);
    }
}
