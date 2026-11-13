//! The input box: the native <textarea> under the terminal (so the phone
//! keyboard's dictation mic and Win+H work) and the button row beneath it.
//! What Send does with the text, the answer words and buttons and the
//! refusal texts are shared with the native client (module "inputrules",
//! src/inputrules/send.zig); this file keeps only what is browser-specific:
//! which keydown sends, and the button ids of index.html.

const std = @import("std");
const rules = @import("inputrules");

pub const Policy = rules.Policy;
pub const Decision = rules.Decision;
pub const Refusal = rules.Refusal;
pub const Tone = rules.Tone;
pub const Note = rules.Note;
pub const max_frame = rules.max_frame;
pub const decide = rules.decide;
pub const refusalText = rules.refusalText;
pub const serverRefusal = rules.serverRefusal;
pub const keyLabel = rules.keyLabel;
pub const placeholder = rules.placeholder;

/// What Send would do with the box's text (the note under the box).
pub fn preview(policy: Policy, text: []const u8, touch: bool, buf: []u8) Note {
    return rules.preview(policy, text, if (touch) .touch else .browser, buf);
}

/// Should this keydown in the box send? Enter without Shift (Ctrl+Enter
/// too), and not while an IME is composing. Mod bits as keys.Mods, plus
/// 16 = composing.
pub fn boxKeySends(key: []const u8, mods: u32) bool {
    if (!std.mem.eql(u8, key, "Enter")) return false;
    return mods & (1 | 4 | 8 | 16) == 0;
}

// ------------------------------------------------------------ the button row

/// The data-btn ids in index.html: the shared answer buttons in order,
/// then Send, then the shared Up/Down buttons (class "menu": shown only
/// while the page has class "menu", rules.showMenuButtons).
pub const Button = enum(u32) { yes, no, one, two, three, esc, enter, send, up, down };

/// The key a button presses (null for Send).
pub fn buttonKey(b: Button) ?[]const u8 {
    const i = @intFromEnum(b);
    if (i < rules.answer_buttons.len) return rules.answer_buttons[i].key;
    const m = i -% (rules.answer_buttons.len + 1);
    return if (m < rules.menu_buttons.len) rules.menu_buttons[m].key else null;
}

/// An Up/Down button (sent only while rules.showMenuButtons).
pub fn isMenuButton(b: Button) bool {
    return b == .up or b == .down;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "box keys and buttons" {
    try testing.expect(boxKeySends("Enter", 0));
    try testing.expect(boxKeySends("Enter", 2)); // Ctrl+Enter
    try testing.expect(!boxKeySends("Enter", 1)); // Shift+Enter: new line
    try testing.expect(!boxKeySends("Enter", 16)); // IME composing
    try testing.expect(!boxKeySends("a", 0));
    try testing.expectEqualStrings("y", buttonKey(.yes).?);
    try testing.expectEqualStrings("3", buttonKey(.three).?);
    try testing.expectEqualStrings("esc", buttonKey(.esc).?);
    try testing.expectEqualStrings("enter", buttonKey(.enter).?);
    try testing.expectEqual(@as(?[]const u8, null), buttonKey(.send));
    // One id per shared answer button, then Send, then Up/Down.
    try testing.expectEqual(rules.answer_buttons.len + 1 + rules.menu_buttons.len, std.enums.values(Button).len);
    for (rules.answer_buttons, 0..) |a, i| try testing.expectEqualStrings(a.key, buttonKey(@enumFromInt(i)).?);
    try testing.expectEqualStrings("up", buttonKey(.up).?);
    try testing.expectEqualStrings("down", buttonKey(.down).?);
    try testing.expect(isMenuButton(.down) and !isMenuButton(.enter));
}

test "preview picks the device's help" {
    var buf: [160]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, preview(.instruct, "", false, &buf).text, "Shift+Enter") != null);
    try testing.expect(std.mem.indexOf(u8, preview(.instruct, "", true, &buf).text, "mic") != null);
}
