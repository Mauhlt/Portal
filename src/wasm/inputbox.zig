//! The input box: the native <textarea> under the terminal (so the phone
//! keyboard's dictation mic and Win+H work), the button row beneath it, and
//! what Send does with the box's text. Pure logic, no state; main.zig calls
//! it, and the e2e tests use it to drive a real server the way the page does.
//!
//! Send:
//!   * an answer word ("Yes.", "two", "Escape", "OK") presses that key;
//!   * otherwise, in `instruct` mode, the text becomes an instruction line
//!     (`l:<text>`), checked here with the server's own rules first so a
//!     refusal is shown at once and the text stays in the box;
//!   * in `keys` mode only answer words can be sent;
//!   * in `text` mode the text is typed (`t:`) and Enter pressed.
//! Line breaks (Shift+Enter, dictated "new line") collapse to spaces: an
//! instruction line is one line.

const std = @import("std");
const keymap = @import("keymap");

/// What the server accepts from this viewer (hello's `input`).
pub const Policy = enum { none, keys, instruct, text };

// ------------------------------------------------------------ answer words

const Word = struct { word: []const u8, key: []const u8 };

/// Spoken or typed answers and the key each presses (docs/protocol.md §4
/// key names). Matched after normalising (see `normalize`).
pub const answer_words = [_]Word{
    .{ .word = "yes", .key = "y" },     .{ .word = "y", .key = "y" },
    .{ .word = "yeah", .key = "y" },    .{ .word = "yep", .key = "y" },
    .{ .word = "no", .key = "n" },      .{ .word = "n", .key = "n" },
    .{ .word = "nope", .key = "n" },    .{ .word = "zero", .key = "0" },
    .{ .word = "one", .key = "1" },     .{ .word = "two", .key = "2" },
    .{ .word = "three", .key = "3" },   .{ .word = "four", .key = "4" },
    .{ .word = "five", .key = "5" },    .{ .word = "six", .key = "6" },
    .{ .word = "seven", .key = "7" },   .{ .word = "eight", .key = "8" },
    .{ .word = "nine", .key = "9" },    .{ .word = "0", .key = "0" },
    .{ .word = "1", .key = "1" },       .{ .word = "2", .key = "2" },
    .{ .word = "3", .key = "3" },       .{ .word = "4", .key = "4" },
    .{ .word = "5", .key = "5" },       .{ .word = "6", .key = "6" },
    .{ .word = "7", .key = "7" },       .{ .word = "8", .key = "8" },
    .{ .word = "9", .key = "9" },       .{ .word = "escape", .key = "esc" },
    .{ .word = "esc", .key = "esc" },   .{ .word = "cancel", .key = "esc" },
    .{ .word = "enter", .key = "enter" }, .{ .word = "ok", .key = "enter" },
    .{ .word = "okay", .key = "enter" }, .{ .word = "o.k", .key = "enter" },
};

/// "option two", "number 3": a digit answer said with a lead-in word.
const digit_prefixes = [_][]const u8{ "option ", "number " };

/// Longest normalised text that can still be an answer word.
const max_word = 24;

fn isSpace(cp: u21) bool {
    return switch (cp) {
        ' ', '\t', '\r', '\n', 0x0B, 0x0C, 0x85, 0xA0, 0x1680, 0x2000...0x200B, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF => true,
        else => false,
    };
}

/// Punctuation dictation (or a person) puts around a single word.
fn isPunct(c: u8) bool {
    return switch (c) {
        '.', ',', '!', '?', ';', ':', '"', '\'', '(', ')', '-', '*' => true,
        else => false,
    };
}

/// Non-ASCII punctuation, mapped to '.' so it is stripped like ASCII.
fn wideMark(cp: u21) bool {
    return switch (cp) {
        0x2026, // …
        0x3002, 0x3001, // 。 、
        0xFF61, // ｡
        0x00A1, 0x00BF, // ¡ ¿
        0x2018, 0x2019, 0x201C, 0x201D, // curly quotes
        0x00AB, 0x00BB, // « »
        => true,
        else => false,
    };
}

/// Case-folds and trims `text` into `buf`: full-width forms (Ｙｅｓ, １) to
/// ASCII, Unicode spaces to one ASCII space, surrounding punctuation
/// dropped. Null if the result cannot be an answer word (non-ASCII
/// letters, too long, invalid UTF-8).
pub fn normalize(text: []const u8, buf: *[max_word]u8) ?[]const u8 {
    if (text.len > 4 * max_word + 64) return null;
    const view = std.unicode.Utf8View.init(text) catch return null;
    var it = view.iterator();
    var n: usize = 0;
    var space = false;
    while (it.nextCodepoint()) |cp0| {
        var cp = cp0;
        if (cp >= 0xFF01 and cp <= 0xFF5E) cp -= 0xFEE0; // full-width ASCII
        if (isSpace(cp)) {
            space = n > 0;
            continue;
        }
        if (wideMark(cp)) cp = '.';
        if (cp >= 0x80 or cp < 0x20 or cp == 0x7f) return null;
        if (space) {
            if (n >= max_word) return null;
            buf[n] = ' ';
            n += 1;
            space = false;
        }
        if (n >= max_word) return null;
        buf[n] = std.ascii.toLower(@intCast(cp));
        n += 1;
    }
    var s: []const u8 = buf[0..n];
    // Surrounding punctuation and the blanks next to it: "Yes.", "¿no?",
    // "\"okay\"", "yes !".
    while (s.len > 0 and (isPunct(s[s.len - 1]) or s[s.len - 1] == ' ')) s = s[0 .. s.len - 1];
    while (s.len > 0 and (isPunct(s[0]) or s[0] == ' ')) s = s[1..];
    return s;
}

/// The key an answer word presses, or null if `text` is not one.
pub fn answerKey(text: []const u8) ?[]const u8 {
    var buf: [max_word]u8 = undefined;
    var w = normalize(text, &buf) orelse return null;
    if (w.len == 0) return null;
    var digit_only = false;
    for (digit_prefixes) |p| if (std.mem.startsWith(u8, w, p)) {
        w = w[p.len..];
        digit_only = true;
        break;
    };
    for (answer_words) |e| if (std.mem.eql(u8, e.word, w)) {
        if (digit_only and !(e.key.len == 1 and std.ascii.isDigit(e.key[0]))) return null;
        return e.key;
    };
    return null;
}

/// Short label for a key name, as on the buttons ("y" → "Yes").
pub fn keyLabel(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "y")) return "Yes";
    if (std.mem.eql(u8, name, "n")) return "No";
    if (std.mem.eql(u8, name, "esc")) return "Esc";
    if (std.mem.eql(u8, name, "enter")) return "Enter";
    return name;
}

// ------------------------------------------------------------ send decision

pub const Refusal = enum {
    empty,
    answers_only,
    offline,
    too_long,
    invalid_utf8,
    control_character,
    shell_escape,
    slash_command,
    memory_shortcut,
};

pub const Decision = union(enum) {
    /// View only: the box is hidden and Send does nothing.
    nothing,
    /// Press `k:<name>`, then clear the box.
    key: []const u8,
    /// Send `l:<line>`, then clear the box.
    line: []const u8,
    /// Text mode: send `t:<text>` and `k:enter`, then clear the box.
    typed: []const u8,
    /// Don't send; show why and keep the text.
    refuse: Refusal,
};

/// Largest client frame (docs/protocol.md §4).
pub const max_frame = 4096;

/// Replaces each run of line breaks and tabs (CR, LF, TAB, VT, FF, NEL,
/// U+2028/9) with one space and trims blanks. `out.len >= in.len`.
pub fn collapse(in: []const u8, out: []u8) []const u8 {
    std.debug.assert(out.len >= in.len);
    var n: usize = 0;
    var i: usize = 0;
    var gap = false;
    while (i < in.len) {
        const c = in[i];
        var brk: usize = 0;
        if (c == '\r' or c == '\n' or c == '\t' or c == 0x0B or c == 0x0C) {
            brk = 1;
        } else if (c == 0xC2 and i + 1 < in.len and in[i + 1] == 0x85) {
            brk = 2;
        } else if (c == 0xE2 and i + 2 < in.len and in[i + 1] == 0x80 and (in[i + 2] == 0xA8 or in[i + 2] == 0xA9)) {
            brk = 3;
        }
        if (brk > 0) {
            gap = true;
            i += brk;
            continue;
        }
        if (gap) {
            // Blanks around a break fold into the one space.
            if (c == ' ') {
                i += 1;
                continue;
            }
            if (n > 0 and out[n - 1] != ' ') {
                out[n] = ' ';
                n += 1;
            }
            gap = false;
        }
        out[n] = c;
        n += 1;
        i += 1;
    }
    return std.mem.trim(u8, out[0..n], " ");
}

fn lineRefusal(err: keymap.LineError) Refusal {
    return switch (err) {
        error.Empty => .empty,
        error.TooLong => .too_long,
        error.InvalidUtf8 => .invalid_utf8,
        error.ControlCharacter => .control_character,
        error.ShellEscape => .shell_escape,
        error.SlashCommand => .slash_command,
        error.MemoryShortcut => .memory_shortcut,
    };
}

/// What Send does with the box's `text` under `policy`. `scratch` holds
/// the collapsed line (`scratch.len >= text.len`); returned slices point
/// into it or into static tables.
pub fn decide(policy: Policy, text: []const u8, scratch: []u8) Decision {
    if (policy == .none) return .nothing;
    if (answerKey(text)) |k| return .{ .key = k };
    const line = collapse(text, scratch);
    if (line.len == 0) return .{ .refuse = .empty };
    switch (policy) {
        .none => unreachable,
        .keys => return .{ .refuse = .answers_only },
        .instruct => {
            const ok = keymap.validateLine(line) catch |err| return .{ .refuse = lineRefusal(err) };
            return .{ .line = ok };
        },
        .text => {
            if (line.len + 2 > max_frame) return .{ .refuse = .too_long };
            if (!std.unicode.utf8ValidateSlice(line)) return .{ .refuse = .invalid_utf8 };
            return .{ .typed = line };
        },
    }
}

pub fn refusalText(r: Refusal) []const u8 {
    return switch (r) {
        .empty => "Type or dictate something first.",
        .answers_only => "Answers only here: yes, no, 1-9, esc, enter.",
        .offline => "Not connected; your text is kept.",
        .too_long => "Too long: at most 2000 bytes per line.",
        .invalid_utf8 => "That text could not be read (bad encoding).",
        .control_character => "Remove the control or text-direction characters.",
        .shell_escape => "Lines can't start with ! (shell commands are blocked).",
        .slash_command => "Lines can't start with / (slash commands are blocked).",
        .memory_shortcut => "Lines can't start with # (the memory shortcut is blocked).",
    };
}

/// A `{"t":"rejected","reason":...}` reason (keymap.LineError names).
pub fn serverRefusal(reason: []const u8) ?Refusal {
    const table = [_]struct { []const u8, Refusal }{
        .{ "Empty", .empty },                       .{ "TooLong", .too_long },
        .{ "InvalidUtf8", .invalid_utf8 },          .{ "ControlCharacter", .control_character },
        .{ "ShellEscape", .shell_escape },          .{ "SlashCommand", .slash_command },
        .{ "MemoryShortcut", .memory_shortcut },
    };
    for (table) |e| if (std.mem.eql(u8, e[0], reason)) return e[1];
    return null;
}

pub const Tone = enum(u32) { neutral = 0, ok = 1, bad = 2 };
pub const Note = struct { text: []const u8, tone: Tone = .neutral };

/// The line under the box while typing: what Send would do. `buf` holds
/// formatted text.
pub fn preview(policy: Policy, text: []const u8, touch: bool, buf: []u8) Note {
    if (policy == .none) return .{ .text = "" };
    if (answerKey(text)) |k|
        return .{ .text = std.fmt.bufPrint(buf, "Send presses {s}.", .{keyLabel(k)}) catch "", .tone = .ok };
    const blank = std.mem.trim(u8, text, " \t\r\n").len == 0;
    if (blank) return .{ .text = help(policy, touch) };
    return switch (policy) {
        .none => unreachable,
        .keys => .{ .text = refusalText(.answers_only), .tone = .bad },
        .instruct => blk: {
            // Same check as Send, without copying more than needed.
            if (text.len > buf.len) break :blk .{ .text = refusalText(.too_long), .tone = .bad };
            break :blk switch (decide(policy, text, buf)) {
                .refuse => |r| .{ .text = refusalText(r), .tone = .bad },
                else => .{ .text = "Send types this line and presses Enter." },
            };
        },
        .text => .{ .text = "Send types this and presses Enter." },
    };
}

/// Help shown under an empty box.
pub fn help(policy: Policy, touch: bool) []const u8 {
    return switch (policy) {
        .none => "",
        .keys => if (touch)
            "Answers only: say or type yes, no, a number, esc or enter, or tap a button."
        else
            "Answers only: type or dictate (Win+H on Windows) yes, no, a number, esc or enter.",
        .instruct, .text => if (touch)
            "Dictate with the keyboard mic, or type. Saying \"yes\", \"no\" or a number presses that key."
        else
            "Enter sends, Shift+Enter adds a line (sent as spaces). Dictate with Win+H on Windows. \"yes\", \"no\" or a number press that key.",
    };
}

/// Placeholder inside the empty box.
pub fn placeholder(policy: Policy) []const u8 {
    return switch (policy) {
        .none => "",
        .keys => "answers only",
        .instruct => "Instruction, or yes / no / a number",
        .text => "Text to type, or yes / no / a number",
    };
}

/// Should this keydown in the box send? Enter without Shift (Ctrl+Enter
/// too), and not while an IME is composing. Mod bits as keys.Mods, plus
/// 16 = composing.
pub fn boxKeySends(key: []const u8, mods: u32) bool {
    if (!std.mem.eql(u8, key, "Enter")) return false;
    return mods & (1 | 4 | 8 | 16) == 0;
}

// ------------------------------------------------------------ the button row

pub const Button = enum(u32) { yes, no, one, two, three, esc, enter, send };

/// The key a button presses (null for Send).
pub fn buttonKey(b: Button) ?[]const u8 {
    return switch (b) {
        .yes => "y",
        .no => "n",
        .one => "1",
        .two => "2",
        .three => "3",
        .esc => "esc",
        .enter => "enter",
        .send => null,
    };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn expectAnswer(want: ?[]const u8, text: []const u8) !void {
    const got = answerKey(text);
    if (want == null) {
        if (got != null) {
            std.debug.print("'{s}' unexpectedly maps to {s}\n", .{ text, got.? });
            return error.TestUnexpectedResult;
        }
        return;
    }
    if (got == null) {
        std.debug.print("'{s}' should map to {s}\n", .{ text, want.? });
        return error.TestUnexpectedResult;
    }
    try testing.expectEqualStrings(want.?, got.?);
}

test "answer words: the table" {
    for (answer_words) |e| try expectAnswer(e.key, e.word);
    try expectAnswer("y", "yes");
    try expectAnswer("y", "yeah");
    try expectAnswer("y", "yep");
    try expectAnswer("n", "nope");
    try expectAnswer("esc", "cancel");
    try expectAnswer("enter", "okay");
    try expectAnswer("9", "nine");
}

test "answer words: dictation punctuation and case" {
    try expectAnswer("y", "Yes.");
    try expectAnswer("y", "YES!");
    try expectAnswer("y", "  yes  ");
    try expectAnswer("y", "Yes?!");
    try expectAnswer("n", "No.");
    try expectAnswer("n", "no,");
    try expectAnswer("2", "Two.");
    try expectAnswer("1", "1.");
    try expectAnswer("3", "\"three\"");
    try expectAnswer("enter", "OK.");
    try expectAnswer("enter", "O.K.");
    try expectAnswer("enter", "Okay!");
    try expectAnswer("esc", "Escape.");
    try expectAnswer("2", "Option two.");
    try expectAnswer("3", "number 3");
    try expectAnswer("y", "yes\n"); // a dictated "new line" after it
    try expectAnswer("y", "yes !");
}

test "answer words: unicode" {
    try expectAnswer("y", "Yes\u{3002}"); // ideographic full stop
    try expectAnswer("y", "\u{FF39}\u{FF25}\u{FF33}"); // full-width ＹＥＳ
    try expectAnswer("1", "\u{FF11}"); // full-width １
    try expectAnswer("n", "\u{FF2E}\u{FF4F}\u{FF01}"); // Ｎｏ！
    try expectAnswer("y", "\u{00A0}yes\u{2026}"); // nbsp, ellipsis
    try expectAnswer("n", "\u{00BF}no?"); // ¿no?
    try expectAnswer("y", "\u{201C}Yes\u{201D}"); // curly quotes
    try expectAnswer("y", "\u{3000}yes\u{3000}"); // ideographic space
    try expectAnswer(null, "y\u{00E8}s"); // yès
    try expectAnswer(null, "\u{0423}\u{0435}s"); // Cyrillic look-alikes
    try expectAnswer(null, "yes\u{200D}x");
    try expectAnswer(null, "bad\xff");
}

test "answer words: everything else is not an answer" {
    for ([_][]const u8{
        "",       "   ",          ".",             "yes please",  "no way",   "yess",
        "10",     "12",           "one two",       "option yes",  "number",   "option",
        "y y",    "run the tests", "/permissions", "!dir",        "#note",    "yesno",
        "escape the string",       "okay then",
    }) |t| try expectAnswer(null, t);
    const long: [200]u8 = @splat('a');
    try expectAnswer(null, &long);
}

test "collapse: line breaks become spaces" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("fix the tests then commit", collapse("fix the tests\nthen commit", &buf));
    try testing.expectEqualStrings("a b", collapse("a\r\n\r\nb", &buf));
    try testing.expectEqualStrings("a b", collapse("a \n b", &buf));
    try testing.expectEqualStrings("a b", collapse("a\tb", &buf));
    try testing.expectEqualStrings("a b c", collapse("a\u{2028}b\u{85}c", &buf));
    try testing.expectEqualStrings("x", collapse("\n\n x \n", &buf));
    try testing.expectEqualStrings("", collapse("\r\n", &buf));
    try testing.expectEqualStrings("caf\u{e9} \u{4e2d}", collapse("caf\u{e9}\n\u{4e2d}", &buf));
}

test "send decisions per input mode" {
    var buf: [256]u8 = undefined;
    // Answer words press keys in every mode that has input.
    for ([_]Policy{ .keys, .instruct, .text }) |p| {
        try testing.expectEqualStrings("y", decide(p, "Yes.", &buf).key);
        try testing.expectEqualStrings("2", decide(p, "two", &buf).key);
        try testing.expectEqualStrings("esc", decide(p, "Cancel", &buf).key);
        try testing.expectEqual(Decision{ .refuse = .empty }, decide(p, " \n ", &buf));
    }
    // View only: nothing, ever.
    try testing.expectEqual(Decision.nothing, decide(.none, "yes", &buf));
    try testing.expectEqual(Decision.nothing, decide(.none, "run tests", &buf));
    // keys: answers only.
    try testing.expectEqual(Decision{ .refuse = .answers_only }, decide(.keys, "run the tests", &buf));
    // instruct: checked lines, newlines collapsed, the server's rules.
    try testing.expectEqualStrings("run the tests and fix failures", decide(.instruct, "  run the tests\nand fix failures ", &buf).line);
    try testing.expectEqual(Decision{ .refuse = .shell_escape }, decide(.instruct, "!rm -rf .", &buf));
    try testing.expectEqual(Decision{ .refuse = .shell_escape }, decide(.instruct, "\n !dir", &buf));
    try testing.expectEqual(Decision{ .refuse = .slash_command }, decide(.instruct, "/permissions", &buf));
    try testing.expectEqual(Decision{ .refuse = .memory_shortcut }, decide(.instruct, "# note", &buf));
    try testing.expectEqual(Decision{ .refuse = .control_character }, decide(.instruct, "a\x1b[31mb", &buf));
    try testing.expectEqual(Decision{ .refuse = .control_character }, decide(.instruct, "a\u{202E}b", &buf));
    var big: [2100]u8 = @splat('a');
    var big_buf: [2100]u8 = undefined;
    try testing.expectEqual(Decision{ .refuse = .too_long }, decide(.instruct, &big, &big_buf));
    // text: typed as is (slash commands allowed: full remote control).
    try testing.expectEqualStrings("/help me", decide(.text, "/help\nme", &buf).typed);
    big = @splat('b');
    try testing.expectEqualStrings(&big, decide(.text, &big, &big_buf).typed);
    var huge: [max_frame]u8 = @splat('c');
    var huge_buf: [max_frame]u8 = undefined;
    try testing.expectEqual(Decision{ .refuse = .too_long }, decide(.text, &huge, &huge_buf));
}

test "server rejection reasons and notes" {
    try testing.expectEqual(Refusal.shell_escape, serverRefusal("ShellEscape").?);
    try testing.expectEqual(Refusal.control_character, serverRefusal("ControlCharacter").?);
    try testing.expectEqual(@as(?Refusal, null), serverRefusal("Bogus"));
    // Every refusal has a message.
    for (std.enums.values(Refusal)) |r| try testing.expect(refusalText(r).len > 0);
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("Send presses Yes.", preview(.instruct, "Yes.", true, &buf).text);
    try testing.expectEqual(Tone.bad, preview(.instruct, "/config", true, &buf).tone);
    try testing.expectEqual(Tone.bad, preview(.keys, "do things", true, &buf).tone);
    try testing.expectEqual(Tone.neutral, preview(.instruct, "do things", true, &buf).tone);
    try testing.expect(std.mem.indexOf(u8, preview(.instruct, "", false, &buf).text, "Win+H") != null);
    try testing.expect(std.mem.indexOf(u8, help(.keys, false), "Win+H") != null);
    try testing.expectEqualStrings("", preview(.none, "yes", true, &buf).text);
    try testing.expectEqualStrings("answers only", placeholder(.keys));
}

test "box keys and buttons" {
    try testing.expect(boxKeySends("Enter", 0));
    try testing.expect(boxKeySends("Enter", 2)); // Ctrl+Enter
    try testing.expect(!boxKeySends("Enter", 1)); // Shift+Enter: new line
    try testing.expect(!boxKeySends("Enter", 16)); // IME composing
    try testing.expect(!boxKeySends("a", 0));
    try testing.expectEqualStrings("y", buttonKey(.yes).?);
    try testing.expectEqualStrings("esc", buttonKey(.esc).?);
    try testing.expectEqual(@as(?[]const u8, null), buttonKey(.send));
    // Every key a button or answer word presses is an answer key the
    // server accepts in keys mode.
    for (std.enums.values(Button)) |b| if (buttonKey(b)) |k| try testing.expect(keymap.keyBytes(.keys, k) != null);
    for (answer_words) |e| try testing.expect(keymap.keyBytes(.keys, e.key) != null);
}
