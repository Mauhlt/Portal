//! Web input: protocol key names -> terminal bytes (docs/protocol.md §4).
//!
//! Clients never send raw terminal bytes. They send a key *name* (`k:enter`)
//! or, in text mode only, plain text (`t:hello`). Portal produces every byte
//! that reaches the PTY from the tables below, so no escape sequence can
//! originate from the web, whatever a client sends.

const std = @import("std");
/// What web viewers may send (`portal run --input`).
///   none - view only.
///   keys - answer the session program's numbered prompts: digits, y/n,
///          Enter, and at most one Esc per second. (`portal run` uses this
///          for a shell, where instruct would be remote typing.)
///   instruct - (default) answer keys, plus whole instruction lines (`l:<text>`) that
///          Portal validates before typing them (validateLine): no `!` shell
///          escape, no `/` slash commands, no `#` memory shortcut, no control
///          characters or line breaks. The agent still asks permission for
///          anything it runs; the device answers with the answer keys.
///   text - FULL REMOTE CONTROL: typed text is an agent prompt, slash
///          commands, Shift+Tab mode changes, Ctrl+C. A `!` typed by a device
///          at the start of a line is dropped (TextGuard, best effort).
pub const Policy = enum {
    none,
    keys,
    instruct,
    text,

    pub fn parse(s: []const u8) ?Policy {
        return std.meta.stringToEnum(Policy, s);
    }
};

const Key = struct { name: []const u8, bytes: []const u8 };

/// Accepted in `keys` and `text` mode: enough to answer the agent's numbered
/// prompts. No arrows or Backspace in `keys` (Up+Enter at an empty prompt
/// would resubmit an earlier prompt from history).
const answer_keys = [_]Key{
    .{ .name = "0", .bytes = "0" }, .{ .name = "1", .bytes = "1" },
    .{ .name = "2", .bytes = "2" }, .{ .name = "3", .bytes = "3" },
    .{ .name = "4", .bytes = "4" }, .{ .name = "5", .bytes = "5" },
    .{ .name = "6", .bytes = "6" }, .{ .name = "7", .bytes = "7" },
    .{ .name = "8", .bytes = "8" }, .{ .name = "9", .bytes = "9" },
    .{ .name = "y", .bytes = "y" },     .{ .name = "n", .bytes = "n" },
    .{ .name = "enter", .bytes = "\r" }, .{ .name = "esc", .bytes = "\x1b" },
};

/// Additionally accepted in `text` mode (full remote control).
const text_keys = [_]Key{
    .{ .name = "backspace", .bytes = "\x7f" },
    .{ .name = "tab", .bytes = "\t" },
    .{ .name = "shift-tab", .bytes = "\x1b[Z" },
    .{ .name = "up", .bytes = "\x1b[A" },
    .{ .name = "down", .bytes = "\x1b[B" },
    .{ .name = "right", .bytes = "\x1b[C" },
    .{ .name = "left", .bytes = "\x1b[D" },
    .{ .name = "home", .bytes = "\x1b[H" },
    .{ .name = "end", .bytes = "\x1b[F" },
    .{ .name = "pageup", .bytes = "\x1b[5~" },
    .{ .name = "pagedown", .bytes = "\x1b[6~" },
    .{ .name = "delete", .bytes = "\x1b[3~" },
    .{ .name = "ctrl-c", .bytes = "\x03" },
};

/// Bytes for key `name` under `policy`, or null if not allowed.
pub fn keyBytes(policy: Policy, name: []const u8) ?[]const u8 {
    if (policy == .none) return null;
    for (answer_keys) |k| if (std.mem.eql(u8, k.name, name)) return k.bytes;
    if (policy != .text) return null;
    for (text_keys) |k| if (std.mem.eql(u8, k.name, name)) return k.bytes;
    return null;
}

// ------------------------------------------------------------ instruct lines

pub const max_line_bytes = 2000;

pub const LineError = error{
    Empty,
    TooLong,
    InvalidUtf8,
    ControlCharacter,
    /// Leading `!`: the agent would run the rest in a shell directly.
    ShellEscape,
    /// Leading `/`: slash commands can change permissions, folders, config.
    SlashCommand,
    /// Leading `#`: writes to the agent's memory files.
    MemoryShortcut,
};

/// Characters that, first in the agent's input, switch it into a special
/// mode. Full-width look-alikes are included.
fn modePrefix(cp: u21) ?LineError {
    return switch (cp) {
        '!', 0xFF01 => error.ShellEscape,
        '/', 0xFF0F => error.SlashCommand,
        '#', 0xFF03 => error.MemoryShortcut,
        else => null,
    };
}

/// Validates a remote instruction line (`l:<text>`). Returns the text to
/// type, with surrounding blanks trimmed.
pub fn validateLine(line_in: []const u8) LineError![]const u8 {
    if (line_in.len > max_line_bytes) return error.TooLong;
    if (!std.unicode.utf8ValidateSlice(line_in)) return error.InvalidUtf8;
    const line = std.mem.trim(u8, line_in, " \t");
    if (line.len == 0) return error.Empty;
    var it = std.unicode.Utf8View.initUnchecked(line).iterator();
    var first = true;
    while (it.nextCodepoint()) |cp| {
        if (cp < 0x20 or cp == 0x7f or (cp >= 0x80 and cp <= 0x9f)) return error.ControlCharacter;
        // Line/paragraph separators and bidi controls are rejected too: they
        // could hide or reorder text in what the owner reads.
        if (cp == 0x2028 or cp == 0x2029 or (cp >= 0x202A and cp <= 0x202E) or (cp >= 0x2066 and cp <= 0x2069))
            return error.ControlCharacter;
        if (first) {
            if (modePrefix(cp)) |e| return e;
            first = false;
        }
    }
    return line;
}

/// Text mode, best effort: drops `!` (or full-width `！`) typed by a device
/// at the start of a line, so it can't flip the agent into shell mode.
/// Portal can't see the agent's input box, so "start of line" means "nothing
/// typed by a device since the last Enter / Esc / Ctrl+C".
pub const TextGuard = struct {
    at_line_start: bool = true,

    pub fn onKey(g: *TextGuard, name: []const u8) void {
        if (std.mem.eql(u8, name, "enter") or std.mem.eql(u8, name, "esc") or std.mem.eql(u8, name, "ctrl-c"))
            g.at_line_start = true;
    }

    /// Filters already-sanitised text; returns the part that may be typed.
    pub fn filter(g: *TextGuard, text: []const u8) []const u8 {
        var t = text;
        if (g.at_line_start) {
            while (true) {
                t = std.mem.trimStart(u8, t, " ");
                if (t.len > 0 and t[0] == '!') {
                    t = t[1..];
                } else if (std.mem.startsWith(u8, t, "\u{FF01}")) {
                    t = t["\u{FF01}".len..];
                } else break;
            }
        }
        if (t.len > 0) g.at_line_start = false;
        return t;
    }
};

/// Text-mode typing: keeps printable characters only (valid UTF-8; no C0,
/// DEL or C1 controls, so no escape sequences and no Enter). Returns the
/// sanitised text in `out` (`out.len >= in.len`). Empty in other modes.
pub fn sanitizeText(policy: Policy, in: []const u8, out: []u8) []const u8 {
    std.debug.assert(out.len >= in.len);
    if (policy != .text) return out[0..0];
    var o: usize = 0;
    var view = std.unicode.Utf8View.init(in) catch return out[0..0];
    var it = view.iterator();
    while (it.nextCodepointSlice()) |cs| {
        const cp = std.unicode.utf8Decode(cs) catch continue;
        if (cp < 0x20 or cp == 0x7f or (cp >= 0x80 and cp <= 0x9f)) continue;
        @memcpy(out[o..][0..cs.len], cs);
        o += cs.len;
    }
    return out[0..o];
}

const testing = std.testing;

test "keys mode: answers only" {
    try testing.expectEqualStrings("1", keyBytes(.keys, "1").?);
    try testing.expectEqualStrings("\r", keyBytes(.keys, "enter").?);
    try testing.expectEqualStrings("\x1b", keyBytes(.keys, "esc").?);
    try testing.expect(keyBytes(.keys, "up") == null);
    try testing.expect(keyBytes(.keys, "backspace") == null);
    try testing.expect(keyBytes(.keys, "ctrl-c") == null);
    try testing.expect(keyBytes(.keys, "shift-tab") == null);
    try testing.expect(keyBytes(.keys, "\x1b[A") == null);
    try testing.expect(keyBytes(.keys, "") == null);
}

test "instruct mode: answer keys only, no editing keys" {
    try testing.expectEqualStrings("1", keyBytes(.instruct, "1").?);
    try testing.expectEqualStrings("\r", keyBytes(.instruct, "enter").?);
    try testing.expect(keyBytes(.instruct, "up") == null);
    try testing.expect(keyBytes(.instruct, "ctrl-c") == null);
    try testing.expect(keyBytes(.instruct, "shift-tab") == null);
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("", sanitizeText(.instruct, "hello", &buf)); // no t: typing
}

test "validateLine: plain instructions pass" {
    try testing.expectEqualStrings("run the tests and fix failures", try validateLine("  run the tests and fix failures "));
    try testing.expectEqualStrings("what does foo/bar.zig do?", try validateLine("what does foo/bar.zig do?"));
    try testing.expectEqualStrings("café 中文 ok!", try validateLine("café 中文 ok!"));
}

test "validateLine: shell, slash and memory prefixes rejected" {
    try testing.expectError(error.ShellEscape, validateLine("!rm -rf ."));
    try testing.expectError(error.ShellEscape, validateLine("   !dir"));
    try testing.expectError(error.ShellEscape, validateLine("\t!dir"));
    try testing.expectError(error.ShellEscape, validateLine("\u{FF01}dir"));
    try testing.expectError(error.SlashCommand, validateLine("/permissions"));
    try testing.expectError(error.SlashCommand, validateLine(" /add-dir C:\\"));
    try testing.expectError(error.SlashCommand, validateLine("\u{FF0F}config"));
    try testing.expectError(error.MemoryShortcut, validateLine("# remember this"));
}

test "validateLine: control characters, line breaks and bidi rejected" {
    try testing.expectError(error.ControlCharacter, validateLine("ok\nthen !rm"));
    try testing.expectError(error.ControlCharacter, validateLine("ok\r!rm"));
    try testing.expectError(error.ControlCharacter, validateLine("a\x1b[201~b"));
    try testing.expectError(error.ControlCharacter, validateLine("a\x03"));
    try testing.expectError(error.ControlCharacter, validateLine("a\xc2\x9bb"));
    try testing.expectError(error.ControlCharacter, validateLine("a\u{2028}b"));
    try testing.expectError(error.ControlCharacter, validateLine("a\u{202E}b"));
    try testing.expectError(error.InvalidUtf8, validateLine("bad\xff"));
    try testing.expectError(error.Empty, validateLine("   "));
    const big: [max_line_bytes + 1]u8 = @splat('a');
    try testing.expectError(error.TooLong, validateLine(&big));
}

test "TextGuard drops a leading ! per line" {
    var g: TextGuard = .{};
    try testing.expectEqualStrings("", g.filter("!"));
    try testing.expectEqualStrings("dir", g.filter("dir"));
    try testing.expectEqualStrings("!", g.filter("!")); // mid-line ! is ordinary text
    g.onKey("enter");
    try testing.expectEqualStrings("ls", g.filter(" ! !ls"));
    g.onKey("esc");
    try testing.expectEqualStrings("", g.filter("\u{FF01}"));
    try testing.expectEqualStrings("", g.filter("  "));
    try testing.expectEqualStrings("x", g.filter("!x")); // still at line start: blanks typed nothing
}

test "none mode: nothing" {
    try testing.expect(keyBytes(.none, "1") == null);
    try testing.expect(keyBytes(.none, "enter") == null);
}

test "text mode: extended keys" {
    try testing.expectEqualStrings("\x1b[A", keyBytes(.text, "up").?);
    try testing.expectEqualStrings("\x03", keyBytes(.text, "ctrl-c").?);
    try testing.expectEqualStrings("y", keyBytes(.text, "y").?);
    try testing.expect(keyBytes(.text, "f13") == null);
}

test "sanitizeText strips every control" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("hello", sanitizeText(.text, "hello", &buf));
    try testing.expectEqualStrings("[6n", sanitizeText(.text, "\x1b[6n", &buf));
    try testing.expectEqualStrings("ab", sanitizeText(.text, "a\r\n\x03\x7fb", &buf));
    try testing.expectEqualStrings("héllo", sanitizeText(.text, "héllo", &buf));
    try testing.expectEqualStrings("a6n", sanitizeText(.text, "a\xc2\x9b6n", &buf)); // C1 CSI
    try testing.expectEqualStrings("", sanitizeText(.text, "bad\xff", &buf)); // invalid UTF-8
    try testing.expectEqualStrings("", sanitizeText(.keys, "hello", &buf));
}
