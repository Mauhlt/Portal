//! Web input: protocol key names -> terminal bytes (docs/protocol.md §4).
//!
//! Clients never send raw terminal bytes. They send a key *name* (`k:enter`)
//! or, in text mode only, plain text (`t:hello`). Portal produces every byte
//! that reaches the PTY from the tables below, so no escape sequence can
//! originate from the web, whatever a client sends.

const std = @import("std");
/// What web viewers may send (`portal run --input`).
///   none - view only.
///   keys - (default) answer the agent's numbered prompts: digits, y/n, Enter,
///          and at most one Esc per second.
///   text - FULL REMOTE CONTROL: typed text is an agent prompt, `!` runs
///          shell commands, slash commands, Shift+Tab mode changes, Ctrl+C.
pub const Policy = enum {
    none,
    keys,
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
