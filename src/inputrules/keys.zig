//! Remote input policy and the one list of key names (docs/protocol.md §4),
//! shared by the server (src/keymap.zig re-exports it), the native client
//! (client/src/keys.zig) and the browser client (src/wasm/keys.zig).
//!
//! Clients never send raw terminal bytes. They send a key *name* (`k:enter`)
//! or, in text mode only, plain text (`t:hello`). Portal produces every byte
//! that reaches the PTY from the tables below, so no escape sequence can
//! originate from the web, whatever a client sends. The clients map keys
//! with the same tables (`special`, `char`), so they never offer what the
//! server would drop; each client only translates its own key events into
//! protocol names.

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
///          Up/Down (`menu_keys`) only while the program waits for an
///          answer (`lookupAt`), for arrow-select menus such as the
///          folder-trust prompt.
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

    /// What a viewer may do, as every client shows it.
    pub fn label(p: Policy) []const u8 {
        return switch (p) {
            .none => "view only",
            .keys => "answer keys",
            .instruct => "instructions",
            .text => "typing allowed",
        };
    }

    /// The answer keys (and the answer buttons) work in this mode.
    pub fn acceptsAnswers(p: Policy) bool {
        return p != .none;
    }
};

pub const Key = struct { name: []const u8, bytes: []const u8 };

/// Accepted in `keys`, `instruct` and `text` mode: enough to answer the agent's numbered
/// prompts. No arrows or Backspace in `keys` (Up+Enter at an empty prompt
/// would resubmit an earlier prompt from history).
pub const answer_keys = [_]Key{
    .{ .name = "0", .bytes = "0" }, .{ .name = "1", .bytes = "1" },
    .{ .name = "2", .bytes = "2" }, .{ .name = "3", .bytes = "3" },
    .{ .name = "4", .bytes = "4" }, .{ .name = "5", .bytes = "5" },
    .{ .name = "6", .bytes = "6" }, .{ .name = "7", .bytes = "7" },
    .{ .name = "8", .bytes = "8" }, .{ .name = "9", .bytes = "9" },
    .{ .name = "y", .bytes = "y" },     .{ .name = "n", .bytes = "n" },
    .{ .name = "enter", .bytes = "\r" }, .{ .name = "esc", .bytes = "\x1b" },
};

/// Accepted in `instruct` mode only while the session program waits for
/// an answer (`waiting` in `lookupAt`): its OSC 7501 state is `blocked`, or
/// the Conversation view has an open question. That is how arrow-select
/// menus (the agent's folder-trust prompt, its permission and question menus)
/// are answered. Never otherwise: at the agent's input box Up recalls an
/// earlier prompt from history (a `!` shell command or a slash command
/// typed at the desk among them) and Enter would submit it, past every
/// instruction-line check. Not in `keys` mode at all. `text` mode has them
/// anyway (text_keys).
pub const menu_keys = [_]Key{
    .{ .name = "up", .bytes = "\x1b[A" },
    .{ .name = "down", .bytes = "\x1b[B" },
};

/// A menu key (`menu_keys`): allowed in `instruct` mode only while waiting.
pub fn isMenuKey(name: []const u8) bool {
    for (&menu_keys) |*k| if (std.mem.eql(u8, k.name, name)) return true;
    return false;
}

/// Additionally accepted in `text` mode (full remote control).
pub const text_keys = [_]Key{
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

/// The table entry for key `name` under `policy`, or null if not allowed,
/// for a program that is not waiting for an answer (see `lookupAt`).
pub fn lookup(policy: Policy, name: []const u8) ?*const Key {
    if (policy == .none) return null;
    for (&answer_keys) |*k| if (std.mem.eql(u8, k.name, name)) return k;
    if (policy != .text) return null;
    for (&text_keys) |*k| if (std.mem.eql(u8, k.name, name)) return k;
    return null;
}

/// `lookup`, knowing whether the session program waits for an answer
/// (`waiting`): `instruct` mode then also takes the menu keys (Up/Down).
pub fn lookupAt(policy: Policy, waiting: bool, name: []const u8) ?*const Key {
    if (lookup(policy, name)) |k| return k;
    if (policy != .instruct or !waiting) return null;
    for (&menu_keys) |*k| if (std.mem.eql(u8, k.name, name)) return k;
    return null;
}

/// Why the server refused a key it otherwise knows (sent back as
/// `{"t":"rejected","reason":"NotWaiting"}`): Up/Down in `instruct` mode
/// while the program is not waiting for an answer.
pub const KeyError = error{NotWaiting};

/// The server's decision for `k:<name>`: the bytes to write, null for a
/// name the policy never takes (dropped silently), or error.NotWaiting for
/// a menu key in `instruct` mode while the program is not waiting.
pub fn keyBytesAt(policy: Policy, waiting: bool, name: []const u8) KeyError!?[]const u8 {
    if (lookupAt(policy, waiting, name)) |k| return k.bytes;
    if (policy == .instruct and isMenuKey(name)) return error.NotWaiting;
    return null;
}

/// Bytes for key `name` under `policy`, or null if not allowed.
pub fn keyBytes(policy: Policy, name: []const u8) ?[]const u8 {
    return if (lookup(policy, name)) |k| k.bytes else null;
}

/// Whether a client may send `k:<name>` under `policy`.
pub fn allowed(policy: Policy, name: []const u8) bool {
    return lookup(policy, name) != null;
}

// ------------------------------------------------- client-side key mapping

/// Modifiers held with a key, as every client reports them.
pub const Mods = struct {
    shift: bool = false,
    ctrl: bool = false,
    alt: bool = false,
    /// Windows / Command / Super.
    meta: bool = false,
};

/// What a key press at the terminal sends.
pub const Action = union(enum) {
    none,
    /// `k:<name>`; the name points into the static tables.
    key: []const u8,
    /// `t:<text>` (text mode only).
    text: []const u8,
};

/// A special (non-character) key, by protocol name ("enter", "up", "tab"),
/// pressed at the terminal. The one rule for every client: Ctrl, Alt and
/// Meta combinations send nothing (Ctrl+Enter is not Enter); Shift+Tab is
/// `shift-tab`; otherwise the key is sent if `policy` allows it.
pub fn special(policy: Policy, name: []const u8, mods: Mods) Action {
    return specialAt(policy, false, name, mods);
}

/// `special`, knowing whether the shown tab's program waits for an answer
/// (its tab `state` is `waiting`, or the Conversation view has an open
/// question): `instruct` mode then also sends Up/Down (`menu_keys`).
pub fn specialAt(policy: Policy, waiting: bool, name: []const u8, mods: Mods) Action {
    if (mods.alt or mods.meta or mods.ctrl) return .none;
    const n = if (mods.shift and std.mem.eql(u8, name, "tab")) "shift-tab" else name;
    const k = lookupAt(policy, waiting, n) orelse return .none;
    return .{ .key = k.name };
}

/// Printable: not C0, DEL, C1, a surrogate or out of range.
pub fn printable(cp: u21) bool {
    return !(cp < 0x20 or cp == 0x7f or (cp >= 0x80 and cp < 0xa0) or (cp >= 0xD800 and cp <= 0xDFFF) or cp > 0x10FFFF);
}

/// A typed character at the terminal. Text mode types it (`t:`) and maps
/// Ctrl+C to `ctrl-c`; the other modes take the answer characters (digits,
/// y, n, either case) as keys and nothing else. `buf` holds the encoded
/// text.
pub fn char(policy: Policy, cp: u21, mods: Mods, buf: *[4]u8) Action {
    if (policy == .none or mods.alt or mods.meta) return .none;
    if (mods.ctrl) {
        if (policy == .text and (cp == 'c' or cp == 'C')) return .{ .key = lookup(.text, "ctrl-c").?.name };
        return .none;
    }
    if (!printable(cp)) return .none;
    if (policy == .text) {
        const n = std.unicode.utf8Encode(cp, buf) catch return .none;
        return .{ .text = buf[0..n] };
    }
    if (cp >= 0x80) return .none;
    const lower = std.ascii.toLower(@intCast(cp));
    for (&answer_keys) |*k| if (k.name.len == 1 and k.name[0] == lower) return .{ .key = k.name };
    return .none;
}

/// Formats `action` as a frame into `buf`; null if none or it does not fit.
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
/// Portal can't see the agent's input box (or its cursor), so "start of line"
/// means "nothing typed by a device since the last key that is not a
/// character": Enter, Esc, Ctrl+C, and also Backspace, Delete, the arrows,
/// Home/End, Tab (otherwise `t:x`, `k:backspace`, `t:!cmd` would put a `!`
/// first). The character keys (digits, y, n) type text.
pub const TextGuard = struct {
    at_line_start: bool = true,

    pub fn onKey(g: *TextGuard, name: []const u8) void {
        const typed = name.len == 1 and for (answer_keys) |k| {
            if (std.mem.eql(u8, k.name, name)) break true;
        } else false;
        g.at_line_start = !typed;
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

test "instruct mode: Up/Down only while the program waits" {
    // Waiting: the menu keys, and still no other editing key.
    try testing.expectEqualStrings("\x1b[A", (try keyBytesAt(.instruct, true, "up")).?);
    try testing.expectEqualStrings("\x1b[B", (try keyBytesAt(.instruct, true, "down")).?);
    try testing.expectEqualStrings("1", (try keyBytesAt(.instruct, true, "1")).?);
    for ([_][]const u8{ "left", "right", "backspace", "tab", "shift-tab", "ctrl-c", "home", "pageup", "\x1b[A" }) |k|
        try testing.expect((try keyBytesAt(.instruct, true, k)) == null);
    // Not waiting (working, idle, unknown): refused, with a reason.
    try testing.expectError(error.NotWaiting, keyBytesAt(.instruct, false, "up"));
    try testing.expectError(error.NotWaiting, keyBytesAt(.instruct, false, "down"));
    try testing.expectEqualStrings("\r", (try keyBytesAt(.instruct, false, "enter")).?);
    // keys mode never takes them; text mode always does; none nothing.
    for ([_]bool{ false, true }) |wt| {
        try testing.expect((try keyBytesAt(.keys, wt, "up")) == null);
        try testing.expect((try keyBytesAt(.keys, wt, "down")) == null);
        try testing.expectEqualStrings("\x1b[A", (try keyBytesAt(.text, wt, "up")).?);
        try testing.expect((try keyBytesAt(.none, wt, "up")) == null);
        try testing.expect((try keyBytesAt(.none, wt, "1")) == null);
    }
    // The client rule follows the same gate.
    try testing.expectEqualStrings("up", specialAt(.instruct, true, "up", .{}).key);
    try testing.expectEqualStrings("down", specialAt(.instruct, true, "down", .{ .shift = true }).key);
    try testing.expectEqual(Action.none, specialAt(.instruct, true, "up", .{ .ctrl = true }));
    try testing.expectEqual(Action.none, specialAt(.instruct, false, "up", .{}));
    try testing.expectEqual(Action.none, specialAt(.keys, true, "up", .{}));
    try testing.expectEqual(Action.none, specialAt(.instruct, true, "left", .{}));
    // An arrow resets text mode's line start (it is not a character key).
    var g: TextGuard = .{};
    _ = g.filter("x");
    g.onKey("up");
    try testing.expectEqualStrings("cmd", g.filter("!cmd"));
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

test "TextGuard: editing and navigation keys reset the line start" {
    for ([_][]const u8{ "backspace", "delete", "left", "right", "up", "down", "home", "end", "pageup", "pagedown", "tab", "shift-tab", "enter", "esc", "ctrl-c" }) |k| {
        var g: TextGuard = .{};
        try testing.expectEqualStrings("x", g.filter("x"));
        g.onKey(k);
        try testing.expectEqualStrings("cmd", g.filter("!cmd"));
    }
    // Answer keys type characters: a `!` after them is mid-line.
    var g: TextGuard = .{};
    g.onKey("1");
    try testing.expectEqualStrings("!", g.filter("!"));
    g.onKey("y");
    try testing.expectEqualStrings("!", g.filter("!"));
}

test "client mapping: one rule for every client" {
    var b: [4]u8 = undefined;
    // keys and instruct: answer characters, Enter, Esc; nothing else.
    for ([_]Policy{ .keys, .instruct }) |p| {
        try testing.expectEqualStrings("enter", special(p, "enter", .{}).key);
        try testing.expectEqualStrings("esc", special(p, "esc", .{ .shift = true }).key);
        try testing.expectEqual(Action.none, special(p, "up", .{}));
        try testing.expectEqual(Action.none, special(p, "backspace", .{}));
        try testing.expectEqualStrings("y", char(p, 'Y', .{ .shift = true }, &b).key);
        try testing.expectEqualStrings("7", char(p, '7', .{}, &b).key);
        try testing.expectEqual(Action.none, char(p, 'a', .{}, &b));
        try testing.expectEqual(Action.none, char(p, 'c', .{ .ctrl = true }, &b));
    }
    // Ctrl / Alt / Meta with a special key: nothing, in any mode.
    for ([_]Policy{ .keys, .instruct, .text }) |p| {
        try testing.expectEqual(Action.none, special(p, "enter", .{ .ctrl = true }));
        try testing.expectEqual(Action.none, special(p, "esc", .{ .ctrl = true }));
        try testing.expectEqual(Action.none, special(p, "enter", .{ .alt = true }));
        try testing.expectEqual(Action.none, char(p, 'y', .{ .meta = true }, &b));
    }
    // text: the extended keys, typed text, Ctrl+C.
    try testing.expectEqualStrings("shift-tab", special(.text, "tab", .{ .shift = true }).key);
    try testing.expectEqualStrings("pagedown", special(.text, "pagedown", .{}).key);
    try testing.expectEqual(Action.none, special(.text, "f5", .{}));
    try testing.expectEqualStrings("\xE4\xB8\xAD", char(.text, 0x4E2D, .{}, &b).text);
    try testing.expectEqualStrings("ctrl-c", char(.text, 'C', .{ .ctrl = true, .shift = true }, &b).key);
    try testing.expectEqual(Action.none, char(.text, 'x', .{ .ctrl = true }, &b));
    try testing.expectEqual(Action.none, char(.text, 0x1b, .{}, &b));
    try testing.expectEqual(Action.none, char(.text, 0xD800, .{}, &b));
    // view only: nothing.
    try testing.expectEqual(Action.none, special(.none, "enter", .{}));
    try testing.expectEqual(Action.none, char(.none, '1', .{}, &b));
    // Whatever a client maps to, the server accepts under the same policy.
    for (std.enums.values(Policy)) |p| {
        for (answer_keys ++ text_keys) |k| switch (special(p, k.name, .{})) {
            .key => |n| try testing.expect(keyBytes(p, n) != null),
            else => {},
        };
        for (answer_keys ++ text_keys ++ menu_keys) |k| switch (specialAt(p, true, k.name, .{})) {
            .key => |n| try testing.expect((keyBytesAt(p, true, n) catch null) != null),
            else => {},
        };
        var cp: u21 = 0;
        while (cp < 0x300) : (cp += 1) switch (char(p, cp, .{}, &b)) {
            .key => |n| try testing.expect(keyBytes(p, n) != null),
            .text => try testing.expect(p == .text),
            .none => {},
        };
    }
}

test "frame formatting" {
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("k:enter", frame(&buf, .{ .key = "enter" }).?);
    try testing.expectEqualStrings("t:ab", frame(&buf, .{ .text = "ab" }).?);
    try testing.expectEqual(@as(?[]const u8, null), frame(&buf, .{ .text = "toolongtext" }));
    try testing.expectEqual(@as(?[]const u8, null), frame(&buf, .none));
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
