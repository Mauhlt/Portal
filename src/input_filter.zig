//! Filters keystrokes arriving from the web before they reach the PTY.
//!
//! Policies:
//!   none - viewer only, everything is dropped.
//!   keys - (default) only what is needed to answer the agent's numbered
//!          prompts: digits, y/n, Enter, and a single Esc (rate limited).
//!          No arrows or Backspace: at an empty prompt, Up+Enter would
//!          resubmit an earlier prompt from history, and Esc Esc opens the
//!          rewind menu.
//!   text - FULL REMOTE CONTROL OF THE PROGRAM. Typing is allowed (printable
//!          UTF-8, Enter, Tab, Backspace, Ctrl+C, navigation keys, Shift+Tab,
//!          bracketed paste). In the agent that means new prompts, `!` shell
//!          commands, slash commands, permission-mode changes and exiting.
//!          Only unrecognised escape sequences and stray control bytes are
//!          dropped. Opt-in only.

const std = @import("std");

pub const Policy = enum {
    none,
    keys,
    text,

    pub fn parse(s: []const u8) ?Policy {
        return std.meta.stringToEnum(Policy, s);
    }
};

/// Writes the allowed subset of `in` into `out` and returns it.
/// `out.len` must be >= `in.len` (output never grows).
/// Each web message is filtered independently; xterm.js delivers each key's
/// escape sequence whole within a single onData call.
pub fn filter(policy: Policy, in: []const u8, out: []u8) []u8 {
    std.debug.assert(out.len >= in.len);
    switch (policy) {
        .none => return out[0..0],
        .keys => return filterKeys(in, out),
        .text => {},
    }
    if (!std.unicode.utf8ValidateSlice(in)) return out[0..0];

    var o: usize = 0;
    var i: usize = 0;
    while (i < in.len) {
        const c = in[i];
        if (c == 0x1b) {
            const seq_len = escapeLen(policy, in[i..]);
            if (seq_len > 0) {
                @memcpy(out[o..][0..seq_len], in[i..][0..seq_len]);
                o += seq_len;
                i += seq_len;
            } else {
                // Drop the whole unrecognised sequence, not just the ESC, so
                // its tail is not misread as literal typing.
                i += skipLen(in[i..]);
            }
            continue;
        }
        // C1 controls U+0080..U+009F (UTF-8 C2 80..C2 9F), e.g. 8-bit CSI.
        if (c == 0xc2 and i + 1 < in.len and in[i + 1] >= 0x80 and in[i + 1] <= 0x9f) {
            i += 2;
            continue;
        }
        if (byteAllowed(policy, c)) {
            out[o] = c;
            o += 1;
        }
        i += 1;
    }
    return out[0..o];
}

fn filterKeys(in: []const u8, out: []u8) []u8 {
    // A lone Esc press arrives as exactly one ESC byte; any other ESC is part
    // of a sequence (arrows, Alt+key, ...) and is dropped with its tail.
    if (in.len == 1 and in[0] == 0x1b) {
        out[0] = 0x1b;
        return out[0..1];
    }
    if (std.mem.indexOfScalar(u8, in, 0x1b) != null) return out[0..0];
    var o: usize = 0;
    for (in) |c| {
        if (byteAllowed(.keys, c)) {
            out[o] = c;
            o += 1;
        }
    }
    return out[0..o];
}

/// Cross-message state, shared by every web connection to a session.
/// Each message is filtered on its own, so without this an escape sequence
/// could be split across two messages (ESC then "[6n") and reassembled in
/// the PTY input pipe.
pub const State = struct {
    last_was_esc: bool = false,
    last_esc_ms: i64 = std.math.minInt(i64),
};

pub fn filterStateful(policy: Policy, st: *State, in_full: []const u8, out: []u8, now_ms: i64) []u8 {
    var in = in_full;
    if (st.last_was_esc and in.len > 0) switch (in[0]) {
        '[', 'O', ']', 'P', '_', '^' => in = in[1..],
        else => {},
    };
    if (policy == .keys and in.len == 1 and in[0] == 0x1b) {
        if (now_ms -| st.last_esc_ms < 1000) return out[0..0]; // no Esc Esc
        st.last_esc_ms = now_ms;
    }
    const r = filter(policy, in, out);
    if (r.len > 0) st.last_was_esc = r[r.len - 1] == 0x1b;
    return r;
}

fn byteAllowed(policy: Policy, c: u8) bool {
    return switch (policy) {
        .none => false,
        .keys => switch (c) {
            '0'...'9', 'y', 'n', 'Y', 'N', '\r' => true,
            else => false,
        },
        .text => switch (c) {
            '\r', '\n', '\t', 0x7f, 0x03 => true, // Enter, paste newlines, Tab, Backspace, Ctrl+C
            0x00...0x02, 0x04...0x08, 0x0b, 0x0c, 0x0e...0x1a, 0x1c...0x1f => false,
            else => true, // printable ASCII and UTF-8 bytes (validated above)
        },
    };
}

/// Length of an allowed escape sequence at the start of `s` (s[0] == ESC),
/// or 0 if it is not allowed.
fn escapeLen(policy: Policy, s: []const u8) usize {
    if (s.len == 1) return 1; // lone Esc: cancels agent prompts
    switch (s[1]) {
        '[' => {
            const csi = parseCsi(s) orelse return 0;
            if (csi.params.len == 0) switch (csi.final) {
                'A', 'B', 'C', 'D' => return csi.len, // arrows
                'H', 'F' => return if (policy == .text) csi.len else 0, // Home/End
                // Shift+Tab cycles the agent's permission mode; only in text policy.
                'Z' => return if (policy == .text) csi.len else 0,
                else => return 0,
            };
            if (policy == .text and csi.final == '~') {
                const allowed = [_][]const u8{ "3", "5", "6", "200", "201" }; // Del, PgUp, PgDn, paste start/end
                for (allowed) |p| if (std.mem.eql(u8, csi.params, p)) return csi.len;
            }
            return 0;
        },
        'O' => {
            // SS3 arrows, sent when the app enables application cursor mode.
            if (s.len >= 3) switch (s[2]) {
                'A', 'B', 'C', 'D' => return 3,
                else => {},
            };
            return 0;
        },
        // OSC / DCS / APC / PM string sequences are never keystrokes.
        ']', 'P', '_', '^' => return 0,
        else => {
            // ESC followed by an ordinary byte (Alt+key). Allow the Esc alone;
            // the following byte is filtered on its own.
            return 1;
        },
    }
}

const Csi = struct { params: []const u8, final: u8, len: usize };

fn parseCsi(s: []const u8) ?Csi {
    // ESC [ params(0x30-0x3F)* intermediates(0x20-0x2F)* final(0x40-0x7E)
    var i: usize = 2;
    const p_start = i;
    while (i < s.len and s[i] >= 0x30 and s[i] <= 0x3f) i += 1;
    const p_end = i;
    while (i < s.len and s[i] >= 0x20 and s[i] <= 0x2f) i += 1;
    if (i >= s.len or s[i] < 0x40 or s[i] > 0x7e) return null;
    if (i != p_end) return null; // intermediates present: not a key we accept
    return .{ .params = s[p_start..p_end], .final = s[i], .len = i + 1 };
}

/// How many bytes to discard for a rejected escape sequence.
fn skipLen(s: []const u8) usize {
    if (s.len >= 2 and s[1] == '[') {
        var i: usize = 2;
        while (i < s.len and s[i] >= 0x20 and s[i] <= 0x3f) i += 1;
        return if (i < s.len) i + 1 else i;
    }
    if (s.len >= 3 and s[1] == 'O') return 3;
    if (s.len >= 2 and (s[1] == ']' or s[1] == 'P' or s[1] == '_' or s[1] == '^')) {
        // Skip to the string terminator: BEL or ESC '\', else to the end.
        var i: usize = 2;
        while (i < s.len) : (i += 1) {
            if (s[i] == 0x07) return i + 1;
            if (s[i] == 0x1b and i + 1 < s.len and s[i + 1] == '\\') return i + 2;
        }
        return s.len;
    }
    return @min(s.len, 2);
}

const testing = std.testing;

fn expectFiltered(policy: Policy, in: []const u8, expected: []const u8) !void {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings(expected, filter(policy, in, &buf));
}

test "none drops everything" {
    try expectFiltered(.none, "1\r", "");
}

test "keys allows prompt answers" {
    try expectFiltered(.keys, "1", "1");
    try expectFiltered(.keys, "\r", "\r");
    try expectFiltered(.keys, "\x1b", "\x1b");
    try expectFiltered(.keys, "y", "y");
}

test "keys blocks history recall, editing and Alt combos" {
    try expectFiltered(.keys, "\x1b[A", ""); // Up: would recall old prompts
    try expectFiltered(.keys, "\x1bOB", "");
    try expectFiltered(.keys, "\x7f", ""); // Backspace: edits the owner's draft
    try expectFiltered(.keys, "\x1b\x1b", ""); // Esc Esc: rewind menu
    try expectFiltered(.keys, "\x1b1", "");
}

test "stateful: split escape sequence is not reassembled" {
    var st: State = .{};
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("\x1b", filterStateful(.text, &st, "\x1b", &buf, 0));
    try testing.expectEqualStrings("6n", filterStateful(.text, &st, "[6n", &buf, 1));
    try testing.expectEqualStrings("[x", filterStateful(.text, &st, "[x", &buf, 2));
}

test "stateful: keys Esc is rate limited, first use does not overflow" {
    var st: State = .{};
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("\x1b", filterStateful(.keys, &st, "\x1b", &buf, 0));
    try testing.expectEqualStrings("", filterStateful(.keys, &st, "\x1b", &buf, 500));
    try testing.expectEqualStrings("\x1b", filterStateful(.keys, &st, "\x1b", &buf, 1500));
}

test "text drops C1 controls" {
    try expectFiltered(.text, "a\xc2\x9b6nb", "a6nb");
    try expectFiltered(.text, "\xc2\xa0", "\xc2\xa0"); // NBSP is fine
}

test "keys blocks free text and control" {
    try expectFiltered(.keys, "rm -rf", "");
    try expectFiltered(.keys, "\x03", "");
    try expectFiltered(.keys, "\x1b[Z", ""); // shift+tab
    try expectFiltered(.keys, "!ls\r", "\r");
}

test "text allows typing and paste" {
    try expectFiltered(.text, "hello world\r", "hello world\r");
    try expectFiltered(.text, "\x1b[200~a\nb\x1b[201~", "\x1b[200~a\nb\x1b[201~");
    try expectFiltered(.text, "héllo", "héllo");
    try expectFiltered(.text, "\x03", "\x03");
}

test "text drops unknown escapes and stray controls" {
    // Device status / window manipulation queries must not reach the app.
    try expectFiltered(.text, "a\x1b[6nb", "ab");
    try expectFiltered(.text, "\x1b]0;title\x07x", "x"); // OSC dropped whole
    try expectFiltered(.text, "\x1bPq\x1b\\y", "y"); // DCS dropped whole
    try expectFiltered(.text, "a\x00b\x1ac", "abc");
    try expectFiltered(.text, "\x1b[1;5A", ""); // modified arrows not needed
}

test "text rejects invalid utf8" {
    try expectFiltered(.text, "ab\xffcd", "");
}

test "output never exceeds input" {
    var buf: [4]u8 = undefined;
    const r = filter(.text, "\x1b[A", &buf);
    try testing.expectEqual(@as(usize, 3), r.len);
}
