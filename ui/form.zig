//! Editing state for the UI's panels: bounded one-line text fields and a
//! focus ring. Pure data, no drawing (frame.Panel draws what the panels
//! build from these), so the panels' state machines are unit-tested.

const std = @import("std");

/// A one-line UTF-8 text field holding at most `cap` bytes. Control
/// characters, line breaks and bidi controls are never stored.
pub fn TextField(comptime cap: usize) type {
    return struct {
        const Self = @This();
        buf: [cap]u8 = undefined,
        len: usize = 0,

        pub fn text(f: *const Self) []const u8 {
            return f.buf[0..f.len];
        }

        pub fn clear(f: *Self) void {
            f.len = 0;
        }

        /// Replaces the contents (cut at a codepoint boundary if too long;
        /// characters that `insert` would refuse are dropped).
        pub fn set(f: *Self, s: []const u8) void {
            f.len = 0;
            _ = f.insertText(s);
        }

        /// Appends one character. False if it is not allowed or does not fit.
        pub fn insert(f: *Self, cp: u21) bool {
            if (!allowed(cp)) return false;
            var enc: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(cp, &enc) catch return false;
            if (f.len + n > cap) return false;
            @memcpy(f.buf[f.len..][0..n], enc[0..n]);
            f.len += n;
            return true;
        }

        /// Appends pasted text up to its first line break. Returns the
        /// number of characters added.
        pub fn insertText(f: *Self, s: []const u8) usize {
            var added: usize = 0;
            const view = std.unicode.Utf8View.init(s) catch return 0;
            var it = view.iterator();
            while (it.nextCodepoint()) |cp| {
                if (cp == '\r' or cp == '\n') break;
                if (cp == '\t') {
                    if (f.insert(' ')) added += 1;
                    continue;
                }
                if (f.insert(cp)) added += 1;
            }
            return added;
        }

        /// Deletes the last character.
        pub fn backspace(f: *Self) void {
            if (f.len == 0) return;
            var i = f.len - 1;
            while (i > 0 and (f.buf[i] & 0xC0) == 0x80) i -= 1;
            f.len = i;
        }
    };
}

/// Characters a text field accepts: printable, not a line/paragraph
/// separator or bidi control (which could make the text read differently).
pub fn allowed(cp: u21) bool {
    return switch (cp) {
        0x00...0x1F, 0x7F...0x9F, 0x2028, 0x2029, 0x202A...0x202E, 0x2066...0x2069, 0x200E, 0x200F, 0x061C, 0xFEFF => false,
        else => true,
    };
}

/// Which of `count` focusable items (fields, then buttons) has the focus.
pub const Focus = struct {
    index: u8 = 0,
    count: u8 = 1,

    pub fn reset(f: *Focus, count: u8, index: u8) void {
        f.count = @max(count, 1);
        f.index = @min(index, f.count - 1);
    }
    pub fn next(f: *Focus) void {
        f.index = (f.index + 1) % f.count;
    }
    pub fn prev(f: *Focus) void {
        f.index = (f.index + f.count - 1) % f.count;
    }
    pub fn is(f: Focus, i: u8) bool {
        return f.index == i;
    }
};

const testing = std.testing;

test "TextField editing" {
    var f: TextField(8) = .{};
    try testing.expect(f.insert('a'));
    try testing.expect(f.insert(0xE9)); // é, 2 bytes
    try testing.expectEqualStrings("a\u{e9}", f.text());
    f.backspace();
    try testing.expectEqualStrings("a", f.text());
    try testing.expect(!f.insert('\n'));
    try testing.expect(!f.insert(0x202E));
    try testing.expectEqual(@as(usize, 7), f.insertText("bcdefghij"));
    try testing.expectEqualStrings("abcdefgh", f.text());
    try testing.expect(!f.insert('z')); // full
    f.set("one\ntwo");
    try testing.expectEqualStrings("one", f.text());
    f.set("x\ty");
    try testing.expectEqualStrings("x y", f.text());
    f.set("\xff bad utf8");
    try testing.expectEqualStrings("", f.text());
    f.clear();
    f.backspace();
    try testing.expectEqual(@as(usize, 0), f.len);
    // A multi-byte character that does not fit is refused whole.
    var g: TextField(2) = .{};
    try testing.expect(g.insert('a'));
    try testing.expect(!g.insert(0xE9));
    try testing.expectEqualStrings("a", g.text());
}

test "Focus ring" {
    var f: Focus = .{};
    f.reset(3, 0);
    f.next();
    f.next();
    try testing.expect(f.is(2));
    f.next();
    try testing.expect(f.is(0));
    f.prev();
    try testing.expect(f.is(2));
    f.reset(2, 9);
    try testing.expect(f.is(1));
    f.reset(0, 0);
    f.next();
    try testing.expect(f.is(0));
}
