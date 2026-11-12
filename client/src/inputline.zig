//! The native client's instruction line (`instruct` mode, the server's
//! default): a one-line field under the answer bar, the counterpart of the
//! browser's input box. What Enter does with the text, the answer words and
//! the refusal texts are the shared logic (module "inputrules",
//! src/inputrules/send.zig), so both clients behave the same:
//!
//!   * Enter: an answer word ("yes", "two", "esc") presses that key; any
//!     other text is checked with the server's rules and sent as an
//!     instruction line (`l:<text>`); a refusal is shown and the text kept.
//!     On an empty line Enter presses Enter (to confirm a prompt).
//!   * Esc clears the line; on an empty line it presses Esc.
//!   * Backspace edits; other keys do nothing here.
//!   * A line the server refuses ({"t":"rejected"}) comes back into the
//!     field if nothing new was typed meanwhile.
//!
//! Pure state, no drawing: remote.zig builds the bottom pane from `snapshot()`.

const std = @import("std");
const rules = @import("inputrules");
const view_mod = @import("view");
const input = view_mod.input;

/// A little above the line limit, so an over-long line gets the "too long"
/// note instead of silently refusing more characters.
pub const cap = rules.max_line_bytes + 16;

pub const Line = struct {
    field: view_mod.form.TextField(cap) = .{},
    /// The last line sent, for a server refusal.
    last_buf: [rules.max_line_bytes]u8 = undefined,
    last_len: usize = 0,
    note_buf: [192]u8 = undefined,
    note_len: usize = 0,
    note_tone: rules.Tone = .neutral,
    frame_buf: [rules.max_frame]u8 = undefined,
    scratch: [cap]u8 = undefined,

    pub fn text(l: *const Line) []const u8 {
        return l.field.text();
    }

    pub fn note(l: *const Line) []const u8 {
        return l.note_buf[0..l.note_len];
    }

    fn setNote(l: *Line, t: []const u8, tone: rules.Tone) void {
        const n = @min(t.len, l.note_buf.len);
        @memcpy(l.note_buf[0..n], t[0..n]);
        l.note_len = n;
        l.note_tone = tone;
    }

    /// The note for what Enter would do now (or the help on an empty line).
    fn preview(l: *Line) void {
        var buf: [192]u8 = undefined;
        const n = rules.preview(.instruct, l.field.text(), .native, &buf);
        l.setNote(n.text, n.tone);
    }

    fn frame(l: *Line, prefix: []const u8, body: []const u8) []const u8 {
        @memcpy(l.frame_buf[0..prefix.len], prefix);
        @memcpy(l.frame_buf[prefix.len..][0..body.len], body);
        return l.frame_buf[0 .. prefix.len + body.len];
    }

    /// Presses `k:<key>` through `sender` (see `onKey`).
    fn press(l: *Line, key: []const u8, sender: anytype) bool {
        if (!sender.send(l.frame("k:", key))) {
            l.setNote(rules.refusalText(.offline), .bad);
            return false;
        }
        var buf: [32]u8 = undefined;
        l.setNote(std.fmt.bufPrint(&buf, "Pressed {s}.", .{rules.keyLabel(key)}) catch "", .ok);
        return true;
    }

    /// A special key while the line has the keyboard. `sender` has
    /// `fn send(self, frame: []const u8) bool` (false: not connected).
    /// Returns true when the line or its note changed (redraw).
    pub fn onKey(l: *Line, key: input.Key, mods: input.Mods, sender: anytype) bool {
        if (mods.alt or mods.super) return false;
        switch (key) {
            .enter => l.submit(sender),
            .escape => if (l.field.len > 0) {
                l.field.clear();
                l.preview();
            } else {
                _ = l.press("esc", sender);
            },
            .backspace => {
                l.field.backspace();
                l.preview();
            },
            else => return false,
        }
        return true;
    }

    /// A typed character. Returns true when the line changed.
    pub fn onChar(l: *Line, cp: u21, mods: input.Mods) bool {
        if (mods.ctrl or mods.alt or mods.super) return false;
        if (!l.field.insert(cp)) return false;
        l.preview();
        return true;
    }

    /// Enter: what the shared `decide` says.
    fn submit(l: *Line, sender: anytype) void {
        const t = l.field.text();
        if (std.mem.trim(u8, t, " \t").len == 0) {
            if (l.press("enter", sender)) l.field.clear();
            return;
        }
        switch (rules.decide(.instruct, t, &l.scratch)) {
            .refuse => |r| l.setNote(rules.refusalText(r), .bad),
            .key => |k| if (l.press(k, sender)) l.field.clear(),
            .line => |line| {
                if (!sender.send(l.frame("l:", line))) return l.setNote(rules.refusalText(.offline), .bad);
                @memcpy(l.last_buf[0..line.len], line);
                l.last_len = line.len;
                l.field.clear();
                l.setNote("Sent.", .ok);
            },
            // Not produced in instruct mode.
            .typed, .nothing => {},
        }
    }

    /// The server refused the last line (`reason`: a LineError name): say
    /// why, and put the line back unless something new was typed.
    pub fn rejected(l: *Line, reason: []const u8) void {
        if (l.field.len == 0 and l.last_len > 0) l.field.set(l.last_buf[0..l.last_len]);
        if (rules.serverRefusal(reason)) |r| {
            l.setNote(rules.refusalText(r), .bad);
        } else {
            l.setNote("The desktop refused that line.", .bad);
        }
    }

    /// What the overlay shows.
    pub fn snapshot(l: *const Line) View {
        return .{ .text = l.field.text(), .note = l.note(), .note_tone = l.note_tone };
    }
};

pub const View = struct {
    text: []const u8 = "",
    note: []const u8 = "",
    note_tone: rules.Tone = .neutral,
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

const Recorder = struct {
    frames: [8][rules.max_frame]u8 = undefined,
    lens: [8]usize = undefined,
    n: usize = 0,
    online: bool = true,

    fn send(r: *Recorder, f: []const u8) bool {
        if (!r.online) return false;
        @memcpy(r.frames[r.n][0..f.len], f);
        r.lens[r.n] = f.len;
        r.n += 1;
        return true;
    }
    fn last(r: *const Recorder) []const u8 {
        return r.frames[r.n - 1][0..r.lens[r.n - 1]];
    }
};

fn typeText(l: *Line, s: []const u8) void {
    var it = std.unicode.Utf8View.initUnchecked(s).iterator();
    while (it.nextCodepoint()) |cp| _ = l.onChar(cp, .{});
}

test "instruction lines, answer words, Enter and Esc on an empty line" {
    var l: Line = .{};
    var r: Recorder = .{};
    typeText(&l, "run the tests");
    try testing.expectEqualStrings("run the tests", l.text());
    _ = l.onKey(.enter, .{}, &r);
    try testing.expectEqualStrings("l:run the tests", r.last());
    try testing.expectEqualStrings("", l.text());
    try testing.expectEqualStrings("Sent.", l.note());
    // An answer word presses its key.
    typeText(&l, "Yes.");
    _ = l.onKey(.enter, .{}, &r);
    try testing.expectEqualStrings("k:y", r.last());
    try testing.expectEqualStrings("Pressed Yes.", l.note());
    typeText(&l, "two");
    _ = l.onKey(.enter, .{ .ctrl = true }, &r); // Ctrl+Enter sends too
    try testing.expectEqualStrings("k:2", r.last());
    // Empty line: Enter and Esc are pressed.
    _ = l.onKey(.enter, .{}, &r);
    try testing.expectEqualStrings("k:enter", r.last());
    _ = l.onKey(.escape, .{}, &r);
    try testing.expectEqualStrings("k:esc", r.last());
    // Esc on a non-empty line clears it and sends nothing.
    const before = r.n;
    typeText(&l, "oops");
    _ = l.onKey(.escape, .{}, &r);
    try testing.expectEqualStrings("", l.text());
    try testing.expectEqual(before, r.n);
    // Backspace edits; arrows do nothing here.
    typeText(&l, "ab");
    _ = l.onKey(.backspace, .{}, &r);
    try testing.expectEqualStrings("a", l.text());
    try testing.expect(!l.onKey(.up, .{}, &r));
    try testing.expect(!l.onChar('v', .{ .ctrl = true }));
    try testing.expectEqual(before, r.n);
}

test "local refusals keep the text; offline keeps it too" {
    var l: Line = .{};
    var r: Recorder = .{};
    typeText(&l, "!rm -rf .");
    try testing.expectEqual(rules.Tone.bad, l.note_tone); // the preview warns while typing
    _ = l.onKey(.enter, .{}, &r);
    try testing.expectEqual(@as(usize, 0), r.n);
    try testing.expectEqualStrings("!rm -rf .", l.text());
    try testing.expectEqualStrings(rules.refusalText(.shell_escape), l.note());
    l.field.clear();
    typeText(&l, "/permissions");
    _ = l.onKey(.enter, .{}, &r);
    try testing.expectEqualStrings(rules.refusalText(.slash_command), l.note());
    l.field.clear();
    typeText(&l, "# remember");
    _ = l.onKey(.enter, .{}, &r);
    try testing.expectEqualStrings(rules.refusalText(.memory_shortcut), l.note());
    try testing.expectEqual(@as(usize, 0), r.n);
    // Not connected: nothing lost.
    l.field.clear();
    r.online = false;
    typeText(&l, "fix it");
    _ = l.onKey(.enter, .{}, &r);
    try testing.expectEqualStrings("fix it", l.text());
    try testing.expectEqualStrings(rules.refusalText(.offline), l.note());
    // Too long: refused before sending.
    r.online = true;
    l.field.clear();
    for (0..rules.max_line_bytes + 5) |_| _ = l.onChar('a', .{});
    _ = l.onKey(.enter, .{}, &r);
    try testing.expectEqual(@as(usize, 0), r.n);
    try testing.expectEqualStrings(rules.refusalText(.too_long), l.note());
}

test "a server refusal puts the line back" {
    var l: Line = .{};
    var r: Recorder = .{};
    typeText(&l, "do the thing");
    _ = l.onKey(.enter, .{}, &r);
    l.rejected("ShellEscape");
    try testing.expectEqualStrings("do the thing", l.text());
    try testing.expectEqualStrings(rules.refusalText(.shell_escape), l.note());
    // Something new typed meanwhile stays.
    _ = l.onKey(.enter, .{}, &r);
    typeText(&l, "new");
    l.rejected("Bogus");
    try testing.expectEqualStrings("new", l.text());
    try testing.expectEqualStrings("The desktop refused that line.", l.note());
}
