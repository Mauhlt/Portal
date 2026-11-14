//! What becomes of a dictated transcript once it is in the input line:
//! the three responses stt learns from (docs/stt-sync-contract.md):
//!
//!   * sent unchanged          nothing (silence confirms it after 60 s);
//!   * edited, then sent       feedback(id, corrected, true), where
//!                             `corrected` is the sent line minus what was
//!                             typed before the dictation;
//!   * cleared (Esc) or sent   discard: feedback(id, _, false). Also when
//!     with the dictated part  a sent line no longer starts with what was
//!     gone                    typed before (the correction can't be told
//!                             apart from it).
//!
//! One transcript is tracked at a time: a second dictation into the same
//! line settles the first (kept if its text is still in the line, else
//! discarded). Pure logic: the device glue performs the decisions.

const std = @import("std");

/// Transcripts are at most 8 KiB (src/speech/limits.zig max_text).
pub const max_text = 8 * 1024;

pub const Decision = union(enum) {
    none,
    /// feedback(id, text, true): learn the correction.
    learn: struct { id: u64, text: []const u8 },
    /// feedback(id, _, false).
    discard: u64,
};

pub const Tracker = struct {
    id: u64 = 0,
    /// The line before the transcript was added, and the transcript.
    before_buf: [max_text]u8 = undefined,
    before_len: usize = 0,
    text_buf: [max_text]u8 = undefined,
    text_len: usize = 0,
    out_buf: [max_text]u8 = undefined,

    pub fn pending(t: *const Tracker) bool {
        return t.id != 0;
    }

    fn before(t: *const Tracker) []const u8 {
        return t.before_buf[0..t.before_len];
    }
    fn text(t: *const Tracker) []const u8 {
        return t.text_buf[0..t.text_len];
    }

    /// The text to append to `line` for transcript `id` (a space between
    /// them when needed), written into `out`. Settles a previous transcript
    /// first: that decision is returned through `settled`.
    pub fn added(t: *Tracker, id: u64, transcript: []const u8, line: []const u8, out: []u8, settled: *Decision) []const u8 {
        settled.* = .none;
        if (t.id != 0) {
            settled.* = if (std.mem.indexOf(u8, line, t.text()) != null) .none else .{ .discard = t.id };
            t.id = 0;
        }
        const words = std.mem.trim(u8, transcript, " \t\r\n");
        const sep: []const u8 = if (line.len > 0 and line[line.len - 1] != ' ' and words.len > 0) " " else "";
        const s = std.fmt.bufPrint(out, "{s}{s}", .{ sep, words }) catch out[0..0];
        if (id == 0 or words.len == 0 or line.len > max_text or words.len > max_text) return s;
        t.id = id;
        @memcpy(t.before_buf[0..line.len], line);
        t.before_len = line.len;
        // What the user sees of it: the line as it will be, minus the start.
        @memcpy(t.text_buf[0..words.len], words);
        t.text_len = words.len;
        return s;
    }

    /// The line `sent` was sent (Enter or Send).
    pub fn sent(t: *Tracker, line: []const u8) Decision {
        if (t.id == 0) return .none;
        const id = t.id;
        t.id = 0;
        const b = std.mem.trim(u8, t.before(), " ");
        if (!std.mem.startsWith(u8, line, b)) return .{ .discard = id };
        const corrected = std.mem.trim(u8, line[b.len..], " \t");
        if (corrected.len == 0) return .{ .discard = id };
        if (std.mem.eql(u8, corrected, t.text())) return .none;
        @memcpy(t.out_buf[0..corrected.len], corrected);
        return .{ .learn = .{ .id = id, .text = t.out_buf[0..corrected.len] } };
    }

    /// The line was cleared without being sent (Esc).
    pub fn cleared(t: *Tracker) Decision {
        if (t.id == 0) return .none;
        const id = t.id;
        t.id = 0;
        return .{ .discard = id };
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "sent unchanged: nothing (silence confirms)" {
    var t: Tracker = .{};
    var out: [128]u8 = undefined;
    var d: Decision = undefined;
    const add = t.added(7, " Run the tests. ", "", &out, &d);
    try testing.expectEqualStrings("Run the tests.", add);
    try testing.expect(t.pending());
    try testing.expect(t.sent("Run the tests.") == .none);
    try testing.expect(!t.pending());
}

test "edited then sent: learn the correction, without what was typed before" {
    var t: Tracker = .{};
    var out: [128]u8 = undefined;
    var d: Decision = undefined;
    const add = t.added(9, "written in Piersig.", "Note:", &out, &d);
    try testing.expectEqualStrings(" written in Piersig.", add);
    const r = t.sent("Note: written in pure Zig.");
    try testing.expectEqual(@as(u64, 9), r.learn.id);
    try testing.expectEqualStrings("written in pure Zig.", r.learn.text);
}

test "discard: cleared, emptied, or the typed start changed; nothing heard" {
    var t: Tracker = .{};
    var out: [128]u8 = undefined;
    var d: Decision = undefined;
    _ = t.added(3, "hello", "", &out, &d);
    try testing.expectEqual(@as(u64, 3), t.cleared().discard);
    try testing.expect(t.cleared() == .none);
    _ = t.added(4, "hello", "abc ", &out, &d);
    try testing.expectEqual(@as(u64, 4), t.sent("abc").discard);
    _ = t.added(5, "hello", "abc ", &out, &d);
    try testing.expectEqual(@as(u64, 5), t.sent("xyz hello").discard);
    // id 0: nothing heard, nothing to track.
    _ = t.added(0, "", "", &out, &d);
    try testing.expect(!t.pending());
}

test "a second dictation settles the first" {
    var t: Tracker = .{};
    var out: [128]u8 = undefined;
    var d: Decision = undefined;
    _ = t.added(1, "first part", "", &out, &d);
    try testing.expect(d == .none);
    _ = t.added(2, "second", "first part", &out, &d);
    try testing.expect(d == .none); // still in the line: silence confirms it
    _ = t.added(3, "third", "changed", &out, &d);
    try testing.expectEqual(@as(u64, 2), d.discard);
    try testing.expectEqual(@as(u64, 3), t.id);
}
