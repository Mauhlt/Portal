//! Subagent sub-tabs on the wire (docs/protocol.md section 3e): the
//! read-only conversations of the subagents a tab's agent session
//! spawned, listed under that tab. One implementation for the server
//! (web.zig), the native client (client/src/net/client.zig) and tests.
//!
//!   {"t":"subtabs","id":"<tab, 32 hex>","subs":[SUB,...]}
//!   SUB = {"id":"<32 hex>","name":"<description>","done":true|false}
//!
//!   * scoped like `convo`: only the tab the viewer watches (`id`); sent
//!     after every `session` (and after hello) and whenever that tab's
//!     sub-tabs change;
//!   * `id`: a random 128-bit id of Portal's own, never the subagent's id
//!     in the agent, never reused while the desktop runs;
//!   * `name`: the description the session gave the subagent, scrubbed
//!     on the desktop (paths, the user's name), one printable line of at
//!     most `tabs.max_name` bytes, escaped like tab names (`"`, `\`);
//!   * `done`: the subagent finished (its sub-tab stays, read-only).
//!
//! A viewer shows a sub-tab's conversation with `a:<sub id>` and goes back
//! to the tab's own with `a:` (viewFrame). Sub-tabs take no input.
//!
//! Parsing is strict and bounded: anything malformed, too long or with
//! more than `max_subs` entries is rejected as a whole.

const std = @import("std");
const tabs = @import("tabs.zig");

pub const Id = tabs.Id;
/// Most sub-tabs one tab keeps (and a list may carry).
pub const max_subs = 16;
pub const max_name = tabs.max_name;
/// Room for any `subtabs` message.
pub const max_message = 64 + tabs.hex_len + max_subs * (32 + tabs.hex_len + 2 * max_name + 32);

pub const Entry = struct {
    id: Id = @splat(0),
    name_buf: [max_name]u8 = undefined,
    name_len: u8 = 0,
    done: bool = false,

    pub fn name(e: *const Entry) []const u8 {
        return e.name_buf[0..e.name_len];
    }

    pub fn setName(e: *Entry, n: []const u8) void {
        const len = @min(n.len, max_name);
        @memcpy(e.name_buf[0..len], n[0..len]);
        e.name_len = @intCast(len);
    }
};

pub const List = struct {
    /// The tab these sub-tabs belong to.
    tab: Id = @splat(0),
    items: [max_subs]Entry = undefined,
    len: usize = 0,

    pub fn slice(l: *const List) []const Entry {
        return l.items[0..l.len];
    }

    pub fn find(l: *const List, id: Id) ?usize {
        for (l.items[0..l.len], 0..) |e, i| if (std.mem.eql(u8, &e.id, &id)) return i;
        return null;
    }
};

/// Writes a whole `subtabs` message. Names must be tabs.validName.
pub fn write(w: *std.Io.Writer, tab: Id, list: []const Entry) !void {
    try w.print("{{\"t\":\"subtabs\",\"id\":\"{s}\",\"subs\":[", .{&tabs.idHex(tab)});
    for (list, 0..) |e, i| {
        if (i > 0) try w.writeByte(',');
        try w.print("{{\"id\":\"{s}\",\"name\":\"", .{&tabs.idHex(e.id)});
        for (e.name()) |c| {
            if (c == '"' or c == '\\') try w.writeByte('\\');
            try w.writeByte(c);
        }
        try w.print("\",\"done\":{}}}", .{e.done});
    }
    try w.writeAll("]}");
}

/// The frame a viewer sends to show sub-tab `id` (or, null, the tab's own
/// conversation again): "a:<32 hex>" / "a:".
pub fn viewFrame(id: ?Id, out: *[2 + tabs.hex_len]u8) []const u8 {
    out[0] = 'a';
    out[1] = ':';
    const i = id orelse return out[0..2];
    out[2..].* = tabs.idHex(i);
    return out[0..];
}

/// A name fit for the wire from any text (already scrubbed): control
/// characters and line breaks become spaces, runs of spaces one, cut at
/// `max_name` bytes on a character boundary; "Subagent" if nothing is left
/// or it is not a tabs.validName.
pub fn displayName(raw: []const u8, out: *[max_name]u8) []const u8 {
    var n: usize = 0;
    var i: usize = 0;
    var space = true; // drop leading spaces
    while (i < raw.len) {
        const len = std.unicode.utf8ByteSequenceLength(raw[i]) catch {
            i += 1;
            continue;
        };
        if (i + len > raw.len) break;
        const seq = raw[i..][0..len];
        i += len;
        const cp = std.unicode.utf8Decode(seq) catch continue;
        const blank = switch (cp) {
            0x00...0x20, 0x7F...0x9F, 0x2028, 0x2029, 0x202A...0x202E, 0x2066...0x2069, 0x200E, 0x200F, 0x061C, 0xFEFF => true,
            else => false,
        };
        if (blank) {
            if (space) continue;
            if (n + 1 > out.len) break;
            out[n] = ' ';
            n += 1;
            space = true;
            continue;
        }
        if (n + len > out.len) break;
        @memcpy(out[n..][0..len], seq);
        n += len;
        space = false;
    }
    while (n > 0 and out[n - 1] == ' ') n -= 1;
    if (!tabs.validName(out[0..n])) {
        const d = "Subagent";
        @memcpy(out[0..d.len], d);
        return out[0..d.len];
    }
    return out[0..n];
}

/// A `subtabs` message, or null if it is not one or is malformed.
pub fn parse(text: []const u8) ?List {
    if (text.len > max_message) return null;
    if (std.mem.indexOf(u8, text, "\"t\":\"subtabs\"") == null) return null;
    var list: List = .{};
    list.tab = tabs.idField(text, "id") orelse return null;
    var p = tabs.fieldValue(text, "subs") orelse return null;
    if (p >= text.len or text[p] != '[') return null;
    p = tabs.skipSpace(text, p + 1);
    if (p < text.len and text[p] == ']') return list;
    while (true) {
        if (list.len == max_subs) return null;
        p = tabs.skipSpace(text, p);
        p = parseEntry(text, p, &list.items[list.len]) orelse return null;
        list.len += 1;
        p = tabs.skipSpace(text, p);
        if (p >= text.len) return null;
        if (text[p] == ']') return list;
        if (text[p] != ',') return null;
        p += 1;
    }
}

fn parseEntry(text: []const u8, start: usize, e: *Entry) ?usize {
    var p = start;
    if (p >= text.len or text[p] != '{') return null;
    p += 1;
    var have_id = false;
    var have_name = false;
    e.* = .{};
    var key_buf: [8]u8 = undefined;
    var val_buf: [max_name]u8 = undefined;
    while (true) {
        p = tabs.skipSpace(text, p);
        if (p < text.len and text[p] == '}') break;
        const k = tabs.readString(text, &p, &key_buf) orelse return null;
        p = tabs.skipSpace(text, p);
        if (p >= text.len or text[p] != ':') return null;
        p = tabs.skipSpace(text, p + 1);
        if (std.mem.eql(u8, k, "done")) {
            if (std.mem.startsWith(u8, text[p..], "true")) {
                e.done = true;
                p += 4;
            } else if (std.mem.startsWith(u8, text[p..], "false")) {
                e.done = false;
                p += 5;
            } else return null;
        } else {
            const v = tabs.readString(text, &p, &val_buf) orelse return null;
            if (std.mem.eql(u8, k, "id")) {
                e.id = tabs.parseId(v) orelse return null;
                have_id = true;
            } else if (std.mem.eql(u8, k, "name")) {
                if (!tabs.validName(v)) return null;
                e.setName(v);
                have_name = true;
            }
        }
        p = tabs.skipSpace(text, p);
        if (p >= text.len) return null;
        if (text[p] == ',') {
            p += 1;
            continue;
        }
        if (text[p] == '}') break;
        return null;
    }
    if (!have_id or !have_name) return null;
    return p + 1;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "write and parse round-trip; strict" {
    var l: [2]Entry = .{ .{ .id = @splat(0xab) }, .{ .id = @splat(0x01), .done = true } };
    l[0].setName("Review \"the\" diff\\x");
    l[1].setName("Find tests");
    var buf: [max_message]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const tab: Id = @splat(7);
    try write(&w, tab, &l);
    const text = w.buffered();
    const back = parse(text).?;
    try testing.expectEqualSlices(u8, &tab, &back.tab);
    try testing.expectEqual(@as(usize, 2), back.len);
    try testing.expectEqualStrings("Review \"the\" diff\\x", back.items[0].name());
    try testing.expect(!back.items[0].done and back.items[1].done);
    try testing.expectEqual(@as(?usize, 1), back.find(@splat(0x01)));

    var ew: std.Io.Writer = .fixed(&buf);
    try write(&ew, tab, &.{});
    try testing.expectEqual(@as(usize, 0), parse(ew.buffered()).?.len);

    const id = "abababababababababababababababab";
    try testing.expect(parse("{\"t\":\"subtabs\",\"id\":\"" ++ id ++ "\",\"subs\":[{\"id\":\"" ++ id ++ "\"}]}") == null); // no name
    try testing.expect(parse("{\"t\":\"subtabs\",\"id\":\"" ++ id ++ "\",\"subs\":[{\"id\":\"" ++ id ++ "\",\"name\":\"a\nb\"}]}") == null);
    try testing.expect(parse("{\"t\":\"subtabs\",\"id\":\"" ++ id ++ "\",\"subs\":[{\"id\":\"" ++ id ++ "\",\"name\":\"x\",\"done\":1}]}") == null);
    try testing.expect(parse("{\"t\":\"tabs\",\"id\":\"" ++ id ++ "\",\"subs\":[]}") == null);
    try testing.expect(parse("{\"t\":\"subtabs\",\"subs\":[]}") == null);
    // Too many entries.
    var many: [max_subs + 1]Entry = undefined;
    for (&many) |*e| {
        e.* = .{};
        e.setName("x");
    }
    var big: [max_message * 2]u8 = undefined;
    var bw: std.Io.Writer = .fixed(&big);
    try write(&bw, tab, &many);
    try testing.expect(parse(bw.buffered()) == null);
}

test "displayName: one printable line, cut on a character boundary" {
    var out: [max_name]u8 = undefined;
    try testing.expectEqualStrings("Find the bug", displayName("  Find\tthe\n\nbug  ", &out));
    try testing.expectEqualStrings("Subagent", displayName("", &out));
    try testing.expectEqualStrings("Subagent", displayName("\x1b\x07", &out));
    try testing.expectEqualStrings("a b", displayName("a\u{202E}b", &out));
    var long: [80]u8 = undefined; // e-acute 40 times
    for (0..40) |k| long[2 * k ..][0..2].* = "é".*;
    const cut = displayName(&long, &out);
    try testing.expectEqual(@as(usize, 64), cut.len);
    try testing.expect(std.unicode.utf8ValidateSlice(cut));
}

test "viewFrame" {
    var b: [34]u8 = undefined;
    try testing.expectEqualStrings("a:", viewFrame(null, &b));
    try testing.expectEqualStrings("a:0101010101010101010101010101010101"[0..34], viewFrame(@splat(1), &b));
}
