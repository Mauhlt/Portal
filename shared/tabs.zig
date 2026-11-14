//! Project tabs on the wire (docs/protocol.md, protocol v2): the session
//! list in `hello` and `tabs`, session ids, tab colours and the per-tab
//! program state. One implementation for the server (web.zig) and the
//! native client (client/src/net/client.zig), so both ends agree on the
//! format and its limits.
//!
//! A session entry is `{"id":"<32 hex>","name":"<name>","color":"#rrggbb",
//! "state":"<state>"}`:
//!   * `id`: a random 128-bit id, lower-case hex, never reused while the
//!     desktop runs; never an index or a path (docs/tabs-design.md rule 3);
//!   * `name`: the desk-assigned display name (a folder's basename or
//!     `--project`), printable UTF-8, at most 64 bytes, with `"` and `\`
//!     escaped as `\"` and `\\` (the only escapes); never a path (rule 1);
//!   * `color`: the tab colour;
//!   * `state`: what the session's program reports (OSC 7501), one of
//!     `State`'s names; `waiting` means it needs an answer.
//!
//! Parsing is strict and bounded: anything malformed, too long or with
//! more than `max_tabs` entries is rejected as a whole.

const std = @import("std");
const theme = @import("theme.zig");

pub const id_len = 16;
pub const Id = [id_len]u8;
pub const hex_len = 2 * id_len;
/// Most tabs one desktop holds (and a list may carry).
pub const max_tabs = 12;
/// Longest name, in bytes (title.max_project_bytes on the server).
pub const max_name = 64;

/// What the session's program last reported (OSC 7501 "program status").
/// Untrusted: it only changes a highlight, never what input is accepted.
pub const State = enum {
    unknown,
    /// Busy (`working`).
    working,
    /// Needs an answer: a permission prompt or a question (`blocked`).
    waiting,
    /// At its prompt, nothing pending (`idle`).
    idle,
    /// Finished its turn (`done`).
    done,
    /// Reported an error (`error`).
    failed,

    pub fn wire(s: State) []const u8 {
        return switch (s) {
            .failed => "error",
            else => @tagName(s),
        };
    }

    pub fn fromWire(text: []const u8) State {
        if (std.mem.eql(u8, text, "error")) return .failed;
        if (std.mem.eql(u8, text, "failed")) return .unknown;
        return std.meta.stringToEnum(State, text) orelse .unknown;
    }

    /// The tab should draw attention: its program waits for the owner.
    pub fn attention(s: State) bool {
        return s == .waiting;
    }
};

// ------------------------------------------------------------------ ids

pub fn idHex(id: Id) [hex_len]u8 {
    return std.fmt.bytesToHex(id, .lower);
}

/// Exactly 32 lower-case hex digits, or null.
pub fn parseId(text: []const u8) ?Id {
    if (text.len != hex_len) return null;
    var out: Id = undefined;
    for (0..id_len) |i| {
        const hi = hexDigit(text[2 * i]) orelse return null;
        const lo = hexDigit(text[2 * i + 1]) orelse return null;
        out[i] = hi << 4 | lo;
    }
    return out;
}

fn hexDigit(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        else => null,
    };
}

// --------------------------------------------------------------- colours

/// The colours project names are hashed into: the theme's accent set (theme.zig,
/// the one place Portal's colours are defined).
pub const palette = theme.accents;

/// A stable colour for a project name (FNV-1a over the bytes, ignoring
/// ASCII case, into `palette`).
pub const colorFromName = theme.tabColor;

/// "#rrggbb" (either case) as 0xRRGGBB, or null.
pub fn parseColor(text: []const u8) ?u32 {
    if (text.len != 7 or text[0] != '#') return null;
    return std.fmt.parseInt(u32, text[1..], 16) catch null;
}

pub fn colorHex(c: u32) [7]u8 {
    var out: [7]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "#{x:0>6}", .{c & 0xFFFFFF}) catch unreachable;
    return out;
}

/// True if `s` may be a tab name: 1..max_name bytes of valid UTF-8 on one
/// line, no control characters, line separators or bidi controls, not
/// only spaces (the server's title.validProject is the same rule).
pub fn validName(s: []const u8) bool {
    if (s.len == 0 or s.len > max_name) return false;
    const v = std.unicode.Utf8View.init(s) catch return false;
    var it = v.iterator();
    while (it.nextCodepoint()) |cp| if (blocked(cp)) return false;
    return std.mem.trim(u8, s, " ").len > 0;
}

/// Code points no shown text may hold: C0 and C1 controls and DEL, line
/// and paragraph separators, bidi embeddings, overrides, isolates and
/// marks, and the BOM. Tab names, and (but for line feed and tab)
/// conversation and activity texts (convo.printable).
pub fn blocked(cp: u21) bool {
    return switch (cp) {
        0x00...0x1F, 0x7F...0x9F, 0x2028, 0x2029, 0x202A...0x202E, 0x2066...0x2069, 0x200E, 0x200F, 0x061C, 0xFEFF => true,
        else => false,
    };
}

// --------------------------------------------------------------- entries

pub const Entry = struct {
    id: Id = @splat(0),
    name_buf: [max_name]u8 = undefined,
    name_len: u8 = 0,
    color: u32 = 0,
    state: State = .unknown,

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
    items: [max_tabs]Entry = undefined,
    len: usize = 0,

    pub fn slice(l: *const List) []const Entry {
        return l.items[0..l.len];
    }

    pub fn find(l: *const List, id: Id) ?usize {
        for (l.items[0..l.len], 0..) |e, i| if (std.mem.eql(u8, &e.id, &id)) return i;
        return null;
    }
};

/// Writes one entry. `name` must be a validName.
pub fn writeEntry(w: *std.Io.Writer, id: Id, name: []const u8, color: u32, state: State) !void {
    try w.print("{{\"id\":\"{s}\",\"name\":\"", .{&idHex(id)});
    for (name) |c| {
        if (c == '"' or c == '\\') try w.writeByte('\\');
        try w.writeByte(c);
    }
    try w.print("\",\"color\":\"{s}\",\"state\":\"{s}\"}}", .{ &colorHex(color), state.wire() });
}

/// Writes `"sessions":[...]`.
pub fn writeList(w: *std.Io.Writer, list: []const Entry) !void {
    try w.writeAll("\"sessions\":[");
    for (list, 0..) |e, i| {
        if (i > 0) try w.writeByte(',');
        try writeEntry(w, e.id, e.name(), e.color, e.state);
    }
    try w.writeByte(']');
}

/// Room for any message carrying a full list: per entry at most
/// 38 + 32 + 2 * max_name + 7 + 7 + ~70 bytes of syntax.
pub const max_list_json = max_tabs * 300 + 64;

// --------------------------------------------------------------- parsing

/// The `"sessions":[...]` array of a server message, or null if absent or
/// malformed in any way (the whole list is then ignored).
pub fn parseList(text: []const u8) ?List {
    var p = fieldValue(text, "sessions") orelse return null;
    var list: List = .{};
    if (p >= text.len or text[p] != '[') return null;
    p += 1;
    p = skipSpace(text, p);
    if (p < text.len and text[p] == ']') return list;
    while (true) {
        if (list.len == max_tabs) return null;
        p = skipSpace(text, p);
        p = parseEntry(text, p, &list.items[list.len]) orelse return null;
        list.len += 1;
        p = skipSpace(text, p);
        if (p >= text.len) return null;
        if (text[p] == ']') return list;
        if (text[p] != ',') return null;
        p += 1;
    }
}

/// Parses `{...}` at `p` into `e`; returns the position after it.
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
        p = skipSpace(text, p);
        if (p < text.len and text[p] == '}') break;
        const k = readString(text, &p, &key_buf) orelse return null;
        p = skipSpace(text, p);
        if (p >= text.len or text[p] != ':') return null;
        p = skipSpace(text, p + 1);
        const v = readString(text, &p, &val_buf) orelse return null;
        if (std.mem.eql(u8, k, "id")) {
            e.id = parseId(v) orelse return null;
            have_id = true;
        } else if (std.mem.eql(u8, k, "name")) {
            if (!validName(v)) return null;
            e.setName(v);
            have_name = true;
        } else if (std.mem.eql(u8, k, "color")) {
            e.color = parseColor(v) orelse return null;
        } else if (std.mem.eql(u8, k, "state")) {
            e.state = State.fromWire(v);
        }
        p = skipSpace(text, p);
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

/// Reads a JSON string at `p.*` (escapes `\"` and `\\` only) into `out`
/// and moves `p` past it. Null if malformed or longer than `out`.
pub fn readString(text: []const u8, p: *usize, out: []u8) ?[]const u8 {
    var i = p.*;
    if (i >= text.len or text[i] != '"') return null;
    i += 1;
    var n: usize = 0;
    while (i < text.len) : (i += 1) {
        var c = text[i];
        if (c == '"') {
            p.* = i + 1;
            if (!std.unicode.utf8ValidateSlice(out[0..n])) return null;
            return out[0..n];
        }
        if (c < 0x20) return null;
        if (c == '\\') {
            i += 1;
            if (i >= text.len) return null;
            c = text[i];
            if (c != '"' and c != '\\') return null;
        }
        if (n >= out.len) return null;
        out[n] = c;
        n += 1;
    }
    return null;
}

pub fn skipSpace(text: []const u8, start: usize) usize {
    var p = start;
    while (p < text.len and (text[p] == ' ' or text[p] == '\t' or text[p] == '\n' or text[p] == '\r')) p += 1;
    return p;
}

/// Position just after `"name"` and a colon (top-level or not: Portal's
/// field names are unique within a message), or null.
pub fn fieldValue(text: []const u8, name: []const u8) ?usize {
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, text, from, name)) |at| {
        from = at + 1;
        if (at == 0 or text[at - 1] != '"') continue;
        var p = at + name.len;
        if (p >= text.len or text[p] != '"') continue;
        p = skipSpace(text, p + 1);
        if (p >= text.len or text[p] != ':') continue;
        return skipSpace(text, p + 1);
    }
    return null;
}

/// The session id in a field (`"session"` of hello, `"id"` of session /
/// ended), or null.
pub fn idField(text: []const u8, name: []const u8) ?Id {
    const p = fieldValue(text, name) orelse return null;
    if (p + hex_len + 2 > text.len or text[p] != '"' or text[p + 1 + hex_len] != '"') return null;
    return parseId(text[p + 1 ..][0..hex_len]);
}

/// The frame a viewer sends to watch session `id`: "s:<32 hex>".
pub fn subscribeFrame(id: Id) [2 + hex_len]u8 {
    var out: [2 + hex_len]u8 = undefined;
    out[0] = 's';
    out[1] = ':';
    out[2..].* = idHex(id);
    return out;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "ids round trip; anything else is not an id" {
    const id: Id = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xff };
    const h = idHex(id);
    try testing.expectEqualStrings("000102030405060708090a0b0c0d0eff", &h);
    try testing.expectEqual(id, parseId(&h).?);
    try testing.expect(parseId("000102030405060708090A0B0C0D0EFF") == null); // upper case
    try testing.expect(parseId("0001") == null);
    try testing.expect(parseId("000102030405060708090a0b0c0d0eff0") == null);
    try testing.expect(parseId("..\\..\\windows\\system32\\drivers") == null);
    const f = subscribeFrame(id);
    try testing.expectEqualStrings("s:000102030405060708090a0b0c0d0eff", &f);
}

test "colours" {
    try testing.expectEqual(colorFromName("Alpha"), colorFromName("alpha"));
    try testing.expectEqual(@as(u32, 0x3366CC), parseColor("#3366cc").?);
    try testing.expectEqual(@as(u32, 0x3366CC), parseColor("#3366CC").?);
    try testing.expect(parseColor("3366cc") == null);
    try testing.expect(parseColor("#3366c") == null);
    try testing.expect(parseColor("#33g6cc") == null);
    try testing.expectEqualStrings("#0a0b0c", &colorHex(0x0A0B0C));
    // Different names spread over the palette.
    var seen: [palette.len]bool = @splat(false);
    for ([_][]const u8{ "Alpha", "Beta", "Gamma", "Delta", "portal", "acme-api", "web", "docs" }) |n| {
        for (palette, 0..) |c, i| if (c == colorFromName(n)) {
            seen[i] = true;
        };
    }
    var distinct: usize = 0;
    for (seen) |s| distinct += @intFromBool(s);
    try testing.expect(distinct >= 4);
}

test "list round trip, with escapes" {
    var buf: [max_list_json]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var list: List = .{};
    list.items[0] = .{ .id = @splat(0xab), .color = 0x112233, .state = .waiting };
    list.items[0].setName("a \"b\" \\c 中");
    list.items[1] = .{ .id = @splat(0x01), .color = 0xFFFFFF, .state = .failed };
    list.items[1].setName("Beta");
    list.len = 2;
    try w.writeAll("{\"t\":\"tabs\",");
    try writeList(&w, list.slice());
    try w.writeByte('}');
    const text = w.buffered();
    try testing.expect(std.mem.indexOf(u8, text, "\"state\":\"error\"") != null);
    const got = parseList(text).?;
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expectEqualStrings("a \"b\" \\c 中", got.items[0].name());
    try testing.expectEqual(@as(u32, 0x112233), got.items[0].color);
    try testing.expectEqual(State.waiting, got.items[0].state);
    try testing.expectEqual(State.failed, got.items[1].state);
    try testing.expectEqual(@as(?usize, 1), got.find(@splat(0x01)));
    try testing.expect(got.find(@splat(0x02)) == null);
    // The largest list fits the documented bound.
    var big: List = .{};
    const worst: [max_name]u8 = @splat('"');
    for (&big.items) |*e| {
        e.* = .{};
        e.setName(&worst);
    }
    big.len = max_tabs;
    var w2: std.Io.Writer = .fixed(&buf);
    try w2.writeAll("{\"t\":\"hello\",\"v\":2,\"input\":\"instruct\",");
    try writeList(&w2, big.slice());
    try w2.writeByte('}');
    try testing.expectEqual(@as(usize, max_tabs), parseList(w2.buffered()).?.len);
}

const long_name: [max_name + 1]u8 = @splat('x');

test "malformed lists are rejected whole" {
    const good = "{\"id\":\"000102030405060708090a0b0c0d0eff\",\"name\":\"A\",\"color\":\"#000000\",\"state\":\"idle\"}";
    try testing.expectEqual(@as(usize, 1), parseList("{\"sessions\":[" ++ good ++ "]}").?.len);
    try testing.expectEqual(@as(usize, 0), parseList("{\"sessions\":[]}").?.len);
    try testing.expectEqual(@as(usize, 2), parseList("{\"sessions\": [ " ++ good ++ " , " ++ good ++ " ] }").?.len);
    const bad = [_][]const u8{
        "{\"t\":\"tabs\"}",
        "{\"sessions\":[" ++ good,
        "{\"sessions\":[" ++ good ++ ",]}",
        "{\"sessions\":[{\"name\":\"A\"}]}", // no id
        "{\"sessions\":[{\"id\":\"000102030405060708090a0b0c0d0eff\"}]}", // no name
        "{\"sessions\":[{\"id\":\"0001\",\"name\":\"A\"}]}",
        "{\"sessions\":[{\"id\":\"000102030405060708090a0b0c0d0eff\",\"name\":\"\"}]}",
        "{\"sessions\":[{\"id\":\"000102030405060708090a0b0c0d0eff\",\"name\":\"a\\nb\"}]}",
        "{\"sessions\":[{\"id\":\"000102030405060708090a0b0c0d0eff\",\"name\":\"a\x01b\"}]}",
        "{\"sessions\":[{\"id\":\"000102030405060708090a0b0c0d0eff\",\"name\":\"A\",\"color\":\"red\"}]}",
        "{\"sessions\":[{\"id\":\"000102030405060708090a0b0c0d0eff\",\"name\":\"A\",\"n\":1}]}", // non-string value
        "{\"sessions\":[{\"id\":\"000102030405060708090a0b0c0d0eff\",\"name\":\"" ++ long_name ++ "\"}]}",
        "{\"sessions\":[{\"id\":\"000102030405060708090a0b0c0d0eff\",\"name\":\"\xff\"}]}",
    };
    for (bad) |b| try testing.expect(parseList(b) == null);
    // More than max_tabs entries.
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll("{\"sessions\":[");
    for (0..max_tabs + 1) |i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll(good);
    }
    try w.writeAll("]}");
    try testing.expect(parseList(w.buffered()) == null);
}

test "idField and state names" {
    const t = "{\"t\":\"session\",\"id\":\"000102030405060708090a0b0c0d0eff\"}";
    try testing.expectEqual(@as(u8, 0xff), idField(t, "id").?[15]);
    try testing.expect(idField("{\"t\":\"session\",\"id\":\"00\"}", "id") == null);
    try testing.expect(idField("{\"t\":\"session\"}", "id") == null);
    try testing.expectEqual(State.failed, State.fromWire("error"));
    try testing.expectEqual(State.unknown, State.fromWire("failed"));
    try testing.expectEqual(State.unknown, State.fromWire("bogus"));
    try testing.expect(State.waiting.attention());
    try testing.expect(!State.working.attention());
}

test "validName" {
    try testing.expect(validName("acme-api"));
    try testing.expect(!validName(""));
    try testing.expect(!validName("  "));
    try testing.expect(!validName("a\u{202e}b"));
    const over: [max_name + 1]u8 = @splat('p');
    try testing.expect(!validName(&over));
}
