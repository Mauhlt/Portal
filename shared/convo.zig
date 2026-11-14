//! The Conversation view on the wire (docs/protocol.md section 3b): what the
//! session program (the agent) and the owner said in the tab a viewer
//! watches, as readable items instead of a terminal grid. One writer and
//! one parser for the server (src/convo/model.zig, web.zig) and the native
//! client, so both ends agree on the format and its limits.
//!
//!   {"t":"convo","id":"<32 hex>","on":true,"items":[ITEM,...]}
//!       the whole conversation of tab `id` (sent after `hello`/`session`
//!       for the tab shown, and again whenever the server starts over, e.g.
//!       a new transcript): replaces everything the client had for it.
//!       `on` is false while the tab has no transcript to read (none yet,
//!       or the program does not save one): the client says so and offers
//!       the terminal.
//!   {"t":"convo+","id":"<32 hex>","items":[ITEM,...]}
//!       new or changed items: an item whose `n` the client already has
//!       replaces it, any other is appended (`n` only grows). An item
//!       with an empty `text` removes item `n` (a note Portal took back).
//!
//!   ITEM = {"n":<u32>,"k":"<kind>","text":"<text>"
//!           [,"open":true|false][,"multi":true]
//!           [,"options":[{"label":"<text>","key":"<answer key>"},...]]}
//!
//! Kinds: `user` (the owner's prompt), `assistant` (the program's reply,
//! plain text with Markdown code blocks kept), `tool` (a one-liner such as
//! "Edited 2 files"; never arguments or paths), `question` (the program
//! waits for an answer: `open` while it does; `options`, when known, are
//! answered by sending `k:<key>`, nothing new), `error` (a one-liner) and
//! `status` (a note such as "Conversation compacted").
//!
//! Every text is printable UTF-8 (line feeds and tabs allowed), scrubbed of
//! paths and the user's name on the desktop before it is written. Strings
//! escape `"`, `\`, line feed (`\n`), tab (`\t`) and other controls as
//! `\u00XX`; the parser also accepts `\/`, `\r`, `\b`, `\f` and BMP `\uXXXX`.
//!
//! Parsing is strict and bounded: anything malformed, with too many items
//! or options, an unknown kind or an answer key outside `answer_keys` is
//! rejected whole.

const std = @import("std");
const tabs = @import("tabs.zig");

pub const Id = tabs.Id;

/// Most items one conversation keeps (and a snapshot carries).
pub const max_items = 200;
/// Longest text of one item, in bytes (longer ones are cut, ending "…").
pub const max_text = 16 * 1024;
/// Most text bytes one conversation keeps (oldest items go first).
pub const max_total_text = 256 * 1024;
/// Most options one question offers.
pub const max_options = 10;
/// Longest option label, in bytes.
pub const max_label = 200;
/// Most options one conversation carries in all.
pub const max_total_options = 400;
/// Room for any convo message: every byte of text may double when
/// escaped (`"`, `\`, line feeds), plus syntax per item and option.
pub const max_message = 2 * max_total_text + max_items * 96 + max_total_options * (2 * max_label + 40) + 128;

pub const Kind = enum {
    user,
    assistant,
    tool,
    question,
    @"error",
    status,
};

/// The keys an option may name: answer keys every input mode but `none`
/// accepts (src/inputrules/keys.zig, first row). Answering is pressing one.
pub const answer_keys = [_][]const u8{ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "y", "n", "enter", "esc" };

pub fn validKey(k: []const u8) bool {
    for (answer_keys) |a| if (std.mem.eql(u8, a, k)) return true;
    return false;
}

pub const Option = struct {
    label: []const u8,
    key: []const u8,
};

pub const Item = struct {
    n: u32,
    kind: Kind,
    text: []const u8,
    /// Questions: still waiting for the answer.
    open: bool = false,
    /// Questions: several options may be chosen (each key toggles one;
    /// `enter` submits).
    multi: bool = false,
    options: []const Option = &.{},
};

// ---------------------------------------------------------------- writing

/// Writes a JSON string (quotes included).
pub fn writeString(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\t' => try w.writeAll("\\t"),
        0...8, 0x0b...0x1f, 0x7f => try w.print("\\u{x:0>4}", .{c}),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

pub fn writeItem(w: *std.Io.Writer, it: Item) !void {
    try w.print("{{\"n\":{d},\"k\":\"{s}\",\"text\":", .{ it.n, @tagName(it.kind) });
    try writeString(w, it.text);
    if (it.kind == .question) {
        try w.print(",\"open\":{}", .{it.open});
        if (it.multi) try w.writeAll(",\"multi\":true");
        if (it.options.len > 0) {
            try w.writeAll(",\"options\":[");
            for (it.options, 0..) |o, i| {
                if (i > 0) try w.writeByte(',');
                try w.writeAll("{\"label\":");
                try writeString(w, o.label);
                try w.print(",\"key\":\"{s}\"}}", .{o.key});
            }
            try w.writeByte(']');
        }
    }
    try w.writeByte('}');
}

/// `{"t":"convo","id":...,"on":...,"items":[` (snapshot) or
/// `{"t":"convo+","id":...,"items":[` (append); then items with
/// `writeItem` separated by `,`, then `writeEnd`.
pub fn writeBegin(w: *std.Io.Writer, snapshot: bool, id: Id, on: bool) !void {
    try w.print("{{\"t\":\"{s}\",\"id\":\"{s}\"", .{ if (snapshot) "convo" else "convo+", &tabs.idHex(id) });
    if (snapshot) try w.print(",\"on\":{}", .{on});
    try w.writeAll(",\"items\":[");
}

pub fn writeEnd(w: *std.Io.Writer) !void {
    try w.writeAll("]}");
}

// ---------------------------------------------------------------- parsing

pub const Message = struct {
    snapshot: bool,
    id: Id,
    /// Snapshot only: the tab has a transcript.
    on: bool = true,
    items: []Item,
};

/// Storage a parse decodes into (strings, items, options). A client keeps
/// one and copies what it keeps out of it.
pub const Scratch = struct {
    items: [max_items]Item = undefined,
    options: [max_total_options]Option = undefined,
    /// Decoded text never exceeds the encoded message.
    text: []u8,
};

/// Parses a `convo` or `convo+` message, or null if it is not one or is
/// malformed in any way. Strings point into `scratch.text`, which must be
/// at least `text.len` bytes.
pub fn parse(text: []const u8, scratch: *Scratch) ?Message {
    if (scratch.text.len < text.len) return null;
    var p: Parser = .{ .s = text, .out = scratch.text };
    var msg: Message = .{ .snapshot = false, .id = undefined, .items = scratch.items[0..0] };
    var have_t = false;
    var have_id = false;
    var have_items = false;
    var n_items: usize = 0;
    var n_opts: usize = 0;
    p.ws();
    if (!p.eat('{')) return null;
    var first = true;
    while (true) {
        p.ws();
        if (p.eat('}')) break;
        if (!first and !p.eat(',')) return null;
        first = false;
        p.ws();
        const key = p.string() orelse return null;
        p.ws();
        if (!p.eat(':')) return null;
        p.ws();
        if (std.mem.eql(u8, key, "t")) {
            const v = p.string() orelse return null;
            if (std.mem.eql(u8, v, "convo")) msg.snapshot = true else if (!std.mem.eql(u8, v, "convo+")) return null;
            have_t = true;
        } else if (std.mem.eql(u8, key, "id")) {
            const v = p.string() orelse return null;
            msg.id = tabs.parseId(v) orelse return null;
            have_id = true;
        } else if (std.mem.eql(u8, key, "on")) {
            msg.on = p.boolean() orelse return null;
        } else if (std.mem.eql(u8, key, "items")) {
            if (have_items or !p.eat('[')) return null;
            have_items = true;
            p.ws();
            if (!p.eat(']')) while (true) {
                if (n_items == max_items) return null;
                p.ws();
                scratch.items[n_items] = parseItem(&p, scratch, &n_opts) orelse return null;
                n_items += 1;
                p.ws();
                if (p.eat(']')) break;
                if (!p.eat(',')) return null;
            };
        } else {
            if (!p.scalar()) return null;
        }
    }
    p.ws();
    if (p.i != text.len or !have_t or !have_id or !have_items) return null;
    msg.items = scratch.items[0..n_items];
    return msg;
}

fn parseItem(p: *Parser, scratch: *Scratch, n_opts: *usize) ?Item {
    if (!p.eat('{')) return null;
    var it: Item = .{ .n = 0, .kind = .status, .text = "" };
    var have_n = false;
    var have_k = false;
    var have_text = false;
    var first = true;
    while (true) {
        p.ws();
        if (p.eat('}')) break;
        if (!first and !p.eat(',')) return null;
        first = false;
        p.ws();
        const key = p.string() orelse return null;
        p.ws();
        if (!p.eat(':')) return null;
        p.ws();
        if (std.mem.eql(u8, key, "n")) {
            it.n = p.number() orelse return null;
            have_n = true;
        } else if (std.mem.eql(u8, key, "k")) {
            const v = p.string() orelse return null;
            it.kind = std.meta.stringToEnum(Kind, v) orelse return null;
            have_k = true;
        } else if (std.mem.eql(u8, key, "text")) {
            const v = p.string() orelse return null;
            if (v.len > max_text or !printable(v)) return null;
            it.text = v;
            have_text = true;
        } else if (std.mem.eql(u8, key, "open")) {
            it.open = p.boolean() orelse return null;
        } else if (std.mem.eql(u8, key, "multi")) {
            it.multi = p.boolean() orelse return null;
        } else if (std.mem.eql(u8, key, "options")) {
            if (!p.eat('[')) return null;
            const start = n_opts.*;
            p.ws();
            if (!p.eat(']')) while (true) {
                if (n_opts.* - start == max_options or n_opts.* == scratch.options.len) return null;
                p.ws();
                scratch.options[n_opts.*] = parseOption(p) orelse return null;
                n_opts.* += 1;
                p.ws();
                if (p.eat(']')) break;
                if (!p.eat(',')) return null;
            };
            it.options = scratch.options[start..n_opts.*];
        } else {
            if (!p.scalar()) return null;
        }
    }
    if (!have_n or !have_k or !have_text) return null;
    if (it.kind != .question and (it.options.len > 0 or it.open or it.multi)) return null;
    return it;
}

fn parseOption(p: *Parser) ?Option {
    if (!p.eat('{')) return null;
    var o: Option = .{ .label = "", .key = "" };
    var have_label = false;
    var have_key = false;
    var first = true;
    while (true) {
        p.ws();
        if (p.eat('}')) break;
        if (!first and !p.eat(',')) return null;
        first = false;
        p.ws();
        const key = p.string() orelse return null;
        p.ws();
        if (!p.eat(':')) return null;
        p.ws();
        if (std.mem.eql(u8, key, "label")) {
            const v = p.string() orelse return null;
            if (v.len == 0 or v.len > max_label or !printable(v) or std.mem.indexOfScalar(u8, v, '\n') != null) return null;
            o.label = v;
            have_label = true;
        } else if (std.mem.eql(u8, key, "key")) {
            const v = p.string() orelse return null;
            if (!validKey(v)) return null;
            o.key = v;
            have_key = true;
        } else {
            if (!p.scalar()) return null;
        }
    }
    if (!have_label or !have_key) return null;
    return o;
}

/// Valid UTF-8 without control characters other than line feed and tab,
/// and none of the other code points tab names refuse (C1 controls, line
/// separators, bidi controls, BOM: tabs.blocked).
pub fn printable(s: []const u8) bool {
    const v = std.unicode.Utf8View.init(s) catch return false;
    var it = v.iterator();
    while (it.nextCodepoint()) |cp| {
        if (cp == '\n' or cp == '\t') continue;
        if (tabs.blocked(cp)) return false;
    }
    return true;
}

test "printable refuses what tab names refuse, but for line feed and tab" {
    try std.testing.expect(printable("a\tb\nc é 日本"));
    for ([_][]const u8{ "a\x00", "a\x1b[31m", "a\x7f", "a\u{85}", "a\u{9b}", "x\u{202e}gnp.exe", "\u{2066}a", "a\u{2069}", "a\u{200f}", "a\u{061c}", "\u{feff}a", "a\u{2028}b", "\xff" }) |bad|
        try std.testing.expect(!printable(bad));
}

/// The strict, bounded JSON reader the shared message parsers use
/// (convo, activity, sys): decoded strings go to `out`.
pub const Parser = struct {
    s: []const u8,
    i: usize = 0,
    /// Decoded strings go here, one after another.
    out: []u8,
    o: usize = 0,

    pub fn ws(p: *Parser) void {
        while (p.i < p.s.len and (p.s[p.i] == ' ' or p.s[p.i] == '\t' or p.s[p.i] == '\n' or p.s[p.i] == '\r')) p.i += 1;
    }

    pub fn eat(p: *Parser, c: u8) bool {
        if (p.i < p.s.len and p.s[p.i] == c) {
            p.i += 1;
            return true;
        }
        return false;
    }

    pub fn put(p: *Parser, c: u8) bool {
        if (p.o >= p.out.len) return false;
        p.out[p.o] = c;
        p.o += 1;
        return true;
    }

    /// A JSON string, decoded into `out`.
    pub fn string(p: *Parser) ?[]const u8 {
        if (!p.eat('"')) return null;
        const start = p.o;
        while (p.i < p.s.len) {
            const c = p.s[p.i];
            p.i += 1;
            switch (c) {
                '"' => return p.out[start..p.o],
                '\\' => {
                    if (p.i >= p.s.len) return null;
                    const e = p.s[p.i];
                    p.i += 1;
                    const d: u8 = switch (e) {
                        '"', '\\', '/' => e,
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        'b' => 0x08,
                        'f' => 0x0c,
                        'u' => {
                            if (p.i + 4 > p.s.len) return null;
                            const cp = std.fmt.parseInt(u16, p.s[p.i..][0..4], 16) catch return null;
                            p.i += 4;
                            if (cp >= 0xD800 and cp <= 0xDFFF) return null;
                            var b: [3]u8 = undefined;
                            const len = std.unicode.utf8Encode(cp, &b) catch return null;
                            for (b[0..len]) |x| if (!p.put(x)) return null;
                            continue;
                        },
                        else => return null,
                    };
                    if (!p.put(d)) return null;
                },
                0...0x1f => return null,
                else => if (!p.put(c)) return null,
            }
        }
        return null;
    }

    pub fn boolean(p: *Parser) ?bool {
        if (std.mem.startsWith(u8, p.s[p.i..], "true")) {
            p.i += 4;
            return true;
        }
        if (std.mem.startsWith(u8, p.s[p.i..], "false")) {
            p.i += 5;
            return false;
        }
        return null;
    }

    pub fn number(p: *Parser) ?u32 {
        const start = p.i;
        while (p.i < p.s.len and p.s[p.i] >= '0' and p.s[p.i] <= '9') p.i += 1;
        if (p.i == start or p.i - start > 10) return null;
        if (p.s[start] == '0' and p.i - start > 1) return null;
        return std.fmt.parseInt(u32, p.s[start..p.i], 10) catch null;
    }

    /// A non-negative integer up to 2^53 (JSON's exact range).
    pub fn number64(p: *Parser) ?u64 {
        const start = p.i;
        while (p.i < p.s.len and p.s[p.i] >= '0' and p.s[p.i] <= '9') p.i += 1;
        if (p.i == start or p.i - start > 16) return null;
        if (p.s[start] == '0' and p.i - start > 1) return null;
        const v = std.fmt.parseInt(u64, p.s[start..p.i], 10) catch return null;
        return if (v > (1 << 53)) null else v;
    }

    /// An unknown field's value: a string, number, boolean or null (never
    /// an object or array, so the bounds stay the parser's own).
    pub fn scalar(p: *Parser) bool {
        if (p.i >= p.s.len) return false;
        switch (p.s[p.i]) {
            '"' => return p.string() != null,
            't', 'f' => return p.boolean() != null,
            'n' => {
                if (!std.mem.startsWith(u8, p.s[p.i..], "null")) return false;
                p.i += 4;
                return true;
            },
            '0'...'9', '-' => {
                if (p.s[p.i] == '-') p.i += 1;
                const start = p.i;
                while (p.i < p.s.len and (std.ascii.isDigit(p.s[p.i]) or p.s[p.i] == '.' or p.s[p.i] == 'e' or p.s[p.i] == 'E' or p.s[p.i] == '+' or p.s[p.i] == '-')) p.i += 1;
                return p.i > start;
            },
            else => return false,
        }
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn roundTrip(snapshot: bool, items: []const Item, buf: []u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try writeBegin(&w, snapshot, @splat(0xab), true);
    for (items, 0..) |it, i| {
        if (i > 0) try w.writeByte(',');
        try writeItem(&w, it);
    }
    try writeEnd(&w);
    return w.buffered();
}

test "round trip: every kind, escapes, options" {
    const opts = [_]Option{ .{ .label = "Yes \"really\"", .key = "1" }, .{ .label = "No", .key = "esc" } };
    const items = [_]Item{
        .{ .n = 1, .kind = .user, .text = "fix the \\ build\nplease\tnow" },
        .{ .n = 2, .kind = .assistant, .text = "Done:\n```zig\nconst x = \"a\";\n```\n中文 ✓" },
        .{ .n = 3, .kind = .tool, .text = "Edited 2 files" },
        .{ .n = 4, .kind = .question, .text = "Which one?", .open = true, .multi = true, .options = &opts },
        .{ .n = 5, .kind = .@"error", .text = "API error (529)" },
        .{ .n = 6, .kind = .status, .text = "Conversation compacted" },
        .{ .n = 7, .kind = .question, .text = "Closed one", .open = false },
    };
    var buf: [4096]u8 = undefined;
    const text = try roundTrip(true, &items, &buf);
    var sbuf: [4096]u8 = undefined;
    var scratch: Scratch = .{ .text = &sbuf };
    const m = parse(text, &scratch).?;
    try testing.expect(m.snapshot);
    try testing.expect(m.on);
    try testing.expectEqual(@as(u8, 0xab), m.id[3]);
    try testing.expectEqual(items.len, m.items.len);
    for (items, m.items) |a, b| {
        try testing.expectEqual(a.n, b.n);
        try testing.expectEqual(a.kind, b.kind);
        try testing.expectEqualStrings(a.text, b.text);
        try testing.expectEqual(a.open, b.open);
        try testing.expectEqual(a.multi, b.multi);
        try testing.expectEqual(a.options.len, b.options.len);
        for (a.options, b.options) |x, y| {
            try testing.expectEqualStrings(x.label, y.label);
            try testing.expectEqualStrings(x.key, y.key);
        }
    }
    // Append form, empty.
    const t2 = try roundTrip(false, &.{}, &buf);
    try testing.expectEqualStrings("{\"t\":\"convo+\",\"id\":\"abababababababababababababababab\",\"items\":[]}", t2);
    const m2 = parse(t2, &scratch).?;
    try testing.expect(!m2.snapshot);
    try testing.expectEqual(@as(usize, 0), m2.items.len);
}

test "controls are escaped and never parse back as raw controls" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeString(&w, "a\x1bb\x00c");
    try testing.expectEqualStrings("\"a\\u001bb\\u0000c\"", w.buffered());
    // A message carrying one is not printable: rejected.
    const bad = "{\"t\":\"convo+\",\"id\":\"abababababababababababababababab\",\"items\":[{\"n\":1,\"k\":\"user\",\"text\":\"a\\u001bb\"}]}";
    var sbuf: [512]u8 = undefined;
    var scratch: Scratch = .{ .text = &sbuf };
    try testing.expect(parse(bad, &scratch) == null);
}

test "malformed messages are rejected whole" {
    const id = "\"id\":\"abababababababababababababababab\"";
    const good = "{\"t\":\"convo\"," ++ id ++ ",\"on\":false,\"items\":[{\"n\":1,\"k\":\"status\",\"text\":\"x\"}]}";
    var sbuf: [4096]u8 = undefined;
    var scratch: Scratch = .{ .text = &sbuf };
    const m = parse(good, &scratch).?;
    try testing.expect(!m.on);
    // Unknown scalar fields are fine (forward compatible).
    try testing.expect(parse("{\"t\":\"convo+\"," ++ id ++ ",\"x\":1,\"items\":[{\"n\":1,\"k\":\"tool\",\"text\":\"x\",\"y\":\"z\"}]}", &scratch) != null);
    const bad = [_][]const u8{
        "",
        "{}",
        "{\"t\":\"tabs\"," ++ id ++ ",\"items\":[]}",
        "{\"t\":\"convo\",\"items\":[]}", // no id
        "{\"t\":\"convo\"," ++ id ++ "}", // no items
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[]", // truncated
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[]}x",
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":1,\"k\":\"shell\",\"text\":\"x\"}]}",
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":1,\"k\":\"user\"}]}",
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":-1,\"k\":\"user\",\"text\":\"x\"}]}",
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":99999999999,\"k\":\"user\",\"text\":\"x\"}]}",
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":1,\"k\":\"user\",\"text\":\"\xff\"}]}",
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":1,\"k\":\"user\",\"text\":\"x\u{202e}y\"}]}", // bidi override, raw
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":1,\"k\":\"user\",\"text\":\"x\\u0085y\"}]}", // C1 control, escaped
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":1,\"k\":\"question\",\"text\":\"x\",\"options\":[{\"label\":\"a\\u2066b\",\"key\":\"1\"}]}]}", // bidi isolate in a label
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":1,\"k\":\"user\",\"text\":\"x\",\"open\":true}]}",
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":1,\"k\":\"question\",\"text\":\"x\",\"options\":[{\"label\":\"a\",\"key\":\"ctrl-c\"}]}]}",
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":1,\"k\":\"question\",\"text\":\"x\",\"options\":[{\"label\":\"\",\"key\":\"1\"}]}]}",
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":1,\"k\":\"question\",\"text\":\"x\",\"options\":[{\"key\":\"1\"}]}]}",
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":1,\"k\":\"user\",\"text\":\"x\",\"z\":{}}]}",
        "{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":1,\"k\":\"user\",\"text\":\"\\ud800\"}]}",
    };
    for (bad) |b| {
        if (parse(b, &scratch) != null) {
            std.debug.print("accepted: {s}\n", .{b});
            return error.TestUnexpectedResult;
        }
    }
    // Too many options.
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll("{\"t\":\"convo\"," ++ id ++ ",\"items\":[{\"n\":1,\"k\":\"question\",\"text\":\"x\",\"options\":[");
    for (0..max_options + 1) |i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"label\":\"a\",\"key\":\"1\"}");
    }
    try w.writeAll("]}]}");
    try testing.expect(parse(w.buffered(), &scratch) == null);
    // Scratch smaller than the message.
    var tiny: [8]u8 = undefined;
    var small: Scratch = .{ .text = &tiny };
    try testing.expect(parse(good, &small) == null);
}

test "the largest conversation fits max_message" {
    const gpa = testing.allocator;
    const buf = try gpa.alloc(u8, max_message);
    defer gpa.free(buf);
    var w: std.Io.Writer = .fixed(buf);
    try writeBegin(&w, true, @splat(1), true);
    // Worst case: every text byte escapes to two, as many options as a
    // conversation may carry, each with the longest label.
    const per = max_total_text / max_items;
    const text: [per]u8 = @splat('"');
    const label: [max_label]u8 = @splat('\\');
    var opts: [max_options]Option = undefined;
    for (&opts) |*o| o.* = .{ .label = &label, .key = "enter" };
    for (0..max_items) |i| {
        if (i > 0) try w.writeByte(',');
        const with = i < max_total_options / max_options;
        try writeItem(&w, .{ .n = std.math.maxInt(u32), .kind = .question, .text = &text, .open = true, .multi = true, .options = if (with) &opts else &.{} });
    }
    try writeEnd(&w);
    const sbuf = try gpa.alloc(u8, max_message);
    defer gpa.free(sbuf);
    const scratch = try gpa.create(Scratch);
    defer gpa.destroy(scratch);
    scratch.* = .{ .text = sbuf };
    const m = parse(w.buffered(), scratch).?;
    try testing.expectEqual(@as(usize, max_items), m.items.len);
}
