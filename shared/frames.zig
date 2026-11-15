//! Device -> desk frames on the interactive WebSocket (docs/protocol.md
//! section 4): the one list of their prefixes, and the one codec for the
//! desk's answer to a request frame. The desk's dispatch (src/web.zig) and
//! every client build on it, so a prefix can't be taken twice.
//!
//! Every frame is `<letter>:<rest>`. Request families (`p:`, `i:`, `r:`)
//! are `<letter>:<verb> <argument>` and answered by one message
//!
//!   {"t":"<family>","op":"<verb>","result":"<result>"[,"<ref>":"<value>"]}
//!
//! where `op` is the frame's verb, `result` the family's result name and
//! the reference (a project name, an item id, a tab id) only ever the
//! desk's own value, never the device's text echoed back.
//!
//! `f:` (Forget this desktop) is exactly the two bytes `f:`. Desks before
//! this list existed forget the device on any frame starting `f`, so no
//! other frame may ever start with `f`.

const std = @import("std");
const convo = @import("convo.zig");

pub const Prefix = enum(u8) {
    /// `k:<name>`: press a key.
    key = 'k',
    /// `t:<utf8>`: type text (`text` mode).
    text = 't',
    /// `l:<line>`: an instruction line.
    line = 'l',
    /// `s:<32 hex>`: watch an open tab.
    session = 's',
    /// `a:<32 hex>` / `a:`: show a sub-tab / the tab's own conversation.
    sub = 'a',
    /// `y:on` / `y:off`: the System panel opened / closed.
    sys = 'y',
    /// `f:` exactly: Forget this desktop.
    forget = 'f',
    /// `p:start <name>` / `p:stop <name>`: startable projects (projects.zig).
    project = 'p',
    /// `i:yes <id>` / `i:no <id>`: a For-you item (foryou.zig).
    item = 'i',
    /// `r:recap <tab id>`: ask a tab for a recap (recap.zig).
    recap = 'r',
    /// `m:<seq>`: the device saved the desk's endpoint announcement
    /// number <seq> (decimal digits only). An acknowledgement and nothing
    /// else: it carries no endpoint, and the desk only marks that device
    /// "moved" for an announcement it made itself (src/portmove.zig). No
    /// device frame can change, request or influence the desk's port or
    /// endpoint.
    moved = 'm',
};

/// `m:<seq>` for announcement `seq`.
pub fn movedFrame(seq: u64, buf: *[24]u8) []const u8 {
    return std.fmt.bufPrint(buf, "m:{d}", .{seq}) catch unreachable;
}

/// The seq of an `m:` frame's rest: 1-20 decimal digits, nothing else.
pub fn parseMoved(rest: []const u8) ?u64 {
    if (rest.len == 0 or rest.len > 20) return null;
    for (rest) |ch| if (ch < '0' or ch > '9') return null;
    const v = std.fmt.parseInt(u64, rest, 10) catch return null;
    return if (v == 0) null else v;
}

test "m: acknowledgements are only a number" {
    var b: [24]u8 = undefined;
    const f = movedFrame(1700000001, &b);
    const fr = classify(f).?;
    try std.testing.expectEqual(Prefix.moved, fr.prefix);
    try std.testing.expectEqual(@as(?u64, 1700000001), parseMoved(fr.rest));
    for ([_][]const u8{ "", "0", "1 x", "x", "12:51821", "home.example.org:51821", "-1", "99999999999999999999999" }) |r|
        try std.testing.expect(parseMoved(r) == null);
}

pub const Frame = struct { prefix: Prefix, rest: []const u8 };

/// The frame's prefix and what follows the colon, or null for a frame no
/// desk knows (ignored). `f:` with anything after it is null too.
pub fn classify(payload: []const u8) ?Frame {
    if (payload.len < 2 or payload[1] != ':') return null;
    const prefix = std.enums.fromInt(Prefix, payload[0]) orelse return null;
    if (prefix == .forget and payload.len != 2) return null;
    return .{ .prefix = prefix, .rest = payload[2..] };
}

/// `<verb> <argument>` of a request frame's rest, for a verb of `Op`.
/// Exactly one space; the argument is not checked here.
pub fn verb(comptime Op: type, rest: []const u8) ?struct { op: Op, arg: []const u8 } {
    const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    const op = std.meta.stringToEnum(Op, rest[0..sp]) orelse return null;
    return .{ .op = op, .arg = rest[sp + 1 ..] };
}

// ------------------------------------------------------------ answers

/// Longest `t`, `op`, `result` or reference value an answer carries.
pub const max_field = 64;
/// Room for any answer: four fields, each escaped at most twice over.
pub const max_answer = 64 + 8 * max_field;

/// Writes `{"t":"<t>","op":"<op>","result":"<result>"[,"<ref_key>":<ref>]}`.
pub fn writeAnswer(w: *std.Io.Writer, t: []const u8, op: []const u8, result: []const u8, ref_key: []const u8, ref: ?[]const u8) !void {
    try w.writeAll("{\"t\":");
    try convo.writeString(w, t);
    try w.writeAll(",\"op\":");
    try convo.writeString(w, op);
    try w.writeAll(",\"result\":");
    try convo.writeString(w, result);
    if (ref) |r| {
        try w.writeByte(',');
        try convo.writeString(w, ref_key);
        try w.writeByte(':');
        try convo.writeString(w, r);
    }
    try w.writeByte('}');
}

/// An answer's fields, decoded into the caller's `Scratch`.
pub const RawAnswer = struct {
    op: []const u8,
    result: []const u8,
    ref: ?[]const u8 = null,
};

pub const Scratch = [max_answer]u8;

/// A strict answer message of family `t`: one object with `t`, `op` and
/// `result` strings, at most the `ref_key` string besides, unknown scalar
/// fields ignored. Null if malformed or another message.
pub fn parseAnswer(text: []const u8, t: []const u8, ref_key: []const u8, scratch: *Scratch) ?RawAnswer {
    if (text.len > max_answer) return null;
    var p: convo.Parser = .{ .s = text, .out = scratch };
    var have_t = false;
    var op: ?[]const u8 = null;
    var result: ?[]const u8 = null;
    var ref: ?[]const u8 = null;
    p.ws();
    if (!p.eat('{')) return null;
    var first = true;
    while (true) {
        p.ws();
        if (p.eat('}')) break;
        if (!first and !p.eat(',')) return null;
        first = false;
        p.ws();
        const mark = p.o;
        const key = p.string() orelse return null;
        p.ws();
        if (!p.eat(':')) return null;
        p.ws();
        const known = std.mem.eql(u8, key, "t") or std.mem.eql(u8, key, "op") or
            std.mem.eql(u8, key, "result") or std.mem.eql(u8, key, ref_key);
        if (!known) {
            p.o = mark; // keys and unknown values need no room
            if (!p.scalar()) return null;
            p.o = mark;
            continue;
        }
        const is_t = std.mem.eql(u8, key, "t");
        const is_op = std.mem.eql(u8, key, "op");
        const is_result = std.mem.eql(u8, key, "result");
        p.o = mark;
        const v = p.string() orelse return null;
        if (v.len > max_field) return null;
        if (is_t) {
            if (have_t or !std.mem.eql(u8, v, t)) return null;
            p.o = mark;
            have_t = true;
        } else if (is_op) {
            if (op != null) return null;
            op = v;
        } else if (is_result) {
            if (result != null) return null;
            result = v;
        } else {
            if (ref != null) return null;
            ref = v;
        }
    }
    p.ws();
    if (p.i != text.len or !have_t) return null;
    return .{ .op = op orelse return null, .result = result orelse return null, .ref = ref };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "every prefix is one letter, and nothing else starts with f" {
    const values = std.enums.values(Prefix);
    for (values, 0..) |a, i| {
        try testing.expect(std.ascii.isLower(@backingInt(a)));
        for (values[i + 1 ..]) |b| try testing.expect(a != b);
    }
    try testing.expectEqual(Prefix.forget, classify("f:").?.prefix);
    // A request that looked like `f:yes` would unpair the device on older
    // desks; the desk treats it as an unknown frame, never as Forget.
    try testing.expect(classify("f:yes 00") == null);
    try testing.expect(classify("f:x") == null);
    try testing.expect(classify("") == null);
    try testing.expect(classify("k") == null);
    try testing.expect(classify("kx") == null);
    try testing.expect(classify("z:x") == null);
    try testing.expect(classify("K:enter") == null);
    const f = classify("i:yes abc").?;
    try testing.expectEqual(Prefix.item, f.prefix);
    try testing.expectEqualStrings("yes abc", f.rest);
    try testing.expectEqualStrings("", classify("a:").?.rest);
}

test "verbs: exact name, one space" {
    const Op = enum { yes, no };
    const v = verb(Op, "yes abc").?;
    try testing.expectEqual(Op.yes, v.op);
    try testing.expectEqualStrings("abc", v.arg);
    try testing.expectEqualStrings("", verb(Op, "no ").?.arg);
    try testing.expectEqualStrings(" abc", verb(Op, "no  abc").?.arg);
    for ([_][]const u8{ "yes", "Yes abc", "yesabc", "maybe abc", "", " yes abc" }) |bad|
        try testing.expect(verb(Op, bad) == null);
}

test "answers round trip; strict parse" {
    var buf: [max_answer]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeAnswer(&w, "project", "start", "switched", "name", "a \\b");
    try testing.expectEqualStrings("{\"t\":\"project\",\"op\":\"start\",\"result\":\"switched\",\"name\":\"a \\\\b\"}", w.buffered());
    var s: Scratch = undefined;
    const a = parseAnswer(w.buffered(), "project", "name", &s).?;
    try testing.expectEqualStrings("start", a.op);
    try testing.expectEqualStrings("switched", a.result);
    try testing.expectEqualStrings("a \\b", a.ref.?);
    const b = parseAnswer("{ \"t\" : \"recap\", \"op\":\"recap\",\"result\":\"ok\",\"new\":1,\"x\":\"y\"} ", "recap", "id", &s).?;
    try testing.expect(b.ref == null);
    try testing.expectEqualStrings("ok", b.result);
    const long: [max_field + 1]u8 = @splat('x');
    for ([_][]const u8{
        "{\"t\":\"recap\",\"op\":\"recap\"}",
        "{\"t\":\"recap\",\"result\":\"ok\"}",
        "{\"op\":\"recap\",\"result\":\"ok\"}",
        "{\"t\":\"item\",\"op\":\"recap\",\"result\":\"ok\"}",
        "{\"t\":\"recap\",\"op\":\"recap\",\"result\":\"ok\"",
        "{\"t\":\"recap\",\"op\":\"recap\",\"result\":\"ok\"}x",
        "{\"t\":\"recap\",\"op\":\"recap\",\"result\":\"ok\",\"result\":\"ok\"}",
        "{\"t\":\"recap\",\"op\":\"recap\",\"result\":\"ok\",\"x\":{}}",
        "{\"t\":\"recap\",\"op\":\"recap\",\"result\":1}",
        "{\"t\":\"recap\",\"op\":\"recap\",\"result\":\"" ++ long ++ "\"}",
    }) |bad| try testing.expect(parseAnswer(bad, "recap", "id", &s) == null);
}
