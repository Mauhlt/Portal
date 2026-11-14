//! "For you" items on the wire (docs/protocol.md section 3g): what a tab
//! needs from the owner, or suggests, as cards a device answers with yes
//! or no. The desk builds them (from the agent's hooks and transcript),
//! keeps them and decides what an answer does; a device only shows them
//! and sends `i:yes <id>` / `i:no <id>`. One writer and strict parser for
//! the server and every client.
//!
//!   server -> device
//!     {"t":"foryou","id":"<tab, 32 hex>","items":[ITEM,...]}
//!     ITEM = {"id":"<32 hex>","k":"<kind>","text":"<summary>"
//!             [,"cmd":"<command>"][,"why":"<why>"][,"project":"<name>"]}
//!     {"t":"item","op":"yes"|"no","result":"<result>"[,"id":"<item id>"]}
//!   device -> server
//!     i:yes <item id>
//!     i:no <item id>
//!
//! An item's `id` is random (128 bits) and never reused; the desk gives an
//! item a new id whenever anything in it changes, so the id is also its
//! version: an answer naming an id that is no longer current (replaced,
//! answered from another device or at the desk, gone) is refused `stale`
//! and changes nothing.
//!
//! The prefix is `i:`, not `f:`: `f:` is Forget this desktop, and desks
//! before frames.zig forget the device on any frame starting with `f`.

const std = @import("std");
const tabs = @import("tabs.zig");
const convo = @import("convo.zig");
const frames = @import("frames.zig");

pub const Id = tabs.Id;

/// Most items one tab carries.
pub const max_items = 16;
/// Longest summary (one line), in bytes.
pub const max_summary = 120;
/// Longest command (permission prompt, suggested run), in bytes.
pub const max_cmd = 1024;
/// Longest why-line, in bytes.
pub const max_why = 240;
pub const max_name = tabs.max_name;

pub const Kind = enum {
    /// The agent waits on a permission prompt: yes allows, no denies.
    waiting_permission,
    /// The desk suggests running `cmd`: yes sends the agent
    /// "Please run `<cmd>`." (runMessage); no dismisses.
    suggest_run,
    /// The desk suggests switching to `project`: yes sends the agent
    /// "Please switch to the <project> project." (gotoMessage); no
    /// dismisses.
    suggest_goto,
    /// The agent asked a yes/no question (`text`): yes / no sends that
    /// answer.
    answer,
    /// The agent waits for something only the desk can give (an
    /// administrator prompt, a folder-trust prompt, a sign-in). Shown only:
    /// yes and no dismiss.
    needs_desk,
    /// A command has run for a long time. Shown only: yes and no dismiss.
    long_running,

    /// What an answer does at the desk.
    pub fn effect(k: Kind, op: Op) Effect {
        return switch (k) {
            .waiting_permission, .answer => .answer,
            .suggest_run, .suggest_goto => if (op == .yes) .send_message else .dismiss,
            .needs_desk, .long_running => .dismiss,
        };
    }
};

pub const Op = enum { yes, no };

/// What answering an item does, and so which input modes allow it.
pub const Effect = enum {
    /// Removes the item for every device; nothing reaches the agent.
    dismiss,
    /// Answers the agent's prompt or question, like an answer key.
    answer,
    /// Sends the agent a fixed-template message, like an instruction line.
    send_message,

    /// True if a device whose `hello.input` is `mode` may do this:
    /// dismissing in every mode, answering in `keys` and above, sending a
    /// message in `instruct` and `text`.
    pub fn allowedIn(e: Effect, mode: []const u8) bool {
        const is = std.mem.eql;
        return switch (e) {
            .dismiss => true,
            .answer => is(u8, mode, "keys") or is(u8, mode, "instruct") or is(u8, mode, "text"),
            .send_message => is(u8, mode, "instruct") or is(u8, mode, "text"),
        };
    }
};

// ------------------------------------------------------------- items

pub const Item = struct {
    id: Id = @splat(0),
    kind: Kind = .needs_desk,
    summary_buf: [max_summary]u8 = undefined,
    summary_len: u8 = 0,
    cmd_buf: [max_cmd]u8 = undefined,
    cmd_len: u16 = 0,
    why_buf: [max_why]u8 = undefined,
    why_len: u8 = 0,
    project_buf: [max_name]u8 = undefined,
    project_len: u8 = 0,

    pub fn summary(it: *const Item) []const u8 {
        return it.summary_buf[0..it.summary_len];
    }
    /// Empty: none.
    pub fn cmd(it: *const Item) []const u8 {
        return it.cmd_buf[0..it.cmd_len];
    }
    /// Empty: none.
    pub fn why(it: *const Item) []const u8 {
        return it.why_buf[0..it.why_len];
    }
    /// Empty: none.
    pub fn project(it: *const Item) []const u8 {
        return it.project_buf[0..it.project_len];
    }

    /// Setters cut to the bound; `valid` says whether the item may be sent.
    pub fn setSummary(it: *Item, s: []const u8) void {
        it.summary_len = @intCast(copy(&it.summary_buf, s));
    }
    pub fn setCmd(it: *Item, s: []const u8) void {
        it.cmd_len = @intCast(copy(&it.cmd_buf, s));
    }
    pub fn setWhy(it: *Item, s: []const u8) void {
        it.why_len = @intCast(copy(&it.why_buf, s));
    }
    pub fn setProject(it: *Item, s: []const u8) void {
        it.project_len = @intCast(copy(&it.project_buf, s));
    }

    /// Every field within its rules, and the fields its kind needs:
    /// `suggest_run` a runnable `cmd`, `suggest_goto` a `project`.
    pub fn valid(it: *const Item) bool {
        if (it.summary().len == 0 or !oneLine(it.summary(), max_summary)) return false;
        if (it.cmd().len > 0 and !convo.printable(it.cmd())) return false;
        if (it.why().len > 0 and !oneLine(it.why(), max_why)) return false;
        if (it.project().len > 0 and !tabs.validName(it.project())) return false;
        return switch (it.kind) {
            .suggest_run => runnable(it.cmd()),
            .suggest_goto => it.project().len > 0,
            else => true,
        };
    }
};

fn copy(dst: []u8, s: []const u8) usize {
    const n = @min(s.len, dst.len);
    @memcpy(dst[0..n], s[0..n]);
    return n;
}

/// One printable line of at most `max` bytes (no line feed or tab).
fn oneLine(s: []const u8, max: usize) bool {
    return s.len <= max and convo.printable(s) and std.mem.indexOfAny(u8, s, "\n\t") == null;
}

/// A command fit for "Please run `<cmd>`.": one printable line without a
/// backtick (which would end the code span), not blank.
pub fn runnable(c: []const u8) bool {
    if (!oneLine(c, max_cmd) or std.mem.indexOfScalar(u8, c, '`') != null) return false;
    return std.mem.trim(u8, c, " ").len > 0;
}

/// The message `suggest_run`'s yes sends the agent, or null if `c` is not
/// runnable. One definition, so a device can show exactly what will be sent.
pub fn runMessage(c: []const u8, buf: *[max_cmd + 16]u8) ?[]const u8 {
    if (!runnable(c)) return null;
    return std.fmt.bufPrint(buf, "Please run `{s}`.", .{c}) catch null;
}

/// The message `suggest_goto`'s yes sends the agent, or null if `name` is
/// not a tab name.
pub fn gotoMessage(name: []const u8, buf: *[max_name + 40]u8) ?[]const u8 {
    if (!tabs.validName(name)) return null;
    return std.fmt.bufPrint(buf, "Please switch to the {s} project.", .{name}) catch null;
}

pub const List = struct {
    /// The tab the items belong to.
    tab: Id = @splat(0),
    items: [max_items]Item = undefined,
    len: usize = 0,

    pub fn slice(l: *const List) []const Item {
        return l.items[0..l.len];
    }

    pub fn find(l: *const List, id: Id) ?usize {
        for (l.items[0..l.len], 0..) |*it, i| if (std.mem.eql(u8, &it.id, &id)) return i;
        return null;
    }

    /// The tab waits for something only the desk can give: the "needs
    /// desk" mark on its tab (there is no separate tab-status flag).
    pub fn needsDesk(l: *const List) bool {
        for (l.slice()) |*it| if (it.kind == .needs_desk) return true;
        return false;
    }
};

// ---------------------------------------------------------------- writing

/// Room for any `foryou` message: every text byte may double when escaped.
pub const max_message = 96 + max_items * (160 + 2 * (max_summary + max_cmd + max_why + max_name));

/// Writes `{"t":"foryou","id":...,"items":[...]}`. Items that are not
/// `valid` are left out (the desk never sends half an item).
pub fn write(w: *std.Io.Writer, tab: Id, items: []const Item) !void {
    try w.print("{{\"t\":\"foryou\",\"id\":\"{s}\",\"items\":[", .{&tabs.idHex(tab)});
    var first = true;
    for (items[0..@min(items.len, max_items)]) |*it| {
        if (!it.valid()) continue;
        if (!first) try w.writeByte(',');
        first = false;
        try w.print("{{\"id\":\"{s}\",\"k\":\"{s}\",\"text\":", .{ &tabs.idHex(it.id), @tagName(it.kind) });
        try convo.writeString(w, it.summary());
        if (it.cmd().len > 0) {
            try w.writeAll(",\"cmd\":");
            try convo.writeString(w, it.cmd());
        }
        if (it.why().len > 0) {
            try w.writeAll(",\"why\":");
            try convo.writeString(w, it.why());
        }
        if (it.project().len > 0) {
            try w.writeAll(",\"project\":");
            try convo.writeString(w, it.project());
        }
        try w.writeByte('}');
    }
    try w.writeAll("]}");
}

// ---------------------------------------------------------------- parsing

/// Parses a `foryou` message into `out`; false (and `out` unspecified) if
/// it is not one or is malformed in any way: too many items, an unknown
/// kind, a field out of bounds, an item its kind can't have, two items
/// with one id. Unknown scalar fields are ignored.
pub fn parse(text: []const u8, out: *List) bool {
    if (text.len > max_message) return false;
    var sbuf: [max_cmd + 1]u8 = undefined;
    var p: convo.Parser = .{ .s = text, .out = &sbuf };
    out.len = 0;
    out.tab = @splat(0);
    var have_t = false;
    var have_id = false;
    var have_items = false;
    p.ws();
    if (!p.eat('{')) return false;
    var first = true;
    while (true) {
        p.ws();
        if (p.eat('}')) break;
        if (!first and !p.eat(',')) return false;
        first = false;
        const key = field(&p) orelse return false;
        if (key == .t) {
            if (have_t or !eq(p.string() orelse return false, "foryou")) return false;
            have_t = true;
        } else if (key == .id) {
            if (have_id) return false;
            out.tab = tabs.parseId(p.string() orelse return false) orelse return false;
            have_id = true;
        } else if (key == .items) {
            if (have_items or !p.eat('[')) return false;
            have_items = true;
            p.ws();
            if (!p.eat(']')) while (true) {
                if (out.len == max_items) return false;
                p.ws();
                const it = &out.items[out.len];
                if (!parseItem(&p, it)) return false;
                if (out.find(it.id) != null) return false;
                out.len += 1;
                p.ws();
                if (p.eat(']')) break;
                if (!p.eat(',')) return false;
            };
        } else if (!p.scalar()) return false;
    }
    p.ws();
    return p.i == text.len and have_t and have_id and have_items;
}

const Key = enum { t, id, items, k, text, cmd, why, project, other };

/// A field's key and its colon; string scratch is reset for each field.
fn field(p: *convo.Parser) ?Key {
    p.ws();
    p.o = 0;
    const k = p.string() orelse return null;
    const key = std.meta.stringToEnum(Key, k) orelse .other;
    p.ws();
    if (!p.eat(':')) return null;
    p.ws();
    p.o = 0;
    return if (key == .other) .other else key;
}

fn parseItem(p: *convo.Parser, it: *Item) bool {
    it.* = .{};
    if (!p.eat('{')) return false;
    var seen: std.EnumSet(Key) = .{};
    var first = true;
    while (true) {
        p.ws();
        if (p.eat('}')) break;
        if (!first and !p.eat(',')) return false;
        first = false;
        const key = field(p) orelse return false;
        if (key != .other) {
            if (seen.contains(key)) return false;
            seen.insert(key);
        }
        switch (key) {
            .id => it.id = tabs.parseId(p.string() orelse return false) orelse return false,
            .k => it.kind = std.meta.stringToEnum(Kind, p.string() orelse return false) orelse return false,
            .text => {
                const v = p.string() orelse return false;
                if (v.len == 0 or !oneLine(v, max_summary)) return false;
                it.setSummary(v);
            },
            .cmd => {
                const v = p.string() orelse return false;
                if (v.len == 0 or v.len > max_cmd) return false;
                it.setCmd(v);
            },
            .why => {
                const v = p.string() orelse return false;
                if (v.len == 0 or !oneLine(v, max_why)) return false;
                it.setWhy(v);
            },
            .project => {
                const v = p.string() orelse return false;
                if (!tabs.validName(v)) return false;
                it.setProject(v);
            },
            .other => if (!p.scalar()) return false,
            .t, .items => return false,
        }
    }
    if (!seen.contains(.id) or !seen.contains(.k) or !seen.contains(.text)) return false;
    return it.valid();
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

// ------------------------------------------------------- device requests

pub const Request = struct { op: Op, id: Id };

/// The frame a device sends: "i:yes <32 hex>" / "i:no <32 hex>".
pub fn requestFrame(op: Op, id: Id, buf: *[6 + tabs.hex_len]u8) []const u8 {
    return std.fmt.bufPrint(buf, "i:{s} {s}", .{ @tagName(op), &tabs.idHex(id) }) catch unreachable;
}

/// What follows "i:": exactly "yes " or "no " and an item id. Null for
/// anything else (answered `stale`, like an id that is not current).
pub fn parseRequest(rest: []const u8) ?Request {
    const v = frames.verb(Op, rest) orelse return null;
    return .{ .op = v.op, .id = tabs.parseId(v.arg) orelse return null };
}

/// What the desk did with an `i:` frame (the `item` message's `result`).
pub const Result = enum {
    /// The answer reached the agent (permission answered, message or
    /// answer sent); the item is gone.
    sent,
    /// The item was dismissed (no reached the agent with nothing, or the
    /// item is informational); it is gone.
    dismissed,
    /// No current item has that id (replaced, answered elsewhere, gone;
    /// also a malformed frame). Nothing happened.
    stale,
    /// The desk's input mode for devices does not allow it (Effect.allowedIn).
    refused,
    /// Too many requests from this device in the last minute.
    rate_limited,
    /// The desk could not deliver it (the tab ended, the agent is not at
    /// its prompt); the item stays.
    failed,

    pub fn ok(r: Result) bool {
        return r == .sent or r == .dismissed;
    }

    /// What a device shows (UI strings may name the product).
    pub fn text(r: Result) []const u8 {
        return switch (r) {
            .sent => "Sent.",
            .dismissed => "Dismissed.",
            .stale => "That card changed or was already answered.",
            .refused => "This desk's input mode does not allow that.",
            .rate_limited => "Too many requests: wait a minute.",
            .failed => "The desk could not deliver it.",
        };
    }
};

/// The answer to an `i:` frame. `id` (the desk's item, never the device's
/// text) whenever the frame named a well-formed id.
pub fn writeResult(w: *std.Io.Writer, op: Op, result: Result, id: ?Id) !void {
    const hex = if (id) |i| tabs.idHex(i) else undefined;
    try frames.writeAnswer(w, "item", @tagName(op), @tagName(result), "id", if (id != null) &hex else null);
}

pub const Answer = struct { op: Op, result: Result, id: ?Id };

/// An `item` message, or null.
pub fn parseResult(text: []const u8) ?Answer {
    var s: frames.Scratch = undefined;
    const a = frames.parseAnswer(text, "item", "id", &s) orelse return null;
    return .{
        .op = std.meta.stringToEnum(Op, a.op) orelse return null,
        .result = std.meta.stringToEnum(Result, a.result) orelse return null,
        .id = if (a.ref) |r| tabs.parseId(r) orelse return null else null,
    };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn sample() List {
    var l: List = .{ .tab = @splat(0xab) };
    l.items[0] = .{ .id = @splat(1), .kind = .waiting_permission };
    l.items[0].setSummary("Wants to run a command.");
    l.items[0].setCmd("zig build test\n  --summary all \"x\" \\y");
    l.items[0].setWhy("Runs the unit tests.");
    l.items[1] = .{ .id = @splat(2), .kind = .suggest_run };
    l.items[1].setSummary("Run the e2e suite?");
    l.items[1].setCmd("zig build e2e");
    l.items[2] = .{ .id = @splat(3), .kind = .suggest_goto };
    l.items[2].setSummary("acme-api has a failing build.");
    l.items[2].setProject("acme \"api\"");
    l.items[3] = .{ .id = @splat(4), .kind = .needs_desk };
    l.items[3].setSummary("An administrator prompt is open at the desk.");
    l.len = 4;
    return l;
}

fn same(a: *const Item, b: *const Item) bool {
    return eq(&a.id, &b.id) and a.kind == b.kind and eq(a.summary(), b.summary()) and
        eq(a.cmd(), b.cmd()) and eq(a.why(), b.why()) and eq(a.project(), b.project());
}

test "list round trip" {
    const l = sample();
    var buf: [max_message]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try write(&w, l.tab, l.slice());
    var got: List = undefined;
    try testing.expect(parse(w.buffered(), &got));
    try testing.expectEqual(l.len, got.len);
    try testing.expectEqual(l.tab, got.tab);
    for (l.slice(), got.slice()) |*a, *b| try testing.expect(same(a, b));
    try testing.expect(got.needsDesk());
    try testing.expectEqual(@as(?usize, 2), got.find(@splat(3)));
    var empty: List = undefined;
    try testing.expect(parse("{\"t\":\"foryou\",\"id\":\"abababababababababababababababab\",\"items\":[],\"later\":1}", &empty));
    try testing.expect(empty.len == 0 and !empty.needsDesk());
}

test "the largest list fits max_message" {
    var l: List = .{};
    const cmd: [max_cmd]u8 = @splat('"');
    const why: [max_why]u8 = @splat('\\');
    const summary: [max_summary]u8 = @splat('"');
    const name: [max_name]u8 = @splat('"');
    for (&l.items, 0..) |*it, i| {
        it.* = .{ .id = @splat(@intCast(i)), .kind = .waiting_permission };
        it.setSummary(&summary);
        it.setCmd(&cmd);
        it.setWhy(&why);
        it.setProject(&name);
    }
    l.len = max_items;
    var buf: [max_message]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try write(&w, l.tab, l.slice());
    var got: List = undefined;
    try testing.expect(parse(w.buffered(), &got));
    try testing.expectEqual(@as(usize, max_items), got.len);
}

test "writer leaves out items it may not send" {
    var l = sample();
    l.items[1].setCmd("echo `whoami`"); // breaks the template
    l.items[2].project_len = 0; // goto without a target
    var buf: [max_message]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try write(&w, l.tab, l.slice());
    var got: List = undefined;
    try testing.expect(parse(w.buffered(), &got));
    try testing.expectEqual(@as(usize, 2), got.len);
}

test "malformed lists are rejected whole" {
    const tab = "\"id\":\"abababababababababababababababab\"";
    const id1 = "\"id\":\"01010101010101010101010101010101\"";
    const good = "{" ++ id1 ++ ",\"k\":\"answer\",\"text\":\"Proceed?\"}";
    var l: List = undefined;
    try testing.expect(parse("{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[" ++ good ++ "]}", &l));
    const long_summary: [max_summary + 1]u8 = @splat('s');
    const long_why: [max_why + 1]u8 = @splat('w');
    const bad = [_][]const u8{
        "{\"t\":\"foryou\",\"items\":[]}", // no tab
        "{\"t\":\"foryou\"," ++ tab ++ "}", // no items
        "{\"t\":\"activity\"," ++ tab ++ ",\"items\":[]}",
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[" ++ good ++ "," ++ good ++ "]}", // one id twice
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[" ++ good ++ "]",
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[" ++ good ++ "]}x",
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"bogus\",\"text\":\"x\"}]}",
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"text\":\"x\"}]}", // no kind
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"answer\"}]}", // no text
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{\"k\":\"answer\",\"text\":\"x\"}]}", // no id
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"answer\",\"text\":\"\"}]}",
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"answer\",\"text\":\"a\\nb\"}]}",
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"answer\",\"text\":\"a\\u001bb\"}]}",
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"answer\",\"text\":\"" ++ long_summary ++ "\"}]}",
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"answer\",\"text\":\"x\",\"why\":\"" ++ long_why ++ "\"}]}",
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"answer\",\"text\":\"x\",\"text\":\"y\"}]}",
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"answer\",\"text\":\"x\",\"more\":[1]}]}",
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"suggest_run\",\"text\":\"x\"}]}", // no cmd
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"suggest_run\",\"text\":\"x\",\"cmd\":\"a`b\"}]}",
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"suggest_run\",\"text\":\"x\",\"cmd\":\"a\\nb\"}]}",
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"suggest_goto\",\"text\":\"x\"}]}", // no project
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"suggest_goto\",\"text\":\"x\",\"project\":\"a\\u202eb\"}]}",
        "{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[{" ++ id1 ++ ",\"k\":\"answer\",\"text\":\"x\",\"cmd\":\"a\\u0000\"}]}",
    };
    for (bad) |b| try testing.expect(!parse(b, &l));
    // More than max_items.
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll("{\"t\":\"foryou\"," ++ tab ++ ",\"items\":[");
    for (0..max_items + 1) |i| {
        if (i > 0) try w.writeByte(',');
        try w.print("{{\"id\":\"{s}\",\"k\":\"needs_desk\",\"text\":\"x\"}}", .{&tabs.idHex(@splat(@intCast(i)))});
    }
    try w.writeAll("]}");
    try testing.expect(!parse(w.buffered(), &l));
}

test "templates" {
    var b: [max_cmd + 16]u8 = undefined;
    try testing.expectEqualStrings("Please run `zig build test`.", runMessage("zig build test", &b).?);
    try testing.expect(runMessage("rm `x`", &b) == null);
    try testing.expect(runMessage("a\nb", &b) == null);
    try testing.expect(runMessage("  ", &b) == null);
    var g: [max_name + 40]u8 = undefined;
    try testing.expectEqualStrings("Please switch to the acme-api project.", gotoMessage("acme-api", &g).?);
    try testing.expect(gotoMessage("", &g) == null);
}

test "effects and input modes" {
    try testing.expectEqual(Effect.answer, Kind.waiting_permission.effect(.no));
    try testing.expectEqual(Effect.send_message, Kind.suggest_run.effect(.yes));
    try testing.expectEqual(Effect.dismiss, Kind.suggest_goto.effect(.no));
    try testing.expectEqual(Effect.answer, Kind.answer.effect(.yes));
    try testing.expectEqual(Effect.dismiss, Kind.needs_desk.effect(.yes));
    try testing.expectEqual(Effect.dismiss, Kind.long_running.effect(.no));
    try testing.expect(Effect.dismiss.allowedIn("none"));
    try testing.expect(!Effect.answer.allowedIn("none"));
    try testing.expect(Effect.answer.allowedIn("keys"));
    try testing.expect(!Effect.send_message.allowedIn("keys"));
    try testing.expect(Effect.send_message.allowedIn("instruct"));
    try testing.expect(Effect.send_message.allowedIn("text"));
}

test "requests and results" {
    var b: [6 + tabs.hex_len]u8 = undefined;
    const id: Id = @splat(0x5a);
    const f = requestFrame(.no, id, &b);
    try testing.expectEqualStrings("i:no 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", f);
    const fr = frames.classify(f).?;
    try testing.expectEqual(frames.Prefix.item, fr.prefix);
    const r = parseRequest(fr.rest).?;
    try testing.expectEqual(Op.no, r.op);
    try testing.expectEqual(id, r.id);
    try testing.expectEqualStrings("i:yes 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", requestFrame(.yes, id, &b));
    for ([_][]const u8{ "yes", "yes ", "yes 5a", "Yes 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", "yes  5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", "yes 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a ", "yes 5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A", "maybe 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a" }) |bad|
        try testing.expect(parseRequest(bad) == null);
    var buf: [frames.max_answer]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeResult(&w, .yes, .stale, id);
    const a = parseResult(w.buffered()).?;
    try testing.expect(a.op == .yes and a.result == .stale and std.mem.eql(u8, &a.id.?, &id));
    var w2: std.Io.Writer = .fixed(&buf);
    try writeResult(&w2, .no, .rate_limited, null);
    try testing.expect(parseResult(w2.buffered()).?.id == null);
    try testing.expect(parseResult("{\"t\":\"item\",\"op\":\"yes\",\"result\":\"sent\",\"id\":\"zz\"}") == null);
    try testing.expect(parseResult("{\"t\":\"item\",\"op\":\"maybe\",\"result\":\"sent\"}") == null);
    try testing.expect(Result.sent.ok() and !Result.stale.ok());
}
