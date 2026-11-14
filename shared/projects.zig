//! Projects a device may start (docs/protocol.md section 3f, docs/
//! tabs-design.md "Starting projects from a device"): the desk-approved
//! list, the `projects` message that carries it, the `p:` frames a device
//! sends and the `project` answer. One implementation for the server
//! (src/web.zig, src/tabs.zig) and every client (client/src/net/client.zig,
//! the e2e suite), so both ends agree on the format and its limits.
//!
//!   server -> device
//!     {"t":"projects","list":[ENTRY,...]}
//!     ENTRY = {"name":"<name>","color":"#rrggbb","mode":"ask"|"plan",
//!              "running":true|false,"stoppable":true|false}
//!     {"t":"project","op":"start"|"stop","result":"<result>"[,"name":"<name>"]}
//!   device -> server
//!     p:start <name>
//!     p:stop <name>
//!
//! Only names, colours and booleans: the folder of a project never leaves
//! the desktop (privacy rule 1). `name` is a startable name (startableName:
//! a tab name that can never look like a path or an option). The parser
//! is strict and bounded; anything malformed is rejected whole.

const std = @import("std");
const tabs = @import("tabs.zig");
const frames = @import("frames.zig");

/// Most projects the desk may mark startable.
pub const max_projects = 16;
pub const max_name = tabs.max_name;

/// How a device-started session runs (the desk chooses, per project; a
/// device can't change it). Never a permissive mode: the agent's
/// `--permission-mode default` (every edit and command asks) or `plan`
/// (read-only planning).
pub const Mode = enum {
    ask,
    plan,

    pub fn wire(m: Mode) []const u8 {
        return @tagName(m);
    }

    pub fn fromWire(t: []const u8) ?Mode {
        return std.meta.stringToEnum(Mode, t);
    }

    /// The agent's `--permission-mode` value for this mode.
    pub fn agentArg(m: Mode) []const u8 {
        return switch (m) {
            .ask => "default",
            .plan => "plan",
        };
    }
};

/// True if `s` may name a startable project: a tab name (tabs.validName)
/// without `\`, `/`, `:` or `|`, not starting with `-` or `.`, so a name
/// can never be read as a path, a drive, an option or a settings field.
pub fn startableName(s: []const u8) bool {
    if (!tabs.validName(s)) return false;
    if (std.mem.indexOfAny(u8, s, "\\/:|\"") != null) return false;
    if (s[0] == '-' or s[0] == '.' or s[0] == ' ') return false;
    return s[s.len - 1] != ' ';
}

// --------------------------------------------------------------- the list

pub const Entry = struct {
    name_buf: [max_name]u8 = undefined,
    name_len: u8 = 0,
    color: u32 = 0,
    mode: Mode = .ask,
    running: bool = false,
    /// Running and started from a device: a device may stop it.
    stoppable: bool = false,

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
    items: [max_projects]Entry = undefined,
    len: usize = 0,

    pub fn slice(l: *const List) []const Entry {
        return l.items[0..l.len];
    }

    /// The entry named exactly `n` (case-sensitive, like the desk's check).
    pub fn find(l: *const List, n: []const u8) ?usize {
        for (l.items[0..l.len], 0..) |*e, i| if (std.mem.eql(u8, e.name(), n)) return i;
        return null;
    }

    pub fn eql(a: *const List, b: *const List) bool {
        if (a.len != b.len) return false;
        for (a.slice(), b.slice()) |*x, *y| {
            if (!std.mem.eql(u8, x.name(), y.name()) or x.color != y.color or x.mode != y.mode or
                x.running != y.running or x.stoppable != y.stoppable) return false;
        }
        return true;
    }
};

/// Room for any `projects` message.
pub const max_message = max_projects * (2 * max_name + 110) + 32;

/// Writes `{"t":"projects","list":[...]}`. Names must be startableName.
pub fn write(w: *std.Io.Writer, list: []const Entry) !void {
    try w.writeAll("{\"t\":\"projects\",\"list\":[");
    for (list, 0..) |*e, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"name\":\"");
        try writeName(w, e.name());
        try w.print("\",\"color\":\"{s}\",\"mode\":\"{s}\",\"running\":{},\"stoppable\":{}}}", .{ &tabs.colorHex(e.color), e.mode.wire(), e.running, e.stoppable });
    }
    try w.writeAll("]}");
}

fn writeName(w: *std.Io.Writer, n: []const u8) !void {
    for (n) |c| {
        if (c == '"' or c == '\\') try w.writeByte('\\');
        try w.writeByte(c);
    }
}

/// A `projects` message, or null if malformed in any way.
pub fn parse(text: []const u8) ?List {
    if (!std.mem.startsWith(u8, text, "{\"t\":\"projects\"")) return null;
    var p = tabs.fieldValue(text, "list") orelse return null;
    var list: List = .{};
    if (p >= text.len or text[p] != '[') return null;
    p = tabs.skipSpace(text, p + 1);
    if (p < text.len and text[p] == ']') return list;
    while (true) {
        if (list.len == max_projects) return null;
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

fn readBool(text: []const u8, p: *usize) ?bool {
    if (std.mem.startsWith(u8, text[p.*..], "true")) {
        p.* += 4;
        return true;
    }
    if (std.mem.startsWith(u8, text[p.*..], "false")) {
        p.* += 5;
        return false;
    }
    return null;
}

fn parseEntry(text: []const u8, start: usize, e: *Entry) ?usize {
    var p = start;
    if (p >= text.len or text[p] != '{') return null;
    p += 1;
    e.* = .{};
    var have_name = false;
    var have_mode = false;
    var key_buf: [16]u8 = undefined;
    var val_buf: [max_name]u8 = undefined;
    while (true) {
        p = tabs.skipSpace(text, p);
        if (p < text.len and text[p] == '}') break;
        const k = tabs.readString(text, &p, &key_buf) orelse return null;
        p = tabs.skipSpace(text, p);
        if (p >= text.len or text[p] != ':') return null;
        p = tabs.skipSpace(text, p + 1);
        if (p >= text.len) return null;
        if (std.mem.eql(u8, k, "running") or std.mem.eql(u8, k, "stoppable")) {
            const b = readBool(text, &p) orelse return null;
            if (k[0] == 'r') e.running = b else e.stoppable = b;
        } else {
            const v = tabs.readString(text, &p, &val_buf) orelse return null;
            if (std.mem.eql(u8, k, "name")) {
                if (!startableName(v)) return null;
                e.setName(v);
                have_name = true;
            } else if (std.mem.eql(u8, k, "color")) {
                e.color = tabs.parseColor(v) orelse return null;
            } else if (std.mem.eql(u8, k, "mode")) {
                e.mode = Mode.fromWire(v) orelse return null;
                have_mode = true;
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
    if (!have_name or !have_mode) return null;
    // Only a running project can be stopped.
    if (e.stoppable and !e.running) return null;
    return p + 1;
}

// ------------------------------------------------------- device requests

pub const Op = enum { start, stop };

pub const Request = struct { op: Op, name: []const u8 };

/// The frame a device sends: "p:start <name>" / "p:stop <name>". Null if
/// `name` is not a startable name or does not fit.
pub fn requestFrame(op: Op, name: []const u8, buf: []u8) ?[]const u8 {
    if (!startableName(name)) return null;
    return std.fmt.bufPrint(buf, "p:{s} {s}", .{ @tagName(op), name }) catch null;
}

/// What follows "p:" in a device's frame: exactly "start " or "stop ",
/// then a startableName and nothing else. Anything else (a path, an
/// option, a second word that makes the name invalid, control characters,
/// an empty name) is null: the server answers it like an unknown name.
pub fn parseRequest(rest: []const u8) ?Request {
    const v = frames.verb(Op, rest) orelse return null;
    if (!startableName(v.arg)) return null;
    return .{ .op = v.op, .name = v.arg };
}

/// What the desk did with a request (the `project` message's `result`).
pub const Result = enum {
    /// Started from the device (start) / asked to exit (stop).
    started,
    stopped,
    /// Already running: the device now shows it (start).
    switched,
    /// No such startable project (also: a malformed request).
    unknown,
    /// The desk's input mode for devices is `none` (view only).
    refused,
    /// Too many requests from this device in the last minute.
    rate_limited,
    /// The desk's program setting is not the agent, or allows a permissive
    /// permission mode: device starts are refused until it is fixed.
    unsafe_program,
    /// Stop: the session was started at the desk (only the desk stops it).
    not_device_started,
    /// Stop: it is not running.
    not_running,
    /// Start: the desk holds as many tabs as it can.
    too_many_tabs,
    /// Start: the program could not be started.
    failed,

    pub fn wire(r: Result) []const u8 {
        return @tagName(r);
    }

    pub fn fromWire(t: []const u8) ?Result {
        return std.meta.stringToEnum(Result, t);
    }

    /// What a device shows (UI strings may name the product).
    pub fn text(r: Result) []const u8 {
        return switch (r) {
            .started => "Started.",
            .stopped => "Stopped: Claude was asked to exit.",
            .switched => "Already running: switched to it.",
            .unknown => "The desk does not offer that project.",
            .refused => "This desk is view-only for devices.",
            .rate_limited => "Too many requests: wait a minute.",
            .unsafe_program => "The desk's program setting is not safe to start from a device (fix it at the desk).",
            .not_device_started => "Started at the desk: only the desk can stop it.",
            .not_running => "It is not running.",
            .too_many_tabs => "The desk has no room for another tab.",
            .failed => "The desk could not start it.",
        };
    }

    pub fn ok(r: Result) bool {
        return r == .started or r == .stopped or r == .switched;
    }
};

/// The answer to a `p:` frame. `name` (a startableName from the desk's
/// list, never the device's text) only for a known project.
pub fn writeResult(w: *std.Io.Writer, op: Op, result: Result, name: ?[]const u8) !void {
    try frames.writeAnswer(w, "project", @tagName(op), result.wire(), "name", name);
}

pub const Answer = struct {
    op: Op,
    result: Result,
    name_buf: [max_name]u8 = undefined,
    name_len: u8 = 0,

    pub fn name(a: *const Answer) ?[]const u8 {
        return if (a.name_len == 0) null else a.name_buf[0..a.name_len];
    }
};

/// A `project` message, or null.
pub fn parseResult(text: []const u8) ?Answer {
    var s: frames.Scratch = undefined;
    const raw = frames.parseAnswer(text, "project", "name", &s) orelse return null;
    var a: Answer = .{
        .op = std.meta.stringToEnum(Op, raw.op) orelse return null,
        .result = Result.fromWire(raw.result) orelse return null,
    };
    if (raw.ref) |n| {
        if (!startableName(n)) return null;
        @memcpy(a.name_buf[0..n.len], n);
        a.name_len = @intCast(n.len);
    }
    return a;
}

// ---------------------------------------------------------- rate limits

/// At most `n` events per `window_ms`, by timestamps (no timer): the
/// times of the last `n` accepted events.
pub fn Window(comptime n: usize) type {
    return struct {
        const Self = @This();
        times: [n]i64 = @splat(std.math.minInt(i64)),
        next: usize = 0,

        /// True (and counted) if fewer than `n` events were accepted in
        /// the `window_ms` before `now_ms`.
        pub fn allow(w: *Self, now_ms: i64, window_ms: i64) bool {
            const oldest = w.times[w.next];
            if (oldest != std.math.minInt(i64) and now_ms - oldest < window_ms) return false;
            w.times[w.next] = now_ms;
            w.next = (w.next + 1) % n;
            return true;
        }
    };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "startable names: never a path, an option or a field separator" {
    try testing.expect(startableName("acme-api"));
    try testing.expect(startableName("My Project 2"));
    for ([_][]const u8{ "", " x", "x ", "C:\\code\\acme", "..\\x", "a/b", "c:", "a|b", "-p", "--dangerously-skip-permissions", ".hidden", "a\nb", "a\x01b", "a\"b", "a\u{202e}b" }) |bad|
        try testing.expect(!startableName(bad));
    const over: [max_name + 1]u8 = @splat('p');
    try testing.expect(!startableName(&over));
}

test "list round trip; malformed lists rejected whole" {
    var l: List = .{};
    l.items[0] = .{ .color = 0x112233, .mode = .plan, .running = true, .stoppable = true };
    l.items[0].setName("acme api");
    l.items[1] = .{ .color = 0xFFFFFF };
    l.items[1].setName("Beta");
    l.len = 2;
    var buf: [max_message]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try write(&w, l.slice());
    const got = parse(w.buffered()).?;
    try testing.expect(got.eql(&l));
    try testing.expectEqual(@as(?usize, 1), got.find("Beta"));
    try testing.expect(got.find("beta") == null);
    try testing.expectEqual(@as(usize, 0), parse("{\"t\":\"projects\",\"list\":[]}").?.len);
    // The largest list fits.
    var big: List = .{};
    const worst: [max_name]u8 = @splat('w');
    for (&big.items) |*e| {
        e.* = .{ .running = true, .stoppable = true };
        e.setName(&worst);
    }
    big.len = max_projects;
    var w2: std.Io.Writer = .fixed(&buf);
    try write(&w2, big.slice());
    try testing.expectEqual(@as(usize, max_projects), parse(w2.buffered()).?.len);
    const good = "{\"name\":\"A\",\"color\":\"#000000\",\"mode\":\"ask\",\"running\":false,\"stoppable\":false}";
    try testing.expectEqual(@as(usize, 1), parse("{\"t\":\"projects\",\"list\":[" ++ good ++ "]}").?.len);
    const bad = [_][]const u8{
        "{\"t\":\"tabs\",\"list\":[]}",
        "{\"t\":\"projects\"}",
        "{\"t\":\"projects\",\"list\":[" ++ good,
        "{\"t\":\"projects\",\"list\":[{\"name\":\"A\"}]}", // no mode
        "{\"t\":\"projects\",\"list\":[{\"name\":\"C:\\\\code\\\\x\",\"mode\":\"ask\"}]}", // a path
        "{\"t\":\"projects\",\"list\":[{\"name\":\"A\",\"mode\":\"bypassPermissions\"}]}",
        "{\"t\":\"projects\",\"list\":[{\"name\":\"A\",\"mode\":\"ask\",\"running\":1}]}",
        "{\"t\":\"projects\",\"list\":[{\"name\":\"A\",\"mode\":\"ask\",\"running\":false,\"stoppable\":true}]}",
    };
    for (bad) |b| try testing.expect(parse(b) == null);
}

test "requests: exact verb and a startable name, nothing else" {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("p:start acme", requestFrame(.start, "acme", &buf).?);
    try testing.expectEqualStrings("p:stop acme", requestFrame(.stop, "acme", &buf).?);
    try testing.expect(requestFrame(.start, "C:\\x", &buf) == null);
    const r = parseRequest("start acme api").?;
    try testing.expectEqual(Op.start, r.op);
    try testing.expectEqualStrings("acme api", r.name);
    try testing.expectEqual(Op.stop, parseRequest("stop acme").?.op);
    for ([_][]const u8{
        "start",                "start ",                "start  acme",          "Start acme",                                "run acme",                                  "startacme",
        "start C:\\code\\acme", "start ..\\..\\Windows", "start /etc",           "start acme --dangerously-skip-permissions", "start --permission-mode bypassPermissions", "start acme\n",
        "start acme\x00",       "start acme|C:\\x",      "start acme \"C:\\x\"", "stop -x",
    }) |bad| {
        // Either malformed, or a name the desk can't have (it still has to
        // match the desk's list exactly, which the desk checks).
        if (parseRequest(bad)) |rr| {
            try testing.expect(std.mem.indexOfAny(u8, rr.name, "\\/:|\"") == null);
            try testing.expect(rr.name[0] != '-');
        }
    }
    try testing.expect(parseRequest("start C:\\code\\acme") == null);
    try testing.expect(parseRequest("start --permission-mode bypassPermissions") == null);
    // An option after a name makes a different name, never an argument.
    try testing.expectEqualStrings("acme --dangerously-skip-permissions", parseRequest("start acme --dangerously-skip-permissions").?.name);
}

test "result messages round trip" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeResult(&w, .start, .switched, "acme api");
    const a = parseResult(w.buffered()).?;
    try testing.expectEqual(Op.start, a.op);
    try testing.expectEqual(Result.switched, a.result);
    try testing.expectEqualStrings("acme api", a.name().?);
    var w2: std.Io.Writer = .fixed(&buf);
    try writeResult(&w2, .stop, .unknown, null);
    const b = parseResult(w2.buffered()).?;
    try testing.expect(b.name() == null and b.result == .unknown and b.op == .stop);
    try testing.expect(parseResult("{\"t\":\"project\",\"op\":\"start\",\"result\":\"nope\"}") == null);
    try testing.expect(Result.started.ok() and !Result.unknown.ok());
}

test "rate window: n per window, by timestamps" {
    var r: Window(3) = .{};
    try testing.expect(r.allow(0, 60_000));
    try testing.expect(r.allow(10, 60_000));
    try testing.expect(r.allow(20, 60_000));
    try testing.expect(!r.allow(30, 60_000));
    try testing.expect(!r.allow(59_999, 60_000));
    try testing.expect(r.allow(60_000, 60_000)); // the first one aged out
    try testing.expect(!r.allow(60_005, 60_000));
    try testing.expect(r.allow(60_010, 60_000));
}
