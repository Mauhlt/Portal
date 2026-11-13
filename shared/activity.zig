//! What each tab's session program is doing in the background, and what
//! it has used, on the wire (docs/protocol.md section 3c): one `activity`
//! message for all open tabs, so every tab's badge can show its counts.
//! One writer and one strict parser for the server (src/convo/activity.zig,
//! web.zig), the native client and the desk window.
//!
//!   {"t":"activity","sysmon":<bool>,"tabs":[TAB,...]}
//!   TAB  = {"id":"<32 hex>"[,"model":"<model id>"],
//!           "usage":USAGE,"today":USAGE,"tasks":[TASK,...]}
//!   USAGE = {"in":<n>,"out":<n>,"cr":<n>,"cw":<n>}
//!   TASK = {"k":"shell"|"monitor","state":"<state>","since":<unix s>,
//!           "text":"<short description>"}
//!
//! * `tabs`: the open tabs, in bar order (tabs without a transcript have
//!   empty usage and no tasks).
//! * `usage`: tokens of the session the tab follows now (its transcript):
//!   input, output, cache reads, cache writes. `today`: the same, counted
//!   only for replies dated today (the desktop's local day).
//! * `model`: the model id of the latest reply (letters, digits, `.`, `-`,
//!   `_`, `:`, `[`, `]`, `@`; at most 64 bytes); absent if unknown.
//! * `tasks`: background shells and monitors the program started, newest
//!   last, at most `max_tasks`; `text` is the description the program gave
//!   (scrubbed of paths and the user's name on the desktop; never the
//!   command), one printable line of at most `max_text` bytes.
//! * `sysmon`: the desk's "Show system monitor" setting (the System button
//!   and `y:on` work only while it is on).
//!
//! Parsing is strict and bounded: anything malformed, too long, with too
//! many tabs or tasks, an unknown kind or state is rejected whole.

const std = @import("std");
const tabs = @import("tabs.zig");
const convo = @import("convo.zig");

pub const Id = tabs.Id;
pub const max_tabs = tabs.max_tabs;
/// Most tasks one tab carries (finished ones go first when it is full).
pub const max_tasks = 16;
/// Longest task description, in bytes.
pub const max_text = 120;
/// Longest model id, in bytes.
pub const max_model = 64;

pub const Kind = enum { shell, monitor };

pub const State = enum {
    running,
    /// Ended normally (`completed`), or a monitor's timeout passed.
    done,
    failed,
    killed,
    /// Started before the tab did (an older run of the program): not
    /// known to be running.
    stale,

    pub fn live(s: State) bool {
        return s == .running;
    }
};

pub const Usage = struct {
    input: u64 = 0,
    output: u64 = 0,
    cache_read: u64 = 0,
    cache_write: u64 = 0,

    pub fn add(u: *Usage, o: Usage) void {
        u.input +|= o.input;
        u.output +|= o.output;
        u.cache_read +|= o.cache_read;
        u.cache_write +|= o.cache_write;
    }

    pub fn total(u: Usage) u64 {
        return u.input +| u.output +| u.cache_read +| u.cache_write;
    }

    pub fn isZero(u: Usage) bool {
        return u.total() == 0;
    }
};

pub const Task = struct {
    kind: Kind = .shell,
    state: State = .running,
    /// Unix seconds (from the transcript's record), 0 if unknown.
    since: i64 = 0,
    text_buf: [max_text]u8 = undefined,
    text_len: u8 = 0,

    pub fn text(t: *const Task) []const u8 {
        return t.text_buf[0..t.text_len];
    }

    /// Sets the text, cut to `max_text` at a character boundary.
    pub fn setText(t: *Task, s: []const u8) void {
        var n = @min(s.len, max_text);
        while (n > 0 and n < s.len and (s[n] & 0xC0) == 0x80) n -= 1;
        @memcpy(t.text_buf[0..n], s[0..n]);
        t.text_len = @intCast(n);
    }
};

pub const Tab = struct {
    id: Id = @splat(0),
    model_buf: [max_model]u8 = undefined,
    model_len: u8 = 0,
    usage: Usage = .{},
    today: Usage = .{},
    tasks: [max_tasks]Task = undefined,
    n_tasks: usize = 0,

    pub fn model(t: *const Tab) []const u8 {
        return t.model_buf[0..t.model_len];
    }

    pub fn setModel(t: *Tab, m: []const u8) void {
        if (!validModel(m)) {
            t.model_len = 0;
            return;
        }
        @memcpy(t.model_buf[0..m.len], m);
        t.model_len = @intCast(m.len);
    }

    pub fn taskSlice(t: *const Tab) []const Task {
        return t.tasks[0..t.n_tasks];
    }

    /// Tasks of `kind` still running.
    pub fn running(t: *const Tab, kind: Kind) u32 {
        var n: u32 = 0;
        for (t.taskSlice()) |*k| n += @intFromBool(k.kind == kind and k.state.live());
        return n;
    }
};

pub const Activity = struct {
    tabs: [max_tabs]Tab = undefined,
    len: usize = 0,
    /// The desk's "Show system monitor" setting.
    sysmon: bool = false,

    pub fn slice(a: *const Activity) []const Tab {
        return a.tabs[0..a.len];
    }

    pub fn find(a: *const Activity, id: Id) ?*const Tab {
        for (a.tabs[0..a.len]) |*t| if (std.mem.eql(u8, &t.id, &id)) return t;
        return null;
    }

    /// Today's tokens across every open tab.
    pub fn today(a: *const Activity) Usage {
        var u: Usage = .{};
        for (a.slice()) |*t| u.add(t.today);
        return u;
    }
};

/// A model id fit to show: 1..max_model bytes of [A-Za-z0-9._:@\[\]-].
pub fn validModel(m: []const u8) bool {
    if (m.len == 0 or m.len > max_model) return false;
    for (m) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.indexOfScalar(u8, "._-:[]@", c) == null) return false;
    return true;
}

/// One printable line: valid UTF-8, no controls at all.
pub fn validText(s: []const u8) bool {
    if (s.len > max_text or !convo.printable(s)) return false;
    return std.mem.indexOfAny(u8, s, "\n\t") == null;
}

// ---------------------------------------------------------------- writing

fn writeUsage(w: *std.Io.Writer, u: Usage) !void {
    try w.print("{{\"in\":{d},\"out\":{d},\"cr\":{d},\"cw\":{d}}}", .{ clamp53(u.input), clamp53(u.output), clamp53(u.cache_read), clamp53(u.cache_write) });
}

fn clamp53(v: u64) u64 {
    return @min(v, 1 << 53);
}

pub fn writeTab(w: *std.Io.Writer, t: *const Tab) !void {
    try w.print("{{\"id\":\"{s}\"", .{&tabs.idHex(t.id)});
    if (validModel(t.model())) try w.print(",\"model\":\"{s}\"", .{t.model()});
    try w.writeAll(",\"usage\":");
    try writeUsage(w, t.usage);
    try w.writeAll(",\"today\":");
    try writeUsage(w, t.today);
    try w.writeAll(",\"tasks\":[");
    for (t.taskSlice(), 0..) |*k, i| {
        if (i > 0) try w.writeByte(',');
        try w.print("{{\"k\":\"{s}\",\"state\":\"{s}\",\"since\":{d},\"text\":", .{ @tagName(k.kind), @tagName(k.state), @max(k.since, 0) });
        try convo.writeString(w, if (validText(k.text())) k.text() else "");
        try w.writeByte('}');
    }
    try w.writeAll("]}");
}

/// The whole `activity` message.
pub fn write(w: *std.Io.Writer, a: *const Activity) !void {
    try w.print("{{\"t\":\"activity\",\"sysmon\":{},\"tabs\":[", .{a.sysmon});
    for (a.slice(), 0..) |*t, i| {
        if (i > 0) try w.writeByte(',');
        try writeTab(w, t);
    }
    try w.writeAll("]}");
}

/// Room for any activity message: per task its syntax and twice its text
/// (`"` and `\` escape), per tab its id, model and usage.
pub const max_message = 64 + max_tabs * (160 + max_model + 2 * 110 + max_tasks * (96 + 2 * max_text));

// ---------------------------------------------------------------- parsing

/// Parses an `activity` message into `out`; false (and `out` unspecified)
/// if it is not one or is malformed in any way.
pub fn parse(text: []const u8, out: *Activity) bool {
    if (text.len > max_message) return false;
    var sbuf: [max_message]u8 = undefined;
    var p: convo.Parser = .{ .s = text, .out = &sbuf };
    out.* = .{};
    var have_t = false;
    var have_tabs = false;
    p.ws();
    if (!p.eat('{')) return false;
    var first = true;
    while (true) {
        p.ws();
        if (p.eat('}')) break;
        if (!first and !p.eat(',')) return false;
        first = false;
        p.ws();
        const key = p.string() orelse return false;
        p.ws();
        if (!p.eat(':')) return false;
        p.ws();
        if (eq(key, "t")) {
            if (!eq(p.string() orelse return false, "activity")) return false;
            have_t = true;
        } else if (eq(key, "sysmon")) {
            out.sysmon = p.boolean() orelse return false;
        } else if (eq(key, "tabs")) {
            if (have_tabs or !p.eat('[')) return false;
            have_tabs = true;
            p.ws();
            if (!p.eat(']')) while (true) {
                if (out.len == max_tabs) return false;
                p.ws();
                if (!parseTab(&p, &out.tabs[out.len])) return false;
                out.len += 1;
                p.ws();
                if (p.eat(']')) break;
                if (!p.eat(',')) return false;
            };
        } else if (!p.scalar()) return false;
    }
    p.ws();
    return p.i == text.len and have_t and have_tabs;
}

fn parseTab(p: *convo.Parser, t: *Tab) bool {
    t.* = .{};
    if (!p.eat('{')) return false;
    var have_id = false;
    var first = true;
    while (true) {
        p.ws();
        if (p.eat('}')) break;
        if (!first and !p.eat(',')) return false;
        first = false;
        p.ws();
        const key = p.string() orelse return false;
        p.ws();
        if (!p.eat(':')) return false;
        p.ws();
        if (eq(key, "id")) {
            t.id = tabs.parseId(p.string() orelse return false) orelse return false;
            have_id = true;
        } else if (eq(key, "model")) {
            const m = p.string() orelse return false;
            if (!validModel(m)) return false;
            t.setModel(m);
        } else if (eq(key, "usage")) {
            t.usage = parseUsage(p) orelse return false;
        } else if (eq(key, "today")) {
            t.today = parseUsage(p) orelse return false;
        } else if (eq(key, "tasks")) {
            if (!p.eat('[')) return false;
            p.ws();
            if (!p.eat(']')) while (true) {
                if (t.n_tasks == max_tasks) return false;
                p.ws();
                if (!parseTask(p, &t.tasks[t.n_tasks])) return false;
                t.n_tasks += 1;
                p.ws();
                if (p.eat(']')) break;
                if (!p.eat(',')) return false;
            };
        } else if (!p.scalar()) return false;
    }
    return have_id;
}

fn parseUsage(p: *convo.Parser) ?Usage {
    if (!p.eat('{')) return null;
    var u: Usage = .{};
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
        if (eq(key, "in")) {
            u.input = p.number64() orelse return null;
        } else if (eq(key, "out")) {
            u.output = p.number64() orelse return null;
        } else if (eq(key, "cr")) {
            u.cache_read = p.number64() orelse return null;
        } else if (eq(key, "cw")) {
            u.cache_write = p.number64() orelse return null;
        } else if (!p.scalar()) return null;
    }
    return u;
}

fn parseTask(p: *convo.Parser, k: *Task) bool {
    k.* = .{};
    if (!p.eat('{')) return false;
    var have_k = false;
    var have_state = false;
    var first = true;
    while (true) {
        p.ws();
        if (p.eat('}')) break;
        if (!first and !p.eat(',')) return false;
        first = false;
        p.ws();
        const key = p.string() orelse return false;
        p.ws();
        if (!p.eat(':')) return false;
        p.ws();
        if (eq(key, "k")) {
            k.kind = std.meta.stringToEnum(Kind, p.string() orelse return false) orelse return false;
            have_k = true;
        } else if (eq(key, "state")) {
            k.state = std.meta.stringToEnum(State, p.string() orelse return false) orelse return false;
            have_state = true;
        } else if (eq(key, "since")) {
            k.since = @intCast(p.number64() orelse return false);
        } else if (eq(key, "text")) {
            const v = p.string() orelse return false;
            if (!validText(v)) return false;
            k.setText(v);
        } else if (!p.scalar()) return false;
    }
    return have_k and have_state;
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn sample() Activity {
    var a: Activity = .{ .sysmon = true };
    a.len = 2;
    a.tabs[0] = .{ .id = @splat(0xab), .usage = .{ .input = 12, .output = 3400, .cache_read = 1 << 40, .cache_write = 7 }, .today = .{ .input = 2, .output = 5 } };
    a.tabs[0].setModel("model-large-4-1-20250805");
    a.tabs[0].tasks[0] = .{ .kind = .shell, .state = .running, .since = 1_762_941_600 };
    a.tabs[0].tasks[0].setText("Run the \"tests\" in acme\\src");
    a.tabs[0].tasks[1] = .{ .kind = .monitor, .state = .done, .since = 1 };
    a.tabs[0].tasks[1].setText("Watch the build log");
    a.tabs[0].n_tasks = 2;
    a.tabs[1] = .{ .id = @splat(0x01) };
    return a;
}

test "activity round trip" {
    const a = sample();
    var buf: [max_message]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try write(&w, &a);
    var b: Activity = undefined;
    try testing.expect(parse(w.buffered(), &b));
    try testing.expect(b.sysmon);
    try testing.expectEqual(@as(usize, 2), b.len);
    const t = &b.tabs[0];
    try testing.expectEqualStrings("model-large-4-1-20250805", t.model());
    try testing.expectEqual(@as(u64, 1 << 40), t.usage.cache_read);
    try testing.expectEqual(@as(u64, 3400), t.usage.output);
    try testing.expectEqual(@as(u64, 7), b.today().total());
    try testing.expectEqual(@as(usize, 2), t.n_tasks);
    try testing.expectEqualStrings("Run the \"tests\" in acme\\src", t.tasks[0].text());
    try testing.expectEqual(State.done, t.tasks[1].state);
    try testing.expectEqual(@as(u32, 1), t.running(.shell));
    try testing.expectEqual(@as(u32, 0), t.running(.monitor));
    try testing.expectEqual(@as(i64, 1_762_941_600), t.tasks[0].since);
    try testing.expectEqualStrings("", b.tabs[1].model());
    try testing.expect(b.find(@splat(0x01)) != null);
    try testing.expect(b.find(@splat(0x02)) == null);
}

test "the largest activity message fits max_message" {
    var a: Activity = .{ .len = max_tabs };
    for (&a.tabs) |*t| {
        t.* = .{ .usage = .{ .input = 1 << 53, .output = 1 << 53, .cache_read = 1 << 53, .cache_write = 1 << 53 }, .today = .{ .input = 1 << 53, .output = 1 << 53, .cache_read = 1 << 53, .cache_write = 1 << 53 } };
        const mm: [max_model]u8 = @splat('m');
        t.setModel(&mm);
        t.n_tasks = max_tasks;
        for (&t.tasks) |*k| {
            k.* = .{ .kind = .monitor, .state = .killed, .since = std.math.maxInt(i32) };
            const q: [max_text]u8 = @splat('"');
            k.setText(&q);
        }
    }
    var buf: [max_message]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try write(&w, &a);
    var b: Activity = undefined;
    try testing.expect(parse(w.buffered(), &b));
    try testing.expectEqual(@as(usize, max_tasks), b.tabs[max_tabs - 1].n_tasks);
}

const long_text: [max_text + 1]u8 = @splat('x');

test "malformed activity is rejected whole" {
    const id = "\"id\":\"abababababababababababababababab\"";
    var a: Activity = undefined;
    try testing.expect(parse("{\"t\":\"activity\",\"tabs\":[]}", &a));
    try testing.expect(parse("{\"t\":\"activity\",\"future\":1,\"tabs\":[{" ++ id ++ ",\"x\":\"y\"}]}", &a));
    const bad = [_][]const u8{
        "",
        "{\"t\":\"activity\"}",
        "{\"t\":\"tabs\",\"tabs\":[]}",
        "{\"t\":\"activity\",\"tabs\":[{}]}",
        "{\"t\":\"activity\",\"tabs\":[{" ++ id ++ ",\"model\":\"C:\\\\Users\\\\bob\"}]}",
        "{\"t\":\"activity\",\"tabs\":[{" ++ id ++ ",\"usage\":{\"in\":-1}}]}",
        "{\"t\":\"activity\",\"tabs\":[{" ++ id ++ ",\"usage\":{\"in\":1.5}}]}",
        "{\"t\":\"activity\",\"tabs\":[{" ++ id ++ ",\"tasks\":[{\"k\":\"agent\",\"state\":\"running\"}]}]}",
        "{\"t\":\"activity\",\"tabs\":[{" ++ id ++ ",\"tasks\":[{\"k\":\"shell\",\"state\":\"zombie\"}]}]}",
        "{\"t\":\"activity\",\"tabs\":[{" ++ id ++ ",\"tasks\":[{\"k\":\"shell\"}]}]}",
        "{\"t\":\"activity\",\"tabs\":[{" ++ id ++ ",\"tasks\":[{\"k\":\"shell\",\"state\":\"running\",\"text\":\"a\\nb\"}]}]}",
        "{\"t\":\"activity\",\"tabs\":[{" ++ id ++ ",\"tasks\":[{\"k\":\"shell\",\"state\":\"running\",\"text\":\"" ++ long_text ++ "\"}]}]}",
        "{\"t\":\"activity\",\"tabs\":[]} trailing",
        "{\"t\":\"activity\",\"tabs\":[{" ++ id ++ ",\"tasks\":{}}]}",
    };
    for (bad) |b| {
        if (parse(b, &a)) {
            std.debug.print("accepted: {s}\n", .{b});
            return error.TestUnexpectedResult;
        }
    }
    // Too many tasks.
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll("{\"t\":\"activity\",\"tabs\":[{" ++ id ++ ",\"tasks\":[");
    for (0..max_tasks + 1) |i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"k\":\"shell\",\"state\":\"running\",\"since\":0,\"text\":\"\"}");
    }
    try w.writeAll("]}]}");
    try testing.expect(!parse(w.buffered(), &a));
}

test "validModel and text cutting" {
    try testing.expect(validModel("model-small-4-5[1m]"));
    try testing.expect(!validModel("<synthetic>"));
    try testing.expect(!validModel(""));
    try testing.expect(!validModel("a b"));
    var t: Task = .{};
    t.setText("é" ++ "é" ++ "éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé"); // 140 bytes: cut at a character boundary
    try testing.expectEqual(@as(usize, 120), t.text().len);
    try testing.expect(std.unicode.utf8ValidateSlice(t.text()));
}
