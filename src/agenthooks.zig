//! `portalctl hooks install | uninstall | status` and the desk's Settings
//! item "Claude Code integration": Portal's entries in the agent's user
//! settings (`%CLAUDE_CONFIG_DIR%\settings.json`, else
//! `%USERPROFILE%\.claude\settings.json`).
//!
//! One matcher group per event in hookmsg.Event, each with one command
//! hook in exec form (with `args`, `command` is spawned directly, no shell, so the
//! Windows path needs no quoting):
//!
//!   {"hooks": [{"type": "command", "command": "<...>\\portalctl.exe",
//!               "args": ["hook"], "timeout": 10}]}
//!
//! (Notification's group also has `"matcher": "permission_prompt|idle_prompt"`.)
//! A group is Portal's when it holds exactly one hook whose command is a
//! `portalctl.exe` and whose args are exactly ["hook"]; nothing else is
//! ever touched.
//!
//! Editing is textual, so everything else stays byte for byte: the file
//! is first validated as JSON (std.json; a file that does not parse is
//! refused with the reason), then a small span parser finds the places to
//! insert or cut. Insertions copy the file's indentation and line ends;
//! uninstall cuts exactly what install inserted (an event array or the
//! `hooks` object left empty by it goes too), so install + uninstall
//! gives back the original bytes. Writes are atomic (temp + rename) after
//! a timestamped backup next to the file, and refused if the file changed
//! while Portal was editing it.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const hookmsg = @import("hookmsg.zig");
const fsutil = @import("fsutil.zig");

pub const exe_name = "portalctl.exe";
/// Seconds the agent waits for the hook at most (the hook itself takes
/// milliseconds; this only bounds a hung machine).
pub const timeout_s = 10;
pub const max_file = 16 << 20;

pub const events = std.enums.values(hookmsg.Event);

fn matcherOf(e: hookmsg.Event) ?[]const u8 {
    return if (e == .Notification) hookmsg.notification_matcher else null;
}

pub const Error = error{ NotJson, NotAnObject, HooksNotAnObject, EventNotAnArray, OutOfMemory };

pub fn describe(err: anyerror) []const u8 {
    return switch (err) {
        error.NotJson => "it is not valid JSON",
        error.NotAnObject => "its top level is not a JSON object",
        error.HooksNotAnObject => "its \"hooks\" is not a JSON object",
        error.EventNotAnArray => "one of its \"hooks\" events is not a JSON array",
        error.ChangedMeanwhile => "it changed while Portal was editing it (try again)",
        error.FileTooBig => "it is larger than 16 MiB",
        else => @errorName(err),
    };
}

// ------------------------------------------------------------ span parser

const Kind = enum { object, array, string, other };

const Node = struct {
    kind: Kind,
    start: usize,
    end: usize,
    members: []Member = &.{},
    items: []Node = &.{},

    fn get(n: Node, key: []const u8) ?*const Member {
        for (n.members) |*m| if (std.mem.eql(u8, m.key, key)) return m;
        return null;
    }
};

const Member = struct {
    key: []const u8,
    start: usize,
    value: Node,
};

const Parser = struct {
    a: Allocator,
    s: []const u8,
    i: usize,

    fn ws(p: *Parser) void {
        while (p.i < p.s.len and (p.s[p.i] == ' ' or p.s[p.i] == '\t' or p.s[p.i] == '\n' or p.s[p.i] == '\r')) p.i += 1;
    }

    // The input is valid JSON (validated first), so this only tracks spans.
    fn value(p: *Parser) Error!Node {
        p.ws();
        const start = p.i;
        switch (p.s[p.i]) {
            '{' => {
                p.i += 1;
                var ms: std.ArrayList(Member) = .empty;
                p.ws();
                if (p.s[p.i] == '}') {
                    p.i += 1;
                } else while (true) {
                    p.ws();
                    const ks = p.i;
                    try p.string();
                    const key = std.json.parseFromSliceLeaky([]const u8, p.a, p.s[ks..p.i], .{}) catch return error.NotJson;
                    p.ws();
                    p.i += 1; // ':'
                    const v = try p.value();
                    try ms.append(p.a, .{ .key = key, .start = ks, .value = v });
                    p.ws();
                    const c = p.s[p.i];
                    p.i += 1;
                    if (c == '}') break;
                }
                return .{ .kind = .object, .start = start, .end = p.i, .members = ms.items };
            },
            '[' => {
                p.i += 1;
                var it: std.ArrayList(Node) = .empty;
                p.ws();
                if (p.s[p.i] == ']') {
                    p.i += 1;
                } else while (true) {
                    try it.append(p.a, try p.value());
                    p.ws();
                    const c = p.s[p.i];
                    p.i += 1;
                    if (c == ']') break;
                }
                return .{ .kind = .array, .start = start, .end = p.i, .items = it.items };
            },
            '"' => {
                try p.string();
                return .{ .kind = .string, .start = start, .end = p.i };
            },
            else => {
                while (p.i < p.s.len and std.mem.indexOfScalar(u8, " \t\r\n,]}", p.s[p.i]) == null) p.i += 1;
                return .{ .kind = .other, .start = start, .end = p.i };
            },
        }
    }

    fn string(p: *Parser) Error!void {
        if (p.s[p.i] != '"') return error.NotJson;
        p.i += 1;
        while (p.s[p.i] != '"') p.i += if (p.s[p.i] == '\\') 2 else 1;
        p.i += 1;
    }
};

fn bomLen(text: []const u8) usize {
    return if (std.mem.startsWith(u8, text, "\xEF\xBB\xBF")) 3 else 0;
}

/// Validates and parses; the top level must be an object.
fn parse(a: Allocator, text: []const u8) Error!Node {
    const body = text[bomLen(text)..];
    if (!(std.json.validate(a, body) catch return error.OutOfMemory)) return error.NotJson;
    var p: Parser = .{ .a = a, .s = text, .i = bomLen(text) };
    const root = try p.value();
    if (root.kind != .object) return error.NotAnObject;
    return root;
}

fn decodeString(a: Allocator, text: []const u8, n: Node) ?[]const u8 {
    if (n.kind != .string) return null;
    return std.json.parseFromSliceLeaky([]const u8, a, text[n.start..n.end], .{}) catch null;
}

/// The command of a Portal group (see the file comment), or null.
fn portalCommand(a: Allocator, text: []const u8, group: Node) ?[]const u8 {
    if (group.kind != .object) return null;
    const hs = (group.get("hooks") orelse return null).value;
    if (hs.kind != .array or hs.items.len != 1) return null;
    const h = hs.items[0];
    if (h.kind != .object) return null;
    const cmd = decodeString(a, text, (h.get("command") orelse return null).value) orelse return null;
    const base = cmd[if (std.mem.lastIndexOfAny(u8, cmd, "\\/")) |k| k + 1 else 0..];
    if (!std.ascii.eqlIgnoreCase(base, exe_name)) return null;
    const args = (h.get("args") orelse return null).value;
    if (args.kind != .array or args.items.len != 1) return null;
    const a0 = decodeString(a, text, args.items[0]) orelse return null;
    if (!std.mem.eql(u8, a0, "hook")) return null;
    return cmd;
}

// ------------------------------------------------------------ status

pub const Report = struct {
    /// Events with Portal's group for this exe.
    current: usize = 0,
    /// Portal groups for another portalctl.exe.
    other: usize = 0,
    /// `disableAllHooks: true` at the top level.
    all_disabled: bool = false,

    pub const State = enum { not_installed, installed, partly, other_exe };

    pub fn state(r: Report) State {
        if (r.current == events.len and r.other == 0) return .installed;
        if (r.current == 0 and r.other == 0) return .not_installed;
        if (r.current == 0) return .other_exe;
        return .partly;
    }
};

pub fn status(gpa: Allocator, text: []const u8, exe: []const u8) Error!Report {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try parse(a, text);
    var r: Report = .{};
    if (root.get("disableAllHooks")) |m| r.all_disabled = std.mem.eql(u8, text[m.value.start..m.value.end], "true");
    const hooks = (root.get("hooks") orelse return r).value;
    if (hooks.kind != .object) return error.HooksNotAnObject;
    for (events) |e| {
        const arr = (hooks.get(@tagName(e)) orelse continue).value;
        if (arr.kind != .array) return error.EventNotAnArray;
        var mine = false;
        for (arr.items) |g| if (portalCommand(a, text, g)) |cmd| {
            if (std.ascii.eqlIgnoreCase(cmd, exe)) mine = true else r.other += 1;
        };
        if (mine) r.current += 1;
    }
    // Portal groups under events Portal no longer uses count as other.
    for (hooks.members) |m| {
        if (hookmsg.Event.fromName(m.key) != null or m.value.kind != .array) continue;
        for (m.value.items) |g| if (portalCommand(a, text, g) != null) {
            r.other += 1;
        };
    }
    return r;
}

// ------------------------------------------------------------ editing

const Style = struct {
    nl: []const u8,
    unit: []const u8,

    fn of(text: []const u8, root: Node) Style {
        const nl: []const u8 = if (std.mem.indexOf(u8, text, "\r\n") != null) "\r\n" else "\n";
        var unit: []const u8 = "  ";
        if (root.members.len > 0) {
            const k = root.members[0].start;
            var b = k;
            while (b > 0 and (text[b - 1] == ' ' or text[b - 1] == '\t')) b -= 1;
            if (b < k and b > 0 and text[b - 1] == '\n') unit = text[b..k];
        }
        return .{ .nl = nl, .unit = unit };
    }

    fn indent(st: Style, w: *std.Io.Writer, level: usize) !void {
        for (0..level) |_| try w.writeAll(st.unit);
    }
};

fn writeJsonString(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0...8, 11, 12, 14...0x1f => try w.print("\\u{x:0>4}", .{c}),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

/// Portal's matcher group for `e`, at nesting `level`.
fn writeGroup(w: *std.Io.Writer, st: Style, level: usize, e: hookmsg.Event, exe: []const u8) !void {
    try w.writeAll("{");
    try w.writeAll(st.nl);
    if (matcherOf(e)) |m| {
        try st.indent(w, level + 1);
        try w.writeAll("\"matcher\": ");
        try writeJsonString(w, m);
        try w.writeAll(",");
        try w.writeAll(st.nl);
    }
    try st.indent(w, level + 1);
    try w.writeAll("\"hooks\": [");
    try w.writeAll(st.nl);
    try st.indent(w, level + 2);
    try w.writeAll("{");
    try w.writeAll(st.nl);
    try st.indent(w, level + 3);
    try w.writeAll("\"type\": \"command\",");
    try w.writeAll(st.nl);
    try st.indent(w, level + 3);
    try w.writeAll("\"command\": ");
    try writeJsonString(w, exe);
    try w.writeAll(",");
    try w.writeAll(st.nl);
    try st.indent(w, level + 3);
    try w.writeAll("\"args\": [");
    try w.writeAll(st.nl);
    try st.indent(w, level + 4);
    try w.writeAll("\"hook\"");
    try w.writeAll(st.nl);
    try st.indent(w, level + 3);
    try w.writeAll("],");
    try w.writeAll(st.nl);
    try st.indent(w, level + 3);
    try w.print("\"timeout\": {d}", .{timeout_s});
    try w.writeAll(st.nl);
    try st.indent(w, level + 2);
    try w.writeAll("}");
    try w.writeAll(st.nl);
    try st.indent(w, level + 1);
    try w.writeAll("]");
    try w.writeAll(st.nl);
    try st.indent(w, level);
    try w.writeAll("}");
}

/// `"Event": [ group ]` at member level `level`.
fn writeEventMember(w: *std.Io.Writer, st: Style, level: usize, e: hookmsg.Event, exe: []const u8) !void {
    try w.print("\"{t}\": [", .{e});
    try w.writeAll(st.nl);
    try st.indent(w, level + 1);
    try writeGroup(w, st, level + 1, e, exe);
    try w.writeAll(st.nl);
    try st.indent(w, level);
    try w.writeAll("]");
}

/// text[0..at] ++ insert ++ text[cut..], into a new buffer.
fn splice(a: Allocator, text: []const u8, at: usize, until: usize, insert: []const u8) Error![]u8 {
    return std.mem.concat(a, u8, &.{ text[0..at], insert, text[until..] });
}

/// Appends an element (member or item: `body` is its text) to the
/// container `c` whose own nesting is `level`.
fn append(a: Allocator, text: []const u8, st: Style, c: Node, level: usize, body: []const u8) Error![]u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    const w = &out.writer;
    const last_end: ?usize = switch (c.kind) {
        .object => if (c.members.len > 0) c.members[c.members.len - 1].value.end else null,
        .array => if (c.items.len > 0) c.items[c.items.len - 1].end else null,
        else => unreachable,
    };
    if (last_end) |e| {
        w.writeAll(",") catch return error.OutOfMemory;
        w.writeAll(st.nl) catch return error.OutOfMemory;
        st.indent(w, level + 1) catch return error.OutOfMemory;
        w.writeAll(body) catch return error.OutOfMemory;
        return splice(a, text, e, e, out.written());
    }
    w.writeAll(st.nl) catch return error.OutOfMemory;
    st.indent(w, level + 1) catch return error.OutOfMemory;
    w.writeAll(body) catch return error.OutOfMemory;
    w.writeAll(st.nl) catch return error.OutOfMemory;
    st.indent(w, level) catch return error.OutOfMemory;
    return splice(a, text, c.start + 1, c.end - 1, out.written());
}

/// Cuts element `i` of a container whose element spans are `spans`
/// (start of member key or item, end of value), with its separator.
fn cut(a: Allocator, text: []const u8, c: Node, starts: []const usize, ends: []const usize, i: usize) Error![]u8 {
    if (starts.len == 1) return splice(a, text, c.start + 1, c.end - 1, "");
    if (i > 0) return splice(a, text, ends[i - 1], ends[i], "");
    return splice(a, text, starts[0], starts[1], "");
}

fn cutMember(a: Allocator, text: []const u8, obj: Node, i: usize) Error![]u8 {
    const s = try a.alloc(usize, obj.members.len);
    const e = try a.alloc(usize, obj.members.len);
    for (obj.members, 0..) |m, k| {
        s[k] = m.start;
        e[k] = m.value.end;
    }
    return cut(a, text, obj, s, e, i);
}

fn cutItem(a: Allocator, text: []const u8, arr: Node, i: usize) Error![]u8 {
    const s = try a.alloc(usize, arr.items.len);
    const e = try a.alloc(usize, arr.items.len);
    for (arr.items, 0..) |m, k| {
        s[k] = m.start;
        e[k] = m.end;
    }
    return cut(a, text, arr, s, e, i);
}

fn indexOfMember(obj: Node, key: []const u8) ?usize {
    for (obj.members, 0..) |m, i| if (std.mem.eql(u8, m.key, key)) return i;
    return null;
}

/// One Portal group removed (with whatever its removal leaves empty), or
/// null when there is none left.
fn removeOne(a: Allocator, text: []const u8) Error!?[]u8 {
    const root = try parse(a, text);
    const hi = indexOfMember(root, "hooks") orelse return null;
    const hooks = root.members[hi].value;
    if (hooks.kind != .object) return error.HooksNotAnObject;
    for (hooks.members, 0..) |m, ei| {
        if (m.value.kind != .array) continue;
        for (m.value.items, 0..) |g, gi| {
            if (portalCommand(a, text, g) == null) continue;
            if (m.value.items.len > 1) return try cutItem(a, text, m.value, gi);
            if (hooks.members.len > 1) return try cutMember(a, text, hooks, ei);
            return try cutMember(a, text, root, hi);
        }
    }
    return null;
}

/// The file without any of Portal's groups; null if it had none.
pub fn uninstall(gpa: Allocator, text: []const u8) Error!?[]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var cur: []const u8 = text;
    var changed = false;
    while (try removeOne(a, cur)) |next| {
        cur = next;
        changed = true;
    }
    if (!changed) return null;
    return try gpa.dupe(u8, cur);
}

/// The file with Portal's group for every event, running `exe`; null if
/// it already has exactly that. Portal groups for another exe are
/// replaced.
pub fn install(gpa: Allocator, text: []const u8, exe: []const u8) Error!?[]u8 {
    const before = try status(gpa, text, exe);
    if (before.state() == .installed) return null;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var cur: []const u8 = text;
    while (try removeOne(a, cur)) |next| cur = next;
    var root = try parse(a, cur);
    const st = Style.of(cur, root);
    if (root.get("hooks") == null) {
        var out: std.Io.Writer.Allocating = .init(a);
        const w = &out.writer;
        writeHooks(w, st, exe) catch return error.OutOfMemory;
        cur = try append(a, cur, st, root, 0, out.written());
    } else for (events) |e| {
        root = try parse(a, cur);
        const hooks = root.get("hooks").?.value;
        if (hooks.kind != .object) return error.HooksNotAnObject;
        var out: std.Io.Writer.Allocating = .init(a);
        const w = &out.writer;
        if (hooks.get(@tagName(e))) |m| {
            if (m.value.kind != .array) return error.EventNotAnArray;
            writeGroup(w, st, 3, e, exe) catch return error.OutOfMemory;
            cur = try append(a, cur, st, m.value, 2, out.written());
        } else {
            writeEventMember(w, st, 2, e, exe) catch return error.OutOfMemory;
            cur = try append(a, cur, st, hooks, 1, out.written());
        }
    }
    return try gpa.dupe(u8, cur);
}

fn writeHooks(w: *std.Io.Writer, st: Style, exe: []const u8) !void {
    try w.writeAll("\"hooks\": {");
    for (events, 0..) |e, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll(st.nl);
        try st.indent(w, 2);
        try writeEventMember(w, st, 2, e, exe);
    }
    try w.writeAll(st.nl);
    try st.indent(w, 1);
    try w.writeAll("}");
}

// ------------------------------------------------------------ files

/// The agent's user settings file. Caller frees.
pub fn settingsPath(gpa: Allocator, env: *const std.process.Environ.Map) ![]u8 {
    if (env.get("CLAUDE_CONFIG_DIR")) |d| if (d.len > 0) return std.fs.path.join(gpa, &.{ d, "settings.json" });
    const home = env.get("USERPROFILE") orelse return error.NoProfile;
    return std.fs.path.join(gpa, &.{ home, ".claude", "settings.json" });
}

/// The installed launcher, %LOCALAPPDATA%\Portal\bin\portalctl.exe.
/// Caller frees.
pub fn defaultExe(gpa: Allocator, env: *const std.process.Environ.Map) ![]u8 {
    const base = env.get("LOCALAPPDATA") orelse return error.NoLocalAppData;
    return std.fs.path.join(gpa, &.{ base, "Portal", "bin", exe_name });
}

/// The file's bytes, or null when it does not exist. Caller frees.
fn readFile(gpa: Allocator, io: Io, path: []const u8) !?[]u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_file)) catch |err| switch (err) {
        error.FileNotFound => null,
        error.StreamTooLong => error.FileTooBig,
        else => err,
    };
}

pub fn statusFile(gpa: Allocator, io: Io, path: []const u8, exe: []const u8) !Report {
    const text = (try readFile(gpa, io, path)) orelse return .{};
    defer gpa.free(text);
    if (std.mem.trim(u8, text[bomLen(text)..], " \t\r\n").len == 0) return .{};
    return status(gpa, text, exe);
}

pub const Change = struct {
    /// False: the file already was as asked (nothing written).
    written: bool = false,
    /// The backup of the previous content, if one was made. Caller frees.
    backup: ?[]u8 = null,
};

pub const Op = enum { install, uninstall };

/// Installs or uninstalls in the file at `path` (see the file comment).
pub fn editFile(gpa: Allocator, io: Io, path: []const u8, op: Op, exe: []const u8) !Change {
    const old = try readFile(gpa, io, path);
    defer if (old) |o| gpa.free(o);
    const blank = if (old) |o| std.mem.trim(u8, o[bomLen(o)..], " \t\r\n").len == 0 else true;
    const base: []const u8 = if (blank) "{}\n" else old.?;
    const new = (switch (op) {
        .install => try install(gpa, base, exe),
        .uninstall => if (blank) null else try uninstall(gpa, base),
    }) orelse return .{};
    defer gpa.free(new);
    if (std.fs.path.dirname(path)) |d| try Io.Dir.cwd().createDirPath(io, d);
    var change: Change = .{ .written = true };
    errdefer if (change.backup) |b| gpa.free(b);
    if (old) |o| if (o.len > 0) {
        change.backup = try backupPath(gpa, io, path);
        try fsutil.writeAtomic(gpa, io, change.backup.?, o);
    };
    // The agent (or the owner) may have written it meanwhile.
    const now = try readFile(gpa, io, path);
    defer if (now) |n| gpa.free(n);
    const same = if (old) |o| (if (now) |n| std.mem.eql(u8, o, n) else false) else now == null;
    if (!same) return error.ChangedMeanwhile;
    try fsutil.writeAtomic(gpa, io, path, new);
    return change;
}

/// `<path>.portal-backup-<UTC yyyymmdd-hhmmss>[-n]`, not yet existing.
fn backupPath(gpa: Allocator, io: Io, path: []const u8) ![]u8 {
    const secs: u64 = @intCast(@max(Io.Timestamp.now(io, .real).toSeconds(), 0));
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();
    var n: usize = 0;
    while (true) : (n += 1) {
        const p = if (n == 0)
            try std.fmt.allocPrint(gpa, "{s}.portal-backup-{d:0>4}{d:0>2}{d:0>2}-{d:0>2}{d:0>2}{d:0>2}", .{ path, day.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() })
        else
            try std.fmt.allocPrint(gpa, "{s}.portal-backup-{d:0>4}{d:0>2}{d:0>2}-{d:0>2}{d:0>2}{d:0>2}-{d}", .{ path, day.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(), n });
        _ = Io.Dir.cwd().statFile(io, p, .{}) catch return p;
        gpa.free(p);
    }
}

// ------------------------------------------------------------ CLI

/// `portalctl hooks install [--exe PATH] | uninstall | status [--exe PATH]`.
/// Returns the exit code.
pub fn command(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, args: []const []const u8) u8 {
    const usage = "usage: portalctl hooks install [--exe PATH] | uninstall | status [--exe PATH]\n";
    if (args.len == 0) {
        std.debug.print("{s}", .{usage});
        return 2;
    }
    const sub = args[0];
    var exe_arg: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--exe") and i + 1 < args.len) {
            exe_arg = args[i + 1];
            i += 1;
        } else {
            std.debug.print("{s}", .{usage});
            return 2;
        }
    }
    const path = settingsPath(gpa, env) catch {
        std.debug.print("portalctl: cannot find Claude Code's settings (no USERPROFILE)\n", .{});
        return 1;
    };
    defer gpa.free(path);
    const exe = if (exe_arg) |e| gpa.dupe(u8, e) catch return 1 else defaultExe(gpa, env) catch {
        std.debug.print("portalctl: LOCALAPPDATA is not set\n", .{});
        return 1;
    };
    defer gpa.free(exe);
    if (!std.fs.path.isAbsolute(exe)) {
        std.debug.print("portalctl: --exe must be an absolute path\n", .{});
        return 2;
    }
    if (std.mem.eql(u8, sub, "status")) {
        const r = statusFile(gpa, io, path, exe) catch |err| {
            std.debug.print("portalctl: cannot read {s}: {s}\n", .{ path, describe(err) });
            return 1;
        };
        const text = switch (r.state()) {
            .installed => "installed",
            .not_installed => "not installed",
            .partly => "partly installed (run `portalctl hooks install` to complete it)",
            .other_exe => "installed for another portalctl.exe (run `portalctl hooks install` to point it here)",
        };
        std.debug.print("Claude Code integration: {s}\n  settings: {s}\n  hook:     {s} hook\n", .{ text, path, exe });
        if (r.all_disabled) std.debug.print("  note: disableAllHooks is true in that file, so Claude Code runs no hooks\n", .{});
        return 0;
    }
    const op: Op = if (std.mem.eql(u8, sub, "install")) .install else if (std.mem.eql(u8, sub, "uninstall")) .uninstall else {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    if (op == .install) {
        _ = Io.Dir.cwd().statFile(io, exe, .{}) catch
            std.debug.print("portalctl: note: {s} does not exist yet (install a Portal release, `zig build release`)\n", .{exe});
    }
    const ch = editFile(gpa, io, path, op, exe) catch |err| {
        std.debug.print("portalctl: {s} was not changed: {s}\n", .{ path, describe(err) });
        return 1;
    };
    defer if (ch.backup) |b| gpa.free(b);
    if (!ch.written) {
        std.debug.print("{s}: nothing to do ({s})\n", .{ path, if (op == .install) "already installed" else "not installed" });
        return 0;
    }
    if (ch.backup) |b| std.debug.print("backup of the previous file: {s}\n", .{b});
    std.debug.print("{s} {s}: {s}\n", .{ if (op == .install) "installed in" else "removed from", path, if (op == .install) "Claude Code sessions started in Portal tabs now report their state (new and running sessions pick it up)" else "Portal's hooks are gone; everything else is unchanged" });
    return 0;
}

// ------------------------------------------------------------ tests

const testing = std.testing;
const exe_a = "C:\\Users\\x\\AppData\\Local\\Portal\\bin\\portalctl.exe";
const exe_b = "D:\\dev\\Portal\\zig-out\\bin\\portalctl.exe";

fn roundTrip(original: []const u8) !void {
    const inst = (try install(testing.allocator, original, exe_a)).?;
    defer testing.allocator.free(inst);
    try testing.expect(std.json.validate(testing.allocator, inst[bomLen(inst)..]) catch false);
    try testing.expectEqual(Report.State.installed, (try status(testing.allocator, inst, exe_a)).state());
    // Idempotent.
    try testing.expect((try install(testing.allocator, inst, exe_a)) == null);
    const back = (try uninstall(testing.allocator, inst)).?;
    defer testing.allocator.free(back);
    try testing.expectEqualStrings(original, back);
    try testing.expect((try uninstall(testing.allocator, back)) == null);
}

test "install / uninstall round-trip byte for byte, keeping everything else" {
    try roundTrip("{\n  \"theme\": \"dark\"\n}\n");
    try roundTrip("{}");
    try roundTrip("{\r\n\t\"permissions\": {\r\n\t\t\"ask\": [\"Bash(ls *)\"]\r\n\t},\r\n\t\"x\": 1.50e3\r\n}\r\n");
    try roundTrip("\xEF\xBB\xBF{\"a\":{\"b\":[1,2,{\"c\":null}]},\"u\":\"\\u00e9\"}");
    // Existing hooks: other events and other groups of the same event.
    try roundTrip(
        \\{
        \\  "hooks": {
        \\    "PreToolUse": [
        \\      {
        \\        "matcher": "Bash",
        \\        "hooks": [{ "type": "command", "command": "lint.sh" }]
        \\      }
        \\    ],
        \\    "Stop": [
        \\      {
        \\        "hooks": [{ "type": "command", "command": "notify.sh" }]
        \\      }
        \\    ]
        \\  },
        \\  "model": "opus"
        \\}
        \\
    );
}

test "the one inexact case: a `hooks` (or event array) that was already empty goes too" {
    const inst = (try install(testing.allocator, "{\"hooks\":{}}", exe_a)).?;
    defer testing.allocator.free(inst);
    const back = (try uninstall(testing.allocator, inst)).?;
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("{}", back);
}

test "install writes exec-form entries for every event; the user's hooks stay" {
    const original =
        \\{
        \\  "hooks": {
        \\    "Stop": [
        \\      { "hooks": [{ "type": "command", "command": "C:\\tools\\portalctl.exe", "args": ["other"] }] }
        \\    ]
        \\  }
        \\}
    ;
    const inst = (try install(testing.allocator, original, exe_a)).?;
    defer testing.allocator.free(inst);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, inst, .{});
    defer parsed.deinit();
    const hooks = parsed.value.object.get("hooks").?.object;
    for (events) |e| {
        const arr = hooks.get(@tagName(e)).?.array;
        const g = arr.items[arr.items.len - 1].object;
        const h = g.get("hooks").?.array.items[0].object;
        try testing.expectEqualStrings("command", h.get("type").?.string);
        try testing.expectEqualStrings(exe_a, h.get("command").?.string);
        try testing.expectEqualStrings("hook", h.get("args").?.array.items[0].string);
        try testing.expectEqual(@as(i64, timeout_s), h.get("timeout").?.integer);
        if (e == .Notification) try testing.expectEqualStrings(hookmsg.notification_matcher, g.get("matcher").?.string) else try testing.expect(g.get("matcher") == null);
    }
    // The user's portalctl hook with other args is not Portal's.
    try testing.expectEqual(@as(usize, 2), hooks.get("Stop").?.array.items.len);
    const back = (try uninstall(testing.allocator, inst)).?;
    defer testing.allocator.free(back);
    try testing.expectEqualStrings(original, back);
}

test "another exe: status says so, install replaces it, no duplicates" {
    const a = (try install(testing.allocator, "{}", exe_b)).?;
    defer testing.allocator.free(a);
    try testing.expectEqual(Report.State.other_exe, (try status(testing.allocator, a, exe_a)).state());
    const b = (try install(testing.allocator, a, exe_a)).?;
    defer testing.allocator.free(b);
    const r = try status(testing.allocator, b, exe_a);
    try testing.expectEqual(Report.State.installed, r.state());
    try testing.expectEqual(@as(usize, 0), r.other);
    try testing.expect(std.mem.indexOf(u8, b, "zig-out") == null);
    // Partly installed (one entry deleted by hand) is completed.
    const p = try std.mem.replaceOwned(u8, testing.allocator, b, "\"SessionEnd\"", "\"SessionEndX\"");
    defer testing.allocator.free(p);
    const pr = try status(testing.allocator, p, exe_a);
    try testing.expectEqual(Report.State.partly, pr.state());
    const fixed = (try install(testing.allocator, p, exe_a)).?;
    defer testing.allocator.free(fixed);
    try testing.expectEqual(Report.State.installed, (try status(testing.allocator, fixed, exe_a)).state());
}

test "refused: not JSON, comments, wrong shapes; the reason is given" {
    try testing.expectError(error.NotJson, install(testing.allocator, "{\"a\":1,}", exe_a));
    try testing.expectError(error.NotJson, install(testing.allocator, "// c\n{}", exe_a));
    try testing.expectError(error.NotJson, install(testing.allocator, "{\"a\":1} x", exe_a));
    try testing.expectError(error.NotAnObject, install(testing.allocator, "[1]", exe_a));
    try testing.expectError(error.HooksNotAnObject, install(testing.allocator, "{\"hooks\":[]}", exe_a));
    try testing.expectError(error.EventNotAnArray, install(testing.allocator, "{\"hooks\":{\"Stop\":{}}}", exe_a));
    try testing.expectError(error.NotJson, uninstall(testing.allocator, "{"));
    try testing.expect(std.mem.indexOf(u8, describe(error.NotJson), "JSON") != null);
}

test "status: disableAllHooks; paths with quotes are escaped" {
    const r = try status(testing.allocator, "{\"disableAllHooks\": true}", exe_a);
    try testing.expect(r.all_disabled);
    try testing.expectEqual(Report.State.not_installed, r.state());
    const odd = "C:\\a \"b\"\\portalctl.exe";
    const t = (try install(testing.allocator, "{}", odd)).?;
    defer testing.allocator.free(t);
    try testing.expectEqual(Report.State.installed, (try status(testing.allocator, t, odd)).state());
}

test "editFile: backup, atomic write, missing file created, round trip on disk" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const dir = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(dir);
    const path = try std.fs.path.join(testing.allocator, &.{ dir, "cfg", "settings.json" });
    defer testing.allocator.free(path);
    // Missing: created; uninstall then leaves an empty object.
    const c1 = try editFile(testing.allocator, io, path, .install, exe_a);
    try testing.expect(c1.written and c1.backup == null);
    try testing.expectEqual(Report.State.installed, (try statusFile(testing.allocator, io, path, exe_a)).state());
    const c2 = try editFile(testing.allocator, io, path, .install, exe_a);
    try testing.expect(!c2.written);
    // An existing file comes back exactly, with a backup of each version.
    const original = "{\n  \"theme\": \"dark\"\n}\n";
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = original });
    const c3 = try editFile(testing.allocator, io, path, .install, exe_a);
    defer if (c3.backup) |b| testing.allocator.free(b);
    const saved = try Io.Dir.cwd().readFileAlloc(io, c3.backup.?, testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(saved);
    try testing.expectEqualStrings(original, saved);
    const c4 = try editFile(testing.allocator, io, path, .uninstall, exe_a);
    defer if (c4.backup) |b| testing.allocator.free(b);
    try testing.expect(c4.written);
    const back = try Io.Dir.cwd().readFileAlloc(io, path, testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(back);
    try testing.expectEqualStrings(original, back);
    // A broken file is left alone.
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "{oops" });
    try testing.expectError(error.NotJson, editFile(testing.allocator, io, path, .install, exe_a));
    const still = try Io.Dir.cwd().readFileAlloc(io, path, testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(still);
    try testing.expectEqualStrings("{oops", still);
}
