//! Agent hooks -> Portal (docs/tabs-design.md, "Detecting the agent is
//! waiting", fallback 2): the pure part. `portalctl hook` (hookpipe.zig)
//! reads the hook's JSON from stdin, keeps three fields and sends a tiny
//! text message to the running Portal; Portal maps it to the tab's state.
//!
//! Agent hook input: JSON on stdin with
//! `hook_event_name`, and per event `tool_name` (PermissionRequest),
//! `notification_type` (Notification), `agent_id` (SubagentStart,
//! SubagentStop). PreToolUse's `tool_input.command` is read by the hook
//! process only (elevation.zig) and never sent. Everything else (the prompt, tool
//! input, messages, paths) is never read past the parser and never sent.
//!
//! The message (at most `max_message` bytes, ASCII lines):
//!
//!   portal-hook-v1
//!   tab=<32 lower-case hex: the tab's PORTAL_TAB>
//!   event=<one of `Event`>
//!   tool=<tool name>              (PermissionRequest, PreToolUse; optional)
//!   ntype=<notification type>     (Notification only)
//!   agent=<subagent id>           (SubagentStart / SubagentStop only)
//!   error=rate_limit              (StopFailure only, and only this value:
//!                                  the plan's limit, usage_desk.zig)
//!   guard=marked|denied           (PreToolUse only: the admin-prompt guard)
//!
//! Untrusted on both ends: the sender only sends enumerated event names
//! and `[A-Za-z0-9_-]{1,64}` names; the receiver accepts only those, maps
//! only enumerated values, and uses the tool name only to pick a phrase
//! from a fixed table (transcript.category). Nothing of it is displayed or
//! logged as received.

const std = @import("std");
const vt = @import("vt.zig");
const Wait = @import("convo/model.zig").Wait;
const transcript = @import("convo/transcript.zig");

pub const header = "portal-hook-v1";
pub const max_message = 256;
pub const max_name = 64;
/// The environment variable Portal sets for each tab's program (one
/// random 128-bit value per tab launch, 32 lower-case hex). Desktop-only:
/// never logged, never sent to devices.
pub const env_name = "PORTAL_TAB";
pub const Key = [16]u8;

/// The hook events Portal listens to (settings.json gets one entry each,
/// agenthooks.zig).
pub const Event = enum {
    /// Before a shell command runs (its matcher is `pretool_matcher`, so
    /// it fires only for the Bash and PowerShell tools, not for every tool
    /// call): the admin-prompt guard and the long-running deadline
    /// (docs/tabs-design.md). `guard` says what the hook did about an
    /// elevating command; no state change.
    PreToolUse,
    UserPromptSubmit,
    PermissionRequest,
    Notification,
    Stop,
    StopFailure,
    SessionEnd,
    /// A subagent started / finished (`agent_id`): the tab's sub-tabs
    /// (tabs.Tab.subagentEvent); no state change.
    SubagentStart,
    SubagentStop,

    pub fn fromName(s: []const u8) ?Event {
        return std.meta.stringToEnum(Event, s);
    }
};

/// The Notification types that change a tab (Notification's matcher in
/// settings.json is exactly these, so others don't even start the hook).
pub const notification_matcher = "permission_prompt|idle_prompt";
/// PreToolUse's matcher: the shell tools only.
pub const pretool_matcher = "Bash|PowerShell";

/// What `portalctl hook` did about a PreToolUse command that asks for
/// elevation (elevation.zig): nothing to say, let it run and told Portal
/// (a "needs desk" card), or denied it.
pub const Guard = enum { none, marked, denied };

/// The environment variable Portal sets for a tab a paired device started
/// (value `device`): its hook denies elevating commands. Added after
/// childenv's filter like PORTAL_TAB, so it is never inherited.
pub const guard_env_name = "PORTAL_GUARD";

/// `[A-Za-z0-9_-]{1,64}`: the only names that travel.
pub fn validName(s: []const u8) bool {
    if (s.len == 0 or s.len > max_name) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-') return false;
    return true;
}

pub fn parseKey(hex: []const u8) ?Key {
    if (hex.len != 32) return null;
    for (hex) |c| if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return null;
    var k: Key = undefined;
    _ = std.fmt.hexToBytes(&k, hex) catch return null;
    return k;
}

pub fn keyHex(k: Key) [32]u8 {
    return std.fmt.bytesToHex(k, .lower);
}

pub const Message = struct {
    key: Key,
    event: Event,
    tool_buf: [max_name]u8 = undefined,
    tool_len: u8 = 0,
    ntype_buf: [max_name]u8 = undefined,
    ntype_len: u8 = 0,
    agent_buf: [max_name]u8 = undefined,
    agent_len: u8 = 0,
    /// StopFailure because of the plan's rate limit (`error`: `rate_limit`).
    rate_limit: bool = false,
    guard: Guard = .none,

    pub fn tool(m: *const Message) []const u8 {
        return m.tool_buf[0..m.tool_len];
    }
    pub fn ntype(m: *const Message) []const u8 {
        return m.ntype_buf[0..m.ntype_len];
    }
    pub fn agent(m: *const Message) []const u8 {
        return m.agent_buf[0..m.agent_len];
    }
    fn setAgent(m: *Message, s: []const u8) void {
        if (!validName(s)) return;
        @memcpy(m.agent_buf[0..s.len], s);
        m.agent_len = @intCast(s.len);
    }
    fn setTool(m: *Message, s: []const u8) void {
        if (!validName(s)) return;
        @memcpy(m.tool_buf[0..s.len], s);
        m.tool_len = @intCast(s.len);
    }
    fn setNtype(m: *Message, s: []const u8) void {
        if (!validName(s)) return;
        @memcpy(m.ntype_buf[0..s.len], s);
        m.ntype_len = @intCast(s.len);
    }

    pub fn format(m: *const Message, buf: *[max_message]u8) []const u8 {
        var wr: std.Io.Writer = .fixed(buf);
        const hex = keyHex(m.key);
        wr.print("{s}\ntab={s}\nevent={t}\n", .{ header, &hex, m.event }) catch unreachable;
        if (m.tool_len > 0) wr.print("tool={s}\n", .{m.tool()}) catch unreachable;
        if (m.ntype_len > 0) wr.print("ntype={s}\n", .{m.ntype()}) catch unreachable;
        if (m.agent_len > 0) wr.print("agent={s}\n", .{m.agent()}) catch unreachable;
        if (m.rate_limit) wr.writeAll("error=rate_limit\n") catch unreachable;
        if (m.guard != .none) wr.print("guard={t}\n", .{m.guard}) catch unreachable;
        return wr.buffered();
    }
};

/// The receiver's strict parser: anything malformed is null (dropped).
pub fn parse(text: []const u8) ?Message {
    if (text.len > max_message) return null;
    var it = std.mem.splitScalar(u8, text, '\n');
    if (!std.mem.eql(u8, it.next() orelse return null, header)) return null;
    var key: ?Key = null;
    var event: ?Event = null;
    var tool: []const u8 = "";
    var ntype: []const u8 = "";
    var agent: []const u8 = "";
    var rate_limit = false;
    var guard: Guard = .none;
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse return null;
        const k = line[0..eq];
        const v = line[eq + 1 ..];
        if (std.mem.eql(u8, k, "tab")) {
            key = parseKey(v) orelse return null;
        } else if (std.mem.eql(u8, k, "event")) {
            event = Event.fromName(v) orelse return null;
        } else if (std.mem.eql(u8, k, "tool")) {
            if (!validName(v)) return null;
            tool = v;
        } else if (std.mem.eql(u8, k, "ntype")) {
            if (!validName(v)) return null;
            ntype = v;
        } else if (std.mem.eql(u8, k, "agent")) {
            if (!validName(v)) return null;
            agent = v;
        } else if (std.mem.eql(u8, k, "error")) {
            if (!validName(v)) return null;
            rate_limit = std.mem.eql(u8, v, "rate_limit");
        } else if (std.mem.eql(u8, k, "guard")) {
            guard = std.meta.stringToEnum(Guard, v) orelse return null;
        } // unknown keys: ignored (a newer sender)
    }
    var m: Message = .{ .key = key orelse return null, .event = event orelse return null, .guard = guard };
    m.setTool(tool);
    m.setNtype(ntype);
    m.setAgent(agent);
    m.rate_limit = rate_limit and m.event == .StopFailure;
    return m;
}

/// The sender's side: the agent's hook JSON (stdin) to a message, or
/// null when there is nothing worth telling Portal (an event Portal does
/// not use, a Notification of another type, unparsable input).
pub fn fromHookJson(scratch: std.mem.Allocator, key: Key, json: []const u8) ?Message {
    return (parseHook(scratch, key, json) orelse return null).msg;
}

/// What the hook process reads from the agent's JSON: the message, and
/// for PreToolUse the shell command (`tool_input.command`, in `scratch`),
/// which only the hook process looks at (the admin-prompt guard) and
/// which never travels.
pub const Parsed = struct { msg: Message, command: ?[]const u8 = null };

pub fn parseHook(scratch: std.mem.Allocator, key: Key, json: []const u8) ?Parsed {
    const In = struct {
        hook_event_name: ?[]const u8 = null,
        tool_name: ?[]const u8 = null,
        notification_type: ?[]const u8 = null,
        agent_id: ?[]const u8 = null,
        @"error": ?[]const u8 = null,
        // Any shape (another tool's input may hold anything).
        tool_input: ?std.json.Value = null,
    };
    const in = std.json.parseFromSliceLeaky(In, scratch, json, .{ .ignore_unknown_fields = true, .duplicate_field_behavior = .use_last }) catch return null;
    const event = Event.fromName(in.hook_event_name orelse return null) orelse return null;
    var m: Message = .{ .key = key, .event = event };
    var command: ?[]const u8 = null;
    switch (event) {
        .PreToolUse => {
            if (in.tool_name) |t| m.setTool(t);
            if (in.tool_input) |ti| if (ti == .object) if (ti.object.get("command")) |c| if (c == .string) {
                command = c.string;
            };
        },
        .PermissionRequest => if (in.tool_name) |t| m.setTool(t),
        // Only the plan's limit travels (the matcher's value): other
        // errors are just `error`.
        .StopFailure => m.rate_limit = if (in.@"error") |e| std.mem.eql(u8, e, "rate_limit") else false,
        .Notification => {
            const nt = in.notification_type orelse return null;
            if (!std.mem.eql(u8, nt, "permission_prompt") and !std.mem.eql(u8, nt, "idle_prompt")) return null;
            m.setNtype(nt);
        },
        // Without a usable id there is nothing to tell.
        .SubagentStart, .SubagentStop => {
            m.setAgent(in.agent_id orelse return null);
            if (m.agent_len == 0) return null;
        },
        else => {},
    }
    return .{ .msg = m, .command = command };
}

/// What a message does to its tab.
pub const Effect = struct {
    state: vt.ProgramState,
    wait: Wait,
    /// PermissionRequest: the tool's category, for "Claude wants to
    /// <phrase>" (null: keep what is known).
    cat: ?transcript.Category = null,
};

/// The mapping (docs/tabs-design.md). Null: the message changes nothing.
pub fn effect(m: *const Message) ?Effect {
    return switch (m.event) {
        .UserPromptSubmit => .{ .state = .working, .wait = .none },
        .PermissionRequest => .{
            .state = .waiting,
            .wait = .permission,
            // A fixed phrase per category; an unknown tool is "use a tool"
            // (the name itself is never shown).
            .cat = if (m.tool_len > 0) transcript.category(m.tool()) else .other,
        },
        .Notification => if (std.mem.eql(u8, m.ntype(), "permission_prompt"))
            .{ .state = .waiting, .wait = .permission }
        else if (std.mem.eql(u8, m.ntype(), "idle_prompt"))
            .{ .state = .idle, .wait = .none }
        else
            null,
        .Stop => .{ .state = .done, .wait = .none },
        .StopFailure => .{ .state = .failed, .wait = .none },
        .SessionEnd => .{ .state = .idle, .wait = .none },
        .SubagentStart, .SubagentStop, .PreToolUse => null,
    };
}

/// The pipe's name for this user and data directory:
/// `\\.\pipe\portal-hook-<32 hex>`, the hex the first 16 bytes of
/// SHA-256 over the user's SID and the (lower-cased) data directory, so
/// two users, or two Portals with their own data directories (the e2e
/// tests), never share one. Not a secret: the pipe's DACL is what keeps
/// other users out (hookpipe.zig).
pub fn pipeName(buf: *[64]u8, sid: []const u8, data_dir: []const u8) []const u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("portal-hook-v1\x00");
    h.update(sid);
    h.update("\x00");
    for (data_dir) |c| h.update(&.{std.ascii.toLower(c)});
    var d: [32]u8 = undefined;
    h.final(&d);
    const hex = std.fmt.bytesToHex(d[0..16].*, .lower);
    return std.fmt.bufPrint(buf, "\\\\.\\pipe\\portal-hook-{s}", .{&hex}) catch unreachable;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "fromHookJson: the documented inputs; unknown fields, other events and types dropped" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key: Key = @splat(0xab);
    // Sample hook payloads.
    const perm = fromHookJson(a, key,
        \\{"session_id":"abc123","transcript_path":"C:\\x\\t.jsonl","cwd":"C:\\p","permission_mode":"default",
        \\ "hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"rm -rf node_modules"},
        \\ "permission_suggestions":[{"type":"addRules","rules":[{"toolName":"Bash"}]}]}
    ).?;
    try testing.expectEqual(Event.PermissionRequest, perm.event);
    try testing.expectEqualStrings("Bash", perm.tool());
    const ups = fromHookJson(a, key,
        \\{"session_id":"abc","hook_event_name":"UserPromptSubmit","prompt":"tool=x\nevent=Stop"}
    ).?;
    try testing.expectEqual(Event.UserPromptSubmit, ups.event);
    try testing.expectEqual(@as(u8, 0), ups.tool_len);
    const n = fromHookJson(a, key,
        \\{"hook_event_name":"Notification","message":"Agent needs your permission","title":"Permission needed","notification_type":"permission_prompt"}
    ).?;
    try testing.expectEqualStrings("permission_prompt", n.ntype());
    try testing.expect(fromHookJson(a, key, "{\"hook_event_name\":\"Notification\",\"notification_type\":\"auth_success\"}") == null);
    try testing.expect(fromHookJson(a, key, "{\"hook_event_name\":\"PreTool\",\"tool_name\":\"Bash\"}") == null);
    try testing.expect(fromHookJson(a, key, "{\"hook_event_name\":\"stop\"}") == null);
    try testing.expect(fromHookJson(a, key, "not json") == null);
    try testing.expect(fromHookJson(a, key, "[]") == null);
    try testing.expect(fromHookJson(a, key, "{}") == null);
    // A hostile tool name never travels.
    const bad = fromHookJson(a, key, "{\"hook_event_name\":\"PermissionRequest\",\"tool_name\":\"x\\ntab=00\"}").?;
    try testing.expectEqual(@as(u8, 0), bad.tool_len);
    const stopf = fromHookJson(a, key, "{\"hook_event_name\":\"StopFailure\",\"error\":\"rate_limit\"}").?;
    try testing.expectEqual(Event.StopFailure, stopf.event);
    try testing.expect(stopf.rate_limit);
    var fb: [max_message]u8 = undefined;
    try testing.expect(parse(stopf.format(&fb)).?.rate_limit);
    try testing.expect(!fromHookJson(a, key, "{\"hook_event_name\":\"StopFailure\",\"error\":\"server_error\",\"error_details\":\"x\"}").?.rate_limit);
    try testing.expect(!fromHookJson(a, key, "{\"hook_event_name\":\"Stop\",\"error\":\"rate_limit\"}").?.rate_limit);
    try testing.expect(!parse("portal-hook-v1\ntab=01010101010101010101010101010101\nevent=Stop\nerror=rate_limit\n").?.rate_limit);
    try testing.expect(parse("portal-hook-v1\ntab=01010101010101010101010101010101\nevent=StopFailure\nerror=a b\n") == null);
}

test "format and parse round-trip; the parser is strict" {
    var m: Message = .{ .key = @splat(0x01), .event = .PermissionRequest };
    m.setTool("mcp__srv__do_it");
    var buf: [max_message]u8 = undefined;
    const text = m.format(&buf);
    try testing.expectEqualStrings("portal-hook-v1\ntab=01010101010101010101010101010101\nevent=PermissionRequest\ntool=mcp__srv__do_it\n", text);
    const back = parse(text).?;
    try testing.expectEqualSlices(u8, &m.key, &back.key);
    try testing.expectEqual(Event.PermissionRequest, back.event);
    try testing.expectEqualStrings("mcp__srv__do_it", back.tool());
    try testing.expect(parse("portal-hook-v2\ntab=01010101010101010101010101010101\nevent=Stop\n") == null);
    try testing.expect(parse("portal-hook-v1\ntab=0101\nevent=Stop\n") == null);
    try testing.expect(parse("portal-hook-v1\ntab=0101010101010101010101010101010G\nevent=Stop\n") == null);
    try testing.expect(parse("portal-hook-v1\ntab=01010101010101010101010101010101\nevent=PreTool\n") == null);
    try testing.expect(parse("portal-hook-v1\ntab=01010101010101010101010101010101\nevent=PreToolUse\nguard=maybe\n") == null);
    try testing.expect(parse("portal-hook-v1\ntab=01010101010101010101010101010101\n") == null);
    try testing.expect(parse("portal-hook-v1\nevent=Stop\n") == null);
    try testing.expect(parse("portal-hook-v1\ntab=01010101010101010101010101010101\nevent=Stop\ntool=a b\n") == null);
    try testing.expect(parse("portal-hook-v1\ntab=01010101010101010101010101010101\nevent=Stop\nnoequals\n") == null);
    try testing.expect(parse("portal-hook-v1\ntab=01010101010101010101010101010101\nevent=Stop\nfuture=1\n") != null);
    const long: [max_message + 1]u8 = @splat('a');
    try testing.expect(parse(&long) == null);
}

test "effect: the mapping" {
    const E = struct {
        fn of(ev: Event, tool: []const u8, nt: []const u8) ?Effect {
            var m: Message = .{ .key = @splat(1), .event = ev };
            m.setTool(tool);
            m.setNtype(nt);
            return effect(&m);
        }
    };
    try testing.expectEqual(vt.ProgramState.working, E.of(.UserPromptSubmit, "", "").?.state);
    const p = E.of(.PermissionRequest, "Bash", "").?;
    try testing.expectEqual(vt.ProgramState.waiting, p.state);
    try testing.expectEqual(Wait.permission, p.wait);
    try testing.expectEqual(transcript.Category.command, p.cat.?);
    try testing.expectEqual(transcript.Category.other, E.of(.PermissionRequest, "mcp__x__y", "").?.cat.?);
    try testing.expectEqual(transcript.Category.other, E.of(.PermissionRequest, "", "").?.cat.?);
    const np = E.of(.Notification, "", "permission_prompt").?;
    try testing.expectEqual(vt.ProgramState.waiting, np.state);
    try testing.expect(np.cat == null);
    try testing.expectEqual(vt.ProgramState.idle, E.of(.Notification, "", "idle_prompt").?.state);
    try testing.expect(E.of(.Notification, "", "auth_success") == null);
    try testing.expect(E.of(.Notification, "", "") == null);
    try testing.expectEqual(vt.ProgramState.done, E.of(.Stop, "", "").?.state);
    try testing.expectEqual(vt.ProgramState.failed, E.of(.StopFailure, "", "").?.state);
    try testing.expectEqual(vt.ProgramState.idle, E.of(.SessionEnd, "", "").?.state);
}

test "PreToolUse: the command stays in the hook process; the guard travels" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key: Key = @splat(0x03);
    const p = parseHook(a, key,
        \\{"session_id":"s","cwd":"C:\\p","hook_event_name":"PreToolUse","tool_name":"PowerShell","tool_input":{"command":"Start-Process x -Verb RunAs","description":"d"},"tool_use_id":"t"}
    ).?;
    try testing.expectEqual(Event.PreToolUse, p.msg.event);
    try testing.expectEqualStrings("Start-Process x -Verb RunAs", p.command.?);
    try testing.expect(effect(&p.msg) == null);
    var m = p.msg;
    m.guard = .marked;
    var buf: [max_message]u8 = undefined;
    const text = m.format(&buf);
    try testing.expect(std.mem.indexOf(u8, text, "RunAs") == null);
    try testing.expectEqualStrings("portal-hook-v1\ntab=03030303030303030303030303030303\nevent=PreToolUse\ntool=PowerShell\nguard=marked\n", text);
    try testing.expectEqual(Guard.marked, parse(text).?.guard);
    // Another tool's input of any shape: no command, still a message.
    const q = parseHook(a, key, "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":[1,{\"command\":2}]}").?;
    try testing.expect(q.command == null);
    // A PermissionRequest whose input has a non-string command still parses.
    try testing.expect(fromHookJson(a, key, "{\"hook_event_name\":\"PermissionRequest\",\"tool_name\":\"mcp__x__y\",\"tool_input\":{\"command\":{\"a\":1}}}") != null);
}

test "pipeName: per user and data directory, case-insensitive directory" {
    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    const x = pipeName(&a, "S-1-5-21-1-2-3-1001", "C:\\Users\\x\\AppData\\Local\\Portal");
    try testing.expect(std.mem.startsWith(u8, x, "\\\\.\\pipe\\portal-hook-"));
    try testing.expectEqual(@as(usize, "\\\\.\\pipe\\portal-hook-".len + 32), x.len);
    try testing.expectEqualStrings(x, pipeName(&b, "S-1-5-21-1-2-3-1001", "c:\\users\\X\\appdata\\local\\portal"));
    try testing.expect(!std.mem.eql(u8, x, pipeName(&b, "S-1-5-21-1-2-3-1002", "C:\\Users\\x\\AppData\\Local\\Portal")));
    try testing.expect(!std.mem.eql(u8, x, pipeName(&b, "S-1-5-21-1-2-3-1001", "C:\\t\\Portal")));
}

test "SubagentStart / SubagentStop: the agent id travels, nothing else; no state change" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key: Key = @splat(0x02);
    const start = fromHookJson(a, key,
        \\{"session_id":"s","transcript_path":"C:\\x\\t.jsonl","cwd":"C:\\p","hook_event_name":"SubagentStart","agent_id":"a01496045a85e979c","agent_type":"Explore"}
    ).?;
    try testing.expectEqual(Event.SubagentStart, start.event);
    try testing.expectEqualStrings("a01496045a85e979c", start.agent());
    try testing.expect(effect(&start) == null);
    const stop = fromHookJson(a, key,
        \\{"hook_event_name":"SubagentStop","agent_id":"a1","agent_type":"x","agent_transcript_path":"C:\\x\\agent-a1.jsonl","last_assistant_message":"secret","stop_hook_active":false}
    ).?;
    var buf: [max_message]u8 = undefined;
    const text = stop.format(&buf);
    try testing.expectEqualStrings("portal-hook-v1\ntab=02020202020202020202020202020202\nevent=SubagentStop\nagent=a1\n", text);
    const back = parse(text).?;
    try testing.expectEqualStrings("a1", back.agent());
    // No id, or one that is not a plain name: nothing to tell.
    try testing.expect(fromHookJson(a, key, "{\"hook_event_name\":\"SubagentStop\"}") == null);
    try testing.expect(fromHookJson(a, key, "{\"hook_event_name\":\"SubagentStart\",\"agent_id\":\"../x\"}") == null);
    try testing.expect(parse("portal-hook-v1\ntab=02020202020202020202020202020202\nevent=SubagentStop\nagent=a/b\n") == null);
}
