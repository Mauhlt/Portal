//! Subagent sub-tabs (docs/protocol.md section 3e): the fake session
//! program (fake_agent.zig, a folder named "...subagent...") starts a
//! subagent the way the real program lays it out on disk (the session's
//! `subagents\agent-<id>.jsonl` and `.meta.json`, under the harness's own
//! transcript folder, never the user's), and a viewer must get:
//!   * a `subtabs` message for the tab watched, the sub-tab named by the
//!     subagent's description, scrubbed (the folder reads as the tab's
//!     name, the user's name as [user]), running;
//!   * with `a:<sub id>`, that sub-tab's conversation as `convo` with the
//!     sub-tab's id: the subagent's own prompt and reply, tool use as a
//!     one-liner; read-only: input sent meanwhile reaches nothing;
//!   * SubagentStart / SubagentStop through a real `portalctl hook` (the
//!     tab's own key): a sub-tab at once, then marked done;
//!   * the subagent finishing (its meta file rewritten): done;
//!   * `a:` and any id that is not a sub-tab: the tab's own conversation;
//!   * no message carries a path, the user's name, the subagent's id in
//!     the program, the session id, tool arguments or results.

const std = @import("std");
const w = @import("win.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;
const privacy = @import("privacy.zig");
const shared = @import("shared");
const tabs_wire = shared.tabs;
const subtabs_wire = shared.subtabs;
const wire = shared.convo;

fn selfExe(gpa: std.mem.Allocator) ![]u8 {
    var buf: [1024]u16 = undefined;
    const n = w.GetModuleFileNameW(null, &buf, buf.len);
    if (n == 0 or n >= buf.len) return error.NoSelf;
    return std.unicode.utf16LeToUtf8Alloc(gpa, buf[0..n]);
}

/// The latest `subtabs` message for tab `tab`, parsed.
fn lastSubs(v: *const client.Viewer, tab: tabs_wire.Id) ?subtabs_wire.List {
    var i = v.texts.items.len;
    while (i > 0) {
        i -= 1;
        const t = v.texts.items[i];
        if (std.mem.indexOf(u8, t, "\"t\":\"subtabs\"") == null) continue;
        const l = subtabs_wire.parse(t) orelse continue;
        if (std.mem.eql(u8, &l.tab, &tab)) return l;
    }
    return null;
}

const SubWant = struct { tab: tabs_wire.Id, n: usize, done: ?usize = null };

/// Pumps until the tab's sub-tabs number `n` (and `done` of them done).
fn waitSubs(v: *client.Viewer, want: SubWant, ms: u32) bool {
    return v.pumpUntil(ms, want, struct {
        fn f(wt: SubWant, vv: *client.Viewer) bool {
            const l = lastSubs(vv, wt.tab) orelse return false;
            if (l.len != wt.n) return false;
            const d = wt.done orelse return true;
            var k: usize = 0;
            for (l.slice()) |e| k += @intFromBool(e.done);
            return k == d;
        }
    }.f);
}

/// The texts of conversation `id` (snapshot and updates applied), "|"-
/// separated as "<kind>:<text>".
fn convoOf(gpa: std.mem.Allocator, v: *const client.Viewer, id: tabs_wire.Id, out: *std.ArrayList(u8)) !void {
    var items: std.ArrayList(struct { n: u32, kind: wire.Kind, text: []u8 }) = .empty;
    defer {
        for (items.items) |it| gpa.free(it.text);
        items.deinit(gpa);
    }
    for (v.texts.items) |t| {
        if (std.mem.indexOf(u8, t, "\"t\":\"convo") == null) continue;
        const buf = try gpa.alloc(u8, t.len);
        defer gpa.free(buf);
        const scratch = try gpa.create(wire.Scratch);
        defer gpa.destroy(scratch);
        scratch.* = .{ .text = buf };
        const m = wire.parse(t, scratch) orelse continue;
        if (!std.mem.eql(u8, &m.id, &id)) continue;
        if (m.snapshot) {
            for (items.items) |it| gpa.free(it.text);
            items.clearRetainingCapacity();
        }
        outer: for (m.items) |it| {
            for (items.items) |*old| if (old.n == it.n) {
                gpa.free(old.text);
                old.text = try gpa.dupe(u8, it.text);
                old.kind = it.kind;
                continue :outer;
            };
            try items.append(gpa, .{ .n = it.n, .kind = it.kind, .text = try gpa.dupe(u8, it.text) });
        }
    }
    out.clearRetainingCapacity();
    for (items.items) |it| try out.print(gpa, "{s}:{s}|", .{ @tagName(it.kind), it.text });
}

const ConvoWant = struct { gpa: std.mem.Allocator, id: tabs_wire.Id, has: []const u8 };

fn waitConvo(v: *client.Viewer, want: ConvoWant, ms: u32) bool {
    return v.pumpUntil(ms, want, struct {
        fn f(wt: ConvoWant, vv: *client.Viewer) bool {
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(wt.gpa);
            convoOf(wt.gpa, vv, wt.id, &out) catch return false;
            return std.mem.indexOf(u8, out.items, wt.has) != null;
        }
    }.f);
}

/// The last `convo` snapshot's id.
fn lastSnapshotId(v: *const client.Viewer) ?tabs_wire.Id {
    const t = v.lastText("\"t\":\"convo\"") orelse return null;
    return tabs_wire.idField(t, "id");
}

/// One `portalctl hook` run with `payload` on stdin and PORTAL_TAB `tab`.
fn hook(h: *proc.Harness, dir: []const u8, tab: []const u8, payload: []const u8) ?u32 {
    const env = [_]proc.EnvSet{.{ .name = "PORTAL_TAB", .value = tab }};
    const c = proc.LiveCli.startEnv(h, dir, &.{"hook"}, &env) catch return null;
    defer c.deinit();
    c.answer(payload);
    c.closeInput();
    const code = c.wait(10_000);
    if (code == null) c.kill();
    return code;
}

fn inputIs(h: *proc.Harness, folder: []const u8, want: []const u8, settle_ms: u32) bool {
    h.io.sleep(.fromMilliseconds(settle_ms), .awake) catch {};
    var buf: [256]u8 = undefined;
    const path = std.fs.path.join(h.gpa, &.{ folder, "e2e-input" }) catch return false;
    defer h.gpa.free(path);
    const got = std.Io.Dir.cwd().readFile(h.io, path, &buf) catch |err| return err == error.FileNotFound and want.len == 0;
    if (!std.mem.eql(u8, got, want)) std.debug.print("    program input: {x} (want {x})\n", .{ got, want });
    return std.mem.eql(u8, got, want);
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("subtabs");
    const proj = try h.dataDir("subtabs\\subagent-proj");
    const self = try selfExe(gpa);
    const bin = try h.dataDir("subtabs\\bin");
    // Run as the program Portal gives a session id (see convo_tests).
    const prog = try std.fmt.allocPrint(gpa, "{s}\\claude.exe", .{bin});
    try std.Io.Dir.cwd().copyFile(self, std.Io.Dir.cwd(), prog, h.io, .{});
    const args = [_][]const u8{ "--input", "instruct", "--cwd", proj, "--", prog, "--fake-agent" };
    const inst = try proc.Instance.start(h, dir, port, &args);
    defer inst.kill();
    {
        const go = try std.fmt.allocPrint(gpa, "{s}\\e2e-go", .{proj});
        try std.Io.Dir.cwd().writeFile(h.io, .{ .sub_path = go, .data = "" });
    }

    var leaks = try privacy.Leaks.standard(h, dir);
    defer leaks.deinit();
    try leaks.add(proj);
    var tb: [1024]u8 = undefined;
    try leaks.add(h.transcriptRoot(&tb));
    const secrets = [_][]const u8{ "ARG-SECRET", "RESULT-SECRET", "e2esub1", "e2ehook2", "agent-e2e", "toolu_sub1", "subagents", ".jsonl", "meta.json", "general-purpose" };

    const creds = try client.pair(inst, "subtabs");
    const v = try client.Viewer.open(inst, creds.sessionCookie());
    defer v.deinit();
    var dump: [8192]u8 = undefined;
    const id = tabs_wire.idField(v.helloText(), "session") orelse {
        _ = r.check("hello names the tab shown", false, "{s}", .{v.helloText()});
        return;
    };
    _ = r.check("a subtabs message follows hello", v.waitText("\"t\":\"subtabs\"", 1, 8000), "{?s}", .{v.lastText("\"t\":\"subtabs\"")});
    _ = r.check("the fake program starts a subagent", v.waitFor("FAKE-SUB-STARTED", 15_000), "{s}", .{v.dump(&dump)});
    var sid_buf: [64]u8 = undefined;
    const sid = std.Io.Dir.cwd().readFile(h.io, try std.fmt.allocPrint(gpa, "{s}\\e2e-sid", .{proj}), &sid_buf) catch "";
    if (sid.len == 36) try leaks.add(try gpa.dupe(u8, sid));

    // The sub-tab: found through the folder's change notifications.
    const user_name = h.env.get("USERNAME") orelse "";
    const want_name = if (user_name.len >= 2) "Look in subagent-proj\\src for [user]" else "Look in subagent-proj\\src for nobody";
    const got = waitSubs(v, .{ .tab = id, .n = 1, .done = 0 }, 10_000);
    const l = lastSubs(v, id);
    _ = r.check("subtabs: one sub-tab, named by its description (scrubbed), running", got and l != null and std.mem.eql(u8, l.?.items[0].name(), want_name), "{?s}", .{v.lastText("\"t\":\"subtabs\"")});
    const sub_id = if (l) |x| (if (x.len > 0) x.items[0].id else null) else null;
    const sub = sub_id orelse return;
    _ = r.check("a sub-tab's id is Portal's own, not the tab's", !std.mem.eql(u8, &sub, &id), "", .{});

    // Its conversation, read-only.
    var vb: [34]u8 = undefined;
    v.send(subtabs_wire.viewFrame(sub, &vb));
    const sub_prompt = waitConvo(v, .{ .gpa = gpa, .id = sub, .has = "user:SUB-PROMPT search subagent-proj\\src|" }, 8000);
    const work = if (user_name.len >= 2) "assistant:SUB-WORKING in subagent-proj\\lib for [user]|" else "assistant:SUB-WORKING in subagent-proj\\lib for nobody|";
    const sub_work = waitConvo(v, .{ .gpa = gpa, .id = sub, .has = work }, 8000);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try convoOf(gpa, v, sub, &out);
    _ = r.check("a:<sub>: its conversation (scrubbed), with the sub-tab's id", sub_prompt and sub_work and std.mem.indexOf(u8, out.items, "tool:") != null, "{s}", .{out.items});
    _ = r.check("the main transcript's records are not in it", std.mem.indexOf(u8, out.items, "MAIN-PROMPT") == null, "{s}", .{out.items});
    // Read-only: a key sent while it is shown reaches nothing.
    v.send("k:1");
    v.send("l:hello");
    _ = r.check("read-only: input while a sub-tab is shown reaches nothing", inputIs(h, proj, "", 1200) and !v.waitFor("FAKE-SUB-DONE", 1), "{s}", .{v.dump(&dump)});

    // Hooks: SubagentStart gives a sub-tab at once, SubagentStop marks it.
    const key_path = try std.fs.path.join(gpa, &.{ proj, "e2e-tabkey" });
    var kb: [128]u8 = undefined;
    const key = std.mem.trim(u8, std.Io.Dir.cwd().readFile(h.io, key_path, &kb) catch "", " \r\n");
    if (key.len == 32) {
        try leaks.add(key);
        const c1 = hook(h, dir, key, "{\"session_id\":\"s\",\"hook_event_name\":\"SubagentStart\",\"agent_id\":\"e2ehook2\",\"agent_type\":\"general-purpose\"}");
        _ = r.check("SubagentStart (portalctl hook): a second sub-tab at once", c1 == 0 and waitSubs(v, .{ .tab = id, .n = 2, .done = 0 }, 8000), "{?s}", .{v.lastText("\"t\":\"subtabs\"")});
        const c2 = hook(h, dir, key, "{\"session_id\":\"s\",\"hook_event_name\":\"SubagentStop\",\"agent_id\":\"e2ehook2\",\"agent_type\":\"general-purpose\",\"agent_transcript_path\":\"C:\\\\x\\\\agent-e2ehook2.jsonl\",\"last_assistant_message\":\"RESULT-SECRET\"}");
        _ = r.check("SubagentStop: that sub-tab is done", c2 == 0 and waitSubs(v, .{ .tab = id, .n = 2, .done = 1 }, 8000), "{?s}", .{v.lastText("\"t\":\"subtabs\"")});
        // Another tab's key (none open) changes nothing.
        _ = hook(h, dir, "0123456789abcdef0123456789abcdef", "{\"hook_event_name\":\"SubagentStart\",\"agent_id\":\"zz\"}");
    } else _ = r.check("the program got its PORTAL_TAB", false, "{s}", .{key});

    // Back to the tab's own conversation; now the answer reaches it.
    const snaps0 = v.countText("\"t\":\"convo\"");
    v.send("a:");
    {
        const main_back = v.waitText("\"t\":\"convo\"", snaps0 + 1, 8000) and waitConvo(v, .{ .gpa = gpa, .id = id, .has = "user:MAIN-PROMPT find the tests|" }, 8000);
        try convoOf(gpa, v, id, &out);
        const last_id = lastSnapshotId(v);
        _ = r.check("a: shows the tab's own conversation again", main_back and
            if (last_id) |s| std.mem.eql(u8, &s, &id) else false, "{s} (last snapshot for the tab: {})", .{ out.items, if (last_id) |s| std.mem.eql(u8, &s, &id) else false });
    }
    v.send("k:1");
    _ = r.check("the tab takes input again (the program got 1)", v.waitFor("FAKE-SUB-DONE", 8000) and inputIs(h, proj, "1", 300), "{s}", .{v.dump(&dump)});
    _ = r.check("the subagent finished (meta rewritten): both sub-tabs done", waitSubs(v, .{ .tab = id, .n = 2, .done = 2 }, 10_000), "{?s}", .{v.lastText("\"t\":\"subtabs\"")});
    v.send(subtabs_wire.viewFrame(sub, &vb));
    _ = r.check("a finished sub-tab stays readable, its last reply included", waitConvo(v, .{ .gpa = gpa, .id = sub, .has = "assistant:SUB-RESULT found 3 tests|" }, 8000), "", .{});
    // An id that is not a sub-tab: the tab's own conversation.
    const snaps = v.countText("\"t\":\"convo\"");
    v.send("a:0123456789abcdef0123456789abcdef");
    _ = r.check("a:<not a sub-tab>: the tab's own conversation", v.waitText("\"t\":\"convo\"", snaps + 1, 8000) and
        if (lastSnapshotId(v)) |s| std.mem.eql(u8, &s, &id) else false, "", .{});

    // Nothing sent carries a path, the user's name or the program's ids.
    {
        var dirty: ?[]const u8 = null;
        var where: []const u8 = "";
        for (v.texts.items) |t| {
            if (leaks.find(t)) |n| {
                dirty = n;
                where = t;
            }
            for (secrets) |s| if (client.containsIgnoreCase(t, s)) {
                dirty = s;
                where = t;
            };
            if (user_name.len >= 4 and (std.mem.indexOf(u8, t, "\"t\":\"convo") != null or std.mem.indexOf(u8, t, "\"t\":\"subtabs\"") != null) and client.containsIgnoreCase(t, user_name)) {
                dirty = "the user name";
                where = t;
            }
        }
        _ = r.check("no message carries a path, the user name, the program's subagent or session ids, tool arguments or results", dirty == null, "{?s} in {s}", .{ dirty, where[0..@min(where.len, 600)] });
    }
    _ = r.ok("portal still running", inst.alive() and client.alive(inst));
}
