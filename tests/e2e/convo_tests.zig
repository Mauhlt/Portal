//! The Conversation view (docs/protocol.md section 3b): a fake session
//! program (fake_agent.zig) writes a synthetic transcript under the
//! harness's own transcript folder (CLAUDE_CONFIG_DIR, never the
//! user's), and a viewer must receive it as `convo` / `convo+` items:
//!   * prompts and replies as text, scrubbed of paths and the user's name
//!     (the project folder reads as the tab's name);
//!   * tool use as one-liners, never arguments, results or thinking;
//!   * a question with its options as answer keys, answered with `k:<key>`
//!     (no new input power), then closed;
//!   * a permission prompt reported only by OSC 7501 as a plain wait (no
//!     Yes = 1: any program can print it), answered with `k:1`;
//!   * the program reads exactly the answers sent: nothing before them,
//!     nothing from viewers reconnecting or restarting (its e2e-input log);
//!   * Portal starts the agent (here the fake, run as claude.exe) with
//!     its own `--session-id`, and follows exactly that transcript: another
//!     session's transcript in the same folder is not picked up;
//!   * a tab without a transcript says so (`on`:false);
//!   * snapshots on switching tabs, scoped to the tab watched;
//!   * nothing in any text message leaks a path or a name (privacy rule 1).

const std = @import("std");
const w = @import("win.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;
const console_tests = @import("console_tests.zig");
const privacy = @import("privacy.zig");
const shared = @import("shared");
const tabs_wire = shared.tabs;
const wire = shared.convo;

const Item = struct {
    n: u32,
    kind: wire.Kind,
    text: []u8,
    open: bool,
    /// "label=key;label=key"
    options: []u8,
};

/// The conversation of tab `id` as the viewer has it: every `convo` /
/// `convo+` message for it applied in order.
const Conv = struct {
    gpa: std.mem.Allocator,
    items: std.ArrayList(Item) = .empty,
    on: bool = false,
    snapshots: usize = 0,
    appends: usize = 0,
    bad: usize = 0,

    fn deinit(c: *Conv) void {
        c.clear();
        c.items.deinit(c.gpa);
    }

    fn clear(c: *Conv) void {
        for (c.items.items) |it| {
            c.gpa.free(it.text);
            c.gpa.free(it.options);
        }
        c.items.clearRetainingCapacity();
    }

    fn build(gpa: std.mem.Allocator, v: *const client.Viewer, id: tabs_wire.Id) !Conv {
        var c: Conv = .{ .gpa = gpa };
        errdefer c.deinit();
        for (v.texts.items) |t| {
            if (std.mem.indexOf(u8, t, "\"t\":\"convo") == null) continue;
            const buf = try gpa.alloc(u8, t.len);
            defer gpa.free(buf);
            const scratch = try gpa.create(wire.Scratch);
            defer gpa.destroy(scratch);
            scratch.* = .{ .text = buf };
            const m = wire.parse(t, scratch) orelse {
                c.bad += 1;
                continue;
            };
            if (!std.mem.eql(u8, &m.id, &id)) continue;
            if (m.snapshot) {
                c.clear();
                c.on = m.on;
                c.snapshots += 1;
            } else c.appends += 1;
            for (m.items) |it| try c.put(it);
        }
        return c;
    }

    fn put(c: *Conv, it: wire.Item) !void {
        var opts: std.ArrayList(u8) = .empty;
        defer opts.deinit(c.gpa);
        for (it.options, 0..) |o, i| {
            if (i > 0) try opts.append(c.gpa, ';');
            try opts.print(c.gpa, "{s}={s}", .{ o.label, o.key });
        }
        const new: Item = .{ .n = it.n, .kind = it.kind, .text = try c.gpa.dupe(u8, it.text), .open = it.open, .options = try opts.toOwnedSlice(c.gpa) };
        for (c.items.items) |*old| if (old.n == it.n) {
            c.gpa.free(old.text);
            c.gpa.free(old.options);
            old.* = new;
            return;
        };
        try c.items.append(c.gpa, new);
    }

    fn find(c: *const Conv, kind: wire.Kind, text: []const u8) ?Item {
        for (c.items.items) |it| if (it.kind == kind and std.mem.eql(u8, it.text, text)) return it;
        return null;
    }

    fn has(c: *const Conv, kind: wire.Kind, text: []const u8) bool {
        return c.find(kind, text) != null;
    }

    fn dump(c: *const Conv, buf: []u8) []const u8 {
        var wr: std.Io.Writer = .fixed(buf);
        wr.print("on={} snaps={d} items:", .{ c.on, c.snapshots }) catch {};
        for (c.items.items) |it| wr.print(" [{d} {s}{s} '{s}' {s}]", .{ it.n, @tagName(it.kind), if (it.open) " open" else "", it.text, it.options }) catch {};
        return wr.buffered();
    }
};

const Want = struct { gpa: std.mem.Allocator, id: tabs_wire.Id, kind: wire.Kind, text: []const u8, open: ?bool = null };

const act_wire = shared.activity;

/// The tab's entry of the latest `activity` message, if it parses.
fn lastActivity(v: *const client.Viewer, id: tabs_wire.Id, out: *act_wire.Activity) ?*const act_wire.Tab {
    const t = v.lastText("\"t\":\"activity\"") orelse return null;
    if (!act_wire.parse(t, out)) return null;
    return out.find(id);
}

const ActWant = struct { id: tabs_wire.Id, shells: u32, monitors: u32, tasks: usize };

/// Pumps until the tab's activity shows these counts.
fn waitActivity(v: *client.Viewer, want: ActWant, ms: u32) bool {
    return v.pumpUntil(ms, want, struct {
        fn f(wt: ActWant, vv: *client.Viewer) bool {
            var a: act_wire.Activity = undefined;
            const t = lastActivity(vv, wt.id, &a) orelse return false;
            return t.running(.shell) == wt.shells and t.running(.monitor) == wt.monitors and t.n_tasks == wt.tasks;
        }
    }.f);
}

/// Pumps until the tab's conversation has the item.
fn waitItem(v: *client.Viewer, want: Want, ms: u32) bool {
    return v.pumpUntil(ms, want, struct {
        fn f(wt: Want, vv: *client.Viewer) bool {
            var c = Conv.build(wt.gpa, vv, wt.id) catch return false;
            defer c.deinit();
            const it = c.find(wt.kind, wt.text) orelse return false;
            return if (wt.open) |o| it.open == o else true;
        }
    }.f);
}

/// Whether the fake program in `folder` has read exactly `want` (its
/// e2e-input log), after `settle_ms` for anything late to arrive.
fn inputIs(h: *proc.Harness, folder: []const u8, want: []const u8, settle_ms: u32) bool {
    h.io.sleep(.fromMilliseconds(settle_ms), .awake) catch {};
    var buf: [256]u8 = undefined;
    const path = std.fs.path.join(h.gpa, &.{ folder, "e2e-input" }) catch return false;
    defer h.gpa.free(path);
    const got = std.Io.Dir.cwd().readFile(h.io, path, &buf) catch |err| return err == error.FileNotFound and want.len == 0;
    if (!std.mem.eql(u8, got, want)) std.debug.print("    program input: {x} (want {x})\n", .{ got, want });
    return std.mem.eql(u8, got, want);
}

/// This program (portal-e2e), to run as the fake agent.
pub fn selfExe(gpa: std.mem.Allocator) ![]u8 {
    var buf: [1024]u16 = undefined;
    const n = w.GetModuleFileNameW(null, &buf, buf.len);
    if (n == 0 or n >= buf.len) return error.NoSelf;
    return std.unicode.utf16LeToUtf8Alloc(gpa, buf[0..n]);
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("convo");
    const proj = try h.dataDir("convo\\convo-acme");
    const quiet = try h.dataDir("convo\\quiet-proj");
    // The fake session program as `claude.exe`: Portal gives it a session id.
    const self = try selfExe(gpa);
    const bin = try h.dataDir("convo\\bin");
    const agent_exe = try std.fmt.allocPrint(gpa, "{s}\\claude.exe", .{bin});
    try std.Io.Dir.cwd().copyFile(self, std.Io.Dir.cwd(), agent_exe, h.io, .{});
    const args = [_][]const u8{ "--cwd", proj, "--", agent_exe, "--fake-agent" };
    const inst = try proc.Instance.start(h, dir, port, &args);
    defer inst.kill();

    // Another agent session in the same folder, outside Portal, writes its
    // transcript first; then the tab's program may start writing.
    var outside_path: []const u8 = "";
    var outside_line: []const u8 = "";
    {
        var tb0: [1024]u8 = undefined;
        const folder = try gpa.dupe(u8, proj);
        for (folder) |*c| if (!std.ascii.isAlphanumeric(c.*)) {
            c.* = '-';
        };
        const odir = try std.fmt.allocPrint(gpa, "{s}\\{s}", .{ h.transcriptRoot(&tb0), folder });
        try std.Io.Dir.cwd().createDirPath(h.io, odir);
        const opath = try std.fmt.allocPrint(gpa, "{s}\\0dd51de0-0000-4000-8000-000000000001.jsonl", .{odir});
        var esc: std.ArrayList(u8) = .empty;
        for (proj) |c| {
            if (c == '\\') try esc.append(gpa, '\\');
            try esc.append(gpa, c);
        }
        const line = try std.fmt.allocPrint(gpa, "{{\"type\":\"user\",\"cwd\":\"{s}\",\"sessionId\":\"0dd51de0-0000-4000-8000-000000000001\",\"message\":{{\"role\":\"user\",\"content\":\"OUTSIDE-SESSION\"}}}}\n", .{esc.items});
        try std.Io.Dir.cwd().writeFile(h.io, .{ .sub_path = opath, .data = line });
        outside_path = opath;
        outside_line = try std.fmt.allocPrint(gpa, "{{\"type\":\"user\",\"cwd\":\"{s}\",\"sessionId\":\"0dd51de0-0000-4000-8000-000000000001\",\"message\":{{\"role\":\"user\",\"content\":\"OUTSIDE-LATER\"}}}}\n", .{esc.items});
        const go = try std.fmt.allocPrint(gpa, "{s}\\e2e-go", .{proj});
        try std.Io.Dir.cwd().writeFile(h.io, .{ .sub_path = go, .data = "" });
    }

    var leaks = try privacy.Leaks.standard(h, dir);
    defer leaks.deinit();
    try leaks.add(proj);
    var tb: [1024]u8 = undefined;
    try leaks.add(h.transcriptRoot(&tb));
    try leaks.add("agent-config");
    // Never sent at all, scrubbed or not.
    const secrets = [_][]const u8{ "THINKING-SECRET", "ARG-SECRET", "RESULT-SECRET", "injected", "not JSON", "system-reminder", ".jsonl", "e2e00000", "OUTSIDE-SESSION", "OUTSIDE-LATER", "0dd51de0", "SECRET-CMD", "SUMMARY-SECRET", "bshell00", "bmon0000", "task-notification", "output-file" };

    const creds = try client.pair(inst, "convo");
    const v = try client.Viewer.open(inst, creds.sessionCookie());
    defer v.deinit();
    var dump: [8192]u8 = undefined;
    var cdump: [8192]u8 = undefined;
    const id = tabs_wire.idField(v.helloText(), "session") orelse {
        _ = r.check("hello names the tab shown", false, "{s}", .{v.helloText()});
        return;
    };
    _ = r.check("a convo snapshot follows hello for the tab shown", v.waitText("\"t\":\"convo\"", 1, 8000), "{d} texts", .{v.texts.items.len});
    _ = r.check("Portal starts the agent with its own --session-id", v.waitFor("FAKE-SESSION-ID", 8000) and !v.waitFor("FAKE-BAD-SESSION-ID", 1), "{s}", .{v.dump(&dump)});
    _ = r.check("the fake program asks its question", v.waitFor("FAKE-ASKED", 15_000), "{s}", .{v.dump(&dump)});
    // The id Portal chose is desktop-only: it must never reach a device.
    var sid_buf: [64]u8 = undefined;
    const sid_path = try std.fmt.allocPrint(gpa, "{s}\\e2e-sid", .{proj});
    const sid = std.Io.Dir.cwd().readFile(h.io, sid_path, &sid_buf) catch "";
    _ = r.check("the session id is a v4 UUID", sid.len == 36 and sid[14] == '4', "{s}", .{sid});
    if (sid.len == 36) try leaks.add(try gpa.dupe(u8, sid));

    // The turn, scrubbed: the project folder reads as the tab's name.
    const user_name = h.env.get("USERNAME") orelse "";
    const prompt = if (user_name.len >= 2) "Please fix the build in convo-acme\\src and tell [user]" else "Please fix the build in convo-acme\\src and tell nobody";
    const got_q = waitItem(v, .{ .gpa = gpa, .id = id, .kind = .question, .text = "Which fix should I apply in convo-acme?", .open = true }, 10_000);
    {
        var c = try Conv.build(gpa, v, id);
        defer c.deinit();
        _ = r.check("convo is on (a transcript is followed) and every message parses", c.on and c.bad == 0, "{s}", .{c.dump(&cdump)});
        _ = r.check("the owner's prompt, scrubbed of paths and the user name", c.has(.user, prompt), "{s}", .{c.dump(&cdump)});
        // C:\Users\<user>\notes.txt: the home folder reads [home] when it is
        // %USERPROFILE% (as on most machines); otherwise the path is [path].
        _ = r.check("the reply as text, other paths removed", c.has(.assistant, "I will look at convo-acme\\build.zig and [home]\\notes.txt") or
            c.has(.assistant, "I will look at convo-acme\\build.zig and [path]"), "{s}", .{c.dump(&cdump)});
        _ = r.check("edits as one line: Edited 2 files", c.has(.tool, "Edited 2 files"), "{s}", .{c.dump(&cdump)});
        _ = r.check("a command as one line: Ran a command", c.has(.tool, "Ran a command"), "{s}", .{c.dump(&cdump)});
        const q = c.find(.question, "Which fix should I apply in convo-acme?");
        _ = r.check("the question, open, its options as answer keys", got_q and q != null and q.?.open and
            std.mem.eql(u8, q.?.options, "Alpha=1;Beta in [path]=2"), "{s}", .{c.dump(&cdump)});
        var n_user: usize = 0;
        for (c.items.items) |it| n_user += @intFromBool(it.kind == .user);
        _ = r.check("injected context is not a prompt; only the typed one is", n_user == 1, "{s}", .{c.dump(&cdump)});
    }

    // Background tasks and usage (section 3c), from the same transcript: a
    // shell and a monitor run, another shell finished; each reply's usage
    // counted once; the description scrubbed, never the command.
    {
        const got_act = waitActivity(v, .{ .id = id, .shells = 1, .monitors = 1, .tasks = 3 }, 8000);
        var a: act_wire.Activity = undefined;
        const t = lastActivity(v, id, &a);
        const at = v.lastText("\"t\":\"activity\"") orelse "";
        _ = r.check("activity: 1 shell and 1 monitor running, 1 shell done", got_act and t != null and t.?.tasks[2].state == .done, "{s}", .{at});
        const desc = if (user_name.len >= 2) "Run the tests in convo-acme\\src for [user]" else "Run the tests in convo-acme\\src for nobody";
        _ = r.check("a task's text is its description, scrubbed; a monitor's too", t != null and std.mem.eql(u8, t.?.tasks[0].text(), desc) and t.?.tasks[0].kind == .shell and
            std.mem.eql(u8, t.?.tasks[1].text(), "Watch the build log") and t.?.tasks[1].kind == .monitor and std.mem.eql(u8, t.?.tasks[2].text(), "Lint the docs"), "{s}", .{at});
        _ = r.check("usage: each reply once (in 11, out 22, cache read 300, cache write 40), the model, today the same", t != null and t.?.usage.input == 11 and t.?.usage.output == 22 and
            t.?.usage.cache_read == 300 and t.?.usage.cache_write == 40 and std.mem.eql(u8, t.?.model(), "model-e2e-1") and t.?.today.total() == t.?.usage.total(), "{s}", .{at});
        _ = r.check("activity: the system monitor is off by default", !a.sysmon, "{s}", .{at});
    }
    // Slash commands stay blocked from devices: /usage is the desk's (its
    // Usage panel), never a device's.
    {
        const before = v.countText("\"t\":\"rejected\"");
        v.send("l:/usage");
        _ = r.check("a device's l:/usage is rejected (SlashCommand)", v.waitText("\"t\":\"rejected\"", before + 1, 8000) and
            std.mem.indexOf(u8, v.lastText("\"t\":\"rejected\"") orelse "", "SlashCommand") != null, "{?s}", .{v.lastText("\"t\":\"rejected\"")});
    }
    // The system monitor is off: y:on is ignored (and logged at the desk).
    v.send("y:on");

    // Nothing reaches the program but the answers sent (it logs every
    // byte it reads; a stray key would also show as FAKE-STRAY).
    _ = r.check("no input reaches the program before an answer is sent", inputIs(h, proj, "", 1000), "{s}", .{v.dump(&dump)});
    // Up/Down reach the program while it waits (an arrow-select menu such
    // as the folder-trust prompt), in instruct mode.
    v.send("k:up");
    v.send("k:down");
    _ = r.check("instruct: k:up / k:down reach the program while it waits for an answer", v.waitFor("FAKE-UP-ASKED", 8000) and v.waitFor("FAKE-DOWN-ASKED", 8000), "{s}", .{v.dump(&dump)});

    // Answering uses the ordinary answer keys.
    v.send("k:2");
    _ = r.check("k:2 answers the question (the program got 2)", v.waitFor("FAKE-GOT-2", 8000), "{s}", .{v.dump(&dump)});
    const closed = waitItem(v, .{ .gpa = gpa, .id = id, .kind = .question, .text = "Which fix should I apply in convo-acme?", .open = false }, 8000);
    const reply = waitItem(v, .{ .gpa = gpa, .id = id, .kind = .assistant, .text = "You chose Beta." }, 8000);
    {
        var c = try Conv.build(gpa, v, id);
        defer c.deinit();
        _ = r.check("the answered question closes; the reply follows (as convo+ appends)", closed and reply and c.appends > 0, "{s}", .{c.dump(&cdump)});
    }

    // A permission prompt known only from the program's OSC 7501 state:
    // any program in the tab can print that, so it is a plain wait (no
    // Yes = 1 card); only an agent hook makes a permission card
    // (hooks_tests.zig).
    _ = r.check("the fake program asks for permission", v.waitFor("FAKE-PERMISSION", 8000), "{s}", .{v.dump(&dump)});
    const perm = "Claude is waiting for your answer. The terminal shows the question.";
    const got_perm = waitItem(v, .{ .gpa = gpa, .id = id, .kind = .question, .text = perm, .open = true }, 8000);
    {
        var c = try Conv.build(gpa, v, id);
        defer c.deinit();
        const p = c.find(.question, perm);
        _ = r.check("an OSC 7501 permission wait is a question without answer keys", got_perm and p != null and p.?.options.len == 0 and !c.has(.question, "Claude wants to run a command. Allow it?"), "{s}", .{c.dump(&cdump)});
    }
    // Viewers coming and going (a device reconnecting, a client
    // restarting: a fresh hello, the tab chosen again) send nothing.
    {
        const sub = tabs_wire.subscribeFrame(id);
        for (0..3) |_| {
            const v2 = try client.Viewer.open(inst, creds.sessionCookie());
            v2.send(&sub);
            v2.pump(300);
            v2.deinit();
        }
        v.send(&sub);
        _ = r.check("reconnects and restarts send no input (only Up, Down and the question's answer so far)", inputIs(h, proj, "\x1b[A\x1b[B2", 1500) and !v.waitFor("FAKE-ALLOWED", 1), "{s}", .{v.dump(&dump)});
    }
    v.send("k:1");
    _ = r.check("k:1 allows it (the program got 1)", v.waitFor("FAKE-ALLOWED", 8000), "{s}", .{v.dump(&dump)});
    _ = r.check("the waiting note goes once the program works again", v.pumpUntil(8000, Want{ .gpa = gpa, .id = id, .kind = .question, .text = perm }, struct {
        fn f(wt: Want, vv: *client.Viewer) bool {
            var c = Conv.build(wt.gpa, vv, wt.id) catch return false;
            defer c.deinit();
            return !c.has(wt.kind, wt.text);
        }
    }.f), "", .{});
    _ = r.check("the closing reply arrives", waitItem(v, .{ .gpa = gpa, .id = id, .kind = .assistant, .text = "All done." }, 8000), "", .{});
    // At the idle prompt (OSC 7501 idle, no open question) Up would recall
    // history: refused, and the viewer told why.
    {
        _ = v.waitFor("FAKE-DONE", 8000);
        const before = v.countText("\"t\":\"rejected\"");
        v.send("k:up");
        const told = v.waitText("\"t\":\"rejected\"", before + 1, 8000) and
            std.mem.indexOf(u8, v.lastText("\"t\":\"rejected\"") orelse "", "NotWaiting") != null;
        v.pump(800);
        _ = r.check("instruct: k:up refused once the program no longer waits (rejected NotWaiting, nothing typed)", told and !v.waitFor("FAKE-UP-IDLE", 1), "{?s} {s}", .{ v.lastText("\"t\":\"rejected\""), v.dump(&dump) });
    }
    {
        const done = waitActivity(v, .{ .id = id, .shells = 0, .monitors = 0, .tasks = 3 }, 8000);
        var a: act_wire.Activity = undefined;
        const t = lastActivity(v, id, &a);
        _ = r.check("the shell's notification ends it (done); TaskStop kills the monitor; nothing runs", done and t != null and t.?.tasks[0].state == .done and t.?.tasks[1].state == .killed, "{?s}", .{v.lastText("\"t\":\"activity\"")});
        _ = r.check("no sys message while the monitor is off", v.countText("\"t\":\"sys\"") == 0, "{d}", .{v.countText("\"t\":\"sys\"")});
        var lb: [64 * 1024]u8 = undefined;
        const log_path = try std.fmt.allocPrint(gpa, "{s}\\Portal\\portal.log", .{dir});
        const log = std.Io.Dir.cwd().readFile(h.io, log_path, &lb) catch "";
        _ = r.check("the desk logged the refused y:on", std.mem.indexOf(u8, log, "asked for the system monitor") != null, "{d} bytes of log", .{log.len});
    }

    // A tab without a transcript says so; switching sends that tab's
    // snapshot, and switching back the whole conversation again.
    const o = try inst.cli(&.{ "open", quiet });
    _ = r.check("portalctl open a second tab", o.code == 0, "{d} {s}", .{ o.code, o.out });
    const Listed = struct {
        fn quietId(vv: *const client.Viewer) ?tabs_wire.Id {
            const t = vv.lastText("\"t\":\"tabs\"") orelse return null;
            const l = tabs_wire.parseList(t) orelse return null;
            for (l.slice()) |e| if (std.mem.eql(u8, e.name(), "quiet-proj")) return e.id;
            return null;
        }
        fn f(_: void, vv: *client.Viewer) bool {
            return quietId(vv) != null;
        }
    };
    _ = v.pumpUntil(8000, {}, Listed.f);
    const quiet_id = Listed.quietId(v);
    if (quiet_id) |qid| {
        const before = v.countText("\"t\":\"convo\"");
        const f = tabs_wire.subscribeFrame(qid);
        v.send(&f);
        _ = v.waitFor("FAKE-QUIET", 8000);
        _ = v.waitText("\"t\":\"convo\"", before + 1, 8000);
        var c = try Conv.build(gpa, v, qid);
        defer c.deinit();
        _ = r.check("a tab without a transcript: on=false and a status saying so", !c.on and c.snapshots >= 1 and c.items.items.len == 1 and c.items.items[0].kind == .status, "{s}", .{c.dump(&cdump)});
        // No OSC 7501 and no question there: the state is unknown, so
        // Up/Down stay refused.
        {
            const rb = v.countText("\"t\":\"rejected\"");
            v.send("k:down");
            const told = v.waitText("\"t\":\"rejected\"", rb + 1, 8000);
            v.pump(800);
            _ = r.check("instruct: k:down refused while the state is unknown", told and !v.waitFor("FAKE-DOWN-QUIET", 1), "{s}", .{v.dump(&dump)});
        }
        const back = tabs_wire.subscribeFrame(id);
        const before2 = v.countText("\"t\":\"convo\"");
        v.send(&back);
        _ = v.waitText("\"t\":\"convo\"", before2 + 1, 8000);
        var c2 = try Conv.build(gpa, v, id);
        defer c2.deinit();
        _ = r.check("switching back sends the whole conversation again", c2.on and c2.has(.assistant, "All done.") and c2.has(.user, prompt), "{s}", .{c2.dump(&cdump)});
    } else _ = r.check("the second tab is listed", false, "{?s}", .{v.lastText("\"t\":\"tabs\"")});

    // The outside session writes again while the tab is quiet: not the
    // tab's (its program printed nothing within follow.adopt_window_ms,
    // 2 s, before or after).
    {
        const Never = struct {
            fn f(_: void, _: *client.Viewer) bool {
                return false;
            }
        };
        _ = v.pumpUntil(2500, {}, Never.f);
        var of = try std.Io.Dir.cwd().createFile(h.io, outside_path, .{ .truncate = false });
        const end = of.length(h.io) catch 0;
        of.writePositionalAll(h.io, outside_line, end) catch {};
        of.close(h.io);
        const Moved = struct {
            fn f(wt: Want, vv: *client.Viewer) bool {
                var c = Conv.build(wt.gpa, vv, wt.id) catch return false;
                defer c.deinit();
                return !c.has(.assistant, "All done.");
            }
        };
        // Past its window too, so the next output cannot claim it.
        const moved = v.pumpUntil(2500, Want{ .gpa = gpa, .id = id, .kind = .assistant, .text = "" }, Moved.f);
        var c = try Conv.build(gpa, v, id);
        defer c.deinit();
        _ = r.check("an outside session writing while the tab is quiet is not followed", !moved and c.has(.assistant, "All done."), "{s}", .{c.dump(&cdump)});
    }

    // /clear in the tab: it prints, then writes a new session file; the
    // view follows it and starts over. The `1` is typed at the desk's own
    // console this time: what reached the program in a visual run as an
    // "unexplained" answer (that console had the keyboard focus, and the
    // owner's Numpad-1 presses meant for another window went to it; Portal
    // types its console's keys into the tab, by design).
    _ = r.check("a key typed at the desk's console reaches the tab's program (the stray 1, reproduced)", console_tests.inject(gpa, w.GetProcessId(inst.process.?), 0, 0, "1"), "", .{});
    _ = r.check("the fake program clears (prints, then a new transcript)", v.waitFor("FAKE-CLEARED", 8000), "{s}", .{v.dump(&dump)});
    {
        const fresh = waitItem(v, .{ .gpa = gpa, .id = id, .kind = .assistant, .text = "Fresh start." }, 8000);
        var c = try Conv.build(gpa, v, id);
        defer c.deinit();
        _ = r.check("after /clear the tab follows its new transcript, from the start", fresh and c.has(.user, "AFTER-CLEAR prompt") and !c.has(.assistant, "All done."), "{s}", .{c.dump(&cdump)});
    }
    {
        // The new transcript: finished tasks dropped, usage starts over.
        const reset = waitActivity(v, .{ .id = id, .shells = 0, .monitors = 0, .tasks = 0 }, 8000);
        var a: act_wire.Activity = undefined;
        const t = lastActivity(v, id, &a);
        _ = r.check("after /clear: finished tasks are gone and usage starts over", reset and t != null and t.?.usage.input < 11, "{?s}", .{v.lastText("\"t\":\"activity\"")});
    }

    // Nothing Portal sent as text carries a path, a name or a secret.
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
            if (user_name.len >= 4 and (std.mem.indexOf(u8, t, "\"t\":\"convo") != null or std.mem.indexOf(u8, t, "\"t\":\"activity\"") != null) and client.containsIgnoreCase(t, user_name)) {
                dirty = "the user name";
                where = t;
            }
        }
        _ = r.check("no convo or activity message carries a path, the user name, a command, tool arguments, results, task ids or thinking", dirty == null, "{?s} in {s}", .{ dirty, where[0..@min(where.len, 600)] });
    }
    _ = r.check("the program got exactly the answers sent (Up, Down while asked; 2, 1, 1: the last from the console; no refused arrow), nothing stray", inputIs(h, proj, "\x1b[A\x1b[B211", 500) and !v.waitFor("FAKE-STRAY", 1), "{s}", .{v.dump(&dump)});
    _ = r.check("the quiet tab's program got no input at all", inputIs(h, quiet, "", 1), "", .{});
    _ = r.ok("portal still running", inst.alive() and client.alive(inst));
}
