//! For you, recap and the admin-prompt guard (docs/protocol.md sections
//! 3g, 4b; docs/tabs-design.md, "For you"). The session program is the
//! fake agent as `claude.exe` in a folder named "foryou" (fake_agent.zig,
//! forYouRun): one turn whose reply suggests `zig build e2e`, says not to
//! run `zig build release`, shows a shell block holding a home path and
//! ends "Shall I commit this?"; then it echoes every line typed into it.
//! A paired device (input mode instruct) must get:
//!   * a `foryou` list for the tab: the suggestion and the question, not
//!     the negated command, not the command holding a path;
//!   * `i:yes <id>` on the suggestion: `sent`, and the agent receives
//!     exactly "Please run `zig build e2e`."; the same id again: `stale`;
//!   * `r:recap <tab>`: `ok`, and the agent receives recap.prompt; a
//!     second one within the minute (also as the line `recap`):
//!     `rate_limited`;
//!   * the admin-prompt guard, through real `portalctl hook` runs: in the
//!     desk-started tab an elevating command runs (no output) and the tab
//!     gets a `needs_desk` card; in a tab a device started (p:start) the
//!     agent's environment says so and the same command is denied with the
//!     hook's decision output; the desk's log says which;
//!   * no message carries a path or the user's name (privacy rule 1).

const std = @import("std");
const w = @import("win.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;
const privacy = @import("privacy.zig");
const selfExe = @import("convo_tests.zig").selfExe;
const shared = @import("shared");
const foryou = shared.foryou;
const recap = shared.recap;
const tabs_wire = shared.tabs;

const Hook = struct { code: ?u32, out: []const u8 };

/// One `portalctl hook` run with `payload` on stdin, PORTAL_TAB `tab` and
/// PORTAL_GUARD `guard` (null: not set). hookAs: with other arguments,
/// e.g. as the device guard of Portal's settings layer runs it (`hook
/// --device <mode>`).
fn hook(h: *proc.Harness, dir: []const u8, tab: []const u8, guard: ?[]const u8, payload: []const u8) Hook {
    return hookAs(h, dir, &.{"hook"}, tab, guard, payload);
}

fn hookAs(h: *proc.Harness, dir: []const u8, args: []const []const u8, tab: []const u8, guard: ?[]const u8, payload: []const u8) Hook {
    const env = [_]proc.EnvSet{ .{ .name = "PORTAL_TAB", .value = tab }, .{ .name = "PORTAL_GUARD", .value = guard } };
    const c = proc.LiveCli.startEnv(h, dir, args, &env) catch return .{ .code = null, .out = "" };
    defer c.deinit();
    c.answer(payload);
    c.closeInput();
    const code = c.wait(10_000);
    if (code == null) c.kill();
    return .{ .code = code, .out = h.gpa.dupe(u8, c.output()) catch "" };
}

/// The latest `foryou` list for tab `tab` that holds a card of `kind`.
fn listWith(v: *const client.Viewer, tab: tabs_wire.Id, kind: foryou.Kind, out: *foryou.List) bool {
    var i = v.texts.items.len;
    while (i > 0) {
        i -= 1;
        const t = v.texts.items[i];
        if (std.mem.indexOf(u8, t, "\"t\":\"foryou\"") == null) continue;
        if (!foryou.parse(t, out) or !std.mem.eql(u8, &out.tab, &tab)) continue;
        for (out.slice()) |*it| if (it.kind == kind) return true;
        return false;
    }
    return false;
}

const Want = struct { tab: tabs_wire.Id, kind: foryou.Kind };

fn waitKind(v: *client.Viewer, tab: tabs_wire.Id, kind: foryou.Kind, ms: u32) bool {
    return v.pumpUntil(ms, Want{ .tab = tab, .kind = kind }, struct {
        fn f(wt: Want, vv: *client.Viewer) bool {
            var l: foryou.List = undefined;
            return listWith(vv, wt.tab, wt.kind, &l);
        }
    }.f);
}

/// Sends `frame` and waits for the next answer with `needle`.
fn ask(v: *client.Viewer, frame: []const u8, needle: []const u8) ?[]const u8 {
    const n = v.countText(needle);
    v.send(frame);
    if (!v.waitText(needle, n + 1, 10_000)) return null;
    return v.lastText(needle);
}

fn readKey(h: *proc.Harness, folder: []const u8, name: []const u8, buf: []u8) []const u8 {
    const p = std.fs.path.join(h.gpa, &.{ folder, name }) catch return "";
    var tries: usize = 0;
    while (tries < 100) : (tries += 1) {
        const got = std.Io.Dir.cwd().readFile(h.io, p, buf) catch {
            w.Sleep(100);
            continue;
        };
        if (got.len > 0) return std.mem.trim(u8, got, " \r\n");
        w.Sleep(100);
    }
    return "";
}

const elevate =
    \\{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"PowerShell","tool_input":{"command":"Start-Process winget -Verb RunAs -ArgumentList 'install SECRET-PKG'"}}
;

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("foryou");
    const proj = try h.dataDir("foryou\\foryou-proj");
    const dev = try h.dataDir("foryou\\foryou-dev-quiet");
    const self = try selfExe(gpa);
    const bin = try h.dataDir("foryou\\bin");
    const prog = try std.fmt.allocPrint(gpa, "{s}\\claude.exe", .{bin});
    try std.Io.Dir.cwd().copyFile(self, std.Io.Dir.cwd(), prog, h.io, .{});
    {
        const res = try proc.runCli(h, dir, &.{ "startable", "add", dev, "--name", "devproj", "--mode", "ask" });
        defer gpa.free(res.out);
        _ = r.check("portalctl startable add", res.code == 0, "{s}", .{res.out});
    }

    const args = [_][]const u8{ "--input", "instruct", "--cwd", proj, "--", prog, "--fake-agent" };
    const inst = try proc.Instance.start(h, dir, port, &args);
    defer inst.kill();
    var leaks = try privacy.Leaks.standard(h, dir);
    defer leaks.deinit();
    for ([_][]const u8{ proj, dev, bin }) |p| try leaks.add(p);

    _ = try client.pair(inst, "fy-phone");
    const v = try client.Viewer.open(inst, "fy-phone");
    defer v.deinit();
    var dump: [8192]u8 = undefined;
    const tab = tabs_wire.idField(v.helloText(), "session") orelse {
        _ = r.check("hello names the tab shown", false, "{s}", .{v.helloText()});
        return;
    };
    // The fake agent waits for the go-ahead before its transcript.
    const go = try std.fmt.allocPrint(gpa, "{s}\\e2e-go", .{proj});
    try std.Io.Dir.cwd().writeFile(h.io, .{ .sub_path = go, .data = "" });
    _ = r.check("the turn ran", v.waitFor("FAKE-TURN-DONE", 15_000), "{s}", .{v.dump(&dump)});

    // ---- a turn yields cards
    _ = r.check("a foryou list with the run suggestion", waitKind(v, tab, .suggest_run, 15_000), "{?s}", .{v.lastText("\"t\":\"foryou\"")});
    var l: foryou.List = undefined;
    _ = listWith(v, tab, .suggest_run, &l);
    var run_id: ?foryou.Id = null;
    var question = false;
    var negated = false;
    var with_path = false;
    for (l.slice()) |*it| {
        if (it.kind == .suggest_run and std.mem.eql(u8, it.cmd(), "zig build e2e")) run_id = it.id;
        if (it.kind == .answer and std.mem.eql(u8, it.summary(), "Shall I commit this?")) question = true;
        if (std.mem.indexOf(u8, it.cmd(), "release") != null) negated = true;
        if (std.mem.indexOf(u8, it.cmd(), "notes") != null) with_path = true;
    }
    _ = r.check("cards: `zig build e2e` and the closing question", run_id != null and question, "{?s}", .{v.lastText("\"t\":\"foryou\"")});
    _ = r.check("no card for the negated command or the one holding a path", !negated and !with_path, "{?s}", .{v.lastText("\"t\":\"foryou\"")});

    // ---- yes on the suggestion: the fixed message reaches the agent
    if (run_id) |id| {
        var fb: [6 + tabs_wire.hex_len]u8 = undefined;
        const f = foryou.requestFrame(.yes, id, &fb);
        const a = foryou.parseResult(ask(v, f, "\"t\":\"item\"") orelse "");
        _ = r.check("i:yes on the suggestion: sent", a != null and a.?.result == .sent, "{?s}", .{v.lastText("\"t\":\"item\"")});
        _ = r.check("the agent got \"Please run `zig build e2e`.\"", v.waitFor("FAKE-LINE: Please run `zig build e2e`.", 10_000), "{s}", .{v.dump(&dump)});
        const b = foryou.parseResult(ask(v, f, "\"t\":\"item\"") orelse "");
        _ = r.check("the same id again: stale", b != null and b.?.result == .stale, "{?s}", .{v.lastText("\"t\":\"item\"")});
    }
    {
        const c = foryou.parseResult(ask(v, "i:no 0123456789abcdef0123456789abcdef", "\"t\":\"item\"") orelse "");
        _ = r.check("an id no card has: stale, not echoed", c != null and c.?.result == .stale and c.?.id == null, "{?s}", .{v.lastText("\"t\":\"item\"")});
    }

    // ---- recap
    {
        const f = recap.requestFrame(tab);
        const a = recap.parseResult(ask(v, &f, "\"t\":\"recap\"") orelse "");
        _ = r.check("r:recap: ok", a != null and a.?.result == .ok, "{?s}", .{v.lastText("\"t\":\"recap\"")});
        _ = r.check("the agent got the recap prompt", v.waitFor("FAKE-LINE: Please give me a short recap", 10_000), "{s}", .{v.dump(&dump)});
        const b = recap.parseResult(ask(v, "l:recap", "\"t\":\"recap\"") orelse "");
        _ = r.check("the line `recap` within the minute: rate_limited", b != null and b.?.result == .rate_limited, "{?s}", .{v.lastText("\"t\":\"recap\"")});
    }

    // ---- the admin-prompt guard, desk-started tab: runs, needs the desk
    var kb: [128]u8 = undefined;
    const key = try gpa.dupe(u8, readKey(h, proj, "e2e-tabkey", &kb));
    try leaks.add(key);
    var gb: [32]u8 = undefined;
    _ = r.check("a desk-started tab has no PORTAL_GUARD", std.mem.eql(u8, readKey(h, proj, "e2e-guard", &gb), "none"), "", .{});
    const marked = hook(h, dir, key, null, elevate);
    _ = r.check("desk-started: the elevating command runs (exit 0, no decision)", marked.code == 0 and marked.out.len == 0, "code {?d}: {s}", .{ marked.code, marked.out });
    _ = r.check("desk-started: a needs_desk card", waitKind(v, tab, .needs_desk, 10_000), "{?s}", .{v.lastText("\"t\":\"foryou\"")});
    _ = r.check("the desk's log: it runs, the tab needs the desk", inst.logHas("a command asks for elevation; it runs"), "", .{});
    const plain = hook(h, dir, key, null, "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"zig build\"}}");
    _ = r.check("an ordinary command: exit 0, no output", plain.code == 0 and plain.out.len == 0, "{s}", .{plain.out});

    // ---- a device-started tab: denied
    {
        const n = v.countText("\"t\":\"project\",");
        v.send("p:start devproj");
        _ = r.check("p:start devproj answered", v.waitText("\"t\":\"project\",", n + 1, 15_000), "", .{});
        var db: [128]u8 = undefined;
        const dkey = try gpa.dupe(u8, readKey(h, dev, "e2e-tabkey", &db));
        try leaks.add(dkey);
        var dg: [32]u8 = undefined;
        const guard = try gpa.dupe(u8, readKey(h, dev, "e2e-guard", &dg));
        _ = r.check("a device-started tab's agent has PORTAL_GUARD=device", std.mem.eql(u8, guard, "device"), "{s}", .{guard});
        // The user's own hook (if installed) denies it too, and leaves
        // telling Portal to the device guard.
        const plain_dev = hook(h, dir, dkey, guard, elevate);
        _ = r.check("device-started, the user's hook: denied too", plain_dev.code == 0 and
            std.mem.indexOf(u8, plain_dev.out, "\"permissionDecision\":\"deny\"") != null, "code {?d}: {s}", .{ plain_dev.code, plain_dev.out });
        const denied = hookAs(h, dir, &.{ "hook", "--device", "ask" }, dkey, guard, elevate);
        _ = r.check("device-started: denied with the hook's decision output", denied.code == 0 and
            std.mem.indexOf(u8, denied.out, "\"permissionDecision\":\"deny\"") != null and
            std.mem.indexOf(u8, denied.out, "\"hookEventName\":\"PreToolUse\"") != null and
            std.mem.indexOf(u8, denied.out, "only run at the desk") != null, "code {?d}: {s}", .{ denied.code, denied.out });
        _ = r.check("the reason never holds the command", std.mem.indexOf(u8, denied.out, "SECRET-PKG") == null, "", .{});
        _ = r.check("the desk's log: denied, started by a device", inst.logHas("was denied (the session was started by a device)"), "", .{});
    }

    v.pump(500);
    try leaks.add("SECRET-PKG");
    privacy.checkMessages(r, v, &leaks, "no message carries a path, a name, a hook key or a command's text");
    _ = r.ok("portal still running", inst.alive() and client.alive(inst));
}
