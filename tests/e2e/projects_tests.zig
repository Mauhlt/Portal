//! Startable projects (docs/protocol.md section 3f; docs/tabs-design.md,
//! "Starting projects from a device"). The desk marks three folders
//! startable with `portalctl startable add` (alpha, the desk's own first
//! tab; beta in plan mode; gamma in ask mode); the session program is the
//! fake agent as `claude.exe` (fake_agent.zig), which prints the
//! permission mode it was launched with and idles ("quiet" folders). A
//! paired device must get:
//!   * a `projects` message after hello: names, colours, modes, running
//!     state; no folder ever (privacy rule 1);
//!   * `p:start beta`: started, its view switched to the new tab, the
//!     agent launched with `--permission-mode plan`, the desk's log saying
//!     who started it; the list then shows it running and stoppable;
//!   * a second start: switched; an unknown name: unknown, without a
//!     name; a fourth start within the minute: rate_limited;
//!   * `p:stop` of the desk-started tab: not_device_started; of the
//!     device-started one: stopped, and the list shows it ended;
//!   * another device's own limit, and `--permission-mode default` for an
//!     ask project; `f:` with anything after it is not Forget;
//!   * a project added at the desk while it runs: a new `projects` list;
//!   * a desk in input mode `none` (a second instance): refused.

const std = @import("std");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;
const privacy = @import("privacy.zig");
const selfExe = @import("convo_tests.zig").selfExe;
const projects = @import("shared").projects;

const answer_needle = "\"t\":\"project\",";
const list_needle = "\"t\":\"projects\"";

/// Sends `frame` and waits for the next `project` answer.
fn ask(v: *client.Viewer, frame: []const u8) ?projects.Answer {
    const n = v.countText(answer_needle);
    v.send(frame);
    if (!v.waitText(answer_needle, n + 1, 15_000)) return null;
    return projects.parseResult(v.lastText(answer_needle).?);
}

fn answered(a: ?projects.Answer, result: projects.Result, name: ?[]const u8) bool {
    const x = a orelse return false;
    if (x.result != result) return false;
    const got = x.name() orelse return name == null;
    return if (name) |n| std.mem.eql(u8, got, n) else false;
}

/// The latest `projects` list.
fn lastList(v: *const client.Viewer) ?projects.List {
    return projects.parse(v.lastText(list_needle) orelse return null);
}

const Want = struct { name: []const u8, running: bool, stoppable: bool = false, n: ?usize = null };

/// Pumps until the latest list has `want.name` in that state (and, with
/// `n`, that many entries).
fn waitList(v: *client.Viewer, want: Want, ms: u32) bool {
    return v.pumpUntil(ms, want, struct {
        fn f(wt: Want, vv: *client.Viewer) bool {
            const l = lastList(vv) orelse return false;
            if (wt.n) |n| if (l.len != n) return false;
            const i = l.find(wt.name) orelse return false;
            return l.items[i].running == wt.running and l.items[i].stoppable == wt.stoppable;
        }
    }.f);
}

fn startable(h: *proc.Harness, dir: []const u8, folder: []const u8, name: []const u8, mode: []const u8) !bool {
    const res = try proc.runCli(h, dir, &.{ "startable", "add", folder, "--name", name, "--mode", mode });
    defer h.gpa.free(res.out);
    if (res.code != 0) std.debug.print("    portalctl startable add said: {s}\n", .{res.out});
    return res.code == 0;
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("projects");
    const alpha = try h.dataDir("projects\\alpha-quiet");
    const beta = try h.dataDir("projects\\beta-quiet");
    const gamma = try h.dataDir("projects\\gamma-quiet");
    const delta = try h.dataDir("projects\\delta-quiet");
    const self = try selfExe(gpa);
    const bin = try h.dataDir("projects\\bin");
    const prog = try std.fmt.allocPrint(gpa, "{s}\\claude.exe", .{bin});
    try std.Io.Dir.cwd().copyFile(self, std.Io.Dir.cwd(), prog, h.io, .{});

    _ = r.check("portalctl startable add (ask, plan)", try startable(h, dir, alpha, "alpha", "ask") and
        try startable(h, dir, beta, "beta", "plan") and try startable(h, dir, gamma, "gamma", "ask"), "", .{});
    {
        const bad = try proc.runCli(h, dir, &.{ "startable", "add", delta, "--name", "d", "--mode", "bypassPermissions" });
        defer gpa.free(bad.out);
        _ = r.check("startable add refuses a permissive mode", bad.code != 0, "{s}", .{bad.out});
    }

    const args = [_][]const u8{ "--input", "instruct", "--cwd", alpha, "--", prog, "--fake-agent" };
    const inst = try proc.Instance.start(h, dir, port, &args);
    defer inst.kill();

    var leaks = try privacy.Leaks.standard(h, dir);
    defer leaks.deinit();
    for ([_][]const u8{ alpha, beta, gamma, delta, bin }) |p| try leaks.add(p);

    _ = try client.pair(inst, "proj-phone");
    const v = try client.Viewer.open(inst, "proj-phone");
    defer v.deinit();
    var dump: [8192]u8 = undefined;
    _ = r.check("a desk-started tab runs without --permission-mode", v.waitFor("FAKE-NO-PERMISSION-MODE", 10_000), "{s}", .{v.dump(&dump)});

    // The list after hello: names, modes, running state.
    _ = r.check("projects follows hello: alpha running (desk-started), beta and gamma not", waitList(v, .{ .name = "alpha", .running = true, .n = 3 }, 10_000) and
        waitList(v, .{ .name = "beta", .running = false }, 1) and waitList(v, .{ .name = "gamma", .running = false }, 1), "{?s}", .{v.lastText(list_needle)});
    if (lastList(v)) |l| {
        const b = l.items[l.find("beta") orelse 0];
        _ = r.check("the list carries the desk's mode per project", b.mode == .plan and l.items[0].mode == .ask, "{?s}", .{v.lastText(list_needle)});
    }

    // Start beta: started, the view switches to it, plan mode.
    const sessions = v.countText("\"t\":\"session\"");
    const a1 = ask(v, "p:start beta");
    _ = r.check("p:start beta: started", answered(a1, .started, "beta"), "{?s}", .{v.lastText(answer_needle)});
    _ = r.check("the device's view switches to the new tab", v.waitText("\"t\":\"session\"", sessions + 1, 10_000), "", .{});
    _ = r.check("the agent was launched with --permission-mode plan", v.waitFor("FAKE-PERMISSION-MODE=plan", 15_000), "{s}", .{v.dump(&dump)});
    _ = r.check("the desk's log says which device started it", inst.logHas("started by device 'proj-phone' (permission mode plan)"), "", .{});
    _ = r.check("the list: beta running, stoppable (device-started)", waitList(v, .{ .name = "beta", .running = true, .stoppable = true }, 10_000), "{?s}", .{v.lastText(list_needle)});
    _ = r.check("p:start beta again: switched", answered(ask(v, "p:start beta"), .switched, "beta"), "{?s}", .{v.lastText(answer_needle)});
    {
        const a = ask(v, "p:start nope");
        _ = r.check("p:start <unknown>: unknown, no name echoed", answered(a, .unknown, null) and
            std.mem.indexOf(u8, v.lastText(answer_needle).?, "nope") == null, "{?s}", .{v.lastText(answer_needle)});
    }
    _ = r.check("a fourth start within a minute: rate_limited", answered(ask(v, "p:start alpha"), .rate_limited, null), "{?s}", .{v.lastText(answer_needle)});

    // Stop: only what a device started.
    _ = r.check("p:stop alpha (started at the desk): not_device_started", answered(ask(v, "p:stop alpha"), .not_device_started, "alpha"), "{?s}", .{v.lastText(answer_needle)});
    _ = r.check("p:stop beta (device-started): stopped", answered(ask(v, "p:stop beta"), .stopped, "beta"), "{?s}", .{v.lastText(answer_needle)});
    _ = r.check("the desk's log says which device stopped it", inst.logHas("stopped by device 'proj-phone'"), "", .{});
    _ = r.check("the list: beta ended (not running)", waitList(v, .{ .name = "beta", .running = false }, 20_000), "{?s}", .{v.lastText(list_needle)});
    _ = r.check("p:stop beta again: not_running", answered(ask(v, "p:stop beta"), .not_running, "beta"), "{?s}", .{v.lastText(answer_needle)});

    // Another device: its own limit; ask mode is the agent's default mode.
    _ = try client.pair(inst, "proj-laptop");
    const v2 = try client.Viewer.open(inst, "proj-laptop");
    defer v2.deinit();
    _ = r.check("another device has its own limit: p:start gamma started", answered(ask(v2, "p:start gamma"), .started, "gamma"), "{?s}", .{v2.lastText(answer_needle)});
    _ = r.check("an ask project runs with --permission-mode default", v2.waitFor("FAKE-PERMISSION-MODE=default", 15_000), "{s}", .{v2.dump(&dump)});
    _ = r.check("the first device sees gamma running, stoppable", waitList(v, .{ .name = "gamma", .running = true, .stoppable = true }, 10_000), "{?s}", .{v.lastText(list_needle)});
    // "f:" followed by anything is not Forget (frames.classify).
    v2.send("f:yes 00");
    _ = r.check("f:<anything> does not forget the device", v2.ping("still-here", 5000) and v2.countText("forgotten") == 0 and !v2.got_logout, "", .{});

    // The desk adds a project while Portal runs: SettingsWatch follows the file.
    _ = r.check("startable add while running", try startable(h, dir, delta, "delta", "plan"), "", .{});
    _ = r.check("a new projects list reaches the device", waitList(v, .{ .name = "delta", .running = false, .n = 4 }, 10_000), "{?s}", .{v.lastText(list_needle)});

    privacy.checkMessages(r, v, &leaks, "no projects message or answer carries a folder path (first device)");
    privacy.checkMessages(r, v2, &leaks, "no projects message or answer carries a folder path (second device)");

    // A view-only desk: refused, whatever the name.
    {
        const dir2 = try h.dataDir("projects-none");
        const proj2 = try h.dataDir("projects-none\\none-quiet");
        _ = try startable(h, dir2, proj2, "solo", "ask");
        const args2 = [_][]const u8{ "--input", "none", "--cwd", proj2, "--", prog, "--fake-agent" };
        const inst2 = try proc.Instance.start(h, dir2, port + 1, &args2);
        defer inst2.kill();
        _ = try client.pair(inst2, "proj-viewonly");
        const v3 = try client.Viewer.open(inst2, "proj-viewonly");
        defer v3.deinit();
        _ = r.check("view-only desk: the list is still sent", waitList(v3, .{ .name = "solo", .running = true, .n = 1 }, 10_000), "{?s}", .{v3.lastText(list_needle)});
        _ = r.check("view-only desk: p:start refused", answered(ask(v3, "p:start solo"), .refused, null), "{?s}", .{v3.lastText(answer_needle)});
        _ = r.check("view-only desk: p:stop refused", answered(ask(v3, "p:stop solo"), .refused, null), "{?s}", .{v3.lastText(answer_needle)});
    }
}
