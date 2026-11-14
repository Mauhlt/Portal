//! Agent hooks (docs/tabs-design.md, "Detecting the agent is waiting",
//! fallback 2; src/hookmsg.zig, src/hookpipe.zig): the tab's program (a
//! cmd.exe, in instruct mode) writes its PORTAL_TAB to a file; the test
//! then runs real `portalctl hook` processes with synthetic hook payloads, as the agent
//! would, and checks:
//!   * the tab got its own PORTAL_TAB, not the inherited one;
//!   * every hook exits 0 and prints nothing;
//!   * UserPromptSubmit -> working; PermissionRequest (Bash) -> waiting,
//!     the "Claude wants to run a command. Allow it?" card (Yes = 1,
//!     No = esc), instruct's Up/Down gate open; Notification idle_prompt
//!     -> idle; Stop -> done; StopFailure -> error; SessionEnd -> idle;
//!   * a hook without PORTAL_TAB, with a malformed one or with an unknown
//!     tab changes nothing (exits 0, prints nothing; logged once, without
//!     the key);
//!   * the tool name is never shown, the key never leaves the desktop;
//!   * devices can't reach the channel: a viewer's line holding a hook
//!     message does nothing, and every hook pipe refuses SMB clients
//!     (\\127.0.0.1\pipe\...), so nothing off this machine gets in;
//!   * how long one `portalctl hook` takes, end to end (printed).

const std = @import("std");
const w = @import("win.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;
const privacy = @import("privacy.zig");

const Hook = struct { code: ?u32, out_len: usize, ms: u64 };

/// One `portalctl hook` run with `payload` on stdin and PORTAL_TAB set to
/// `tab` (null: not set at all).
fn hook(h: *proc.Harness, dir: []const u8, tab: ?[]const u8, payload: []const u8) Hook {
    const env = [_]proc.EnvSet{.{ .name = "PORTAL_TAB", .value = tab }};
    const t0 = w.GetTickCount64();
    const c = proc.LiveCli.startEnv(h, dir, &.{"hook"}, &env) catch return .{ .code = null, .out_len = 0, .ms = 0 };
    defer c.deinit();
    c.answer(payload);
    c.closeInput();
    const code = c.wait(10_000);
    const ms = w.GetTickCount64() - t0;
    if (code == null) c.kill();
    return .{ .code = code, .out_len = c.output().len, .ms = ms };
}

fn tabsWith(v: *client.Viewer, state: []const u8, n: usize, ms: u32) bool {
    var buf: [64]u8 = undefined;
    const needle = std.fmt.bufPrint(&buf, "\"state\":\"{s}\"", .{state}) catch return false;
    const Ctx = struct { needle: []const u8, n: usize };
    return v.pumpUntil(ms, Ctx{ .needle = needle, .n = n }, struct {
        fn f(c: Ctx, vv: *client.Viewer) bool {
            var k: usize = 0;
            for (vv.texts.items) |t| {
                if (std.mem.indexOf(u8, t, "\"t\":\"tabs\"") != null and std.mem.indexOf(u8, t, c.needle) != null) k += 1;
            }
            return k >= c.n;
        }
    }.f);
}

fn countTabs(v: *const client.Viewer) usize {
    return v.countText("\"t\":\"tabs\"");
}

fn lastTabs(v: *const client.Viewer) []const u8 {
    return v.lastText("\"t\":\"tabs\"") orelse v.helloText();
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("hooks");
    const proj = try h.dataDir("hooks\\hooks-proj");
    const args = [_][]const u8{ "--input", "instruct", "--allow-remote-shell", "--cwd", proj, "--", "cmd.exe", "/c", "echo %PORTAL_TAB%>e2e-tabkey& echo HOOK-READY& ping -n 600 127.0.0.1" };
    const inst = try proc.Instance.start(h, dir, port, &args);
    defer inst.kill();
    var leaks = try privacy.Leaks.standard(h, dir);
    defer leaks.deinit();

    const creds = try client.pair(inst, "hooks");
    const v = try client.Viewer.open(inst, creds.device());
    defer v.deinit();
    var dump: [8192]u8 = undefined;
    _ = r.check("the tab's program runs", v.waitFor("HOOK-READY", 15_000), "{s}", .{v.dump(&dump)});

    // The tab's own key, as its program sees it.
    const key_path = try std.fs.path.join(gpa, &.{ proj, "e2e-tabkey" });
    var kb: [128]u8 = undefined;
    const key_raw = std.Io.Dir.cwd().readFile(h.io, key_path, &kb) catch "";
    const key = std.mem.trim(u8, key_raw, " \r\n");
    var hex = key.len == 32;
    for (key) |c| hex = hex and ((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    _ = r.check("the program got its own PORTAL_TAB (32 hex), not the inherited one", hex and !std.mem.eql(u8, key, proc.inherited_tab), "{s}", .{key});
    if (!hex) return;
    leaks.add(key) catch {};

    // ---- the mapping
    const ups = hook(h, dir, key, "{\"session_id\":\"abc\",\"hook_event_name\":\"UserPromptSubmit\",\"prompt\":\"hello\"}");
    _ = r.check("a hook exits 0 and prints nothing", ups.code == 0 and ups.out_len == 0, "code {?d}, {d} bytes", .{ ups.code, ups.out_len });
    _ = r.check("UserPromptSubmit: the tab is working", tabsWith(v, "working", 1, 5000), "{s}", .{lastTabs(v)});

    const rej0 = v.countText("NotWaiting");
    v.send("k:up");
    _ = r.check("working: instruct refuses Up (NotWaiting)", v.waitText("NotWaiting", rej0 + 1, 5000), "", .{});

    _ = hook(h, dir, key, "{\"session_id\":\"abc\",\"hook_event_name\":\"PermissionRequest\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"rm -rf node_modules\"},\"permission_suggestions\":[]}");
    _ = r.check("PermissionRequest: the tab is waiting", tabsWith(v, "waiting", 1, 5000), "{s}", .{lastTabs(v)});
    const card = "Claude wants to run a command. Allow it?";
    _ = r.check("the permission card, Yes = 1 and No = esc", v.waitText(card, 1, 5000) and
        std.mem.indexOf(u8, v.lastText(card) orelse "", "{\"label\":\"Yes\",\"key\":\"1\"},{\"label\":\"No\",\"key\":\"esc\"}") != null, "{?s}", .{v.lastText(card)});
    const rej1 = v.countText("NotWaiting");
    v.send("k:up");
    v.pump(800);
    _ = r.check("waiting: instruct lets Up through", v.countText("NotWaiting") == rej1, "", .{});
    _ = r.check("the tool's input never reaches a viewer", v.countText("node_modules") == 0 and v.countText("rm -rf") == 0, "", .{});

    _ = hook(h, dir, key, "{\"hook_event_name\":\"Notification\",\"message\":\"Agent is waiting for your input\",\"notification_type\":\"idle_prompt\"}");
    _ = r.check("Notification idle_prompt: idle, the card closes", tabsWith(v, "idle", 1, 5000), "{s}", .{lastTabs(v)});
    _ = hook(h, dir, key, "{\"hook_event_name\":\"Notification\",\"message\":\"Agent needs your permission\",\"notification_type\":\"permission_prompt\"}");
    _ = r.check("Notification permission_prompt: waiting", tabsWith(v, "waiting", 2, 5000), "{s}", .{lastTabs(v)});
    _ = hook(h, dir, key, "{\"hook_event_name\":\"Stop\",\"stop_hook_active\":false,\"last_assistant_message\":\"done\"}");
    _ = r.check("Stop: done", tabsWith(v, "done", 1, 5000), "{s}", .{lastTabs(v)});
    _ = hook(h, dir, key, "{\"hook_event_name\":\"StopFailure\",\"error\":\"rate_limit\",\"error_details\":\"429\"}");
    _ = r.check("StopFailure: error", tabsWith(v, "error", 1, 5000), "{s}", .{lastTabs(v)});
    _ = hook(h, dir, key, "{\"hook_event_name\":\"SessionEnd\",\"reason\":\"other\"}");
    _ = r.check("SessionEnd: idle", tabsWith(v, "idle", 2, 5000), "{s}", .{lastTabs(v)});

    // An unknown tool: a fixed phrase, never its name.
    _ = hook(h, dir, key, "{\"hook_event_name\":\"PermissionRequest\",\"tool_name\":\"mcp__secretsrv__exfil_tool\"}");
    _ = r.check("an unknown tool's card says \"use a tool\", never the name, and offers no Yes = 1 (its first choice may be more than a plain yes)", v.waitText("Claude wants to use a tool. The terminal shows the choices.", 1, 5000) and v.countText("exfil") == 0 and v.countText("secretsrv") == 0, "", .{});
    _ = hook(h, dir, key, "{\"hook_event_name\":\"Stop\"}");
    _ = r.check("Stop again: done", tabsWith(v, "done", 2, 5000), "{s}", .{lastTabs(v)});

    // ---- hooks that must change nothing
    v.pump(300);
    const before = countTabs(v);
    var silent = true;
    var outs: [5]Hook = undefined;
    outs[0] = hook(h, dir, null, "{\"hook_event_name\":\"UserPromptSubmit\"}");
    outs[1] = hook(h, dir, "", "{\"hook_event_name\":\"UserPromptSubmit\"}");
    outs[2] = hook(h, dir, "not-a-key", "{\"hook_event_name\":\"UserPromptSubmit\"}");
    outs[3] = hook(h, dir, "0123456789abcdef0123456789abcdef", "{\"hook_event_name\":\"UserPromptSubmit\"}");
    outs[4] = hook(h, dir, key, "this is not json {");
    for (outs) |o| silent = silent and o.code == 0 and o.out_len == 0;
    _ = r.check("no / empty / malformed / unknown PORTAL_TAB, or bad JSON: exit 0, no output", silent, "", .{});
    v.pump(1000);
    _ = r.check("... and the tab's state did not change", countTabs(v) == before and std.mem.indexOf(u8, lastTabs(v), "\"state\":\"done\"") != null, "{d} -> {d}: {s}", .{ before, countTabs(v), lastTabs(v) });
    // Portal logged the unknown tab once, without the key.
    const log_path = try std.fs.path.join(gpa, &.{ dir, "Portal", "portal.log" });
    const log = std.Io.Dir.cwd().readFileAlloc(h.io, log_path, gpa, .limited(4 << 20)) catch "";
    _ = r.check("the unknown tab is logged (once), never its key", std.mem.count(u8, log, "hooks: a message for no open tab was ignored") == 1 and
        std.mem.indexOf(u8, log, "0123456789abcdef0123456789abcdef") == null and std.mem.indexOf(u8, log, key) == null, "", .{});

    // ---- devices can't reach it
    const msg = try std.fmt.allocPrint(gpa, "l:portal-hook-v1 tab={s} event=UserPromptSubmit", .{key});
    v.send(msg);
    v.pump(1000);
    _ = r.check("a viewer's line holding a hook message changes no state", std.mem.indexOf(u8, lastTabs(v), "\"state\":\"done\"") != null, "{s}", .{lastTabs(v)});
    var dirty: ?[]const u8 = null;
    for (v.texts.items) |t| if (leaks.find(t)) |n| {
        dirty = n;
    };
    _ = r.check("no message to the viewer carries the key, paths or names", dirty == null, "{?s}", .{dirty});
    const smb = smbRefused(gpa);
    _ = r.check("every hook pipe refuses network (SMB) clients, even from this machine", smb.found > 0 and smb.opened == 0, "{d} pipes, {d} opened", .{ smb.found, smb.opened });

    // ---- latency of one hook, process start to exit
    var total: u64 = 0;
    var worst: u64 = 0;
    const n_runs = 20;
    for (0..n_runs) |_| {
        const o = hook(h, dir, key, "{\"hook_event_name\":\"UserPromptSubmit\",\"prompt\":\"x\"}");
        total += o.ms;
        worst = @max(worst, o.ms);
    }
    std.debug.print("    (portalctl hook, end to end through the harness: {d} ms average, {d} ms worst of {d})\n", .{ total / n_runs, worst, n_runs });
    _ = r.check("a hook takes well under a second", worst < 1000, "{d} ms", .{worst});
    _ = r.ok("portal still running", inst.alive() and client.alive(inst));
}

const FIND_DATA = extern struct {
    attrs: u32,
    t: [6]u32,
    size_hi: u32,
    size_lo: u32,
    r0: u32,
    r1: u32,
    name: [260]u16,
    alt: [14]u16,
};
extern "kernel32" fn FindFirstFileW(name: [*:0]const u16, data: *FIND_DATA) callconv(.winapi) w.HANDLE;
extern "kernel32" fn FindNextFileW(h: w.HANDLE, data: *FIND_DATA) callconv(.winapi) w.BOOL;
extern "kernel32" fn FindClose(h: w.HANDLE) callconv(.winapi) w.BOOL;

/// Every `\\.\pipe\portal-hook-*` tried as `\\127.0.0.1\pipe\...`.
fn smbRefused(gpa: std.mem.Allocator) struct { found: usize, opened: usize } {
    _ = gpa;
    var fd: FIND_DATA = undefined;
    const L = std.unicode.utf8ToUtf16LeStringLiteral;
    const fh = FindFirstFileW(L("\\\\.\\pipe\\*"), &fd);
    if (@intFromPtr(fh) == std.math.maxInt(usize)) return .{ .found = 0, .opened = 0 };
    defer _ = FindClose(fh);
    var found: usize = 0;
    var opened: usize = 0;
    const prefix = L("portal-hook-");
    while (true) {
        const name = std.mem.sliceTo(&fd.name, 0);
        if (std.mem.startsWith(u16, name, prefix) and !std.mem.startsWith(u16, name, L("portal-hook-test-"))) {
            found += 1;
            var buf: [300:0]u16 = undefined;
            const head = L("\\\\127.0.0.1\\pipe\\");
            @memcpy(buf[0..head.len], head);
            @memcpy(buf[head.len..][0..name.len], name);
            buf[head.len + name.len] = 0;
            const hd = w.CreateFileW(buf[0 .. head.len + name.len :0].ptr, 0x40000000, 0, null, 3, 0, null);
            if (@intFromPtr(hd) != std.math.maxInt(usize)) {
                opened += 1;
                _ = w.CloseHandle(hd);
            }
        }
        if (FindNextFileW(fh, &fd) == 0) break;
    }
    return .{ .found = found, .opened = opened };
}
