//! The plan-usage bar (docs/protocol.md section 3h; src/usage_desk.zig,
//! src/statusline.zig). The tab's program is the fake agent (run as
//! `claude.exe` in a folder named "...usage..."): it checks that Portal
//! passed `--settings <file>` holding only a statusLine, runs that
//! statusLine command the way the agent does, with a status line JSON on
//! stdin (rate limits plus a transcript path and folder that must never
//! travel), and prints what the command printed. Then the test runs real
//! `portalctl statusline` and `portalctl hook` processes with the tab's
//! PORTAL_TAB, as the agent would, and checks:
//!   * a device gets `usage` on connect (after hello), with only
//!     percentages and reset times;
//!   * a second update within 5 minutes is held back; a threshold
//!     crossing (75 %) goes out at once;
//!   * a StopFailure hook with `error` = `rate_limit` sets limit_reached
//!     at once; a later Stop clears it;
//!   * `portalctl statusline` outside a Portal tab changes nothing and
//!     still exits 0;
//!   * the user's own agent settings are never touched (the harness's
//!     scratch CLAUDE_CONFIG_DIR's settings.json is as it was).
//!
//! `fakeRun` is the fake agent's side (fake_agent.zig calls it).

const std = @import("std");
const w = @import("win.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;
const privacy = @import("privacy.zig");
const planusage = @import("shared").planusage;

const max_out = 512;

// ------------------------------------------------------------ the fake agent

/// The fake agent in a "usage" folder: `say` prints to its terminal.
pub fn fakeRun(gpa: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map, args: []const []const u8, cwd: []const u8, say: *const fn ([]const u8) void) void {
    // The tab's hook key, for the test's own statusline and hook runs.
    if (std.fs.path.join(gpa, &.{ cwd, "e2e-tabkey" })) |kp| {
        std.Io.Dir.cwd().writeFile(io, .{ .sub_path = kp, .data = env.get("PORTAL_TAB") orelse "" }) catch {};
    } else |_| {}
    var settings: ?[]const u8 = null;
    for (args, 0..) |a, i| if (std.mem.eql(u8, a, "--settings") and i + 1 < args.len) {
        settings = args[i + 1];
    };
    const path = settings orelse return say("FAKE-NO-SETTINGS\r\n");
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 * 1024)) catch return say("FAKE-SETTINGS-UNREADABLE\r\n");
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, text, .{}) catch return say("FAKE-SETTINGS-NOT-JSON\r\n");
    const obj = if (parsed.value == .object) parsed.value.object else return say("FAKE-SETTINGS-BAD\r\n");
    const sl = obj.get("statusLine") orelse return say("FAKE-SETTINGS-BAD\r\n");
    if (obj.count() != 1 or sl != .object) return say("FAKE-SETTINGS-BAD\r\n");
    const cmd_v = sl.object.get("command") orelse return say("FAKE-SETTINGS-BAD\r\n");
    if (cmd_v != .string) return say("FAKE-SETTINGS-BAD\r\n");
    const cmd = cmd_v.string;
    if (std.fs.path.join(gpa, &.{ cwd, "e2e-statusline-cmd" })) |cp| {
        std.Io.Dir.cwd().writeFile(io, .{ .sub_path = cp, .data = cmd }) catch {};
    } else |_| {}
    say("FAKE-SETTINGS-OK\r\n");
    // Run it as the agent does: the command, the JSON on stdin.
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    const json = std.fmt.allocPrint(gpa, "{{\"hook_event_name\":\"Status\",\"session_id\":\"e2e\",\"transcript_path\":\"{s}\\\\TRANSCRIPT-SECRET.jsonl\",\"cwd\":\"{s}\",\"model\":{{\"id\":\"MODEL-SECRET\"}}," ++
        "\"rate_limits\":{{\"five_hour\":{{\"used_percentage\":12.5,\"resets_at\":{d}}},\"seven_day\":{{\"used_percentage\":40,\"resets_at\":{d}}}}}}}", .{ jsonPath(gpa, cwd), jsonPath(gpa, cwd), now + 3600, now + 3 * 86400 }) catch return;
    var out: [max_out]u8 = undefined;
    const got = runCommand(gpa, cmd, json, &out) orelse return say("FAKE-STATUSLINE-FAILED\r\n");
    say("FAKE-STATUSLINE:[");
    say(got);
    say("]\r\n");
}

fn jsonPath(gpa: std.mem.Allocator, p: []const u8) []const u8 {
    var o: std.ArrayList(u8) = .empty;
    for (p) |c| {
        if (c == '\\') o.append(gpa, '\\') catch {};
        o.append(gpa, c) catch {};
    }
    return o.items;
}

/// Runs `<exe> <arg>` (the statusLine command: a path with forward
/// slashes and one argument), writes `input` to its stdin, returns its
/// stdout.
fn runCommand(gpa: std.mem.Allocator, cmd: []const u8, input: []const u8, out: []u8) ?[]const u8 {
    const sp = std.mem.lastIndexOfScalar(u8, cmd, ' ') orelse return null;
    const exe = gpa.dupe(u8, cmd[0..sp]) catch return null;
    for (exe) |*c| if (c.* == '/') {
        c.* = '\\';
    };
    return runExec(gpa, exe, &.{cmd[sp + 1 ..]}, input, out);
}

/// Runs `exe` with `args` (plain words, as a hook's exec form gives
/// them), writes `input` to its stdin, returns its stdout.
pub fn runExec(gpa: std.mem.Allocator, exe: []const u8, args: []const []const u8, input: []const u8, out: []u8) ?[]const u8 {
    var lb: std.ArrayList(u8) = .empty;
    lb.print(gpa, "\"{s}\"", .{exe}) catch return null;
    for (args) |a| lb.print(gpa, " {s}", .{a}) catch return null;
    const line = lb.items;
    const app_w = std.unicode.utf8ToUtf16LeAllocZ(gpa, exe) catch return null;
    const line_w = std.unicode.utf8ToUtf16LeAllocZ(gpa, line) catch return null;
    var sa: w.SECURITY_ATTRIBUTES = .{ .bInheritHandle = 1 };
    var out_rd: w.HANDLE = undefined;
    var out_wr: w.HANDLE = undefined;
    var in_rd: w.HANDLE = undefined;
    var in_wr: w.HANDLE = undefined;
    if (w.CreatePipe(&out_rd, &out_wr, &sa, 4096) == 0) return null;
    if (w.CreatePipe(&in_rd, &in_wr, &sa, 64 * 1024) == 0) return null;
    _ = w.SetHandleInformation(out_rd, w.HANDLE_FLAG_INHERIT, 0);
    _ = w.SetHandleInformation(in_wr, w.HANDLE_FLAG_INHERIT, 0);
    var si: w.STARTUPINFOEXW = .{ .StartupInfo = .{ .cb = @sizeOf(w.STARTUPINFOW), .dwFlags = w.STARTF_USESTDHANDLES, .hStdInput = in_rd, .hStdOutput = out_wr, .hStdError = out_wr } };
    var pi: w.PROCESS_INFORMATION = undefined;
    if (w.CreateProcessW(app_w.ptr, line_w.ptr, null, null, 1, w.CREATE_NO_WINDOW, null, null, &si, &pi) == 0) return null;
    _ = w.CloseHandle(pi.hThread);
    _ = w.CloseHandle(out_wr);
    _ = w.CloseHandle(in_rd);
    var n: w.DWORD = 0;
    _ = w.WriteFile(in_wr, input.ptr, @intCast(input.len), &n, null);
    _ = w.CloseHandle(in_wr);
    var len: usize = 0;
    while (len < out.len) {
        var r: w.DWORD = 0;
        if (w.ReadFile(out_rd, out[len..].ptr, @intCast(out.len - len), &r, null) == 0 or r == 0) break;
        len += r;
    }
    _ = w.WaitForSingleObject(pi.hProcess, 10_000);
    _ = w.CloseHandle(pi.hProcess);
    _ = w.CloseHandle(out_rd);
    return out[0..len];
}

// ------------------------------------------------------------ the test

const Run = struct { code: ?u32, out: []const u8 };

/// One real `portalctl <cmd>` run with `payload` on stdin and PORTAL_TAB
/// set to `tab` (null: not set).
fn cli(h: *proc.Harness, dir: []const u8, cmd: []const u8, tab: ?[]const u8, payload: []const u8) Run {
    const env = [_]proc.EnvSet{.{ .name = "PORTAL_TAB", .value = tab }};
    const c = proc.LiveCli.startEnv(h, dir, &.{cmd}, &env) catch return .{ .code = null, .out = "" };
    defer c.deinit();
    c.answer(payload);
    c.closeInput();
    const code = c.wait(10_000);
    if (code == null) c.kill();
    return .{ .code = code, .out = h.gpa.dupe(u8, c.output()) catch "" };
}

/// Reset times relative to now: usage_desk drops implausible ones.
fn statusJson(gpa: std.mem.Allocator, io: std.Io, week: f64, five: f64) []const u8 {
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    return std.fmt.allocPrint(gpa, "{{\"transcript_path\":\"C:\\\\TRANSCRIPT-SECRET.jsonl\",\"rate_limits\":{{\"five_hour\":{{\"used_percentage\":{d},\"resets_at\":{d}}},\"seven_day\":{{\"used_percentage\":{d},\"resets_at\":{d}}}}}}}", .{ five, now + 3600, week, now + 3 * 86400 }) catch "";
}

fn lastUsage(v: *const client.Viewer) ?planusage.Usage {
    return planusage.parse(v.lastText("\"t\":\"usage\"") orelse return null);
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("usage");
    const proj = try h.dataDir("usage\\usage-proj");
    const bin = try h.dataDir("usage\\bin");
    var self_buf: [1024]u16 = undefined;
    const sn = w.GetModuleFileNameW(null, &self_buf, self_buf.len);
    const self = try std.unicode.utf16LeToUtf8Alloc(gpa, self_buf[0..sn]);
    const prog = try std.fmt.allocPrint(gpa, "{s}\\claude.exe", .{bin});
    try std.Io.Dir.cwd().copyFile(self, std.Io.Dir.cwd(), prog, h.io, .{});
    const args = [_][]const u8{ "--input", "instruct", "--cwd", proj, "--", prog, "--fake-agent" };
    const inst = try proc.Instance.start(h, dir, port, &args);
    defer inst.kill();
    var leaks = try privacy.Leaks.standard(h, dir);
    defer leaks.deinit();
    try leaks.add(proj);
    for ([_][]const u8{ "TRANSCRIPT-SECRET", "MODEL-SECRET", "statusline", "rate_limits", "used_percentage" }) |s| try leaks.add(s);

    // The agent's user settings as they were (the scratch CLAUDE_CONFIG_DIR).
    var cfg_buf: [1024]u8 = undefined;
    const user_settings = try std.fs.path.join(gpa, &.{ h.agentConfig(&cfg_buf), "settings.json" });
    const settings_before: ?[]u8 = std.Io.Dir.cwd().readFileAlloc(h.io, user_settings, gpa, .limited(1 << 20)) catch null;

    const creds = try client.pair(inst, "usage");
    const v = try client.Viewer.open(inst, creds.device());
    defer v.deinit();
    var dump: [8192]u8 = undefined;

    // ---- the settings file and the agent's own run of the command
    _ = r.check("Portal passed --settings with only a statusLine", v.waitFor("FAKE-SETTINGS-OK", 15_000), "{s}", .{v.dump(&dump)});
    var cb: [1024]u8 = undefined;
    const cmd = std.Io.Dir.cwd().readFile(h.io, try std.fs.path.join(gpa, &.{ proj, "e2e-statusline-cmd" }), &cb) catch "";
    _ = r.check("the statusLine command is portalctl statusline (forward slashes)", std.mem.endsWith(u8, cmd, "/portalctl.exe statusline") and std.mem.indexOfScalar(u8, cmd, '\\') == null, "{s}", .{cmd});
    _ = r.check("the command prints the short line back", v.waitFor("FAKE-STATUSLINE:[5-hour 12%", 10_000) and v.waitFor("week 40%]", 2000), "{s}", .{v.dump(&dump)});
    _ = r.check("the device gets usage: week 40 %, five-hour 12 %, reset times", v.waitText("\"t\":\"usage\"", 1, 8000) and
        lastUsage(v) != null and lastUsage(v).?.week.?.pct == 40 and lastUsage(v).?.five_hour.?.pct == 12 and lastUsage(v).?.week.?.resets_at != 0, "{?s}", .{v.lastText("\"t\":\"usage\"")});

    // ---- on connect: a second device connection gets it right after hello
    const v2 = try client.Viewer.open(inst, creds.device());
    defer v2.deinit();
    _ = r.check("on connect: usage follows hello at once", v2.waitText("\"t\":\"usage\"", 1, 3000) and lastUsage(v2).?.week.?.pct == 40, "{?s}", .{v2.lastText("\"t\":\"usage\"")});

    // The tab's key, as its program saw it.
    var kb: [128]u8 = undefined;
    const key = std.mem.trim(u8, std.Io.Dir.cwd().readFile(h.io, try std.fs.path.join(gpa, &.{ proj, "e2e-tabkey" }), &kb) catch "", " \r\n");
    _ = r.check("the program got its PORTAL_TAB", key.len == 32, "{s}", .{key});
    if (key.len != 32) return;
    try leaks.add(try gpa.dupe(u8, key));

    // ---- throttle: within 5 minutes a small change is held ...
    const before = v.countText("\"t\":\"usage\"");
    const held = cli(h, dir, "statusline", key, statusJson(gpa, h.io, 45, 20));
    _ = r.check("portalctl statusline exits 0 and prints the line", held.code == 0 and std.mem.eql(u8, held.out, "5-hour 20% \u{00B7} week 45%"), "{?d} '{s}'", .{ held.code, held.out });
    v.pump(3000);
    _ = r.check("a second update within 5 minutes is held back", v.countText("\"t\":\"usage\"") == before, "{d} -> {d}", .{ before, v.countText("\"t\":\"usage\"") });
    // ... a threshold crossing goes at once.
    _ = cli(h, dir, "statusline", key, statusJson(gpa, h.io, 80, 20));
    _ = r.check("crossing 75 % goes out at once", v.waitText("\"t\":\"usage\"", before + 1, 3000) and lastUsage(v).?.week.?.pct == 80, "{?s}", .{v.lastText("\"t\":\"usage\"")});

    // ---- the limit: StopFailure rate_limit, then a finished turn
    const n_lim = v.countText("\"t\":\"usage\"");
    const hk = cli(h, dir, "hook", key, "{\"hook_event_name\":\"StopFailure\",\"error\":\"rate_limit\",\"error_details\":\"429 DETAILS-SECRET\"}");
    _ = r.check("the hook exits 0, prints nothing", hk.code == 0 and hk.out.len == 0, "{?d} '{s}'", .{ hk.code, hk.out });
    _ = r.check("StopFailure rate_limit: limit_reached at once (the fuller window)", v.waitText("\"limit_reached\":\"week\"", 1, 3000) and v.countText("\"t\":\"usage\"") == n_lim + 1, "{?s}", .{v.lastText("\"t\":\"usage\"")});
    _ = cli(h, dir, "hook", key, "{\"hook_event_name\":\"StopFailure\",\"error\":\"server_error\"}");
    _ = cli(h, dir, "hook", key, "{\"hook_event_name\":\"Stop\"}");
    _ = r.check("a finished turn clears it at once", v.pumpUntil(3000, {}, struct {
        fn f(_: void, vv: *client.Viewer) bool {
            const u = lastUsage(vv) orelse return false;
            return u.limit_reached == null and vv.countText("\"limit_reached\"") >= 1;
        }
    }.f), "{?s}", .{v.lastText("\"t\":\"usage\"")});

    // ---- outside a Portal tab: nothing changes
    const n_out = v.countText("\"t\":\"usage\"");
    const outside = cli(h, dir, "statusline", null, statusJson(gpa, h.io, 99, 99));
    const unknown = cli(h, dir, "statusline", "0123456789abcdef0123456789abcdef", statusJson(gpa, h.io, 99, 99));
    const garbage = cli(h, dir, "statusline", key, "not json {");
    _ = r.check("no / unknown PORTAL_TAB, or garbage: exit 0", outside.code == 0 and unknown.code == 0 and garbage.code == 0 and garbage.out.len == 0, "{?d} {?d} {?d}", .{ outside.code, unknown.code, garbage.code });
    v.pump(2000);
    _ = r.check("... and no usage message", v.countText("\"t\":\"usage\"") == n_out, "{d} -> {d}", .{ n_out, v.countText("\"t\":\"usage\"") });

    // ---- privacy: only percentages and times left the desk
    var dirty: ?[]const u8 = null;
    for (v.texts.items) |t| if (std.mem.indexOf(u8, t, "\"t\":\"usage\"") != null) {
        if (leaks.find(t)) |l| dirty = l;
        if (std.mem.indexOf(u8, t, "DETAILS-SECRET") != null) dirty = "DETAILS-SECRET";
    };
    _ = r.check("usage messages carry nothing but percentages and times", dirty == null, "{?s}", .{dirty});
    const settings_after: ?[]u8 = std.Io.Dir.cwd().readFileAlloc(h.io, user_settings, gpa, .limited(1 << 20)) catch null;
    const same = if (settings_before) |b| (if (settings_after) |a| std.mem.eql(u8, a, b) else false) else settings_after == null;
    _ = r.check("the agent's user settings were not touched", same, "{s}", .{user_settings});
    _ = r.ok("portal still running", inst.alive() and client.alive(inst));
}
