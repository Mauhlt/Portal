//! The status panels every Portal screen offers (desk and devices alike):
//!
//!   tasks    background shells and monitors per tab (a tab's badge or the
//!            status line's "2 shells · 1 monitor" opens it)
//!   usage    tokens per tab this session, the model, today's totals
//!            (the top bar's Usage); on the desk each tab also gets
//!            "Open /usage", which types `/usage` into that tab (plan
//!            limits are not in transcripts); devices never get it
//!   system   the desktop's CPU, memory, GPUs and each tab's load (the top
//!            bar's System, only while the desk's "Show system monitor"
//!            setting is on)
//!
//! Pure functions from the protocol's numbers (shared/activity.zig,
//! shared/sysinfo.zig) to a frame.Panel; the shell (shell.zig) decides
//! which one is open and routes its buttons.

const std = @import("std");
const shared = @import("shared");
const tabs_wire = shared.tabs;
const activity = shared.activity;
const sysinfo = shared.sysinfo;
const frame = @import("../frame.zig");

pub const Screen = enum { none, tasks, usage, system };

/// Button ids, clear of the other panels' and the shell's ranges.
pub const ids = struct {
    pub const close: u32 = 1300;
    /// "Open /usage" of the tab at bar position i (desk only): slash0 + i.
    pub const slash0: u32 = 1310;
};

pub const max_rows = 28;

pub const Bufs = struct {
    lines: [6]frame.PanelText = undefined,
    line_txt: [6][200]u8 = undefined,
    rows: [max_rows]frame.PanelRow = undefined,
    row_txt: [max_rows][220]u8 = undefined,
    after: [2]frame.PanelText = undefined,
    buttons: [1]frame.PanelButton = undefined,
};

pub const Input = struct {
    /// The desk (Open /usage buttons) or a device.
    desk: bool,
    tabs: []const tabs_wire.Entry,
    /// The tab whose badge was clicked: listed first.
    first: ?tabs_wire.Id = null,
    activity: ?*const activity.Activity = null,
    sys: ?*const sysinfo.Snapshot = null,
    /// Unix seconds now (task ages).
    now: i64 = 0,
};

/// "2 shells · 1 monitor" for what runs in `t`; "" if nothing does.
pub fn tasksText(t: *const activity.Tab, buf: []u8) []const u8 {
    const sh = t.running(.shell);
    const mo = t.running(.monitor);
    if (sh == 0 and mo == 0) return "";
    var w: std.Io.Writer = .fixed(buf);
    if (sh > 0) w.print("{d} shell{s}", .{ sh, if (sh == 1) "" else "s" }) catch {};
    if (sh > 0 and mo > 0) w.writeAll(" \u{00B7} ") catch {};
    if (mo > 0) w.print("{d} monitor{s}", .{ mo, if (mo == 1) "" else "s" }) catch {};
    return w.buffered();
}

/// A tab's badge: how many tasks run ("" for none).
pub fn badgeText(t: *const activity.Tab, buf: []u8) []const u8 {
    const n = t.running(.shell) + t.running(.monitor);
    if (n == 0) return "";
    return std.fmt.bufPrint(buf, "{d}", .{n}) catch "";
}

/// "950", "12.3k", "4.5M", "1.2B".
pub fn tokens(n: u64, buf: []u8) []const u8 {
    const units = [_]struct { v: u64, s: []const u8 }{ .{ .v = 1_000_000_000, .s = "B" }, .{ .v = 1_000_000, .s = "M" }, .{ .v = 1_000, .s = "k" } };
    for (units) |u| if (n >= u.v) {
        const tenths = (n * 10 + u.v / 2) / u.v;
        return std.fmt.bufPrint(buf, "{d}.{d}{s}", .{ tenths / 10, tenths % 10, u.s }) catch "";
    };
    return std.fmt.bufPrint(buf, "{d}", .{n}) catch "";
}

fn usageLine(u: activity.Usage, buf: []u8) []const u8 {
    var a: [16]u8 = undefined;
    var b: [16]u8 = undefined;
    var c: [16]u8 = undefined;
    var d: [16]u8 = undefined;
    var e: [16]u8 = undefined;
    return std.fmt.bufPrint(buf, "{s} tokens (in {s} \u{00B7} out {s} \u{00B7} cache read {s} \u{00B7} cache write {s})", .{
        tokens(u.total(), &a), tokens(u.input, &b), tokens(u.output, &c), tokens(u.cache_read, &d), tokens(u.cache_write, &e),
    }) catch "";
}

/// "in 1.2k · out 34.5k · cache read 2.1M · cache write 9.0k".
fn breakdown(u: activity.Usage, buf: []u8) []const u8 {
    var b: [16]u8 = undefined;
    var c: [16]u8 = undefined;
    var d: [16]u8 = undefined;
    var e: [16]u8 = undefined;
    return std.fmt.bufPrint(buf, "in {s} \u{00B7} out {s} \u{00B7} cache read {s} \u{00B7} cache write {s}", .{ tokens(u.input, &b), tokens(u.output, &c), tokens(u.cache_read, &d), tokens(u.cache_write, &e) }) catch "";
}

/// "just started", "5 min", "2 h 10 min", "3 days".
pub fn age(since: i64, now: i64, buf: []u8) []const u8 {
    if (since <= 0 or now <= 0) return "";
    const d = @max(0, now - since);
    if (d < 60) return "just started";
    if (d < 3600) return std.fmt.bufPrint(buf, "{d} min", .{@divFloor(d, 60)}) catch "";
    if (d < 86400) return std.fmt.bufPrint(buf, "{d} h {d} min", .{ @divFloor(d, 3600), @divFloor(@mod(d, 3600), 60) }) catch "";
    return std.fmt.bufPrint(buf, "{d} days", .{@divFloor(d, 86400)}) catch "";
}

fn stateWord(s: activity.State) []const u8 {
    return switch (s) {
        .running => "running",
        .done => "done",
        .failed => "failed",
        .killed => "stopped",
        .stale => "from an earlier run",
    };
}

fn stateTone(s: activity.State) frame.Tone {
    return switch (s) {
        .running => .good,
        .failed => .bad,
        else => .muted,
    };
}

/// The tabs in display order: `first` (if any) then bar order.
fn order(in: Input, out: *[tabs_wire.max_tabs]usize) []const usize {
    var n: usize = 0;
    if (in.first) |f| for (in.tabs, 0..) |e, i| if (std.mem.eql(u8, &e.id, &f)) {
        out[n] = i;
        n += 1;
    };
    for (in.tabs, 0..) |e, i| {
        if (in.first) |f| if (std.mem.eql(u8, &e.id, &f)) continue;
        out[n] = i;
        n += 1;
    }
    return out[0..n];
}

const Build = struct {
    b: *Bufs,
    nl: usize = 0,
    nr: usize = 0,

    fn line(x: *Build, tone: frame.Tone, bold: bool, comptime fmt: []const u8, args: anytype) void {
        if (x.nl == x.b.lines.len) return;
        const t = std.fmt.bufPrint(&x.b.line_txt[x.nl], fmt, args) catch x.b.line_txt[x.nl][0..0];
        x.b.lines[x.nl] = .{ .text = t, .tone = tone, .bold = bold };
        x.nl += 1;
    }

    fn row(x: *Build, tone: frame.Tone, selected: bool, button: ?frame.PanelButton, comptime fmt: []const u8, args: anytype) bool {
        if (x.nr == x.b.rows.len) return false;
        const t = std.fmt.bufPrint(&x.b.row_txt[x.nr], fmt, args) catch blk: {
            // Too long: cut at a character boundary.
            const buf = &x.b.row_txt[x.nr];
            var n: usize = buf.len;
            while (n > 0 and (buf[n - 1] & 0xC0) == 0x80) n -= 1;
            break :blk buf[0..n];
        };
        x.b.rows[x.nr] = .{ .text = t, .tone = tone, .selected = selected, .button = button };
        x.nr += 1;
        return true;
    }
};

/// The open panel, or null for `.none`.
pub fn panel(screen: Screen, in: Input, b: *Bufs) ?frame.Panel {
    var x: Build = .{ .b = b };
    var p: frame.Panel = .{ .title = "" };
    var ob: [tabs_wire.max_tabs]usize = undefined;
    switch (screen) {
        .none => return null,
        .tasks => {
            p.title = "Background tasks";
            var shells: u32 = 0;
            var monitors: u32 = 0;
            var listed: usize = 0;
            if (in.activity) |a| for (order(in, &ob)) |i| {
                const t = a.find(in.tabs[i].id) orelse continue;
                shells += t.running(.shell);
                monitors += t.running(.monitor);
                if (t.n_tasks == 0) continue;
                var tb: [64]u8 = undefined;
                const what = tasksText(t, &tb);
                if (!x.row(.normal, true, null, "{s} \u{2014} {s}", .{ in.tabs[i].name(), if (what.len > 0) what else "nothing running" })) break;
                listed += 1;
                // Newest first.
                var k = t.n_tasks;
                while (k > 0) {
                    k -= 1;
                    const task = &t.tasks[k];
                    var ab: [32]u8 = undefined;
                    const ag = age(task.since, in.now, &ab);
                    const kind = if (task.kind == .shell) "Shell" else "Monitor";
                    const ok = if (ag.len > 0 and task.state == .running)
                        x.row(stateTone(task.state), false, null, "   {s} \u{00B7} {s} \u{00B7} {s} \u{00B7} {s}", .{ kind, stateWord(task.state), ag, task.text() })
                    else
                        x.row(stateTone(task.state), false, null, "   {s} \u{00B7} {s} \u{00B7} {s}", .{ kind, stateWord(task.state), task.text() });
                    if (!ok) break;
                }
            };
            if (shells + monitors == 0) {
                x.line(.muted, false, "Nothing is running in the background.", .{});
            } else {
                x.line(.good, true, "Running now: {d} shell{s} \u{00B7} {d} monitor{s}", .{ shells, if (shells == 1) "" else "s", monitors, if (monitors == 1) "" else "s" });
            }
            if (listed == 0 and in.activity != null) x.line(.muted, false, "No background shells or monitors were started in these sessions.", .{});
            p.note = .{ .text = "From each tab's transcript: what the program started with run_in_background, and its monitors. Commands are never shown." };
        },
        .usage => {
            p.title = "Usage";
            if (in.activity) |a| {
                var lb: [160]u8 = undefined;
                x.line(.normal, true, "Today, all tabs: {s}", .{usageLine(a.today(), &lb)});
                for (in.tabs, 0..) |e, i| {
                    const t = a.find(e.id) orelse continue;
                    var tb: [16]u8 = undefined;
                    var ub: [160]u8 = undefined;
                    const btn: ?frame.PanelButton = if (in.desk) .{ .label = "Open /usage", .id = ids.slash0 + @as(u32, @intCast(i)) } else null;
                    if (!x.row(.normal, true, btn, "{s} \u{00B7} {s} \u{00B7} {s} tokens this session", .{ e.name(), if (t.model().len > 0) t.model() else "model not known yet", tokens(t.usage.total(), &tb) })) break;
                    if (!x.row(.muted, false, null, "   {s}", .{breakdown(t.usage, &ub)})) break;
                }
            } else x.line(.muted, false, "No usage known yet.", .{});
            b.after[0] = .{ .text = if (in.desk)
                "Plan limits are not in transcripts: Open /usage types /usage into that tab, which shows them."
            else
                "Plan limits are not in transcripts: run /usage at the desk (slash commands are not sent from devices)." };
            p.after = b.after[0..1];
        },
        .system => {
            p.title = "System";
            if (in.sys) |s| {
                var pb: [16]u8 = undefined;
                var m1: [16]u8 = undefined;
                var m2: [16]u8 = undefined;
                x.line(.normal, true, "CPU {s} \u{00B7} memory {s} of {s}", .{ sysinfo.formatPct(s.cpu, &pb), sysinfo.formatBytes(s.mem_used, &m1), sysinfo.formatBytes(s.mem_total, &m2) });
                for (s.gpuSlice(), 1..) |g, gi| {
                    var gb: [16]u8 = undefined;
                    var v1: [16]u8 = undefined;
                    var v2: [16]u8 = undefined;
                    if (g.total > 0) {
                        x.line(.normal, false, "GPU {d}: {s} \u{00B7} video memory {s} of {s}", .{ gi, sysinfo.formatPct(g.util, &gb), sysinfo.formatBytes(g.used, &v1), sysinfo.formatBytes(g.total, &v2) });
                    } else x.line(.normal, false, "GPU {d}: {s} \u{00B7} video memory {s}", .{ gi, sysinfo.formatPct(g.util, &gb), sysinfo.formatBytes(g.used, &v1) });
                }
                for (in.tabs) |e| {
                    const l = s.find(e.id) orelse continue;
                    var cb: [16]u8 = undefined;
                    var mb: [16]u8 = undefined;
                    if (!x.row(if (l.cpu >= 500) .warn else .normal, false, null, "{s} \u{00B7} CPU {s} \u{00B7} {s} \u{00B7} {d} process{s}", .{ e.name(), sysinfo.formatPct(l.cpu, &cb), sysinfo.formatBytes(l.mem, &mb), l.procs, if (l.procs == 1) "" else "es" })) break;
                }
            } else x.line(.muted, false, "Waiting for the first sample\u{2026}", .{});
            p.note = .{ .text = "Measured once a second, only while a System panel is open. Each tab counts its program and everything it started." };
        },
    }
    p.lines = b.lines[0..x.nl];
    p.rows = b.rows[0..x.nr];
    b.buttons[0] = .{ .label = "Close", .id = ids.close, .focused = true };
    p.buttons = b.buttons[0..1];
    return p;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn fixture(list: *[2]tabs_wire.Entry, a: *activity.Activity) void {
    list[0] = .{ .id = @splat(1), .color = 0x3366CC };
    list[0].setName("Alpha");
    list[1] = .{ .id = @splat(2), .color = 0x10B981 };
    list[1].setName("Beta");
    a.* = .{ .len = 2 };
    a.tabs[0] = .{ .id = @splat(1), .usage = .{ .input = 1200, .output = 34_500, .cache_read = 2_100_000, .cache_write = 9000 }, .today = .{ .input = 100, .output = 200 } };
    a.tabs[0].setModel("model-large-4-1");
    a.tabs[0].tasks[0] = .{ .kind = .shell, .state = .running, .since = 1000 };
    a.tabs[0].tasks[0].setText("Run the tests");
    a.tabs[0].tasks[1] = .{ .kind = .shell, .state = .failed, .since = 900 };
    a.tabs[0].tasks[1].setText("Build docs");
    a.tabs[0].tasks[2] = .{ .kind = .monitor, .state = .running, .since = 1100 };
    a.tabs[0].tasks[2].setText("Watch the log");
    a.tabs[0].n_tasks = 3;
    a.tabs[1] = .{ .id = @splat(2), .today = .{ .input = 5 } };
}

test "texts: counts, badges, tokens, ages" {
    var list: [2]tabs_wire.Entry = undefined;
    var a: activity.Activity = undefined;
    fixture(&list, &a);
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("1 shell \u{00B7} 1 monitor", tasksText(&a.tabs[0], &buf));
    try testing.expectEqualStrings("", tasksText(&a.tabs[1], &buf));
    try testing.expectEqualStrings("2", badgeText(&a.tabs[0], &buf));
    try testing.expectEqualStrings("", badgeText(&a.tabs[1], &buf));
    try testing.expectEqualStrings("950", tokens(950, &buf));
    try testing.expectEqualStrings("12.3k", tokens(12_345, &buf));
    try testing.expectEqualStrings("2.1M", tokens(2_100_000, &buf));
    try testing.expectEqualStrings("5 min", age(1000, 1300, &buf));
    try testing.expectEqualStrings("just started", age(1000, 1010, &buf));
    try testing.expectEqualStrings("2 h 10 min", age(0 + 1, 7801, &buf));
}

test "tasks panel: the clicked tab first, newest task first, counts" {
    var list: [2]tabs_wire.Entry = undefined;
    var a: activity.Activity = undefined;
    fixture(&list, &a);
    var b: Bufs = .{};
    const p = panel(.tasks, .{ .desk = false, .tabs = &list, .first = @splat(1), .activity = &a, .now = 1400 }, &b).?;
    try testing.expectEqualStrings("Background tasks", p.title);
    try testing.expectEqualStrings("Running now: 1 shell \u{00B7} 1 monitor", p.lines[0].text);
    try testing.expectEqualStrings("Alpha \u{2014} 1 shell \u{00B7} 1 monitor", p.rows[0].text);
    try testing.expectEqualStrings("   Monitor \u{00B7} running \u{00B7} 5 min \u{00B7} Watch the log", p.rows[1].text);
    try testing.expectEqualStrings("   Shell \u{00B7} failed \u{00B7} Build docs", p.rows[2].text);
    try testing.expectEqual(frame.Tone.bad, p.rows[2].tone);
    try testing.expectEqual(@as(usize, 4), p.rows.len); // Beta has no tasks
    try testing.expectEqual(ids.close, p.buttons[0].id);
    try testing.expect(panel(.none, .{ .desk = true, .tabs = &list }, &b) == null);
}

test "usage panel: per tab and today; Open /usage on the desk only" {
    var list: [2]tabs_wire.Entry = undefined;
    var a: activity.Activity = undefined;
    fixture(&list, &a);
    var b: Bufs = .{};
    const d = panel(.usage, .{ .desk = true, .tabs = &list, .activity = &a }, &b).?;
    try testing.expectEqualStrings("Today, all tabs: 305 tokens (in 105 \u{00B7} out 200 \u{00B7} cache read 0 \u{00B7} cache write 0)", d.lines[0].text);
    try testing.expectEqualStrings("Alpha \u{00B7} model-large-4-1 \u{00B7} 2.1M tokens this session", d.rows[0].text);
    try testing.expectEqualStrings("   in 1.2k \u{00B7} out 34.5k \u{00B7} cache read 2.1M \u{00B7} cache write 9.0k", d.rows[1].text);
    try testing.expectEqualStrings("Beta \u{00B7} model not known yet \u{00B7} 0 tokens this session", d.rows[2].text);
    try testing.expectEqual(ids.slash0 + 1, d.rows[2].button.?.id);
    try testing.expect(d.rows[3].button == null);
    var b2: Bufs = .{};
    const v = panel(.usage, .{ .desk = false, .tabs = &list, .activity = &a }, &b2).?;
    for (v.rows) |r| try testing.expect(r.button == null);
    try testing.expect(std.mem.indexOf(u8, v.after[0].text, "at the desk") != null);
}

test "system panel: numbers per adapter and tab" {
    var list: [2]tabs_wire.Entry = undefined;
    var a: activity.Activity = undefined;
    fixture(&list, &a);
    var s: sysinfo.Snapshot = .{ .cpu = 125, .mem_used = 7 << 30, .mem_total = 32 << 30, .n_gpus = 1, .n_tabs = 1 };
    s.gpus[0] = .{ .util = 30, .used = 1 << 30, .total = 8 << 30 };
    s.tabs[0] = .{ .id = @splat(2), .cpu = 42, .mem = 350 << 20, .procs = 3 };
    var b: Bufs = .{};
    const p = panel(.system, .{ .desk = false, .tabs = &list, .sys = &s }, &b).?;
    try testing.expectEqualStrings("CPU 12.5 % \u{00B7} memory 7.0 GB of 32.0 GB", p.lines[0].text);
    try testing.expectEqualStrings("GPU 1: 3.0 % \u{00B7} video memory 1.0 GB of 8.0 GB", p.lines[1].text);
    try testing.expectEqualStrings("Beta \u{00B7} CPU 4.2 % \u{00B7} 350 MB \u{00B7} 3 processes", p.rows[0].text);
    var b2: Bufs = .{};
    try testing.expectEqualStrings("Waiting for the first sample\u{2026}", panel(.system, .{ .desk = true, .tabs = &list }, &b2).?.lines[0].text);
}
