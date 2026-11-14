//! `portalctl statusline`: the agent's status line command for the
//! sessions Portal launches (docs/tabs-design.md, "The plan-usage bar";
//! the settings file and its `--settings` argument: usage_desk.zig). The
//! agent runs it after its replies with a JSON document on stdin; of that
//! document only `rate_limits.five_hour` and `rate_limits.seven_day`
//! (`used_percentage`, `resets_at` in Unix seconds) are read. Everything
//! else in it (the transcript path, the folder, the model, costs) is never
//! read past the parser, never kept and never sent. The windows appear
//! only for claude.ai subscriptions and only after the session's first
//! reply; each may be absent.
//!
//! It hands the two windows to the running Portal over the hook pipe
//! (hookpipe.zig: this user only, no remote clients), with the tab's
//! PORTAL_TAB so only Portal's own sessions count, and prints a short
//! line back for the agent to show ("5-hour 23% · week 41%", or nothing).
//! It never waits long (the pipe's connect timeout) and always exits 0.
//!
//! The pipe message (ASCII lines, at most hookmsg.max_message bytes):
//!
//!   portal-usage-v1
//!   tab=<32 lower-case hex>
//!   week=<pct 0..100>:<resets_at, 0: unknown>        (optional)
//!   five_hour=<pct 0..100>:<resets_at, 0: unknown>   (optional)
//!
//! At least one window; the receiver's parser is strict.

const std = @import("std");
const builtin = @import("builtin");
const planusage = @import("shared").planusage;
const hookmsg = @import("hookmsg.zig");

pub const header = "portal-usage-v1";
/// Largest resets_at kept (2^53, as the wire allows).
const max_epoch: u64 = 1 << 53;

/// What the agent's status line JSON says about the plan's windows; null
/// when it says nothing usable (no `rate_limits`, no window, garbage).
pub fn extract(scratch: std.mem.Allocator, json: []const u8) ?planusage.Usage {
    const Win = struct {
        used_percentage: ?f64 = null,
        resets_at: ?f64 = null,
    };
    const In = struct {
        rate_limits: ?struct {
            five_hour: ?Win = null,
            seven_day: ?Win = null,
        } = null,
    };
    const in = std.json.parseFromSliceLeaky(In, scratch, json[hookmsg.bomLen(json)..], .{
        .ignore_unknown_fields = true,
        .duplicate_field_behavior = .use_last,
    }) catch return null;
    const rl = in.rate_limits orelse return null;
    const u: planusage.Usage = .{
        .week = window(rl.seven_day),
        .five_hour = window(rl.five_hour),
    };
    if (u.week == null and u.five_hour == null) return null;
    return u;
}

fn window(w: anytype) ?planusage.Window {
    const v = w orelse return null;
    const p = v.used_percentage orelse return null;
    if (!std.math.isFinite(p)) return null;
    // Floor: 99.6 % is not the limit yet.
    const pct: u8 = @intFromFloat(std.math.clamp(@floor(p), 0, 100));
    var r: u64 = 0;
    if (v.resets_at) |t| if (std.math.isFinite(t) and t > 0) {
        r = @intFromFloat(@min(@floor(t), @as(f64, @floatFromInt(max_epoch))));
    };
    return .{ .pct = pct, .resets_at = r };
}

/// One report on the pipe: a tab's key and the windows it saw.
pub const Report = struct {
    key: hookmsg.Key,
    usage: planusage.Usage,
};

pub fn encode(r: *const Report, buf: *[hookmsg.max_message]u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    const hex = hookmsg.keyHex(r.key);
    w.print("{s}\ntab={s}\n", .{ header, &hex }) catch unreachable;
    if (r.usage.week) |x| w.print("week={d}:{d}\n", .{ @min(x.pct, 100), @min(x.resets_at, max_epoch) }) catch unreachable;
    if (r.usage.five_hour) |x| w.print("five_hour={d}:{d}\n", .{ @min(x.pct, 100), @min(x.resets_at, max_epoch) }) catch unreachable;
    return w.buffered();
}

/// The receiver's strict parser: anything malformed is null (dropped).
pub fn parse(text: []const u8) ?Report {
    if (text.len > hookmsg.max_message) return null;
    var it = std.mem.splitScalar(u8, text, '\n');
    if (!std.mem.eql(u8, it.next() orelse return null, header)) return null;
    var key: ?hookmsg.Key = null;
    var u: planusage.Usage = .{};
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse return null;
        const k = line[0..eq];
        const v = line[eq + 1 ..];
        if (std.mem.eql(u8, k, "tab")) {
            if (key != null) return null;
            key = hookmsg.parseKey(v) orelse return null;
        } else if (std.mem.eql(u8, k, "week")) {
            if (u.week != null) return null;
            u.week = parseWindow(v) orelse return null;
        } else if (std.mem.eql(u8, k, "five_hour")) {
            if (u.five_hour != null) return null;
            u.five_hour = parseWindow(v) orelse return null;
        } // unknown keys: ignored (a newer sender)
    }
    if (u.week == null and u.five_hour == null) return null;
    return .{ .key = key orelse return null, .usage = u };
}

fn parseWindow(v: []const u8) ?planusage.Window {
    const colon = std.mem.indexOfScalar(u8, v, ':') orelse return null;
    const pct = digits(u8, v[0..colon], 100) orelse return null;
    const r = digits(u64, v[colon + 1 ..], max_epoch) orelse return null;
    return .{ .pct = pct, .resets_at = r };
}

fn digits(comptime T: type, s: []const u8, max: u64) ?T {
    if (s.len == 0 or s.len > 16) return null;
    for (s) |c| if (c < '0' or c > '9') return null;
    const n = std.fmt.parseInt(u64, s, 10) catch return null;
    if (n > max) return null;
    return @intCast(n);
}

/// What the command prints back for the agent's status line:
/// "5-hour 23% · week 41%" (the windows known), "" without any.
pub fn statusText(u: ?planusage.Usage, buf: []u8) []const u8 {
    const x = u orelse return "";
    var w: std.Io.Writer = .fixed(buf);
    if (x.five_hour) |f| w.print("5-hour {d}%", .{f.pct}) catch return "";
    if (x.week) |k| w.print("{s}week {d}%", .{ if (x.five_hour != null) " \u{00B7} " else "", k.pct }) catch return "";
    return w.buffered();
}

// ------------------------------------------------------------ the command

/// Largest status line input read; the rest is drained and the input
/// counts as unparsable (the agent's document is a few KB).
pub const max_input = 256 * 1024;

/// `portalctl statusline`: reads stdin (bounded), sends the windows to
/// Portal when run in a Portal tab (PORTAL_TAB) and prints the short line.
/// Always exits 0 (the caller exits).
pub fn command(tab: ?[]const u8, data_dir: ?[]const u8) void {
    if (builtin.os.tag != .windows) return;
    const hookpipe = @import("hookpipe.zig");
    const in = hookpipe.stdinHandle();
    const buf = std.heap.page_allocator.alloc(u8, max_input) catch return hookpipe.drain(in);
    defer std.heap.page_allocator.free(buf);
    const n = hookpipe.readInput(in, buf);
    hookpipe.drain(in);
    const json = buf[0 .. n orelse return];
    var scratch: [32 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const u = extract(fba.allocator(), json) orelse extract(arena.allocator(), json);
    var out: [96]u8 = undefined;
    const line = statusText(u, &out);
    if (u) |usage| send: {
        const key = hookmsg.parseKey(tab orelse break :send) orelse break :send;
        var nb: [80:0]u16 = undefined;
        const name = hookpipe.pipeNameW(&nb, data_dir orelse break :send) orelse break :send;
        const r: Report = .{ .key = key, .usage = usage };
        var mb: [hookmsg.max_message]u8 = undefined;
        hookpipe.send(name, encode(&r, &mb)) catch {};
    }
    const w = @import("win32.zig");
    const h = w.validHandle(w.GetStdHandle(w.STD_OUTPUT_HANDLE)) orelse return;
    var wrote: w.DWORD = 0;
    _ = w.WriteFile(h, line.ptr, @intCast(line.len), &wrote, null);
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "extract: the two windows only; absent windows, absent fields, garbage" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // The documented shape, with everything around it.
    const full = extract(a,
        \\{"hook_event_name":"Status","session_id":"abc","transcript_path":"C:\\Users\\bob\\t.jsonl",
        \\ "cwd":"C:\\secret","model":{"id":"claude-x","display_name":"X"},"workspace":{"current_dir":"C:\\secret"},
        \\ "cost":{"total_cost_usd":0.01},
        \\ "rate_limits":{"five_hour":{"used_percentage":23.5,"resets_at":1738425600},
        \\   "seven_day":{"used_percentage":41.2,"resets_at":1738857600},
        \\   "spend_limit":{"used_percentage":62.8,"resets_at":1740787200,"used_usd":314.12,"limit_usd":500,"period":"monthly"}}}
    ).?;
    try testing.expectEqual(@as(u8, 23), full.five_hour.?.pct);
    try testing.expectEqual(@as(u64, 1738425600), full.five_hour.?.resets_at);
    try testing.expectEqual(@as(u8, 41), full.week.?.pct);
    try testing.expectEqual(@as(u64, 1738857600), full.week.?.resets_at);
    try testing.expect(full.limit_reached == null);
    // One window; integers; no reset time.
    const one = extract(a, "{\"rate_limits\":{\"seven_day\":{\"used_percentage\":75}}}").?;
    try testing.expect(one.five_hour == null);
    try testing.expectEqual(planusage.Window{ .pct = 75, .resets_at = 0 }, one.week.?);
    // Out of range: clamped; 99.9 is not 100.
    const clamp = extract(a, "{\"rate_limits\":{\"five_hour\":{\"used_percentage\":140,\"resets_at\":-5},\"seven_day\":{\"used_percentage\":99.9,\"resets_at\":1e300}}}").?;
    try testing.expectEqual(planusage.Window{ .pct = 100, .resets_at = 0 }, clamp.five_hour.?);
    try testing.expectEqual(planusage.Window{ .pct = 99, .resets_at = 1 << 53 }, clamp.week.?);
    // Nothing usable: API-key sessions, before the first reply, garbage.
    for ([_][]const u8{
        "{\"model\":{\"id\":\"x\"}}",
        "{\"rate_limits\":{}}",
        "{\"rate_limits\":null}",
        "{\"rate_limits\":{\"five_hour\":{\"resets_at\":5}}}",
        "{\"rate_limits\":[1,2]}",
        "not json",
        "",
        "[]",
        "{\"rate_limits\":{\"five_hour\":{\"used_percentage\":1}}",
    }) |bad| try testing.expect(extract(a, bad) == null);
}

test "extract: a leading byte order mark (Windows PowerShell 5.1's pipe) is skipped" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const u = extract(arena.allocator(), "\xEF\xBB\xBF{\"rate_limits\":{\"five_hour\":{\"used_percentage\":23,\"resets_at\":1738425600}}}").?;
    try testing.expectEqual(planusage.Window{ .pct = 23, .resets_at = 1738425600 }, u.five_hour.?);
    var buf: [96]u8 = undefined;
    try testing.expectEqualStrings("5-hour 23%", statusText(u, &buf));
    // Only one, and only at the start.
    try testing.expect(extract(arena.allocator(), "\xEF\xBB\xBF\xEF\xBB\xBF{\"rate_limits\":{\"five_hour\":{\"used_percentage\":23}}}") == null);
    try testing.expect(extract(arena.allocator(), "\xEF\xBB\xBF") == null);
}

test "extract: a huge input is bounded by the caller's scratch" {
    // A long transcript excerpt before the windows: the fixed scratch runs
    // out (null), the command then retries with an arena; neither keeps
    // anything but the two windows.
    var big: std.ArrayList(u8) = .empty;
    defer big.deinit(testing.allocator);
    try big.appendSlice(testing.allocator, "{\"junk\":[");
    for (0..20_000) |i| {
        if (i > 0) try big.append(testing.allocator, ',');
        try big.appendSlice(testing.allocator, "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"");
    }
    try big.appendSlice(testing.allocator, "],\"rate_limits\":{\"seven_day\":{\"used_percentage\":5}}}");
    var small: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&small);
    // Skipped values need no memory: even the small scratch suffices, or
    // the parse fails cleanly. Either way no crash and no partial result.
    if (extract(fba.allocator(), big.items)) |u| try testing.expectEqual(@as(u8, 5), u.week.?.pct);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqual(@as(u8, 5), extract(arena.allocator(), big.items).?.week.?.pct);
}

test "pipe message: round trip; the parser is strict" {
    const r: Report = .{ .key = @splat(0x3c), .usage = .{ .week = .{ .pct = 62, .resets_at = 1_800_000_000 }, .five_hour = .{ .pct = 0 } } };
    var buf: [hookmsg.max_message]u8 = undefined;
    const text = encode(&r, &buf);
    try testing.expectEqualStrings("portal-usage-v1\ntab=3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c\nweek=62:1800000000\nfive_hour=0:0\n", text);
    const back = parse(text).?;
    try testing.expectEqualSlices(u8, &r.key, &back.key);
    try testing.expect(r.usage.eql(back.usage));
    const tab = "tab=3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c\n";
    for ([_][]const u8{
        "portal-usage-v2\n" ++ tab ++ "week=1:0\n",
        "portal-usage-v1\n" ++ tab,
        "portal-usage-v1\nweek=1:0\n",
        "portal-usage-v1\n" ++ tab ++ "week=101:0\n",
        "portal-usage-v1\n" ++ tab ++ "week=-1:0\n",
        "portal-usage-v1\n" ++ tab ++ "week=1\n",
        "portal-usage-v1\n" ++ tab ++ "week=1:9007199254740993\n",
        "portal-usage-v1\n" ++ tab ++ "week=1:0\nweek=2:0\n",
        "portal-usage-v1\n" ++ tab ++ tab ++ "week=1:0\n",
        "portal-usage-v1\n" ++ tab ++ "week= 1:0\n",
        "portal-usage-v1\n" ++ tab ++ "noequals\n",
        // A hook message is not a usage report.
        "portal-hook-v1\n" ++ tab ++ "event=Stop\n",
    }) |bad| try testing.expect(parse(bad) == null);
    try testing.expect(parse("portal-usage-v1\n" ++ tab ++ "five_hour=100:7\nlater=1\n") != null);
    const long: [hookmsg.max_message + 1]u8 = @splat('a');
    try testing.expect(parse(&long) == null);
}

test "statusText" {
    var b: [96]u8 = undefined;
    try testing.expectEqualStrings("", statusText(null, &b));
    try testing.expectEqualStrings("5-hour 23% \u{00B7} week 41%", statusText(.{ .five_hour = .{ .pct = 23 }, .week = .{ .pct = 41 } }, &b));
    try testing.expectEqualStrings("week 9%", statusText(.{ .week = .{ .pct = 9 } }, &b));
}
