//! The plan-usage bar, desk side (docs/protocol.md section 3h,
//! docs/tabs-design.md "The plan-usage bar"):
//!
//!   * Where the numbers come from: the agent's status line. Portal gives
//!     the sessions it launches a settings file of its own with
//!     `--settings <data>\agent-statusline.json`, holding only
//!     `statusLine` = `portalctl statusline` (statusline.zig). The agent
//!     layers it over the user's settings for that session only; the
//!     user's own files are never touched, and since the file has no
//!     `hooks` key their hooks stay as they are (keys a settings layer
//!     leaves out keep their values; hook entries merge across layers).
//!     When the program setting already passes `--settings`, Portal adds
//!     nothing.
//!   * `State`: the latest windows (`report`), the limit (`limitReached`
//!     from a StopFailure hook with `error` = `rate_limit`, cleared by a
//!     later finished turn or the window's reset).
//!   * `Throttle`: per viewer, when `{"t":"usage"}` goes out: after hello,
//!     then at most once per `interval_ms`, at once when a window crosses
//!     75 %, 90 % or 100 %, or the limit changes. The viewer's loop waits
//!     for the one deadline it returns (`Decision.at`): no polling.
//!
//! Only percentages and Unix times leave the desk.

const std = @import("std");
const builtin = @import("builtin");
const planusage = @import("shared").planusage;
const Usage = planusage.Usage;
const Window = planusage.Window;

pub const interval_ms: i64 = 5 * 60 * 1000;

pub const State = struct {
    latest: Usage = .{},
    /// The limited window's `resets_at` when its limit was reached (0:
    /// unknown): a later report with another reset time is a new window.
    limit_resets_at: u64 = 0,

    pub fn known(s: *const State) bool {
        return s.latest.week != null or s.latest.five_hour != null;
    }

    /// A status line report: the windows it names replace the known ones
    /// (a window it leaves out stays as it was). A limit whose window has
    /// reset since (another reset time, or that time passed) is cleared.
    /// True if anything changed.
    pub fn report(s: *State, u: Usage, now_unix: i64) bool {
        const before = s.latest;
        if (u.week) |w| s.latest.week = w;
        if (u.five_hour) |w| s.latest.five_hour = w;
        if (s.latest.limit_reached) |k| {
            const w = s.windowOf(k);
            const reset_passed = s.limit_resets_at != 0 and now_unix >= @as(i64, @intCast(@min(s.limit_resets_at, std.math.maxInt(i63))));
            const new_window = w != null and w.?.resets_at != 0 and s.limit_resets_at != 0 and w.?.resets_at != s.limit_resets_at;
            if (reset_passed or new_window) s.clearLimit();
        }
        return !before.eql(s.latest);
    }

    /// StopFailure with `rate_limit`: the window at 100 %, else the fuller
    /// one. With no window known (an API key, before the first reply)
    /// nothing is set: there is no plan bar to show it on. True if changed.
    pub fn limitReached(s: *State) bool {
        const kind = (planusage.higher(s.latest) orelse return false).kind;
        if (s.latest.limit_reached == kind) return false;
        s.latest.limit_reached = kind;
        s.limit_resets_at = if (s.windowOf(kind)) |w| w.resets_at else 0;
        return true;
    }

    /// A turn finished normally (Stop): the agent got a reply, so no limit
    /// holds now. True if changed.
    pub fn turnDone(s: *State) bool {
        if (s.latest.limit_reached == null) return false;
        s.clearLimit();
        return true;
    }

    fn clearLimit(s: *State) void {
        s.latest.limit_reached = null;
        s.limit_resets_at = 0;
    }

    fn windowOf(s: *const State, k: planusage.WindowKind) ?Window {
        return switch (k) {
            .week => s.latest.week,
            .five_hour => s.latest.five_hour,
        };
    }
};

const band = planusage.band;

/// A change that goes out at once: a window into a higher band, or the
/// limit set, moved or cleared.
pub fn urgent(prev: Usage, next: Usage) bool {
    if (band(next.week) > band(prev.week)) return true;
    if (band(next.five_hour) > band(prev.five_hour)) return true;
    return next.limit_reached != prev.limit_reached;
}

/// One viewer's sending schedule (its write loop owns it).
pub const Throttle = struct {
    /// What this viewer got last (null: nothing yet) and when (awake ms).
    sent: ?Usage = null,
    sent_ms: i64 = 0,

    pub const Decision = union(enum) {
        /// Nothing to send (no data, or the viewer has the latest).
        idle,
        /// Send `latest` now.
        now,
        /// Send `latest` at this awake time (ms) unless something comes first.
        at: i64,
    };

    pub fn decide(t: *const Throttle, latest: Usage, now_ms: i64) Decision {
        const prev = t.sent orelse {
            // On connect: whatever is known (nothing: the bar stays hidden).
            const any = latest.week != null or latest.five_hour != null or latest.limit_reached != null;
            return if (any) .now else .idle;
        };
        if (prev.eql(latest)) return .idle;
        if (urgent(prev, latest)) return .now;
        const due = t.sent_ms +| interval_ms;
        return if (now_ms >= due) .now else .{ .at = due };
    }

    pub fn markSent(t: *Throttle, u: Usage, now_ms: i64) void {
        t.sent = u;
        t.sent_ms = now_ms;
    }
};

// ------------------------------------------------------------ settings file

pub const settings_name = "agent-statusline.json";

/// The statusLine command for `exe` (the agent runs it in a shell: Git
/// Bash or PowerShell on Windows), with forward slashes; null when the
/// path has anything a shell could read differently (spaces, quotes,
/// `$`, `&`, parentheses...): only letters, digits and `/ : . _ -`.
pub fn commandFor(exe: []const u8, buf: []u8) ?[]const u8 {
    const tail = " statusline";
    if (exe.len == 0 or exe.len + tail.len > buf.len) return null;
    for (exe, 0..) |c, i| {
        buf[i] = switch (c) {
            '\\' => '/',
            'a'...'z', 'A'...'Z', '0'...'9', '/', ':', '.', '_', '-' => c,
            else => return null,
        };
    }
    @memcpy(buf[exe.len..][0..tail.len], tail);
    return buf[0 .. exe.len + tail.len];
}

/// The settings file's content: `statusLine` and nothing else.
pub fn settingsJson(command: []const u8, buf: []u8) ![]const u8 {
    // commandFor's characters need no JSON escaping.
    return std.fmt.bufPrint(buf, "{{\"statusLine\":{{\"type\":\"command\",\"command\":\"{s}\",\"padding\":0}}}}\n", .{command});
}

/// Writes `<data_dir>\agent-statusline.json` for `portalctl.exe` next to
/// this executable and returns the file's path (caller frees), or null
/// with the reason in `why` (the bar then stays off; logged by the caller).
pub fn prepare(gpa: std.mem.Allocator, io: std.Io, data_dir: []const u8, why: *[]const u8) ?[]u8 {
    if (builtin.os.tag != .windows) return null;
    const w = @import("win32.zig");
    const fsutil = @import("fsutil.zig");
    var exe_w: [1024]u16 = undefined;
    const n = w.GetModuleFileNameW(null, &exe_w, exe_w.len);
    if (n == 0 or n >= exe_w.len) {
        why.* = "this program's path is unknown";
        return null;
    }
    const self = std.unicode.wtf16LeToWtf8Alloc(gpa, exe_w[0..n]) catch return null;
    defer gpa.free(self);
    const dir = std.fs.path.dirname(self) orelse return null;
    const exe = std.fs.path.join(gpa, &.{ dir, "portalctl.exe" }) catch return null;
    defer gpa.free(exe);
    std.Io.Dir.cwd().access(io, exe, .{}) catch {
        why.* = "portalctl.exe is not next to this program";
        return null;
    };
    var cb: [1100]u8 = undefined;
    const cmd = commandFor(exe, &cb) orelse blk: {
        // A path with spaces: its 8.3 short form, if the volume has one.
        const short = shortPath(gpa, exe) orelse break :blk null;
        defer gpa.free(short);
        break :blk commandFor(short, &cb);
    } orelse {
        why.* = "portalctl.exe's path has characters a shell would misread (and no short name)";
        return null;
    };
    var jb: [1300]u8 = undefined;
    const json = settingsJson(cmd, &jb) catch return null;
    const path = std.fs.path.join(gpa, &.{ data_dir, settings_name }) catch return null;
    fsutil.writeAtomic(gpa, io, path, json) catch {
        why.* = "the settings file could not be written";
        gpa.free(path);
        return null;
    };
    return path;
}

extern "kernel32" fn GetShortPathNameW(long: [*:0]const u16, short: [*]u16, len: u32) callconv(.winapi) u32;

fn shortPath(gpa: std.mem.Allocator, path: []const u8) ?[]u8 {
    const wide = std.unicode.wtf8ToWtf16LeAllocZ(gpa, path) catch return null;
    defer gpa.free(wide);
    var out: [1024]u16 = undefined;
    const n = GetShortPathNameW(wide.ptr, &out, out.len);
    if (n == 0 or n >= out.len) return null;
    return std.unicode.wtf16LeToWtf8Alloc(gpa, out[0..n]) catch null;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "State: reports, the limit and its clearing" {
    var s: State = .{};
    try testing.expect(!s.known());
    // A StopFailure before anything is known sets nothing.
    try testing.expect(!s.limitReached());
    try testing.expect(s.report(.{ .week = .{ .pct = 40, .resets_at = 1000 } }, 10));
    try testing.expect(!s.report(.{ .week = .{ .pct = 40, .resets_at = 1000 } }, 11));
    // A report without a window keeps the one known.
    try testing.expect(s.report(.{ .five_hour = .{ .pct = 96, .resets_at = 500 } }, 12));
    try testing.expectEqual(@as(u8, 40), s.latest.week.?.pct);
    try testing.expect(s.limitReached());
    try testing.expectEqual(planusage.WindowKind.five_hour, s.latest.limit_reached.?);
    try testing.expect(!s.limitReached());
    // Same window, before its reset: the limit holds.
    try testing.expect(!s.report(.{ .five_hour = .{ .pct = 96, .resets_at = 500 } }, 100));
    try testing.expect(s.latest.limit_reached != null);
    // Its reset time passed: cleared.
    try testing.expect(s.report(.{ .five_hour = .{ .pct = 96, .resets_at = 500 } }, 500));
    try testing.expect(s.latest.limit_reached == null);
    // A new window (another reset time) clears it too; so does a turn.
    _ = s.limitReached();
    try testing.expect(s.report(.{ .five_hour = .{ .pct = 3, .resets_at = 900 } }, 501));
    try testing.expect(s.latest.limit_reached == null);
    _ = s.limitReached();
    try testing.expectEqual(planusage.WindowKind.week, s.latest.limit_reached.?);
    try testing.expect(s.turnDone());
    try testing.expect(!s.turnDone());
}

test "Throttle: connect, 5 minutes, threshold crossings (fake clock)" {
    var t: Throttle = .{};
    const a: Usage = .{ .week = .{ .pct = 60, .resets_at = 9 } };
    // Nothing known: nothing to send, even on connect.
    try testing.expectEqual(Throttle.Decision.idle, t.decide(.{}, 0));
    // On connect: at once.
    try testing.expectEqual(Throttle.Decision.now, t.decide(a, 1000));
    t.markSent(a, 1000);
    try testing.expectEqual(Throttle.Decision.idle, t.decide(a, 2000));
    // A small change within 5 minutes: held until the deadline.
    const b: Usage = .{ .week = .{ .pct = 62, .resets_at = 9 } };
    try testing.expectEqual(Throttle.Decision{ .at = 1000 + interval_ms }, t.decide(b, 60_000));
    try testing.expectEqual(Throttle.Decision.now, t.decide(b, 1000 + interval_ms));
    t.markSent(b, 1000 + interval_ms);
    // Crossing 75: at once, whenever it was last sent.
    const c: Usage = .{ .week = .{ .pct = 75, .resets_at = 9 } };
    try testing.expectEqual(Throttle.Decision.now, t.decide(c, 1001 + interval_ms));
    t.markSent(c, 1001 + interval_ms);
    // Within the band: held again.
    const d: Usage = .{ .week = .{ .pct = 80, .resets_at = 9 } };
    try testing.expect(t.decide(d, 1002 + interval_ms) == .at);
    // 90, the five-hour window, 100, the limit: each at once.
    try testing.expectEqual(Throttle.Decision.now, t.decide(.{ .week = .{ .pct = 90, .resets_at = 9 } }, 1002 + interval_ms));
    try testing.expectEqual(Throttle.Decision.now, t.decide(.{ .week = c.week, .five_hour = .{ .pct = 75 } }, 1002 + interval_ms));
    try testing.expectEqual(Throttle.Decision.now, t.decide(.{ .week = .{ .pct = 100, .resets_at = 9 } }, 1002 + interval_ms));
    try testing.expectEqual(Throttle.Decision.now, t.decide(.{ .week = c.week, .limit_reached = .week }, 1002 + interval_ms));
    // Falling (a window reset) is not urgent.
    try testing.expect(t.decide(.{ .week = .{ .pct = 1, .resets_at = 99 } }, 1002 + interval_ms) == .at);
    // A clock far past the deadline: now.
    try testing.expectEqual(Throttle.Decision.now, t.decide(d, std.math.maxInt(i64)));
}

test "commandFor and the settings file" {
    var b: [256]u8 = undefined;
    const c = commandFor("C:\\Users\\bob\\AppData\\Local\\Portal\\bin\\portalctl.exe", &b).?;
    try testing.expectEqualStrings("C:/Users/bob/AppData/Local/Portal/bin/portalctl.exe statusline", c);
    var jb: [512]u8 = undefined;
    const j = try settingsJson(c, &jb);
    try testing.expectEqualStrings("{\"statusLine\":{\"type\":\"command\",\"command\":\"C:/Users/bob/AppData/Local/Portal/bin/portalctl.exe statusline\",\"padding\":0}}\n", j);
    // Valid JSON with exactly one key: no hooks, nothing else layered.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, j, .{});
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 1), parsed.value.object.count());
    try testing.expect(parsed.value.object.get("hooks") == null);
    for ([_][]const u8{ "C:\\Program Files\\p.exe", "C:\\a&b\\p.exe", "C:\\$x\\p.exe", "C:\\a(1)\\p.exe", "C:\\a'b\\p.exe", "C:\\a\"b\\p.exe", "" }) |bad|
        try testing.expect(commandFor(bad, &b) == null);
}
