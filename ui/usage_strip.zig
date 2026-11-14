//! The plan-usage strip (docs/layout-design.md, "The usage strip";
//! docs/protocol.md section 3h): a thin line above the top bar on every
//! screen, desk and devices alike, "Week 62% · resets Mon" over a slim
//! meter, showing whichever window is closer to its limit. Neutral below
//! 75 %, amber from 75, red from 90 (and at the limit). A tap toggles the
//! detail: both windows with their meters and reset times. A toast says
//! once when a window passes 75 % or 90 %, or the limit is reached. No
//! data (API-key sessions, nothing reported yet): no strip.
//!
//! Pure: the glue hands it the latest `planusage.Usage`, the time and
//! the local time zone's offset; it gives back a frame.UsageStrip, a
//! toast and the toast's deadline (the glue's one wake for it).

const std = @import("std");
const planusage = @import("shared").planusage;
const frame = @import("frame.zig");

const Usage = planusage.Usage;
const Kind = planusage.WindowKind;

pub const toast_ms: i64 = 6000;

pub const Strip = struct {
    /// The detail is open (a tap toggles it).
    expanded: bool = false,
    /// Per window: the highest step already told (1: 75 %, 2: 90 %) for
    /// the window with this reset time (a new window starts over).
    told: [2]Told = .{ .{}, .{} },
    told_limit: ?Kind = null,
    toast_buf: [96]u8 = undefined,
    toast_len: usize = 0,
    toast_tone: frame.Tone = .warn,
    toast_until: i64 = 0,
    bufs: Bufs = .{},

    const Told = struct { step: u8 = 0, resets_at: u64 = 0 };

    const Bufs = struct {
        label: [96]u8 = undefined,
        names: [2][32]u8 = undefined,
        rights: [2][48]u8 = undefined,
        rows: [2]frame.UsageRow = undefined,
    };

    pub fn toggle(s: *Strip) void {
        s.expanded = !s.expanded;
    }

    /// Notes what `u` crossed since last time (the one-time toasts).
    /// Call with every new value; `now_ms` on the glue's awake clock.
    pub fn update(s: *Strip, u: ?Usage, now_ms: i64, now_unix: i64, utc_offset_s: i32) void {
        const x = u orelse return;
        var told_now: ?struct { kind: Kind, step: u8 } = null;
        inline for (.{ Kind.week, Kind.five_hour }) |k| {
            if (@field(x, @tagName(k))) |w| {
                const t = &s.told[@intFromEnum(k)];
                if (w.resets_at != t.resets_at) t.* = .{ .resets_at = w.resets_at };
                const step = @min(planusage.band(w), 2);
                if (step > t.step) {
                    t.step = step;
                    if (told_now == null or step > told_now.?.step) told_now = .{ .kind = k, .step = step };
                }
            }
        }
        if (x.limit_reached != s.told_limit) {
            s.told_limit = x.limit_reached;
            if (x.limit_reached) |k| {
                var rb: [32]u8 = undefined;
                const r = resetText(windowOf(x, k), now_unix, utc_offset_s, false, &rb);
                s.setToast(.bad, now_ms, "{s} limit reached{s}{s}", .{ kindName(k), if (r.len > 0) " \u{00B7} " else "", r });
                return;
            }
        }
        if (told_now) |t| s.setToast(if (t.step >= 2) .bad else .warn, now_ms, "{s} usage passed {d}%", .{ kindName(t.kind), @as(u8, if (t.step >= 2) 90 else 75) });
    }

    fn setToast(s: *Strip, t_tone: frame.Tone, now_ms: i64, comptime fmt: []const u8, args: anytype) void {
        const t = std.fmt.bufPrint(&s.toast_buf, fmt, args) catch return;
        s.toast_len = t.len;
        s.toast_tone = t_tone;
        s.toast_until = now_ms + toast_ms;
    }

    pub fn toast(s: *const Strip, now_ms: i64) ?frame.Toast {
        if (s.toast_len == 0 or now_ms >= s.toast_until) return null;
        return .{ .text = s.toast_buf[0..s.toast_len], .tone = s.toast_tone };
    }

    /// Milliseconds until the toast goes (the glue wakes then); null: none.
    pub fn deadline(s: *const Strip, now_ms: i64) ?u32 {
        if (s.toast_len == 0 or now_ms >= s.toast_until) return null;
        return @intCast(@min(s.toast_until - now_ms, toast_ms));
    }

    /// The strip for `u` (null: hidden, nothing known).
    pub fn strip(s: *Strip, u: ?Usage, id: u32, now_unix: i64, utc_offset_s: i32) ?frame.UsageStrip {
        const x = u orelse return null;
        const top = planusage.higher(x) orelse return null;
        const b = &s.bufs;
        const limited = x.limit_reached;
        const shown_kind = limited orelse top.kind;
        const shown = windowOf(x, shown_kind) orelse top.window;
        var rb: [32]u8 = undefined;
        const r = resetText(shown, now_unix, utc_offset_s, false, &rb);
        const label = if (limited != null)
            std.fmt.bufPrint(&b.label, "{s} limit reached{s}{s}", .{ kindName(shown_kind), if (r.len > 0) " \u{00B7} " else "", r }) catch ""
        else
            std.fmt.bufPrint(&b.label, "{s} {d}%{s}{s}", .{ kindName(shown_kind), shown.pct, if (r.len > 0) " \u{00B7} " else "", r }) catch "";
        var out: frame.UsageStrip = .{
            .label = label,
            .pct = if (limited != null) 100 else shown.pct,
            .tone = if (limited != null) .bad else tone(shown.pct),
            .id = id,
        };
        if (s.expanded) {
            var n: usize = 0;
            inline for (.{ Kind.week, Kind.five_hour }) |k| {
                if (@field(x, @tagName(k))) |w| {
                    const lim = limited == k;
                    var rr: [32]u8 = undefined;
                    const rt = resetText(w, now_unix, utc_offset_s, true, &rr);
                    b.rows[n] = .{
                        .name = std.fmt.bufPrint(&b.names[n], "{s} {d}%", .{ kindName(k), if (lim) 100 else w.pct }) catch kindName(k),
                        .pct = if (lim) 100 else w.pct,
                        .tone = if (lim) .bad else tone(w.pct),
                        .right = if (rt.len > 0) (std.fmt.bufPrint(&b.rights[n], "{s}", .{rt}) catch "") else "",
                    };
                    n += 1;
                }
            }
            out.rows = b.rows[0..n];
            out.note = "From Claude Code. Refreshed when this device connects and at most every 5 minutes. Tap to close.";
        }
        return out;
    }
};

pub fn tone(pct: u8) frame.Tone {
    return switch (planusage.band(.{ .pct = pct })) {
        0 => .muted,
        1 => .warn,
        else => .bad,
    };
}

fn kindName(k: Kind) []const u8 {
    return switch (k) {
        .week => "Week",
        .five_hour => "5-hour",
    };
}

fn windowOf(u: Usage, k: Kind) ?planusage.Window {
    return switch (k) {
        .week => u.week,
        .five_hour => u.five_hour,
    };
}

const day_names = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" }; // 1970-01-01 was a Thursday

/// "resets 14:20" within a day, "resets Mon" further out ("resets Mon
/// 09:00" with `full`), local time; "" when the reset time is unknown.
pub fn resetText(w: ?planusage.Window, now_unix: i64, utc_offset_s: i32, full: bool, buf: []u8) []const u8 {
    const win = w orelse return "";
    if (win.resets_at == 0) return "";
    const t: i64 = @intCast(@min(win.resets_at, std.math.maxInt(i48)));
    const local = t + utc_offset_s;
    const day = @divFloor(local, 86400);
    const secs = @mod(local, 86400);
    const hh: u32 = @intCast(@divFloor(secs, 3600));
    const mm: u32 = @intCast(@divFloor(@mod(secs, 3600), 60));
    const name = day_names[@intCast(@mod(day, 7))];
    if (t - now_unix < 86400) return std.fmt.bufPrint(buf, "resets {d:0>2}:{d:0>2}", .{ hh, mm }) catch "";
    if (full) return std.fmt.bufPrint(buf, "resets {s} {d:0>2}:{d:0>2}", .{ name, hh, mm }) catch "";
    return std.fmt.bufPrint(buf, "resets {s}", .{name}) catch "";
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

// 2026-11-16 (a Monday) 09:00 UTC.
const monday_9: u64 = 1794819600;

test "resetText: time within a day, weekday further out, local offset" {
    var b: [32]u8 = undefined;
    try testing.expectEqualStrings("resets 09:00", resetText(.{ .pct = 1, .resets_at = monday_9 }, @intCast(monday_9 - 3600), 0, false, &b));
    try testing.expectEqualStrings("resets 10:00", resetText(.{ .pct = 1, .resets_at = monday_9 }, @intCast(monday_9 - 3600), 3600, false, &b));
    try testing.expectEqualStrings("resets Mon", resetText(.{ .pct = 1, .resets_at = monday_9 }, @intCast(monday_9 - 3 * 86400), 0, false, &b));
    try testing.expectEqualStrings("resets Mon 09:00", resetText(.{ .pct = 1, .resets_at = monday_9 }, @intCast(monday_9 - 3 * 86400), 0, true, &b));
    // West of UTC at 02:00 UTC: still Sunday locally.
    try testing.expectEqualStrings("resets Sun", resetText(.{ .pct = 1, .resets_at = monday_9 - 7 * 3600 }, @intCast(monday_9 - 3 * 86400), -5 * 3600, false, &b));
    try testing.expectEqualStrings("", resetText(.{ .pct = 1 }, 0, 0, false, &b));
    try testing.expectEqualStrings("", resetText(null, 0, 0, false, &b));
}

test "strip: the higher window, tones, the limit, hidden without data" {
    var s: Strip = .{};
    const now: i64 = @intCast(monday_9 - 3 * 86400);
    try testing.expect(s.strip(null, 7, now, 0) == null);
    try testing.expect(s.strip(.{}, 7, now, 0) == null);
    const a = s.strip(.{ .week = .{ .pct = 62, .resets_at = monday_9 }, .five_hour = .{ .pct = 38 } }, 7, now, 0).?;
    try testing.expectEqualStrings("Week 62% \u{00B7} resets Mon", a.label);
    try testing.expectEqual(frame.Tone.muted, a.tone);
    try testing.expectEqual(@as(u32, 7), a.id);
    try testing.expectEqual(@as(usize, 0), a.rows.len);
    try testing.expectEqual(frame.Tone.warn, s.strip(.{ .week = .{ .pct = 81 } }, 7, now, 0).?.tone);
    const r = s.strip(.{ .week = .{ .pct = 94 }, .five_hour = .{ .pct = 97, .resets_at = @intCast(now + 3600) } }, 7, now, 0).?;
    try testing.expect(std.mem.startsWith(u8, r.label, "5-hour 97% \u{00B7} resets "));
    try testing.expectEqual(frame.Tone.bad, r.tone);
    const lim = s.strip(.{ .week = .{ .pct = 99 }, .five_hour = .{ .pct = 40 }, .limit_reached = .week }, 7, now, 0).?;
    try testing.expectEqualStrings("Week limit reached", lim.label);
    try testing.expectEqual(@as(u8, 100), lim.pct);
    // The detail: both windows.
    s.toggle();
    const d = s.strip(.{ .week = .{ .pct = 62, .resets_at = monday_9 }, .five_hour = .{ .pct = 38 } }, 7, now, 0).?;
    try testing.expectEqual(@as(usize, 2), d.rows.len);
    try testing.expectEqualStrings("Week 62%", d.rows[0].name);
    try testing.expectEqualStrings("resets Mon 09:00", d.rows[0].right);
    try testing.expectEqualStrings("5-hour 38%", d.rows[1].name);
    try testing.expectEqualStrings("", d.rows[1].right);
    try testing.expect(d.note.len > 0);
}

test "toasts: once per crossing, per window; the limit; the deadline" {
    var s: Strip = .{};
    s.update(.{ .week = .{ .pct = 60, .resets_at = 5 } }, 0, 0, 0);
    try testing.expect(s.toast(0) == null);
    try testing.expect(s.deadline(0) == null);
    s.update(.{ .week = .{ .pct = 76, .resets_at = 5 } }, 1000, 0, 0);
    try testing.expectEqualStrings("Week usage passed 75%", s.toast(1000).?.text);
    try testing.expectEqual(@as(u32, toast_ms), s.deadline(1000).?);
    try testing.expect(s.toast(1000 + toast_ms) == null);
    // The same step again: no second toast.
    s.update(.{ .week = .{ .pct = 80, .resets_at = 5 } }, 9000, 0, 0);
    try testing.expect(s.toast(9000) == null);
    // 90 %, then the other window's 75 %.
    s.update(.{ .week = .{ .pct = 91, .resets_at = 5 } }, 20_000, 0, 0);
    try testing.expectEqualStrings("Week usage passed 90%", s.toast(20_000).?.text);
    try testing.expectEqual(frame.Tone.bad, s.toast(20_000).?.tone);
    s.update(.{ .week = .{ .pct = 91, .resets_at = 5 }, .five_hour = .{ .pct = 75 } }, 40_000, 0, 0);
    try testing.expectEqualStrings("5-hour usage passed 75%", s.toast(40_000).?.text);
    // A new week (another reset time) starts over.
    s.update(.{ .week = .{ .pct = 76, .resets_at = 99 }, .five_hour = .{ .pct = 75 } }, 60_000, 0, 0);
    try testing.expectEqualStrings("Week usage passed 75%", s.toast(60_000).?.text);
    // The limit, once.
    s.update(.{ .week = .{ .pct = 76, .resets_at = 99 }, .five_hour = .{ .pct = 100 }, .limit_reached = .five_hour }, 80_000, 0, 0);
    try testing.expectEqualStrings("5-hour limit reached", s.toast(80_000).?.text);
    s.update(.{ .week = .{ .pct = 76, .resets_at = 99 }, .five_hour = .{ .pct = 100 }, .limit_reached = .five_hour }, 99_000, 0, 0);
    try testing.expect(s.toast(99_000) == null);
}
