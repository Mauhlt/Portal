//! The plan-usage bar on the wire (docs/protocol.md section 3h): how much
//! of the owner's plan limits is used, per window, as the desk knows it.
//! Not token counts (those are `activity`, section 3c): percentages and
//! reset times only.
//!
//!   {"t":"usage"[,"week":WINDOW][,"five_hour":WINDOW]
//!    [,"limit_reached":"week"|"five_hour"]}
//!   WINDOW = {"pct":<0..100>[,"resets_at":<unix s>]}
//!
//! A window that is absent is unknown. When the desk sends it (on connect,
//! at most once per 5 minutes, at once on crossing 75 %, 90 % or the
//! limit) is the desk's business; this is the message and its codec only.

const std = @import("std");
const convo = @import("convo.zig");

pub const WindowKind = enum { week, five_hour };

pub const Window = struct {
    /// Percent used, 0..100.
    pct: u8 = 0,
    /// When the window resets (unix seconds); 0: unknown.
    resets_at: u64 = 0,
};

pub const Usage = struct {
    week: ?Window = null,
    five_hour: ?Window = null,
    limit_reached: ?WindowKind = null,

    pub fn eql(a: Usage, b: Usage) bool {
        return std.meta.eql(a, b);
    }
};

/// Room for any `usage` message.
pub const max_message = 160;

pub fn write(w: *std.Io.Writer, u: Usage) !void {
    try w.writeAll("{\"t\":\"usage\"");
    inline for (.{ "week", "five_hour" }) |name| {
        if (@field(u, name)) |win| {
            try w.print(",\"" ++ name ++ "\":{{\"pct\":{d}", .{@min(win.pct, 100)});
            if (win.resets_at != 0) try w.print(",\"resets_at\":{d}", .{@min(win.resets_at, 1 << 53)});
            try w.writeByte('}');
        }
    }
    if (u.limit_reached) |l| try w.print(",\"limit_reached\":\"{s}\"", .{@tagName(l)});
    try w.writeByte('}');
}

/// A `usage` message, or null if it is not one or is malformed in any way
/// (a percentage over 100, a field twice, an unknown window name). Unknown
/// scalar fields are ignored.
pub fn parse(text: []const u8) ?Usage {
    if (text.len > 4 * max_message) return null;
    var sbuf: [4 * max_message]u8 = undefined;
    var p: convo.Parser = .{ .s = text, .out = &sbuf };
    var u: Usage = .{};
    var have_t = false;
    var have_limit = false;
    p.ws();
    if (!p.eat('{')) return null;
    var first = true;
    while (true) {
        p.ws();
        if (p.eat('}')) break;
        if (!first and !p.eat(',')) return null;
        first = false;
        p.ws();
        p.o = 0;
        const key = p.string() orelse return null;
        p.ws();
        if (!p.eat(':')) return null;
        p.ws();
        if (std.mem.eql(u8, key, "t")) {
            if (have_t) return null;
            p.o = 0;
            if (!std.mem.eql(u8, p.string() orelse return null, "usage")) return null;
            have_t = true;
        } else if (std.mem.eql(u8, key, "week")) {
            if (u.week != null) return null;
            u.week = parseWindow(&p) orelse return null;
        } else if (std.mem.eql(u8, key, "five_hour")) {
            if (u.five_hour != null) return null;
            u.five_hour = parseWindow(&p) orelse return null;
        } else if (std.mem.eql(u8, key, "limit_reached")) {
            if (have_limit) return null;
            have_limit = true;
            p.o = 0;
            u.limit_reached = std.meta.stringToEnum(WindowKind, p.string() orelse return null) orelse return null;
        } else {
            p.o = 0;
            if (!p.scalar()) return null;
        }
    }
    p.ws();
    if (p.i != text.len or !have_t) return null;
    return u;
}

fn parseWindow(p: *convo.Parser) ?Window {
    if (!p.eat('{')) return null;
    var win: Window = .{};
    var have_pct = false;
    var have_reset = false;
    var first = true;
    while (true) {
        p.ws();
        if (p.eat('}')) break;
        if (!first and !p.eat(',')) return null;
        first = false;
        p.ws();
        p.o = 0;
        const key = p.string() orelse return null;
        p.ws();
        if (!p.eat(':')) return null;
        p.ws();
        if (std.mem.eql(u8, key, "pct")) {
            if (have_pct) return null;
            const v = p.number() orelse return null;
            if (v > 100) return null;
            win.pct = @intCast(v);
            have_pct = true;
        } else if (std.mem.eql(u8, key, "resets_at")) {
            if (have_reset) return null;
            win.resets_at = p.number64() orelse return null;
            have_reset = true;
        } else {
            p.o = 0;
            if (!p.scalar()) return null;
        }
    }
    return if (have_pct) win else null;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "round trip" {
    const cases = [_]Usage{
        .{},
        .{ .week = .{ .pct = 42, .resets_at = 1_800_000_000 } },
        .{ .five_hour = .{ .pct = 100 }, .limit_reached = .five_hour },
        .{ .week = .{ .pct = 100, .resets_at = 1 << 53 }, .five_hour = .{ .pct = 0, .resets_at = 7 }, .limit_reached = .week },
    };
    for (cases) |u| {
        var buf: [max_message]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try write(&w, u);
        try testing.expect(u.eql(parse(w.buffered()).?));
    }
    var buf: [max_message]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try write(&w, .{ .week = .{ .pct = 75, .resets_at = 9 } });
    try testing.expectEqualStrings("{\"t\":\"usage\",\"week\":{\"pct\":75,\"resets_at\":9}}", w.buffered());
    // Unknown scalars are ignored, in the message and in a window.
    const u = parse("{ \"t\":\"usage\", \"week\":{\"pct\":5,\"src\":\"x\"}, \"later\":true }").?;
    try testing.expectEqual(@as(u8, 5), u.week.?.pct);
}

test "malformed messages are rejected" {
    for ([_][]const u8{
        "{\"week\":{\"pct\":1}}",
        "{\"t\":\"activity\"}",
        "{\"t\":\"usage\",\"week\":{\"pct\":101}}",
        "{\"t\":\"usage\",\"week\":{\"pct\":-1}}",
        "{\"t\":\"usage\",\"week\":{\"pct\":1.5}}",
        "{\"t\":\"usage\",\"week\":{\"resets_at\":1}}",
        "{\"t\":\"usage\",\"week\":{\"pct\":1},\"week\":{\"pct\":2}}",
        "{\"t\":\"usage\",\"week\":{\"pct\":1,\"pct\":2}}",
        "{\"t\":\"usage\",\"week\":{\"pct\":\"1\"}}",
        "{\"t\":\"usage\",\"week\":{\"pct\":1,\"x\":{}}}",
        "{\"t\":\"usage\",\"limit_reached\":\"month\"}",
        "{\"t\":\"usage\",\"limit_reached\":\"week\",\"limit_reached\":\"week\"}",
        "{\"t\":\"usage\",\"week\":{\"pct\":1,\"resets_at\":9007199254740993}}",
        "{\"t\":\"usage\"",
        "{\"t\":\"usage\"}x",
    }) |bad| try testing.expect(parse(bad) == null);
}
