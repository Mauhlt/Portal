//! "For you" and recap on a viewer's interactive WebSocket (docs/protocol.md
//! sections 3g, 4a, 4b): the `i:yes <id>` / `i:no <id>` and `r:recap <tab>`
//! frames, and the `foryou` messages a viewer's writer sends. web.zig only
//! calls in; the cards themselves are foryou_desk.zig's, per tab.
//!
//! An answer:
//!   * names a current card of any open tab, else `stale` (replaced,
//!     answered elsewhere, gone, malformed: all the same, nothing echoed);
//!   * is allowed by the desk's input mode for devices (Effect.allowedIn),
//!     else `refused`;
//!   * is rate limited per device (`max_per_minute`, both families
//!     together), else `rate_limited`;
//!   * then does what its kind says, through the tab's own input paths: a
//!     suggestion's yes types the fixed message (foryou.runMessage /
//!     gotoMessage) as an instruction line (Session.writeWebLine, under the
//!     line rules), a permission card's yes / no presses `1` / `esc`
//!     (Session.writeWebKey, as the permission card does), a question's yes
//!     / no types "Yes." / "No."; anything else dismisses. Answered or
//!     dismissed, the card is gone for every device.
//! A recap types recap.prompt into the tab as an instruction line (input
//! mode `instruct` or `text`, the agent's tabs only, at most one per tab
//! a minute: foryou_desk.recap_interval_ms). An instruction line that is
//! exactly `recap` does the same for the tab the viewer watches.

const std = @import("std");
const Io = std.Io;
const shared = @import("shared");
const foryou = shared.foryou;
const recap = shared.recap;
const frames = shared.frames;
const tabs = @import("tabs.zig");
const devices = @import("devices.zig");
const Log = @import("log.zig").Log;
const foryou_desk = @import("foryou_desk.zig");
const ratelimit = @import("ratelimit.zig");

/// Requests (`i:` and `r:`) one device may make in a minute.
pub const max_per_minute = 30;
const window_ms: i64 = 60_000;

/// Per-device request windows, for every connection of the device
/// together (both families count in the one lane).
pub const Limits = ratelimit.PerDevice(enum { request }, max_per_minute, window_ms);

/// Who asks, and where.
pub const Ctx = struct {
    hub: *tabs.Hub,
    limits: *Limits,
    log: *Log,
    device: devices.DeviceId,
    device_name: []const u8,
    now_ms: i64,
};

/// The answer to an `i:` or `r:` frame (`fr` from frames.classify), in `buf`.
pub fn handle(c: Ctx, fr: frames.Frame, buf: *[frames.max_answer]u8) []const u8 {
    return switch (fr.prefix) {
        .item => item(c, fr.rest, buf),
        .recap => recapFrame(c, fr.rest, buf),
        else => unreachable,
    };
}

/// An instruction line that asks for a recap instead (`recap`, exactly).
pub fn isRecapLine(line: []const u8) bool {
    return std.mem.eql(u8, line, "recap");
}

fn answerItem(buf: *[frames.max_answer]u8, op: foryou.Op, r: foryou.Result, id: ?foryou.Id) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    foryou.writeResult(&w, op, r, id) catch unreachable;
    return w.buffered();
}

fn answerRecap(buf: *[frames.max_answer]u8, r: recap.Result, tab: ?tabs.Id) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    recap.writeResult(&w, r, tab) catch unreachable;
    return w.buffered();
}

fn policyName(h: *const tabs.Hub) []const u8 {
    return @tagName(h.policy);
}

fn item(c: Ctx, rest: []const u8, buf: *[frames.max_answer]u8) []const u8 {
    const h = c.hub;
    const req = foryou.parseRequest(rest) orelse
        return answerItem(buf, if (std.mem.startsWith(u8, rest, "no ")) .no else .yes, .stale, null);
    if (!c.limits.allow(h.io, c.device, .request, c.now_ms).ok) return answerItem(buf, req.op, .rate_limited, null);

    // The card, of whichever open tab holds it.
    h.mutex.lockUncancelable(h.io);
    var tab: ?*tabs.Tab = null;
    var taken: foryou_desk.Taken = undefined;
    for (h.tabs[0..h.n]) |t| if (t.foryou.take(req.id)) |tk| {
        t.acquire();
        tab = t;
        taken = tk;
        break;
    };
    h.mutex.unlock(h.io);
    const t = tab orelse return answerItem(buf, req.op, .stale, null);
    defer t.release();
    const it = &taken.item;
    const effect = it.kind.effect(req.op);
    if (!effect.allowedIn(policyName(h))) return answerItem(buf, req.op, .refused, it.id);

    const result: foryou.Result = switch (effect) {
        .dismiss => .dismissed,
        .send_message => blk: {
            var mb: [foryou.max_cmd + 16]u8 = undefined;
            var gb: [foryou.max_name + 40]u8 = undefined;
            const msg = (if (it.kind == .suggest_run) foryou.runMessage(it.cmd(), &mb) else foryou.gotoMessage(it.project(), &gb)) orelse break :blk .failed;
            t.session.writeWebLine(msg) catch break :blk .failed;
            break :blk .sent;
        },
        .answer => blk: {
            if (it.kind == .waiting_permission) {
                t.session.writeWebKey(if (req.op == .yes) "1" else "esc", c.now_ms) catch break :blk .failed;
            } else {
                t.session.writeDeskLine(if (req.op == .yes) "Yes." else "No.") catch break :blk .failed;
            }
            break :blk .sent;
        },
    };
    if (result.ok()) t.forYouDismiss(taken.sig);
    c.log.print("for you: device '{s}' answered {t} {t} in tab '{s}': {t}", .{ c.device_name, it.kind, req.op, t.name(), result });
    return answerItem(buf, req.op, result, it.id);
}


fn recapFrame(c: Ctx, rest: []const u8, buf: *[frames.max_answer]u8) []const u8 {
    const id = recap.parseRequest(rest) orelse return answerRecap(buf, .unknown, null);
    const h = c.hub;
    h.mutex.lockUncancelable(h.io);
    const t = h.acquireLocked(id);
    h.mutex.unlock(h.io);
    const tab = t orelse {
        // Counted like any request, so probing costs the same.
        _ = c.limits.allow(h.io, c.device, .request, c.now_ms);
        return answerRecap(buf, .unknown, null);
    };
    defer tab.release();
    return recapTab(c, tab, buf);
}

/// A recap for open tab `t` (`r:recap`, or the line `recap` for the tab
/// watched; null: none watched).
pub fn recapTab(c: Ctx, tab: ?*tabs.Tab, buf: *[frames.max_answer]u8) []const u8 {
    const h = c.hub;
    if (!c.limits.allow(h.io, c.device, .request, c.now_ms).ok) return answerRecap(buf, .rate_limited, null);
    const t = tab orelse return answerRecap(buf, .unknown, null);
    if ((h.policy != .instruct and h.policy != .text) or h.program.device_start == .not_agent)
        return answerRecap(buf, .refused, t.id);
    h.mutex.lockUncancelable(h.io);
    const open = !t.removed and !t.session.closed;
    const allowed = open and t.foryou.recapAllowed(c.now_ms);
    h.mutex.unlock(h.io);
    if (!open) return answerRecap(buf, .unknown, null);
    if (!allowed) return answerRecap(buf, .rate_limited, t.id);
    t.session.writeWebLine(recap.prompt) catch return answerRecap(buf, .refused, t.id);
    c.log.print("for you: device '{s}' asked tab '{s}' for a recap", .{ c.device_name, t.name() });
    return answerRecap(buf, .ok, t.id);
}

// ------------------------------------------------------------ the writer

/// One viewer's `foryou` messages: every open tab's cards after hello,
/// then each tab whose cards changed (the hub's generation and each tab's
/// own, foryou_desk.State.gen). Filled under the hub's lock, sent after.
pub const Outbox = struct {
    out: std.Io.Writer.Allocating,
    ends: std.ArrayList(usize) = .empty,
    gpa: std.mem.Allocator,
    /// The hub's For-you generation last sent (0: nothing yet).
    seen: u64 = 0,

    pub fn init(gpa: std.mem.Allocator) Outbox {
        return .{ .out = .init(gpa), .gpa = gpa };
    }

    pub fn deinit(o: *Outbox) void {
        o.out.deinit();
        o.ends.deinit(o.gpa);
    }

    /// Caller holds the hub's mutex: something to send.
    pub fn due(o: *const Outbox, h: *const tabs.Hub) bool {
        return h.foryou_gen != o.seen;
    }

    /// Caller holds the hub's mutex.
    pub fn fill(o: *Outbox, h: *const tabs.Hub) !void {
        o.out.clearRetainingCapacity();
        o.ends.clearRetainingCapacity();
        if (!o.due(h)) return;
        for (h.tabs[0..h.n]) |t| {
            if (o.seen != 0 and t.foryou.gen <= o.seen) continue;
            try foryou.write(&o.out.writer, t.id, t.foryou.list.slice());
            try o.ends.append(o.gpa, o.out.written().len);
        }
        o.seen = h.foryou_gen;
    }

    pub const Iterator = struct {
        o: *Outbox,
        i: usize = 0,
        pub fn next(it: *Iterator) ?[]const u8 {
            if (it.i >= it.o.ends.items.len) return null;
            const start = if (it.i == 0) 0 else it.o.ends.items[it.i - 1];
            const end = it.o.ends.items[it.i];
            it.i += 1;
            return it.o.out.written()[start..end];
        }
    };

    pub fn messages(o: *Outbox) Iterator {
        return .{ .o = o };
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "limits: per device, a minute's window" {
    var l: Limits = .{};
    const a: devices.DeviceId = @splat(1);
    const b: devices.DeviceId = @splat(2);
    for (0..max_per_minute) |i| try testing.expect(l.allow(testing.io, a, .request, @intCast(i)).ok);
    try testing.expect(!l.allow(testing.io, a, .request, 100).ok);
    try testing.expect(l.allow(testing.io, b, .request, 100).ok);
    try testing.expect(l.allow(testing.io, a, .request, window_ms + 1).ok);
}

test "the recap line is exactly `recap`" {
    try testing.expect(isRecapLine("recap"));
    try testing.expect(!isRecapLine("Recap"));
    try testing.expect(!isRecapLine("recap please"));
}
