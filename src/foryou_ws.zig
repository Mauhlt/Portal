//! "For you" and recap answers (docs/protocol.md sections 3g, 4a, 4b): the
//! `i:yes <id>` / `i:no <id>` and `r:recap <tab>` frames, from a viewer's
//! interactive WebSocket (web.zig) or from the desk's own window (gui.zig,
//! in process: its For-you panel's frames come straight here), and the
//! `foryou` messages a viewer's writer sends. The cards themselves are
//! foryou_desk.zig's, per tab. Both sources take the one code path
//! (`handle`); only `From` differs.
//!
//! An answer:
//!   * names a current card of any open tab, else `stale` (replaced,
//!     answered elsewhere, gone, malformed: all the same, nothing echoed);
//!   * is allowed by the input mode (Effect.allowedIn): a device's is the
//!     desk's input mode for devices; the desk's own is `text` (the owner
//!     at the keyboard may do anything a `text`-mode device could), else
//!     `refused`;
//!   * from a device, is rate limited per device (`max_per_minute`, both
//!     families together), else `rate_limited`; the desk's is not;
//!   * then does what its kind says, through the tab's own input paths: a
//!     suggestion's yes types the fixed message (foryou.runMessage /
//!     gotoMessage) as an instruction line (Session.writeWebLine from a
//!     device, writeDeskLine from the desk: the line rules either way), a
//!     permission card's yes / no presses `1` / `esc` (Session.writeWebKey,
//!     as the permission card does; from the desk, the keys its Instruct
//!     panel types; only a prompt whose `1` is a plain one-time yes is
//!     such a card), a question's yes / no types the desk's fixed line
//!     "Yes." / "No." (Session.writeDeskLine from either source, since
//!     `keys` mode may answer a question but writeWebLine refuses it);
//!     anything else dismisses. The card is claimed (gone for every
//!     device and the desk) under the hub's lock before anything is
//!     typed, so a second answer to it is `stale`; one that could not be
//!     delivered (`failed`) comes back.
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
const keymap = @import("keymap.zig");
const rules = @import("inputrules");

/// Requests (`i:` and `r:`) one device may make in a minute.
pub const max_per_minute = 30;
const window_ms: i64 = 60_000;

/// Per-device request windows, for every connection of the device
/// together (both families count in the one lane).
pub const Limits = ratelimit.PerDevice(enum { request }, max_per_minute, window_ms);

/// Who asks: a paired device (its connection's), or the desk's own window.
pub const From = union(enum) {
    device: struct {
        limits: *Limits,
        id: devices.DeviceId,
        name: []const u8,
    },
    desk,
};

/// Who asks, and where.
pub const Ctx = struct {
    hub: *tabs.Hub,
    log: *Log,
    from: From,
    now_ms: i64,

    /// The input mode the answer is checked against: the desk's for
    /// devices, or `text` for the desk itself.
    pub fn policy(c: Ctx) keymap.Policy {
        return switch (c.from) {
            .device => c.hub.policy,
            .desk => .text,
        };
    }

    /// Counts one request (the desk's are not limited).
    fn allow(c: Ctx) bool {
        return switch (c.from) {
            .device => |d| d.limits.allow(c.hub.io, d.id, .request, c.now_ms).ok,
            .desk => true,
        };
    }

    /// Who, for the log.
    fn who(c: Ctx, buf: []u8) []const u8 {
        return switch (c.from) {
            .device => |d| std.fmt.bufPrint(buf, "device '{s}'", .{d.name}) catch "a device",
            .desk => "the desk",
        };
    }

    /// An instruction line into tab `t`, as this source types one.
    fn line(c: Ctx, t: *tabs.Tab, text: []const u8) !void {
        return switch (c.from) {
            .device => t.session.writeWebLine(text),
            .desk => t.session.writeDeskLine(text),
        };
    }

    /// A named key (`1`, `esc`) into tab `t`, as this source presses one.
    fn key(c: Ctx, t: *tabs.Tab, name: []const u8) !void {
        switch (c.from) {
            .device => try t.session.writeWebKey(name, c.now_ms),
            .desk => t.session.writeInput(rules.keyBytes(.text, name) orelse return error.UnknownKey),
        }
    }
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

fn item(c: Ctx, rest: []const u8, buf: *[frames.max_answer]u8) []const u8 {
    const h = c.hub;
    const req = foryou.parseRequest(rest) orelse
        return answerItem(buf, if (std.mem.startsWith(u8, rest, "no ")) .no else .yes, .stale, null);
    if (!c.allow()) return answerItem(buf, req.op, .rate_limited, null);

    // The card, of whichever open tab holds it, claimed under the hub's
    // lock (gone for everyone at once), so two answers to one card can't
    // both reach the agent: the second finds nothing (`stale`).
    h.mutex.lockUncancelable(h.io);
    var tab: ?*tabs.Tab = null;
    var taken: foryou_desk.Taken = undefined;
    var refused = false;
    for (h.tabs[0..h.n]) |t| if (t.foryou.take(req.id)) |tk| {
        taken = tk;
        if (!tk.item.kind.effect(req.op).allowedIn(@tagName(c.policy()))) {
            refused = true;
            break;
        }
        _ = t.foryou.claim(h.io, req.id);
        t.forYouChangedLocked();
        t.acquire();
        tab = t;
        break;
    };
    h.mutex.unlock(h.io);
    if (refused) return answerItem(buf, req.op, .refused, taken.item.id);
    const t = tab orelse return answerItem(buf, req.op, .stale, null);
    defer t.release();
    h.broadcast();
    const it = &taken.item;
    const effect = it.kind.effect(req.op);

    const result: foryou.Result = switch (effect) {
        .dismiss => .dismissed,
        .send_message => blk: {
            var mb: [foryou.max_cmd + 16]u8 = undefined;
            var gb: [foryou.max_name + 40]u8 = undefined;
            const msg = (if (it.kind == .suggest_run) foryou.runMessage(it.cmd(), &mb) else foryou.gotoMessage(it.project(), &gb)) orelse break :blk .failed;
            c.line(t, msg) catch break :blk .failed;
            break :blk .sent;
        },
        .answer => blk: {
            if (it.kind == .waiting_permission) {
                // Only ever a prompt whose `1` is a plain one-time yes
                // (foryou_desk.zig: others are `needs_desk`).
                c.key(t, if (req.op == .yes) "1" else "esc") catch break :blk .failed;
            } else {
                // A question's answer is the desk's own fixed line, typed
                // in `keys` mode too (Effect.answer): writeDeskLine, the
                // line rules in any input mode (writeWebLine would refuse
                // a `keys`-mode device).
                t.session.writeDeskLine(if (req.op == .yes) "Yes." else "No.") catch break :blk .failed;
            }
            break :blk .sent;
        },
    };
    // Not delivered: the card comes back (for any device to try again).
    if (!result.ok()) t.forYouRestore(taken.sig);
    var wb: [96]u8 = undefined;
    c.log.print("for you: {s} answered {t} {t} in tab '{s}': {t}", .{ c.who(&wb), it.kind, req.op, t.name(), result });
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
        _ = c.allow();
        return answerRecap(buf, .unknown, null);
    };
    defer tab.release();
    return recapTab(c, tab, buf);
}

/// A recap for open tab `t` (`r:recap`, or the line `recap` for the tab
/// watched; null: none watched).
pub fn recapTab(c: Ctx, tab: ?*tabs.Tab, buf: *[frames.max_answer]u8) []const u8 {
    const h = c.hub;
    if (!c.allow()) return answerRecap(buf, .rate_limited, null);
    const t = tab orelse return answerRecap(buf, .unknown, null);
    const mode = c.policy();
    if ((mode != .instruct and mode != .text) or h.program.device_start == .not_agent)
        return answerRecap(buf, .refused, t.id);
    h.mutex.lockUncancelable(h.io);
    const open = !t.removed and !t.session.closed;
    const allowed = open and t.foryou.recapAllowed(c.now_ms);
    h.mutex.unlock(h.io);
    if (!open) return answerRecap(buf, .unknown, null);
    if (!allowed) return answerRecap(buf, .rate_limited, t.id);
    c.line(t, recap.prompt) catch return answerRecap(buf, .refused, t.id);
    var wb: [96]u8 = undefined;
    c.log.print("for you: {s} asked tab '{s}' for a recap", .{ c.who(&wb), t.name() });
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

test "who asks: the desk answers as `text` and is never rate limited; a device under the desk's mode and its limit" {
    var hub: tabs.Hub = undefined;
    hub.io = testing.io;
    hub.policy = .none;
    var log: Log = undefined;
    var l: Limits = .{};
    const desk: Ctx = .{ .hub = &hub, .log = &log, .from = .desk, .now_ms = 0 };
    const dev: Ctx = .{ .hub = &hub, .log = &log, .from = .{ .device = .{ .limits = &l, .id = @splat(3), .name = "phone" } }, .now_ms = 0 };
    // The desk is the owner at the keyboard: everything `text` allows,
    // whatever the devices may.
    try testing.expectEqual(keymap.Policy.text, desk.policy());
    try testing.expectEqual(keymap.Policy.none, dev.policy());
    for ([_]foryou.Effect{ .dismiss, .answer, .send_message }) |e| {
        try testing.expect(e.allowedIn(@tagName(desk.policy())));
        try testing.expectEqual(e == .dismiss, e.allowedIn(@tagName(dev.policy())));
    }
    for (0..max_per_minute) |_| try testing.expect(dev.allow());
    try testing.expect(!dev.allow());
    for (0..2 * max_per_minute) |_| try testing.expect(desk.allow());
    var b: [96]u8 = undefined;
    try testing.expectEqualStrings("the desk", desk.who(&b));
    try testing.expectEqualStrings("device 'phone'", dev.who(&b));
}

test "the recap line is exactly `recap`" {
    try testing.expect(isRecapLine("recap"));
    try testing.expect(!isRecapLine("Recap"));
    try testing.expect(!isRecapLine("recap please"));
}
