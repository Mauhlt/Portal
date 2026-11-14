//! Startable projects on a device's interactive WebSocket (docs/protocol.md
//! section 3f; docs/tabs-design.md, "Starting projects from a device"):
//! the `p:start` / `p:stop` frames and the `projects` list. src/web.zig only
//! calls in here (its reader with each `p:` frame, its writer on every wake);
//! what a start runs is decided in src/tabs.zig (Hub.deviceStart: the desk's
//! folder, program and permission mode) and src/cmdline.zig.
//!
//! A request is checked in this order, and nothing of it but the name
//! (exactly one of the desk's names) is ever used:
//!   1. `<verb> <argument>` with a verb of projects.Op, else ignored;
//!   2. the desk's input mode: `none` (view only) is `refused`;
//!   3. the device's rate: at most `per_minute` starts and `per_minute`
//!      stops a minute per paired device, across all its connections
//!      (timestamps only, no timer), else `rate_limited`;
//!   4. a startable name, else `unknown`; then the hub decides.

const std = @import("std");
const Io = std.Io;
const shared = @import("shared");
const projects = shared.projects;
const frames = shared.frames;
const tabs = @import("tabs.zig");
const devices = @import("devices.zig");
const keymap = @import("keymap.zig");
const ratelimit = @import("ratelimit.zig");

pub const per_minute = 3;
pub const window_ms: i64 = 60_000;

/// Each paired device's request windows (`p:start` and `p:stop` apart),
/// shared by all its connections: reconnecting doesn't reset them.
pub const Limits = ratelimit.PerDevice(projects.Op, per_minute, window_ms);

/// What to do with a `p:` frame (decide): nothing, answer at once, or ask
/// the hub to start / stop the project named (a startable name).
pub const Decision = union(enum) {
    ignore,
    answer: struct { op: projects.Op, result: projects.Result, over: u32 = 0 },
    start: []const u8,
    stop: []const u8,
};

/// Steps 1-4 above, for the rest of a `p:` frame (after "p:").
pub fn decide(policy: keymap.Policy, limits: *Limits, io: Io, device: devices.DeviceId, now_ms: i64, rest: []const u8) Decision {
    const v = frames.verb(projects.Op, rest) orelse return .ignore;
    if (policy == .none) return .{ .answer = .{ .op = v.op, .result = .refused } };
    const c = limits.allow(io, device, v.op, now_ms);
    if (!c.ok) return .{ .answer = .{ .op = v.op, .result = .rate_limited, .over = c.over } };
    const r = projects.parseRequest(rest) orelse return .{ .answer = .{ .op = v.op, .result = .unknown } };
    return switch (r.op) {
        .start => .{ .start = r.name },
        .stop => .{ .stop = r.name },
    };
}

/// The `project` answer, and the tab the device now shows (started or
/// already running: web.zig switches its view, as `s:<id>` would).
pub const Outcome = struct {
    answer: []const u8,
    show: ?tabs.Id = null,
};

pub const Device = struct { id: devices.DeviceId, name: []const u8 };

/// A `p:` frame from paired device `device` (the reader task). Null: no
/// answer (not a request).
pub fn handle(hub: *tabs.Hub, limits: *Limits, device: Device, now_ms: i64, rest: []const u8, buf: *[frames.max_answer]u8) ?Outcome {
    var w: Io.Writer = .fixed(buf);
    switch (decide(hub.policy, limits, hub.io, device.id, now_ms, rest)) {
        .ignore => return null,
        .answer => |a| {
            if (a.result != .rate_limited or a.over <= 3 or std.math.isPowerOfTwo(a.over))
                hub.log.print("device '{s}' asked to {t} a project: {t}", .{ device.name, a.op, a.result });
            projects.writeResult(&w, a.op, a.result, null) catch return null;
            return .{ .answer = w.buffered() };
        },
        .start => |name| {
            var nb: [projects.max_name]u8 = undefined;
            const own = deskName(hub, name, &nb);
            const out = hub.deviceStart(name, device.name);
            var show: ?tabs.Id = null;
            if (out.tab) |t| {
                show = t.id;
                t.release();
            }
            projects.writeResult(&w, .start, out.result, if (out.result == .unknown) null else own) catch return null;
            return .{ .answer = w.buffered(), .show = if (out.result.ok()) show else null };
        },
        .stop => |name| {
            var nb: [projects.max_name]u8 = undefined;
            const own = deskName(hub, name, &nb);
            const result = hub.deviceStop(name, device.name);
            if (result != .stopped) hub.log.print("device '{s}' asked to stop a project: {t}", .{ device.name, result });
            projects.writeResult(&w, .stop, result, if (result == .unknown) null else own) catch return null;
            return .{ .answer = w.buffered() };
        },
    }
}

/// The desk's own spelling of `name` (copied from its list), null if it
/// has none: answers carry the desk's value, never the device's text.
fn deskName(hub: *tabs.Hub, name: []const u8, buf: *[projects.max_name]u8) ?[]const u8 {
    var l: projects.List = .{};
    hub.mutex.lockUncancelable(hub.io);
    hub.projectsLocked(&l);
    hub.mutex.unlock(hub.io);
    const i = l.find(name) orelse return null;
    const n = l.items[i].name();
    @memcpy(buf[0..n.len], n);
    return buf[0..n.len];
}

/// One viewer's `projects` messages (the writer task): the list after
/// hello, then again whenever it differs from the one last sent (the
/// desk's list changed, a project started or ended, a device stopped
/// one). Event-driven: looked at only when the writer wakes anyway.
pub const Feed = struct {
    /// hub.projects_gen and hub.gen when last looked at.
    pgen: u64 = 0,
    tgen: u64 = 0,
    sent: bool = false,
    last: projects.List = .{},
    buf: [projects.max_message]u8 = undefined,

    /// Caller holds hub.mutex. Whether the writer must wake for the list
    /// (tab changes bump hub.gen, which it watches already).
    pub fn dueLocked(f: *const Feed, hub: *const tabs.Hub) bool {
        return !f.sent or hub.projects_gen != f.pgen;
    }

    /// Caller holds hub.mutex. The message to send now, if any (valid
    /// until the next call).
    pub fn collectLocked(f: *Feed, hub: *tabs.Hub) ?[]const u8 {
        if (f.sent and hub.projects_gen == f.pgen and hub.gen == f.tgen) return null;
        f.pgen = hub.projects_gen;
        f.tgen = hub.gen;
        var l: projects.List = .{};
        hub.projectsLocked(&l);
        if (f.sent and l.eql(&f.last)) return null;
        // Looked at, whatever happens next: the writer never spins on it.
        f.last = l;
        f.sent = true;
        var w: Io.Writer = .fixed(&f.buf);
        projects.write(&w, l.slice()) catch return null; // max_message holds any list
        return w.buffered();
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "decide: verb, then view-only, then the device's rate, then the name" {
    const io = testing.io;
    var lim: Limits = .{};
    const a: devices.DeviceId = @splat(1);
    const b: devices.DeviceId = @splat(2);
    try testing.expect(decide(.instruct, &lim, io, a, 0, "run acme") == .ignore);
    try testing.expect(decide(.instruct, &lim, io, a, 0, "startacme") == .ignore);
    // View only: refused, and not counted.
    const r = decide(.none, &lim, io, a, 0, "start acme");
    try testing.expectEqual(projects.Result.refused, r.answer.result);
    try testing.expectEqual(projects.Op.start, r.answer.op);
    try testing.expectEqualStrings("acme", decide(.keys, &lim, io, a, 1, "start acme").start);
    // A malformed name counts too (probing is rate limited).
    try testing.expectEqual(projects.Result.unknown, decide(.keys, &lim, io, a, 2, "start C:\\code\\acme").answer.result);
    try testing.expectEqualStrings("acme", decide(.keys, &lim, io, a, 3, "start acme").start);
    const over = decide(.keys, &lim, io, a, 4, "start acme");
    try testing.expectEqual(projects.Result.rate_limited, over.answer.result);
    try testing.expectEqual(@as(u32, 1), over.answer.over);
    // Stops have their own window; another device its own.
    try testing.expectEqualStrings("acme", decide(.keys, &lim, io, a, 5, "stop acme").stop);
    try testing.expectEqualStrings("acme", decide(.keys, &lim, io, b, 6, "start acme").start);
    // A minute after the first: one more start.
    try testing.expectEqualStrings("acme", decide(.keys, &lim, io, a, 60_001, "start acme").start);
    try testing.expect(decide(.keys, &lim, io, a, 60_001, "start acme").answer.result == .rate_limited);
}
