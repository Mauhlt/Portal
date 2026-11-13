//! One tab's background work and token use (docs/protocol.md section 3c),
//! from the same transcript records the Conversation view reads
//! (transcript.zig, follow.zig). Numbers and short descriptions only.
//!
//! Background tasks (owner's request, 2026-11-12):
//!   * a `Bash` / `PowerShell` tool_use with `run_in_background` starts a
//!     shell, a `Monitor` tool_use a monitor; its `description` (scrubbed
//!     of paths and the user's name, one line, cut) is what is shown,
//!     never the command;
//!   * its tool_result names the task id (`toolUseResult.backgroundTaskId`
//!     / `.taskId`); a result marked as an error means it never started
//!     (dropped);
//!   * it ends with a task notification carrying that id and a status
//!     (`completed` → done, `failed`, `killed`), queued (`queue-operation`)
//!     or delivered (a `user` record); `TaskStop` on it (answered without
//!     error) kills it; a monitor with a timeout and not `persistent` is
//!     done once a later record is dated past its timeout;
//!   * started in records written before the tab started (an earlier run
//!     of the program, e.g. a resumed session): `stale`, not running;
//!   * a new transcript (`/clear`, `/resume`) keeps the tasks still
//!     running (the same program runs them) and drops finished ones; the
//!     tab closing ends everything with it;
//!   * at most `wire.max_tasks`: finished ones go first, then the oldest.
//!
//! Usage: the sum of `message.usage` over the followed transcript's
//! assistant replies, each `message.id` counted once (the agent repeats
//! a reply's usage on every record of it); `today` counts only replies
//! dated today (local day, `dayOf`); the model is the latest reply's.
//! A new transcript starts both over.
//!
//! Every change bumps `rev`. Locking: the caller holds the hub's mutex.

const std = @import("std");
const Allocator = std.mem.Allocator;
const wire = @import("shared").activity;
const transcript = @import("transcript.zig");
const scrub = @import("scrub.zig");
const cleanText = @import("model.zig").cleanText;

const Entry = struct {
    task: wire.Task,
    /// Hash of the tool_use id that started it.
    tool_id: u64,
    /// Hash of the task id its result named (0: not yet known).
    task_id: u64 = 0,
    /// Monitors: seconds until it ends by itself (0: none).
    timeout_s: i64 = 0,
};

const Stop = struct { tool_id: u64, task: u64 };

/// The UTC day of a Unix time (tests; the server passes the local one).
pub fn utcDay(t: i64) i64 {
    return @divFloor(t, 86400);
}

pub const Activity = struct {
    gpa: Allocator,
    /// How descriptions are scrubbed (borrowed from the tab).
    ctx: scrub.Context,
    dayOf: *const fn (i64) i64 = utcDay,

    entries: [wire.max_tasks]Entry = undefined,
    n: usize = 0,
    stops: [8]Stop = undefined,
    n_stops: usize = 0,
    /// Replies already counted (message id hashes), newest last.
    seen: [64]u64 = @splat(0),
    seen_at: usize = 0,
    usage: wire.Usage = .{},
    today: wire.Usage = .{},
    /// The day `today` counts (minInt: none yet).
    day: i64 = std.math.minInt(i64),
    model_buf: [wire.max_model]u8 = undefined,
    model_len: u8 = 0,
    rev: u64 = 1,

    pub fn init(gpa: Allocator, ctx: scrub.Context) Activity {
        return .{ .gpa = gpa, .ctx = ctx };
    }

    fn bump(a: *Activity) void {
        a.rev +%= 1;
    }

    pub fn tasks(a: *const Activity) []const Entry {
        return a.entries[0..a.n];
    }

    /// A new transcript is followed (or none): usage starts over, tasks
    /// still running stay.
    pub fn reset(a: *Activity) void {
        var k: usize = 0;
        for (a.entries[0..a.n]) |e| if (e.task.state.live()) {
            a.entries[k] = e;
            k += 1;
        };
        a.n = k;
        a.n_stops = 0;
        a.seen = @splat(0);
        a.seen_at = 0;
        a.usage = .{};
        a.today = .{};
        a.day = std.math.minInt(i64);
        a.model_len = 0;
        a.bump();
    }

    pub fn applyRecord(a: *Activity, rec: *const transcript.Record) void {
        if (rec.sidechain) return;
        switch (rec.rtype) {
            .assistant => a.assistant(rec),
            .user => a.user(rec),
            .queue => if (rec.enqueue) {
                if (transcript.taskNotice(rec.content)) |n| a.notice(n);
            },
            else => {},
        }
        if (rec.timestamp != 0) a.expire(rec.timestamp);
    }

    fn assistant(a: *Activity, rec: *const transcript.Record) void {
        if (!rec.api_error) if (rec.usage) |u| a.countUsage(rec, u);
        for (rec.blockSlice()) |*b| {
            if (b.kind != .tool_use) continue;
            const name = b.tool();
            if ((std.mem.eql(u8, name, "Bash") or std.mem.eql(u8, name, "PowerShell")) and b.background) {
                a.start(rec, b, .shell, "Background command");
            } else if (std.mem.eql(u8, name, "Monitor")) {
                a.start(rec, b, .monitor, "Monitor");
            } else if (std.mem.eql(u8, name, "TaskStop") and b.task_ref != 0 and b.id_hash != 0) {
                if (a.n_stops == a.stops.len) {
                    std.mem.copyForwards(Stop, a.stops[0 .. a.stops.len - 1], a.stops[1..]);
                    a.n_stops -= 1;
                }
                a.stops[a.n_stops] = .{ .tool_id = b.id_hash, .task = b.task_ref };
                a.n_stops += 1;
            }
        }
    }

    fn countUsage(a: *Activity, rec: *const transcript.Record, u: transcript.Usage) void {
        if (rec.msg_hash != 0) {
            for (a.seen) |s| if (s == rec.msg_hash) return;
            a.seen[a.seen_at] = rec.msg_hash;
            a.seen_at = (a.seen_at + 1) % a.seen.len;
        }
        const add: wire.Usage = .{ .input = u.input, .output = u.output, .cache_read = u.cache_read, .cache_write = u.cache_write };
        a.usage.add(add);
        if (rec.timestamp != 0) {
            const d = a.dayOf(rec.timestamp);
            if (d > a.day) {
                a.day = d;
                a.today = .{};
            }
            if (d == a.day) a.today.add(add);
        }
        const m = rec.model();
        if (wire.validModel(m)) {
            @memcpy(a.model_buf[0..m.len], m);
            a.model_len = @intCast(m.len);
        }
        a.bump();
    }

    /// A task started by tool_use `b`.
    fn start(a: *Activity, rec: *const transcript.Record, b: *const transcript.Block, kind: wire.Kind, fallback: []const u8) void {
        if (b.id_hash == 0) return;
        for (a.entries[0..a.n]) |e| if (e.tool_id == b.id_hash) return; // a record read again
        var e: Entry = .{
            .task = .{ .kind = kind, .state = if (rec.history) .stale else .running, .since = @max(rec.timestamp, 0) },
            .tool_id = b.id_hash,
            .timeout_s = if (kind == .monitor) @intCast(@min(b.timeout_ms / 1000, std.math.maxInt(i32))) else 0,
        };
        a.describe(&e.task, b.desc, fallback);
        a.makeRoom();
        a.entries[a.n] = e;
        a.n += 1;
        a.bump();
    }

    /// The description as one scrubbed, cut line; `fallback` if nothing
    /// is left (or memory is short).
    fn describe(a: *Activity, t: *wire.Task, raw: []const u8, fallback: []const u8) void {
        t.setText(fallback);
        if (raw.len == 0) return;
        var clean: std.ArrayList(u8) = .empty;
        defer clean.deinit(a.gpa);
        cleanText(a.gpa, raw, &clean) catch return;
        for (clean.items) |*c| if (c.* == '\n' or c.* == '\t') {
            c.* = ' ';
        };
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(a.gpa);
        scrub.scrub(a.gpa, a.ctx, std.mem.trim(u8, clean.items, " "), &out) catch return;
        const s = std.mem.trim(u8, out.items, " ");
        if (s.len == 0) return;
        t.setText(s);
        if (s.len > wire.max_text) {
            // Cut: end with an ellipsis, at a character boundary.
            const ell = "\u{2026}";
            var n: usize = wire.max_text - ell.len;
            while (n > 0 and (s[n] & 0xC0) == 0x80) n -= 1;
            @memcpy(t.text_buf[0..n], s[0..n]);
            @memcpy(t.text_buf[n..][0..ell.len], ell);
            t.text_len = @intCast(n + ell.len);
        }
    }

    fn makeRoom(a: *Activity) void {
        if (a.n < a.entries.len) return;
        var drop: usize = 0;
        for (a.entries[0..a.n], 0..) |e, i| if (!e.task.state.live()) {
            drop = i;
            break;
        };
        std.mem.copyForwards(Entry, a.entries[drop .. a.n - 1], a.entries[drop + 1 .. a.n]);
        a.n -= 1;
    }

    fn user(a: *Activity, rec: *const transcript.Record) void {
        for (rec.blockSlice()) |*b| switch (b.kind) {
            .tool_result => a.result(rec, b),
            .text => if (transcript.taskNotice(b.text)) |n| a.notice(n),
            else => {},
        };
    }

    fn result(a: *Activity, rec: *const transcript.Record, b: *const transcript.Block) void {
        if (b.id_hash == 0) return;
        var i: usize = 0;
        while (i < a.n) {
            const e = &a.entries[i];
            if (e.tool_id != b.id_hash) {
                i += 1;
                continue;
            }
            if (b.is_error) {
                // It never started.
                std.mem.copyForwards(Entry, a.entries[i .. a.n - 1], a.entries[i + 1 .. a.n]);
                a.n -= 1;
                a.bump();
                continue;
            }
            if (rec.result_task != 0) e.task_id = rec.result_task;
            if (e.task.kind == .monitor and rec.result_persistent) e.timeout_s = 0;
            a.bump();
            i += 1;
        }
        var k: usize = 0;
        while (k < a.n_stops) {
            if (a.stops[k].tool_id == b.id_hash) {
                if (!b.is_error) a.end(a.stops[k].task, .killed);
                std.mem.copyForwards(Stop, a.stops[k .. a.n_stops - 1], a.stops[k + 1 .. a.n_stops]);
                a.n_stops -= 1;
            } else k += 1;
        }
    }

    fn notice(a: *Activity, n: transcript.Notice) void {
        const st = n.status orelse return; // an event: still running
        a.end(n.task, switch (st) {
            .completed => .done,
            .failed => .failed,
            .killed => .killed,
        });
    }

    fn end(a: *Activity, task: u64, state: wire.State) void {
        for (a.entries[0..a.n]) |*e| if (e.task_id == task and e.task.state != state) {
            e.task.state = state;
            a.bump();
        };
    }

    /// Monitors with a timeout end by themselves.
    fn expire(a: *Activity, now: i64) void {
        for (a.entries[0..a.n]) |*e| {
            if (e.task.kind != .monitor or !e.task.state.live() or e.timeout_s == 0 or e.task.since == 0) continue;
            if (now > e.task.since + e.timeout_s) {
                e.task.state = .done;
                a.bump();
            }
        }
    }

    /// The tab's entry of the `activity` message; `today` only if `now_day`
    /// is the day it counts.
    pub fn toWire(a: *const Activity, id: wire.Id, now_day: i64, out: *wire.Tab) void {
        out.* = .{ .id = id, .usage = a.usage, .today = if (a.day == now_day) a.today else .{} };
        out.setModel(a.model_buf[0..a.model_len]);
        for (a.entries[0..a.n], 0..) |e, i| out.tasks[i] = e.task;
        out.n_tasks = a.n;
    }

    pub fn running(a: *const Activity, kind: wire.Kind) u32 {
        var n: u32 = 0;
        for (a.entries[0..a.n]) |e| n += @intFromBool(e.task.kind == kind and e.task.state.live());
        return n;
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;
const ctx_acme: scrub.Context = .{ .root = "C:\\Users\\bob\\code\\acme", .name = "acme", .user = "bob" };

const Fx = struct {
    a: Activity,
    rec: *transcript.Record,
    history: bool = false,

    fn init() !Fx {
        return .{ .a = Activity.init(testing.allocator, ctx_acme), .rec = try testing.allocator.create(transcript.Record) };
    }
    fn deinit(f: *Fx) void {
        testing.allocator.destroy(f.rec);
    }
    fn feed(f: *Fx, line: []const u8) !void {
        try testing.expect(transcript.parseLine(testing.allocator, line, true, f.rec));
        f.rec.history = f.history;
        f.a.applyRecord(f.rec);
    }
    fn state(f: *Fx, i: usize) wire.State {
        return f.a.entries[i].task.state;
    }
};

fn bg(comptime id: []const u8, comptime ts: []const u8, comptime desc: []const u8) []const u8 {
    return "{\"type\":\"assistant\",\"timestamp\":\"" ++ ts ++ "\",\"message\":{\"id\":\"m-" ++ id ++ "\",\"content\":[{\"type\":\"tool_use\",\"id\":\"" ++ id ++ "\",\"name\":\"Bash\",\"input\":{\"command\":\"SECRET-CMD C:\\\\Users\\\\bob\",\"description\":\"" ++ desc ++ "\",\"run_in_background\":true}}]}}";
}

fn started(comptime id: []const u8, comptime task: []const u8) []const u8 {
    return "{\"type\":\"user\",\"message\":{\"content\":[{\"tool_use_id\":\"" ++ id ++ "\",\"type\":\"tool_result\",\"content\":\"Command running in background with ID: " ++ task ++ "\"}]},\"toolUseResult\":{\"stdout\":\"\",\"backgroundTaskId\":\"" ++ task ++ "\"}}";
}

fn queued(comptime task: []const u8, comptime status: []const u8) []const u8 {
    return "{\"type\":\"queue-operation\",\"operation\":\"enqueue\",\"timestamp\":\"2025-11-12T11:00:00.000Z\",\"content\":\"<task-notification>\\n<task-id>" ++ task ++ "</task-id>\\n<status>" ++ status ++ "</status>\\n<summary>Background command done</summary>\\n</task-notification>\"}";
}

test "shells: start, id from the result, finish by notification; descriptions scrubbed" {
    var f = try Fx.init();
    defer f.deinit();
    try f.feed(bg("t1", "2025-11-12T10:00:00.000Z", "Run tests in C:\\\\Users\\\\bob\\\\code\\\\acme\\\\src for bob"));
    try testing.expectEqual(@as(u32, 1), f.a.running(.shell));
    try testing.expectEqualStrings("Run tests in acme\\src for [user]", f.a.entries[0].task.text());
    try testing.expectEqual(@as(i64, 1_762_941_600), f.a.entries[0].task.since);
    try f.feed(started("t1", "b1"));
    try testing.expectEqual(transcript.hash("b1"), f.a.entries[0].task_id);
    // A second shell whose start failed: gone.
    try f.feed(bg("t2", "2025-11-12T10:01:00.000Z", "Doomed"));
    try testing.expectEqual(@as(usize, 2), f.a.n);
    try f.feed("{\"type\":\"user\",\"message\":{\"content\":[{\"tool_use_id\":\"t2\",\"type\":\"tool_result\",\"content\":\"denied\",\"is_error\":true}]}}");
    try testing.expectEqual(@as(usize, 1), f.a.n);
    // The queued notification ends it; a delivered copy changes nothing.
    const rev = f.a.rev;
    try f.feed(queued("b1", "completed"));
    try testing.expectEqual(wire.State.done, f.state(0));
    try testing.expect(f.a.rev != rev);
    try f.feed("{\"type\":\"user\",\"origin\":{\"kind\":\"task-notification\"},\"message\":{\"content\":\"<task-notification>\\n<task-id>b1</task-id>\\n<status>completed</status>\\n</task-notification>\"}}");
    try testing.expectEqual(@as(u32, 0), f.a.running(.shell));
    // A notification for some other task (an agent's): nothing.
    try f.feed(queued("other", "failed"));
    try testing.expectEqual(wire.State.done, f.state(0));
    // No description: a plain label; never the command.
    try f.feed("{\"type\":\"assistant\",\"message\":{\"id\":\"x\",\"content\":[{\"type\":\"tool_use\",\"id\":\"t3\",\"name\":\"PowerShell\",\"input\":{\"command\":\"SECRET-CMD\",\"run_in_background\":true}}]}}");
    try testing.expectEqualStrings("Background command", f.a.entries[1].task.text());
    // A foreground command is no task.
    try f.feed("{\"type\":\"assistant\",\"message\":{\"id\":\"y\",\"content\":[{\"type\":\"tool_use\",\"id\":\"t4\",\"name\":\"Bash\",\"input\":{\"command\":\"ls\",\"description\":\"List\"}}]}}");
    try testing.expectEqual(@as(usize, 2), f.a.n);
    for (f.a.tasks()) |e| try testing.expect(std.mem.indexOf(u8, e.task.text(), "SECRET") == null);
}

test "monitors: events keep them running, TaskStop kills, timeouts end them" {
    var f = try Fx.init();
    defer f.deinit();
    try f.feed("{\"type\":\"assistant\",\"timestamp\":\"2025-11-12T10:00:00Z\",\"message\":{\"id\":\"m1\",\"content\":[{\"type\":\"tool_use\",\"id\":\"mon1\",\"name\":\"Monitor\",\"input\":{\"command\":\"tail\",\"description\":\"Watch the build\",\"timeout_ms\":60000}}]}}");
    try f.feed("{\"type\":\"user\",\"message\":{\"content\":[{\"tool_use_id\":\"mon1\",\"type\":\"tool_result\",\"content\":\"ok\"}]},\"toolUseResult\":{\"taskId\":\"k1\",\"timeoutMs\":60000,\"persistent\":false}}");
    try f.feed("{\"type\":\"queue-operation\",\"operation\":\"enqueue\",\"timestamp\":\"2025-11-12T10:00:30Z\",\"content\":\"<task-notification><task-id>k1</task-id><event>a line</event></task-notification>\"}");
    try testing.expectEqual(@as(u32, 1), f.a.running(.monitor));
    // A record dated after its timeout: done.
    try f.feed("{\"type\":\"system\",\"timestamp\":\"2025-11-12T10:01:01Z\",\"subtype\":\"turn_duration\"}");
    try testing.expectEqual(wire.State.done, f.state(0));
    // A persistent monitor has no timeout; TaskStop kills it.
    try f.feed("{\"type\":\"assistant\",\"timestamp\":\"2025-11-12T10:02:00Z\",\"message\":{\"id\":\"m2\",\"content\":[{\"type\":\"tool_use\",\"id\":\"mon2\",\"name\":\"Monitor\",\"input\":{\"description\":\"Watch forever\",\"timeout_ms\":60000}}]}}");
    try f.feed("{\"type\":\"user\",\"message\":{\"content\":[{\"tool_use_id\":\"mon2\",\"type\":\"tool_result\",\"content\":\"ok\"}]},\"toolUseResult\":{\"taskId\":\"k2\",\"persistent\":true}}");
    try f.feed("{\"type\":\"system\",\"timestamp\":\"2025-11-12T12:00:00Z\"}");
    try testing.expectEqual(wire.State.running, f.state(1));
    try f.feed("{\"type\":\"assistant\",\"message\":{\"id\":\"m3\",\"content\":[{\"type\":\"tool_use\",\"id\":\"stop1\",\"name\":\"TaskStop\",\"input\":{\"task_id\":\"k2\"}}]}}");
    try testing.expectEqual(wire.State.running, f.state(1)); // not until it is answered
    try f.feed("{\"type\":\"user\",\"message\":{\"content\":[{\"tool_use_id\":\"stop1\",\"type\":\"tool_result\",\"content\":\"stopped\"}]}}");
    try testing.expectEqual(wire.State.killed, f.state(1));
}

test "stale: started before the tab; a new transcript keeps what still runs" {
    var f = try Fx.init();
    defer f.deinit();
    f.history = true;
    try f.feed(bg("old", "2025-11-10T10:00:00Z", "From an earlier run"));
    try f.feed(started("old", "b-old"));
    f.history = false;
    try f.feed(bg("new", "2025-11-12T10:00:00Z", "Mine"));
    try f.feed(started("new", "b-new"));
    try f.feed(bg("fin", "2025-11-12T10:00:00Z", "Finished"));
    try f.feed(started("fin", "b-fin"));
    try f.feed(queued("b-fin", "killed"));
    try testing.expectEqual(wire.State.stale, f.state(0));
    try testing.expectEqual(wire.State.running, f.state(1));
    try testing.expectEqual(wire.State.killed, f.state(2));
    try testing.expectEqual(@as(u32, 1), f.a.running(.shell));
    // /clear: the running one stays and can still finish.
    f.a.reset();
    try testing.expectEqual(@as(usize, 1), f.a.n);
    try f.feed(queued("b-new", "failed"));
    try testing.expectEqual(wire.State.failed, f.state(0));
}

test "bounded: finished tasks go first" {
    var f = try Fx.init();
    defer f.deinit();
    var line: [512]u8 = undefined;
    for (0..wire.max_tasks + 5) |i| {
        const l = try std.fmt.bufPrint(&line, "{{\"type\":\"assistant\",\"message\":{{\"id\":\"m{d}\",\"content\":[{{\"type\":\"tool_use\",\"id\":\"t{d}\",\"name\":\"Bash\",\"input\":{{\"description\":\"task {d}\",\"run_in_background\":true}}}}]}}}}", .{ i, i, i });
        try f.feed(l);
        if (i == 0) {
            try f.feed(started("t0", "b0"));
            try f.feed(queued("b0", "completed"));
        }
    }
    try testing.expectEqual(@as(usize, wire.max_tasks), f.a.n);
    // The finished one went first, then the oldest running ones.
    for (f.a.tasks()) |e| try testing.expect(e.task.state.live());
    try testing.expectEqualStrings("task 20", f.a.entries[wire.max_tasks - 1].task.text());
}

fn reply(comptime id: []const u8, comptime ts: []const u8, comptime model: []const u8, comptime in: []const u8, comptime out: []const u8) []const u8 {
    return "{\"type\":\"assistant\",\"timestamp\":\"" ++ ts ++ "\",\"message\":{\"model\":\"" ++ model ++ "\",\"id\":\"" ++ id ++ "\",\"usage\":{\"input_tokens\":" ++ in ++ ",\"cache_creation_input_tokens\":100,\"cache_read_input_tokens\":1000,\"output_tokens\":" ++ out ++ "},\"content\":[{\"type\":\"text\",\"text\":\"secret words\"}]}}";
}

test "usage: each reply once, today by day, latest model, reset" {
    var f = try Fx.init();
    defer f.deinit();
    try f.feed(reply("r1", "2025-11-11T23:00:00Z", "model-small-4-5", "10", "5"));
    try f.feed(reply("r2", "2025-11-12T09:00:00Z", "model-large-4-1", "3", "7"));
    // The same reply's next record repeats its usage: not counted twice.
    try f.feed(reply("r2", "2025-11-12T09:00:01Z", "model-large-4-1", "3", "7"));
    // The agent's own notes have a model of "<synthetic>": not a model.
    try f.feed(reply("r3", "2025-11-12T09:00:02Z", "<synthetic>", "0", "0"));
    try testing.expectEqual(@as(u64, 13), f.a.usage.input);
    try testing.expectEqual(@as(u64, 12), f.a.usage.output);
    try testing.expectEqual(@as(u64, 3000), f.a.usage.cache_read);
    try testing.expectEqual(@as(u64, 300), f.a.usage.cache_write);
    var t: wire.Tab = undefined;
    const today = utcDay(1_762_941_600);
    f.a.toWire(@splat(3), today, &t);
    try testing.expectEqualStrings("model-large-4-1", t.model());
    try testing.expectEqual(@as(u64, 3), t.today.input);
    try testing.expectEqual(@as(u64, 2200), t.today.cache_read + t.today.cache_write);
    // The next day, with no reply yet: nothing today.
    f.a.toWire(@splat(3), today + 1, &t);
    try testing.expect(t.today.isZero());
    // API errors count nothing.
    try f.feed("{\"type\":\"assistant\",\"isApiErrorMessage\":true,\"message\":{\"id\":\"e\",\"model\":\"<synthetic>\",\"usage\":{\"input_tokens\":999,\"output_tokens\":999},\"content\":[{\"type\":\"text\",\"text\":\"API Error\"}]}}");
    try testing.expectEqual(@as(u64, 13), f.a.usage.input);
    f.a.reset();
    try testing.expect(f.a.usage.isZero());
    f.a.toWire(@splat(3), today, &t);
    try testing.expectEqualStrings("", t.model());
}
