//! Deadlines for blocking network work. std.Io.Threaded cannot time out a
//! connect (it panics on a connect timeout in this Zig version) and its
//! socket reads have no timeout, so each network step runs as an `Io`
//! concurrent task while the calling thread watches a deadline the task
//! keeps moving forward; past the deadline the task is canceled, which makes
//! its blocked connect/read/write return `error.Canceled`.
//!
//! Tasks run under a watchdog must not swallow `error.Canceled` from an
//! `Io` call (only the first cancelation point after a cancel request sees
//! it); see `Client.sendFrame`, which re-arms it with `io.recancel()`.

const std = @import("std");
const Io = std.Io;

pub fn nowMs(io: Io) i64 {
    return Io.Clock.awake.now(io).toMilliseconds();
}

pub const Watchdog = struct {
    io: Io,
    deadline_ms: std.atomic.Value(i64) = .init(std.math.maxInt(i64)),
    done: Io.Event = .unset,
    /// Set when the deadline passed and the task was canceled.
    expired: std.atomic.Value(bool) = .init(false),

    pub const Tick = struct {
        ctx: *anyopaque,
        /// Returns when it next needs to run (awake-clock ms).
        f: *const fn (*anyopaque) i64,
    };

    /// Moves the deadline to `ms` from now (callable from the task).
    pub fn extend(w: *Watchdog, ms: i64) void {
        w.deadline_ms.store(nowMs(w.io) +| ms, .release);
    }

    fn Ret(comptime func: anytype) type {
        return @typeInfo(@TypeOf(func)).@"fn".return_type.?;
    }

    /// Runs `func(args)` and returns its result. `extend` must have been
    /// called first. `tick` (if any) runs on this thread whenever it said it
    /// is next due (WebSocket pings). Event-driven: this thread sleeps until
    /// the task finishes, the deadline passes or the tick is due.
    pub fn run(w: *Watchdog, comptime func: anytype, args: std.meta.ArgsTuple(@TypeOf(func)), tick: ?Tick) Ret(func) {
        const R = Ret(func);
        const Args = @TypeOf(args);
        const Wrap = struct {
            fn task(wd: *Watchdog, a: Args) R {
                defer wd.done.set(wd.io);
                return @call(.auto, func, a);
            }
        };
        w.done.reset();
        w.expired.store(false, .release);
        // Without concurrency (should not happen with std.Io.Threaded) run
        // inline: the OS limits still apply.
        var fut = w.io.concurrent(Wrap.task, .{ w, args }) catch return @call(.auto, func, args);
        var tick_due: i64 = if (tick) |t| t.f(t.ctx) else std.math.maxInt(i64);
        while (true) {
            // The task may have moved the deadline while this thread slept;
            // waking at the old one just re-reads it.
            const wake_at = @min(w.deadline_ms.load(.acquire), tick_due);
            const left = wake_at -| nowMs(w.io);
            if (left > 0) w.done.waitTimeout(w.io, .{ .duration = .{ .raw = .fromMilliseconds(left), .clock = .awake } }) catch {};
            if (w.done.isSet()) return fut.await(w.io);
            const now = nowMs(w.io);
            if (now > w.deadline_ms.load(.acquire)) {
                w.expired.store(true, .release);
                return fut.cancel(w.io);
            }
            if (tick) |t| if (now >= tick_due) {
                tick_due = t.f(t.ctx);
            };
        }
    }
};

test "watchdog cancels a stalled task and returns a finished one" {
    const io = std.testing.io;
    var w: Watchdog = .{ .io = io };
    const T = struct {
        fn quick(x: u32) u32 {
            return x + 1;
        }
        fn stall(i: Io) Io.Cancelable!u32 {
            try i.sleep(.fromSeconds(30), .awake);
            return 7;
        }
    };
    w.extend(5000);
    try std.testing.expectEqual(@as(u32, 3), w.run(T.quick, .{2}, null));
    try std.testing.expect(!w.expired.load(.acquire));
    w.extend(300);
    const t0 = nowMs(io);
    try std.testing.expectError(error.Canceled, w.run(T.stall, .{io}, null));
    try std.testing.expect(w.expired.load(.acquire));
    try std.testing.expect(nowMs(io) - t0 < 5000);
}

test "watchdog wakes only when the tick is due, not on a fixed period" {
    const io = std.testing.io;
    var w: Watchdog = .{ .io = io };
    const T = struct {
        var calls: u32 = 0;
        var tio: Io = undefined;
        fn tick(_: *anyopaque) i64 {
            calls += 1;
            return nowMs(tio) + 200;
        }
        fn work(i: Io) Io.Cancelable!u32 {
            try i.sleep(.fromMilliseconds(700), .awake);
            return 1;
        }
    };
    T.tio = io;
    var dummy: u8 = 0;
    w.extend(5000);
    try std.testing.expectEqual(@as(u32, 1), try w.run(T.work, .{io}, .{ .ctx = &dummy, .f = T.tick }));
    // About 700/200 + 1 calls; a fixed 250 ms period would also be close,
    // but a busy or 10 ms loop would be far above.
    try std.testing.expect(T.calls >= 3 and T.calls <= 6);
}
