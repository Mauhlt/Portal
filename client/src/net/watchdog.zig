//! Deadlines for blocking network work. std.Io.Threaded cannot time out a
//! connect (it panics on a connect timeout in this Zig version) and its
//! socket reads have no timeout, so each network step runs as an `Io`
//! concurrent task while the calling thread watches a deadline the task
//! keeps moving forward; past the deadline the task is canceled, which makes
//! its blocked connect/read/write return `error.Canceled`.
//!
//! The watching thread never does I/O itself: a `Tick` only computes when
//! it is next due and may set flags or events (the stream's "ping due"),
//! so nothing a task blocks on can keep the watchdog from its deadline.
//!
//! A cancelation is delivered once. Tasks run under a watchdog must not
//! swallow `error.Canceled` from an `Io` call; as a second line of defence
//! `stopped` is set before the task is canceled, and connections opened
//! with `tlsconn.Conn.openWatched(..., &wd.stopped)` refuse to block again
//! once it is set (like the desktop's `web.Conn.stop`).

const std = @import("std");
const Io = std.Io;

pub fn nowMs(io: Io) i64 {
    return Io.Clock.awake.now(io).toMilliseconds();
}

pub const Watchdog = struct {
    io: Io,
    deadline_ms: std.atomic.Value(i64) = .init(std.math.maxInt(i64)),
    /// Wakes the watching thread: set when the task finishes, or by `poke`.
    done: Io.Event = .unset,
    finished: std.atomic.Value(bool) = .init(false),
    /// Set when the deadline passed and the task was canceled.
    expired: std.atomic.Value(bool) = .init(false),
    /// Set (before canceling) whenever the task is canceled: by the
    /// deadline, by `abort`, or because the watching task itself was
    /// canceled. Connections opened with it never block again.
    stopped: std.atomic.Value(bool) = .init(false),
    /// When set, a true value cancels the task early (e.g. the user
    /// cancelled pairing); whoever sets it calls `poke` afterwards.
    abort: ?*const std.atomic.Value(bool) = null,

    pub const Tick = struct {
        ctx: *anyopaque,
        /// Returns when it next needs to run (awake-clock ms). Runs on the
        /// watching thread: it must never block (no I/O, no locks held by
        /// the task across I/O); it only sets flags and events.
        f: *const fn (*anyopaque) i64,
    };

    /// Moves the deadline to `ms` from now (callable from the task).
    pub fn extend(w: *Watchdog, ms: i64) void {
        w.deadline_ms.store(nowMs(w.io) +| ms, .release);
    }

    /// Wakes the watching thread to re-check `abort` (any thread).
    pub fn poke(w: *Watchdog) void {
        w.done.set(w.io);
    }

    fn Ret(comptime func: anytype) type {
        return @typeInfo(@TypeOf(func)).@"fn".return_type.?;
    }

    /// Runs `func(args)` and returns its result. `extend` must have been
    /// called first. `tick` (if any) runs on this thread whenever it said it
    /// is next due (it only flags "ping due"). Event-driven: this thread
    /// sleeps until the task finishes, the deadline passes, the tick is
    /// due or `poke` is called.
    pub fn run(w: *Watchdog, comptime func: anytype, args: std.meta.ArgsTuple(@TypeOf(func)), tick: ?Tick) Ret(func) {
        const R = Ret(func);
        const Args = @TypeOf(args);
        const Wrap = struct {
            fn task(wd: *Watchdog, a: Args) R {
                defer {
                    wd.finished.store(true, .release);
                    wd.done.set(wd.io);
                }
                return @call(.auto, func, a);
            }
        };
        w.done.reset();
        w.finished.store(false, .release);
        w.expired.store(false, .release);
        w.stopped.store(false, .seq_cst);
        // Without concurrency (should not happen with std.Io.Threaded) run
        // inline: the OS limits still apply.
        var fut = w.io.concurrent(Wrap.task, .{ w, args }) catch return @call(.auto, func, args);
        var tick_due: i64 = if (tick) |t| t.f(t.ctx) else std.math.maxInt(i64);
        while (true) {
            if (w.finished.load(.acquire)) return fut.await(w.io);
            if (w.abort) |a| if (a.load(.acquire)) {
                w.stopped.store(true, .seq_cst);
                return fut.cancel(w.io);
            };
            const now = nowMs(w.io);
            if (now >= w.deadline_ms.load(.acquire)) {
                w.expired.store(true, .release);
                w.stopped.store(true, .seq_cst);
                return fut.cancel(w.io);
            }
            if (tick) |t| if (now >= tick_due) {
                tick_due = t.f(t.ctx);
                continue;
            };
            // The task may move the deadline while this thread sleeps;
            // waking at the old one just re-reads it.
            const wake_at = @min(w.deadline_ms.load(.acquire), tick_due);
            w.done.waitTimeout(w.io, .{ .duration = .{ .raw = .fromMilliseconds(@max(wake_at - now, 1)), .clock = .awake } }) catch |err| switch (err) {
                error.Timeout => {},
                // This thread is itself a canceled task: stop ours, keep
                // the cancelation armed for the caller's next Io call.
                error.Canceled => {
                    w.stopped.store(true, .seq_cst);
                    const r = fut.cancel(w.io);
                    w.io.recancel();
                    return r;
                },
            };
            // A poke without a finished task: re-arm the event, then
            // re-check (a finish after the reset sets it again).
            if (!w.finished.load(.acquire)) w.done.reset();
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

test "abort cancels the task early; poke alone does not" {
    const io = std.testing.io;
    var w: Watchdog = .{ .io = io };
    var flag: std.atomic.Value(bool) = .init(false);
    w.abort = &flag;
    const T = struct {
        fn stall(i: Io) Io.Cancelable!u32 {
            try i.sleep(.fromSeconds(30), .awake);
            return 7;
        }
        fn quick(i: Io) Io.Cancelable!u32 {
            try i.sleep(.fromMilliseconds(100), .awake);
            return 1;
        }
        fn later(wd: *Watchdog, f: *std.atomic.Value(bool), i: Io, set: bool) void {
            i.sleep(.fromMilliseconds(50), .awake) catch return;
            if (set) f.store(true, .release);
            wd.poke();
        }
    };
    // A poke with no abort: the task still finishes normally.
    w.extend(5000);
    var p1 = try io.concurrent(T.later, .{ &w, &flag, io, false });
    try std.testing.expectEqual(@as(u32, 1), try w.run(T.quick, .{io}, null));
    p1.await(io);
    // An abort ends a stalled task long before its deadline.
    w.extend(20_000);
    const t0 = nowMs(io);
    var p2 = try io.concurrent(T.later, .{ &w, &flag, io, true });
    try std.testing.expectError(error.Canceled, w.run(T.stall, .{io}, null));
    p2.await(io);
    try std.testing.expect(w.stopped.load(.acquire) and !w.expired.load(.acquire));
    try std.testing.expect(nowMs(io) - t0 < 5000);
}
