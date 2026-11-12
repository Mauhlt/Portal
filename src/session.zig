//! The one terminal session Portal exposes: PTY output fan-out to the local
//! console and any number of web viewers, and serialised keystroke input.

const std = @import("std");
const Io = std.Io;
const vt = @import("vt.zig");
const Pty = @import("conpty.zig").Pty;
const Size = @import("conpty.zig").Size;
const Console = @import("console.zig").Console;
const keymap = @import("keymap.zig");
const Policy = keymap.Policy;

pub const Session = struct {
    io: Io,
    pty: *Pty,
    console: *Console,
    policy: Policy,

    /// Guards everything below except `input_mutex`'s domain.
    mutex: Io.Mutex = .init,
    /// Broadcast on new output, resize, close, or a viewer disconnecting.
    cond: Io.Condition = .init,
    /// Display-only emulation of the session's screen. Web viewers receive
    /// rendered rows from it (docs/protocol.md); they never see raw output.
    term: vt.Terminal,
    size: Size,
    closed: bool = false,
    exit_code: u32 = 0,
    viewers: u32 = 0,
    /// False once shutdown has begun closing the pseudo console. Distinct
    /// from `closed` (which tells viewers the session ended, and is only set
    /// after trailing output has drained): no ResizePseudoConsole may be
    /// issued once this is false, since the HPCON is about to be freed.
    pty_live: bool = true,

    /// Serialises writes into the PTY from the local console and web viewers
    /// so keystroke sequences never interleave mid-sequence.
    input_mutex: Io.Mutex = .init,
    /// Guarded by input_mutex. Keys mode lets through at most one Esc per
    /// second, so a viewer can't send Esc Esc (the agent's rewind menu).
    last_web_esc_ms: i64 = std.math.minInt(i64),
    /// Guarded by input_mutex. False once shutdown has begun; no write may
    /// touch the PTY input pipe after that, since it is about to be closed.
    input_open: bool = true,

    pub fn appendOutput(s: *Session, data: []const u8) void {
        s.mutex.lockUncancelable(s.io);
        s.term.feed(data);
        s.mutex.unlock(s.io);
        s.cond.broadcast(s.io);
    }

    /// A key pressed in a web viewer, by protocol name. Portal generates the
    /// bytes itself (keymap.zig); unknown or disallowed names are dropped.
    pub fn writeWebKey(s: *Session, name: []const u8, now_ms: i64) void {
        const bytes = keymap.keyBytes(s.policy, name) orelse return;
        s.input_mutex.lockUncancelable(s.io);
        defer s.input_mutex.unlock(s.io);
        if (!s.input_open) return;
        if (s.policy == .keys and std.mem.eql(u8, name, "esc")) {
            if (withinWindow(now_ms, s.last_web_esc_ms, 1000)) return;
            s.last_web_esc_ms = now_ms;
        }
        s.pty.write(bytes) catch {};
    }

    /// Text typed in a web viewer (text mode only), reduced to printable
    /// characters (keymap.sanitizeText).
    pub fn writeWebText(s: *Session, text: []const u8) void {
        if (text.len == 0 or text.len > 4096) return;
        var buf: [4096]u8 = undefined;
        const clean = keymap.sanitizeText(s.policy, text, &buf);
        if (clean.len == 0) return;
        s.input_mutex.lockUncancelable(s.io);
        defer s.input_mutex.unlock(s.io);
        if (!s.input_open) return;
        s.pty.write(clean) catch {};
    }

    /// Keystrokes from the desktop's own console: unfiltered.
    pub fn writeInput(s: *Session, data: []const u8) void {
        if (data.len == 0) return;
        s.input_mutex.lockUncancelable(s.io);
        defer s.input_mutex.unlock(s.io);
        if (!s.input_open) return;
        s.pty.write(data) catch {};
    }

    /// Called by the local console resize poller. The desktop window decides
    /// the terminal size; web viewers adapt to it.
    pub fn setSize(s: *Session, size: Size) void {
        s.mutex.lockUncancelable(s.io);
        const changed = size.cols != s.size.cols or size.rows != s.size.rows;
        if (changed) {
            // Only adopt the new size if the emulator could allocate for it,
            // so the emulator and the pseudo console never disagree.
            if (s.term.resize(size.cols, size.rows)) |_| {
                s.size = size;
                if (s.pty_live) s.pty.resize(size);
            } else |_| {}
        }
        s.mutex.unlock(s.io);
        if (changed) s.cond.broadcast(s.io);
    }

    /// Shuts the pseudo console down safely with respect to the resize
    /// poller and web viewers, then closes it. Neither lock is held across
    /// ClosePseudoConsole: before 24H2 it blocks until conhost has flushed
    /// its output, and the drain thread needs `mutex` (appendOutput) to make
    /// progress, so holding `mutex` would deadlock. `input_mutex` is held
    /// only long enough to flip `input_open`; it waits at most for one
    /// in-flight write (<= 4 KiB, which conhost consumes while alive) rather
    /// than for the whole ClosePseudoConsole.
    pub fn shutdownPty(s: *Session) void {
        s.mutex.lockUncancelable(s.io);
        s.pty_live = false;
        s.mutex.unlock(s.io);

        s.input_mutex.lockUncancelable(s.io);
        s.input_open = false;
        s.input_mutex.unlock(s.io);

        s.pty.close();
    }

    pub fn markClosed(s: *Session, code: u32) void {
        s.mutex.lockUncancelable(s.io);
        s.closed = true;
        s.exit_code = code;
        s.mutex.unlock(s.io);
        s.cond.broadcast(s.io);
    }

    pub fn viewerDelta(s: *Session, delta: i32) u32 {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        // Saturating both ways; @abs avoids overflow negating minInt(i32).
        if (delta > 0) s.viewers +|= @abs(delta) else s.viewers -|= @abs(delta);
        return s.viewers;
    }
};

/// True if `now` is less than `window` ms after `last`. A clock that went
/// backwards (now < last) counts as outside the window, so a time jump can't
/// lock a rate-limited action out for hours. Saturating, never overflows.
pub fn withinWindow(now: i64, last: i64, window: i64) bool {
    const dt = now -| last;
    return dt >= 0 and dt < window;
}

test "withinWindow" {
    const min = std.math.minInt(i64);
    const max = std.math.maxInt(i64);
    try std.testing.expect(!withinWindow(0, min, 2000));
    try std.testing.expect(!withinWindow(min, max, 2000));
    try std.testing.expect(!withinWindow(max, min, 2000));
    try std.testing.expect(withinWindow(1000, 0, 2000));
    try std.testing.expect(!withinWindow(2000, 0, 2000));
    try std.testing.expect(!withinWindow(0, 1000, 2000)); // clock went back
}

test "viewerDelta saturates" {
    var s: Session = .{
        .io = std.testing.io,
        .pty = undefined,
        .console = undefined,
        .policy = .keys,
        .term = try vt.Terminal.init(std.testing.allocator, 80, 24),
        .size = .{ .cols = 80, .rows = 24 },
    };
    defer s.term.deinit();
    try std.testing.expectEqual(@as(u32, 1), s.viewerDelta(1));
    try std.testing.expectEqual(@as(u32, 0), s.viewerDelta(-1));
    try std.testing.expectEqual(@as(u32, 0), s.viewerDelta(-1));
    try std.testing.expectEqual(@as(u32, 0), s.viewerDelta(std.math.minInt(i32)));
    s.viewers = std.math.maxInt(u32);
    try std.testing.expectEqual(std.math.maxInt(u32), s.viewerDelta(std.math.maxInt(i32)));
}
