//! The one terminal session Portal exposes: PTY output fan-out to the local
//! console and any number of web viewers, and serialised keystroke input.

const std = @import("std");
const Io = std.Io;
const Ring = @import("ring.zig").Ring;
const Pty = @import("conpty.zig").Pty;
const Size = @import("conpty.zig").Size;
const Console = @import("console.zig").Console;
const input_filter = @import("input_filter.zig");
const Policy = input_filter.Policy;

pub const Session = struct {
    io: Io,
    pty: *Pty,
    console: *Console,
    policy: Policy,

    /// Guards everything below except `input_mutex`'s domain.
    mutex: Io.Mutex = .init,
    /// Broadcast on new output, resize, close, or a viewer disconnecting.
    cond: Io.Condition = .init,
    ring: Ring,
    size: Size,
    size_gen: u32 = 0,
    closed: bool = false,
    exit_code: u32 = 0,
    viewers: u32 = 0,
    last_redraw_ms: i64 = std.math.minInt(i64),

    /// Serialises writes into the PTY from the local console and web viewers
    /// so keystroke sequences never interleave mid-sequence.
    input_mutex: Io.Mutex = .init,
    /// Guarded by input_mutex.
    web_filter: input_filter.State = .{},

    pub fn appendOutput(s: *Session, data: []const u8) void {
        s.mutex.lockUncancelable(s.io);
        s.ring.append(data);
        s.mutex.unlock(s.io);
        s.cond.broadcast(s.io);
    }

    /// Keystrokes from a web viewer: filtered by the session's policy with
    /// cross-message state shared across all viewers (see input_filter.State).
    pub fn writeWebInput(s: *Session, data: []const u8, now_ms: i64) void {
        if (s.policy == .none or data.len == 0 or data.len > 4096) return;
        var buf: [4096]u8 = undefined;
        s.input_mutex.lockUncancelable(s.io);
        defer s.input_mutex.unlock(s.io);
        if (s.pty.closed) return;
        const keys = input_filter.filterStateful(s.policy, &s.web_filter, data, &buf, now_ms);
        if (keys.len > 0) s.pty.write(keys) catch {};
    }

    /// Keystrokes from the desktop's own console: unfiltered.
    pub fn writeInput(s: *Session, data: []const u8) void {
        if (data.len == 0) return;
        s.input_mutex.lockUncancelable(s.io);
        defer s.input_mutex.unlock(s.io);
        if (s.pty.closed) return;
        s.pty.write(data) catch {};
    }

    /// Called by the local console resize poller. The desktop window decides
    /// the terminal size; web viewers adapt to it.
    pub fn setSize(s: *Session, size: Size) void {
        s.mutex.lockUncancelable(s.io);
        const changed = size.cols != s.size.cols or size.rows != s.size.rows;
        if (changed) {
            s.size = size;
            s.size_gen +%= 1;
            if (!s.closed) s.pty.resize(size);
        }
        s.mutex.unlock(s.io);
        if (changed) s.cond.broadcast(s.io);
    }

    /// A newly attached viewer only sees scrollback, which for a full-screen
    /// TUI may not reconstruct the screen. Nudging the size makes the program
    /// repaint. Rate limited, since it also repaints the desktop console.
    pub fn requestRedraw(s: *Session, now_ms: i64) void {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        // Saturating: last_redraw_ms starts at minInt, and a plain `-` overflowed
        // (panicking the whole process) on the first viewer's redraw.
        if (s.closed or now_ms -| s.last_redraw_ms < 2000) return;
        s.last_redraw_ms = now_ms;
        const sz = s.size;
        s.pty.resize(.{ .cols = sz.cols, .rows = @max(sz.rows, 2) - 1 });
        s.pty.resize(sz);
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
        if (delta > 0) s.viewers += @intCast(delta) else s.viewers -|= @intCast(-delta);
        return s.viewers;
    }
};
