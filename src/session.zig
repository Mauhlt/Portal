//! One terminal session (one project tab, tabs.zig): PTY output fan-out to
//! the local window (or console) and any number of web viewers, and
//! serialised keystroke input.

const std = @import("std");
const Io = std.Io;
const vt = @import("vt.zig");
const Pty = @import("conpty.zig").Pty;
const Size = @import("conpty.zig").Size;
const Console = @import("console.zig").Console;
const keymap = @import("keymap.zig");
const Policy = keymap.Policy;
const convo_model = @import("convo/model.zig");

pub const Session = struct {
    io: Io,
    pty: *Pty,
    /// The desktop console in `portal run --console`; a detached no-op
    /// Console in the GUI (web.zig sets its title on viewer changes).
    console: *Console,
    policy: Policy,
    /// Writes the desktop's own input (window or console) into the PTY on
    /// its own thread, so the GUI thread never blocks on the pipe (a big
    /// paste, or a program not reading its input). Null in unit tests:
    /// writeInput then writes directly.
    local: ?*LocalInput = null,
    /// Optional change hook: the local GUI uses it to wake its message loop
    /// on output, resize, close or a viewer change. Set before any thread
    /// starts; called after `mutex` is released, on the changing thread.
    notify_ctx: ?*anyopaque = null,
    notify_fn: ?*const fn (ctx: *anyopaque) void = null,

    /// Guards everything below except `input_mutex`'s domain. Shared by
    /// every tab (tabs.Hub.mutex), so a viewer can wait for its own
    /// session and the tab list at once.
    mutex: *Io.Mutex,
    /// Broadcast on new output, resize, close, a tab list change, or a
    /// viewer disconnecting (tabs.Hub.cond, shared like `mutex`).
    cond: *Io.Condition,
    /// Display-only emulation of the session's screen. Web viewers receive
    /// rendered rows from it (docs/protocol.md); they never see raw output.
    term: vt.Terminal,
    size: Size,
    closed: bool = false,
    exit_code: u32 = 0,
    /// The program's OSC 7501 state as last seen (term.program_state),
    /// and the tab list's generation, bumped when it changes (tabs.Hub.gen;
    /// null outside a hub).
    state: vt.ProgramState = .unknown,
    list_gen: ?*u64 = null,
    /// The tab's Conversation view (tabs.Tab.convo; null outside a hub):
    /// told when the program starts or stops waiting for an answer.
    convo: ?*convo_model.Convo = null,
    wait: convo_model.Wait = .none,
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
    /// Guarded by input_mutex. When a bare Esc from a web viewer was last
    /// written. Any web input that follows within `esc_gap_ms` is held back
    /// until the gap has passed, so the program can't read Esc + key as
    /// Alt+key (a different shortcut).
    last_esc_write_ms: i64 = std.math.minInt(i64),
    /// Guarded by input_mutex. Text mode's leading-`!` filter.
    text_guard: keymap.TextGuard = .{},
    /// Guarded by input_mutex. False once shutdown has begun; no write may
    /// touch the PTY input pipe after that, since it is about to be closed.
    input_open: bool = true,
    /// Set (before taking input_mutex) when shutdown begins: a long local
    /// write stops at its next chunk, so shutdown waits for at most one
    /// chunk, never for a whole paste.
    input_closing: std.atomic.Value(bool) = .init(false),

    pub fn appendOutput(s: *Session, data: []const u8) void {
        s.mutex.lockUncancelable(s.io);
        s.term.feed(data);
        if (s.term.program_state != s.state) {
            s.state = s.term.program_state;
            if (s.list_gen) |g| g.* +%= 1;
        }
        const wait: convo_model.Wait = if (s.term.program_state != .waiting) .none else if (s.term.program_kind == .permission) .permission else .other;
        if (wait != s.wait) {
            s.wait = wait;
            if (s.convo) |c| c.programState(wait);
        }
        s.mutex.unlock(s.io);
        s.cond.broadcast(s.io);
        s.notify();
    }

    fn notify(s: *Session) void {
        if (s.notify_fn) |f| if (s.notify_ctx) |c| f(c);
    }

    /// A key pressed in a web viewer, by protocol name. Portal generates the
    /// bytes itself (keymap.zig); unknown or disallowed names are dropped.
    pub fn writeWebKey(s: *Session, name: []const u8, now_ms: i64) void {
        const bytes = keymap.keyBytes(s.policy, name) orelse return;
        s.input_mutex.lockUncancelable(s.io);
        defer s.input_mutex.unlock(s.io);
        if (!s.input_open) return;
        if ((s.policy == .keys or s.policy == .instruct) and std.mem.eql(u8, name, "esc")) {
            if (withinWindow(now_ms, s.last_web_esc_ms, 1000)) return;
            s.last_web_esc_ms = now_ms;
        }
        s.text_guard.onKey(name);
        s.escGap();
        s.pty.write(bytes) catch {};
        if (std.mem.eql(u8, bytes, "\x1b")) s.last_esc_write_ms = s.clockMs();
    }

    fn clockMs(s: *Session) i64 {
        return Io.Timestamp.now(s.io, .awake).toMilliseconds();
    }

    /// Caller holds input_mutex. Waits out the rest of the gap after a web
    /// Esc (at most `esc_gap_ms`), keeping later input in order behind it.
    fn escGap(s: *Session) void {
        const d = escGapDelay(s.clockMs(), s.last_esc_write_ms, esc_gap_ms);
        if (d > 0) s.io.sleep(.fromMilliseconds(d), .awake) catch {};
    }

    /// Text typed in a web viewer (text mode only), reduced to printable
    /// characters (keymap.sanitizeText), with a leading `!` per line dropped
    /// (keymap.TextGuard) so a device can't flip the agent into shell mode.
    pub fn writeWebText(s: *Session, text: []const u8) void {
        if (text.len == 0 or text.len > 4096) return;
        var buf: [4096]u8 = undefined;
        const clean = keymap.sanitizeText(s.policy, text, &buf);
        if (clean.len == 0) return;
        s.input_mutex.lockUncancelable(s.io);
        defer s.input_mutex.unlock(s.io);
        if (!s.input_open) return;
        const allowed = s.text_guard.filter(clean);
        if (allowed.len == 0) return;
        s.escGap();
        s.pty.write(allowed) catch {};
    }

    /// A whole instruction line from a web viewer (instruct and text modes).
    /// Validated by keymap.validateLine (no `!`/`/`/`#` prefix, no control
    /// characters), then typed and submitted. When the program has enabled
    /// bracketed paste it is sent as a paste, so characters such as `?` are
    /// not taken as keyboard shortcuts. Returns why it was rejected, if it was.
    pub fn writeWebLine(s: *Session, line: []const u8) keymap.LineError!void {
        if (s.policy != .instruct and s.policy != .text) return error.Empty;
        const text = try keymap.validateLine(line);
        s.mutex.lockUncancelable(s.io);
        const paste = s.term.bracketedPaste();
        s.mutex.unlock(s.io);
        s.input_mutex.lockUncancelable(s.io);
        defer s.input_mutex.unlock(s.io);
        if (!s.input_open) return;
        s.escGap();
        if (paste) s.pty.write("\x1b[200~") catch return;
        s.pty.write(text) catch return;
        if (paste) s.pty.write("\x1b[201~") catch return;
        s.pty.write("\r") catch return;
        s.text_guard.at_line_start = true;
    }

    /// Keystrokes and pastes from the desktop's own console or window:
    /// unfiltered. Never blocks on the PTY: queued for the LocalInput
    /// writer thread (when there is one).
    pub fn writeInput(s: *Session, data: []const u8) void {
        if (data.len == 0) return;
        if (s.local) |l| return l.push(data);
        s.writeLocal(data);
    }

    /// Largest piece of local input written at once.
    pub const input_chunk = 4096;

    /// Writes one local input item (a key's bytes, or a whole paste) in
    /// `input_chunk` pieces under input_mutex, so web input never lands
    /// inside it; stops early once shutdown has begun.
    pub fn writeLocal(s: *Session, data: []const u8) void {
        s.input_mutex.lockUncancelable(s.io);
        defer s.input_mutex.unlock(s.io);
        var rest = data;
        while (rest.len > 0) {
            if (!s.input_open or s.input_closing.load(.acquire)) return;
            const n = @min(rest.len, input_chunk);
            s.pty.write(rest[0..n]) catch return;
            rest = rest[n..];
        }
    }

    /// Called by the local console resize poller or the GUI window. The
    /// desktop decides the terminal size; web viewers adapt to it.
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
        if (changed) {
            s.cond.broadcast(s.io);
            s.notify();
        }
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

        s.input_closing.store(true, .release);
        s.input_mutex.lockUncancelable(s.io);
        s.input_open = false;
        s.input_mutex.unlock(s.io);
        if (s.local) |l| l.close();

        s.pty.closeConsole();
    }

    pub fn markClosed(s: *Session, code: u32) void {
        s.mutex.lockUncancelable(s.io);
        s.closed = true;
        s.exit_code = code;
        s.mutex.unlock(s.io);
        s.cond.broadcast(s.io);
        s.notify();
    }
};

/// The queue between the desktop's input (GUI thread, console input
/// thread) and the PTY. `push` never blocks on the pipe; `run` (its own
/// thread) writes each queued item with Session.writeLocal, in order.
/// Event-driven: the writer sleeps on a condition until something is
/// queued or the queue is closed.
pub const LocalInput = struct {
    gpa: std.mem.Allocator,
    io: Io,
    session: *Session,
    mutex: Io.Mutex = .init,
    cond: Io.Condition = .init,
    /// Queued bytes, item after item; `lens` gives each item's length.
    bytes: std.ArrayList(u8) = .empty,
    lens: std.ArrayList(usize) = .empty,
    closed: bool = false,

    /// More than this waiting (a stuck program, pastes piling up) and new
    /// input is dropped rather than growing without bound.
    pub const max_queued = 8 << 20;

    pub fn push(l: *LocalInput, data: []const u8) void {
        l.mutex.lockUncancelable(l.io);
        defer l.mutex.unlock(l.io);
        if (l.closed or l.bytes.items.len + data.len > max_queued) return;
        l.lens.append(l.gpa, data.len) catch return;
        l.bytes.appendSlice(l.gpa, data) catch {
            l.lens.items.len -= 1;
            return;
        };
        l.cond.signal(l.io);
    }

    pub fn deinit(l: *LocalInput) void {
        l.bytes.deinit(l.gpa);
        l.lens.deinit(l.gpa);
    }

    /// Ends `run` (shutdown); later pushes are dropped.
    pub fn close(l: *LocalInput) void {
        l.mutex.lockUncancelable(l.io);
        l.closed = true;
        l.mutex.unlock(l.io);
        l.cond.broadcast(l.io);
    }

    /// The writer thread.
    pub fn run(l: *LocalInput) void {
        var item: std.ArrayList(u8) = .empty;
        defer item.deinit(l.gpa);
        while (true) {
            l.mutex.lockUncancelable(l.io);
            while (!l.closed and l.lens.items.len == 0) l.cond.waitUncancelable(l.io, &l.mutex);
            if (l.closed) {
                l.mutex.unlock(l.io);
                return;
            }
            const n = l.lens.items[0];
            item.clearRetainingCapacity();
            const ok = if (item.appendSlice(l.gpa, l.bytes.items[0..n])) true else |_| false;
            // Take the item off the queue (also when it could not be copied:
            // dropped, like input that does not fit).
            std.mem.copyForwards(u8, l.bytes.items, l.bytes.items[n..]);
            l.bytes.items.len -= n;
            std.mem.copyForwards(usize, l.lens.items, l.lens.items[1..]);
            l.lens.items.len -= 1;
            l.mutex.unlock(l.io);
            if (ok) l.session.writeLocal(item.items);
        }
    }
};

/// Gap enforced after a web Esc before the next web input is written.
pub const esc_gap_ms: i64 = 50;

/// How long to wait before writing input at `now` when a bare Esc was
/// written at `last_esc`: the rest of `gap`, or 0.
pub fn escGapDelay(now: i64, last_esc: i64, gap: i64) i64 {
    if (!withinWindow(now, last_esc, gap)) return 0;
    return gap - (now - last_esc);
}

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

test "escGapDelay" {
    const min = std.math.minInt(i64);
    try std.testing.expectEqual(@as(i64, 0), escGapDelay(1000, min, 50));
    try std.testing.expectEqual(@as(i64, 50), escGapDelay(1000, 1000, 50));
    try std.testing.expectEqual(@as(i64, 20), escGapDelay(1030, 1000, 50));
    try std.testing.expectEqual(@as(i64, 0), escGapDelay(1050, 1000, 50));
    try std.testing.expectEqual(@as(i64, 0), escGapDelay(900, 1000, 50)); // clock went back
}

test "LocalInput writes queued items whole and in order, on its own thread" {
    const w = @import("win32.zig");
    const gpa = std.testing.allocator;
    var rd: w.HANDLE = undefined;
    var wr: w.HANDLE = undefined;
    if (w.CreatePipe(&rd, &wr, null, 1 << 16) == 0) return error.SkipZigTest;
    defer _ = w.CloseHandle(rd);
    defer _ = w.CloseHandle(wr);
    var pty: Pty = .{ .hpc = undefined, .in_write = wr, .out_read = undefined, .process = undefined, .job = undefined };
    var mu: Io.Mutex = .init;
    var cv: Io.Condition = .init;
    var s: Session = .{
        .io = std.testing.io,
        .mutex = &mu,
        .cond = &cv,
        .pty = &pty,
        .console = undefined,
        .policy = .keys,
        .term = try vt.Terminal.init(gpa, 10, 5),
        .size = .{ .cols = 10, .rows = 5 },
    };
    defer s.term.deinit();
    var l: LocalInput = .{ .gpa = gpa, .io = std.testing.io, .session = &s };
    defer l.deinit();
    s.local = &l;
    // Queued before the writer runs: the caller never touches the pipe.
    const big: [3 * Session.input_chunk + 5]u8 = @splat('p');
    s.writeInput("a");
    s.writeInput(&big);
    s.writeInput("z");
    try std.testing.expectEqual(@as(usize, 3), l.lens.items.len);
    const t = try std.Thread.spawn(.{}, LocalInput.run, .{&l});
    var got: [big.len + 2]u8 = undefined;
    var n: usize = 0;
    while (n < got.len) {
        var r: w.DWORD = 0;
        if (w.ReadFile(rd, got[n..].ptr, @intCast(got.len - n), &r, null) == 0) return error.ReadFailed;
        n += r;
    }
    l.close();
    t.join();
    try std.testing.expectEqual(@as(u8, 'a'), got[0]);
    try std.testing.expectEqualSlices(u8, &big, got[1 .. 1 + big.len]);
    try std.testing.expectEqual(@as(u8, 'z'), got[got.len - 1]);
    // After close, input is dropped.
    s.writeInput("x");
    try std.testing.expectEqual(@as(usize, 0), l.lens.items.len);
}

test "writeLocal stops at the next chunk once shutdown begins" {
    const w = @import("win32.zig");
    var rd: w.HANDLE = undefined;
    var wr: w.HANDLE = undefined;
    if (w.CreatePipe(&rd, &wr, null, 1 << 16) == 0) return error.SkipZigTest;
    defer _ = w.CloseHandle(rd);
    defer _ = w.CloseHandle(wr);
    var pty: Pty = .{ .hpc = undefined, .in_write = wr, .out_read = undefined, .process = undefined, .job = undefined };
    var mu: Io.Mutex = .init;
    var cv: Io.Condition = .init;
    var s: Session = .{
        .io = std.testing.io,
        .mutex = &mu,
        .cond = &cv,
        .pty = &pty,
        .console = undefined,
        .policy = .keys,
        .term = try vt.Terminal.init(std.testing.allocator, 10, 5),
        .size = .{ .cols = 10, .rows = 5 },
    };
    defer s.term.deinit();
    s.input_closing.store(true, .release);
    const big: [2 * Session.input_chunk]u8 = @splat('p');
    s.writeLocal(&big);
    var avail: w.DWORD = 0;
    try std.testing.expect(w.PeekNamedPipe(rd, null, 0, null, &avail, null) != 0);
    try std.testing.expectEqual(@as(w.DWORD, 0), avail);
}
