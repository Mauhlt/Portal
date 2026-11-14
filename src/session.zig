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
const Poke = @import("convo/follow.zig").Poke;
const hookmsg = @import("hookmsg.zig");

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
    /// The program's state: from OSC 7501 (term.program_state) or from
    /// an agent hook (setHookState), whichever changed last (a `wait` of
    /// `.permission` only ever from a hook: oscWait); and the
    /// tab list's generation, bumped when it changes (tabs.Hub.gen; null
    /// outside a hub).
    state: vt.ProgramState = .unknown,
    /// The OSC 7501 state and kind as last seen, so a hook's state stays
    /// until the program reports a new one of its own.
    osc_state: vt.ProgramState = .unknown,
    osc_kind: vt.ProgramKind = .none,
    /// `state` was set by a hook (hookmsg.zig), not by OSC 7501.
    hook_state: bool = false,
    list_gen: ?*u64 = null,
    /// Called (with `mutex` held) whenever `state` or `wait` changes: the
    /// tab's For-you cards (tabs.zig). Must not take `mutex`.
    state_ctx: ?*anyopaque = null,
    state_fn: ?*const fn (ctx: *anyopaque) void = null,
    /// The tab's Conversation view (tabs.Tab.convo; null outside a hub):
    /// told when the program starts or stops waiting for an answer.
    convo: ?*convo_model.Convo = null,
    wait: convo_model.Wait = .none,
    /// Poked after every piece of output (OSC 7501 state changes are output
    /// too): the transcript follower looks at what the program wrote. Cheap
    /// and coalesced (follow.Poke). Null outside a hub.
    convo_poke: ?*Poke = null,
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
        var reply_buf: [vt.max_reply_bytes]u8 = undefined;
        s.mutex.lockUncancelable(s.io);
        s.term.feed(data);
        // The OSC 7501 feature-detection reply (vt.zig): fixed bytes, asked
        // for by the program's own output, so it goes in like the desktop's
        // own input (writeInput), never through a device's policy.
        const reply = s.term.takeReplies(&reply_buf);
        if (s.term.program_state != s.osc_state or s.term.program_kind != s.osc_kind) {
            s.osc_state = s.term.program_state;
            s.osc_kind = s.term.program_kind;
            s.hook_state = false;
            const wait = oscWait(s.osc_state, s.osc_kind, s.wait);
            _ = s.setStateLocked(s.osc_state, wait);
        }
        s.mutex.unlock(s.io);
        if (reply.len > 0) s.writeInput(reply);
        s.cond.broadcast(s.io);
        s.notify();
        if (s.convo_poke) |p| p.poke();
    }

    /// Caller holds `mutex`. True if anything changed.
    fn setStateLocked(s: *Session, state: vt.ProgramState, wait: convo_model.Wait) bool {
        var changed = false;
        if (state != s.state) {
            s.state = state;
            if (s.list_gen) |g| g.* +%= 1;
            changed = true;
        }
        if (wait != s.wait) {
            s.wait = wait;
            if (s.convo) |c| c.programState(wait);
            changed = true;
        }
        if (changed) if (s.state_fn) |f| f(s.state_ctx.?);
        return changed;
    }

    /// An agent hook reported the program's state (tabs.Hub.applyHook,
    /// hookmsg.effect). The same paths as OSC 7501: the tab list's
    /// generation, the Conversation view's question, every viewer and the
    /// window woken. True if the state changed.
    pub fn setHookState(s: *Session, e: hookmsg.Effect) bool {
        s.mutex.lockUncancelable(s.io);
        s.hook_state = true;
        if (e.cat) |cat| if (s.convo) |c| c.permissionHint(cat);
        const changed = s.setStateLocked(e.state, e.wait);
        s.mutex.unlock(s.io);
        s.cond.broadcast(s.io);
        s.notify();
        return changed;
    }

    /// Caller holds `mutex`. The transcript shows the program went on
    /// after a hook said it waits for a permission answer (a tool result:
    /// the prompt was answered), or that the owner interrupted it (no Stop
    /// hook follows an interrupt). Hooks report no "working again" of
    /// their own here (PreToolUse/PostToolUse are not used: too chatty).
    /// True if the state changed.
    pub fn transcriptMovedOnLocked(s: *Session, tool_result: bool, interrupted: bool) bool {
        if (!s.hook_state) return false;
        if (interrupted) return s.setStateLocked(.idle, .none);
        if (tool_result and s.state == .waiting and s.wait == .permission) return s.setStateLocked(.working, .none);
        return false;
    }

    fn notify(s: *Session) void {
        if (s.notify_fn) |f| if (s.notify_ctx) |c| f(c);
    }

    /// Whether the program waits for an answer: its OSC 7501 state is
    /// `blocked`, or the Conversation view has an open question (an
    /// AskUserQuestion the transcript shows unanswered). Caller holds
    /// `mutex`. A program that never reports OSC 7501 and asks nothing
    /// in its transcript is never waiting.
    fn waitingLocked(s: *const Session) bool {
        if (s.state == .waiting) return true;
        const c = s.convo orelse return false;
        return c.hasOpenQuestion();
    }

    /// A key pressed in a web viewer, by protocol name. Portal generates the
    /// bytes itself (keymap.zig); unknown or disallowed names are dropped.
    /// Up/Down in instruct mode go through only while the program waits for
    /// an answer (keymap.keyBytesAt), decided now, as the key arrives:
    /// otherwise error.NotWaiting (the viewer is told).
    pub fn writeWebKey(s: *Session, name: []const u8, now_ms: i64) keymap.KeyError!void {
        const waiting = if (s.policy == .instruct and keymap.isMenuKey(name)) blk: {
            s.mutex.lockUncancelable(s.io);
            defer s.mutex.unlock(s.io);
            break :blk s.waitingLocked();
        } else false;
        const bytes = (try keymap.keyBytesAt(s.policy, waiting, name)) orelse return;
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
        return s.writeDeskLine(line);
    }

    /// A line the desk itself made (a For-you question's "Yes." / "No.",
    /// foryou_ws.zig, whose input mode the caller checked): the line rules
    /// of writeWebLine, in any input mode.
    pub fn writeDeskLine(s: *Session, line: []const u8) keymap.LineError!void {
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
        // The desk may have pressed Enter (or erased the line): a device's
        // next `!` counts as first on the line again (TextGuard).
        if (data.len > 0) s.text_guard.at_line_start = true;
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

/// What an OSC 7501 report means for `Session.wait`. Any program in the
/// tab can print one (shared/tabs.zig: untrusted, a highlight only), so
/// `blocked` is never a permission prompt of its own: that is `.other` (a
/// question without answer keys). A permission prompt comes only from an
/// agent hook (setHookState); one already known stays while the program
/// also reports `kind=permission`.
pub fn oscWait(state: vt.ProgramState, kind: vt.ProgramKind, current: convo_model.Wait) convo_model.Wait {
    if (state != .waiting) return .none;
    if (kind == .permission and current == .permission) return .permission;
    return .other;
}

test "oscWait: OSC 7501 never makes a permission prompt" {
    try std.testing.expectEqual(convo_model.Wait.other, oscWait(.waiting, .permission, .none));
    try std.testing.expectEqual(convo_model.Wait.other, oscWait(.waiting, .permission, .other));
    try std.testing.expectEqual(convo_model.Wait.permission, oscWait(.waiting, .permission, .permission));
    try std.testing.expectEqual(convo_model.Wait.other, oscWait(.waiting, .none, .permission));
    try std.testing.expectEqual(convo_model.Wait.none, oscWait(.working, .permission, .permission));
}

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

test "instruct: Up/Down only while the program waits (OSC 7501 or an open question)" {
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
        .policy = .instruct,
        .term = try vt.Terminal.init(gpa, 10, 5),
        .size = .{ .cols = 10, .rows = 5 },
    };
    defer s.term.deinit();
    const T = struct {
        fn pending(h: w.HANDLE) usize {
            var avail: w.DWORD = 0;
            if (PeekNamedPipe(h, null, 0, null, &avail, null) == 0) return 0;
            return avail;
        }
        fn drain(h: w.HANDLE, buf: []u8) []u8 {
            var r: w.DWORD = 0;
            const n = pending(h);
            if (n == 0) return buf[0..0];
            _ = w.ReadFile(h, buf.ptr, @intCast(@min(n, buf.len)), &r, null);
            return buf[0..r];
        }
        extern "kernel32" fn PeekNamedPipe(h: w.HANDLE, buf: ?*anyopaque, size: w.DWORD, read: ?*w.DWORD, avail: ?*w.DWORD, left: ?*w.DWORD) callconv(.winapi) w.BOOL;
    };
    var buf: [64]u8 = undefined;
    // Unknown (no OSC 7501 yet): refused.
    try std.testing.expectError(error.NotWaiting, s.writeWebKey("up", 0));
    try std.testing.expectEqual(@as(usize, 0), T.pending(rd));
    // Working and idle: refused.
    for ([_][]const u8{ "working", "idle" }) |st| {
        var ob: [64]u8 = undefined;
        s.appendOutput(try std.fmt.bufPrint(&ob, "\x1b]7501;state={s}\x07", .{st}));
        try std.testing.expectError(error.NotWaiting, s.writeWebKey("down", 0));
        try std.testing.expectEqual(@as(usize, 0), T.pending(rd));
    }
    // Waiting (blocked): accepted.
    s.appendOutput("\x1b]7501;state=blocked:kind=permission\x07");
    try s.writeWebKey("up", 0);
    try s.writeWebKey("down", 0);
    try std.testing.expectEqualStrings("\x1b[A\x1b[B", T.drain(rd, &buf));
    // Still no other editing key.
    try s.writeWebKey("left", 0);
    try std.testing.expectEqual(@as(usize, 0), T.pending(rd));
    // Refused at once after the state leaves waiting.
    s.appendOutput("\x1b]7501;state=working\x07");
    try std.testing.expectError(error.NotWaiting, s.writeWebKey("up", 0));
    try std.testing.expectEqual(@as(usize, 0), T.pending(rd));
    // An open question in the Conversation view counts as waiting too
    // (the program reports `working`, or no OSC 7501 at all).
    var c = convo_model.Convo.init(gpa, .{});
    defer c.deinit();
    c.reset(true);
    s.convo = &c;
    try std.testing.expectError(error.NotWaiting, s.writeWebKey("up", 0));
    c.programState(.other);
    try s.writeWebKey("up", 0);
    try std.testing.expectEqualStrings("\x1b[A", T.drain(rd, &buf));
    c.programState(.none);
    try std.testing.expectError(error.NotWaiting, s.writeWebKey("up", 0));
    s.convo = null;
    // Answer keys are untouched by the gate.
    try s.writeWebKey("1", 0);
    try std.testing.expectEqualStrings("1", T.drain(rd, &buf));
    // keys mode never takes them, waiting or not; text mode always does.
    s.appendOutput("\x1b]7501;state=blocked\x07");
    s.policy = .keys;
    try s.writeWebKey("up", 0);
    try std.testing.expectEqual(@as(usize, 0), T.pending(rd));
    s.policy = .text;
    s.appendOutput("\x1b]7501;state=idle\x07");
    try s.writeWebKey("up", 0);
    try std.testing.expectEqualStrings("\x1b[A", T.drain(rd, &buf));
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

test "an OSC 7501 probe in the output is answered on the PTY input, nothing else is" {
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
        .policy = .text,
        .term = try vt.Terminal.init(gpa, 20, 5),
        .size = .{ .cols = 20, .rows = 5 },
    };
    defer s.term.deinit();
    s.appendOutput("hello\x1b]7501;state=idle\x07\x1b[c"); // no probe: nothing written
    s.appendOutput("\x1b]7501;"); // the probe, split across reads
    s.appendOutput("?\x07\x1b[c");
    // A device can't make one: web text and lines drop the control bytes.
    s.writeWebText("\x1b]7501;?\x07");
    try std.testing.expectError(error.ControlCharacter, s.writeWebLine("\x1b]7501;?\x07"));
    var got: [64]u8 = undefined;
    var avail: w.DWORD = 0;
    try std.testing.expect(w.PeekNamedPipe(rd, null, 0, null, &avail, null) != 0);
    var r: w.DWORD = 0;
    try std.testing.expect(w.ReadFile(rd, &got, avail, &r, null) != 0);
    // The reply, then whatever printable text the web filters let through.
    try std.testing.expect(std.mem.startsWith(u8, got[0..r], vt.status_reply_bel));
    try std.testing.expect(std.mem.indexOfScalar(u8, got[vt.status_reply_bel.len..r], 0x1b) == null);
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

test "hook states: same generation and convo paths as OSC 7501; OSC wins only when it changes" {
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
    var gen: u64 = 1;
    var c = convo_model.Convo.init(gpa, .{});
    defer c.deinit();
    c.reset(true);
    var s: Session = .{
        .io = std.testing.io,
        .mutex = &mu,
        .cond = &cv,
        .pty = &pty,
        .console = undefined,
        .policy = .instruct,
        .term = try vt.Terminal.init(gpa, 10, 5),
        .size = .{ .cols = 10, .rows = 5 },
        .list_gen = &gen,
        .convo = &c,
    };
    defer s.term.deinit();
    _ = s.setHookState(.{ .state = .working, .wait = .none });
    try std.testing.expectEqual(vt.ProgramState.working, s.state);
    try std.testing.expectEqual(@as(u64, 2), gen);
    // Output without OSC 7501 leaves the hook's state alone.
    s.appendOutput("hello");
    try std.testing.expectEqual(vt.ProgramState.working, s.state);
    // PermissionRequest: waiting, the permission card, Up/Down allowed.
    _ = s.setHookState(.{ .state = .waiting, .wait = .permission, .cat = .edit });
    try std.testing.expectEqual(@as(u64, 3), gen);
    try std.testing.expect(c.hasOpenQuestion());
    try std.testing.expectEqualStrings("Claude wants to edit a file. Allow it?", c.last().?.text);
    try s.writeWebKey("up", 0);
    // The transcript shows a tool result: the prompt was answered.
    mu.lockUncancelable(std.testing.io);
    try std.testing.expect(s.transcriptMovedOnLocked(true, false));
    mu.unlock(std.testing.io);
    try std.testing.expectEqual(vt.ProgramState.working, s.state);
    try std.testing.expect(!c.hasOpenQuestion());
    try std.testing.expectError(error.NotWaiting, s.writeWebKey("up", 0));
    // Stop, then an OSC 7501 report takes over.
    _ = s.setHookState(.{ .state = .done, .wait = .none });
    try std.testing.expectEqual(vt.ProgramState.done, s.state);
    s.appendOutput("\x1b]7501;state=working\x07");
    try std.testing.expectEqual(vt.ProgramState.working, s.state);
    try std.testing.expect(!s.hook_state);
    mu.lockUncancelable(std.testing.io);
    try std.testing.expect(!s.transcriptMovedOnLocked(false, true)); // not a hook state
    mu.unlock(std.testing.io);
    // A hook after it wins again; an interrupt in the transcript is idle.
    _ = s.setHookState(.{ .state = .waiting, .wait = .permission });
    mu.lockUncancelable(std.testing.io);
    try std.testing.expect(s.transcriptMovedOnLocked(false, true));
    mu.unlock(std.testing.io);
    try std.testing.expectEqual(vt.ProgramState.idle, s.state);
}

test "desk input puts the text guard back at the line's start" {
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
        .policy = .text,
        .term = try vt.Terminal.init(std.testing.allocator, 10, 5),
        .size = .{ .cols = 10, .rows = 5 },
    };
    defer s.term.deinit();
    s.writeWebText("ab");
    try std.testing.expect(!s.text_guard.at_line_start);
    // The owner presses Enter at the desk: a device's `!` is first again.
    s.writeLocal("\r");
    try std.testing.expect(s.text_guard.at_line_start);
    s.writeWebText("!x");
    var got: [16]u8 = undefined;
    var r: w.DWORD = 0;
    try std.testing.expect(w.ReadFile(rd, &got, got.len, &r, null) != 0);
    try std.testing.expectEqualStrings("ab\rx", got[0..r]);
}
