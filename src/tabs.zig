//! Project tabs (docs/tabs-design.md): one Portal holds several projects,
//! each a tab with its own session program in its own pseudo console and
//! its own emulated screen (session.zig).
//!
//! The hub owns the list of open tabs. Only the desk opens tabs (the
//! window's folder picker, `portal open <dir>` / `portalctl open <dir>`
//! through the data directory, see OpenWatch in main.zig) and only the
//! desk closes them; remote viewers can switch between open tabs (web.zig)
//! but nothing they send can create or end one.
//!
//! Locking: `Hub.mutex` guards the list and, shared through
//! Session.mutex, every tab's screen, so a viewer waits on one condition
//! for its own session's output and for tab list changes alike.
//!
//! Lifetime: a tab is reference counted. The list holds one reference;
//! each of the tab's threads (output, input writer, supervisor, closer)
//! and every viewer or window showing it hold one more. A tab leaves the
//! list when its program has exited and its output has drained; its memory
//! and handles go when the last reference does.
//!
//! Ids are random 128-bit values that are never reused and never derived
//! from a path or an index (privacy rule 3). Names are desk-assigned: the
//! folder's basename or `--project`, never a path (rule 1).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const wire = @import("shared").tabs;
const session_mod = @import("session.zig");
const Session = session_mod.Session;
const LocalInput = session_mod.LocalInput;
const conpty = @import("conpty.zig");
const Console = @import("console.zig").Console;
const keymap = @import("keymap.zig");
const vt = @import("vt.zig");
const Log = @import("log.zig").Log;
const title = @import("title.zig");

pub const Id = wire.Id;
pub const State = wire.State;
pub const max_tabs = wire.max_tabs;

/// How long a program gets to exit after its tab (or the window) was
/// closed before Portal ends it through its job; then how long Portal
/// waits for it to be gone.
pub const close_timeout_ms = 10_000;
pub const terminate_timeout_ms = 5_000;
/// Consecutive non-EOF read failures after which the output thread gives
/// up (about 10 s at 10 ms apart; see main.zig's history of this limit).
const max_read_failures = 1000;

pub fn stateOf(s: vt.ProgramState) State {
    return switch (s) {
        .unknown => .unknown,
        .working => .working,
        .waiting => .waiting,
        .idle => .idle,
        .done => .done,
        .failed => .failed,
    };
}

pub const Tab = struct {
    hub: *Hub,
    session: Session,
    pty: conpty.Pty,
    local: LocalInput,
    id: Id,
    name_buf: [wire.max_name]u8 = undefined,
    name_len: u8 = 0,
    color: u32,
    /// Mirror PTY output to the console (`portalctl run --console`, the
    /// first tab only).
    mirror: bool = false,
    refs: std.atomic.Value(u32) = .init(1),
    /// Guarded by hub.mutex: no longer in the list.
    removed: bool = false,

    child_code: std.atomic.Value(u32) = .init(1),
    child_done: std.atomic.Value(bool) = .init(false),
    /// Set once, when the program has exited (the closer's watchdog waits
    /// on it).
    child_exited: Io.Event = .unset,
    out_done: std.atomic.Value(bool) = .init(false),
    close_done: std.atomic.Value(bool) = .init(false),
    /// Set by the output and closer threads as they finish; only the
    /// supervisor waits on it.
    step: Io.Event = .unset,
    closing: std.atomic.Value(bool) = .init(false),
    close_requested: std.atomic.Value(bool) = .init(false),
    ended_by_portal: std.atomic.Value(bool) = .init(false),
    attr_buf: [256]u8 align(@alignOf(usize)) = undefined,

    pub fn name(t: *const Tab) []const u8 {
        return t.name_buf[0..t.name_len];
    }

    pub fn fromSession(s: *Session) *Tab {
        return @fieldParentPtr("session", s);
    }

    pub fn acquire(t: *Tab) void {
        _ = t.refs.fetchAdd(1, .monotonic);
    }

    /// Drops a reference; the last one frees the tab. Never takes the
    /// hub's lock, so it may be called with it held.
    pub fn release(t: *Tab) void {
        if (t.refs.fetchSub(1, .acq_rel) != 1) return;
        const gpa = t.hub.gpa;
        t.session.term.deinit();
        t.local.deinit();
        t.pty.release();
        gpa.destroy(t);
    }

    /// The desk closed this tab (or the window): close its pseudo console,
    /// the program's cue to exit, and end it through its job if it is
    /// still running after `close_timeout_ms`. Idempotent; never blocks.
    pub fn requestClose(t: *Tab) void {
        if (t.close_requested.swap(true, .acq_rel)) return;
        t.beginClose();
        t.acquire();
        const th = std.Thread.spawn(.{}, closeWatch, .{t}) catch {
            t.release();
            return;
        };
        th.detach();
    }

    fn closeWatch(t: *Tab) void {
        defer t.release();
        const io = t.hub.io;
        if (t.child_done.load(.acquire)) return;
        t.child_exited.waitTimeout(io, .{ .duration = .{ .raw = .fromMilliseconds(close_timeout_ms), .clock = .awake } }) catch {};
        if (t.child_done.load(.acquire)) return;
        t.hub.log.print("tab '{s}': the program did not exit within {d} s of closing: ending it", .{ t.name(), close_timeout_ms / 1000 });
        t.ended_by_portal.store(true, .release);
        t.pty.terminate();
    }

    /// Closes the pseudo console on its own thread (ClosePseudoConsole can
    /// block until conhost has flushed, which needs the output thread to
    /// keep draining). Idempotent.
    fn beginClose(t: *Tab) void {
        if (t.closing.swap(true, .acq_rel)) return;
        t.acquire();
        const th = std.Thread.spawn(.{}, closer, .{t}) catch {
            closer(t);
            return;
        };
        th.detach();
    }

    fn closer(t: *Tab) void {
        defer t.release();
        t.session.shutdownPty();
        t.close_done.store(true, .release);
        t.step.set(t.hub.io);
    }

    fn outputThread(t: *Tab) void {
        defer t.release();
        defer {
            t.out_done.store(true, .release);
            t.step.set(t.hub.io);
        }
        const io = t.hub.io;
        var buf: [32 * 1024]u8 = undefined;
        var failures: u32 = 0;
        while (true) {
            const n = t.pty.read(&buf) catch {
                // Keep draining until EOF: see max_read_failures.
                failures +|= 1;
                if (failures >= max_read_failures) return;
                io.sleep(.fromMilliseconds(10), .awake) catch {};
                continue;
            };
            failures = 0;
            if (n == 0) return;
            if (t.mirror) t.hub.console.mirror(buf[0..n]);
            t.session.appendOutput(buf[0..n]);
        }
    }

    fn inputThread(t: *Tab) void {
        defer t.release();
        t.local.run();
    }

    /// Waits for the program, then for its output to drain and its pseudo
    /// console to close (at most `close_timeout_ms`), then takes the tab
    /// out of the list. This thread owns the process handle.
    fn supervise(t: *Tab) void {
        defer t.release();
        const io = t.hub.io;
        t.child_code.store(t.pty.waitExit(), .release);
        t.child_done.store(true, .release);
        t.child_exited.set(io);
        t.beginClose();
        const deadline = Io.Clock.awake.now(io).toMilliseconds() + close_timeout_ms;
        var clean = true;
        while (true) {
            // Reset before checking: a step finishing after the check sets
            // the event again, so no wake-up is lost.
            t.step.reset();
            if (t.out_done.load(.acquire) and t.close_done.load(.acquire)) break;
            const left = deadline - Io.Clock.awake.now(io).toMilliseconds();
            if (left <= 0) {
                clean = false;
                break;
            }
            t.step.waitTimeout(io, .{ .duration = .{ .raw = .fromMilliseconds(left), .clock = .awake } }) catch {};
        }
        t.hub.finish(t, t.child_code.load(.acquire), clean);
    }
};

/// Everything a new tab needs that is the same for all of them.
pub const Program = struct {
    /// cmdline.Resolved: the program and its command line (WTF-16).
    app: [:0]const u16,
    cmdline: [:0]const u16,
    /// For log lines only.
    command_name: []const u8,
};

pub const Hub = struct {
    gpa: Allocator,
    io: Io,
    log: *Log,
    /// The desktop console (`portalctl run --console`), or a detached one.
    console: *Console,
    policy: keymap.Policy,
    program: Program,
    /// Tab colours chosen in settings.txt (`color = NAME #rrggbb`).
    colors: []const ColorChoice = &.{},

    mutex: Io.Mutex = .init,
    cond: Io.Condition = .init,
    /// Open tabs, in bar order. Guarded by `mutex`.
    tabs: [max_tabs]*Tab = undefined,
    n: usize = 0,
    /// Bumped on any change viewers announce (`tabs`): a tab opened or
    /// closed, renamed, or its program's state changed. Guarded by `mutex`.
    gen: u64 = 1,
    /// The tab the desk shows (new viewers start there). Guarded by `mutex`.
    desk_active: ?*Tab = null,
    /// The size the desk gives every tab (the window or console).
    size: conpty.Size = .{ .cols = 80, .rows = 24 },
    /// All tabs have ended (after at least one ran), and the last one's
    /// exit code. Guarded by `mutex`; `finished_event` is set then.
    finished: bool = false,
    last_code: u32 = 0,
    finished_event: Io.Event = .unset,

    viewers: u32 = 0,
    /// Viewer sockets not yet closed: a viewer counts here from its
    /// upgrade until its socket is closed (after the exit notice and the
    /// closing handshake), which is later than it leaves `viewers`.
    /// Shutdown waits for this to reach 0, so the process never exits
    /// (which resets open sockets) while an exit notice is in flight.
    viewer_sockets: u32 = 0,
    /// Set on every viewer (or viewer socket) count change.
    viewers_changed: Io.Event = .unset,

    /// Optional change hook (the desk window): any tab's output, resize,
    /// list or viewer change. Set before any tab starts; called with no
    /// lock held.
    notify_ctx: ?*anyopaque = null,
    notify_fn: ?*const fn (ctx: *anyopaque) void = null,

    pub const ColorChoice = struct { name: []const u8, color: u32 };

    pub const OpenError = error{ TooManyTabs, Finished, OutOfMemory, SpawnFailed };

    fn notify(h: *Hub) void {
        if (h.notify_fn) |f| if (h.notify_ctx) |c| f(c);
    }

    /// Wakes every viewer and the window (after any change they look at).
    pub fn broadcast(h: *Hub) void {
        h.mutex.lockUncancelable(h.io);
        h.mutex.unlock(h.io);
        h.cond.broadcast(h.io);
        h.notify();
    }

    pub fn colorFor(h: *const Hub, name: []const u8) u32 {
        for (h.colors) |c| if (std.ascii.eqlIgnoreCase(c.name, name)) return c.color;
        return wire.colorFromName(name);
    }

    /// Starts the configured program in `cwd` (null: Portal's own working
    /// directory) as a new tab named `name` (a display name, see
    /// displayName) and makes it the desk's tab.
    pub fn open(h: *Hub, cwd: ?[:0]const u16, name: []const u8, mirror: bool) OpenError!*Tab {
        h.mutex.lockUncancelable(h.io);
        const full = h.n >= max_tabs;
        const done = h.finished;
        const size = h.size;
        h.mutex.unlock(h.io);
        if (done) return error.Finished;
        if (full) return error.TooManyTabs;

        const t = try h.gpa.create(Tab);
        var id: Id = undefined;
        while (true) {
            h.io.randomSecure(&id) catch h.io.random(&id);
            if (!std.mem.allEqual(u8, &id, 0)) break;
        }
        t.* = .{
            .hub = h,
            .id = id,
            .color = h.colorFor(name),
            .mirror = mirror,
            .pty = undefined,
            .local = undefined,
            .session = .{
                .io = h.io,
                .mutex = &h.mutex,
                .cond = &h.cond,
                .pty = undefined,
                .console = h.console,
                .policy = h.policy,
                .term = vt.Terminal.init(h.gpa, size.cols, size.rows) catch {
                    h.gpa.destroy(t);
                    return error.OutOfMemory;
                },
                .size = size,
                .list_gen = &h.gen,
                .notify_ctx = h,
                .notify_fn = notifyThunk,
            },
        };
        const nl = @min(name.len, wire.max_name);
        @memcpy(t.name_buf[0..nl], name[0..nl]);
        t.name_len = @intCast(nl);

        const line = h.gpa.dupeSentinel(u16, h.program.cmdline, 0) catch {
            t.session.term.deinit();
            h.gpa.destroy(t);
            return error.OutOfMemory;
        };
        defer h.gpa.free(line);
        t.pty = conpty.Pty.spawn(h.program.app, line, cwd, size, &t.attr_buf) catch |err| {
            h.log.print("tab '{s}': could not start '{s}': {t}", .{ t.name(), h.program.command_name, err });
            t.session.term.deinit();
            h.gpa.destroy(t);
            return error.SpawnFailed;
        };
        t.session.pty = &t.pty;
        t.local = .{ .gpa = h.gpa, .io = h.io, .session = &t.session };
        t.session.local = &t.local;

        // The list's reference is the initial one; each thread takes its own.
        const threads = .{ Tab.outputThread, Tab.inputThread, Tab.supervise };
        var failed = false;
        inline for (threads) |f| if (!failed) {
            t.acquire();
            if (std.Thread.spawn(.{}, f, .{t})) |th| {
                th.detach();
            } else |_| {
                // Cannot run the tab without its threads: end it at once.
                t.release();
                h.log.print("tab '{s}': cannot start its threads; ending it", .{t.name()});
                t.pty.terminate();
                failed = true;
            }
        };

        h.mutex.lockUncancelable(h.io);
        h.tabs[h.n] = t;
        h.n += 1;
        h.gen +%= 1;
        h.desk_active = t;
        h.mutex.unlock(h.io);
        h.cond.broadcast(h.io);
        h.notify();
        h.log.print("tab opened: '{s}' ({d} open)", .{ t.name(), h.count() });
        return t;
    }

    fn notifyThunk(ctx: *anyopaque) void {
        const h: *Hub = @ptrCast(@alignCast(ctx));
        h.notify();
    }

    pub fn count(h: *Hub) usize {
        h.mutex.lockUncancelable(h.io);
        defer h.mutex.unlock(h.io);
        return h.n;
    }

    /// The tab's program has exited and its output drained: the tab
    /// leaves the list. The last one to go finishes the hub.
    fn finish(h: *Hub, t: *Tab, code: u32, clean: bool) void {
        h.mutex.lockUncancelable(h.io);
        t.session.closed = true;
        t.session.exit_code = code;
        var idx: ?usize = null;
        for (h.tabs[0..h.n], 0..) |x, i| if (x == t) {
            idx = i;
        };
        if (idx) |i| {
            std.mem.copyForwards(*Tab, h.tabs[i .. h.n - 1], h.tabs[i + 1 .. h.n]);
            h.n -= 1;
            t.removed = true;
            h.gen +%= 1;
            if (h.desk_active == t) h.desk_active = if (h.n == 0) null else h.tabs[@min(i, h.n - 1)];
        }
        const left = h.n;
        if (left == 0) {
            h.finished = true;
            h.last_code = code;
        }
        h.mutex.unlock(h.io);
        h.cond.broadcast(h.io);
        h.notify();
        h.log.print("tab closed: '{s}', program exited with code {d}{s}{s} ({d} open)", .{
            t.name(),
            code,
            if (t.ended_by_portal.load(.acquire)) " (ended by Portal after the tab closed)" else "",
            if (clean) "" else " (pseudo console did not close in time)",
            left,
        });
        if (left == 0) h.finished_event.set(h.io);
        if (idx != null) t.release(); // the list's reference
    }

    /// The window was closed: every tab is asked to end.
    pub fn closeAll(h: *Hub) void {
        var buf: [max_tabs]*Tab = undefined;
        for (h.snapshot(&buf)) |t| {
            t.requestClose();
            t.release();
        }
    }

    /// Waits until every tab has ended or `deadline_ms` (awake clock)
    /// passes. True if all ended.
    pub fn waitFinished(h: *Hub, deadline_ms: ?i64) bool {
        while (true) {
            h.finished_event.reset();
            h.mutex.lockUncancelable(h.io);
            const done = h.finished;
            h.mutex.unlock(h.io);
            if (done) return true;
            const d = deadline_ms orelse {
                h.finished_event.wait(h.io) catch {};
                continue;
            };
            const left = d - Io.Clock.awake.now(h.io).toMilliseconds();
            if (left <= 0) return false;
            h.finished_event.waitTimeout(h.io, .{ .duration = .{ .raw = .fromMilliseconds(left), .clock = .awake } }) catch {};
        }
    }

    /// The open tabs, each with a reference the caller releases.
    pub fn snapshot(h: *Hub, buf: *[max_tabs]*Tab) []*Tab {
        h.mutex.lockUncancelable(h.io);
        defer h.mutex.unlock(h.io);
        for (h.tabs[0..h.n], 0..) |t, i| {
            t.acquire();
            buf[i] = t;
        }
        return buf[0..h.n];
    }

    /// Caller holds `mutex`. The open tab with this id, with a reference
    /// for the caller; null for anything else (closed, never existed or
    /// malformed all answer the same: privacy rule 3).
    pub fn acquireLocked(h: *Hub, id: Id) ?*Tab {
        for (h.tabs[0..h.n]) |t| if (std.mem.eql(u8, &t.id, &id)) {
            t.acquire();
            return t;
        };
        return null;
    }

    /// The tab a new viewer starts on (the desk's), with a reference; null
    /// once every tab has ended.
    pub fn acquireInitial(h: *Hub) ?*Tab {
        h.mutex.lockUncancelable(h.io);
        defer h.mutex.unlock(h.io);
        const t = h.desk_active orelse (if (h.n > 0) h.tabs[0] else return null);
        t.acquire();
        return t;
    }

    /// Caller holds `mutex`. The list as protocol entries.
    pub fn entriesLocked(h: *Hub, out: *wire.List) void {
        out.len = h.n;
        for (h.tabs[0..h.n], 0..) |t, i| {
            out.items[i] = .{ .id = t.id, .color = t.color, .state = stateOf(t.session.state) };
            out.items[i].setName(t.name());
        }
    }

    pub fn setDeskActive(h: *Hub, t: *Tab) void {
        h.mutex.lockUncancelable(h.io);
        if (!t.removed) h.desk_active = t;
        h.mutex.unlock(h.io);
    }

    /// The desk's terminal size, for every tab (new ones start with it).
    pub fn setSize(h: *Hub, size: conpty.Size) void {
        h.mutex.lockUncancelable(h.io);
        h.size = size;
        h.mutex.unlock(h.io);
        var buf: [max_tabs]*Tab = undefined;
        for (h.snapshot(&buf)) |t| {
            t.session.setSize(size);
            t.release();
        }
    }

    pub fn viewerDelta(h: *Hub, delta: i32) u32 {
        h.mutex.lockUncancelable(h.io);
        // Saturating both ways; @abs avoids overflow negating minInt(i32).
        if (delta > 0) h.viewers +|= @abs(delta) else h.viewers -|= @abs(delta);
        const n = h.viewers;
        h.mutex.unlock(h.io);
        h.viewers_changed.set(h.io);
        h.notify();
        return n;
    }

    /// A viewer socket opened (+1) or was closed (-1); see viewer_sockets.
    pub fn viewerSocketDelta(h: *Hub, delta: i32) void {
        h.mutex.lockUncancelable(h.io);
        if (delta > 0) h.viewer_sockets +|= @abs(delta) else h.viewer_sockets -|= @abs(delta);
        h.mutex.unlock(h.io);
        h.viewers_changed.set(h.io);
    }

    /// Waits until every viewer socket is closed or `deadline_ms` (awake
    /// clock) passes. Woken by every viewer change; no polling.
    pub fn waitViewersGone(h: *Hub, deadline_ms: i64) void {
        while (true) {
            // Reset before checking, so a change right after is not lost.
            h.viewers_changed.reset();
            h.mutex.lockUncancelable(h.io);
            const n = h.viewer_sockets;
            h.mutex.unlock(h.io);
            if (n == 0) return;
            const left = deadline_ms - Io.Clock.awake.now(h.io).toMilliseconds();
            if (left <= 0) return;
            h.viewers_changed.waitTimeout(h.io, .{ .duration = .{ .raw = .fromMilliseconds(left), .clock = .awake } }) catch {};
        }
    }

    /// The name of the desk's tab (for the console title), copied.
    pub fn deskName(h: *Hub, buf: []u8) ?[]const u8 {
        h.mutex.lockUncancelable(h.io);
        defer h.mutex.unlock(h.io);
        const t = h.desk_active orelse return null;
        const n = @min(buf.len, t.name_len);
        @memcpy(buf[0..n], t.name()[0..n]);
        return buf[0..n];
    }
};

/// The tab name for a folder: its basename, made printable and cut to 64
/// bytes. Never the path, and never the user's name: the home folder
/// itself is "Home" (its basename is the user name), a drive root or
/// anything with no usable characters is "Project".
pub fn displayName(path: []const u8, home: ?[]const u8, user: ?[]const u8, buf: *[wire.max_name]u8) []const u8 {
    var p = path;
    while (p.len > 1 and (p[p.len - 1] == '\\' or p[p.len - 1] == '/')) p = p[0 .. p.len - 1];
    if (home) |hm| {
        var hh = hm;
        while (hh.len > 1 and (hh[hh.len - 1] == '\\' or hh[hh.len - 1] == '/')) hh = hh[0 .. hh.len - 1];
        if (std.ascii.eqlIgnoreCase(p, hh)) return "Home";
    }
    const base = std.fs.path.basenameWindows(p);
    if (user) |u| if (u.len > 0 and std.ascii.eqlIgnoreCase(base, u)) return "Home";
    // Keep printable characters only, whole code points, at most 64 bytes.
    var n: usize = 0;
    var it = (std.unicode.Utf8View.init(base) catch return "Project").iterator();
    while (it.nextCodepointSlice()) |cs| {
        if (n + cs.len > buf.len) break;
        if (!wire.validName(cs) and !std.mem.eql(u8, cs, " ")) continue;
        @memcpy(buf[n..][0..cs.len], cs);
        n += cs.len;
    }
    const out = std.mem.trim(u8, buf[0..n], " ");
    if (!wire.validName(out)) return "Project";
    return out;
}

test "displayName: basename only, never a path or the user name" {
    var buf: [wire.max_name]u8 = undefined;
    try std.testing.expectEqualStrings("acme-api", displayName("C:\\code\\acme-api", null, null, &buf));
    try std.testing.expectEqualStrings("acme-api", displayName("C:\\code\\acme-api\\", null, null, &buf));
    try std.testing.expectEqualStrings("Home", displayName("C:\\Users\\bob", "C:\\Users\\bob\\", "bob", &buf));
    try std.testing.expectEqualStrings("Home", displayName("D:\\backup\\BOB", null, "bob", &buf));
    try std.testing.expectEqualStrings("Project", displayName("C:\\", null, null, &buf));
    try std.testing.expectEqualStrings("ab", displayName("C:\\x\\a\u{202e}b", null, null, &buf));
    var long_dir: [3 + 100]u8 = @splat('q');
    long_dir[0..3].* = "C:\\".*;
    try std.testing.expectEqual(@as(usize, 64), displayName(&long_dir, null, null, &buf).len);
}
