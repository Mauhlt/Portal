//! Project tabs (docs/tabs-design.md): one Portal holds several projects,
//! each a tab with its own session program in its own pseudo console and
//! its own emulated screen (session.zig).
//!
//! The hub owns the list of open tabs. The desk opens tabs (the window's
//! folder picker, `portal open <dir>` / `portalctl open <dir>` through
//! the data directory, see OpenWatch in main.zig) and closes them. Remote
//! viewers switch between open tabs (web.zig); the one thing they can
//! start is a project the desk marked startable (`startable`, from
//! settings.txt), by its exact name, in the desk's folder with the desk's
//! program and a permission mode the desk chose (deviceStart), and the one
//! thing they can end is a session a device started (deviceStop).
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
const w32 = @import("win32.zig");
const Convo = @import("convo/model.zig").Convo;
const Activity = @import("convo/activity.zig").Activity;
const activity_wire = @import("shared").activity;
const follow = @import("convo/follow.zig");
const subagents = @import("convo/subagents.zig");
const SubTabs = @import("convo/subtabs.zig").SubTabs;
const scrub = @import("convo/scrub.zig");
const transcript = @import("convo/transcript.zig");
const cmdline = @import("cmdline.zig");
const childenv = @import("childenv.zig");
const hookmsg = @import("hookmsg.zig");
const projects_wire = @import("shared").projects;
const settings = @import("settings.zig");

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
    /// The tab's folder (WTF-8), for its conversation's transcript and
    /// scrubbing. Never sent (privacy rule 1).
    cwd: []u8 = &.{},
    /// The Conversation view (docs/protocol.md section 3b). Guarded by
    /// hub.mutex, like the screen.
    convo: Convo = undefined,
    /// Background tasks and token use (docs/protocol.md section 3c), from
    /// the same transcript. Guarded by hub.mutex.
    activity: Activity = undefined,
    /// The transcript the tab follows (its session id), so two tabs in
    /// one folder never show the same one. Guarded by hub.mutex.
    convo_claim: [36]u8 = undefined,
    convo_claimed: bool = false,
    /// Set when the tab leaves the list: its transcript follower stops.
    convo_stop: ?w32.HANDLE = null,
    /// Poked on the program's output (session.zig): the follower then
    /// checks the transcript's size (appends through a handle kept open
    /// are not always reported by the directory).
    convo_poke: ?follow.Poke = null,
    /// The subagents of the session the tab follows, each a read-only
    /// sub-tab (docs/protocol.md section 3e). Guarded by hub.mutex.
    subs: SubTabs = undefined,
    /// Set by the agent's SubagentStart / SubagentStop hooks
    /// (subagentEvent): the follower's subagent watcher looks again.
    subs_kick: ?w32.HANDLE = null,
    /// The `--session-id` Portal gave the agent for this launch (its
    /// transcript's name), if it gave one. Desktop-only.
    session_uuid: ?[36]u8 = null,
    /// The paired device that started this tab (deviceStart), and the
    /// permission mode it runs in; empty: started at the desk. Shown on
    /// the desk's tab ("started by <device>") and logged; never sent.
    started_by_buf: [64]u8 = undefined,
    started_by_len: u8 = 0,
    start_mode: ?projects_wire.Mode = null,
    /// The device that stopped it (deviceStop); empty: none. Guarded by
    /// hub.mutex.
    stopped_by_buf: [64]u8 = undefined,
    stopped_by_len: u8 = 0,
    /// This launch's PORTAL_TAB (random, 128 bits, not the tab's `id`):
    /// how `portalctl hook` names the tab (hookmsg.zig). Desktop-only:
    /// never logged, never sent to devices.
    hook_key: hookmsg.Key = undefined,

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

    /// The device that started this tab, or null (the desk did).
    pub fn startedBy(t: *const Tab) ?[]const u8 {
        return if (t.started_by_len == 0) null else t.started_by_buf[0..t.started_by_len];
    }

    /// Caller holds hub.mutex. The device that stopped it, or null.
    pub fn stoppedByLocked(t: *const Tab) ?[]const u8 {
        return if (t.stopped_by_len == 0) null else t.stopped_by_buf[0..t.stopped_by_len];
    }

    /// The desk's note on its tab ("started by iPhone", "stopping: asked by
    /// iPhone"), "" for none. Caller holds hub.mutex.
    pub fn deskNoteLocked(t: *const Tab, buf: []u8) []const u8 {
        if (t.stoppedByLocked()) |d| return std.fmt.bufPrint(buf, "stopped by {s}", .{d}) catch "stopped by a device";
        const by = t.startedBy() orelse return "";
        return std.fmt.bufPrint(buf, "started by {s}{s}", .{ by, if (t.start_mode == .plan) " (plan)" else "" }) catch "started by a device";
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
        t.convo.deinit();
        t.subs.deinit();
        gpa.free(t.cwd);
        if (t.convo_stop) |e| _ = w32.CloseHandle(e);
        if (t.subs_kick) |e| _ = w32.CloseHandle(e);
        if (t.convo_poke) |*p| p.deinit();
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

    /// Follows the tab's transcript into its conversation until the tab
    /// leaves the list (convo_stop). Blocks on change notifications only.
    fn convoThread(t: *Tab) void {
        defer t.release();
        const h = t.hub;
        const projects = h.convo_projects orelse return;
        const stop = t.convo_stop orelse return;
        var f = follow.Follower.init(h.gpa, .{ .ctx = t, .apply = convoApply, .reset = convoReset, .claim = convoClaim, .contested = convoContested }, projects, t.cwd) catch return;
        defer f.deinit();
        f.expected = t.session_uuid;
        // The session's subagents, as sub-tabs (subagents.zig).
        var sw = subagents.Watcher.init(h.gpa, .{ .ctx = t, .clear = subsClear, .upsert = subsUpsert, .apply = subsApply, .restart = subsRestart }) catch null;
        defer if (sw) |*s| s.deinit();
        if (sw) |*s| {
            s.kick = t.subs_kick;
            f.subs = s;
        }
        f.run(stop, if (t.convo_poke) |*p| p else null);
    }

    /// The sub-tabs changed: viewers and the desk look again.
    fn subsChanged(h: *Hub) void {
        h.mutex.unlock(h.io);
        h.cond.broadcast(h.io);
        h.notify();
    }

    fn subsClear(ctx: *anyopaque) void {
        const t: *Tab = @ptrCast(@alignCast(ctx));
        const h = t.hub;
        h.mutex.lockUncancelable(h.io);
        t.subs.clear();
        subsChanged(h);
    }

    fn subsUpsert(ctx: *anyopaque, agent: []const u8, description: ?[]const u8, done: bool) bool {
        const t: *Tab = @ptrCast(@alignCast(ctx));
        const h = t.hub;
        h.mutex.lockUncancelable(h.io);
        const ok = t.subs.upsert(agent, description, done) != null;
        subsChanged(h);
        return ok;
    }

    fn subsApply(ctx: *anyopaque, agent: []const u8, rec: *const transcript.Record) void {
        const t: *Tab = @ptrCast(@alignCast(ctx));
        const h = t.hub;
        h.mutex.lockUncancelable(h.io);
        t.subs.apply(agent, rec);
        subsChanged(h);
    }

    fn subsRestart(ctx: *anyopaque, agent: []const u8) void {
        const t: *Tab = @ptrCast(@alignCast(ctx));
        const h = t.hub;
        h.mutex.lockUncancelable(h.io);
        t.subs.restart(agent);
        subsChanged(h);
    }

    /// What an agent hook says about one of the tab's subagents.
    pub const SubagentEvent = enum { start, stop };

    /// The seam for the agent's SubagentStart / SubagentStop hooks
    /// (Hub.applyHook): `start` gives subagent `agent` its sub-tab at once
    /// (named once its meta file is read), `stop` marks it finished. Either
    /// way the follower's watcher looks at the subagents folder again
    /// (`subs_kick`), so what the subagent wrote last is read. The files
    /// stay the source of the conversation; hooks only make it timely.
    pub fn subagentEvent(t: *Tab, ev: SubagentEvent, agent: []const u8) void {
        const h = t.hub;
        h.mutex.lockUncancelable(h.io);
        _ = t.subs.upsert(agent, null, ev == .stop);
        subsChanged(h);
        if (t.subs_kick) |k| _ = w32.SetEvent(k);
    }

    fn convoApply(ctx: *anyopaque, rec: *const transcript.Record) void {
        const t: *Tab = @ptrCast(@alignCast(ctx));
        const h = t.hub;
        h.mutex.lockUncancelable(h.io);
        t.convo.applyRecord(rec) catch {};
        const rev = t.activity.rev;
        t.activity.applyRecord(rec);
        const act = t.activity.rev != rev;
        if (act) h.activity_gen +%= 1;
        // A state from a hook that the transcript shows is over.
        var moved = false;
        if (rec.rtype == .user and !rec.sidechain and !rec.history) {
            var result = false;
            var interrupted = false;
            for (rec.blockSlice()) |*b| switch (b.kind) {
                .tool_result => result = true,
                .text => if (transcript.interruptPrompt(b.text)) {
                    interrupted = true;
                },
                else => {},
            };
            moved = t.session.transcriptMovedOnLocked(result, interrupted);
        }
        h.mutex.unlock(h.io);
        h.cond.broadcast(h.io);
        if (act or moved) h.notify();
    }

    fn convoReset(ctx: *anyopaque, on: bool) void {
        const t: *Tab = @ptrCast(@alignCast(ctx));
        const h = t.hub;
        h.mutex.lockUncancelable(h.io);
        t.convo.reset(on);
        t.activity.reset();
        h.activity_gen +%= 1;
        h.mutex.unlock(h.io);
        h.cond.broadcast(h.io);
        h.notify();
    }

    /// The claim table: a transcript is one tab's at most, and a tab's own
    /// `--session-id` transcript is never another's (follow.Sink.claim).
    fn convoClaim(ctx: *anyopaque, stem: []const u8, rival_since: ?i64) follow.Claim {
        const t: *Tab = @ptrCast(@alignCast(ctx));
        const h = t.hub;
        if (stem.len != 36) return .taken;
        h.mutex.lockUncancelable(h.io);
        defer h.mutex.unlock(h.io);
        for (h.tabs[0..h.n]) |o| {
            if (o == t) continue;
            if (o.convo_claimed and std.mem.eql(u8, &o.convo_claim, stem)) return .taken;
            if (o.session_uuid) |*u| if (std.mem.eql(u8, u, stem)) return .taken;
        }
        if (rival_since) |since| {
            var mine_buf: [1024]u8 = undefined;
            const mine = transcript.folderName(transcript.normalizeCwd(t.cwd), &mine_buf) catch "";
            for (h.tabs[0..h.n]) |o| {
                if (o == t) continue;
                const printed = if (o.convo_poke) |*p| p.last_ms.load(.acquire) else follow.Poke.never;
                if (printed < since) continue;
                var other_buf: [1024]u8 = undefined;
                const other = transcript.folderName(transcript.normalizeCwd(o.cwd), &other_buf) catch "";
                // Same transcript folder (case aside, to err towards "unclear").
                if (mine.len == 0 or other.len == 0 or std.ascii.eqlIgnoreCase(mine, other)) return .contested;
            }
        }
        t.convo_claim = stem[0..36].*;
        t.convo_claimed = true;
        return .ok;
    }

    /// Desktop log only, and without paths: the tab's name is shown on
    /// the desktop anyway.
    fn convoContested(ctx: *anyopaque) void {
        const t: *Tab = @ptrCast(@alignCast(ctx));
        t.hub.log.print("tab '{s}': a new transcript appeared while another tab in the same folder was printing too; its conversation view keeps the current one", .{t.name()});
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
    /// The agent without a session chosen in its arguments: each tab's
    /// launch gets its own `--session-id <uuid>` (cmdline.wantsSessionId).
    session_id: bool = false,
    /// Whether devices may start sessions of it (cmdline.deviceStart:
    /// the agent, without a permissive flag); checked on every start.
    device_start: cmdline.DeviceStart = .not_agent,
};

/// How a tab is opened (Hub.open).
pub const OpenOptions = struct {
    /// Mirror PTY output to the console (`portalctl run --console`, the
    /// first tab only).
    mirror: bool = false,
    /// Started by a paired device (deviceStart): who, and the permission
    /// mode the desk chose for the project. Null: the desk.
    device: ?DeviceLaunch = null,
};

pub const DeviceLaunch = struct { by: []const u8, mode: projects_wire.Mode };

/// What deviceStart did, and the tab it started or found (with a
/// reference for the caller), so the viewer can be switched to it.
pub const StartOutcome = struct { result: projects_wire.Result, tab: ?*Tab = null };

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
    /// The projects devices may start (settings.txt `startable`, the one
    /// source: set with setStartable whenever the file changes). Guarded
    /// by `mutex`; `projects_gen` is bumped on every change.
    startable: [settings.max_startable]settings.StartableEntry = undefined,
    n_startable: usize = 0,
    projects_gen: u64 = 1,
    /// The agent's transcript folder (`...\.claude\projects`), read for
    /// each tab's Conversation view; null: no conversations (the view says
    /// there is no transcript).
    convo_projects: ?[]const u8 = null,
    /// The user's name, scrubbed from conversation texts.
    user_name: ?[]const u8 = null,
    /// The user's other names and home folders, scrubbed likewise.
    identity: scrub.Identity = .{},
    /// The desk's "Show system monitor" setting, as viewers are told
    /// (`activity.sysmon`). Guarded by `mutex`; set with setSysmon.
    sysmon_on: bool = false,

    mutex: Io.Mutex = .init,
    cond: Io.Condition = .init,
    /// Open tabs, in bar order. Guarded by `mutex`.
    tabs: [max_tabs]*Tab = undefined,
    n: usize = 0,
    /// Bumped on any change viewers announce (`tabs`): a tab opened or
    /// closed, renamed, or its program's state changed. Guarded by `mutex`.
    gen: u64 = 1,
    /// Bumped when any tab's activity (tasks, usage) or the sysmon setting
    /// changes: viewers send `activity` again. Guarded by `mutex`.
    activity_gen: u64 = 1,
    /// The tab the desk shows (new viewers start there). Guarded by `mutex`.
    desk_active: ?*Tab = null,
    /// The size the desk gives every tab (the window or console).
    size: conpty.Size = .{ .cols = 80, .rows = 24 },
    /// All tabs have ended (after at least one ran), and the last one's
    /// exit code. Guarded by `mutex`; `finished_event` is set then.
    finished: bool = false,
    last_code: u32 = 0,
    finished_event: Io.Event = .unset,

    /// When a hook message for no open tab was last logged (awake ms).
    /// Guarded by `mutex`.
    hook_unknown_logged_ms: i64 = std.math.minInt(i64),

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

    pub const OpenError = error{ TooManyTabs, Finished, OutOfMemory, SpawnFailed, UnsafeProgram };

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
    pub fn open(h: *Hub, cwd: ?[:0]const u16, name: []const u8, opts: OpenOptions) OpenError!*Tab {
        const mirror = opts.mirror;
        // A device start never runs a program whose permission mode Portal
        // can't pin to the desk's choice (cmdline.deviceStart).
        if (opts.device != null and h.program.device_start != .ok) return error.UnsafeProgram;
        h.mutex.lockUncancelable(h.io);
        const full = h.n >= max_tabs;
        const done = h.finished;
        const size = h.size;
        h.mutex.unlock(h.io);
        if (done) return error.Finished;
        if (full) return error.TooManyTabs;

        // The folder as text, for the conversation (never sent).
        const cwd_text: []u8 = if (cwd) |c|
            (std.unicode.wtf16LeToWtf8Alloc(h.gpa, c) catch return error.OutOfMemory)
        else blk: {
            const here = std.process.currentPathAlloc(h.io, h.gpa) catch break :blk h.gpa.dupe(u8, "") catch return error.OutOfMemory;
            defer h.gpa.free(here);
            break :blk h.gpa.dupe(u8, here) catch return error.OutOfMemory;
        };
        errdefer h.gpa.free(cwd_text);
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
            .cwd = cwd_text,
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
        if (opts.device) |d| {
            const bl = @min(d.by.len, t.started_by_buf.len);
            @memcpy(t.started_by_buf[0..bl], d.by[0..bl]);
            t.started_by_len = @intCast(bl);
            t.start_mode = d.mode;
        }

        // The agent gets this launch's own session id, so the tab's
        // transcript is exactly `<id>.jsonl`. Never logged, never sent:
        // viewers only ever see Portal's own tab ids.
        if (h.program.session_id) {
            var rnd: [16]u8 = undefined;
            h.io.randomSecure(&rnd) catch h.io.random(&rnd);
            t.session_uuid = cmdline.uuidV4(rnd);
        }
        // The hook key, passed to the program (and so to the agent's
        // hooks) as PORTAL_TAB, added after childenv's filter. It
        // authenticates hook messages, so without secure randomness the
        // tab is not started (no guessable fallback).
        while (true) {
            h.io.randomSecure(&t.hook_key) catch |err| {
                h.log.print("tab '{s}': no secure randomness for its hook key ({t}); not started", .{ t.name(), err });
                t.session.term.deinit();
                h.gpa.destroy(t);
                return error.SpawnFailed;
            };
            if (!std.mem.allEqual(u8, &t.hook_key, 0)) break;
        }
        // The launch's own arguments, decided in one place
        // (cmdline.launchArgs): a device start's permission mode, the
        // session id.
        var arg_buf: [4][]const u8 = undefined;
        const extra = cmdline.launchArgs(&arg_buf, if (opts.device) |d| d.mode.agentArg() else null, if (t.session_uuid) |*u| u else null);
        const line = cmdline.withArgs(h.gpa, h.program.cmdline, extra) catch {
            t.session.term.deinit();
            h.gpa.destroy(t);
            return error.OutOfMemory;
        };
        defer h.gpa.free(line);
        // Its own environment: Portal's, without what leaks the context
        // Portal was started from (a parent agent session's markers,
        // PORTAL_*): childenv.zig.
        var tab_var: [hookmsg.env_name.len + 1 + 32]u16 = undefined;
        {
            const hex = hookmsg.keyHex(t.hook_key);
            for (hookmsg.env_name ++ "=", 0..) |c, i| tab_var[i] = c;
            for (hex, 0..) |c, i| tab_var[hookmsg.env_name.len + 1 + i] = c;
        }
        const env_block = childenv.forSessionWith(h.gpa, &.{&tab_var}) catch |err| {
            h.log.print("tab '{s}': could not prepare the environment: {t}", .{ t.name(), err });
            t.session.term.deinit();
            h.gpa.destroy(t);
            return error.SpawnFailed;
        };
        defer h.gpa.free(env_block);
        t.pty = conpty.Pty.spawn(h.program.app, line, cwd, env_block, size, &t.attr_buf) catch |err| {
            h.log.print("tab '{s}': could not start '{s}': {t}", .{ t.name(), h.program.command_name, err });
            t.session.term.deinit();
            h.gpa.destroy(t);
            return error.SpawnFailed;
        };
        t.session.pty = &t.pty;
        t.local = .{ .gpa = h.gpa, .io = h.io, .session = &t.session };
        t.session.local = &t.local;
        const sctx: scrub.Context = .{ .root = t.cwd, .name = t.name(), .user = h.user_name, .users = h.identity.users, .homes = h.identity.homes };
        t.convo = Convo.init(h.gpa, sctx);
        t.activity = Activity.init(h.gpa, sctx);
        t.activity.dayOf = localDay;
        t.session.convo = &t.convo;
        t.subs = SubTabs.init(h.gpa, h.io, sctx);
        if (h.convo_projects != null) {
            t.subs_kick = w32.validHandle(w32.CreateEventW(null, 0, 0, null));
            t.convo_stop = w32.validHandle(w32.CreateEventW(null, 1, 0, null));
            t.convo_poke = follow.Poke.init();
            if (t.convo_poke) |*p| t.session.convo_poke = p;
        }

        // The list's reference is the initial one; each thread takes its own.
        const threads = .{ Tab.outputThread, Tab.inputThread, Tab.supervise, Tab.convoThread };
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
        // A device start leaves the desk on the tab it shows.
        if (opts.device == null or h.desk_active == null) h.desk_active = t;
        h.mutex.unlock(h.io);
        h.cond.broadcast(h.io);
        h.notify();
        if (t.startedBy()) |by|
            h.log.print("tab opened: '{s}' ({d} open), started by device '{s}' (permission mode {s})", .{ t.name(), h.count(), by, t.start_mode.?.agentArg() })
        else
            h.log.print("tab opened: '{s}' ({d} open)", .{ t.name(), h.count() });
        return t;
    }

    // ------------------------------------------------- startable projects

    /// The desk's startable list changed (settings.txt): devices are told.
    pub fn setStartable(h: *Hub, list: []const settings.StartableEntry) void {
        h.mutex.lockUncancelable(h.io);
        const n = @min(list.len, h.startable.len);
        var same = n == h.n_startable;
        if (same) for (list[0..n], h.startable[0..n]) |*a, *b| {
            if (!std.mem.eql(u8, a.name.get() orelse "", b.name.get() orelse "") or a.mode != b.mode or
                !std.mem.eql(u8, a.path.get() orelse "", b.path.get() orelse "")) same = false;
        };
        if (!same) {
            @memcpy(h.startable[0..n], list[0..n]);
            h.n_startable = n;
            h.projects_gen +%= 1;
        }
        h.mutex.unlock(h.io);
        if (same) return;
        h.cond.broadcast(h.io);
        h.notify();
        h.log.print("startable projects: {d} (settings.txt)", .{n});
    }

    /// Caller holds `mutex`. The open tab running startable entry `e`
    /// (its folder), if any.
    fn runningLocked(h: *Hub, e: *const settings.StartableEntry) ?*Tab {
        const path = e.path.get() orelse return null;
        for (h.tabs[0..h.n]) |t| if (settings.samePath(t.cwd, path)) return t;
        return null;
    }

    /// Caller holds `mutex`. The startable list as devices see it: names,
    /// colours, modes, whether each runs and may be stopped from a
    /// device. Never a folder (privacy rule 1).
    pub fn projectsLocked(h: *Hub, out: *projects_wire.List) void {
        out.len = 0;
        for (h.startable[0..h.n_startable]) |*e| {
            const n = e.name.get() orelse continue;
            const t = h.runningLocked(e);
            var x: projects_wire.Entry = .{
                .color = h.colorFor(n),
                .mode = e.mode,
                .running = t != null,
                .stoppable = if (t) |tt| tt.started_by_len > 0 and tt.stopped_by_len == 0 else false,
            };
            x.setName(n);
            out.items[out.len] = x;
            out.len += 1;
        }
    }

    /// `p:start <name>` from paired device `by` (web.zig has checked its
    /// input mode and rate limit). Only an exact name of the desk's list
    /// counts; nothing of the request but the name is used. Running: the
    /// tab it runs in (switched). Otherwise the desk's program in the
    /// desk's folder for it, with the desk's permission mode for it
    /// (never a permissive one: cmdline.deviceStart), named as listed.
    pub fn deviceStart(h: *Hub, name: []const u8, by: []const u8) StartOutcome {
        h.mutex.lockUncancelable(h.io);
        var entry: ?settings.StartableEntry = null;
        for (h.startable[0..h.n_startable]) |*e| if (std.mem.eql(u8, e.name.get() orelse "", name)) {
            entry = e.*;
        };
        const e = entry orelse {
            h.mutex.unlock(h.io);
            return .{ .result = .unknown };
        };
        if (h.runningLocked(&e)) |t| {
            t.acquire();
            h.mutex.unlock(h.io);
            return .{ .result = .switched, .tab = t };
        }
        h.mutex.unlock(h.io);
        const n = e.name.get().?;
        if (h.program.device_start != .ok) {
            var rb: [200]u8 = undefined;
            h.log.print("device '{s}' asked to start '{s}': refused, {s}", .{ by, n, cmdline.deviceStartText(h.program.device_start, &rb) });
            return .{ .result = .unsafe_program };
        }
        const path = e.path.get() orelse return .{ .result = .failed };
        const ok_dir = blk: {
            var d = Io.Dir.cwd().openDir(h.io, path, .{}) catch break :blk false;
            d.close(h.io);
            break :blk true;
        };
        if (!ok_dir) {
            h.log.print("device '{s}' asked to start '{s}': its folder is not there any more", .{ by, n });
            return .{ .result = .failed };
        }
        const cwd_w = std.unicode.wtf8ToWtf16LeAllocZ(h.gpa, path) catch return .{ .result = .failed };
        defer h.gpa.free(cwd_w);
        const t = h.open(cwd_w, n, .{ .device = .{ .by = by, .mode = e.mode } }) catch |err| {
            h.log.print("device '{s}' asked to start '{s}': {t}", .{ by, n, err });
            return .{ .result = switch (err) {
                error.TooManyTabs => .too_many_tabs,
                error.UnsafeProgram => .unsafe_program,
                else => .failed,
            } };
        };
        // A device start does not take the desk's own view away: the desk
        // keeps the tab it shows (open made the new tab the desk's).
        t.acquire();
        return .{ .result = .started, .tab = t };
    }

    /// `p:stop <name>` from paired device `by` (input mode and rate limit
    /// checked by web.zig): ends a session that a device started, the
    /// same way the desk closes a tab (the program is asked to exit and
    /// ended after close_timeout_ms). Sessions started at the desk are
    /// only ever stopped there.
    pub fn deviceStop(h: *Hub, name: []const u8, by: []const u8) projects_wire.Result {
        h.mutex.lockUncancelable(h.io);
        var found = false;
        var tab: ?*Tab = null;
        var started_here = false;
        for (h.startable[0..h.n_startable]) |*e| if (std.mem.eql(u8, e.name.get() orelse "", name)) {
            found = true;
            if (h.runningLocked(e)) |t| {
                if (t.started_by_len == 0) {
                    started_here = true;
                } else {
                    t.acquire();
                    tab = t;
                    if (t.stopped_by_len == 0) {
                        const bl = @min(by.len, t.stopped_by_buf.len);
                        @memcpy(t.stopped_by_buf[0..bl], by[0..bl]);
                        t.stopped_by_len = @intCast(bl);
                        h.gen +%= 1;
                        h.projects_gen +%= 1;
                    }
                }
            }
        };
        h.mutex.unlock(h.io);
        if (!found) return .unknown;
        if (started_here) return .not_device_started;
        const t = tab orelse return .not_running;
        defer t.release();
        h.cond.broadcast(h.io);
        h.notify();
        h.log.print("tab '{s}' stopped by device '{s}': asking its program to exit (ended after {d} s if it doesn't)", .{ t.name(), by, close_timeout_ms / 1000 });
        t.requestClose();
        return .stopped;
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
        if (t.convo_stop) |e| _ = w32.SetEvent(e);
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

    /// Caller holds `mutex`. Every open tab's activity, in bar order, as
    /// of the real-time clock's day.
    pub fn activityLocked(h: *Hub, out: *activity_wire.Activity) void {
        const now_day = localDay(std.Io.Timestamp.now(h.io, .real).toSeconds());
        out.len = h.n;
        out.sysmon = h.sysmon_on;
        for (h.tabs[0..h.n], 0..) |t, i| t.activity.toWire(t.id, now_day, &out.tabs[i]);
    }

    /// The desk changed "Show system monitor": viewers learn it from the
    /// next `activity`.
    pub fn setSysmon(h: *Hub, on: bool) void {
        h.mutex.lockUncancelable(h.io);
        h.sysmon_on = on;
        h.activity_gen +%= 1;
        h.mutex.unlock(h.io);
        h.cond.broadcast(h.io);
        h.notify();
    }

    /// A message from `portalctl hook` (hookpipe.zig's server thread).
    /// Only an open tab's own key counts; anything else changes nothing
    /// and is logged at most once a minute, without its contents.
    pub fn applyHook(h: *Hub, m: *const hookmsg.Message) void {
        switch (m.event) {
            .SubagentStart, .SubagentStop => return h.applySubagentHook(m),
            else => {},
        }
        const e = hookmsg.effect(m) orelse return;
        h.mutex.lockUncancelable(h.io);
        var found: ?*Tab = null;
        for (h.tabs[0..h.n]) |t| if (std.crypto.timing_safe.eql(hookmsg.Key, t.hook_key, m.key)) {
            t.acquire();
            found = t;
        };
        var log_it = false;
        if (found == null) {
            const now = Io.Clock.awake.now(h.io).toMilliseconds();
            if (!session_mod.withinWindow(now, h.hook_unknown_logged_ms, 60_000)) {
                h.hook_unknown_logged_ms = now;
                log_it = true;
            }
        }
        h.mutex.unlock(h.io);
        const t = found orelse {
            if (log_it) h.log.print("hooks: a message for no open tab was ignored (further ones within a minute are not logged)", .{});
            return;
        };
        defer t.release();
        // Desktop log only: the tab's name (shown on the desk anyway),
        // the event and the new state; never the key or anything else.
        if (t.session.setHookState(e)) h.log.print("hooks: tab '{s}': {t} -> {t}", .{ t.name(), m.event, stateOf(e.state) });
    }

    /// SubagentStart / SubagentStop from `portalctl hook`: only an open
    /// tab's own key counts (like applyHook); its sub-tabs learn it.
    fn applySubagentHook(h: *Hub, m: *const hookmsg.Message) void {
        if (m.agent_len == 0) return;
        h.mutex.lockUncancelable(h.io);
        var found: ?*Tab = null;
        for (h.tabs[0..h.n]) |t| if (std.crypto.timing_safe.eql(hookmsg.Key, t.hook_key, m.key)) {
            t.acquire();
            found = t;
        };
        h.mutex.unlock(h.io);
        const t = found orelse return;
        defer t.release();
        t.subagentEvent(if (m.event == .SubagentStart) .start else .stop, m.agent());
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

/// The desktop's local day number of Unix time `t` (days since
/// 1970-01-01 in the local time zone): what "today" means for usage.
pub fn localDay(t: i64) i64 {
    if (t <= 0) return @divFloor(t, 86400);
    const ft: w32.FILETIME = .fromU64((@as(u64, @intCast(t)) + 11644473600) * 10_000_000);
    var local: w32.FILETIME = undefined;
    if (w32.FileTimeToLocalFileTime(&ft, &local) == 0) return @divFloor(t, 86400);
    const lt: i64 = @as(i64, @intCast(local.toU64() / 10_000_000)) - 11644473600;
    return @divFloor(lt, 86400);
}

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
