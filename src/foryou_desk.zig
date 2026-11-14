//! One tab's "For you" cards on the desk (docs/tabs-design.md, "For you";
//! the wire: shared/foryou.zig, docs/protocol.md section 3g). The desk
//! builds them, keeps them and decides what an answer does; devices only
//! show them.
//!
//! Inputs, all under the hub's mutex (tabs.zig calls in):
//!   * the agent's last reply (its texts from the Conversation view,
//!     already scrubbed) -> suggestions (foryou_extract.zig), shown only
//!     while the turn is over (the program neither works nor waits);
//!   * the program waiting on a permission prompt -> `waiting_permission`
//!     at the top (yes = `1`, no = `esc`, as the permission card);
//!   * the admin-prompt guard (PreToolUse, `guard=marked`) -> `needs_desk`
//!     until the command's result or the turn's end;
//!   * a shell command (PreToolUse) running `long_running_ms` with no new
//!     transcript record -> `long_running` (a deadline, `Watcher`; no
//!     polling), until its result or the turn's end.
//!
//! Every card has a random 128-bit id, kept while the card stays the same
//! and replaced whenever it changes (foryou.zig: the id is the version),
//! so an answer to a card that changed is `stale`. A card answered or
//! dismissed is gone for every device (one list per tab, not per device)
//! and stays gone while the reply that made it is the last one; a
//! permission prompt, admin prompt or long run that comes again is a new
//! card (each has its own sequence number in its signature).

const std = @import("std");
const Io = std.Io;
const foryou = @import("shared").foryou;
const extract = @import("foryou_extract.zig");

pub const Item = foryou.Item;
pub const Names = extract.Names;

/// How long one shell command may run without a new transcript record
/// before the tab gets a `long_running` card.
pub const long_running_ms: i64 = 3 * 60 * 1000;
/// At most one recap per tab in this long (any device).
pub const recap_interval_ms: i64 = 60 * 1000;

pub const needs_desk_text = "An administrator prompt may be open at the desk.";
pub const needs_desk_why = "The agent ran a command that asks for elevation; only someone at the desk can answer the prompt.";
pub const long_running_text = "A command has been running for over 3 minutes.";
pub const long_running_why = "No new output from the agent since it started.";
pub const permission_text = "Claude is waiting for your permission.";

/// What a hook or the transcript says about the tab's shell commands.
pub const Event = union(enum) {
    /// A shell command starts (PreToolUse); `marked`: it asks for
    /// elevation and runs (the guard let it).
    pre_tool: struct { marked: bool },
    /// A transcript record arrived; `result`: it holds a tool result (the
    /// command finished).
    record: struct { result: bool },
    /// The turn ended or a new one began (Stop, StopFailure, SessionEnd,
    /// UserPromptSubmit).
    turn_end,
};

pub const State = struct {
    list: foryou.List = .{},
    /// The hub's For-you generation when `list` last changed (writers send
    /// the tabs changed since they last looked).
    gen: u64 = 0,

    // The reply's suggestions, and the cards dismissed or answered since
    // it became the last one (signatures).
    reply_hash: u64 = 0,
    sugg: extract.Out = .{},
    dismissed: [32]u64 = @splat(0),
    n_dismissed: usize = 0,

    /// The program works or waits (suggestions wait for the turn's end).
    busy: bool = false,
    /// A permission prompt is open, and its text (the Conversation view's
    /// question); `perm_seq` counts prompts.
    permission: bool = false,
    perm_buf: [foryou.max_summary]u8 = undefined,
    perm_len: u8 = 0,
    perm_seq: u32 = 0,
    /// The admin-prompt guard marked the running command.
    needs_desk: bool = false,
    desk_seq: u32 = 0,
    /// A shell command runs: its deadline (awake ms; null: none), and
    /// whether it passed.
    long_deadline: ?i64 = null,
    long_fired: bool = false,
    long_seq: u32 = 0,
    /// When the tab last sent a recap prompt (awake ms).
    recap_ms: i64 = std.math.minInt(i64),

    /// The last reply's texts changed (or not): new suggestions, and
    /// dismissals forgotten when it is another reply.
    pub fn setReply(s: *State, texts: []const []const u8, names: Names) void {
        var h = std.hash.Wyhash.init(0xf0f0);
        for (texts) |t| {
            h.update(t);
            h.update(&.{0});
        }
        const hash = h.final();
        if (hash == s.reply_hash) return;
        s.reply_hash = hash;
        s.n_dismissed = 0;
        extract.extract(texts, names, &s.sugg);
    }

    /// The program's state: `busy` (working, or waiting on anything), and
    /// whether that wait is a permission prompt (its question's text).
    pub fn setProgram(s: *State, busy: bool, permission: bool, text: ?[]const u8) void {
        s.busy = busy;
        if (permission and !s.permission) s.perm_seq +%= 1;
        s.permission = permission;
        const t = text orelse permission_text;
        const n = @min(t.len, s.perm_buf.len);
        @memcpy(s.perm_buf[0..n], t[0..n]);
        s.perm_len = @intCast(n);
    }

    /// A hook or transcript event at `now` (awake ms). True if a deadline
    /// was set or moved (the Watcher looks again).
    pub fn event(s: *State, e: Event, now: i64) bool {
        switch (e) {
            .pre_tool => |p| {
                s.long_deadline = now +| long_running_ms;
                s.long_fired = false;
                s.long_seq +%= 1;
                if (p.marked) {
                    s.needs_desk = true;
                    s.desk_seq +%= 1;
                }
                return true;
            },
            .record => |r| {
                if (r.result) {
                    s.long_deadline = null;
                    s.long_fired = false;
                    s.needs_desk = false;
                    return false;
                }
                // Output: the deadline starts over.
                if (s.long_deadline != null) {
                    s.long_deadline = now +| long_running_ms;
                    return true;
                }
                return false;
            },
            .turn_end => {
                s.long_deadline = null;
                s.long_fired = false;
                s.needs_desk = false;
                return false;
            },
        }
    }

    /// The deadline passed at `now`? While the program waits for an answer
    /// the command is not running: the deadline moves on. True if the
    /// cards change (`rebuild`).
    pub fn fireDue(s: *State, now: i64, waiting: bool) bool {
        const d = s.long_deadline orelse return false;
        if (now < d) return false;
        if (waiting) {
            s.long_deadline = now +| long_running_ms;
            return false;
        }
        s.long_deadline = null;
        s.long_fired = true;
        return true;
    }

    fn isDismissed(s: *const State, sig: u64) bool {
        for (s.dismissed[0..s.n_dismissed]) |d| if (d == sig) return true;
        return false;
    }

    /// Forgets card `sig` for good (answered or dismissed) and takes it off.
    pub fn dismiss(s: *State, io: Io, sig: u64) bool {
        if (!s.isDismissed(sig)) {
            if (s.n_dismissed == s.dismissed.len) {
                std.mem.copyForwards(u64, s.dismissed[0 .. s.dismissed.len - 1], s.dismissed[1..]);
                s.n_dismissed -= 1;
            }
            s.dismissed[s.n_dismissed] = sig;
            s.n_dismissed += 1;
        }
        return s.rebuild(io);
    }

    /// The card `id` names, if it is current.
    pub fn take(s: *const State, id: foryou.Id) ?Taken {
        const i = s.list.find(id) orelse return null;
        const it = &s.list.items[i];
        return .{ .item = it.*, .sig = s.sigOf(it) };
    }

    fn sigOf(s: *const State, it: *const Item) u64 {
        var h = std.hash.Wyhash.init(0x1d);
        h.update(&.{@intFromEnum(it.kind)});
        const seq: u32 = switch (it.kind) {
            .waiting_permission => s.perm_seq,
            .needs_desk => s.desk_seq,
            .long_running => s.long_seq,
            else => 0,
        };
        h.update(std.mem.asBytes(&seq));
        for ([_][]const u8{ it.summary(), it.cmd(), it.why(), it.project() }) |f| {
            h.update(f);
            h.update(&.{0});
        }
        return h.final();
    }

    /// Builds the cards from the inputs: waiting ones first (permission,
    /// admin prompt, long run), then, once the turn is over, the question
    /// and the suggestions in reply order; at most foryou.max_items. A card
    /// that stays the same keeps its id; anything new gets a new one. True
    /// if the list changed.
    pub fn rebuild(s: *State, io: Io) bool {
        var want: [foryou.max_items]Item = undefined;
        var n: usize = 0;
        const Add = struct {
            fn add(st: *const State, w: *[foryou.max_items]Item, k: *usize, it: Item) void {
                if (k.* == w.len or !it.valid() or st.isDismissed(st.sigOf(&it))) return;
                w[k.*] = it;
                k.* += 1;
            }
        };
        if (s.permission) {
            var it: Item = .{ .kind = .waiting_permission };
            it.setSummary(s.perm_buf[0..s.perm_len]);
            Add.add(s, &want, &n, it);
        }
        if (s.needs_desk) {
            var it: Item = .{ .kind = .needs_desk };
            it.setSummary(needs_desk_text);
            it.setWhy(needs_desk_why);
            Add.add(s, &want, &n, it);
        }
        if (s.long_fired) {
            var it: Item = .{ .kind = .long_running };
            it.setSummary(long_running_text);
            it.setWhy(long_running_why);
            Add.add(s, &want, &n, it);
        }
        if (!s.busy) {
            for (s.sugg.slice()) |it| if (it.kind == .answer) Add.add(s, &want, &n, it);
            for (s.sugg.slice()) |it| if (it.kind != .answer) Add.add(s, &want, &n, it);
        }
        // Ids: kept for a card that is the same, new otherwise.
        var changed = n != s.list.len;
        for (want[0..n], 0..) |*it, i| {
            const sig = s.sigOf(it);
            var id: ?foryou.Id = null;
            for (s.list.slice()) |*old| if (s.sigOf(old) == sig) {
                id = old.id;
                break;
            };
            it.id = id orelse newId(io);
            if (!changed and !std.mem.eql(u8, &it.id, &s.list.items[i].id)) changed = true;
        }
        if (!changed) return false;
        @memcpy(s.list.items[0..n], want[0..n]);
        s.list.len = n;
        return true;
    }

    /// A recap for this tab now? (at most one per recap_interval_ms; the
    /// time is taken if so).
    pub fn recapAllowed(s: *State, now: i64) bool {
        if (s.recap_ms != std.math.minInt(i64) and now -| s.recap_ms < recap_interval_ms) return false;
        s.recap_ms = now;
        return true;
    }
};

pub const Taken = struct { item: Item, sig: u64 };

fn newId(io: Io) foryou.Id {
    var id: foryou.Id = undefined;
    while (true) {
        io.randomSecure(&id) catch io.random(&id);
        if (!std.mem.allEqual(u8, &id, 0)) return id;
    }
}

// ------------------------------------------------------------ deadlines

/// The long-running deadlines of every tab, on one thread that sleeps
/// until the earliest (or forever without one) and is woken when one is
/// set earlier (`poke`). `scan` fires what is due and returns the next
/// deadline.
pub const Watcher = struct {
    // Set before `start` (tabs.Hub.open).
    io: Io = undefined,
    ctx: *anyopaque = undefined,
    scan: *const fn (ctx: *anyopaque, now_ms: i64) ?i64 = undefined,
    wake: Io.Event = .unset,
    started: std.atomic.Value(bool) = .init(false),

    /// Starts the thread once (the first tab).
    pub fn start(w: *Watcher) void {
        if (w.started.swap(true, .acq_rel)) return;
        const th = std.Thread.spawn(.{}, run, .{w}) catch {
            w.started.store(false, .release);
            return;
        };
        th.detach();
    }

    pub fn poke(w: *Watcher) void {
        if (!w.started.load(.acquire)) return;
        w.wake.set(w.io);
    }

    fn run(w: *Watcher) void {
        while (true) {
            // Reset before scanning: a deadline set meanwhile wakes again.
            w.wake.reset();
            const now = Io.Clock.awake.now(w.io).toMilliseconds();
            const next = w.scan(w.ctx, now);
            if (next) |d| {
                const left = @max(d - now, 1);
                w.wake.waitTimeout(w.io, .{ .duration = .{ .raw = .fromMilliseconds(left), .clock = .awake } }) catch {};
            } else {
                w.wake.wait(w.io) catch {};
            }
        }
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;
const tio = testing.io;

fn kinds(s: *const State, buf: []u8) []const u8 {
    var n: usize = 0;
    for (s.list.slice()) |*it| {
        buf[n] = switch (it.kind) {
            .waiting_permission => 'W',
            .needs_desk => 'D',
            .long_running => 'L',
            .answer => 'A',
            .suggest_run => 'R',
            .suggest_goto => 'G',
        };
        n += 1;
    }
    return buf[0..n];
}

test "waiting cards first; suggestions only once the turn is over" {
    var s: State = .{};
    s.setReply(&.{"Run `zig build e2e` next. Shall I commit?"}, .{});
    s.setProgram(true, false, null);
    try testing.expect(!s.rebuild(tio));
    try testing.expectEqual(@as(usize, 0), s.list.len);
    s.setProgram(false, false, null);
    try testing.expect(s.rebuild(tio));
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings("AR", kinds(&s, &b));
    // A permission prompt: on top, the suggestions wait.
    s.setProgram(true, true, "Claude wants to run a command. Allow it?");
    _ = s.event(.{ .pre_tool = .{ .marked = true } }, 0);
    try testing.expect(s.rebuild(tio));
    try testing.expectEqualStrings("WD", kinds(&s, &b));
    try testing.expectEqualStrings("Claude wants to run a command. Allow it?", s.list.items[0].summary());
    try testing.expect(s.list.needsDesk());
    // The command's result: the admin card goes.
    _ = s.event(.{ .record = .{ .result = true } }, 10);
    s.setProgram(false, false, null);
    try testing.expect(s.rebuild(tio));
    try testing.expectEqualStrings("AR", kinds(&s, &b));
}

test "ids: kept while a card stays, new when it changes; stale ids refused" {
    var s: State = .{};
    s.setReply(&.{"Run `zig build test`."}, .{});
    _ = s.rebuild(tio);
    const id1 = s.list.items[0].id;
    try testing.expect(!s.rebuild(tio));
    try testing.expectEqual(id1, s.list.items[0].id);
    try testing.expect(s.take(id1) != null);
    // Another reply with another command: a new id; the old one is stale.
    s.setReply(&.{"Run `zig build e2e`."}, .{});
    try testing.expect(s.rebuild(tio));
    try testing.expect(!std.mem.eql(u8, &id1, &s.list.items[0].id));
    try testing.expect(s.take(id1) == null);
    // A second permission prompt with the same text is a new card.
    s.setProgram(true, true, "Allow?");
    _ = s.rebuild(tio);
    const p1 = s.list.items[0].id;
    s.setProgram(false, false, null);
    _ = s.rebuild(tio);
    s.setProgram(true, true, "Allow?");
    _ = s.rebuild(tio);
    try testing.expect(!std.mem.eql(u8, &p1, &s.list.items[0].id));
}

test "dismissed cards stay gone for this reply, come back with another" {
    var s: State = .{};
    s.setReply(&.{"Run `a b`. Run `c d`."}, .{});
    _ = s.rebuild(tio);
    const t = s.take(s.list.items[0].id).?;
    try testing.expect(s.dismiss(tio, t.sig));
    try testing.expectEqual(@as(usize, 1), s.list.len);
    try testing.expectEqualStrings("c d", s.list.items[0].cmd());
    _ = s.rebuild(tio);
    try testing.expectEqual(@as(usize, 1), s.list.len);
    s.setReply(&.{"Again: run `a b`."}, .{});
    _ = s.rebuild(tio);
    try testing.expectEqualStrings("a b", s.list.items[0].cmd());
}

test "the cap: at most max_items, waiting ones kept" {
    var s: State = .{};
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    for (0..30) |i| try w.print("Run `zig build t{d}`.\n", .{i});
    s.setReply(&.{w.buffered()}, .{});
    s.setProgram(false, false, null);
    _ = s.event(.{ .pre_tool = .{ .marked = true } }, 0);
    _ = s.rebuild(tio);
    try testing.expectEqual(@as(usize, foryou.max_items), s.list.len);
    try testing.expectEqual(foryou.Kind.needs_desk, s.list.items[0].kind);
}

test "long running: a deadline, moved by output and waits, cleared by the result" {
    var s: State = .{};
    try testing.expect(s.event(.{ .pre_tool = .{ .marked = false } }, 1000));
    try testing.expectEqual(@as(?i64, 1000 + long_running_ms), s.long_deadline);
    try testing.expect(!s.fireDue(1000 + long_running_ms - 1, false));
    // A record without a result is output: the deadline starts over.
    try testing.expect(s.event(.{ .record = .{ .result = false } }, 5000));
    try testing.expect(!s.fireDue(1000 + long_running_ms, false));
    // Waiting for an answer is not running.
    try testing.expect(!s.fireDue(5000 + long_running_ms, true));
    try testing.expect(s.fireDue(5000 + 2 * long_running_ms, false));
    _ = s.rebuild(tio);
    try testing.expectEqual(foryou.Kind.long_running, s.list.items[0].kind);
    _ = s.event(.{ .record = .{ .result = true } }, 0);
    _ = s.rebuild(tio);
    try testing.expectEqual(@as(usize, 0), s.list.len);
}

test "recap: once a minute per tab" {
    var s: State = .{};
    try testing.expect(s.recapAllowed(100));
    try testing.expect(!s.recapAllowed(100 + recap_interval_ms - 1));
    try testing.expect(s.recapAllowed(100 + recap_interval_ms));
}

test "every card is valid and carries no scrubbed path" {
    var s: State = .{};
    s.setReply(&.{"Run `cat [path]\\x`. Run `zig build`."}, .{});
    _ = s.rebuild(tio);
    try testing.expectEqual(@as(usize, 1), s.list.len);
    for (s.list.slice()) |*it| try testing.expect(it.valid());
}
