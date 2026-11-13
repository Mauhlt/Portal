//! Finds and reads the subagents of the transcript a tab follows
//! (follow.zig), for the tab's sub-tabs (subtabs.zig). Driven by the
//! follower's own thread and wait loop; nothing is polled:
//!   * directory change notifications (ReadDirectoryChangesW) on
//!     `<folder>\<session>\subagents\` report new subagents, their meta
//!     files being rewritten and, where NTFS reports them, appends;
//!   * until that folder exists, a change notification on the nearest
//!     existing ancestor (`<folder>\<session>`, then `<folder>`) waits for
//!     it to appear;
//!   * the tab's program printing (the follower's poke) checks the sizes of
//!     the subagents still running, as for the main transcript (appends
//!     through a handle the writer keeps open are not always reported);
//!   * the agent's SubagentStart / SubagentStop hooks (tabs.zig,
//!     Tab.subagentEvent) set `kick`: look again now.
//!
//! The folder's structure, as the agent (2.1.3xx) writes it (checked
//! 2026-11-13 on real sessions, key names and types only; see
//! docs/tabs-design.md, "Subagent sub-tabs"):
//!   * `agent-<agentId>.jsonl`: the subagent's transcript, the same record
//!     format as the session's (transcript.zig) with `isSidechain` true,
//!     `agentId` (the file's id) and `sessionId` (the parent session);
//!   * `agent-<agentId>.meta.json`: one JSON object with `agentType`,
//!     `description` (the Agent tool call's description: the sub-tab's
//!     name), `toolUseId` (the parent's Agent tool_use id), `spawnDepth`,
//!     ... and `finished: true` once the subagent ended (absent while it
//!     runs). Only `description` and `finished` are read.
//!
//! What counts: when the tab took a transcript it did not start (`/resume`
//! of an earlier session) the subagents that had already finished when the
//! folder was first looked at are history and get no sub-tab; every other
//! one does (sink.upsert), and its transcript is read from its start
//! (from its last `follow.tail_read` bytes if it is bigger than
//! `follow.max_initial`).
//!
//! Memory: per subagent a few counters and, only while a line is being
//! written, its partial line (at most `follow.max_line`, freed when it
//! finishes); one shared record. At most `max_agents` subagents are
//! tracked per transcript.

const std = @import("std");
const Allocator = std.mem.Allocator;
const w = @import("../win32.zig");
const fsutil = @import("../fsutil.zig");
const transcript = @import("transcript.zig");
const follow = @import("follow.zig");
const subtabs = @import("subtabs.zig");

pub const max_agents = 64;
/// A meta file bigger than this is not read.
const max_meta = 64 * 1024;
const prefix = "agent-";
const jsonl_ext = ".jsonl";
const meta_ext = ".meta.json";

/// Where the watcher delivers what it finds. Called on the follower's
/// thread; each call takes whatever lock the sub-tabs need.
pub const Sink = struct {
    ctx: *anyopaque,
    /// The followed transcript changed (or there is none): every sub-tab
    /// goes.
    clear: *const fn (ctx: *anyopaque) void,
    /// Subagent `agent` exists; its description once known (raw, the sink
    /// scrubs it); `done` once it finished. False: it has no sub-tab (no
    /// room), so it is not read.
    upsert: *const fn (ctx: *anyopaque, agent: []const u8, description: ?[]const u8, done: bool) bool,
    /// One record of its transcript.
    apply: *const fn (ctx: *anyopaque, agent: []const u8, rec: *const transcript.Record) void,
    /// Its transcript is read again from the start (replaced or cut).
    restart: *const fn (ctx: *anyopaque, agent: []const u8) void,
};

/// `agent-<id>.jsonl` / `agent-<id>.meta.json` → the id and which, or null.
pub fn parseName(name: []const u8) ?struct { agent: []const u8, meta: bool } {
    if (!std.mem.startsWith(u8, name, prefix)) return null;
    const rest = name[prefix.len..];
    const meta = std.mem.endsWith(u8, rest, meta_ext);
    const ext_len = if (meta) meta_ext.len else if (std.mem.endsWith(u8, rest, jsonl_ext)) jsonl_ext.len else return null;
    const id = rest[0 .. rest.len - ext_len];
    if (!subtabs.validAgent(id)) return null;
    return .{ .agent = id, .meta = meta };
}

/// What a meta file says (only these two fields are read).
pub const Meta = struct {
    description: ?[]const u8 = null,
    finished: bool = false,
};

/// Parses a meta file; null if it is not a JSON object.
pub fn parseMeta(arena: Allocator, text: []const u8) ?Meta {
    const In = struct {
        description: ?[]const u8 = null,
        finished: ?bool = null,
    };
    const in = std.json.parseFromSliceLeaky(In, arena, text, .{ .ignore_unknown_fields = true, .duplicate_field_behavior = .use_last }) catch return null;
    return .{ .description = in.description, .finished = in.finished orelse false };
}

const Agent = struct {
    id_buf: [subtabs.max_agent]u8 = undefined,
    id_len: u8 = 0,
    /// History, or no room: never read.
    ignored: bool = false,
    /// It has a sub-tab (sink.upsert said yes).
    shown: bool = false,
    named: bool = false,
    done: bool = false,
    /// The meta file's size when last read (a rewrite changes it).
    meta_size: ?u64 = null,
    offset: u64 = 0,
    started: bool = false,
    line: std.ArrayList(u8) = .empty,
    line_cut: bool = false,
    skip_partial: bool = false,

    fn id(a: *const Agent) []const u8 {
        return a.id_buf[0..a.id_len];
    }
};

pub const Watcher = struct {
    gpa: Allocator,
    sink: Sink,
    /// Set by others (hooks) to make the watcher look again; optional, not
    /// owned.
    kick: ?w.HANDLE = null,
    /// `<folder>\<session>` and its `subagents` (owned) while following.
    session_dir: ?[]u8 = null,
    sub_dir: ?[]u8 = null,
    /// The transcript is one the tab started: every subagent is new.
    fresh: bool = true,
    /// The subagents folder was listed once.
    scanned: bool = false,
    dc: ?*follow.DirChanges = null,
    /// While `sub_dir` does not exist: its nearest existing ancestor.
    anc: ?fsutil.DirWatch = null,
    agents: std.ArrayList(Agent) = .empty,
    rec: *transcript.Record,

    pub fn init(gpa: Allocator, sink: Sink) !Watcher {
        return .{ .gpa = gpa, .sink = sink, .rec = try gpa.create(transcript.Record) };
    }

    pub fn deinit(sw: *Watcher) void {
        sw.close();
        sw.gpa.destroy(sw.rec);
        sw.agents.deinit(sw.gpa);
    }

    fn close(sw: *Watcher) void {
        if (sw.dc) |d| d.close();
        sw.dc = null;
        if (sw.anc) |*a| a.close();
        sw.anc = null;
        if (sw.session_dir) |p| sw.gpa.free(p);
        if (sw.sub_dir) |p| sw.gpa.free(p);
        sw.session_dir = null;
        sw.sub_dir = null;
        for (sw.agents.items) |*a| a.line.deinit(sw.gpa);
        sw.agents.clearRetainingCapacity();
        sw.scanned = false;
    }

    /// The follower now reads `<folder>\<stem>.jsonl`; `fresh`: a
    /// transcript the tab started (not an earlier session's).
    pub fn follow_(sw: *Watcher, folder: []const u8, stem: []const u8, fresh: bool) void {
        sw.close();
        sw.sink.clear(sw.sink.ctx);
        sw.fresh = fresh;
        var pb: [2048]u8 = undefined;
        const sd = fsutil.join(&pb, &.{ folder, stem }) catch return;
        sw.session_dir = sw.gpa.dupe(u8, sd) catch return;
        var qb: [2048]u8 = undefined;
        const sub = fsutil.join(&qb, &.{ sd, "subagents" }) catch return;
        sw.sub_dir = sw.gpa.dupe(u8, sub) catch return;
        sw.attach();
    }

    /// The follower reads no transcript now (its folder went).
    pub fn stop(sw: *Watcher) void {
        const had = sw.session_dir != null;
        sw.close();
        if (had) sw.sink.clear(sw.sink.ctx);
    }

    /// Watches `sub_dir` if it exists, else waits for it on its nearest
    /// existing ancestor.
    fn attach(sw: *Watcher) void {
        const sub = sw.sub_dir orelse return;
        if (sw.dc != null) return;
        if (sw.anc) |*a| a.close();
        sw.anc = null;
        if (isDir(sw.gpa, sub)) {
            const dc = follow.DirChanges.open(sw.gpa, sub, w.FILE_NOTIFY_CHANGE_FILE_NAME | w.FILE_NOTIFY_CHANGE_SIZE | w.FILE_NOTIFY_CHANGE_LAST_WRITE) catch return sw.waitFor(sub);
            dc.arm() catch {
                dc.close();
                return sw.waitFor(sub);
            };
            sw.dc = dc;
            sw.scan();
            return;
        }
        sw.waitFor(sub);
    }

    fn waitFor(sw: *Watcher, sub: []const u8) void {
        var anc: []const u8 = std.fs.path.dirnameWindows(sub) orelse return;
        while (!isDir(sw.gpa, anc)) anc = std.fs.path.dirnameWindows(anc) orelse return;
        sw.anc = fsutil.DirWatch.open(sw.gpa, anc, .{ .dirs = true }) catch null;
        // It may have appeared while the watch was set up.
        if (sw.anc != null and isDir(sw.gpa, sub)) sw.attach();
    }

    /// The handles to wait on besides the follower's own, into `out`.
    pub fn handles(sw: *Watcher, out: *[2]w.HANDLE) []const w.HANDLE {
        var n: usize = 0;
        if (sw.dc) |d| {
            out[n] = d.ev;
            n += 1;
        } else if (sw.anc) |a| {
            out[n] = a.h;
            n += 1;
        }
        if (sw.kick) |k| {
            out[n] = k;
            n += 1;
        }
        return out[0..n];
    }

    /// Handle `h` (one of `handles`) was signalled.
    pub fn signaled(sw: *Watcher, h: w.HANDLE) void {
        if (sw.dc) |d| if (h == d.ev) {
            var batch = d.collect() catch return sw.lost();
            d.arm() catch return sw.lost();
            if (batch.overflow) return sw.scan();
            var nb: [1024]u8 = undefined;
            while (batch.next(&nb)) |name| sw.changed(name);
            return;
        };
        if (sw.anc) |*a| if (h == a.h) {
            a.rearm() catch {};
            return sw.attach();
        };
        if (sw.kick) |k| if (h == k) {
            sw.attach();
            if (sw.dc != null) sw.scan();
        };
    }

    /// The subagents folder went (or cannot be watched): wait for it again.
    fn lost(sw: *Watcher) void {
        if (sw.dc) |d| d.close();
        sw.dc = null;
        sw.attach();
    }

    /// The tab's program printed: read what running subagents gained, and
    /// whether their meta files changed (finished).
    pub fn printed(sw: *Watcher) void {
        if (sw.dc == null) return;
        var i: usize = 0;
        while (i < sw.agents.items.len) : (i += 1) {
            const a = &sw.agents.items[i];
            if (a.ignored or a.done) continue;
            var ib: [subtabs.max_agent]u8 = undefined;
            const id = ib[0..a.id_len];
            @memcpy(id, a.id());
            sw.readMeta(id, false);
            sw.readMore(id);
        }
    }

    /// Lists the folder: meta files first (history is decided by them),
    /// then transcripts.
    fn scan(sw: *Watcher) void {
        const sub = sw.sub_dir orelse return;
        const first = !sw.scanned;
        sw.scanned = true;
        for ([_]bool{ true, false }) |metas| {
            var pat_buf: [2048]u8 = undefined;
            const pat = std.fmt.bufPrint(&pat_buf, "{s}\\" ++ prefix ++ "*", .{sub}) catch return;
            var it = follow.Find.open(sw.gpa, pat) catch return;
            defer it.close();
            var nb: [1024]u8 = undefined;
            while (it.next(&nb)) |e| {
                if (e.dir) continue;
                const p = parseName(e.name) orelse continue;
                if (p.meta != metas) continue;
                if (metas) sw.readMeta(p.agent, first and !sw.fresh) else sw.readMore(p.agent);
            }
        }
    }

    fn changed(sw: *Watcher, name: []const u8) void {
        const p = parseName(name) orelse return;
        if (p.meta) sw.readMeta(p.agent, false) else sw.readMore(p.agent);
    }

    /// The tracked subagent `id`, added if new (null: untracked, too many).
    fn agentFor(sw: *Watcher, id: []const u8) ?*Agent {
        for (sw.agents.items) |*a| if (std.mem.eql(u8, a.id(), id)) return a;
        if (sw.agents.items.len >= max_agents) return null;
        const a = sw.agents.addOne(sw.gpa) catch return null;
        a.* = .{};
        @memcpy(a.id_buf[0..id.len], id);
        a.id_len = @intCast(id.len);
        return a;
    }

    /// Gives `a` its sub-tab (or learns there is no room).
    fn show(sw: *Watcher, a: *Agent, description: ?[]const u8) void {
        if (a.ignored) return;
        if (!sw.sink.upsert(sw.sink.ctx, a.id(), description, a.done)) {
            if (!a.shown) a.ignored = true;
            return;
        }
        a.shown = true;
        if (description != null) a.named = true;
    }

    fn pathOf(sw: *Watcher, buf: []u8, id: []const u8, ext: []const u8) ?[]const u8 {
        const sub = sw.sub_dir orelse return null;
        return std.fmt.bufPrint(buf, "{s}\\" ++ prefix ++ "{s}{s}", .{ sub, id, ext }) catch null;
    }

    /// Reads `agent-<id>.meta.json` if it changed: the description, and
    /// whether it finished. `history`: one already finished is not shown.
    fn readMeta(sw: *Watcher, id: []const u8, history: bool) void {
        const a = sw.agentFor(id) orelse return;
        if (a.ignored) return;
        var pb: [2048]u8 = undefined;
        const path = sw.pathOf(&pb, id, meta_ext) orelse return;
        const size = follow.sizeOf(sw.gpa, path) orelse return;
        if (size > max_meta) return;
        if (a.meta_size) |s| if (s == size) return;
        const buf = sw.gpa.alloc(u8, @intCast(size)) catch return;
        defer sw.gpa.free(buf);
        const n = follow.readAt(sw.gpa, path, 0, buf) catch return;
        if (n != size) return; // being written: its next change brings it
        var arena = std.heap.ArenaAllocator.init(sw.gpa);
        defer arena.deinit();
        const m = parseMeta(arena.allocator(), buf[0..n]) orelse return; // partial: wait for the rest
        a.meta_size = size;
        if (history and m.finished) {
            a.ignored = true;
            return;
        }
        const finishing = m.finished and !a.done;
        if (finishing) {
            // Whatever it wrote last comes before "done".
            sw.readMore(id);
            a.done = true;
        }
        if (!a.shown or finishing or (!a.named and m.description != null)) sw.show(a, m.description);
        if (a.done) {
            a.line.deinit(sw.gpa);
            a.line = .empty;
        }
    }

    /// Reads what `agent-<id>.jsonl` gained since last time.
    fn readMore(sw: *Watcher, id: []const u8) void {
        const a = sw.agentFor(id) orelse return;
        if (a.ignored) return;
        if (!a.shown) {
            sw.show(a, null);
            if (!a.shown) return;
        }
        var pb: [2048]u8 = undefined;
        const path = sw.pathOf(&pb, id, jsonl_ext) orelse return;
        const size = follow.sizeOf(sw.gpa, path) orelse return;
        if (!a.started) {
            a.started = true;
            if (size > follow.max_initial) {
                a.offset = size - follow.tail_read;
                a.skip_partial = true;
            }
        } else if (size < a.offset) {
            a.offset = 0;
            a.line.clearRetainingCapacity();
            a.line_cut = false;
            a.skip_partial = false;
            sw.sink.restart(sw.sink.ctx, id);
        }
        var chunk: [64 * 1024]u8 = undefined;
        while (a.offset < size) {
            const want: usize = @intCast(@min(chunk.len, size - a.offset));
            const n = follow.readAt(sw.gpa, path, a.offset, chunk[0..want]) catch return;
            if (n == 0) return;
            a.offset += n;
            sw.feed(a, chunk[0..n]);
        }
    }

    fn feed(sw: *Watcher, a: *Agent, data: []const u8) void {
        var rest = data;
        while (rest.len > 0) {
            const nl = std.mem.indexOfScalar(u8, rest, '\n');
            const piece = rest[0 .. nl orelse rest.len];
            const room = follow.max_line - a.line.items.len;
            if (piece.len > room) a.line_cut = true;
            a.line.appendSlice(sw.gpa, piece[0..@min(piece.len, room)]) catch {
                a.line_cut = true;
            };
            const end = nl orelse return;
            rest = rest[end + 1 ..];
            if (a.skip_partial) {
                a.skip_partial = false;
            } else {
                const line = std.mem.trimEnd(u8, a.line.items, "\r");
                if (std.mem.trim(u8, line, " \t").len > 0 and transcript.parseLine(sw.gpa, line, !a.line_cut, sw.rec))
                    sw.sink.apply(sw.sink.ctx, a.id(), sw.rec);
            }
            a.line.clearRetainingCapacity();
            a.line_cut = false;
        }
    }
};

fn isDir(gpa: Allocator, path: []const u8) bool {
    const pw = fsutil.longWide(gpa, path) catch return false;
    defer gpa.free(pw);
    const attr = w.GetFileAttributesW(pw.ptr);
    return attr != w.INVALID_FILE_ATTRIBUTES and attr & w.FILE_ATTRIBUTE_DIRECTORY != 0;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "parseName and parseMeta" {
    const j = parseName("agent-a01496045a85e979c.jsonl").?;
    try testing.expectEqualStrings("a01496045a85e979c", j.agent);
    try testing.expect(!j.meta);
    const m = parseName("agent-a01496045a85e979c.meta.json").?;
    try testing.expect(m.meta);
    try testing.expect(parseName("agent-.jsonl") == null);
    try testing.expect(parseName("agent-x y.jsonl") == null);
    try testing.expect(parseName("agent-x.txt") == null);
    try testing.expect(parseName("11111111-2222-3333-4444-555555555555.jsonl") == null);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const running = parseMeta(a, "{\"agentType\":\"general-purpose\",\"description\":\"Find tests\",\"toolUseId\":\"toolu_1\",\"spawnDepth\":1,\"future\":{\"x\":[1]}}").?;
    try testing.expectEqualStrings("Find tests", running.description.?);
    try testing.expect(!running.finished);
    try testing.expect(parseMeta(a, "{\"description\":\"x\",\"finished\":true}").?.finished);
    try testing.expect(parseMeta(a, "{\"description\":\"x\",\"fini") == null);
    try testing.expect(parseMeta(a, "[]") == null);
}

/// Records what the watcher reports.
const TestSink = struct {
    clears: u32 = 0,
    restarts: u32 = 0,
    room: usize = 16,
    agents: [8]struct { id: [32]u8, len: usize, desc: [64]u8, desc_len: usize, done: bool, texts: u32 } = undefined,
    n: usize = 0,

    fn sink(s: *TestSink) Sink {
        return .{ .ctx = s, .clear = clear, .upsert = upsert, .apply = apply, .restart = restart };
    }
    fn of(ctx: *anyopaque) *TestSink {
        return @ptrCast(@alignCast(ctx));
    }
    fn find(s: *TestSink, agent: []const u8) ?usize {
        for (s.agents[0..s.n], 0..) |a, i| if (std.mem.eql(u8, a.id[0..a.len], agent)) return i;
        return null;
    }
    fn clear(ctx: *anyopaque) void {
        const s = of(ctx);
        s.clears += 1;
        s.n = 0;
    }
    fn upsert(ctx: *anyopaque, agent: []const u8, desc: ?[]const u8, done: bool) bool {
        const s = of(ctx);
        const i = s.find(agent) orelse blk: {
            if (s.n == s.room) return false;
            s.agents[s.n] = .{ .id = undefined, .len = agent.len, .desc = undefined, .desc_len = 0, .done = false, .texts = 0 };
            @memcpy(s.agents[s.n].id[0..agent.len], agent);
            s.n += 1;
            break :blk s.n - 1;
        };
        if (desc) |d| {
            @memcpy(s.agents[i].desc[0..d.len], d);
            s.agents[i].desc_len = d.len;
        }
        if (done) s.agents[i].done = true;
        return true;
    }
    fn apply(ctx: *anyopaque, agent: []const u8, rec: *const transcript.Record) void {
        const s = of(ctx);
        const i = s.find(agent) orelse return;
        if (rec.sidechain) s.agents[i].texts += 1;
    }
    fn restart(ctx: *anyopaque, agent: []const u8) void {
        _ = agent;
        of(ctx).restarts += 1;
    }
};

const TmpDir = struct {
    tmp: testing.TmpDir,
    root: []u8,

    fn init() !TmpDir {
        var t: TmpDir = .{ .tmp = testing.tmpDir(.{}), .root = undefined };
        const cwd = try std.process.currentPathAlloc(testing.io, testing.allocator);
        defer testing.allocator.free(cwd);
        t.root = try std.fmt.allocPrint(testing.allocator, "{s}\\.zig-cache\\tmp\\{s}", .{ cwd, &t.tmp.sub_path });
        return t;
    }
    fn deinit(t: *TmpDir) void {
        testing.allocator.free(t.root);
        t.tmp.cleanup();
    }
    fn write(t: *TmpDir, rel: []const u8, data: []const u8, append: bool) !void {
        var pb: [1024]u8 = undefined;
        const p = try std.fmt.bufPrint(&pb, "{s}\\{s}", .{ t.root, rel });
        const pw = try fsutil.longWide(testing.allocator, p);
        defer testing.allocator.free(pw);
        const h = w.validHandle(w.CreateFileW(pw.ptr, if (append) w.FILE_APPEND_DATA else w.GENERIC_WRITE, w.FILE_SHARE_READ | w.FILE_SHARE_WRITE | w.FILE_SHARE_DELETE, null, if (append) w.OPEN_ALWAYS else w.CREATE_ALWAYS, w.FILE_ATTRIBUTE_NORMAL, null)) orelse return error.OpenFailed;
        defer _ = w.CloseHandle(h);
        var n: w.DWORD = 0;
        if (w.WriteFile(h, data.ptr, @intCast(data.len), &n, null) == 0) return error.WriteFailed;
    }
};

const test_stem = "11111111-2222-3333-4444-555555555555";
const side = "{\"type\":\"user\",\"isSidechain\":true,\"agentId\":\"a1\",\"sessionId\":\"" ++ test_stem ++ "\",\"message\":{\"role\":\"user\",\"content\":\"go\"}}\n";

/// Waits (bounded) for one of the watcher's handles and hands it over.
fn pump(sw: *Watcher) bool {
    var hb: [2]w.HANDLE = undefined;
    const hs = sw.handles(&hb);
    if (hs.len == 0) return false;
    const r = w.WaitForMultipleObjects(@intCast(hs.len), hs.ptr, 0, 2000);
    if (r >= hs.len) return false;
    sw.signaled(hs[r]);
    return true;
}

test "watcher: waits for the folder, finds subagents, reads appends, marks finished" {
    var t = try TmpDir.init();
    defer t.deinit();
    const gpa = testing.allocator;
    try t.tmp.dir.createDirPath(testing.io, "proj");
    var fb: [1024]u8 = undefined;
    const folder = try std.fmt.bufPrint(&fb, "{s}\\proj", .{t.root});

    var ts: TestSink = .{};
    var sw = try Watcher.init(gpa, ts.sink());
    defer sw.deinit();
    sw.follow_(folder, test_stem, true);
    try testing.expectEqual(@as(u32, 1), ts.clears);
    try testing.expect(sw.dc == null and sw.anc != null); // waiting

    // The session's folder, then its subagents folder appear.
    try t.tmp.dir.createDirPath(testing.io, "proj\\" ++ test_stem);
    try testing.expect(pump(&sw));
    try testing.expect(sw.dc == null and sw.anc != null); // now on the session folder
    try t.tmp.dir.createDirPath(testing.io, "proj\\" ++ test_stem ++ "\\subagents");
    try testing.expect(pump(&sw));
    try testing.expect(sw.dc != null);

    // A subagent: its transcript first, then its meta.
    try t.write("proj\\" ++ test_stem ++ "\\subagents\\agent-a1.jsonl", side, true);
    sw.changed("agent-a1.jsonl");
    try testing.expectEqual(@as(usize, 1), ts.n);
    try testing.expectEqual(@as(u32, 1), ts.agents[0].texts);
    try testing.expectEqual(@as(usize, 0), ts.agents[0].desc_len);
    try t.write("proj\\" ++ test_stem ++ "\\subagents\\agent-a1.meta.json", "{\"agentType\":\"general-purpose\",\"description\":\"Find tests\",\"spawnDepth\":1}", false);
    sw.changed("agent-a1.meta.json");
    try testing.expectEqualStrings("Find tests", ts.agents[0].desc[0..ts.agents[0].desc_len]);
    try testing.expect(!ts.agents[0].done);

    // Half a line, then the rest (through the poke path).
    try t.write("proj\\" ++ test_stem ++ "\\subagents\\agent-a1.jsonl", side[0..30], true);
    sw.printed();
    try testing.expectEqual(@as(u32, 1), ts.agents[0].texts);
    try t.write("proj\\" ++ test_stem ++ "\\subagents\\agent-a1.jsonl", side[30..], true);
    sw.printed();
    try testing.expectEqual(@as(u32, 2), ts.agents[0].texts);

    // It finishes: the meta file is rewritten with finished.
    try t.write("proj\\" ++ test_stem ++ "\\subagents\\agent-a1.meta.json", "{\"agentType\":\"general-purpose\",\"description\":\"Find tests\",\"spawnDepth\":1,\"finished\":true}", false);
    sw.printed();
    try testing.expect(ts.agents[0].done);

    // Another transcript followed: everything starts over.
    sw.follow_(folder, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", true);
    try testing.expectEqual(@as(u32, 2), ts.clears);
    try testing.expectEqual(@as(usize, 0), ts.n);
}

test "watcher: a resumed transcript's finished subagents are history; no room means not read" {
    var t = try TmpDir.init();
    defer t.deinit();
    const gpa = testing.allocator;
    try t.tmp.dir.createDirPath(testing.io, "proj\\" ++ test_stem ++ "\\subagents");
    const d = "proj\\" ++ test_stem ++ "\\subagents\\";
    try t.write(d ++ "agent-old.meta.json", "{\"description\":\"Old\",\"finished\":true}", false);
    try t.write(d ++ "agent-old.jsonl", side, false);
    try t.write(d ++ "agent-run.meta.json", "{\"description\":\"Running\"}", false);
    try t.write(d ++ "agent-run.jsonl", side, false);
    var fb: [1024]u8 = undefined;
    const folder = try std.fmt.bufPrint(&fb, "{s}\\proj", .{t.root});

    var ts: TestSink = .{};
    var sw = try Watcher.init(gpa, ts.sink());
    defer sw.deinit();
    sw.follow_(folder, test_stem, false);
    try testing.expectEqual(@as(usize, 1), ts.n);
    try testing.expectEqualStrings("run", ts.agents[0].id[0..ts.agents[0].len]);
    try testing.expectEqual(@as(u32, 1), ts.agents[0].texts);

    // The same folder for a transcript the tab started: all of them.
    var ts2: TestSink = .{};
    var sw2 = try Watcher.init(gpa, ts2.sink());
    defer sw2.deinit();
    sw2.follow_(folder, test_stem, true);
    try testing.expectEqual(@as(usize, 2), ts2.n);

    // No room: a new subagent is not read, and not asked again.
    var ts3: TestSink = .{ .room = 0 };
    var sw3 = try Watcher.init(gpa, ts3.sink());
    defer sw3.deinit();
    sw3.follow_(folder, test_stem, true);
    try testing.expectEqual(@as(usize, 0), ts3.n);
    ts3.room = 4;
    sw3.changed("agent-run.jsonl");
    try testing.expectEqual(@as(usize, 0), ts3.n);
}
