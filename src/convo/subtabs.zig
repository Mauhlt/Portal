//! A tab's subagent sub-tabs (docs/protocol.md section 3e): one read-only
//! Conversation view (model.zig) per subagent the tab's agent
//! session spawned, found and read by subagents.zig from the session's
//! `<session>\subagents\` folder, or announced by the agent's
//! SubagentStart / SubagentStop hooks (tabs.Tab.subagentEvent).
//!
//! Each sub-tab has a random 128-bit id of Portal's own (never the
//! subagent's id in the agent, which stays on the desktop), the
//! description its session gave it (scrubbed like conversation texts,
//! one line, at most 64 bytes) and whether it finished. A finished
//! sub-tab stays (read-only, marked done) until the tab's conversation
//! starts over (`/clear`, `/resume`: `clear`) or room is needed: at most
//! `wire.max_subs`, the oldest finished one goes first; with every one
//! still running, a new subagent gets no sub-tab.
//!
//! Locking: the caller holds the hub's mutex (tabs.Hub.mutex) for every
//! call, as for the tab's own conversation. `gen` changes whenever the
//! list (ids, names, done) changes.

const std = @import("std");
const Allocator = std.mem.Allocator;
const wire = @import("shared").subtabs;
const transcript = @import("transcript.zig");
const scrub = @import("scrub.zig");
const Convo = @import("model.zig").Convo;

pub const Id = wire.Id;
pub const max_subs = wire.max_subs;
/// Longest subagent id kept (the agent's are 17 characters).
pub const max_agent = 64;
pub const default_name = "Subagent";

/// `[A-Za-z0-9_-]{1,max_agent}`: the subagent ids Portal accepts (from
/// file names `agent-<id>.jsonl` and from hooks' `agent_id`).
pub fn validAgent(s: []const u8) bool {
    if (s.len == 0 or s.len > max_agent) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-') return false;
    return true;
}

pub const Sub = struct {
    id: Id,
    agent_buf: [max_agent]u8 = undefined,
    agent_len: u8 = 0,
    name_buf: [wire.max_name]u8 = undefined,
    name_len: u8 = 0,
    /// The description is known (meta file or hook), not the default.
    named: bool = false,
    done: bool = false,
    /// When it got its sub-tab (eviction order).
    seq: u64,
    convo: Convo,

    pub fn agent(s: *const Sub) []const u8 {
        return s.agent_buf[0..s.agent_len];
    }

    pub fn name(s: *const Sub) []const u8 {
        return s.name_buf[0..s.name_len];
    }
};

pub const SubTabs = struct {
    gpa: Allocator,
    /// Random ids.
    io: std.Io,
    /// How descriptions and texts are scrubbed (the tab's).
    ctx: scrub.Context,
    subs: [max_subs]*Sub = undefined,
    n: usize = 0,
    next_seq: u64 = 1,
    gen: u64 = 1,

    pub fn init(gpa: Allocator, io: std.Io, ctx: scrub.Context) SubTabs {
        return .{ .gpa = gpa, .io = io, .ctx = ctx };
    }

    pub fn deinit(st: *SubTabs) void {
        st.clear();
    }

    pub fn slice(st: *SubTabs) []*Sub {
        return st.subs[0..st.n];
    }

    pub fn find(st: *SubTabs, agent: []const u8) ?*Sub {
        for (st.subs[0..st.n]) |s| if (std.mem.eql(u8, s.agent(), agent)) return s;
        return null;
    }

    pub fn byId(st: *SubTabs, id: Id) ?*Sub {
        for (st.subs[0..st.n]) |s| if (std.mem.eql(u8, &s.id, &id)) return s;
        return null;
    }

    /// Every sub-tab goes (the tab's conversation starts over).
    pub fn clear(st: *SubTabs) void {
        if (st.n == 0) return;
        for (st.subs[0..st.n]) |s| st.free(s);
        st.n = 0;
        st.gen +%= 1;
    }

    fn free(st: *SubTabs, s: *Sub) void {
        s.convo.deinit();
        st.gpa.destroy(s);
    }

    /// The sub-tab of subagent `agent`, made if there is none (and room).
    /// `description` (raw, untrusted) names it once known; `done` marks it
    /// finished (never undone). Null: invalid id, no room, or no memory.
    pub fn upsert(st: *SubTabs, agent: []const u8, description: ?[]const u8, done: bool) ?*Sub {
        if (!validAgent(agent)) return null;
        const s = st.find(agent) orelse (st.open(agent) orelse return null);
        if (description) |d| if (!s.named) {
            st.setName(s, d);
            s.named = true;
            st.gen +%= 1;
        };
        if (done and !s.done) {
            s.done = true;
            st.gen +%= 1;
        }
        return s;
    }

    fn open(st: *SubTabs, agent: []const u8) ?*Sub {
        if (st.n == max_subs) {
            // The oldest finished one makes room.
            var oldest: ?usize = null;
            for (st.subs[0..st.n], 0..) |s, i| if (s.done and (oldest == null or s.seq < st.subs[oldest.?].seq)) {
                oldest = i;
            };
            const i = oldest orelse return null;
            st.free(st.subs[i]);
            std.mem.copyForwards(*Sub, st.subs[i .. st.n - 1], st.subs[i + 1 .. st.n]);
            st.n -= 1;
        }
        const s = st.gpa.create(Sub) catch return null;
        var id: Id = undefined;
        st.io.randomSecure(&id) catch st.io.random(&id);
        s.* = .{ .id = id, .seq = st.next_seq, .convo = Convo.init(st.gpa, st.ctx) };
        st.next_seq += 1;
        s.convo.sidechain = true;
        s.convo.reset(true);
        @memcpy(s.agent_buf[0..agent.len], agent);
        s.agent_len = @intCast(agent.len);
        @memcpy(s.name_buf[0..default_name.len], default_name);
        s.name_len = default_name.len;
        st.subs[st.n] = s;
        st.n += 1;
        st.gen +%= 1;
        return s;
    }

    fn setName(st: *SubTabs, s: *Sub, raw: []const u8) void {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(st.gpa);
        // Scrubbed whole, cut after (as model.zig's texts are): a name or
        // path cut first could slip past the scrubber in pieces. The
        // transcript keeps at most max_desc bytes; a description cut
        // there loses its last (maybe partial) word too.
        var src = raw;
        if (src.len >= transcript.max_desc) src = src[0 .. std.mem.lastIndexOfScalar(u8, src, ' ') orelse 0];
        scrub.scrub(st.gpa, st.ctx, src, &out) catch return;
        var nb: [wire.max_name]u8 = undefined;
        const n = wire.displayName(out.items, &nb);
        @memcpy(s.name_buf[0..n.len], n);
        s.name_len = @intCast(n.len);
    }

    /// One record of subagent `agent`'s transcript (ignored if it has no
    /// sub-tab).
    pub fn apply(st: *SubTabs, agent: []const u8, rec: *const transcript.Record) void {
        const s = st.find(agent) orelse return;
        s.convo.applyRecord(rec) catch {};
    }

    /// Subagent `agent`'s transcript is read again from its start.
    pub fn restart(st: *SubTabs, agent: []const u8) void {
        const s = st.find(agent) orelse return;
        s.convo.reset(true);
    }

    /// The list for viewers (bar order: as they appeared).
    pub fn entries(st: *SubTabs, tab: Id, out: *wire.List) void {
        out.tab = tab;
        out.len = st.n;
        for (st.subs[0..st.n], 0..) |s, i| {
            out.items[i] = .{ .id = s.id, .done = s.done };
            out.items[i].setName(s.name());
        }
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn userRec(rec: *transcript.Record, line: []const u8) !void {
    try testing.expect(transcript.parseLine(testing.allocator, line, true, rec));
}

test "sub-tabs: open, name (scrubbed), finish, records only from sidechains, room, clear" {
    var st = SubTabs.init(testing.allocator, testing.io, .{ .root = "C:\\code\\acme", .name = "acme", .user = "alice" });
    defer st.deinit();
    const g0 = st.gen;
    const a = st.upsert("a1b2", null, false).?;
    try testing.expectEqualStrings("Subagent", a.name());
    try testing.expect(st.gen != g0);
    try testing.expect(st.upsert("bad id!", null, false) == null);
    try testing.expect(st.upsert("", null, false) == null);
    // The description arrives (scrubbed: the user's name, other paths).
    _ = st.upsert("a1b2", "Check C:\\Users\\alice\\x.txt for\nalice", false).?;
    try testing.expectEqualStrings("Check [path] for [user]", a.name());
    // A later description does not rename it.
    _ = st.upsert("a1b2", "Other", false).?;
    try testing.expectEqualStrings("Check [path] for [user]", a.name());
    const g1 = st.gen;
    _ = st.upsert("a1b2", null, true).?;
    try testing.expect(a.done and st.gen != g1);
    const g2 = st.gen;
    _ = st.upsert("a1b2", null, true).?;
    try testing.expectEqual(g2, st.gen);

    // Only sidechain records reach a sub-tab's conversation.
    const rec = try testing.allocator.create(transcript.Record);
    defer testing.allocator.destroy(rec);
    const len0 = a.convo.len;
    try userRec(rec, "{\"type\":\"user\",\"isSidechain\":false,\"message\":{\"role\":\"user\",\"content\":\"main\"}}");
    st.apply("a1b2", rec);
    try testing.expectEqual(len0, a.convo.len);
    try userRec(rec, "{\"type\":\"user\",\"isSidechain\":true,\"agentId\":\"a1b2\",\"message\":{\"role\":\"user\",\"content\":\"Look in C:\\\\code\\\\acme\\\\src\"}}");
    st.apply("a1b2", rec);
    try testing.expectEqual(len0 + 1, a.convo.len);
    try testing.expectEqualStrings("Look in acme\\src", a.convo.slots[(a.convo.first + a.convo.len - 1) % a.convo.slots.len].text);

    // The list on the wire: Portal's id, the name, done.
    var l: wire.List = .{};
    st.entries(@splat(9), &l);
    try testing.expectEqual(@as(usize, 1), l.len);
    try testing.expectEqualSlices(u8, &a.id, &l.items[0].id);
    try testing.expect(l.items[0].done);
    try testing.expectEqual(a, st.byId(a.id).?);

    // Full: the oldest finished one goes; all running: no room.
    var nb: [8]u8 = undefined;
    for (1..max_subs) |i| _ = st.upsert(std.fmt.bufPrint(&nb, "r{d}", .{i}) catch unreachable, null, false).?;
    try testing.expectEqual(@as(usize, max_subs), st.n);
    const n = st.upsert("new1", null, false).?;
    try testing.expect(st.find("a1b2") == null);
    try testing.expectEqual(n, st.find("new1").?);
    try testing.expect(st.upsert("new2", null, false) == null);
    st.clear();
    try testing.expectEqual(@as(usize, 0), st.n);
}
