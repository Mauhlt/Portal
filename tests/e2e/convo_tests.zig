//! The Conversation view (docs/protocol.md section 3b): a fake session
//! program (fake_agent.zig) writes a synthetic transcript under the
//! harness's own transcript folder (PORTAL_AGENT_PROJECTS, never the
//! user's), and a viewer must receive it as `convo` / `convo+` items:
//!   * prompts and replies as text, scrubbed of paths and the user's name
//!     (the project folder reads as the tab's name);
//!   * tool use as one-liners, never arguments, results or thinking;
//!   * a question with its options as answer keys, answered with `k:<key>`
//!     (no new input power), then closed;
//!   * a permission prompt (OSC 7501) as Yes/No, answered with `k:1`;
//!   * a tab without a transcript says so (`on`:false);
//!   * snapshots on switching tabs, scoped to the tab watched;
//!   * nothing in any text message leaks a path or a name (privacy rule 1).

const std = @import("std");
const w = @import("win.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;
const privacy = @import("privacy.zig");
const shared = @import("shared");
const tabs_wire = shared.tabs;
const wire = shared.convo;

const Item = struct {
    n: u32,
    kind: wire.Kind,
    text: []u8,
    open: bool,
    /// "label=key;label=key"
    options: []u8,
};

/// The conversation of tab `id` as the viewer has it: every `convo` /
/// `convo+` message for it applied in order.
const Conv = struct {
    gpa: std.mem.Allocator,
    items: std.ArrayList(Item) = .empty,
    on: bool = false,
    snapshots: usize = 0,
    appends: usize = 0,
    bad: usize = 0,

    fn deinit(c: *Conv) void {
        c.clear();
        c.items.deinit(c.gpa);
    }

    fn clear(c: *Conv) void {
        for (c.items.items) |it| {
            c.gpa.free(it.text);
            c.gpa.free(it.options);
        }
        c.items.clearRetainingCapacity();
    }

    fn build(gpa: std.mem.Allocator, v: *const client.Viewer, id: tabs_wire.Id) !Conv {
        var c: Conv = .{ .gpa = gpa };
        errdefer c.deinit();
        for (v.texts.items) |t| {
            if (std.mem.indexOf(u8, t, "\"t\":\"convo") == null) continue;
            const buf = try gpa.alloc(u8, t.len);
            defer gpa.free(buf);
            const scratch = try gpa.create(wire.Scratch);
            defer gpa.destroy(scratch);
            scratch.* = .{ .text = buf };
            const m = wire.parse(t, scratch) orelse {
                c.bad += 1;
                continue;
            };
            if (!std.mem.eql(u8, &m.id, &id)) continue;
            if (m.snapshot) {
                c.clear();
                c.on = m.on;
                c.snapshots += 1;
            } else c.appends += 1;
            for (m.items) |it| try c.put(it);
        }
        return c;
    }

    fn put(c: *Conv, it: wire.Item) !void {
        var opts: std.ArrayList(u8) = .empty;
        defer opts.deinit(c.gpa);
        for (it.options, 0..) |o, i| {
            if (i > 0) try opts.append(c.gpa, ';');
            try opts.print(c.gpa, "{s}={s}", .{ o.label, o.key });
        }
        const new: Item = .{ .n = it.n, .kind = it.kind, .text = try c.gpa.dupe(u8, it.text), .open = it.open, .options = try opts.toOwnedSlice(c.gpa) };
        for (c.items.items) |*old| if (old.n == it.n) {
            c.gpa.free(old.text);
            c.gpa.free(old.options);
            old.* = new;
            return;
        };
        try c.items.append(c.gpa, new);
    }

    fn find(c: *const Conv, kind: wire.Kind, text: []const u8) ?Item {
        for (c.items.items) |it| if (it.kind == kind and std.mem.eql(u8, it.text, text)) return it;
        return null;
    }

    fn has(c: *const Conv, kind: wire.Kind, text: []const u8) bool {
        return c.find(kind, text) != null;
    }

    fn dump(c: *const Conv, buf: []u8) []const u8 {
        var wr: std.Io.Writer = .fixed(buf);
        wr.print("on={} snaps={d} items:", .{ c.on, c.snapshots }) catch {};
        for (c.items.items) |it| wr.print(" [{d} {s}{s} '{s}' {s}]", .{ it.n, @tagName(it.kind), if (it.open) " open" else "", it.text, it.options }) catch {};
        return wr.buffered();
    }
};

const Want = struct { gpa: std.mem.Allocator, id: tabs_wire.Id, kind: wire.Kind, text: []const u8, open: ?bool = null };

/// Pumps until the tab's conversation has the item.
fn waitItem(v: *client.Viewer, want: Want, ms: u32) bool {
    return v.pumpUntil(ms, want, struct {
        fn f(wt: Want, vv: *client.Viewer) bool {
            var c = Conv.build(wt.gpa, vv, wt.id) catch return false;
            defer c.deinit();
            const it = c.find(wt.kind, wt.text) orelse return false;
            return if (wt.open) |o| it.open == o else true;
        }
    }.f);
}

fn selfExe(gpa: std.mem.Allocator) ![]u8 {
    var buf: [1024]u16 = undefined;
    const n = w.GetModuleFileNameW(null, &buf, buf.len);
    if (n == 0 or n >= buf.len) return error.NoSelf;
    return std.unicode.utf16LeToUtf8Alloc(gpa, buf[0..n]);
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("convo");
    const proj = try h.dataDir("convo\\convo-acme");
    const quiet = try h.dataDir("convo\\quiet-proj");
    const self = try selfExe(gpa);
    const args = [_][]const u8{ "--cwd", proj, "--", self, "--fake-agent" };
    const inst = try proc.Instance.start(h, dir, port, &args);
    defer inst.kill();

    var leaks = try privacy.Leaks.standard(h, dir);
    defer leaks.deinit();
    try leaks.add(proj);
    var tb: [1024]u8 = undefined;
    try leaks.add(h.transcriptRoot(&tb));
    try leaks.add("agent-projects");
    // Never sent at all, scrubbed or not.
    const secrets = [_][]const u8{ "THINKING-SECRET", "ARG-SECRET", "RESULT-SECRET", "injected", "not JSON", "system-reminder", ".jsonl", "e2e00000" };

    const creds = try client.pair(inst, "convo");
    const v = try client.Viewer.open(inst, creds.sessionCookie());
    defer v.deinit();
    var dump: [8192]u8 = undefined;
    var cdump: [8192]u8 = undefined;
    const id = tabs_wire.idField(v.helloText(), "session") orelse {
        _ = r.check("hello names the tab shown", false, "{s}", .{v.helloText()});
        return;
    };
    _ = r.check("a convo snapshot follows hello for the tab shown", v.waitText("\"t\":\"convo\"", 1, 8000), "{d} texts", .{v.texts.items.len});
    _ = r.check("the fake program asks its question", v.waitFor("FAKE-ASKED", 15_000), "{s}", .{v.dump(&dump)});

    // The turn, scrubbed: the project folder reads as the tab's name.
    const user_name = h.env.get("USERNAME") orelse "";
    const prompt = if (user_name.len >= 2) "Please fix the build in convo-acme\\src and tell [user]" else "Please fix the build in convo-acme\\src and tell nobody";
    const got_q = waitItem(v, .{ .gpa = gpa, .id = id, .kind = .question, .text = "Which fix should I apply in convo-acme?", .open = true }, 10_000);
    {
        var c = try Conv.build(gpa, v, id);
        defer c.deinit();
        _ = r.check("convo is on (a transcript is followed) and every message parses", c.on and c.bad == 0, "{s}", .{c.dump(&cdump)});
        _ = r.check("the owner's prompt, scrubbed of paths and the user name", c.has(.user, prompt), "{s}", .{c.dump(&cdump)});
        _ = r.check("the reply as text, other paths removed", c.has(.assistant, "I will look at convo-acme\\build.zig and [path]"), "{s}", .{c.dump(&cdump)});
        _ = r.check("edits as one line: Edited 2 files", c.has(.tool, "Edited 2 files"), "{s}", .{c.dump(&cdump)});
        _ = r.check("a command as one line: Ran a command", c.has(.tool, "Ran a command"), "{s}", .{c.dump(&cdump)});
        const q = c.find(.question, "Which fix should I apply in convo-acme?");
        _ = r.check("the question, open, its options as answer keys", got_q and q != null and q.?.open and
            std.mem.eql(u8, q.?.options, "Alpha=1;Beta in [path]=2"), "{s}", .{c.dump(&cdump)});
        var n_user: usize = 0;
        for (c.items.items) |it| n_user += @intFromBool(it.kind == .user);
        _ = r.check("injected context is not a prompt; only the typed one is", n_user == 1, "{s}", .{c.dump(&cdump)});
    }

    // Answering uses the ordinary answer keys.
    v.send("k:2");
    _ = r.check("k:2 answers the question (the program got 2)", v.waitFor("FAKE-GOT-2", 8000), "{s}", .{v.dump(&dump)});
    const closed = waitItem(v, .{ .gpa = gpa, .id = id, .kind = .question, .text = "Which fix should I apply in convo-acme?", .open = false }, 8000);
    const reply = waitItem(v, .{ .gpa = gpa, .id = id, .kind = .assistant, .text = "You chose Beta." }, 8000);
    {
        var c = try Conv.build(gpa, v, id);
        defer c.deinit();
        _ = r.check("the answered question closes; the reply follows (as convo+ appends)", closed and reply and c.appends > 0, "{s}", .{c.dump(&cdump)});
    }

    // A permission prompt, known only from the program's OSC 7501 state.
    _ = r.check("the fake program asks for permission", v.waitFor("FAKE-PERMISSION", 8000), "{s}", .{v.dump(&dump)});
    const perm = "Claude wants to run a command. Allow it?";
    const got_perm = waitItem(v, .{ .gpa = gpa, .id = id, .kind = .question, .text = perm, .open = true }, 8000);
    {
        var c = try Conv.build(gpa, v, id);
        defer c.deinit();
        const p = c.find(.question, perm);
        _ = r.check("a permission prompt becomes a question: Yes = 1, No = esc", got_perm and p != null and std.mem.eql(u8, p.?.options, "Yes=1;No=esc"), "{s}", .{c.dump(&cdump)});
    }
    v.send("k:1");
    _ = r.check("k:1 allows it (the program got 1)", v.waitFor("FAKE-ALLOWED", 8000), "{s}", .{v.dump(&dump)});
    _ = r.check("the permission question closes", waitItem(v, .{ .gpa = gpa, .id = id, .kind = .question, .text = perm, .open = false }, 8000), "", .{});
    _ = r.check("the closing reply arrives", waitItem(v, .{ .gpa = gpa, .id = id, .kind = .assistant, .text = "All done." }, 8000), "", .{});

    // A tab without a transcript says so; switching sends that tab's
    // snapshot, and switching back the whole conversation again.
    const o = try inst.cli(&.{ "open", quiet });
    _ = r.check("portalctl open a second tab", o.code == 0, "{d} {s}", .{ o.code, o.out });
    const Listed = struct {
        fn quietId(vv: *const client.Viewer) ?tabs_wire.Id {
            const t = vv.lastText("\"t\":\"tabs\"") orelse return null;
            const l = tabs_wire.parseList(t) orelse return null;
            for (l.slice()) |e| if (std.mem.eql(u8, e.name(), "quiet-proj")) return e.id;
            return null;
        }
        fn f(_: void, vv: *client.Viewer) bool {
            return quietId(vv) != null;
        }
    };
    _ = v.pumpUntil(8000, {}, Listed.f);
    const quiet_id = Listed.quietId(v);
    if (quiet_id) |qid| {
        const before = v.countText("\"t\":\"convo\"");
        const f = tabs_wire.subscribeFrame(qid);
        v.send(&f);
        _ = v.waitFor("FAKE-QUIET", 8000);
        _ = v.waitText("\"t\":\"convo\"", before + 1, 8000);
        var c = try Conv.build(gpa, v, qid);
        defer c.deinit();
        _ = r.check("a tab without a transcript: on=false and a status saying so", !c.on and c.snapshots >= 1 and c.items.items.len == 1 and c.items.items[0].kind == .status, "{s}", .{c.dump(&cdump)});
        const back = tabs_wire.subscribeFrame(id);
        const before2 = v.countText("\"t\":\"convo\"");
        v.send(&back);
        _ = v.waitText("\"t\":\"convo\"", before2 + 1, 8000);
        var c2 = try Conv.build(gpa, v, id);
        defer c2.deinit();
        _ = r.check("switching back sends the whole conversation again", c2.on and c2.has(.assistant, "All done.") and c2.has(.user, prompt), "{s}", .{c2.dump(&cdump)});
    } else _ = r.check("the second tab is listed", false, "{?s}", .{v.lastText("\"t\":\"tabs\"")});

    // Nothing Portal sent as text carries a path, a name or a secret.
    {
        var dirty: ?[]const u8 = null;
        var where: []const u8 = "";
        for (v.texts.items) |t| {
            if (leaks.find(t)) |n| {
                dirty = n;
                where = t;
            }
            for (secrets) |s| if (client.containsIgnoreCase(t, s)) {
                dirty = s;
                where = t;
            };
            if (user_name.len >= 4 and std.mem.indexOf(u8, t, "\"t\":\"convo") != null and client.containsIgnoreCase(t, user_name)) {
                dirty = "the user name";
                where = t;
            }
        }
        _ = r.check("no convo message carries a path, the user name, tool arguments, results or thinking", dirty == null, "{?s} in {s}", .{ dirty, where[0..@min(where.len, 600)] });
    }
    _ = r.ok("portal still running", inst.alive() and client.alive(inst));
}
