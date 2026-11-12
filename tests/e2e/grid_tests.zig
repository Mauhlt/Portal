//! Protocol v1 stream: hello, grid snapshots and diffs against changing
//! output, reconnect snapshots, and mixed/legacy input in keys mode
//! (ported from grid_smoke.py; token login replaced by pairing).

const std = @import("std");
const net = @import("net.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const pairing = @import("pairing.zig");
const Runner = @import("runner.zig").Runner;

const get = client.get;

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const dir = try h.dataDir("grid");
    const inst = try proc.Instance.start(h, dir, port, &pairing.ping_child);
    defer inst.kill();
    const creds = try client.pair(inst, "laptop");
    const sess = creds.sessionCookie();

    {
        var resp = try get(inst, "/", sess);
        defer resp.deinit();
        _ = r.check("viewer page served, no xterm", resp.status == 200 and !resp.bodyContains("xterm"), "{d}", .{resp.status});
        var js = try get(inst, "/static/app.js", sess);
        defer js.deinit();
        _ = r.check("app.js served as javascript", js.status == 200 and std.mem.startsWith(u8, js.header("content-type") orelse "", "text/javascript"), "{d}", .{js.status});
        var css = try get(inst, "/static/app.css", null);
        defer css.deinit();
        _ = r.check("app.css served", css.status == 200, "{d}", .{css.status});
        var x = try get(inst, "/static/xterm.js", sess);
        defer x.deinit();
        _ = r.check("xterm.js no longer served", x.status == 404, "{d}", .{x.status});
    }

    var dump_buf: [4096]u8 = undefined;
    const v = try client.Viewer.open(inst, sess);
    defer v.deinit();
    _ = r.ok("websocket upgrade", true);
    _ = r.check("hello is the first message and says keys", v.hello_first and std.mem.indexOf(u8, v.helloText(), "\"input\":\"keys\"") != null, "{s}", .{v.helloText()});
    _ = r.check("first grid frame is a full snapshot", v.first_full, "", .{});
    _ = r.check("grid size is sane", v.g.cols >= 20 and v.g.rows >= 5, "{d}x{d}", .{ v.g.cols, v.g.rows });

    _ = r.check("program output visible in grid", v.waitFor("PORTAL-SMOKE-TEST", 8000), "{s}", .{v.dump(&dump_buf)});
    _ = r.check("ping output visible in grid", v.waitFor("Reply from 127.0.0.1", 8000), "{s}", .{v.dump(&dump_buf)});

    // Changing output arrives as diff frames carrying only changed rows.
    const replies0 = v.g.count("Reply from");
    const diffs0 = v.g.diff_frames;
    v.pump(3000);
    const replies1 = v.g.count("Reply from");
    _ = r.check("grid follows changing output", replies1 > replies0, "{d} -> {d}", .{ replies0, replies1 });
    _ = r.check("later frames are diffs (changed rows only)", v.g.diff_frames > diffs0, "diffs {d} -> {d}, full {d}", .{ diffs0, v.g.diff_frames, v.g.full_frames });
    _ = r.check("every frame so far decoded strictly", v.bad == null, "{?t}", .{v.bad});

    // Snapshot of a second viewer == first viewer's snapshot + diffs.
    {
        var same = false;
        var why_buf: [512]u8 = undefined;
        var why: []const u8 = "never quiet";
        var attempts: usize = 0;
        while (attempts < 5 and !same) : (attempts += 1) {
            // ping prints once a second: catch the quiet gap.
            _ = v.settle(250, 3000);
            const v2 = try client.Viewer.open(inst, sess);
            defer v2.deinit();
            const before = v.g.frames;
            v.pump(150);
            if (v.g.frames == before and v2.g.frames == 1) {
                same = v.g.sameAs(&v2.g);
                why = v.g.diffReason(&v2.g, &why_buf);
            }
        }
        _ = r.check("snapshot + diffs == fresh snapshot (byte-identical runs)", same, "{d} attempts; {s}", .{ attempts, why });
    }

    // Legacy raw input, disallowed keys and junk are all dropped in keys
    // mode. k:ctrl-c reaching the child would stop ping and end the session.
    const legacy = [_][]const u8{
        "i1",     "r",         "k:up",       "k:ctrl-c", "t:hello",     "k:\x1b[A", "k:1",
        "k:esc",  "k:esc",     "",           "x",        "z:foo",       "k:",       "k:ENTER",
        "k:9999", "k:ctrl-c ", "t:\x03\x03", "k:tab",    "k:backspace",
    };
    for (legacy) |m| v.send(m);
    v.send("k:ctrl-c");
    v.c.send(.binary, "garbage\x00\xff") catch {};
    const replies2 = v.g.count("Reply from");
    v.pump(3000);
    _ = r.check("ctrl-c and junk dropped: child keeps running", !v.got_exit and !v.closed and v.g.count("Reply from") > replies2, "exit={} closed={} {d}->{d}", .{ v.got_exit, v.closed, replies2, v.g.count("Reply from") });
    _ = r.check("server alive after mixed input", client.alive(inst), "", .{});
    _ = r.check("no decode errors after mixed input", v.bad == null, "{?t}", .{v.bad});

    // Reconnect gets a fresh full snapshot (no replay of history).
    {
        v.c.sock.close();
        const v3 = try client.Viewer.open(inst, sess);
        defer v3.deinit();
        _ = r.check("reconnect: hello then a full snapshot", v3.hello_first and v3.first_full and v3.g.find("Reply from") != null, "{s}", .{v3.dump(&dump_buf)});
        // Two viewers at once.
        const v4 = try client.Viewer.open(inst, sess);
        defer v4.deinit();
        _ = r.check("second simultaneous viewer gets a full snapshot", v4.first_full, "", .{});
        _ = r.ok("viewer connections logged", inst.logHas("viewer connected"));
    }
    _ = r.ok("portal still running at end of group", inst.alive() and client.alive(inst));
}
