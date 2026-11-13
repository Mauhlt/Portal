//! The optional system monitor (docs/protocol.md section 3d), with the
//! desk's "Show system monitor" turned on in settings.txt:
//!   * `activity` says so (`sysmon`: the System button shows);
//!   * a viewer that sends `y:on` gets `sys` samples, about once a second,
//!     numbers and tab ids only;
//!   * a viewer that never asked gets none;
//!   * `y:off` stops them (the sampler stops when no panel is open);
//!   * a viewer's connection closing counts as `y:off`.
//! The default (off) is covered by the privacy and convo groups: `y:on`
//! is ignored there and no `sys` message ever arrives.

const std = @import("std");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;
const privacy = @import("privacy.zig");
const pairing = @import("pairing.zig");
const shared = @import("shared");
const tabs_wire = shared.tabs;
const sysinfo = shared.sysinfo;

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("status");
    // The desk's setting, as its Settings panel saves it.
    const pdir = try std.fmt.allocPrint(gpa, "{s}\\Portal", .{dir});
    try std.Io.Dir.cwd().createDirPath(h.io, pdir);
    const sp = try std.fmt.allocPrint(gpa, "{s}\\settings.txt", .{pdir});
    try std.Io.Dir.cwd().writeFile(h.io, .{ .sub_path = sp, .data = "# e2e\r\nsystem_monitor = on\r\n" });

    const inst = try proc.Instance.start(h, dir, port, &pairing.ping_child);
    defer inst.kill();
    var leaks = try privacy.Leaks.standard(h, dir);
    defer leaks.deinit();

    const creds = try client.pair(inst, "status");
    const v = try client.Viewer.open(inst, creds.sessionCookie());
    defer v.deinit();
    const quiet = try client.Viewer.open(inst, creds.sessionCookie());
    defer quiet.deinit();
    const id = tabs_wire.idField(v.helloText(), "session") orelse {
        _ = r.check("hello names the tab shown", false, "{s}", .{v.helloText()});
        return;
    };
    _ = r.check("activity says the system monitor is on", v.waitText("\"t\":\"activity\"", 1, 8000) and
        std.mem.indexOf(u8, v.lastText("\"t\":\"activity\"") orelse "", "\"sysmon\":true") != null, "{?s}", .{v.lastText("\"t\":\"activity\"")});
    v.pump(1500);
    _ = r.check("no sys message before a System panel opens", v.countText("\"t\":\"sys\"") == 0, "{d}", .{v.countText("\"t\":\"sys\"")});

    // The System panel opens.
    v.send("y:on");
    const t0 = std.Io.Timestamp.now(h.io, .awake).toMilliseconds();
    const got = v.waitText("\"t\":\"sys\"", 3, 8000);
    const t1 = std.Io.Timestamp.now(h.io, .awake).toMilliseconds();
    _ = r.check("y:on: sys samples arrive, about once a second", got and t1 - t0 >= 1200, "{d} in {d} ms", .{ v.countText("\"t\":\"sys\""), t1 - t0 });
    var s: sysinfo.Snapshot = undefined;
    const last = v.lastText("\"t\":\"sys\"") orelse "";
    const ok = sysinfo.parse(last, &s);
    const tab = if (ok) s.find(id) else null;
    _ = r.check("a sample: machine CPU and memory, the tab's process tree (numbers only)", ok and s.cpu <= 1000 and s.mem_total > 0 and s.mem_used <= s.mem_total and
        tab != null and tab.?.procs >= 1 and tab.?.mem > 0, "{s}", .{last});
    var dirty: ?[]const u8 = null;
    for (v.texts.items) |t| if (std.mem.indexOf(u8, t, "\"t\":\"sys\"") != null) if (leaks.find(t)) |n| {
        dirty = n;
    };
    _ = r.check("sys carries no paths, names or process names", dirty == null and std.mem.indexOf(u8, last, "cmd") == null and std.mem.indexOf(u8, last, "ping") == null, "{?s} {s}", .{ dirty, last });
    _ = r.check("a viewer that did not ask gets no sys", quiet.countText("\"t\":\"sys\"") == 0, "{d}", .{quiet.countText("\"t\":\"sys\"")});

    // The panel closes: no more samples.
    v.send("y:off");
    v.pump(600); // one already on its way may still arrive
    const n = v.countText("\"t\":\"sys\"");
    v.pump(2500);
    _ = r.check("y:off: samples stop", v.countText("\"t\":\"sys\"") == n, "{d} -> {d}", .{ n, v.countText("\"t\":\"sys\"") });

    // Two panels: one closing leaves the other's samples running; the
    // viewer going away counts as closing.
    v.send("y:on");
    quiet.send("y:on");
    _ = r.check("two panels open: both get samples", v.waitText("\"t\":\"sys\"", n + 1, 5000) and quiet.waitText("\"t\":\"sys\"", 1, 5000), "", .{});
    v.send("y:off");
    const q = quiet.countText("\"t\":\"sys\"");
    _ = r.check("one closes: the other keeps getting them", quiet.waitText("\"t\":\"sys\"", q + 2, 5000), "{d}", .{quiet.countText("\"t\":\"sys\"")});
    _ = r.ok("portal still running", inst.alive() and client.alive(inst));
}
