//! Project tabs (protocol v2, docs/tabs-design.md): several sessions in one
//! Portal, opened only at the desk (`portalctl open <dir>`), switched by
//! viewers with `s:<id>`, input going to the tab chosen, a tab's end
//! announced while the others go on, and the privacy rules:
//!   1. no paths in any text message (names are folders' basenames);
//!   3. unknown, malformed and closed ids all get the same `nosession`;
//!   *  nothing a viewer sends opens or closes a tab.
//!
//! Every tab runs `cd & choice /c YN & (if errorlevel 2 exit 7) & choice
//! /c 12 & exit 3`: it prints its folder (the grid is exempt from rule 1,
//! it is the session), waits for Y or N, exits with code 7 on N, else
//! waits for 1 or 2 and exits with code 3.

const std = @import("std");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;
const privacy = @import("privacy.zig");
const tabs_wire = @import("shared").tabs;

const child = [_][]const u8{ "--", "cmd.exe", "/c", "cd & choice /c YN & (if errorlevel 2 exit 7) & choice /c 12 & exit 3" };

fn hello(v: *client.Viewer) ?tabs_wire.List {
    return tabs_wire.parseList(v.helloText());
}

/// The latest tab list the viewer knows: the last `tabs`, else hello's.
fn latest(v: *client.Viewer) ?tabs_wire.List {
    if (v.lastText("\"t\":\"tabs\"")) |t| return tabs_wire.parseList(t);
    return hello(v);
}

fn byName(l: tabs_wire.List, name: []const u8) ?tabs_wire.Entry {
    for (l.slice()) |e| if (std.mem.eql(u8, e.name(), name)) return e;
    return null;
}

/// Switches to `id`, waits for the `session` answer and the new screen.
fn switchTo(v: *client.Viewer, id: tabs_wire.Id, needle: []const u8) bool {
    const n = v.countText("\"t\":\"session\"");
    const f = tabs_wire.subscribeFrame(id);
    v.send(&f);
    if (!v.waitText("\"t\":\"session\"", n + 1, 8000)) return false;
    const got = tabs_wire.idField(v.lastText("\"t\":\"session\"").?, "id") orelse return false;
    if (!std.mem.eql(u8, &got, &id)) return false;
    return v.waitFor(needle, 8000);
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("tabs");
    const alpha_dir = try h.dataDir("tabs\\alpha-proj");
    const beta_dir = try h.dataDir("tabs\\beta-proj");
    const inst = try proc.Instance.start(h, dir, port, &child);
    defer inst.kill();
    var leaks = try privacy.Leaks.standard(h, dir);
    defer leaks.deinit();
    try leaks.add(alpha_dir);
    try leaks.add(beta_dir);

    const creds = try client.pair(inst, "tabs");
    const sess = creds.sessionCookie();
    var dump: [4096]u8 = undefined;

    const v = try client.Viewer.open(inst, sess);
    defer v.deinit();
    const l0 = hello(v);
    _ = r.check("hello: protocol v2, one tab, the tab shown", std.mem.indexOf(u8, v.helloText(), "\"v\":2") != null and l0 != null and l0.?.len == 1 and
        tabs_wire.idField(v.helloText(), "session") != null, "{s}", .{v.helloText()});
    const first = l0.?.items[0];
    _ = r.check("the first tab waits for its answer", v.waitFor("[Y,N]?", 8000), "{s}", .{v.dump(&dump)});

    // Only the desk opens tabs: `portalctl open` through the data directory.
    const o1 = try inst.cli(&.{ "open", alpha_dir });
    _ = r.check("portalctl open <dir> opens a tab", o1.code == 0 and o1.has("opened"), "{d} {s}", .{ o1.code, o1.out });
    const o2 = try inst.cli(&.{ "open", beta_dir, "--name", "Beta" });
    _ = r.check("portalctl open <dir> --name NAME", o2.code == 0, "{d} {s}", .{ o2.code, o2.out });
    const o3 = try inst.cli(&.{ "open", "C:\\definitely\\not\\here" });
    _ = r.check("portalctl open refuses a missing folder", o3.code != 0, "{d} {s}", .{ o3.code, o3.out });

    const Three = struct {
        fn f(_: void, vv: *client.Viewer) bool {
            const l = latest(vv) orelse return false;
            return l.len == 3;
        }
    };
    _ = r.check("viewers are told: `tabs` lists three", v.pumpUntil(10_000, {}, Three.f), "{d} texts", .{v.texts.items.len});
    const l3 = latest(v) orelse return error.NoList;
    const alpha = byName(l3, "alpha-proj");
    const beta = byName(l3, "Beta");
    _ = r.check("tab names are the folder's name (or --name), never a path", alpha != null and beta != null, "{s}", .{v.lastText("\"tabs\"") orelse ""});
    _ = r.check("ids are 128-bit, distinct", alpha != null and beta != null and !std.mem.eql(u8, &alpha.?.id, &beta.?.id) and
        !std.mem.eql(u8, &alpha.?.id, &first.id), "", .{});
    _ = r.check("tab colours come from the name", alpha != null and alpha.?.color == tabs_wire.colorFromName("alpha-proj"), "", .{});
    if (alpha == null or beta == null) return;

    // Switching: the viewer sees the other tab's screen, input goes there.
    _ = r.check("s:<id> switches the screen (session answer, the other folder's output)", switchTo(v, alpha.?.id, "alpha-proj"), "{s}", .{v.dump(&dump)});
    _ = r.check("the switched-to tab's screen waits for its answer", v.waitFor("[Y,N]?", 8000), "{s}", .{v.dump(&dump)});
    v.send("k:y");
    _ = r.check("input goes to the tab shown", v.waitFor("[Y,N]?Y", 8000), "{s}", .{v.dump(&dump)});
    _ = r.check("switching back shows the first tab", switchTo(v, first.id, "[Y,N]?"), "{s}", .{v.dump(&dump)});
    v.pump(500);
    _ = r.check("...which did not get the other tab's input", v.g.find("[Y,N]?Y") == null, "{s}", .{v.dump(&dump)});

    // Probing: unknown, malformed and (below) closed ids are answered alike.
    var rnd: [16]u8 = undefined;
    h.io.random(&rnd);
    const unknown = tabs_wire.subscribeFrame(rnd);
    var answered: usize = 0;
    for ([_][]const u8{ &unknown, "s:..\\..\\Windows", "s:C:\\Users", "s:0" }) |probe| {
        const nos0 = v.countText("nosession");
        const texts0 = v.texts.items.len;
        v.send(probe);
        if (v.waitText("nosession", nos0 + 1, 8000) and v.texts.items.len == texts0 + 1 and
            std.mem.eql(u8, v.lastText("nosession").?, "{\"t\":\"nosession\"}")) answered += 1;
    }
    _ = r.check("unknown and malformed ids: `nosession`, nothing else", answered == 4, "{d} of 4", .{answered});
    // With no tab chosen, input goes nowhere.
    v.send("k:y");
    v.pump(800);
    _ = r.check("after an unknown id, input goes to no tab", v.g.find("[Y,N]?Y") == null, "{s}", .{v.dump(&dump)});
    _ = r.check("rejected ids are logged on the desktop", inst.logHas("asked for a session that is not open"), "", .{});

    // Nothing a viewer sends opens or closes a tab.
    for ([_][]const u8{ "o:C:\\Windows", "open:C:\\", "c:" ++ "x", "n:new", "x:close", "s:", "s:new", "s:*", "k:ctrl-w", "t:portalctl open C:\\" }) |f| v.send(f);
    v.pump(800);
    {
        const v2 = try client.Viewer.open(inst, sess);
        defer v2.deinit();
        const l = hello(v2);
        _ = r.check("no message from a device opens or closes a tab", l != null and l.?.len == 3, "{s}", .{v2.helloText()});
        _ = r.check("a second viewer's hello has no paths or names", leaks.find(v2.helloText()) == null, "{?s}", .{leaks.find(v2.helloText())});
    }

    // A tab's program ends while the others run: `ended`, a new list.
    _ = r.check("switch to Beta", switchTo(v, beta.?.id, "beta-proj"), "{s}", .{v.dump(&dump)});
    _ = v.waitFor("[Y,N]?", 8000);
    v.send("k:n");
    _ = r.check("a tab's end is announced: ended, with its code", v.waitText("\"t\":\"ended\"", 1, 10_000) and
        std.mem.indexOf(u8, v.lastText("\"ended\"").?, "\"code\":7") != null and
        std.mem.eql(u8, &tabs_wire.idField(v.lastText("\"ended\"").?, "id").?, &beta.?.id), "{s}", .{v.lastText("\"ended\"") orelse ""});
    const Two = struct {
        fn f(_: void, vv: *client.Viewer) bool {
            const l = latest(vv) orelse return false;
            return l.len == 2;
        }
    };
    _ = r.check("...and the tab leaves the list; the others go on", v.pumpUntil(5000, {}, Two.f) and inst.alive() and client.alive(inst), "", .{});

    // The closed tab's id gets exactly the answer an unknown one gets.
    const nos1 = v.countText("nosession");
    const closed = tabs_wire.subscribeFrame(beta.?.id);
    v.send(&closed);
    _ = r.check("a closed tab's id: the same `nosession` as an unknown one", v.waitText("nosession", nos1 + 1, 8000) and
        std.mem.eql(u8, v.lastText("nosession").?, "{\"t\":\"nosession\"}"), "{s}", .{v.lastText("nosession") orelse ""});

    // No text message carried a path, a user or a data-dir name.
    {
        var dirty: ?[]const u8 = null;
        for (v.texts.items) |t| if (leaks.find(t)) |n| {
            dirty = n;
        };
        _ = r.check("no tabs/session/ended message has a path or a name from the desktop", dirty == null and leaks.find(v.helloText()) == null, "{?s}", .{dirty});
    }

    // The last tabs end: the first (N, code 7), then alpha, the last one
    // (1, code 3): the existing exit path, with the last program's code.
    _ = r.check("back to the first tab", switchTo(v, first.id, "[Y,N]?"), "{s}", .{v.dump(&dump)});
    v.send("k:n");
    _ = r.check("the first tab ends too", v.waitText("\"t\":\"ended\"", 2, 10_000), "", .{});
    _ = r.check("one tab left", v.pumpUntil(5000, {}, struct {
        fn f(_: void, vv: *client.Viewer) bool {
            const l = latest(vv) orelse return false;
            return l.len == 1;
        }
    }.f), "", .{});
    _ = r.check("to the last tab", switchTo(v, alpha.?.id, "[1,2]?"), "{s}", .{v.dump(&dump)});
    v.send("k:1");
    const Exit = struct {
        fn f(_: void, vv: *client.Viewer) bool {
            return vv.got_exit;
        }
    };
    _ = r.check("the last tab's end is Portal's end: exit with its code", v.pumpUntil(10_000, {}, Exit.f) and
        v.lastText("\"exit\"") != null and std.mem.indexOf(u8, v.lastText("\"exit\"").?, "\"code\":3") != null, "{s}", .{v.lastText("\"exit\"") orelse ""});
    var gone = false;
    for (0..50) |_| {
        if (!inst.alive()) {
            gone = true;
            break;
        }
        @import("net.zig").sleep(100);
    }
    _ = r.check("Portal exits after the last tab", gone, "stop logged: {}", .{inst.logHas("stop:")});
    _ = gpa;
}
