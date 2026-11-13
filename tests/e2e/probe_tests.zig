//! OSC 7501 feature detection (docs/protocol.md, "Program status (OSC
//! 7501)"): the fake session program (fake_agent.zig, in a folder named
//! "probe-...") sends the query the agent sends, `ESC ] 7501 ; ? BEL`,
//! followed by a DA1 request as its sentinel, and must read:
//!   * Portal's fixed reply, `ESC ] 7501 ; ? BEL`, exactly, once, through
//!     ConPTY (which drops an OSC in its input: Portal types it as
//!     win32-input-mode key records);
//!   * nothing else from Portal unasked (conhost's own DA reply aside).
//! Which reply came first is printed, not checked: conhost answers DA1
//! itself, at once, so under ConPTY the DA reply always wins, and the agent
//! (which stops at its sentinel) still takes OSC 7501 as unsupported.
//! Then the program reports `state=blocked:kind=permission`, and the tab is
//! waiting (instruct mode lets Up through). A device can't make Portal
//! answer for it, nor send the sequence itself: `l:` with the probe is
//! rejected (ControlCharacter), and the program's input stays as it was.

const std = @import("std");
const w = @import("win.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;

const reply = "\x1b]7501;?\x07";

fn readInput(h: *proc.Harness, folder: []const u8, buf: []u8) []const u8 {
    const path = std.fs.path.join(h.gpa, &.{ folder, "e2e-input" }) catch return "";
    defer h.gpa.free(path);
    return std.Io.Dir.cwd().readFile(h.io, path, buf) catch "";
}

fn selfExe(gpa: std.mem.Allocator) ![]u8 {
    var buf: [1024]u16 = undefined;
    const n = w.GetModuleFileNameW(null, &buf, buf.len);
    if (n == 0 or n >= buf.len) return error.NoSelf;
    return std.unicode.utf16LeToUtf8Alloc(gpa, buf[0..n]);
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("probe");
    const proj = try h.dataDir("probe\\probe-proj");
    const self = try selfExe(gpa);
    const bin = try h.dataDir("probe\\bin");
    const agent_exe = try std.fmt.allocPrint(gpa, "{s}\\claude.exe", .{bin});
    try std.Io.Dir.cwd().copyFile(self, std.Io.Dir.cwd(), agent_exe, h.io, .{});
    const args = [_][]const u8{ "--cwd", proj, "--", agent_exe, "--fake-agent" };
    const inst = try proc.Instance.start(h, dir, port, &args);
    defer inst.kill();

    const creds = try client.pair(inst, "probe");
    const v = try client.Viewer.open(inst, creds.sessionCookie());
    defer v.deinit();
    var dump: [8192]u8 = undefined;
    var ib: [512]u8 = undefined;

    const replied = v.waitFor("FAKE-PROBE-REPLY", 15_000);
    _ = r.check("the program's OSC 7501 query is answered", replied, "{s}", .{v.dump(&dump)});
    std.debug.print("    (first reply the program read: {s})\n", .{if (v.waitFor("FAKE-PROBE-DA-FIRST", 1)) "conhost's DA reply" else "Portal's OSC 7501 reply"});
    _ = r.check("the program reports a permission wait", v.waitFor("FAKE-PROBE-BLOCKED", 8000), "{s}", .{v.dump(&dump)});

    // Settle: anything else Portal or conhost would write arrives now.
    h.io.sleep(.fromMilliseconds(1000), .awake) catch {};
    var base_buf: [512]u8 = undefined;
    const base_in = readInput(h, proj, &ib);
    const base = base_buf[0..base_in.len];
    @memcpy(base, base_in);
    // conhost's DA1 reply (`ESC [ ? ... c`) may come first; then exactly the reply.
    const da_end = if (std.mem.startsWith(u8, base, "\x1b[?")) (std.mem.indexOfScalar(u8, base, 'c') orelse base.len - 1) + 1 else 0;
    _ = r.check("the program read exactly ESC ] 7501 ; ? BEL, once (besides conhost's DA reply)", std.mem.eql(u8, base[da_end..], reply), "{x}", .{base});

    // A device can neither send the probe's reply nor make Portal send one.
    const rej0 = v.countText("\"t\":\"rejected\"");
    v.send("l:\x1b]7501;?\x07");
    _ = r.check("a device's line holding the sequence is rejected (ControlCharacter)", v.waitText("\"t\":\"rejected\"", rej0 + 1, 8000) and
        std.mem.indexOf(u8, v.lastText("\"t\":\"rejected\"") orelse "", "ControlCharacter") != null, "{?s}", .{v.lastText("\"t\":\"rejected\"")});
    v.send("k:\x1b]7501;?\x07");
    h.io.sleep(.fromMilliseconds(800), .awake) catch {};
    const after = readInput(h, proj, &ib);
    _ = r.check("nothing a device sent reached the program", std.mem.eql(u8, after, base), "{x} (was {x})", .{ after, base });

    // The wait the program reported counts: instruct lets Up through.
    v.send("k:up");
    _ = r.check("the tab is waiting: instruct lets k:up through", v.waitFor("FAKE-UP-PROBE", 8000), "{s}", .{v.dump(&dump)});
}
