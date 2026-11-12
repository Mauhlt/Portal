//! Energy: an idle server must not poll. One signed-in viewer stays
//! connected to an idle session for 60 s; Portal then logs how often its
//! connection supervisor, the viewer's writer and the pairing watcher woke
//! up meanwhile ("viewer disconnected ... wakeups while connected: ...").
//! The design target is no periodic wakeups at all; the checks allow the
//! few event-driven wakes that connecting and disconnecting cause.

const std = @import("std");
const net = @import("net.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;

/// Prints one line, then waits for a key: no output while idle.
const idle_child = [_][]const u8{ "--", "cmd.exe", "/c", "echo IDLE-READY & pause" };
pub const idle_ms = 60_000;

fn field(line: []const u8, key: []const u8) ?u32 {
    const i = std.mem.indexOf(u8, line, key) orelse return null;
    var j = i + key.len;
    const start = j;
    while (j < line.len and std.ascii.isDigit(line[j])) j += 1;
    return std.fmt.parseInt(u32, line[start..j], 10) catch null;
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const dir = try h.dataDir("idle");
    const inst = try proc.Instance.start(h, dir, port, &idle_child);
    defer inst.kill();
    const creds = try client.pair(inst, "idle");
    net.sleep(500); // let the pairing's own store changes settle
    {
        const v = try client.Viewer.open(inst, creds.sessionCookie());
        defer v.deinit();
        _ = r.check("idle session shows its banner", v.waitFor("IDLE-READY", 10_000), "", .{});
        std.debug.print("     (idling {d} s with one viewer connected...)\n", .{idle_ms / 1000});
        v.pump(idle_ms);
        _ = r.ok("viewer still connected after the idle period", !v.closed);
    }
    // The disconnect line is written when the server notices the close.
    var line_buf: [512]u8 = undefined;
    var line: []const u8 = "";
    const deadline = net.now() + 10_000;
    while (net.now() < deadline and line.len == 0) : (net.sleep(100)) {
        const text = inst.log() catch continue;
        defer h.gpa.free(text);
        const i = std.mem.lastIndexOf(u8, text, "viewer disconnected") orelse continue;
        const end = std.mem.indexOfScalarPos(u8, text, i, '\r') orelse text.len;
        const n = @min(end - i, line_buf.len);
        @memcpy(line_buf[0..n], text[i..][0..n]);
        line = line_buf[0..n];
    }
    const sup = field(line, "supervisor ") orelse 999;
    const wr = field(line, "writer ") orelse 999;
    const pw = field(line, "pairing watcher ") orelse 999;
    std.debug.print("     measured over {d} s idle: supervisor {d}, writer {d}, pairing watcher {d} wakeups\n", .{ idle_ms / 1000, sup, wr, pw });
    _ = r.check("wakeup counts are logged on disconnect", line.len > 0, "", .{});
    // A 500 ms tick would be ~120 here and a 5 s recheck ~12.
    _ = r.check("connection supervisor: no periodic wakeups while idle", sup <= 3, "{s}", .{line});
    _ = r.check("viewer writer: no periodic wakeups while idle", wr <= 6, "{s}", .{line});
    _ = r.check("pairing watcher: no wakeups while no window is open", pw <= 2, "{s}", .{line});
    _ = r.ok("portal still running", inst.alive());
}
