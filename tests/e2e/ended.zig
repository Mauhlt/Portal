//! The session program exits: every viewer (two raw WebSocket viewers and
//! the native client's own stream code) receives {"t":"exit","code":N}
//! before the closing handshake; Portal stays up until the viewers have
//! closed their end (bounded), then exits with the program's code; the
//! native client then shows the ended session, and once nothing listens,
//! "Desktop offline".
//!
//! The program is `choice.exe /c YN` answered with Y (exit code 1), as in
//! the demo where the laptop never learned the session had ended.

const std = @import("std");
const net = @import("net.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;
const native = @import("client");
const nc = native.net_client;

const ended_child = [_][]const u8{ "--input", "keys", "--", "choice.exe", "/c", "YN" };

const Native = struct {
    shared: nc.Shared = .{},
    c: nc.Client = undefined,
    result: nc.Client.StreamResult = .gone,
    done: std.Io.Event = .unset,

    fn stream(n: *Native) void {
        var backoff: i64 = 1000;
        n.result = n.c.runStream(&backoff);
        n.done.set(n.c.io);
    }

    fn status(n: *Native) nc.Status {
        n.shared.mutex.lockUncancelable(n.c.io);
        defer n.shared.mutex.unlock(n.c.io);
        return n.shared.status;
    }

    fn waitStatus(n: *Native, want: nc.Status, ms: u64) bool {
        const deadline = net.now() + ms;
        while (net.now() < deadline) : (net.sleep(20)) if (n.status() == want) return true;
        return false;
    }
};

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const dir = try h.dataDir("ended");
    const inst = try proc.Instance.start(h, dir, port, &ended_child);
    defer inst.kill();
    const creds = try client.pair(inst, "laptop");
    const sess = creds.sessionCookie();

    var dump_buf: [4096]u8 = undefined;
    const v1 = try client.Viewer.open(inst, sess);
    var v1_open = true;
    defer if (v1_open) v1.deinit();
    const v2 = try client.Viewer.open(inst, sess);
    var v2_open = true;
    defer if (v2_open) v2.deinit();
    _ = r.check("choice prompt visible", v1.waitFor("[Y,N]?", 8000), "{s}", .{v1.dump(&dump_buf)});

    // The native client's stream, against the same Portal.
    const n = try h.gpa.create(Native);
    defer h.gpa.destroy(n);
    n.* = .{};
    // Its own tunnel (the laptop's link) and the CA pinned from the export.
    var ca_buf: [native.x509check_mod.max_cert_len]u8 = undefined;
    const pem = try std.fmt.allocPrint(h.gpa, "{s}\\portal-ca.pem", .{inst.ca_dir});
    const der = try native.pin.readCaFile(h.io, pem, &ca_buf);
    n.c = try nc.Client.init(h.gpa, h.io, &n.shared, inst.host, inst.link("laptop").?.tun.dialer(), .{ .pinned = der });
    n.c.quiet = true;
    var task = try h.io.concurrent(Native.stream, .{n});
    defer task.cancel(h.io);
    _ = r.check("native client connected", n.waitStatus(.connected, 10_000), "{t}", .{n.status()});

    // Answer Y: choice exits with code 1, which ends the session.
    v1.send("k:y");
    _ = r.check("viewer 1 receives the exit notice with the code", v1.waitExit(10_000) and v1.exit_code == 1, "exit={} code={?d} closed={}", .{ v1.got_exit, v1.exit_code, v1.closed });
    _ = r.check("viewer 2 receives the exit notice with the code", v2.waitExit(5_000) and v2.exit_code == 1, "exit={} code={?d} closed={}", .{ v2.got_exit, v2.exit_code, v2.closed });
    _ = r.check("exit notice comes before the close frame", v1.exit_before_close and v2.exit_before_close, "", .{});
    // While these viewers have not closed their end, Portal waits for them
    // (bounded) instead of exiting under an exit notice in flight.
    _ = r.check("Portal waits for viewers to close before exiting", inst.alive(), "", .{});
    _ = r.check("closing handshake follows (1000)", v1.waitClose(3_000) and v1.close_payload[0] == 0x03 and v1.close_payload[1] == 0xe8, "closed={} {x}", .{ v1.closed, v1.close_payload });

    // The native client got it too and says so.
    const got_native = blk: {
        const deadline = net.now() + 5_000;
        while (net.now() < deadline) : (net.sleep(20)) if (n.done.isSet()) break :blk true;
        break :blk false;
    };
    _ = r.check("native client stream ends with the exit code", got_native and n.result == .exited and n.result.exited == 1, "done={} {s}", .{ got_native, @tagName(std.meta.activeTag(n.result)) });
    if (got_native) {
        var backoff: i64 = 10;
        n.c.streamEnded(n.result, &backoff);
        _ = r.check("native client shows the ended session", n.status() == .session_ended and
            std.mem.eql(u8, n.shared.detail(), "Session ended on the desktop (exit code 1)"), "{t}: {s}", .{ n.status(), n.shared.detail() });
    }

    // The viewers close their end: Portal exits at once (event-driven),
    // with the program's exit code.
    const t0 = net.now();
    v1.deinit();
    v1_open = false;
    v2.deinit();
    v2_open = false;
    const code = inst.waitExit(10_000);
    const took = net.now() - t0;
    _ = r.check("Portal exits with the program's code", code != null and code.? == 1, "{?d}", .{code});
    _ = r.check("Portal exits promptly once the viewers closed", took < 1_400, "{d} ms", .{took});
    _ = r.ok("exit logged", inst.logHas("stop: child exited with code 1"));

    // Nothing listens any more: the native client's next attempt says
    // "Desktop offline" and keeps the ended session's code. Only once the
    // first stream has returned: two streams on one client would share its
    // watchdog and events.
    if (!got_native) {
        _ = r.ok("native client: desktop offline after Portal exited", false);
    } else {
        var backoff: i64 = 10;
        const r2 = n.c.runStream(&backoff);
        const unreachable_ = r2 == .unreachable_err;
        n.c.streamEnded(r2, &backoff);
        _ = r.check("native client: desktop offline after Portal exited", unreachable_ and n.status() == .desktop_offline and
            std.mem.eql(u8, n.shared.detail(), nc.offline_text) and n.shared.exit_code == 1, "{s} {t}: {s}", .{ @tagName(std.meta.activeTag(r2)), n.status(), n.shared.detail() });
    }
}
