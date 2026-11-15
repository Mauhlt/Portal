//! Portal's one connection path, end to end: a desk (`portalctl run
//! --console`, its WireGuard tunnel on 127.0.0.1 UDP) and devices that
//! reach it only through their own in-process tunnels (link.zig; and the
//! headless `portalctl sync-device`, the code `portal connect` runs).
//!
//!   * pairing at the desk by key and check code (`portalctl pair`), the
//!     device list, the device's tunnel address as its identity;
//!   * the interactive WebSocket: hello, typed input and its echo;
//!   * a key the desk never approved gets nothing (no handshake);
//!   * reconnect: the desk restarts, the device's tunnel and viewer come
//!     back by themselves;
//!   * Forget from the device ("f:"): its record goes, both ways;
//!   * Unpair at the desk: a `logout`, then the key is no longer let in;
//!   * an unreadable device list fails closed: connections end without a
//!     `logout` (the device keeps its pairing) and nothing is let in until
//!     the list reads again;
//!   * sync over the bulk WebSocket (a signed 50 MiB package) while a
//!     viewer types: every keystroke's echo is timed and must stay fast;
//!   * only /ws and /ws/bulk exist; nothing Portal sends names a path.

const std = @import("std");
const net = @import("net.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const http = @import("http.zig");
const Runner = @import("runner.zig").Runner;
const Link = @import("link.zig").Link;
/// The product's device code (devicelink: the endpoint announcement).
const client_mod = @import("client");

/// Text input into a shell (the latency check types into it).
const run_args = [_][]const u8{ "--input", "text", "--allow-remote-shell", "--", "cmd.exe", "/q", "/k", "prompt READY$G" };

/// The headless device's credential-store slot (never the owner's key).
const key_slot = "e2e-tunnel";

fn has(hay: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, hay, needle) != null;
}

/// `portalctl sync-device <args>` as a separate device process (its own
/// LOCALAPPDATA/APPDATA under `dev`, its key in `key_slot`).
fn device(h: *proc.Harness, dev: []const u8, args: []const []const u8, ms: u32) !struct { code: ?u32, out: []const u8, cli: *proc.LiveCli } {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(h.gpa);
    try argv.append(h.gpa, "sync-device");
    try argv.appendSlice(h.gpa, args);
    const c = try proc.LiveCli.startEnv(h, dev, argv.items, &.{.{ .name = "PORTAL_DEVICE_KEY_SLOT", .value = key_slot }});
    const code = c.wait(ms);
    return .{ .code = code, .out = c.output(), .cli = c };
}

/// Types `token` (then Enter) and returns the ms until the viewer's grid
/// shows it, or null.
fn echoMs(v: *client.Viewer, token: []const u8) ?u64 {
    var msg: [64]u8 = undefined;
    const m = std.fmt.bufPrint(&msg, "t:{s}", .{token}) catch return null;
    const t0 = net.now();
    v.send(m);
    if (!v.waitFor(token, 10_000)) return null;
    const dt = net.now() - t0;
    v.send("k:enter");
    return dt;
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("tunnel");
    var inst = try proc.Instance.start(h, dir, port, &run_args);
    var killed = false;
    defer if (!killed) inst.kill();

    // ---------------------------------------------------------- pairing
    const laptop = inst.pair("laptop") catch |err| {
        _ = r.check("a device pairs at the desk by key and check code", false, "{t}", .{err});
        return err;
    };
    _ = r.ok("a device pairs at the desk by key and check code (portalctl pair)", true);
    {
        const d = try inst.cli(&.{"devices"});
        _ = r.check("`portalctl devices` lists it with its tunnel address and key", has(d.out, "laptop") and has(d.out, "10.8.0.2") and has(d.out, &laptop.key_text), "{s}", .{d.out});
    }

    // ------------------------------------------- interactive WebSocket
    var v = client.Viewer.open(inst, "laptop") catch |err| {
        _ = r.check("the device opens the interactive WebSocket through its tunnel", false, "{t}", .{err});
        return err;
    };
    _ = r.ok("the device opens the interactive WebSocket through its tunnel (hello + grid)", v.hello_first and v.g.frames > 0);
    _ = r.check("typed input reaches the session and its echo comes back", v.waitFor("READY>", 10_000) and echoMs(v, "zq1") != null, "", .{});
    {
        const log = inst.log() catch "";
        _ = r.check("Portal knows the device by its tunnel address (10.8.0.2)", has(log, "viewer connected from 10.8.0.2:"), "", .{});
    }
    {
        // Nothing but the two WebSockets answers, and nothing names a path.
        var resp = try http.request(gpa, laptop.port, .{ .path = "/", .host = inst.host, .tls = inst.tls });
        defer resp.deinit();
        var resp2 = try http.request(gpa, laptop.port, .{ .path = "/pair", .host = inst.host, .tls = inst.tls });
        defer resp2.deinit();
        _ = r.check("every other route is 404 (no pages, no sign-in, no static files)", resp.status == 404 and resp2.status == 404, "{d} {d}", .{ resp.status, resp2.status });
        _ = r.check("the hello names no path or data directory", !has(v.helloText(), dir) and !has(v.helloText(), ":\\"), "{s}", .{v.helloText()});
    }

    // ------------------------------------------------ an unknown key
    {
        const s = try inst.stranger(laptop);
        defer s.stop();
        const got = client.Viewer.open(inst, "stranger");
        const refused = if (got) |vv| blk: {
            vv.deinit();
            break :blk false;
        } else |_| true;
        _ = r.check("a key the desk never approved gets nothing (no handshake, no connection)", refused, "", .{});
    }

    // ------------------------------------------------ desk restart
    {
        v.deinit();
        inst.kill();
        const links = inst.links;
        inst = try proc.Instance.start(h, dir, port, &run_args);
        inst.links = links;
        inst.port = laptop.port;
        // The device's tunnel re-handshakes by itself (keepalive / new data).
        var back: ?*client.Viewer = null;
        const deadline = net.now() + 30_000;
        while (back == null and net.now() < deadline) : (net.sleep(500)) {
            back = client.Viewer.open(inst, "laptop") catch null;
        }
        _ = r.check("after the desk restarts, the device reconnects through the same tunnel", back != null, "", .{});
        v = back orelse return error.NoReconnect;
    }

    // ------------------------------------------------ sync over bulk
    const dev = try h.dataDir("tunnel-device");
    defer {
        const d = device(h, dev, &.{"--drop-key"}, 10_000) catch null;
        if (d) |x| x.cli.deinit();
    }
    var dev_code: []const u8 = "";
    {
        const k = try device(h, dev, &.{"--key"}, 15_000);
        defer k.cli.deinit();
        const at = std.mem.indexOf(u8, k.out, "key ") orelse 0;
        const key_text = if (at > 0 and k.out.len >= at + 4 + 44) k.out[at + 4 ..][0..44] else "";
        var eb: [32]u8 = undefined;
        const pc = try inst.liveCli(&.{ "pair", "box", key_text, "--endpoint", try std.fmt.bufPrint(&eb, "127.0.0.1:{d}", .{port}) });
        defer pc.deinit();
        _ = pc.waitFor("Pair it? [y/N]", 15_000);
        pc.answer("y\r\n");
        _ = pc.wait(15_000);
        const out = pc.output();
        const ci = std.mem.indexOf(u8, out, "portal-pair 2 ") orelse 0;
        const ce = std.mem.indexOfAnyPos(u8, out, ci, "\r\n") orelse out.len;
        dev_code = try gpa.dupe(u8, out[ci..ce]);
        _ = r.check("a second (headless) device pairs by its key", ci > 0 and key_text.len == 44, "{s}", .{out});
    }
    {
        // 50 MiB of data, published and subscribed for `box`.
        const src = try std.fmt.allocPrint(gpa, "{s}\\bulk-src", .{dir});
        try std.Io.Dir.cwd().createDirPath(h.io, src);
        const big = try gpa.alloc(u8, 50 << 20);
        defer gpa.free(big);
        for (big, 0..) |*b, i| b.* = @truncate((i *% 2654435761) >> 7);
        const fpath = try std.fmt.allocPrint(gpa, "{s}\\model.bin", .{src});
        try std.Io.Dir.cwd().writeFile(h.io, .{ .sub_path = fpath, .data = big });
        const p = try inst.cli(&.{ "publish", "stt-model", src, "--kind", "data", "--version", "1.0" });
        _ = r.check("the desk publishes a signed 50 MiB package", p.code == 0, "{s}", .{p.out});
        const s = try inst.cli(&.{ "sync", "subscribe", "box", "stt-model" });
        _ = r.check("...for the headless device", s.code == 0, "{s}", .{s.out});
    }
    {
        // Baseline keystroke echo, then the same while the download runs.
        var base: u64 = 0;
        for (0..5) |i| {
            var tb: [16]u8 = undefined;
            base = @max(base, echoMs(v, std.fmt.bufPrint(&tb, "b{d}x", .{i}) catch "b") orelse 99_999);
        }
        var argv = [_][]const u8{ "sync-device", "--pairing-code", dev_code, "--approve" };
        const dl = try proc.LiveCli.startEnv(h, dev, &argv, &.{.{ .name = "PORTAL_DEVICE_KEY_SLOT", .value = key_slot }});
        defer dl.deinit();
        var worst: u64 = 0;
        var samples: usize = 0;
        var during: usize = 0;
        const t_end = net.now() + 120_000;
        while (net.now() < t_end) {
            var tb: [16]u8 = undefined;
            const ms = echoMs(v, std.fmt.bufPrint(&tb, "d{d}x", .{samples}) catch "d") orelse 99_999;
            samples += 1;
            if (dl.wait(0) == null) {
                during += 1;
                worst = @max(worst, ms);
            } else break;
            net.sleep(50);
        }
        const code = dl.wait(120_000);
        std.debug.print("     keystroke echo: worst {d} ms idle, worst {d} ms during the 50 MiB bulk download ({d} samples during it)\n", .{ base, worst, during });
        _ = r.check("the headless device syncs the 50 MiB package over the bulk WebSocket", code == 0 and has(dl.output(), "1 installed"), "code={?d} {s}", .{ code, dl.output() });
        _ = r.check("keystrokes were measured while the download ran", during > 0, "{d}", .{during});
        _ = r.check("keystroke echo stays fast during the bulk download (< 250 ms)", worst < 250, "worst {d} ms (idle {d} ms)", .{ worst, base });
    }

    // ------------------------------------------------ Forget (device side)
    {
        _ = try inst.pair("phone");
        const pv = try client.Viewer.open(inst, "phone");
        defer pv.deinit();
        pv.send("f:");
        const said = pv.pumpUntil(10_000, {}, struct {
            fn f(_: void, vv: *client.Viewer) bool {
                return vv.lastText("\"forgotten\"") != null or vv.closed;
            }
        }.f);
        _ = r.check("a device that forgets the desktop is told {\"t\":\"forgotten\"}", said and pv.lastText("\"forgotten\"") != null, "", .{});
        var gone = false;
        const deadline = net.now() + 10_000;
        while (!gone and net.now() < deadline) : (net.sleep(200)) {
            const d = inst.cli(&.{"devices"}) catch continue;
            gone = !has(d.out, "phone");
        }
        _ = r.check("...and the desk no longer lists it (mutual Forget)", gone, "", .{});
    }

    // ------------------------------------------------ Unpair at the desk
    {
        const u = try inst.cli(&.{ "unpair", "laptop" });
        _ = r.check("`portalctl unpair` removes the device", u.code == 0, "{s}", .{u.out});
        _ = r.check("its open viewer gets {\"t\":\"logout\",\"reason\":\"unpaired\"}", v.waitLogout(15_000) and v.logout_reason == .unpaired, "", .{});
        v.deinit();
        net.sleep(1000);
        const again = client.Viewer.open(inst, "laptop");
        const refused = if (again) |vv| blk: {
            vv.deinit();
            break :blk false;
        } else |_| true;
        _ = r.check("...and its key is no longer let into the tunnel", refused, "", .{});
    }

    // ------------------------------------- an unreadable device list
    {
        _ = try inst.pair("tablet");
        const tv = try client.Viewer.open(inst, "tablet");
        defer tv.deinit();
        const io = h.io;
        const store = try std.fmt.allocPrint(h.gpa, "{s}\\Portal\\devices.txt", .{inst.data_dir});
        const tmp = try std.fmt.allocPrint(h.gpa, "{s}\\Portal\\devices.e2e-tmp", .{inst.data_dir});
        const good = try std.Io.Dir.cwd().readFileAlloc(io, store, h.gpa, .limited(64 * 1024));
        // Replaced by rename, as every store write is (the watch sees it).
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = tmp, .data = "not a device list\n" });
        try std.Io.Dir.cwd().rename(tmp, std.Io.Dir.cwd(), store, io);
        const ended = tv.waitClose(15_000);
        _ = r.check("an unreadable device list ends the connection, without a logout", ended and !tv.got_logout, "closed {}, logout {}", .{ ended, tv.got_logout });
        const in_meanwhile = if (client.Viewer.open(inst, "tablet")) |vv| blk: {
            vv.deinit();
            break :blk true;
        } else |_| false;
        _ = r.check("...and nothing is let in while it is unreadable", !in_meanwhile, "", .{});
        _ = r.check("...and the desk logs why", inst.logHas("device store unreadable"), "", .{});
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = tmp, .data = good });
        try std.Io.Dir.cwd().rename(tmp, std.Io.Dir.cwd(), store, io);
        var back = false;
        const deadline = net.now() + 15_000;
        while (!back and net.now() < deadline) : (net.sleep(300)) {
            if (client.Viewer.open(inst, "tablet")) |vv| {
                vv.deinit();
                back = true;
            } else |_| {}
        }
        _ = r.check("once it reads again the same pairing gets in (nothing to pair again)", back, "", .{});
    }
    try movePort(r, inst, port);
    _ = r.ok("portal still running", inst.alive());
    inst.kill();
    killed = true;
    try busyPort(h, r, port);
}

/// The desk moves its tunnel port with a device connected; the device
/// follows the announcement and reconnects. Before that, a device tries
/// every endpoint-like frame: the desk ignores them (only the desk can
/// move the desk). Loopback ports only (the group's block: port + 1).
fn movePort(r: *Runner, inst: *proc.Instance, port: u16) !void {
    const link = try inst.pair("mover");
    const v = try client.Viewer.open(inst, "mover");
    defer v.deinit();
    _ = v.waitFor("READY>", 10_000);

    // A device can't move the desk.
    for ([_][]const u8{
        "{\"t\":\"endpoint\",\"endpoint\":\"127.0.0.1:1\",\"seq\":99999999999}",
        "m:99999999999",
        "m:127.0.0.1:1",
        "e:127.0.0.1:1",
    }) |f| v.send(f);
    _ = r.check("endpoint-like frames from a device are ignored: the desk keeps its port and the session works", echoMs(v, "mv0") != null and !inst.logHas("now listening on UDP") and !inst.logHas("saved the announced endpoint"), "", .{});

    // The desk moves (its own console command; the window's Settings does
    // the same after its confirmation).
    const new_port = port + 1;
    var pb: [8]u8 = undefined;
    var eb: [32]u8 = undefined;
    const cli = try inst.liveCli(&.{ "tunnel-port", try std.fmt.bufPrint(&pb, "{d}", .{new_port}), "--endpoint", try std.fmt.bufPrint(&eb, "127.0.0.1:{d}", .{new_port}), "--router-forwarded" });
    defer cli.deinit();
    const told = v.waitFor("\"t\":\"endpoint\"", 15_000) or v.lastText("\"t\":\"endpoint\"") != null;
    const msg = v.lastText("\"t\":\"endpoint\"") orelse "";
    _ = r.check("the connected device is told the new endpoint with a sequence number", told and has(msg, "\"seq\":"), "{s}", .{msg});
    // The device: validated, the code's endpoint (only) replaced, acked,
    // then its tunnel follows (what devicelink.Follower does).
    const m = client_mod.devicelink.parseEndpointMessage(msg) orelse return error.BadAnnouncement;
    const moved = switch (client_mod.devicelink.acceptMove(&link.code, &m)) {
        .moved => |c| c,
        else => return error.AnnouncementRefused,
    };
    _ = r.check("the announcement changes only the endpoint (same keys and address)", std.mem.eql(u8, &moved.desk_key, &link.code.desk_key) and std.mem.eql(u8, &moved.device_ip, &link.code.device_ip), "", .{});
    var ab: [24]u8 = undefined;
    v.send(@import("shared").frames.movedFrame(m.seq, &ab));
    v.pump(client_mod.devicelink.Follower.switch_delay_ms);
    link.code = moved;
    try link.tun.setPeers(&.{client_mod.devicelink.deskPeer(&link.code)});
    const code = cli.wait(20_000);
    _ = r.check("`portalctl tunnel-port` moves the running desk's tunnel", code == 0 and has(cli.output(), "now listens on UDP"), "code={?d} {s}", .{ code, cli.output() });
    _ = r.check("the desk saw the device's acknowledgement before moving", inst.logHas("saved the announced endpoint"), "", .{});
    var lb: [64]u8 = undefined;
    _ = r.check("the desk listens on the new port, keys and peers unchanged", inst.logHas(try std.fmt.bufPrint(&lb, "now listening on UDP {d}", .{new_port})), "", .{});
    // A replay of the same, or an older, announcement changes nothing.
    _ = r.check("a replayed announcement is refused by the device", client_mod.devicelink.acceptMove(&link.code, &m) == .same and
        client_mod.devicelink.acceptMove(&link.code, &.{ .seq = m.seq - 1, .endpoint_buf = m.endpoint_buf, .endpoint_len = m.endpoint_len }) == .stale, "", .{});
    // The device reaches the desk at the new endpoint: the open viewer
    // keeps working, or a new one connects.
    var ok = echoMs(v, "mv1") != null;
    if (!ok) {
        const deadline = net.now() + 30_000;
        while (!ok and net.now() < deadline) : (net.sleep(500)) {
            const nv = client.Viewer.open(inst, "mover") catch continue;
            nv.deinit();
            ok = true;
        }
    }
    _ = r.check("the device follows to the new port and reconnects (no pairing again)", ok, "", .{});
    inst.udp_port = new_port;
}

/// The tunnel's UDP port is taken at start: Portal says so plainly (the
/// port, the program holding it) and keeps running; moving the port then
/// binds it.
fn busyPort(h: *proc.Harness, r: *Runner, port: u16) !void {
    const busy = port + 2;
    // Another program holding it (here: a second tunnel in this process).
    var hk = client_mod.tunnel.keys.KeyPair.generate(h.io);
    defer hk.wipe();
    const holder = try client_mod.tunnel.Tunnel.start(h.gpa, h.io, .{ .private_key = hk.private, .address = .{ 10, 9, 0, 1 }, .udp_port = busy, .loopback_only = true });
    defer holder.destroy();
    const dir = try h.dataDir("tunnel-busy");
    const inst = try proc.Instance.start(h, dir, busy, &run_args);
    defer inst.kill();
    var mb: [64]u8 = undefined;
    _ = r.check("a taken tunnel port is reported plainly with the program holding it", inst.logHas(try std.fmt.bufPrint(&mb, "UDP port {d} is already in use by ", .{busy})) and inst.logHas("Tunnel UDP port"), "", .{});
    _ = r.check("...and Portal keeps running for local sessions", inst.alive(), "", .{});
    var pb: [8]u8 = undefined;
    const c = try inst.cli(&.{ "tunnel-port", try std.fmt.bufPrint(&pb, "{d}", .{port + 3}), "--router-forwarded" });
    _ = r.check("choosing another port binds the tunnel without a restart", c.code == 0 and inst.logHas("now listening on UDP"), "{s}", .{c.out});
}
