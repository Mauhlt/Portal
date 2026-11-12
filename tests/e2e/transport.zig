//! Transport hardening (ported from fix-web/smoke.py and stuck.py, adapted
//! to pairing and protocol v1): Host/Origin checks, strict HTTP framing,
//! split and pipelined heads, head/idle timeouts, slowloris, connection
//! slot eviction, WebSocket handshake and frame validation, ping/close,
//! logout of open viewers, and the stuck-viewer send watchdog.
//!
//! The slow checks (10 s head timeout, slowloris, 60 s keep-alive idle,
//! 30 s send watchdog) run as background probes while the fast checks run,
//! so the group takes about as long as the longest probe.

const std = @import("std");
const net = @import("net.zig");
const http = @import("http.zig");
const ws = @import("ws.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const pairing = @import("pairing.zig");
const Runner = @import("runner.zig").Runner;
const Allocator = std.mem.Allocator;
const rep = client.rep;

const heavy_child = [_][]const u8{ "--", "cmd.exe", "/c", "for /L %i in (1,1,2000000000) do @echo HEAVY-OUTPUT-LINE-%i" };

// ---------------------------------------------------------------- probes

const Probe = struct {
    name: []const u8,
    ok: bool = false,
    detail_buf: [512]u8 = undefined,
    detail_len: usize = 0,
    thread: ?std.Thread = null,

    fn set(p: *Probe, ok: bool, comptime fmt: []const u8, args: anytype) void {
        p.ok = ok;
        const s: []const u8 = std.fmt.bufPrint(&p.detail_buf, fmt, args) catch &p.detail_buf;
        p.detail_len = s.len;
    }

    fn start(p: *Probe, comptime f: anytype, args: anytype) void {
        p.thread = std.Thread.spawn(.{}, f, .{p} ++ args) catch {
            p.set(false, "could not start probe thread", .{});
            return;
        };
    }

    fn finish(p: *Probe, r: *Runner) void {
        if (p.thread) |t| t.join();
        p.thread = null;
        _ = r.check(p.name, p.ok, "{s}", .{p.detail_buf[0..p.detail_len]});
    }
};

/// A connection that sends nothing is closed by the head timeout (10 s).
fn probeIdleHead(p: *Probe, port: u16) void {
    var s = net.Socket.connect(port, .{}) catch |e| return p.set(false, "connect: {t}", .{e});
    defer s.close();
    const t0 = net.now();
    const d = s.recvUntilClose(std.heap.smp_allocator, 1, 20_000) catch |e| return p.set(false, "recv: {t}", .{e});
    const dt = net.now() - t0;
    p.set(d.closed and d.data.len == 0 and dt >= 8000 and dt <= 13_000, "closed={} bytes={d} after {d} ms", .{ d.closed, d.data.len, dt });
}

/// Dribbling a head one header every 0.5 s does not extend the deadline.
fn probeSlowloris(p: *Probe, port: u16, host: []const u8) void {
    var s = net.Socket.connect(port, .{}) catch |e| return p.set(false, "connect: {t}", .{e});
    defer s.close();
    const t0 = net.now();
    var buf: [256]u8 = undefined;
    const first = std.fmt.bufPrint(&buf, "GET / HTTP/1.1\r\nHost: {s}\r\n", .{host}) catch unreachable;
    s.sendAll(first) catch {};
    var closed = false;
    var i: usize = 0;
    while (i < 50 and !closed) : (i += 1) {
        net.sleep(500);
        s.sendAll("X-a: b\r\n") catch {
            closed = true;
            break;
        };
        var tmp: [64]u8 = undefined;
        const n = s.recvSome(&tmp, 1) catch |e| switch (e) {
            error.Timeout => continue,
            else => {
                closed = true;
                break;
            },
        };
        if (n == 0) closed = true;
    }
    const dt = net.now() - t0;
    p.set(closed and dt <= 13_000, "closed={} after {d} ms", .{ closed, dt });
}

/// After a response, a keep-alive connection waits at most 60 s for the
/// next request.
fn probeKeepAliveIdle(p: *Probe, port: u16, host: []const u8) void {
    const gpa = std.heap.smp_allocator;
    var s = net.Socket.connect(port, .{}) catch |e| return p.set(false, "connect: {t}", .{e});
    defer s.close();
    var buf: [256]u8 = undefined;
    const req = std.fmt.bufPrint(&buf, "GET /pair HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host}) catch unreachable;
    s.sendAll(req) catch |e| return p.set(false, "send: {t}", .{e});
    var resp = http.readResponse(gpa, &s, 10_000) catch |e| return p.set(false, "response: {t}", .{e});
    const keep = std.mem.eql(u8, resp.header("connection") orelse "", "keep-alive");
    resp.deinit();
    const t0 = net.now();
    const d = s.recvUntilClose(gpa, 1, 75_000) catch |e| return p.set(false, "recv: {t}", .{e});
    const dt = net.now() - t0;
    p.set(keep and d.closed and d.data.len == 0 and dt >= 55_000 and dt <= 67_000, "keep-alive={} closed={} after {d} ms", .{ keep, d.closed, dt });
}

/// A viewer that never reads (tiny receive buffer) under heavy output: its
/// blocked send must be cancelled by the 30 s watchdog.
fn probeStuckViewer(p: *Probe, inst: *proc.Instance, session: []const u8) void {
    const gpa = std.heap.smp_allocator;
    var c = ws.Client.connect(gpa, inst.port, .{ .host = inst.host, .origin = inst.origin, .cookie = session, .rcvbuf = 4096 }) catch |e|
        return p.set(false, "connect: {t}", .{e});
    defer c.close();
    if (c.status != 101) return p.set(false, "status {d}", .{c.status});
    const t0 = net.now();
    var found = false;
    while (net.now() - t0 < 60_000) {
        net.sleep(1000);
        if (inst.logHas("cancelled: timed out")) {
            found = true;
            break;
        }
    }
    const dt = net.now() - t0;
    net.sleep(500);
    const logged = inst.logHas("viewer disconnected");
    p.set(found and dt >= 25_000 and dt < 50_000 and logged, "watchdog fired={} after {d} ms, disconnect logged={}", .{ found, dt, logged });
}

/// A viewer that pauses 12 s (server send blocks, but < 30 s) then drains:
/// it must stay connected and every frame must decode.
fn probeSlowViewer(p: *Probe, inst: *proc.Instance, session: []const u8) void {
    const v = client.Viewer.open(inst, session) catch |e| return p.set(false, "open: {t}", .{e});
    defer v.deinit();
    net.sleep(12_000);
    const before = v.g.frames;
    v.pump(6000);
    const got = v.g.frames - before;
    p.set(!v.closed and v.bad == null and got > 10 and v.g.find("HEAVY-OUTPUT-LINE") != null, "closed={} bad={?t} frames after pause={d}", .{ v.closed, v.bad, got });
}

// ---------------------------------------------------------------- helpers

fn statusOf(gpa: Allocator, inst: *proc.Instance, req: http.Request) u16 {
    var resp = http.request(gpa, inst.port, req) catch return 0;
    defer resp.deinit();
    return resp.status;
}

fn wsStatus(gpa: Allocator, inst: *proc.Instance, o: ws.ConnectOptions) u16 {
    var c = ws.Client.connect(gpa, inst.port, o) catch return 0;
    defer c.close();
    return c.status;
}

/// Sends `frame` on a fresh viewer; the server must answer with close 1002
/// and end the connection.
fn badFrame(r: *Runner, inst: *proc.Instance, session: []const u8, name: []const u8, frame: []const u8) void {
    const v = client.Viewer.open(inst, session) catch |e| {
        _ = r.check(name, false, "open: {t}", .{e});
        return;
    };
    defer v.deinit();
    v.c.sendRaw(frame) catch {};
    const closed = v.waitClose(5000);
    const code = std.mem.readInt(u16, &v.close_payload, .big);
    _ = r.check(name, closed and code == 1002, "closed={} code={d}", .{ closed, code });
}

fn frameBytes(gpa: Allocator, first: u8, second: u8, ext: []const u8, payload: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(gpa, first);
    try out.append(gpa, second);
    try out.appendSlice(gpa, ext);
    if (second & 0x80 != 0) try out.appendSlice(gpa, &.{ 0, 0, 0, 0 }); // zero mask key
    try out.appendSlice(gpa, payload);
    return out.toOwnedSlice(gpa);
}

// ------------------------------------------------------------------- run

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir1 = try h.dataDir("transport");
    const dir2 = try h.dataDir("transport-heavy");
    const inst = try proc.Instance.start(h, dir1, port, &pairing.ping_child);
    defer inst.kill();
    const heavy = try proc.Instance.start(h, dir2, port + 1, &heavy_child);
    defer heavy.kill();
    const host = inst.host;
    const origin = inst.origin;

    const hc = try client.pair(heavy, "laptop");
    var probes = [_]Probe{
        .{ .name = "idle connection dropped by the 10 s head timeout" },
        .{ .name = "slowloris head dropped within ~10 s" },
        .{ .name = "idle keep-alive connection closed after ~60 s" },
        .{ .name = "stuck viewer cancelled by the 30 s send watchdog" },
        .{ .name = "slow viewer (12 s pause) stays connected, frames intact" },
    };
    probes[0].start(probeIdleHead, .{port});
    probes[1].start(probeSlowloris, .{ port, host });
    probes[2].start(probeKeepAliveIdle, .{ port, host });
    probes[3].start(probeStuckViewer, .{ heavy, hc.sessionCookie() });
    probes[4].start(probeSlowViewer, .{ heavy, hc.sessionCookie() });
    defer for (&probes) |*p| if (p.thread) |t| t.join();

    const creds = try client.pair(inst, "laptop");
    const sess = creds.sessionCookie();

    // ------------------------------------------------ Host, routes, headers
    _ = r.check("wrong Host rejected (DNS rebinding)", statusOf(gpa, inst, .{ .host = "evil.example:8420" }) == 421, "", .{});
    _ = r.check("missing Host rejected", statusOf(gpa, inst, .{ .host = null }) == 421, "", .{});
    {
        var hb: [32]u8 = undefined;
        const other = try std.fmt.bufPrint(&hb, "127.0.0.1:{d}", .{port + 1000});
        _ = r.check("Host with another port rejected", statusOf(gpa, inst, .{ .host = other }) == 421, "", .{});
        _ = r.check("Host 'localhost' rejected (only the listen address)", statusOf(gpa, inst, .{ .host = "localhost" }) == 421, "", .{});
    }
    {
        var resp = try client.get(inst, "/pair", null);
        defer resp.deinit();
        const csp = resp.header("content-security-policy") orelse "";
        _ = r.check("pair page: CSP with frame-ancestors 'none'", std.mem.indexOf(u8, csp, "frame-ancestors 'none'") != null and std.mem.indexOf(u8, csp, "default-src 'none'") != null, "{s}", .{csp});
        _ = r.ok("pair page: nosniff, DENY, no-referrer, no-store", std.mem.eql(u8, resp.header("x-content-type-options") orelse "", "nosniff") and
            std.mem.eql(u8, resp.header("x-frame-options") orelse "", "DENY") and
            std.mem.eql(u8, resp.header("referrer-policy") orelse "", "no-referrer") and
            std.mem.eql(u8, resp.header("cache-control") orelse "", "no-store"));
    }
    {
        var resp = try client.get(inst, "/login", null);
        defer resp.deinit();
        _ = r.check("legacy /login redirects to /pair", resp.status == 303 and std.mem.eql(u8, resp.location(), "/pair"), "{d}", .{resp.status});
    }
    _ = r.check("unknown path 404", statusOf(gpa, inst, .{ .path = "/etc/passwd", .host = host, .cookie = sess }) == 404, "", .{});
    _ = r.check("path traversal 404", statusOf(gpa, inst, .{ .path = "/static/../src/main.zig", .host = host, .cookie = sess }) == 404, "", .{});
    _ = r.check("PUT rejected 405", statusOf(gpa, inst, .{ .method = "PUT", .path = "/", .host = host, .cookie = sess }) == 405, "", .{});
    _ = r.check("POST to an unknown path 404", statusOf(gpa, inst, .{ .method = "POST", .path = "/nope", .host = host, .origin = origin, .body = "" }) == 404, "", .{});
    _ = r.check("POST with Origin 'null' rejected", statusOf(gpa, inst, .{ .method = "POST", .path = "/pair", .host = host, .origin = "null", .body = "" }) == 403, "", .{});
    _ = r.check("POST with https Origin rejected (scheme must match)", statusOf(gpa, inst, .{ .method = "POST", .path = "/pair", .host = host, .origin = "https://127.0.0.1", .body = "" }) == 403, "", .{});

    // ---------------------------------------------- WebSocket handshake
    const wsopt: ws.ConnectOptions = .{ .host = host, .origin = origin, .cookie = sess };
    {
        var o = wsopt;
        o.origin = "http://evil.example";
        _ = r.check("websocket with foreign Origin rejected (CSWSH)", wsStatus(gpa, inst, o) == 403, "", .{});
        o.origin = null;
        _ = r.check("websocket without Origin rejected", wsStatus(gpa, inst, o) == 403, "", .{});
        o = wsopt;
        o.cookie = null;
        _ = r.check("websocket without session rejected", wsStatus(gpa, inst, o) == 401, "", .{});
        o.cookie = "portal_session=" ++ &rep(43, 'A');
        _ = r.check("websocket with forged session rejected", wsStatus(gpa, inst, o) == 401, "", .{});
        o.cookie = creds.deviceCookie();
        _ = r.check("websocket with only a device cookie rejected", wsStatus(gpa, inst, o) == 401, "", .{});
        o = wsopt;
        o.version = "8";
        _ = r.check("websocket version 8 rejected", wsStatus(gpa, inst, o) == 400, "", .{});
        o = wsopt;
        o.key = "short";
        _ = r.check("websocket bad key rejected", wsStatus(gpa, inst, o) == 400, "", .{});
        o.key = "!!!!!!!!!!!!!!!!!!!!!!==";
        _ = r.check("websocket non-base64 key rejected", wsStatus(gpa, inst, o) == 400, "", .{});
        o = wsopt;
        o.upgrade_headers = false;
        _ = r.check("websocket without Upgrade/Connection rejected", wsStatus(gpa, inst, o) == 400, "", .{});
    }

    // ------------------------------------------------- WebSocket frames
    {
        const v = try client.Viewer.open(inst, sess);
        defer v.deinit();
        _ = r.check("websocket with session upgrades (hello + snapshot)", v.hello_first and v.first_full, "", .{});
        _ = r.ok("ping answered with pong (same payload)", v.ping("hey", 5000));
        // A ping split into single bytes.
        {
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(gpa);
            try v.c.encode(&out, 9, "split", .{});
            const before = v.pongs;
            for (out.items) |b| {
                v.c.sendRaw(&.{b}) catch {};
                net.sleep(20);
            }
            _ = r.ok("frame split byte-by-byte still parsed", v.pumpUntil(5000, before, struct {
                fn f(b: usize, vv: *client.Viewer) bool {
                    return vv.pongs > b;
                }
            }.f));
        }
        v.c.send(.pong, "unsolicited") catch {};
        v.c.send(.text, "") catch {};
        v.c.send(.binary, "\x00\x01") catch {};
        {
            var big: [4097]u8 = undefined;
            @memcpy(big[0..2], "t:");
            @memset(big[2..], 'a');
            v.c.send(.text, &big) catch {};
        }
        _ = r.ok("pong, empty, binary and max-size (4097) frames tolerated", v.ping("still", 5000) and !v.closed);
        _ = r.check("no decode errors", v.bad == null, "{?t}", .{v.bad});
    }
    {
        // A frame pipelined in the same write as the handshake.
        const ping = "\x89\x84\x00\x00\x00\x00pipe";
        var o = wsopt;
        o.trailing = ping;
        var c = try ws.Client.connect(gpa, inst.port, o);
        defer c.close();
        var got = false;
        const deadline = net.now() + 5000;
        while (!got and net.now() < deadline) {
            const f = c.next(1000) catch break;
            if (f.op == .pong and std.mem.eql(u8, f.payload, "pipe")) got = true;
        }
        _ = r.check("frame sent with the handshake (leftover bytes) answered", c.status == 101 and got, "status={d}", .{c.status});
    }
    {
        const v = try client.Viewer.open(inst, sess);
        defer v.deinit();
        v.c.send(.close, &.{ 0x03, 0xe8 }) catch {};
        const closed = v.waitClose(5000);
        _ = r.check("close frame echoed with status 1000", closed and std.mem.readInt(u16, &v.close_payload, .big) == 1000, "closed={} code={d}", .{ closed, std.mem.readInt(u16, &v.close_payload, .big) });
        _ = r.ok("connection ends after close", v.c.waitClosed(3000));
    }
    {
        const cases = [_]struct { name: []const u8, b0: u8, b1: u8, ext: []const u8, payload: []const u8 }{
            .{ .name = "unmasked client frame -> close 1002", .b0 = 0x81, .b1 = 0x03, .ext = "", .payload = "k:1" },
            .{ .name = "fragmented frame (FIN=0) -> close 1002", .b0 = 0x01, .b1 = 0x83, .ext = "", .payload = "k:1" },
            .{ .name = "continuation frame -> close 1002", .b0 = 0x80, .b1 = 0x83, .ext = "", .payload = "k:1" },
            .{ .name = "RSV1 bit set -> close 1002", .b0 = 0xC1, .b1 = 0x83, .ext = "", .payload = "k:1" },
            .{ .name = "reserved opcode 3 -> close 1002", .b0 = 0x83, .b1 = 0x83, .ext = "", .payload = "k:1" },
            .{ .name = "control frame over 125 bytes -> close 1002", .b0 = 0x89, .b1 = 0x80 | 126, .ext = "\x00\x7e", .payload = "" },
            .{ .name = "4098-byte message -> close 1002", .b0 = 0x81, .b1 = 0x80 | 126, .ext = "\x10\x02", .payload = "" },
            .{ .name = "2^63-byte length -> close 1002", .b0 = 0x82, .b1 = 0x80 | 127, .ext = "\x7f\xff\xff\xff\xff\xff\xff\xff", .payload = "" },
        };
        for (cases) |c| {
            const bytes = try frameBytes(gpa, c.b0, c.b1, c.ext, c.payload);
            defer gpa.free(bytes);
            badFrame(r, inst, sess, c.name, bytes);
        }
        _ = r.ok("server survives every bad frame", client.alive(inst) and inst.alive());
    }

    // ------------------------------------------- malformed HTTP requests
    {
        const big_header = try std.fmt.allocPrint(gpa, "GET / HTTP/1.1\r\nHost: {s}\r\nX: {s}\r\n\r\n", .{ host, &rep(40000, 'a') });
        const big_body = try std.fmt.allocPrint(gpa, "POST /pair HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}\r\nContent-Length: 513\r\n\r\n{s}", .{ host, origin, &rep(513, 'a') });
        const long_target = try std.fmt.allocPrint(gpa, "GET /{s} HTTP/1.1\r\nHost: {s}\r\n\r\n", .{ &rep(2048, 'a'), host });
        var many: std.ArrayList(u8) = .empty;
        try many.print(gpa, "GET / HTTP/1.1\r\nHost: {s}\r\n", .{host});
        for (0..64) |i| try many.print(gpa, "X-{d}: v\r\n", .{i});
        try many.appendSlice(gpa, "\r\n");

        const Case = struct { name: []const u8, bytes: []const u8, want: u16 };
        const cases = [_]Case{
            .{ .name = "POST without Content-Length", .bytes = try std.fmt.allocPrint(gpa, "POST /logout HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}\r\n\r\n", .{ host, origin }), .want = 411 },
            .{ .name = "chunked POST", .bytes = try std.fmt.allocPrint(gpa, "POST /pair HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", .{ host, origin }), .want = 400 },
            .{ .name = "Transfer-Encoding on GET", .bytes = try std.fmt.allocPrint(gpa, "GET /pair HTTP/1.1\r\nHost: {s}\r\nTransfer-Encoding: identity\r\n\r\n", .{host}), .want = 400 },
            .{ .name = "Expect: 100-continue", .bytes = try std.fmt.allocPrint(gpa, "POST /pair HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n", .{ host, origin }), .want = 417 },
            .{ .name = "GET with body", .bytes = try std.fmt.allocPrint(gpa, "GET /pair HTTP/1.1\r\nHost: {s}\r\nContent-Length: 4\r\n\r\nabcd", .{host}), .want = 400 },
            .{ .name = "garbage request", .bytes = "\x00\xff\r\n\r\n", .want = 400 },
            .{ .name = "huge header (40 kB)", .bytes = big_header, .want = 431 },
            .{ .name = "oversized POST body (513)", .bytes = big_body, .want = 413 },
            .{ .name = "Content-Length of 10 digits", .bytes = try std.fmt.allocPrint(gpa, "POST /pair HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}\r\nContent-Length: 9999999999\r\n\r\n", .{ host, origin }), .want = 413 },
            .{ .name = "Content-Length of 11 digits", .bytes = try std.fmt.allocPrint(gpa, "POST /pair HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}\r\nContent-Length: 99999999999\r\n\r\n", .{ host, origin }), .want = 400 },
            .{ .name = "non-numeric Content-Length", .bytes = try std.fmt.allocPrint(gpa, "POST /pair HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}\r\nContent-Length: 1x\r\n\r\n", .{ host, origin }), .want = 400 },
            .{ .name = "negative Content-Length", .bytes = try std.fmt.allocPrint(gpa, "POST /pair HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}\r\nContent-Length: -1\r\n\r\n", .{ host, origin }), .want = 400 },
            .{ .name = "duplicate Content-Length", .bytes = try std.fmt.allocPrint(gpa, "POST /pair HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n", .{ host, origin }), .want = 400 },
            .{ .name = "duplicate Host", .bytes = try std.fmt.allocPrint(gpa, "GET / HTTP/1.1\r\nHost: {s}\r\nHost: {s}\r\n\r\n", .{ host, host }), .want = 400 },
            .{ .name = "duplicate Origin", .bytes = try std.fmt.allocPrint(gpa, "POST /pair HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}\r\nOrigin: {s}\r\nContent-Length: 0\r\n\r\n", .{ host, origin, origin }), .want = 400 },
            .{ .name = "HTTP/1.0", .bytes = try std.fmt.allocPrint(gpa, "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{host}), .want = 400 },
            .{ .name = "HTTP/2 preface", .bytes = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", .want = 400 },
            .{ .name = "absolute-form target", .bytes = try std.fmt.allocPrint(gpa, "GET http://{s}/ HTTP/1.1\r\nHost: {s}\r\n\r\n", .{ host, host }), .want = 400 },
            .{ .name = "target over 2048 bytes", .bytes = long_target, .want = 400 },
            .{ .name = "65 headers", .bytes = many.items, .want = 400 },
            .{ .name = "obs-fold header continuation", .bytes = try std.fmt.allocPrint(gpa, "GET / HTTP/1.1\r\nHost: {s}\r\nX: a\r\n b\r\n\r\n", .{host}), .want = 400 },
            .{ .name = "bare LF inside the head", .bytes = try std.fmt.allocPrint(gpa, "GET / HTTP/1.1\r\nHost: {s}\r\nX: a\nY: b\r\n\r\n", .{host}), .want = 400 },
            .{ .name = "space in a header name", .bytes = try std.fmt.allocPrint(gpa, "GET / HTTP/1.1\r\nHost: {s}\r\nBad Name: x\r\n\r\n", .{host}), .want = 400 },
            .{ .name = "NUL in a header value", .bytes = try std.fmt.allocPrint(gpa, "GET / HTTP/1.1\r\nHost: {s}\r\nX: a\x00b\r\n\r\n", .{host}), .want = 400 },
            .{ .name = "double space in the request line", .bytes = try std.fmt.allocPrint(gpa, "GET  / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host}), .want = 400 },
            .{ .name = "control character in the target", .bytes = try std.fmt.allocPrint(gpa, "GET /a\x01b HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host}), .want = 400 },
            .{ .name = "unknown method", .bytes = try std.fmt.allocPrint(gpa, "DELETE / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host}), .want = 405 },
            .{ .name = "lower-case method", .bytes = try std.fmt.allocPrint(gpa, "get / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host}), .want = 405 },
            .{ .name = "no Host header", .bytes = "GET / HTTP/1.1\r\n\r\n", .want = 421 },
        };
        for (cases) |c| {
            const data = http.rawExchange(gpa, port, c.bytes, 5000) catch |e| {
                _ = r.check(c.name, false, "{t}", .{e});
                continue;
            };
            defer gpa.free(data);
            var name_buf: [128]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buf, "rejected: {s} -> {d}", .{ c.name, c.want });
            var codes_buf: [8]u16 = undefined;
            const codes = http.statusLines(data, &codes_buf);
            _ = r.check(name, codes.len == 1 and codes[0] == c.want, "got {any} ({d} bytes)", .{ codes, data.len });
        }
        _ = r.ok("server survives every malformed request", client.alive(inst) and inst.alive());
    }

    // --------------------------------------------- split heads, pipelining
    {
        var s = try net.Socket.connect(port, .{});
        defer s.close();
        for ([_][]const u8{ "GET / HTTP/1.1\r\n", "A\r", "\n" }) |part| {
            s.sendAll(part) catch {};
            net.sleep(100);
        }
        s.sendAll("\r\n") catch {};
        const d = try s.recvUntilClose(gpa, 4096, 5000);
        _ = r.check("split head with a bad header -> 400", std.mem.startsWith(u8, d.data, "HTTP/1.1 400"), "{s}", .{d.data[0..@min(d.data.len, 40)]});
    }
    {
        var s = try net.Socket.connect(port, .{});
        defer s.close();
        var hb: [64]u8 = undefined;
        const parts = [_][]const u8{ "GET /pair HTTP/1.1\r\n", try std.fmt.bufPrint(&hb, "Host: {s}\r", .{host}), "\n", "\r", "\n" };
        for (parts) |part| {
            s.sendAll(part) catch {};
            net.sleep(100);
        }
        var resp = http.readResponse(gpa, &s, 5000) catch |e| blk: {
            _ = r.check("valid head split across 5 sends -> 200", false, "{t}", .{e});
            break :blk null;
        };
        if (resp) |*rr| {
            defer rr.deinit();
            _ = r.check("valid head split across 5 sends -> 200", rr.status == 200, "{d}", .{rr.status});
        }
    }
    {
        const two = try std.fmt.allocPrint(gpa, "GET /static/app.css HTTP/1.1\r\nHost: {s}\r\n\r\nGET /pair HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{ host, host });
        const data = try http.rawExchange(gpa, port, two, 5000);
        var cb: [8]u16 = undefined;
        const codes = http.statusLines(data, &cb);
        _ = r.check("pipelined GETs both answered", codes.len == 2 and codes[0] == 200 and codes[1] == 200, "{any}", .{codes});
    }
    {
        const pp = try std.fmt.allocPrint(gpa, "POST /logout HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}\r\nContent-Length: 0\r\n\r\nGET /pair HTTP/1.1\r\nHost: {s}\r\n\r\n", .{ host, origin, host });
        const data = try http.rawExchange(gpa, port, pp, 5000);
        var cb: [8]u16 = undefined;
        const codes = http.statusLines(data, &cb);
        _ = r.check("pipelined POST then GET: only the POST answered, then close", codes.len == 1 and codes[0] == 303, "{any}", .{codes});
    }
    {
        var s = try net.Socket.connect(port, .{});
        defer s.close();
        var ok = true;
        for (0..3) |_| {
            const req = try http.format(gpa, .{ .path = "/pair", .host = host });
            s.sendAll(req) catch {};
            var resp = http.readResponse(gpa, &s, 5000) catch {
                ok = false;
                break;
            };
            ok = ok and resp.status == 200;
            resp.deinit();
        }
        _ = r.ok("keep-alive: three sequential requests on one connection", ok);
    }
    {
        var many: std.ArrayList(u8) = .empty;
        for (0..200) |_| try many.print(gpa, "GET /static/app.css HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host});
        var s = try net.Socket.connect(port, .{});
        defer s.close();
        try s.sendAll(many.items);
        const d = try s.recvUntilClose(gpa, 64 << 20, 15_000);
        var cb: [256]u16 = undefined;
        const codes = http.statusLines(d.data, &cb);
        _ = r.check("200 pipelined requests answered, then the connection closes", codes.len == 200 and d.closed, "{d} answered, closed={}", .{ codes.len, d.closed });
    }

    // ------------------------------------- slot eviction (heavy instance)
    {
        const va = try client.Viewer.open(heavy, hc.sessionCookie());
        defer va.deinit();
        var idles: [40]net.Socket = undefined;
        var n_open: usize = 0;
        defer for (idles[0..n_open]) |*s| s.close();
        while (n_open < idles.len) : (n_open += 1) {
            idles[n_open] = net.Socket.connect(heavy.port, .{}) catch break;
        }
        net.sleep(1000);
        const t0 = net.now();
        const c2 = client.signIn(heavy, hc.deviceCookie()) catch null;
        const dt = net.now() - t0;
        _ = r.check("device sign-in works with 40 idle connections open", c2 != null, "", .{});
        _ = r.check("...and promptly", dt < 3000, "{d} ms", .{dt});
        if (c2) |c| {
            var resp = try client.get(heavy, "/", c.sessionCookie());
            defer resp.deinit();
            _ = r.check("...and its session works", resp.status == 200, "{d}", .{resp.status});
        }
        var evicted: usize = 0;
        for (idles[0..n_open]) |*s| {
            var tmp: [16]u8 = undefined;
            const got = s.recvSome(&tmp, 20) catch |e| switch (e) {
                error.Timeout => continue,
                else => {
                    evicted += 1;
                    continue;
                },
            };
            if (got == 0) evicted += 1;
        }
        _ = r.check("idle pre-auth connections evicted (per-address cap 8)", evicted >= n_open -| 9, "{d} of {d} evicted", .{ evicted, n_open });
        _ = r.ok("signed-in viewer not evicted (ping answered)", va.ping("alive", 10_000) and !va.closed);
        _ = r.check("heavy-output viewer frames decode strictly", va.bad == null, "{?t}", .{va.bad});
    }

    // ------------------------------- logout reaches open viewers
    {
        const reading = try client.Viewer.open(inst, sess);
        defer reading.deinit();
        var silent = try ws.Client.connect(gpa, port, wsopt);
        defer silent.close();
        _ = r.check("second websocket on the same session upgrades", silent.status == 101, "{d}", .{silent.status});
        net.sleep(500);
        var resp = try client.post(inst, "/logout", sess, true);
        defer resp.deinit();
        _ = r.check("logout clears the cookies", resp.status == 303 and std.mem.indexOf(u8, resp.setCookieLine(client.session_cookie) orelse "", "Max-Age=0") != null, "{d}", .{resp.status});
        const t0 = net.now();
        const got = reading.waitLogout(12_000);
        _ = r.check("open websocket told about logout", got, "after {d} ms", .{net.now() - t0});
        net.sleep(1000);
        const d = silent.sock.recvUntilClose(gpa, 64 << 20, 20_000) catch null;
        const silent_ok = if (d) |dd| dd.closed and std.mem.indexOf(u8, dd.data, "{\"t\":\"logout\"}") != null else false;
        _ = r.check("silent websocket got logout and was closed", silent_ok, "", .{});
        var resp2 = try client.get(inst, "/", sess);
        defer resp2.deinit();
        _ = r.check("old session no longer works", resp2.status == 303, "{d}", .{resp2.status});
    }

    // --------------------------------------------------- log + probes
    for (&probes) |*p| p.finish(r);
    {
        const text = try inst.log();
        _ = r.ok("Host rejection logged", std.mem.indexOf(u8, text, "not allowed") != null);
        _ = r.ok("bad Origin logged", std.mem.indexOf(u8, text, "bad origin") != null);
        _ = r.ok("no panic in log", !client.containsIgnoreCase(text, "panic"));
        const t2 = try heavy.log();
        _ = r.ok("no panic in heavy instance log", !client.containsIgnoreCase(t2, "panic"));
    }
    _ = r.ok("portal still running at end of group", inst.alive() and client.alive(inst));
    _ = r.ok("heavy-output portal still running", heavy.alive() and client.alive(heavy));
}
