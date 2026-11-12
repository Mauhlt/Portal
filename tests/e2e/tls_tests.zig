//! Portal with TLS on (its default): the whole device flow over HTTPS and
//! WSS, trusting only the CA that `portal ca export` writes.
//!
//!   * transport: the handshake verifies against the exported Portal CA
//!     (and nothing else); another Portal CA, a TLS 1.2-only hello and
//!     plain HTTP are refused;
//!   * the CA download listener on port+1 (plain HTTP) is up only while a
//!     pairing window is open and serves only /, /ca.cer, /ca.mobileconfig;
//!   * desk-approved pairing, `__Host-` cookies with Secure, HttpOnly,
//!     SameSite=Strict and the right Max-Age; sign-in and refresh;
//!   * Origin: http:// is refused on every POST and on the WSS upgrade;
//!   * WSS: hello, full snapshot, key input, ping/pong, close; logout and
//!     unpair drop the viewer;
//!   * privacy: no paths or user names in anything sent over TLS.

const std = @import("std");
const net = @import("net.zig");
const http = @import("http.zig");
const ws = @import("ws.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const tlsnet = @import("tlsnet.zig");
const privacy = @import("privacy.zig");
const Runner = @import("runner.zig").Runner;

const marker = "PORTAL-TLS-TEST";
const run_args = [_][]const u8{ "--input", "keys", "--", "cmd.exe", "/k", "echo " ++ marker };

fn has(s: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, s, needle) != null;
}

/// Set-Cookie attributes every Portal cookie must carry over HTTPS.
fn secureAttrs(line: []const u8) bool {
    return std.mem.startsWith(u8, line, "__Host-") and has(line, "; Secure") and has(line, "; HttpOnly") and
        has(line, "; SameSite=Strict") and has(line, "; Path=/") and !client.containsIgnoreCase(line, "domain=");
}

fn maxAge(line: []const u8, comptime n: i64) bool {
    return has(line, std.fmt.comptimePrint("; Max-Age={d}", .{n}));
}

/// Collects the first privacy leak seen in anything sent over TLS.
const Scan = struct {
    leaks: *const privacy.Leaks,
    scanned: usize = 0,
    leaked: usize = 0,
    first: [160]u8 = undefined,
    first_len: usize = 0,

    fn look(s: *Scan, what: []const u8, data: []const u8) void {
        s.scanned += 1;
        const n = s.leaks.find(data) orelse return;
        s.leaked += 1;
        if (s.first_len == 0) s.first_len = (std.fmt.bufPrint(&s.first, "{s} contains '{s}'", .{ what, n }) catch @as([]u8, &.{})).len;
    }
};

/// Plain-HTTP GET to the CA download listener.
fn caGet(inst: *proc.Instance, ca_port: u16, method: []const u8, path: []const u8) !http.Response {
    var host_buf: [32]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buf, "127.0.0.1:{d}", .{ca_port});
    return http.request(inst.h.gpa, ca_port, .{ .method = method, .path = path, .host = host, .body = if (std.mem.eql(u8, method, "POST")) "" else null });
}

fn listening(port: u16) bool {
    var s = net.Socket.connect(port, .{}) catch return false;
    s.close();
    return true;
}

/// Waits until the port accepts (want=true) or refuses (want=false).
fn waitListening(port: u16, want: bool, ms: u32) bool {
    const deadline = net.now() + ms;
    while (true) {
        if (listening(port) == want) return true;
        if (net.now() >= deadline) return false;
        net.sleep(50);
    }
}

/// A TLS 1.2 ClientHello (no TLS 1.3 offered), as a raw record.
fn tls12Hello(out: *std.ArrayList(u8), gpa: std.mem.Allocator, supported_versions: bool) !void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    try body.appendSlice(gpa, &.{ 0x03, 0x03 }); // client_version TLS 1.2
    var random: [32]u8 = undefined;
    for (&random, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    try body.appendSlice(gpa, &random);
    try body.append(gpa, 0); // no session id
    const suites = [_]u8{ 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0x00, 0x9c };
    try body.appendSlice(gpa, &.{ 0, suites.len });
    try body.appendSlice(gpa, &suites);
    try body.appendSlice(gpa, &.{ 1, 0 }); // null compression
    var ext: std.ArrayList(u8) = .empty;
    defer ext.deinit(gpa);
    try ext.appendSlice(gpa, &.{ 0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17 }); // groups
    try ext.appendSlice(gpa, &.{ 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 }); // point formats
    try ext.appendSlice(gpa, &.{ 0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01 }); // sig algs
    if (supported_versions) try ext.appendSlice(gpa, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x03 }); // only 1.2
    try body.appendSlice(gpa, &.{ @intCast(ext.items.len >> 8), @truncate(ext.items.len) });
    try body.appendSlice(gpa, ext.items);
    const hs_len = body.items.len;
    const rec_len = hs_len + 4;
    try out.appendSlice(gpa, &.{ 0x16, 0x03, 0x01, @intCast(rec_len >> 8), @truncate(rec_len) });
    try out.appendSlice(gpa, &.{ 0x01, 0, @intCast(hs_len >> 8), @truncate(hs_len) });
    try out.appendSlice(gpa, body.items);
}

/// GET /pair/wait until the outcome is decided; returns the 303 response.
fn waitDecided(inst: *proc.Instance, req_cookie: []const u8, ms: u32) !?http.Response {
    const deadline = net.now() + ms;
    while (net.now() < deadline) {
        var resp = try client.waitPage(inst, req_cookie, null);
        if (resp.status == 303) return resp;
        resp.deinit();
        net.sleep(50);
    }
    return null;
}

fn waitLine(v: *client.Viewer, want: []const u8, ms: u32) bool {
    return v.pumpUntil(ms, want, struct {
        fn f(wnt: []const u8, vv: *client.Viewer) bool {
            return std.mem.eql(u8, vv.cursorLine(), wnt);
        }
    }.f);
}

fn readFile(h: *proc.Harness, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(h.io, path, h.gpa, .limited(1 << 20));
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const ca_port = port + 1;
    const dir = try h.dataDir("tls");
    const inst = try proc.Instance.startTls(h, dir, port, &run_args);
    defer inst.kill();
    const trust = inst.tls.?;
    var leaks = try privacy.Leaks.standard(h, dir);
    defer leaks.deinit();
    var scan: Scan = .{ .leaks = &leaks };
    var dump_buf: [4096]u8 = undefined;

    const cer_path = try std.fmt.allocPrint(gpa, "{s}\\portal-ca.cer", .{inst.ca_dir});
    const ca_der = try readFile(h, cer_path);
    var fp_buf: [95]u8 = undefined;
    const fingerprint = blk: {
        var d: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(ca_der, &d, .{});
        const hex = "0123456789ABCDEF";
        for (d, 0..) |b, i| {
            fp_buf[i * 3] = hex[b >> 4];
            fp_buf[i * 3 + 1] = hex[b & 0xf];
            if (i < 31) fp_buf[i * 3 + 2] = ':';
        }
        break :blk fp_buf[0..95];
    };

    // ------------------------------------------------------------ transport
    {
        _ = r.check("portal ca export wrote one CA certificate (the only trust anchor)", trust.bundle.map.count() == 1, "{d} certs", .{trust.bundle.map.count()});
        if (tlsnet.TlsSocket.connect(gpa, port, trust, .{})) |t| {
            defer t.close();
            _ = r.check("handshake verifies against the exported Portal CA (no OS roots added)", trust.bundle.map.count() == 1, "bundle {d}", .{trust.bundle.map.count()});
            _ = r.check("TLS 1.3 is negotiated", t.version() == .tls_1_3, "{t}", .{t.version()});
        } else |err| {
            _ = r.check("handshake verifies against the exported Portal CA (no OS roots added)", false, "{t} ({?t})", .{ err, tlsnet.last_handshake_error });
        }
        var resp = try client.get(inst, "/pair", null);
        defer resp.deinit();
        _ = r.check("GET /pair over HTTPS is 200", resp.status == 200 and resp.bodyContains("Pair a device"), "{d}", .{resp.status});
        scan.look("/pair", resp.raw);
    }
    {
        // Another Portal installation's CA (a second data directory).
        const other = try h.dataDir("tls-other-ca");
        const ini = try proc.runCli(h, other, &.{ "ca", "init" });
        const odir = try std.fmt.allocPrint(gpa, "{s}\\ca-export", .{other});
        const ex = try proc.runCli(h, other, &.{ "ca", "export", "--out", odir });
        if (r.check("a second Portal CA can be made and exported", ini.code == 0 and ex.code == 0, "init={d} export={d} {s}", .{ ini.code, ex.code, ex.out })) {
            const pem = try std.fmt.allocPrint(gpa, "{s}\\portal-ca.pem", .{odir});
            const wrong = try tlsnet.Trust.load(gpa, h.io, pem);
            defer wrong.deinit();
            tlsnet.last_handshake_error = null;
            if (tlsnet.TlsSocket.connect(gpa, port, wrong, .{})) |t| {
                t.close();
                _ = r.check("a different Portal CA does not verify the server", false, "handshake succeeded", .{});
            } else |err| {
                _ = r.check("a different Portal CA does not verify the server", err == error.TlsHandshakeFailed or err == error.NotVerifiedByPortalCa, "{t} ({?t})", .{ err, tlsnet.last_handshake_error });
                std.debug.print("     (wrong CA: {t}, detail {?t})\n", .{ err, tlsnet.last_handshake_error });
            }
            _ = r.check("...and std did not swap OS roots into the wrong-CA bundle", wrong.bundle.map.count() == 1, "{d}", .{wrong.bundle.map.count()});
            const req = http.request(gpa, port, .{ .path = "/pair", .host = inst.host, .tls = wrong });
            if (req) |resp| {
                var rr = resp;
                rr.deinit();
            } else |_| {}
            _ = r.ok("HTTPS request with the wrong CA gets no response", std.meta.isError(req));
        }
    }
    for ([_]bool{ false, true }) |sv| {
        var hello: std.ArrayList(u8) = .empty;
        defer hello.deinit(gpa);
        try tls12Hello(&hello, gpa, sv);
        var s = try net.Socket.connect(port, .{});
        defer s.close();
        s.sendAll(hello.items) catch {};
        const got = try s.recvUntilClose(gpa, 64 * 1024, 5000);
        defer gpa.free(got.data);
        // Refused: a protocol_version alert (70), never a ServerHello; then closed.
        const alert_only = got.data.len >= 7 and got.data[0] == 0x15;
        const desc: u8 = if (got.data.len >= 7 and got.data[0] == 0x15) got.data[6] else 0;
        const name = if (sv) "TLS 1.2-only hello (supported_versions = 1.2) gets protocol_version and is closed" else "TLS 1.2-only hello (legacy, no supported_versions) gets protocol_version and is closed";
        _ = r.check(name, alert_only and desc == 70 and got.closed, "{d} bytes, first {x}, alert {d}, closed={}", .{ got.data.len, if (got.data.len > 0) got.data[0] else 0, desc, got.closed });
        std.debug.print("     (server sent alert {d}, {d} bytes)\n", .{ desc, got.data.len });
    }
    {
        var req_buf: [128]u8 = undefined;
        const req = try std.fmt.bufPrint(&req_buf, "GET /pair HTTP/1.1\r\nHost: {s}\r\n\r\n", .{inst.host});
        const got = try http.rawExchange(gpa, port, req, 5000);
        defer gpa.free(got);
        _ = r.check("plain HTTP to the TLS port gets 400 and the https:// hint", http.firstStatus(got) == 400 and has(got, "speaks HTTPS") and !has(got, "Set-Cookie"), "{s}", .{got[0..@min(got.len, 200)]});
        scan.look("plain-HTTP hint", got);
    }
    _ = r.ok("CA download listener is down with no pairing window", !listening(ca_port));

    // --------------------------------------- first pairing, desk approval
    var creds: client.Creds = undefined;
    {
        const pc = try inst.liveCli(&.{ "pair", "laptop" });
        defer pc.deinit();
        _ = r.check("portal pair opens a window and waits at the desk", pc.waitFor("Waiting for the device", 15_000) and pc.alive(), "{s}", .{pc.output()});
        _ = r.check("portal pair prints the exported CA's SHA-256", pc.has(fingerprint), "want {s}: {s}", .{ fingerprint, pc.output() });
        var up_buf: [96]u8 = undefined;
        const up = try std.fmt.bufPrint(&up_buf, "Certificate download is up: http://127.0.0.1:{d}/", .{ca_port});
        _ = r.check("portal pair reports the certificate download listener up", pc.waitFor(up, 10_000), "{s}", .{pc.output()});
        _ = r.ok("CA download listener accepts on port+1 while the window is open", waitListening(ca_port, true, 5000));

        // The CA download listener: plain HTTP, three routes only.
        {
            var resp = try caGet(inst, ca_port, "GET", "/");
            defer resp.deinit();
            var link_buf: [64]u8 = undefined;
            const link = try std.fmt.bufPrint(&link_buf, "https://127.0.0.1:{d}/pair", .{port});
            _ = r.check("CA listener /: 200 page with the fingerprint and the https:// link", resp.status == 200 and resp.bodyContains(fingerprint) and resp.bodyContains(link) and resp.setCookieCount() == 0, "{d}", .{resp.status});
            scan.look("CA listener /", resp.raw);
        }
        {
            var resp = try caGet(inst, ca_port, "GET", "/ca.cer");
            defer resp.deinit();
            _ = r.check("CA listener /ca.cer is exactly the exported CA (DER)", resp.status == 200 and std.mem.eql(u8, resp.body, ca_der) and
                std.mem.eql(u8, resp.header("content-type") orelse "", "application/pkix-cert"), "{d} {d} bytes", .{ resp.status, resp.body.len });
        }
        {
            var resp = try caGet(inst, ca_port, "GET", "/ca.mobileconfig");
            defer resp.deinit();
            _ = r.check("CA listener /ca.mobileconfig is an Apple profile", resp.status == 200 and
                std.mem.eql(u8, resp.header("content-type") orelse "", "application/x-apple-aspen-config") and resp.bodyContains("PayloadContent"), "{d}", .{resp.status});
            scan.look("CA listener /ca.mobileconfig", resp.raw);
        }
        {
            const others = [_][2][]const u8{
                .{ "GET", "/pair" },          .{ "GET", "/pair/wait" },       .{ "GET", "/ws" },
                .{ "GET", "/static/app.js" }, .{ "GET", "/static/app.wasm" }, .{ "GET", "/ca.pem" },
                .{ "GET", "/ca.key" },        .{ "GET", "/tls/ca.key" },      .{ "GET", "/../tls/ca.key" },
                .{ "GET", "/ca.cer/" },       .{ "GET", "/CA.CER" },          .{ "GET", "/favicon.ico" },
                .{ "GET", "/portal.log" },    .{ "POST", "/pair" },           .{ "POST", "/auth/refresh" },
                .{ "POST", "/logout" },       .{ "GET", "/index.html" },      .{ "GET", "/ca.mobileconfig/../ca.cer" },
            };
            var bad: usize = 0;
            var answered: usize = 0;
            var first: [96]u8 = undefined;
            var first_len: usize = 0;
            for (others) |o| {
                var resp = caGet(inst, ca_port, o[0], o[1]) catch continue; // closed: served nothing
                defer resp.deinit();
                answered += 1;
                scan.look(o[1], resp.raw);
                if (resp.status == 200 or resp.status == 303 or resp.setCookieCount() != 0) {
                    bad += 1;
                    if (first_len == 0) first_len = (std.fmt.bufPrint(&first, "{s} {s} -> {d}", .{ o[0], o[1], resp.status }) catch @as([]u8, &.{})).len;
                }
            }
            _ = r.check("CA listener serves only /, /ca.cer and /ca.mobileconfig", bad == 0 and answered == others.len, "{d} bad, {d}/{d} answered; first: {s}", .{ bad, answered, others.len, first[0..first_len] });
        }
        if (tlsnet.TlsSocket.connect(gpa, ca_port, trust, .{})) |t| {
            t.close();
            _ = r.ok("CA listener does not speak TLS (it exists for devices without the CA)", false);
        } else |_| _ = r.ok("CA listener does not speak TLS (it exists for devices without the CA)", true);

        _ = r.ok("pairing window becomes visible over HTTPS", client.waitPairOpen(inst, 10_000));
        {
            var bad_origin_buf: [40]u8 = undefined;
            const bad_origin = try std.fmt.bufPrint(&bad_origin_buf, "http://127.0.0.1:{d}", .{port});
            var resp = try http.request(gpa, port, .{ .method = "POST", .path = "/pair", .host = inst.host, .origin = bad_origin, .body = "", .tls = trust });
            defer resp.deinit();
            _ = r.check("POST /pair over HTTPS with an http:// Origin is 403, nothing registered", resp.status == 403 and resp.setCookieCount() == 0, "{d}", .{resp.status});
        }
        var req_cookie_buf: [96]u8 = undefined;
        var req_cookie: []const u8 = "";
        {
            var resp = try http.request(gpa, port, .{ .method = "POST", .path = "/pair", .host = inst.host, .origin = inst.origin, .body = "", .tls = trust });
            defer resp.deinit();
            const line = resp.setCookieLine(client.tls_pairreq_cookie) orelse "";
            _ = r.check("POST /pair registers a request and sends the device to wait", resp.status == 303 and std.mem.eql(u8, resp.location(), "/pair/wait") and resp.setCookieCount() == 1, "{d} {s}", .{ resp.status, resp.location() });
            _ = r.check("request cookie is __Host-portal_pairreq: Secure, HttpOnly, SameSite=Strict, Max-Age=600", secureAttrs(line) and maxAge(line, 600), "{s}", .{line});
            if (resp.cookie(client.tls_pairreq_cookie)) |v| {
                req_cookie = try std.fmt.bufPrint(&req_cookie_buf, "{s}={s}", .{ client.tls_pairreq_cookie, v });
            }
            _ = r.check("no plain-named (non-__Host-) cookie is set over HTTPS", resp.setCookieLine(client.pairreq_cookie) == null, "", .{});
        }
        // The first /pair/wait is answered at once; later ones are held
        // until the desk answers (long poll), so keep this page's code.
        var page_code: [4]u8 = @splat('?');
        {
            var resp = try client.waitPage(inst, req_cookie, null);
            defer resp.deinit();
            _ = r.check("waiting page over HTTPS: 200, refreshes, issues nothing", resp.status == 200 and resp.bodyContains("http-equiv=\"refresh\"") and resp.setCookieCount() == 0, "{d}", .{resp.status});
            scan.look("/pair/wait", resp.raw);
            const hc = resp.header("x-portal-request-code") orelse "";
            if (hc.len == 4 and resp.bodyContains(hc)) @memcpy(&page_code, hc);
        }
        _ = r.check("desk prompt appears for the device", pc.waitFor("[y/N]", 10_000), "{s}", .{pc.output()});
        const code = pc.lastAfter("(request ", 4) orelse "????";
        _ = r.check("device page shows the same request code as the desk", std.mem.eql(u8, &page_code, code), "page={s} desk={s}", .{ &page_code, code });
        pc.answer("y\r\n");
        const decided = try waitDecided(inst, req_cookie, 10_000);
        if (decided) |d| {
            var resp = d;
            defer resp.deinit();
            const dl = resp.setCookieLine(client.tls_device_cookie) orelse "";
            const sl = resp.setCookieLine(client.tls_session_cookie) orelse "";
            const ql = resp.setCookieLine(client.tls_pairreq_cookie) orelse "";
            _ = r.check("'y' at the desk: the device collects its credential (303 to /)", std.mem.eql(u8, resp.location(), "/"), "303 to {s}; desk: {s}", .{ resp.location(), pc.output() });
            _ = r.check("__Host-portal_device: Secure, HttpOnly, SameSite=Strict, Path=/, Max-Age=90 days", secureAttrs(dl) and maxAge(dl, 90 * 24 * 3600), "{s}", .{dl});
            _ = r.check("__Host-portal (session): Secure, HttpOnly, SameSite=Strict, Path=/, Max-Age=7 days", secureAttrs(sl) and maxAge(sl, 7 * 24 * 3600), "{s}", .{sl});
            _ = r.check("the request cookie is cleared (Secure, Max-Age=0)", secureAttrs(ql) and maxAge(ql, 0), "{s}", .{ql});
            _ = r.check("no plain-named credential cookies over HTTPS", resp.setCookieLine(client.device_cookie) == null and resp.setCookieLine(client.session_cookie) == null, "", .{});
            creds = client.Creds.fromResponse(&resp) orelse return error.NoCookies;
            scan.look("pairing 303", resp.raw);
        } else {
            _ = r.check("'y' at the desk: the device collects its credential (303 to /)", false, "still pending; desk: {s}", .{pc.output()});
            return error.PairingFailed;
        }
        _ = r.check("portal pair reports success and exits 0", pc.wait(10_000) == 0 and pc.has("Paired 'laptop' at 127.0.0.1"), "{s}", .{pc.output()});
        _ = r.ok("CA download listener closes when the window closes", waitListening(ca_port, false, 5000));
    }

    // ------------------------------------------------ sign-in and assets
    {
        var resp = try client.get(inst, "/", creds.sessionCookie());
        defer resp.deinit();
        _ = r.check("session opens the viewer page over HTTPS", resp.status == 200 and resp.bodyContains("app.js"), "{d}", .{resp.status});
        scan.look("/", resp.raw);
    }
    for ([_][2][]const u8{
        .{ "/static/app.wasm", "application/wasm" },
        .{ "/static/app.js", "text/javascript; charset=utf-8" },
        .{ "/static/app.css", "text/css; charset=utf-8" },
    }) |a| {
        var resp = try client.get(inst, a[0], null);
        defer resp.deinit();
        const wasm_ok = !std.mem.endsWith(u8, a[0], ".wasm") or std.mem.startsWith(u8, resp.body, "\x00asm");
        var name_buf: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "{s} is served over HTTPS", .{a[0]});
        _ = r.check(name, resp.status == 200 and wasm_ok and resp.body.len > 0 and std.mem.eql(u8, resp.header("content-type") orelse "", a[1]), "{d} {d} bytes", .{ resp.status, resp.body.len });
        scan.look(a[0], resp.raw);
    }
    {
        var resp = try client.get(inst, "/", creds.deviceCookie());
        defer resp.deinit();
        const c2 = client.Creds.fromResponse(&resp);
        _ = r.check("device cookie signs in over HTTPS and rotates", resp.status == 303 and std.mem.eql(u8, resp.location(), "/") and c2 != null and
            !std.mem.eql(u8, c2.?.deviceValue(), creds.deviceValue()) and std.mem.startsWith(u8, c2.?.deviceValue(), "laptop."), "{d} {s}", .{ resp.status, resp.location() });
        _ = r.check("rotated cookies keep Secure/HttpOnly/SameSite and the __Host- names", secureAttrs(resp.setCookieLine(client.tls_device_cookie) orelse "") and
            secureAttrs(resp.setCookieLine(client.tls_session_cookie) orelse ""), "", .{});
        creds = c2 orelse return error.SignInFailed;
        var page = try client.get(inst, "/", creds.sessionCookie());
        defer page.deinit();
        _ = r.check("rotated session works", page.status == 200, "{d}", .{page.status});
    }
    {
        var resp = try client.post(inst, "/auth/refresh", creds.deviceCookie(), true);
        defer resp.deinit();
        const c3 = client.Creds.fromResponse(&resp);
        _ = r.check("POST /auth/refresh over HTTPS: 204 with rotated __Host- cookies", resp.status == 204 and c3 != null and
            !std.mem.eql(u8, c3.?.deviceValue(), creds.deviceValue()) and secureAttrs(resp.setCookieLine(client.tls_device_cookie) orelse ""), "{d}", .{resp.status});
        creds = c3 orelse return error.RefreshFailed;
    }

    // ------------------------------------------------------------- Origin
    {
        var both_buf: [256]u8 = undefined;
        const both = try std.fmt.bufPrint(&both_buf, "{s}; {s}", .{ creds.deviceCookie(), creds.sessionCookie() });
        var o_buf: [2][48]u8 = undefined;
        const origins = [_]?[]const u8{
            try std.fmt.bufPrint(&o_buf[0], "http://127.0.0.1:{d}", .{port}),
            try std.fmt.bufPrint(&o_buf[1], "https://127.0.0.1:{d}", .{port + 7}),
            "null",
            null,
        };
        var refused: usize = 0;
        var total: usize = 0;
        var first: [96]u8 = undefined;
        var first_len: usize = 0;
        for ([_][]const u8{ "/pair", "/auth/refresh", "/logout" }) |p| {
            for (origins) |o| {
                total += 1;
                var resp = try http.request(gpa, port, .{ .method = "POST", .path = p, .host = inst.host, .origin = o, .cookie = both, .body = "", .tls = trust });
                defer resp.deinit();
                if (resp.status == 403 and resp.setCookieCount() == 0) {
                    refused += 1;
                } else if (first_len == 0) first_len = (std.fmt.bufPrint(&first, "{s} origin={?s} -> {d}", .{ p, o, resp.status }) catch @as([]u8, &.{})).len;
            }
        }
        _ = r.check("every POST with an http://, foreign-port, null or missing Origin is 403", refused == total, "{d}/{d}; first: {s}", .{ refused, total, first[0..first_len] });
        // The credential was not touched by any of them.
        var page = try client.get(inst, "/", creds.sessionCookie());
        defer page.deinit();
        _ = r.check("...and none of them logged the device out", page.status == 200, "{d}", .{page.status});
        var p1 = try client.post(inst, "/pair", null, true);
        defer p1.deinit();
        var p2 = try client.post(inst, "/auth/refresh", null, true);
        defer p2.deinit();
        _ = r.check("https:// Origin is accepted (POST /pair -> closed window, /auth/refresh -> 401 without a cookie)", p1.status == 303 and
            std.mem.eql(u8, p1.location(), "/pair?e=closed") and p2.status == 401, "{d} {s} / {d}", .{ p1.status, p1.location(), p2.status });
    }
    {
        var bad_buf: [48]u8 = undefined;
        const bad = try std.fmt.bufPrint(&bad_buf, "http://127.0.0.1:{d}", .{port});
        var c1 = try ws.Client.connect(gpa, port, .{ .host = inst.host, .origin = bad, .cookie = creds.sessionCookie(), .tls = trust });
        defer c1.close();
        var c2 = try ws.Client.connect(gpa, port, .{ .host = inst.host, .origin = null, .cookie = creds.sessionCookie(), .tls = trust });
        defer c2.close();
        _ = r.check("WSS upgrade with an http:// Origin is 403", c1.status == 403, "{d}", .{c1.status});
        _ = r.check("WSS upgrade without an Origin is 403", c2.status == 403, "{d}", .{c2.status});
        var c3 = try ws.Client.connect(gpa, port, .{ .host = inst.host, .origin = inst.origin, .cookie = null, .tls = trust });
        defer c3.close();
        _ = r.check("WSS upgrade without a session is 401", c3.status == 401, "{d}", .{c3.status});
    }

    // ---------------------------------------------------------------- WSS
    {
        const v = client.Viewer.open(inst, creds.sessionCookie()) catch |err| {
            _ = r.check("WSS upgrade with the https:// Origin: 101, hello, snapshot", false, "{t}", .{err});
            return err;
        };
        defer v.deinit();
        _ = r.check("WSS upgrade with the https:// Origin: 101, hello first, then a full snapshot", v.c.status == 101 and v.hello_first and v.first_full, "status={d} hello_first={} full={}", .{ v.c.status, v.hello_first, v.first_full });
        _ = r.check("hello says keys", std.mem.eql(u8, v.helloText(), "{\"t\":\"hello\",\"input\":\"keys\"}"), "{s}", .{v.helloText()});
        scan.look("hello", v.helloText());
        _ = r.check("the snapshot carries the child's output", v.waitFor(marker, 10_000), "{s}", .{v.dump(&dump_buf)});
        _ = r.check("shell prompt reaches the viewer", waitLine(v, "E2E>", 10_000), "cursor '{s}'", .{v.cursorLine()});
        _ = v.settle(300, 2000);
        v.send("k:1");
        _ = r.check("key input over WSS (k:1) reaches the child", waitLine(v, "E2E>1", 5000), "cursor '{s}'", .{v.cursorLine()});
        v.send("k:enter");
        _ = r.check("k:enter submits it", v.waitFor("'1' is not recognized", 5000), "{s}", .{v.dump(&dump_buf)});
        _ = r.ok("ping over WSS gets the matching pong", v.ping("tls-ping", 5000));
        _ = r.check("no bad frames over WSS", v.bad == null, "{?t}", .{v.bad});
        v.c.send(.close, &.{ 0x03, 0xe8 }) catch {};
        const closed = v.waitClose(5000);
        _ = r.check("close: the server answers 1000 and closes", closed and v.close_payload[0] == 0x03 and v.close_payload[1] == 0xe8, "closed={} {x}", .{ closed, v.close_payload });
    }

    // ------------------------------------- logout and unpair drop viewers
    {
        const v = try client.Viewer.open(inst, creds.sessionCookie());
        defer v.deinit();
        var resp = try client.post(inst, "/logout", creds.sessionCookie(), true);
        defer resp.deinit();
        _ = r.check("POST /logout over HTTPS clears both __Host- cookies", resp.status == 303 and std.mem.eql(u8, resp.location(), "/pair?bye") and
            maxAge(resp.setCookieLine(client.tls_device_cookie) orelse "", 0) and secureAttrs(resp.setCookieLine(client.tls_device_cookie) orelse "") and
            maxAge(resp.setCookieLine(client.tls_session_cookie) orelse "", 0), "{d} {s}", .{ resp.status, resp.location() });
        _ = r.ok("logout drops the device's WSS viewer (logout message)", v.waitLogout(10_000));
        _ = r.ok("...and closes the WSS connection", v.waitClose(12_000));
        var page = try client.get(inst, "/", creds.deviceCookie());
        defer page.deinit();
        _ = r.check("logged-out device can't sign in (told it is no longer paired)", std.mem.eql(u8, page.location(), "/pair?e=gone"), "{s}", .{page.location()});
    }
    {
        const c = try client.pair(inst, "phone");
        const v = try client.Viewer.open(inst, c.sessionCookie());
        defer v.deinit();
        _ = r.ok("second device pairs over HTTPS and opens WSS", true);
        const u = try inst.cli(&.{ "unpair", "phone" });
        _ = r.check("portal unpair succeeds", u.code == 0, "{s}", .{u.out});
        _ = r.ok("desk unpair drops the WSS viewer (logout message)", v.waitLogout(10_000));
        _ = r.ok("...and closes the WSS connection", v.waitClose(12_000));
    }

    // ------- two requests from one address: what yields /pair?e=denied
    {
        const pc = try inst.liveCli(&.{ "pair", "tablet" });
        defer pc.deinit();
        _ = pc.waitFor("Waiting for the device", 15_000);
        _ = client.waitPairOpen(inst, 10_000);
        const rq1 = try client.requestPair(inst, null);
        const rq2 = try client.requestPair(inst, null);
        _ = r.check("two pending requests from one address", rq1.waiting() and rq2.waiting(), "{s} / {s}", .{ rq1.location(), rq2.location() });
        _ = r.check("desk asks about the oldest request first", pc.waitFor("[y/N]", 10_000), "{s}", .{pc.output()});
        const code = pc.lastAfter("(request ", 4) orelse "????";
        var p1 = try client.waitPage(inst, rq1.cookie(), null);
        defer p1.deinit();
        _ = r.check("...whose code is the first request's", p1.bodyContains(code), "code={s}", .{code});
        pc.answer("y\r\n");
        const second = try client.collect(inst, rq2.cookie(), null, 10_000);
        const second_denied = switch (second) {
            .refused => |why| std.mem.eql(u8, std.mem.sliceTo(&why, 0), "/pair?e=denied"),
            else => false,
        };
        _ = r.check("'y' approves the oldest; the newer request is denied (/pair?e=denied)", second_denied, "{any}", .{second});
        const first = try client.collect(inst, rq1.cookie(), null, 10_000);
        _ = r.check("...and the approved (oldest) request collects the credential", first == .creds, "{any}", .{first});
        _ = pc.wait(10_000);
    }

    _ = r.check("nothing sent over TLS contains paths or user names", scan.leaked == 0 and scan.scanned > 20, "{d} of {d}; first: {s}", .{ scan.leaked, scan.scanned, scan.first[0..scan.first_len] });
    _ = r.ok("portal still running at end of group", inst.alive() and client.alive(inst));
}
