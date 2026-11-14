//! Device pairing (desk approval), sign-in, rotation, revocation and the
//! device CLI.

const std = @import("std");
const net = @import("net.zig");
const http = @import("http.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;

const get = client.get;
const rep = client.rep;
const post = client.post;

pub const ping_child = [_][]const u8{ "--", "cmd.exe", "/c", "echo PORTAL-SMOKE-TEST & ping -n 600 127.0.0.1" };

/// Another loopback source address: a second "device" or a racing peer.
const other_ip = [4]u8{ 127, 0, 0, 2 };

fn has(s: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, s, needle) != null;
}

fn refusedTo(c: client.Collected, where: []const u8) bool {
    return switch (c) {
        .refused => |r| std.mem.eql(u8, std.mem.sliceTo(&r, 0), where),
        else => false,
    };
}

/// Whether this machine lets us connect from 127.0.0.2.
fn otherIpWorks(inst: *proc.Instance) bool {
    var r = http.request(inst.h.gpa, inst.port, .{ .path = "/pair", .host = inst.host, .source = other_ip }) catch return false;
    r.deinit();
    return true;
}

fn logCount(inst: *proc.Instance, needle: []const u8) usize {
    const text = inst.log() catch return 0;
    defer inst.h.gpa.free(text);
    return std.mem.count(u8, text, needle);
}

/// A GET /pair/wait loop on its own thread, to see that the server holds
/// the request (long poll) until the desk answers.
const HeldWait = struct {
    inst: *proc.Instance,
    cookie: []const u8,
    done: std.atomic.Value(bool) = .init(false),
    finished_at: u64 = 0,
    result: anyerror!client.Collected = error.NotRun,

    fn run(h: *HeldWait) void {
        h.result = client.collect(h.inst, h.cookie, null, 10_000);
        h.finished_at = net.now();
        h.done.store(true, .release);
    }
};

const SignInJob = struct {
    inst: *proc.Instance,
    cookie: []const u8,
    result: ?client.Creds = null,
    failed: bool = false,

    fn run(j: *SignInJob) void {
        j.result = client.signIn(j.inst, j.cookie) catch {
            j.failed = true;
            return;
        };
    }
};

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("pairing");
    var inst = try proc.Instance.start(h, dir, port, &ping_child);
    const two_ips = otherIpWorks(inst);

    // ------------------------------------------------ before any pairing
    {
        var resp = try get(inst, "/", null);
        defer resp.deinit();
        _ = r.check("unpaired visitor is sent to /pair", resp.status == 303 and std.mem.eql(u8, resp.location(), "/pair"), "{d} {s}", .{ resp.status, resp.location() });
    }
    {
        var resp = try get(inst, "/pair", null);
        defer resp.deinit();
        _ = r.check("pair page explains the desk step (no button)", resp.status == 200 and resp.bodyContains("Pair a device") and !resp.bodyContains("type=\"submit\""), "{d}", .{resp.status});
    }
    {
        var resp = try post(inst, "/pair", null, true);
        defer resp.deinit();
        _ = r.check("pairing refused with no window open", resp.status == 303 and std.mem.eql(u8, resp.location(), "/pair?e=closed") and resp.setCookieCount() == 0, "{d} {s} cookies={d}", .{ resp.status, resp.location(), resp.setCookieCount() });
    }
    {
        var resp = try post(inst, "/pair", null, false);
        defer resp.deinit();
        _ = r.check("POST /pair without Origin is 403", resp.status == 403, "{d}", .{resp.status});
    }
    {
        var resp = try http.request(gpa, port, .{ .method = "POST", .path = "/pair", .host = inst.host, .origin = "http://evil.example", .body = "" });
        defer resp.deinit();
        _ = r.check("POST /pair with a foreign Origin is 403", resp.status == 403, "{d}", .{resp.status});
    }
    {
        var resp = try get(inst, "/pair/wait", null);
        defer resp.deinit();
        _ = r.check("waiting page without a request reveals nothing", resp.status == 303 and std.mem.eql(u8, resp.location(), "/pair?e=expired") and resp.body.len == 0, "{d} {s}", .{ resp.status, resp.location() });
    }
    {
        const d = try inst.cli(&.{"devices"});
        _ = r.check("portal devices: none paired yet", d.code == 0 and d.has("No paired devices"), "code={d} out={s}", .{ d.code, d.out });
    }

    // ------------------------------------------------------ CLI validation
    {
        const p = try inst.cli(&.{ "pair", "Bad Name" });
        _ = r.check("portal pair rejects a bad device name", p.code != 0, "code={d}", .{p.code});
        const m = try inst.cli(&.{ "pair", "x", "--minutes", "11" });
        _ = r.check("portal pair rejects --minutes 11", m.code != 0, "code={d}", .{m.code});
        const t = try inst.cli(&.{"token"});
        _ = r.check("portal token explains it was replaced by pairing", t.code != 0 and t.has("pairing"), "code={d} out={s}", .{ t.code, t.out });
        const u = try inst.cli(&.{ "unpair", "nobody" });
        _ = r.check("portal unpair of an unknown device fails", u.code != 0, "code={d}", .{u.code});
    }

    // ------------------------- first pair: desk approval, racing request
    var c1: client.Creds = undefined;
    {
        const pc = try inst.liveCli(&.{ "pair", "laptop" });
        defer pc.deinit();
        _ = r.check("portal pair opens a window and waits at the desk", pc.waitFor("Waiting for the device", 15_000) and pc.alive(), "{s}", .{pc.output()});
        _ = r.check("portal pair prints the CA state (none yet with --no-tls)", pc.has("Portal CA"), "{s}", .{pc.output()});
        _ = r.check("pairing window becomes visible to the server", client.waitPairOpen(inst, 10_000), "", .{});
        _ = r.check("portal pair reports that this server has no certificate download (--no-tls)", pc.waitFor("--no-tls: no certificate download", 10_000), "{s}", .{pc.output()});
        {
            var resp = try get(inst, "/pair", null);
            defer resp.deinit();
            _ = r.check("pair page shows the button and device name", resp.bodyContains("type=\"submit\"") and resp.bodyContains("laptop"), "", .{});
            const d = try inst.cli(&.{"devices"});
            _ = r.check("portal devices shows the open window", d.has("Pairing window open for 'laptop'"), "{s}", .{d.out});
        }

        // A racing peer asks first (it polled the page and tapped quickly).
        var racer: ?client.PairReq = null;
        if (two_ips) {
            const rq = try client.requestPair(inst, other_ip);
            _ = r.check("racing peer only gets a pending request, no credential", rq.waiting() and rq.set_cookies == 1, "{d} {s} cookies={d}", .{ rq.status, rq.location(), rq.set_cookies });
            racer = rq;
            _ = r.check("desk is asked about the racing peer, with its address", pc.waitFor("from 127.0.0.2 (request ", 10_000), "{s}", .{pc.output()});
        } else r.skip("racing request from another address", "cannot connect from 127.0.0.2", .{});

        // The real device asks.
        const rq = try client.requestPair(inst, null);
        _ = r.check("POST /pair registers a request and sends the device to wait", rq.waiting() and rq.set_cookies == 1, "{d} {s} cookies={d}", .{ rq.status, rq.location(), rq.set_cookies });
        {
            const again = try client.requestPair(inst, null);
            _ = r.check("third request from the same address... (first: pending)", again.waiting(), "{d} {s}", .{ again.status, again.location() });
            const third = try client.requestPair(inst, null);
            _ = r.check("pending requests per address are bounded (busy)", std.mem.eql(u8, third.location(), "/pair?e=busy"), "{s}", .{third.location()});
        }
        // The first /pair/wait is answered at once; later ones are held
        // until the desk answers (long poll), so keep this page's code.
        var page_code: [4]u8 = @splat('?');
        {
            var resp = try client.waitPage(inst, rq.cookie(), null);
            defer resp.deinit();
            _ = r.check("waiting page: 200, refreshes itself, issues nothing", resp.status == 200 and resp.bodyContains("http-equiv=\"refresh\"") and
                resp.bodyContains("Request code") and resp.setCookieCount() == 0, "{d} cookies={d}", .{ resp.status, resp.setCookieCount() });
            const hc = resp.header("x-portal-request-code") orelse "";
            if (hc.len == 4 and resp.bodyContains(hc)) @memcpy(&page_code, hc);
            var resp2 = try client.waitPage(inst, rq.cookie(), other_ip);
            defer resp2.deinit();
            _ = r.check("a request token is bound to its address", !two_ips or (resp2.status == 303 and std.mem.eql(u8, resp2.location(), "/pair?e=expired")), "{d} {s}", .{ resp2.status, resp2.location() });
        }

        if (racer) |rc| {
            // The desk sees the racer first: deny it. The window stays open.
            _ = r.check("desk prompt for the racer", pc.waitForCount("[y/N]", 1, 10_000) and (pc.lastAfter("Pair 'laptop' from ", 9) != null), "{s}", .{pc.output()});
            const prompt_ip = pc.lastAfter("Pair 'laptop' from ", 9) orelse "";
            _ = r.check("first prompt is for the oldest request (the racer)", std.mem.eql(u8, prompt_ip, "127.0.0.2"), "{s}", .{prompt_ip});
            pc.answer("n\r\n");
            const got = try client.collect(inst, rc.cookie(), other_ip, 10_000);
            _ = r.check("denied request: clear page, no credential", refusedTo(got, "/pair?e=denied"), "{any}", .{got});
            _ = r.check("denying keeps the window open", pc.alive() and pc.waitFor("Denied request", 5000), "{s}", .{pc.output()});
            const again = try client.requestPair(inst, other_ip);
            _ = r.check("a denied address can't ask again in this window", std.mem.eql(u8, again.location(), "/pair?e=denied"), "{s}", .{again.location()});
        }

        // Now the real device's prompt; the code matches the device page.
        const n_prompts: usize = if (racer != null) 2 else 1;
        _ = r.check("desk prompt for the device", pc.waitForCount("[y/N]", n_prompts, 10_000), "{s}", .{pc.output()});
        const code = pc.lastAfter("(request ", 4) orelse "????";
        _ = r.check("device page shows the same request code as the desk", std.mem.eql(u8, &page_code, code), "page={s} desk={s}", .{ &page_code, code });
        // The page above was the first answer for this request; asking
        // again is held until the desk answers (no poll interval).
        var held: HeldWait = .{ .inst = inst, .cookie = rq.cookie() };
        const held_thread = try std.Thread.spawn(.{}, HeldWait.run, .{&held});
        net.sleep(1500);
        _ = r.check("a repeated /pair/wait is held while the desk has not answered (long poll)", !held.done.load(.acquire), "", .{});
        const t_answer = net.now();
        pc.answer("y\r\n");
        held_thread.join();
        _ = r.check("...and answered as soon as the desk approves", held.finished_at -| t_answer < 5000, "after {d} ms", .{held.finished_at -| t_answer});
        const got = try held.result;
        switch (got) {
            .creds => |c| c1 = c,
            else => {
                _ = r.check("approved device collects its credential", false, "{any}", .{got});
                return error.PairingFailed;
            },
        }
        const dv = c1.deviceValue();
        _ = r.check("approved device gets device + session cookies", std.mem.startsWith(u8, dv, "laptop.") and dv.len == "laptop.".len + 43 and c1.session_len == client.session_cookie.len + 1 + 43, "{s}", .{dv});
        _ = r.check("portal pair reports success and exits 0", pc.wait(10_000) == 0 and pc.has("Paired 'laptop' at 127.0.0.1"), "{s}", .{pc.output()});
        {
            const again = try client.collect(inst, rq.cookie(), null, 2000);
            _ = r.check("a request token is single-use", refusedTo(again, "/pair?e=expired"), "{any}", .{again});
            const late = try client.requestPair(inst, null);
            _ = r.check("pairing window is single-use", std.mem.eql(u8, late.location(), "/pair?e=closed") and late.set_cookies == 0, "{s}", .{late.location()});
        }
        _ = r.ok("approval logged", inst.logHas("approved at the desk"));
    }
    {
        // Cookie attributes of a freshly issued credential (one more pairing).
        _ = try inst.cli(&.{ "unpair", "laptop" });
        const pc = try inst.liveCli(&.{ "pair", "laptop" });
        defer pc.deinit();
        _ = pc.waitFor("Waiting for the device", 15_000);
        const seen = client.waitPairOpen(inst, 10_000);
        const rq = try client.requestPair(inst, null);
        if (!r.check("second pairing: request accepted", seen and rq.waiting(), "seen={} {d} {s}", .{ seen, rq.status, rq.location() })) {
            const text = try inst.log();
            std.debug.print("---- portal.log\n{s}\n----\n", .{text});
        }
        _ = pc.waitFor("[y/N]", 10_000);
        pc.answer("y\r\n");
        var resp: http.Response = undefined;
        var ok = false;
        const deadline = net.now() + 10_000;
        while (net.now() < deadline) {
            resp = try client.waitPage(inst, rq.cookie(), null);
            if (resp.status == 303) {
                ok = true;
                break;
            }
            resp.deinit();
            net.sleep(50);
        }
        if (ok) {
            defer resp.deinit();
            const dl = resp.setCookieLine(client.device_cookie) orelse "";
            const sl = resp.setCookieLine(client.session_cookie) orelse "";
            const ql = resp.setCookieLine(client.pairreq_cookie) orelse "";
            _ = r.check("cookies are HttpOnly, SameSite=Strict, Path=/", has(dl, "HttpOnly") and has(dl, "SameSite=Strict") and has(dl, "Path=/") and
                has(sl, "HttpOnly") and has(sl, "SameSite=Strict") and has(sl, "Path=/"), "{s} / {s} (303 to {s}; desk: {s})", .{ dl, sl, resp.location(), pc.output() });
            _ = r.check("device cookie lives 90 days, no Secure without TLS", has(dl, "Max-Age=7776000") and !has(dl, "Secure"), "{s}", .{dl});
            _ = r.check("the request cookie is cleared on success", has(ql, "Max-Age=0"), "{s}", .{ql});
            c1 = client.Creds.fromResponse(&resp) orelse return error.NoCookies;
        } else _ = r.check("second pairing completes", false, "{s}", .{pc.output()});
        _ = pc.wait(10_000);
    }
    {
        var resp = try get(inst, "/", c1.sessionCookie());
        defer resp.deinit();
        _ = r.check("session opens the viewer page", resp.status == 200 and resp.bodyContains("app.js"), "{d}", .{resp.status});
        _ = r.check("viewer page has CSP, nosniff, DENY, no-store", has(resp.header("content-security-policy") orelse "", "frame-ancestors 'none'") and
            std.mem.eql(u8, resp.header("x-content-type-options") orelse "", "nosniff") and
            std.mem.eql(u8, resp.header("x-frame-options") orelse "", "DENY") and
            std.mem.eql(u8, resp.header("cache-control") orelse "", "no-store"), "", .{});
    }

    // ------------------------------------------------ deny path, CLI exit
    {
        const pc = try inst.liveCli(&.{ "pair", "phone" });
        defer pc.deinit();
        _ = pc.waitFor("Waiting for the device", 15_000);
        _ = client.waitPairOpen(inst, 10_000);
        const rq = try client.requestPair(inst, null);
        _ = r.check("deny path: desk prompt", pc.waitFor("[y/N]", 10_000), "{s}", .{pc.output()});
        pc.answer("\r\n"); // Enter alone means No
        const got = try client.collect(inst, rq.cookie(), null, 10_000);
        _ = r.check("Enter alone denies: device told so, no credential", refusedTo(got, "/pair?e=denied"), "{any}", .{got});
        const d = try inst.cli(&.{"devices"});
        _ = r.check("denied device was not paired", !d.has("phone ") and d.has("request "), "{s}", .{d.out});
        _ = r.ok("denial logged", inst.logHas("denied at the desk"));
        // Killing `portal pair` closes the window at once (process watch).
        pc.kill();
        const t0 = net.now();
        var closed = false;
        while (net.now() - t0 < 5000) {
            var resp = try get(inst, "/pair", null);
            defer resp.deinit();
            if (!resp.bodyContains("type=\"submit\"")) {
                closed = true;
                break;
            }
            net.sleep(50);
        }
        _ = r.check("window closes as soon as `portal pair` exits", closed, "after {d} ms", .{net.now() - t0});
        const late = try client.requestPair(inst, null);
        _ = r.check("no requests after `portal pair` exited", std.mem.eql(u8, late.location(), "/pair?e=closed"), "{s}", .{late.location()});
    }

    // ------------------------------------------------ rotation and grace
    const c2 = (try client.signIn(inst, c1.deviceCookie())) orelse {
        _ = r.ok("device signs in silently and rotates", false);
        return error.SignInFailed;
    };
    _ = r.check("device signs in silently and rotates", !std.mem.eql(u8, c2.deviceValue(), c1.deviceValue()) and std.mem.startsWith(u8, c2.deviceValue(), "laptop."), "{s}", .{c2.deviceValue()});
    {
        var resp = try get(inst, "/", c2.sessionCookie());
        defer resp.deinit();
        _ = r.check("rotated sign-in gives a working session", resp.status == 200, "{d}", .{resp.status});
    }
    // c1 is now superseded: still valid during the grace period.
    const c3 = (try client.signIn(inst, c1.deviceCookie())) orelse {
        _ = r.ok("previous credential still valid in grace period", false);
        return error.SignInFailed;
    };
    _ = r.ok("previous credential still valid in grace period", true);
    {
        // ...and so is c2, which the sign-in above did not overwrite.
        const again = try client.signIn(inst, c2.deviceCookie());
        _ = r.check("a credential issued within the grace window survives a later sign-in with an older one", again != null, "", .{});
    }
    var c4: client.Creds = undefined;
    {
        var resp = try post(inst, "/auth/refresh", c3.deviceCookie(), true);
        defer resp.deinit();
        const creds = client.Creds.fromResponse(&resp);
        _ = r.check("native refresh: 204 with rotated cookies", resp.status == 204 and creds != null and
            !std.mem.eql(u8, creds.?.deviceValue(), c3.deviceValue()), "{d} cookies={d}", .{ resp.status, resp.setCookieCount() });
        c4 = creds orelse return error.NoCookies;
    }
    {
        var resp = try post(inst, "/auth/refresh", c4.deviceCookie(), false);
        defer resp.deinit();
        _ = r.check("refresh needs Origin", resp.status == 403, "{d}", .{resp.status});
        var resp2 = try post(inst, "/auth/refresh", null, true);
        defer resp2.deinit();
        _ = r.check("refresh without a device cookie is 401", resp2.status == 401, "{d}", .{resp2.status});
    }
    {
        const d = try inst.cli(&.{"devices"});
        _ = r.check("portal devices lists the device and its address", d.has("laptop") and d.has("127.0.0.1") and d.has("last used"), "{s}", .{d.out});
    }

    // ------------------- parallel sign-ins with the same credential (tabs)
    var cur: client.Creds = c4;
    {
        var jobs: [4]SignInJob = undefined;
        var threads: [4]?std.Thread = @splat(null);
        for (&jobs, &threads) |*j, *t| {
            j.* = .{ .inst = inst, .cookie = cur.deviceCookie() };
            t.* = std.Thread.spawn(.{}, SignInJob.run, .{j}) catch null;
        }
        for (threads) |t| if (t) |th| th.join();
        var ok: usize = 0;
        for (jobs) |j| {
            if (j.result != null) ok += 1;
        }
        _ = r.check("4 parallel sign-ins with the same device cookie all succeed", ok == jobs.len, "{d}/{d}", .{ ok, jobs.len });
        _ = r.ok("...and none revoked the device", !inst.logHas("DEVICE REVOKED"));
        var still: usize = 0;
        for (jobs) |j| if (j.result) |res| {
            var resp = try get(inst, "/", res.sessionCookie());
            defer resp.deinit();
            if (resp.status == 200) still += 1;
        };
        _ = r.check("every parallel sign-in's session works", still == ok, "{d}/{d}", .{ still, ok });
        if (jobs[jobs.len - 1].result) |res| cur = res;
        cur = (try client.signIn(inst, cur.deviceCookie())) orelse {
            _ = r.ok("device still signs in after parallel sign-ins", false);
            return error.SignInFailed;
        };
        _ = r.ok("device still signs in after parallel sign-ins", true);
    }

    // --------------------------------------------- wrong source address
    wrong_addr: {
        if (!two_ips) {
            r.skip("credential from another address is rejected", "cannot connect from 127.0.0.2", .{});
            break :wrong_addr;
        }
        var resp = try http.request(gpa, port, .{ .path = "/", .host = inst.host, .cookie = cur.deviceCookie(), .source = other_ip });
        defer resp.deinit();
        _ = r.check("credential from another address is rejected like an unknown one (not revoked)", resp.status == 303 and
            std.mem.eql(u8, resp.location(), "/pair"), "{d} {s}", .{ resp.status, resp.location() });
        _ = r.check("wrong-address attempt clears the cookies", has(resp.setCookieLine(client.device_cookie) orelse "", "Max-Age=0"), "", .{});
        cur = (try client.signIn(inst, cur.deviceCookie())) orelse {
            _ = r.ok("device still works from its own address", false);
            return error.SignInFailed;
        };
        _ = r.ok("device still works from its own address", true);
        _ = r.ok("wrong-address attempt logged (the distinction stays local)", inst.logHas("unexpected address"));

        // A session cookie is bound to the address it was issued to.
        var s1 = try http.request(gpa, port, .{ .path = "/", .host = inst.host, .cookie = cur.sessionCookie(), .source = other_ip });
        defer s1.deinit();
        _ = r.check("session cookie replayed from another address does not open the viewer", s1.status == 303 and
            std.mem.eql(u8, s1.location(), "/pair"), "{d} {s}", .{ s1.status, s1.location() });
        var s2 = try http.request(gpa, port, .{ .path = "/sync/index", .host = inst.host, .cookie = cur.sessionCookie(), .source = other_ip });
        defer s2.deinit();
        _ = r.check("session cookie replayed from another address gets no /sync", s2.status == 401, "{d}", .{s2.status});
        var s3 = try get(inst, "/", cur.sessionCookie());
        defer s3.deinit();
        _ = r.check("...and the session still works from its own address (refused, not revoked)", s3.status == 200, "{d}", .{s3.status});
    }

    // ------------------------ stale credential (out of the grace ring)
    {
        // Rotate enough times that c1 falls out of the 4-entry grace ring.
        var i: usize = 0;
        while (i < 5) : (i += 1) cur = (try client.signIn(inst, cur.deviceCookie())) orelse return error.SignInFailed;
        var resp = try get(inst, "/", c1.deviceCookie());
        defer resp.deinit();
        _ = r.check("a credential that fell out of the grace ring revokes the device", std.mem.eql(u8, resp.location(), "/pair?e=revoked"), "{d} {s}", .{ resp.status, resp.location() });
        var resp2 = try get(inst, "/", cur.deviceCookie());
        defer resp2.deinit();
        _ = r.check("revoked device's newest credential no longer works (told it is no longer paired)", std.mem.eql(u8, resp2.location(), "/pair?e=gone"), "{s}", .{resp2.location()});
        var resp3 = try post(inst, "/auth/refresh", cur.deviceCookie(), true);
        defer resp3.deinit();
        _ = r.check("revoked device's refresh is 401", resp3.status == 401, "{d}", .{resp3.status});
        var resp4 = try get(inst, "/", cur.sessionCookie());
        defer resp4.deinit();
        _ = r.check("revocation ends the device's sessions", resp4.status == 303, "{d}", .{resp4.status});
        _ = r.ok("revocation logged", inst.logHas("DEVICE REVOKED"));
    }

    // ------------------------------------------------- forged credential
    {
        const c6 = try client.pair(inst, "laptop");
        var forged_buf: [128]u8 = undefined;
        const forged = try std.fmt.bufPrint(&forged_buf, "portal_device=laptop.{s}", .{&rep(43, 'A')});
        var resp = try get(inst, "/", forged);
        defer resp.deinit();
        _ = r.check("forged credential revokes the device", std.mem.eql(u8, resp.location(), "/pair?e=revoked"), "{s}", .{resp.location()});
        var resp2 = try get(inst, "/", c6.deviceCookie());
        defer resp2.deinit();
        _ = r.check("real credential no longer works after a forgery", std.mem.eql(u8, resp2.location(), "/pair?e=gone"), "{s}", .{resp2.location()});
        var resp3 = try get(inst, "/", "portal_device=nosuchdevice." ++ &rep(43, 'B'));
        defer resp3.deinit();
        _ = r.check("unknown device name just goes to /pair", std.mem.eql(u8, resp3.location(), "/pair"), "{s}", .{resp3.location()});
        var resp4 = try get(inst, "/", "portal_session=" ++ &rep(43, 'A'));
        defer resp4.deinit();
        _ = r.check("forged session cookie is not accepted", resp4.status == 303 and std.mem.eql(u8, resp4.location(), "/pair"), "{d}", .{resp4.status});
    }

    // ------------- re-pairing a name removes the old record and its sessions
    {
        const old = try client.pair(inst, "laptop");
        const v = try client.Viewer.open(inst, old.sessionCookie());
        defer v.deinit();
        const fresh = try client.pair(inst, "laptop");
        // The old record's sessions end before the new credential is
        // issued, so the logout is already on its way when pair() returns.
        _ = r.check("re-pair: the old device's open viewer is told to log out at once", v.waitLogout(3000), "", .{});
        _ = r.check("re-pair: ...with reason \"replaced\" (it signs in again to learn more)", v.logout_reason == .replaced, "{t}", .{v.logout_reason});
        _ = r.check("re-pair: ...and its connection is closed", v.waitClose(12_000), "", .{});
        var resp = try get(inst, "/", old.sessionCookie());
        defer resp.deinit();
        _ = r.check("re-pair: the old session no longer opens the viewer", resp.status == 303 and std.mem.eql(u8, resp.location(), "/pair"), "{d} {s}", .{ resp.status, resp.location() });
        var resp2 = try get(inst, "/sync/index", old.sessionCookie());
        defer resp2.deinit();
        _ = r.check("re-pair: the old session gets no /sync", resp2.status == 401, "{d}", .{resp2.status});
        var resp3 = try get(inst, "/", fresh.sessionCookie());
        defer resp3.deinit();
        _ = r.check("re-pair: the new device's session works", resp3.status == 200, "{d}", .{resp3.status});
        _ = r.ok("re-pair logged with the old record's sessions ended", inst.logHas("re-pair: previous device record 'laptop' removed; 1 of its session(s) ended"));
        {
            // The old credential is told, unambiguously, that it is gone,
            // and does not revoke the new record (tombstone, not theft).
            var rr = try post(inst, "/auth/refresh", old.deviceCookie(), true);
            defer rr.deinit();
            _ = r.check("re-pair: the old credential's sign-in is 401 with X-Portal-Device: gone", rr.status == 401 and
                std.mem.eql(u8, rr.header("x-portal-device") orelse "", "gone"), "{d} {s}", .{ rr.status, rr.header("x-portal-device") orelse "-" });
            var still = try get(inst, "/", fresh.sessionCookie());
            defer still.deinit();
            _ = r.check("re-pair: ...and the new device is not revoked by it", still.status == 200, "{d}", .{still.status});
            var wa = try http.request(gpa, inst.port, .{ .method = "POST", .path = "/auth/refresh", .host = inst.host, .origin = inst.origin, .cookie = fresh.deviceCookie(), .body = "", .source = other_ip });
            defer wa.deinit();
            _ = r.check("a known device from another address is refused without the gone header", !two_ips or (wa.status == 401 and wa.header("x-portal-device") == null), "{d}", .{wa.status});
        }
        const d = try inst.cli(&.{"devices"});
        _ = r.check("re-pair: one 'laptop' record", std.mem.count(u8, d.out, "laptop ") == 1, "{s}", .{d.out});
    }

    // ----------------------------- unpair at the desk drops open viewers
    {
        const c7 = try client.pair(inst, "laptop");
        const v = try client.Viewer.open(inst, c7.sessionCookie());
        defer v.deinit();
        _ = r.ok("viewer connects after re-pair", true);
        const t0 = net.now();
        const u = try inst.cli(&.{ "unpair", "laptop" });
        _ = r.check("portal unpair succeeds", u.code == 0 and u.has("Unpaired"), "code={d} {s}", .{ u.code, u.out });
        const got = v.waitLogout(15_000);
        const dt = net.now() - t0;
        _ = r.check("open viewer told to log out after unpair", got, "after {d} ms", .{dt});
        _ = r.check("...with reason \"unpaired\" (the device forgets this desktop)", v.logout_reason == .unpaired, "{t}", .{v.logout_reason});
        {
            var rr = try post(inst, "/auth/refresh", c7.deviceCookie(), true);
            defer rr.deinit();
            _ = r.check("an unpaired device's sign-in is 401 with X-Portal-Device: gone", rr.status == 401 and
                std.mem.eql(u8, rr.header("x-portal-device") orelse "", "gone"), "{d}", .{rr.status});
        }
        _ = r.check("...promptly (event-driven, no polling interval)", dt < 3000, "{d} ms", .{dt});
        _ = r.check("viewer connection closed after logout", v.waitClose(12_000), "", .{});
        var resp = try get(inst, "/", c7.deviceCookie());
        defer resp.deinit();
        _ = r.check("unpaired device can't sign in (told it is no longer paired)", std.mem.eql(u8, resp.location(), "/pair?e=gone"), "{s}", .{resp.location()});
        _ = r.ok("desk unpair logged", inst.logHas("unpaired from the desktop"));
    }

    // ------------------- the device forgets this desktop: POST /device/forget
    {
        const cf = try client.pair(inst, "laptop");
        const v = try client.Viewer.open(inst, cf.sessionCookie());
        defer v.deinit();
        {
            var nos = try post(inst, "/device/forget", null, true);
            defer nos.deinit();
            _ = r.check("POST /device/forget needs a live session", nos.status == 401, "{d}", .{nos.status});
            var bad = try http.request(gpa, port, .{ .method = "POST", .path = "/device/forget", .host = inst.host, .origin = "http://evil.example", .cookie = cf.sessionCookie(), .body = "" });
            defer bad.deinit();
            _ = r.check("...and an allowed Origin", bad.status == 403, "{d}", .{bad.status});
        }
        var resp = try post(inst, "/device/forget", cf.sessionCookie(), true);
        defer resp.deinit();
        _ = r.check("POST /device/forget with the device's session: 204", resp.status == 204, "{d}", .{resp.status});
        _ = r.check("...its open viewer is told (logout, reason unpaired)", v.waitLogout(3000) and v.logout_reason == .unpaired, "{t}", .{v.logout_reason});
        const d = try inst.cli(&.{"devices"});
        _ = r.check("...the desktop no longer lists it", !d.has("laptop "), "{s}", .{d.out});
        _ = r.ok("...and logged it", inst.logHas("device 'laptop' forgot this desktop from"));
        var rr = try post(inst, "/auth/refresh", cf.deviceCookie(), true);
        defer rr.deinit();
        _ = r.check("...its credential then gets X-Portal-Device: gone", rr.status == 401 and std.mem.eql(u8, rr.header("x-portal-device") orelse "", "gone"), "{d}", .{rr.status});
    }

    // ------------------------------------------- self-unpair via /logout
    {
        const c8 = try client.pair(inst, "phone");
        var resp = try post(inst, "/logout", c8.sessionCookie(), true);
        defer resp.deinit();
        _ = r.check("POST /logout redirects to /pair?bye and clears both cookies", resp.status == 303 and std.mem.eql(u8, resp.location(), "/pair?bye") and
            has(resp.setCookieLine(client.device_cookie) orelse "", "Max-Age=0") and has(resp.setCookieLine(client.session_cookie) orelse "", "Max-Age=0"), "{d} {s}", .{ resp.status, resp.location() });
        const d = try inst.cli(&.{"devices"});
        _ = r.check("logout unpaired the device", d.has("No paired devices"), "{s}", .{d.out});
        var resp2 = try get(inst, "/", c8.deviceCookie());
        defer resp2.deinit();
        _ = r.check("logged-out device can't sign in (told it is no longer paired)", std.mem.eql(u8, resp2.location(), "/pair?e=gone"), "{s}", .{resp2.location()});
        var resp3 = try get(inst, "/", c8.sessionCookie());
        defer resp3.deinit();
        _ = r.check("logged-out session is gone", resp3.status == 303, "{d}", .{resp3.status});
    }
    {
        // Session expired (or Portal restarted): the device cookie alone
        // still unpairs the device, instead of claiming to.
        const c9 = try client.pair(inst, "tablet");
        var resp = try post(inst, "/logout", c9.deviceCookie(), true);
        defer resp.deinit();
        _ = r.check("logout without a live session still unpairs (device cookie)", std.mem.eql(u8, resp.location(), "/pair?bye"), "{s}", .{resp.location()});
        const d = try inst.cli(&.{"devices"});
        _ = r.check("...and the device is really gone", !d.has("tablet"), "{s}", .{d.out});
        var gone = try get(inst, "/", c9.deviceCookie());
        defer gone.deinit();
        _ = r.check("...and its credential is remembered as unpaired (told it is no longer paired)", std.mem.eql(u8, gone.location(), "/pair?e=gone"), "{s}", .{gone.location()});
        var resp2 = try post(inst, "/logout", null, true);
        defer resp2.deinit();
        _ = r.check("logout with nothing to unpair does not claim it did", std.mem.eql(u8, resp2.location(), "/pair"), "{s}", .{resp2.location()});
    }

    // ------------------------------- restart: sessions are memory-only
    {
        const c9 = try client.pair(inst, "laptop");
        const revoked_before = logCount(inst, "DEVICE REVOKED");
        _ = r.ok("server alive before restart", inst.alive() and client.alive(inst));
        inst.kill();
        inst = try proc.Instance.start(h, dir, port + 5, &ping_child);
        var resp = try get(inst, "/", c9.sessionCookie());
        defer resp.deinit();
        _ = r.check("after a restart the old session is gone", resp.status == 303 and std.mem.eql(u8, resp.location(), "/pair"), "{d} {s}", .{ resp.status, resp.location() });
        // Two tabs reopening at once after the restart: neither revokes.
        var jobs: [2]SignInJob = .{ .{ .inst = inst, .cookie = c9.deviceCookie() }, .{ .inst = inst, .cookie = c9.deviceCookie() } };
        var threads: [2]?std.Thread = @splat(null);
        for (&jobs, &threads) |*j, *t| t.* = std.Thread.spawn(.{}, SignInJob.run, .{j}) catch null;
        for (threads) |t| if (t) |th| th.join();
        _ = r.check("after a restart, two tabs sign in silently at once", jobs[0].result != null and jobs[1].result != null, "", .{});
        if (jobs[0].result) |c| {
            var resp2 = try get(inst, "/", c.sessionCookie());
            defer resp2.deinit();
            _ = r.check("...and their new sessions work", resp2.status == 200, "{d}", .{resp2.status});
        }
        _ = r.ok("...without revoking the device", logCount(inst, "DEVICE REVOKED") == revoked_before);
    }

    r.skip("pairing window expiry", "shortest window is 1 minute; covered by devices.zig unit tests", .{});
    _ = r.ok("portal still running at end of group", inst.alive() and client.alive(inst));
    inst.kill();
}
