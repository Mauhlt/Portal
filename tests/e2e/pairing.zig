//! Device pairing, sign-in, rotation, revocation and the device CLI
//! (ported from pair_smoke.py, extended).

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

fn has(s: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, s, needle) != null;
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("pairing");
    var inst = try proc.Instance.start(h, dir, port, &ping_child);

    // ------------------------------------------------ before any pairing
    {
        var resp = try get(inst, "/", null);
        defer resp.deinit();
        _ = r.check("unpaired visitor is sent to /pair", resp.status == 303 and std.mem.eql(u8, resp.location(), "/pair"), "{d} {s}", .{ resp.status, resp.location() });
    }
    {
        var resp = try get(inst, "/pair", null);
        defer resp.deinit();
        _ = r.check("pair page explains the desk step (no button)", resp.status == 200 and resp.bodyContains("portal pair") and !resp.bodyContains("type=\"submit\""), "{d}", .{resp.status});
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

    // --------------------------------------------------------- first pair
    {
        const p = try inst.cli(&.{ "pair", "laptop" });
        _ = r.check("portal pair opens a window", p.code == 0 and p.has("Pairing open"), "code={d} out={s}", .{ p.code, p.out });
    }
    {
        var resp = try get(inst, "/pair", null);
        defer resp.deinit();
        _ = r.check("pair page shows the button and device name", resp.bodyContains("Pair this device") and resp.bodyContains("laptop"), "", .{});
        const d = try inst.cli(&.{"devices"});
        _ = r.check("portal devices shows the open window", d.has("Pairing window open for 'laptop'"), "{s}", .{d.out});
    }
    var c1: client.Creds = undefined;
    {
        var resp = try post(inst, "/pair", null, true);
        defer resp.deinit();
        const creds = client.Creds.fromResponse(&resp);
        const dv = resp.cookie(client.device_cookie) orelse "";
        const sv = resp.cookie(client.session_cookie) orelse "";
        _ = r.check("pairing issues device + session cookies", resp.status == 303 and std.mem.eql(u8, resp.location(), "/") and
            std.mem.startsWith(u8, dv, "laptop.") and dv.len == "laptop.".len + 43 and sv.len == 43, "{d} {s} dev={s} sess={s}", .{ resp.status, resp.location(), dv, sv });
        const dl = resp.setCookieLine(client.device_cookie) orelse "";
        const sl = resp.setCookieLine(client.session_cookie) orelse "";
        _ = r.check("cookies are HttpOnly, SameSite=Strict, Path=/", has(dl, "HttpOnly") and has(dl, "SameSite=Strict") and has(dl, "Path=/") and
            has(sl, "HttpOnly") and has(sl, "SameSite=Strict") and has(sl, "Path=/"), "{s} / {s}", .{ dl, sl });
        _ = r.check("device cookie lives 90 days, no Secure without --https", has(dl, "Max-Age=7776000") and !has(dl, "Secure"), "{s}", .{dl});
        c1 = creds orelse return error.NoCookies;
    }
    {
        var resp = try post(inst, "/pair", null, true);
        defer resp.deinit();
        _ = r.check("pairing window is single-use", std.mem.eql(u8, resp.location(), "/pair?e=closed") and resp.setCookieCount() == 0, "{s}", .{resp.location()});
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
    // c1 is now the previous secret: still valid during the grace period.
    const c3 = (try client.signIn(inst, c1.deviceCookie())) orelse {
        _ = r.ok("previous credential still valid in grace period", false);
        return error.SignInFailed;
    };
    _ = r.ok("previous credential still valid in grace period", true);
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

    // --------------------------------------------- wrong source address
    var c5: client.Creds = c4;
    wrong_addr: {
        var resp = http.request(gpa, port, .{ .path = "/", .host = inst.host, .cookie = c4.deviceCookie(), .source = .{ 127, 0, 0, 2 } }) catch |err| {
            r.skip("credential from another address is rejected", "cannot connect from 127.0.0.2: {t}", .{err});
            break :wrong_addr;
        };
        defer resp.deinit();
        _ = r.check("credential from another address is rejected (not revoked)", resp.status == 303 and
            std.mem.eql(u8, resp.location(), "/pair?e=address"), "{d} {s}", .{ resp.status, resp.location() });
        _ = r.check("wrong-address attempt clears the cookies", has(resp.setCookieLine(client.device_cookie) orelse "", "Max-Age=0"), "", .{});
        c5 = (try client.signIn(inst, c4.deviceCookie())) orelse {
            _ = r.ok("device still works from its own address", false);
            return error.SignInFailed;
        };
        _ = r.ok("device still works from its own address", true);
        _ = r.ok("wrong-address attempt logged", inst.logHas("unexpected address"));
    }

    // ------------------------------- stale credential (older than grace)
    {
        // c2's secret was replaced twice since: neither current nor previous.
        var resp = try get(inst, "/", c2.deviceCookie());
        defer resp.deinit();
        _ = r.check("stale (twice-rotated) credential revokes the device", std.mem.eql(u8, resp.location(), "/pair?e=revoked"), "{d} {s}", .{ resp.status, resp.location() });
        var resp2 = try get(inst, "/", c5.deviceCookie());
        defer resp2.deinit();
        _ = r.check("revoked device's newest credential no longer works", std.mem.eql(u8, resp2.location(), "/pair"), "{s}", .{resp2.location()});
        var resp3 = try post(inst, "/auth/refresh", c5.deviceCookie(), true);
        defer resp3.deinit();
        _ = r.check("revoked device's refresh is 401", resp3.status == 401, "{d}", .{resp3.status});
        var resp4 = try get(inst, "/", c5.sessionCookie());
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
        _ = r.check("real credential no longer works after a forgery", std.mem.eql(u8, resp2.location(), "/pair"), "{s}", .{resp2.location()});
        var resp3 = try get(inst, "/", "portal_device=nosuchdevice." ++ &rep(43, 'B'));
        defer resp3.deinit();
        _ = r.check("unknown device name just goes to /pair", std.mem.eql(u8, resp3.location(), "/pair"), "{s}", .{resp3.location()});
        var resp4 = try get(inst, "/", "portal_session=" ++ &rep(43, 'A'));
        defer resp4.deinit();
        _ = r.check("forged session cookie is not accepted", resp4.status == 303 and std.mem.eql(u8, resp4.location(), "/pair"), "{d}", .{resp4.status});
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
        _ = r.check("...within the 5 s recheck (+slack)", dt < 12_000, "{d} ms", .{dt});
        _ = r.check("viewer connection closed after logout", v.waitClose(5000), "", .{});
        var resp = try get(inst, "/", c7.deviceCookie());
        defer resp.deinit();
        _ = r.check("unpaired device can't sign in", std.mem.eql(u8, resp.location(), "/pair"), "{s}", .{resp.location()});
        _ = r.ok("desk unpair logged", inst.logHas("unpaired from the desktop"));
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
        _ = r.check("logged-out device can't sign in", std.mem.eql(u8, resp2.location(), "/pair"), "{s}", .{resp2.location()});
        var resp3 = try get(inst, "/", c8.sessionCookie());
        defer resp3.deinit();
        _ = r.check("logged-out session is gone", resp3.status == 303, "{d}", .{resp3.status});
    }

    // ------------------------------- restart: sessions are memory-only
    {
        const c9 = try client.pair(inst, "laptop");
        _ = r.ok("server alive before restart", inst.alive() and client.alive(inst));
        inst.kill();
        inst = try proc.Instance.start(h, dir, port + 5, &ping_child);
        var resp = try get(inst, "/", c9.sessionCookie());
        defer resp.deinit();
        _ = r.check("after a restart the old session is gone", resp.status == 303 and std.mem.eql(u8, resp.location(), "/pair"), "{d} {s}", .{ resp.status, resp.location() });
        const c10 = try client.signIn(inst, c9.deviceCookie());
        _ = r.check("after a restart the device signs in silently", c10 != null, "", .{});
        if (c10) |c| {
            var resp2 = try get(inst, "/", c.sessionCookie());
            defer resp2.deinit();
            _ = r.check("...and its new session works", resp2.status == 200, "{d}", .{resp2.status});
        }
    }

    r.skip("pairing window expiry", "shortest window is 1 minute; covered by devices.zig unit tests", .{});
    _ = r.ok("portal still running at end of group", inst.alive() and client.alive(inst));
    inst.kill();
}
