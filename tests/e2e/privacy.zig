//! Privacy: the web API must never reveal the desktop's file system, folder
//! names or other projects, to anyone. Sniffers on the path only ever see
//! WireGuard (and, with TLS, also TLS) ciphertext; these checks cover what a
//! client that reaches the port can learn:
//!   * no route serves anything from disk; path-traversal and guessed URLs
//!     get nothing, with or without a session;
//!   * nothing Portal itself sends (headers, pages, assets incl. the wasm
//!     binary, WebSocket text messages) contains file-system paths, the data
//!     directory, the user name or the session's working folder. The
//!     terminal grid is exempt: showing the session is its purpose;
//!   * without a session, nothing about the session is visible at all.

const std = @import("std");
const proc = @import("proc.zig");
const client = @import("client.zig");
const pairing = @import("pairing.zig");
const http = @import("http.zig");
const Runner = @import("runner.zig").Runner;
const tabs_wire = @import("shared").tabs;

const get = client.get;

/// Routes that may answer 200, by design.
const public_ok = [_][]const u8{ "/pair", "/static/app.js", "/static/app.css", "/static/app.wasm" };
const session_ok = [_][]const u8{"/"};

const probes = [_][]const u8{
    "/..",                            "/../",                           "/../../../../",
    "/static/../src/main.zig",        "/static/..%2fsrc%2fmain.zig",    "/%2e%2e/%2e%2e/",
    "/%2E%2E%2F%2E%2E%2F",            "/static/app.js/..",              "/static/",
    "/static",                        "/static/app.wasm/../../../",     "/static/./app.js",
    "/static//app.js",                "/.git/config",                   "/.git/HEAD",
    "/portal.log",                    "/devices.txt",                   "/devices.lock",
    "/token.sha256",                  "/Portal/portal.log",             "/tls/ca.key",
    "/tls/leaf.key",                  "/src/main.zig",                  "/build.zig",
    "/README.md",                     "/C:/Windows/win.ini",            "/C:\\Windows\\win.ini",
    "/\\..\\..\\",                    "/..\\..\\Windows\\win.ini",      "/etc/passwd",
    "/api",                           "/api/projects",                  "/api/sessions",
    "/api/files",                     "/projects",                      "/sessions",
    "/recent",                        "/files",                         "/fs",
    "/ls",                            "/tree",                          "/dir",
    "/open",                          "/cwd",                           "/home",
    "/sync/update",                   "/sync/bundle",                   "/stt/transcribe",
    "/ws/../pair",                    "//",                             "///etc/passwd",
    "/pair/..",                       "/pair/../static/app.js",         "/PAIR",
    "/Static/app.js",                 "/static/APP.JS",                 "/favicon.ico",
    "/index.html",                    "/static/index.html",             "/static/pair.html",
    "/static/fonts/DejaVuSansMono.ttf", "/static/app.js.map",           "/static/app.wasm.map",
    "/?path=C:\\Users",               "/pair?dir=..",                   "/static/app.js?../../",
};

fn allowed(target: []const u8, list: []const []const u8) bool {
    // Query strings are ignored by the server (exact-path routing), so
    // "/pair?dir=.." is just the pairing page.
    const path = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;
    for (list) |p| if (std.mem.eql(u8, p, path)) return true;
    return false;
}

pub const Leaks = struct {
    needles: std.ArrayList([]const u8) = .empty,
    gpa: std.mem.Allocator,

    pub fn add(l: *Leaks, s: []const u8) !void {
        if (s.len >= 4) try l.needles.append(l.gpa, s);
    }

    /// First needle found (case-insensitive), or null.
    pub fn find(l: *const Leaks, data: []const u8) ?[]const u8 {
        for (l.needles.items) |n| if (client.containsIgnoreCase(data, n)) return n;
        return null;
    }

    pub fn deinit(l: *Leaks) void {
        l.needles.deinit(l.gpa);
    }

    /// What must never appear in anything Portal sends outside the grid,
    /// for an instance whose LOCALAPPDATA is `dir`.
    pub fn standard(h: *proc.Harness, dir: []const u8) !Leaks {
        var l: Leaks = .{ .gpa = h.gpa };
        errdefer l.deinit();
        try l.add(dir);
        try l.add(h.root);
        try l.add("\\Portal\\");
        try l.add("LOCALAPPDATA");
        try l.add("USERPROFILE");
        try l.add(":\\Users\\");
        try l.add(":/Users/");
        try l.add("\\AppData\\");
        try l.add("\\code\\zig");
        try l.add("/code/zig");
        if (h.env.get("USERPROFILE")) |v| try l.add(v);
        if (h.env.get("USERNAME")) |v| if (v.len >= 4) try l.add(v);
        if (h.env.get("COMPUTERNAME")) |v| try l.add(v);
        return l;
    }
};

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("privacy");
    const inst = try proc.Instance.start(h, dir, port, &pairing.ping_child);
    defer inst.kill();

    // What must never appear in anything Portal sends outside the grid.
    var leaks = try Leaks.standard(h, dir);
    defer leaks.deinit();

    // Without a session: nothing about the session is visible.
    {
        var resp = try get(inst, "/", null);
        defer resp.deinit();
        _ = r.check("no session: / reveals nothing (redirect to /pair, empty body)", resp.status == 303 and std.mem.eql(u8, resp.location(), "/pair") and resp.body.len == 0, "{d} {s} body={d}", .{ resp.status, resp.location(), resp.body.len });
    }

    // Every probe, without and then with a session: no 200 unless it is an
    // exact route, and nothing path-like in any response.
    const creds = try client.pair(inst, "privacy");
    const sess = creds.sessionCookie();
    var bad_status: usize = 0;
    var leaked: usize = 0;
    var first_bad: [160]u8 = undefined;
    var first_bad_len: usize = 0;
    var first_leak: [160]u8 = undefined;
    var first_leak_len: usize = 0;
    for ([_]?[]const u8{ null, sess }) |cookie| {
        for (probes) |p| {
            var resp = get(inst, p, cookie) catch continue; // a reset is fine: it served nothing
            defer resp.deinit();
            const ok_route = allowed(p, &public_ok) or (cookie != null and allowed(p, &session_ok));
            const status_ok = if (ok_route) true else switch (resp.status) {
                400, 404, 421 => true,
                303 => std.mem.startsWith(u8, resp.location(), "/pair"),
                else => false,
            };
            if (!status_ok) {
                bad_status += 1;
                if (first_bad_len == 0) first_bad_len = note(&first_bad, "{s} -> {d}", .{ p, resp.status });
            }
            if (leaks.find(resp.raw)) |n| {
                leaked += 1;
                if (first_leak_len == 0) first_leak_len = note(&first_leak, "{s} leaked '{s}'", .{ p, n });
            }
        }
    }
    _ = r.check("traversal / guessed URLs never served (with or without session)", bad_status == 0, "{d} bad; first: {s}", .{ bad_status, first_bad[0..first_bad_len] });
    _ = r.check("no path, user or data-dir names in any probe response", leaked == 0, "{d}; first: {s}", .{ leaked, first_leak[0..first_leak_len] });

    // Every legitimate page and asset, including the wasm binary, is free of
    // build-machine paths and user names (e.g. embedded source file paths).
    {
        var dirty: usize = 0;
        var first: [160]u8 = undefined;
        var first_len: usize = 0;
        const pages = public_ok ++ session_ok;
        for (pages) |p| {
            var resp = try get(inst, p, sess);
            defer resp.deinit();
            if (resp.status != 200) {
                dirty += 1;
                if (first_len == 0) first_len = note(&first, "{s} -> {d}", .{ p, resp.status });
                continue;
            }
            if (leaks.find(resp.raw)) |n| {
                dirty += 1;
                if (first_len == 0) first_len = note(&first, "{s} contains '{s}'", .{ p, n });
            }
        }
        _ = r.check("pages and assets (incl. app.wasm) contain no paths or user names", dirty == 0, "{s}", .{first[0..first_len]});
    }

    // Pairing pages while a window is open show only the device name (and,
    // to the requesting device, its own address and request code).
    {
        const pc = try inst.liveCli(&.{ "pair", "phone" });
        defer pc.deinit();
        _ = pc.waitFor("Waiting for the device", 15_000);
        _ = client.waitPairOpen(inst, 10_000);
        var resp = try get(inst, "/pair", null);
        defer resp.deinit();
        _ = r.check("open pairing window reveals only the device name", resp.bodyContains("phone") and leaks.find(resp.raw) == null, "{?s}", .{leaks.find(resp.raw)});
        const rq = try client.requestPair(inst, null);
        var wait = try client.waitPage(inst, rq.cookie(), null);
        defer wait.deinit();
        _ = r.check("waiting page reveals no paths or names", wait.status == 200 and leaks.find(wait.raw) == null, "{d} {?s}", .{ wait.status, leaks.find(wait.raw) });
    }

    // Protocol text messages carry no paths (the grid is exempt by design).
    {
        const v = try client.Viewer.open(inst, sess);
        defer v.deinit();
        const hello = v.helloText();
        _ = r.check("hello message has no paths or names", hello.len > 0 and leaks.find(hello) == null, "{s}", .{hello});
        // v2: the input mode, the tab's display name (the folder's name,
        // never a path), its random id, and the open tabs: nothing else.
        const list = tabs_wire.parseList(hello);
        const id = tabs_wire.idField(hello, "session");
        _ = r.check("hello carries the input mode, the tab list and the tab shown, nothing else", std.mem.startsWith(u8, hello, "{\"t\":\"hello\",\"v\":2,\"input\":\"keys\",\"project\":\"") and
            list != null and list.?.len == 1 and id != null and list.?.find(id.?) != null and
            std.mem.indexOfScalar(u8, list.?.items[0].name(), '\\') == null and std.mem.indexOfScalar(u8, list.?.items[0].name(), '/') == null and
            std.mem.indexOfScalar(u8, list.?.items[0].name(), ':') == null, "{s}", .{hello});
    }

    // Without a session, the stream is refused before any data.
    {
        var resp = try http.request(gpa, inst.port, .{
            .path = "/ws",
            .host = inst.host,
            .origin = inst.origin,
            .extra = &.{
                .{ .name = "Upgrade", .value = "websocket" },
                .{ .name = "Connection", .value = "Upgrade" },
                .{ .name = "Sec-WebSocket-Key", .value = "dGhlIHNhbXBsZSBub25jZQ==" },
                .{ .name = "Sec-WebSocket-Version", .value = "13" },
            },
        });
        defer resp.deinit();
        _ = r.check("no session: websocket refused (401), nothing streamed", resp.status == 401, "{d}", .{resp.status});
    }

    _ = r.ok("portal still running at end of group", inst.alive() and client.alive(inst));
}

/// Formats a failure note into `buf`; returns its length (0 if it didn't fit).
fn note(buf: []u8, comptime fmt: []const u8, args: anytype) usize {
    return (std.fmt.bufPrint(buf, fmt, args) catch return 0).len;
}
