//! Portal-specific client helpers shared by the scenario groups: pairing a
//! device, signing in, and a WebSocket viewer that tracks the grid.

const std = @import("std");
const Allocator = std.mem.Allocator;
const net = @import("net.zig");
const http = @import("http.zig");
const ws = @import("ws.zig");
const grid = @import("grid.zig");
const proc = @import("proc.zig");

pub const Instance = proc.Instance;

pub const device_cookie = "portal_device";
pub const session_cookie = "portal_session";

/// GET with an optional Cookie header value.
pub fn get(inst: *Instance, path: []const u8, cookie: ?[]const u8) !http.Response {
    return http.request(inst.h.gpa, inst.port, .{ .path = path, .host = inst.host, .cookie = cookie });
}

/// Empty-bodied POST; `origin` false omits the Origin header.
pub fn post(inst: *Instance, path: []const u8, cookie: ?[]const u8, origin: bool) !http.Response {
    return http.request(inst.h.gpa, inst.port, .{
        .method = "POST",
        .path = path,
        .host = inst.host,
        .origin = if (origin) inst.origin else null,
        .cookie = cookie,
        .body = "",
    });
}

/// A device's credentials, as Cookie header values ("name=value").
pub const Creds = struct {
    device: [128]u8 = undefined,
    device_len: usize = 0,
    session: [96]u8 = undefined,
    session_len: usize = 0,

    pub fn deviceCookie(c: *const Creds) []const u8 {
        return c.device[0..c.device_len];
    }
    pub fn sessionCookie(c: *const Creds) []const u8 {
        return c.session[0..c.session_len];
    }
    /// The bare device value "<name>.<secret>".
    pub fn deviceValue(c: *const Creds) []const u8 {
        return c.deviceCookie()[device_cookie.len + 1 ..];
    }

    /// Fills from a response's Set-Cookie headers; false if either is missing.
    pub fn fromResponse(r: *const http.Response) ?Creds {
        var c: Creds = .{};
        const d = r.cookie(device_cookie) orelse return null;
        const s = r.cookie(session_cookie) orelse return null;
        if (d.len == 0 or s.len == 0) return null;
        c.device_len = (std.fmt.bufPrint(&c.device, "{s}={s}", .{ device_cookie, d }) catch return null).len;
        c.session_len = (std.fmt.bufPrint(&c.session, "{s}={s}", .{ session_cookie, s }) catch return null).len;
        return c;
    }
};

/// `portal pair <name>` then POST /pair.
pub fn pair(inst: *Instance, name: []const u8) !Creds {
    const res = try inst.cli(&.{ "pair", name });
    inst.h.gpa.free(res.out);
    if (res.code != 0) return error.PairCommandFailed;
    var r = try post(inst, "/pair", null, true);
    defer r.deinit();
    if (r.status != 303 or !std.mem.eql(u8, r.location(), "/")) return error.PairingRefused;
    return Creds.fromResponse(&r) orelse error.NoCookies;
}

/// Device sign-in (GET / with only the device cookie). Returns the new
/// credentials, or null if the server sent the device elsewhere.
pub fn signIn(inst: *Instance, device: []const u8) !?Creds {
    var r = try get(inst, "/", device);
    defer r.deinit();
    if (r.status != 303 or !std.mem.eql(u8, r.location(), "/")) return null;
    return Creds.fromResponse(&r);
}

pub const Viewer = struct {
    c: ws.Client,
    g: grid.Grid,
    hello: [96]u8 = undefined,
    hello_len: usize = 0,
    /// The first message was the hello text frame.
    hello_first: bool = false,
    /// The first grid frame was a full snapshot.
    first_full: bool = false,
    got_logout: bool = false,
    got_exit: bool = false,
    closed: bool = false,
    close_payload: [2]u8 = .{ 0, 0 },
    pongs: usize = 0,
    last_pong: [128]u8 = undefined,
    last_pong_len: usize = 0,
    /// First decode or framing error seen (frames must all be valid).
    bad: ?anyerror = null,
    last_frame_ms: u64 = 0,
    trace: bool = false,

    /// Upgrades, reads hello and the first grid frame.
    pub fn open(inst: *Instance, session: []const u8) !*Viewer {
        const gpa = inst.h.gpa;
        const v = try gpa.create(Viewer);
        errdefer gpa.destroy(v);
        v.* = .{
            .c = try ws.Client.connect(gpa, inst.port, .{ .host = inst.host, .origin = inst.origin, .cookie = session }),
            .g = grid.Grid.init(gpa),
        };
        errdefer v.c.close();
        if (v.c.status != 101) return error.NotUpgraded;
        const deadline = net.now() + 10_000;
        var n: usize = 0;
        while (v.g.frames == 0) {
            const t = net.now();
            if (t >= deadline or v.closed) return error.NoSnapshot;
            const f = v.c.next(@intCast(deadline - t)) catch |err| return err;
            if (n == 0) v.hello_first = f.op == .text and std.mem.indexOf(u8, f.payload, "\"hello\"") != null;
            n += 1;
            v.handle(f);
            if (v.g.frames == 1) v.first_full = v.g.full_frames == 1;
        }
        return v;
    }

    pub fn deinit(v: *Viewer) void {
        const gpa = v.c.gpa;
        v.c.close();
        v.g.deinit();
        gpa.destroy(v);
    }

    pub fn helloText(v: *const Viewer) []const u8 {
        return v.hello[0..v.hello_len];
    }

    fn handle(v: *Viewer, f: ws.Frame) void {
        v.last_frame_ms = net.now();
        switch (f.op) {
            .text => {
                const p = f.payload;
                if (std.mem.indexOf(u8, p, "\"hello\"") != null) {
                    const n = @min(p.len, v.hello.len);
                    @memcpy(v.hello[0..n], p[0..n]);
                    v.hello_len = n;
                } else if (std.mem.indexOf(u8, p, "\"logout\"") != null) {
                    v.got_logout = true;
                } else if (std.mem.indexOf(u8, p, "\"exit\"") != null) {
                    v.got_exit = true;
                }
            },
            .binary => if (v.g.apply(f.payload)) |a| {
                if (v.trace) std.debug.print("  frame +{d}ms rows={d} full={} cursor={d},{d}\n", .{ net.now() % 100000, a.n_rows, a.full, v.g.cursor_x, v.g.cursor_y });
            } else |err| {
                if (v.bad == null) v.bad = err;
            },
            .pong => {
                v.pongs += 1;
                const n = @min(f.payload.len, v.last_pong.len);
                @memcpy(v.last_pong[0..n], f.payload[0..n]);
                v.last_pong_len = n;
            },
            .close => {
                v.closed = true;
                if (f.payload.len >= 2) v.close_payload = f.payload[0..2].*;
            },
            else => {},
        }
    }

    /// Processes frames for up to `ms`, or until `stop(v)` is true.
    pub fn pumpUntil(v: *Viewer, ms: u32, ctx: anytype, comptime stop: fn (@TypeOf(ctx), *Viewer) bool) bool {
        const deadline = net.now() + ms;
        while (true) {
            if (stop(ctx, v)) return true;
            if (v.closed) return false;
            const t = net.now();
            if (t >= deadline) return false;
            const f = v.c.next(@intCast(@min(deadline - t, 200))) catch |err| switch (err) {
                error.Timeout => continue,
                error.Closed => {
                    v.closed = true;
                    return stop(ctx, v);
                },
                else => {
                    if (v.bad == null) v.bad = err;
                    v.closed = true;
                    return false;
                },
            };
            v.handle(f);
        }
    }

    fn never(_: void, _: *Viewer) bool {
        return false;
    }

    pub fn pump(v: *Viewer, ms: u32) void {
        _ = v.pumpUntil(ms, {}, never);
    }

    pub fn waitFor(v: *Viewer, needle: []const u8, ms: u32) bool {
        return v.pumpUntil(ms, needle, struct {
            fn f(n: []const u8, vv: *Viewer) bool {
                return vv.g.find(n) != null;
            }
        }.f);
    }

    /// Waits until no frame has arrived for `quiet_ms` (output settled).
    pub fn settle(v: *Viewer, quiet_ms: u32, max_ms: u32) bool {
        v.last_frame_ms = net.now();
        return v.pumpUntil(max_ms, quiet_ms, struct {
            fn f(q: u32, vv: *Viewer) bool {
                return net.now() -| vv.last_frame_ms >= q;
            }
        }.f);
    }

    pub fn waitLogout(v: *Viewer, ms: u32) bool {
        return v.pumpUntil(ms, {}, struct {
            fn f(_: void, vv: *Viewer) bool {
                return vv.got_logout;
            }
        }.f);
    }

    pub fn waitClose(v: *Viewer, ms: u32) bool {
        _ = v.pumpUntil(ms, {}, never);
        return v.closed;
    }

    /// Sends a ping and waits for the matching pong.
    pub fn ping(v: *Viewer, payload: []const u8, ms: u32) bool {
        const before = v.pongs;
        v.c.send(.ping, payload) catch return false;
        const Ctx = struct { before: usize, p: []const u8 };
        return v.pumpUntil(ms, Ctx{ .before = before, .p = payload }, struct {
            fn f(c: Ctx, vv: *Viewer) bool {
                return vv.pongs > c.before and std.mem.eql(u8, vv.last_pong[0..vv.last_pong_len], c.p);
            }
        }.f);
    }

    pub fn send(v: *Viewer, msg: []const u8) void {
        v.c.sendText(msg) catch {};
    }

    /// Trimmed text of the cursor row.
    pub fn cursorLine(v: *const Viewer) []const u8 {
        return std.mem.trimEnd(u8, v.g.cursorRow(), " ");
    }

    pub fn dump(v: *const Viewer, buf: []u8) []const u8 {
        return v.g.dump(buf);
    }
};

/// The server answers a plain GET /pair (used as a liveness probe).
pub fn alive(inst: *Instance) bool {
    var r = get(inst, "/pair", null) catch return false;
    defer r.deinit();
    return r.status == 200;
}

/// `n` copies of `c` (comptime; `**` on strings is gone in Zig 0.18).
pub fn rep(comptime n: usize, comptime c: u8) [n]u8 {
    return @splat(c);
}

pub fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    for (0..haystack.len - needle.len + 1) |i| {
        if (std.ascii.eqlIgnoreCase(haystack[i..][0..needle.len], needle)) return true;
    }
    return false;
}
