//! Portal-specific client helpers shared by the scenario groups: pairing
//! an in-process device (proc.Instance.pair: its own WireGuard key and
//! tunnel, link.zig) and a WebSocket viewer that tracks the grid. A device
//! is its tunnel key: there are no cookies or sign-in.

const std = @import("std");
const Allocator = std.mem.Allocator;
const net = @import("net.zig");
const http = @import("http.zig");
const ws = @import("ws.zig");
const grid = @import("grid.zig");
const proc = @import("proc.zig");

pub const Instance = proc.Instance;

/// A paired device, as the groups use it: `sessionCookie()` names the
/// device for Viewer.open (it picks that device's tunnel).
pub const Creds = struct {
    name_buf: [32]u8 = undefined,
    name_len: usize = 0,

    pub fn sessionCookie(c: *const Creds) []const u8 {
        return c.name_buf[0..c.name_len];
    }
    pub fn deviceCookie(c: *const Creds) []const u8 {
        return c.sessionCookie();
    }
};

/// Pairs a new in-process device called `name` at the desk (see
/// proc.Instance.pair).
pub fn pair(inst: *Instance, name: []const u8) !Creds {
    _ = try inst.pair(name);
    var c: Creds = .{};
    c.name_len = @min(name.len, c.name_buf.len);
    @memcpy(c.name_buf[0..c.name_len], name[0..c.name_len]);
    return c;
}

pub const Viewer = struct {
    c: ws.Client,
    g: grid.Grid,
    hello: [4096]u8 = undefined,
    hello_len: usize = 0,
    /// Every text message after hello, in order (protocol v2 tabs:
    /// `tabs`, `session`, `nosession`, `ended`; see tabs_tests.zig).
    texts: std.ArrayList([]u8) = .empty,
    /// The first message was the hello text frame.
    hello_first: bool = false,
    /// The first grid frame was a full snapshot.
    first_full: bool = false,
    got_logout: bool = false,
    /// The logout's `reason`, if it had one.
    logout_reason: enum { none, unpaired, replaced } = .none,
    got_exit: bool = false,
    /// {"t":"exit"}'s code, and whether it came before the close frame.
    exit_code: ?i64 = null,
    exit_before_close: bool = false,
    closed: bool = false,
    close_payload: [2]u8 = .{ 0, 0 },
    /// Last {"t":"rejected",...} message (instruct-mode lines Portal refused).
    rejected: [128]u8 = undefined,
    rejected_len: usize = 0,
    rejected_count: usize = 0,
    pongs: usize = 0,
    last_pong: [128]u8 = undefined,
    last_pong_len: usize = 0,
    /// First decode or framing error seen (frames must all be valid).
    bad: ?anyerror = null,
    last_frame_ms: u64 = 0,
    trace: bool = false,

    /// Upgrades, reads hello and the first grid frame.
    /// `device` names a device paired with `inst` (Creds.sessionCookie):
    /// the viewer connects through that device's tunnel.
    pub fn open(inst: *Instance, device: []const u8) !*Viewer {
        const gpa = inst.h.gpa;
        const l = inst.link(device) orelse return error.NoSuchDevice;
        const v = try gpa.create(Viewer);
        errdefer gpa.destroy(v);
        v.* = .{
            .c = try ws.Client.connect(gpa, l.port, .{ .host = inst.host, .origin = null, .cookie = null, .tls = inst.tls }),
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
        for (v.texts.items) |t| gpa.free(t);
        v.texts.deinit(gpa);
        gpa.destroy(v);
    }

    /// Number of text messages containing `needle`.
    pub fn countText(v: *const Viewer, needle: []const u8) usize {
        var n: usize = 0;
        for (v.texts.items) |t| n += @intFromBool(std.mem.indexOf(u8, t, needle) != null);
        return n;
    }

    /// The last text message containing `needle`.
    pub fn lastText(v: *const Viewer, needle: []const u8) ?[]const u8 {
        var i = v.texts.items.len;
        while (i > 0) {
            i -= 1;
            if (std.mem.indexOf(u8, v.texts.items[i], needle) != null) return v.texts.items[i];
        }
        return null;
    }

    /// Waits until `n` text messages contain `needle`.
    pub fn waitText(v: *Viewer, needle: []const u8, n: usize, ms: u32) bool {
        const Ctx = struct { needle: []const u8, n: usize };
        return v.pumpUntil(ms, Ctx{ .needle = needle, .n = n }, struct {
            fn f(c: Ctx, vv: *Viewer) bool {
                return vv.countText(c.needle) >= c.n;
            }
        }.f);
    }

    pub fn helloText(v: *const Viewer) []const u8 {
        return v.hello[0..v.hello_len];
    }

    fn handle(v: *Viewer, f: ws.Frame) void {
        v.last_frame_ms = net.now();
        switch (f.op) {
            .text => {
                const p = f.payload;
                if (std.mem.indexOf(u8, p, "\"hello\"") == null) {
                    if (v.c.gpa.dupe(u8, p)) |copy| {
                        v.texts.append(v.c.gpa, copy) catch v.c.gpa.free(copy);
                    } else |_| {}
                }
                if (std.mem.indexOf(u8, p, "\"hello\"") != null) {
                    const n = @min(p.len, v.hello.len);
                    @memcpy(v.hello[0..n], p[0..n]);
                    v.hello_len = n;
                } else if (std.mem.indexOf(u8, p, "\"rejected\"") != null) {
                    const n = @min(p.len, v.rejected.len);
                    @memcpy(v.rejected[0..n], p[0..n]);
                    v.rejected_len = n;
                    v.rejected_count += 1;
                } else if (std.mem.indexOf(u8, p, "\"logout\"") != null) {
                    v.got_logout = true;
                    if (std.mem.indexOf(u8, p, "\"reason\":\"unpaired\"") != null) v.logout_reason = .unpaired;
                    if (std.mem.indexOf(u8, p, "\"reason\":\"replaced\"") != null) v.logout_reason = .replaced;
                } else if (std.mem.indexOf(u8, p, "\"exit\"") != null) {
                    v.got_exit = true;
                    v.exit_before_close = !v.closed;
                    const key = "\"code\":";
                    if (std.mem.indexOf(u8, p, key)) |at| {
                        const rest = p[at + key.len ..];
                        const end = std.mem.indexOfAny(u8, rest, ",}") orelse rest.len;
                        v.exit_code = std.fmt.parseInt(i64, rest[0..end], 10) catch null;
                    }
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

    pub fn waitExit(v: *Viewer, ms: u32) bool {
        return v.pumpUntil(ms, {}, struct {
            fn f(_: void, vv: *Viewer) bool {
                return vv.got_exit;
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

/// The desk still answers through the last paired device's tunnel (any
/// path but the two WebSockets is a 404).
pub fn alive(inst: *Instance) bool {
    var r = http.request(inst.h.gpa, inst.port, .{ .path = "/", .host = inst.host, .tls = inst.tls }) catch return false;
    defer r.deinit();
    return r.status == 404;
}
