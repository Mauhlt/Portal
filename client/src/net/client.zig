//! Connection thread: pairing, session refresh, the WebSocket stream and
//! reconnects (docs/protocol.md).
//!
//!   no stored device credential -> wait for the user to press "Pair"
//!       -> POST /pair -> store portal_device in the OS credential store
//!   stored credential -> POST /auth/refresh -> store the rotated value
//!       immediately (before anything else), keep portal_session in memory
//!   GET /ws with the session cookie -> 'G' frames into the shared grid
//!   401 on refresh -> delete the credential, back to "Pair this device"
//!   401 on /ws or a `logout` message -> refresh again
//!   network errors -> retry with backoff 1 s doubling to 15 s
//!
//! Everything read from the network is bounded and parsed defensively.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const http = @import("http.zig");
const ws = @import("ws.zig");
const Grid = @import("view").grid.Grid;
const gframe = @import("../gframe.zig");
const keys = @import("../keys.zig");
const credstore = @import("../credstore.zig");

pub const max_frame_payload = 8 << 20;

pub const Status = enum {
    starting,
    need_pairing,
    pairing,
    pair_closed,
    refreshing,
    connecting,
    connected,
    retrying,
    session_ended,
    store_unavailable,
};

pub const Shared = struct {
    mutex: Io.Mutex = .init,
    grid: Grid = .{},
    mode: keys.Mode = .unknown,
    status: Status = .starting,
    detail_buf: [160]u8 = undefined,
    detail_len: usize = 0,
    retry_in_ms: i64 = 0,
    exit_code: ?i64 = null,
    /// Bumped on any change the UI should redraw for.
    version: std.atomic.Value(u64) = .init(0),
    pair_requested: std.atomic.Value(bool) = .init(false),
    wake_ctx: ?*anyopaque = null,
    wake_fn: ?*const fn (*anyopaque) void = null,

    pub fn detail(s: *const Shared) []const u8 {
        return s.detail_buf[0..s.detail_len];
    }
};

pub const Client = struct {
    gpa: std.mem.Allocator,
    io: Io,
    shared: *Shared,
    addr: net.IpAddress,
    host_buf: [64]u8 = undefined,
    host_len: usize = 0,
    target_buf: [credstore.max_target]u8 = undefined,
    target_len: usize = 0,

    write_mutex: Io.Mutex = .init,
    stream: ?net.Stream = null,

    pub fn init(gpa: std.mem.Allocator, io: Io, shared: *Shared, server: []const u8) !Client {
        var c: Client = .{ .gpa = gpa, .io = io, .shared = shared, .addr = undefined };
        const h = try http.canonicalHost(server, &c.host_buf);
        c.host_len = h.len;
        c.addr = net.IpAddress.parseLiteral(h) catch return error.BadServerAddress;
        c.target_len = credstore.targetName(h, &c.target_buf).len;
        return c;
    }

    pub fn host(c: *const Client) []const u8 {
        return c.host_buf[0..c.host_len];
    }

    pub fn target(c: *const Client) []const u8 {
        return c.target_buf[0..c.target_len];
    }

    // ------------------------------------------------------------ status

    fn setStatus(c: *Client, status: Status, comptime fmt: []const u8, args: anytype) void {
        const s = c.shared;
        s.mutex.lockUncancelable(c.io);
        s.status = status;
        const d = std.fmt.bufPrint(&s.detail_buf, fmt, args) catch s.detail_buf[0..0];
        s.detail_len = d.len;
        if (status != .connected) s.mode = if (status == .session_ended) s.mode else .unknown;
        s.mutex.unlock(c.io);
        c.notify();
    }

    fn notify(c: *Client) void {
        _ = c.shared.version.fetchAdd(1, .release);
        if (c.shared.wake_fn) |f| f(c.shared.wake_ctx.?);
    }

    fn sleepMs(c: *Client, ms: i64) void {
        c.io.sleep(.fromMilliseconds(ms), .awake) catch {};
    }

    // ------------------------------------------------------------ main loop

    pub fn run(c: *Client) void {
        var backoff: i64 = 1000;
        var session: ?http.Cookie = null;
        defer if (session) |*s| s.wipe();
        while (true) {
            if (session == null) {
                session = c.authenticate(&backoff);
                if (session == null) continue;
            }
            c.setStatus(.connecting, "opening stream", .{});
            const result = c.runStream(&session.?, &backoff);
            switch (result) {
                .unauthorized, .logout => {
                    session.?.wipe();
                    session = null; // refresh (or re-pair) next
                },
                .exited => |code| {
                    c.shared.mutex.lockUncancelable(c.io);
                    c.shared.exit_code = code;
                    c.shared.mutex.unlock(c.io);
                    c.setStatus(.session_ended, "program exited (code {d}); waiting for a new session", .{code});
                    c.sleepMs(backoff);
                    backoff = @min(backoff * 2, 15000);
                },
                .failed => |why| {
                    c.retryWait(&backoff, why);
                },
            }
        }
    }

    fn retryWait(c: *Client, backoff: *i64, why: []const u8) void {
        var left = backoff.*;
        while (left > 0) : (left -= 250) {
            c.shared.mutex.lockUncancelable(c.io);
            c.shared.retry_in_ms = left;
            c.shared.mutex.unlock(c.io);
            c.setStatus(.retrying, "{s}; retrying in {d} s", .{ why, @divTrunc(left + 999, 1000) });
            c.sleepMs(@min(250, left));
        }
        backoff.* = @min(backoff.* * 2, 15000);
    }

    /// Returns a fresh session cookie, or null after showing why not.
    fn authenticate(c: *Client, backoff: *i64) ?http.Cookie {
        var buf: [credstore.max_secret]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        const stored = credstore.load(c.target(), &buf) catch |err| {
            c.setStatus(.store_unavailable, "OS credential store unavailable ({t}); cannot pair securely", .{err});
            c.sleepMs(5000);
            return null;
        };
        if (stored) |value| {
            var device = http.Cookie.fromValue(.device, value) orelse {
                credstore.delete(c.target()) catch {};
                return null;
            };
            defer device.wipe();
            c.setStatus(.refreshing, "signing in", .{});
            return c.refresh(&device, backoff);
        }
        // Not paired: wait for the user.
        c.shared.mutex.lockUncancelable(c.io);
        const already = c.shared.status == .need_pairing;
        c.shared.mutex.unlock(c.io);
        if (!already) c.setStatus(.need_pairing, "", .{}); // keep any "no longer paired" note
        while (!c.shared.pair_requested.swap(false, .acq_rel)) c.sleepMs(100);
        c.setStatus(.pairing, "pairing", .{});
        return c.pair();
    }

    fn pair(c: *Client) ?http.Cookie {
        var resp_buf: [http.max_head_bytes]u8 = undefined;
        var req_buf: [512]u8 = undefined;
        var w: Io.Writer = .fixed(&req_buf);
        http.writePairRequest(&w, c.host()) catch return null;
        const resp = c.roundTrip(w.buffered(), &resp_buf) catch |err| {
            c.setStatus(.pair_closed, "could not reach the server ({t})", .{err});
            return null;
        };
        defer std.crypto.secureZero(u8, &resp_buf);
        var r = resp;
        defer if (r.device) |*d| d.wipe();
        switch (http.pairOutcome(&r)) {
            .ok => {
                credstore.save(c.target(), r.device.?.value()) catch |err| {
                    c.setStatus(.store_unavailable, "could not save the device credential ({t})", .{err});
                    return null;
                };
                return r.session.?;
            },
            .closed => c.setStatus(.pair_closed, "pairing window is closed", .{}),
            .unexpected => c.setStatus(.pair_closed, "unexpected pairing response (HTTP {d})", .{r.status}),
        }
        return null;
    }

    fn refresh(c: *Client, device: *const http.Cookie, backoff: *i64) ?http.Cookie {
        var resp_buf: [http.max_head_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &resp_buf);
        var req_buf: [768]u8 = undefined;
        defer std.crypto.secureZero(u8, &req_buf);
        var w: Io.Writer = .fixed(&req_buf);
        http.writeRefreshRequest(&w, c.host(), device) catch return null;
        var r = c.roundTrip(w.buffered(), &resp_buf) catch |err| {
            c.retryWait(backoff, @errorName(err));
            return null;
        };
        defer if (r.device) |*d| d.wipe();
        switch (http.refreshOutcome(&r)) {
            .ok => {
                // Rotate first: the old value is only valid for 10 minutes.
                credstore.save(c.target(), r.device.?.value()) catch |err| {
                    c.setStatus(.store_unavailable, "could not save the rotated credential ({t})", .{err});
                    c.sleepMs(5000);
                    return null;
                };
                return r.session.?;
            },
            .revoked => {
                credstore.delete(c.target()) catch {};
                c.setStatus(.need_pairing, "this device is no longer paired", .{});
                return null;
            },
            .unexpected => {
                var why: [48]u8 = undefined;
                c.retryWait(backoff, std.fmt.bufPrint(&why, "sign-in failed (HTTP {d})", .{r.status}) catch "sign-in failed");
                return null;
            },
        }
    }

    fn connect(c: *Client) !net.Stream {
        // No connect timeout: std.Io.Threaded panics ("TODO") when one is
        // given, on both Windows and POSIX in this Zig version. The OS default
        // applies (about 21 s on Windows) when the tunnel is down.
        return c.addr.connect(c.io, .{ .mode = .stream });
    }

    /// Sends a request on a fresh connection and parses the response head.
    /// Returned slices point into `buf`.
    fn roundTrip(c: *Client, request: []const u8, buf: *[http.max_head_bytes]u8) !http.Response {
        const stream = try c.connect();
        defer stream.close(c.io);
        var wbuf: [256]u8 = undefined;
        var sw = stream.writer(c.io, &wbuf);
        try sw.interface.writeAll(request);
        try sw.interface.flush();
        var len: usize = 0;
        while (true) {
            if (len == buf.len) return error.ResponseTooLarge;
            var vec = [_][]u8{buf[len..]};
            const n = sockRead(stream, c.io, &vec) catch return error.ReadFailed;
            if (n == 0) return error.ConnectionClosed;
            len += n;
            if (http.findHeadEnd(buf[0..len])) |end| return http.parseResponseHead(buf[0..end]);
        }
    }

    // ------------------------------------------------------------ stream

    const StreamResult = union(enum) {
        unauthorized,
        logout,
        exited: i64,
        failed: []const u8,
    };

    fn runStream(c: *Client, session: *const http.Cookie, backoff: *i64) StreamResult {
        const stream = c.connect() catch |err| return .{ .failed = @errorName(err) };
        defer stream.close(c.io);

        var rnd: [16]u8 = undefined;
        c.io.randomSecure(&rnd) catch return .{ .failed = "no secure randomness" };
        const key = ws.makeKey(rnd);
        {
            var req_buf: [768]u8 = undefined;
            defer std.crypto.secureZero(u8, &req_buf);
            var w: Io.Writer = .fixed(&req_buf);
            http.writeUpgradeRequest(&w, c.host(), session, &key) catch return .{ .failed = "request too long" };
            var wbuf: [256]u8 = undefined;
            var sw = stream.writer(c.io, &wbuf);
            sw.interface.writeAll(w.buffered()) catch return .{ .failed = "write failed" };
            sw.interface.flush() catch return .{ .failed = "write failed" };
        }

        // Buffer for the response head and then for frames; grows on demand.
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(c.gpa);
        buf.ensureTotalCapacity(c.gpa, 64 * 1024) catch return .{ .failed = "out of memory" };

        // Response head.
        var head_end: usize = 0;
        while (true) {
            if (buf.items.len >= http.max_head_bytes) return .{ .failed = "response head too large" };
            if (!c.readMore(stream, &buf)) return .{ .failed = "connection closed during upgrade" };
            if (http.findHeadEnd(buf.items)) |e| {
                if (e > http.max_head_bytes) return .{ .failed = "response head too large" };
                head_end = e;
                break;
            }
        }
        const resp = http.parseResponseHead(buf.items[0..head_end]) catch return .{ .failed = "bad upgrade response" };
        if (resp.status == 401) return .unauthorized;
        if (resp.status != 101) return .{ .failed = "upgrade refused" };
        const expected = ws.expectedAccept(&key);
        if (!resp.upgrade_websocket or !resp.connection_upgrade or resp.accept == null or
            !std.mem.eql(u8, resp.accept.?, &expected)) return .{ .failed = "bad websocket handshake" };
        // Drop the head; keep any frame bytes that followed it.
        std.mem.copyForwards(u8, buf.items[0 .. buf.items.len - head_end], buf.items[head_end..]);
        buf.shrinkRetainingCapacity(buf.items.len - head_end);

        c.write_mutex.lockUncancelable(c.io);
        c.stream = stream;
        c.write_mutex.unlock(c.io);
        defer {
            c.write_mutex.lockUncancelable(c.io);
            c.stream = null;
            c.write_mutex.unlock(c.io);
        }
        c.setStatus(.connected, "", .{});
        c.shared.mutex.lockUncancelable(c.io);
        c.shared.exit_code = null;
        c.shared.mutex.unlock(c.io);

        while (true) {
            // Drain complete frames.
            while (true) {
                const frame = ws.parseServerFrame(buf.items, max_frame_payload) catch |err| {
                    return .{ .failed = @errorName(err) };
                } orelse break;
                if (c.handleFrame(frame, backoff)) |r| return r;
                const used = frame.len;
                std.mem.copyForwards(u8, buf.items[0 .. buf.items.len - used], buf.items[used..]);
                buf.shrinkRetainingCapacity(buf.items.len - used);
            }
            if (buf.items.len > max_frame_payload + 16) return .{ .failed = "frame too large" };
            if (!c.readMore(stream, &buf)) return .{ .failed = "connection lost" };
        }
    }

    fn readMore(c: *Client, stream: net.Stream, buf: *std.ArrayList(u8)) bool {
        buf.ensureUnusedCapacity(c.gpa, 32 * 1024) catch return false;
        const spare = buf.unusedCapacitySlice();
        var vec = [_][]u8{spare};
        const n = sockRead(stream, c.io, &vec) catch return false;
        if (n == 0) return false;
        buf.items.len += n;
        return true;
    }

    const Msg = struct {
        t: []const u8 = "",
        input: ?[]const u8 = null,
        code: ?i64 = null,
    };

    fn handleFrame(c: *Client, frame: ws.Frame, backoff: *i64) ?StreamResult {
        switch (frame.opcode) {
            .binary => {
                if (frame.payload.len == 0 or frame.payload[0] != 'G') return null; // unknown: ignore
                c.shared.mutex.lockUncancelable(c.io);
                const r = gframe.apply(&c.shared.grid, c.gpa, frame.payload);
                c.shared.mutex.unlock(c.io);
                r catch |err| return .{ .failed = @errorName(err) }; // reconnect for a fresh snapshot
                c.notify();
            },
            .text => {
                if (frame.payload.len > 4096) return null;
                const parsed = std.json.parseFromSlice(Msg, c.gpa, frame.payload, .{ .ignore_unknown_fields = true }) catch return null;
                defer parsed.deinit();
                const m = parsed.value;
                if (std.mem.eql(u8, m.t, "hello")) {
                    c.shared.mutex.lockUncancelable(c.io);
                    c.shared.mode = keys.Mode.parse(m.input orelse "none");
                    c.shared.mutex.unlock(c.io);
                    backoff.* = 1000;
                    c.notify();
                } else if (std.mem.eql(u8, m.t, "exit")) {
                    return .{ .exited = m.code orelse 0 };
                } else if (std.mem.eql(u8, m.t, "logout")) {
                    return .logout;
                }
            },
            .ping => c.sendFrame(.pong, frame.payload) catch {},
            .close => {
                c.sendFrame(.close, "") catch {};
                return .{ .failed = "server closed the stream" };
            },
            else => {},
        }
        return null;
    }

    fn sendFrame(c: *Client, opcode: ws.Opcode, payload: []const u8) !void {
        if (payload.len > ws.max_client_payload) return error.TooLarge;
        var mask: [4]u8 = undefined;
        try c.io.randomSecure(&mask);
        var out: [ws.max_client_payload + 16]u8 = undefined;
        const frame = try ws.encodeClientFrame(&out, opcode, payload, mask);
        c.write_mutex.lockUncancelable(c.io);
        defer c.write_mutex.unlock(c.io);
        const stream = c.stream orelse return error.NotConnected;
        var wbuf: [64]u8 = undefined;
        var sw = stream.writer(c.io, &wbuf);
        try sw.interface.writeAll(frame);
        try sw.interface.flush();
    }

    /// Sends an input frame ("k:..." or "t:..."); callable from the UI thread.
    pub fn sendInput(c: *Client, text: []const u8) bool {
        c.sendFrame(.text, text) catch return false;
        return true;
    }

    pub fn requestPairing(c: *Client) void {
        c.shared.pair_requested.store(true, .release);
    }
};

/// std.Io.net.Stream.read does not compile in this Zig version (it
/// destructures a struct); the control-data variant is equivalent.
fn sockRead(stream: net.Stream, io: Io, vec: [][]u8) !usize {
    const r = try stream.readWithControl(io, vec, &.{});
    return r.data_len;
}
