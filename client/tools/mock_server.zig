//! Mock Portal server for end-to-end testing of portal-client.
//!
//! Implements docs/protocol.md: POST /pair (single-use window),
//! POST /auth/refresh (rotation, 10-minute grace for the previous secret,
//! revocation when an older/wrong secret is presented, source-address
//! binding), GET /ws (hello, scripted 'G' frames: snapshot, diffs, colours,
//! attributes, wide characters, a resize), and logs every client frame,
//! checking that it is masked. Test tool only; not hardened like Portal.
//!
//!   portal-mock-server [--listen 127.0.0.1:18420] [--input keys|text|none]
//!                      [--pair-window SECS] [--revoke-after SECS]
//!                      [--resize-after SECS]

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const wcwidth = @import("wcwidth");

const C_DEFAULT: u32 = 0xFF000000;
const C_BG_AS_FG: u32 = 0xFF000002;
const C_FG_AS_BG: u32 = 0xFF000003;

const Config = struct {
    listen: []const u8 = "127.0.0.1:18420",
    input: []const u8 = "keys",
    pair_window_s: i64 = 120,
    revoke_after_s: i64 = 0,
    resize_after_s: i64 = 8,
};

const Device = struct {
    name: []const u8,
    current: [43]u8,
    previous: ?[43]u8 = null,
    previous_expiry_ms: i64 = 0,
    peer: [64]u8 = undefined,
    peer_len: usize = 0,
    revoked: bool = false,
};

const Session = struct { value: [43]u8, device: usize };

const State = struct {
    io: Io,
    gpa: std.mem.Allocator,
    cfg: Config,
    host: []const u8,
    origin: []const u8,
    mutex: Io.Mutex = .init,
    pair_deadline_ms: i64,
    devices: std.ArrayList(Device) = .empty,
    sessions: std.ArrayList(Session) = .empty,
    start_ms: i64,
    last_key: [64]u8 = @splat(' '),
    last_key_len: usize = 0,
    keys_received: usize = 0,

    fn now(s: *State) i64 {
        return Io.Timestamp.now(s.io, .awake).toMilliseconds();
    }

    fn log(s: *State, comptime fmt: []const u8, args: anytype) void {
        const t = s.now() - s.start_ms;
        std.debug.print("[mock {d:>6}ms] " ++ fmt ++ "\n", .{t} ++ args);
    }

    fn randomSecret(s: *State) [43]u8 {
        var raw: [32]u8 = undefined;
        s.io.randomSecure(&raw) catch @panic("no randomness");
        var out: [43]u8 = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&out, &raw);
        return out;
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var cfg: Config = .{};
    var it: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |a| {
        const v = it.next() orelse return error.MissingValue;
        if (std.mem.eql(u8, a, "--listen")) cfg.listen = try gpa.dupe(u8, v) //
        else if (std.mem.eql(u8, a, "--input")) cfg.input = try gpa.dupe(u8, v) //
        else if (std.mem.eql(u8, a, "--pair-window")) cfg.pair_window_s = try std.fmt.parseInt(i64, v, 10) //
        else if (std.mem.eql(u8, a, "--revoke-after")) cfg.revoke_after_s = try std.fmt.parseInt(i64, v, 10) //
        else if (std.mem.eql(u8, a, "--resize-after")) cfg.resize_after_s = try std.fmt.parseInt(i64, v, 10) //
        else return error.UnknownArgument;
    }
    const addr = try net.IpAddress.parseLiteral(cfg.listen);
    var host_buf: [64]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buf, "{f}", .{addr});
    const origin = try std.fmt.allocPrint(gpa, "http://{s}", .{host});

    const start = Io.Timestamp.now(io, .awake).toMilliseconds();
    var state: State = .{
        .io = io,
        .gpa = gpa,
        .cfg = cfg,
        .host = host,
        .origin = origin,
        .start_ms = start,
        .pair_deadline_ms = start + cfg.pair_window_s * 1000,
    };
    var server = try addr.listen(io, .{ .reuse_address = true });
    state.log("listening on {s} (input={s}, pair window {d}s, revoke after {d}s)", .{ host, cfg.input, cfg.pair_window_s, cfg.revoke_after_s });
    while (true) {
        const stream = server.accept(io) catch continue;
        const t = std.Thread.spawn(.{}, handleConnection, .{ &state, stream }) catch {
            stream.close(io);
            continue;
        };
        t.detach();
    }
}

// ------------------------------------------------------------------ HTTP

const Request = struct {
    method: []const u8,
    path: []const u8,
    host: ?[]const u8 = null,
    origin: ?[]const u8 = null,
    cookie: ?[]const u8 = null,
    upgrade: bool = false,
    ws_key: ?[]const u8 = null,
};

fn parseRequest(head: []const u8) ?Request {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    var parts = std.mem.splitScalar(u8, lines.first(), ' ');
    var r: Request = .{ .method = parts.next() orelse return null, .path = parts.next() orelse return null };
    while (lines.next()) |l| {
        if (l.len == 0) continue;
        const c = std.mem.indexOfScalar(u8, l, ':') orelse return null;
        const name = l[0..c];
        const v = std.mem.trim(u8, l[c + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "host")) r.host = v;
        if (std.ascii.eqlIgnoreCase(name, "origin")) r.origin = v;
        if (std.ascii.eqlIgnoreCase(name, "cookie")) r.cookie = v;
        if (std.ascii.eqlIgnoreCase(name, "upgrade") and std.ascii.eqlIgnoreCase(v, "websocket")) r.upgrade = true;
        if (std.ascii.eqlIgnoreCase(name, "sec-websocket-key")) r.ws_key = v;
    }
    return r;
}

fn cookieValue(header: ?[]const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, header orelse return null, ';');
    while (it.next()) |p| {
        const kv = std.mem.trim(u8, p, " ");
        if (kv.len > name.len and std.mem.startsWith(u8, kv, name) and kv[name.len] == '=') return kv[name.len + 1 ..];
    }
    return null;
}

fn respond(w: *Io.Writer, status: []const u8, headers: []const u8) !void {
    try w.print("HTTP/1.1 {s}\r\n{s}Content-Length: 0\r\nConnection: close\r\n\r\n", .{ status, headers });
    try w.flush();
}

fn handleConnection(s: *State, stream: net.Stream) void {
    defer stream.close(s.io);
    var peer_buf: [64]u8 = undefined;
    // Source address without the port, for credential binding.
    const peer_full = std.fmt.bufPrint(&peer_buf, "{f}", .{stream.socket.address}) catch "?";
    const peer = peer_full[0 .. std.mem.lastIndexOfScalar(u8, peer_full, ':') orelse peer_full.len];

    var buf: [8192]u8 = undefined;
    var len: usize = 0;
    const head_end = while (true) {
        if (len == buf.len) return;
        var vec = [_][]u8{buf[len..]};
        const n = sockRead(stream, s.io, &vec) catch return;
        if (n == 0) return;
        len += n;
        if (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n")) |i| break i + 4;
    };
    const req = parseRequest(buf[0 .. head_end - 4]) orelse return;
    var wbuf: [4096]u8 = undefined;
    var sw = stream.writer(s.io, &wbuf);
    const w = &sw.interface;

    if (req.host == null or !std.mem.eql(u8, req.host.?, s.host)) {
        s.log("REJECT {s} {s}: bad Host {?s}", .{ req.method, req.path, req.host });
        return respond(w, "421 Misdirected Request", "") catch {};
    }
    const needs_origin = std.mem.eql(u8, req.method, "POST") or std.mem.eql(u8, req.path, "/ws");
    if (needs_origin and (req.origin == null or !std.mem.eql(u8, req.origin.?, s.origin))) {
        s.log("REJECT {s} {s}: bad Origin {?s}", .{ req.method, req.path, req.origin });
        return respond(w, "403 Forbidden", "") catch {};
    }
    if (std.mem.eql(u8, req.method, "POST") and std.mem.eql(u8, req.path, "/pair")) return handlePair(s, w, peer);
    if (std.mem.eql(u8, req.method, "POST") and std.mem.eql(u8, req.path, "/auth/refresh")) return handleRefresh(s, w, req, peer);
    if (std.mem.eql(u8, req.method, "GET") and std.mem.eql(u8, req.path, "/ws")) return handleWs(s, stream, w, req, buf[head_end..len]);
    s.log("404 {s} {s}", .{ req.method, req.path });
    respond(w, "404 Not Found", "") catch {};
}

fn newSession(s: *State, device: usize) [43]u8 {
    const v = s.randomSecret();
    s.sessions.append(s.gpa, .{ .value = v, .device = device }) catch {};
    return v;
}

fn handlePair(s: *State, w: *Io.Writer, peer: []const u8) void {
    s.mutex.lockUncancelable(s.io);
    defer s.mutex.unlock(s.io);
    if (s.now() > s.pair_deadline_ms) {
        s.log("PAIR refused from {s}: window closed", .{peer});
        return respond(w, "303 See Other", "Location: /pair?e=closed\r\n") catch {};
    }
    s.pair_deadline_ms = 0; // single use
    var d: Device = .{ .name = "mock-laptop", .current = s.randomSecret() };
    @memcpy(d.peer[0..peer.len], peer);
    d.peer_len = peer.len;
    s.devices.append(s.gpa, d) catch return;
    const idx = s.devices.items.len - 1;
    const sess = newSession(s, idx);
    var hdr: [512]u8 = undefined;
    const h = std.fmt.bufPrint(&hdr, "Location: /\r\nSet-Cookie: portal_device={s}.{s}; Path=/; HttpOnly; SameSite=Strict; Max-Age=7776000\r\n" ++
        "Set-Cookie: portal_session={s}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200\r\n", .{ d.name, &d.current, &sess }) catch return;
    s.log("PAIR ok: device {s} bound to {s}", .{ d.name, peer });
    respond(w, "303 See Other", h) catch {};
}

fn handleRefresh(s: *State, w: *Io.Writer, req: Request, peer: []const u8) void {
    s.mutex.lockUncancelable(s.io);
    defer s.mutex.unlock(s.io);
    const value = cookieValue(req.cookie, "portal_device") orelse {
        s.log("REFRESH 401: no device cookie", .{});
        return respond(w, "401 Unauthorized", "") catch {};
    };
    const dot = std.mem.lastIndexOfScalar(u8, value, '.') orelse return respond(w, "401 Unauthorized", "") catch {};
    const name = value[0..dot];
    const secret = value[dot + 1 ..];
    for (s.devices.items, 0..) |*d, idx| {
        if (!std.mem.eql(u8, d.name, name) or d.revoked) continue;
        if (!std.mem.eql(u8, d.peer[0..d.peer_len], peer)) {
            s.log("REFRESH 401: device {s} used from {s}, bound to {s}", .{ name, peer, d.peer[0..d.peer_len] });
            return respond(w, "401 Unauthorized", "") catch {};
        }
        const is_current = std.mem.eql(u8, secret, &d.current);
        const is_grace = d.previous != null and std.mem.eql(u8, secret, &d.previous.?) and s.now() < d.previous_expiry_ms;
        if (!is_current and !is_grace) {
            d.revoked = true;
            s.log("REFRESH 401: stale or wrong secret for {s}; device REVOKED (theft detection)", .{name});
            return respond(w, "401 Unauthorized", "") catch {};
        }
        if (is_current) {
            d.previous = d.current;
            d.previous_expiry_ms = s.now() + 10 * 60 * 1000;
        }
        d.current = s.randomSecret();
        const sess = newSession(s, idx);
        var hdr: [512]u8 = undefined;
        const h = std.fmt.bufPrint(&hdr, "Set-Cookie: portal_device={s}.{s}; Path=/; HttpOnly; SameSite=Strict; Max-Age=7776000\r\n" ++
            "Set-Cookie: portal_session={s}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200\r\n", .{ d.name, &d.current, &sess }) catch return;
        s.log("REFRESH ok: {s} rotated ({s})", .{ name, if (is_current) "current" else "previous, in grace period" });
        return respond(w, "204 No Content", h) catch {};
    }
    s.log("REFRESH 401: unknown or revoked device {s}", .{name});
    respond(w, "401 Unauthorized", "") catch {};
}

// ------------------------------------------------------------------ WebSocket

fn sessionDevice(s: *State, cookie: ?[]const u8) ?usize {
    const v = cookieValue(cookie, "portal_session") orelse return null;
    for (s.sessions.items) |sess| {
        if (std.mem.eql(u8, &sess.value, v) and !s.devices.items[sess.device].revoked) return sess.device;
    }
    return null;
}

fn writeFrame(w: *Io.Writer, opcode: u8, payload: []const u8) !void {
    try w.writeByte(0x80 | opcode);
    if (payload.len < 126) {
        try w.writeByte(@intCast(payload.len));
    } else if (payload.len <= 0xffff) {
        try w.writeByte(126);
        try w.writeInt(u16, @intCast(payload.len), .big);
    } else {
        try w.writeByte(127);
        try w.writeInt(u64, payload.len, .big);
    }
    try w.writeAll(payload);
    try w.flush();
}

const WsCtx = struct {
    s: *State,
    stream: net.Stream,
    dead: std.atomic.Value(bool) = .init(false),
    write_mutex: Io.Mutex = .init,
    w: *Io.Writer,
    pending: []const u8,

    fn send(c: *WsCtx, opcode: u8, payload: []const u8) bool {
        c.write_mutex.lockUncancelable(c.s.io);
        defer c.write_mutex.unlock(c.s.io);
        writeFrame(c.w, opcode, payload) catch return false;
        return true;
    }
};

fn handleWs(s: *State, stream: net.Stream, w: *Io.Writer, req: Request, extra: []const u8) void {
    s.mutex.lockUncancelable(s.io);
    const dev = sessionDevice(s, req.cookie);
    s.mutex.unlock(s.io);
    if (dev == null) {
        s.log("WS 401: no valid session", .{});
        return respond(w, "401 Unauthorized", "") catch {};
    }
    const key = req.ws_key orelse return respond(w, "400 Bad Request", "") catch {};
    if (!req.upgrade) return respond(w, "400 Bad Request", "") catch {};
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(key);
    sha.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    var digest: [20]u8 = undefined;
    sha.final(&digest);
    var accept: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&accept, &digest);
    w.print("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{&accept}) catch return;
    w.flush() catch return;
    s.log("WS open for device #{d}", .{dev.?});

    var ctx: WsCtx = .{ .s = s, .stream = stream, .w = w, .pending = extra };
    const reader = std.Thread.spawn(.{}, wsReader, .{&ctx}) catch return;
    defer {
        ctx.dead.store(true, .release);
        stream.shutdown(s.io, .both) catch {};
        reader.join();
        s.log("WS closed", .{});
    }

    var hello: [64]u8 = undefined;
    if (!ctx.send(1, std.fmt.bufPrint(&hello, "{{\"t\":\"hello\",\"input\":\"{s}\"}}", .{s.cfg.input}) catch return)) return;

    var screen: Screen = .{};
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(s.gpa);
    const opened = s.now();
    var big = false;
    var tick: u32 = 0;
    var last_keys: usize = std.math.maxInt(usize);
    screen.init(80, 24);
    screen.drawPattern(s, 0);
    screen.encode(s.gpa, &out, null) catch return;
    if (!ctx.send(2, out.items)) return;
    while (!ctx.dead.load(.acquire)) {
        s.io.sleep(.fromMilliseconds(250), .awake) catch return;
        const elapsed = s.now() - opened;
        if (s.cfg.revoke_after_s > 0 and elapsed > s.cfg.revoke_after_s * 1000) {
            s.mutex.lockUncancelable(s.io);
            for (s.devices.items) |*d| d.revoked = true;
            s.mutex.unlock(s.io);
            s.log("REVOKE: all devices revoked; sending logout", .{});
            _ = ctx.send(1, "{\"t\":\"logout\"}");
            return;
        }
        if (!big and s.cfg.resize_after_s > 0 and elapsed > s.cfg.resize_after_s * 1000) {
            big = true;
            screen.init(100, 30);
            screen.drawPattern(s, tick);
            out.clearRetainingCapacity();
            screen.encode(s.gpa, &out, null) catch return;
            s.log("RESIZE to 100x30 (full snapshot, {d} bytes)", .{out.items.len});
            if (!ctx.send(2, out.items)) return;
            continue;
        }
        s.mutex.lockUncancelable(s.io);
        const nkeys = s.keys_received;
        s.mutex.unlock(s.io);
        if (@mod(elapsed, 1000) < 250 or nkeys != last_keys) {
            tick += 1;
            last_keys = nkeys;
            const rows = screen.drawDynamic(s, tick);
            out.clearRetainingCapacity();
            screen.encode(s.gpa, &out, &rows) catch return;
            if (!ctx.send(2, out.items)) return;
        }
    }
}

fn wsReader(c: *WsCtx) void {
    const s = c.s;
    var buf: [16384]u8 = undefined;
    var len: usize = c.pending.len;
    @memcpy(buf[0..len], c.pending);
    while (!c.dead.load(.acquire)) {
        // Parse complete client frames.
        while (len >= 2) {
            const b0 = buf[0];
            const b1 = buf[1];
            if (b1 & 0x80 == 0) {
                s.log("PROTOCOL VIOLATION: unmasked client frame", .{});
                c.dead.store(true, .release);
                return;
            }
            var plen: usize = b1 & 0x7f;
            var off: usize = 2;
            if (plen == 126) {
                if (len < 4) break;
                plen = std.mem.readInt(u16, buf[2..4], .big);
                off = 4;
            } else if (plen == 127) {
                s.log("PROTOCOL VIOLATION: client frame too large", .{});
                c.dead.store(true, .release);
                return;
            }
            if (len < off + 4 + plen) break;
            const mask = buf[off..][0..4].*;
            const payload = buf[off + 4 ..][0..plen];
            for (payload, 0..) |*p, i| p.* ^= mask[i & 3];
            const opcode = b0 & 0x0f;
            if (opcode == 1) {
                const valid = (std.mem.startsWith(u8, payload, "k:") or std.mem.startsWith(u8, payload, "t:")) and plen <= 4096;
                s.log("KEY {s} (masked, {d} bytes){s}", .{ payload, plen, if (valid) "" else "  <-- not a valid input frame" });
                s.mutex.lockUncancelable(s.io);
                const n = @min(payload.len, s.last_key.len);
                @memcpy(s.last_key[0..n], payload[0..n]);
                s.last_key_len = n;
                s.keys_received += 1;
                s.mutex.unlock(s.io);
            } else if (opcode == 8) {
                s.log("client sent close", .{});
                c.dead.store(true, .release);
                return;
            } else if (opcode == 10) {
                // pong
            } else {
                s.log("client opcode {d} ({d} bytes)", .{ opcode, plen });
            }
            const used = off + 4 + plen;
            std.mem.copyForwards(u8, buf[0 .. len - used], buf[used..len]);
            len -= used;
        }
        if (len == buf.len) return;
        var vec = [_][]u8{buf[len..]};
        const n = sockRead(c.stream, s.io, &vec) catch {
            c.dead.store(true, .release);
            return;
        };
        if (n == 0) {
            c.dead.store(true, .release);
            return;
        }
        len += n;
    }
}

// ------------------------------------------------------------------ screen

const Cell = struct { cp: u21 = ' ', fg: u32 = C_DEFAULT, bg: u32 = C_DEFAULT, attrs: u8 = 0, cont: bool = false };

const Screen = struct {
    cols: u16 = 0,
    rows: u16 = 0,
    cells: [100 * 30]Cell = undefined,
    cx: u16 = 0,
    cy: u16 = 0,

    fn init(sc: *Screen, cols: u16, rows: u16) void {
        sc.cols = cols;
        sc.rows = rows;
        @memset(sc.cells[0 .. @as(usize, cols) * rows], .{});
    }

    fn clearRow(sc: *Screen, y: u16) void {
        @memset(sc.cells[@as(usize, y) * sc.cols ..][0..sc.cols], .{});
    }

    fn put(sc: *Screen, x0: u16, y: u16, text: []const u8, fg: u32, bg: u32, attrs: u8) u16 {
        var x = x0;
        var it = (std.unicode.Utf8View.init(text) catch return x).iterator();
        while (it.nextCodepoint()) |cp| {
            const w = wcwidth.of(cp);
            if (w == 0) continue;
            if (x + w > sc.cols) break;
            const i = @as(usize, y) * sc.cols + x;
            sc.cells[i] = .{ .cp = cp, .fg = fg, .bg = bg, .attrs = attrs };
            if (w == 2) sc.cells[i + 1] = .{ .cp = ' ', .fg = fg, .bg = bg, .attrs = attrs, .cont = true };
            x += w;
        }
        return x;
    }

    fn drawPattern(sc: *Screen, s: *State, tick: u32) void {
        const title = " Portal mock server: protocol v1 test pattern ";
        var x = sc.put(0, 0, title, C_BG_AS_FG, C_FG_AS_BG, 1);
        while (x < sc.cols) : (x += 1) _ = sc.put(x, 0, " ", C_BG_AS_FG, C_FG_AS_BG, 0);
        x = sc.put(1, 2, "Bold", C_DEFAULT, C_DEFAULT, 1);
        x = sc.put(x + 2, 2, "Dim", C_DEFAULT, C_DEFAULT, 2);
        x = sc.put(x + 2, 2, "Italic", C_DEFAULT, C_DEFAULT, 4);
        x = sc.put(x + 2, 2, "Underline", C_DEFAULT, C_DEFAULT, 8);
        x = sc.put(x + 2, 2, "Strikethrough", C_DEFAULT, C_DEFAULT, 16);
        x = sc.put(x + 2, 2, "Inverse", C_BG_AS_FG, C_FG_AS_BG, 0);
        const colors = [_]u32{ 0xE06C75, 0x98C379, 0xE5C07B, 0x61AFEF, 0xC678DD, 0x56B6C2 };
        x = 1;
        for (colors, [_][]const u8{ "red", "green", "yellow", "blue", "magenta", "cyan" }) |c, n| x = sc.put(x, 3, n, c, C_DEFAULT, 0) + 1;
        x += 1;
        for (colors) |c| x = sc.put(x, 3, "  ", C_DEFAULT, c, 0);
        x = sc.put(x + 1, 3, " white on blue ", 0xFFFFFF, 0x2050A0, 1);
        _ = sc.put(1, 5, "Wide: 中文字符 日本語 한국어 😀🚀 <- each takes two cells|", C_DEFAULT, C_DEFAULT, 0);
        _ = sc.put(1, 6, "Accents: café naïve Ελληνικά Русский  Missing glyph: \u{E000} \u{10FFFD}", C_DEFAULT, C_DEFAULT, 0);
        _ = sc.put(1, 8, "╭──────────────────────────────────────────╮", 0x808890, C_DEFAULT, 0);
        _ = sc.put(1, 9, "│ Do you want to make this edit to app.zig?│", 0x808890, C_DEFAULT, 0);
        _ = sc.put(3, 9, "Do you want to make this edit to app.zig?", C_DEFAULT, C_DEFAULT, 1);
        _ = sc.put(1, 10, "│ ❯ 1. Yes                                 │", 0x808890, C_DEFAULT, 0);
        _ = sc.put(3, 10, "❯ 1. Yes", 0x61AFEF, C_DEFAULT, 0);
        _ = sc.put(1, 11, "│   2. Yes, and don't ask again            │", 0x808890, C_DEFAULT, 0);
        _ = sc.put(5, 11, "2. Yes, and don't ask again", C_DEFAULT, C_DEFAULT, 0);
        _ = sc.put(1, 12, "│   3. No, tell agent what to do (esc)     │", 0x808890, C_DEFAULT, 0);
        _ = sc.put(5, 12, "3. No, tell agent what to do (esc) ", C_DEFAULT, C_DEFAULT, 0);
        _ = sc.put(1, 13, "╰──────────────────────────────────────────╯", 0x808890, C_DEFAULT, 0);
        _ = sc.put(1, 15, "Blocks: ░░▒▒▓▓██ ▁▂▃▄▅▆▇█ ▏▎▍▌▋▊▉ ═══ ║ ┏━┓", 0xC678DD, C_DEFAULT, 0);
        var buf: [64]u8 = undefined;
        _ = sc.put(1, 22, std.fmt.bufPrint(&buf, "Grid {d} x {d}", .{ sc.cols, sc.rows }) catch "", 0x808890, C_DEFAULT, 2);
        _ = sc.drawDynamic(s, tick);
    }

    /// Updates the clock and last-key rows; returns their indices.
    fn drawDynamic(sc: *Screen, s: *State, tick: u32) [3]u16 {
        var buf: [96]u8 = undefined;
        sc.clearRow(17);
        sc.clearRow(18);
        sc.clearRow(19);
        const spin = "|/-\\";
        _ = sc.put(1, 17, std.fmt.bufPrint(&buf, "Tick {d} {c}  (row diff every second)", .{ tick, spin[tick % 4] }) catch "", 0x98C379, C_DEFAULT, 0);
        s.mutex.lockUncancelable(s.io);
        const key = std.fmt.bufPrint(&buf, "Last input from client: {s}   (total {d})", .{ s.last_key[0..s.last_key_len], s.keys_received }) catch "";
        s.mutex.unlock(s.io);
        _ = sc.put(1, 18, key, 0xE5C07B, C_DEFAULT, 1);
        const x = sc.put(1, 19, "> ", 0x61AFEF, C_DEFAULT, 1);
        sc.cx = x + @as(u16, @intCast(tick % 6));
        sc.cy = 19;
        return .{ 17, 18, 19 };
    }

    fn encode(sc: *Screen, gpa: std.mem.Allocator, out: *std.ArrayList(u8), only: ?[]const u16) !void {
        try out.append(gpa, 'G');
        for ([_]u16{ sc.cols, sc.rows, sc.cx, sc.cy }) |v| try put16(gpa, out, v);
        try out.append(gpa, 1);
        var all: [30]u16 = undefined;
        for (0..sc.rows) |i| all[i] = @intCast(i);
        const rows = only orelse all[0..sc.rows];
        try put16(gpa, out, @intCast(rows.len));
        for (rows) |y| {
            const row = sc.cells[@as(usize, y) * sc.cols ..][0..sc.cols];
            var end: usize = row.len;
            while (end > 0 and row[end - 1].cp == ' ' and row[end - 1].bg == C_DEFAULT and row[end - 1].attrs == 0 and !row[end - 1].cont) end -= 1;
            try put16(gpa, out, y);
            const n_runs_pos = out.items.len;
            try put16(gpa, out, 0);
            var n_runs: u16 = 0;
            var i: usize = 0;
            while (i < end) {
                const c0 = row[i];
                try put32(gpa, out, c0.fg);
                try put32(gpa, out, c0.bg);
                try out.append(gpa, c0.attrs);
                const len_pos = out.items.len;
                try put16(gpa, out, 0);
                const text_start = out.items.len;
                while (i < end and row[i].fg == c0.fg and row[i].bg == c0.bg and row[i].attrs == c0.attrs) : (i += 1) {
                    if (row[i].cont) continue;
                    var tmp: [4]u8 = undefined;
                    const n = std.unicode.utf8Encode(row[i].cp, &tmp) catch 1;
                    try out.appendSlice(gpa, tmp[0..n]);
                }
                std.mem.writeInt(u16, out.items[len_pos..][0..2], @intCast(out.items.len - text_start), .little);
                n_runs += 1;
            }
            std.mem.writeInt(u16, out.items[n_runs_pos..][0..2], n_runs, .little);
        }
    }
};

fn put16(gpa: std.mem.Allocator, out: *std.ArrayList(u8), v: u16) !void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .little);
    try out.appendSlice(gpa, &b);
}

fn put32(gpa: std.mem.Allocator, out: *std.ArrayList(u8), v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try out.appendSlice(gpa, &b);
}

/// std.Io.net.Stream.read does not compile in this Zig version (it
/// destructures a struct); the control-data variant is equivalent.
fn sockRead(stream: net.Stream, io: Io, vec: [][]u8) !usize {
    const r = try stream.readWithControl(io, vec, &.{});
    return r.data_len;
}
