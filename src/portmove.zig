//! Moving the desk's tunnel: a new UDP port and/or a new endpoint
//! (HOST:PORT) for devices, decided at the desk and only there
//! (docs/wireguard.md, "Changing the port").
//!
//! The owner's rule: only the desk changes the desk's port. There is no
//! device -> desk message that asks for, or carries, a port or an
//! endpoint. A device's only part is the acknowledgement `m:<seq>`
//! (shared/frames.zig), a number that marks it "moved" for an
//! announcement the desk itself made (`Announce.ack`); anything else
//! endpoint-like from a device is an unknown frame and ignored
//! (web.zig).
//!
//! A move (`run`, on a worker thread; the Settings flow confirms first
//! that the router forwards the new port):
//!   1. a new port is tried first (bound and released) so a taken one
//!      fails before any device is told;
//!   2. a changed endpoint is announced to every connected paired device
//!      over its authenticated WebSocket (TLS inside the tunnel):
//!      {"t":"endpoint","endpoint":"host:port","seq":N}, N strictly
//!      increasing and stored on the desk (`nextSeq`); each device saves
//!      it and acknowledges; the desk waits for those acknowledgements
//!      (`ack_timeout_ms` at most);
//!   3. the tunnel moves to the new port (Tunnel.setUdpPort): the keys,
//!      peers and sessions stay, and devices follow to the new endpoint;
//!      if the port can't be bound after all, the old endpoint is
//!      announced again (a newer N) and the tunnel stays where it was;
//!   4. the outcome per paired device: moved, or not yet (offline, or no
//!      answer); those find the desktop again on their "Desktop offline"
//!      screen (devicelink.Follower.setEndpoint).
//! The router is never touched (no UPnP, no NAT-PMP), and a taken port is
//! never replaced by another one automatically.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const devices = @import("devices.zig");
const fsutil = @import("fsutil.zig");
const frames = @import("shared").frames;
const pairqr = @import("shared").pairqr;
const Log = @import("log.zig").Log;

/// How long the desk waits for every connected device's acknowledgement.
pub const ack_timeout_ms = 5_000;

/// The announcement being made, and who has acknowledged it. Lives in
/// web.Server (its writers send it, its readers record `m:` frames).
pub const Announce = struct {
    mutex: Io.Mutex = .init,
    cond: Io.Condition = .init,
    /// The announcement's number (0: none made by this run).
    seq: u64 = 0,
    endpoint_buf: [pairqr.max_endpoint]u8 = undefined,
    endpoint_len: usize = 0,
    /// Bumped with every announcement: each writer sends it once.
    gen: std.atomic.Value(u64) = .init(0),
    /// Devices that acknowledged `seq`.
    acked: [devices.max_devices]devices.DeviceId = undefined,
    n_acked: usize = 0,

    pub const max_message = 64 + pairqr.max_endpoint;

    /// A new announcement: forgets the old acknowledgements. The caller
    /// wakes the writers (web.Server.announceEndpoint).
    pub fn set(a: *Announce, io: Io, seq: u64, endpoint: []const u8) void {
        a.mutex.lockUncancelable(io);
        defer a.mutex.unlock(io);
        const n = @min(endpoint.len, a.endpoint_buf.len);
        @memcpy(a.endpoint_buf[0..n], endpoint[0..n]);
        a.endpoint_len = n;
        a.seq = seq;
        a.n_acked = 0;
        _ = a.gen.fetchAdd(1, .acq_rel);
    }

    /// The message to send, if one was announced: the desk's own values
    /// only.
    pub fn message(a: *Announce, io: Io, buf: *[max_message]u8) ?[]const u8 {
        a.mutex.lockUncancelable(io);
        defer a.mutex.unlock(io);
        if (a.seq == 0) return null;
        return formatMessage(buf, a.endpoint_buf[0..a.endpoint_len], a.seq);
    }

    /// `m:<rest>` from device `id` (its authenticated connection): marks it
    /// moved if `rest` is exactly the number of the desk's current
    /// announcement. Nothing else is read from it, and nothing but this
    /// mark can change. True if it counted.
    pub fn ack(a: *Announce, io: Io, id: devices.DeviceId, rest: []const u8) bool {
        const seq = frames.parseMoved(rest) orelse return false;
        a.mutex.lockUncancelable(io);
        defer a.mutex.unlock(io);
        if (a.seq == 0 or seq != a.seq) return false;
        for (a.acked[0..a.n_acked]) |x| if (std.mem.eql(u8, &x, &id)) return true;
        if (a.n_acked == a.acked.len) return false;
        a.acked[a.n_acked] = id;
        a.n_acked += 1;
        a.cond.broadcast(io);
        return true;
    }

    pub fn hasAcked(a: *Announce, io: Io, id: devices.DeviceId) bool {
        a.mutex.lockUncancelable(io);
        defer a.mutex.unlock(io);
        return a.hasAckedLocked(id);
    }

    fn hasAckedLocked(a: *const Announce, id: devices.DeviceId) bool {
        for (a.acked[0..a.n_acked]) |x| if (std.mem.eql(u8, &x, &id)) return true;
        return false;
    }

    /// Waits (event-driven, bounded) until every device in `ids` has
    /// acknowledged, or `deadline_ms` (awake clock) passes.
    pub fn awaitAcks(a: *Announce, io: Io, ids: []const devices.DeviceId, deadline_ms: i64) void {
        a.mutex.lockUncancelable(io);
        defer a.mutex.unlock(io);
        while (true) {
            var all = true;
            for (ids) |id| if (!a.hasAckedLocked(id)) {
                all = false;
            };
            if (all) return;
            const left = deadline_ms -| Io.Clock.awake.now(io).toMilliseconds();
            if (left <= 0) return;
            a.cond.waitTimeout(io, &a.mutex, .{ .duration = .{ .raw = .fromMilliseconds(left), .clock = .awake } }) catch |err| switch (err) {
                error.Timeout => {},
                error.Canceled => return,
            };
        }
    }
};

/// {"t":"endpoint","endpoint":"<endpoint>","seq":N}. The endpoint is the
/// desk's own validated setting (host characters only), so no escaping.
pub fn formatMessage(buf: *[Announce.max_message]u8, endpoint: []const u8, seq: u64) []const u8 {
    return std.fmt.bufPrint(buf, "{{\"t\":\"endpoint\",\"endpoint\":\"{s}\",\"seq\":{d}}}", .{ endpoint, seq }) catch buf[0..0];
}

// ------------------------------------------------------------ the number

const seq_file = "endpoint-seq.txt";

/// The next announcement number, stored before it is used: one more than
/// the last, and at least the clock's seconds (so a lost file still gives
/// a number newer than any a device saved, unless the clock went back).
pub fn nextSeq(gpa: Allocator, io: Io, dir: []const u8, now_unix: i64) !u64 {
    var pb: [1100]u8 = undefined;
    const p = try fsutil.join(&pb, &.{ dir, "tunnel", seq_file });
    var buf: [32]u8 = undefined;
    const last: u64 = if (Io.Dir.cwd().readFile(io, p, &buf)) |t|
        std.fmt.parseInt(u64, std.mem.trim(u8, t, " \r\n"), 10) catch 0
    else |_| 0;
    const next = @max(last + 1, @as(u64, @intCast(@max(now_unix, 1))));
    var tb: [32]u8 = undefined;
    var db: [1100]u8 = undefined;
    try Io.Dir.cwd().createDirPath(io, try fsutil.join(&db, &.{ dir, "tunnel" }));
    try fsutil.writeAtomic(gpa, io, p, std.fmt.bufPrint(&tb, "{d}\n", .{next}) catch unreachable);
    return next;
}

// ------------------------------------------------------------ a move

pub const Plan = struct {
    /// The UDP port to listen on (the same: no rebind).
    port: u16,
    /// The endpoint to announce (null: unchanged, nothing announced).
    endpoint: ?[]const u8 = null,
    /// The endpoint devices had (announced again if the port fails).
    old_endpoint: ?[]const u8 = null,
};

pub const RowState = enum { moved, not_connected, no_answer };

pub const Row = struct { name: devices.Text = .{}, state: RowState = .not_connected };

pub const Outcome = struct {
    rows: [devices.max_devices]Row = undefined,
    n: usize = 0,
    announced: bool = false,
    /// The tunnel listens on the new port.
    port_moved: bool = false,
    /// Why the new port could not be used (nothing moved then).
    port_error: ?anyerror = null,
    /// Storing the announcement number failed (nothing announced).
    seq_error: ?anyerror = null,

    pub fn slice(o: *const Outcome) []const Row {
        return o.rows[0..o.n];
    }
};

/// What a move needs from the desk (main.zig wires the real ones; the
/// tests fake them).
pub fn Desk(comptime Srv: type, comptime Tun: type) type {
    return struct {
        gpa: Allocator,
        io: Io,
        srv: *Srv,
        tun: *Tun,
        dir: []const u8,
        log: *Log,
        /// Try a port before telling devices (null: no probe).
        probe: ?*const fn (port: u16) anyerror!void = null,

        const Self = @This();

        /// Performs `plan` (blocking for at most about ack_timeout_ms).
        pub fn run(d: Self, plan: Plan) Outcome {
            var o: Outcome = .{};
            const now_port = d.tun.udpPort();
            const bound = d.tun.bindError() == null;
            const port_change = plan.port != now_port or !bound;
            if (port_change and bound) if (d.probe) |p| p(plan.port) catch |err| {
                o.port_error = err;
                d.log.print("tunnel: UDP {d} cannot be used ({t}); nothing changed, no device was told", .{ plan.port, err });
                d.fill(&o, &.{});
                return o;
            };
            var connected: [devices.max_devices]devices.DeviceId = undefined;
            var n_conn: usize = 0;
            if (plan.endpoint) |ep| {
                if (d.announce(ep)) |seq| {
                    o.announced = true;
                    n_conn = d.srv.connectedDevices(&connected).len;
                    d.log.print("tunnel: announced endpoint {s} (#{d}) to {d} connected device(s)", .{ ep, seq, n_conn });
                    d.srv.move.awaitAcks(d.io, connected[0..n_conn], Io.Clock.awake.now(d.io).toMilliseconds() + ack_timeout_ms);
                } else |err| {
                    o.seq_error = err;
                    d.log.print("ERROR: tunnel: the announcement number could not be stored ({t}); nothing announced, nothing moved", .{err});
                    d.fill(&o, &.{});
                    return o;
                }
            }
            if (port_change) {
                if (d.tun.setUdpPort(plan.port)) {
                    o.port_moved = true;
                    d.log.print("tunnel: now listening on UDP {d} (was {d}); keys and peers unchanged", .{ plan.port, now_port });
                } else |err| {
                    o.port_error = err;
                    d.log.print("ERROR: tunnel: UDP {d} could not be bound ({t}); it stays on {d}", .{ plan.port, err, d.tun.udpPort() });
                    // Devices that followed go back.
                    if (o.announced) if (plan.old_endpoint) |old| {
                        _ = d.announce(old) catch {};
                    };
                }
            }
            d.fill(&o, connected[0..n_conn]);
            return o;
        }

        fn announce(d: Self, ep: []const u8) !u64 {
            const seq = try nextSeq(d.gpa, d.io, d.dir, Io.Timestamp.now(d.io, .real).toSeconds());
            d.srv.announceEndpoint(seq, ep);
            return seq;
        }

        fn fill(d: Self, o: *Outcome, connected: []const devices.DeviceId) void {
            var peers: [devices.max_devices]PeerInfo = undefined;
            for (d.srv.pairedDevices(&peers)) |p| {
                var st: RowState = .not_connected;
                if (o.announced and d.srv.move.hasAcked(d.io, p.id)) {
                    st = .moved;
                } else for (connected) |c| {
                    if (std.mem.eql(u8, &c, &p.id)) st = .no_answer;
                }
                // Nothing announced (the endpoint stays): a port change
                // alone moves every device with the router's forward.
                if (!o.announced and o.port_error == null and o.seq_error == null) st = .moved;
                o.rows[o.n] = .{ .name = p.name, .state = st };
                o.n += 1;
            }
        }
    };
}

/// A paired device as `pairedDevices` lists it.
pub const PeerInfo = struct { id: devices.DeviceId, name: devices.Text };

/// The endpoint a port change implies when the owner left the endpoint
/// as it was: its port follows the listening port if it named the old
/// one (the usual router forward, external port = internal port). Null:
/// nothing to change. `buf` holds the result.
pub fn followPort(endpoint: []const u8, old_port: u16, new_port: u16, buf: *[pairqr.max_endpoint]u8) ?[]const u8 {
    if (old_port == new_port) return null;
    const colon = std.mem.lastIndexOfScalar(u8, endpoint, ':') orelse return null;
    const p = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch return null;
    if (p != old_port) return null;
    return std.fmt.bufPrint(buf, "{s}:{d}", .{ endpoint[0..colon], new_port }) catch null;
}

// ------------------------------------------------------------ tests

const testing = std.testing;

test "announcement message and acknowledgements: only the desk's own number counts" {
    const io = testing.io;
    var a: Announce = .{};
    var mb: [Announce.max_message]u8 = undefined;
    try testing.expect(a.message(io, &mb) == null);
    const id1: devices.DeviceId = @splat(1);
    const id2: devices.DeviceId = @splat(2);
    // Nothing announced: no acknowledgement counts.
    try testing.expect(!a.ack(io, id1, "1"));
    a.set(io, 1700000000, "home.example.org:51821");
    try testing.expectEqualStrings("{\"t\":\"endpoint\",\"endpoint\":\"home.example.org:51821\",\"seq\":1700000000}", a.message(io, &mb).?);
    // The wrong number, or anything that is not exactly a number.
    for ([_][]const u8{ "1699999999", "1700000001", "1700000000 ", "home.example.org:51821", "", "{\"t\":\"endpoint\"}" }) |r|
        try testing.expect(!a.ack(io, id1, r));
    try testing.expect(!a.hasAcked(io, id1));
    try testing.expect(a.ack(io, id1, "1700000000"));
    try testing.expect(a.hasAcked(io, id1) and !a.hasAcked(io, id2));
    // Waiting returns at once when everyone acknowledged; else at the deadline.
    a.awaitAcks(io, &.{id1}, Io.Clock.awake.now(io).toMilliseconds() + 60_000);
    const t0 = Io.Clock.awake.now(io).toMilliseconds();
    a.awaitAcks(io, &.{ id1, id2 }, t0 + 50);
    try testing.expect(Io.Clock.awake.now(io).toMilliseconds() - t0 >= 40);
    // A new announcement starts over.
    a.set(io, 1700000001, "home.example.org:51822");
    try testing.expect(!a.hasAcked(io, id1));
}

test "the announcement number only grows, and is stored" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db: [1024]u8 = undefined;
    const dir = db[0..try tmp.dir.realPath(io, &db)];
    const a = try nextSeq(testing.allocator, io, dir, 1000);
    try testing.expectEqual(@as(u64, 1000), a);
    const b = try nextSeq(testing.allocator, io, dir, 900); // the clock went back
    try testing.expectEqual(@as(u64, 1001), b);
    const c = try nextSeq(testing.allocator, io, dir, 5000);
    try testing.expectEqual(@as(u64, 5000), c);
}

test "a port change carries the endpoint's port along only when it named the old one" {
    var b: [pairqr.max_endpoint]u8 = undefined;
    try testing.expectEqualStrings("home.example.org:51821", followPort("home.example.org:51820", 51820, 51821, &b).?);
    try testing.expectEqualStrings("[2001:db8::1]:51821", followPort("[2001:db8::1]:51820", 51820, 51821, &b).?);
    try testing.expect(followPort("home.example.org:4000", 51820, 51821, &b) == null);
    try testing.expect(followPort("home.example.org:51820", 51820, 51820, &b) == null);
}

/// A fake desk for `run`.
const Fake = struct {
    move: Announce = .{},
    port: u16 = 51820,
    bind_err: ?anyerror = null,
    fail_port: ?u16 = null,
    announced: std.ArrayList(u64) = .empty,
    /// The connected devices acknowledge at once (as their clients do).
    connected: []const devices.DeviceId = &.{},
    paired: []const PeerInfo = &.{},

    pub fn udpPort(f: *Fake) u16 {
        return f.port;
    }
    pub fn bindError(f: *Fake) ?anyerror {
        return f.bind_err;
    }
    pub fn setUdpPort(f: *Fake, p: u16) !void {
        if (f.fail_port == p) return error.AddressInUse;
        f.port = p;
        f.bind_err = null;
    }
    pub fn announceEndpoint(f: *Fake, seq: u64, ep: []const u8) void {
        f.move.set(testing.io, seq, ep);
        f.announced.append(testing.allocator, seq) catch {};
        var b: [24]u8 = undefined;
        for (f.connected) |id| _ = f.move.ack(testing.io, id, frames.movedFrame(seq, &b)[2..]);
    }
    pub fn connectedDevices(f: *Fake, out: []devices.DeviceId) []devices.DeviceId {
        @memcpy(out[0..f.connected.len], f.connected);
        return out[0..f.connected.len];
    }
    pub fn pairedDevices(f: *Fake, out: []PeerInfo) []PeerInfo {
        @memcpy(out[0..f.paired.len], f.paired);
        return out[0..f.paired.len];
    }
};

fn testLog(dir: []const u8) !Log {
    var pb: [1100]u8 = undefined;
    return Log.open(testing.allocator, testing.io, try fsutil.join(&pb, &.{ dir, "portal.log" }));
}

test "a move: connected devices are told and acknowledge, then the port moves; the rest are 'not yet'" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db: [1024]u8 = undefined;
    const dir = db[0..try tmp.dir.realPath(io, &db)];
    var log = try testLog(dir);
    defer log.close();
    var laptop: PeerInfo = .{ .id = @splat(1), .name = .{} };
    laptop.name.set("laptop");
    var phone: PeerInfo = .{ .id = @splat(2), .name = .{} };
    phone.name.set("iphone");
    var f: Fake = .{ .connected = &.{laptop.id}, .paired = &.{ laptop, phone } };
    defer f.announced.deinit(testing.allocator);
    const D = Desk(Fake, Fake);
    const d: D = .{ .gpa = testing.allocator, .io = io, .srv = &f, .tun = &f, .dir = dir, .log = &log };
    const o = d.run(.{ .port = 51821, .endpoint = "home.example.org:51821", .old_endpoint = "home.example.org:51820" });
    try testing.expect(o.announced and o.port_moved and o.port_error == null);
    try testing.expectEqual(@as(u16, 51821), f.port);
    try testing.expectEqual(RowState.moved, o.slice()[0].state);
    try testing.expectEqual(RowState.not_connected, o.slice()[1].state);
    try testing.expectEqual(@as(usize, 1), f.announced.items.len);

    // The new port can't be bound: the old endpoint is announced again
    // (a newer number) and the port stays.
    f.fail_port = 51822;
    const bad = d.run(.{ .port = 51822, .endpoint = "home.example.org:51822", .old_endpoint = "home.example.org:51821" });
    try testing.expect(bad.port_error != null and !bad.port_moved);
    try testing.expectEqual(@as(u16, 51821), f.port);
    try testing.expectEqual(@as(usize, 3), f.announced.items.len);
    try testing.expect(f.announced.items[2] > f.announced.items[1]);
    var mb: [Announce.max_message]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, f.move.message(io, &mb).?, "home.example.org:51821") != null);

    // A probe that fails tells nobody anything.
    const probe = struct {
        fn p(_: u16) anyerror!void {
            return error.AddressInUse;
        }
    }.p;
    const dp: D = .{ .gpa = testing.allocator, .io = io, .srv = &f, .tun = &f, .dir = dir, .log = &log, .probe = probe };
    const refused = dp.run(.{ .port = 51900, .endpoint = "home.example.org:51900" });
    try testing.expect(refused.port_error != null and !refused.announced);
    try testing.expectEqual(@as(usize, 3), f.announced.items.len);

    // A port unbound since start (it was busy): moving binds it.
    f.bind_err = error.AddressInUse;
    const fixed = dp.run(.{ .port = 51901 });
    try testing.expect(fixed.port_moved and !fixed.announced);
    try testing.expectEqual(@as(u16, 51901), f.port);
}
