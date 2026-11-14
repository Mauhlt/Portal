//! Paired devices. A device IS its WireGuard public key: the in-process
//! tunnel lets in exactly the keys listed here, each only from its own
//! tunnel address, so a connection from 10.8.0.x is that device and no
//! other (WireGuard's allowed-IPs source check). There are no cookies,
//! credentials, rotation or sign-in: the tunnel's handshake is the
//! authentication, and TLS 1.3 with the pinned Portal CA on top of it is
//! defence in depth for the desktop's identity.
//!
//! Pairing happens at the desk only; nothing is exchanged over the
//! network before the device's key is in the peer table:
//!   1. the device (`portal connect`) shows its public key and that key's
//!      check code (shared/tunnelnet.zig checkCode, "ABCDE-FGHJK");
//!   2. the owner enters the name and the key at the desk (Pair a device,
//!      or `portalctl pair <name> <key>`); the desk shows the check code
//!      of what was entered, and the owner approves only if both screens
//!      show the same code (`pair`);
//!   3. the desk shows the pairing code for the device: its own key (with
//!      its check code), endpoint, the CA fingerprint and the device's
//!      tunnel address (shared/pairqr.zig, version 2).
//!
//!  * Every record has a random id, issued when it is paired: what live
//!    connections are tagged with.
//!  * Pairing under a name, or a key, already in use removes the old
//!    record outright (its connections end); nothing is updated in place.
//!    The address is kept for a re-paired name, else the lowest free one.
//!  * Forget is mutual: a device that forgets this desktop says so on its
//!    WebSocket and its record goes; a record removed at the desk (Unpair,
//!    `portalctl unpair`) ends its connections with a `logout` message,
//!    after which the device forgets this desktop. A device that is
//!    offline then only finds the desktop unreachable (its key is no
//!    longer let in); the owner forgets it there.
//!  * Devices unused for 90 days are forgotten.
//!
//! The store is a small text file shared by the running Portal and the
//! `portalctl pair/devices/unpair` commands; every change is a locked
//! read-modify-write with a flushed, atomic replace (see `withStore`).
//! Processes learn about each other's changes from a directory change
//! notification (`DirWatch`), not by polling.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const fsutil = @import("fsutil.zig");
const tunnelnet = @import("shared").tunnelnet;
const wgkeys = @import("WireGuard").device.keys;

pub const max_devices = 16;
pub const max_name = 32;
pub const max_ip = tunnelnet.max_ip_text;
pub const id_len = 16;
pub const DeviceId = [id_len]u8;
pub const Key = wgkeys.Key;
/// Devices unused for this long are forgotten.
pub const unused_expiry_s: i64 = 90 * 24 * 3600;
/// `last_seen` is written at most this often (a connect writes the store
/// only when the previous mark is older).
pub const seen_granularity_s: i64 = 3600;

/// v4: devices are WireGuard keys. Earlier files (cookie credentials) hold
/// nothing a tunnel can use: they read as an empty store and are rewritten
/// as v4 (every device is paired again), see `parse`.
const header = "portal-devices-v4";
const old_headers = [_][]const u8{ "portal-devices-v1", "portal-devices-v2", "portal-devices-v3" };

pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name) return false;
    for (name) |c| switch (c) {
        'a'...'z', '0'...'9', '-' => {},
        else => return false,
    };
    return true;
}

pub const Text = struct {
    buf: [max_name]u8 = undefined,
    len: u8 = 0,
    pub fn set(t: *Text, s: []const u8) void {
        const n = @min(s.len, t.buf.len);
        @memcpy(t.buf[0..n], s[0..n]);
        t.len = @intCast(n);
    }
    pub fn get(t: *const Text) []const u8 {
        return t.buf[0..t.len];
    }
};

pub const Device = struct {
    name: Text = .{},
    /// Its tunnel address (10.8.0.x).
    ip: tunnelnet.Ip4,
    /// Its WireGuard public key: the device's identity.
    key: Key,
    /// Random, issued at pairing; what live connections are tagged with.
    id: DeviceId,
    created: i64,
    last_seen: i64,

    pub fn ipText(d: *const Device, buf: *[tunnelnet.max_ip_text]u8) []const u8 {
        return tunnelnet.formatIp(d.ip, buf);
    }

    pub fn keyText(d: *const Device) [wgkeys.base64_len]u8 {
        return wgkeys.encode(&d.key);
    }
};

/// Records a pairing removed (same name or same key as the new one). The
/// caller ends their connections.
pub const Replaced = struct {
    list: [max_devices]Device = undefined,
    n: usize = 0,

    pub fn items(r: *const Replaced) []const Device {
        return r.list[0..r.n];
    }
};

pub const Paired = struct {
    device: Device,
    replaced: Replaced = .{},
};

pub const PairError = error{ BadName, BadKey, OwnKey, TooManyDevices, NoAddressLeft, DuplicateDeviceId };

pub const Store = struct {
    devices: [max_devices]?Device = @splat(null),

    pub fn find(s: *const Store, name: []const u8) ?usize {
        for (s.devices, 0..) |d, i| if (d) |dev| if (std.mem.eql(u8, dev.name.get(), name)) return i;
        return null;
    }

    pub fn findId(s: *const Store, id: DeviceId) ?usize {
        for (s.devices, 0..) |d, i| if (d) |dev| if (std.mem.eql(u8, &dev.id, &id)) return i;
        return null;
    }

    /// The device using tunnel address `ip` (at most one).
    pub fn findIp(s: *const Store, ip: tunnelnet.Ip4) ?usize {
        for (s.devices, 0..) |d, i| if (d) |dev| if (std.mem.eql(u8, &dev.ip, &ip)) return i;
        return null;
    }

    pub fn findKey(s: *const Store, k: *const Key) ?usize {
        for (s.devices, 0..) |d, i| if (d) |dev| if (std.mem.eql(u8, &dev.key, k)) return i;
        return null;
    }

    pub fn count(s: *const Store) usize {
        var n: usize = 0;
        for (s.devices) |d| n += @intFromBool(d != null);
        return n;
    }

    /// Forgets long-unused devices.
    pub fn expire(s: *Store, now: i64) bool {
        var changed = false;
        for (&s.devices) |*slot| if (slot.*) |d| if (now -| d.last_seen > unused_expiry_s) {
            slot.* = null;
            changed = true;
        };
        return changed;
    }

    /// The desk approved device `name` with public key `k` (after the
    /// owner compared its check code on both screens). Removes any record
    /// with the same name or key (reported in `replaced`), then adds the
    /// new one with id `new_id`. `desk_key` is the desk's own public key,
    /// which can never be a device.
    pub fn pair(s: *Store, name: []const u8, k: Key, desk_key: Key, new_id: DeviceId, now: i64) PairError!Paired {
        if (!validName(name)) return error.BadName;
        if (wgkeys.isZero(&k)) return error.BadKey;
        if (std.mem.eql(u8, &k, &desk_key)) return error.OwnKey;
        // An id collision (2^-128) would let connections cross records.
        if (s.findId(new_id) != null) return error.DuplicateDeviceId;
        var out: Paired = .{ .device = undefined };
        var prefer: ?tunnelnet.Ip4 = null;
        for (&s.devices) |*slot| if (slot.*) |d| {
            const same_name = std.mem.eql(u8, d.name.get(), name);
            if (same_name or std.mem.eql(u8, &d.key, &k)) {
                if (same_name) prefer = d.ip;
                out.replaced.list[out.replaced.n] = d;
                out.replaced.n += 1;
                slot.* = null;
            }
        };
        var used: [max_devices]tunnelnet.Ip4 = undefined;
        var nu: usize = 0;
        for (s.devices) |slot| if (slot) |d| {
            used[nu] = d.ip;
            nu += 1;
        };
        const ip = tunnelnet.assign(used[0..nu], prefer) orelse return error.NoAddressLeft;
        var dev: Device = .{ .ip = ip, .key = k, .id = new_id, .created = now, .last_seen = now };
        dev.name.set(name);
        for (&s.devices) |*slot| if (slot.* == null) {
            slot.* = dev;
            out.device = dev;
            return out;
        };
        return error.TooManyDevices;
    }

    /// Unpairs device `name`.
    pub fn remove(s: *Store, name: []const u8) ?Device {
        const i = s.find(name) orelse return null;
        defer s.devices[i] = null;
        return s.devices[i];
    }

    /// Removes record `id` only (a newer record under the same name stays).
    pub fn removeId(s: *Store, id: DeviceId) ?Device {
        const i = s.findId(id) orelse return null;
        defer s.devices[i] = null;
        return s.devices[i];
    }

    /// A connection from device `id` at `now`: true if `last_seen` moved.
    pub fn markSeen(s: *Store, id: DeviceId, now: i64) bool {
        const i = s.findId(id) orelse return false;
        const d = &s.devices[i].?;
        if (now -| d.last_seen < seen_granularity_s) return false;
        d.last_seen = now;
        return true;
    }

    // ----------------------------------------------------------- file format

    ///   portal-devices-v4
    ///   dev <name> <10.8.0.x> <WireGuard public key> <id hex> <created> <last_seen>
    pub fn parse(text: []const u8) error{BadDeviceFile}!Store {
        var s: Store = .{};
        var lines = std.mem.tokenizeAny(u8, text, "\r\n");
        const first = lines.next() orelse return error.BadDeviceFile;
        for (old_headers) |h| if (std.mem.eql(u8, first, h)) return s;
        if (!std.mem.eql(u8, first, header)) return error.BadDeviceFile;
        var n: usize = 0;
        while (lines.next()) |line| {
            var f = std.mem.tokenizeScalar(u8, line, ' ');
            const kind = f.next() orelse continue;
            if (!std.mem.eql(u8, kind, "dev") or n >= max_devices) return error.BadDeviceFile;
            const name = f.next() orelse return error.BadDeviceFile;
            const ip = tunnelnet.parseIp(f.next() orelse return error.BadDeviceFile) orelse return error.BadDeviceFile;
            const k = wgkeys.decode(f.next() orelse return error.BadDeviceFile) catch return error.BadDeviceFile;
            const id = try parseId(f.next());
            var d: Device = .{ .ip = ip, .key = k, .id = id, .created = try parseInt(f.next()), .last_seen = try parseInt(f.next()) };
            if (f.next() != null) return error.BadDeviceFile;
            if (!validName(name) or !tunnelnet.isDeviceIp(ip)) return error.BadDeviceFile;
            d.name.set(name);
            // One record per name, id, address and key.
            for (s.devices[0..n]) |o| {
                const e = o.?;
                if (std.mem.eql(u8, e.name.get(), name) or std.mem.eql(u8, &e.id, &id) or
                    std.mem.eql(u8, &e.ip, &ip) or std.mem.eql(u8, &e.key, &k)) return error.BadDeviceFile;
            }
            s.devices[n] = d;
            n += 1;
        }
        return s;
    }

    pub fn format(s: *const Store, gpa: Allocator, out: *std.ArrayList(u8)) !void {
        var buf: [256]u8 = undefined;
        try out.appendSlice(gpa, header ++ "\n");
        for (s.devices) |slot| {
            const d = slot orelse continue;
            var ib: [tunnelnet.max_ip_text]u8 = undefined;
            try out.appendSlice(gpa, try std.fmt.bufPrint(&buf, "dev {s} {s} {s} {x} {d} {d}\n", .{
                d.name.get(), d.ipText(&ib), &d.keyText(), &d.id, d.created, d.last_seen,
            }));
        }
    }
};

fn parseInt(s: ?[]const u8) error{BadDeviceFile}!i64 {
    return std.fmt.parseInt(i64, s orelse return error.BadDeviceFile, 10) catch error.BadDeviceFile;
}

fn parseId(s: ?[]const u8) error{BadDeviceFile}!DeviceId {
    const hex = s orelse return error.BadDeviceFile;
    if (hex.len != 2 * id_len) return error.BadDeviceFile;
    var id: DeviceId = undefined;
    _ = std.fmt.hexToBytes(&id, hex) catch return error.BadDeviceFile;
    return id;
}

/// A one-line explanation, with the way out, for errors from `withStore`
/// and `Desk`.
pub fn describeError(err: anyerror) []const u8 {
    return switch (err) {
        error.BadDeviceFile => "the device list (devices.txt in %LOCALAPPDATA%\\Portal) is damaged or from a newer Portal. " ++
            "To recover: close Portal, move devices.txt somewhere else (keep it if you want to report the problem), " ++
            "start Portal again, and re-pair every device (Pair a device in the Portal window)",
        error.DeviceStoreBusy => "the device list is held open by an older Portal process; close it and try again",
        error.DeviceStoreWriteFailed => "could not replace devices.txt (disk full, or the file is locked by another program)",
        error.BadName => "a device name is 1-32 characters of a-z, 0-9 and -",
        error.BadKey => "that is not a WireGuard public key (44 characters ending in =, as the device shows it)",
        error.OwnKey => "that is this desktop's own key, not the device's",
        error.TooManyDevices => "16 devices are paired already; unpair one first",
        error.NoAddressLeft => "no tunnel address is left",
        else => "could not access the device list in %LOCALAPPDATA%\\Portal",
    };
}

// ------------------------------------------------------------- file access

/// %LOCALAPPDATA%\Portal
pub const Paths = fsutil.DataDir;

/// Locked read-modify-write of the device store. `op(ctx, *Store)` returns
/// whether it changed the store; if so the file is replaced atomically
/// (written, flushed to disk, then renamed over the old one). The lock is
/// `devices.lock`, shared with every other Portal process; waiting for it
/// blocks without polling, and a cancel during the wait is returned and
/// stays armed (fsutil.FileLock).
pub fn withStore(gpa: Allocator, io: Io, paths: Paths, now: i64, ctx: anytype, comptime op: anytype) !void {
    var lb: [1024]u8 = undefined;
    var pb: [1024]u8 = undefined;
    const Ctx = struct { gpa: Allocator, now: i64, inner: @TypeOf(ctx) };
    fsutil.update(gpa, io, try lockPath(paths, &lb), try paths.join(&pb, &.{"devices.txt"}), 64 * 1024, Ctx{
        .gpa = gpa,
        .now = now,
        .inner = ctx,
    }, struct {
        fn edit(c: Ctx, old: ?[]const u8, out: *std.ArrayList(u8)) !bool {
            var legacy = false;
            if (old) |text| for (old_headers) |h| {
                if (std.mem.startsWith(u8, text, h)) legacy = true;
            };
            var store: Store = if (old) |text| try Store.parse(text) else .{}; // corrupt file: fail closed
            var dirty = store.expire(c.now) or legacy; // an old format is rewritten as v4
            if (try op(c.inner, &store)) dirty = true;
            if (!dirty) return false;
            try store.format(c.gpa, out);
            return true;
        }
    }.edit) catch |err| return switch (err) {
        error.LockBusy => error.DeviceStoreBusy,
        error.ReplaceFailed => error.DeviceStoreWriteFailed,
        else => err,
    };
}

/// The store's lock file (`withStore`). Anything else that must not race
/// a pairing (the desk's tunnel key, tunneldesk.zig) takes it too.
pub fn lockPath(paths: Paths, buf: []u8) ![]const u8 {
    return paths.join(buf, &.{"devices.lock"});
}

/// The store as it is now (a locked read; changes nothing but expiry).
pub fn read(gpa: Allocator, io: Io, paths: Paths) !Store {
    var st: Store = .{};
    try withStore(gpa, io, paths, Io.Timestamp.now(io, .real).toSeconds(), &st, struct {
        fn op(o: *Store, s: *Store) !bool {
            o.* = s.*;
            return false;
        }
    }.op);
    return st;
}

// ------------------------------------------------------ desk approval API

/// The desk side of pairing, used by `portalctl pair` and the Portal
/// window alike. Each call is one locked read-modify-write of the store;
/// the running Portal sees it through `DirWatch` and updates the tunnel's
/// peer table and its live connections.
pub const Desk = struct {
    gpa: Allocator,
    io: Io,
    paths: Paths,

    fn now(d: Desk) i64 {
        return Io.Timestamp.now(d.io, .real).toSeconds();
    }

    /// Records the approved device (see `Store.pair`).
    pub fn pair(d: Desk, name: []const u8, k: Key, desk_key: Key) !Paired {
        var id: DeviceId = undefined;
        try d.io.randomSecure(&id);
        var out: Paired = undefined;
        const t = d.now();
        const Ctx = struct { name: []const u8, k: Key, desk_key: Key, id: DeviceId, now: i64, out: *Paired };
        try withStore(d.gpa, d.io, d.paths, t, Ctx{ .name = name, .k = k, .desk_key = desk_key, .id = id, .now = t, .out = &out }, struct {
            fn op(c: Ctx, st: *Store) !bool {
                c.out.* = try st.pair(c.name, c.k, c.desk_key, c.id, c.now);
                return true;
            }
        }.op);
        return out;
    }

    /// Unpairs `name`; the removed record, if there was one.
    pub fn unpair(d: Desk, name: []const u8) !?Device {
        var out: ?Device = null;
        const Ctx = struct { name: []const u8, out: *?Device };
        try withStore(d.gpa, d.io, d.paths, d.now(), Ctx{ .name = name, .out = &out }, struct {
            fn op(c: Ctx, st: *Store) !bool {
                c.out.* = st.remove(c.name);
                return c.out.* != null;
            }
        }.op);
        return out;
    }

    /// Removes record `id` only (a device forgetting this desktop, or
    /// Unpair at the desk: a record paired again under the same name
    /// meanwhile stays). True if it was there.
    pub fn forget(d: Desk, id: DeviceId) !bool {
        var removed = false;
        const Ctx = struct { id: DeviceId, out: *bool };
        try withStore(d.gpa, d.io, d.paths, d.now(), Ctx{ .id = id, .out = &removed }, struct {
            fn op(c: Ctx, st: *Store) !bool {
                c.out.* = st.removeId(c.id) != null;
                return c.out.*;
            }
        }.op);
        return removed;
    }

    pub fn markSeen(d: Desk, id: DeviceId) !void {
        const t = d.now();
        const Ctx = struct { id: DeviceId, now: i64 };
        try withStore(d.gpa, d.io, d.paths, t, Ctx{ .id = id, .now = t }, struct {
            fn op(c: Ctx, st: *Store) !bool {
                return st.markSeen(c.id, c.now);
            }
        }.op);
    }
};

// --------------------------------------------------- change notification

/// Signalled whenever a file in the data directory is created, renamed or
/// deleted. Every store change ends in a rename (see `withStore`), so this
/// wakes every Portal process sharing the directory without anyone
/// polling. Log appends do not trigger it.
pub fn watchStore(gpa: Allocator, paths: Paths) !fsutil.DirWatch {
    return fsutil.DirWatch.open(gpa, paths.dir, .{});
}

// -------------------------------------------------------------------- tests

const testing = std.testing;

fn testKey(fill: u8) Key {
    var k: Key = @splat(fill);
    k[0] = 1;
    return k;
}

const test_desk_key = testKey(0xdd);

test "pair: addresses lowest first, re-pair keeps the address and replaces the record" {
    var s: Store = .{};
    const a = try s.pair("laptop", testKey(2), test_desk_key, @splat(1), 10);
    try testing.expectEqual(tunnelnet.Ip4{ 10, 8, 0, 2 }, a.device.ip);
    const b = try s.pair("iphone", testKey(3), test_desk_key, @splat(2), 11);
    try testing.expectEqual(tunnelnet.Ip4{ 10, 8, 0, 3 }, b.device.ip);
    const c = try s.pair("surface", testKey(4), test_desk_key, @splat(3), 12);
    try testing.expectEqual(tunnelnet.Ip4{ 10, 8, 0, 4 }, c.device.ip);
    // The laptop gets a new key: same address, a new record, the old one reported.
    const a2 = try s.pair("laptop", testKey(5), test_desk_key, @splat(4), 13);
    try testing.expectEqual(tunnelnet.Ip4{ 10, 8, 0, 2 }, a2.device.ip);
    try testing.expectEqual(@as(usize, 1), a2.replaced.n);
    try testing.expectEqualSlices(u8, &a.device.id, &a2.replaced.items()[0].id);
    try testing.expect(s.findKey(&testKey(2)) == null);
    try testing.expectEqual(@as(usize, 3), s.count());
    // The same key under another name replaces that record too (one record per key).
    const d = try s.pair("tablet", testKey(5), test_desk_key, @splat(5), 14);
    try testing.expectEqual(@as(usize, 1), d.replaced.n);
    try testing.expect(s.find("laptop") == null);
    try testing.expectEqual(tunnelnet.Ip4{ 10, 8, 0, 2 }, d.device.ip); // lowest free
    try testing.expectEqual(@as(?usize, s.find("tablet")), s.findIp(.{ 10, 8, 0, 2 }));
}

test "pair refuses bad names, empty keys, the desk's own key, a duplicate id" {
    var s: Store = .{};
    try testing.expectError(error.BadName, s.pair("Laptop", testKey(2), test_desk_key, @splat(1), 1));
    try testing.expectError(error.BadKey, s.pair("laptop", @splat(0), test_desk_key, @splat(1), 1));
    try testing.expectError(error.OwnKey, s.pair("laptop", test_desk_key, test_desk_key, @splat(1), 1));
    _ = try s.pair("laptop", testKey(2), test_desk_key, @splat(1), 1);
    try testing.expectError(error.DuplicateDeviceId, s.pair("phone", testKey(3), test_desk_key, @splat(1), 1));
}

test "store file round trip; old formats read as empty; damage fails closed" {
    var s: Store = .{};
    _ = try s.pair("laptop", testKey(2), test_desk_key, @splat(0xab), 100);
    _ = try s.pair("iphone", testKey(3), test_desk_key, @splat(0xcd), 200);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try s.format(testing.allocator, &out);
    const back = try Store.parse(out.items);
    try testing.expectEqual(@as(usize, 2), back.count());
    const i = back.find("iphone").?;
    try testing.expectEqual(tunnelnet.Ip4{ 10, 8, 0, 3 }, back.devices[i].?.ip);
    try testing.expectEqualSlices(u8, &testKey(3), &back.devices[i].?.key);
    try testing.expectEqual(@as(i64, 200), back.devices[i].?.created);

    try testing.expectEqual(@as(usize, 0), (try Store.parse("portal-devices-v3\ndev a 10.8.0.2 00 00 1 1\n")).count());
    try testing.expectError(error.BadDeviceFile, Store.parse("portal-devices-v9\n"));
    try testing.expectError(error.BadDeviceFile, Store.parse(""));
    const kt = wgkeys.encode(&testKey(9));
    const zid = "00000000000000000000000000000000";
    var line: [200]u8 = undefined;
    // A second record for an address in use.
    var dup: std.ArrayList(u8) = .empty;
    defer dup.deinit(testing.allocator);
    try dup.appendSlice(testing.allocator, out.items);
    try dup.appendSlice(testing.allocator, try std.fmt.bufPrint(&line, "dev other 10.8.0.2 {s} {s} 1 1\n", .{ &kt, zid }));
    try testing.expectError(error.BadDeviceFile, Store.parse(dup.items));
    // The desk's address, a bad key, a trailing field.
    try testing.expectError(error.BadDeviceFile, Store.parse(try std.fmt.bufPrint(&line, header ++ "\ndev a 10.8.0.1 {s} {s} 1 1\n", .{ &kt, zid })));
    try testing.expectError(error.BadDeviceFile, Store.parse(try std.fmt.bufPrint(&line, header ++ "\ndev a 10.8.0.2 notakey {s} 1 1\n", .{zid})));
    try testing.expectError(error.BadDeviceFile, Store.parse(try std.fmt.bufPrint(&line, header ++ "\ndev a 10.8.0.2 {s} {s} 1 1 x\n", .{ &kt, zid })));
}

test "expiry, last seen, forget by id" {
    var s: Store = .{};
    const a = try s.pair("laptop", testKey(2), test_desk_key, @splat(1), 0);
    try testing.expect(!s.markSeen(a.device.id, 10)); // within the granularity
    try testing.expect(s.markSeen(a.device.id, seen_granularity_s + 1));
    try testing.expect(!s.expire(unused_expiry_s));
    try testing.expect(s.expire(seen_granularity_s + 2 + unused_expiry_s));
    try testing.expectEqual(@as(usize, 0), s.count());
    const b = try s.pair("laptop", testKey(2), test_desk_key, @splat(2), 0);
    _ = try s.pair("laptop", testKey(3), test_desk_key, @splat(3), 0); // re-paired
    try testing.expect(s.removeId(b.device.id) == null); // the old id is gone already
    try testing.expectEqual(@as(usize, 1), s.count());
}
