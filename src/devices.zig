//! Paired devices: the credential model that replaced the static token.
//!
//!  * `portal pair <name>` at the desktop opens a short pairing window.
//!  * A device that taps "Pair this device" inside the window gets a random
//!    256-bit device secret (cookie `portal_device=<name>.<secret>`; the native
//!    client keeps it in the OS credential store). Only its SHA-256 is stored.
//!  * The credential is bound to the device's source address (its WireGuard
//!    address), and rotates every time it is used: the new secret replaces
//!    the old, which stays valid for `grace_s` only so a lost response does
//!    not lock the device out.
//!  * Presenting any other secret for a known device revokes the device:
//!    either the credential was copied and used elsewhere, or it is garbage.
//!    Either way, re-pairing at the desk is required.
//!
//! The store is a small text file shared by the running server and the
//! `portal pair/devices/unpair` commands; every change is a locked
//! read-modify-write with an atomic replace (see `withStore`).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const auth = @import("auth.zig");
const w = @import("win32.zig");

pub const max_devices = 16;
pub const max_name = 32;
pub const max_ip = 46;
/// How long the previous secret stays valid after a rotation.
pub const grace_s: i64 = 10 * 60;
/// Devices unused for this long are forgotten.
pub const unused_expiry_s: i64 = 90 * 24 * 3600;
pub const default_pair_window_s: i64 = 120;
pub const max_pair_window_s: i64 = 600;

const header = "portal-devices-v1";

pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name) return false;
    for (name) |c| switch (c) {
        'a'...'z', '0'...'9', '-' => {},
        else => return false,
    };
    return true;
}

fn validIp(ip: []const u8) bool {
    if (ip.len == 0 or ip.len > max_ip) return false;
    for (ip) |c| switch (c) {
        '0'...'9', 'a'...'f', 'A'...'F', '.', ':', '%' => {},
        else => return false,
    };
    return true;
}

/// "10.8.0.2:51234" -> "10.8.0.2"; "[fd00::2]:5" -> "fd00::2".
pub fn ipOnly(peer: []const u8) []const u8 {
    if (peer.len > 0 and peer[0] == '[') {
        const end = std.mem.indexOfScalar(u8, peer, ']') orelse return peer;
        return peer[1..end];
    }
    const colon = std.mem.lastIndexOfScalar(u8, peer, ':') orelse return peer;
    return peer[0..colon];
}

const Text = struct {
    buf: [max_ip]u8 = undefined,
    len: u8 = 0,
    fn set(t: *Text, s: []const u8) void {
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
    ip: Text = .{},
    cur: auth.Hash,
    prev: ?auth.Hash = null,
    prev_until: i64 = 0,
    created: i64,
    last_seen: i64,
};

pub const Pairing = struct {
    name: Text = .{},
    expires: i64,
};

pub const AuthResult = union(enum) {
    /// Valid. Caller should rotate with `rotate(idx, ...)`.
    ok: usize,
    /// Known device, but presented from a different address. Not revoked.
    wrong_address,
    /// Wrong or stale secret for a known device: the device was revoked.
    revoked: []const u8,
    unknown,
};

pub const Store = struct {
    devices: [max_devices]?Device = @splat(null),
    pairing: ?Pairing = null,

    pub fn find(s: *const Store, name: []const u8) ?usize {
        for (s.devices, 0..) |d, i| {
            if (d) |dev| if (std.mem.eql(u8, dev.name.get(), name)) return i;
        }
        return null;
    }

    pub fn count(s: *const Store) usize {
        var n: usize = 0;
        for (s.devices) |d| {
            if (d != null) n += 1;
        }
        return n;
    }

    /// Drops expired pairing windows and long-unused devices.
    pub fn expire(s: *Store, now: i64) bool {
        var changed = false;
        if (s.pairing) |p| if (now > p.expires or now < p.expires - max_pair_window_s) {
            s.pairing = null;
            changed = true;
        };
        for (&s.devices) |*slot| {
            if (slot.*) |d| if (now -| d.last_seen > unused_expiry_s) {
                slot.* = null;
                changed = true;
            };
        }
        return changed;
    }

    /// Checks a presented `<name>.<secret>` cookie from address `ip`.
    /// May modify the store (revocation); caller persists it.
    pub fn authenticate(s: *Store, cookie: []const u8, ip: []const u8, now: i64) AuthResult {
        const dot = std.mem.indexOfScalar(u8, cookie, '.') orelse return .unknown;
        const name = cookie[0..dot];
        const secret = cookie[dot + 1 ..];
        if (!validName(name) or secret.len != auth.encoded_len) return .unknown;
        const idx = s.find(name) orelse return .unknown;
        const dev = &s.devices[idx].?;
        if (!std.mem.eql(u8, dev.ip.get(), ip)) return .wrong_address;
        const h = auth.hashSecret(secret);
        const is_cur = std.crypto.timing_safe.eql(auth.Hash, h, dev.cur);
        const is_prev = if (dev.prev) |p|
            std.crypto.timing_safe.eql(auth.Hash, h, p) and now <= dev.prev_until
        else
            false;
        if (is_cur or is_prev) return .{ .ok = idx };
        s.devices[idx] = null;
        return .{ .revoked = name };
    }

    /// Replaces the device's secret with `new_hash`. The secret just
    /// presented stays valid for `grace_s`.
    pub fn rotate(s: *Store, idx: usize, presented: []const u8, new_hash: auth.Hash, now: i64) void {
        const dev = &(s.devices[idx] orelse return);
        const dot = std.mem.indexOfScalar(u8, presented, '.') orelse return;
        dev.prev = auth.hashSecret(presented[dot + 1 ..]);
        dev.prev_until = now +| grace_s;
        dev.cur = new_hash;
        dev.last_seen = now;
    }

    pub fn beginPair(s: *Store, name: []const u8, now: i64, window_s: i64) !void {
        if (!validName(name)) return error.BadName;
        var p: Pairing = .{ .expires = now +| std.math.clamp(window_s, 10, max_pair_window_s) };
        p.name.set(name);
        s.pairing = p;
    }

    pub fn pairingName(s: *const Store, now: i64) ?[]const u8 {
        const p = &(s.pairing orelse return null);
        if (now > p.expires) return null;
        return p.name.get();
    }

    /// Consumes the pairing window, registering the device at `ip`. A device
    /// already using that name, or that address, is replaced.
    pub fn completePair(s: *Store, ip: []const u8, new_hash: auth.Hash, now: i64) ![]const u8 {
        const name = s.pairingName(now) orelse return error.NoPairingWindow;
        if (!validIp(ip)) return error.BadAddress;
        var dev: Device = .{ .cur = new_hash, .created = now, .last_seen = now };
        dev.name.set(name);
        dev.ip.set(ip);
        s.pairing = null;
        for (&s.devices) |*slot| {
            if (slot.*) |d| if (std.mem.eql(u8, d.name.get(), dev.name.get()) or std.mem.eql(u8, d.ip.get(), ip)) {
                slot.* = null;
            };
        }
        for (&s.devices) |*slot| {
            if (slot.* == null) {
                slot.* = dev;
                return slot.*.?.name.get();
            }
        }
        return error.TooManyDevices;
    }

    pub fn remove(s: *Store, name: []const u8) bool {
        const idx = s.find(name) orelse return false;
        s.devices[idx] = null;
        return true;
    }

    // ----------------------------------------------------------- file format

    pub fn parse(text: []const u8) !Store {
        var s: Store = .{};
        var lines = std.mem.tokenizeAny(u8, text, "\r\n");
        const first = lines.next() orelse return error.BadDeviceFile;
        if (!std.mem.eql(u8, first, header)) return error.BadDeviceFile;
        var n: usize = 0;
        while (lines.next()) |line| {
            var f = std.mem.tokenizeScalar(u8, line, ' ');
            const kind = f.next() orelse continue;
            if (std.mem.eql(u8, kind, "pair")) {
                const name = f.next() orelse return error.BadDeviceFile;
                const exp = try parseInt(f.next());
                if (!validName(name)) return error.BadDeviceFile;
                var p: Pairing = .{ .expires = exp };
                p.name.set(name);
                s.pairing = p;
            } else if (std.mem.eql(u8, kind, "dev")) {
                if (n >= max_devices) return error.BadDeviceFile;
                const name = f.next() orelse return error.BadDeviceFile;
                const ip = f.next() orelse return error.BadDeviceFile;
                if (!validName(name) or !validIp(ip)) return error.BadDeviceFile;
                var d: Device = .{
                    .cur = try parseHash(f.next()),
                    .created = 0,
                    .last_seen = 0,
                };
                const prev = f.next() orelse return error.BadDeviceFile;
                if (!std.mem.eql(u8, prev, "-")) d.prev = try parseHash(prev);
                d.prev_until = try parseInt(f.next());
                d.created = try parseInt(f.next());
                d.last_seen = try parseInt(f.next());
                d.name.set(name);
                d.ip.set(ip);
                s.devices[n] = d;
                n += 1;
            } else return error.BadDeviceFile;
            if (f.next() != null) return error.BadDeviceFile;
        }
        return s;
    }

    pub fn format(s: *const Store, gpa: Allocator, out: *std.ArrayList(u8)) !void {
        var buf: [512]u8 = undefined;
        try out.appendSlice(gpa, header ++ "\n");
        if (s.pairing) |p| try out.appendSlice(gpa, try std.fmt.bufPrint(&buf, "pair {s} {d}\n", .{ p.name.get(), p.expires }));
        for (s.devices) |slot| {
            const d = slot orelse continue;
            var prev_hex: [64]u8 = @splat('-');
            const prev: []const u8 = if (d.prev) |p| std.fmt.bufPrint(&prev_hex, "{x}", .{&p}) catch unreachable else "-";
            try out.appendSlice(gpa, try std.fmt.bufPrint(&buf, "dev {s} {s} {x} {s} {d} {d} {d}\n", .{
                d.name.get(), d.ip.get(), &d.cur, prev, d.prev_until, d.created, d.last_seen,
            }));
        }
    }
};

fn parseInt(s: ?[]const u8) !i64 {
    return std.fmt.parseInt(i64, s orelse return error.BadDeviceFile, 10) catch error.BadDeviceFile;
}

fn parseHash(s: ?[]const u8) !auth.Hash {
    const hex = s orelse return error.BadDeviceFile;
    if (hex.len != 64) return error.BadDeviceFile;
    var h: auth.Hash = undefined;
    _ = std.fmt.hexToBytes(&h, hex) catch return error.BadDeviceFile;
    return h;
}

// ------------------------------------------------------------- file access

pub const Paths = struct {
    /// %LOCALAPPDATA%\Portal
    dir: []const u8,

    fn join(p: Paths, buf: []u8, name: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}\\{s}", .{ p.dir, name });
    }
};

fn wide(gpa: Allocator, s: []const u8) ![:0]u16 {
    return std.unicode.utf8ToUtf16LeAllocZ(gpa, s);
}

/// Locked read-modify-write of the device store. `op(ctx, *Store)` returns
/// whether it changed the store; if so the file is replaced atomically.
/// The lock is an exclusively opened `devices.lock`, shared with any other
/// Portal process (the running server and the `pair`/`unpair` commands).
pub fn withStore(gpa: Allocator, io: Io, paths: Paths, now: i64, ctx: anytype, comptime op: anytype) !void {
    var pbuf: [1024]u8 = undefined;
    const lock_w = try wide(gpa, try paths.join(&pbuf, "devices.lock"));
    defer gpa.free(lock_w);
    var lock: ?w.HANDLE = null;
    var tries: usize = 0;
    while (tries < 200) : (tries += 1) {
        lock = w.validHandle(w.CreateFileW(lock_w.ptr, w.GENERIC_WRITE, 0, null, w.OPEN_ALWAYS, w.FILE_ATTRIBUTE_NORMAL, null));
        if (lock != null) break;
        io.sleep(.fromMilliseconds(10), .awake) catch {};
    }
    const lock_h = lock orelse return error.DeviceStoreBusy;
    defer _ = w.CloseHandle(lock_h);

    const path = try paths.join(&pbuf, "devices.txt");
    var store: Store = blk: {
        const text = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 * 1024)) catch |err| switch (err) {
            error.FileNotFound => break :blk .{},
            else => return err,
        };
        defer gpa.free(text);
        break :blk try Store.parse(text); // corrupt file: fail closed
    };
    var dirty = store.expire(now);
    if (try op(ctx, &store)) dirty = true;
    if (!dirty) return;

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try store.format(gpa, &out);
    var tbuf: [1024]u8 = undefined;
    const tmp = try paths.join(&tbuf, "devices.txt.tmp");
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = tmp, .data = out.items });
    const tmp_w = try wide(gpa, tmp);
    defer gpa.free(tmp_w);
    const path_w = try wide(gpa, path);
    defer gpa.free(path_w);
    if (w.MoveFileExW(tmp_w.ptr, path_w.ptr, w.MOVEFILE_REPLACE_EXISTING | w.MOVEFILE_WRITE_THROUGH) == 0)
        return error.DeviceStoreWriteFailed;
}

// -------------------------------------------------------------------- tests

const testing = std.testing;

fn secretFor(fill: u8) [auth.encoded_len]u8 {
    const raw: [auth.secret_bytes]u8 = @splat(fill);
    var out: [auth.encoded_len]u8 = undefined;
    _ = auth.encodeSecret(&raw, &out);
    return out;
}

fn cookieFor(buf: []u8, name: []const u8, fill: u8) []const u8 {
    const sec = secretFor(fill);
    return std.fmt.bufPrint(buf, "{s}.{s}", .{ name, &sec }) catch unreachable;
}

test "names and addresses" {
    try testing.expect(validName("laptop"));
    try testing.expect(validName("iphone-2"));
    try testing.expect(!validName(""));
    try testing.expect(!validName("Laptop"));
    try testing.expect(!validName("a b"));
    try testing.expect(!validName("a.b"));
    try testing.expectEqualStrings("10.8.0.2", ipOnly("10.8.0.2:51234"));
    try testing.expectEqualStrings("fd00::2", ipOnly("[fd00::2]:5"));
}

test "pair, authenticate, rotate, grace, theft detection" {
    var s: Store = .{};
    try testing.expectError(error.NoPairingWindow, s.completePair("10.8.0.2", auth.hashSecret(&secretFor(1)), 0));
    try s.beginPair("laptop", 0, 120);
    try testing.expectEqualStrings("laptop", s.pairingName(10).?);
    var b1: [80]u8 = undefined;
    const c1 = cookieFor(&b1, "laptop", 1);
    _ = try s.completePair("10.8.0.2", auth.hashSecret(c1[7..]), 10);
    try testing.expect(s.pairingName(11) == null); // window consumed

    // Valid from the bound address only.
    try testing.expect(s.authenticate(c1, "10.8.0.3", 20) == .wrong_address);
    const r = s.authenticate(c1, "10.8.0.2", 20);
    try testing.expect(r == .ok);

    // Rotate to secret 2; secret 1 still works during the grace period.
    var b2: [80]u8 = undefined;
    const c2 = cookieFor(&b2, "laptop", 2);
    s.rotate(r.ok, c1, auth.hashSecret(c2[7..]), 20);
    try testing.expect(s.authenticate(c2, "10.8.0.2", 30) == .ok);
    try testing.expect(s.authenticate(c1, "10.8.0.2", 30) == .ok);

    // After the grace period, the old secret revokes the device.
    const late = s.authenticate(c1, "10.8.0.2", 20 + grace_s + 1);
    try testing.expect(late == .revoked);
    try testing.expect(s.find("laptop") == null);
    try testing.expect(s.authenticate(c2, "10.8.0.2", 20 + grace_s + 2) == .unknown);
}

test "garbage secret for a known device revokes it" {
    var s: Store = .{};
    try s.beginPair("phone", 0, 120);
    var b: [80]u8 = undefined;
    const c = cookieFor(&b, "phone", 5);
    _ = try s.completePair("10.8.0.3", auth.hashSecret(c[6..]), 1);
    var bad: [80]u8 = undefined;
    try testing.expect(s.authenticate(cookieFor(&bad, "phone", 9), "10.8.0.3", 2) == .revoked);
    try testing.expect(s.count() == 0);
}

test "malformed cookies are unknown, not revocations" {
    var s: Store = .{};
    try s.beginPair("phone", 0, 120);
    var b: [80]u8 = undefined;
    const c = cookieFor(&b, "phone", 5);
    _ = try s.completePair("10.8.0.3", auth.hashSecret(c[6..]), 1);
    try testing.expect(s.authenticate("phone", "10.8.0.3", 2) == .unknown);
    try testing.expect(s.authenticate("phone.short", "10.8.0.3", 2) == .unknown);
    try testing.expect(s.authenticate("PHONE.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "10.8.0.3", 2) == .unknown);
    try testing.expect(s.count() == 1);
}

test "re-pairing replaces same name or same address" {
    var s: Store = .{};
    try s.beginPair("laptop", 0, 120);
    _ = try s.completePair("10.8.0.2", auth.hashSecret("a"), 1);
    try s.beginPair("laptop2", 2, 120);
    _ = try s.completePair("10.8.0.2", auth.hashSecret("b"), 3);
    try testing.expect(s.find("laptop") == null);
    try testing.expect(s.find("laptop2") != null);
    try testing.expectEqual(@as(usize, 1), s.count());
}

test "pairing window expires" {
    var s: Store = .{};
    try s.beginPair("laptop", 100, 120);
    try testing.expect(s.pairingName(220) != null);
    try testing.expect(s.pairingName(221) == null);
    try testing.expect(s.expire(221));
    try testing.expect(s.pairing == null);
    try s.beginPair("laptop", 0, 99999);
    try testing.expectEqual(max_pair_window_s, s.pairing.?.expires);
}

test "unused devices are forgotten" {
    var s: Store = .{};
    try s.beginPair("old", 0, 120);
    _ = try s.completePair("10.8.0.9", auth.hashSecret("x"), 1);
    try testing.expect(!s.expire(1 + unused_expiry_s));
    try testing.expect(s.expire(2 + unused_expiry_s));
    try testing.expectEqual(@as(usize, 0), s.count());
}

test "file round trip and strict parsing" {
    var s: Store = .{};
    try s.beginPair("laptop", 0, 120);
    _ = try s.completePair("10.8.0.2", auth.hashSecret("a"), 5);
    var b: [80]u8 = undefined;
    const c = cookieFor(&b, "laptop", 3);
    const r = s.authenticate("laptop.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "10.8.0.2", 6);
    _ = r; // revoked (wrong secret) — re-pair for the round trip
    try s.beginPair("laptop", 6, 120);
    _ = try s.completePair("10.8.0.2", auth.hashSecret(c[7..]), 7);
    s.rotate(s.find("laptop").?, c, auth.hashSecret("new"), 8);
    try s.beginPair("phone", 9, 60);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try s.format(testing.allocator, &out);
    var t = try Store.parse(out.items);
    try testing.expectEqualStrings("phone", t.pairingName(10).?);
    const d = t.devices[t.find("laptop").?].?;
    try testing.expectEqualStrings("10.8.0.2", d.ip.get());
    try testing.expectEqual(auth.hashSecret("new"), d.cur);
    try testing.expectEqual(auth.hashSecret(c[7..]), d.prev.?);
    try testing.expectEqual(@as(i64, 8 + grace_s), d.prev_until);

    try testing.expectError(error.BadDeviceFile, Store.parse(""));
    try testing.expectError(error.BadDeviceFile, Store.parse("portal-devices-v2\n"));
    try testing.expectError(error.BadDeviceFile, Store.parse(header ++ "\ndev x\n"));
    try testing.expectError(error.BadDeviceFile, Store.parse(header ++ "\nhack\n"));
    try testing.expectError(error.BadDeviceFile, Store.parse(header ++ "\npair Bad 5\n"));
    _ = &t;
}
