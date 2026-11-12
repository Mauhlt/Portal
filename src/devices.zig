//! Paired devices: the credential model that replaced the static token.
//!
//!  * `portal pair <name>` at the desktop opens a short pairing window and
//!    stays running in its console. A device that taps "Pair this device"
//!    inside the window does NOT get a credential yet: it registers a
//!    pending *request* (source address, a short random request code shown
//!    on both screens, and a random request token kept in a cookie).
//!  * The owner approves or denies each request at the desk (`[y/N]`).
//!    Only the approved request, presented again from the same address with
//!    its token, receives the device credential. Approving one closes the
//!    window to everyone else; denying one leaves it open. Nothing is typed
//!    on the device.
//!  * The credential is a random 256-bit device secret (cookie
//!    `portal_device=<name>.<secret>`; the native client keeps it in the OS
//!    credential store). Only its SHA-256 is stored.
//!  * It is bound to the device's source address (its WireGuard address),
//!    and rotates every time it is used. Secrets superseded within the last
//!    `grace_s` stay valid until their own expiry (a small ring, so two tabs
//!    signing in at once, or a lost response, never lock the device out).
//!    A grace window is never extended.
//!  * Presenting any other secret for a known device revokes the device:
//!    either the credential was copied and used elsewhere, or it is garbage.
//!    Either way, re-pairing at the desk is required.
//!  * Every device record has a random id, issued when it is paired.
//!    Sessions are tagged with it (auth.Sessions), not with the name. A
//!    re-pair under a name (or from an address) already in use removes the
//!    old record outright and the server ends every session of it before
//!    the new credential is issued; nothing of the old record is kept or
//!    merged, so a misidentified device never inherits anything.
//!
//! The store is a small text file shared by the running server and the
//! `portal pair/devices/unpair` commands; every change is a locked
//! read-modify-write with a flushed, atomic replace (see `withStore`).
//! Processes learn about each other's changes from a directory change
//! notification (`DirWatch`), not by polling.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const auth = @import("auth.zig");
const w = @import("win32.zig");
const fsutil = @import("fsutil.zig");

pub const max_devices = 16;
pub const max_name = 32;
pub const max_ip = 46;
/// How long a superseded secret stays valid after the rotation that
/// replaced it.
pub const grace_s: i64 = 10 * 60;
/// Superseded secrets remembered per device (each valid until its own
/// expiry). Older ones fall out of the ring and then revoke the device.
pub const ring_len = 4;
/// Devices unused for this long are forgotten.
pub const unused_expiry_s: i64 = 90 * 24 * 3600;
pub const default_pair_window_s: i64 = 120;
pub const max_pair_window_s: i64 = 600;
/// Pairing requests per window (pending + answered), and pending ones per
/// source address.
pub const max_requests = 8;
pub const max_requests_per_ip = 2;
/// Request code shown on the device and at the desk: 4 hex digits.
pub const code_len = 4;

const header_v1 = "portal-devices-v1";
const header_v2 = "portal-devices-v2";
/// v3: `dev` lines carry the record id.
const header = "portal-devices-v3";

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

/// "10.8.0.1:8421", "[fd00::1]:8421": what the CA listener reports.
pub fn validWhere(s: []const u8) bool {
    if (s.len == 0 or s.len > max_ip) return false;
    for (s) |c| switch (c) {
        '0'...'9', 'a'...'f', 'A'...'F', '.', ':', '[', ']' => {},
        else => return false,
    };
    return true;
}

pub fn validCode(code: []const u8) bool {
    if (code.len != code_len) return false;
    for (code) |c| switch (c) {
        '0'...'9', 'a'...'f' => {},
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

pub const Text = struct {
    buf: [max_ip]u8 = undefined,
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

pub const Grace = struct {
    hash: auth.Hash,
    /// Valid while now <= until. Never extended.
    until: i64,
};

pub const Device = struct {
    name: Text = .{},
    ip: Text = .{},
    /// Random, issued at pairing; what sessions are tagged with.
    id: auth.DeviceId,
    cur: auth.Hash,
    /// Recently superseded secrets, each valid until its own `until`.
    ring: [ring_len]?Grace = @splat(null),
    created: i64,
    last_seen: i64,

    /// The record's identity, as sessions are tagged with it.
    pub fn ref(d: *const Device) auth.Device {
        return .init(d.id, d.name.get());
    }
};

/// Id for a record from a file older than v3 (which had none): derived
/// from its current secret hash, so it is stable until the file is
/// rewritten as v3. Sessions are memory-only, so none predate it.
fn legacyId(cur: auth.Hash) auth.DeviceId {
    var h: auth.Hash = undefined;
    var s = std.crypto.hash.sha2.Sha256.init(.{});
    s.update("portal-device-id-v2:");
    s.update(&cur);
    s.final(&h);
    return h[0..auth.device_id_len].*;
}

pub const ReqState = enum {
    pending,
    approved,
    denied,
    /// The approved device collected its credential.
    done,
};

pub const Request = struct {
    code: [code_len]u8,
    /// SHA-256 of the request token (the device's `portal_pairreq` cookie).
    token: auth.Hash,
    ip: Text = .{},
    created: i64,
    state: ReqState = .pending,
};

/// State of the plain-HTTP certificate download listener (listen port + 1)
/// for this window, as reported by the running server.
pub const CaState = enum {
    /// No `portal run` has reported on this window yet.
    unknown,
    up,
    failed,
    /// The server runs with --no-tls: no certificate listener.
    off,
};

pub const Pairing = struct {
    name: Text = .{},
    /// Identifies the `portal pair` invocation that owns this window.
    nonce: u64 = 0,
    expires: i64,
    /// Process id of that `portal pair` (the server closes the window as
    /// soon as that process exits).
    pid: u32 = 0,
    ca: CaState = .unknown,
    ca_where: Text = .{},
    requests: [max_requests]?Request = @splat(null),

    /// True once a request was approved (or collected): no new requests.
    pub fn decided(p: *const Pairing) bool {
        for (p.requests) |slot| {
            const r = slot orelse continue;
            if (r.state == .approved or r.state == .done) return true;
        }
        return false;
    }

    /// The request whose token hashes to `token`. Scans every slot.
    pub fn findToken(p: *const Pairing, token: auth.Hash) ?usize {
        var found: ?usize = null;
        for (p.requests, 0..) |slot, i| {
            const r = slot orelse continue;
            if (std.crypto.timing_safe.eql(auth.Hash, r.token, token)) found = i;
        }
        return found;
    }

    pub fn findCode(p: *const Pairing, code: []const u8) ?usize {
        for (p.requests, 0..) |slot, i| {
            const r = slot orelse continue;
            if (std.mem.eql(u8, &r.code, code)) return i;
        }
        return null;
    }
};

pub const AuthResult = union(enum) {
    /// Valid. Caller should rotate with `rotate(idx, ...)`.
    ok: usize,
    /// Known device, but presented from a different address. Not revoked.
    wrong_address,
    /// Wrong or stale secret for a known device: that record was removed;
    /// the caller ends its sessions.
    revoked: auth.Device,
    unknown,
};

pub const RequestError = error{
    NoPairingWindow,
    /// A request was already approved: the window takes no more.
    WindowDecided,
    TooManyRequests,
    TooManyFromAddress,
    /// The owner denied a request from this address in this window.
    AddressDenied,
    BadAddress,
    DuplicateCode,
};

pub const AnswerResult = enum { approved, denied, not_pending, no_such_request, window_gone };

/// Device records a pairing removed (same name or same address as the new
/// one). The caller ends all their sessions before issuing the new
/// credential.
pub const Replaced = struct {
    list: [max_devices]auth.Device = undefined,
    n: usize = 0,

    pub fn items(r: *const Replaced) []const auth.Device {
        return r.list[0..r.n];
    }
};

pub const Paired = struct {
    /// The new record.
    device: auth.Device,
    replaced: Replaced = .{},
};

pub const ClaimResult = union(enum) {
    pending,
    denied,
    /// No such request (expired, window closed, wrong address).
    unknown,
    paired: Paired,
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

    /// The record with id `id` (a re-paired name has a different one).
    pub fn findId(s: *const Store, id: auth.DeviceId) ?usize {
        for (s.devices, 0..) |d, i| {
            if (d) |dev| if (std.mem.eql(u8, &dev.id, &id)) return i;
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

    /// Drops expired pairing windows, expired grace secrets and long-unused
    /// devices.
    pub fn expire(s: *Store, now: i64) bool {
        var changed = false;
        if (s.pairing) |p| if (now > p.expires or now < p.expires - max_pair_window_s) {
            s.pairing = null;
            changed = true;
        };
        for (&s.devices) |*slot| {
            if (slot.*) |*d| {
                if (now -| d.last_seen > unused_expiry_s) {
                    slot.* = null;
                    changed = true;
                    continue;
                }
                for (&d.ring) |*g| if (g.*) |e| if (now > e.until) {
                    g.* = null;
                    changed = true;
                };
            }
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
        var valid = std.crypto.timing_safe.eql(auth.Hash, h, dev.cur);
        for (dev.ring) |slot| {
            const g = slot orelse continue;
            if (std.crypto.timing_safe.eql(auth.Hash, h, g.hash) and now <= g.until) valid = true;
        }
        if (valid) return .{ .ok = idx };
        const gone = dev.ref();
        s.devices[idx] = null;
        return .{ .revoked = gone };
    }

    /// Issues `new_hash` as the device's current secret. The secret it
    /// replaces joins the grace ring for `grace_s`; secrets already in the
    /// ring keep their own (never extended) expiry. Call only after
    /// `authenticate` returned `.ok`.
    pub fn rotate(s: *Store, idx: usize, new_hash: auth.Hash, now: i64) void {
        const dev = &(s.devices[idx] orelse return);
        // Newest first; expired entries drop out, and when full the oldest
        // issued one goes (by order, not by expiry: secrets issued within
        // the same second all expire together).
        var kept: [ring_len]?Grace = @splat(null);
        kept[0] = .{ .hash = dev.cur, .until = now +| grace_s };
        var n: usize = 1;
        for (dev.ring) |slot| {
            const g = slot orelse continue;
            if (now > g.until or n == ring_len) continue;
            kept[n] = g;
            n += 1;
        }
        dev.ring = kept;
        dev.cur = new_hash;
        dev.last_seen = now;
    }

    pub fn beginPair(s: *Store, name: []const u8, now: i64, window_s: i64, nonce: u64, pid: u32) !void {
        if (!validName(name)) return error.BadName;
        var p: Pairing = .{
            .expires = now +| std.math.clamp(window_s, 10, max_pair_window_s),
            .nonce = nonce,
            .pid = pid,
        };
        p.name.set(name);
        s.pairing = p;
    }

    /// Ends window `nonce` (if it is still the open one).
    pub fn endPair(s: *Store, nonce: u64) bool {
        const p = s.pairing orelse return false;
        if (p.nonce != nonce) return false;
        s.pairing = null;
        return true;
    }

    pub fn pairingName(s: *const Store, now: i64) ?[]const u8 {
        const p = &(s.pairing orelse return null);
        if (now > p.expires) return null;
        return p.name.get();
    }

    /// Registers a pending request from `ip` with request token hash
    /// `token` and display code `code`.
    pub fn addRequest(s: *Store, ip: []const u8, token: auth.Hash, code: [code_len]u8, now: i64) RequestError!void {
        const p = &(s.pairing orelse return error.NoPairingWindow);
        if (now > p.expires) return error.NoPairingWindow;
        if (!validIp(ip)) return error.BadAddress;
        if (!validCode(&code)) return error.DuplicateCode;
        if (p.decided()) return error.WindowDecided;
        if (p.findCode(&code) != null) return error.DuplicateCode;
        var from_ip: usize = 0;
        for (p.requests) |slot| {
            const r = slot orelse continue;
            if (!std.mem.eql(u8, r.ip.get(), ip)) continue;
            if (r.state == .denied) return error.AddressDenied;
            if (r.state == .pending) from_ip += 1;
        }
        if (from_ip >= max_requests_per_ip) return error.TooManyFromAddress;
        // A free slot, else the oldest answered (denied) one.
        var target: ?usize = null;
        for (p.requests, 0..) |slot, i| {
            if (slot == null) {
                target = i;
                break;
            }
        }
        if (target == null) {
            var oldest: i64 = std.math.maxInt(i64);
            for (p.requests, 0..) |slot, i| {
                const r = slot.?;
                if (r.state == .denied and r.created < oldest) {
                    oldest = r.created;
                    target = i;
                }
            }
        }
        const t = target orelse return error.TooManyRequests;
        var r: Request = .{ .code = code, .token = token, .created = now };
        r.ip.set(ip);
        p.requests[t] = r;
    }

    /// The owner's answer to request `code` of window `nonce`. Approving
    /// one denies every other pending request: the window is decided.
    pub fn answer(s: *Store, nonce: u64, code: []const u8, approve: bool) AnswerResult {
        const p = &(s.pairing orelse return .window_gone);
        if (p.nonce != nonce) return .window_gone;
        const i = p.findCode(code) orelse return .no_such_request;
        const r = &p.requests[i].?;
        if (r.state != .pending) return .not_pending;
        if (!approve) {
            r.state = .denied;
            return .denied;
        }
        r.state = .approved;
        for (&p.requests, 0..) |*slot, j| {
            if (j == i) continue;
            if (slot.*) |*o| if (o.state == .pending) {
                o.state = .denied;
            };
        }
        return .approved;
    }

    /// The device behind request `token` asks for its outcome from `ip`.
    /// If approved, registers a new device record with id `new_id` and
    /// secret hash `new_hash`. Any record already using that name, or that
    /// address, is removed (never updated or merged) and reported in
    /// `replaced`, so the caller can end its sessions.
    pub fn claim(s: *Store, token: auth.Hash, ip: []const u8, new_id: auth.DeviceId, new_hash: auth.Hash, now: i64) !ClaimResult {
        const p = &(s.pairing orelse return .unknown);
        if (now > p.expires) return .unknown;
        const i = p.findToken(token) orelse return .unknown;
        const r = &p.requests[i].?;
        if (!std.mem.eql(u8, r.ip.get(), ip)) return .unknown;
        switch (r.state) {
            .pending => return .pending,
            .denied => return .denied,
            .done => return .unknown, // single use
            .approved => {},
        }
        // An id collision (2^-128) would let sessions cross records.
        if (s.findId(new_id) != null) return error.DuplicateDeviceId;
        var dev: Device = .{ .id = new_id, .cur = new_hash, .created = now, .last_seen = now };
        dev.name = p.name;
        dev.ip.set(ip);
        var out: Paired = .{ .device = dev.ref() };
        for (&s.devices) |*slot| {
            if (slot.*) |*d| if (std.mem.eql(u8, d.name.get(), dev.name.get()) or std.mem.eql(u8, d.ip.get(), ip)) {
                out.replaced.list[out.replaced.n] = d.ref();
                out.replaced.n += 1;
                slot.* = null;
            };
        }
        for (&s.devices) |*slot| {
            if (slot.* == null) {
                slot.* = dev;
                r.state = .done;
                return .{ .paired = out };
            }
        }
        return error.TooManyDevices;
    }

    pub fn remove(s: *Store, name: []const u8) bool {
        const idx = s.find(name) orelse return false;
        s.devices[idx] = null;
        return true;
    }

    /// Removes record `id` only: a newer record under the same name stays.
    pub fn removeId(s: *Store, id: auth.DeviceId) bool {
        const idx = s.findId(id) orelse return false;
        s.devices[idx] = null;
        return true;
    }

    // ----------------------------------------------------------- file format

    pub fn parse(text: []const u8) !Store {
        var s: Store = .{};
        var lines = std.mem.tokenizeAny(u8, text, "\r\n");
        const first = lines.next() orelse return error.BadDeviceFile;
        const v1 = std.mem.eql(u8, first, header_v1);
        const v2 = std.mem.eql(u8, first, header_v2);
        if (!v1 and !v2 and !std.mem.eql(u8, first, header)) return error.BadDeviceFile;
        var n: usize = 0;
        var n_req: usize = 0;
        while (lines.next()) |line| {
            var f = std.mem.tokenizeScalar(u8, line, ' ');
            const kind = f.next() orelse continue;
            if (std.mem.eql(u8, kind, "pair")) {
                const name = f.next() orelse return error.BadDeviceFile;
                if (!validName(name)) return error.BadDeviceFile;
                if (v1) {
                    // A v1 window predates desk approval: drop it.
                    _ = try parseInt(f.next());
                } else {
                    var p: Pairing = .{ .expires = 0 };
                    p.name.set(name);
                    p.nonce = std.fmt.parseInt(u64, f.next() orelse return error.BadDeviceFile, 16) catch return error.BadDeviceFile;
                    p.expires = try parseInt(f.next());
                    p.pid = std.fmt.parseInt(u32, f.next() orelse return error.BadDeviceFile, 10) catch return error.BadDeviceFile;
                    p.ca = std.meta.stringToEnum(CaState, f.next() orelse return error.BadDeviceFile) orelse return error.BadDeviceFile;
                    const where = f.next() orelse return error.BadDeviceFile;
                    if (!std.mem.eql(u8, where, "-")) {
                        if (!validWhere(where)) return error.BadDeviceFile;
                        p.ca_where.set(where);
                    }
                    s.pairing = p;
                    n_req = 0;
                }
            } else if (std.mem.eql(u8, kind, "req") and !v1) {
                const p = &(s.pairing orelse return error.BadDeviceFile);
                if (n_req >= max_requests) return error.BadDeviceFile;
                const code = f.next() orelse return error.BadDeviceFile;
                if (!validCode(code)) return error.BadDeviceFile;
                var r: Request = .{ .code = code[0..code_len].*, .token = try parseHash(f.next()), .created = 0 };
                const ip = f.next() orelse return error.BadDeviceFile;
                if (!validIp(ip)) return error.BadDeviceFile;
                r.ip.set(ip);
                r.created = try parseInt(f.next());
                r.state = std.meta.stringToEnum(ReqState, f.next() orelse return error.BadDeviceFile) orelse return error.BadDeviceFile;
                p.requests[n_req] = r;
                n_req += 1;
            } else if (std.mem.eql(u8, kind, "dev")) {
                if (n >= max_devices) return error.BadDeviceFile;
                const name = f.next() orelse return error.BadDeviceFile;
                const ip = f.next() orelse return error.BadDeviceFile;
                if (!validName(name) or !validIp(ip)) return error.BadDeviceFile;
                const id: ?auth.DeviceId = if (v1 or v2) null else try parseId(f.next());
                const cur = try parseHash(f.next());
                var d: Device = .{ .id = id orelse legacyId(cur), .cur = cur, .created = 0, .last_seen = 0 };
                for (s.devices[0..n]) |o| if (std.mem.eql(u8, &o.?.id, &d.id)) return error.BadDeviceFile;
                if (v1) {
                    const prev = f.next() orelse return error.BadDeviceFile;
                    const prev_until = try parseInt(f.next());
                    if (!std.mem.eql(u8, prev, "-")) d.ring[0] = .{ .hash = try parseHash(prev), .until = prev_until };
                    d.created = try parseInt(f.next());
                    d.last_seen = try parseInt(f.next());
                } else {
                    d.created = try parseInt(f.next());
                    d.last_seen = try parseInt(f.next());
                    var k: usize = 0;
                    while (f.peek() != null) : (k += 1) {
                        if (k >= ring_len) return error.BadDeviceFile;
                        const g = f.next().?;
                        const colon = std.mem.indexOfScalar(u8, g, ':') orelse return error.BadDeviceFile;
                        d.ring[k] = .{ .hash = try parseHash(g[0..colon]), .until = try parseInt(g[colon + 1 ..]) };
                    }
                }
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
        var buf: [256]u8 = undefined;
        try out.appendSlice(gpa, header ++ "\n");
        if (s.pairing) |p| {
            try out.appendSlice(gpa, try std.fmt.bufPrint(&buf, "pair {s} {x:0>16} {d} {d} {t} {s}\n", .{
                p.name.get(), p.nonce, p.expires, p.pid, p.ca, if (p.ca_where.len > 0) p.ca_where.get() else "-",
            }));
            for (p.requests) |slot| {
                const r = slot orelse continue;
                try out.appendSlice(gpa, try std.fmt.bufPrint(&buf, "req {s} {x} {s} {d} {t}\n", .{
                    &r.code, &r.token, r.ip.get(), r.created, r.state,
                }));
            }
        }
        for (s.devices) |slot| {
            const d = slot orelse continue;
            try out.appendSlice(gpa, try std.fmt.bufPrint(&buf, "dev {s} {s} {x} {x} {d} {d}", .{
                d.name.get(), d.ip.get(), &d.id, &d.cur, d.created, d.last_seen,
            }));
            for (d.ring) |gs| {
                const g = gs orelse continue;
                try out.appendSlice(gpa, try std.fmt.bufPrint(&buf, " {x}:{d}", .{ &g.hash, g.until }));
            }
            try out.append(gpa, '\n');
        }
    }
};

fn parseInt(s: ?[]const u8) !i64 {
    return std.fmt.parseInt(i64, s orelse return error.BadDeviceFile, 10) catch error.BadDeviceFile;
}

fn parseId(s: ?[]const u8) !auth.DeviceId {
    const hex = s orelse return error.BadDeviceFile;
    if (hex.len != 2 * auth.device_id_len) return error.BadDeviceFile;
    var id: auth.DeviceId = undefined;
    _ = std.fmt.hexToBytes(&id, hex) catch return error.BadDeviceFile;
    return id;
}

fn parseHash(s: ?[]const u8) !auth.Hash {
    const hex = s orelse return error.BadDeviceFile;
    if (hex.len != 64) return error.BadDeviceFile;
    var h: auth.Hash = undefined;
    _ = std.fmt.hexToBytes(&h, hex) catch return error.BadDeviceFile;
    return h;
}

/// A one-line explanation, with the way out, for errors from `withStore`.
pub fn describeError(err: anyerror) []const u8 {
    return switch (err) {
        error.BadDeviceFile => "the device list (devices.txt in %LOCALAPPDATA%\\Portal) is damaged or from a newer Portal. " ++
            "To recover: close Portal, move devices.txt somewhere else (keep it if you want to report the problem), " ++
            "start Portal again, and re-pair every device (Pair a device in the Portal window)",
        error.DeviceStoreBusy => "the device list is held open by an older Portal process; close it and try again",
        error.DeviceStoreWriteFailed => "could not replace devices.txt (disk full, or the file is locked by another program)",
        else => "could not access the device list in %LOCALAPPDATA%\\Portal",
    };
}

// ------------------------------------------------------------- file access

/// %LOCALAPPDATA%\Portal
pub const Paths = fsutil.DataDir;

/// Locked read-modify-write of the device store. `op(ctx, *Store)` returns
/// whether it changed the store; if so the file is replaced atomically
/// (written, flushed to disk, then renamed over the old one). The lock is
/// `devices.lock`, shared with every other Portal process (the running
/// server and the `pair`/`unpair` commands); waiting for it blocks without
/// polling, and a cancel during the wait is returned and stays armed
/// (fsutil.FileLock).
pub fn withStore(gpa: Allocator, io: Io, paths: Paths, now: i64, ctx: anytype, comptime op: anytype) !void {
    var lb: [1024]u8 = undefined;
    var pb: [1024]u8 = undefined;
    const Ctx = struct { gpa: Allocator, now: i64, inner: @TypeOf(ctx) };
    fsutil.update(gpa, io, try paths.join(&lb, &.{"devices.lock"}), try paths.join(&pb, &.{"devices.txt"}), 64 * 1024, Ctx{
        .gpa = gpa,
        .now = now,
        .inner = ctx,
    }, struct {
        fn edit(c: Ctx, old: ?[]const u8, out: *std.ArrayList(u8)) !bool {
            var store: Store = if (old) |text| try Store.parse(text) else .{}; // corrupt file: fail closed
            var dirty = store.expire(c.now);
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

// ------------------------------------------------------ desk approval API

/// The desk side of pairing: open a window, see who asks, approve or deny,
/// cancel. Used by `portal pair` (a thin console wrapper) and, through
/// web.Server's `desk*` functions, by the Portal window itself. Each call
/// is one locked read-modify-write of the store, so callers in different
/// processes can't race each other; changes reach the running server
/// through `DirWatch`.
pub const Desk = struct {
    gpa: Allocator,
    io: Io,
    paths: Paths,

    fn now(d: Desk) i64 {
        return Io.Timestamp.now(d.io, .real).toSeconds();
    }

    /// Opens window `nonce` for device `name` for `window_s` seconds (10 s
    /// to 10 min), owned by process `pid` (the server closes it when that
    /// process exits). Replaces any open window; returns its device name.
    pub fn begin(d: Desk, name: []const u8, window_s: i64, nonce: u64, pid: u32) !?Text {
        const t = d.now();
        var replaced: ?Text = null;
        const Ctx = struct { name: []const u8, now: i64, secs: i64, nonce: u64, pid: u32, replaced: *?Text };
        try withStore(d.gpa, d.io, d.paths, t, Ctx{ .name = name, .now = t, .secs = window_s, .nonce = nonce, .pid = pid, .replaced = &replaced }, struct {
            fn op(c: Ctx, st: *Store) !bool {
                if (st.pairingName(c.now) != null) c.replaced.* = st.pairing.?.name;
                try st.beginPair(c.name, c.now, c.secs, c.nonce, c.pid);
                return true;
            }
        }.op);
        return replaced;
    }

    /// Window `nonce` as stored now (requests and their states, the
    /// certificate listener's state), or null once it has expired, been
    /// cancelled or been replaced.
    pub fn get(d: Desk, nonce: u64) !?Pairing {
        var out: ?Pairing = null;
        const Ctx = struct { nonce: u64, out: *?Pairing };
        try withStore(d.gpa, d.io, d.paths, d.now(), Ctx{ .nonce = nonce, .out = &out }, struct {
            fn op(c: Ctx, st: *Store) !bool {
                const p = st.pairing orelse return false;
                if (p.nonce == c.nonce) c.out.* = p;
                return false;
            }
        }.op);
        return out;
    }

    /// Approves or denies request `code` of window `nonce`.
    pub fn answer(d: Desk, nonce: u64, code: []const u8, approve: bool) !AnswerResult {
        var r: AnswerResult = .window_gone;
        const Ctx = struct { nonce: u64, code: []const u8, approve: bool, r: *AnswerResult };
        try withStore(d.gpa, d.io, d.paths, d.now(), Ctx{ .nonce = nonce, .code = code, .approve = approve, .r = &r }, struct {
            fn op(c: Ctx, st: *Store) !bool {
                c.r.* = st.answer(c.nonce, c.code, c.approve);
                return c.r.* == .approved or c.r.* == .denied;
            }
        }.op);
        return r;
    }

    /// Closes window `nonce` (no-op if it is no longer the open one).
    pub fn cancel(d: Desk, nonce: u64) !void {
        try withStore(d.gpa, d.io, d.paths, d.now(), nonce, struct {
            fn op(n: u64, st: *Store) !bool {
                return st.endPair(n);
            }
        }.op);
    }
};

/// The device a window paired, once its approved request was collected.
pub fn pairedRequest(p: *const Pairing) ?Request {
    for (p.requests) |slot| {
        const r = slot orelse continue;
        if (r.state == .done) return r;
    }
    return null;
}

// --------------------------------------------------- change notification

/// Signalled whenever a file in the data directory is created, renamed or
/// deleted. Every store change ends in a rename (see `withStore`), so this
/// wakes every Portal process sharing the directory, however many there
/// are, without anyone polling. Log appends do not trigger it.
pub fn watchStore(gpa: Allocator, paths: Paths) !fsutil.DirWatch {
    return fsutil.DirWatch.open(gpa, paths.dir, .{});
}

/// Milliseconds to wait (for WaitForMultipleObjects) until unix second
/// `deadline_s`, plus a little slack; INFINITE for none.
pub fn waitMs(now_s: i64, deadline_s: ?i64) w.DWORD {
    const d = deadline_s orelse return w.INFINITE;
    const dt = d -| now_s;
    if (dt < 0) return 0;
    return @intCast(@min(dt *| 1000 +| 250, 24 * 3600 * 1000));
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

fn hashOf(cookie: []const u8) auth.Hash {
    return auth.hashSecret(cookie[std.mem.indexOfScalar(u8, cookie, '.').? + 1 ..]);
}

/// A test record id (real ones are random).
fn idOf(h: auth.Hash) auth.DeviceId {
    return h[0..auth.device_id_len].*;
}

/// Pairs `name` at `ip` through the request/approve/claim flow.
fn testPair(s: *Store, name: []const u8, ip: []const u8, secret_hash: auth.Hash, now: i64) !void {
    _ = try testPairReplacing(s, name, ip, secret_hash, now);
}

fn testPairReplacing(s: *Store, name: []const u8, ip: []const u8, secret_hash: auth.Hash, now: i64) !Paired {
    try s.beginPair(name, now, 120, 0x1234, 1);
    const tok = auth.hashSecret("token");
    try s.addRequest(ip, tok, "ab12".*, now);
    try testing.expectEqual(AnswerResult.approved, s.answer(0x1234, "ab12", true));
    const r = try s.claim(tok, ip, idOf(secret_hash), secret_hash, now);
    try testing.expectEqualStrings(name, r.paired.device.name());
    _ = s.endPair(0x1234);
    return r.paired;
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
    try testing.expect(validCode("7f3a"));
    try testing.expect(!validCode("7F3A"));
    try testing.expect(!validCode("7f3"));
}

test "desk approval: only the approved request gets a credential" {
    var s: Store = .{};
    const tok_a = auth.hashSecret("A");
    const tok_b = auth.hashSecret("B");
    try testing.expectError(error.NoPairingWindow, s.addRequest("10.8.0.2", tok_a, "aaaa".*, 0));
    try s.beginPair("iphone", 0, 120, 7, 99);
    try s.addRequest("10.8.0.3", tok_a, "aaaa".*, 1); // the real phone
    try s.addRequest("10.8.0.9", tok_b, "bbbb".*, 2); // a racing peer
    try testing.expectError(error.DuplicateCode, s.addRequest("10.8.0.4", auth.hashSecret("C"), "aaaa".*, 2));

    // Nothing is issued before the owner answers.
    try testing.expect((try s.claim(tok_b, "10.8.0.9", idOf(auth.hashSecret("x")), auth.hashSecret("x"), 3)) == .pending);
    try testing.expectEqual(@as(usize, 0), s.count());

    // Deny the wrong-looking one: the window stays open.
    try testing.expectEqual(AnswerResult.denied, s.answer(7, "bbbb", false));
    try testing.expect((try s.claim(tok_b, "10.8.0.9", idOf(auth.hashSecret("x")), auth.hashSecret("x"), 4)) == .denied);
    try testing.expectError(error.AddressDenied, s.addRequest("10.8.0.9", auth.hashSecret("D"), "dddd".*, 4));
    try testing.expectEqual(AnswerResult.not_pending, s.answer(7, "bbbb", true));
    try testing.expectEqual(AnswerResult.window_gone, s.answer(8, "aaaa", true));
    try testing.expectEqual(AnswerResult.no_such_request, s.answer(7, "cccc", true));

    // Approve the phone; the token is bound to its address.
    try testing.expectEqual(AnswerResult.approved, s.answer(7, "aaaa", true));
    try testing.expect((try s.claim(tok_a, "10.8.0.9", idOf(auth.hashSecret("x")), auth.hashSecret("x"), 5)) == .unknown);
    try testing.expect((try s.claim(auth.hashSecret("guess"), "10.8.0.3", idOf(auth.hashSecret("x")), auth.hashSecret("x"), 5)) == .unknown);
    try testing.expectError(error.WindowDecided, s.addRequest("10.8.0.5", auth.hashSecret("E"), "eeee".*, 5));
    const r = try s.claim(tok_a, "10.8.0.3", idOf(auth.hashSecret("secret")), auth.hashSecret("secret"), 6);
    try testing.expectEqualStrings("iphone", r.paired.device.name());
    try testing.expectEqual(@as(usize, 0), r.paired.replaced.n);
    try testing.expectEqual(@as(usize, 1), s.count());
    try testing.expectEqualStrings("10.8.0.3", s.devices[s.find("iphone").?].?.ip.get());
    // Single use.
    try testing.expect((try s.claim(tok_a, "10.8.0.3", idOf(auth.hashSecret("again")), auth.hashSecret("again"), 7)) == .unknown);
}

test "approving one request denies the other pending ones" {
    var s: Store = .{};
    try s.beginPair("laptop", 0, 120, 1, 1);
    try s.addRequest("10.8.0.2", auth.hashSecret("1"), "0001".*, 1);
    try s.addRequest("10.8.0.3", auth.hashSecret("2"), "0002".*, 1);
    try testing.expectEqual(AnswerResult.approved, s.answer(1, "0002", true));
    try testing.expect((try s.claim(auth.hashSecret("1"), "10.8.0.2", idOf(auth.hashSecret("x")), auth.hashSecret("x"), 2)) == .denied);
}

test "pairing request bounds" {
    var s: Store = .{};
    try s.beginPair("laptop", 0, 120, 1, 1);
    try s.addRequest("10.8.0.2", auth.hashSecret("1"), "0001".*, 1);
    try s.addRequest("10.8.0.2", auth.hashSecret("2"), "0002".*, 1);
    try testing.expectError(error.TooManyFromAddress, s.addRequest("10.8.0.2", auth.hashSecret("3"), "0003".*, 1));
    var i: u8 = 0;
    while (i < max_requests - 2) : (i += 1) {
        var code: [4]u8 = "10a0".*;
        code[3] = '0' + i;
        var ip_buf: [16]u8 = undefined;
        const ip = try std.fmt.bufPrint(&ip_buf, "10.8.1.{d}", .{i});
        try s.addRequest(ip, auth.hashSecret(ip), code, 2);
    }
    try testing.expectError(error.TooManyRequests, s.addRequest("10.8.2.1", auth.hashSecret("z"), "ffff".*, 3));
    // A denied request's slot can be reused (oldest first).
    try testing.expectEqual(AnswerResult.denied, s.answer(1, "10a0", false));
    try s.addRequest("10.8.2.1", auth.hashSecret("z"), "ffff".*, 3);
    try testing.expect(s.pairing.?.findCode("10a0") == null);
}

test "authenticate, rotate, grace ring, theft detection" {
    var s: Store = .{};
    var b1: [80]u8 = undefined;
    const c1 = cookieFor(&b1, "laptop", 1);
    try testPair(&s, "laptop", "10.8.0.2", hashOf(c1), 10);

    // Valid from the bound address only.
    try testing.expect(s.authenticate(c1, "10.8.0.3", 20) == .wrong_address);
    const r = s.authenticate(c1, "10.8.0.2", 20);
    try testing.expect(r == .ok);

    // Rotate to secret 2; secret 1 still works during the grace period.
    var b2: [80]u8 = undefined;
    const c2 = cookieFor(&b2, "laptop", 2);
    s.rotate(r.ok, hashOf(c2), 20);
    try testing.expect(s.authenticate(c2, "10.8.0.2", 30) == .ok);
    try testing.expect(s.authenticate(c1, "10.8.0.2", 30) == .ok);

    // After the grace period, the old secret revokes the device.
    const late = s.authenticate(c1, "10.8.0.2", 20 + grace_s + 1);
    try testing.expect(late == .revoked);
    try testing.expect(s.find("laptop") == null);
    try testing.expect(s.authenticate(c2, "10.8.0.2", 20 + grace_s + 2) == .unknown);
}

test "two tabs signing in with the same credential: no revocation" {
    var s: Store = .{};
    var ba: [80]u8 = undefined;
    const a = cookieFor(&ba, "laptop", 1);
    try testPair(&s, "laptop", "10.8.0.2", hashOf(a), 0);
    var bb: [80]u8 = undefined;
    const b = cookieFor(&bb, "laptop", 2);
    var bc: [80]u8 = undefined;
    const c = cookieFor(&bc, "laptop", 3);
    // Tab 1 presents A and gets B; tab 2 presents A (now superseded) and gets C.
    s.rotate(s.authenticate(a, "10.8.0.2", 100).ok, hashOf(b), 100);
    s.rotate(s.authenticate(a, "10.8.0.2", 101).ok, hashOf(c), 101);
    // Every secret issued within the grace window still works, including
    // the one tab 1 got (the old design overwrote it, then revoked).
    try testing.expect(s.authenticate(b, "10.8.0.2", 102) == .ok);
    try testing.expect(s.authenticate(c, "10.8.0.2", 102) == .ok);
    try testing.expect(s.authenticate(a, "10.8.0.2", 102) == .ok);
    try testing.expectEqual(@as(usize, 1), s.count());
}

test "re-presenting a superseded secret never extends its grace" {
    var s: Store = .{};
    var ba: [80]u8 = undefined;
    const a = cookieFor(&ba, "laptop", 1);
    try testPair(&s, "laptop", "10.8.0.2", hashOf(a), 0);
    var t: i64 = 100;
    s.rotate(s.authenticate(a, "10.8.0.2", t).ok, auth.hashSecret("n0"), t); // A valid until 100+grace
    var i: u8 = 0;
    while (i < 3) : (i += 1) {
        t += 60;
        // A presented again inside its grace: accepted, but A's expiry stays.
        const r = s.authenticate(a, "10.8.0.2", t);
        try testing.expect(r == .ok);
        s.rotate(r.ok, auth.hashSecret(&[_]u8{ 'n', '1' + i }), t);
    }
    try testing.expect(s.authenticate(a, "10.8.0.2", 100 + grace_s) == .ok);
    try testing.expect(s.authenticate(a, "10.8.0.2", 100 + grace_s + 1) == .revoked);
}

test "grace ring holds ring_len secrets; older ones revoke" {
    var s: Store = .{};
    var buf: [ring_len + 2][80]u8 = undefined;
    var cs: [ring_len + 2][]const u8 = undefined;
    for (&cs, 0..) |*c, i| c.* = cookieFor(&buf[i], "phone", @intCast(i + 1));
    try testPair(&s, "phone", "10.8.0.3", hashOf(cs[0]), 0);
    for (1..cs.len) |i| {
        const r = s.authenticate(cs[i - 1], "10.8.0.3", @intCast(i));
        try testing.expect(r == .ok);
        s.rotate(r.ok, hashOf(cs[i]), @intCast(i));
    }
    // Current + the last ring_len superseded are valid...
    for (cs.len - 1 - ring_len..cs.len) |i| try testing.expect(s.authenticate(cs[i], "10.8.0.3", 50) == .ok);
    // ...the one before fell out of the ring.
    try testing.expect(s.authenticate(cs[0], "10.8.0.3", 50) == .revoked);
}

test "four tabs signing in at once within one second: no revocation" {
    var s: Store = .{};
    var ba: [80]u8 = undefined;
    const a = cookieFor(&ba, "laptop", 1);
    try testPair(&s, "laptop", "10.8.0.2", hashOf(a), 0);
    // Fill the ring first (earlier rotations, same second).
    for (0..ring_len) |i| s.rotate(0, auth.hashSecret(&[_]u8{ 'x', @intCast(i) }), 5);
    var bufs: [ring_len][80]u8 = undefined;
    var cur: [80]u8 = undefined;
    const c = cookieFor(&cur, "laptop", 9);
    s.devices[0].?.cur = hashOf(c);
    for (0..ring_len) |i| {
        const r = s.authenticate(c, "10.8.0.2", 5);
        try testing.expect(r == .ok);
        s.rotate(r.ok, hashOf(cookieFor(&bufs[i], "laptop", @intCast(20 + i))), 5);
    }
    for (0..ring_len) |i| try testing.expect(s.authenticate(cookieFor(&bufs[i], "laptop", @intCast(20 + i)), "10.8.0.2", 5) == .ok);
}

test "garbage secret for a known device revokes it" {
    var s: Store = .{};
    var b: [80]u8 = undefined;
    const c = cookieFor(&b, "phone", 5);
    try testPair(&s, "phone", "10.8.0.3", hashOf(c), 1);
    var bad: [80]u8 = undefined;
    try testing.expect(s.authenticate(cookieFor(&bad, "phone", 9), "10.8.0.3", 2) == .revoked);
    try testing.expect(s.count() == 0);
}

test "malformed cookies are unknown, not revocations" {
    var s: Store = .{};
    var b: [80]u8 = undefined;
    const c = cookieFor(&b, "phone", 5);
    try testPair(&s, "phone", "10.8.0.3", hashOf(c), 1);
    try testing.expect(s.authenticate("phone", "10.8.0.3", 2) == .unknown);
    try testing.expect(s.authenticate("phone.short", "10.8.0.3", 2) == .unknown);
    try testing.expect(s.authenticate("PHONE.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "10.8.0.3", 2) == .unknown);
    try testing.expect(s.count() == 1);
}

test "re-pairing replaces same name or same address" {
    var s: Store = .{};
    try testPair(&s, "laptop", "10.8.0.2", auth.hashSecret("a"), 1);
    const p = try testPairReplacing(&s, "laptop2", "10.8.0.2", auth.hashSecret("b"), 3);
    try testing.expect(s.find("laptop") == null);
    try testing.expect(s.find("laptop2") != null);
    try testing.expectEqual(@as(usize, 1), s.count());
    try testing.expectEqual(@as(usize, 1), p.replaced.n);
    try testing.expectEqualStrings("laptop", p.replaced.items()[0].name());
    try testing.expectEqual(idOf(auth.hashSecret("a")), p.replaced.items()[0].id);
}

test "re-pairing a name: the old record is removed outright, never updated" {
    var s: Store = .{};
    var b1: [80]u8 = undefined;
    const old = cookieFor(&b1, "laptop", 1);
    try testPair(&s, "laptop", "10.8.0.2", hashOf(old), 1);
    s.rotate(s.find("laptop").?, auth.hashSecret("rotated"), 2); // grace ring has `old`
    // The same name re-paired from another address (another machine).
    var b2: [80]u8 = undefined;
    const new = cookieFor(&b2, "laptop", 2);
    const p = try testPairReplacing(&s, "laptop", "10.8.0.7", hashOf(new), 3);
    try testing.expectEqual(@as(usize, 1), p.replaced.n);
    try testing.expectEqual(idOf(hashOf(old)), p.replaced.items()[0].id);
    try testing.expect(!std.mem.eql(u8, &p.device.id, &p.replaced.items()[0].id));
    try testing.expectEqual(@as(usize, 1), s.count());
    const d = s.devices[s.find("laptop").?].?;
    // Nothing carried over: new id, address, secret, empty grace ring, new created.
    try testing.expectEqual(p.device.id, d.id);
    try testing.expectEqualStrings("10.8.0.7", d.ip.get());
    try testing.expectEqual(@as(i64, 3), d.created);
    for (d.ring) |g| try testing.expect(g == null);
    try testing.expect(s.findId(idOf(hashOf(old))) == null);
    // The old credential (current or in its grace ring) is just unknown
    // now from the old address, and never works for the new record.
    try testing.expect(s.authenticate(old, "10.8.0.2", 4) == .wrong_address);
    try testing.expect(s.authenticate(old, "10.8.0.7", 4) == .revoked);
}

test "removeId spares a newer record under the same name" {
    var s: Store = .{};
    try testPair(&s, "laptop", "10.8.0.2", auth.hashSecret("a"), 1);
    const old_id = s.devices[s.find("laptop").?].?.id;
    try testPair(&s, "laptop", "10.8.0.2", auth.hashSecret("b"), 2);
    try testing.expect(!s.removeId(old_id));
    try testing.expect(s.find("laptop") != null);
    try testing.expect(s.removeId(idOf(auth.hashSecret("b"))));
    try testing.expectEqual(@as(usize, 0), s.count());
}

test "authenticate reports which record it revoked" {
    var s: Store = .{};
    var b: [80]u8 = undefined;
    const c = cookieFor(&b, "phone", 5);
    try testPair(&s, "phone", "10.8.0.3", hashOf(c), 1);
    var bad: [80]u8 = undefined;
    const r = s.authenticate(cookieFor(&bad, "phone", 9), "10.8.0.3", 2);
    try testing.expectEqualStrings("phone", r.revoked.name());
    try testing.expectEqual(idOf(hashOf(c)), r.revoked.id);
}

test "pairing window expires and ends" {
    var s: Store = .{};
    try s.beginPair("laptop", 100, 120, 5, 1);
    try testing.expect(s.pairingName(220) != null);
    try testing.expect(s.pairingName(221) == null);
    try testing.expect(s.expire(221));
    try testing.expect(s.pairing == null);
    try s.beginPair("laptop", 0, 99999, 5, 1);
    try testing.expectEqual(max_pair_window_s, s.pairing.?.expires);
    try testing.expect(!s.endPair(6));
    try testing.expect(s.endPair(5));
    try testing.expect(s.pairing == null);
    // An approved request can't be collected after the window expired.
    try s.beginPair("laptop", 0, 60, 9, 1);
    try s.addRequest("10.8.0.2", auth.hashSecret("t"), "0a0a".*, 1);
    _ = s.answer(9, "0a0a", true);
    try testing.expect((try s.claim(auth.hashSecret("t"), "10.8.0.2", idOf(auth.hashSecret("x")), auth.hashSecret("x"), 61)) == .unknown);
}

test "unused devices are forgotten" {
    var s: Store = .{};
    try testPair(&s, "old", "10.8.0.9", auth.hashSecret("x"), 1);
    try testing.expect(!s.expire(1 + unused_expiry_s));
    try testing.expect(s.expire(2 + unused_expiry_s));
    try testing.expectEqual(@as(usize, 0), s.count());
}

test "expired grace secrets are dropped" {
    var s: Store = .{};
    try testPair(&s, "old", "10.8.0.9", auth.hashSecret("x"), 1);
    s.rotate(0, auth.hashSecret("y"), 2);
    try testing.expect(!s.expire(2 + grace_s));
    try testing.expect(s.expire(3 + grace_s));
    try testing.expect(s.devices[0].?.ring[0] == null);
}

const zeros64: [64]u8 = @splat('0');

test "file round trip and strict parsing" {
    var s: Store = .{};
    var b: [80]u8 = undefined;
    const c = cookieFor(&b, "laptop", 3);
    try testPair(&s, "laptop", "10.8.0.2", hashOf(c), 7);
    s.rotate(s.find("laptop").?, auth.hashSecret("new"), 8);
    try s.beginPair("phone", 9, 60, 0xdeadbeef01, 4242);
    s.pairing.?.ca = .up;
    s.pairing.?.ca_where.set("10.8.0.1:8421");
    try s.addRequest("10.8.0.3", auth.hashSecret("tok"), "7f3a".*, 9);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try s.format(testing.allocator, &out);
    const t = try Store.parse(out.items);
    try testing.expectEqualStrings("phone", t.pairingName(10).?);
    const p = t.pairing.?;
    try testing.expectEqual(@as(u64, 0xdeadbeef01), p.nonce);
    try testing.expectEqual(@as(u32, 4242), p.pid);
    try testing.expectEqual(CaState.up, p.ca);
    try testing.expectEqualStrings("10.8.0.1:8421", p.ca_where.get());
    const rq = p.requests[p.findCode("7f3a").?].?;
    try testing.expectEqualStrings("10.8.0.3", rq.ip.get());
    try testing.expectEqual(ReqState.pending, rq.state);
    try testing.expectEqual(auth.hashSecret("tok"), rq.token);
    const d = t.devices[t.find("laptop").?].?;
    try testing.expectEqualStrings("10.8.0.2", d.ip.get());
    try testing.expectEqual(auth.hashSecret("new"), d.cur);
    try testing.expectEqual(hashOf(c), d.ring[0].?.hash);
    try testing.expectEqual(@as(i64, 8 + grace_s), d.ring[0].?.until);
    try testing.expectEqual(idOf(hashOf(c)), d.id);

    try testing.expectError(error.BadDeviceFile, Store.parse(""));
    try testing.expectError(error.BadDeviceFile, Store.parse("portal-devices-v4\n"));
    try testing.expectError(error.BadDeviceFile, Store.parse(header ++ "\ndev x\n"));
    try testing.expectError(error.BadDeviceFile, Store.parse(header ++ "\nhack\n"));
    try testing.expectError(error.BadDeviceFile, Store.parse(header ++ "\npair Bad 5\n"));
    try testing.expectError(error.BadDeviceFile, Store.parse(header ++ "\nreq 7f3a " ++ &zeros64 ++ " 10.8.0.3 1 pending\n"));
    // Two records with one id would let sessions cross between them.
    const dup = "dev a 10.8.0.2 " ++ zeros64[0..32] ++ " " ++ &zeros64 ++ " 1 1\n";
    try testing.expectError(error.BadDeviceFile, Store.parse(header ++ "\n" ++ dup ++ "dev b 10.8.0.3 " ++ zeros64[0..32] ++ " " ++ &zeros64 ++ " 1 1\n"));
    _ = try Store.parse(header ++ "\n" ++ dup);
}

test "v2 files still load (ids derived, stable)" {
    const h1: [64]u8 = @splat('1');
    const v2 = header_v2 ++ "\ndev laptop 10.8.0.2 " ++ &h1 ++ " 5 6\n";
    const a = try Store.parse(v2);
    const b = try Store.parse(v2);
    try testing.expectEqual(a.devices[0].?.id, b.devices[0].?.id);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try a.format(testing.allocator, &out);
    try testing.expect(std.mem.startsWith(u8, out.items, header ++ "\n"));
    try testing.expectEqual(a.devices[0].?.id, (try Store.parse(out.items)).devices[0].?.id);
}

test "v1 files still load (prev secret becomes the ring; v1 windows are dropped)" {
    const h1: [64]u8 = @splat('1');
    const h2: [64]u8 = @splat('2');
    const v1 = header_v1 ++ "\npair laptop 500\ndev laptop 10.8.0.2 " ++ &h1 ++ " " ++ &h2 ++ " 900 5 6\n";
    const s = try Store.parse(v1);
    try testing.expect(s.pairing == null);
    const d = s.devices[s.find("laptop").?].?;
    try testing.expectEqual(@as(i64, 900), d.ring[0].?.until);
    try testing.expectEqual(@as(i64, 6), d.last_seen);
}

test "Desk: begin, see a request, approve, collect, cancel (on a real store file)" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var pbuf: [256]u8 = undefined;
    const dir = try std.fmt.bufPrint(&pbuf, ".zig-cache\\tmp\\{s}", .{&tmp.sub_path});
    const desk: Desk = .{ .gpa = testing.allocator, .io = io, .paths = .{ .dir = dir } };
    try testing.expect((try desk.begin("phone", 120, 42, 7)) == null);
    try testing.expectEqualStrings("phone", (try desk.begin("phone", 120, 43, 7)).?.get()); // replaced
    try testing.expect((try desk.get(42)) == null);
    const now = Io.Timestamp.now(io, .real).toSeconds();
    // A device asks (what POST /pair does on the server).
    const Ctx = struct { now: i64 };
    try withStore(testing.allocator, io, desk.paths, now, Ctx{ .now = now }, struct {
        fn op(c: Ctx, st: *Store) !bool {
            try st.addRequest("10.8.0.3", auth.hashSecret("tok"), "7f3a".*, c.now);
            return true;
        }
    }.op);
    const p = (try desk.get(43)).?;
    try testing.expectEqual(ReqState.pending, p.requests[p.findCode("7f3a").?].?.state);
    try testing.expectEqual(AnswerResult.approved, try desk.answer(43, "7f3a", true));
    try testing.expectEqual(AnswerResult.not_pending, try desk.answer(43, "7f3a", false));
    try withStore(testing.allocator, io, desk.paths, now, Ctx{ .now = now }, struct {
        fn op(c: Ctx, st: *Store) !bool {
            _ = try st.claim(auth.hashSecret("tok"), "10.8.0.3", idOf(auth.hashSecret("secret")), auth.hashSecret("secret"), c.now);
            return true;
        }
    }.op);
    try testing.expectEqualStrings("10.8.0.3", pairedRequest(&(try desk.get(43)).?).?.ip.get());
    try desk.cancel(43);
    try testing.expect((try desk.get(43)) == null);
    // The tmp file was flushed and renamed; nothing is left behind.
    var it = tmp.dir.iterate();
    while (try it.next(io)) |e| try testing.expect(!std.mem.endsWith(u8, e.name, ".tmp"));
}

test "withStore: a cancel while waiting for the lock is returned and stays armed" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [256]u8 = undefined;
    const dir = try std.fmt.bufPrint(&pbuf, ".zig-cache\\tmp\\{s}", .{&tmp.sub_path});
    const paths: Paths = .{ .dir = dir };

    // Hold the lock (as another Portal process would) so withStore waits.
    var lbuf: [1024]u8 = undefined;
    const held = try fsutil.FileLock.acquire(io, try paths.join(&lbuf, &.{"devices.lock"}));
    defer held.release(io);

    const Task = struct {
        /// Like the web handlers: the store error is turned into something
        /// else (a 500), then the task carries on to its next blocking call.
        fn run(t_io: Io, p: Paths, started: *Io.Event) struct { store: anyerror!void, next: Io.Cancelable!void } {
            started.set(t_io);
            const r = withStore(testing.allocator, t_io, p, 0, {}, struct {
                fn op(_: void, _: *Store) !bool {
                    return false;
                }
            }.op);
            // The next cancelation point must still see the cancel.
            const next = t_io.sleep(.fromSeconds(30), .awake);
            return .{ .store = r, .next = next };
        }
    };
    var started: Io.Event = .unset;
    var fut = io.concurrent(Task.run, .{ io, paths, &started }) catch return error.SkipZigTest;
    try started.wait(io);
    try io.sleep(.fromMilliseconds(30), .awake); // let it block on the lock
    const res = fut.cancel(io);
    try testing.expectError(error.Canceled, res.store);
    try testing.expectError(error.Canceled, res.next);
}

test "error messages tell the owner how to recover" {
    try testing.expect(std.mem.indexOf(u8, describeError(error.BadDeviceFile), "move devices.txt") != null);
}

test "waitMs" {
    try testing.expectEqual(w.INFINITE, waitMs(0, null));
    try testing.expectEqual(@as(w.DWORD, 0), waitMs(10, 5));
    try testing.expectEqual(@as(w.DWORD, 2250), waitMs(10, 12));
}
