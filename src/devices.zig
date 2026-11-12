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
const header = "portal-devices-v2";

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
    cur: auth.Hash,
    /// Recently superseded secrets, each valid until its own `until`.
    ring: [ring_len]?Grace = @splat(null),
    created: i64,
    last_seen: i64,
};

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
    /// Wrong or stale secret for a known device: the device was revoked.
    revoked: []const u8,
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

pub const ClaimResult = union(enum) {
    pending,
    denied,
    /// No such request (expired, window closed, wrong address).
    unknown,
    /// Paired: the device's name.
    paired: []const u8,
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
        s.devices[idx] = null;
        return .{ .revoked = name };
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
    /// If approved, registers the device with secret hash `new_hash` (a
    /// device already using that name, or that address, is replaced).
    pub fn claim(s: *Store, token: auth.Hash, ip: []const u8, new_hash: auth.Hash, now: i64) !ClaimResult {
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
        var dev: Device = .{ .cur = new_hash, .created = now, .last_seen = now };
        dev.name = p.name;
        dev.ip.set(ip);
        for (&s.devices) |*slot| {
            if (slot.*) |d| if (std.mem.eql(u8, d.name.get(), dev.name.get()) or std.mem.eql(u8, d.ip.get(), ip)) {
                slot.* = null;
            };
        }
        for (&s.devices) |*slot| {
            if (slot.* == null) {
                slot.* = dev;
                r.state = .done;
                return .{ .paired = slot.*.?.name.get() };
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
        const v1 = std.mem.eql(u8, first, header_v1);
        if (!v1 and !std.mem.eql(u8, first, header)) return error.BadDeviceFile;
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
                var d: Device = .{ .cur = try parseHash(f.next()), .created = 0, .last_seen = 0 };
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
            try out.appendSlice(gpa, try std.fmt.bufPrint(&buf, "dev {s} {s} {x} {d} {d}", .{
                d.name.get(), d.ip.get(), &d.cur, d.created, d.last_seen,
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
            "start Portal again, and re-pair every device with `portal pair <name>`",
        error.DeviceStoreBusy => "the device list is locked by another Portal process; try again",
        error.DeviceStoreWriteFailed => "could not replace devices.txt (disk full, or the file is locked by another program)",
        else => "could not access the device list in %LOCALAPPDATA%\\Portal",
    };
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

const CREATE_ALWAYS: w.DWORD = 2;
extern "kernel32" fn FlushFileBuffers(h: w.HANDLE) callconv(.winapi) w.BOOL;

/// Writes `data` to `path_w` and flushes it to disk before returning, so the
/// atomic rename that follows can never publish an empty or partial file.
fn writeFlushed(path_w: [:0]const u16, data: []const u8) !void {
    const h = w.validHandle(w.CreateFileW(path_w.ptr, w.GENERIC_WRITE, 0, null, CREATE_ALWAYS, w.FILE_ATTRIBUTE_NORMAL, null)) orelse
        return error.DeviceStoreWriteFailed;
    defer _ = w.CloseHandle(h);
    var off: usize = 0;
    while (off < data.len) {
        var n: w.DWORD = 0;
        const chunk: w.DWORD = @intCast(@min(data.len - off, 1 << 20));
        if (w.WriteFile(h, data[off..].ptr, chunk, &n, null) == 0 or n == 0) return error.DeviceStoreWriteFailed;
        off += n;
    }
    if (FlushFileBuffers(h) == 0) return error.DeviceStoreWriteFailed;
}

/// Locked read-modify-write of the device store. `op(ctx, *Store)` returns
/// whether it changed the store; if so the file is replaced atomically
/// (written, flushed to disk, then renamed over the old one).
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
    const tmp_w = try wide(gpa, tmp);
    defer gpa.free(tmp_w);
    try writeFlushed(tmp_w, out.items);
    const path_w = try wide(gpa, path);
    defer gpa.free(path_w);
    if (w.MoveFileExW(tmp_w.ptr, path_w.ptr, w.MOVEFILE_REPLACE_EXISTING | w.MOVEFILE_WRITE_THROUGH) == 0)
        return error.DeviceStoreWriteFailed;
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

pub const WAIT_OBJECT_0: w.DWORD = 0;
pub const WAIT_TIMEOUT: w.DWORD = 258;
const FILE_NOTIFY_CHANGE_FILE_NAME: w.DWORD = 0x1;
extern "kernel32" fn FindFirstChangeNotificationW(path: [*:0]const u16, subtree: w.BOOL, filter: w.DWORD) callconv(.winapi) ?w.HANDLE;
extern "kernel32" fn FindNextChangeNotification(h: w.HANDLE) callconv(.winapi) w.BOOL;
extern "kernel32" fn FindCloseChangeNotification(h: w.HANDLE) callconv(.winapi) w.BOOL;
pub extern "kernel32" fn WaitForMultipleObjects(n: w.DWORD, handles: [*]const w.HANDLE, all: w.BOOL, ms: w.DWORD) callconv(.winapi) w.DWORD;

/// Signalled whenever a file in the data directory is created, renamed or
/// deleted. Every store change ends in a rename (see `withStore`), so this
/// wakes every Portal process sharing the directory, however many there
/// are, without anyone polling. Log appends do not trigger it.
pub const DirWatch = struct {
    h: ?w.HANDLE = null,

    pub fn open(gpa: Allocator, paths: Paths) DirWatch {
        const dir_w = wide(gpa, paths.dir) catch return .{};
        defer gpa.free(dir_w);
        return .{ .h = w.validHandle(FindFirstChangeNotificationW(dir_w.ptr, 0, FILE_NOTIFY_CHANGE_FILE_NAME)) };
    }

    /// Re-arms after a wake. Call before re-reading the store, so a change
    /// made while reading signals again.
    pub fn rearm(d: *DirWatch) void {
        if (d.h) |h| if (FindNextChangeNotification(h) == 0) {
            _ = FindCloseChangeNotification(h);
            d.h = null;
        };
    }

    pub fn close(d: *DirWatch) void {
        if (d.h) |h| _ = FindCloseChangeNotification(h);
        d.h = null;
    }
};

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

/// Pairs `name` at `ip` through the request/approve/claim flow.
fn testPair(s: *Store, name: []const u8, ip: []const u8, secret_hash: auth.Hash, now: i64) !void {
    try s.beginPair(name, now, 120, 0x1234, 1);
    const tok = auth.hashSecret("token");
    try s.addRequest(ip, tok, "ab12".*, now);
    try testing.expectEqual(AnswerResult.approved, s.answer(0x1234, "ab12", true));
    const r = try s.claim(tok, ip, secret_hash, now);
    try testing.expectEqualStrings(name, r.paired);
    _ = s.endPair(0x1234);
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
    try testing.expect((try s.claim(tok_b, "10.8.0.9", auth.hashSecret("x"), 3)) == .pending);
    try testing.expectEqual(@as(usize, 0), s.count());

    // Deny the wrong-looking one: the window stays open.
    try testing.expectEqual(AnswerResult.denied, s.answer(7, "bbbb", false));
    try testing.expect((try s.claim(tok_b, "10.8.0.9", auth.hashSecret("x"), 4)) == .denied);
    try testing.expectError(error.AddressDenied, s.addRequest("10.8.0.9", auth.hashSecret("D"), "dddd".*, 4));
    try testing.expectEqual(AnswerResult.not_pending, s.answer(7, "bbbb", true));
    try testing.expectEqual(AnswerResult.window_gone, s.answer(8, "aaaa", true));
    try testing.expectEqual(AnswerResult.no_such_request, s.answer(7, "cccc", true));

    // Approve the phone; the token is bound to its address.
    try testing.expectEqual(AnswerResult.approved, s.answer(7, "aaaa", true));
    try testing.expect((try s.claim(tok_a, "10.8.0.9", auth.hashSecret("x"), 5)) == .unknown);
    try testing.expect((try s.claim(auth.hashSecret("guess"), "10.8.0.3", auth.hashSecret("x"), 5)) == .unknown);
    try testing.expectError(error.WindowDecided, s.addRequest("10.8.0.5", auth.hashSecret("E"), "eeee".*, 5));
    const r = try s.claim(tok_a, "10.8.0.3", auth.hashSecret("secret"), 6);
    try testing.expectEqualStrings("iphone", r.paired);
    try testing.expectEqual(@as(usize, 1), s.count());
    try testing.expectEqualStrings("10.8.0.3", s.devices[s.find("iphone").?].?.ip.get());
    // Single use.
    try testing.expect((try s.claim(tok_a, "10.8.0.3", auth.hashSecret("again"), 7)) == .unknown);
}

test "approving one request denies the other pending ones" {
    var s: Store = .{};
    try s.beginPair("laptop", 0, 120, 1, 1);
    try s.addRequest("10.8.0.2", auth.hashSecret("1"), "0001".*, 1);
    try s.addRequest("10.8.0.3", auth.hashSecret("2"), "0002".*, 1);
    try testing.expectEqual(AnswerResult.approved, s.answer(1, "0002", true));
    try testing.expect((try s.claim(auth.hashSecret("1"), "10.8.0.2", auth.hashSecret("x"), 2)) == .denied);
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
    try testPair(&s, "laptop2", "10.8.0.2", auth.hashSecret("b"), 3);
    try testing.expect(s.find("laptop") == null);
    try testing.expect(s.find("laptop2") != null);
    try testing.expectEqual(@as(usize, 1), s.count());
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
    try testing.expect((try s.claim(auth.hashSecret("t"), "10.8.0.2", auth.hashSecret("x"), 61)) == .unknown);
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

    try testing.expectError(error.BadDeviceFile, Store.parse(""));
    try testing.expectError(error.BadDeviceFile, Store.parse("portal-devices-v3\n"));
    try testing.expectError(error.BadDeviceFile, Store.parse(header ++ "\ndev x\n"));
    try testing.expectError(error.BadDeviceFile, Store.parse(header ++ "\nhack\n"));
    try testing.expectError(error.BadDeviceFile, Store.parse(header ++ "\npair Bad 5\n"));
    try testing.expectError(error.BadDeviceFile, Store.parse(header ++ "\nreq 7f3a " ++ &zeros64 ++ " 10.8.0.3 1 pending\n"));
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
    var tmp = testing.tmpDir(.{});
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
            _ = try st.claim(auth.hashSecret("tok"), "10.8.0.3", auth.hashSecret("secret"), c.now);
            return true;
        }
    }.op);
    try testing.expectEqualStrings("10.8.0.3", pairedRequest(&(try desk.get(43)).?).?.ip.get());
    try desk.cancel(43);
    try testing.expect((try desk.get(43)) == null);
    // The tmp file was flushed and renamed; nothing is left behind.
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, "devices.txt.tmp", .{}));
}

test "error messages tell the owner how to recover" {
    try testing.expect(std.mem.indexOf(u8, describeError(error.BadDeviceFile), "move devices.txt") != null);
}

test "waitMs" {
    try testing.expectEqual(w.INFINITE, waitMs(0, null));
    try testing.expectEqual(@as(w.DWORD, 0), waitMs(10, 5));
    try testing.expectEqual(@as(w.DWORD, 2250), waitMs(10, 12));
}
