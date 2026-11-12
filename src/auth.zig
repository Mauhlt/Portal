//! Authentication primitives. Pure logic: callers supply time (wall-clock ms,
//! so time asleep counts towards expiry; a clock that jumps back fails closed)
//! and randomness, which keeps everything here unit-testable.
//!
//! Model:
//!   * Devices are paired at the desk (devices.zig); a paired device's
//!     rotating credential creates a session here.
//!   * The browser holds a random session id in an HttpOnly cookie. Only
//!     hashes of session ids are kept in memory, tagged with the paired
//!     device's random record id (and its name, for display and sync), so
//!     unpairing or re-pairing a device ends exactly that record's
//!     sessions: a new device under the same name never inherits them.
//!   * Sessions live in memory only; restarting Portal ends them, and paired
//!     devices silently get new ones on their next visit.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const b64 = std.base64.url_safe_no_pad;

pub const secret_bytes = 32;
pub const encoded_len = b64.Encoder.calcSize(secret_bytes); // 43
pub const Hash = [Sha256.digest_length]u8;

pub fn hashSecret(s: []const u8) Hash {
    var out: Hash = undefined;
    Sha256.hash(s, &out, .{});
    return out;
}

/// Encode 32 random bytes as the printable secret handed to the user/browser.
pub fn encodeSecret(raw: *const [secret_bytes]u8, out: *[encoded_len]u8) []const u8 {
    return b64.Encoder.encode(out, raw);
}

/// Constant-time check of a presented secret against a stored hash.
/// Hashing first means comparison time is independent of the presented length
/// and content.
pub fn verify(stored: Hash, presented: []const u8) bool {
    if (presented.len == 0 or presented.len > 256) return false;
    return std.crypto.timing_safe.eql(Hash, hashSecret(presented), stored);
}

// ------------------------------------------------------------------ sessions

/// A paired device record's identity: random, issued at pairing, never
/// reused. A re-pair under the same name gets a new one.
pub const device_id_len = 16;
pub const DeviceId = [device_id_len]u8;

/// Which paired device a session belongs to.
pub const Device = struct {
    pub const max_name = 32;

    id: DeviceId,
    name_buf: [max_name]u8 = undefined,
    name_len: u8 = 0,

    pub fn init(id: DeviceId, device_name: []const u8) Device {
        var d: Device = .{ .id = id };
        const n = @min(device_name.len, max_name);
        @memcpy(d.name_buf[0..n], device_name[0..n]);
        d.name_len = @intCast(n);
        return d;
    }

    pub fn name(d: *const Device) []const u8 {
        return d.name_buf[0..d.name_len];
    }
};

pub const Sessions = struct {
    pub const max_sessions = 8;

    idle_timeout_ms: i64 = 12 * std.time.ms_per_hour,
    absolute_timeout_ms: i64 = 7 * std.time.ms_per_day,
    slots: [max_sessions]?Slot = @splat(null),

    const Slot = struct {
        id_hash: Hash,
        created_ms: i64,
        last_seen_ms: i64,
        device: ?Device = null,
    };

    /// Register a new session id (the encoded cookie value) that belongs
    /// to no device. Evicts the least-recently-used session when full.
    pub fn create(s: *Sessions, cookie_value: []const u8, now_ms: i64) void {
        s.put(cookie_value, now_ms, null);
    }

    /// Like `create`, for a session of paired device `device`.
    pub fn createFor(s: *Sessions, cookie_value: []const u8, now_ms: i64, device: Device) void {
        s.put(cookie_value, now_ms, device);
    }

    fn put(s: *Sessions, cookie_value: []const u8, now_ms: i64, device: ?Device) void {
        s.expire(now_ms);
        var target: usize = 0;
        var oldest: i64 = std.math.maxInt(i64);
        for (s.slots, 0..) |slot, i| {
            const seen = if (slot) |v| v.last_seen_ms else std.math.minInt(i64);
            if (seen < oldest) {
                oldest = seen;
                target = i;
            }
        }
        s.slots[target] = .{ .id_hash = hashSecret(cookie_value), .created_ms = now_ms, .last_seen_ms = now_ms, .device = device };
    }

    /// Returns true and refreshes the idle timer if the cookie is a live session.
    pub fn validate(s: *Sessions, cookie_value: []const u8, now_ms: i64) bool {
        s.expire(now_ms);
        const idx = s.find(cookie_value) orelse return false;
        s.slots[idx].?.last_seen_ms = now_ms;
        return true;
    }

    /// Like `validate` but does not refresh the idle timer. Used by long-lived
    /// WebSockets so an open tab alone does not keep a session alive forever.
    pub fn isLive(s: *Sessions, cookie_value: []const u8, now_ms: i64) bool {
        s.expire(now_ms);
        return s.find(cookie_value) != null;
    }

    pub const Live = union(enum) {
        /// No such live session.
        none,
        /// Live, but belongs to no paired device.
        anonymous,
        device: Device,
    };

    /// Whose session `cookie_value` is, if it is live.
    pub fn live(s: *Sessions, cookie_value: []const u8, now_ms: i64, refresh: bool) Live {
        s.expire(now_ms);
        const idx = s.find(cookie_value) orelse return .none;
        const slot = &s.slots[idx].?;
        if (refresh) slot.last_seen_ms = now_ms;
        return if (slot.device) |d| .{ .device = d } else .anonymous;
    }

    /// The paired device a live session belongs to; null if not live or
    /// untagged.
    pub fn liveDevice(s: *Sessions, cookie_value: []const u8, now_ms: i64, refresh: bool) ?Device {
        return switch (s.live(cookie_value, now_ms, refresh)) {
            .device => |d| d,
            else => null,
        };
    }

    /// Ends every session of device record `id`. Returns how many.
    pub fn revokeDevice(s: *Sessions, id: DeviceId) usize {
        var n: usize = 0;
        for (&s.slots) |*slot| {
            const v = slot.* orelse continue;
            const d = v.device orelse continue;
            if (std.mem.eql(u8, &d.id, &id)) {
                slot.* = null;
                n += 1;
            }
        }
        return n;
    }

    /// When the session `cookie_value` will expire if not refreshed (the
    /// earlier of its idle and absolute limits), or null if it is not live.
    /// Lets a viewer sleep until then instead of polling.
    pub fn expiresAt(s: *Sessions, cookie_value: []const u8, now_ms: i64) ?i64 {
        s.expire(now_ms);
        const idx = s.find(cookie_value) orelse return null;
        const v = s.slots[idx].?;
        return @min(v.last_seen_ms +| s.idle_timeout_ms, v.created_ms +| s.absolute_timeout_ms);
    }

    /// Ends the sessions of device records for which `paired(ctx, id)` is
    /// false. Sessions created at or after `since_ms` are kept: the
    /// caller's view of the device list may predate them. Untagged
    /// sessions are kept. Returns how many were ended.
    pub fn revokeUnpaired(s: *Sessions, since_ms: i64, ctx: anytype, comptime paired: fn (@TypeOf(ctx), DeviceId) bool) usize {
        var n: usize = 0;
        for (&s.slots) |*slot| {
            const v = slot.* orelse continue;
            const d = v.device orelse continue;
            if (v.created_ms >= since_ms) continue;
            if (!paired(ctx, d.id)) {
                slot.* = null;
                n += 1;
            }
        }
        return n;
    }

    pub fn revoke(s: *Sessions, cookie_value: []const u8) void {
        if (s.find(cookie_value)) |idx| s.slots[idx] = null;
    }

    pub fn revokeAll(s: *Sessions) void {
        s.slots = @splat(null);
    }

    pub fn count(s: *const Sessions) usize {
        var n: usize = 0;
        for (s.slots) |slot| {
            if (slot != null) n += 1;
        }
        return n;
    }

    fn find(s: *const Sessions, cookie_value: []const u8) ?usize {
        if (cookie_value.len != encoded_len) return null;
        const h = hashSecret(cookie_value);
        var found: ?usize = null;
        // Scan every slot without early exit.
        for (s.slots, 0..) |slot, i| {
            if (slot) |v| {
                if (std.crypto.timing_safe.eql(Hash, v.id_hash, h)) found = i;
            }
        }
        return found;
    }

    fn expire(s: *Sessions, now_ms: i64) void {
        for (&s.slots) |*slot| {
            if (slot.*) |v| {
                if (now_ms - v.last_seen_ms > s.idle_timeout_ms or
                    now_ms - v.created_ms > s.absolute_timeout_ms or
                    now_ms < v.created_ms) // clock went backwards: fail closed
                {
                    slot.* = null;
                }
            }
        }
    }
};

// --------------------------------------------------------------------- tests

const testing = std.testing;

test "verify accepts right secret, rejects others" {
    const raw: [secret_bytes]u8 = @splat(7);
    var buf: [encoded_len]u8 = undefined;
    const tok = encodeSecret(&raw, &buf);
    try testing.expectEqual(@as(usize, 43), tok.len);
    const h = hashSecret(tok);
    try testing.expect(verify(h, tok));
    try testing.expect(!verify(h, tok[0 .. tok.len - 1]));
    try testing.expect(!verify(h, ""));
    var wrong = buf;
    wrong[0] ^= 1;
    try testing.expect(!verify(h, &wrong));
}

fn testCookie(fill: u8) [encoded_len]u8 {
    const raw: [secret_bytes]u8 = @splat(fill);
    var out: [encoded_len]u8 = undefined;
    _ = encodeSecret(&raw, &out);
    return out;
}

test "sessions: create, validate, revoke" {
    var s: Sessions = .{};
    const a = testCookie(1);
    const b = testCookie(2);
    s.create(&a, 0);
    try testing.expect(s.validate(&a, 10));
    try testing.expect(!s.validate(&b, 10));
    s.revoke(&a);
    try testing.expect(!s.validate(&a, 20));
}

test "sessions: idle and absolute timeouts" {
    var s: Sessions = .{ .idle_timeout_ms = 100, .absolute_timeout_ms = 250 };
    const a = testCookie(1);
    s.create(&a, 0);
    try testing.expect(s.validate(&a, 90));
    try testing.expect(s.validate(&a, 180));
    try testing.expect(!s.validate(&a, 260)); // absolute limit
    s.create(&a, 1000);
    try testing.expect(!s.validate(&a, 1101)); // idle limit
}

test "sessions: isLive does not refresh idle timer" {
    var s: Sessions = .{ .idle_timeout_ms = 100 };
    const a = testCookie(1);
    s.create(&a, 0);
    try testing.expect(s.isLive(&a, 90));
    try testing.expect(!s.isLive(&a, 101));
}

test "sessions: eviction when full keeps newest" {
    var s: Sessions = .{};
    var cookies: [Sessions.max_sessions + 1][encoded_len]u8 = undefined;
    for (&cookies, 0..) |*c, i| {
        c.* = testCookie(@intCast(i + 1));
        s.create(c, @intCast(i));
    }
    try testing.expectEqual(@as(usize, Sessions.max_sessions), s.count());
    try testing.expect(!s.isLive(&cookies[0], 10));
    try testing.expect(s.isLive(&cookies[Sessions.max_sessions], 10));
}

fn testId(fill: u8) DeviceId {
    return @splat(fill);
}

test "sessions: device tags" {
    var s: Sessions = .{};
    const a = testCookie(1);
    const b = testCookie(2);
    const c = testCookie(3);
    s.createFor(&a, 0, .init(testId(1), "laptop"));
    s.createFor(&b, 0, .init(testId(2), "phone"));
    s.create(&c, 0);
    try testing.expectEqualStrings("laptop", s.liveDevice(&a, 1, false).?.name());
    try testing.expect(s.live(&c, 1, false) == .anonymous);
    try testing.expect(s.live(&testCookie(9), 1, false) == .none);
    try testing.expectEqual(@as(usize, 1), s.revokeDevice(testId(1)));
    try testing.expect(s.liveDevice(&a, 2, false) == null);
    try testing.expectEqualStrings("phone", s.liveDevice(&b, 2, false).?.name());
}

test "sessions: a re-paired name does not inherit or keep the old record's sessions" {
    var s: Sessions = .{};
    const old_a = testCookie(1);
    const old_b = testCookie(2);
    const new = testCookie(3);
    // Two sessions of the old "laptop" record (two tabs).
    s.createFor(&old_a, 0, .init(testId(1), "laptop"));
    s.createFor(&old_b, 0, .init(testId(1), "laptop"));
    // Re-paired: the old record's sessions go, then the new one is issued.
    try testing.expectEqual(@as(usize, 2), s.revokeDevice(testId(1)));
    s.createFor(&new, 1, .init(testId(7), "laptop"));
    try testing.expect(!s.isLive(&old_a, 2) and !s.isLive(&old_b, 2));
    // Revoking the old record again (late watcher pass) spares the new one.
    try testing.expectEqual(@as(usize, 0), s.revokeDevice(testId(1)));
    try testing.expect(std.mem.eql(u8, &s.liveDevice(&new, 2, false).?.id, &testId(7)));
}

test "sessions: clock going backwards fails closed" {
    var s: Sessions = .{};
    const a = testCookie(1);
    s.create(&a, 1000);
    try testing.expect(!s.validate(&a, 500));
}



test "sessions: expiresAt is the earlier limit" {
    var s: Sessions = .{ .idle_timeout_ms = 100, .absolute_timeout_ms = 250 };
    const a = testCookie(1);
    s.create(&a, 0);
    try testing.expectEqual(@as(?i64, 100), s.expiresAt(&a, 10));
    try testing.expect(s.validate(&a, 90));
    try testing.expectEqual(@as(?i64, 190), s.expiresAt(&a, 95));
    try testing.expect(s.validate(&a, 180));
    try testing.expectEqual(@as(?i64, 250), s.expiresAt(&a, 181));
    try testing.expectEqual(@as(?i64, null), s.expiresAt(&testCookie(2), 181));
}

test "sessions: revokeUnpaired keeps new and untagged sessions" {
    var s: Sessions = .{};
    const a = testCookie(1);
    const b = testCookie(2);
    const c = testCookie(3);
    const d = testCookie(4);
    s.createFor(&a, 0, .init(testId(1), "laptop"));
    s.createFor(&b, 0, .init(testId(2), "laptop")); // same name, the record that is kept
    s.create(&d, 0);
    s.createFor(&c, 50, .init(testId(1), "laptop")); // created after the device list was read
    const n = s.revokeUnpaired(40, {}, struct {
        fn f(_: void, id: DeviceId) bool {
            return std.mem.eql(u8, &id, &testId(2));
        }
    }.f);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(!s.isLive(&a, 60));
    try testing.expect(s.isLive(&b, 60) and s.isLive(&c, 60) and s.isLive(&d, 60));
}
