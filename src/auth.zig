//! Authentication primitives. Pure logic: callers supply time (ms, monotonic)
//! and randomness, which keeps everything here unit-testable.
//!
//! Model:
//!   * Devices are paired at the desk (devices.zig); a paired device's
//!     rotating credential creates a session here.
//!   * The browser holds a random session id in an HttpOnly cookie. Only
//!     hashes of session ids are kept in memory, tagged with the device name
//!     so unpairing a device ends its sessions.
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

pub const Sessions = struct {
    pub const max_sessions = 8;

    idle_timeout_ms: i64 = 12 * std.time.ms_per_hour,
    absolute_timeout_ms: i64 = 7 * std.time.ms_per_day,
    slots: [max_sessions]?Slot = @splat(null),

    pub const max_tag = 32;

    const Slot = struct {
        id_hash: Hash,
        created_ms: i64,
        last_seen_ms: i64,
        tag: [max_tag]u8 = undefined,
        tag_len: u8 = 0,
    };

    /// Register a new session id (the encoded cookie value). Evicts the
    /// least-recently-used session when full.
    pub fn create(s: *Sessions, cookie_value: []const u8, now_ms: i64) void {
        s.createTagged(cookie_value, now_ms, "");
    }

    /// Like `create`, remembering `tag` (the paired device's name).
    pub fn createTagged(s: *Sessions, cookie_value: []const u8, now_ms: i64, tag: []const u8) void {
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
        var slot: Slot = .{ .id_hash = hashSecret(cookie_value), .created_ms = now_ms, .last_seen_ms = now_ms };
        const n = @min(tag.len, max_tag);
        @memcpy(slot.tag[0..n], tag[0..n]);
        slot.tag_len = @intCast(n);
        s.slots[target] = slot;
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

    /// Copies the tag of a live session into `out`. Null if not live.
    pub fn liveTag(s: *Sessions, cookie_value: []const u8, now_ms: i64, refresh: bool, out: *[max_tag]u8) ?[]const u8 {
        s.expire(now_ms);
        const idx = s.find(cookie_value) orelse return null;
        const slot = &s.slots[idx].?;
        if (refresh) slot.last_seen_ms = now_ms;
        @memcpy(out[0..slot.tag_len], slot.tag[0..slot.tag_len]);
        return out[0..slot.tag_len];
    }

    /// Ends every session belonging to device `tag`.
    pub fn revokeTag(s: *Sessions, tag: []const u8) void {
        for (&s.slots) |*slot| {
            if (slot.*) |v| if (std.mem.eql(u8, v.tag[0..v.tag_len], tag)) {
                slot.* = null;
            };
        }
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

test "sessions: tags" {
    var s: Sessions = .{};
    const a = testCookie(1);
    const b = testCookie(2);
    s.createTagged(&a, 0, "laptop");
    s.createTagged(&b, 0, "phone");
    var buf: [Sessions.max_tag]u8 = undefined;
    try testing.expectEqualStrings("laptop", s.liveTag(&a, 1, false, &buf).?);
    s.revokeTag("laptop");
    try testing.expect(s.liveTag(&a, 2, false, &buf) == null);
    try testing.expectEqualStrings("phone", s.liveTag(&b, 2, false, &buf).?);
}

test "sessions: clock going backwards fails closed" {
    var s: Sessions = .{};
    const a = testCookie(1);
    s.create(&a, 1000);
    try testing.expect(!s.validate(&a, 500));
}


