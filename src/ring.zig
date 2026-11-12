//! Fixed-capacity scrollback buffer addressed by absolute byte position.
//!
//! The PTY output thread appends; each web client remembers the absolute
//! position it has sent up to. If a client falls further behind than the
//! buffer capacity, it is fast-forwarded to the oldest byte still held.
//! Not thread-safe by itself: callers hold the owning Session's mutex.

const std = @import("std");

pub const Ring = struct {
    buf: []u8,
    /// Total bytes ever appended. Position `total` is "one past the newest byte".
    total: u64 = 0,

    pub fn init(buf: []u8) Ring {
        std.debug.assert(buf.len > 0);
        return .{ .buf = buf };
    }

    /// Absolute position of the oldest byte still stored.
    pub fn oldest(r: *const Ring) u64 {
        return r.total -| @as(u64, r.buf.len);
    }

    pub fn append(r: *Ring, data_in: []const u8) void {
        var data = data_in;
        // Only the last `cap` bytes can survive; skip the rest up front.
        if (data.len > r.buf.len) {
            const skip = data.len - r.buf.len;
            r.total += skip;
            data = data[skip..];
        }
        var start: usize = @intCast(r.total % r.buf.len);
        var remaining = data;
        while (remaining.len > 0) {
            const n = @min(remaining.len, r.buf.len - start);
            @memcpy(r.buf[start..][0..n], remaining[0..n]);
            remaining = remaining[n..];
            start = 0;
        }
        r.total += data.len;
    }

    pub const ReadResult = struct {
        /// Bytes copied into `out`.
        n: usize,
        /// Position to pass to the next call.
        next: u64,
        /// True if `pos` had already been overwritten and data was lost.
        skipped: bool,
    };

    pub fn readFrom(r: *const Ring, pos_in: u64, out: []u8) ReadResult {
        var pos = pos_in;
        var skipped = false;
        if (pos > r.total) pos = r.total; // defensive: never read the future
        if (pos < r.oldest()) {
            pos = r.oldest();
            skipped = true;
        }
        const avail: usize = @intCast(r.total - pos);
        const want = @min(avail, out.len);
        var copied: usize = 0;
        while (copied < want) {
            const idx: usize = @intCast((pos + copied) % r.buf.len);
            const n = @min(want - copied, r.buf.len - idx);
            @memcpy(out[copied..][0..n], r.buf[idx..][0..n]);
            copied += n;
        }
        return .{ .n = copied, .next = pos + copied, .skipped = skipped };
    }
};

const testing = std.testing;

test "append and read without wrap" {
    var storage: [8]u8 = undefined;
    var r = Ring.init(&storage);
    r.append("abc");
    var out: [16]u8 = undefined;
    const res = r.readFrom(0, &out);
    try testing.expectEqualStrings("abc", out[0..res.n]);
    try testing.expectEqual(@as(u64, 3), res.next);
    try testing.expect(!res.skipped);
}

test "wraparound keeps newest bytes and reports skip" {
    var storage: [4]u8 = undefined;
    var r = Ring.init(&storage);
    r.append("abc");
    r.append("defg"); // total 7, holds "defg"
    var out: [16]u8 = undefined;
    const res = r.readFrom(0, &out);
    try testing.expect(res.skipped);
    try testing.expectEqualStrings("defg", out[0..res.n]);
    try testing.expectEqual(@as(u64, 7), res.next);
}

test "append larger than capacity" {
    var storage: [4]u8 = undefined;
    var r = Ring.init(&storage);
    r.append("0123456789");
    var out: [16]u8 = undefined;
    const res = r.readFrom(r.oldest(), &out);
    try testing.expectEqualStrings("6789", out[0..res.n]);
    try testing.expectEqual(@as(u64, 10), r.total);
}

test "partial reads respect out buffer and wrap" {
    var storage: [5]u8 = undefined;
    var r = Ring.init(&storage);
    r.append("abcd");
    r.append("efg"); // holds "cdefg", physical layout wraps
    var out: [2]u8 = undefined;
    var pos = r.oldest();
    var collected: [8]u8 = undefined;
    var len: usize = 0;
    while (pos < r.total) {
        const res = r.readFrom(pos, &out);
        @memcpy(collected[len..][0..res.n], out[0..res.n]);
        len += res.n;
        pos = res.next;
    }
    try testing.expectEqualStrings("cdefg", collected[0..len]);
}

test "position past end is clamped" {
    var storage: [4]u8 = undefined;
    var r = Ring.init(&storage);
    r.append("ab");
    var out: [4]u8 = undefined;
    const res = r.readFrom(100, &out);
    try testing.expectEqual(@as(usize, 0), res.n);
    try testing.expectEqual(@as(u64, 2), res.next);
}
