//! Minimal DER (X.690) writer and a bounds-checked reader.
//!
//! The writer builds a value bottom-up: each helper takes already-encoded
//! children and returns the encoded parent, allocated from an arena. That
//! keeps every length exact without a second pass.
//!
//! The reader is the one bounds-checked DER walker of every Portal program:
//! the server reads back its own certificate files with it (cert.zig), and
//! the native client checks a server's certificate with it before std's
//! `Certificate` parser, which indexes without bounds checks, sees the
//! bytes (client/src/net/x509check.zig). It accepts DER only: one-byte
//! tags, definite minimal lengths.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Tag = struct {
    pub const boolean: u8 = 0x01;
    pub const integer: u8 = 0x02;
    pub const bit_string: u8 = 0x03;
    pub const octet_string: u8 = 0x04;
    pub const null_: u8 = 0x05;
    pub const oid: u8 = 0x06;
    pub const utf8_string: u8 = 0x0c;
    pub const printable_string: u8 = 0x13;
    pub const ia5_string: u8 = 0x16;
    pub const utc_time: u8 = 0x17;
    pub const generalized_time: u8 = 0x18;
    pub const sequence: u8 = 0x30;
    pub const set: u8 = 0x31;

    /// [n] context-specific, constructed (EXPLICIT or IMPLICIT SEQUENCE).
    pub fn contextConstructed(n: u5) u8 {
        return 0xa0 | @as(u8, n);
    }
    /// [n] context-specific, primitive (IMPLICIT primitive).
    pub fn contextPrimitive(n: u5) u8 {
        return 0x80 | @as(u8, n);
    }
};

/// Largest content length the writer will encode (certificates are a few
/// hundred bytes; this only guards against misuse).
pub const max_len = 1 << 20;

pub const Writer = struct {
    arena: Allocator,

    pub fn tlv(d: Writer, tag: u8, content: []const u8) ![]u8 {
        if (content.len > max_len) return error.DerTooLong;
        var hdr: [5]u8 = undefined;
        hdr[0] = tag;
        var hl: usize = 2;
        if (content.len < 0x80) {
            hdr[1] = @intCast(content.len);
        } else if (content.len <= 0xff) {
            hdr[1] = 0x81;
            hdr[2] = @intCast(content.len);
            hl = 3;
        } else if (content.len <= 0xffff) {
            hdr[1] = 0x82;
            std.mem.writeInt(u16, hdr[2..4], @intCast(content.len), .big);
            hl = 4;
        } else {
            hdr[1] = 0x83;
            hdr[2] = @intCast(content.len >> 16);
            std.mem.writeInt(u16, hdr[3..5], @intCast(content.len & 0xffff), .big);
            hl = 5;
        }
        const out = try d.arena.alloc(u8, hl + content.len);
        @memcpy(out[0..hl], hdr[0..hl]);
        @memcpy(out[hl..], content);
        return out;
    }

    pub fn concat(d: Writer, parts: []const []const u8) ![]u8 {
        return std.mem.concat(d.arena, u8, parts);
    }

    /// Constructed value of `tag` whose content is `parts` concatenated.
    pub fn constructed(d: Writer, tag: u8, parts: []const []const u8) ![]u8 {
        return d.tlv(tag, try d.concat(parts));
    }

    pub fn seq(d: Writer, parts: []const []const u8) ![]u8 {
        return d.constructed(Tag.sequence, parts);
    }

    pub fn set(d: Writer, parts: []const []const u8) ![]u8 {
        return d.constructed(Tag.set, parts);
    }

    /// INTEGER from unsigned big-endian magnitude bytes (minimal encoding:
    /// leading zeros stripped, a 0x00 added when the top bit is set).
    pub fn uintBytes(d: Writer, magnitude: []const u8) ![]u8 {
        var m = magnitude;
        while (m.len > 1 and m[0] == 0) m = m[1..];
        if (m.len == 0) return d.tlv(Tag.integer, &.{0});
        if (m[0] & 0x80 != 0) return d.constructedRaw(Tag.integer, &.{ &.{0}, m });
        return d.tlv(Tag.integer, m);
    }

    fn constructedRaw(d: Writer, tag: u8, parts: []const []const u8) ![]u8 {
        return d.tlv(tag, try d.concat(parts));
    }

    pub fn uint(d: Writer, v: u64) ![]u8 {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .big);
        return d.uintBytes(&b);
    }

    pub fn boolean(d: Writer, v: bool) ![]u8 {
        return d.tlv(Tag.boolean, &.{if (v) 0xff else 0x00});
    }

    /// `encoded` is the OID content octets (see `oids`).
    pub fn oid(d: Writer, encoded: []const u8) ![]u8 {
        return d.tlv(Tag.oid, encoded);
    }

    pub fn octets(d: Writer, content: []const u8) ![]u8 {
        return d.tlv(Tag.octet_string, content);
    }

    /// BIT STRING holding whole bytes (0 unused bits).
    pub fn bitString(d: Writer, content: []const u8) ![]u8 {
        return d.constructedRaw(Tag.bit_string, &.{ &.{0}, content });
    }

    /// BIT STRING for a NamedBitList (keyUsage): bit 0 is the MSB of the
    /// first byte. DER drops trailing zero bits, so unused-bits is computed.
    pub fn namedBits(d: Writer, bits: u16) ![]u8 {
        if (bits == 0) return d.tlv(Tag.bit_string, &.{0});
        // bits: bit i of the NamedBitList is (bits >> (15 - i)) & 1.
        var last: u4 = 0;
        var i: u5 = 0;
        while (i < 16) : (i += 1) {
            if ((bits >> @intCast(15 - i)) & 1 != 0) last = @intCast(i);
        }
        const nbytes: usize = @as(usize, last) / 8 + 1;
        const unused: u8 = @intCast(7 - (@as(usize, last) % 8));
        const b = [2]u8{ @intCast(bits >> 8), @intCast(bits & 0xff) };
        return d.constructedRaw(Tag.bit_string, &.{ &.{unused}, b[0..nbytes] });
    }

    pub fn utf8(d: Writer, s: []const u8) ![]u8 {
        return d.tlv(Tag.utf8_string, s);
    }

    pub fn printable(d: Writer, s: []const u8) ![]u8 {
        return d.tlv(Tag.printable_string, s);
    }

    /// X.509 Time: UTCTime for 1950..2049, GeneralizedTime otherwise
    /// (RFC 5280 4.1.2.5).
    pub fn time(d: Writer, unix_s: i64) ![]u8 {
        if (unix_s < 0) return error.DerBadTime;
        const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(unix_s) };
        const yd = es.getEpochDay().calculateYearDay();
        const md = yd.calculateMonthDay();
        const ds = es.getDaySeconds();
        var buf: [15]u8 = undefined;
        const year: u32 = yd.year;
        if (year >= 10000) return error.DerBadTime;
        if (year < 2050) {
            const s = std.fmt.bufPrint(&buf, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
                year % 100, md.month.numeric(), @as(u32, md.day_index) + 1,
                ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
            }) catch unreachable;
            return d.tlv(Tag.utc_time, s);
        }
        const s = std.fmt.bufPrint(&buf, "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
            year, md.month.numeric(), @as(u32, md.day_index) + 1,
            ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
        }) catch unreachable;
        return d.tlv(Tag.generalized_time, s);
    }
};

/// Pre-encoded OID content octets.
pub const oids = struct {
    pub const common_name = [_]u8{ 0x55, 0x04, 0x03 };
    pub const organization = [_]u8{ 0x55, 0x04, 0x0a };
    pub const ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
    pub const prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    pub const ecdsa_with_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
    pub const subject_key_identifier = [_]u8{ 0x55, 0x1d, 0x0e };
    pub const key_usage = [_]u8{ 0x55, 0x1d, 0x0f };
    pub const subject_alt_name = [_]u8{ 0x55, 0x1d, 0x11 };
    pub const basic_constraints = [_]u8{ 0x55, 0x1d, 0x13 };
    pub const name_constraints = [_]u8{ 0x55, 0x1d, 0x1e };
    pub const authority_key_identifier = [_]u8{ 0x55, 0x1d, 0x23 };
    pub const ext_key_usage = [_]u8{ 0x55, 0x1d, 0x25 };
    pub const kp_server_auth = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
};

// ------------------------------------------------------------------ reader

pub const Element = struct {
    tag: u8,
    /// Content octets.
    content: []const u8,
    /// The whole TLV.
    raw: []const u8,
};

pub const ReadError = error{DerMalformed};

/// Bounds-checked cursor over a DER buffer. Never panics on any input.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    pub fn atEnd(r: Reader) bool {
        return r.pos >= r.buf.len;
    }

    pub fn peekTag(r: Reader) ?u8 {
        if (r.pos >= r.buf.len) return null;
        return r.buf[r.pos];
    }

    pub fn next(r: *Reader) ReadError!Element {
        const start = r.pos;
        if (r.buf.len - r.pos < 2) return error.DerMalformed;
        const tag = r.buf[r.pos];
        if (tag & 0x1f == 0x1f) return error.DerMalformed; // high tag numbers unused here
        const l0 = r.buf[r.pos + 1];
        var p = r.pos + 2;
        var len: usize = 0;
        if (l0 < 0x80) {
            len = l0;
        } else {
            const n = l0 & 0x7f;
            if (n == 0 or n > 3) return error.DerMalformed; // no indefinite / huge lengths
            if (r.buf.len - p < n) return error.DerMalformed;
            // Minimal (X.690 10.1): long form only from 0x80, and no
            // leading zero length octets.
            if (r.buf[p] == 0) return error.DerMalformed;
            for (r.buf[p..][0..n]) |b| len = (len << 8) | b;
            p += n;
            if (len < 0x80) return error.DerMalformed;
        }
        if (r.buf.len - p < len) return error.DerMalformed;
        r.pos = p + len;
        return .{ .tag = tag, .content = r.buf[p .. p + len], .raw = r.buf[start .. p + len] };
    }

    pub fn expect(r: *Reader, tag: u8) ReadError!Element {
        const e = try r.next();
        if (e.tag != tag) return error.DerMalformed;
        return e;
    }
};

/// Parses an X.509 Time element to Unix seconds.
pub fn parseTime(e: Element) ReadError!i64 {
    const s = e.content;
    var year: i64 = 0;
    var rest: []const u8 = undefined;
    if (e.tag == Tag.utc_time) {
        if (s.len != 13 or s[12] != 'Z') return error.DerMalformed;
        const yy = try digits(s[0..2]);
        year = if (yy >= 50) 1900 + yy else 2000 + yy;
        rest = s[2..12];
    } else if (e.tag == Tag.generalized_time) {
        if (s.len != 15 or s[14] != 'Z') return error.DerMalformed;
        year = try digits(s[0..4]);
        rest = s[4..14];
    } else return error.DerMalformed;
    const month = try digits(rest[0..2]);
    const day = try digits(rest[2..4]);
    const hh = try digits(rest[4..6]);
    const mm = try digits(rest[6..8]);
    const ss = try digits(rest[8..10]);
    if (month < 1 or month > 12 or day < 1 or day > 31 or hh > 23 or mm > 59 or ss > 59) return error.DerMalformed;
    if (year < 1970) return error.DerMalformed;
    return daysFromCivil(year, month, day) * 86400 + hh * 3600 + mm * 60 + ss;
}

fn digits(s: []const u8) ReadError!i64 {
    var v: i64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return error.DerMalformed;
        v = v * 10 + (c - '0');
    }
    return v;
}

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant).
fn daysFromCivil(y0: i64, m: i64, d: i64) i64 {
    const y = if (m <= 2) y0 - 1 else y0;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp = if (m > 2) m - 3 else m + 9;
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

// -------------------------------------------------------------------- tests

const testing = std.testing;

test "der lengths and integers" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const d: Writer = .{ .arena = arena.allocator() };
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x01, 0x00 }, try d.uint(0));
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x01, 0x7f }, try d.uint(127));
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x02, 0x00, 0x80 }, try d.uint(128));
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x02, 0x01, 0x00 }, try d.uint(256));
    const big = try d.octets(&@as([200]u8, @splat(0xaa)));
    try testing.expectEqualSlices(u8, &.{ 0x04, 0x81, 200 }, big[0..3]);
    const bigger = try d.octets(&@as([300]u8, @splat(0xaa)));
    try testing.expectEqualSlices(u8, &.{ 0x04, 0x82, 0x01, 0x2c }, bigger[0..4]);
    // keyUsage: digitalSignature only -> 03 02 07 80; keyCertSign|cRLSign -> 03 02 01 06
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x02, 0x07, 0x80 }, try d.namedBits(0x8000));
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x02, 0x01, 0x06 }, try d.namedBits(0x0600));

    var r: Reader = .init(bigger);
    const e = try r.next();
    try testing.expectEqual(@as(usize, 300), e.content.len);
    try testing.expect(r.atEnd());
}

test "der time round trip" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const d: Writer = .{ .arena = arena.allocator() };
    const t1: i64 = 1_778_000_000; // 2026
    const e1 = try d.time(t1);
    try testing.expectEqual(Tag.utc_time, e1[0]);
    var r1: Reader = .init(e1);
    try testing.expectEqual(t1, try parseTime(try r1.next()));
    const t2: i64 = 2_600_000_000; // 2052: GeneralizedTime
    const e2 = try d.time(t2);
    try testing.expectEqual(Tag.generalized_time, e2[0]);
    var r2: Reader = .init(e2);
    try testing.expectEqual(t2, try parseTime(try r2.next()));
}

test "der reader rejects non-minimal and indefinite lengths" {
    const zeros: [0x80]u8 = @splat(0);
    var ok: Reader = .init(&([_]u8{ 0x04, 0x81, 0x80 } ++ zeros));
    _ = try ok.next();
    const bad = [_][]const u8{
        &.{ 0x04, 0x81, 0x05, 1, 2, 3, 4, 5 }, // short length in long form
        &([_]u8{ 0x04, 0x82, 0x00, 0x80 } ++ zeros), // leading zero length octet
        &.{ 0x30, 0x80, 0x00, 0x00 }, // indefinite
        &.{ 0x04, 0x84, 0, 0, 0, 1, 0 }, // four length octets
        &.{ 0x1f, 0x01, 0x00 }, // high tag number
    };
    for (bad) |b| {
        var r: Reader = .init(b);
        try testing.expectError(error.DerMalformed, r.next());
    }
}

test "der reader never panics on garbage" {
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const rand = prng.random();
    var buf: [64]u8 = undefined;
    for (0..20000) |_| {
        const n = rand.uintLessThan(usize, buf.len + 1);
        rand.bytes(buf[0..n]);
        var r: Reader = .init(buf[0..n]);
        while (!r.atEnd()) {
            const e = r.next() catch break;
            var inner: Reader = .init(e.content);
            while (!inner.atEnd()) _ = inner.next() catch break;
            _ = parseTime(e) catch {};
        }
    }
}
