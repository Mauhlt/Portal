//! TLS 1.3 pieces shared by Portal's TLS server (src/tls/server.zig) and
//! the native client's handshake inspector (client/src/net/tlsconn.zig,
//! which decrypts the server's encrypted handshake flight to check the
//! certificate before std's TLS client does): the two cipher suites
//! Portal speaks, HKDF-Expand-Label, one direction's record protection
//! (RFC 8446 5.2, 5.3, 7.3) and a bounds-checked big-endian cursor.

const std = @import("std");
const tls = std.crypto.tls;
const crypto = std.crypto;

const Hkdf = crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const ContentType = tls.ContentType;

pub const record_header_len = tls.record_header_len;
/// Largest TLSPlaintext / TLSInnerPlaintext content.
pub const max_plaintext = tls.max_ciphertext_inner_record_len; // 2^14
/// Content + inner content type.
pub const max_inner = max_plaintext + 1;
pub const tag_len = 16;

/// TLS_AES_128_GCM_SHA256 and TLS_CHACHA20_POLY1305_SHA256, the suites
/// Portal's server offers.
pub const Suite = enum {
    aes_128_gcm_sha256,
    chacha20_poly1305_sha256,

    pub fn code(s: Suite) u16 {
        return switch (s) {
            .aes_128_gcm_sha256 => 0x1301,
            .chacha20_poly1305_sha256 => 0x1303,
        };
    }

    /// The suite for a CipherSuite value, if it is one of these.
    pub fn fromCode(code_: u16) ?Suite {
        return switch (code_) {
            0x1301 => .aes_128_gcm_sha256,
            0x1303 => .chacha20_poly1305_sha256,
            else => null,
        };
    }
};

pub fn expandLabel(secret: [32]u8, label: []const u8, context: []const u8, comptime len: usize) [len]u8 {
    return tls.hkdfExpandLabel(Hkdf, secret, label, context, len);
}

/// One direction's traffic protection.
pub const Traffic = struct {
    suite: Suite,
    secret: [32]u8,
    key: [32]u8,
    iv: [12]u8,
    seq: u64 = 0,

    pub fn init(suite: Suite, secret: [32]u8) Traffic {
        var t: Traffic = .{ .suite = suite, .secret = secret, .key = @splat(0), .iv = expandLabel(secret, "iv", "", 12) };
        switch (suite) {
            .aes_128_gcm_sha256 => t.key[0..16].* = expandLabel(secret, "key", "", 16),
            .chacha20_poly1305_sha256 => t.key = expandLabel(secret, "key", "", 32),
        }
        return t;
    }

    /// KeyUpdate: next generation of this direction's secret.
    pub fn update(t: *Traffic) void {
        var next = expandLabel(t.secret, "traffic upd", "", 32);
        defer crypto.secureZero(u8, &next);
        const suite = t.suite;
        t.wipe();
        t.* = init(suite, next);
    }

    pub fn wipe(t: *Traffic) void {
        crypto.secureZero(u8, &t.secret);
        crypto.secureZero(u8, &t.key);
        crypto.secureZero(u8, &t.iv);
    }

    fn nonce(t: *const Traffic) [12]u8 {
        var n = t.iv;
        var s: [8]u8 = undefined;
        std.mem.writeInt(u64, &s, t.seq, .big);
        for (n[4..], s) |*a, b| a.* ^= b;
        return n;
    }

    /// Encrypts `inner` (content followed by its content type) as one
    /// TLSCiphertext record into `out`. Returns the record length.
    pub fn seal(t: *Traffic, out: []u8, inner: []const u8) error{ TlsInternalError, BufferTooSmall }!usize {
        if (inner.len == 0 or inner.len > max_inner) return error.TlsInternalError;
        const total = record_header_len + inner.len + tag_len;
        if (out.len < total) return error.BufferTooSmall;
        if (t.seq == std.math.maxInt(u64)) return error.TlsInternalError;
        out[0] = @backingInt(ContentType.application_data);
        out[1] = 0x03;
        out[2] = 0x03;
        std.mem.writeInt(u16, out[3..5], @intCast(inner.len + tag_len), .big);
        const n = t.nonce();
        const c = out[record_header_len..][0..inner.len];
        const tag = out[record_header_len + inner.len ..][0..tag_len];
        switch (t.suite) {
            .aes_128_gcm_sha256 => Aes128Gcm.encrypt(c, tag, inner, out[0..record_header_len], n, t.key[0..16].*),
            .chacha20_poly1305_sha256 => ChaCha20Poly1305.encrypt(c, tag, inner, out[0..record_header_len], n, t.key),
        }
        t.seq += 1;
        return total;
    }

    pub const Opened = struct { content_type: u8, len: usize };

    /// Decrypts a TLSCiphertext body (ciphertext followed by the tag) into
    /// `out`, removes padding and returns the inner content type and
    /// content length. Does not send alerts: the server's
    /// `Connection.readRecord` maps the errors to them.
    pub fn open(t: *Traffic, header: *const [record_header_len]u8, body: []const u8, out: []u8) error{ BadRecordMac, RecordOverflow, NoContentType, SequenceOverflow }!Opened {
        if (body.len < tag_len + 1) return error.BadRecordMac;
        const clen = body.len - tag_len;
        if (clen > max_inner) return error.RecordOverflow;
        if (out.len < clen) return error.RecordOverflow;
        if (t.seq == std.math.maxInt(u64)) return error.SequenceOverflow;
        const n = t.nonce();
        const m = out[0..clen];
        const tag = body[clen..][0..tag_len].*;
        switch (t.suite) {
            .aes_128_gcm_sha256 => Aes128Gcm.decrypt(m, body[0..clen], tag, header, n, t.key[0..16].*) catch return error.BadRecordMac,
            .chacha20_poly1305_sha256 => ChaCha20Poly1305.decrypt(m, body[0..clen], tag, header, n, t.key) catch return error.BadRecordMac,
        }
        t.seq += 1;
        var i = clen;
        while (i > 0) {
            i -= 1;
            if (m[i] != 0) return .{ .content_type = m[i], .len = i };
        }
        return error.NoContentType;
    }
};

/// Bounds-checked big-endian cursor.
pub const Cursor = struct {
    b: []const u8,
    i: usize = 0,

    pub fn done(c: *const Cursor) bool {
        return c.i >= c.b.len;
    }
    /// Bytes not read yet.
    pub fn left(c: *const Cursor) usize {
        return c.b.len - c.i;
    }
    pub fn bytes(c: *Cursor, n: usize) error{TlsDecodeError}![]const u8 {
        if (c.b.len - c.i < n) return error.TlsDecodeError;
        defer c.i += n;
        return c.b[c.i..][0..n];
    }
    pub fn int(c: *Cursor, comptime T: type) error{TlsDecodeError}!T {
        const n = @divExact(@bitSizeOf(T), 8);
        const s = try c.bytes(n);
        return std.mem.readInt(T, s[0..n], .big);
    }
    /// A vector with a `L`-sized length prefix.
    pub fn vec(c: *Cursor, comptime L: type) error{TlsDecodeError}![]const u8 {
        const n = try c.int(L);
        return c.bytes(n);
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "seal and open round-trip, tampering, padding" {
    for ([_]Suite{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256 }) |suite| {
        const secret: [32]u8 = @splat(0x5a);
        var tx = Traffic.init(suite, secret);
        var rx = Traffic.init(suite, secret);
        var rec: [64]u8 = undefined;
        const n = try tx.seal(&rec, "hi" ++ [_]u8{23});
        var out: [32]u8 = undefined;
        const o = try rx.open(rec[0..record_header_len], rec[record_header_len..n], &out);
        try testing.expectEqual(@as(u8, 23), o.content_type);
        try testing.expectEqualStrings("hi", out[0..o.len]);
        // The sequence number moved on: replaying the record fails.
        try testing.expectError(error.BadRecordMac, rx.open(rec[0..record_header_len], rec[record_header_len..n], &out));
        // Padding (zeros after the content type) is removed.
        var tx2 = Traffic.init(suite, secret);
        var rx2 = Traffic.init(suite, secret);
        const m = try tx2.seal(&rec, "x" ++ [_]u8{ 22, 0, 0, 0 });
        const o2 = try rx2.open(rec[0..record_header_len], rec[record_header_len..m], &out);
        try testing.expectEqual(@as(u8, 22), o2.content_type);
        try testing.expectEqual(@as(usize, 1), o2.len);
        // All padding, no content type.
        var tx3 = Traffic.init(suite, secret);
        var rx3 = Traffic.init(suite, secret);
        const k = try tx3.seal(&rec, &.{ 0, 0 });
        try testing.expectError(error.NoContentType, rx3.open(rec[0..record_header_len], rec[record_header_len..k], &out));
        try testing.expectError(error.BadRecordMac, rx3.open(rec[0..record_header_len], rec[record_header_len..][0..3], &out));
        try testing.expectEqual(suite, Suite.fromCode(suite.code()).?);
    }
    try testing.expectEqual(@as(?Suite, null), Suite.fromCode(0x1302));
}

test "cursor" {
    var c: Cursor = .{ .b = &.{ 0, 3, 'a', 'b', 'c', 1 } };
    try testing.expectEqualStrings("abc", try c.vec(u16));
    try testing.expectEqual(@as(u8, 1), try c.int(u8));
    try testing.expect(c.done());
    try testing.expectError(error.TlsDecodeError, c.int(u8));
    var d: Cursor = .{ .b = &.{ 0, 9, 'a' } };
    try testing.expectError(error.TlsDecodeError, d.vec(u16));
}
