//! Certificate checks for the TLS layer, run before std.crypto.Certificate
//! ever sees the bytes.
//!
//! std's certificate parser (std/crypto/Certificate.zig, `der.Element.parse`)
//! indexes its input without bounds checks and adds untrusted u32 lengths
//! without overflow checks: a truncated element, a length that runs past
//! the buffer, or a missing sibling element makes it read out of bounds
//! (a panic in safe builds, undefined behaviour in ReleaseFast). The server
//! certificate arrives before the server is authenticated, so anyone who can
//! answer the TCP connection could crash the client. `validateCertificate`
//! therefore checks, with bounds-checked code, that every element std's
//! parser and `verifyHostName` will visit exists and lies inside its parent,
//! and only Portal's profile (ECDSA P-256, SHA-256) is accepted.
//!
//! Also: PEM/DER loading of the CA file and SHA-256 fingerprints.

const std = @import("std");
const Certificate = std.crypto.Certificate;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Portal's certificates are well under 2 KiB.
pub const max_cert_len = 8 * 1024;
const max_depth = 20;

pub const Error = error{ BadCertificate, UnsupportedCertificate };

const Tlv = struct {
    tag: u8,
    /// Content bounds.
    start: usize,
    end: usize,

    fn constructed(t: Tlv) bool {
        return t.tag & 0x20 != 0;
    }
};

const tag_integer = 0x02;
const tag_bit_string = 0x03;
const tag_octet_string = 0x04;
const tag_oid = 0x06;
const tag_boolean = 0x01;
const tag_utc_time = 0x17;
const tag_generalized_time = 0x18;
const tag_sequence = 0x30;
const tag_set = 0x31;

/// One DER header at `pos`, content inside `[pos, limit)`.
fn header(buf: []const u8, pos: usize, limit: usize) Error!Tlv {
    if (limit > buf.len or pos > limit or limit - pos < 2) return error.BadCertificate;
    const tag = buf[pos];
    if (tag & 0x1f == 0x1f) return error.BadCertificate; // multi-byte tags: std reads one byte
    const l0 = buf[pos + 1];
    var i = pos + 2;
    var len: usize = 0;
    if (l0 < 0x80) {
        len = l0;
    } else {
        const n: usize = l0 & 0x7f;
        if (n == 0 or n > 2) return error.BadCertificate; // indefinite, or >= 64 KiB
        if (limit - i < n) return error.BadCertificate;
        for (buf[i .. i + n]) |b| len = (len << 8) | b;
        i += n;
    }
    if (len > limit - i) return error.BadCertificate;
    return .{ .tag = tag, .start = i, .end = i + len };
}

/// Children of a constructed element, each checked recursively.
const Children = struct {
    buf: []const u8,
    pos: usize,
    end: usize,
    depth: u8,

    fn of(buf: []const u8, t: Tlv, depth: u8) Error!Children {
        if (!t.constructed()) return error.BadCertificate;
        if (depth >= max_depth) return error.BadCertificate;
        return .{ .buf = buf, .pos = t.start, .end = t.end, .depth = depth + 1 };
    }

    fn next(c: *Children) Error!?Tlv {
        if (c.pos == c.end) return null;
        const t = try header(c.buf, c.pos, c.end);
        c.pos = t.end;
        try generic(c.buf, t, c.depth);
        return t;
    }

    fn need(c: *Children) Error!Tlv {
        return (try c.next()) orelse error.BadCertificate;
    }

    fn needTag(c: *Children, tag: u8) Error!Tlv {
        const t = try c.need();
        if (t.tag != tag) return error.BadCertificate;
        return t;
    }

    fn done(c: *Children) Error!void {
        if (c.pos != c.end) return error.BadCertificate;
    }
};

/// Structure every element must have, whatever it is: constructed elements
/// nest properly; BIT STRINGs have their unused-bits byte (std reads it).
fn generic(buf: []const u8, t: Tlv, depth: u8) Error!void {
    if (t.tag == tag_bit_string and t.end == t.start) return error.BadCertificate;
    if (!t.constructed()) return;
    var c = try Children.of(buf, t, depth);
    while (try c.next()) |_| {}
}

/// A SEQUENCE starting with an OID (AlgorithmIdentifier), returning the OID.
fn algorithm(buf: []const u8, t: Tlv, depth: u8, min_children: usize) Error![]const u8 {
    if (t.tag != tag_sequence) return error.BadCertificate;
    var c = try Children.of(buf, t, depth);
    const oid = try c.needTag(tag_oid);
    var n: usize = 1;
    while (try c.next()) |_| n += 1;
    if (n < min_children) return error.BadCertificate;
    return buf[oid.start..oid.end];
}

/// Name ::= SEQUENCE OF SET OF SEQUENCE { OID, value }.
fn name(buf: []const u8, t: Tlv, depth: u8) Error!void {
    if (t.tag != tag_sequence) return error.BadCertificate;
    var rdns = try Children.of(buf, t, depth);
    while (try rdns.next()) |rdn| {
        if (rdn.tag != tag_set) return error.BadCertificate;
        var atavs = try Children.of(buf, rdn, rdns.depth);
        while (try atavs.next()) |atav| {
            if (atav.tag != tag_sequence) return error.BadCertificate;
            var parts = try Children.of(buf, atav, atavs.depth);
            _ = try parts.needTag(tag_oid);
            _ = try parts.need();
            try parts.done();
        }
    }
}

const oid_ecdsa_with_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_subject_alt_name = [_]u8{ 0x55, 0x1d, 0x11 };

/// Checks that `der` is one X.509 certificate in Portal's profile whose
/// structure std's parser can walk without leaving the buffer.
pub fn validateCertificate(der: []const u8) Error!void {
    if (der.len < 2 or der.len > max_cert_len) return error.BadCertificate;
    const cert = try header(der, 0, der.len);
    if (cert.tag != tag_sequence or cert.end != der.len) return error.BadCertificate;
    var top = try Children.of(der, cert, 0);
    const tbs = try top.needTag(tag_sequence);
    const sig_alg = try top.need();
    if (!std.mem.eql(u8, try algorithm(der, sig_alg, top.depth, 1), &oid_ecdsa_with_sha256)) return error.UnsupportedCertificate;
    _ = try top.needTag(tag_bit_string);
    try top.done();

    var f = try Children.of(der, tbs, top.depth);
    var first = try f.need();
    if (first.tag == 0xa0) {
        if (first.end - first.start != 3) return error.BadCertificate;
        first = try f.need(); // serial
    }
    if (first.tag != tag_integer) return error.BadCertificate;
    if (!std.mem.eql(u8, try algorithm(der, try f.need(), f.depth, 1), &oid_ecdsa_with_sha256)) return error.UnsupportedCertificate;
    try name(der, try f.need(), f.depth); // issuer
    {
        const validity = try f.needTag(tag_sequence);
        var v = try Children.of(der, validity, f.depth);
        for (0..2) |_| {
            const t = try v.need();
            if (t.tag != tag_utc_time and t.tag != tag_generalized_time) return error.BadCertificate;
        }
        try v.done();
    }
    try name(der, try f.need(), f.depth); // subject
    {
        const spki = try f.needTag(tag_sequence);
        var s = try Children.of(der, spki, f.depth);
        const alg = try s.needTag(tag_sequence);
        var a = try Children.of(der, alg, s.depth);
        const alg_oid = try a.needTag(tag_oid);
        if (!std.mem.eql(u8, der[alg_oid.start..alg_oid.end], &oid_ec_public_key)) return error.UnsupportedCertificate;
        const curve = try a.needTag(tag_oid);
        if (!std.mem.eql(u8, der[curve.start..curve.end], &oid_prime256v1)) return error.UnsupportedCertificate;
        try a.done();
        _ = try s.needTag(tag_bit_string);
        try s.done();
    }
    // Optional issuerUniqueID [1], subjectUniqueID [2], extensions [3].
    while (try f.next()) |t| {
        if (t.tag != 0xa3) continue;
        var outer = try Children.of(der, t, f.depth);
        const exts = try outer.needTag(tag_sequence);
        try outer.done();
        var e = try Children.of(der, exts, outer.depth);
        while (try e.next()) |ext| {
            if (ext.tag != tag_sequence) return error.BadCertificate;
            var x = try Children.of(der, ext, e.depth);
            const oid = try x.needTag(tag_oid);
            var value = try x.need();
            if (value.tag == tag_boolean) value = try x.need();
            if (value.tag != tag_octet_string) return error.BadCertificate;
            try x.done();
            // Every extension value is DER (RFC 5280 4.1); std parses the
            // subjectAltName value in verifyHostName.
            const inner = try header(der, value.start, value.end);
            if (inner.end != value.end) return error.BadCertificate;
            try generic(der, inner, x.depth);
            if (std.mem.eql(u8, der[oid.start..oid.end], &oid_subject_alt_name) and inner.tag != tag_sequence)
                return error.BadCertificate;
        }
    }
}

/// Parses a certificate after `validateCertificate`.
pub fn parse(der: []const u8) Error!Certificate.Parsed {
    try validateCertificate(der);
    const p = Certificate.parse(.{ .buffer = der, .index = 0 }) catch return error.BadCertificate;
    switch (p.pub_key_algo) {
        .X9_62_id_ecPublicKey => |curve| if (curve != .X9_62_prime256v1) return error.UnsupportedCertificate,
        else => return error.UnsupportedCertificate,
    }
    if (p.signature_algorithm != .ecdsa_with_SHA256) return error.UnsupportedCertificate;
    return p;
}

pub const PinError = error{ NotIssuedByPinnedCa, CaExpired, CertificateExpired, CertificateNotYetValid, HostMismatch } || Error;

/// The server certificate must be signed by exactly the pinned CA, be
/// within its validity period, and name `ip` (the bare server IP) in its
/// subjectAltName.
pub fn verifyLeaf(leaf_der: []const u8, ca_der: []const u8, ip: []const u8, now_sec: i64) PinError!void {
    const ca = try parse(ca_der);
    const leaf = try parse(leaf_der);
    if (now_sec > ca.validity.not_after or now_sec < ca.validity.not_before) return error.CaExpired;
    leaf.verify(ca, now_sec) catch |err| return switch (err) {
        error.CertificateExpired => error.CertificateExpired,
        error.CertificateNotYetValid => error.CertificateNotYetValid,
        else => error.NotIssuedByPinnedCa,
    };
    leaf.verifyHostName(ip) catch return error.HostMismatch;
}

// ------------------------------------------------------------------ files

pub const LoadError = error{ NotACertificate, MoreThanOneCertificate } || Error;

/// A CA certificate from a .pem (exactly one CERTIFICATE block) or a .cer
/// (DER) file, decoded into `out`. Validated and parsed.
pub fn loadCertificate(data: []const u8, out: *[max_cert_len]u8) LoadError![]const u8 {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const der: []const u8 = if (std.mem.indexOf(u8, data, begin)) |b| der: {
        const body_start = b + begin.len;
        const e = std.mem.indexOfPos(u8, data, body_start, end_marker) orelse return error.NotACertificate;
        if (std.mem.indexOfPos(u8, data, e, begin) != null) return error.MoreThanOneCertificate;
        // Base64 with line breaks: strip whitespace first.
        var b64: [max_cert_len * 2]u8 = undefined;
        var n: usize = 0;
        for (data[body_start..e]) |ch| {
            if (ch == '\r' or ch == '\n' or ch == ' ' or ch == '\t') continue;
            if (n == b64.len) return error.NotACertificate;
            b64[n] = ch;
            n += 1;
        }
        const dec = std.base64.standard.Decoder;
        const len = dec.calcSizeForSlice(b64[0..n]) catch return error.NotACertificate;
        if (len > out.len) return error.NotACertificate;
        dec.decode(out[0..len], b64[0..n]) catch return error.NotACertificate;
        break :der out[0..len];
    } else der: {
        if (data.len > out.len) return error.NotACertificate;
        @memcpy(out[0..data.len], data);
        break :der out[0..data.len];
    };
    _ = parse(der) catch |err| return switch (err) {
        error.BadCertificate => error.NotACertificate,
        else => |e| e,
    };
    return der;
}

/// PEM encoding of one certificate (64-column lines).
pub fn writePem(w: *std.Io.Writer, der: []const u8) std.Io.Writer.Error!void {
    try w.writeAll("-----BEGIN CERTIFICATE-----\n");
    var i: usize = 0;
    while (i < der.len) {
        const chunk = der[i..@min(der.len, i + 48)];
        var line: [64]u8 = undefined;
        try w.writeAll(std.base64.standard.Encoder.encode(&line, chunk));
        try w.writeAll("\n");
        i += chunk.len;
    }
    try w.writeAll("-----END CERTIFICATE-----\n");
}

pub fn fingerprint(der: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(der, &out, .{});
    return out;
}

/// "AB:CD:..." (the form `portal ca export` prints).
pub fn formatFingerprint(fp: [32]u8, out: *[95]u8) []const u8 {
    const hex = "0123456789ABCDEF";
    for (fp, 0..) |b, i| {
        out[i * 3] = hex[b >> 4];
        out[i * 3 + 1] = hex[b & 15];
        if (i < 31) out[i * 3 + 2] = ':';
    }
    return out[0..95];
}

/// Accepts 64 hex digits, optionally separated by ':' or spaces, any case.
pub fn parseFingerprint(text: []const u8) error{BadFingerprint}![32]u8 {
    var out: [32]u8 = undefined;
    var n: usize = 0;
    var hi: ?u4 = null;
    for (text) |ch| {
        if (ch == ':' or ch == ' ' or ch == '-') continue;
        const v: u4 = @intCast(std.fmt.charToDigit(ch, 16) catch return error.BadFingerprint);
        if (hi) |h| {
            if (n == 32) return error.BadFingerprint;
            out[n] = (@as(u8, h) << 4) | v;
            n += 1;
            hi = null;
        } else hi = v;
    }
    if (n != 32 or hi != null) return error.BadFingerprint;
    return out;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;
pub const testdata = @import("testdata.zig");

test "Portal CA and leaf: validate, parse, verify" {
    try validateCertificate(testdata.ca_der);
    try validateCertificate(testdata.leaf_der);
    try validateCertificate(testdata.other_ca_der);
    const now = testdata.now_sec;
    try verifyLeaf(testdata.leaf_der, testdata.ca_der, testdata.leaf_ip, now);
    try testing.expectError(error.HostMismatch, verifyLeaf(testdata.leaf_der, testdata.ca_der, "10.8.0.99", now));
    try testing.expectError(error.NotIssuedByPinnedCa, verifyLeaf(testdata.leaf_der, testdata.other_ca_der, testdata.leaf_ip, now));
    try testing.expectError(error.CertificateExpired, verifyLeaf(testdata.leaf_der, testdata.ca_der, testdata.leaf_ip, now + 3 * 365 * 86400));
    // A leaf is not a CA for itself.
    try testing.expectError(error.NotIssuedByPinnedCa, verifyLeaf(testdata.leaf_der, testdata.leaf_der, testdata.leaf_ip, now));
}

test "every truncation and every single-byte change is rejected or parsed safely" {
    var buf: [max_cert_len]u8 = undefined;
    for ([_][]const u8{ testdata.leaf_der, testdata.ca_der }) |orig| {
        for (0..orig.len) |n| {
            try testing.expect(std.meta.isError(validateCertificate(orig[0..n])));
        }
        for (0..orig.len) |i| {
            @memcpy(buf[0..orig.len], orig);
            for ([_]u8{ 0x00, 0x01, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0xff, buf[i] ^ 0x20 }) |v| {
                buf[i] = v;
                const c = buf[0..orig.len];
                if (parse(c)) |p| {
                    // Whatever std then does with it must stay in bounds.
                    _ = p.verifyHostName(testdata.leaf_ip) catch {};
                    _ = verifyLeaf(c, testdata.ca_der, testdata.leaf_ip, testdata.now_sec) catch {};
                    _ = verifyLeaf(testdata.leaf_der, c, testdata.leaf_ip, testdata.now_sec) catch {};
                } else |_| {}
            }
        }
    }
}

test "fuzz: random DER never panics" {
    var prng = std.Random.DefaultPrng.init(11);
    const rand = prng.random();
    var buf: [600]u8 = undefined;
    for (0..20000) |_| {
        const n = rand.uintLessThan(usize, buf.len);
        rand.bytes(buf[0..n]);
        // Bias towards plausible headers.
        if (n > 4) {
            buf[0] = 0x30;
            buf[1] = 0x82;
            std.mem.writeInt(u16, buf[2..4], @intCast(n - 4), .big);
        }
        if (parse(buf[0..n])) |p| {
            _ = p.verifyHostName("10.8.0.1") catch {};
        } else |_| {}
    }
}

test "PEM and DER loading, fingerprints" {
    var out: [max_cert_len]u8 = undefined;
    const der = try loadCertificate(testdata.ca_der, &out);
    try testing.expectEqualSlices(u8, testdata.ca_der, der);
    var pem_buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&pem_buf);
    try writePem(&w, testdata.ca_der);
    var out2: [max_cert_len]u8 = undefined;
    try testing.expectEqualSlices(u8, testdata.ca_der, try loadCertificate(w.buffered(), &out2));
    // CRLF line endings, as Windows editors write them.
    var crlf: [5000]u8 = undefined;
    var cn: usize = 0;
    for (w.buffered()) |ch| {
        if (ch == '\n') {
            crlf[cn] = '\r';
            cn += 1;
        }
        crlf[cn] = ch;
        cn += 1;
    }
    try testing.expectEqualSlices(u8, testdata.ca_der, try loadCertificate(crlf[0..cn], &out2));
    var two: [9000]u8 = undefined;
    @memcpy(two[0..w.buffered().len], w.buffered());
    @memcpy(two[w.buffered().len..][0..w.buffered().len], w.buffered());
    try testing.expectError(error.MoreThanOneCertificate, loadCertificate(two[0 .. 2 * w.buffered().len], &out2));
    try testing.expectError(error.NotACertificate, loadCertificate("hello", &out2));
    try testing.expectError(error.NotACertificate, loadCertificate("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n", &out2));

    const fp = fingerprint(testdata.ca_der);
    var fbuf: [95]u8 = undefined;
    const text = formatFingerprint(fp, &fbuf);
    try testing.expectEqualStrings(testdata.ca_fingerprint, text);
    try testing.expectEqual(fp, try parseFingerprint(text));
    var lower: [95]u8 = undefined;
    _ = std.ascii.lowerString(&lower, text);
    try testing.expectEqual(fp, try parseFingerprint(&lower));
    var bare: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&bare, "{x}", .{fp}) catch unreachable;
    try testing.expectEqual(fp, try parseFingerprint(&bare));
    try testing.expectError(error.BadFingerprint, parseFingerprint(bare[0..63]));
    try testing.expectError(error.BadFingerprint, parseFingerprint("zz"));
    try testing.expectError(error.BadFingerprint, parseFingerprint(""));
}
