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
//! The structure walk uses the shared bounds-checked DER reader
//! (shared/pki/der.zig, also the server's); `verifyLeaf` additionally reads
//! the leaf's extensions with the server's own certificate parser
//! (shared/pki/cert.zig) to require a TLS server certificate.
//!
//! Also: PEM/DER loading of the CA file and SHA-256 fingerprints.

const std = @import("std");
const Certificate = std.crypto.Certificate;
const pki = @import("shared").pki;
const der_mod = pki.der;
const Tag = der_mod.Tag;
const oids = der_mod.oids;
const Element = der_mod.Element;

/// Portal's certificates are well under 2 KiB.
pub const max_cert_len = 8 * 1024;
const max_depth = 20;

pub const Error = error{ BadCertificate, UnsupportedCertificate };

fn constructed(e: Element) bool {
    return e.tag & 0x20 != 0;
}

/// The elements inside a constructed element, each checked recursively.
const Children = struct {
    r: der_mod.Reader,
    depth: u8,

    fn of(e: Element, depth: u8) Error!Children {
        if (!constructed(e)) return error.BadCertificate;
        if (depth >= max_depth) return error.BadCertificate;
        return .{ .r = .init(e.content), .depth = depth + 1 };
    }

    fn next(c: *Children) Error!?Element {
        if (c.r.atEnd()) return null;
        const e = c.r.next() catch return error.BadCertificate;
        try generic(e, c.depth);
        return e;
    }

    fn need(c: *Children) Error!Element {
        return (try c.next()) orelse error.BadCertificate;
    }

    fn needTag(c: *Children, tag: u8) Error!Element {
        const e = try c.need();
        if (e.tag != tag) return error.BadCertificate;
        return e;
    }

    fn done(c: *Children) Error!void {
        if (!c.r.atEnd()) return error.BadCertificate;
    }
};

/// Structure every element must have, whatever it is: constructed elements
/// nest properly; BIT STRINGs have their unused-bits byte (std reads it).
fn generic(e: Element, depth: u8) Error!void {
    if (e.tag == Tag.bit_string and e.content.len == 0) return error.BadCertificate;
    if (!constructed(e)) return;
    var c = try Children.of(e, depth);
    while (try c.next()) |_| {}
}

/// A SEQUENCE starting with an OID (AlgorithmIdentifier), returning the OID.
fn algorithm(e: Element, depth: u8) Error![]const u8 {
    if (e.tag != Tag.sequence) return error.BadCertificate;
    var c = try Children.of(e, depth);
    const oid = try c.needTag(Tag.oid);
    while (try c.next()) |_| {}
    return oid.content;
}

/// Name ::= SEQUENCE OF SET OF SEQUENCE { OID, value }.
fn name(e: Element, depth: u8) Error!void {
    if (e.tag != Tag.sequence) return error.BadCertificate;
    var rdns = try Children.of(e, depth);
    while (try rdns.next()) |rdn| {
        if (rdn.tag != Tag.set) return error.BadCertificate;
        var atavs = try Children.of(rdn, rdns.depth);
        while (try atavs.next()) |atav| {
            if (atav.tag != Tag.sequence) return error.BadCertificate;
            var parts = try Children.of(atav, atavs.depth);
            _ = try parts.needTag(Tag.oid);
            _ = try parts.need();
            try parts.done();
        }
    }
}

/// Checks that `der` is one X.509 certificate in Portal's profile whose
/// structure std's parser can walk without leaving the buffer.
pub fn validateCertificate(der: []const u8) Error!void {
    if (der.len < 2 or der.len > max_cert_len) return error.BadCertificate;
    var r: der_mod.Reader = .init(der);
    const cert = r.expect(Tag.sequence) catch return error.BadCertificate;
    if (!r.atEnd()) return error.BadCertificate;
    var top = try Children.of(cert, 0);
    const tbs = try top.needTag(Tag.sequence);
    const sig_alg = try top.need();
    if (!std.mem.eql(u8, try algorithm(sig_alg, top.depth), &oids.ecdsa_with_sha256)) return error.UnsupportedCertificate;
    _ = try top.needTag(Tag.bit_string);
    try top.done();

    var f = try Children.of(tbs, top.depth);
    var first = try f.need();
    if (first.tag == Tag.contextConstructed(0)) {
        if (first.content.len != 3) return error.BadCertificate;
        first = try f.need(); // serial
    }
    if (first.tag != Tag.integer) return error.BadCertificate;
    if (!std.mem.eql(u8, try algorithm(try f.need(), f.depth), &oids.ecdsa_with_sha256)) return error.UnsupportedCertificate;
    try name(try f.need(), f.depth); // issuer
    {
        const validity = try f.needTag(Tag.sequence);
        var v = try Children.of(validity, f.depth);
        for (0..2) |_| {
            const t = try v.need();
            if (t.tag != Tag.utc_time and t.tag != Tag.generalized_time) return error.BadCertificate;
        }
        try v.done();
    }
    try name(try f.need(), f.depth); // subject
    {
        const spki = try f.needTag(Tag.sequence);
        var s = try Children.of(spki, f.depth);
        const alg = try s.needTag(Tag.sequence);
        var a = try Children.of(alg, s.depth);
        const alg_oid = try a.needTag(Tag.oid);
        if (!std.mem.eql(u8, alg_oid.content, &oids.ec_public_key)) return error.UnsupportedCertificate;
        const curve = try a.needTag(Tag.oid);
        if (!std.mem.eql(u8, curve.content, &oids.prime256v1)) return error.UnsupportedCertificate;
        try a.done();
        _ = try s.needTag(Tag.bit_string);
        try s.done();
    }
    // Optional issuerUniqueID [1], subjectUniqueID [2], extensions [3].
    while (try f.next()) |t| {
        if (t.tag != Tag.contextConstructed(3)) continue;
        var outer = try Children.of(t, f.depth);
        const exts = try outer.needTag(Tag.sequence);
        try outer.done();
        var e = try Children.of(exts, outer.depth);
        while (try e.next()) |ext| {
            if (ext.tag != Tag.sequence) return error.BadCertificate;
            var x = try Children.of(ext, e.depth);
            const oid = try x.needTag(Tag.oid);
            var value = try x.need();
            if (value.tag == Tag.boolean) value = try x.need();
            if (value.tag != Tag.octet_string) return error.BadCertificate;
            try x.done();
            // Every extension value is DER (RFC 5280 4.1); std parses the
            // subjectAltName value in verifyHostName.
            var vr: der_mod.Reader = .init(value.content);
            const inner = vr.next() catch return error.BadCertificate;
            if (!vr.atEnd()) return error.BadCertificate;
            try generic(inner, x.depth);
            if (std.mem.eql(u8, oid.content, &oids.subject_alt_name) and inner.tag != Tag.sequence)
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
/// within its validity period, be a TLS server certificate (extKeyUsage
/// serverAuth, basicConstraints CA:FALSE: Portal's leaf profile, so a CA
/// certificate or one for another purpose is refused even when the pinned
/// CA signed it), and name `ip` (the bare server IP) in its subjectAltName.
pub fn verifyLeaf(leaf_der: []const u8, ca_der: []const u8, ip: []const u8, now_sec: i64) PinError!void {
    const ca = try parse(ca_der);
    const leaf = try parse(leaf_der);
    if (now_sec > ca.validity.not_after or now_sec < ca.validity.not_before) return error.CaExpired;
    leaf.verify(ca, now_sec) catch |err| return switch (err) {
        error.CertificateExpired => error.CertificateExpired,
        error.CertificateNotYetValid => error.CertificateNotYetValid,
        else => error.NotIssuedByPinnedCa,
    };
    try requireServerCert(leaf_der);
    leaf.verifyHostName(ip) catch return error.HostMismatch;
}

/// extKeyUsage lists serverAuth and basicConstraints is present with
/// CA:FALSE (read with the same parser the server uses for its own
/// certificates, which also refuses duplicate extensions and a signed
/// algorithm that differs from the outer one).
fn requireServerCert(leaf_der: []const u8) Error!void {
    const info = pki.cert.parse(leaf_der) catch return error.BadCertificate;
    if (!info.has_basic_constraints or info.is_ca) return error.UnsupportedCertificate;
    if (!pki.cert.ekuAllows(info.eku, &oids.kp_server_auth)) return error.UnsupportedCertificate;
}

// ------------------------------------------------------------------ files

pub const LoadError = error{ NotACertificate, MoreThanOneCertificate } || Error;

/// A CA certificate from a .pem (exactly one CERTIFICATE block) or a .cer
/// (DER) file, decoded into `out`. Validated and parsed.
pub fn loadCertificate(data: []const u8, out: *[max_cert_len]u8) LoadError![]const u8 {
    const der: []const u8 = if (pki.pem.isPem(data)) pki.pem.decode(data, out) catch |err| return switch (err) {
        error.MoreThanOneCertificate => error.MoreThanOneCertificate,
        else => error.NotACertificate,
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
pub const writePem = pki.pem.write;
/// SHA-256 of a DER certificate.
pub const fingerprint = pki.fingerprint.sha256;
/// "AB:CD:..." (the form `portal ca export` prints).
pub const formatFingerprint = pki.fingerprint.format;
/// Accepts 64 hex digits, optionally separated by ':' or spaces, any case.
pub const parseFingerprint = pki.fingerprint.parse;

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
    // The CA itself (CA:TRUE) is not a server certificate, even though it
    // is signed by the pinned CA and lists serverAuth.
    try testing.expectError(error.UnsupportedCertificate, verifyLeaf(testdata.ca_der, testdata.ca_der, testdata.leaf_ip, now));
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
