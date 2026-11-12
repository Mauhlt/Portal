//! X.509 certificate reading for Portal's profile (ECDSA P-256 with
//! SHA-256, version 3), on the bounds-checked DER reader. Used by the
//! server for the certificates it wrote itself (src/tls/x509.zig, pki.zig)
//! and by the native client for the server certificate it is shown
//! (client/src/net/x509check.zig), so both read extensions the same way.

const std = @import("std");
const der = @import("der.zig");
const oids = der.oids;
const Tag = der.Tag;

pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// More extensions than any Portal certificate has (six).
const max_extensions = 16;

/// What Portal needs to know about a certificate. Every field is located
/// with the bounds-checked reader.
pub const Info = struct {
    tbs_raw: []const u8,
    serial: []const u8,
    issuer_raw: []const u8,
    subject_raw: []const u8,
    not_before: i64,
    not_after: i64,
    /// Uncompressed SEC1 point (65 bytes for P-256).
    public_key: []const u8,
    /// The whole SubjectPublicKeyInfo (for SPKI pins).
    spki_raw: []const u8,
    signature_der: []const u8,
    /// subjectAltName extension value (GeneralNames DER), or empty.
    san: []const u8 = "",
    /// nameConstraints extension value, or empty.
    name_constraints: []const u8 = "",
    name_constraints_critical: bool = false,
    /// A basicConstraints extension is present.
    has_basic_constraints: bool = false,
    is_ca: bool = false,
    path_len: ?u64 = null,
    basic_constraints_critical: bool = false,
    key_usage: []const u8 = "",
    key_usage_critical: bool = false,
    eku: []const u8 = "",
    ski: []const u8 = "",
    aki: []const u8 = "",
};

pub fn parse(cert: []const u8) !Info {
    var top: der.Reader = .init(cert);
    const certificate = try top.expect(Tag.sequence);
    if (!top.atEnd()) return error.DerMalformed;
    var c: der.Reader = .init(certificate.content);
    const tbs = try c.expect(Tag.sequence);
    const alg = try c.expect(Tag.sequence);
    const sig = try c.expect(Tag.bit_string);
    if (!c.atEnd()) return error.DerMalformed;
    if (!std.mem.eql(u8, alg.content, &([_]u8{ Tag.oid, oids.ecdsa_with_sha256.len } ++ oids.ecdsa_with_sha256)))
        return error.UnsupportedAlgorithm;
    if (sig.content.len < 2 or sig.content[0] != 0) return error.DerMalformed;

    var t: der.Reader = .init(tbs.content);
    const version = try t.expect(Tag.contextConstructed(0));
    var vr: der.Reader = .init(version.content);
    const v = try vr.expect(Tag.integer);
    if (!std.mem.eql(u8, v.content, &.{2})) return error.UnsupportedVersion;
    const serial = try t.expect(Tag.integer);
    // The signed algorithm must be the one the signature claims
    // (RFC 5280 4.1.1.2): otherwise the unsigned outer field could be
    // swapped without breaking the signature.
    const inner_alg = try t.expect(Tag.sequence);
    if (!std.mem.eql(u8, inner_alg.raw, alg.raw)) return error.AlgorithmMismatch;
    const issuer = try t.expect(Tag.sequence);
    const validity = try t.expect(Tag.sequence);
    const subject = try t.expect(Tag.sequence);
    const spki_e = try t.expect(Tag.sequence);

    var vv: der.Reader = .init(validity.content);
    const nb = try der.parseTime(try vv.next());
    const na = try der.parseTime(try vv.next());

    var sp: der.Reader = .init(spki_e.content);
    const algid = try sp.expect(Tag.sequence);
    const expect_alg = [_]u8{ Tag.oid, oids.ec_public_key.len } ++ oids.ec_public_key ++
        [_]u8{ Tag.oid, oids.prime256v1.len } ++ oids.prime256v1;
    if (!std.mem.eql(u8, algid.content, &expect_alg)) return error.UnsupportedAlgorithm;
    const pk_bits = try sp.expect(Tag.bit_string);
    if (pk_bits.content.len != 66 or pk_bits.content[0] != 0) return error.DerMalformed;

    var info: Info = .{
        .tbs_raw = tbs.raw,
        .serial = serial.content,
        .issuer_raw = issuer.raw,
        .subject_raw = subject.raw,
        .not_before = nb,
        .not_after = na,
        .public_key = pk_bits.content[1..],
        .spki_raw = spki_e.raw,
        .signature_der = sig.content[1..],
    };

    while (!t.atEnd()) {
        const e = try t.next();
        if (e.tag != Tag.contextConstructed(3)) continue;
        var outer: der.Reader = .init(e.content);
        const list = try outer.expect(Tag.sequence);
        var exts: der.Reader = .init(list.content);
        var seen: [max_extensions][]const u8 = undefined;
        var n_seen: usize = 0;
        while (!exts.atEnd()) {
            const ext = try exts.expect(Tag.sequence);
            var er: der.Reader = .init(ext.content);
            const oid = try er.expect(Tag.oid);
            // Each extension at most once (RFC 5280 4.2): two different
            // answers to one question would let parsers disagree.
            for (seen[0..n_seen]) |o| if (std.mem.eql(u8, o, oid.content)) return error.DuplicateExtension;
            if (n_seen == seen.len) return error.DerMalformed;
            seen[n_seen] = oid.content;
            n_seen += 1;
            var critical = false;
            if (er.peekTag() == Tag.boolean) {
                const b = try er.next();
                critical = b.content.len == 1 and b.content[0] == 0xff;
            }
            const val = (try er.expect(Tag.octet_string)).content;
            if (std.mem.eql(u8, oid.content, &oids.subject_alt_name)) {
                info.san = val;
            } else if (std.mem.eql(u8, oid.content, &oids.name_constraints)) {
                info.name_constraints = val;
                info.name_constraints_critical = critical;
            } else if (std.mem.eql(u8, oid.content, &oids.basic_constraints)) {
                info.has_basic_constraints = true;
                info.basic_constraints_critical = critical;
                var br: der.Reader = .init(val);
                const bs = try br.expect(Tag.sequence);
                var bi: der.Reader = .init(bs.content);
                if (bi.peekTag() == Tag.boolean) {
                    const b = try bi.next();
                    info.is_ca = b.content.len == 1 and b.content[0] == 0xff;
                }
                if (bi.peekTag() == Tag.integer) {
                    const n = try bi.next();
                    if (n.content.len >= 1 and n.content.len <= 8) {
                        var x: u64 = 0;
                        for (n.content) |byte| x = (x << 8) | byte;
                        info.path_len = x;
                    }
                }
            } else if (std.mem.eql(u8, oid.content, &oids.key_usage)) {
                info.key_usage = val;
                info.key_usage_critical = critical;
            } else if (std.mem.eql(u8, oid.content, &oids.ext_key_usage)) {
                info.eku = val;
            } else if (std.mem.eql(u8, oid.content, &oids.subject_key_identifier)) {
                info.ski = val;
            } else if (std.mem.eql(u8, oid.content, &oids.authority_key_identifier)) {
                info.aki = val;
            }
        }
    }
    return info;
}

/// Verifies that `subject` was signed by the key in `issuer` (and the names
/// chain). Does not check validity times.
pub fn verifySignedBy(subject: Info, issuer: Info) !void {
    if (!std.mem.eql(u8, subject.issuer_raw, issuer.subject_raw)) return error.IssuerMismatch;
    const pk = try Ecdsa.PublicKey.fromSec1(issuer.public_key);
    const sig = try Ecdsa.Signature.fromDer(subject.signature_der);
    try sig.verify(subject.tbs_raw, pk);
}

/// Whether an extKeyUsage value (SEQUENCE OF KeyPurposeId) lists
/// `purpose` (OID content octets, e.g. `der.oids.kp_server_auth`).
pub fn ekuAllows(eku: []const u8, purpose: []const u8) bool {
    var r: der.Reader = .init(eku);
    const list = r.expect(Tag.sequence) catch return false;
    if (!r.atEnd()) return false;
    var l: der.Reader = .init(list.content);
    while (!l.atEnd()) {
        const oid = l.expect(Tag.oid) catch return false;
        if (std.mem.eql(u8, oid.content, purpose)) return true;
    }
    return false;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "extended key usage" {
    const server_auth = [_]u8{ Tag.sequence, 2 + oids.kp_server_auth.len, Tag.oid, oids.kp_server_auth.len } ++ oids.kp_server_auth;
    try testing.expect(ekuAllows(&server_auth, &oids.kp_server_auth));
    try testing.expect(!ekuAllows(&server_auth, &oids.common_name));
    try testing.expect(!ekuAllows("", &oids.kp_server_auth));
    try testing.expect(!ekuAllows(&.{ 0x30, 0x00 }, &oids.kp_server_auth));
    try testing.expect(!ekuAllows(server_auth[0 .. server_auth.len - 1], &oids.kp_server_auth));
}
