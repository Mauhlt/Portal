//! Portal's private certificate authority: X.509 profiles for the CA and
//! the server (leaf) certificate, built with the DER writer in shared/pki/der.zig and
//! signed with ECDSA P-256 / SHA-256 (std.crypto).
//!
//! CA profile (RFC 5280):
//!   * subject = issuer = CN "Portal Local CA (<8 hex>)", O "Portal"
//!   * basicConstraints  critical  CA:TRUE, pathLenConstraint 0
//!   * keyUsage          critical  keyCertSign | cRLSign
//!   * extKeyUsage       serverAuth only. Not an RFC 5280 CA field, but
//!     Windows CryptoAPI, Chrome, Firefox, Apple and OpenSSL treat a CA's
//!     EKU as a ceiling for the chain, so a leaked CA key cannot mint
//!     code-signing, S/MIME or TLS client certificates that a device
//!     trusting this root would accept.
//!   * subjectKeyIdentifier
//!   * nameConstraints   critical  permitted iPAddress subtrees (the
//!     WireGuard subnet and loopback by default) plus permitted dNSName
//!     subtrees. With no DNS names configured the single permitted dNSName
//!     is "invalid" (RFC 6761: never resolves), so the dNSName form is
//!     constrained too: a constraint on iPAddress alone would leave every
//!     DNS name unconstrained (RFC 5280 4.2.1.10 only restricts name forms
//!     that have a constraint), and a leaked CA key could then mint a
//!     certificate for any web site. The same trick closes the other name
//!     forms a relying party might accept: rfc822Name "invalid" (mailboxes
//!     at the host "invalid" only), uniformResourceIdentifier ".invalid"
//!     (hosts under "invalid" only) and directoryName O=Portal (exactly the
//!     leaf's subject).
//!   * validity ~10 years
//!
//! Leaf profile (also Apple's TLS server requirements, support.apple.com
//! HT210176 / HT211025):
//!   * subject O=Portal only (no CN: see leafSubject)
//!   * subjectAltName iPAddress (+ dNSName when configured and permitted)
//!   * extKeyUsage serverAuth, keyUsage critical digitalSignature
//!   * basicConstraints CA:FALSE, authority/subject key identifiers
//!   * ECDSA P-256, SHA-256, validity 397 days (Apple: <= 398), but never
//!     past the CA's own notAfter
//!   * serial: 16 random bytes, positive

const std = @import("std");
const Allocator = std.mem.Allocator;
const shared_pki = @import("shared").pki;
const der = shared_pki.der;
const cert = shared_pki.cert;
const pki_fp = shared_pki.fingerprint;
const oids = der.oids;
const Tag = der.Tag;

pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
pub const KeyPair = Ecdsa.KeyPair;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const ca_validity_s: i64 = 3650 * 86400;
pub const leaf_validity_s: i64 = 397 * 86400;
/// Certificates start this long in the past to tolerate device clock skew.
pub const backdate_s: i64 = 3600;
/// Renew the leaf when it has less than this left.
pub const renew_before_s: i64 = 30 * 86400;

pub const max_subnets = 8;
pub const max_dns = 8;
pub const max_dns_len = 253;

/// An IP subnet (address + mask), v4 or v6.
pub const Subnet = struct {
    v6: bool,
    addr: [16]u8 = @splat(0),
    mask: [16]u8 = @splat(0),

    pub fn len(s: Subnet) usize {
        return if (s.v6) 16 else 4;
    }

    /// "10.8.0.0/24", "127.0.0.1/32", "fd00::/64". A bare address is /32 (/128).
    pub fn parse(text: []const u8) !Subnet {
        const slash = std.mem.indexOfScalar(u8, text, '/');
        const host = if (slash) |i| text[0..i] else text;
        var s: Subnet = undefined;
        var max_prefix: u8 = 32;
        if (std.Io.net.Ip4Address.parse(host, 0)) |a| {
            s = .{ .v6 = false };
            @memcpy(s.addr[0..4], &a.bytes);
        } else |_| {
            const a6 = std.Io.net.Ip6Address.parse(host, 0) catch return error.BadSubnet;
            s = .{ .v6 = true };
            s.addr = a6.bytes;
            max_prefix = 128;
        }
        const prefix: u8 = if (slash) |i|
            std.fmt.parseInt(u8, text[i + 1 ..], 10) catch return error.BadSubnet
        else
            max_prefix;
        if (prefix > max_prefix) return error.BadSubnet;
        var i: usize = 0;
        while (i < s.len()) : (i += 1) {
            const bits_here: u8 = if (prefix >= (i + 1) * 8) 8 else if (prefix > i * 8) @intCast(prefix - i * 8) else 0;
            s.mask[i] = if (bits_here == 0) 0 else @as(u8, 0xff) << @intCast(8 - bits_here);
            s.addr[i] &= s.mask[i];
        }
        return s;
    }

    pub fn contains(s: Subnet, ip: []const u8) bool {
        if (ip.len != s.len()) return false;
        for (ip, 0..) |b, i| if (b & s.mask[i] != s.addr[i]) return false;
        return true;
    }

    pub fn prefixLen(s: Subnet) u8 {
        var n: u8 = 0;
        for (s.mask[0..s.len()]) |m| n += @popCount(m);
        return n;
    }

    pub fn format(s: Subnet, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (s.v6) {
            const a: std.Io.net.Ip6Address = .{ .bytes = s.addr, .port = 0 };
            // Ip6Address formats as [addr]:port; print the bare address.
            var buf: [64]u8 = undefined;
            const full = std.fmt.bufPrint(&buf, "{f}", .{a}) catch "?";
            const end = std.mem.lastIndexOfScalar(u8, full, ']') orelse full.len;
            const start: usize = if (full.len > 0 and full[0] == '[') 1 else 0;
            try w.print("{s}/{d}", .{ full[start..end], s.prefixLen() });
        } else {
            try w.print("{d}.{d}.{d}.{d}/{d}", .{ s.addr[0], s.addr[1], s.addr[2], s.addr[3], s.prefixLen() });
        }
    }
};

pub const default_permits = [_][]const u8{ "10.8.0.0/24", "127.0.0.1/32" };

pub const Constraints = struct {
    subnets: [max_subnets]Subnet = undefined,
    n_subnets: usize = 0,
    dns: [max_dns][]const u8 = undefined,
    n_dns: usize = 0,
    /// Set by parseConstraints when the closed rfc822Name,
    /// uniformResourceIdentifier and directoryName subtrees are present
    /// (always written now; missing in CAs made by older versions).
    closed_rfc822: bool = false,
    closed_uri: bool = false,
    directory_portal: bool = false,

    pub fn ipPermitted(c: *const Constraints, ip: []const u8) bool {
        for (c.subnets[0..c.n_subnets]) |s| if (s.contains(ip)) return true;
        return false;
    }

    /// RFC 5280 dNSName constraint semantics: the name equals the
    /// constraint or ends with "." + constraint (case-insensitive).
    pub fn dnsPermitted(c: *const Constraints, name: []const u8) bool {
        for (c.dns[0..c.n_dns]) |base| {
            if (std.ascii.eqlIgnoreCase(name, base)) return true;
            if (name.len > base.len + 1 and name[name.len - base.len - 1] == '.' and
                std.ascii.eqlIgnoreCase(name[name.len - base.len ..], base)) return true;
        }
        return false;
    }
};

/// A DNS name we are willing to put in a certificate: LDH labels only.
pub fn validDnsName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_dns_len) return false;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |ch| switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-' => {},
            else => return false,
        };
    }
    return true;
}

pub const SanEntry = union(enum) {
    ip: struct { bytes: [16]u8, len: u8 },
    dns: []const u8,
};

// ---------------------------------------------------------------- builders

/// Subject of the server certificate: O=Portal only. Names live in the
/// subjectAltName. No CN on purpose: Windows CryptoAPI checks a CN that
/// looks like a host name against the CA's dNSName constraints (and would
/// reject "CN=10.8.0.1" under the "invalid"-only DNS constraint), and
/// modern clients ignore the CN for name matching anyway.
pub fn leafSubject(d: der.Writer) ![]u8 {
    return d.seq(&.{
        try d.set(&.{try d.seq(&.{ try d.oid(&oids.organization), try d.utf8("Portal") })}),
    });
}

fn dnName(d: der.Writer, cn: []const u8) ![]u8 {
    return d.seq(&.{
        try d.set(&.{try d.seq(&.{ try d.oid(&oids.organization), try d.utf8("Portal") })}),
        try d.set(&.{try d.seq(&.{ try d.oid(&oids.common_name), try d.utf8(cn) })}),
    });
}

fn spki(d: der.Writer, pk: Ecdsa.PublicKey) ![]u8 {
    const point = pk.toUncompressedSec1();
    return d.seq(&.{
        try d.seq(&.{ try d.oid(&oids.ec_public_key), try d.oid(&oids.prime256v1) }),
        try d.bitString(&point),
    });
}

/// Key identifier: first 20 bytes of SHA-256 over the public key bits
/// (RFC 7093 section 2, method 1).
pub fn keyId(pk: Ecdsa.PublicKey) [20]u8 {
    var h: [32]u8 = undefined;
    Sha256.hash(&pk.toUncompressedSec1(), &h, .{});
    return h[0..20].*;
}

fn extension(d: der.Writer, oid: []const u8, critical: bool, value: []const u8) ![]u8 {
    if (critical) return d.seq(&.{ try d.oid(oid), try d.boolean(true), try d.octets(value) });
    return d.seq(&.{ try d.oid(oid), try d.octets(value) });
}

/// ExtKeyUsageSyntax with id-kp-serverAuth only (CA and leaf).
fn ekuServerAuth(d: der.Writer) ![]u8 {
    return d.seq(&.{try d.oid(&oids.kp_server_auth)});
}

/// The encoded extKeyUsage value Portal writes (for profile checks).
pub const eku_server_auth_der = [_]u8{ Tag.sequence, 2 + oids.kp_server_auth.len, Tag.oid, oids.kp_server_auth.len } ++ oids.kp_server_auth;

/// True if `info` (a Portal CA) has the current profile: extKeyUsage
/// serverAuth only and the closed rfc822Name / URI / directoryName
/// subtrees. CAs made by older versions lack these; they keep working,
/// but are only as narrow as their iPAddress/dNSName constraints.
pub fn isCurrentCaProfile(info: Info, c: *const Constraints) bool {
    return std.mem.eql(u8, info.eku, &eku_server_auth_der) and
        c.closed_rfc822 and c.closed_uri and c.directory_portal;
}

fn sigAlg(d: der.Writer) ![]u8 {
    return d.seq(&.{try d.oid(&oids.ecdsa_with_sha256)});
}

/// Signs `tbs` and wraps it into a Certificate.
fn finish(d: der.Writer, tbs: []const u8, signer: *const KeyPair, noise: ?[Ecdsa.noise_length]u8) ![]u8 {
    const sig = try signer.sign(tbs, noise);
    var sig_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&sig_buf);
    return d.seq(&.{ tbs, try sigAlg(d), try d.bitString(sig_der) });
}

/// rfc822Name constraint: a host name, so only mailboxes "x@invalid".
const closed_rfc822 = "invalid";
/// uniformResourceIdentifier constraint: a leading "." means hosts within
/// that domain, so only URIs whose host ends in ".invalid".
const closed_uri = ".invalid";

/// The nameConstraints extension value.
pub fn nameConstraintsValue(d: der.Writer, c: *const Constraints) ![]u8 {
    var subtrees: std.ArrayList([]const u8) = .empty;
    for (c.subnets[0..c.n_subnets]) |s| {
        var both: [32]u8 = undefined;
        @memcpy(both[0..s.len()], s.addr[0..s.len()]);
        @memcpy(both[s.len() .. 2 * s.len()], s.mask[0..s.len()]);
        try subtrees.append(d.arena, try d.seq(&.{try d.tlv(Tag.contextPrimitive(7), both[0 .. 2 * s.len()])}));
    }
    if (c.n_dns == 0) {
        try subtrees.append(d.arena, try d.seq(&.{try d.tlv(Tag.contextPrimitive(2), "invalid")}));
    } else for (c.dns[0..c.n_dns]) |n| {
        try subtrees.append(d.arena, try d.seq(&.{try d.tlv(Tag.contextPrimitive(2), n)}));
    }
    // Close the other name forms (see the profile notes at the top).
    try subtrees.append(d.arena, try d.seq(&.{try d.tlv(Tag.contextPrimitive(1), closed_rfc822)}));
    try subtrees.append(d.arena, try d.seq(&.{try d.tlv(Tag.contextPrimitive(6), closed_uri)}));
    try subtrees.append(d.arena, try d.seq(&.{try d.tlv(Tag.contextConstructed(4), try leafSubject(d))}));
    return d.seq(&.{try d.constructed(Tag.contextConstructed(0), subtrees.items)});
}

pub const CaParams = struct {
    /// By pointer: the private key is not copied into the parameters.
    key: *const KeyPair,
    /// 8 lowercase hex characters, shown in the CA's name.
    tag: [8]u8,
    serial: [16]u8,
    now: i64,
    constraints: *const Constraints,
    noise: ?[Ecdsa.noise_length]u8 = null,
};

pub fn buildCa(gpa: Allocator, p: CaParams) ![]u8 {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const d: der.Writer = .{ .arena = arena.allocator() };

    var cn_buf: [64]u8 = undefined;
    const cn = try std.fmt.bufPrint(&cn_buf, "Portal Local CA ({s})", .{&p.tag});
    const subject = try dnName(d, cn);
    const kid = keyId(p.key.public_key);
    const exts = try d.seq(&.{
        try extension(d, &oids.basic_constraints, true, try d.seq(&.{ try d.boolean(true), try d.uint(0) })),
        try extension(d, &oids.key_usage, true, try d.namedBits(0x0600)), // keyCertSign | cRLSign
        try extension(d, &oids.ext_key_usage, false, try ekuServerAuth(d)),
        try extension(d, &oids.subject_key_identifier, false, try d.octets(&kid)),
        try extension(d, &oids.name_constraints, true, try nameConstraintsValue(d, p.constraints)),
    });
    const tbs = try d.seq(&.{
        try d.tlv(Tag.contextConstructed(0), try d.uint(2)), // v3
        try d.uintBytes(&positiveSerial(p.serial)),
        try sigAlg(d),
        subject,
        try d.seq(&.{ try d.time(p.now - backdate_s), try d.time(p.now - backdate_s + ca_validity_s) }),
        subject,
        try spki(d, p.key.public_key),
        try d.tlv(Tag.contextConstructed(3), exts),
    });
    return gpa.dupe(u8, try finish(d, tbs, p.key, p.noise));
}

/// Top bit cleared (positive INTEGER), second-highest set (keeps 16 bytes).
fn positiveSerial(s: [16]u8) [16]u8 {
    var out = s;
    out[0] = (out[0] & 0x7f) | 0x40;
    return out;
}

/// The subjectAltName extension value for `sans` (in order).
pub fn sanValue(d: der.Writer, sans: []const SanEntry) ![]u8 {
    var names: std.ArrayList([]const u8) = .empty;
    for (sans) |s| switch (s) {
        .ip => |ip| try names.append(d.arena, try d.tlv(Tag.contextPrimitive(7), ip.bytes[0..ip.len])),
        .dns => |n| try names.append(d.arena, try d.tlv(Tag.contextPrimitive(2), n)),
    };
    return d.seq(names.items);
}

pub const LeafParams = struct {
    key: Ecdsa.PublicKey,
    /// By pointer: the CA private key is not copied into the parameters.
    ca_key: *const KeyPair,
    /// The CA certificate (its subject becomes the issuer).
    ca_der: []const u8,
    sans: []const SanEntry,
    serial: [16]u8,
    now: i64,
    noise: ?[Ecdsa.noise_length]u8 = null,
};

pub fn buildLeaf(gpa: Allocator, p: LeafParams) ![]u8 {
    if (p.sans.len == 0) return error.NoSubjectAltNames;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const d: der.Writer = .{ .arena = arena.allocator() };

    const ca = try parse(p.ca_der);
    // A certificate must not outlive its issuer: path validation checks
    // every certificate's validity (RFC 5280 6.1.3).
    if (ca.not_after <= p.now) return error.CaExpired;
    const not_after = @min(p.now - backdate_s + leaf_validity_s, ca.not_after);
    const aki = keyId(p.ca_key.public_key);
    const ski = keyId(p.key);
    const exts = try d.seq(&.{
        try extension(d, &oids.basic_constraints, true, try d.seq(&.{})), // CA:FALSE
        try extension(d, &oids.key_usage, true, try d.namedBits(0x8000)), // digitalSignature
        try extension(d, &oids.ext_key_usage, false, try ekuServerAuth(d)),
        try extension(d, &oids.subject_alt_name, false, try sanValue(d, p.sans)),
        try extension(d, &oids.authority_key_identifier, false, try d.seq(&.{try d.tlv(Tag.contextPrimitive(0), &aki)})),
        try extension(d, &oids.subject_key_identifier, false, try d.octets(&ski)),
    });
    const tbs = try d.seq(&.{
        try d.tlv(Tag.contextConstructed(0), try d.uint(2)),
        try d.uintBytes(&positiveSerial(p.serial)),
        try sigAlg(d),
        ca.subject_raw,
        try d.seq(&.{ try d.time(p.now - backdate_s), try d.time(not_after) }),
        try leafSubject(d),
        try spki(d, p.key),
        try d.tlv(Tag.contextConstructed(3), exts),
    });
    return gpa.dupe(u8, try finish(d, tbs, p.ca_key, p.noise));
}

pub fn formatIp(buf: []u8, ip: []const u8) []const u8 {
    if (ip.len == 4) return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "?";
    if (ip.len == 16) {
        const a: std.Io.net.Ip6Address = .{ .bytes = ip[0..16].*, .port = 0 };
        const full = std.fmt.bufPrint(buf, "{f}", .{a}) catch return "?";
        const end = std.mem.lastIndexOfScalar(u8, full, ']') orelse full.len;
        const start: usize = if (full.len > 0 and full[0] == '[') 1 else 0;
        return full[start..end];
    }
    return "?";
}

// ----------------------------------------------------------------- parsing

/// Certificate reading lives in shared/pki/cert.zig (also used by the
/// native client); fingerprints in shared/pki/fingerprint.zig.
pub const Info = cert.Info;
pub const parse = cert.parse;
pub const verifySignedBy = cert.verifySignedBy;
pub const fingerprint = pki_fp.sha256;
pub const formatFingerprint = pki_fp.format;

// -------------------------------------------------------------------- tests

const testing = std.testing;
const Certificate = std.crypto.Certificate;

fn testConstraints() Constraints {
    var c: Constraints = .{};
    for (default_permits) |p| {
        c.subnets[c.n_subnets] = Subnet.parse(p) catch unreachable;
        c.n_subnets += 1;
    }
    return c;
}

pub const TestPki = struct {
    ca_key: KeyPair,
    leaf_key: KeyPair,
    ca_der: []u8,
    leaf_der: []u8,

    pub fn init(gpa: Allocator, now: i64, sans: []const SanEntry) !TestPki {
        const ca_key = try KeyPair.generateDeterministic(@splat(7));
        const leaf_key = try KeyPair.generateDeterministic(@splat(9));
        const c = testConstraints();
        const ca_der = try buildCa(gpa, .{ .key = &ca_key, .tag = "0123abcd".*, .serial = @splat(0x11), .now = now, .constraints = &c });
        errdefer gpa.free(ca_der);
        const leaf_der = try buildLeaf(gpa, .{
            .key = leaf_key.public_key,
            .ca_key = &ca_key,
            .ca_der = ca_der,
            .sans = sans,
            .serial = @splat(0x22),
            .now = now,
        });
        return .{ .ca_key = ca_key, .leaf_key = leaf_key, .ca_der = ca_der, .leaf_der = leaf_der };
    }

    pub fn deinit(p: *TestPki, gpa: Allocator) void {
        gpa.free(p.ca_der);
        gpa.free(p.leaf_der);
    }
};

pub fn ip4(a: u8, b: u8, c: u8, d: u8) SanEntry {
    var bytes: [16]u8 = @splat(0);
    bytes[0..4].* = .{ a, b, c, d };
    return .{ .ip = .{ .bytes = bytes, .len = 4 } };
}

test "subnet parsing" {
    const s = try Subnet.parse("10.8.0.77/24");
    try testing.expectEqualSlices(u8, &.{ 10, 8, 0, 0 }, s.addr[0..4]);
    try testing.expectEqualSlices(u8, &.{ 255, 255, 255, 0 }, s.mask[0..4]);
    try testing.expect(s.contains(&.{ 10, 8, 0, 2 }));
    try testing.expect(!s.contains(&.{ 10, 8, 1, 2 }));
    try testing.expectEqual(@as(u8, 24), s.prefixLen());
    const l = try Subnet.parse("127.0.0.1");
    try testing.expectEqual(@as(u8, 32), l.prefixLen());
    const v6 = try Subnet.parse("fd00::/8");
    try testing.expect(v6.v6 and v6.mask[0] == 0xff and v6.mask[1] == 0);
    try testing.expectError(error.BadSubnet, Subnet.parse("10.8.0.0/33"));
    try testing.expectError(error.BadSubnet, Subnet.parse("nonsense/8"));
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("10.8.0.0/24", try std.fmt.bufPrint(&buf, "{f}", .{s}));
}

test "dns constraint matching" {
    var c: Constraints = .{};
    c.dns[0] = "portal.home";
    c.n_dns = 1;
    try testing.expect(c.dnsPermitted("portal.home"));
    try testing.expect(c.dnsPermitted("desk.Portal.HOME"));
    try testing.expect(!c.dnsPermitted("evilportal.home"));
    try testing.expect(!c.dnsPermitted("home"));
    try testing.expect(validDnsName("desk.portal.home"));
    try testing.expect(!validDnsName("bad_name.home"));
    try testing.expect(!validDnsName("a..b"));
}

test "CA and leaf round-trip through std.crypto.Certificate" {
    const gpa = testing.allocator;
    const now: i64 = 1_790_000_000;
    var pki = try TestPki.init(gpa, now, &.{ ip4(10, 8, 0, 1), .{ .dns = "desk.invalid" } });
    defer pki.deinit(gpa);

    const ca: Certificate = .{ .buffer = pki.ca_der, .index = 0 };
    const leaf: Certificate = .{ .buffer = pki.leaf_der, .index = 0 };
    const ca_p = try ca.parse();
    const leaf_p = try leaf.parse();
    try testing.expectEqualStrings("Portal Local CA (0123abcd)", ca_p.commonName());
    try testing.expectEqualStrings("", leaf_p.commonName()); // no CN: names are in the SAN
    try testing.expectEqual(Certificate.Version.v3, leaf_p.version);
    try testing.expectEqual(Certificate.Algorithm.ecdsa_with_SHA256, leaf_p.signature_algorithm);
    try testing.expectEqual(Certificate.NamedCurve.X9_62_prime256v1, leaf_p.pub_key_algo.X9_62_id_ecPublicKey);
    try ca_p.verify(ca_p, now); // self-signed
    try leaf_p.verify(ca_p, now);
    try testing.expectError(error.CertificateExpired, leaf_p.verify(ca_p, now + leaf_validity_s));
    try leaf_p.verifyHostName("10.8.0.1");
    try leaf_p.verifyHostName("desk.invalid");
    try testing.expectError(error.CertificateHostMismatch, leaf_p.verifyHostName("10.8.0.2"));
    try testing.expectEqual(@as(u64, @intCast(now - backdate_s + leaf_validity_s)), leaf_p.validity.not_after);
    try testing.expectEqual(@as(u64, @intCast(now - backdate_s + ca_validity_s)), ca_p.validity.not_after);
    // Apple: leaf validity <= 398 days.
    try testing.expect(leaf_p.validity.not_after - leaf_p.validity.not_before <= 398 * 86400);
}

test "certificate profile fields" {
    const gpa = testing.allocator;
    const now: i64 = 1_790_000_000;
    var pki = try TestPki.init(gpa, now, &.{ip4(10, 8, 0, 1)});
    defer pki.deinit(gpa);

    const ca = try parse(pki.ca_der);
    try testing.expect(ca.is_ca and ca.basic_constraints_critical);
    try testing.expectEqual(@as(?u64, 0), ca.path_len);
    try testing.expect(ca.key_usage_critical);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x02, 0x01, 0x06 }, ca.key_usage);
    try testing.expect(ca.name_constraints_critical);
    // permittedSubtrees [0] { iPAddress 10.8.0.0/255.255.255.0, iPAddress 127.0.0.1/32,
    //   dNSName "invalid", rfc822Name "invalid", URI ".invalid", directoryName O=Portal }
    const expected_nc = [_]u8{
        0x30, 0x53, 0xa0, 0x51,
        0x30, 0x0a, 0x87, 0x08, 10,   8,    0,    0,    255,  255,  255,  0,
        0x30, 0x0a, 0x87, 0x08, 127,  0,    0,    1,    255,  255,  255,  255,
        0x30, 0x09, 0x82, 0x07, 'i',  'n',  'v',  'a',  'l',  'i',  'd',
        0x30, 0x09, 0x81, 0x07, 'i',  'n',  'v',  'a',  'l',  'i',  'd',
        0x30, 0x0a, 0x86, 0x08, '.',  'i',  'n',  'v',  'a',  'l',  'i',  'd',
        0x30, 0x15, 0xa4, 0x13, 0x30, 0x11, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x06, 'P',  'o',  'r',  't',  'a',  'l',
    };
    try testing.expectEqualSlices(u8, &expected_nc, ca.name_constraints);
    try testing.expectEqualSlices(u8, &eku_server_auth_der, ca.eku);
    const cc = try parseConstraints(ca.name_constraints);
    try testing.expect(isCurrentCaProfile(ca, &cc));
    try testing.expectEqual(@as(usize, 22), ca.ski.len); // 04 14 <20>
    try testing.expectEqualSlices(u8, ca.subject_raw, ca.issuer_raw);
    try testing.expectEqual(@as(u8, 0x40), ca.serial[0] & 0xc0); // positive, 16 bytes
    try testing.expectEqual(@as(usize, 16), ca.serial.len);

    const leaf = try parse(pki.leaf_der);
    try testing.expect(!leaf.is_ca and leaf.basic_constraints_critical);
    try testing.expect(leaf.key_usage_critical);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x02, 0x07, 0x80 }, leaf.key_usage);
    try testing.expectEqualSlices(u8, &([_]u8{ 0x30, 0x0a, 0x06, 0x08 } ++ oids.kp_server_auth), leaf.eku);
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x06, 0x87, 0x04, 10, 8, 0, 1 }, leaf.san);
    try testing.expectEqualSlices(u8, ca.subject_raw, leaf.issuer_raw);
    // AKI keyIdentifier == CA SKI
    try testing.expectEqualSlices(u8, ca.ski[2..], leaf.aki[4..]);
    try verifySignedBy(leaf, ca);
    try verifySignedBy(ca, ca);
    try testing.expectEqual(@as(usize, 16), leaf.serial.len);
    try testing.expectEqualSlices(u8, &pki.leaf_key.public_key.toUncompressedSec1(), leaf.public_key);

    // A leaf signed by some other key does not verify.
    const other = try KeyPair.generateDeterministic(@splat(3));
    const forged = try buildLeaf(gpa, .{
        .key = pki.leaf_key.public_key,
        .ca_key = &other,
        .ca_der = pki.ca_der,
        .sans = &.{ip4(10, 8, 0, 1)},
        .serial = @splat(1),
        .now = now,
    });
    defer gpa.free(forged);
    try testing.expectError(error.SignatureVerificationFailed, verifySignedBy(try parse(forged), ca));
}

/// A leaf like buildLeaf's but with the given extensions, for tests.
fn customLeaf(gpa: Allocator, p: *const TestPki, now: i64, exts: []const []const u8) ![]u8 {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const d: der.Writer = .{ .arena = arena.allocator() };
    const ca = try parse(p.ca_der);
    const tbs = try d.seq(&.{
        try d.tlv(Tag.contextConstructed(0), try d.uint(2)),
        try d.uintBytes(&positiveSerial(@splat(0x33))),
        try sigAlg(d),
        ca.subject_raw,
        try d.seq(&.{ try d.time(now - backdate_s), try d.time(now + 86400) }),
        try leafSubject(d),
        try spki(d, p.leaf_key.public_key),
        try d.tlv(Tag.contextConstructed(3), try d.seq(exts)),
    });
    return gpa.dupe(u8, try finish(d, tbs, &p.ca_key, null));
}

test "parser rejects duplicate extensions and a swapped signature algorithm" {
    const gpa = testing.allocator;
    const now: i64 = 1_790_000_000;
    var p = try TestPki.init(gpa, now, &.{ip4(10, 8, 0, 1)});
    defer p.deinit(gpa);

    // The signed AlgorithmIdentifier comes first; change its hash.
    const alg = [_]u8{ Tag.sequence, 2 + oids.ecdsa_with_sha256.len, Tag.oid, oids.ecdsa_with_sha256.len } ++ oids.ecdsa_with_sha256;
    const swapped = try gpa.dupe(u8, p.leaf_der);
    defer gpa.free(swapped);
    const at = std.mem.indexOf(u8, swapped, &alg).?;
    swapped[at + alg.len - 1] = 0x03; // ecdsa-with-SHA384
    try testing.expectError(error.AlgorithmMismatch, parse(swapped));

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const d: der.Writer = .{ .arena = arena.allocator() };
    const bc_false = try extension(d, &oids.basic_constraints, true, try d.seq(&.{}));
    const dup = try customLeaf(gpa, &p, now, &.{ bc_false, bc_false });
    defer gpa.free(dup);
    try testing.expectError(error.DuplicateExtension, parse(dup));
}

test "the native client accepts only server certificates from the pinned CA" {
    const gpa = testing.allocator;
    const now: i64 = 1_790_000_000;
    var p = try TestPki.init(gpa, now, &.{ip4(10, 8, 0, 1)});
    defer p.deinit(gpa);
    const x509check = @import("client").x509check_mod;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const d: der.Writer = .{ .arena = arena.allocator() };
    const bc_false = try extension(d, &oids.basic_constraints, true, try d.seq(&.{}));
    const bc_true = try extension(d, &oids.basic_constraints, true, try d.seq(&.{try d.boolean(true)}));
    const ku = try extension(d, &oids.key_usage, true, try d.namedBits(0x8000));
    const eku = try extension(d, &oids.ext_key_usage, false, try ekuServerAuth(d));
    const san = try extension(d, &oids.subject_alt_name, false, try sanValue(d, &.{ip4(10, 8, 0, 1)}));

    try x509check.verifyLeaf(p.leaf_der, p.ca_der, "10.8.0.1", now);
    const Case = struct { exts: []const []const u8, ok: bool };
    for ([_]Case{
        .{ .exts = &.{ bc_false, ku, eku, san }, .ok = true },
        .{ .exts = &.{ bc_false, ku, san }, .ok = false }, // no extKeyUsage
        .{ .exts = &.{ ku, eku, san }, .ok = false }, // no basicConstraints
        .{ .exts = &.{ bc_true, ku, eku, san }, .ok = false }, // CA:TRUE
    }) |c| {
        const leaf = try customLeaf(gpa, &p, now, c.exts);
        defer gpa.free(leaf);
        if (c.ok) {
            try x509check.verifyLeaf(leaf, p.ca_der, "10.8.0.1", now);
        } else {
            try testing.expectError(error.UnsupportedCertificate, x509check.verifyLeaf(leaf, p.ca_der, "10.8.0.1", now));
        }
    }
}

test "certificate parser never panics on corrupted certificates" {
    const gpa = testing.allocator;
    var pki = try TestPki.init(gpa, 1_790_000_000, &.{ip4(127, 0, 0, 1)});
    defer pki.deinit(gpa);
    var buf: [2048]u8 = undefined;
    const n = pki.leaf_der.len;
    var prng: std.Random.DefaultPrng = .init(42);
    const rand = prng.random();
    for (0..n) |cut| _ = parse(pki.leaf_der[0..cut]) catch {};
    for (0..5000) |_| {
        @memcpy(buf[0..n], pki.leaf_der);
        const flips = rand.uintLessThan(usize, 4) + 1;
        for (0..flips) |_| buf[rand.uintLessThan(usize, n)] = rand.int(u8);
        const info = parse(buf[0..n]) catch continue;
        _ = verifySignedBy(info, info) catch {};
    }
}

/// Reads back the permitted subtrees of a nameConstraints value written by
/// `nameConstraintsValue`. DNS names point into `val`.
pub fn parseConstraints(val: []const u8) !Constraints {
    var c: Constraints = .{};
    var r: der.Reader = .init(val);
    const nc = try r.expect(Tag.sequence);
    var nr: der.Reader = .init(nc.content);
    while (!nr.atEnd()) {
        const part = try nr.next();
        if (part.tag != Tag.contextConstructed(0)) continue; // excluded subtrees: none written
        var sr: der.Reader = .init(part.content);
        while (!sr.atEnd()) {
            const subtree = try sr.expect(Tag.sequence);
            var gr: der.Reader = .init(subtree.content);
            const base = try gr.next();
            if (base.tag == Tag.contextPrimitive(7)) {
                if (base.content.len != 8 and base.content.len != 32) return error.DerMalformed;
                if (c.n_subnets == max_subnets) return error.TooManyConstraints;
                const half = base.content.len / 2;
                var s: Subnet = .{ .v6 = half == 16 };
                @memcpy(s.addr[0..half], base.content[0..half]);
                @memcpy(s.mask[0..half], base.content[half..]);
                c.subnets[c.n_subnets] = s;
                c.n_subnets += 1;
            } else if (base.tag == Tag.contextPrimitive(2)) {
                if (c.n_dns == max_dns) return error.TooManyConstraints;
                c.dns[c.n_dns] = base.content;
                c.n_dns += 1;
            } else if (base.tag == Tag.contextPrimitive(1)) {
                if (std.mem.eql(u8, base.content, closed_rfc822)) c.closed_rfc822 = true;
            } else if (base.tag == Tag.contextPrimitive(6)) {
                if (std.mem.eql(u8, base.content, closed_uri)) c.closed_uri = true;
            } else if (base.tag == Tag.contextConstructed(4)) {
                var arena_buf: [256]u8 = undefined;
                var fba: std.heap.FixedBufferAllocator = .init(&arena_buf);
                const want = leafSubject(.{ .arena = fba.allocator() }) catch return error.DerMalformed;
                if (std.mem.eql(u8, base.content, want)) c.directory_portal = true;
            }
        }
    }
    return c;
}

test "name constraints read back" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const d: der.Writer = .{ .arena = arena.allocator() };
    var c = testConstraints();
    c.subnets[c.n_subnets] = try Subnet.parse("fd00::/8");
    c.n_subnets += 1;
    c.dns[0] = "portal.home";
    c.n_dns = 1;
    const v = try nameConstraintsValue(d, &c);
    const back = try parseConstraints(v);
    try testing.expectEqual(@as(usize, 3), back.n_subnets);
    try testing.expect(back.ipPermitted(&.{ 10, 8, 0, 9 }));
    try testing.expect(back.ipPermitted(&.{ 127, 0, 0, 1 }));
    try testing.expect(!back.ipPermitted(&.{ 127, 0, 0, 2 }));
    try testing.expect(back.subnets[2].v6);
    try testing.expectEqual(@as(usize, 1), back.n_dns);
    try testing.expect(back.dnsPermitted("x.portal.home"));
    try testing.expect(back.closed_rfc822 and back.closed_uri and back.directory_portal);
}

test "old CA profile is detected" {
    // A CA as made before extKeyUsage and the closed name forms: iPAddress
    // and dNSName subtrees only, no EKU.
    const old_nc = [_]u8{
        0x30, 0x0e, 0xa0, 0x0c,
        0x30, 0x0a, 0x87, 0x08, 127, 0, 0, 1, 255, 255, 255, 255,
        // (no dNSName: still parses)
    };
    const c = try parseConstraints(&old_nc);
    try testing.expect(!c.closed_rfc822 and !c.closed_uri and !c.directory_portal);
    var pki = try TestPki.init(testing.allocator, 1_790_000_000, &.{ip4(127, 0, 0, 1)});
    defer pki.deinit(testing.allocator);
    var info = try parse(pki.ca_der);
    try testing.expect(!isCurrentCaProfile(info, &c));
    const cur = try parseConstraints(info.name_constraints);
    try testing.expect(isCurrentCaProfile(info, &cur));
    info.eku = "";
    try testing.expect(!isCurrentCaProfile(info, &cur));
}

test "leaf never outlives the CA" {
    const gpa = testing.allocator;
    const ca_key = try KeyPair.generateDeterministic(@splat(7));
    const leaf_key = try KeyPair.generateDeterministic(@splat(9));
    const c = testConstraints();
    const ca_made: i64 = 1_790_000_000;
    const ca_der = try buildCa(gpa, .{ .key = &ca_key, .tag = "0123abcd".*, .serial = @splat(0x11), .now = ca_made, .constraints = &c });
    defer gpa.free(ca_der);
    const ca = try parse(ca_der);
    // 100 days before the CA expires: the leaf ends with the CA.
    const now = ca.not_after - 100 * 86400;
    const leaf_der = try buildLeaf(gpa, .{ .key = leaf_key.public_key, .ca_key = &ca_key, .ca_der = ca_der, .sans = &.{ip4(127, 0, 0, 1)}, .serial = @splat(0x22), .now = now });
    defer gpa.free(leaf_der);
    const leaf = try parse(leaf_der);
    try testing.expectEqual(ca.not_after, leaf.not_after);
    try verifySignedBy(leaf, ca);
    // std's verifier agrees.
    const ca_p = try (Certificate{ .buffer = ca_der, .index = 0 }).parse();
    const leaf_p = try (Certificate{ .buffer = leaf_der, .index = 0 }).parse();
    try leaf_p.verify(ca_p, now);
    // An expired CA issues nothing.
    try testing.expectError(error.CaExpired, buildLeaf(gpa, .{ .key = leaf_key.public_key, .ca_key = &ca_key, .ca_der = ca_der, .sans = &.{ip4(127, 0, 0, 1)}, .serial = @splat(0x22), .now = ca.not_after }));
}
