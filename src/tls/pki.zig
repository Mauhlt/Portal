//! On-disk state of Portal's private CA, in %LOCALAPPDATA%\Portal\tls\:
//!
//!   ca.crt    CA certificate (DER)
//!   ca.key    CA private key, DPAPI-protected (current user)
//!   leaf.crt  server certificate (DER), issued by the CA
//!   leaf.key  server private key, DPAPI-protected (current user)
//!
//! The files inherit the ACL of %LOCALAPPDATA% (the user, SYSTEM and
//! Administrators); DPAPI additionally binds the keys to this Windows
//! account. The CA key is decrypted only while signing a new server
//! certificate and wiped right after.
//!
//! What DPAPI (CurrentUser) does and does not protect: the blobs are
//! useless on another machine or account, and to anyone reading the disk
//! offline without the user's password. They are NOT protected from
//! software running as this user: any such process can call
//! CryptUnprotectData and get the CA key (the "purpose" entropy is not a
//! secret; it is in this file). That is the residual risk the CA's
//! profile limits: a stolen CA key can only mint TLS server certificates
//! for the permitted addresses (see x509.zig).
//!
//! Why there is no "prompt on unprotect" option
//! (CRYPTPROTECT_PROMPT_ON_UNPROTECT): it makes CryptUnprotectData show a
//! modal GUI dialog, which (a) blocks `portal run` whenever the server
//! certificate is renewed, including unattended starts and sessions
//! without a desktop (with CRYPTPROTECT_UI_FORBIDDEN the call fails with
//! ERROR_PASSWORD_RESTRICTION, checked on Windows 11); (b) at the
//! default "medium" security level is a click-through confirmation,
//! which any malware running as the user can trigger and wait for, so it
//! adds little against the threat above; and (c) only the
//! "high" level adds a password, which is an extra secret to manage once
//! a year. A user who wants the CA key off this machine can instead keep
//! %LOCALAPPDATA%\Portal\tls\ca.key offline and restore it before the
//! server certificate is due for renewal (`portal ca` shows when).
//!
//! Also produces the device exports: portal-ca.cer (DER), portal-ca.pem
//! and portal-ca.mobileconfig (Apple configuration profile).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const x509 = @import("x509.zig");
const dpapi = @import("dpapi.zig");
const fsutil = @import("../fsutil.zig");

pub const KeyPair = x509.KeyPair;

const ca_key_purpose = "Portal CA private key v1";
const leaf_key_purpose = "Portal server private key v1";
const key_magic = "PORTAL-KEY-V1\n";
const max_file = 64 * 1024;

pub const Store = struct {
    gpa: Allocator,
    io: Io,
    /// ...\Portal\tls
    dir: []const u8,

    fn path(s: Store, buf: []u8, name: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}\\{s}", .{ s.dir, name });
    }

    fn read(s: Store, name: []const u8) ![]u8 {
        var buf: [1024]u8 = undefined;
        return Io.Dir.cwd().readFileAlloc(s.io, try s.path(&buf, name), s.gpa, .limited(max_file));
    }

    fn exists(s: Store, name: []const u8) bool {
        const data = s.read(name) catch return false;
        s.gpa.free(data);
        return true;
    }

    /// Write to a temporary file, then atomically replace (fsutil).
    fn writeAtomic(s: Store, name: []const u8, data: []const u8) !void {
        try Io.Dir.cwd().createDirPath(s.io, s.dir);
        var pbuf: [1024]u8 = undefined;
        fsutil.writeAtomic(s.gpa, s.io, try s.path(&pbuf, name), data) catch |err| return switch (err) {
            error.ReplaceFailed => error.TlsStoreWriteFailed,
            else => err,
        };
    }

    fn writeKey(s: Store, name: []const u8, kp: KeyPair, purpose: []const u8) !void {
        var secret = kp.secret_key.toBytes();
        defer std.crypto.secureZero(u8, &secret);
        const sealed = try dpapi.protect(s.gpa, &secret, purpose);
        defer s.gpa.free(sealed);
        const data = try std.mem.concat(s.gpa, u8, &.{ key_magic, sealed });
        defer s.gpa.free(data);
        try s.writeAtomic(name, data);
    }

    /// Reads a DPAPI-protected key and checks it matches `public_key`.
    fn readKey(s: Store, name: []const u8, purpose: []const u8, public_key: []const u8) !KeyPair {
        const data = try s.read(name);
        defer s.gpa.free(data);
        if (!std.mem.startsWith(u8, data, key_magic)) return error.BadKeyFile;
        const plain = try dpapi.unprotect(s.gpa, data[key_magic.len..], purpose);
        defer {
            std.crypto.secureZero(u8, plain);
            s.gpa.free(plain);
        }
        if (plain.len != 32) return error.BadKeyFile;
        var sk = try x509.Ecdsa.SecretKey.fromBytes(plain[0..32].*);
        defer std.crypto.secureZero(u8, &sk.bytes);
        var kp = try KeyPair.fromSecretKey(sk);
        errdefer wipeKey(&kp);
        if (!std.mem.eql(u8, &kp.public_key.toUncompressedSec1(), public_key)) return error.KeyDoesNotMatchCertificate;
        return kp;
    }
};

pub fn wipeKey(kp: *KeyPair) void {
    std.crypto.secureZero(u8, &kp.secret_key.bytes);
}

fn randomKey(io: Io) !KeyPair {
    while (true) {
        var seed: [32]u8 = undefined;
        try io.randomSecure(&seed);
        defer std.crypto.secureZero(u8, &seed);
        return KeyPair.generateDeterministic(seed) catch continue;
    }
}

// ---------------------------------------------------------------------- CA

pub const Ca = struct {
    der: []u8,
    info: x509.Info,
    constraints: x509.Constraints,

    pub fn deinit(ca: *Ca, gpa: Allocator) void {
        gpa.free(ca.der);
    }

    /// False for a CA made by an older version (no extKeyUsage, open
    /// rfc822Name/URI/directoryName forms). It still works; upgrading
    /// means `portal ca init --force` and trusting the new CA again.
    pub fn currentProfile(ca: *const Ca) bool {
        return x509.isCurrentCaProfile(ca.info, &ca.constraints);
    }

    /// Seconds until the CA expires (negative once it has).
    pub fn secondsLeft(ca: *const Ca, now: i64) i64 {
        return ca.info.not_after -| now;
    }

    pub fn commonName(ca: *const Ca) []const u8 {
        // Last RDN of the subject is the CN we wrote.
        const s = ca.info.subject_raw;
        const marker = "Portal Local CA (";
        const i = std.mem.indexOf(u8, s, marker) orelse return "Portal Local CA";
        const end = std.mem.indexOfScalarPos(u8, s, i, ')') orelse return "Portal Local CA";
        return s[i .. end + 1];
    }
};

/// Warn when the CA has less than this left: a new server certificate
/// (397 days) would then be cut short at the CA's expiry.
pub const ca_warn_before_s: i64 = 400 * 86400;

/// Test hook: makes caFromDer fail, to exercise the callers' error paths.
var test_fail_ca_from_der = false;

/// Wraps `der_bytes` into a Ca. Takes ownership only on success: on error
/// the caller still owns (and frees) `der_bytes`.
fn caFromDer(der_bytes: []u8) !Ca {
    if (@import("builtin").is_test and test_fail_ca_from_der) return error.NotAPortalCa;
    const info = try x509.parse(der_bytes);
    if (!info.is_ca or info.name_constraints.len == 0) return error.NotAPortalCa;
    try x509.verifySignedBy(info, info);
    return .{ .der = der_bytes, .info = info, .constraints = try x509.parseConstraints(info.name_constraints) };
}

/// The CA, or null if none has been created yet.
pub fn loadCa(s: Store) !?Ca {
    const der_bytes = s.read("ca.crt") catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    errdefer s.gpa.free(der_bytes);
    return try caFromDer(der_bytes);
}

pub fn defaultConstraints() x509.Constraints {
    var c: x509.Constraints = .{};
    for (x509.default_permits) |p| {
        c.subnets[c.n_subnets] = x509.Subnet.parse(p) catch unreachable;
        c.n_subnets += 1;
    }
    return c;
}

/// Creates a new CA (key + certificate). Refuses to replace an existing one
/// unless `force`: every device would have to trust the new CA again.
pub fn initCa(s: Store, constraints: *const x509.Constraints, now: i64, force: bool) !Ca {
    if (!force and (s.exists("ca.crt") or s.exists("ca.key"))) return error.CaExists;
    if (constraints.n_subnets == 0) return error.NoPermittedSubnets;
    var key = try randomKey(s.io);
    defer wipeKey(&key);
    var rnd: [4 + 16 + 32]u8 = undefined;
    try s.io.randomSecure(&rnd);
    const tag = std.fmt.bytesToHex(rnd[0..4], .lower);
    const der_bytes = try x509.buildCa(s.gpa, .{
        .key = &key,
        .tag = tag,
        .serial = rnd[4..20].*,
        .now = now,
        .constraints = constraints,
        .noise = rnd[20..52].*,
    });
    // Owned here until caFromDer succeeds (it never frees on error).
    errdefer s.gpa.free(der_bytes);
    // Key first: a certificate without its key would be useless.
    try s.writeKey("ca.key", key, ca_key_purpose);
    try s.writeAtomic("ca.crt", der_bytes);
    return caFromDer(der_bytes);
}

// -------------------------------------------------------------------- leaf

pub const Leaf = struct {
    der: []u8,
    key: KeyPair,
    /// Why a new certificate was issued, or null if the stored one was kept.
    renewed: ?[]const u8,
    not_after: i64,

    pub fn deinit(l: *Leaf, gpa: Allocator) void {
        wipeKey(&l.key);
        gpa.free(l.der);
    }
};

/// Returns a server certificate for exactly `sans`, issued by `ca` and
/// valid for at least 30 more days, reusing the stored one when possible.
pub fn ensureLeaf(s: Store, ca: *const Ca, sans: []const x509.SanEntry, now: i64) !Leaf {
    var arena: std.heap.ArenaAllocator = .init(s.gpa);
    defer arena.deinit();
    const want_san = try x509.sanValue(.{ .arena = arena.allocator() }, sans);
    const want_subject = try x509.leafSubject(.{ .arena = arena.allocator() });

    const reason: []const u8 = check: {
        const der_bytes = s.read("leaf.crt") catch break :check "no server certificate yet";
        var keep = false;
        defer if (!keep) s.gpa.free(der_bytes);
        const info = x509.parse(der_bytes) catch break :check "stored certificate unreadable";
        x509.verifySignedBy(info, ca.info) catch break :check "issued by a different CA";
        if (info.not_after > ca.info.not_after) break :check "outlives the CA";
        // A certificate already cut short at the CA's expiry cannot get
        // any longer: keep it rather than re-issue on every start.
        if (info.not_after -| now < x509.renew_before_s and info.not_after < ca.info.not_after)
            break :check "expires within 30 days";
        if (info.not_before > now +| 300) break :check "not valid yet (clock changed?)";
        if (!std.mem.eql(u8, info.san, want_san)) break :check "addresses changed";
        if (!std.mem.eql(u8, info.subject_raw, want_subject)) break :check "certificate profile changed";
        const key = s.readKey("leaf.key", leaf_key_purpose, info.public_key) catch break :check "key unreadable";
        keep = true;
        return .{ .der = der_bytes, .key = key, .renewed = null, .not_after = info.not_after };
    };

    var ca_key = try s.readKey("ca.key", ca_key_purpose, ca.info.public_key);
    defer wipeKey(&ca_key);
    var key = try randomKey(s.io);
    errdefer wipeKey(&key);
    var rnd: [16 + 32]u8 = undefined;
    try s.io.randomSecure(&rnd);
    const der_bytes = try x509.buildLeaf(s.gpa, .{
        .key = key.public_key,
        .ca_key = &ca_key,
        .ca_der = ca.der,
        .sans = sans,
        .serial = rnd[0..16].*,
        .now = now,
        .noise = rnd[16..48].*,
    });
    errdefer s.gpa.free(der_bytes);
    try s.writeKey("leaf.key", key, leaf_key_purpose);
    try s.writeAtomic("leaf.crt", der_bytes);
    const info = try x509.parse(der_bytes);
    return .{ .der = der_bytes, .key = key, .renewed = reason, .not_after = info.not_after };
}

// ------------------------------------------------------------------ export

/// portal-ca.pem (shared/pki/pem.zig, also the native client's writer).
pub const pem = @import("shared").pki.pem.alloc;

/// A UUID derived from the CA certificate, so the same CA always yields the
/// same profile UUIDs.
fn stableUuid(label: []const u8, der_bytes: []const u8) [36]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(label);
    h.update(der_bytes);
    var d = h.finalResult();
    d[6] = (d[6] & 0x0f) | 0x80; // version 8 (custom, RFC 9562)
    d[8] = (d[8] & 0x3f) | 0x80; // RFC variant
    const hex = std.fmt.bytesToHex(d[0..16], .upper);
    var out: [36]u8 = undefined;
    @memcpy(out[0..8], hex[0..8]);
    out[8] = '-';
    @memcpy(out[9..13], hex[8..12]);
    out[13] = '-';
    @memcpy(out[14..18], hex[12..16]);
    out[18] = '-';
    @memcpy(out[19..23], hex[16..20]);
    out[23] = '-';
    @memcpy(out[24..36], hex[20..32]);
    return out;
}

pub const profile_identifier = "local.portal.ca";

/// Apple configuration profile with the CA as a com.apple.security.root
/// payload. Installing it on iOS/iPadOS also requires enabling full trust in
/// Settings > General > About > Certificate Trust Settings.
pub fn mobileconfig(gpa: Allocator, ca: *const Ca) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const b64 = try gpa.alloc(u8, enc.calcSize(ca.der.len));
    defer gpa.free(b64);
    _ = enc.encode(b64, ca.der);
    var wrapped: std.ArrayList(u8) = .empty;
    defer wrapped.deinit(gpa);
    var i: usize = 0;
    while (i < b64.len) : (i += 52) {
        try wrapped.appendSlice(gpa, "\t\t\t");
        try wrapped.appendSlice(gpa, b64[i..@min(i + 52, b64.len)]);
        try wrapped.append(gpa, '\n');
    }
    const cn = ca.commonName(); // "Portal Local CA (<hex>)": no XML specials
    const profile_uuid = stableUuid("portal profile", ca.der);
    const payload_uuid = stableUuid("portal root payload", ca.der);
    return std.fmt.allocPrint(gpa,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<plist version="1.0">
        \\<dict>
        \\  <key>PayloadContent</key>
        \\  <array>
        \\    <dict>
        \\      <key>PayloadCertificateFileName</key>
        \\      <string>portal-ca.cer</string>
        \\      <key>PayloadContent</key>
        \\      <data>
        \\{s}      </data>
        \\      <key>PayloadDescription</key>
        \\      <string>Root certificate of this desktop's Portal (private, name-constrained to the Portal network).</string>
        \\      <key>PayloadDisplayName</key>
        \\      <string>{s}</string>
        \\      <key>PayloadIdentifier</key>
        \\      <string>{s}.root</string>
        \\      <key>PayloadType</key>
        \\      <string>com.apple.security.root</string>
        \\      <key>PayloadUUID</key>
        \\      <string>{s}</string>
        \\      <key>PayloadVersion</key>
        \\      <integer>1</integer>
        \\    </dict>
        \\  </array>
        \\  <key>PayloadDescription</key>
        \\  <string>Lets this device verify the HTTPS connection to Portal on your desktop.</string>
        \\  <key>PayloadDisplayName</key>
        \\  <string>{s}</string>
        \\  <key>PayloadIdentifier</key>
        \\  <string>{s}</string>
        \\  <key>PayloadRemovalDisallowed</key>
        \\  <false/>
        \\  <key>PayloadType</key>
        \\  <string>Configuration</string>
        \\  <key>PayloadUUID</key>
        \\  <string>{s}</string>
        \\  <key>PayloadVersion</key>
        \\  <integer>1</integer>
        \\</dict>
        \\</plist>
        \\
    , .{ wrapped.items, cn, profile_identifier, &payload_uuid, cn, profile_identifier, &profile_uuid });
}

pub const Exported = struct {
    fingerprint: [32]u8,
};

/// Writes portal-ca.cer, portal-ca.pem and portal-ca.mobileconfig to `out_dir`.
pub fn exportCa(gpa: Allocator, io: Io, ca: *const Ca, out_dir: []const u8) !Exported {
    try Io.Dir.cwd().createDirPath(io, out_dir);
    var buf: [1024]u8 = undefined;
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.bufPrint(&buf, "{s}\\portal-ca.cer", .{out_dir}), .data = ca.der });
    const p = try pem(gpa, ca.der);
    defer gpa.free(p);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.bufPrint(&buf, "{s}\\portal-ca.pem", .{out_dir}), .data = p });
    const mc = try mobileconfig(gpa, ca);
    defer gpa.free(mc);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.bufPrint(&buf, "{s}\\portal-ca.mobileconfig", .{out_dir}), .data = mc });
    return .{ .fingerprint = x509.fingerprint(ca.der) };
}

pub const iphone_steps =
    \\On an iPhone or iPad (once per device):
    \\  1. Open the profile (portal-ca.mobileconfig) on the device, e.g. from
    \\     http://<desktop WireGuard IP>:<port+1>/ while pairing is open,
    \\     or AirDrop / Mail the file. Tap Allow.
    \\  2. Settings > General > VPN & Device Management > "Portal Local CA ..."
    \\     > Install (enter the passcode), then Install again.
    \\  3. Settings > General > About > Certificate Trust Settings >
    \\     enable full trust for "Portal Local CA ...". Without this step
    \\     Safari will not trust Portal.
    \\  Compare the SHA-256 fingerprint shown in the profile details with
    \\  the one printed here.
    \\
;

// -------------------------------------------------------------------- tests

const testing = std.testing;

test "pki: CA init, leaf issue/reuse/renew, export" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [1024]u8 = undefined;
    const base_len = try tmp.dir.realPath(io, &path_buf);
    const base = path_buf[0..base_len];
    const dir = try std.fmt.allocPrint(gpa, "{s}\\tls", .{base});
    defer gpa.free(dir);
    const s: Store = .{ .gpa = gpa, .io = io, .dir = dir };

    try testing.expect((try loadCa(s)) == null);
    const now: i64 = 1_790_000_000;
    var c = defaultConstraints();
    var ca = try initCa(s, &c, now, false);
    defer ca.deinit(gpa);
    try testing.expectError(error.CaExists, initCa(s, &c, now, false));
    try testing.expect(ca.constraints.ipPermitted(&.{ 10, 8, 0, 1 }));
    try testing.expect(std.mem.startsWith(u8, ca.commonName(), "Portal Local CA ("));

    // Key files are DPAPI blobs, not raw keys.
    const key_file = try s.read("ca.key");
    defer gpa.free(key_file);
    try testing.expect(std.mem.startsWith(u8, key_file, key_magic));
    try testing.expect(key_file.len > key_magic.len + 100);

    var loaded = (try loadCa(s)).?;
    defer loaded.deinit(gpa);
    try testing.expectEqualSlices(u8, ca.der, loaded.der);

    const sans1 = [_]x509.SanEntry{x509.ip4(10, 8, 0, 1)};
    var l1 = try ensureLeaf(s, &ca, &sans1, now);
    defer l1.deinit(gpa);
    try testing.expect(l1.renewed != null);
    var l2 = try ensureLeaf(s, &ca, &sans1, now + 86400);
    defer l2.deinit(gpa);
    try testing.expect(l2.renewed == null); // reused
    try testing.expectEqualSlices(u8, l1.der, l2.der);
    try testing.expectEqualSlices(u8, &l1.key.secret_key.toBytes(), &l2.key.secret_key.toBytes());
    const sans2 = [_]x509.SanEntry{ x509.ip4(10, 8, 0, 1), x509.ip4(127, 0, 0, 1) };
    var l3 = try ensureLeaf(s, &ca, &sans2, now + 86400);
    defer l3.deinit(gpa);
    try testing.expectEqualStrings("addresses changed", l3.renewed.?);
    var l4 = try ensureLeaf(s, &ca, &sans2, now + 380 * 86400);
    defer l4.deinit(gpa);
    try testing.expectEqualStrings("expires within 30 days", l4.renewed.?);
    try x509.verifySignedBy(try x509.parse(l4.der), ca.info);

    // A new CA invalidates the old leaf.
    var ca2 = try initCa(s, &c, now, true);
    defer ca2.deinit(gpa);
    var l5 = try ensureLeaf(s, &ca2, &sans2, now + 380 * 86400);
    defer l5.deinit(gpa);
    try testing.expectEqualStrings("issued by a different CA", l5.renewed.?);

    const out_dir = try std.fmt.allocPrint(gpa, "{s}\\export", .{base});
    defer gpa.free(out_dir);
    const ex = try exportCa(gpa, io, &ca2, out_dir);
    try testing.expectEqualSlices(u8, &x509.fingerprint(ca2.der), &ex.fingerprint);
    var fbuf: [1100]u8 = undefined;
    const cer = try Io.Dir.cwd().readFileAlloc(io, try std.fmt.bufPrint(&fbuf, "{s}\\portal-ca.cer", .{out_dir}), gpa, .limited(max_file));
    defer gpa.free(cer);
    try testing.expectEqualSlices(u8, ca2.der, cer);
    const mc = try Io.Dir.cwd().readFileAlloc(io, try std.fmt.bufPrint(&fbuf, "{s}\\portal-ca.mobileconfig", .{out_dir}), gpa, .limited(max_file));
    defer gpa.free(mc);
    try testing.expect(std.mem.indexOf(u8, mc, "<string>com.apple.security.root</string>") != null);
    try testing.expect(std.mem.indexOf(u8, mc, "<string>local.portal.ca</string>") != null);
    // Same CA -> same profile bytes (stable UUIDs).
    const mc2 = try mobileconfig(gpa, &ca2);
    defer gpa.free(mc2);
    try testing.expectEqualStrings(mc, mc2);
    // The <data> block decodes back to the certificate.
    const start = std.mem.indexOf(u8, mc, "<data>").? + 6;
    const end = std.mem.indexOf(u8, mc, "</data>").?;
    const dec = std.base64.standard.decoderWithIgnore(" \t\r\n");
    var raw: [2048]u8 = undefined;
    const n = try dec.decode(&raw, mc[start..end]);
    try testing.expectEqualSlices(u8, ca2.der, raw[0..n]);
}

test "pki: CA load/create failures free the certificate exactly once" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [1024]u8 = undefined;
    const base_len = try tmp.dir.realPath(io, &path_buf);
    const dir = try std.fmt.allocPrint(gpa, "{s}\\tls", .{path_buf[0..base_len]});
    defer gpa.free(dir);
    const s: Store = .{ .gpa = gpa, .io = io, .dir = dir };
    const c = defaultConstraints();

    // initCa: caFromDer fails after the certificate was built and written.
    // (Before the fix both caFromDer's errdefer and initCa's freed it; the
    // testing allocator reports the double free.)
    test_fail_ca_from_der = true;
    defer test_fail_ca_from_der = false;
    try testing.expectError(error.NotAPortalCa, initCa(s, &c, 1_790_000_000, false));
    try testing.expectError(error.NotAPortalCa, loadCa(s));
    test_fail_ca_from_der = false;

    // loadCa on a corrupt file and on a certificate that is not a CA.
    try s.writeAtomic("ca.crt", "not a certificate");
    try testing.expectError(error.DerMalformed, loadCa(s));
    var pki = try x509.TestPki.init(gpa, 1_790_000_000, &.{x509.ip4(127, 0, 0, 1)});
    defer pki.deinit(gpa);
    try s.writeAtomic("ca.crt", pki.leaf_der);
    try testing.expectError(error.NotAPortalCa, loadCa(s));
}

test "pki: CA expiry caps the server certificate and is reported" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [1024]u8 = undefined;
    const base_len = try tmp.dir.realPath(io, &path_buf);
    const dir = try std.fmt.allocPrint(gpa, "{s}\\tls", .{path_buf[0..base_len]});
    defer gpa.free(dir);
    const s: Store = .{ .gpa = gpa, .io = io, .dir = dir };
    const c = defaultConstraints();
    var ca = try initCa(s, &c, 1_790_000_000, false);
    defer ca.deinit(gpa);
    try testing.expect(ca.currentProfile());
    try testing.expect(ca.secondsLeft(1_790_000_000) > ca_warn_before_s);

    const late = ca.info.not_after - 200 * 86400;
    try testing.expect(ca.secondsLeft(late) < ca_warn_before_s);
    const sans = [_]x509.SanEntry{x509.ip4(127, 0, 0, 1)};
    var l1 = try ensureLeaf(s, &ca, &sans, late);
    defer l1.deinit(gpa);
    try testing.expectEqual(ca.info.not_after, l1.not_after);
    // 10 days before the end: capped, so kept instead of re-issued.
    var l2 = try ensureLeaf(s, &ca, &sans, ca.info.not_after - 10 * 86400);
    defer l2.deinit(gpa);
    try testing.expect(l2.renewed == null);
    try testing.expect(ca.secondsLeft(ca.info.not_after + 1) < 0);
}
