//! Signed package manifests for Portal sync (docs/sync-design.md), shared by
//! the desktop (publish, serving) and devices (verification, install).
//!
//! A manifest is a canonical, deterministic ASCII text. There is exactly one
//! valid encoding of any manifest: `parse` rejects anything that does not
//! re-encode to the very same bytes, so the bytes that were signed are the
//! bytes that are interpreted, with no JSON-style ambiguity (duplicate keys,
//! whitespace, number forms, escapes, ordering).
//!
//!     portal-manifest-v1\n
//!     package <id>\n                [a-z0-9-]{1,32}
//!     version <version>\n           [0-9A-Za-z.+-]{1,64}, no "..", no
//!                                   leading/trailing '.', not a device name
//!     kind <data|executable>\n
//!     sequence <n>\n                1..2^63-1, monotonic per package
//!     created <unix seconds>\n      0..2^63-1
//!     min-client <d[.d[.d[.d]]]>\n  numeric dotted version
//!     files <count>\n               0..max_files
//!     file <size> <sha256> <path>\n count times, sorted by path (bytes)
//!     end\n
//!
//! Numbers are decimal without leading zeros ("0" is the only one starting
//! with 0). The SHA-256 is 64 lowercase hex digits. The path is the rest of
//! the line (it may contain inner spaces) and must pass `validPath`. Lines
//! end in a single LF; no CR, tabs, blank lines or trailing data.
//!
//! The signature is Ed25519 (std.crypto.sign.Ed25519, cofactorless
//! verifyStrict) over the exact manifest bytes, made with the desktop's
//! release key. The publisher key fingerprint is the SHA-256 of the 32-byte
//! public key.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Ed25519 = std.crypto.sign.Ed25519;

pub const header = "portal-manifest-v1";
pub const max_files = 4096;
/// Bytes of one relative path (UTF-8 is not allowed: ASCII only).
pub const max_path = 260;
pub const max_depth = 32;
pub const max_package_id = 32;
pub const max_version = 64;
/// Total size of one package version (all files).
pub const max_package_bytes: u64 = 8 << 30;
/// Upper bound of an encoded manifest (header + max_files full lines).
pub const max_manifest_bytes = 2 << 20;
pub const signature_len = Ed25519.Signature.encoded_length;
pub const public_key_len = Ed25519.PublicKey.encoded_length;

/// The packages Portal knows by name (others with a valid id are allowed).
pub const known_packages = [_][]const u8{ "portal-client", "stt-local", "stt-model", "stt-adapter", "npu-probe" };
/// Offered right after a laptop is paired ("Install voice model?").
pub const voice_packages = [_][]const u8{ "stt-local", "stt-model", "stt-adapter" };

pub fn isVoicePackage(id: []const u8) bool {
    for (voice_packages) |v| if (std.mem.eql(u8, v, id)) return true;
    return false;
}

pub const Kind = enum {
    /// Model weights, adapters: install automatically.
    data,
    /// Programs: every new version needs approval on the device.
    executable,
};

pub const File = struct {
    /// Relative, '/'-separated, validated (`validPath`).
    path: []const u8,
    size: u64,
    sha256: [32]u8,
};

pub const Manifest = struct {
    package: []const u8,
    version: []const u8,
    kind: Kind,
    sequence: u64,
    created: i64,
    min_client: []const u8,
    /// Sorted by path; owned by the Manifest (the strings are not: they
    /// point into the parsed bytes, or into the caller's data for `encode`).
    files: []File,

    pub fn deinit(m: *Manifest, gpa: Allocator) void {
        gpa.free(m.files);
        m.files = &.{};
    }

    pub fn totalSize(m: *const Manifest) u64 {
        var t: u64 = 0;
        for (m.files) |f| t +|= f.size;
        return t;
    }
};

pub const Error = error{
    BadManifest,
    NotCanonical,
    BadPackageId,
    BadVersion,
    BadPath,
    DuplicatePath,
    TooManyFiles,
    TooLarge,
    OutOfMemory,
};

// ------------------------------------------------------------ validation

pub fn validPackageId(id: []const u8) bool {
    if (id.len == 0 or id.len > max_package_id) return false;
    for (id) |c| switch (c) {
        'a'...'z', '0'...'9', '-' => {},
        else => return false,
    };
    if (id[0] == '-' or id[id.len - 1] == '-') return false;
    return !reservedName(id);
}

pub fn validVersion(v: []const u8) bool {
    if (v.len == 0 or v.len > max_version) return false;
    for (v) |c| switch (c) {
        '0'...'9', 'A'...'Z', 'a'...'z', '.', '+', '-' => {},
        else => return false,
    };
    if (std.mem.indexOf(u8, v, "..") != null) return false;
    if (v[0] == '.' or v[v.len - 1] == '.') return false;
    return !reservedName(v);
}

/// Numeric dotted version: 1 to 4 parts of at most 9 digits, no leading
/// zeros ("0.1.0", "2", "10.0.3.1").
pub fn validClientVersion(v: []const u8) bool {
    if (v.len == 0 or v.len > 39) return false;
    var it = std.mem.splitScalar(u8, v, '.');
    var parts: usize = 0;
    while (it.next()) |p| {
        parts += 1;
        if (parts > 4 or !canonicalUint(p, 9)) return false;
    }
    return true;
}

/// -1, 0, 1 for a < b, a == b, a > b. Both must be validClientVersion;
/// missing parts count as 0.
pub fn compareClientVersions(a: []const u8, b: []const u8) i2 {
    var ia = std.mem.splitScalar(u8, a, '.');
    var ib = std.mem.splitScalar(u8, b, '.');
    for (0..4) |_| {
        const x = std.fmt.parseInt(u32, ia.next() orelse "0", 10) catch 0;
        const y = std.fmt.parseInt(u32, ib.next() orelse "0", 10) catch 0;
        if (x < y) return -1;
        if (x > y) return 1;
    }
    return 0;
}

fn canonicalUint(s: []const u8, max_digits: usize) bool {
    if (s.len == 0 or s.len > max_digits) return false;
    for (s) |c| if (c < '0' or c > '9') return false;
    return !(s.len > 1 and s[0] == '0');
}

/// Windows device names, matched case-insensitively against the part of a
/// name before its first '.', with trailing spaces ignored ("nul.txt",
/// "COM1 .log", "conin$").
pub fn reservedName(name: []const u8) bool {
    const dot = std.mem.indexOfScalar(u8, name, '.') orelse name.len;
    const stem = std.mem.trimEnd(u8, name[0..dot], " ");
    const fixed = [_][]const u8{ "con", "prn", "aux", "nul", "conin$", "conout$", "clock$" };
    for (fixed) |r| if (std.ascii.eqlIgnoreCase(stem, r)) return true;
    if (stem.len == 4 and (std.ascii.eqlIgnoreCase(stem[0..3], "com") or std.ascii.eqlIgnoreCase(stem[0..3], "lpt")) and
        stem[3] >= '0' and stem[3] <= '9') return true;
    return false;
}

/// Why a path is refused (for messages and tests).
pub const PathProblem = enum {
    ok,
    empty,
    too_long,
    absolute,
    drive,
    backslash,
    empty_component,
    dot_component,
    bad_char,
    alternate_stream,
    reserved_name,
    trailing_dot_or_space,
    leading_space,
    too_deep,
};

/// A path inside a package version folder: relative, '/'-separated,
/// normalised, printable ASCII, and harmless on Windows.
pub fn checkPath(p: []const u8) PathProblem {
    if (p.len == 0) return .empty;
    if (p.len > max_path) return .too_long;
    if (p[0] == '/') return .absolute;
    if (p.len >= 2 and std.ascii.isAlphabetic(p[0]) and p[1] == ':') return .drive;
    var depth: usize = 0;
    var it = std.mem.splitScalar(u8, p, '/');
    while (it.next()) |c| {
        depth += 1;
        if (depth > max_depth) return .too_deep;
        if (c.len == 0) return .empty_component;
        if (std.mem.eql(u8, c, ".") or std.mem.eql(u8, c, "..")) return .dot_component;
        for (c) |ch| switch (ch) {
            ':' => return .alternate_stream,
            '\\' => return .backslash,
            0...0x1f, 0x7f...0xff, '<', '>', '"', '|', '?', '*' => return .bad_char,
            else => {},
        };
        if (c[0] == ' ') return .leading_space;
        const last = c[c.len - 1];
        if (last == '.' or last == ' ') return .trailing_dot_or_space;
        if (reservedName(c)) return .reserved_name;
    }
    return .ok;
}

pub fn validPath(p: []const u8) bool {
    return checkPath(p) == .ok;
}

fn lowerEql(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn lessIgnoreCase(_: void, a: []const u8, b: []const u8) bool {
    return std.ascii.lessThanIgnoreCase(a, b);
}

/// Rejects two paths that name the same file on a case-insensitive file
/// system, and a file that is also used as a folder ("a" and "a/b").
fn checkUnique(gpa: Allocator, files: []const File) Error!void {
    if (files.len < 2) return;
    // Every file path, plus every folder prefix of every path (marked).
    const Name = struct { s: []const u8, dir: bool };
    var names: std.ArrayList(Name) = .empty;
    defer names.deinit(gpa);
    for (files) |f| {
        try names.append(gpa, .{ .s = f.path, .dir = false });
        var i: usize = 0;
        while (std.mem.indexOfScalarPos(u8, f.path, i, '/')) |slash| : (i = slash + 1) {
            try names.append(gpa, .{ .s = f.path[0..slash], .dir = true });
        }
    }
    std.mem.sort(Name, names.items, {}, struct {
        fn lt(_: void, a: Name, b: Name) bool {
            if (std.ascii.eqlIgnoreCase(a.s, b.s)) return @intFromBool(a.dir) < @intFromBool(b.dir);
            return std.ascii.lessThanIgnoreCase(a.s, b.s);
        }
    }.lt);
    for (names.items[1..], 1..) |n, i| {
        const prev = names.items[i - 1];
        if (!lowerEql(prev.s, n.s)) continue;
        // Two folders with the same name are fine only if spelled the same.
        if (prev.dir and n.dir and std.mem.eql(u8, prev.s, n.s)) continue;
        return error.DuplicatePath;
    }
}

// --------------------------------------------------------------- encoding

fn lessPath(_: void, a: File, b: File) bool {
    return std.mem.lessThan(u8, a.path, b.path);
}

/// Validates `m` (sorting `m.files` in place) and returns its canonical
/// encoding. Caller frees.
pub fn encode(gpa: Allocator, m: *Manifest) Error![]u8 {
    if (!validPackageId(m.package)) return error.BadPackageId;
    if (!validVersion(m.version)) return error.BadVersion;
    if (!validClientVersion(m.min_client)) return error.BadManifest;
    if (m.sequence == 0 or m.sequence > std.math.maxInt(i63)) return error.BadManifest;
    if (m.created < 0) return error.BadManifest;
    if (m.files.len > max_files) return error.TooManyFiles;
    var total: u64 = 0;
    for (m.files) |f| {
        if (!validPath(f.path)) return error.BadPath;
        if (f.size > max_package_bytes) return error.TooLarge;
        total += f.size;
        if (total > max_package_bytes) return error.TooLarge;
    }
    std.mem.sort(File, m.files, {}, lessPath);
    for (m.files[1..], 1..) |f, i| if (std.mem.eql(u8, f.path, m.files[i - 1].path)) return error.DuplicatePath;
    try checkUnique(gpa, m.files);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.print(gpa, header ++ "\npackage {s}\nversion {s}\nkind {t}\nsequence {d}\ncreated {d}\nmin-client {s}\nfiles {d}\n", .{
        m.package, m.version, m.kind, m.sequence, m.created, m.min_client, m.files.len,
    });
    for (m.files) |f| try out.print(gpa, "file {d} {x} {s}\n", .{ f.size, &f.sha256, f.path });
    try out.appendSlice(gpa, "end\n");
    if (out.items.len > max_manifest_bytes) return error.TooLarge;
    return out.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------- parsing

const Lines = struct {
    rest: []const u8,

    /// The next line without its LF; error if there is no LF or the line
    /// holds a byte outside printable ASCII.
    fn next(l: *Lines) Error![]const u8 {
        const nl = std.mem.indexOfScalar(u8, l.rest, '\n') orelse return error.BadManifest;
        const line = l.rest[0..nl];
        for (line) |c| if (c < 0x20 or c > 0x7e) return error.BadManifest;
        l.rest = l.rest[nl + 1 ..];
        return line;
    }

    fn field(l: *Lines, comptime key: []const u8) Error![]const u8 {
        const line = try l.next();
        if (!std.mem.startsWith(u8, line, key ++ " ")) return error.BadManifest;
        const v = line[key.len + 1 ..];
        if (v.len == 0 or std.mem.indexOfScalar(u8, v, ' ') != null) return error.BadManifest;
        return v;
    }
};

fn parseUint(s: []const u8, max: u64) Error!u64 {
    if (!canonicalUint(s, 19)) return error.BadManifest;
    const v = std.fmt.parseInt(u64, s, 10) catch return error.BadManifest;
    if (v > max) return error.BadManifest;
    return v;
}

fn parseHash(s: []const u8) Error![32]u8 {
    if (s.len != 64) return error.BadManifest;
    for (s) |c| switch (c) {
        '0'...'9', 'a'...'f' => {},
        else => return error.BadManifest,
    };
    var h: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&h, s) catch return error.BadManifest;
    return h;
}

/// Strict parse of manifest `bytes`. The result's strings point into
/// `bytes`; free with `deinit`. Anything not in canonical form, out of
/// range, unsorted, or with a refused path is an error.
pub fn parse(gpa: Allocator, bytes: []const u8) Error!Manifest {
    if (bytes.len > max_manifest_bytes) return error.TooLarge;
    var l: Lines = .{ .rest = bytes };
    if (!std.mem.eql(u8, try l.next(), header)) return error.BadManifest;
    const package = try l.field("package");
    if (!validPackageId(package)) return error.BadPackageId;
    const version = try l.field("version");
    if (!validVersion(version)) return error.BadVersion;
    const kind = std.meta.stringToEnum(Kind, try l.field("kind")) orelse return error.BadManifest;
    const sequence = try parseUint(try l.field("sequence"), std.math.maxInt(i63));
    if (sequence == 0) return error.BadManifest;
    const created: i64 = @intCast(try parseUint(try l.field("created"), std.math.maxInt(i63)));
    const min_client = try l.field("min-client");
    if (!validClientVersion(min_client)) return error.BadManifest;
    const n = try parseUint(try l.field("files"), max_files);

    const files = try gpa.alloc(File, @intCast(n));
    errdefer gpa.free(files);
    var total: u64 = 0;
    for (files, 0..) |*f, i| {
        const line = try l.next();
        if (!std.mem.startsWith(u8, line, "file ")) return error.BadManifest;
        const rest = line["file ".len..];
        const sp1 = std.mem.indexOfScalar(u8, rest, ' ') orelse return error.BadManifest;
        const size = try parseUint(rest[0..sp1], max_package_bytes);
        const rest2 = rest[sp1 + 1 ..];
        if (rest2.len < 66 or rest2[64] != ' ') return error.BadManifest;
        const sha = try parseHash(rest2[0..64]);
        const path = rest2[65..];
        switch (checkPath(path)) {
            .ok => {},
            else => return error.BadPath,
        }
        if (i > 0) {
            const prev = files[i - 1].path;
            if (std.mem.eql(u8, prev, path)) return error.DuplicatePath;
            if (!std.mem.lessThan(u8, prev, path)) return error.NotCanonical;
        }
        total += size;
        if (total > max_package_bytes) return error.TooLarge;
        f.* = .{ .path = path, .size = size, .sha256 = sha };
    }
    if (!std.mem.eql(u8, try l.next(), "end")) return error.BadManifest;
    if (l.rest.len != 0) return error.BadManifest;
    try checkUnique(gpa, files);

    const m: Manifest = .{
        .package = package,
        .version = version,
        .kind = kind,
        .sequence = sequence,
        .created = created,
        .min_client = min_client,
        .files = files,
    };
    // One encoding only: what was signed must be exactly what we read.
    const copy = try gpa.dupe(File, files);
    var again: Manifest = m;
    again.files = copy;
    defer gpa.free(copy);
    const re = encode(gpa, &again) catch return error.NotCanonical;
    defer gpa.free(re);
    if (!std.mem.eql(u8, re, bytes)) return error.NotCanonical;
    return m;
}

// -------------------------------------------------------------- signatures

pub fn fingerprint(public_key: [public_key_len]u8) [32]u8 {
    return @import("shared").pki.fingerprint.sha256(&public_key);
}

/// "AB:CD:..." (95 characters), like the CA fingerprints the desk shows.
pub const formatFingerprint = @import("shared").pki.fingerprint.format;

pub fn sign(kp: Ed25519.KeyPair, bytes: []const u8) ![signature_len]u8 {
    const sig = try kp.sign(bytes, null);
    return sig.toBytes();
}

pub const VerifyError = error{BadSignature};

/// Checks the release signature over the exact manifest bytes.
pub fn verify(bytes: []const u8, sig: [signature_len]u8, public_key: [public_key_len]u8) VerifyError!void {
    const pk = Ed25519.PublicKey.fromBytes(public_key) catch return error.BadSignature;
    Ed25519.Signature.fromBytes(sig).verifyStrict(bytes, pk) catch return error.BadSignature;
}

/// Hex text of a signature or key (lowercase), into `out`.
pub fn hexLower(bytes: []const u8, out: []u8) []const u8 {
    const hex = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0xf];
    }
    return out[0 .. bytes.len * 2];
}

pub fn parseHex(comptime n: usize, s: []const u8) ?[n]u8 {
    if (s.len != n * 2) return null;
    var out: [n]u8 = undefined;
    for (s) |c| switch (c) {
        '0'...'9', 'a'...'f', 'A'...'F' => {},
        else => return null,
    };
    _ = std.fmt.hexToBytes(&out, s) catch return null;
    return out;
}

// ------------------------------------------------------------- the index

/// One line of `GET /sync/index`: what the desktop says is the latest
/// version of a subscribed package. Advisory only: the device trusts
/// nothing here until the signed manifest (whose SHA-256 must match
/// `manifest_sha256`) says the same.
pub const IndexEntry = struct {
    package: []const u8,
    version: []const u8,
    sequence: u64,
    kind: Kind,
    size: u64,
    manifest_sha256: [32]u8,
};

pub const index_header = "portal-sync-index-v1";
pub const max_index_entries = 64;
pub const max_index_bytes = 64 * 1024;

pub fn writeIndexLine(out: *std.ArrayList(u8), gpa: Allocator, e: IndexEntry) !void {
    try out.print(gpa, "pkg {s} {s} {d} {t} {d} {x}\n", .{ e.package, e.version, e.sequence, e.kind, e.size, &e.manifest_sha256 });
}

/// Parses an index into `out` (strings point into `bytes`); returns the
/// entries. Strict like `parse`.
pub fn parseIndex(bytes: []const u8, out: []IndexEntry) Error![]IndexEntry {
    if (bytes.len > max_index_bytes) return error.TooLarge;
    var l: Lines = .{ .rest = bytes };
    if (!std.mem.eql(u8, try l.next(), index_header)) return error.BadManifest;
    var n: usize = 0;
    while (true) {
        const line = try l.next();
        if (std.mem.eql(u8, line, "end")) break;
        if (n == out.len) return error.TooManyFiles;
        var it = std.mem.splitScalar(u8, line, ' ');
        if (!std.mem.eql(u8, it.next() orelse "", "pkg")) return error.BadManifest;
        const pkg = it.next() orelse return error.BadManifest;
        const ver = it.next() orelse return error.BadManifest;
        const seq = try parseUint(it.next() orelse return error.BadManifest, std.math.maxInt(i63));
        const kind = std.meta.stringToEnum(Kind, it.next() orelse return error.BadManifest) orelse return error.BadManifest;
        const size = try parseUint(it.next() orelse return error.BadManifest, max_package_bytes);
        const sha = try parseHash(it.next() orelse return error.BadManifest);
        if (it.next() != null) return error.BadManifest;
        if (!validPackageId(pkg)) return error.BadPackageId;
        if (!validVersion(ver)) return error.BadVersion;
        for (out[0..n]) |e| if (std.mem.eql(u8, e.package, pkg)) return error.DuplicatePath;
        out[n] = .{ .package = pkg, .version = ver, .sequence = seq, .kind = kind, .size = size, .manifest_sha256 = sha };
        n += 1;
    }
    if (l.rest.len != 0) return error.BadManifest;
    return out[0..n];
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn hashOf(fill: u8) [32]u8 {
    return @splat(fill);
}

fn sample(files: []File) Manifest {
    return .{
        .package = "stt-model",
        .version = "1.2.0",
        .kind = .data,
        .sequence = 7,
        .created = 1_731_400_000,
        .min_client = "0.1.0",
        .files = files,
    };
}

test "canonical form: encode sorts, parse round-trips byte for byte" {
    const gpa = testing.allocator;
    var files = [_]File{
        .{ .path = "weights/b.bin", .size = 10, .sha256 = hashOf(2) },
        .{ .path = "README.txt", .size = 0, .sha256 = hashOf(0xab) },
        .{ .path = "weights/a b.bin", .size = 3, .sha256 = hashOf(1) },
    };
    var m = sample(&files);
    const bytes = try encode(gpa, &m);
    defer gpa.free(bytes);
    const want = "portal-manifest-v1\npackage stt-model\nversion 1.2.0\nkind data\nsequence 7\ncreated 1731400000\nmin-client 0.1.0\nfiles 3\n" ++
        "file 0 abababababababababababababababababababababababababababababababab README.txt\n" ++
        "file 3 0101010101010101010101010101010101010101010101010101010101010101 weights/a b.bin\n" ++
        "file 10 0202020202020202020202020202020202020202020202020202020202020202 weights/b.bin\nend\n";
    try testing.expectEqualStrings(want, bytes);
    var p = try parse(gpa, bytes);
    defer p.deinit(gpa);
    try testing.expectEqualStrings("stt-model", p.package);
    try testing.expectEqual(@as(u64, 7), p.sequence);
    try testing.expectEqual(@as(u64, 13), p.totalSize());
    try testing.expectEqualStrings("weights/a b.bin", p.files[1].path);
    try testing.expectEqual(Kind.data, p.kind);
}

test "parse rejects every non-canonical variation" {
    const gpa = testing.allocator;
    var files = [_]File{
        .{ .path = "a.bin", .size = 5, .sha256 = hashOf(1) },
        .{ .path = "b.bin", .size = 6, .sha256 = hashOf(2) },
    };
    var m = sample(&files);
    const good = try encode(gpa, &m);
    defer gpa.free(good);
    var ok = try parse(gpa, good);
    ok.deinit(gpa);

    const Sub = struct { from: []const u8, to: []const u8 };
    const subs = [_]Sub{
        .{ .from = "portal-manifest-v1", .to = "portal-manifest-v2" },
        .{ .from = "\n", .to = "\r\n" },
        .{ .from = "sequence 7", .to = "sequence 07" },
        .{ .from = "sequence 7", .to = "sequence 0" },
        .{ .from = "sequence 7", .to = "sequence  7" },
        .{ .from = "sequence 7", .to = "sequence +7" },
        .{ .from = "sequence 7", .to = "sequence 9223372036854775808" },
        .{ .from = "kind data", .to = "kind Data" },
        .{ .from = "kind data", .to = "kind code" },
        .{ .from = "files 2", .to = "files 3" },
        .{ .from = "files 2", .to = "files 1" },
        .{ .from = "file 5 ", .to = "file 05 " },
        .{ .from = "01010101", .to = "0101010A" },
        .{ .from = "a.bin", .to = "c.bin" }, // unsorted
        .{ .from = "b.bin", .to = "a.bin" }, // duplicate
        .{ .from = "b.bin", .to = "A.BIN" }, // unsorted and a case duplicate
        .{ .from = "end\n", .to = "end\nx" },
        .{ .from = "end\n", .to = "end" },
        .{ .from = "min-client 0.1.0", .to = "min-client 0.01.0" },
        .{ .from = "min-client 0.1.0", .to = "min-client v1" },
        .{ .from = "package stt-model", .to = "package STT-model" },
        .{ .from = "version 1.2.0", .to = "version 1..2" },
        .{ .from = "created 1731400000", .to = "created -1" },
        .{ .from = "package stt-model\n", .to = "package stt-model\npackage stt-model\n" },
        .{ .from = "kind data\n", .to = "" },
        .{ .from = "file 6", .to = "file\t6" },
    };
    for (subs, 0..) |s, i| {
        const bad = try std.mem.replaceOwned(u8, gpa, good, s.from, s.to);
        defer gpa.free(bad);
        if (std.mem.eql(u8, bad, good)) continue;
        if (parse(gpa, bad)) |mm| {
            var x = mm;
            x.deinit(gpa);
            std.debug.print("variation {d} ({s} -> {s}) was accepted\n", .{ i, s.from, s.to });
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "path validation: every rule" {
    const P = PathProblem;
    const cases = [_]struct { p: []const u8, want: P }{
        .{ .p = "model.bin", .want = .ok },
        .{ .p = "weights/layer 1/a.bin", .want = .ok },
        .{ .p = "a.b.c", .want = .ok },
        .{ .p = "", .want = .empty },
        .{ .p = "/etc/passwd", .want = .absolute },
        .{ .p = "C:/Windows/x.dll", .want = .drive },
        .{ .p = "c:x", .want = .drive },
        .{ .p = "..\\x", .want = .backslash },
        .{ .p = "a\\b", .want = .backslash },
        .{ .p = "a//b", .want = .empty_component },
        .{ .p = "a/", .want = .empty_component },
        .{ .p = "./a", .want = .dot_component },
        .{ .p = "a/./b", .want = .dot_component },
        .{ .p = "..", .want = .dot_component },
        .{ .p = "../x", .want = .dot_component },
        .{ .p = "a/../../x", .want = .dot_component },
        .{ .p = "file.txt:evil", .want = .alternate_stream },
        .{ .p = "a/b::$DATA", .want = .alternate_stream },
        .{ .p = "CON", .want = .reserved_name },
        .{ .p = "con.txt", .want = .reserved_name },
        .{ .p = "dir/Nul", .want = .reserved_name },
        .{ .p = "COM1", .want = .reserved_name },
        .{ .p = "lpt9.log", .want = .reserved_name },
        .{ .p = "aux .txt", .want = .reserved_name },
        .{ .p = "CONIN$", .want = .reserved_name },
        .{ .p = "console.txt", .want = .ok },
        .{ .p = "com10", .want = .ok },
        .{ .p = "a.", .want = .trailing_dot_or_space },
        .{ .p = "a /b", .want = .trailing_dot_or_space },
        .{ .p = "dir./b", .want = .trailing_dot_or_space },
        .{ .p = " a", .want = .leading_space },
        .{ .p = "a\x00b", .want = .bad_char },
        .{ .p = "a\nb", .want = .bad_char },
        .{ .p = "a*b", .want = .bad_char },
        .{ .p = "a?b", .want = .bad_char },
        .{ .p = "a<b", .want = .bad_char },
        .{ .p = "a|b", .want = .bad_char },
        .{ .p = "a\"b", .want = .bad_char },
        .{ .p = "caf\xc3\xa9", .want = .bad_char },
    };
    for (cases) |c| {
        const got = checkPath(c.p);
        if (got != c.want) {
            std.debug.print("path '{s}': got {t}, want {t}\n", .{ c.p, got, c.want });
            return error.TestUnexpectedResult;
        }
    }
    const long: [max_path + 1]u8 = @splat('a');
    try testing.expectEqual(P.too_long, checkPath(&long));
    try testing.expectEqual(P.ok, checkPath(long[0..max_path]));
    var deep: [2 * (max_depth + 1)]u8 = undefined;
    for (0..max_depth + 1) |i| {
        deep[2 * i] = 'd';
        deep[2 * i + 1] = '/';
    }
    try testing.expectEqual(P.too_deep, checkPath(deep[0 .. deep.len - 1]));
}

test "case-insensitive duplicates and file-vs-folder clashes are refused" {
    const gpa = testing.allocator;
    const sets = [_][]const []const u8{
        &.{ "Model.bin", "model.bin" },
        &.{ "a", "a/b" },
        &.{ "A", "a/b" },
        &.{ "w/x", "W/y" }, // the same folder spelled two ways
    };
    for (sets) |paths| {
        var files: [2]File = undefined;
        for (paths, 0..) |p, i| files[i] = .{ .path = p, .size = 1, .sha256 = hashOf(1) };
        var m = sample(&files);
        try testing.expectError(error.DuplicatePath, encode(gpa, &m));
    }
    var ok_files = [_]File{
        .{ .path = "w/x", .size = 1, .sha256 = hashOf(1) },
        .{ .path = "w/y", .size = 1, .sha256 = hashOf(1) },
    };
    var m = sample(&ok_files);
    const b = try encode(gpa, &m);
    gpa.free(b);
}

test "ids, versions, client versions" {
    try testing.expect(validPackageId("stt-model"));
    try testing.expect(validPackageId("npu-probe"));
    for (known_packages) |p| try testing.expect(validPackageId(p));
    try testing.expect(!validPackageId(""));
    try testing.expect(!validPackageId("Stt"));
    try testing.expect(!validPackageId("a_b"));
    try testing.expect(!validPackageId("-a"));
    try testing.expect(!validPackageId("nul"));
    try testing.expect(!validPackageId(&@as([33]u8, @splat('a'))));
    try testing.expect(validVersion("1.2.0-rc1+build.5"));
    try testing.expect(!validVersion("1..2"));
    try testing.expect(!validVersion(".1"));
    try testing.expect(!validVersion("1."));
    try testing.expect(!validVersion("1/2"));
    try testing.expect(!validVersion("CON"));
    try testing.expect(!validVersion(&@as([65]u8, @splat('x'))));
    try testing.expect(validClientVersion("0.1.0"));
    try testing.expect(!validClientVersion("1.2.3.4.5"));
    try testing.expect(!validClientVersion("01"));
    try testing.expectEqual(@as(i2, -1), compareClientVersions("0.1.0", "0.2"));
    try testing.expectEqual(@as(i2, 0), compareClientVersions("1", "1.0.0"));
    try testing.expectEqual(@as(i2, 1), compareClientVersions("1.10", "1.9.9"));
    try testing.expect(isVoicePackage("stt-model"));
    try testing.expect(!isVoicePackage("npu-probe"));
}

test "signatures: good, tampered, wrong key" {
    const gpa = testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(7));
    const other = try Ed25519.KeyPair.generateDeterministic(@splat(8));
    var files = [_]File{.{ .path = "probe.exe", .size = 4, .sha256 = hashOf(9) }};
    var m = sample(&files);
    m.kind = .executable;
    const bytes = try encode(gpa, &m);
    defer gpa.free(bytes);
    const sig = try sign(kp, bytes);
    try verify(bytes, sig, kp.public_key.toBytes());
    try testing.expectError(error.BadSignature, verify(bytes, sig, other.public_key.toBytes()));
    const tampered = try gpa.dupe(u8, bytes);
    defer gpa.free(tampered);
    tampered[std.mem.indexOf(u8, tampered, "kind executable").? + 5] = 'E';
    try testing.expectError(error.BadSignature, verify(tampered, sig, kp.public_key.toBytes()));
    var bad_sig = sig;
    bad_sig[10] ^= 1;
    try testing.expectError(error.BadSignature, verify(bytes, bad_sig, kp.public_key.toBytes()));
    try testing.expectError(error.BadSignature, verify(bytes, sig, @splat(0)));
    var fpb: [95]u8 = undefined;
    try testing.expectEqual(@as(usize, 95), formatFingerprint(fingerprint(kp.public_key.toBytes()), &fpb).len);
}

test "index round trip and strictness" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try out.appendSlice(gpa, index_header ++ "\n");
    try writeIndexLine(&out, gpa, .{ .package = "stt-model", .version = "3", .sequence = 3, .kind = .data, .size = 100, .manifest_sha256 = hashOf(0xcd) });
    try writeIndexLine(&out, gpa, .{ .package = "npu-probe", .version = "1.0", .sequence = 1, .kind = .executable, .size = 5, .manifest_sha256 = hashOf(1) });
    try out.appendSlice(gpa, "end\n");
    var buf: [4]IndexEntry = undefined;
    const es = try parseIndex(out.items, &buf);
    try testing.expectEqual(@as(usize, 2), es.len);
    try testing.expectEqualStrings("npu-probe", es[1].package);
    try testing.expectEqual(Kind.executable, es[1].kind);
    try testing.expectError(error.BadManifest, parseIndex(index_header ++ "\npkg x 1 1 data 1\nend\n", &buf));
    try testing.expectError(error.BadManifest, parseIndex(index_header ++ "\nend\nextra", &buf));
    try testing.expectError(error.BadPackageId, parseIndex(index_header ++ "\npkg ../x 1 1 data 1 " ++ &@as([64]u8, @splat('0')) ++ "\nend\n", &buf));
}

test "manifest parser fuzz: random, truncated and mutated input never panics" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x5f17c);
    const rand = prng.random();
    var files = [_]File{
        .{ .path = "a/b.bin", .size = 5, .sha256 = hashOf(1) },
        .{ .path = "c.txt", .size = 0, .sha256 = hashOf(2) },
        .{ .path = "z/y/x", .size = 77, .sha256 = hashOf(3) },
    };
    var m = sample(&files);
    const good = try encode(gpa, &m);
    defer gpa.free(good);
    var buf: [1024]u8 = undefined;
    var accepted: usize = 0;
    for (0..20_000) |iter| {
        var n: usize = undefined;
        switch (iter % 3) {
            0 => { // random bytes, sometimes with the right header
                n = rand.uintLessThan(usize, 400);
                rand.bytes(buf[0..n]);
                if (rand.boolean() and n > header.len + 1) @memcpy(buf[0 .. header.len + 1], header ++ "\n");
            },
            1 => { // truncation
                n = rand.uintLessThan(usize, good.len + 1);
                @memcpy(buf[0..n], good[0..n]);
            },
            else => { // a few byte mutations of a good manifest
                n = good.len;
                @memcpy(buf[0..n], good);
                for (0..1 + rand.uintLessThan(usize, 3)) |_| {
                    const at = rand.uintLessThan(usize, n);
                    buf[at] = switch (rand.uintLessThan(u8, 4)) {
                        0 => rand.int(u8),
                        1 => ' ',
                        2 => '/',
                        else => '.',
                    };
                }
            },
        }
        if (parse(gpa, buf[0..n])) |mm| {
            var x = mm;
            defer x.deinit(gpa);
            accepted += 1;
            // Anything accepted is canonical and valid.
            const re = try encode(gpa, &x);
            defer gpa.free(re);
            try testing.expectEqualSlices(u8, buf[0..n], re);
            for (x.files) |f| try testing.expect(validPath(f.path));
        } else |_| {}
        var ib: [8]IndexEntry = undefined;
        _ = parseIndex(buf[0..n], &ib) catch {};
    }
    try testing.expect(accepted > 0); // mutations of hash digits stay valid
}
