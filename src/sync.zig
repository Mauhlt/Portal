//! Portal sync, desktop side (docs/sync-design.md): the release key, the
//! publish store and per-device subscriptions. The web server (web.zig)
//! serves from these; devices verify everything against the release key
//! they pinned at pairing (client/src/sync).
//!
//!   %LOCALAPPDATA%\Portal\
//!     sync-key\release.key        Ed25519 seed, DPAPI-protected (current
//!                                 user, its own entropy purpose); separate
//!                                 from the TLS CA key
//!     sync-key\release.pub        the public key, hex (checked on load)
//!     publish\<pkg>\<ver>\        one published version (immutable):
//!         manifest.txt            canonical manifest (client/src/sync/manifest.zig)
//!         manifest.sig            Ed25519 signature over it, hex
//!         files\<n>               file n of the manifest
//!     publish\<pkg>\history.txt   every sequence and version ever used
//!     publish\publish.lock        serialises publish / unpublish
//!     sync-subscriptions.txt      which device gets which package
//!     sync-subscriptions.lock
//!
//! Publishing builds a version under publish\<pkg>\.tmp-<random>\ and
//! renames it into place, so the server never sees half a version.
//! Sequences only go up and version names are never reused, even after
//! unpublish, so a device can always refuse a downgrade or a replay.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const manifest = @import("client").sync.manifest;
const dpapi = @import("tls/dpapi.zig");
const devices = @import("devices.zig");
const fsutil = @import("fsutil.zig");

pub const Ed25519 = manifest.Ed25519;

const key_purpose = "Portal sync release key v1";
const key_magic = "PORTAL-SYNC-KEY-V1\n";
const subs_header = "portal-sync-subscriptions-v1";
const history_header = "portal-sync-history-v1";
pub const max_subscriptions = 256;
/// The Portal version devices need by default (manifest min-client).
pub const default_min_client = "0.1.0";

const joinBuf = fsutil.join;
pub const writeAtomic = fsutil.writeAtomic;

// ------------------------------------------------------------ release key

pub const ReleaseKey = struct {
    kp: Ed25519.KeyPair,

    pub fn publicKey(k: *const ReleaseKey) [32]u8 {
        return k.kp.public_key.toBytes();
    }

    pub fn wipe(k: *ReleaseKey) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&k.kp.secret_key));
    }
};

/// %LOCALAPPDATA%\Portal
pub const Paths = fsutil.DataDir;

/// The release public key, if a release key exists (never decrypts).
pub fn loadPublicKey(io: Io, paths: Paths) !?[32]u8 {
    var pb: [1024]u8 = undefined;
    var buf: [128]u8 = undefined;
    const text = Io.Dir.cwd().readFile(io, try paths.join(&pb, &.{ "sync-key", "release.pub" }), &buf) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    return manifest.parseHex(32, std.mem.trim(u8, text, " \r\n")) orelse error.BadSyncKey;
}

/// Decrypts the release key (only to sign) and checks it against
/// release.pub. Caller wipes it.
pub fn loadKey(gpa: Allocator, io: Io, paths: Paths) !?ReleaseKey {
    const public = (try loadPublicKey(io, paths)) orelse return null;
    var pb: [1024]u8 = undefined;
    const plain = dpapi.readSealedFile(gpa, io, try paths.join(&pb, &.{ "sync-key", "release.key" }), key_magic, key_purpose) catch |err| return switch (err) {
        error.BadSealedFile => error.BadSyncKey,
        else => err,
    };
    defer {
        std.crypto.secureZero(u8, plain);
        gpa.free(plain);
    }
    if (plain.len != 32) return error.BadSyncKey;
    const kp = Ed25519.KeyPair.generateDeterministic(plain[0..32].*) catch return error.BadSyncKey;
    if (!std.mem.eql(u8, &kp.public_key.toBytes(), &public)) return error.SyncKeyMismatch;
    return .{ .kp = kp };
}

/// Creates the release key (refuses to replace one unless `force`).
/// Returns the new public key.
pub fn initKey(gpa: Allocator, io: Io, paths: Paths, force: bool) ![32]u8 {
    if (!force) if (try loadPublicKey(io, paths)) |_| return error.SyncKeyExists;
    var pb: [1024]u8 = undefined;
    try Io.Dir.cwd().createDirPath(io, try paths.join(&pb, &.{"sync-key"}));
    var seed: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    var kp: Ed25519.KeyPair = undefined;
    while (true) {
        try io.randomSecure(&seed);
        kp = Ed25519.KeyPair.generateDeterministic(seed) catch continue;
        break;
    }
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kp.secret_key));
    // The key first, then its public half: a crash in between leaves the
    // old public key, which then fails the match on load (fail closed).
    try dpapi.writeSealedFile(gpa, io, try paths.join(&pb, &.{ "sync-key", "release.key" }), key_magic, &seed, key_purpose);
    var hex: [65]u8 = undefined;
    const pk = kp.public_key.toBytes();
    _ = manifest.hexLower(&pk, hex[0..64]);
    hex[64] = '\n';
    try writeAtomic(gpa, io, try paths.join(&pb, &.{ "sync-key", "release.pub" }), &hex);
    return pk;
}

/// The public key, creating the release key on first use.
pub fn ensureKey(gpa: Allocator, io: Io, paths: Paths) ![32]u8 {
    if (try loadPublicKey(io, paths)) |k| return k;
    return initKey(gpa, io, paths, false);
}

// ------------------------------------------------------------ publishing

pub const PublishOptions = struct {
    package: []const u8,
    folder: []const u8,
    kind: manifest.Kind,
    version: ?[]const u8 = null,
    min_client: []const u8 = default_min_client,
    now: i64,
};

pub const Published = struct {
    version_buf: [manifest.max_version]u8 = undefined,
    version_len: usize = 0,
    sequence: u64 = 0,
    files: usize = 0,
    size: u64 = 0,
    manifest_sha256: [32]u8 = undefined,

    pub fn version(p: *const Published) []const u8 {
        return p.version_buf[0..p.version_len];
    }
};

const History = struct {
    last_sequence: u64 = 0,
    /// "seq version\n" lines after the header.
    text: []u8 = &.{},

    fn usedVersion(h: *const History, v: []const u8) bool {
        var it = std.mem.splitScalar(u8, h.text, '\n');
        _ = it.next();
        while (it.next()) |line| {
            const sp = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
            if (std.ascii.eqlIgnoreCase(line[sp + 1 ..], v)) return true;
        }
        return false;
    }
};

fn readHistory(gpa: Allocator, io: Io, file_path: []const u8) !History {
    const text = Io.Dir.cwd().readFileAlloc(io, file_path, gpa, .limited(4 << 20)) catch |err| switch (err) {
        error.FileNotFound => return .{ .text = try gpa.dupe(u8, history_header ++ "\n") },
        else => return err,
    };
    errdefer gpa.free(text);
    var h: History = .{ .text = text };
    var it = std.mem.splitScalar(u8, text, '\n');
    if (!std.mem.eql(u8, it.next() orelse "", history_header)) return error.BadSyncHistory;
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const sp = std.mem.indexOfScalar(u8, line, ' ') orelse return error.BadSyncHistory;
        const s = std.fmt.parseInt(u64, line[0..sp], 10) catch return error.BadSyncHistory;
        if (s <= h.last_sequence) return error.BadSyncHistory;
        h.last_sequence = s;
    }
    return h;
}

/// Copies one file into the store while hashing it (what is stored is
/// what is hashed).
fn copyHashed(io: Io, from: []const u8, to: []const u8, max: u64) !struct { size: u64, sha: [32]u8 } {
    const src = try Io.Dir.cwd().openFile(io, from, .{});
    defer src.close(io);
    const dst = try Io.Dir.cwd().createFile(io, to, .{ .exclusive = true });
    defer dst.close(io);
    var h: Sha256 = .init(.{});
    var buf: [64 * 1024]u8 = undefined;
    var total: u64 = 0;
    while (true) {
        const n = src.readStreaming(io, &.{&buf}) catch |err| switch (err) {
            error.EndOfStream => 0,
            else => return err,
        };
        if (n == 0) break;
        total += n;
        if (total > max) return error.TooLarge;
        h.update(buf[0..n]);
        try dst.writeStreamingAll(io, buf[0..n]);
    }
    try dst.sync(io);
    var d: [32]u8 = undefined;
    h.final(&d);
    return .{ .size = total, .sha = d };
}

/// Hashes and signs `opts.folder` as a new version of `opts.package`.
/// `problem` gets a description of a refused file path.
pub fn publish(gpa: Allocator, io: Io, paths: Paths, opts: PublishOptions, problem: *[300]u8) !Published {
    if (!manifest.validPackageId(opts.package)) return error.BadPackageId;
    if (opts.version) |v| if (!manifest.validVersion(v)) return error.BadVersion;
    if (!manifest.validClientVersion(opts.min_client)) return error.BadClientVersion;
    var key = (try loadKey(gpa, io, paths)) orelse return error.NoSyncKey;
    defer key.wipe();

    // Every regular file under the folder, relative paths with '/'.
    var rels: std.ArrayList([]u8) = .empty;
    defer {
        for (rels.items) |r| gpa.free(r);
        rels.deinit(gpa);
    }
    {
        var dir = try Io.Dir.cwd().openDir(io, opts.folder, .{ .iterate = true });
        defer dir.close(io);
        var walker = try dir.walk(gpa);
        defer walker.deinit();
        while (try walker.next(io)) |e| {
            switch (e.kind) {
                .directory => continue,
                .file => {},
                else => {
                    _ = std.fmt.bufPrint(problem, "{s}: not a regular file (links are not published)", .{e.path}) catch {};
                    return error.BadFolderEntry;
                },
            }
            const rel = try gpa.dupe(u8, e.path);
            for (rel) |*c| if (c.* == '\\') {
                c.* = '/';
            };
            try rels.append(gpa, rel);
            const why = manifest.checkPath(rel);
            if (why != .ok) {
                _ = std.fmt.bufPrint(problem, "{s}: path refused ({t})", .{ rel, why }) catch {};
                return error.BadFolderEntry;
            }
            if (rels.items.len > manifest.max_files) return error.TooManyFiles;
        }
    }
    if (rels.items.len == 0) return error.EmptyFolder;

    var pb: [1024]u8 = undefined;
    const pkg_dir = try paths.join(&pb, &.{ "publish", opts.package });
    try Io.Dir.cwd().createDirPath(io, pkg_dir);
    var lb: [1024]u8 = undefined;
    const lock = try takeLock(io, try paths.join(&lb, &.{ "publish", "publish.lock" }));
    defer lock.release(io);

    var hb: [1024]u8 = undefined;
    const hist_path = try paths.join(&hb, &.{ "publish", opts.package, "history.txt" });
    var hist = try readHistory(gpa, io, hist_path);
    defer gpa.free(hist.text);
    const seq = hist.last_sequence + 1;
    var out: Published = .{ .sequence = seq };
    const ver = opts.version orelse (std.fmt.bufPrint(&out.version_buf, "{d}", .{seq}) catch unreachable);
    if (opts.version) |v| @memcpy(out.version_buf[0..v.len], v);
    out.version_len = ver.len;
    const version = out.version();
    if (hist.usedVersion(version)) return error.VersionUsed;
    {
        // Reserve the sequence first: never reused, even if the build fails.
        const line = try std.fmt.allocPrint(gpa, "{s}{d} {s}\n", .{ hist.text, seq, version });
        defer gpa.free(line);
        try writeAtomic(gpa, io, hist_path, line);
    }

    var rnd: [8]u8 = undefined;
    io.random(&rnd);
    var tn: [32]u8 = undefined;
    var xb: [16]u8 = undefined;
    var tb: [1024]u8 = undefined;
    const tmp = try paths.join(&tb, &.{ "publish", opts.package, try std.fmt.bufPrint(&tn, ".tmp-{s}", .{manifest.hexLower(&rnd, &xb)}) });
    var fb: [1100]u8 = undefined;
    try Io.Dir.cwd().createDirPath(io, try joinBuf(&fb, &.{ tmp, "files" }));
    var placed = false;
    defer if (!placed) Io.Dir.cwd().deleteTree(io, tmp) catch {};

    // Sort first: file n in the store is file n of the manifest.
    std.mem.sort([]u8, rels.items, {}, struct {
        fn lt(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    const files = try gpa.alloc(manifest.File, rels.items.len);
    defer gpa.free(files);
    var total: u64 = 0;
    for (rels.items, 0..) |rel, i| {
        var sb: [1400]u8 = undefined;
        var src_w: Io.Writer = .fixed(&sb);
        src_w.writeAll(opts.folder) catch return error.NameTooLong;
        src_w.writeAll("\\") catch return error.NameTooLong;
        for (rel) |c| src_w.writeByte(if (c == '/') '\\' else c) catch return error.NameTooLong;
        var db: [1200]u8 = undefined;
        var nb: [16]u8 = undefined;
        const dst = try joinBuf(&db, &.{ tmp, "files", try std.fmt.bufPrint(&nb, "{d}", .{i}) });
        const c = try copyHashed(io, src_w.buffered(), dst, manifest.max_package_bytes - total);
        total += c.size;
        files[i] = .{ .path = rel, .size = c.size, .sha256 = c.sha };
    }
    var m: manifest.Manifest = .{
        .package = opts.package,
        .version = version,
        .kind = opts.kind,
        .sequence = seq,
        .created = opts.now,
        .min_client = opts.min_client,
        .files = files,
    };
    const bytes = manifest.encode(gpa, &m) catch |err| {
        if (err == error.DuplicatePath) _ = std.fmt.bufPrint(problem, "two files differ only in letter case (or a file is also a folder name)", .{}) catch {};
        return err;
    };
    defer gpa.free(bytes);
    const sig = try manifest.sign(key.kp, bytes);
    // Self-check before it goes out.
    try manifest.verify(bytes, sig, key.publicKey());
    var mb: [1200]u8 = undefined;
    try writeAtomic(gpa, io, try joinBuf(&mb, &.{ tmp, "manifest.txt" }), bytes);
    var sig_hex: [129]u8 = undefined;
    _ = manifest.hexLower(&sig, sig_hex[0..128]);
    sig_hex[128] = '\n';
    try writeAtomic(gpa, io, try joinBuf(&mb, &.{ tmp, "manifest.sig" }), &sig_hex);
    var vb: [1024]u8 = undefined;
    try Io.Dir.renamePreserve(Io.Dir.cwd(), tmp, Io.Dir.cwd(), try paths.join(&vb, &.{ "publish", opts.package, version }), io);
    placed = true;
    out.files = files.len;
    out.size = total;
    Sha256.hash(bytes, &out.manifest_sha256, .{});
    return out;
}

/// Removes a published version (devices keep what they installed; its
/// sequence and name are never reused).
pub fn unpublish(io: Io, paths: Paths, package: []const u8, version: []const u8) !void {
    if (!manifest.validPackageId(package)) return error.BadPackageId;
    if (!manifest.validVersion(version)) return error.BadVersion;
    var pb: [1024]u8 = undefined;
    try Io.Dir.cwd().createDirPath(io, try paths.join(&pb, &.{"publish"}));
    const lock = try takeLock(io, try paths.join(&pb, &.{ "publish", "publish.lock" }));
    defer lock.release(io);
    var vb: [1024]u8 = undefined;
    const vdir = try paths.join(&vb, &.{ "publish", package, version });
    var rnd: [8]u8 = undefined;
    io.random(&rnd);
    var tn: [32]u8 = undefined;
    var xb: [16]u8 = undefined;
    var tb: [1024]u8 = undefined;
    const trash = try paths.join(&tb, &.{ "publish", package, try std.fmt.bufPrint(&tn, ".trash-{s}", .{manifest.hexLower(&rnd, &xb)}) });
    Io.Dir.rename(Io.Dir.cwd(), vdir, Io.Dir.cwd(), trash, io) catch |err| switch (err) {
        error.FileNotFound => return error.NotPublished,
        else => return err,
    };
    Io.Dir.cwd().deleteTree(io, trash) catch {};
}

// ------------------------------------------------------- reading the store

pub const Version = struct {
    manifest_bytes: []u8,
    sig_hex: [128]u8,
    m: manifest.Manifest,

    pub fn deinit(v: *Version, gpa: Allocator) void {
        v.m.deinit(gpa);
        gpa.free(v.manifest_bytes);
    }

    pub fn entry(v: *const Version) manifest.IndexEntry {
        var d: [32]u8 = undefined;
        Sha256.hash(v.manifest_bytes, &d, .{});
        return .{ .package = v.m.package, .version = v.m.version, .sequence = v.m.sequence, .kind = v.m.kind, .size = v.m.totalSize(), .manifest_sha256 = d };
    }
};

/// One published version, read and strictly parsed (signature not
/// checked here: devices do that against their pin).
pub fn readVersion(gpa: Allocator, io: Io, paths: Paths, package: []const u8, version: []const u8) !Version {
    if (!manifest.validPackageId(package) or !manifest.validVersion(version)) return error.NotPublished;
    var pb: [1024]u8 = undefined;
    const bytes = Io.Dir.cwd().readFileAlloc(io, try paths.join(&pb, &.{ "publish", package, version, "manifest.txt" }), gpa, .limited(manifest.max_manifest_bytes)) catch |err| switch (err) {
        error.FileNotFound => return error.NotPublished,
        else => return err,
    };
    errdefer gpa.free(bytes);
    var sb: [256]u8 = undefined;
    const sig_text = Io.Dir.cwd().readFile(io, try paths.join(&pb, &.{ "publish", package, version, "manifest.sig" }), &sb) catch return error.NotPublished;
    const sig = std.mem.trim(u8, sig_text, " \r\n");
    if (sig.len != 128 or manifest.parseHex(64, sig) == null) return error.NotPublished;
    var m = manifest.parse(gpa, bytes) catch return error.NotPublished;
    errdefer m.deinit(gpa);
    if (!std.mem.eql(u8, m.package, package) or !std.mem.eql(u8, m.version, version)) return error.NotPublished;
    return .{ .manifest_bytes = bytes, .sig_hex = sig[0..128].*, .m = m };
}

/// The published version of `package` with the highest sequence, if any.
pub fn latest(gpa: Allocator, io: Io, paths: Paths, package: []const u8) !?Version {
    var pb: [1024]u8 = undefined;
    var dir = Io.Dir.cwd().openDir(io, try paths.join(&pb, &.{ "publish", package }), .{ .iterate = true }) catch return null;
    defer dir.close(io);
    var best: ?Version = null;
    errdefer if (best) |*b| b.deinit(gpa);
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .directory or !manifest.validVersion(e.name)) continue;
        var v = readVersion(gpa, io, paths, package, e.name) catch continue;
        if (best) |*b| {
            if (v.m.sequence <= b.m.sequence) {
                v.deinit(gpa);
                continue;
            }
            b.deinit(gpa);
        }
        best = v;
    }
    return best;
}

/// Unpublishes every version of `package` but the `keep` newest (by
/// sequence), so superseded versions are not served for ever (devices
/// keep what they installed; sequences and names stay used). A version
/// that can't be removed now (a file of it open, e.g. being served) is
/// left for the next prune. Returns how many went.
pub fn prune(gpa: Allocator, io: Io, paths: Paths, package: []const u8, keep: usize) !usize {
    if (!manifest.validPackageId(package)) return error.BadPackageId;
    const Seen = struct { seq: u64, name: [manifest.max_version]u8, len: usize };
    var seen: std.ArrayList(Seen) = .empty;
    defer seen.deinit(gpa);
    {
        var pb: [1024]u8 = undefined;
        var dir = Io.Dir.cwd().openDir(io, try paths.join(&pb, &.{ "publish", package }), .{ .iterate = true }) catch return 0;
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            if (e.kind != .directory or !manifest.validVersion(e.name)) continue;
            var v = readVersion(gpa, io, paths, package, e.name) catch continue;
            defer v.deinit(gpa);
            var s: Seen = .{ .seq = v.m.sequence, .name = undefined, .len = e.name.len };
            @memcpy(s.name[0..e.name.len], e.name);
            try seen.append(gpa, s);
        }
    }
    if (seen.items.len <= keep) return 0;
    std.mem.sort(Seen, seen.items, {}, struct {
        fn newer(_: void, a: Seen, b: Seen) bool {
            return a.seq > b.seq;
        }
    }.newer);
    var gone: usize = 0;
    for (seen.items[keep..]) |*s| {
        unpublish(io, paths, package, s.name[0..s.len]) catch continue;
        gone += 1;
    }
    return gone;
}

/// The stored file `n` of a published version: its path and the size the
/// manifest promises.
pub fn filePath(paths: Paths, buf: []u8, package: []const u8, version: []const u8, n: usize) ![]const u8 {
    var nb: [16]u8 = undefined;
    return paths.join(buf, &.{ "publish", package, version, "files", try std.fmt.bufPrint(&nb, "{d}", .{n}) });
}

/// Every published package id.
pub fn packages(gpa: Allocator, io: Io, paths: Paths) !std.ArrayList([]u8) {
    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |p| gpa.free(p);
        list.deinit(gpa);
    }
    var pb: [1024]u8 = undefined;
    var dir = Io.Dir.cwd().openDir(io, try paths.join(&pb, &.{"publish"}), .{ .iterate = true }) catch return list;
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .directory or !manifest.validPackageId(e.name)) continue;
        try list.append(gpa, try gpa.dupe(u8, e.name));
    }
    std.mem.sort([]u8, list.items, {}, struct {
        fn lt(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    return list;
}

// ---------------------------------------------------------- subscriptions

pub const Sub = struct {
    device: devices.Text = .{},
    package: devices.Text = .{},
};

pub const Subs = struct {
    items: [max_subscriptions]Sub = undefined,
    n: usize = 0,

    pub fn has(s: *const Subs, device: []const u8, package: []const u8) bool {
        for (s.items[0..s.n]) |x| {
            if (std.mem.eql(u8, x.device.get(), device) and std.mem.eql(u8, x.package.get(), package)) return true;
        }
        return false;
    }

    pub fn add(s: *Subs, device: []const u8, package: []const u8) !bool {
        if (!devices.validName(device)) return error.BadName;
        if (!manifest.validPackageId(package)) return error.BadPackageId;
        if (s.has(device, package)) return false;
        if (s.n == s.items.len) return error.TooManySubscriptions;
        var x: Sub = .{};
        x.device.set(device);
        x.package.set(package);
        s.items[s.n] = x;
        s.n += 1;
        return true;
    }

    pub fn remove(s: *Subs, device: []const u8, package: []const u8) bool {
        for (s.items[0..s.n], 0..) |x, i| {
            if (std.mem.eql(u8, x.device.get(), device) and std.mem.eql(u8, x.package.get(), package)) {
                s.items[i] = s.items[s.n - 1];
                s.n -= 1;
                return true;
            }
        }
        return false;
    }

    /// Packages `device` is subscribed to.
    pub fn forDevice(s: *const Subs, device: []const u8, out: [][]const u8) [][]const u8 {
        var k: usize = 0;
        for (s.items[0..s.n]) |*x| {
            if (k == out.len) break;
            if (std.mem.eql(u8, x.device.get(), device)) {
                out[k] = x.package.get();
                k += 1;
            }
        }
        return out[0..k];
    }

    pub fn parse(text: []const u8) !Subs {
        var s: Subs = .{};
        var it = std.mem.tokenizeAny(u8, text, "\r\n");
        if (!std.mem.eql(u8, it.next() orelse "", subs_header)) return error.BadSubscriptionFile;
        while (it.next()) |line| {
            var f = std.mem.tokenizeScalar(u8, line, ' ');
            if (!std.mem.eql(u8, f.next() orelse "", "sub")) return error.BadSubscriptionFile;
            const d = f.next() orelse return error.BadSubscriptionFile;
            const p = f.next() orelse return error.BadSubscriptionFile;
            if (f.next() != null) return error.BadSubscriptionFile;
            _ = s.add(d, p) catch return error.BadSubscriptionFile;
        }
        return s;
    }

    pub fn format(s: *const Subs, gpa: Allocator, out: *std.ArrayList(u8)) !void {
        try out.appendSlice(gpa, subs_header ++ "\n");
        for (s.items[0..s.n]) |x| try out.print(gpa, "sub {s} {s}\n", .{ x.device.get(), x.package.get() });
    }
};

/// Reads the subscriptions (no lock: the file is only ever replaced
/// atomically).
pub fn readSubs(gpa: Allocator, io: Io, paths: Paths) !Subs {
    var pb: [1024]u8 = undefined;
    const text = Io.Dir.cwd().readFileAlloc(io, try paths.join(&pb, &.{"sync-subscriptions.txt"}), gpa, .limited(256 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return .{},
        else => return err,
    };
    defer gpa.free(text);
    return Subs.parse(text);
}

/// Locked read-modify-write of the subscriptions, like devices.withStore.
pub fn withSubs(gpa: Allocator, io: Io, paths: Paths, ctx: anytype, comptime op: anytype) !void {
    var lb: [1024]u8 = undefined;
    var pb: [1024]u8 = undefined;
    const Ctx = struct { gpa: Allocator, inner: @TypeOf(ctx) };
    fsutil.update(gpa, io, try paths.join(&lb, &.{"sync-subscriptions.lock"}), try paths.join(&pb, &.{"sync-subscriptions.txt"}), 256 * 1024, Ctx{
        .gpa = gpa,
        .inner = ctx,
    }, struct {
        fn edit(c: Ctx, old: ?[]const u8, out: *std.ArrayList(u8)) !bool {
            var s: Subs = if (old) |text| try Subs.parse(text) else .{};
            if (!try op(c.inner, &s)) return false;
            try s.format(c.gpa, out);
            return true;
        }
    }.edit) catch |err| return switch (err) {
        error.LockBusy => error.SyncStoreBusy,
        error.ReplaceFailed => error.SyncStoreWriteFailed,
        else => err,
    };
}

/// The publish lock (publish\publish.lock): waits for the holder; a
/// cancel is returned and stays armed (fsutil.FileLock).
fn takeLock(io: Io, path: []const u8) !fsutil.FileLock {
    return fsutil.FileLock.acquire(io, path) catch |err| switch (err) {
        error.LockBusy => error.SyncStoreBusy,
        else => err,
    };
}

pub fn subscribe(gpa: Allocator, io: Io, paths: Paths, device: []const u8, package: []const u8, on: bool) !bool {
    var changed = false;
    const Ctx = struct { d: []const u8, p: []const u8, on: bool, changed: *bool };
    try withSubs(gpa, io, paths, Ctx{ .d = device, .p = package, .on = on, .changed = &changed }, struct {
        fn op(c: Ctx, s: *Subs) !bool {
            c.changed.* = if (c.on) try s.add(c.d, c.p) else s.remove(c.d, c.p);
            return c.changed.*;
        }
    }.op);
    return changed;
}

// ------------------------------------------------------------------ index

/// GET /sync/index for `device`: its subscribed packages that have a
/// published version, latest by sequence. Caller frees.
pub fn buildIndex(gpa: Allocator, io: Io, paths: Paths, device: []const u8) ![]u8 {
    const subs = try readSubs(gpa, io, paths);
    var pkgs_buf: [manifest.max_index_entries][]const u8 = undefined;
    const pkgs = subs.forDevice(device, &pkgs_buf);
    std.mem.sort([]const u8, pkgs, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, manifest.index_header ++ "\n");
    for (pkgs) |p| {
        var v = (try latest(gpa, io, paths, p)) orelse continue;
        defer v.deinit(gpa);
        try manifest.writeIndexLine(&out, gpa, v.entry());
    }
    try out.appendSlice(gpa, "end\n");
    return out.toOwnedSlice(gpa);
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn tmpPaths(tmp: *testing.TmpDir, buf: []u8) !Paths {
    var abs: [1024]u8 = undefined;
    const n = try Io.Dir.cwd().realPath(testing.io, &abs);
    return .{ .dir = try std.fmt.bufPrint(buf, "{s}\\.zig-cache\\tmp\\{s}", .{ abs[0..n], &tmp.sub_path }) };
}

test "release key: DPAPI round trip, own purpose, refuses to replace without force" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const paths = try tmpPaths(&tmp, &pb);
    try testing.expect((try loadKey(gpa, io, paths)) == null);
    const pk = try initKey(gpa, io, paths, false);
    try testing.expectError(error.SyncKeyExists, initKey(gpa, io, paths, false));
    var k = (try loadKey(gpa, io, paths)).?;
    defer k.wipe();
    try testing.expectEqual(pk, k.publicKey());
    // The blob is useless under another purpose (e.g. the CA key's).
    var kb: [1024]u8 = undefined;
    const data = try Io.Dir.cwd().readFileAlloc(io, try paths.join(&kb, &.{ "sync-key", "release.key" }), gpa, .limited(65536));
    defer gpa.free(data);
    try testing.expectError(error.DpapiUnprotectFailed, dpapi.unprotect(gpa, data[key_magic.len..], "Portal CA private key v1"));
    const pk2 = try initKey(gpa, io, paths, true);
    try testing.expect(!std.mem.eql(u8, &pk, &pk2));
}

test "publish: hash, sign, store atomically; sequences and names never reused; index per device" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const paths = try tmpPaths(&tmp, &pb);
    const pk = try initKey(gpa, io, paths, false);
    var sb: [1024]u8 = undefined;
    const src = try paths.join(&sb, &.{"src"});
    var fb: [1024]u8 = undefined;
    try Io.Dir.cwd().createDirPath(io, try paths.join(&fb, &.{ "src", "sub" }));
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = try paths.join(&fb, &.{ "src", "model.bin" }), .data = "weights" });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = try paths.join(&fb, &.{ "src", "sub", "cfg.txt" }), .data = "cfg" });
    var problem: [300]u8 = undefined;
    const p1 = try publish(gpa, io, paths, .{ .package = "stt-model", .folder = src, .kind = .data, .now = 5 }, &problem);
    try testing.expectEqual(@as(u64, 1), p1.sequence);
    try testing.expectEqualStrings("1", p1.version());
    try testing.expectEqual(@as(usize, 2), p1.files);
    var v = try readVersion(gpa, io, paths, "stt-model", "1");
    defer v.deinit(gpa);
    try manifest.verify(v.manifest_bytes, manifest.parseHex(64, &v.sig_hex).?, pk);
    try testing.expectEqualStrings("model.bin", v.m.files[0].path);
    try testing.expectEqualStrings("sub/cfg.txt", v.m.files[1].path);
    var xb: [1024]u8 = undefined;
    var cb: [16]u8 = undefined;
    try testing.expectEqualStrings("cfg", try Io.Dir.cwd().readFile(io, try filePath(paths, &xb, "stt-model", "1", 1), &cb));

    const p2 = try publish(gpa, io, paths, .{ .package = "stt-model", .folder = src, .kind = .data, .version = "2.0-rc", .now = 6 }, &problem);
    try testing.expectEqual(@as(u64, 2), p2.sequence);
    try testing.expectError(error.VersionUsed, publish(gpa, io, paths, .{ .package = "stt-model", .folder = src, .kind = .data, .version = "2.0-RC", .now = 7 }, &problem));
    try unpublish(io, paths, "stt-model", "2.0-rc");
    try testing.expectError(error.VersionUsed, publish(gpa, io, paths, .{ .package = "stt-model", .folder = src, .kind = .data, .version = "2.0-rc", .now = 8 }, &problem));
    const p4 = try publish(gpa, io, paths, .{ .package = "stt-model", .folder = src, .kind = .data, .now = 9 }, &problem);
    try testing.expect(p4.sequence > p2.sequence);

    // Subscriptions decide what a device sees.
    const empty = try buildIndex(gpa, io, paths, "laptop");
    defer gpa.free(empty);
    try testing.expectEqualStrings(manifest.index_header ++ "\nend\n", empty);
    try testing.expect(try subscribe(gpa, io, paths, "laptop", "stt-model", true));
    try testing.expect(!try subscribe(gpa, io, paths, "laptop", "stt-model", true));
    _ = try subscribe(gpa, io, paths, "laptop", "npu-probe", true); // nothing published: not listed
    const idx = try buildIndex(gpa, io, paths, "laptop");
    defer gpa.free(idx);
    var eb: [8]manifest.IndexEntry = undefined;
    const es = try manifest.parseIndex(idx, &eb);
    try testing.expectEqual(@as(usize, 1), es.len);
    try testing.expectEqual(p4.sequence, es[0].sequence);
    try testing.expectEqual(p4.manifest_sha256, es[0].manifest_sha256);
    const other = try buildIndex(gpa, io, paths, "phone");
    defer gpa.free(other);
    try testing.expectEqualStrings(manifest.index_header ++ "\nend\n", other);
    try testing.expect(try subscribe(gpa, io, paths, "laptop", "stt-model", false));
}

test "a hand-written publish manifest with no files is not published (no panic)" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const paths = try tmpPaths(&tmp, &pb);
    var fb: [1024]u8 = undefined;
    try Io.Dir.cwd().createDirPath(io, try paths.join(&fb, &.{ "publish", "stt-model", "9" }));
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = try paths.join(&fb, &.{ "publish", "stt-model", "9", "manifest.txt" }), .data = manifest.header ++
        "\npackage stt-model\nversion 9\nkind data\nsequence 9\ncreated 1\nmin-client 0.1.0\nfiles 0\nend\n" });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = try paths.join(&fb, &.{ "publish", "stt-model", "9", "manifest.sig" }), .data = &@as([128]u8, @splat('a')) });
    try testing.expectError(error.NotPublished, readVersion(gpa, io, paths, "stt-model", "9"));
    try testing.expect((try latest(gpa, io, paths, "stt-model")) == null);
}

test "subscriptions file is strict" {
    try testing.expectError(error.BadSubscriptionFile, Subs.parse("nope\n"));
    try testing.expectError(error.BadSubscriptionFile, Subs.parse(subs_header ++ "\nsub Laptop x\n"));
    try testing.expectError(error.BadSubscriptionFile, Subs.parse(subs_header ++ "\nsub laptop ../x\n"));
    const s = try Subs.parse(subs_header ++ "\nsub laptop stt-model\nsub laptop npu-probe\n");
    var b: [4][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 2), s.forDevice("laptop", &b).len);
}

test "prune: keeps the newest by sequence (not by name); nothing published, nothing to do" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const paths = try tmpPaths(&tmp, &pb);
    _ = try initKey(gpa, io, paths, false);
    try testing.expectEqual(@as(usize, 0), try prune(gpa, io, paths, "stt-adapter", 2));
    var fb: [1024]u8 = undefined;
    try Io.Dir.cwd().createDirPath(io, try paths.join(&fb, &.{"src"}));
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = try paths.join(&fb, &.{ "src", "a.bin" }), .data = "a" });
    var sb: [1024]u8 = undefined;
    const src = try paths.join(&sb, &.{"src"});
    var problem: [300]u8 = undefined;
    for ([_][]const u8{ "9", "10", "b", "a" }) |v| _ = try publish(gpa, io, paths, .{ .package = "stt-adapter", .folder = src, .kind = .data, .version = v, .now = 1 }, &problem);
    try testing.expectEqual(@as(usize, 2), try prune(gpa, io, paths, "stt-adapter", 2));
    try testing.expectError(error.NotPublished, readVersion(gpa, io, paths, "stt-adapter", "9"));
    try testing.expectError(error.NotPublished, readVersion(gpa, io, paths, "stt-adapter", "10"));
    var l = (try latest(gpa, io, paths, "stt-adapter")).?;
    defer l.deinit(gpa);
    try testing.expectEqualStrings("a", l.m.version);
    try testing.expectEqual(@as(usize, 0), try prune(gpa, io, paths, "stt-adapter", 2));
    try testing.expectError(error.BadPackageId, prune(gpa, io, paths, "../x", 2));
}
