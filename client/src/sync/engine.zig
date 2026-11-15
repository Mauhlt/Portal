//! One sync pass on a device: index -> manifest -> verify -> install.
//! Used by `portal connect` (on connect and on every {"t":"updates"}) and
//! by `portalctl sync-device` (headless, for tests).
//!
//! Every request goes on the bulk WebSocket (`/ws/bulk`, shared/bulk.zig),
//! its own connection with the transport's bulk priority, so a large
//! download never delays the interactive stream. For each package the
//! desktop lists in `get index`:
//!   1. `get manifest <pkg> <ver>`: the manifest bytes, with the signature
//!      in the reply header;
//!   2. its SHA-256 must match the index line, the Ed25519 signature must
//!      verify against the release key pinned at pairing, it must parse
//!      strictly, and its package, version, sequence and kind must be what
//!      the index said;
//!   3. the store's policy (store.checkOffer): sequence above anything
//!      installed (no downgrade, no replay), client new enough, quota;
//!   4. `data` installs now; `executable` only when approved on the device
//!      (`Options.approve`), every new version;
//!   5. `get file <pkg> <ver> <n>` for each file, by index, each
//!      bounded by the manifest's size and verified by SHA-256 in staging.
//! Anything that fails is rejected and reported; nothing is executed.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const manifest = @import("manifest.zig");
const store_mod = @import("store.zig");
const keypin = @import("keypin.zig");
const tlsconn = @import("../net/tlsconn.zig");
const wsclient = @import("../net/wsclient.zig");
const bulk = @import("shared").bulk;
const watchdog = @import("../net/watchdog.zig");

pub const connect_timeout_ms = 15_000;
/// Any request: the server must answer (or send more file bytes) within this.
pub const progress_timeout_ms = 30_000;

/// How to reach the desktop: through the tunnel (the Client's dialer).
pub const Remote = struct {
    gpa: Allocator,
    io: Io,
    addr: net.IpAddress,
    security: tlsconn.Security,
    dialer: tlsconn.transport.Dialer,
    /// Canonical "IP:PORT" (Host header).
    host: []const u8,
};

pub const Response = struct {
    status: u16,
    /// Bytes of the body (when collected), owned by the caller's gpa.
    body: []u8 = &.{},
    sig: ?[manifest.signature_len]u8 = null,
    key_hex: ?[64]u8 = null,

    pub fn deinit(r: *Response, gpa: Allocator) void {
        gpa.free(r.body);
        r.body = &.{};
    }
};

/// Where a response body goes: collected (bounded) or streamed to a sink.
const BodyTarget = union(enum) {
    collect: usize,
    sink: *store_mod.FileSink,
};

/// Where a reply's chunks go, with the watchdog moved on every one.
const BodySink = struct {
    gpa: Allocator,
    wd: *watchdog.Watchdog,
    target: BodyTarget,
    collected: std.ArrayList(u8) = .empty,

    fn chunk(b: *BodySink, bytes: []const u8) anyerror!void {
        switch (b.target) {
            .collect => |cap| {
                if (b.collected.items.len + bytes.len > cap) return error.ResponseTooLarge;
                try b.collected.appendSlice(b.gpa, bytes);
            },
            // The manifest decides the size, not the server (FileSink
            // refuses a byte more).
            .sink => |s| try s.write(bytes),
        }
        b.wd.extend(progress_timeout_ms);
    }
};

fn getTask(r: *const Remote, wd: *watchdog.Watchdog, req: bulk.Request, target: BodyTarget) anyerror!Response {
    var sock = try wsclient.Socket.open(r.gpa, r.io, r.dialer, r.addr, r.security, r.host, .bulk, &wd.stopped);
    defer sock.close();
    wd.extend(progress_timeout_ms);
    var b: BodySink = .{ .gpa = r.gpa, .wd = wd, .target = target };
    errdefer b.collected.deinit(r.gpa);
    const reply = try sock.request(req, &b, BodySink.chunk);
    var resp: Response = switch (reply) {
        .err => |code| .{ .status = code },
        .ok => |o| .{ .status = 200, .sig = if (o.sig) |s| manifest.parseHex(manifest.signature_len, s) else null },
    };
    if (resp.status != 200) return resp;
    switch (target) {
        .collect => resp.body = try b.collected.toOwnedSlice(r.gpa),
        .sink => |s| if (s.remaining() != 0) return error.SizeMismatch,
    }
    return resp;
}

/// One bulk request, under a watchdog (connect + steady progress).
pub fn get(r: *const Remote, req: bulk.Request, target: BodyTarget) anyerror!Response {
    var wd: watchdog.Watchdog = .{ .io = r.io };
    wd.extend(connect_timeout_ms);
    const res = wd.run(getTask, .{ r, &wd, req, target }, null);
    if (wd.expired.load(.acquire)) return error.TimedOut;
    return res;
}

/// The release key the desktop reports (`get key`).
pub fn fetchKey(r: *const Remote) !keypin.Key {
    var resp = try get(r, .key, .{ .collect = 256 });
    defer resp.deinit(r.gpa);
    if (resp.status != 200) return error.NoSyncKey;
    return keypin.parse(resp.body) orelse error.NoSyncKey;
}

// ------------------------------------------------------------------ pass

pub const Approval = struct {
    package: []const u8,
    sequence: u64,
    manifest_sha256: [32]u8,
};

pub const Options = struct {
    /// The running client's version (manifest min-client).
    client_version: []const u8,
    /// Approve every executable (the headless CLI's --approve: it stands
    /// for the click in the app).
    approve_all: bool = false,
    /// Executables the user approved in the app (exact manifests).
    approved: []const Approval = &.{},
    /// Restrict the pass to one package.
    only: ?[]const u8 = null,
    /// The only packages this device accepts at all (null: any). The
    /// iPhone takes `stt-adapter` alone: every other line of the index is
    /// skipped unfetched, and a manifest naming another package, or any
    /// executable, is refused even after its signature verified.
    allow: ?[]const []const u8 = null,
    /// Packages to offer instead of installing (the app's "Install voice
    /// model?" right after pairing): reported as `.offered`.
    hold: []const []const u8 = &.{},
    /// Called before each package (on the pass's thread): `portal connect`
    /// performs the user's pending rollback / revoke there, so the pass's
    /// thread stays the store's only writer.
    between: ?Hook = null,

    pub const Hook = struct {
        ctx: *anyopaque,
        f: *const fn (*anyopaque) void,
    };
};

pub const Outcome = enum {
    installed,
    up_to_date,
    pending_approval,
    /// Held for the user's answer (Options.hold).
    offered,
    rejected,
    refused,
};

pub const Item = struct {
    package_buf: [manifest.max_package_id]u8 = undefined,
    package_len: u8 = 0,
    version_buf: [manifest.max_version]u8 = undefined,
    version_len: u8 = 0,
    sequence: u64 = 0,
    kind: manifest.Kind = .data,
    size: u64 = 0,
    manifest_sha256: [32]u8 = @splat(0),
    outcome: Outcome = .rejected,
    detail_buf: [160]u8 = undefined,
    detail_len: u8 = 0,

    pub fn package(it: *const Item) []const u8 {
        return it.package_buf[0..it.package_len];
    }
    pub fn version(it: *const Item) []const u8 {
        return it.version_buf[0..it.version_len];
    }
    pub fn detail(it: *const Item) []const u8 {
        return it.detail_buf[0..it.detail_len];
    }
    pub fn setDetailText(it: *Item, t: []const u8) void {
        const n = @min(t.len, it.detail_buf.len);
        @memcpy(it.detail_buf[0..n], t[0..n]);
        it.detail_len = @intCast(n);
    }
    fn setDetail(it: *Item, comptime fmt: []const u8, args: anytype) void {
        it.detail_len = @intCast((std.fmt.bufPrint(&it.detail_buf, fmt, args) catch @as([]u8, it.detail_buf[0..0])).len);
    }
    fn set(it: *Item, e: manifest.IndexEntry) void {
        @memcpy(it.package_buf[0..e.package.len], e.package);
        it.package_len = @intCast(e.package.len);
        @memcpy(it.version_buf[0..e.version.len], e.version);
        it.version_len = @intCast(e.version.len);
        it.sequence = e.sequence;
        it.kind = e.kind;
        it.size = e.size;
        it.manifest_sha256 = e.manifest_sha256;
    }
};

pub const Report = struct {
    items: [manifest.max_index_entries]Item = undefined,
    n: usize = 0,

    pub fn slice(rep: *const Report) []const Item {
        return rep.items[0..rep.n];
    }
    pub fn count(rep: *const Report, o: Outcome) usize {
        var c: usize = 0;
        for (rep.slice()) |it| c += @intFromBool(it.outcome == o);
        return c;
    }
};

/// Fetches file n of a manifest into the store's staging sink.
const FileSource = struct {
    r: *const Remote,
    package: []const u8,
    version: []const u8,

    pub fn fetch(src: *FileSource, i: usize, sink: *store_mod.FileSink) !void {
        var resp = try get(src.r, .{ .file = .{ .pkg = .{ .id = src.package, .version = src.version }, .n = @intCast(i) } }, .{ .sink = sink });
        defer resp.deinit(src.r.gpa);
        if (resp.status != 200) return error.FileRefused;
    }
};

pub const Log = struct {
    ctx: ?*anyopaque = null,
    f: ?*const fn (ctx: ?*anyopaque, line: []const u8) void = null,
    fn print(l: Log, comptime fmt: []const u8, args: anytype) void {
        const f = l.f orelse return;
        var buf: [400]u8 = undefined;
        f(l.ctx, std.fmt.bufPrint(&buf, fmt, args) catch return);
    }
};

/// One pass over the index. `pinned` is the release key pinned at pairing.
/// Errors are only for the index itself (network, session); per-package
/// problems are items in the report.
pub fn run(r: *const Remote, st: *store_mod.Store, pinned: keypin.Key, opts: Options, rep: *Report, log: Log) !void {
    rep.n = 0;
    // The store is this desktop's (keypin.desktopRoot): it must be the one
    // for this very key.
    if (!std.mem.eql(u8, &st.signer, &manifest.fingerprint(pinned))) return error.SignerMismatch;
    _ = st.cleanup() catch 0; // never resume from a half-done staging folder
    var idx = try get(r, .index, .{ .collect = manifest.max_index_bytes });
    defer idx.deinit(r.gpa);
    if (idx.status != 200) return error.IndexRefused;
    var entries_buf: [manifest.max_index_entries]manifest.IndexEntry = undefined;
    const entries = try manifest.parseIndex(idx.body, &entries_buf);
    for (entries) |e| {
        if (opts.only) |o| if (!std.mem.eql(u8, o, e.package)) continue;
        if (opts.allow) |a| if (!listed(a, e.package)) continue;
        if (opts.between) |h| h.f(h.ctx);
        const it = &rep.items[rep.n];
        rep.n += 1;
        it.* = .{};
        it.set(e);
        passOne(r, st, pinned, opts, e, it) catch |err| {
            it.outcome = .rejected;
            if (it.detail_len == 0) it.setDetail("{s}", .{describe(err)});
        };
        switch (it.outcome) {
            .rejected => log.print("REJECTED {s} {s} (sequence {d}): {s}", .{ it.package(), it.version(), it.sequence, it.detail() }),
            else => log.print("{t} {s} {s} (sequence {d}){s}{s}", .{ it.outcome, it.package(), it.version(), it.sequence, if (it.detail_len > 0) ": " else "", it.detail() }),
        }
    }
}

pub fn describe(err: anyerror) []const u8 {
    return switch (err) {
        error.BadSignature => "bad signature: not signed by the release key pinned at pairing",
        error.ManifestMismatch => "the manifest does not match the index",
        error.HashMismatch => "a file's SHA-256 does not match the signed manifest",
        error.SizeMismatch => "a file's size does not match the signed manifest",
        error.BadPath => "the manifest has a path that is not allowed",
        error.DuplicatePath => "the manifest names one file twice",
        error.NotCanonical, error.BadManifest, error.BadPackageId, error.BadVersion => "malformed manifest",
        error.TooLarge, error.TooManyFiles => "the package is over the size limits",
        error.OverQuota => "not enough sync quota left on this device",
        error.Downgrade => "downgrade or replay refused",
        error.SignerMismatch => "this device's record of the package names another release key",
        error.VersionFolderClash => "that version is already installed with different content",
        error.NoSignature => "the server sent no signature",
        error.FileRefused, error.ManifestRefused => "the server refused the download",
        error.TimedOut => "the server stopped responding",
        else => @errorName(err),
    };
}

fn listed(list: []const []const u8, pkg: []const u8) bool {
    for (list) |p| if (std.mem.eql(u8, p, pkg)) return true;
    return false;
}

fn passOne(r: *const Remote, st: *store_mod.Store, pinned: keypin.Key, opts: Options, e: manifest.IndexEntry, it: *Item) !void {
    var resp = try get(r, .{ .manifest = .{ .id = e.package, .version = e.version } }, .{ .collect = manifest.max_manifest_bytes });
    defer resp.deinit(r.gpa);
    if (resp.status != 200) return error.ManifestRefused;
    var m = (try vet(r.gpa, st, pinned, opts, e, resp.body, resp.sig, it)) orelse return;
    defer m.deinit(r.gpa);
    var src: FileSource = .{ .r = r, .package = e.package, .version = e.version };
    const res = try st.install(&m, resp.body, resp.sig.?, &src);
    it.outcome = .installed;
    if (res.kept_in_use > 0) it.setDetail("kept {d} older version(s) still in use", .{res.kept_in_use});
}

/// Steps 2-4 for one index line and the manifest the desktop sent for it
/// (nothing fetched or written): the manifest to install (the caller
/// frees it), or null with the item's outcome set (up to date, refused,
/// held, waiting for approval). Errors mean rejected.
pub fn vet(gpa: Allocator, st: *const store_mod.Store, pinned: keypin.Key, opts: Options, e: manifest.IndexEntry, body: []const u8, sig_opt: ?[manifest.signature_len]u8, it: *Item) !?manifest.Manifest {
    const sig = sig_opt orelse return error.NoSignature;
    var digest: [32]u8 = undefined;
    Sha256.hash(body, &digest, .{});
    if (!std.mem.eql(u8, &digest, &e.manifest_sha256)) return error.ManifestMismatch;
    // The signature first: nothing else is interpreted from unsigned bytes.
    try manifest.verify(body, sig, pinned);
    var m = try manifest.parse(gpa, body);
    var keep = false;
    defer if (!keep) m.deinit(gpa);
    if (!std.mem.eql(u8, m.package, e.package) or !std.mem.eql(u8, m.version, e.version) or
        m.sequence != e.sequence or m.kind != e.kind or m.totalSize() != e.size) return error.ManifestMismatch;
    if (opts.allow) |a| if (!listed(a, m.package) or m.kind != .data) {
        it.outcome = .refused;
        it.setDetail("not accepted on this device", .{});
        return null;
    };

    const offer = try st.checkOffer(&m, opts.client_version);
    switch (offer) {
        .install => {},
        .up_to_date => {
            it.outcome = .up_to_date;
            return null;
        },
        else => {
            it.outcome = .refused;
            it.setDetail("{s}", .{switch (offer) {
                .downgrade => "downgrade refused (older than the installed version)",
                .replay => "replay refused (not newer than the highest version installed)",
                .needs_newer_client => "needs a newer Portal on this device",
                .over_quota => "not enough sync quota left on this device",
                else => "refused",
            }});
            return null;
        },
    }
    for (opts.hold) |held| if (std.mem.eql(u8, held, m.package)) {
        it.outcome = .offered;
        it.setDetail("offered: waiting for your answer", .{});
        return null;
    };
    if (m.kind == .executable and !approvedFor(opts, &m, digest)) {
        it.outcome = .pending_approval;
        it.setDetail("waiting for approval on this device", .{});
        return null;
    }
    keep = true;
    return m;
}

fn approvedFor(opts: Options, m: *const manifest.Manifest, digest: [32]u8) bool {
    if (opts.approve_all) return true;
    for (opts.approved) |a| {
        if (std.mem.eql(u8, a.package, m.package) and a.sequence == m.sequence and std.mem.eql(u8, &a.manifest_sha256, &digest)) return true;
    }
    return false;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

/// A signed test package (one file) and its index line.
const TestOffer = struct {
    file: [1]manifest.File,
    m: manifest.Manifest,
    bytes: []u8,
    sig: [manifest.signature_len]u8,

    fn make(gpa: Allocator, kp: manifest.Ed25519.KeyPair, pkg: []const u8, ver: []const u8, seq: u64, kind: manifest.Kind, content: []const u8) !*TestOffer {
        const t = try gpa.create(TestOffer);
        errdefer gpa.destroy(t);
        var d: [32]u8 = undefined;
        Sha256.hash(content, &d, .{});
        t.file = .{.{ .path = "adapter.bin", .size = content.len, .sha256 = d }};
        t.m = .{ .package = pkg, .version = ver, .kind = kind, .sequence = seq, .created = 1, .min_client = "0.1.0", .files = &t.file };
        t.bytes = try manifest.encode(gpa, &t.m);
        t.sig = try manifest.sign(kp, t.bytes);
        return t;
    }

    fn entry(t: *const TestOffer) manifest.IndexEntry {
        var d: [32]u8 = undefined;
        Sha256.hash(t.bytes, &d, .{});
        return .{ .package = t.m.package, .version = t.m.version, .sequence = t.m.sequence, .kind = t.m.kind, .size = t.m.totalSize(), .manifest_sha256 = d };
    }

    fn destroy(t: *TestOffer, gpa: Allocator) void {
        gpa.free(t.bytes);
        gpa.destroy(t);
    }
};

const OneFile = struct {
    content: []const u8,
    pub fn fetch(src: *OneFile, _: usize, sink: *store_mod.FileSink) !void {
        try sink.write(src.content);
    }
};

/// The iPhone's acceptance: `stt-adapter` data only, signed by the pinned
/// key, never an older sequence.
const phone: Options = .{ .client_version = "0.1.0", .allow = &.{"stt-adapter"} };

fn testStore(gpa: Allocator, tmp: *testing.TmpDir, signer: [32]u8) !store_mod.Store {
    const io = testing.io;
    var abs_buf: [1024]u8 = undefined;
    const n = try Io.Dir.cwd().realPath(io, &abs_buf);
    const sep = std.fs.path.sep_str;
    const root = try std.fmt.allocPrint(gpa, "{s}" ++ sep ++ ".zig-cache" ++ sep ++ "tmp" ++ sep ++ "{s}", .{ abs_buf[0..n], &tmp.sub_path });
    errdefer gpa.free(root);
    return store_mod.Store.open(gpa, io, root, manifest.fingerprint(signer));
}

/// vet, then install what it accepts.
fn tryOffer(gpa: Allocator, st: *store_mod.Store, pinned: keypin.Key, opts: Options, t: *const TestOffer, content: []const u8, it: *Item) !Outcome {
    it.* = .{};
    var m = (try vet(gpa, st, pinned, opts, t.entry(), t.bytes, t.sig, it)) orelse return it.outcome;
    defer m.deinit(gpa);
    var src: OneFile = .{ .content = content };
    _ = try st.install(&m, t.bytes, t.sig, &src);
    return .installed;
}

test "iPhone acceptance: a signed stt-adapter installs; another package, an executable, a bad signature or an older sequence is refused" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const kp = try manifest.Ed25519.KeyPair.generateDeterministic(@splat(3));
    const pinned = kp.public_key.toBytes();
    var st = try testStore(gpa, &tmp, pinned);
    defer gpa.free(st.root);
    var it: Item = .{};

    const v2 = try TestOffer.make(gpa, kp, "stt-adapter", "2", 2, .data, "STTUPD01 two");
    defer v2.destroy(gpa);
    try testing.expectEqual(Outcome.installed, try tryOffer(gpa, &st, pinned, phone, v2, "STTUPD01 two", &it));
    try testing.expectEqualStrings("2", (try st.current("stt-adapter")).?.version());
    try testing.expectEqual(Outcome.up_to_date, try tryOffer(gpa, &st, pinned, phone, v2, "STTUPD01 two", &it));

    // Rollback protection: an older (or the same) sequence never installs.
    const v1 = try TestOffer.make(gpa, kp, "stt-adapter", "1", 1, .data, "STTUPD01 one");
    defer v1.destroy(gpa);
    try testing.expectEqual(Outcome.refused, try tryOffer(gpa, &st, pinned, phone, v1, "STTUPD01 one", &it));
    try testing.expect(std.mem.startsWith(u8, it.detail(), "downgrade"));
    const replay = try TestOffer.make(gpa, kp, "stt-adapter", "2b", 2, .data, "STTUPD01 again");
    defer replay.destroy(gpa);
    try testing.expectEqual(Outcome.refused, try tryOffer(gpa, &st, pinned, phone, replay, "STTUPD01 again", &it));
    try testing.expectEqualStrings("2", (try st.current("stt-adapter")).?.version());

    // Any other package, even signed by the pinned key: refused, nothing written.
    const model = try TestOffer.make(gpa, kp, "stt-model", "9", 9, .data, "weights");
    defer model.destroy(gpa);
    try testing.expectEqual(Outcome.refused, try tryOffer(gpa, &st, pinned, phone, model, "weights", &it));
    try testing.expectEqualStrings("not accepted on this device", it.detail());
    try testing.expect((try st.current("stt-model")) == null);
    // An executable under the adapter package name.
    const exe = try TestOffer.make(gpa, kp, "stt-adapter", "3", 3, .executable, "MZ");
    defer exe.destroy(gpa);
    try testing.expectEqual(Outcome.refused, try tryOffer(gpa, &st, pinned, phone, exe, "MZ", &it));

    // Signed by another key: rejected before anything is parsed.
    const other = try manifest.Ed25519.KeyPair.generateDeterministic(@splat(4));
    const forged = try TestOffer.make(gpa, other, "stt-adapter", "4", 4, .data, "STTUPD01 forged");
    defer forged.destroy(gpa);
    try testing.expectError(error.BadSignature, tryOffer(gpa, &st, pinned, phone, forged, "STTUPD01 forged", &it));
    // Tampered after signing, no signature, or an index line that lies.
    const v5 = try TestOffer.make(gpa, kp, "stt-adapter", "5", 5, .data, "STTUPD01 five");
    defer v5.destroy(gpa);
    var bad_sig = v5.sig;
    bad_sig[0] ^= 1;
    try testing.expectError(error.BadSignature, vet(gpa, &st, pinned, phone, v5.entry(), v5.bytes, bad_sig, &it));
    try testing.expectError(error.NoSignature, vet(gpa, &st, pinned, phone, v5.entry(), v5.bytes, null, &it));
    var lie = v5.entry();
    lie.sequence = 50;
    try testing.expectError(error.ManifestMismatch, vet(gpa, &st, pinned, phone, lie, v5.bytes, v5.sig, &it));
    lie = v5.entry();
    lie.manifest_sha256[0] ^= 1;
    try testing.expectError(error.ManifestMismatch, vet(gpa, &st, pinned, phone, lie, v5.bytes, v5.sig, &it));
    // A file that is not what the signed manifest says: nothing changes.
    {
        var m5 = (try vet(gpa, &st, pinned, phone, v5.entry(), v5.bytes, v5.sig, &it)).?;
        defer m5.deinit(gpa);
        var wrong: OneFile = .{ .content = "STTUPD01 fivX" };
        try testing.expectError(error.HashMismatch, st.install(&m5, v5.bytes, v5.sig, &wrong));
    }
    try testing.expectEqualStrings("2", (try st.current("stt-adapter")).?.version());
    // The newer one, intact, installs.
    try testing.expectEqual(Outcome.installed, try tryOffer(gpa, &st, pinned, phone, v5, "STTUPD01 five", &it));
    try testing.expectEqualStrings("5", (try st.current("stt-adapter")).?.version());
}

test "without an allow list every package is vetted as before" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const kp = try manifest.Ed25519.KeyPair.generateDeterministic(@splat(5));
    const pinned = kp.public_key.toBytes();
    var st = try testStore(gpa, &tmp, pinned);
    defer gpa.free(st.root);
    var it: Item = .{};
    const model = try TestOffer.make(gpa, kp, "stt-model", "1", 1, .data, "weights");
    defer model.destroy(gpa);
    try testing.expectEqual(Outcome.installed, try tryOffer(gpa, &st, pinned, .{ .client_version = "0.1.0" }, model, "weights", &it));
    const exe = try TestOffer.make(gpa, kp, "npu-probe", "1", 1, .executable, "MZ");
    defer exe.destroy(gpa);
    try testing.expectEqual(Outcome.pending_approval, try tryOffer(gpa, &st, pinned, .{ .client_version = "0.1.0" }, exe, "MZ", &it));
}
