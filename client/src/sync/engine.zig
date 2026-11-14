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

fn passOne(r: *const Remote, st: *store_mod.Store, pinned: keypin.Key, opts: Options, e: manifest.IndexEntry, it: *Item) !void {
    var resp = try get(r, .{ .manifest = .{ .id = e.package, .version = e.version } }, .{ .collect = manifest.max_manifest_bytes });
    defer resp.deinit(r.gpa);
    if (resp.status != 200) return error.ManifestRefused;
    const sig = resp.sig orelse return error.NoSignature;
    var digest: [32]u8 = undefined;
    Sha256.hash(resp.body, &digest, .{});
    if (!std.mem.eql(u8, &digest, &e.manifest_sha256)) return error.ManifestMismatch;
    // The signature first: nothing else is interpreted from unsigned bytes.
    try manifest.verify(resp.body, sig, pinned);
    var m = try manifest.parse(r.gpa, resp.body);
    defer m.deinit(r.gpa);
    if (!std.mem.eql(u8, m.package, e.package) or !std.mem.eql(u8, m.version, e.version) or
        m.sequence != e.sequence or m.kind != e.kind or m.totalSize() != e.size) return error.ManifestMismatch;

    const offer = try st.checkOffer(&m, opts.client_version);
    switch (offer) {
        .install => {},
        .up_to_date => {
            it.outcome = .up_to_date;
            return;
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
            return;
        },
    }
    for (opts.hold) |held| if (std.mem.eql(u8, held, m.package)) {
        it.outcome = .offered;
        it.setDetail("offered: waiting for your answer", .{});
        return;
    };
    if (m.kind == .executable and !approvedFor(opts, &m, digest)) {
        it.outcome = .pending_approval;
        it.setDetail("waiting for approval on this device", .{});
        return;
    }
    var src: FileSource = .{ .r = r, .package = e.package, .version = e.version };
    const res = try st.install(&m, resp.body, sig, &src);
    it.outcome = .installed;
    if (res.kept_in_use > 0) it.setDetail("kept {d} older version(s) still in use", .{res.kept_in_use});
}

fn approvedFor(opts: Options, m: *const manifest.Manifest, digest: [32]u8) bool {
    if (opts.approve_all) return true;
    for (opts.approved) |a| {
        if (std.mem.eql(u8, a.package, m.package) and a.sequence == m.sequence and std.mem.eql(u8, &a.manifest_sha256, &digest)) return true;
    }
    return false;
}


