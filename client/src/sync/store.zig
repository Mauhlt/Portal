//! The device side of Portal sync: where verified packages are installed.
//! One Store per paired desktop: `<root>` is that desktop's own folder
//! (keypin.desktopRoot), so two desktops can never overwrite or block
//! each other's packages.
//!
//!   <root>\         %LOCALAPPDATA%\Portal\sync\desktops\<host>-<key fp>
//!     staging\<random>\<n>                one download being verified, file
//!                                         n of its manifest (by index, never
//!                                         by a path from the network);
//!                                         deleted afterwards, and on every
//!                                         start
//!     packages\<pkg>\<version>\...        verified, read-only, immutable
//!     packages\<pkg>\.manifests\<ver>.txt the signed manifest it came from
//!     packages\<pkg>\.manifests\<ver>.sig  (and its signature, hex)
//!     state\<pkg>.txt                     ONE record per package: signer,
//!                                         current, previous and the highest
//!                                         sequence ever installed; replaced
//!                                         atomically as a whole (flushed
//!                                         temp + MoveFileEx REPLACE_EXISTING
//!                                         | WRITE_THROUGH), so install,
//!                                         rollback and revoke never leave a
//!                                         half-updated pair of pointers
//!     data\<pkg>\                         the package's own writable state
//!
//! Only one thread may change a Store (in `portal connect`, the sync
//! worker); nothing here locks.
//!
//! Rules (docs/sync-design.md):
//!   * files are verified (size and SHA-256 against the signed manifest)
//!     in staging before anything moves into packages\;
//!   * a version folder is created once, under a temporary name, filled,
//!     then renamed into place: nothing ever writes into an existing
//!     version folder, so a running program is never overwritten. A new
//!     version is always a new folder;
//!   * sequence numbers only go up: a manifest whose sequence is not above
//!     the highest ever installed for that package is refused (downgrade or
//!     replay), except for an explicit local `rollback`; a `revoke` keeps
//!     the highest sequence too, so a revoked version never comes back;
//!   * every record names the release key (its SHA-256) that signed what
//!     it points at; a record signed by another key is refused, never
//!     overwritten;
//!   * pruning keeps current, previous and any version still in use
//!     (a file in it cannot be opened exclusively);
//!   * quotas: the manifest caps one package version, `quota` caps the
//!     whole store;
//!   * nothing here ever executes anything.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const manifest = @import("manifest.zig");
const Manifest = manifest.Manifest;

const is_windows = builtin.os.tag == .windows;
const sep = std.fs.path.sep_str;

/// Everything installed together (all packages, all kept versions).
pub const default_quota: u64 = 32 << 30;
const record_header = "portal-sync-state-v2";
const max_record_bytes = 512;

pub const Error = error{
    SizeMismatch,
    HashMismatch,
    TooLarge,
    OverQuota,
    VersionFolderClash,
    BadPointer,
    NothingToRollBack,
    NotInstalled,
    Downgrade,
    /// The package's record was written for another release key.
    SignerMismatch,
} || Allocator.Error;

/// One version a record points at (current or previous), with the
/// record's highest sequence: what `current()` / `previous()` return.
pub const Pointer = struct {
    version_buf: [manifest.max_version]u8 = undefined,
    version_len: u8 = 0,
    sequence: u64 = 0,
    /// The highest sequence ever installed for this package: replay
    /// protection that survives a local rollback.
    highest: u64 = 0,

    pub fn init(v: []const u8, sequence: u64, highest: u64) Pointer {
        var p: Pointer = .{ .sequence = sequence, .highest = highest };
        const n = @min(v.len, p.version_buf.len);
        @memcpy(p.version_buf[0..n], v[0..n]);
        p.version_len = @intCast(n);
        return p;
    }

    pub fn version(p: *const Pointer) []const u8 {
        return p.version_buf[0..p.version_len];
    }
};

/// state\<pkg>.txt: everything about one package, in one file.
///
///   portal-sync-state-v2
///   signer <64 hex: SHA-256 of the release key>
///   current <version> <sequence>      or  current -
///   previous <version> <sequence>     or  previous -
///   highest <sequence>
pub const Record = struct {
    signer: [32]u8,
    cur: ?Slot = null,
    prev: ?Slot = null,
    /// The highest sequence ever installed: replay protection that
    /// survives a rollback and a revoke.
    highest: u64 = 0,

    pub const Slot = struct {
        version_buf: [manifest.max_version]u8 = undefined,
        version_len: u8 = 0,
        sequence: u64 = 0,

        pub fn init(v: []const u8, sequence: u64) Slot {
            var s: Slot = .{ .sequence = sequence };
            const n = @min(v.len, s.version_buf.len);
            @memcpy(s.version_buf[0..n], v[0..n]);
            s.version_len = @intCast(n);
            return s;
        }
        pub fn version(s: *const Slot) []const u8 {
            return s.version_buf[0..s.version_len];
        }
    };

    fn pointer(r: *const Record, s: ?Slot) ?Pointer {
        const x = s orelse return null;
        return Pointer.init(x.version(), x.sequence, r.highest);
    }

    pub fn format(r: *const Record, buf: []u8) []const u8 {
        var w: Io.Writer = .fixed(buf);
        var hex: [64]u8 = undefined;
        w.print(record_header ++ "\nsigner {s}\n", .{manifest.hexLower(&r.signer, &hex)}) catch return buf[0..0];
        inline for (.{ "current", "previous" }, .{ r.cur, r.prev }) |name, slot| {
            if (slot) |s| {
                w.print(name ++ " {s} {d}\n", .{ s.version(), s.sequence }) catch return buf[0..0];
            } else {
                w.writeAll(name ++ " -\n") catch return buf[0..0];
            }
        }
        w.print("highest {d}\n", .{r.highest}) catch return buf[0..0];
        return w.buffered();
    }

    pub fn parse(text: []const u8) Error!Record {
        var it = std.mem.splitScalar(u8, text, '\n');
        if (!std.mem.eql(u8, it.next() orelse "", record_header)) return error.BadPointer;
        const sh = field(it.next(), "signer ") orelse return error.BadPointer;
        if (sh.len != 64) return error.BadPointer;
        for (sh) |c| switch (c) {
            '0'...'9', 'a'...'f' => {},
            else => return error.BadPointer,
        };
        var r: Record = .{ .signer = manifest.parseHex(32, sh) orelse return error.BadPointer };
        r.cur = try parseSlot(field(it.next(), "current ") orelse return error.BadPointer);
        r.prev = try parseSlot(field(it.next(), "previous ") orelse return error.BadPointer);
        r.highest = try parseSeq(field(it.next(), "highest ") orelse return error.BadPointer);
        if (!std.mem.eql(u8, it.next() orelse "x", "") or it.next() != null) return error.BadPointer;
        if (r.cur) |c| if (c.sequence > r.highest) return error.BadPointer;
        if (r.prev) |p| if (p.sequence > r.highest) return error.BadPointer;
        if (r.cur != null and r.prev != null and std.mem.eql(u8, r.cur.?.version(), r.prev.?.version())) return error.BadPointer;
        return r;
    }

    fn parseSlot(text: []const u8) Error!?Slot {
        if (std.mem.eql(u8, text, "-")) return null;
        const sp = std.mem.indexOfScalar(u8, text, ' ') orelse return error.BadPointer;
        const v = text[0..sp];
        if (!manifest.validVersion(v)) return error.BadPointer;
        return Slot.init(v, try parseSeq(text[sp + 1 ..]));
    }

    /// Decimal, 1..2^64-1, no sign, no leading zeros.
    fn parseSeq(text: []const u8) Error!u64 {
        if (text.len == 0 or text.len > 20 or text[0] == '0') return error.BadPointer;
        for (text) |c| if (c < '0' or c > '9') return error.BadPointer;
        return std.fmt.parseInt(u64, text, 10) catch error.BadPointer;
    }

    fn field(line: ?[]const u8, comptime key: []const u8) ?[]const u8 {
        const l = line orelse return null;
        if (!std.mem.startsWith(u8, l, key)) return null;
        return l[key.len..];
    }
};

/// Whether a verified manifest may be installed.
pub const Offer = enum {
    install,
    /// That exact version is the current one.
    up_to_date,
    /// Older than what is installed.
    downgrade,
    /// Not newer than the highest sequence ever installed (e.g. the version
    /// rolled back from, offered again).
    replay,
    /// The manifest wants a newer Portal client.
    needs_newer_client,
    over_quota,
};

pub const Store = struct {
    gpa: Allocator,
    io: Io,
    /// Absolute path of this desktop's sync folder
    /// (…\Portal\sync\desktops\<host>-<key fp>).
    root: []const u8,
    /// SHA-256 of the release key pinned for this desktop: every record
    /// must name it.
    signer: [32]u8,
    quota: u64 = default_quota,

    /// Creates the layout's folders if needed.
    pub fn open(gpa: Allocator, io: Io, root: []const u8, signer: [32]u8) !Store {
        const s: Store = .{ .gpa = gpa, .io = io, .root = root, .signer = signer };
        for ([_][]const u8{ "staging", "packages", "state", "data" }) |d| {
            var b: [1024]u8 = undefined;
            try Io.Dir.cwd().createDirPath(io, try s.path(&b, &.{d}));
        }
        return s;
    }

    /// Joins the root with `parts` (each may contain '/'), native separators.
    pub fn path(s: *const Store, buf: []u8, parts: []const []const u8) ![]const u8 {
        var w: Io.Writer = .fixed(buf);
        w.writeAll(s.root) catch return error.NameTooLong;
        for (parts) |p| {
            w.writeAll(sep) catch return error.NameTooLong;
            for (p) |c| w.writeByte(if (c == '/') std.fs.path.sep else c) catch return error.NameTooLong;
        }
        return w.buffered();
    }

    fn recordPath(s: *const Store, buf: []u8, pkg: []const u8) ![]const u8 {
        if (!manifest.validPackageId(pkg)) return error.BadPointer;
        var nb: [64]u8 = undefined;
        return s.path(buf, &.{ "state", try std.fmt.bufPrint(&nb, "{s}.txt", .{pkg}) });
    }

    /// The package's record, or null if it was never installed here.
    /// A record for another release key is an error, never reinterpreted.
    pub fn record(s: *const Store, pkg: []const u8) !?Record {
        var pb: [1024]u8 = undefined;
        var fb: [max_record_bytes]u8 = undefined;
        const text = Io.Dir.cwd().readFile(s.io, try s.recordPath(&pb, pkg), &fb) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        const r = try Record.parse(text);
        if (!std.crypto.timing_safe.eql([32]u8, r.signer, s.signer)) return error.SignerMismatch;
        return r;
    }

    pub fn current(s: *const Store, pkg: []const u8) !?Pointer {
        const r = (try s.record(pkg)) orelse return null;
        return r.pointer(r.cur);
    }

    pub fn previous(s: *const Store, pkg: []const u8) !?Pointer {
        const r = (try s.record(pkg)) orelse return null;
        return r.pointer(r.prev);
    }

    /// Replaces the whole record at once: temp file, flushed, then an
    /// atomic replace that is itself written through to disk. A crash
    /// leaves either the old record or the new one.
    fn writeRecord(s: *const Store, pkg: []const u8, r: Record) !void {
        var pb: [1024]u8 = undefined;
        var rec = r;
        rec.signer = s.signer;
        var buf: [max_record_bytes]u8 = undefined;
        try writeAtomic(s.gpa, s.io, try s.recordPath(&pb, pkg), rec.format(&buf));
    }

    // ------------------------------------------------------------ policy

    pub fn checkOffer(s: *const Store, m: *const Manifest, client_version: []const u8) !Offer {
        if (manifest.compareClientVersions(client_version, m.min_client) < 0) return .needs_newer_client;
        if (try s.record(m.package)) |rec| {
            if (rec.cur) |cur| if (cur.sequence == m.sequence and std.mem.eql(u8, cur.version(), m.version)) return .up_to_date;
            if (m.sequence <= rec.highest) {
                const below = if (rec.cur) |cur| m.sequence < cur.sequence else false;
                return if (below) .downgrade else .replay;
            }
        }
        if ((try s.usage()) +| m.totalSize() > s.quota) return .over_quota;
        return .install;
    }

    /// Bytes of every kept version of every package (from their manifests).
    pub fn usage(s: *const Store) !u64 {
        var total: u64 = 0;
        var pb: [1024]u8 = undefined;
        var dir = Io.Dir.cwd().openDir(s.io, try s.path(&pb, &.{"packages"}), .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return 0,
            else => return err,
        };
        defer dir.close(s.io);
        var it = dir.iterate();
        while (try it.next(s.io)) |e| {
            if (e.kind != .directory or !manifest.validPackageId(e.name)) continue;
            // Every version, however many there are (not a bounded list).
            try s.eachVersion(e.name, &total, struct {
                fn add(t: *u64, v: Version) bool {
                    t.* +|= v.size;
                    return true;
                }
            }.add);
        }
        return total;
    }

    pub const Version = struct {
        name_buf: [manifest.max_version]u8 = undefined,
        name_len: u8 = 0,
        size: u64 = 0,
        sequence: u64 = 0,
        pub fn name(v: *const Version) []const u8 {
            return v.name_buf[0..v.name_len];
        }
    };

    /// Installed version folders of `pkg` that have their manifest (up to
    /// `out.len`).
    pub fn versions(s: *const Store, pkg: []const u8, out: []Version) ![]Version {
        const Ctx = struct { out: []Version, n: usize = 0 };
        var c: Ctx = .{ .out = out };
        try s.eachVersion(pkg, &c, struct {
            fn put(x: *Ctx, v: Version) bool {
                if (x.n == x.out.len) return false;
                x.out[x.n] = v;
                x.n += 1;
                return x.n < x.out.len;
            }
        }.put);
        return out[0..c.n];
    }

    /// Calls `f(ctx, v)` for each installed version folder of `pkg` that
    /// has its manifest, until `f` returns false.
    fn eachVersion(s: *const Store, pkg: []const u8, ctx: anytype, comptime f: fn (@TypeOf(ctx), Version) bool) !void {
        var pb: [1024]u8 = undefined;
        var dir = Io.Dir.cwd().openDir(s.io, try s.path(&pb, &.{ "packages", pkg }), .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer dir.close(s.io);
        var it = dir.iterate();
        while (try it.next(s.io)) |e| {
            if (e.kind != .directory or !manifest.validVersion(e.name)) continue;
            const m_bytes = s.readInstalledManifest(pkg, e.name) catch continue;
            defer s.gpa.free(m_bytes.text);
            var m = manifest.parse(s.gpa, m_bytes.text) catch continue;
            defer m.deinit(s.gpa);
            var v: Version = .{ .size = m.totalSize(), .sequence = m.sequence };
            @memcpy(v.name_buf[0..e.name.len], e.name);
            v.name_len = @intCast(e.name.len);
            if (!f(ctx, v)) return;
        }
    }

    pub const InstalledManifest = struct { text: []u8, sig: [manifest.signature_len]u8 };

    /// The manifest (and signature) a version folder was installed from.
    pub fn readInstalledManifest(s: *const Store, pkg: []const u8, ver: []const u8) !InstalledManifest {
        var pb: [1024]u8 = undefined;
        var nb: [80]u8 = undefined;
        const text = try Io.Dir.cwd().readFileAlloc(s.io, try s.path(&pb, &.{ "packages", pkg, ".manifests", try std.fmt.bufPrint(&nb, "{s}.txt", .{ver}) }), s.gpa, .limited(manifest.max_manifest_bytes));
        errdefer s.gpa.free(text);
        var sb: [256]u8 = undefined;
        const sig_hex = try Io.Dir.cwd().readFile(s.io, try s.path(&pb, &.{ "packages", pkg, ".manifests", try std.fmt.bufPrint(&nb, "{s}.sig", .{ver}) }), &sb);
        const sig = manifest.parseHex(manifest.signature_len, std.mem.trim(u8, sig_hex, "\r\n")) orelse return error.BadPointer;
        return .{ .text = text, .sig = sig };
    }

    // ------------------------------------------------------------ install

    pub const Installed = struct {
        /// The version folder already existed with this very manifest
        /// (only the pointers moved).
        reused: bool = false,
        pruned: usize = 0,
        kept_in_use: usize = 0,
    };

    /// Installs a manifest that the caller has already verified against
    /// the pinned release key, and checked with `checkOffer`. `source`
    /// provides the file contents: `source.fetch(index, *FileSink)` writes
    /// file `index` of `m` into the sink. Every file is verified in
    /// staging before anything moves into packages\.
    pub fn install(s: *Store, m: *const Manifest, manifest_bytes: []const u8, sig: [manifest.signature_len]u8, source: anytype) !Installed {
        if (m.totalSize() > manifest.max_package_bytes) return error.TooLarge;
        // Again here, whatever the caller checked: sequences only go up.
        const old = try s.record(m.package);
        if (old) |o| {
            const same = if (o.cur) |cur| cur.sequence == m.sequence and std.mem.eql(u8, cur.version(), m.version) else false;
            if (!same and m.sequence <= o.highest) return error.Downgrade;
        }
        if ((try s.usage()) +| m.totalSize() > s.quota) return error.OverQuota;
        var result: Installed = .{};

        var vb: [1024]u8 = undefined;
        const ver_dir = try s.path(&vb, &.{ "packages", m.package, m.version });
        if (exists(s.io, ver_dir)) {
            // Folders are immutable: the same version may only come back
            // with exactly the same manifest.
            const im = s.readInstalledManifest(m.package, m.version) catch return error.VersionFolderClash;
            defer s.gpa.free(im.text);
            if (!std.mem.eql(u8, im.text, manifest_bytes)) return error.VersionFolderClash;
            result.reused = true;
        } else {
            try s.stageAndPlace(m, manifest_bytes, sig, source);
        }

        // One record: the old current becomes previous, the new current.
        var rec: Record = .{ .signer = s.signer, .cur = .init(m.version, m.sequence), .highest = m.sequence };
        if (old) |o| {
            rec.highest = @max(rec.highest, o.highest);
            rec.prev = o.prev;
            if (o.cur) |c| if (!std.mem.eql(u8, c.version(), m.version)) {
                rec.prev = c;
            };
            if (rec.prev) |p| if (std.mem.eql(u8, p.version(), m.version)) {
                rec.prev = null;
            };
        }
        try s.writeRecord(m.package, rec);

        var db: [1024]u8 = undefined;
        try Io.Dir.cwd().createDirPath(s.io, try s.path(&db, &.{ "data", m.package }));
        const pr = try s.prune(m.package);
        result.pruned = pr.removed;
        result.kept_in_use = pr.in_use;
        return result;
    }

    fn stageAndPlace(s: *Store, m: *const Manifest, manifest_bytes: []const u8, sig: [manifest.signature_len]u8, source: anytype) !void {
        const io = s.io;
        var rnd: [8]u8 = undefined;
        io.random(&rnd);
        var name_buf: [16]u8 = undefined;
        const name = manifest.hexLower(&rnd, &name_buf);
        var sb: [1024]u8 = undefined;
        const stage = try s.path(&sb, &.{ "staging", name });
        try Io.Dir.cwd().createDirPath(io, stage);
        defer Io.Dir.cwd().deleteTree(io, stage) catch {};

        // 1. Download and verify every file, by index.
        for (m.files, 0..) |f, i| {
            var fb: [1100]u8 = undefined;
            const fp = try std.fmt.bufPrint(&fb, "{s}" ++ sep ++ "{d}", .{ stage, i });
            var sink = try FileSink.create(io, fp, f.size, f.sha256);
            defer sink.close();
            try source.fetch(i, &sink);
            try sink.finish();
        }

        // 2. Build the version folder under a temporary name.
        var ib: [1024]u8 = undefined;
        var inc_name: [32]u8 = undefined;
        const incoming = try s.path(&ib, &.{ "packages", m.package, try std.fmt.bufPrint(&inc_name, ".incoming-{s}", .{name}) });
        try Io.Dir.cwd().createDirPath(io, incoming);
        var placed = false;
        defer if (!placed) deleteTreeForce(io, incoming);
        for (m.files, 0..) |f, i| {
            var fb: [1100]u8 = undefined;
            const from = try std.fmt.bufPrint(&fb, "{s}" ++ sep ++ "{d}", .{ stage, i });
            var tb: [1400]u8 = undefined;
            var w: Io.Writer = .fixed(&tb);
            w.writeAll(incoming) catch return error.NameTooLong;
            w.writeAll(sep) catch return error.NameTooLong;
            for (f.path) |c| w.writeByte(if (c == '/') std.fs.path.sep else c) catch return error.NameTooLong;
            const to = w.buffered();
            if (std.fs.path.dirname(to)) |d| try Io.Dir.cwd().createDirPath(io, d);
            // No replace: a name clash (e.g. two spellings of one file on
            // a case-insensitive disk) fails instead of overwriting.
            try Io.Dir.renamePreserve(Io.Dir.cwd(), from, Io.Dir.cwd(), to, io);
            try markReadOnly(s.gpa, io, to);
        }

        // 3. The manifest it came from, then the folder itself, in place.
        var mb: [1024]u8 = undefined;
        const mdir = try s.path(&mb, &.{ "packages", m.package, ".manifests" });
        try Io.Dir.cwd().createDirPath(io, mdir);
        var tb: [1200]u8 = undefined;
        try writeFlushed(io, try std.fmt.bufPrint(&tb, "{s}" ++ sep ++ "{s}.txt", .{ mdir, m.version }), manifest_bytes, false);
        var hex: [manifest.signature_len * 2 + 1]u8 = undefined;
        _ = manifest.hexLower(&sig, hex[0 .. manifest.signature_len * 2]);
        hex[hex.len - 1] = '\n';
        try writeFlushed(io, try std.fmt.bufPrint(&tb, "{s}" ++ sep ++ "{s}.sig", .{ mdir, m.version }), &hex, false);
        var vb: [1024]u8 = undefined;
        try Io.Dir.renamePreserve(Io.Dir.cwd(), incoming, Io.Dir.cwd(), try s.path(&vb, &.{ "packages", m.package, m.version }), io);
        placed = true;
    }

    // ----------------------------------------------------------- rollback

    /// The owner's explicit local rollback: previous becomes current (and
    /// current becomes previous, so it can be undone). The highest sequence
    /// seen is kept, so the version rolled back from is not re-installed
    /// automatically.
    pub fn rollback(s: *Store, pkg: []const u8) !Pointer {
        const rec = (try s.record(pkg)) orelse return error.NotInstalled;
        const cur = rec.cur orelse return error.NotInstalled;
        const prev = rec.prev orelse return error.NothingToRollBack;
        var vb: [1024]u8 = undefined;
        if (!exists(s.io, try s.path(&vb, &.{ "packages", pkg, prev.version() }))) return error.NothingToRollBack;
        // One atomic write swaps both: a crash cannot leave current and
        // previous naming the same version, or neither.
        const now: Record = .{ .signer = s.signer, .cur = prev, .prev = cur, .highest = rec.highest };
        try s.writeRecord(pkg, now);
        return now.pointer(now.cur).?;
    }

    pub const Revoked = struct {
        /// The version now current (the previous one), or null: uninstalled.
        now: ?Pointer,
        pruned: Pruned,
    };

    /// Withdraws the current version (the owner revoking an executable's
    /// approval): the previous version becomes current, or, without one,
    /// the package is uninstalled. The highest sequence is kept, so the
    /// revoked version is never installed again (only a newer one, after a
    /// new approval). Its folder is pruned unless something still runs
    /// from it. data\<pkg>\ is left alone.
    pub fn revoke(s: *Store, pkg: []const u8) !Revoked {
        const rec = (try s.record(pkg)) orelse return error.NotInstalled;
        _ = rec.cur orelse return error.NotInstalled;
        var now: Record = .{ .signer = s.signer, .highest = rec.highest };
        if (rec.prev) |p| {
            var vb: [1024]u8 = undefined;
            if (exists(s.io, try s.path(&vb, &.{ "packages", pkg, p.version() }))) now.cur = p;
        }
        try s.writeRecord(pkg, now);
        return .{ .now = now.pointer(now.cur), .pruned = try s.prune(pkg) };
    }

    // -------------------------------------------------------------- prune

    pub const Pruned = struct { removed: usize = 0, in_use: usize = 0 };

    /// Deletes version folders of `pkg` other than current and previous,
    /// unless a file in them is in use (e.g. a running program).
    pub fn prune(s: *Store, pkg: []const u8) !Pruned {
        const io = s.io;
        var r: Pruned = .{};
        const rec = try s.record(pkg);
        const cur = if (rec) |x| x.cur else null;
        const prev = if (rec) |x| x.prev else null;
        var pb: [1024]u8 = undefined;
        const pkg_dir = try s.path(&pb, &.{ "packages", pkg });
        var names: std.ArrayList([]u8) = .empty;
        defer {
            for (names.items) |n| s.gpa.free(n);
            names.deinit(s.gpa);
        }
        {
            var dir = Io.Dir.cwd().openDir(io, pkg_dir, .{ .iterate = true }) catch |err| switch (err) {
                error.FileNotFound => return r,
                else => return err,
            };
            defer dir.close(io);
            var it = dir.iterate();
            while (try it.next(io)) |e| {
                if (e.kind != .directory or !manifest.validVersion(e.name)) continue;
                if (cur) |c| if (std.mem.eql(u8, c.version(), e.name)) continue;
                if (prev) |p| if (std.mem.eql(u8, p.version(), e.name)) continue;
                try names.append(s.gpa, try s.gpa.dupe(u8, e.name));
            }
        }
        for (names.items) |name| {
            var vb: [1024]u8 = undefined;
            const vdir = try s.path(&vb, &.{ "packages", pkg, name });
            if (inUse(s.gpa, io, vdir)) {
                r.in_use += 1;
                continue;
            }
            var rnd: [8]u8 = undefined;
            io.random(&rnd);
            var tn: [32]u8 = undefined;
            var hb: [16]u8 = undefined;
            var tb: [1024]u8 = undefined;
            const trash = try s.path(&tb, &.{ "packages", pkg, try std.fmt.bufPrint(&tn, ".trash-{s}", .{manifest.hexLower(&rnd, &hb)}) });
            Io.Dir.rename(Io.Dir.cwd(), vdir, Io.Dir.cwd(), trash, io) catch {
                r.in_use += 1; // still locked by someone
                continue;
            };
            deleteTreeForce(io, trash);
            var mb: [1100]u8 = undefined;
            var nb: [80]u8 = undefined;
            for ([_][]const u8{ "txt", "sig" }) |ext| {
                Io.Dir.cwd().deleteFile(io, s.path(&mb, &.{ "packages", pkg, ".manifests", std.fmt.bufPrint(&nb, "{s}.{s}", .{ name, ext }) catch continue }) catch continue) catch {};
            }
            r.removed += 1;
        }
        return r;
    }

    /// Removes leftovers of interrupted runs: everything in staging\, and
    /// packages\<pkg>\.incoming-* / .trash-* folders. Returns how many.
    pub fn cleanup(s: *Store) !usize {
        const io = s.io;
        var n: usize = 0;
        var pb: [1024]u8 = undefined;
        const staging = try s.path(&pb, &.{"staging"});
        n += try deleteChildren(s.gpa, io, staging, null);
        var kb: [1024]u8 = undefined;
        var dir = Io.Dir.cwd().openDir(io, try s.path(&kb, &.{"packages"}), .{ .iterate = true }) catch return n;
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            if (e.kind != .directory or !manifest.validPackageId(e.name)) continue;
            var db: [1024]u8 = undefined;
            n += try deleteChildren(s.gpa, io, try s.path(&db, &.{ "packages", e.name }), ".");
        }
        return n;
    }

    /// Packages with a current version.
    pub fn installedPackages(s: *const Store, out: [][manifest.max_package_id]u8, lens: []u8) !usize {
        var pb: [1024]u8 = undefined;
        var dir = Io.Dir.cwd().openDir(s.io, try s.path(&pb, &.{"state"}), .{ .iterate = true }) catch return 0;
        defer dir.close(s.io);
        var n: usize = 0;
        var it = dir.iterate();
        while (try it.next(s.io)) |e| {
            if (n == out.len) break;
            if (e.kind != .file or !std.mem.endsWith(u8, e.name, ".txt")) continue;
            const id = e.name[0 .. e.name.len - 4];
            if (!manifest.validPackageId(id)) continue;
            const cur = s.current(id) catch continue;
            if (cur == null) continue;
            @memcpy(out[n][0..id.len], id);
            lens[n] = @intCast(id.len);
            n += 1;
        }
        return n;
    }

    /// The kind of an installed version (from its signed manifest).
    pub fn kindOf(s: *const Store, pkg: []const u8, ver: []const u8) !manifest.Kind {
        const im = try s.readInstalledManifest(pkg, ver);
        defer s.gpa.free(im.text);
        var m = try manifest.parse(s.gpa, im.text);
        defer m.deinit(s.gpa);
        return m.kind;
    }
};

/// Writes `data` to `final` atomically: a flushed temp file next to it,
/// then MoveFileEx REPLACE_EXISTING | WRITE_THROUGH (rename elsewhere).
/// Readers see the old file or the new one, never a torn one.
pub fn writeAtomic(gpa: Allocator, io: Io, final: []const u8, data: []const u8) !void {
    var tb: [1100]u8 = undefined;
    var rnd: [8]u8 = undefined;
    io.random(&rnd);
    const tmp = try std.fmt.bufPrint(&tb, "{s}.{x}.tmp", .{ final, &rnd });
    try writeFlushed(io, tmp, data, true);
    errdefer Io.Dir.cwd().deleteFile(io, tmp) catch {};
    try replaceFile(gpa, io, tmp, final);
}

// ------------------------------------------------------------ file sinks

/// One file being downloaded into staging: bounded by the manifest's size,
/// hashed as it arrives.
pub const FileSink = struct {
    io: Io,
    file: ?Io.File,
    want_size: u64,
    want_sha: [32]u8,
    got: u64 = 0,
    hash: Sha256 = .init(.{}),

    pub fn create(io: Io, file_path: []const u8, size: u64, sha: [32]u8) !FileSink {
        const f = try Io.Dir.cwd().createFile(io, file_path, .{ .exclusive = true });
        return .{ .io = io, .file = f, .want_size = size, .want_sha = sha };
    }

    /// Bytes still expected.
    pub fn remaining(fs: *const FileSink) u64 {
        return fs.want_size - fs.got;
    }

    pub fn write(fs: *FileSink, bytes: []const u8) !void {
        if (bytes.len > fs.want_size - fs.got) return error.SizeMismatch;
        fs.hash.update(bytes);
        try fs.file.?.writeStreamingAll(fs.io, bytes);
        fs.got += bytes.len;
    }

    /// Checks size and SHA-256 and flushes the file to disk.
    pub fn finish(fs: *FileSink) !void {
        if (fs.got != fs.want_size) return error.SizeMismatch;
        var d: [32]u8 = undefined;
        fs.hash.final(&d);
        if (!std.crypto.timing_safe.eql([32]u8, d, fs.want_sha)) return error.HashMismatch;
        try fs.file.?.sync(fs.io);
        fs.close();
    }

    pub fn close(fs: *FileSink) void {
        if (fs.file) |f| f.close(fs.io);
        fs.file = null;
    }
};

// ------------------------------------------------------------ OS helpers

fn exists(io: Io, p: []const u8) bool {
    Io.Dir.cwd().access(io, p, .{}) catch return false;
    return true;
}

/// Writes `data` to a new file and flushes it to disk.
fn writeFlushed(io: Io, p: []const u8, data: []const u8, exclusive: bool) !void {
    const f = try Io.Dir.cwd().createFile(io, p, .{ .exclusive = exclusive });
    defer f.close(io);
    try f.writeStreamingAll(io, data);
    try f.sync(io);
}

/// Sets the read-only attribute (Windows) or drops write permission.
fn markReadOnly(gpa: Allocator, io: Io, p: []const u8) !void {
    if (is_windows) {
        const w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, p);
        defer gpa.free(w);
        const attrs = win.GetFileAttributesW(w.ptr);
        if (attrs == win.INVALID_ATTRIBUTES) return error.SetAttributesFailed;
        if (win.SetFileAttributesW(w.ptr, attrs | win.FILE_ATTRIBUTE_READONLY) == 0) return error.SetAttributesFailed;
        return;
    }
    const f = try Io.Dir.cwd().openFile(io, p, .{});
    defer f.close(io);
    const st = try f.stat(io);
    try f.setPermissions(io, st.permissions.setReadOnly(true));
}

pub fn isReadOnly(gpa: Allocator, io: Io, p: []const u8) bool {
    if (is_windows) {
        const w = std.unicode.wtf8ToWtf16LeAllocZ(gpa, p) catch return false;
        defer gpa.free(w);
        const attrs = win.GetFileAttributesW(w.ptr);
        return attrs != win.INVALID_ATTRIBUTES and attrs & win.FILE_ATTRIBUTE_READONLY != 0;
    }
    const f = Io.Dir.cwd().openFile(io, p, .{}) catch return false;
    defer f.close(io);
    const st = f.stat(io) catch return false;
    return st.permissions.readOnly();
}

const win = struct {
    const BOOL = c_int;
    const HANDLE = *anyopaque;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    const GENERIC_READ: u32 = 0x80000000;
    const DELETE: u32 = 0x00010000;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
    extern "kernel32" fn MoveFileExW(from: [*:0]const u16, to: [*:0]const u16, flags: u32) callconv(.winapi) BOOL;
    extern "kernel32" fn CreateFileW(name: [*:0]const u16, access: u32, share: u32, sa: ?*anyopaque, disposition: u32, flags: u32, template: ?HANDLE) callconv(.winapi) HANDLE;
    extern "kernel32" fn CloseHandle(h: HANDLE) callconv(.winapi) BOOL;
    extern "kernel32" fn GetFileAttributesW(name: [*:0]const u16) callconv(.winapi) u32;
    extern "kernel32" fn SetFileAttributesW(name: [*:0]const u16, attrs: u32) callconv(.winapi) BOOL;
    const INVALID_ATTRIBUTES: u32 = 0xFFFFFFFF;
    const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
    const INVALID: usize = std.math.maxInt(usize);
};

/// Atomic replace of `to` by `from`; on Windows written through to disk
/// before it returns (MoveFileEx REPLACE_EXISTING | WRITE_THROUGH).
fn replaceFile(gpa: Allocator, io: Io, from: []const u8, to: []const u8) !void {
    if (is_windows) {
        const a = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, from);
        defer gpa.free(a);
        const b = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, to);
        defer gpa.free(b);
        if (win.MoveFileExW(a.ptr, b.ptr, win.MOVEFILE_REPLACE_EXISTING | win.MOVEFILE_WRITE_THROUGH) == 0) return error.ReplaceFailed;
    } else {
        try Io.Dir.rename(Io.Dir.cwd(), from, Io.Dir.cwd(), to, io);
    }
}

/// True if some file under `dir` cannot be opened exclusively, i.e. a
/// process has it open (a running program's image is always open). Only
/// Windows can tell; elsewhere replacing a running file is harmless.
fn inUse(gpa: Allocator, io: Io, dir_path: []const u8) bool {
    if (!is_windows) return false;
    var dir = Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return true;
    defer dir.close(io);
    var walker = dir.walk(gpa) catch return true;
    defer walker.deinit();
    while (walker.next(io) catch return true) |e| {
        if (e.kind != .file) continue;
        var pb: [1400]u8 = undefined;
        const full = std.fmt.bufPrint(&pb, "{s}" ++ sep ++ "{s}", .{ dir_path, e.path }) catch return true;
        const w = std.unicode.wtf8ToWtf16LeAllocZ(gpa, full) catch return true;
        defer gpa.free(w);
        // Data access with no sharing: fails if any other handle (or an
        // image section) holds the file.
        const h = win.CreateFileW(w.ptr, win.GENERIC_READ | win.DELETE, 0, null, win.OPEN_EXISTING, 0, null);
        if (@intFromPtr(h) == win.INVALID) return true;
        _ = win.CloseHandle(h);
    }
    return false;
}

fn deleteTreeForce(io: Io, p: []const u8) void {
    Io.Dir.cwd().deleteTree(io, p) catch {};
}

/// Deletes every entry of `dir_path` (only those starting with `prefix`
/// if given). Returns how many.
fn deleteChildren(gpa: Allocator, io: Io, dir_path: []const u8, prefix: ?[]const u8) !usize {
    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }
    {
        var dir = Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return 0;
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            if (prefix) |p| if (!std.mem.startsWith(u8, e.name, p) or std.mem.eql(u8, e.name, ".manifests")) continue;
            try names.append(gpa, try gpa.dupe(u8, e.name));
        }
    }
    for (names.items) |n| {
        var pb: [1400]u8 = undefined;
        deleteTreeForce(io, try std.fmt.bufPrint(&pb, "{s}" ++ sep ++ "{s}", .{ dir_path, n }));
    }
    return names.items.len;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

/// Test source: file contents in memory (optionally corrupted).
const MemSource = struct {
    contents: []const []const u8,
    fetched: usize = 0,
    pub fn fetch(src: *MemSource, i: usize, sink: *FileSink) !void {
        src.fetched += 1;
        try sink.write(src.contents[i]);
    }
};

const TestPkg = struct {
    files: [3]manifest.File,
    m: Manifest,
    bytes: []u8,
    sig: [64]u8,

    fn make(gpa: Allocator, kp: manifest.Ed25519.KeyPair, pkg: []const u8, ver: []const u8, seq: u64, contents: []const []const u8, paths: []const []const u8) !*TestPkg {
        const t = try gpa.create(TestPkg);
        for (contents, 0..) |c, i| {
            var d: [32]u8 = undefined;
            Sha256.hash(c, &d, .{});
            t.files[i] = .{ .path = paths[i], .size = c.len, .sha256 = d };
        }
        t.m = .{ .package = pkg, .version = ver, .kind = .data, .sequence = seq, .created = 1, .min_client = "0.1.0", .files = t.files[0..contents.len] };
        t.bytes = try manifest.encode(gpa, &t.m);
        t.sig = try manifest.sign(kp, t.bytes);
        return t;
    }

    fn destroy(t: *TestPkg, gpa: Allocator) void {
        gpa.free(t.bytes);
        gpa.destroy(t);
    }
};

fn testStore(tmp: *testing.TmpDir, buf: []u8) !Store {
    const io = testing.io;
    const rel = try std.fmt.bufPrint(buf, ".zig-cache" ++ sep ++ "tmp" ++ sep ++ "{s}" ++ sep ++ "sync", .{&tmp.sub_path});
    var abs_buf: [1024]u8 = undefined;
    const n = try Io.Dir.cwd().realPath(io, &abs_buf);
    const abs = try std.fmt.allocPrint(testing.allocator, "{s}" ++ sep ++ "{s}", .{ abs_buf[0..n], rel });
    return Store.open(testing.allocator, io, abs, test_signer);
}

const test_signer: [32]u8 = @splat(0x5a);

fn readAll(s: *const Store, parts: []const []const u8, buf: []u8) ![]u8 {
    var pb: [1024]u8 = undefined;
    return Io.Dir.cwd().readFile(s.io, try s.path(&pb, parts), buf);
}

test "record format is strict" {
    const r: Record = .{ .signer = @splat(0xab), .cur = .init("1.2", 5), .prev = .init("1.1", 4), .highest = 7 };
    var b: [512]u8 = undefined;
    const t = r.format(&b);
    try testing.expect(std.mem.startsWith(u8, t, "portal-sync-state-v2\nsigner abab"));
    try testing.expect(std.mem.endsWith(u8, t, "\ncurrent 1.2 5\nprevious 1.1 4\nhighest 7\n"));
    const q = try Record.parse(t);
    try testing.expectEqualStrings("1.2", q.cur.?.version());
    try testing.expectEqualStrings("1.1", q.prev.?.version());
    try testing.expectEqual(@as(u64, 7), q.highest);
    const none: Record = .{ .signer = @splat(1), .highest = 3 };
    const q2 = try Record.parse(none.format(&b));
    try testing.expect(q2.cur == null and q2.prev == null and q2.highest == 3);
    const sig = "portal-sync-state-v2\nsigner " ++ "0101010101010101010101010101010101010101010101010101010101010101" ++ "\n";
    for ([_][]const u8{
        sig ++ "current ../x 1\nprevious -\nhighest 1\n", // bad version
        sig ++ "current 1 3\nprevious -\nhighest 2\n", // above highest
        sig ++ "current 1 1\nprevious -\nhighest 1\nx", // trailing
        sig ++ "current 1 01\nprevious -\nhighest 1\n", // leading zero
        sig ++ "current 1 +1\nprevious -\nhighest 1\n",
        sig ++ "current 1 1\nprevious 1 1\nhighest 1\n", // same version twice
        sig ++ "previous -\ncurrent 1 1\nhighest 1\n", // order
        "portal-sync-state-v2\nsigner " ++ "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A" ++ "\ncurrent -\nprevious -\nhighest 1\n", // uppercase hex
        "portal-sync-pointer-v1\nversion 1\nsequence 1\nhighest 1\n", // the old format
    }) |bad| try testing.expectError(error.BadPointer, Record.parse(bad));
}

test "a record for another release key is refused, not overwritten" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var rb: [256]u8 = undefined;
    var s = try testStore(&tmp, &rb);
    defer gpa.free(s.root);
    const kp = try manifest.Ed25519.KeyPair.generateDeterministic(@splat(9));
    const v1 = try TestPkg.make(gpa, kp, "stt-model", "1", 1, &.{"one"}, &.{"m"});
    defer v1.destroy(gpa);
    var src: MemSource = .{ .contents = &.{"one"} };
    _ = try s.install(&v1.m, v1.bytes, v1.sig, &src);
    var fb: [512]u8 = undefined;
    const before = try readAll(&s, &.{ "state", "stt-model.txt" }, &fb);
    var keep: [512]u8 = undefined;
    @memcpy(keep[0..before.len], before);
    // The same folder opened for another signer.
    var other = s;
    other.signer = @splat(0x77);
    try testing.expectError(error.SignerMismatch, other.current("stt-model"));
    try testing.expectError(error.SignerMismatch, other.checkOffer(&v1.m, "0.1.0"));
    const v2 = try TestPkg.make(gpa, kp, "stt-model", "2", 2, &.{"two"}, &.{"m"});
    defer v2.destroy(gpa);
    var src2: MemSource = .{ .contents = &.{"two"} };
    try testing.expectError(error.SignerMismatch, other.install(&v2.m, v2.bytes, v2.sig, &src2));
    try testing.expectError(error.SignerMismatch, other.rollback("stt-model"));
    try testing.expectError(error.SignerMismatch, other.revoke("stt-model"));
    try testing.expectEqualStrings(keep[0..before.len], try readAll(&s, &.{ "state", "stt-model.txt" }, &fb));
}

test "revoke: back to the previous version, then uninstalled; the revoked version never returns" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var rb: [256]u8 = undefined;
    var s = try testStore(&tmp, &rb);
    defer gpa.free(s.root);
    const kp = try manifest.Ed25519.KeyPair.generateDeterministic(@splat(8));
    const v1 = try TestPkg.make(gpa, kp, "npu-probe", "1", 1, &.{"MZ-1"}, &.{"npu-probe.exe"});
    defer v1.destroy(gpa);
    const v2 = try TestPkg.make(gpa, kp, "npu-probe", "2", 2, &.{"MZ-2"}, &.{"npu-probe.exe"});
    defer v2.destroy(gpa);
    var s1: MemSource = .{ .contents = &.{"MZ-1"} };
    _ = try s.install(&v1.m, v1.bytes, v1.sig, &s1);
    var s2: MemSource = .{ .contents = &.{"MZ-2"} };
    _ = try s.install(&v2.m, v2.bytes, v2.sig, &s2);

    const r1 = try s.revoke("npu-probe");
    try testing.expectEqualStrings("1", r1.now.?.version());
    try testing.expectEqual(@as(usize, 1), r1.pruned.removed); // 2's folder is gone
    try testing.expect((try s.previous("npu-probe")) == null);
    var pb: [1024]u8 = undefined;
    try testing.expect(!exists(s.io, try s.path(&pb, &.{ "packages", "npu-probe", "2" })));
    try testing.expectEqual(Offer.replay, try s.checkOffer(&v2.m, "0.1.0"));
    try testing.expectError(error.NothingToRollBack, s.rollback("npu-probe"));

    const r2 = try s.revoke("npu-probe");
    try testing.expect(r2.now == null);
    try testing.expect((try s.current("npu-probe")) == null);
    try testing.expectError(error.NotInstalled, s.revoke("npu-probe"));
    var ids: [4][manifest.max_package_id]u8 = undefined;
    var lens: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try s.installedPackages(&ids, &lens));
    // Neither revoked version comes back; a newer one may (after approval).
    try testing.expectEqual(Offer.replay, try s.checkOffer(&v1.m, "0.1.0"));
    try testing.expectEqual(Offer.replay, try s.checkOffer(&v2.m, "0.1.0"));
    const v3 = try TestPkg.make(gpa, kp, "npu-probe", "3", 3, &.{"MZ-3"}, &.{"npu-probe.exe"});
    defer v3.destroy(gpa);
    try testing.expectEqual(Offer.install, try s.checkOffer(&v3.m, "0.1.0"));
    var s3: MemSource = .{ .contents = &.{"MZ-3"} };
    _ = try s.install(&v3.m, v3.bytes, v3.sig, &s3);
    try testing.expectEqualStrings("3", (try s.current("npu-probe")).?.version());
    try testing.expect((try s.previous("npu-probe")) == null);
}

test "rollback is one atomic record write; no temp files are left" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var rb: [256]u8 = undefined;
    var s = try testStore(&tmp, &rb);
    defer gpa.free(s.root);
    const kp = try manifest.Ed25519.KeyPair.generateDeterministic(@splat(10));
    const v1 = try TestPkg.make(gpa, kp, "stt-model", "1", 1, &.{"a"}, &.{"m"});
    defer v1.destroy(gpa);
    const v2 = try TestPkg.make(gpa, kp, "stt-model", "2", 2, &.{"b"}, &.{"m"});
    defer v2.destroy(gpa);
    var s1: MemSource = .{ .contents = &.{"a"} };
    _ = try s.install(&v1.m, v1.bytes, v1.sig, &s1);
    var s2: MemSource = .{ .contents = &.{"b"} };
    _ = try s.install(&v2.m, v2.bytes, v2.sig, &s2);
    _ = try s.rollback("stt-model");
    var fb: [512]u8 = undefined;
    const text = try readAll(&s, &.{ "state", "stt-model.txt" }, &fb);
    try testing.expect(std.mem.endsWith(u8, text, "\ncurrent 1 1\nprevious 2 2\nhighest 2\n"));
    var pb: [1024]u8 = undefined;
    var dir = try Io.Dir.cwd().openDir(s.io, try s.path(&pb, &.{"state"}), .{ .iterate = true });
    defer dir.close(s.io);
    var it = dir.iterate();
    var n: usize = 0;
    while (try it.next(s.io)) |e| {
        try testing.expect(std.mem.endsWith(u8, e.name, ".txt") and !std.mem.endsWith(u8, e.name, ".tmp"));
        n += 1;
    }
    try testing.expectEqual(@as(usize, 1), n);
}

test "atomic install, read-only files, upgrade, downgrade/replay refused, rollback" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var rb: [256]u8 = undefined;
    var s = try testStore(&tmp, &rb);
    defer gpa.free(s.root);
    const kp = try manifest.Ed25519.KeyPair.generateDeterministic(@splat(3));

    const v1 = try TestPkg.make(gpa, kp, "stt-model", "1.0", 1, &.{ "cfg", "weights-one" }, &.{ "config.txt", "w/model.bin" });
    defer v1.destroy(gpa);
    try testing.expectEqual(Offer.install, try s.checkOffer(&v1.m, "0.1.0"));
    var src1: MemSource = .{ .contents = &.{ "cfg", "weights-one" } };
    const r1 = try s.install(&v1.m, v1.bytes, v1.sig, &src1);
    try testing.expect(!r1.reused);
    var fb: [64]u8 = undefined;
    try testing.expectEqualStrings("weights-one", try readAll(&s, &.{ "packages", "stt-model", "1.0", "w", "model.bin" }, &fb));
    try testing.expectEqualStrings("1.0", (try s.current("stt-model")).?.version());
    try testing.expect((try s.previous("stt-model")) == null);
    // Read-only on disk.
    {
        var pb: [1024]u8 = undefined;
        try testing.expect(isReadOnly(gpa, s.io, try s.path(&pb, &.{ "packages", "stt-model", "1.0", "config.txt" })));
    }
    // The data folder exists and staging is empty.
    var db: [1024]u8 = undefined;
    try testing.expect(exists(s.io, try s.path(&db, &.{ "data", "stt-model" })));
    try testing.expectEqual(@as(usize, 0), try s.cleanup());
    try testing.expectEqual(Offer.up_to_date, try s.checkOffer(&v1.m, "0.1.0"));

    const v2 = try TestPkg.make(gpa, kp, "stt-model", "2.0", 2, &.{"weights-two"}, &.{"w/model.bin"});
    defer v2.destroy(gpa);
    var src2: MemSource = .{ .contents = &.{"weights-two"} };
    _ = try s.install(&v2.m, v2.bytes, v2.sig, &src2);
    try testing.expectEqualStrings("2.0", (try s.current("stt-model")).?.version());
    try testing.expectEqualStrings("1.0", (try s.previous("stt-model")).?.version());
    // v1's folder is untouched (a new version is a new folder).
    try testing.expectEqualStrings("weights-one", try readAll(&s, &.{ "packages", "stt-model", "1.0", "w", "model.bin" }, &fb));

    // Older or equal sequences are refused.
    try testing.expectEqual(Offer.downgrade, try s.checkOffer(&v1.m, "0.1.0"));
    const replay = try TestPkg.make(gpa, kp, "stt-model", "2.1", 2, &.{"x"}, &.{"x"});
    defer replay.destroy(gpa);
    try testing.expectEqual(Offer.replay, try s.checkOffer(&replay.m, "0.1.0"));
    // install refuses them too, even if a caller skipped checkOffer.
    var src_old: MemSource = .{ .contents = &.{ "cfg", "weights-one" } };
    try testing.expectError(error.Downgrade, s.install(&v1.m, v1.bytes, v1.sig, &src_old));

    // Explicit local rollback; the rolled-back-from version is not taken
    // again automatically.
    const now = try s.rollback("stt-model");
    try testing.expectEqualStrings("1.0", now.version());
    try testing.expectEqual(@as(u64, 2), now.highest);
    try testing.expectEqualStrings("2.0", (try s.previous("stt-model")).?.version());
    try testing.expectEqual(Offer.replay, try s.checkOffer(&v2.m, "0.1.0"));
    const v3 = try TestPkg.make(gpa, kp, "stt-model", "3.0", 3, &.{"weights-3"}, &.{"w/model.bin"});
    defer v3.destroy(gpa);
    try testing.expectEqual(Offer.install, try s.checkOffer(&v3.m, "0.1.0"));
    var src3: MemSource = .{ .contents = &.{"weights-3"} };
    const r3 = try s.install(&v3.m, v3.bytes, v3.sig, &src3);
    // current 3.0, previous 1.0: 2.0 was pruned.
    try testing.expectEqual(@as(usize, 1), r3.pruned);
    try testing.expectEqualStrings("1.0", (try s.previous("stt-model")).?.version());
    var vb: [8]Store.Version = undefined;
    try testing.expectEqual(@as(usize, 2), (try s.versions("stt-model", &vb)).len);

    // A client too old for the manifest.
    var newer = v3.m;
    newer.min_client = "9.0";
    try testing.expectEqual(Offer.needs_newer_client, try s.checkOffer(&newer, "0.1.0"));
}

test "quota usage counts every kept version, not only the first 16" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var rb: [256]u8 = undefined;
    var s = try testStore(&tmp, &rb);
    defer gpa.free(s.root);
    const kp = try manifest.Ed25519.KeyPair.generateDeterministic(@splat(5));
    const p = try TestPkg.make(gpa, kp, "stt-model", "1", 1, &.{"0123456789"}, &.{"w.bin"});
    defer p.destroy(gpa);
    var src: MemSource = .{ .contents = &.{"0123456789"} };
    _ = try s.install(&p.m, p.bytes, p.sig, &src);
    try testing.expectEqual(@as(u64, 10), try s.usage());
    // 24 more version folders with their manifests (left behind, say, by
    // versions kept in use).
    var mb: [1024]u8 = undefined;
    var tb: [1024]u8 = undefined;
    for (0..24) |i| {
        var nb: [16]u8 = undefined;
        const ver = try std.fmt.bufPrint(&nb, "x{d}", .{i});
        try Io.Dir.cwd().createDirPath(s.io, try s.path(&tb, &.{ "packages", "stt-model", ver }));
        for ([_][]const u8{ "txt", "sig" }) |ext| {
            var fb: [32]u8 = undefined;
            var ob: [32]u8 = undefined;
            const from = try s.path(&mb, &.{ "packages", "stt-model", ".manifests", try std.fmt.bufPrint(&ob, "1.{s}", .{ext}) });
            var data_buf: [4096]u8 = undefined;
            const data = try Io.Dir.cwd().readFile(s.io, from, &data_buf);
            try Io.Dir.cwd().writeFile(s.io, .{ .sub_path = try s.path(&tb, &.{ "packages", "stt-model", ".manifests", try std.fmt.bufPrint(&fb, "{s}.{s}", .{ ver, ext }) }), .data = data });
        }
    }
    try testing.expectEqual(@as(u64, 25 * 10), try s.usage());
    var vb: [4]Store.Version = undefined;
    try testing.expectEqual(@as(usize, 4), (try s.versions("stt-model", &vb)).len);
}

test "a corrupted or oversized file is rejected in staging; nothing is installed" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var rb: [256]u8 = undefined;
    var s = try testStore(&tmp, &rb);
    defer gpa.free(s.root);
    const kp = try manifest.Ed25519.KeyPair.generateDeterministic(@splat(4));
    const p = try TestPkg.make(gpa, kp, "stt-adapter", "1", 1, &.{ "good", "also-good" }, &.{ "a", "b" });
    defer p.destroy(gpa);
    var bad_hash: MemSource = .{ .contents = &.{ "good", "also-bad!" } };
    try testing.expectError(error.HashMismatch, s.install(&p.m, p.bytes, p.sig, &bad_hash));
    var too_long: MemSource = .{ .contents = &.{ "good", "also-good-and-more" } };
    try testing.expectError(error.SizeMismatch, s.install(&p.m, p.bytes, p.sig, &too_long));
    var too_short: MemSource = .{ .contents = &.{ "goo", "also-good" } };
    try testing.expectError(error.SizeMismatch, s.install(&p.m, p.bytes, p.sig, &too_short));
    try testing.expect((try s.current("stt-adapter")) == null);
    var vb: [8]Store.Version = undefined;
    try testing.expectEqual(@as(usize, 0), (try s.versions("stt-adapter", &vb)).len);
    // Staging and half-built folders are gone.
    try testing.expectEqual(@as(usize, 0), try s.cleanup());
    var ok: MemSource = .{ .contents = &.{ "good", "also-good" } };
    _ = try s.install(&p.m, p.bytes, p.sig, &ok);
    try testing.expectEqualStrings("1", (try s.current("stt-adapter")).?.version());
}

test "quota and staging cleanup" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var rb: [256]u8 = undefined;
    var s = try testStore(&tmp, &rb);
    defer gpa.free(s.root);
    s.quota = 20;
    const kp = try manifest.Ed25519.KeyPair.generateDeterministic(@splat(5));
    const a = try TestPkg.make(gpa, kp, "stt-model", "1", 1, &.{"0123456789"}, &.{"m"});
    defer a.destroy(gpa);
    var sa: MemSource = .{ .contents = &.{"0123456789"} };
    _ = try s.install(&a.m, a.bytes, a.sig, &sa);
    try testing.expectEqual(@as(u64, 10), try s.usage());
    const b = try TestPkg.make(gpa, kp, "stt-adapter", "1", 1, &.{"0123456789abc"}, &.{"m"});
    defer b.destroy(gpa);
    try testing.expectEqual(Offer.over_quota, try s.checkOffer(&b.m, "0.1.0"));
    var sb: MemSource = .{ .contents = &.{"0123456789abc"} };
    try testing.expectError(error.OverQuota, s.install(&b.m, b.bytes, b.sig, &sb));
    try testing.expectEqual(@as(usize, 0), sb.fetched); // refused before downloading

    // Leftovers of a crash: staging folders and a half-built version.
    var pb: [1024]u8 = undefined;
    try Io.Dir.cwd().createDirPath(s.io, try s.path(&pb, &.{ "staging", "deadbeef" }));
    try Io.Dir.cwd().writeFile(s.io, .{ .sub_path = try s.path(&pb, &.{ "staging", "deadbeef", "0" }), .data = "partial" });
    try Io.Dir.cwd().createDirPath(s.io, try s.path(&pb, &.{ "packages", "stt-model", ".incoming-1234" }));
    try testing.expectEqual(@as(usize, 2), try s.cleanup());
    try testing.expect(!exists(s.io, try s.path(&pb, &.{ "staging", "deadbeef" })));
    try testing.expect(!exists(s.io, try s.path(&pb, &.{ "packages", "stt-model", ".incoming-1234" })));
    try testing.expect(exists(s.io, try s.path(&pb, &.{ "packages", "stt-model", "1" })));
}

test "a running program is never overwritten: new versions land in new folders, in-use ones are kept" {
    if (!is_windows) return error.SkipZigTest;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var rb: [256]u8 = undefined;
    var s = try testStore(&tmp, &rb);
    defer gpa.free(s.root);
    const kp = try manifest.Ed25519.KeyPair.generateDeterministic(@splat(6));
    const v1 = try TestPkg.make(gpa, kp, "npu-probe", "1", 1, &.{"MZ-one"}, &.{"npu-probe.exe"});
    defer v1.destroy(gpa);
    var s1: MemSource = .{ .contents = &.{"MZ-one"} };
    _ = try s.install(&v1.m, v1.bytes, v1.sig, &s1);

    // "Run" v1: hold its exe open the way the loader does (no write or
    // delete sharing).
    var pb: [1024]u8 = undefined;
    const exe = try s.path(&pb, &.{ "packages", "npu-probe", "1", "npu-probe.exe" });
    const exe_w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, exe);
    defer gpa.free(exe_w);
    const h = win.CreateFileW(exe_w.ptr, win.GENERIC_READ, 0x1, null, win.OPEN_EXISTING, 0, null);
    try testing.expect(@intFromPtr(h) != win.INVALID);
    var held = true;
    defer if (held) {
        _ = win.CloseHandle(h);
    };

    const v2 = try TestPkg.make(gpa, kp, "npu-probe", "2", 2, &.{"MZ-two"}, &.{"npu-probe.exe"});
    defer v2.destroy(gpa);
    var s2: MemSource = .{ .contents = &.{"MZ-two"} };
    _ = try s.install(&v2.m, v2.bytes, v2.sig, &s2);
    const v3 = try TestPkg.make(gpa, kp, "npu-probe", "3", 3, &.{"MZ-three"}, &.{"npu-probe.exe"});
    defer v3.destroy(gpa);
    var s3: MemSource = .{ .contents = &.{"MZ-three"} };
    const r3 = try s.install(&v3.m, v3.bytes, v3.sig, &s3);
    // v1 is neither current (3) nor previous (2) but still running: kept.
    try testing.expectEqual(@as(usize, 1), r3.kept_in_use);
    try testing.expectEqual(@as(usize, 0), r3.pruned);
    var fb: [64]u8 = undefined;
    try testing.expectEqualStrings("MZ-one", try readAll(&s, &.{ "packages", "npu-probe", "1", "npu-probe.exe" }, &fb));
    try testing.expectEqualStrings("MZ-two", try readAll(&s, &.{ "packages", "npu-probe", "2", "npu-probe.exe" }, &fb));
    try testing.expectEqualStrings("MZ-three", try readAll(&s, &.{ "packages", "npu-probe", "3", "npu-probe.exe" }, &fb));

    // Once it exits, the next prune removes it.
    _ = win.CloseHandle(h);
    held = false;
    const pr = try s.prune("npu-probe");
    try testing.expectEqual(@as(usize, 1), pr.removed);
    try testing.expect(!exists(s.io, try s.path(&pb, &.{ "packages", "npu-probe", "1" })));
}

test "an existing version folder is never written into" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var rb: [256]u8 = undefined;
    var s = try testStore(&tmp, &rb);
    defer gpa.free(s.root);
    const kp = try manifest.Ed25519.KeyPair.generateDeterministic(@splat(7));
    const a = try TestPkg.make(gpa, kp, "stt-local", "1", 1, &.{"one"}, &.{"stt.exe"});
    defer a.destroy(gpa);
    var sa: MemSource = .{ .contents = &.{"one"} };
    _ = try s.install(&a.m, a.bytes, a.sig, &sa);
    // Same version name, different content and a higher sequence.
    const b = try TestPkg.make(gpa, kp, "stt-local", "1", 2, &.{"two"}, &.{"stt.exe"});
    defer b.destroy(gpa);
    var sb: MemSource = .{ .contents = &.{"two"} };
    try testing.expectError(error.VersionFolderClash, s.install(&b.m, b.bytes, b.sig, &sb));
    try testing.expectEqual(@as(usize, 0), sb.fetched);
    var fb: [16]u8 = undefined;
    try testing.expectEqualStrings("one", try readAll(&s, &.{ "packages", "stt-local", "1", "stt.exe" }, &fb));
}
