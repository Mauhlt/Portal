//! The device side of Portal sync: where verified packages are installed.
//!
//!   <root>\                               %LOCALAPPDATA%\Portal\sync
//!     staging\<random>\<n>                one download being verified, file
//!                                         n of its manifest (by index, never
//!                                         by a path from the network);
//!                                         deleted afterwards, and on every
//!                                         start
//!     packages\<pkg>\<version>\...        verified, read-only, immutable
//!     packages\<pkg>\.manifests\<ver>.txt the signed manifest it came from
//!     packages\<pkg>\.manifests\<ver>.sig  (and its signature, hex)
//!     current\<pkg>.txt                   atomic pointer (temp + MoveFileEx
//!                                         REPLACE_EXISTING | WRITE_THROUGH)
//!     previous\<pkg>.txt                  the last good version (rollback)
//!     data\<pkg>\                         the package's own writable state
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
//!     replay), except for an explicit local `rollback`;
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
const pointer_header = "portal-sync-pointer-v1";
const max_pointer_bytes = 512;

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
} || Allocator.Error;

/// What current\<pkg>.txt and previous\<pkg>.txt hold.
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

    fn format(p: *const Pointer, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, pointer_header ++ "\nversion {s}\nsequence {d}\nhighest {d}\n", .{ p.version(), p.sequence, p.highest }) catch buf[0..0];
    }

    pub fn parse(text: []const u8) Error!Pointer {
        var it = std.mem.splitScalar(u8, text, '\n');
        if (!std.mem.eql(u8, it.next() orelse "", pointer_header)) return error.BadPointer;
        const v = field(it.next(), "version ") orelse return error.BadPointer;
        if (!manifest.validVersion(v)) return error.BadPointer;
        const s = std.fmt.parseInt(u64, field(it.next(), "sequence ") orelse return error.BadPointer, 10) catch return error.BadPointer;
        const h = std.fmt.parseInt(u64, field(it.next(), "highest ") orelse return error.BadPointer, 10) catch return error.BadPointer;
        if (!std.mem.eql(u8, it.next() orelse "x", "") or it.next() != null) return error.BadPointer;
        if (s == 0 or h < s) return error.BadPointer;
        return init(v, s, h);
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
    /// Absolute path of the sync folder (…\Portal\sync).
    root: []const u8,
    quota: u64 = default_quota,

    /// Creates the layout's folders if needed.
    pub fn open(gpa: Allocator, io: Io, root: []const u8) !Store {
        const s: Store = .{ .gpa = gpa, .io = io, .root = root };
        for ([_][]const u8{ "staging", "packages", "current", "previous", "data" }) |d| {
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

    fn pointerPath(s: *const Store, buf: []u8, which: []const u8, pkg: []const u8) ![]const u8 {
        var nb: [64]u8 = undefined;
        return s.path(buf, &.{ which, try std.fmt.bufPrint(&nb, "{s}.txt", .{pkg}) });
    }

    fn readPointer(s: *const Store, which: []const u8, pkg: []const u8) !?Pointer {
        var pb: [1024]u8 = undefined;
        var fb: [max_pointer_bytes]u8 = undefined;
        const text = Io.Dir.cwd().readFile(s.io, try s.pointerPath(&pb, which, pkg), &fb) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        return try Pointer.parse(text);
    }

    pub fn current(s: *const Store, pkg: []const u8) !?Pointer {
        return s.readPointer("current", pkg);
    }

    pub fn previous(s: *const Store, pkg: []const u8) !?Pointer {
        return s.readPointer("previous", pkg);
    }

    /// Writes a pointer: temp file, flushed, then an atomic replace that
    /// is itself written through to disk.
    fn writePointer(s: *const Store, which: []const u8, pkg: []const u8, p: Pointer) !void {
        var pb: [1024]u8 = undefined;
        const final = try s.pointerPath(&pb, which, pkg);
        var tb: [1100]u8 = undefined;
        var rnd: [8]u8 = undefined;
        s.io.random(&rnd);
        const tmp = try std.fmt.bufPrint(&tb, "{s}.{x}.tmp", .{ final, &rnd });
        var buf: [max_pointer_bytes]u8 = undefined;
        try writeFlushed(s.io, tmp, p.format(&buf), true);
        errdefer Io.Dir.cwd().deleteFile(s.io, tmp) catch {};
        try replaceFile(s.gpa, s.io, tmp, final);
    }

    fn deletePointer(s: *const Store, which: []const u8, pkg: []const u8) !void {
        var pb: [1024]u8 = undefined;
        Io.Dir.cwd().deleteFile(s.io, try s.pointerPath(&pb, which, pkg)) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }

    // ------------------------------------------------------------ policy

    pub fn checkOffer(s: *const Store, m: *const Manifest, client_version: []const u8) !Offer {
        if (manifest.compareClientVersions(client_version, m.min_client) < 0) return .needs_newer_client;
        if (try s.current(m.package)) |cur| {
            if (cur.sequence == m.sequence and std.mem.eql(u8, cur.version(), m.version)) return .up_to_date;
            if (m.sequence <= cur.highest) return if (m.sequence < cur.sequence) .downgrade else .replay;
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
            var vb: [16]Version = undefined;
            const vs = try s.versions(e.name, &vb);
            for (vs) |v| total +|= v.size;
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
        var pb: [1024]u8 = undefined;
        var dir = Io.Dir.cwd().openDir(s.io, try s.path(&pb, &.{ "packages", pkg }), .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return out[0..0],
            else => return err,
        };
        defer dir.close(s.io);
        var n: usize = 0;
        var it = dir.iterate();
        while (try it.next(s.io)) |e| {
            if (n == out.len) break;
            if (e.kind != .directory or !manifest.validVersion(e.name)) continue;
            const m_bytes = s.readInstalledManifest(pkg, e.name) catch continue;
            defer s.gpa.free(m_bytes.text);
            var m = manifest.parse(s.gpa, m_bytes.text) catch continue;
            defer m.deinit(s.gpa);
            var v: Version = .{ .size = m.totalSize(), .sequence = m.sequence };
            @memcpy(v.name_buf[0..e.name.len], e.name);
            v.name_len = @intCast(e.name.len);
            out[n] = v;
            n += 1;
        }
        return out[0..n];
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
        if (try s.current(m.package)) |cur| {
            const same = cur.sequence == m.sequence and std.mem.eql(u8, cur.version(), m.version);
            if (!same and m.sequence <= cur.highest) return error.Downgrade;
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

        // Pointers: the old current becomes previous, then the new current.
        const old = try s.current(m.package);
        var highest = m.sequence;
        if (old) |o| {
            highest = @max(highest, o.highest);
            if (!std.mem.eql(u8, o.version(), m.version)) try s.writePointer("previous", m.package, o);
        }
        try s.writePointer("current", m.package, Pointer.init(m.version, m.sequence, highest));

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
        const cur = (try s.current(pkg)) orelse return error.NotInstalled;
        const prev = (try s.previous(pkg)) orelse return error.NothingToRollBack;
        var vb: [1024]u8 = undefined;
        if (!exists(s.io, try s.path(&vb, &.{ "packages", pkg, prev.version() }))) return error.NothingToRollBack;
        const highest = @max(cur.highest, prev.highest);
        try s.writePointer("previous", pkg, Pointer.init(cur.version(), cur.sequence, highest));
        const now = Pointer.init(prev.version(), prev.sequence, highest);
        try s.writePointer("current", pkg, now);
        return now;
    }

    // -------------------------------------------------------------- prune

    pub const Pruned = struct { removed: usize = 0, in_use: usize = 0 };

    /// Deletes version folders of `pkg` other than current and previous,
    /// unless a file in them is in use (e.g. a running program).
    pub fn prune(s: *Store, pkg: []const u8) !Pruned {
        const io = s.io;
        var r: Pruned = .{};
        const cur = try s.current(pkg);
        const prev = try s.previous(pkg);
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

    /// Packages with a current pointer.
    pub fn installedPackages(s: *const Store, out: [][manifest.max_package_id]u8, lens: []u8) !usize {
        var pb: [1024]u8 = undefined;
        var dir = Io.Dir.cwd().openDir(s.io, try s.path(&pb, &.{"current"}), .{ .iterate = true }) catch return 0;
        defer dir.close(s.io);
        var n: usize = 0;
        var it = dir.iterate();
        while (try it.next(s.io)) |e| {
            if (n == out.len) break;
            if (!std.mem.endsWith(u8, e.name, ".txt")) continue;
            const id = e.name[0 .. e.name.len - 4];
            if (!manifest.validPackageId(id)) continue;
            @memcpy(out[n][0..id.len], id);
            lens[n] = @intCast(id.len);
            n += 1;
        }
        return n;
    }
};

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
    return Store.open(testing.allocator, io, abs);
}

fn readAll(s: *const Store, parts: []const []const u8, buf: []u8) ![]u8 {
    var pb: [1024]u8 = undefined;
    return Io.Dir.cwd().readFile(s.io, try s.path(&pb, parts), buf);
}

test "pointer format is strict" {
    const p = Pointer.init("1.2", 5, 7);
    var b: [256]u8 = undefined;
    const t = p.format(&b);
    const q = try Pointer.parse(t);
    try testing.expectEqualStrings("1.2", q.version());
    try testing.expectEqual(@as(u64, 7), q.highest);
    try testing.expectError(error.BadPointer, Pointer.parse("portal-sync-pointer-v1\nversion ../x\nsequence 1\nhighest 1\n"));
    try testing.expectError(error.BadPointer, Pointer.parse("portal-sync-pointer-v1\nversion 1\nsequence 3\nhighest 2\n"));
    try testing.expectError(error.BadPointer, Pointer.parse("portal-sync-pointer-v1\nversion 1\nsequence 1\nhighest 1\nx"));
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
