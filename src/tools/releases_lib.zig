//! Pure logic shared by portal-release and portal-launcher: release id
//! validation, pointer-file parsing, prune selection, BUILD-INFO formatting,
//! timestamps and command-line tail extraction. No I/O here, so all of it is
//! unit tested.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Extra releases kept besides current, known-good and newest-per-zig.
pub const default_keep: usize = 4;

/// Pointer files are tiny; anything larger is treated as invalid.
pub const max_pointer_bytes: usize = 4096;

pub const current_file = "current.txt";
pub const known_good_file = "known-good.txt";
pub const history_file = "history.txt";
pub const staging_dir = "_staging";
pub const deleting_suffix = ".deleting";

const zig_marker = "_zig-";
const stamp_len = "yyyyMMdd-HHmmss".len; // 15

/// Matches ^\d{8}-\d{6}_zig-[0-9A-Za-z.+-]+$ (ASCII digits only, no trailing
/// newline accepted), and never a name ending in ".deleting". Release ids
/// become path components, so this is what keeps a corrupt pointer file from
/// naming anything outside a release dir.
pub fn isValidId(s: []const u8) bool {
    if (s.len < stamp_len + zig_marker.len + 1) return false;
    for (s[0..8]) |c| if (!std.ascii.isDigit(c)) return false;
    if (s[8] != '-') return false;
    for (s[9..15]) |c| if (!std.ascii.isDigit(c)) return false;
    if (!std.mem.eql(u8, s[15..20], zig_marker)) return false;
    for (s[20..]) |c| if (!isVersionChar(c)) return false;
    // A folder being pruned is renamed to "<id>.deleting"; never treat it as
    // a release (its suffix would otherwise pass as part of the version).
    if (std.mem.endsWith(u8, s, deleting_suffix)) return false;
    // Windows drops trailing dots from path components: "<id>." would name
    // the same folder as "<id>" while comparing unequal to it.
    if (s[s.len - 1] == '.') return false;
    return true;
}

fn isVersionChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '.' or c == '+' or c == '-';
}

/// The zig version part of a valid id ("0.18.0-dev.4+5a23bf4b2").
pub fn zigVersionOf(id: []const u8) []const u8 {
    std.debug.assert(isValidId(id));
    return id[stamp_len + zig_marker.len ..];
}

/// Builds "<stamp>_zig-<version>" into `buf`; errors if the result would not
/// be a valid id (e.g. an odd `zig version` output).
pub fn makeId(buf: []u8, stamp: []const u8, zig_version: []const u8) error{InvalidId}![]const u8 {
    const id = std.fmt.bufPrint(buf, "{s}" ++ zig_marker ++ "{s}", .{ stamp, zig_version }) catch return error.InvalidId;
    if (!isValidId(id)) return error.InvalidId;
    return id;
}

/// Returns the id stored in a pointer file's contents, or null if the
/// contents (after trimming whitespace and a UTF-8 BOM) are not a valid id.
pub fn parsePointer(contents: []const u8) ?[]const u8 {
    if (contents.len > max_pointer_bytes) return null;
    var v = contents;
    if (std.mem.startsWith(u8, v, "\xEF\xBB\xBF")) v = v[3..];
    v = std.mem.trim(u8, v, " \t\r\n\x0b\x0c");
    if (!isValidId(v)) return null;
    return v;
}

/// Release ids name folders on a case-insensitive file system, so every
/// comparison between them ignores ASCII case.
pub fn sameId(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn descending(_: void, a: []const u8, b: []const u8) bool {
    return std.ascii.lessThanIgnoreCase(b, a);
}

/// Chooses which release directories to delete. Never selects `current`,
/// `known_good`, or the newest release for each distinct zig version; of the
/// rest, the `keep` newest survive. Names that are not valid ids are ignored.
/// Ids compare case-insensitively (see sameId). Returned slices point into
/// `names`; caller frees the outer slice.
pub fn selectPrune(
    gpa: Allocator,
    names: []const []const u8,
    current: ?[]const u8,
    known_good: ?[]const u8,
    keep: usize,
) Allocator.Error![]const []const u8 {
    var valid: std.ArrayList([]const u8) = .empty;
    defer valid.deinit(gpa);
    for (names) |n| if (isValidId(n)) try valid.append(gpa, n);
    std.mem.sort([]const u8, valid.items, {}, descending);

    var seen_zig: std.ArrayList([]const u8) = .empty;
    defer seen_zig.deinit(gpa);
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(gpa);
    var kept_others: usize = 0;
    var prev: ?[]const u8 = null;
    for (valid.items) |n| {
        if (prev) |p| if (sameId(p, n)) continue; // duplicate name
        prev = n;
        var protected = false;
        if (current) |c| protected = protected or sameId(c, n);
        if (known_good) |k| protected = protected or sameId(k, n);
        const z = zigVersionOf(n);
        const first_for_zig = for (seen_zig.items) |s| {
            if (std.ascii.eqlIgnoreCase(s, z)) break false;
        } else true;
        if (first_for_zig) {
            try seen_zig.append(gpa, z);
            protected = true;
        }
        if (protected) continue;
        if (kept_others < keep) {
            kept_others += 1;
            continue;
        }
        try out.append(gpa, n);
    }
    return out.toOwnedSlice(gpa);
}

/// What reading a pointer file gave.
pub const PointerRead = union(enum) {
    /// The file does not exist (FileNotFound).
    missing,
    /// It exists but could not be read (any other error, e.g. access
    /// denied, sharing violation, too large).
    unreadable,
    contents: []const u8,
};

/// Whether pruning may run, given what reading known-good.txt gave. Pruning
/// deletes releases, so it only runs when the known-good release is known
/// for sure: there is none (no file), or the file holds a valid id. A file
/// that exists but cannot be read or validated skips pruning entirely,
/// since the known-good release could otherwise be deleted.
pub const PruneGuard = union(enum) {
    skip,
    prune: ?[]const u8,
};

pub fn pruneGuard(known_good: PointerRead) PruneGuard {
    return switch (known_good) {
        .missing => .{ .prune = null },
        .unreadable => .skip,
        .contents => |c| if (parsePointer(c)) |id| .{ .prune = id } else .skip,
    };
}

// ------------------------------------------------------------- BUILD-INFO

pub const BuildInfo = struct {
    /// Trimmed output of `<exe> version`.
    portal: []const u8,
    zig_version: []const u8,
    zig_path: []const u8,
    /// See `gitDescription`.
    git: []const u8,
    /// ISO 8601 local time with offset, see `formatIso`.
    built: []const u8,
    sha256_hex: []const u8,
};

/// BUILD-INFO.txt contents, CRLF line endings.
pub fn formatBuildInfo(gpa: Allocator, info: BuildInfo) Allocator.Error![]u8 {
    return std.fmt.allocPrint(gpa, "portal: {s}\r\n" ++
        "zig: {s}\r\n" ++
        "zig path: {s}\r\n" ++
        "git: {s}\r\n" ++
        "built: {s}\r\n" ++
        "sha256(portal.exe): {s}\r\n", .{
        info.portal, info.zig_version, info.zig_path, info.git, info.built, info.sha256_hex,
    });
}

/// "none" when there is no commit; "<hash>" or "<hash> (uncommitted changes)".
pub fn gitDescription(gpa: Allocator, rev_parse_out: ?[]const u8, porcelain_out: ?[]const u8) Allocator.Error![]u8 {
    const commit = std.mem.trim(u8, rev_parse_out orelse "", " \t\r\n");
    if (commit.len == 0) return gpa.dupe(u8, "none");
    const dirty = std.mem.trim(u8, porcelain_out orelse "", " \t\r\n").len > 0;
    return std.fmt.allocPrint(gpa, "{s}{s}", .{ commit, if (dirty) " (uncommitted changes)" else "" });
}

pub fn sha256Hex(data: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

// ------------------------------------------------------------------- time

pub const DateTime = struct {
    year: u32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    /// 100 ns units within the second, 0..9_999_999.
    ticks: u32,
};

const ticks_per_second: u64 = 10_000_000;
/// Days from 1601-01-01 (FILETIME epoch) to 1970-01-01.
const days_1601_to_1970: i64 = 134_774;

/// Converts a Windows FILETIME value (100 ns ticks since 1601-01-01).
pub fn fromFileTime(ft: u64) DateTime {
    const secs = ft / ticks_per_second;
    const sod = secs % 86_400;
    const days: i64 = @as(i64, @intCast(secs / 86_400)) - days_1601_to_1970;
    // Howard Hinnant's civil_from_days.
    const z = days + 719_468;
    const era = @divFloor(z, 146_097);
    const doe: i64 = z - era * 146_097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36_524) - @divFloor(doe, 146_096), 365);
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    const y = yoe + era * 400 + @as(i64, if (m <= 2) 1 else 0);
    return .{
        .year = @intCast(y),
        .month = @intCast(m),
        .day = @intCast(d),
        .hour = @intCast(sod / 3600),
        .minute = @intCast(sod / 60 % 60),
        .second = @intCast(sod % 60),
        .ticks = @intCast(ft % ticks_per_second),
    };
}

/// "yyyyMMdd-HHmmss"
pub fn formatStamp(buf: *[stamp_len]u8, t: DateTime) []const u8 {
    return std.fmt.bufPrint(buf, "{d:0>4}{d:0>2}{d:0>2}-{d:0>2}{d:0>2}{d:0>2}", .{
        t.year, t.month, t.day, t.hour, t.minute, t.second,
    }) catch unreachable;
}

/// Like .NET's round-trip "o" format: 2026-11-11T18:59:19.1234567-05:00.
pub fn formatIso(buf: *[33]u8, t: DateTime, utc_offset_minutes: i32) []const u8 {
    const sign: u8 = if (utc_offset_minutes < 0) '-' else '+';
    const off: u32 = @abs(utc_offset_minutes);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>7}{c}{d:0>2}:{d:0>2}", .{
        t.year, t.month, t.day, t.hour, t.minute, t.second, t.ticks, sign, off / 60, off % 60,
    }) catch unreachable;
}

/// Offset of local time from UTC in whole minutes, given the same instant as
/// FILETIME ticks in both.
pub fn utcOffsetMinutes(utc_ft: u64, local_ft: u64) i32 {
    const diff: i64 = @as(i64, @intCast(local_ft)) - @as(i64, @intCast(utc_ft));
    const per_min: i64 = 60 * @as(i64, ticks_per_second);
    return @intCast(@divFloor(diff + @divExact(per_min, 2), per_min));
}

// ------------------------------------------------------------ command line

/// Returns everything after argv[0] in a raw Windows command line, with the
/// separating whitespace removed. Uses the CommandLineToArgvW rule for the
/// program name: a leading quote runs to the next quote (no escapes),
/// otherwise the name ends at the first space or tab. Works on u8 and u16.
pub fn commandTail(comptime T: type, cmdline: []const T) []const T {
    var i: usize = 0;
    if (cmdline.len > 0 and cmdline[0] == '"') {
        i = 1;
        while (i < cmdline.len and cmdline[i] != '"') i += 1;
        if (i < cmdline.len) i += 1; // closing quote
    }
    while (i < cmdline.len and cmdline[i] != ' ' and cmdline[i] != '\t') i += 1;
    while (i < cmdline.len and (cmdline[i] == ' ' or cmdline[i] == '\t')) i += 1;
    return cmdline[i..];
}

// ------------------------------------------------------------------ paths

pub const RootError = error{ NoLocalAppData, RelativeOverride } || Allocator.Error;

pub const override_env = "PORTAL_RELEASES_DIR";
/// PORTAL_RELEASES_DIR is honoured only while this is also set to "1", so a
/// stray (or planted) variable cannot point the production launcher at
/// another folder of executables.
pub const testing_env = "PORTAL_TESTING";

pub const Override = union(enum) {
    none,
    /// Set, but PORTAL_TESTING=1 is not: ignored (callers warn).
    ignored: []const u8,
    active: []const u8,
};

/// The effective PORTAL_RELEASES_DIR, given it and PORTAL_TESTING.
pub fn releasesOverride(override: ?[]const u8, testing_flag: ?[]const u8) Override {
    const o = override orelse return .none;
    if (o.len == 0) return .none;
    const t = testing_flag orelse return .{ .ignored = o };
    if (!std.mem.eql(u8, t, "1")) return .{ .ignored = o };
    return .{ .active = o };
}

/// `p` without trailing separators, but never shorter than its root: "C:\"
/// stays "C:\" (trimming it to "C:" would mean "the current directory on
/// drive C"), "\\" stays as is.
pub fn trimTrailingSeps(p: []const u8) []const u8 {
    var s = p;
    while (s.len > 0 and (s[s.len - 1] == '\\' or s[s.len - 1] == '/')) {
        const t = s[0 .. s.len - 1];
        if (t.len == 2 and t[1] == ':') break; // "X:"
        if (std.mem.indexOfNone(u8, t, "\\/") == null) break; // only separators left
        s = t;
    }
    return s;
}

/// Releases root: `override` (an active PORTAL_RELEASES_DIR, for testing; see
/// releasesOverride) if set and non-empty, else %LOCALAPPDATA%\Portal\releases.
/// The override must be an absolute path so it never depends on the current
/// directory.
pub fn releasesRoot(gpa: Allocator, override: ?[]const u8, local_app_data: ?[]const u8) RootError![]u8 {
    if (override) |o| if (o.len > 0) {
        if (!std.fs.path.isAbsolute(o)) return error.RelativeOverride;
        return gpa.dupe(u8, trimTrailingSeps(o));
    };
    const base = local_app_data orelse return error.NoLocalAppData;
    if (base.len == 0) return error.NoLocalAppData;
    return std.fs.path.join(gpa, &.{ base, "Portal", "releases" });
}

/// Where `release` installs the launcher: a `bin` directory next to the
/// releases root (%LOCALAPPDATA%\Portal\bin by default).
pub fn launcherBinDir(gpa: Allocator, releases_root: []const u8) Allocator.Error![]u8 {
    const parent = std.fs.path.dirname(releases_root) orelse releases_root;
    return std.fs.path.join(gpa, &.{ parent, "bin" });
}

/// The exes a release holds and the launchers stand in for, with the
/// launcher build installed under each name.
pub const release_exes = [_][]const u8{ "portal.exe", "portalctl.exe", "portal-show.exe" };

/// stage\bin name of the launcher installed as `exe` (the window gets the
/// GUI-subsystem launcher, the console tools the console one).
pub fn launcherFor(exe: []const u8) []const u8 {
    return if (std.ascii.eqlIgnoreCase(exe, "portal.exe")) "portal-launcher.exe" else "portal-launcher-console.exe";
}

pub fn isOldLauncherName(name: []const u8) bool {
    if (!std.ascii.endsWithIgnoreCase(name, ".old")) return false;
    for (release_exes) |e| {
        if (name.len > e.len + 1 and std.ascii.startsWithIgnoreCase(name, e) and name[e.len] == '.') return true;
    }
    return false;
}

/// `pid` in decimal, NUL-terminated, in `buf` (the launcher's
/// PORTAL_VIA_LAUNCHER value; see src/workdir.zig).
pub fn pidWide(pid: u32, buf: *[16]u16) [*:0]const u16 {
    var digits: [10]u8 = undefined;
    const s = std.fmt.bufPrint(&digits, "{d}", .{pid}) catch unreachable; // a u32 has <= 10 digits
    for (s, 0..) |c, i| buf[i] = c;
    buf[s.len] = 0;
    return buf[0..s.len :0].ptr;
}

/// Name of the lock file held for the whole of `portal-release release`.
pub const lock_file = "release.lock";

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "isValidId accepts real ids" {
    try testing.expect(isValidId("20261111-185919_zig-0.18.0-dev.4+5a23bf4b2"));
    try testing.expect(isValidId("20261111-185919_zig-0.15.1"));
    try testing.expect(isValidId("00000000-000000_zig-x"));
}

test "isValidId rejects malformed ids" {
    const bad = [_][]const u8{
        "",
        "20261111-185919_zig-",
        "20261111-185919_zig",
        "2026111-185919_zig-0.1",
        "202611111-85919_zig-0.1",
        "20261111_185919_zig-0.1",
        "20261111-18591a_zig-0.1",
        "20261111-185919-zig-0.1",
        "20261111-185919_ZIG-0.1",
        "20261111-185919_zig-0.1\n",
        "20261111-185919_zig-0.1 ",
        " 20261111-185919_zig-0.1",
        "20261111-185919_zig-..\\..\\evil",
        "20261111-185919_zig-0.1/x",
        "20261111-185919_zig-0.1:x",
        "20261111-185919_zig-0.1\x00",
        "20261111-185919_zig-0.1&calc",
        "20261111-185919_zig-0.1\"",
        "２0261111-185919_zig-0.1", // non-ASCII digit
        "20261111-185919_zig-0.1é",
        "20261111-185919_zig-0.1.deleting",
        "20261111-185919_zig-0.1.",
        "20261111-185919_zig-.",
    };
    for (bad) |b| {
        if (isValidId(b)) {
            std.debug.print("unexpectedly valid: '{s}'\n", .{b});
            return error.TestUnexpectedResult;
        }
    }
}

test "zigVersionOf" {
    try testing.expectEqualStrings("0.18.0-dev.4+5a23bf4b2", zigVersionOf("20261111-185919_zig-0.18.0-dev.4+5a23bf4b2"));
    try testing.expectEqualStrings("x", zigVersionOf("00000000-000000_zig-x"));
}

test "makeId" {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("20261111-185919_zig-0.18.0", try makeId(&buf, "20261111-185919", "0.18.0"));
    try testing.expectError(error.InvalidId, makeId(&buf, "20261111-185919", "0.18.0 extra"));
    try testing.expectError(error.InvalidId, makeId(&buf, "20261111-185919", ""));
    try testing.expectError(error.InvalidId, makeId(&buf, "2026", "0.18.0"));
    var small: [8]u8 = undefined;
    try testing.expectError(error.InvalidId, makeId(&small, "20261111-185919", "0.18.0"));
}

test "parsePointer" {
    const id = "20261111-185919_zig-0.18.0";
    try testing.expectEqualStrings(id, parsePointer(id).?);
    try testing.expectEqualStrings(id, parsePointer(id ++ "\r\n").?);
    try testing.expectEqualStrings(id, parsePointer("  " ++ id ++ "\n\n").?);
    try testing.expectEqualStrings(id, parsePointer("\xEF\xBB\xBF" ++ id ++ "\r\n").?);
    try testing.expect(parsePointer("") == null);
    try testing.expect(parsePointer("\r\n") == null);
    try testing.expect(parsePointer(id ++ "\r\n" ++ id) == null);
    try testing.expect(parsePointer("..\\..\\Windows") == null);
    const big: [max_pointer_bytes + 1]u8 = @splat(0x78);
    try testing.expect(parsePointer(&big) == null);
}

fn expectPrune(names: []const []const u8, current: ?[]const u8, kg: ?[]const u8, keep: usize, expected: []const []const u8) !void {
    const got = try selectPrune(testing.allocator, names, current, kg, keep);
    defer testing.allocator.free(got);
    if (got.len != expected.len) {
        std.debug.print("prune: got {d} names, expected {d}\n", .{ got.len, expected.len });
        for (got) |g| std.debug.print("  got {s}\n", .{g});
        return error.TestUnexpectedResult;
    }
    for (got, expected) |g, e| try testing.expectEqualStrings(e, g);
}

test "selectPrune keeps everything when few releases" {
    const names = [_][]const u8{
        "20260101-000000_zig-a",
        "20260102-000000_zig-a",
        "20260103-000000_zig-a",
    };
    try expectPrune(&names, "20260103-000000_zig-a", null, 4, &.{});
}

test "selectPrune keeps current, known-good, newest per zig, plus keep newest" {
    const names = [_][]const u8{
        "20260101-000000_zig-old", // newest (only) for zig-old: protected
        "20260102-000000_zig-a", // known-good
        "20260103-000000_zig-a",
        "20260104-000000_zig-a",
        "20260105-000000_zig-a",
        "20260106-000000_zig-a",
        "20260107-000000_zig-a",
        "20260108-000000_zig-a",
        "20260109-000000_zig-a",
        "20260110-000000_zig-a", // current, newest zig-a
        "junk",
        "_staging",
        "20260104-000000_zig-a.deleting",
    };
    // Unprotected, newest first: 09 08 07 06 | 05 04 03 -> keep 4, prune 3.
    try expectPrune(&names, "20260110-000000_zig-a", "20260102-000000_zig-a", 4, &.{
        "20260105-000000_zig-a",
        "20260104-000000_zig-a",
        "20260103-000000_zig-a",
    });
}

test "selectPrune with keep 0 and no pointers" {
    const names = [_][]const u8{
        "20260103-000000_zig-b",
        "20260101-000000_zig-a",
        "20260102-000000_zig-a",
        "20260104-000000_zig-b",
    };
    // Newest per zig (04 b, 02 a) protected; the rest go.
    try expectPrune(&names, null, null, 0, &.{
        "20260103-000000_zig-b",
        "20260101-000000_zig-a",
    });
}

test "selectPrune never prunes current even if it is old" {
    const names = [_][]const u8{
        "20260101-000000_zig-a",
        "20260102-000000_zig-a",
        "20260103-000000_zig-a",
    };
    try expectPrune(&names, "20260101-000000_zig-a", null, 0, &.{"20260102-000000_zig-a"});
}

test "selectPrune ignores duplicate names" {
    const names = [_][]const u8{
        "20260101-000000_zig-a",
        "20260101-000000_zig-a",
        "20260102-000000_zig-a",
    };
    try expectPrune(&names, null, null, 0, &.{"20260101-000000_zig-a"});
}

test "selectPrune compares ids case-insensitively" {
    const names = [_][]const u8{
        "20260101-000000_zig-a",
        "20260102-000000_zig-a",
        "20260103-000000_zig-a",
        "20260104-000000_zig-A", // same zig version as -a on disk
    };
    // known-good written in another case must still protect its folder.
    try expectPrune(&names, "20260104-000000_zig-a", "20260101-000000_zig-A", 0, &.{
        "20260103-000000_zig-a",
        "20260102-000000_zig-a",
    });
    // Duplicates differing only in case are one folder.
    const dup = [_][]const u8{
        "20260101-000000_zig-a",
        "20260102-000000_zig-B",
        "20260102-000000_zig-b",
        "20260103-000000_zig-b",
    };
    try expectPrune(&dup, null, null, 0, &.{"20260102-000000_zig-B"});
}

test "pruneGuard skips pruning unless known-good is certain" {
    const id = "20261111-185919_zig-0.18.0";
    try testing.expectEqual(PruneGuard{ .prune = null }, pruneGuard(.missing));
    try testing.expectEqual(PruneGuard.skip, pruneGuard(.unreadable));
    try testing.expectEqual(PruneGuard.skip, pruneGuard(.{ .contents = "garbage" }));
    try testing.expectEqual(PruneGuard.skip, pruneGuard(.{ .contents = "" }));
    try testing.expectEqualStrings(id, pruneGuard(.{ .contents = id ++ "\r\n" }).prune.?);
}

test "releasesOverride needs PORTAL_TESTING=1" {
    try testing.expectEqual(Override.none, releasesOverride(null, "1"));
    try testing.expectEqual(Override.none, releasesOverride("", "1"));
    try testing.expectEqualStrings("C:\\t", releasesOverride("C:\\t", "1").active);
    try testing.expectEqualStrings("C:\\t", releasesOverride("C:\\t", null).ignored);
    try testing.expectEqualStrings("C:\\t", releasesOverride("C:\\t", "0").ignored);
    try testing.expectEqualStrings("C:\\t", releasesOverride("C:\\t", "yes").ignored);
}

test "trimTrailingSeps keeps the root" {
    try testing.expectEqualStrings("C:\\", trimTrailingSeps("C:\\"));
    try testing.expectEqualStrings("C:\\", trimTrailingSeps("C:\\\\"));
    try testing.expectEqualStrings("C:/", trimTrailingSeps("C:/"));
    try testing.expectEqualStrings("C:\\rel", trimTrailingSeps("C:\\rel\\/"));
    try testing.expectEqualStrings("\\", trimTrailingSeps("\\"));
    try testing.expectEqualStrings("\\\\srv\\share", trimTrailingSeps("\\\\srv\\share\\"));
    try testing.expectEqualStrings("rel", trimTrailingSeps("rel"));
}

test pidWide {
    var buf: [16]u16 = undefined;
    try testing.expectEqualSlices(u16, &.{ '4', '2', 0 }, pidWide(42, &buf)[0..3]);
    try testing.expectEqual(@as(usize, 10), std.mem.len(pidWide(std.math.maxInt(u32), &buf)));
}

test "formatBuildInfo" {
    const s = try formatBuildInfo(testing.allocator, .{
        .portal = "portal 0.1.0 (built with zig 0.18.0)",
        .zig_version = "0.18.0",
        .zig_path = "C:\\zig\\zig.exe",
        .git = "abc (uncommitted changes)",
        .built = "2026-11-11T18:59:19.0000000-05:00",
        .sha256_hex = "00ff",
    });
    defer testing.allocator.free(s);
    try testing.expectEqualStrings(
        "portal: portal 0.1.0 (built with zig 0.18.0)\r\n" ++
            "zig: 0.18.0\r\n" ++
            "zig path: C:\\zig\\zig.exe\r\n" ++
            "git: abc (uncommitted changes)\r\n" ++
            "built: 2026-11-11T18:59:19.0000000-05:00\r\n" ++
            "sha256(portal.exe): 00ff\r\n",
        s,
    );
}

test "gitDescription" {
    const a = testing.allocator;
    const cases = [_]struct { ?[]const u8, ?[]const u8, []const u8 }{
        .{ null, null, "none" },
        .{ "", "", "none" },
        .{ "\r\n", " M x", "none" },
        .{ "abc123\n", "", "abc123" },
        .{ "abc123\n", null, "abc123" },
        .{ "abc123\n", " M src/main.zig\n", "abc123 (uncommitted changes)" },
    };
    for (cases) |c| {
        const s = try gitDescription(a, c[0], c[1]);
        defer a.free(s);
        try testing.expectEqualStrings(c[2], s);
    }
}

test "sha256Hex" {
    try testing.expectEqualStrings(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        &sha256Hex("abc"),
    );
}

test "fromFileTime and formatting" {
    // 1970-01-01T00:00:00 is 116444736000000000 ticks after 1601.
    const unix_epoch: u64 = 116_444_736_000_000_000;
    const t0 = fromFileTime(unix_epoch);
    try testing.expectEqual(DateTime{ .year = 1970, .month = 1, .day = 1, .hour = 0, .minute = 0, .second = 0, .ticks = 0 }, t0);

    // 2026-11-11T18:59:19.1234567 = unix 1794423559.
    const ft = unix_epoch + 1_794_423_559 * ticks_per_second + 1_234_567;
    const t = fromFileTime(ft);
    var sb: [15]u8 = undefined;
    try testing.expectEqualStrings("20261111-185919", formatStamp(&sb, t));
    var ib: [33]u8 = undefined;
    try testing.expectEqualStrings("2026-11-11T18:59:19.1234567-05:00", formatIso(&ib, t, -300));
    try testing.expectEqualStrings("2026-11-11T18:59:19.1234567+05:30", formatIso(&ib, t, 330));
    try testing.expectEqualStrings("2026-11-11T18:59:19.1234567+00:00", formatIso(&ib, t, 0));

    // Leap day and end of year.
    const leap = fromFileTime(unix_epoch + 951_782_400 * ticks_per_second); // 2000-02-29
    try testing.expectEqual(@as(u32, 2000), leap.year);
    try testing.expectEqual(@as(u8, 2), leap.month);
    try testing.expectEqual(@as(u8, 29), leap.day);
    const nye = fromFileTime(unix_epoch + 1_798_761_599 * ticks_per_second); // 2026-12-31T23:59:59
    try testing.expectEqualStrings("20261231-235959", formatStamp(&sb, nye));
    // FILETIME epoch itself.
    try testing.expectEqualStrings("16010101-000000", formatStamp(&sb, fromFileTime(0)));
}

test "utcOffsetMinutes" {
    const base: u64 = 133_000_000_000_000_000;
    const min: u64 = 60 * ticks_per_second;
    try testing.expectEqual(@as(i32, 0), utcOffsetMinutes(base, base));
    try testing.expectEqual(@as(i32, -300), utcOffsetMinutes(base, base - 300 * min));
    try testing.expectEqual(@as(i32, 330), utcOffsetMinutes(base, base + 330 * min));
    // Sub-minute jitter between the two clock reads rounds away.
    try testing.expectEqual(@as(i32, -300), utcOffsetMinutes(base, base - 300 * min + 7));
}

test "commandTail" {
    const cases = [_][2][]const u8{
        .{ "portal", "" },
        .{ "portal ", "" },
        .{ "portal version", "version" },
        .{ "portal   run --listen 1.2.3.4:5 -- agent", "run --listen 1.2.3.4:5 -- agent" },
        .{ "\"C:\\Program Files\\portal.exe\" run \"a b\"", "run \"a b\"" },
        .{ "\"C:\\x y\\portal.exe\"", "" },
        .{ "\"C:\\x y\\portal.exe\"\t\tversion", "version" },
        .{ "C:\\bin\\portal.exe\t\"q\" x\\\"y", "\"q\" x\\\"y" },
        .{ "\"unterminated", "" },
        .{ "", "" },
    };
    for (cases) |c| try testing.expectEqualStrings(c[1], commandTail(u8, c[0]));
    const w = std.unicode.utf8ToUtf16LeStringLiteral("\"a b\" run x");
    try testing.expectEqualSlices(u16, std.unicode.utf8ToUtf16LeStringLiteral("run x"), commandTail(u16, w));
}

test "releasesRoot and launcherBinDir" {
    const a = testing.allocator;
    const r1 = try releasesRoot(a, null, "C:\\Users\\u\\AppData\\Local");
    defer a.free(r1);
    try testing.expectEqualStrings("C:\\Users\\u\\AppData\\Local\\Portal\\releases", r1);
    const r2 = try releasesRoot(a, "C:\\tmp\\rel\\", "C:\\ignored");
    defer a.free(r2);
    try testing.expectEqualStrings("C:\\tmp\\rel", r2);
    const r4 = try releasesRoot(a, "C:\\", "C:\\ignored");
    defer a.free(r4);
    try testing.expectEqualStrings("C:\\", r4);
    const r3 = try releasesRoot(a, "", "C:\\L");
    defer a.free(r3);
    try testing.expectEqualStrings("C:\\L\\Portal\\releases", r3);
    try testing.expectError(error.RelativeOverride, releasesRoot(a, "rel", "C:\\L"));
    try testing.expectError(error.NoLocalAppData, releasesRoot(a, null, null));
    try testing.expectError(error.NoLocalAppData, releasesRoot(a, null, ""));

    const b1 = try launcherBinDir(a, r1);
    defer a.free(b1);
    try testing.expectEqualStrings("C:\\Users\\u\\AppData\\Local\\Portal\\bin", b1);
}

test "isOldLauncherName" {
    try testing.expect(isOldLauncherName("portal.exe.20261111-185919.old"));
    try testing.expect(isOldLauncherName("PORTAL.EXE.1.OLD"));
    try testing.expect(!isOldLauncherName("portal.exe"));
    try testing.expect(!isOldLauncherName("other.exe.1.old"));
    try testing.expect(isOldLauncherName("portalctl.exe.20261111-185919.old"));
    try testing.expect(isOldLauncherName("portal-show.exe.1.old"));
    try testing.expect(!isOldLauncherName("portalctl.exe"));
    try testing.expectEqualStrings("portal-launcher.exe", launcherFor("portal.exe"));
    try testing.expectEqualStrings("portal-launcher-console.exe", launcherFor("portalctl.exe"));
    try testing.expectEqualStrings("portal-launcher-console.exe", launcherFor("portal-show.exe"));
}
