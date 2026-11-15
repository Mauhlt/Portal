//! portal-mac-bundle: builds the Mac's Portal.app pieces on any OS (no
//! Xcode, no Mac), for `zig build mac-installer`:
//!
//!   portal-mac-bundle lipo OUT THIN...       a universal (fat) Mach-O
//!   portal-mac-bundle plist OUT VERSION      Contents/Info.plist
//!   portal-mac-bundle icns OUT TYPE=PNG...   an .icns of PNG entries
//!   portal-mac-bundle zip OUT DIR            a zip of DIR (stored, with
//!                                            Unix modes: 0755 for the
//!                                            executable and dylibs)
//!
//! Each thin slice keeps its own code signature (Zig's linker signs arm64
//! macOS output ad hoc; signatures are per slice). The bundle's layout and
//! Info.plist come from client/src/macinstall.zig (module "macinstall"),
//! the same file the app uses to install itself.

const std = @import("std");
const Allocator = std.mem.Allocator;
const mi = @import("macinstall");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var list: std.ArrayList([]const u8) = .empty;
    defer list.deinit(gpa);
    var it: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |a| try list.append(gpa, a);
    const args = list.items;
    if (args.len < 2) return usage();
    const cwd = std.Io.Dir.cwd();
    const cmd = args[0];
    const out = args[1];
    if (std.mem.eql(u8, cmd, "lipo")) {
        var thins: std.ArrayList([]const u8) = .empty;
        defer {
            for (thins.items) |t| gpa.free(t);
            thins.deinit(gpa);
        }
        for (args[2..]) |p| try thins.append(gpa, try cwd.readFileAlloc(io, p, gpa, .limited(512 << 20)));
        const fat = try lipo(gpa, thins.items);
        defer gpa.free(fat);
        try cwd.writeFile(io, .{ .sub_path = out, .data = fat });
    } else if (std.mem.eql(u8, cmd, "plist") and args.len == 3) {
        var b: [4096]u8 = undefined;
        try cwd.writeFile(io, .{ .sub_path = out, .data = try mi.infoPlist(&b, args[2]) });
    } else if (std.mem.eql(u8, cmd, "icns")) {
        var entries: std.ArrayList(IcnsEntry) = .empty;
        defer {
            for (entries.items) |e| gpa.free(e.png);
            entries.deinit(gpa);
        }
        for (args[2..]) |a| {
            const eq = std.mem.indexOfScalar(u8, a, '=') orelse return usage();
            if (eq != 4) return usage();
            try entries.append(gpa, .{ .kind = a[0..4].*, .png = try cwd.readFileAlloc(io, a[5..], gpa, .limited(16 << 20)) });
        }
        const icns = try icnsFile(gpa, entries.items);
        defer gpa.free(icns);
        try cwd.writeFile(io, .{ .sub_path = out, .data = icns });
    } else if (std.mem.eql(u8, cmd, "zip") and args.len == 3) {
        const z = try zipDir(gpa, io, args[2]);
        defer gpa.free(z);
        try cwd.writeFile(io, .{ .sub_path = out, .data = z });
    } else return usage();
}

fn usage() void {
    std.debug.print("usage: portal-mac-bundle lipo OUT THIN... | plist OUT VERSION | icns OUT TYPE=PNG... | zip OUT DIR\n", .{});
    std.process.exit(2);
}

// ------------------------------------------------------------------ lipo

const MH_MAGIC_64: u32 = 0xfeedfacf;
const FAT_MAGIC: u32 = 0xcafebabe;
/// Slices start on 16 KiB (2^14) boundaries, as lipo places arm64 ones.
const fat_align: u5 = 14;

/// A universal binary of the thin 64-bit Mach-O `thins` (big-endian fat
/// header, one fat_arch per slice).
pub fn lipo(gpa: Allocator, thins: []const []const u8) ![]u8 {
    if (thins.len == 0) return error.NoSlices;
    const header = 8 + 20 * thins.len;
    var offsets: [8]u32 = undefined;
    if (thins.len > offsets.len) return error.TooManySlices;
    var end: usize = header;
    for (thins, 0..) |t, i| {
        if (t.len < 32 or std.mem.readInt(u32, t[0..4], .little) != MH_MAGIC_64) return error.NotThinMachO64;
        end = std.mem.alignForward(usize, end, @as(usize, 1) << fat_align);
        offsets[i] = @intCast(end);
        end += t.len;
    }
    const out = try gpa.alloc(u8, end);
    @memset(out, 0);
    std.mem.writeInt(u32, out[0..4], FAT_MAGIC, .big);
    std.mem.writeInt(u32, out[4..8], @intCast(thins.len), .big);
    for (thins, 0..) |t, i| {
        const a = out[8 + 20 * i ..][0..20];
        std.mem.writeInt(u32, a[0..4], std.mem.readInt(u32, t[4..8], .little), .big); // cputype
        std.mem.writeInt(u32, a[4..8], std.mem.readInt(u32, t[8..12], .little), .big); // cpusubtype
        std.mem.writeInt(u32, a[8..12], offsets[i], .big);
        std.mem.writeInt(u32, a[12..16], @intCast(t.len), .big);
        std.mem.writeInt(u32, a[16..20], fat_align, .big);
        @memcpy(out[offsets[i]..][0..t.len], t);
    }
    return out;
}

// ------------------------------------------------------------------ icns

pub const IcnsEntry = struct { kind: [4]u8, png: []const u8 };

/// An .icns: "icns", the total length, then each entry (type, length
/// including its 8-byte header, PNG data), all big-endian.
pub fn icnsFile(gpa: Allocator, entries: []const IcnsEntry) ![]u8 {
    var total: usize = 8;
    for (entries) |e| total += 8 + e.png.len;
    const out = try gpa.alloc(u8, total);
    @memcpy(out[0..4], "icns");
    std.mem.writeInt(u32, out[4..8], @intCast(total), .big);
    var at: usize = 8;
    for (entries) |e| {
        @memcpy(out[at..][0..4], &e.kind);
        std.mem.writeInt(u32, out[at + 4 ..][0..4], @intCast(8 + e.png.len), .big);
        @memcpy(out[at + 8 ..][0..e.png.len], e.png);
        at += 8 + e.png.len;
    }
    return out;
}

// ------------------------------------------------------------------- zip

pub const ZipFile = struct { name: []const u8, data: []const u8, mode: u16 };

/// A zip of `files` (stored, no compression), with Unix modes so the
/// executable bit survives Finder's and `ditto`'s extraction. Directory
/// entries are implied by the names.
pub fn zip(gpa: Allocator, files: []const ZipFile) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var central: std.ArrayList(u8) = .empty;
    defer central.deinit(gpa);
    // A fixed time (1980-01-01): the same input gives the same zip.
    const dos_time: u16 = 0;
    const dos_date: u16 = (0 << 9) | (1 << 5) | 1;
    for (files) |f| {
        const crc = std.hash.Crc32.hash(f.data);
        const offset: u32 = @intCast(out.items.len);
        var lh: [30]u8 = undefined;
        std.mem.writeInt(u32, lh[0..4], 0x04034b50, .little);
        std.mem.writeInt(u16, lh[4..6], 10, .little); // version needed
        std.mem.writeInt(u16, lh[6..8], 0x0800, .little); // UTF-8 names
        std.mem.writeInt(u16, lh[8..10], 0, .little); // stored
        std.mem.writeInt(u16, lh[10..12], dos_time, .little);
        std.mem.writeInt(u16, lh[12..14], dos_date, .little);
        std.mem.writeInt(u32, lh[14..18], crc, .little);
        std.mem.writeInt(u32, lh[18..22], @intCast(f.data.len), .little);
        std.mem.writeInt(u32, lh[22..26], @intCast(f.data.len), .little);
        std.mem.writeInt(u16, lh[26..28], @intCast(f.name.len), .little);
        std.mem.writeInt(u16, lh[28..30], 0, .little);
        try out.appendSlice(gpa, &lh);
        try out.appendSlice(gpa, f.name);
        try out.appendSlice(gpa, f.data);

        var ch: [46]u8 = undefined;
        std.mem.writeInt(u32, ch[0..4], 0x02014b50, .little);
        std.mem.writeInt(u16, ch[4..6], (3 << 8) | 20, .little); // made by Unix
        std.mem.writeInt(u16, ch[6..8], 10, .little);
        std.mem.writeInt(u16, ch[8..10], 0x0800, .little);
        std.mem.writeInt(u16, ch[10..12], 0, .little);
        std.mem.writeInt(u16, ch[12..14], dos_time, .little);
        std.mem.writeInt(u16, ch[14..16], dos_date, .little);
        std.mem.writeInt(u32, ch[16..20], crc, .little);
        std.mem.writeInt(u32, ch[20..24], @intCast(f.data.len), .little);
        std.mem.writeInt(u32, ch[24..28], @intCast(f.data.len), .little);
        std.mem.writeInt(u16, ch[28..30], @intCast(f.name.len), .little);
        std.mem.writeInt(u16, ch[30..32], 0, .little);
        std.mem.writeInt(u16, ch[32..34], 0, .little);
        std.mem.writeInt(u16, ch[34..36], 0, .little);
        std.mem.writeInt(u16, ch[36..38], 0, .little);
        std.mem.writeInt(u32, ch[38..42], @as(u32, 0o100000 | @as(u32, f.mode)) << 16, .little); // S_IFREG | mode
        std.mem.writeInt(u32, ch[42..46], offset, .little);
        try central.appendSlice(gpa, &ch);
        try central.appendSlice(gpa, f.name);
    }
    const cd_offset: u32 = @intCast(out.items.len);
    try out.appendSlice(gpa, central.items);
    var eocd: [22]u8 = undefined;
    std.mem.writeInt(u32, eocd[0..4], 0x06054b50, .little);
    std.mem.writeInt(u16, eocd[4..6], 0, .little);
    std.mem.writeInt(u16, eocd[6..8], 0, .little);
    std.mem.writeInt(u16, eocd[8..10], @intCast(files.len), .little);
    std.mem.writeInt(u16, eocd[10..12], @intCast(files.len), .little);
    std.mem.writeInt(u32, eocd[12..16], @intCast(central.items.len), .little);
    std.mem.writeInt(u32, eocd[16..20], cd_offset, .little);
    std.mem.writeInt(u16, eocd[20..22], 0, .little);
    try out.appendSlice(gpa, &eocd);
    return out.toOwnedSlice(gpa);
}

/// Every file under `dir` (which holds Portal.app), named with `/`
/// (Portal.app/Contents/...), sorted, with the bundle's modes.
fn zipDir(gpa: Allocator, io: std.Io, dir: []const u8) ![]u8 {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var d = try std.Io.Dir.cwd().openDir(io, dir, .{ .iterate = true });
    defer d.close(io);
    var files: std.ArrayList(ZipFile) = .empty;
    var walker = try d.walk(a);
    while (try walker.next(io)) |e| {
        if (e.kind != .file) continue;
        const rel = try a.dupe(u8, e.path);
        std.mem.replaceScalar(u8, rel, '\\', '/');
        const inside = if (std.mem.startsWith(u8, rel, mi.app_dir ++ "/")) rel[mi.app_dir.len + 1 ..] else rel;
        try files.append(a, .{
            .name = rel,
            .data = try d.readFileAlloc(io, e.path, a, .limited(512 << 20)),
            .mode = if (mi.isExecutable(inside)) 0o755 else 0o644,
        });
    }
    std.mem.sort(ZipFile, files.items, {}, struct {
        fn lt(_: void, x: ZipFile, y: ZipFile) bool {
            return std.mem.lessThan(u8, x.name, y.name);
        }
    }.lt);
    return zip(gpa, files.items);
}

// ----------------------------------------------------------------- tests

const testing = std.testing;

fn fakeThin(comptime cpu: u32, comptime sub: u32, comptime fill: u8) [64]u8 {
    var b: [64]u8 = @splat(fill);
    std.mem.writeInt(u32, b[0..4], MH_MAGIC_64, .little);
    std.mem.writeInt(u32, b[4..8], cpu, .little);
    std.mem.writeInt(u32, b[8..12], sub, .little);
    return b;
}

test "lipo: a fat header over aligned slices, each byte for byte" {
    const arm = fakeThin(0x0100000c, 0, 0xaa);
    const x86 = fakeThin(0x01000007, 3, 0xbb);
    const fat = try lipo(testing.allocator, &.{ &arm, &x86 });
    defer testing.allocator.free(fat);
    try testing.expectEqual(FAT_MAGIC, std.mem.readInt(u32, fat[0..4], .big));
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, fat[4..8], .big));
    try testing.expectEqual(@as(u32, 0x0100000c), std.mem.readInt(u32, fat[8..12], .big));
    const off0 = std.mem.readInt(u32, fat[16..20], .big);
    const off1 = std.mem.readInt(u32, fat[36..40], .big);
    try testing.expectEqual(@as(u32, 1 << 14), off0);
    try testing.expectEqual(@as(u32, 2 << 14), off1);
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, fat[32..36], .big)); // x86_64 subtype
    try testing.expectEqualSlices(u8, &arm, fat[off0..][0..64]);
    try testing.expectEqualSlices(u8, &x86, fat[off1..][0..64]);
    try testing.expectError(error.NotThinMachO64, lipo(testing.allocator, &.{"not a mach-o, not at all, really not; padding to 32+"}));
}

test "icns: header and entries" {
    const i = try icnsFile(testing.allocator, &.{ .{ .kind = "ic10".*, .png = "PNG1" }, .{ .kind = "icp4".*, .png = "P2" } });
    defer testing.allocator.free(i);
    try testing.expectEqualStrings("icns", i[0..4]);
    try testing.expectEqual(@as(u32, @intCast(i.len)), std.mem.readInt(u32, i[4..8], .big));
    try testing.expectEqualStrings("ic10", i[8..12]);
    try testing.expectEqual(@as(u32, 12), std.mem.readInt(u32, i[12..16], .big));
    try testing.expectEqualStrings("PNG1", i[16..20]);
    try testing.expectEqualStrings("icp4", i[20..24]);
}

test "zip: std reads it back; modes and names are kept" {
    const files = [_]ZipFile{
        .{ .name = "Portal.app/Contents/Info.plist", .data = "<plist/>", .mode = 0o644 },
        .{ .name = "Portal.app/Contents/MacOS/Portal", .data = "binary", .mode = 0o755 },
    };
    const z = try zip(testing.allocator, &files);
    defer testing.allocator.free(z);
    // The central directory's external attributes carry 0100755.
    const cd = std.mem.indexOf(u8, z, "PK\x01\x02").?;
    const second = cd + 46 + files[0].name.len;
    try testing.expectEqual(@as(u32, 0o100755), std.mem.readInt(u32, z[second + 38 ..][0..4], .little) >> 16);
    // std's reader extracts both, with the right contents.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "t.zip", .data = z });
    var f = try tmp.dir.openFile(io, "t.zip", .{});
    defer f.close(io);
    var rb: [4096]u8 = undefined;
    var r = f.reader(io, &rb);
    try tmp.dir.createDirPath(io, "out");
    var out = try tmp.dir.openDir(io, "out", .{});
    defer out.close(io);
    try std.zip.extract(out, &r, .{});
    var b: [64]u8 = undefined;
    try testing.expectEqualStrings("binary", try out.readFile(io, "Portal.app/Contents/MacOS/Portal", &b));
    try testing.expectEqualStrings("<plist/>", try out.readFile(io, "Portal.app/Contents/Info.plist", &b));
}
