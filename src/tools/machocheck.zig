//! `machocheck FILE...`: the iPhone release check (build.zig, `zig build
//! ios` / `ios-kit` with a release -Doptimize): every Mach-O executable
//! given (the app's and the tunnel extension's) must be a 64-bit arm64
//! Mach-O, carry no debug info (no __DWARF segment, no __debug_*
//! section, no debug-map stab symbols) and embed no absolute path of the
//! machine that built it (the same kind of check as ZVC's check-dist).
//! Writes one line per file; exits 1 on the first kind of failure.

const std = @import("std");

/// Byte strings that only show up in a binary through an absolute build path.
const forbidden = [_][]const u8{ "/home/", "/Users/", "Users\\", "C:\\", "D:\\", "/private/var/folders/", "/tmp/" };

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer args.deinit();
    _ = args.next();
    var checked: usize = 0;
    var clean = true;
    while (args.next()) |path| {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(512 << 20));
        defer gpa.free(bytes);
        const name = std.fs.path.basename(path);
        if (check(bytes)) |p| {
            std.debug.print("machocheck: {s}: stripped, arm64, no build paths ({d} load commands)\n", .{ name, p.ncmds });
        } else |err| {
            clean = false;
            var b: [160]u8 = undefined;
            std.log.err("{s}: {s}", .{ name, describe(err, bytes, &b) });
        }
        checked += 1;
    }
    if (checked == 0) return error.NoBinariesGiven;
    if (!clean) std.process.exit(1);
}

pub const Error = error{ NotMachO64, NotArm64, Truncated, DebugSegment, DebugSection, DebugSymbols, BuildPath };

const MH_MAGIC_64: u32 = 0xfeedfacf;
const CPU_TYPE_ARM64: u32 = 0x0100000c;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
/// nlist_64.n_type bits: a stab (debugger) entry.
const N_STAB: u8 = 0xe0;

pub const Passed = struct { ncmds: u32 };

pub fn check(bytes: []const u8) Error!Passed {
    if (bytes.len < 32) return error.NotMachO64;
    const r = Reader{ .b = bytes };
    if (try r.u32At(0) != MH_MAGIC_64) return error.NotMachO64;
    if (try r.u32At(4) != CPU_TYPE_ARM64) return error.NotArm64;
    const ncmds = try r.u32At(16);
    var off: usize = 32;
    for (0..ncmds) |_| {
        const cmd = try r.u32At(off);
        const size = try r.u32At(off + 4);
        if (size < 8) return error.Truncated;
        switch (cmd) {
            LC_SEGMENT_64 => {
                const segname = try r.name(off + 8);
                if (std.mem.eql(u8, segname, "__DWARF")) return error.DebugSegment;
                const nsects = try r.u32At(off + 64);
                for (0..nsects) |i| {
                    const sectname = try r.name(off + 72 + i * 80);
                    if (std.mem.startsWith(u8, sectname, "__debug_") or std.mem.startsWith(u8, sectname, "__zdebug_")) return error.DebugSection;
                }
            },
            LC_SYMTAB => {
                const symoff = try r.u32At(off + 8);
                const nsyms = try r.u32At(off + 12);
                for (0..nsyms) |i| {
                    const ent = @as(usize, symoff) + i * 16;
                    if (ent + 16 > bytes.len) return error.Truncated;
                    if (bytes[ent + 4] & N_STAB != 0) return error.DebugSymbols;
                }
            },
            else => {},
        }
        off += size;
    }
    if (findForbidden(bytes) != null) return error.BuildPath;
    return .{ .ncmds = ncmds };
}

fn describe(err: Error, bytes: []const u8, buf: []u8) []const u8 {
    return switch (err) {
        error.NotMachO64 => "not a 64-bit Mach-O file",
        error.NotArm64 => "not arm64",
        error.Truncated => "truncated Mach-O load commands",
        error.DebugSegment => "has a __DWARF segment (debug info): build with a release -Doptimize",
        error.DebugSection => "has a __debug_* section (debug info)",
        error.DebugSymbols => "has debug-map (stab) symbols",
        error.BuildPath => blk: {
            const h = findForbidden(bytes).?;
            const end = std.mem.indexOfScalarPos(u8, bytes, h.offset, 0) orelse bytes.len;
            const text = bytes[h.offset..@min(end, h.offset + 100)];
            break :blk std.fmt.bufPrint(buf, "embeds a build-machine path at offset {d}: {s}", .{ h.offset, text }) catch "embeds a build-machine path";
        },
    };
}

const Hit = struct { needle: []const u8, offset: usize };

/// Case-insensitive, so `users\` or `c:\` are caught too.
fn findForbidden(bytes: []const u8) ?Hit {
    for (forbidden) |needle| {
        if (std.ascii.findIgnoreCase(bytes, needle)) |offset| return .{ .needle = needle, .offset = offset };
    }
    return null;
}

const Reader = struct {
    b: []const u8,

    fn u32At(r: Reader, off: usize) Error!u32 {
        if (off + 4 > r.b.len) return error.Truncated;
        return std.mem.readInt(u32, r.b[off..][0..4], .little);
    }

    /// A 16-byte, NUL-padded segment or section name.
    fn name(r: Reader, off: usize) Error![]const u8 {
        if (off + 16 > r.b.len) return error.Truncated;
        const n = r.b[off..][0..16];
        return n[0 .. std.mem.indexOfScalar(u8, n, 0) orelse 16];
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

/// A minimal arm64 Mach-O: the header, one LC_SEGMENT_64 named `seg`
/// with one section `sect`, and `tail` after the load commands.
fn fake(buf: []u8, seg: []const u8, sect: []const u8, tail: []const u8) []const u8 {
    @memset(buf, 0);
    std.mem.writeInt(u32, buf[0..4], MH_MAGIC_64, .little);
    std.mem.writeInt(u32, buf[4..8], CPU_TYPE_ARM64, .little);
    std.mem.writeInt(u32, buf[16..20], 1, .little);
    const lc = buf[32..];
    std.mem.writeInt(u32, lc[0..4], LC_SEGMENT_64, .little);
    std.mem.writeInt(u32, lc[4..8], 72 + 80, .little);
    @memcpy(lc[8..][0..seg.len], seg);
    std.mem.writeInt(u32, lc[64..68], 1, .little);
    @memcpy(lc[72..][0..sect.len], sect);
    const end = 32 + 72 + 80;
    @memcpy(buf[end..][0..tail.len], tail);
    return buf[0 .. end + tail.len];
}

test "stripped arm64 passes; debug info, build paths and other files fail" {
    var b: [512]u8 = undefined;
    _ = try check(fake(&b, "__TEXT", "__text", "/usr/lib/libobjc.A.dylib\x00@executable_path/Frameworks"));
    try testing.expectError(error.DebugSegment, check(fake(&b, "__DWARF", "__debug_info", "")));
    try testing.expectError(error.DebugSection, check(fake(&b, "__TEXT", "__debug_line", "")));
    try testing.expectError(error.BuildPath, check(fake(&b, "__TEXT", "__text", "x/Users/someone/src/Portal/main.zig")));
    try testing.expectError(error.BuildPath, check(fake(&b, "__TEXT", "__text", "c:\\Code\\Portal")));
    var x = b;
    std.mem.writeInt(u32, x[4..8], 7, .little);
    try testing.expectError(error.NotArm64, check(x[0..300]));
    try testing.expectError(error.NotMachO64, check("MZ not this"));
    try testing.expectError(error.Truncated, check(b[0..40]));
}
