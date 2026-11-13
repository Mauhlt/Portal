//! Build helper for `zig build package`: checks that each packaged Windows
//! executable is a PE32+ image for the expected machine and subsystem, so
//! an x86_64 exe can never end up in the aarch64 folder (or a console
//! portal.exe in either), and writes a one-line-per-file report.
//!
//!   portal-pecheck <x86_64|aarch64> <report.txt> (<gui|console> <file.exe>)...

const std = @import("std");
const Io = std.Io;

pub const Machine = enum(u16) {
    x86_64 = 0x8664, // IMAGE_FILE_MACHINE_AMD64
    aarch64 = 0xAA64, // IMAGE_FILE_MACHINE_ARM64
    _,
};

pub const Subsystem = enum(u16) {
    gui = 2, // IMAGE_SUBSYSTEM_WINDOWS_GUI
    console = 3, // IMAGE_SUBSYSTEM_WINDOWS_CUI
    _,
};

pub const Info = struct { machine: Machine, subsystem: Subsystem };

pub const ParseError = error{ NotMz, NotPe, NotPe32Plus, Truncated };

/// The machine and subsystem of a PE image (only the headers are read).
pub fn parse(bytes: []const u8) ParseError!Info {
    if (bytes.len < 0x40) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..2], "MZ")) return error.NotMz;
    const pe = std.mem.readInt(u32, bytes[0x3C..0x40], .little);
    // Signature (4) + COFF header (20) + optional header up to Subsystem (70).
    if (pe > bytes.len or bytes.len - pe < 4 + 20 + 70) return error.Truncated;
    if (!std.mem.eql(u8, bytes[pe..][0..4], "PE\x00\x00")) return error.NotPe;
    const coff = pe + 4;
    const machine: Machine = @fromBackingInt(@intCast(std.mem.readInt(u16, bytes[coff..][0..2], .little)));
    const opt = coff + 20;
    if (std.mem.readInt(u16, bytes[opt..][0..2], .little) != 0x20B) return error.NotPe32Plus;
    const subsystem: Subsystem = @fromBackingInt(@intCast(std.mem.readInt(u16, bytes[opt + 68 ..][0..2], .little)));
    return .{ .machine = machine, .subsystem = subsystem };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer args.deinit();
    _ = args.next();
    const want_machine = std.meta.stringToEnum(Machine, args.next() orelse return error.Usage) orelse return error.Usage;
    const report_path = args.next() orelse return error.Usage;

    var report: std.ArrayList(u8) = .empty;
    defer report.deinit(gpa);
    var failed = false;
    while (args.next()) |kind| {
        const want_sub = std.meta.stringToEnum(Subsystem, kind) orelse return error.Usage;
        const path = args.next() orelse return error.Usage;
        const bytes = try Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(256 << 20));
        defer gpa.free(bytes);
        const name = std.fs.path.basename(path);
        const info = parse(bytes) catch |err| {
            std.debug.print("pecheck: {s}: {t}\n", .{ path, err });
            failed = true;
            continue;
        };
        const ok = info.machine == want_machine and info.subsystem == want_sub;
        if (!ok) {
            std.debug.print("pecheck: {s}: machine 0x{X:0>4}, subsystem {d}; expected {t} {t}\n", .{ path, @backingInt(info.machine), @backingInt(info.subsystem), want_machine, want_sub });
            failed = true;
        }
        try report.print(gpa, "{s} {s} {t} {t} {d} bytes\n", .{ if (ok) "ok  " else "FAIL", name, want_machine, want_sub, bytes.len });
    }
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = report_path, .data = report.items });
    if (failed) std.process.exit(1);
}

/// A minimal PE32+ header: MZ stub, PE signature, COFF and optional header
/// up to the Subsystem field.
fn fakePe(machine: u16, subsystem: u16) [0x40 + 4 + 20 + 70]u8 {
    var b = std.mem.zeroes([0x40 + 4 + 20 + 70]u8);
    b[0] = 'M';
    b[1] = 'Z';
    std.mem.writeInt(u32, b[0x3C..0x40], 0x40, .little);
    @memcpy(b[0x40..0x44], "PE\x00\x00");
    std.mem.writeInt(u16, b[0x44..0x46], machine, .little);
    std.mem.writeInt(u16, b[0x58..0x5A], 0x20B, .little);
    std.mem.writeInt(u16, b[0x58 + 68 ..][0..2], subsystem, .little);
    return b;
}

test "reads machine and subsystem" {
    const a = fakePe(0xAA64, 2);
    try std.testing.expectEqual(Info{ .machine = .aarch64, .subsystem = .gui }, try parse(&a));
    const x = fakePe(0x8664, 3);
    try std.testing.expectEqual(Info{ .machine = .x86_64, .subsystem = .console }, try parse(&x));
}

test "rejects what is not a PE32+ image" {
    var b = fakePe(0x8664, 3);
    try std.testing.expectError(error.Truncated, parse(b[0..0x50]));
    b[0x58] = 0x0B;
    b[0x59] = 0x01; // PE32
    try std.testing.expectError(error.NotPe32Plus, parse(&b));
    b[0x40] = 'X';
    try std.testing.expectError(error.NotPe, parse(&b));
    b[0] = 'Z';
    try std.testing.expectError(error.NotMz, parse(&b));
    var far = fakePe(0x8664, 3);
    std.mem.writeInt(u32, far[0x3C..0x40], 0xFFFF_FFF0, .little);
    try std.testing.expectError(error.Truncated, parse(&far));
}
