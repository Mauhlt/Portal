//! What kind of machine a device is: its OS and CPU, nothing else (no
//! model, no version, nothing identifying). A device says it once per
//! interactive WebSocket, right after `hello`, as the frame
//! `d:platform <name>` (frames.zig; docs/protocol.md section 4), so the
//! desk can subscribe it to the packages that run on it (the laptop speech
//! engine is built for aarch64 Windows only). The desk keeps it in memory
//! for the device; a malformed or unknown name is ignored (unknown).

const std = @import("std");
const builtin = @import("builtin");

pub const Platform = enum {
    windows_x86_64,
    windows_aarch64,
    linux_x86_64,
    linux_aarch64,
    macos_aarch64,
    ios_aarch64,

    /// The wire name: "windows-aarch64".
    pub fn name(p: Platform) []const u8 {
        return switch (p) {
            inline else => |t| comptime blk: {
                var n: [@tagName(t).len]u8 = @tagName(t)[0..].*;
                std.mem.replaceScalar(u8, &n, '_', '-');
                const f = n;
                break :blk &f;
            },
        };
    }

    /// A wire name, exactly; null for anything else.
    pub fn parse(text: []const u8) ?Platform {
        inline for (comptime std.enums.values(Platform)) |p| {
            if (std.mem.eql(u8, text, p.name())) return p;
        }
        return null;
    }
};

/// This build's platform, or null for one not in the list.
pub fn current() ?Platform {
    return of(builtin.os.tag, builtin.cpu.arch);
}

pub fn of(os: std.Target.Os.Tag, arch: std.Target.Cpu.Arch) ?Platform {
    return switch (os) {
        .windows => switch (arch) {
            .x86_64 => .windows_x86_64,
            .aarch64 => .windows_aarch64,
            else => null,
        },
        .linux => switch (arch) {
            .x86_64 => .linux_x86_64,
            .aarch64 => .linux_aarch64,
            else => null,
        },
        .macos => if (arch == .aarch64) .macos_aarch64 else null,
        .ios => if (arch == .aarch64) .ios_aarch64 else null,
        else => null,
    };
}

/// The frame's verb (`d:platform <name>`).
pub const verb = "platform";
pub const max_frame = 2 + verb.len + 1 + 16;

/// `d:platform <name>` for `p`.
pub fn frame(p: Platform, buf: *[max_frame]u8) []const u8 {
    return std.fmt.bufPrint(buf, "d:" ++ verb ++ " {s}", .{p.name()}) catch unreachable;
}

/// The platform a `d:` frame's rest names; null: not `platform <name>`
/// with a known name (ignored).
pub fn parseRest(rest: []const u8) ?Platform {
    const prefix = verb ++ " ";
    if (!std.mem.startsWith(u8, rest, prefix)) return null;
    return Platform.parse(rest[prefix.len..]);
}

const testing = std.testing;

test "wire names round-trip; anything else is unknown" {
    inline for (comptime std.enums.values(Platform)) |p| {
        try testing.expectEqual(@as(?Platform, p), Platform.parse(p.name()));
        var b: [max_frame]u8 = undefined;
        const fr = frame(p, &b);
        try testing.expectEqual(@as(?Platform, p), parseRest(fr[2..]));
    }
    try testing.expectEqualStrings("windows-aarch64", Platform.windows_aarch64.name());
    for ([_][]const u8{ "", "platform", "platform ", "platform windows_aarch64", "platform Windows-aarch64", "platform windows-aarch64 ", "platform  windows-aarch64", "platform windows-arm64", "os windows-aarch64", "platform windows-aarch64\x00" }) |t|
        try testing.expectEqual(@as(?Platform, null), parseRest(t));
    try testing.expectEqual(@as(?Platform, .windows_aarch64), of(.windows, .aarch64));
    try testing.expectEqual(@as(?Platform, null), of(.freebsd, .x86_64));
}
