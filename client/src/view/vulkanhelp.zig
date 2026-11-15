//! What to tell the user when the window cannot start Vulkan (the
//! Renderer's Instanced2D.init failed: no Vulkan driver, or one without
//! what the window needs). One plain-language message per platform naming
//! the fix, for both windows (`portal run`'s desk and `portal connect`):
//!
//!   Windows    the "OpenCL, OpenGL, and Vulkan Compatibility Pack" from
//!              the Microsoft Store, or the graphics card maker's driver
//!   macOS      MoltenVK
//!   Linux/WSL  the Mesa Vulkan drivers
//!
//! `message` is pure (tested below); `detect` finds the platform at run
//! time (WSL is Linux with "microsoft" in the kernel release).
const std = @import("std");
const builtin = @import("builtin");

pub const Platform = enum { windows, macos, linux, wsl, ios, other };

/// The Instanced2D.init errors that mean "Vulkan is not usable here".
pub fn isVulkanError(err: anyerror) bool {
    return switch (err) {
        error.VulkanLibraryNotFound,
        error.MissingGetInstanceProcAddr,
        error.MissingInstanceExtension,
        error.NoSuitableDevice,
        error.NoSuitableMemoryType,
        error.SurfaceUnsupported,
        error.VulkanCallFailed,
        => true,
        else => false,
    };
}

/// The message for `err` on `platform`, or null when `err` is not a
/// Vulkan problem (the caller reports it as before).
pub fn message(err: anyerror, platform: Platform) ?[]const u8 {
    if (!isVulkanError(err)) return null;
    const missing = err == error.VulkanLibraryNotFound or err == error.MissingGetInstanceProcAddr;
    return switch (platform) {
        .windows => if (missing) windows_missing else windows_unsupported,
        .macos => if (missing) macos_missing else macos_unsupported,
        .linux => if (missing) linux_missing else linux_unsupported,
        .wsl => if (missing) wsl_missing else wsl_unsupported,
        .ios, .other => other,
    };
}

/// This machine's platform.
pub fn detect(io: std.Io) Platform {
    return switch (builtin.os.tag) {
        .windows => .windows,
        .macos => .macos,
        .ios => .ios,
        .linux => if (isWsl(io)) .wsl else .linux,
        else => .other,
    };
}

fn isWsl(io: std.Io) bool {
    var buf: [256]u8 = undefined;
    const release = std.Io.Dir.cwd().readFile(io, "/proc/sys/kernel/osrelease", &buf) catch return false;
    var lower: [256]u8 = undefined;
    return std.mem.indexOf(u8, std.ascii.lowerString(&lower, release), "microsoft") != null;
}

const restart = "\n\nThen start Portal again.";

const windows_fix =
    "\n\nTo fix it, install one of these:\n" ++
    "  - the \"OpenCL, OpenGL, and Vulkan Compatibility Pack\" from the Microsoft Store, or\n" ++
    "  - the latest graphics driver from your graphics card's maker (NVIDIA, AMD, Intel or Qualcomm)." ++ restart;
const windows_missing = "Portal can't open its window: this PC has no Vulkan graphics driver." ++ windows_fix;
const windows_unsupported = "Portal can't open its window: this PC's graphics driver doesn't support what Portal needs (Vulkan)." ++ windows_fix;

const macos_fix = "\n\nTo fix it, install MoltenVK (it runs Vulkan on the Mac's own graphics), for example with Homebrew: brew install molten-vk" ++ restart;
const macos_missing = "Portal can't open its window: MoltenVK is not installed on this Mac." ++ macos_fix;
const macos_unsupported = "Portal can't open its window: this Mac's MoltenVK doesn't support what Portal needs." ++ macos_fix;

const linux_fix = "\n\nTo fix it, install the Mesa Vulkan drivers, for example: sudo apt install mesa-vulkan-drivers (Debian, Ubuntu) or sudo dnf install mesa-vulkan-drivers (Fedora)." ++ restart;
const linux_missing = "Portal can't open its window: this computer has no Vulkan graphics driver." ++ linux_fix;
const linux_unsupported = "Portal can't open its window: this computer's graphics driver doesn't support what Portal needs (Vulkan)." ++ linux_fix;

const wsl_fix = "\n\nTo fix it, install the Mesa Vulkan drivers inside WSL (for example: sudo apt install mesa-vulkan-drivers), and keep the Windows graphics driver up to date." ++ restart;
const wsl_missing = "Portal can't open its window: this WSL system has no Vulkan graphics driver." ++ wsl_fix;
const wsl_unsupported = "Portal can't open its window: the graphics driver in WSL doesn't support what Portal needs (Vulkan)." ++ wsl_fix;

const other = "Portal can't open its window: this device's graphics don't support what Portal needs (Vulkan).";

test "the fix named for each platform" {
    const t = std.testing;
    const has = struct {
        fn f(m: ?[]const u8, needle: []const u8) !void {
            try t.expect(std.mem.indexOf(u8, m.?, needle) != null);
        }
    }.f;
    try has(message(error.VulkanLibraryNotFound, .windows), "OpenCL, OpenGL, and Vulkan Compatibility Pack");
    try has(message(error.VulkanLibraryNotFound, .windows), "Microsoft Store");
    try has(message(error.NoSuitableDevice, .windows), "graphics driver from your graphics card's maker");
    try has(message(error.VulkanLibraryNotFound, .macos), "MoltenVK");
    try has(message(error.SurfaceUnsupported, .macos), "MoltenVK");
    try has(message(error.VulkanLibraryNotFound, .linux), "Mesa Vulkan drivers");
    try has(message(error.MissingInstanceExtension, .wsl), "Mesa Vulkan drivers inside WSL");
    try has(message(error.VulkanCallFailed, .other), "Vulkan");
    // "missing" and "unsupported" read differently.
    try has(message(error.VulkanLibraryNotFound, .windows), "no Vulkan graphics driver");
    try has(message(error.SurfaceUnsupported, .windows), "doesn't support");
}

test "other errors keep their own report" {
    try std.testing.expectEqual(@as(?[]const u8, null), message(error.OutOfMemory, .windows));
    try std.testing.expectEqual(@as(?[]const u8, null), message(error.NoMonospaceFont, .linux));
    try std.testing.expect(!isVulkanError(error.FileNotFound));
}

test "detect matches the build's OS" {
    const p = detect(std.testing.io);
    switch (builtin.os.tag) {
        .windows => try std.testing.expectEqual(Platform.windows, p),
        .macos => try std.testing.expectEqual(Platform.macos, p),
        .linux => try std.testing.expect(p == .linux or p == .wsl),
        else => {},
    }
}
