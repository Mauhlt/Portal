//! portal-client build.
//!
//!   zig build                         debug build of portal-client
//!   zig build test                    unit tests (view module + client), plus
//!                                     compile checks of the exe in Debug and
//!                                     ReleaseSafe
//!   zig build -Dtarget=x86_64-linux-gnu   cross-compile (no SDK needed: X11,
//!   zig build -Dtarget=aarch64-macos      Cocoa, Vulkan are loaded at runtime)
//!
//! Module layout (for merging into Portal's root build later):
//!   "view"   src/view/root.zig   window, Vulkan drawing, fonts, input types.
//!                                No networking; imports only "Renderer".
//!   client   src/main.zig        pairing, refresh, WebSocket, 'G' decoding.
//!   "shared" ../shared/root.zig  protocol code shared with Portal's server
//!                                and browser client (a path dependency).
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = addClient(b, "portal-client", target, optimize);
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    run.addPassthruArgs();
    b.step("run", "Run portal-client").dependOn(&run.step);

    const view = viewModule(b, target, optimize);
    const view_tests = b.addTest(.{ .root_module = view });
    const client_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "view", .module = view },
            .{ .name = "shared", .module = sharedModule(b, target, optimize) },
        },
    }) });
    const test_step = b.step("test", "Run unit tests and compile-check the executables");
    test_step.dependOn(&b.addRunArtifact(view_tests).step);
    test_step.dependOn(&b.addRunArtifact(client_tests).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = sharedModule(b, target, optimize) })).step);
    test_step.dependOn(&exe.step);
    test_step.dependOn(&addClient(b, "portal-client-releasesafe-check", target, .ReleaseSafe).step);
}

/// Portal's shared protocol module (../shared/root.zig).
pub fn sharedModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.dependency("shared", .{ .target = target, .optimize = optimize }).module("shared");
}

/// The reusable view module (src/view), wired to the Renderer package.
pub fn viewModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const renderer = b.dependency("Renderer", .{ .target = target, .optimize = optimize, .demo = false });
    // Inline images: pngcheck + imgdec (src/image) on the owner's pinned
    // Image package (see build.zig.zon), as in Portal's root build.
    const pngcheck = b.createModule(.{ .root_source_file = b.path("src/image/pngcheck.zig"), .target = target, .optimize = optimize });
    const imgdec = b.createModule(.{
        .root_source_file = b.path("src/image/imgdec.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "Image", .module = b.dependency("Image", .{ .target = target }).module("Image") },
            .{ .name = "pngcheck", .module = pngcheck },
        },
    });
    return b.createModule(.{
        .root_source_file = b.path("src/view/root.zig"),
        .target = target,
        .optimize = optimize,
        // dlopen (X11, Vulkan loader, Objective-C runtime) needs libc off
        // Windows; Windows talks to kernel32/user32 directly.
        .link_libc = target.result.os.tag != .windows,
        .imports = &.{
            .{ .name = "Renderer", .module = renderer.module("Renderer") },
            .{ .name = "imgdec", .module = imgdec },
            .{ .name = "shared", .module = sharedModule(b, target, optimize) },
        },
    });
}

fn addClient(b: *std.Build, name: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    return b.addExecutable(.{ .name = name, .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = target.result.os.tag != .windows, // libsecret / Security.framework via dlopen
        .imports = &.{
            .{ .name = "view", .module = viewModule(b, target, optimize) },
            .{ .name = "shared", .module = sharedModule(b, target, optimize) },
        },
    }) });
}
