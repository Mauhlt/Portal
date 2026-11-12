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
//!                                No networking; imports the Renderer's
//!                                "Renderer" and "Font" modules and imgdec.
//!   client   src/main.zig        pairing, refresh, WebSocket, 'G' decoding.
//!   "inputrules"  ../src/inputrules/root.zig   the input policy, key names
//!                                and input line, shared with Portal's server
//!                                and browser client (Portal's own source
//!                                tree: this build lives inside it).
//!   "datafeed"    ../src/datafeed/root.zig     the Data slice's model,
//!                                shared with the browser client.
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
            .{ .name = "inputrules", .module = inputrulesModule(b, target, optimize) },
            .{ .name = "datafeed", .module = datafeedModule(b, target, optimize) },
        },
    }) });
    const test_step = b.step("test", "Run unit tests and compile-check the executables");
    test_step.dependOn(&b.addRunArtifact(view_tests).step);
    test_step.dependOn(&b.addRunArtifact(client_tests).step);
    test_step.dependOn(&exe.step);
    test_step.dependOn(&addClient(b, "portal-client-releasesafe-check", target, .ReleaseSafe).step);
}

/// The reusable view module (src/view), wired to the Renderer package.
pub fn viewModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const renderer = b.dependency("Renderer", .{ .target = target, .optimize = optimize, .demo = false });
    // Inline images: imgcheck + imgdec (src/image) on the owner's Image
    // package (see build.zig.zon), as in Portal's root build.
    // Same args as Renderer's, so both share Image's and Renderer's ../Vulkan module.
    const image = b.dependency("Image", .{ .target = target, .optimize = optimize });
    const imgcheck = b.createModule(.{
        .root_source_file = b.path("src/image/imgcheck.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "ImageCheck", .module = image.module("ImageCheck") }},
    });
    const imgdec = b.createModule(.{
        .root_source_file = b.path("src/image/imgdec.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "Image", .module = image.module("Image") },
            .{ .name = "imgcheck", .module = imgcheck },
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
            // Fonts and cell widths: the Renderer's Font module.
            .{ .name = "Font", .module = renderer.module("Font") },
            .{ .name = "imgdec", .module = imgdec },
        },
    });
}

/// The input policy and input line, shared with Portal's server and
/// browser client: Portal's src/inputrules (one directory up; Zig allows a
/// module root outside the build root, and this build only ever runs from
/// inside the Portal checkout).
pub fn inputrulesModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{ .root_source_file = b.path("../src/inputrules/root.zig"), .target = target, .optimize = optimize });
}

/// The Data slice's model, shared with Portal's browser client:
/// Portal's src/datafeed (one directory up, as inputrules).
pub fn datafeedModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{ .root_source_file = b.path("../src/datafeed/root.zig"), .target = target, .optimize = optimize });
}

fn addClient(b: *std.Build, name: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    return b.addExecutable(.{ .name = name, .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = target.result.os.tag != .windows, // libsecret / Security.framework via dlopen
        .imports = &.{
            .{ .name = "view", .module = viewModule(b, target, optimize) },
            .{ .name = "inputrules", .module = inputrulesModule(b, target, optimize) },
            .{ .name = "datafeed", .module = datafeedModule(b, target, optimize) },
        },
    }) });
}
