//! portal-client build.
//!
//!   zig build                         debug build of portal-client (+ mock server)
//!   zig build test                    unit tests (view module + client), plus
//!                                     compile checks of the exe in Debug and
//!                                     ReleaseSafe and of the mock server
//!   zig build -Dtarget=x86_64-linux-gnu   cross-compile (no SDK needed: X11,
//!   zig build -Dtarget=aarch64-macos      Cocoa, Vulkan are loaded at runtime)
//!
//! Module layout (for merging into Portal's root build later):
//!   "view"   src/view/root.zig   window, Vulkan drawing, fonts, input types.
//!                                No networking; imports only "Renderer".
//!   client   src/main.zig        pairing, refresh, WebSocket, 'G' decoding.
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

    // Mock Portal server for end-to-end tests (tools/mock_server.zig).
    const mock = b.addExecutable(.{ .name = "portal-mock-server", .root_module = b.createModule(.{
        .root_source_file = b.path("tools/mock_server.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "wcwidth", .module = b.createModule(.{ .root_source_file = b.path("src/view/wcwidth.zig") }) }},
    }) });
    b.getInstallStep().dependOn(&b.addInstallArtifact(mock, .{}).step);

    const view = viewModule(b, target, optimize);
    const view_tests = b.addTest(.{ .root_module = view });
    const client_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "view", .module = view }},
    }) });
    const test_step = b.step("test", "Run unit tests and compile-check the executables");
    test_step.dependOn(&b.addRunArtifact(view_tests).step);
    test_step.dependOn(&b.addRunArtifact(client_tests).step);
    test_step.dependOn(&exe.step);
    test_step.dependOn(&mock.step);
    test_step.dependOn(&addClient(b, "portal-client-releasesafe-check", target, .ReleaseSafe).step);
}

/// The reusable view module (src/view), wired to the Renderer package.
pub fn viewModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const renderer = b.dependency("Renderer", .{ .target = target, .optimize = optimize, .demo = false });
    return b.createModule(.{
        .root_source_file = b.path("src/view/root.zig"),
        .target = target,
        .optimize = optimize,
        // dlopen (X11, Vulkan loader, Objective-C runtime) needs libc off
        // Windows; Windows talks to kernel32/user32 directly.
        .link_libc = target.result.os.tag != .windows,
        .imports = &.{.{ .name = "Renderer", .module = renderer.module("Renderer") }},
    });
}

fn addClient(b: *std.Build, name: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    return b.addExecutable(.{ .name = name, .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = target.result.os.tag != .windows, // libsecret / Security.framework via dlopen
        .imports = &.{.{ .name = "view", .module = viewModule(b, target, optimize) }},
    }) });
}
