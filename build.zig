const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const root = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const gui_mods = addGuiModules(b, root, target, optimize);

    const exe = b.addExecutable(.{ .name = "portal", .root_module = root });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    // Build API churn: 0.18 replaced `b.args` with `addPassthruArgs`.
    // Supporting both keeps the previous known-good compiler able to build.
    if (@hasDecl(@TypeOf(run_cmd.*), "addPassthruArgs")) {
        run_cmd.addPassthruArgs();
    } else if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    b.step("run", "Run portal").dependOn(&run_cmd.step);

    // Release tooling (src/tools): portal-release builds, tests and promotes
    // releases; portal-launcher is installed as %LOCALAPPDATA%\Portal\bin\portal.exe
    // and runs the current release.
    const release_mod = b.createModule(.{
        .root_source_file = b.path("src/tools/release.zig"),
        .target = target,
        .optimize = optimize,
    });
    const release_exe = b.addExecutable(.{ .name = "portal-release", .root_module = release_mod });
    b.installArtifact(release_exe);
    const launcher_exe = b.addExecutable(.{
        .name = "portal-launcher",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/launcher.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(launcher_exe);

    // `zig build release` tests and promotes with the compiler running this
    // build. The tool runs from the repo root so it finds src/ and build.zig.
    const tool_steps = [_]struct { name: []const u8, sub: []const u8, desc: []const u8 }{
        .{ .name = "release", .sub = "release", .desc = "Test, build ReleaseSafe and promote a new release" },
        .{ .name = "mark-good", .sub = "mark-good", .desc = "Mark the current release as known-good" },
        .{ .name = "rollback", .sub = "rollback", .desc = "Point current back at the known-good release" },
        .{ .name = "release-status", .sub = "status", .desc = "Show current, known-good and release history" },
    };
    for (tool_steps) |t| {
        const run = b.addRunArtifact(release_exe);
        run.addArg(t.sub);
        if (std.mem.eql(u8, t.sub, "release")) run.addArgs(&.{ "--zig", b.graph.zig_exe });
        run.setCwd(b.path("."));
        b.step(t.name, t.desc).dependOn(&run.step);
    }

    // `zig build test` is what ZVC runs to vet a new compiler before promoting
    // it, and what `zig build release` runs before promoting a new build.
    // The test step must also compile the real executable: unit tests alone
    // never analyse `main`, the web server, ConPTY or logging code, so a std
    // change breaking those would otherwise pass `zig build test`.
    const tests = b.addTest(.{ .root_module = root });
    const test_step = b.step("test", "Run unit tests and compile the exe (debug + ReleaseSafe) and release tools");
    test_step.dependOn(&b.addRunArtifact(tests).step);
    test_step.dependOn(&exe.step);
    const exe_safe = b.addExecutable(.{
        .name = "portal-releasesafe-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
        }),
    });
    test_step.dependOn(&exe_safe.step);
    _ = addGuiModules(b, exe_safe.root_module, target, .ReleaseSafe);
    // The shared GUI modules' own unit tests (client/src/view, client/src).
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = gui_mods.view })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = gui_mods.client })).step);
    // Release tooling: unit tests (release.zig pulls in releases_lib.zig's)
    // and full compiles of both tools.
    const tool_tests = b.addTest(.{ .root_module = release_mod });
    test_step.dependOn(&b.addRunArtifact(tool_tests).step);
    test_step.dependOn(&release_exe.step);
    test_step.dependOn(&launcher_exe.step);
}

// ---- GUI modules (shared with client/, which still builds on its own) ----

const GuiModules = struct { view: *std.Build.Module, client: *std.Build.Module };

/// Adds "view" (client/src/view: window, Vulkan drawing via the owner's
/// Renderer, fonts; used by `portal run`'s window) and "client"
/// (client/src: the remote viewer behind `portal connect`) to `mod`.
fn addGuiModules(b: *std.Build, mod: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) GuiModules {
    const renderer = b.dependency("Renderer", .{ .target = target, .optimize = optimize, .demo = false });
    const link_libc = target.result.os.tag != .windows; // dlopen off Windows
    const view = b.createModule(.{
        .root_source_file = b.path("client/src/view/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = link_libc,
        .imports = &.{.{ .name = "Renderer", .module = renderer.module("Renderer") }},
    });
    const client = b.createModule(.{
        .root_source_file = b.path("client/src/connect.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = link_libc,
        .imports = &.{.{ .name = "view", .module = view }},
    });
    mod.addImport("view", view);
    mod.addImport("client", client);
    return .{ .view = view, .client = client };
}
