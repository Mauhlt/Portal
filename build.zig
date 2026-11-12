const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const root = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

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

    // `zig build test` is what ZVC runs to vet a new compiler before promoting
    // it, and what scripts/release.ps1 runs before promoting a new build.
    // The test step must also compile the real executable: unit tests alone
    // never analyse `main`, the web server, ConPTY or logging code, so a std
    // change breaking those would otherwise pass `zig build test`.
    const tests = b.addTest(.{ .root_module = root });
    const test_step = b.step("test", "Run unit tests and compile the exe (debug + ReleaseSafe)");
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
}
