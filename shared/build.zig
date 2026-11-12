//! portal-shared: one module, "shared" (root.zig), with the code both ends
//! of Portal's protocols must agree on. Used through a path dependency by
//! Portal's root build and by client/build.zig.
//!
//!   zig build test     the module's unit tests (fuzz tests included)
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const mod = b.addModule("shared", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tests = b.addTest(.{ .root_module = mod });
    b.step("test", "Run the shared module's unit tests").dependOn(&b.addRunArtifact(tests).step);
}
