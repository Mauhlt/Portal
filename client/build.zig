//! portal-client build.
//!
//!   zig build                         debug build of portal-client
//!   zig build test                    unit tests (portal_ui, view, client), plus
//!                                     compile checks of the exe in Debug and
//!                                     ReleaseSafe
//!   zig build -Dtarget=x86_64-linux-gnu   cross-compile (no SDK needed: Wayland,
//!   zig build -Dtarget=aarch64-macos      AppKit, Vulkan are loaded at runtime;
//!                                         `test` compile-checks both too)
//!
//! Module layout (as in Portal's root build):
//!   "portal_ui"   ../ui/root.zig  the shared Portal UI (layout, draw list,
//!                                shell, panels; colours from the theme in
//!                                ../shared/theme.zig). A plain module made
//!                                here from Portal's tree (like inputrules),
//!                                so it shares this compilation's "Font",
//!                                "shared", "inputrules" and "datafeed".
//!   "view"   src/view/root.zig   the window and Vulkan drawing of the UI's
//!                                draw list. No networking; imports the
//!                                Renderer's "Renderer", "Window" and "Font"
//!                                modules, imgdec and portal_ui.
//!   client   src/main.zig        pairing, refresh, WebSocket, 'G' decoding.
//!   "inputrules"  ../src/inputrules/root.zig   the input policy, key names
//!                                and input line, shared with Portal's server
//!                                (Portal's own source tree: this build
//!                                lives inside it).
//!   "datafeed"    ../src/datafeed/root.zig     the Data slice's model
//!                                (used by portal_ui).
//!   "shared" ../shared/root.zig  protocol code shared with Portal's server
//!                                (a path dependency).
//!   "WireGuard"                  the owner's Zig WireGuard (../../WireGuard,
//!                                a path dependency): the in-process tunnel
//!                                (src/tunnel).
//!   "tunnel_options"             build options of the tunnel
//!                                (-Dnetstack-ready).
//!
//! Portal's root build.zig imports this file for wireguardModule and
//! tunnelOptions, so both builds wire the tunnel the same way.
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

    const mods = modules(b, target, optimize);
    const view_tests = b.addTest(.{ .root_module = mods.view });
    const client_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = mods.clientImports(),
    }) });
    const test_step = b.step("test", "Run unit tests and compile-check the executables");
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = mods.ui })).step);
    test_step.dependOn(&b.addRunArtifact(view_tests).step);
    test_step.dependOn(&b.addRunArtifact(client_tests).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = sharedModule(b, target, optimize) })).step);
    test_step.dependOn(&exe.step);
    test_step.dependOn(&addClient(b, "portal-client-releasesafe-check", target, .ReleaseSafe).step);
    // The laptop client on the other OSes, compile only (they cannot run
    // here): a gap in a window backend (a method one OS lacks) fails
    // `zig build test` instead of a later cross build.
    for (cross_targets) |q| {
        const t = b.resolveTargetQuery(q);
        test_step.dependOn(&addClient(b, b.fmt("portal-client-check-{t}", .{q.os_tag.?}), t, .Debug).step);
    }
}

/// Laptop-client targets compile-checked by `zig build test`.
pub const cross_targets = [_]std.Target.Query{
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
    .{ .cpu_arch = .aarch64, .os_tag = .macos },
};

/// Portal's shared protocol module (../shared/root.zig).
pub fn sharedModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.dependency("shared", .{ .target = target, .optimize = optimize }).module("shared");
}

/// One compilation's modules: each created once, so every user shares the
/// same instance (a source file may belong to only one module).
pub const Modules = struct {
    view: *std.Build.Module,
    ui: *std.Build.Module,
    shared: *std.Build.Module,
    inputrules: *std.Build.Module,
    wireguard: *std.Build.Module,
    tunnel_options: *std.Build.Module,
    imports: [6]std.Build.Module.Import = undefined,

    /// The client's imports (src/main.zig, src/tests.zig).
    pub fn clientImports(m: *Modules) []const std.Build.Module.Import {
        m.imports = .{
            .{ .name = "view", .module = m.view },
            .{ .name = "portal_ui", .module = m.ui },
            .{ .name = "shared", .module = m.shared },
            .{ .name = "inputrules", .module = m.inputrules },
            .{ .name = "WireGuard", .module = m.wireguard },
            .{ .name = "tunnel_options", .module = m.tunnel_options },
        };
        return &m.imports;
    }
};

/// The view module (src/view) and the shared UI (../ui), wired to the
/// Renderer package.
pub fn modules(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *Modules {
    const renderer = b.dependency("Renderer", .{ .target = target, .optimize = optimize });
    const shared = sharedModule(b, target, optimize);
    const inputrules = inputrulesModule(b, target, optimize);
    const ui = b.createModule(.{
        .root_source_file = b.path("../ui/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "Font", .module = renderer.module("Font") },
            .{ .name = "shared", .module = shared },
            .{ .name = "inputrules", .module = inputrules },
            .{ .name = "datafeed", .module = datafeedModule(b, target, optimize) },
        },
    });
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
    const view = b.createModule(.{
        .root_source_file = b.path("src/view/root.zig"),
        .target = target,
        .optimize = optimize,
        // dlopen (Wayland, Vulkan loader, Objective-C runtime) needs libc
        // off Windows; Windows talks to kernel32/user32 directly.
        .link_libc = target.result.os.tag != .windows,
        .imports = &.{
            .{ .name = "Renderer", .module = renderer.module("Renderer") },
            // The native window (Win32 / Wayland / macOS): the Renderer's
            // Window module.
            .{ .name = "Window", .module = renderer.module("Window") },
            // Fonts and cell widths: the Renderer's Font module.
            .{ .name = "Font", .module = renderer.module("Font") },
            .{ .name = "imgdec", .module = imgdec },
            .{ .name = "portal_ui", .module = ui },
        },
    });
    // Instanced2D's shaders (src/view/shaders): Zig, compiled to SPIR-V.
    for ([_][]const u8{ "quad_vert", "quad_frag" }) |name|
        view.addAnonymousImport(b.fmt("{s}.spv", .{name}), .{ .root_source_file = @import("Renderer").addShader(b, name, b.path(b.fmt("src/view/shaders/{s}.zig", .{name}))) });
    // The hero art for the start-up splash (../docs/brand).
    view.addAnonymousImport("portal_hero", .{ .root_source_file = b.path("../docs/brand/portal-hero-768.png") });
    const m = b.allocator.create(Modules) catch @panic("OOM");
    m.* = .{
        .view = view,
        .ui = ui,
        .shared = shared,
        .inputrules = inputrules,
        .wireguard = wireguardModule(b, target, optimize),
        .tunnel_options = tunnelOptions(b),
    };
    return m;
}

/// The owner's Zig WireGuard (the "WireGuard" path dependency): the device,
/// its UDP socket and the userspace TCP/IP stack (`netstack`) Portal's
/// tunnel runs on. Also used by Portal's root build.
pub fn wireguardModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.dependency("WireGuard", .{ .target = target, .optimize = optimize }).module("WireGuard");
}

/// "tunnel_options": `-Dnetstack-ready=false` builds against a WireGuard
/// whose netstack is still a stub; the tunnel then refuses to start and the
/// e2e groups report PENDING instead of running. One module per build (the
/// option may be declared only once). Also used by Portal's root build.
var tunnel_options_module: ?*std.Build.Module = null;

pub fn tunnelOptions(b: *std.Build) *std.Build.Module {
    if (tunnel_options_module) |m| return m;
    const ready = b.option(bool, "netstack-ready", "The WireGuard netstack is implemented (default true)") orelse true;
    const o = b.addOptions();
    o.addOption(bool, "netstack_ready", ready);
    tunnel_options_module = o.createModule();
    return tunnel_options_module.?;
}

/// The input policy and input line, shared with Portal's server:
/// Portal's src/inputrules (one directory up; Zig allows a
/// module root outside the build root, and this build only ever runs from
/// inside the Portal checkout).
pub fn inputrulesModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{ .root_source_file = b.path("../src/inputrules/root.zig"), .target = target, .optimize = optimize });
}

/// The Data slice's model: Portal's src/datafeed (one directory up, as
/// inputrules).
pub fn datafeedModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{ .root_source_file = b.path("../src/datafeed/root.zig"), .target = target, .optimize = optimize });
}

fn addClient(b: *std.Build, name: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const mods = modules(b, target, optimize);
    return b.addExecutable(.{
        .name = name,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = target.result.os.tag != .windows, // libsecret / Security.framework via dlopen
            .imports = mods.clientImports(),
        }),
    });
}
