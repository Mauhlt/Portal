const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const root = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Browser client: Zig compiled to wasm32-freestanding (src/wasm), with
    // the bundled font embedded, itself embedded into portal.exe and served
    // at /static/app.wasm. No WASI, no libc: the module's only imports are
    // the host functions in src/web/app.js (checked by a test in web.zig).
    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    const wasm = b.addExecutable(.{
        .name = "portal-app",
        .root_module = clientModule(b, "src/wasm/main.zig", wasm_target, .ReleaseSmall),
    });
    wasm.entry = .disabled; // a library of exports, no _start
    wasm.rdynamic = true; // keep every `export fn`
    root.addAnonymousImport("app_wasm", .{ .root_source_file = wasm.getEmittedBin() });
    b.step("wasm", "Build the browser client (zig-out/web/app.wasm)").dependOn(
        &b.addInstallFile(wasm.getEmittedBin(), "web/app.wasm").step,
    );
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
    exe_safe.root_module.addAnonymousImport("app_wasm", .{ .root_source_file = wasm.getEmittedBin() });
    test_step.dependOn(&exe_safe.step);
    // Browser client: its pure logic (decoder, layout, keys, reconnects,
    // font parser, rasteriser, renderer) runs natively in Debug, where
    // safety checks catch what would be a wasm trap or silent corruption.
    const client_tests = b.addTest(.{ .root_module = clientModule(b, "src/wasm/tests.zig", target, .Debug) });
    test_step.dependOn(&b.addRunArtifact(client_tests).step);
    test_step.dependOn(&wasm.step);
    _ = addGuiModules(b, exe_safe.root_module, target, .ReleaseSafe);
    // The shared GUI modules' own unit tests (client/src/view, client/src).
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = gui_mods.view })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = gui_mods.client })).step);
    // Inline images: PNG checks and the bounded decoder (fuzzed).
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = gui_mods.pngcheck })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = gui_mods.imgdec })).step);
    // Release tooling: unit tests (release.zig pulls in releases_lib.zig's)
    // and full compiles of both tools.
    const tool_tests = b.addTest(.{ .root_module = release_mod });
    test_step.dependOn(&b.addRunArtifact(tool_tests).step);
    test_step.dependOn(&release_exe.step);
    test_step.dependOn(&launcher_exe.step);

    addE2e(b, target, optimize, exe, gui_mods.pngcheck);
}

/// `zig build e2e [-- group...]`: end-to-end tests (tests/e2e) that launch
/// real `portal` processes in hidden consoles and drive them over sockets.
/// Deliberately not part of `test`: it spawns processes and takes minutes.
fn addE2e(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, portal: *std.Build.Step.Compile, pngcheck: *std.Build.Module) void {
    const e2e_exe = b.addExecutable(.{
        .name = "portal-e2e",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/e2e/main.zig"),
            .target = target,
            .optimize = optimize,
            // The images group writes its test PNG with pngcheck's encoder;
            // the webinput group decides what to send with the browser
            // client's own input-box logic.
            .imports = &.{
                .{ .name = "pngcheck", .module = pngcheck },
                .{ .name = "inputbox", .module = b.createModule(.{
                    .root_source_file = b.path("src/wasm/inputbox.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{.{ .name = "keymap", .module = keymapModule(b, target, optimize) }},
                }) },
            },
        }),
    });
    const run = b.addRunArtifact(e2e_exe);
    run.addArtifactArg(portal);
    run.has_side_effects = true;
    if (@hasDecl(@TypeOf(run.*), "addPassthruArgs")) {
        run.addPassthruArgs();
    } else if (b.args) |args| {
        run.addArgs(args);
    }
    b.step("e2e", "Run end-to-end tests against real portal processes (minutes)").dependOn(&run.step);
}

/// The browser client's module graph: `vt` (src/vt.zig, for the colour
/// sentinels, cell widths and, in tests, real server frames), `keymap`
/// (src/keymap.zig, instruction-line rules) and the
/// bundled fonts as `font_regular` / `font_bold`.
fn keymapModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{ .root_source_file = b.path("src/keymap.zig"), .target = target, .optimize = optimize });
}

fn clientModule(b: *std.Build, root_src: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const img = imageModules(b, target, optimize);
    const m = b.createModule(.{ .root_source_file = b.path(root_src), .target = target, .optimize = optimize });
    const vt_mod = b.createModule(.{ .root_source_file = b.path("src/vt.zig"), .target = target, .optimize = optimize });
    vt_mod.addImport("pngcheck", img.pngcheck);
    m.addImport("vt", vt_mod);
    // The input box checks instruction lines with the server's own rules.
    m.addImport("keymap", keymapModule(b, target, optimize));
    m.addImport("imgdec", img.imgdec);
    m.addImport("pngcheck", img.pngcheck);
    m.addAnonymousImport("font_regular", .{ .root_source_file = b.path("src/web/fonts/DejaVuSansMono.ttf") });
    m.addAnonymousImport("font_bold", .{ .root_source_file = b.path("src/web/fonts/DejaVuSansMono-Bold.ttf") });
    return m;
}

// ---- inline images ----

const ImageModules = struct { pngcheck: *std.Build.Module, imgdec: *std.Build.Module };

/// "pngcheck" (client/src/image/pngcheck.zig: PNG structure + limits, no
/// deps; also imported by src/vt.zig) and "imgdec" (client/src/image:
/// bounded PNG -> RGBA8 on top of the owner's Image package).
///
/// Natively, imgdec imports Image's own published "Image" module. For
/// wasm32 it gets a module built from the same pinned source (Image's
/// src/root.zig) with a stub "Vulkan" (client/src/image/vk_stub.zig: just
/// `Format`, the only Vulkan type the PNG path touches), so the browser
/// build never compiles or links the Vulkan bindings.
fn imageModules(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) ImageModules {
    const pngcheck = b.createModule(.{
        .root_source_file = b.path("client/src/image/pngcheck.zig"),
        .target = target,
        .optimize = optimize,
    });
    const image = if (target.result.cpu.arch.isWasm()) blk: {
        const dep = b.dependency("Image", .{});
        const opts = b.addOptions();
        // 16-byte vectors: wasm32 without simd128 scalarises them anyway,
        // and narrow ones keep the module small.
        opts.addOption(usize, "vector_bytes", 16);
        break :blk b.createModule(.{
            .root_source_file = dep.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "Vulkan", .module = b.createModule(.{ .root_source_file = b.path("client/src/image/vk_stub.zig"), .target = target, .optimize = optimize }) },
                .{ .name = "build_options", .module = opts.createModule() },
            },
        });
    } else b.dependency("Image", .{ .target = target }).module("Image");
    const imgdec = b.createModule(.{
        .root_source_file = b.path("client/src/image/imgdec.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "Image", .module = image },
            .{ .name = "pngcheck", .module = pngcheck },
        },
    });
    return .{ .pngcheck = pngcheck, .imgdec = imgdec };
}

// ---- GUI modules (shared with client/, which still builds on its own) ----

const GuiModules = struct { view: *std.Build.Module, client: *std.Build.Module, imgdec: *std.Build.Module, pngcheck: *std.Build.Module };

/// Adds "view" (client/src/view: window, Vulkan drawing via the owner's
/// Renderer, fonts; used by `portal run`'s window) and "client"
/// (client/src: the remote viewer behind `portal connect`) to `mod`.
fn addGuiModules(b: *std.Build, mod: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) GuiModules {
    const renderer = b.dependency("Renderer", .{ .target = target, .optimize = optimize, .demo = false });
    const link_libc = target.result.os.tag != .windows; // dlopen off Windows
    const img = imageModules(b, target, optimize);
    const view = b.createModule(.{
        .root_source_file = b.path("client/src/view/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = link_libc,
        .imports = &.{
            .{ .name = "Renderer", .module = renderer.module("Renderer") },
            .{ .name = "imgdec", .module = img.imgdec },
        },
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
    // src/vt.zig (a file of the root module) validates transmitted images.
    mod.addImport("pngcheck", img.pngcheck);
    return .{ .view = view, .client = client, .imgdec = img.imgdec, .pngcheck = img.pngcheck };
}
