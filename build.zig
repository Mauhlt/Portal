const std = @import("std");

/// Which program a build of src/main.zig is (build option `gui`):
///   portal.exe     the Portal window (Windows GUI subsystem: no console;
///                  errors go to message boxes). The desk's session window
///                  and `portal connect`, the remote viewer.
///   portalctl.exe  the console tool: pair, devices, unpair, ca, version,
///                  run --console (scripting, tests, fallback).
/// Both are the same code with a different entry dispatch.
const App = enum { gui, ctl };

fn rootModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, app: App, wasm_bin: std.Build.LazyPath) struct { root: *std.Build.Module, gui: GuiModules } {
    const root = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const opts = b.addOptions();
    opts.addOption(bool, "gui", app == .gui);
    root.addOptions("build_options", opts);
    root.addAnonymousImport("app_wasm", .{ .root_source_file = wasm_bin });
    root.addImport("shared", sharedModule(b, target, optimize));
    // src/vt.zig (a file of the root module) takes its cell widths from it.
    root.addImport("Font", fontModule(b, target, optimize));
    // One instance per compilation: src/keymap.zig and the client module
    // (portal connect) share it.
    const rules = inputrulesModule(b, target, optimize);
    root.addImport("inputrules", rules);
    const gui_mods = addGuiModules(b, root, target, optimize, rules);
    return .{ .root = root, .gui = gui_mods };
}

/// portal-show.exe: `portal-show <file.png>` (src/show.zig), a console
/// program because it runs inside sessions and writes to their terminal.
fn showModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, imgcheck: *std.Build.Module) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("src/show_main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "imgcheck", .module = imgcheck }},
    });
}

/// The hand-declared Win32 surface (src/win32.zig) for the release tools,
/// whose module roots are in src/tools.
fn win32Module(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{ .root_source_file = b.path("src/win32.zig"), .target = target, .optimize = optimize });
}

/// portal-launcher: the GUI build is installed as bin\portal.exe, the
/// console build as bin\portalctl.exe and bin\portal-show.exe; each runs
/// the same-named exe of the current release.
fn launcherModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, gui: bool) *std.Build.Module {
    const m = b.createModule(.{
        .root_source_file = b.path("src/tools/launcher.zig"),
        .target = target,
        .optimize = optimize,
    });
    const opts = b.addOptions();
    opts.addOption(bool, "gui", gui);
    m.addOptions("build_options", opts);
    m.addImport("win32", win32Module(b, target, optimize));
    return m;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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
    b.step("wasm", "Build the browser client (zig-out/web/app.wasm)").dependOn(
        &b.addInstallFile(wasm.getEmittedBin(), "web/app.wasm").step,
    );

    const gui_root = rootModule(b, target, optimize, .gui, wasm.getEmittedBin());
    const ctl_root = rootModule(b, target, optimize, .ctl, wasm.getEmittedBin());

    const exe = b.addExecutable(.{ .name = "portal", .root_module = gui_root.root });
    exe.subsystem = .windows; // no console window, ever
    b.installArtifact(exe);
    const ctl_exe = b.addExecutable(.{ .name = "portalctl", .root_module = ctl_root.root });
    b.installArtifact(ctl_exe);
    const show_exe = b.addExecutable(.{ .name = "portal-show", .root_module = showModule(b, target, optimize, gui_root.gui.imgcheck) });
    b.installArtifact(show_exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    // Build API churn: 0.18 replaced `b.args` with `addPassthruArgs`.
    // Supporting both keeps the previous known-good compiler able to build.
    if (@hasDecl(@TypeOf(run_cmd.*), "addPassthruArgs")) {
        run_cmd.addPassthruArgs();
    } else if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    b.step("run", "Run portal (the window)").dependOn(&run_cmd.step);

    // Release tooling (src/tools): portal-release builds, tests and promotes
    // releases; the launchers are installed into %LOCALAPPDATA%\Portal\bin
    // and run the current release.
    const release_mod = b.createModule(.{
        .root_source_file = b.path("src/tools/release.zig"),
        .target = target,
        .optimize = optimize,
    });
    release_mod.addImport("win32", win32Module(b, target, optimize));
    const release_exe = b.addExecutable(.{ .name = "portal-release", .root_module = release_mod });
    b.installArtifact(release_exe);
    const launcher_exe = b.addExecutable(.{ .name = "portal-launcher", .root_module = launcherModule(b, target, optimize, true) });
    launcher_exe.subsystem = .windows;
    b.installArtifact(launcher_exe);
    const launcher_con = b.addExecutable(.{ .name = "portal-launcher-console", .root_module = launcherModule(b, target, optimize, false) });
    b.installArtifact(launcher_con);

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
    // The test step must also compile the real executables: unit tests alone
    // never analyse `main`, the web server, ConPTY or logging code, so a std
    // change breaking those would otherwise pass `zig build test`.
    const test_step = b.step("test", "Run unit tests and compile the exes (debug + ReleaseSafe) and release tools");
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = ctl_root.root })).step);

    test_step.dependOn(&exe.step);
    test_step.dependOn(&ctl_exe.step);
    test_step.dependOn(&show_exe.step);
    const safe_gui = rootModule(b, target, .ReleaseSafe, .gui, wasm.getEmittedBin());
    const exe_safe = b.addExecutable(.{ .name = "portal-releasesafe-check", .root_module = safe_gui.root });
    exe_safe.subsystem = .windows;
    test_step.dependOn(&exe_safe.step);
    const ctl_safe = b.addExecutable(.{ .name = "portalctl-releasesafe-check", .root_module = rootModule(b, target, .ReleaseSafe, .ctl, wasm.getEmittedBin()).root });
    test_step.dependOn(&ctl_safe.step);
    // Browser client: its pure logic (decoder, layout, keys, reconnects,
    // font parser, rasteriser, renderer) runs natively in Debug, where
    // safety checks catch what would be a wasm trap or silent corruption.
    const client_tests = b.addTest(.{ .root_module = clientModule(b, "src/wasm/tests.zig", target, .Debug) });
    test_step.dependOn(&b.addRunArtifact(client_tests).step);
    test_step.dependOn(&wasm.step);
    const gui_mods = gui_root.gui;
    // The shared GUI modules' own unit tests (client/src/view, client/src).
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = gui_mods.view })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = gui_mods.client })).step);
    // The protocol code every program shares (shared/root.zig), including
    // its fuzz tests.
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = sharedModule(b, target, .Debug) })).step);
    // The Renderer's Font module (parser, rasteriser, widths, atlas): its
    // own tests, run here too so vetting a compiler covers them.
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = fontModule(b, target, .Debug) })).step);
    // The input policy and input line shared by server and both clients,
    // and the Data slice's model shared by both clients.
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = gui_mods.inputrules })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = datafeedModule(b, target, optimize) })).step);
    // Inline images: Portal's check policy and the bounded decoder (fuzzed).
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = gui_mods.imgcheck })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = gui_mods.imgdec })).step);
    // Release tooling: unit tests (release.zig pulls in releases_lib.zig's)
    // and full compiles of the tools.
    const tool_tests = b.addTest(.{ .root_module = release_mod });
    test_step.dependOn(&b.addRunArtifact(tool_tests).step);
    test_step.dependOn(&release_exe.step);
    test_step.dependOn(&launcher_exe.step);
    test_step.dependOn(&launcher_con.step);
    // The laptop client (client/src/main.zig) for Linux and macOS, compile
    // only: a gap in one OS's window backend fails here, not in a later
    // cross build.
    for ([_]std.Target.Query{
        .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
        .{ .cpu_arch = .aarch64, .os_tag = .macos },
    }) |q| test_step.dependOn(&laptopClientCheck(b, b.resolveTargetQuery(q)).step);

    addE2e(b, target, optimize, gui_mods, ctl_exe, show_exe);
    addIos(b, optimize, test_step);
}

/// The laptop client's executable (as client/build.zig builds it) for `t`.
fn laptopClientCheck(b: *std.Build, t: std.Build.ResolvedTarget) *std.Build.Step.Compile {
    const inputrules = inputrulesModule(b, t, .Debug);
    const scratch = b.createModule(.{ .target = t, .optimize = .Debug });
    const gui = addGuiModules(b, scratch, t, .Debug, inputrules);
    return b.addExecutable(.{ .name = b.fmt("portal-client-check-{t}", .{t.result.os.tag}), .root_module = b.createModule(.{
        .root_source_file = b.path("client/src/main.zig"),
        .target = t,
        .optimize = .Debug,
        .link_libc = true, // libsecret / Security.framework via dlopen
        .imports = &.{
            .{ .name = "view", .module = gui.view },
            .{ .name = "shared", .module = sharedModule(b, t, .Debug) },
            .{ .name = "inputrules", .module = inputrules },
            .{ .name = "datafeed", .module = datafeedModule(b, t, .Debug) },
        },
    }) });
}

/// "inputrules" (src/inputrules): the input policy, the allowed key names
/// and the input line (answer words, what Send does, refusal texts), shared
/// by the server (src/keymap.zig), the native client (client/src) and the
/// browser client (src/wasm). std only.
fn inputrulesModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{ .root_source_file = b.path("src/inputrules/root.zig"), .target = target, .optimize = optimize });
}

/// "datafeed" (src/datafeed): the Data slice's model (bounded history of
/// what the session pushed, the "new" badge), shared by the browser client
/// (src/wasm/data.zig) and the native one (client/src/dataview.zig).
fn datafeedModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{ .root_source_file = b.path("src/datafeed/root.zig"), .target = target, .optimize = optimize });
}

/// `zig build e2e [-- group...]`: end-to-end tests (tests/e2e) that launch
/// real `portalctl run --console` processes in hidden consoles and drive
/// them over sockets. portalctl.exe and portal-show.exe are copied into one
/// folder, as in a release, so sessions find portal-show next to Portal.
/// Deliberately not part of `test`: it spawns processes and takes minutes.
fn addE2e(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, gui: GuiModules, ctl: *std.Build.Step.Compile, show: *std.Build.Step.Compile) void {
    const e2e_exe = b.addExecutable(.{
        .name = "portal-e2e",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/e2e/main.zig"),
            .target = target,
            .optimize = optimize,
            // The images group writes its test PNG with imgcheck's fixtures;
            // the webinput group decides what to send with the clients'
            // own input-line logic, and drives the native client's
            // instruction line (client/src/inputline.zig, through "client");
            // the ended group runs the native client's own stream code.
            .imports = &.{
                .{ .name = "client", .module = gui.client },
                .{ .name = "imgcheck", .module = gui.imgcheck },
                .{ .name = "inputrules", .module = gui.inputrules },
                .{ .name = "shared", .module = sharedModule(b, target, optimize) },
            },
        }),
    });
    const bin = b.addWriteFiles();
    const ctl_path = bin.addCopyFile(ctl.getEmittedBin(), "portalctl.exe");
    _ = bin.addCopyFile(show.getEmittedBin(), "portal-show.exe");
    const run = b.addRunArtifact(e2e_exe);
    run.addFileArg(ctl_path);
    run.has_side_effects = true;
    if (@hasDecl(@TypeOf(run.*), "addPassthruArgs")) {
        run.addPassthruArgs();
    } else if (b.args) |args| {
        run.addArgs(args);
    }
    b.step("e2e", "Run end-to-end tests against real portalctl processes (minutes)").dependOn(&run.step);
}

/// "shared" (shared/root.zig, its own package so that client/build.zig can
/// use it too): the protocol code the server, both clients and the e2e
/// tests must agree on.
fn sharedModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.dependency("shared", .{ .target = target, .optimize = optimize }).module("shared");
}

/// The browser client's module graph: `vt` (src/vt.zig, for the colour
/// sentinels, cell widths and, in tests, real server frames), `inputrules`
/// (src/inputrules: the input policy, key names and input line, shared
/// with the server and the native client), `datafeed`, the Renderer's
/// `Font` module (TrueType parser + rasteriser) and the bundled fonts as
/// `font_regular` / `font_bold`.
fn clientModule(b: *std.Build, root_src: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const img = imageModules(b, target, optimize);
    const m = b.createModule(.{ .root_source_file = b.path(root_src), .target = target, .optimize = optimize });
    const font = fontModule(b, target, optimize);
    const vt_mod = b.createModule(.{ .root_source_file = b.path("src/vt.zig"), .target = target, .optimize = optimize });
    vt_mod.addImport("imgcheck", img.imgcheck);
    vt_mod.addImport("Font", font);
    m.addImport("vt", vt_mod);
    m.addImport("Font", font);
    // Keys and the input box follow the server's own rules.
    m.addImport("inputrules", inputrulesModule(b, target, optimize));
    m.addImport("datafeed", datafeedModule(b, target, optimize));
    m.addImport("imgdec", img.imgdec);
    m.addImport("imgcheck", img.imgcheck);
    // The screen-frame decoder, shared with the native client.
    m.addImport("shared", sharedModule(b, target, optimize));
    m.addAnonymousImport("font_regular", .{ .root_source_file = b.path("src/web/fonts/DejaVuSansMono.ttf") });
    m.addAnonymousImport("font_bold", .{ .root_source_file = b.path("src/web/fonts/DejaVuSansMono-Bold.ttf") });
    return m;
}

// ---- fonts ----

/// The Renderer's "Font" module (TrueType parser, rasteriser, cell-width
/// table, system font set, glyph atlas). It imports nothing but std, so the
/// wasm32 browser client and the server's terminal emulator (src/vt.zig)
/// use it without compiling the Renderer's Vulkan module; the native view
/// gets the same module instance. The dependency arguments must match
/// addGuiModules' exactly, so every user shares one Font module (a file in
/// two modules of one compilation is an error).
fn fontModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return rendererDep(b, target, optimize).module("Font");
}

fn rendererDep(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Dependency {
    return b.dependency("Renderer", .{ .target = target, .optimize = optimize, .demo = false });
}

// ---- inline images ----

const ImageModules = struct { imgcheck: *std.Build.Module, imgdec: *std.Build.Module };

/// "imgcheck" (client/src/image/imgcheck.zig: Portal's limits over the
/// owner's Image.check, module "ImageCheck": std only, any target; also
/// imported by src/vt_gfx.zig) and "imgdec" (client/src/image: bounded
/// PNG -> RGBA8 on top of the owner's Image package).
///
/// Natively, imgdec imports Image's own published "Image" module. For
/// wasm32 it gets a module built from the same source (Image's
/// src/root.zig) with a stub "Vulkan" (client/src/image/vk_stub.zig: just
/// `Format`, the only Vulkan type the PNG path touches), so the browser
/// build never compiles or links the Vulkan bindings.
fn imageModules(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) ImageModules {
    // Same target and optimize as the Renderer dependency: Image passes them
    // on to ../Vulkan exactly as Renderer does, so both share one "Vulkan"
    // module (a source file may belong to only one module per build).
    const dep = b.dependency("Image", .{ .target = target, .optimize = optimize });
    const check = dep.module("ImageCheck");
    const imgcheck = b.createModule(.{
        .root_source_file = b.path("client/src/image/imgcheck.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "ImageCheck", .module = check }},
    });
    const image = if (target.result.cpu.arch.isWasm()) blk: {
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
                .{ .name = "ImageCheck", .module = check },
            },
        });
    } else dep.module("Image");
    const imgdec = b.createModule(.{
        .root_source_file = b.path("client/src/image/imgdec.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "Image", .module = image },
            .{ .name = "imgcheck", .module = imgcheck },
        },
    });
    return .{ .imgcheck = imgcheck, .imgdec = imgdec };
}

// ---- GUI modules (shared with client/, which still builds on its own) ----

const GuiModules = struct { view: *std.Build.Module, client: *std.Build.Module, imgdec: *std.Build.Module, imgcheck: *std.Build.Module, inputrules: *std.Build.Module };

/// Adds "view" (client/src/view: window, Vulkan drawing via the owner's
/// Renderer, fonts via its Font module; used by `portal run`'s window) and "client"
/// (client/src: the remote viewer behind `portal connect`) to `mod`.
fn addGuiModules(b: *std.Build, mod: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, inputrules: *std.Build.Module) GuiModules {
    const renderer = rendererDep(b, target, optimize);
    const link_libc = target.result.os.tag != .windows; // dlopen off Windows
    const img = imageModules(b, target, optimize);
    const shared = sharedModule(b, target, optimize);
    const view = b.createModule(.{
        .root_source_file = b.path("client/src/view/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = link_libc,
        .imports = &.{
            .{ .name = "Renderer", .module = renderer.module("Renderer") },
            // The native window (Win32 / Wayland / macOS).
            .{ .name = "Window", .module = renderer.module("Window") },
            .{ .name = "Font", .module = renderer.module("Font") },
            .{ .name = "imgdec", .module = img.imgdec },
            .{ .name = "shared", .module = shared },
        },
    });
    const client = b.createModule(.{
        .root_source_file = b.path("client/src/connect.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = link_libc,
        .imports = &.{
            .{ .name = "view", .module = view },
            .{ .name = "shared", .module = shared },
            .{ .name = "inputrules", .module = inputrules },
            .{ .name = "datafeed", .module = datafeedModule(b, target, optimize) },
        },
    });
    mod.addImport("view", view);
    mod.addImport("client", client);
    // src/vt.zig (a file of the root module) validates transmitted images.
    mod.addImport("imgcheck", img.imgcheck);
    return .{ .view = view, .client = client, .imgdec = img.imgdec, .imgcheck = img.imgcheck, .inputrules = inputrules };
}

// ---- iPhone app (client/src/ios; docs/ios-native.md) ----

/// The iPhone app: the same viewer as `portal connect` (module "client")
/// with the iPhone section (client/src/ios) as its entry.
///
///   zig build ios-check      compile it for aarch64-ios (object only: no
///                            iOS SDK needed; part of `zig build test`)
///   zig build ios            build zig-out/ios/Portal.app (on a Mac: needs
///                            the iOS SDK and MoltenVK, see the options)
///   zig build ios-sign       sign it (env: PORTAL_SIGN_IDENTITY,
///                            PORTAL_PROVISIONING_PROFILE, PORTAL_TEAM_ID)
///
/// Both build against a copy of Zig's lib dir with one std line fixed
/// (src/tools/ios_zig_lib.zig: std.Io.Threaded does not compile for iOS
/// in this Zig).
fn addIos(b: *std.Build, optimize: std.builtin.OptimizeMode, test_step: *std.Build.Step) void {
    const bundle_id = b.option([]const u8, "ios-bundle-id", "iPhone app bundle id (default local.portal.Portal; must match the provisioning profile)") orelse "local.portal.Portal";
    const tunnel = b.option(bool, "ios-tunnel", "iPhone app: control the per-app WireGuard tunnel extension (needs the Network Extension entitlement, paid account)") orelse false;
    const env = &b.graph.environ_map;
    const moltenvk = b.option([]const u8, "moltenvk", "iOS MoltenVK: path to libMoltenVK.dylib or MoltenVK.framework for iOS arm64 (env MOLTENVK_PATH)") orelse env.get("MOLTENVK_PATH");
    const sdk = b.option([]const u8, "ios-sdk", "iPhoneOS SDK path (env IOS_SDK; default: xcrun --sdk iphoneos --show-sdk-path on a Mac)") orelse env.get("IOS_SDK") orelse if (b.graph.host.result.os.tag == .macos)
        std.mem.trim(u8, b.run(&.{ "xcrun", "--sdk", "iphoneos", "--show-sdk-path" }), " \r\n")
    else
        null;

    const t = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64,
        .os_tag = .ios,
        .os_version_min = .{ .semver = .{ .major = 16, .minor = 0, .patch = 0 } },
    });

    // The Zig lib dir with the std fix (cached by the build system).
    const lib_tool = b.addExecutable(.{ .name = "ios-zig-lib", .root_module = b.createModule(.{
        .root_source_file = b.path("src/tools/ios_zig_lib.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
    }) });
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = lib_tool.root_module })).step);
    const lib_run = b.addRunArtifact(lib_tool);
    lib_run.addDirectoryArg(.zig_lib);
    const zig_lib = lib_run.addOutputDirectoryArg("zig-lib");

    // Compile check (object): the whole iPhone app and its tunnel extension
    // without the SDK.
    const check = b.addObject(.{ .name = "portal-ios-check", .root_module = iosModule(b, t, .Debug, bundle_id, tunnel), .zig_lib_dir = zig_lib });
    const ext_check = b.addObject(.{ .name = "portal-tunnel-check", .root_module = tunnelExtModule(b, t, .Debug), .zig_lib_dir = zig_lib });
    const ios_check = b.step("ios-check", "Compile the iPhone app and its tunnel extension for aarch64-ios (objects only, no SDK needed)");
    ios_check.dependOn(&check.step);
    ios_check.dependOn(&ext_check.step);
    test_step.dependOn(ios_check);
    // The extension's backend logic (config -> network settings) on this host.
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("client/src/ios/tunnel_ext/backend.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
        .imports = &.{.{ .name = "WireGuard", .module = b.dependency("WireGuard", .{ .target = b.graph.host, .optimize = .Debug }).module("WireGuard") }},
    }) })).step);

    // Placeholder icon and the tools' own tests.
    const icon_tool = b.addExecutable(.{ .name = "ios-icon", .root_module = b.createModule(.{
        .root_source_file = b.path("src/tools/ios_icon.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
    }) });
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = icon_tool.root_module })).step);
    const sign_tool = b.addExecutable(.{ .name = "ios-sign", .root_module = b.createModule(.{
        .root_source_file = b.path("src/tools/ios_sign.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
    }) });
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = sign_tool.root_module })).step);

    const ios_step = b.step("ios", "Build zig-out/ios/Portal.app (Mac: iOS SDK + -Dmoltenvk=...)");
    const sign_step = b.step("ios-sign", "Sign zig-out/ios/Portal.app (env PORTAL_SIGN_IDENTITY, PORTAL_PROVISIONING_PROFILE, PORTAL_TEAM_ID)");
    const sdk_path = sdk orelse {
        const fail = b.addFail("zig build ios needs the iPhoneOS SDK: run it on a Mac with Xcode, or pass -Dios-sdk=<path> / IOS_SDK");
        ios_step.dependOn(&fail.step);
        sign_step.dependOn(&fail.step);
        return;
    };
    const mvk = moltenvk orelse {
        const fail = b.addFail("zig build ios needs MoltenVK for iOS: -Dmoltenvk=<.../MoltenVK/dynamic/dylib/iOS/libMoltenVK.dylib or MoltenVK.framework> (or MOLTENVK_PATH); see docs/ios-native.md");
        ios_step.dependOn(&fail.step);
        sign_step.dependOn(&fail.step);
        return;
    };

    const mod = iosModule(b, t, optimize, bundle_id, tunnel);
    mod.addSystemFrameworkPath(.{ .cwd_relative = b.pathJoin(&.{ sdk_path, "System/Library/Frameworks" }) });
    mod.addLibraryPath(.{ .cwd_relative = b.pathJoin(&.{ sdk_path, "usr/lib" }) });
    mod.addSystemIncludePath(.{ .cwd_relative = b.pathJoin(&.{ sdk_path, "usr/include" }) });
    for ([_][]const u8{ "UIKit", "QuartzCore", "Foundation", "CoreGraphics", "Metal", "Security", "AVFoundation", "LocalAuthentication" }) |fw|
        mod.linkFramework(fw, .{});
    if (tunnel) mod.linkFramework("NetworkExtension", .{});
    mod.linkSystemLibrary("objc", .{});
    // MoltenVK is opened from the bundle at run time (the Vulkan package's
    // loader); the rpath lets a framework build of MoltenVK find itself.
    mod.addRPathSpecial("@executable_path/Frameworks");
    const exe = b.addExecutable(.{ .name = "Portal", .root_module = mod, .zig_lib_dir = zig_lib });
    exe.headerpad_max_install_names = true;
    // The packet tunnel extension (with -Dios-tunnel): Foundation +
    // NetworkExtension, no UIKit window.
    const ext_exe: ?*std.Build.Step.Compile = if (tunnel) blk: {
        const em = tunnelExtModule(b, t, optimize);
        em.addSystemFrameworkPath(.{ .cwd_relative = b.pathJoin(&.{ sdk_path, "System/Library/Frameworks" }) });
        em.addLibraryPath(.{ .cwd_relative = b.pathJoin(&.{ sdk_path, "usr/lib" }) });
        em.linkFramework("Foundation", .{});
        em.linkFramework("NetworkExtension", .{});
        em.linkSystemLibrary("objc", .{});
        break :blk b.addExecutable(.{ .name = "PortalTunnel", .root_module = em, .zig_lib_dir = zig_lib });
    } else null;
    const libc_txt = b.addWriteFiles().add("libc-ios.txt", b.fmt(
        \\include_dir={s}/usr/include
        \\sys_include_dir={s}/usr/include
        \\crt_dir={s}/usr/lib
        \\msvc_lib_dir=
        \\kernel32_lib_dir=
        \\gcc_dir=
        \\
    , .{ sdk_path, sdk_path, sdk_path }));
    exe.setLibCFile(libc_txt);
    if (ext_exe) |e| e.setLibCFile(libc_txt);

    // Portal.app
    const app = b.addWriteFiles();
    _ = app.addCopyFile(exe.getEmittedBin(), "Portal.app/Portal");
    _ = app.add("Portal.app/Info.plist", infoPlist(b, bundle_id));
    _ = app.add("Portal.app/PkgInfo", "APPL????");
    if (ext_exe) |e| {
        _ = app.addCopyFile(e.getEmittedBin(), "Portal.app/PlugIns/PortalTunnel.appex/PortalTunnel");
        _ = app.add("Portal.app/PlugIns/PortalTunnel.appex/Info.plist", tunnelPlist(b, bundle_id));
    }
    if (std.mem.endsWith(u8, std.mem.trimEnd(u8, mvk, "/"), ".framework")) {
        _ = app.addCopyDirectory(.{ .cwd_relative = mvk }, "Portal.app/Frameworks/MoltenVK.framework", .{});
    } else {
        _ = app.addCopyFile(.{ .cwd_relative = mvk }, "Portal.app/Frameworks/libMoltenVK.dylib");
    }
    for ([_]struct { px: []const u8, name: []const u8 }{
        .{ .px = "120", .name = "AppIcon60x60@2x.png" },
        .{ .px = "180", .name = "AppIcon60x60@3x.png" },
    }) |ic| {
        const r = b.addRunArtifact(icon_tool);
        r.addArg(ic.px);
        _ = app.addCopyFile(r.addOutputFileArg(ic.name), b.fmt("Portal.app/{s}", .{ic.name}));
    }
    const install = b.addInstallDirectory(.{ .source_dir = app.getDirectory().path(b, "Portal.app"), .install_dir = .prefix, .install_subdir = "ios/Portal.app" });
    ios_step.dependOn(&install.step);

    // Signs a copy (the cached bundle stays unsigned) and installs it over
    // zig-out/ios/Portal.app.
    const sign = b.addRunArtifact(sign_tool);
    sign.addDirectoryArg(app.getDirectory().path(b, "Portal.app"));
    const signed = sign.addOutputDirectoryArg("signed");
    sign.addArgs(&.{ bundle_id, if (tunnel) "1" else "0" });
    sign.has_side_effects = true; // reads the signing identity from the environment
    const install_signed = b.addInstallDirectory(.{ .source_dir = signed.path(b, "Portal.app"), .install_dir = .prefix, .install_subdir = "ios/Portal.app" });
    install_signed.step.dependOn(&install.step);
    sign_step.dependOn(&install_signed.step);
}

/// The iPhone app's root module for `t`: client/src/ios/main.zig on the
/// shared "view" and "client" modules.
fn iosModule(b: *std.Build, t: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, bundle_id: []const u8, tunnel: bool) *std.Build.Module {
    const inputrules = inputrulesModule(b, t, optimize);
    const scratch = b.createModule(.{ .target = t, .optimize = optimize });
    const gui = addGuiModules(b, scratch, t, optimize, inputrules);
    const opts = b.addOptions();
    opts.addOption(bool, "tunnel", tunnel);
    opts.addOption([]const u8, "bundle_id", bundle_id);
    return b.createModule(.{
        .root_source_file = b.path("client/src/ios/main.zig"),
        .target = t,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "view", .module = gui.view },
            .{ .name = "client", .module = gui.client },
            .{ .name = "ios_options", .module = opts.createModule() },
        },
    });
}

/// The packet tunnel extension's root module: client/src/ios/tunnel_ext
/// on the owner's Zig WireGuard and the Renderer's IosObjC runtime layer.
fn tunnelExtModule(b: *std.Build, t: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("client/src/ios/tunnel_ext/main.zig"),
        .target = t,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "WireGuard", .module = b.dependency("WireGuard", .{ .target = t, .optimize = optimize }).module("WireGuard") },
            .{ .name = "IosObjC", .module = rendererDep(b, t, optimize).module("IosObjC") },
        },
    });
}

/// The tunnel extension's Info.plist (configuration text).
fn tunnelPlist(b: *std.Build, bundle_id: []const u8) []const u8 {
    return b.fmt(
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<plist version="1.0">
        \\<dict>
        \\    <key>CFBundleExecutable</key><string>PortalTunnel</string>
        \\    <key>CFBundleIdentifier</key><string>{s}.tunnel</string>
        \\    <key>CFBundleName</key><string>PortalTunnel</string>
        \\    <key>CFBundleDisplayName</key><string>Portal tunnel</string>
        \\    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
        \\    <key>CFBundlePackageType</key><string>XPC!</string>
        \\    <key>CFBundleShortVersionString</key><string>0.1.0</string>
        \\    <key>CFBundleVersion</key><string>1</string>
        \\    <key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
        \\    <key>MinimumOSVersion</key><string>16.0</string>
        \\    <key>NSExtension</key>
        \\    <dict>
        \\        <key>NSExtensionPointIdentifier</key><string>com.apple.networkextension.packet-tunnel</string>
        \\        <key>NSExtensionPrincipalClass</key><string>PortalPacketTunnelProvider</string>
        \\    </dict>
        \\</dict>
        \\</plist>
            , .{bundle_id});
}

/// Info.plist (configuration text, not code): what iOS reads before the
/// app runs. Scene-based (the Renderer's Window backend provides the scene
/// delegate), launch screen without a storyboard, camera and Face ID
/// usage strings, local-network note for the desk on the LAN.
fn infoPlist(b: *std.Build, bundle_id: []const u8) []const u8 {
    return b.fmt(
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<plist version="1.0">
        \\<dict>
        \\    <key>CFBundleDevelopmentRegion</key><string>en</string>
        \\    <key>CFBundleExecutable</key><string>Portal</string>
        \\    <key>CFBundleIdentifier</key><string>{s}</string>
        \\    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
        \\    <key>CFBundleName</key><string>Portal</string>
        \\    <key>CFBundleDisplayName</key><string>Portal</string>
        \\    <key>CFBundlePackageType</key><string>APPL</string>
        \\    <key>CFBundleShortVersionString</key><string>0.1.0</string>
        \\    <key>CFBundleVersion</key><string>1</string>
        \\    <key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
        \\    <key>DTPlatformName</key><string>iphoneos</string>
        \\    <key>MinimumOSVersion</key><string>16.0</string>
        \\    <key>LSRequiresIPhoneOS</key><true/>
        \\    <key>UIDeviceFamily</key><array><integer>1</integer></array>
        \\    <key>UIRequiredDeviceCapabilities</key><array><string>arm64</string><string>metal</string></array>
        \\    <key>UILaunchScreen</key><dict><key>UIColorName</key><string></string></dict>
        \\    <key>UIApplicationSceneManifest</key>
        \\    <dict><key>UIApplicationSupportsMultipleScenes</key><false/></dict>
        \\    <key>UISupportedInterfaceOrientations</key>
        \\    <array><string>UIInterfaceOrientationPortrait</string><string>UIInterfaceOrientationLandscapeLeft</string><string>UIInterfaceOrientationLandscapeRight</string></array>
        \\    <key>UIStatusBarStyle</key><string>UIStatusBarStyleLightContent</string>
        \\    <key>UIUserInterfaceStyle</key><string>Dark</string>
        \\    <key>CFBundleIcons</key>
        \\    <dict><key>CFBundlePrimaryIcon</key><dict><key>CFBundleIconFiles</key><array><string>AppIcon60x60</string></array></dict></dict>
        \\    <key>NSCameraUsageDescription</key><string>Portal scans the pairing QR code shown on your desktop.</string>
        \\    <key>NSFaceIDUsageDescription</key><string>Portal asks for Face ID before it shows your session or signs in.</string>
        \\    <key>NSLocalNetworkUsageDescription</key><string>Portal connects to the Portal running on your desktop.</string>
        \\</dict>
        \\</plist>
        \\
    , .{bundle_id});
}
