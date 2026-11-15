const std = @import("std");

/// Which program a build of src/main.zig is (build option `gui`):
///   portal.exe     the Portal window (Windows GUI subsystem: no console;
///                  errors go to message boxes). The desk's session window
///                  and `portal connect`, the remote viewer.
///   portalctl.exe  the console tool: pair, devices, unpair, ca, version,
///                  run --console (scripting, tests, fallback).
/// Both are the same code with a different entry dispatch.
const App = enum { gui, ctl };

fn rootModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, app: App) struct { root: *std.Build.Module, gui: GuiModules } {
    const root = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const opts = b.addOptions();
    opts.addOption(bool, "gui", app == .gui);
    // Test-only environment variables (PORTAL_AGENT_PROJECTS) are honoured
    // in Debug builds (unit tests, `zig build e2e`) only, never in the
    // ReleaseSafe builds releases are made of.
    opts.addOption(bool, "test_env", optimize == @TypeOf(optimize).Debug);
    root.addOptions("build_options", opts);
    root.addImport("shared", sharedModule(b, target, optimize));
    // src/vt.zig (a file of the root module) takes its cell widths from it.
    root.addImport("Font", fontModule(b, target, optimize));
    // One instance per compilation: src/keymap.zig and the client module
    // (portal connect) share it.
    const rules = inputrulesModule(b, target, optimize);
    root.addImport("inputrules", rules);
    // Speech input (src/speech): microphone capture and the stt engines.
    root.addImport("speech", speechModule(b, target, optimize));
    // The in-process tunnel (client/src/tunnel): the desk's side of it and
    // its key and peer table (src/tunneldesk.zig).
    root.addImport("WireGuard", wireguardModule(b, target, optimize));
    root.addImport("tunnel_options", tunnelOptions(b));
    const gui_mods = addGuiModules(b, root, target, optimize, rules);
    return .{ .root = root, .gui = gui_mods };
}

/// The owner's Zig WireGuard (../WireGuard) and the tunnel's build options
/// (-Dnetstack-ready): one definition, in client/build.zig.
const client_build = @import("client/build.zig");
const wireguardModule = client_build.wireguardModule;
const tunnelOptions = client_build.tunnelOptions;

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

    const gui_root = rootModule(b, target, optimize, .gui);
    const ctl_root = rootModule(b, target, optimize, .ctl);

    const exe = b.addExecutable(.{ .name = "portal", .root_module = gui_root.root });
    exe.subsystem = .windows; // no console window, ever
    addAppIcon(b, exe);
    b.installArtifact(exe);
    const ctl_exe = b.addExecutable(.{ .name = "portalctl", .root_module = ctl_root.root });
    addAppIcon(b, ctl_exe);
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
    addAppIcon(b, launcher_exe);
    b.installArtifact(launcher_exe);
    const launcher_con = b.addExecutable(.{ .name = "portal-launcher-console", .root_module = launcherModule(b, target, optimize, false) });
    addAppIcon(b, launcher_con);
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
    const safe_gui = rootModule(b, target, .ReleaseSafe, .gui);
    const exe_safe = b.addExecutable(.{ .name = "portal-releasesafe-check", .root_module = safe_gui.root });
    exe_safe.subsystem = .windows;
    test_step.dependOn(&exe_safe.step);
    const ctl_safe = b.addExecutable(.{ .name = "portalctl-releasesafe-check", .root_module = rootModule(b, target, .ReleaseSafe, .ctl).root });
    test_step.dependOn(&ctl_safe.step);
    const gui_mods = gui_root.gui;
    // The shared UI (ui/: layout, draw list, shell, panels, theme use) and
    // the GUI modules' own unit tests (client/src/view, client/src).
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = gui_mods.ui })).step);
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

    // Speech input: the microphone thread with a fake backend, the
    // selection rules, and (with an NVIDIA GPU and ../SpeechToText's model)
    // a recording through stt.Home; the laptop engine's protocol client
    // against a fake stt-local (src/speech/fake_stt_local.zig).
    const fake_stt_local = b.addExecutable(.{ .name = "fake-stt-local", .root_module = b.createModule(.{
        .root_source_file = b.path("src/speech/fake_stt_local.zig"),
        .target = target,
        .optimize = .Debug,
    }) });
    const speech_tests = b.addRunArtifact(b.addTest(.{ .root_module = speechModuleWith(b, target, optimize, fake_stt_local.getEmittedBin()) }));
    test_step.dependOn(&speech_tests.step);
    b.step("test-speech", "Run only the speech module's tests").dependOn(&speech_tests.step);
    // A manual check of the real microphone (never part of `test`).
    const mic_check_mod = b.createModule(.{ .root_source_file = b.path("src/speech/mic_check.zig"), .target = target, .optimize = optimize });
    const speech_mod = speechModule(b, target, optimize);
    mic_check_mod.addImport("speech", speech_mod);
    mic_check_mod.addImport("speech_options", speech_mod.import_table.get("speech_options").?);
    const mic_check = b.addRunArtifact(b.addExecutable(.{ .name = "portal-mic-check", .root_module = mic_check_mod }));
    mic_check.addPassthruArgs();
    b.step("mic-check", "Record from the real microphone and transcribe it (manual check; -- <seconds> [model])").dependOn(&mic_check.step);
    // stt-local (the laptop's engine, built from the stt package into
    // this build's zig-out). `zig build stt-local -Dtarget=aarch64-windows`
    // for the Snapdragon X: the only build that needs the QAIRT SDK headers
    // (TranslateNPU's; -Dsdk=<dir> or QNN_SDK_ROOT). Any other target or
    // step never fetches TranslateNPU or the SDK.
    const stt_sdk = b.option([]const u8, "sdk", "stt-local for aarch64-windows: the QAIRT/QNN SDK root (else QNN_SDK_ROOT)");
    const stt_local = b.dependency("stt", .{ .target = target, .optimize = .fast, .sdk = stt_sdk }).artifact("stt-local");
    b.step("stt-local", "Build stt-local (the laptop speech engine) into zig-out/bin").dependOn(&b.addInstallArtifact(stt_local, .{}).step);
    addVoicePackages(b, stt_sdk);
    addE2e(b, target, optimize, gui_mods, ctl_exe, show_exe);
    addIos(b, optimize, test_step);
    addBrand(b, test_step);
    addPackage(b, test_step);
    addPin(b);
}

/// A sibling repo pinned in build.zig.zon (and, with `client`, in
/// client/build.zig.zon too).
const Pin = struct { name: []const u8, repo: []const u8, branch: []const u8, client: bool };
const pins = [_]Pin{
    .{ .name = "Renderer", .repo = "Renderer", .branch = "main", .client = true },
    .{ .name = "Image", .repo = "Image", .branch = "neuro-formats", .client = true },
    .{ .name = "WireGuard", .repo = "Wireguard", .branch = "master", .client = true },
    .{ .name = "stt", .repo = "SpeechToText", .branch = "main", .client = false },
};

/// `zig build pin [-Dpin=<name>]`: re-pins the sibling repos (or the one
/// named) to the newest commit of their branch on GitHub, with `zig fetch
/// --save`, in build.zig.zon and client/build.zig.zon. Push the sibling
/// first; the deeper pins (Renderer's and Image's Vulkan, ...) are bumped
/// in those repos the same way (README, Development).
fn addPin(b: *std.Build) void {
    const only = b.option([]const u8, "pin", "zig build pin: only this dependency (Renderer, Image, WireGuard or stt)");
    const step = b.step("pin", "Re-pin the sibling repos (or -Dpin=<name>) to the newest commit of their branch on GitHub");
    var prev: ?*std.Build.Step = null;
    var matched = false;
    for (pins) |p| {
        if (only) |o| if (!std.mem.eql(u8, o, p.name)) continue;
        matched = true;
        const url = b.fmt("git+https://github.com/Mauhlt/{s}#{s}", .{ p.repo, p.branch });
        const dirs: []const []const u8 = if (p.client) &.{ ".", "client" } else &.{"."};
        for (dirs) |dir| {
            // One at a time: each run rewrites a build.zig.zon.
            const run = b.addSystemCommand(&.{ b.graph.zig_exe, "fetch", b.fmt("--save={s}", .{p.name}), url });
            run.setCwd(b.path(dir));
            run.has_side_effects = true;
            if (prev) |s| run.step.dependOn(s);
            prev = &run.step;
            step.dependOn(&run.step);
        }
    }
    if (!matched) step.dependOn(&b.addFail(b.fmt("zig build pin: no dependency {s} (Renderer, Image, WireGuard or stt)", .{only.?})).step);
}

/// Windows: links docs/brand/portal.ico as icon resource 1 (Explorer,
/// the taskbar; the window sets it from there with WM_SETICON). The
/// one-line resource script is generated here, next to a copy of the icon.
fn addAppIcon(b: *std.Build, exe: *std.Build.Step.Compile) void {
    if (exe.rootModuleTarget().os.tag != .windows) return;
    const wf = b.addWriteFiles();
    _ = wf.addCopyFile(b.path("docs/brand/portal.ico"), "portal.ico");
    const rc = wf.add("portal.rc", "1 ICON \"portal.ico\"\n");
    exe.root_module.addWin32ResourceFile(.{ .file = rc });
}

/// `zig build package`: ready-to-copy ReleaseSafe folders, one per Windows
/// machine type the owner's devices use, built whatever -Dtarget says:
///   zig-out/portal-x86_64-windows/   the desktop
///   zig-out/portal-aarch64-windows/  the Snapdragon X laptop and the Surface
/// Each holds portal.exe, portalctl.exe, portal-show.exe, README.txt
/// (docs/package-readme.txt). No DLLs: the
/// tunnel is the WireGuard app's own, Vulkan comes with the GPU driver.
/// src/tools/pecheck.zig checks every exe's PE machine and subsystem and
/// writes zig-out/portal-<arch>-windows-check.txt.
fn addPackage(b: *std.Build, test_step: *std.Build.Step) void {
    const step = b.step("package", "Build ReleaseSafe folders for x86_64 and aarch64 Windows (zig-out/portal-<arch>-windows)");
    const pecheck_mod = b.createModule(.{
        .root_source_file = b.path("src/tools/pecheck.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
    });
    const pecheck = b.addExecutable(.{ .name = "portal-pecheck", .root_module = pecheck_mod });
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = pecheck_mod })).step);
    for ([_]std.Target.Cpu.Arch{ .x86_64, .aarch64 }) |arch| {
        // Baseline CPU (no -mcpu=native): the folder runs on any machine of
        // that architecture, not only the one that built it.
        const t = b.resolveTargetQuery(.{ .cpu_arch = arch, .os_tag = .windows });
        const gui_root = rootModule(b, t, .ReleaseSafe, .gui);
        const ctl_root = rootModule(b, t, .ReleaseSafe, .ctl);
        const exe = b.addExecutable(.{ .name = "portal", .root_module = gui_root.root });
        exe.subsystem = .windows;
        addAppIcon(b, exe);
        const ctl = b.addExecutable(.{ .name = "portalctl", .root_module = ctl_root.root });
        addAppIcon(b, ctl);
        const show = b.addExecutable(.{ .name = "portal-show", .root_module = showModule(b, t, .ReleaseSafe, gui_root.gui.imgcheck) });

        const name = b.fmt("portal-{t}-windows", .{arch});
        const wf = b.addWriteFiles();
        _ = wf.addCopyFile(exe.getEmittedBin(), "portal.exe");
        _ = wf.addCopyFile(ctl.getEmittedBin(), "portalctl.exe");
        _ = wf.addCopyFile(show.getEmittedBin(), "portal-show.exe");
        _ = wf.add("README.txt", b.fmt("Portal for {t} Windows (ReleaseSafe)\r\n\r\n{s}", .{ arch, crlf(b, @embedFile("docs/package-readme.txt")) }));

        const check = b.addRunArtifact(pecheck);
        check.addArg(@tagName(arch));
        const report = check.addOutputFileArg("check.txt");
        for ([_]struct { kind: []const u8, c: *std.Build.Step.Compile }{
            .{ .kind = "gui", .c = exe },
            .{ .kind = "console", .c = ctl },
            .{ .kind = "console", .c = show },
        }) |e| {
            check.addArg(e.kind);
            check.addFileArg(e.c.getEmittedBin());
        }

        // `zig build test` compiles the ARM64 exes too (and checks their PE
        // headers), so an aarch64-only break shows up there, not only here.
        if (arch == .aarch64) test_step.dependOn(&check.step);

        const install = b.addInstallDirectory(.{ .source_dir = wf.getDirectory(), .install_dir = .prefix, .install_subdir = name });
        install.step.dependOn(&check.step);
        step.dependOn(&install.step);
        step.dependOn(&b.addInstallFile(report, b.fmt("{s}-check.txt", .{name})).step);
    }
}

/// `text` with CRLF line ends, for Notepad on any Windows.
fn crlf(b: *std.Build, text: []const u8) []const u8 {
    const lf = std.mem.replaceOwned(u8, b.allocator, text, "\r\n", "\n") catch @panic("OOM");
    return std.mem.replaceOwned(u8, b.allocator, lf, "\n", "\r\n") catch @panic("OOM");
}

/// `zig build brand`: regenerates docs/brand's raster assets (the icon
/// PNGs, portal.ico, the embedded hero PNG) with src/tools/brand.zig. Its
/// outputs are committed; normal builds only read them.
fn addBrand(b: *std.Build, test_step: *std.Build.Step) void {
    const host = b.graph.host;
    const mod = b.createModule(.{
        .root_source_file = b.path("src/tools/brand.zig"),
        .target = host,
        .optimize = .ReleaseFast,
        .imports = &.{.{ .name = "Image", .module = b.dependency("Image", .{ .target = host, .optimize = .ReleaseFast }).module("Image") }},
    });
    const tool = b.addExecutable(.{ .name = "portal-brand", .root_module = mod });
    const step = b.step("brand", "Regenerate docs/brand's icon PNGs, portal.ico and the embedded hero PNG");
    const icons = b.addRunArtifact(tool);
    icons.addArgs(&.{ "icons", "docs/brand" });
    icons.setCwd(b.path("."));
    icons.has_side_effects = true;
    step.dependOn(&icons.step);
    const hero = b.addRunArtifact(tool);
    hero.addArgs(&.{ "hero", "docs/brand/portal-hero.jpg", hero_png, b.fmt("{d}", .{hero_side}) });
    hero.setCwd(b.path("."));
    hero.has_side_effects = true;
    step.dependOn(&hero.step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/tools/brand.zig"),
        .target = host,
        .optimize = .Debug,
        .imports = &.{.{ .name = "Image", .module = b.dependency("Image", .{ .target = host, .optimize = .Debug }).module("Image") }},
    }) })).step);
}

/// The hero art Portal embeds (splash, About), made by `zig build brand`.
const hero_png = "docs/brand/portal-hero-768.png";
const hero_side = 768;

/// The laptop client's executable (as client/build.zig builds it) for `t`.
fn laptopClientCheck(b: *std.Build, t: std.Build.ResolvedTarget) *std.Build.Step.Compile {
    const inputrules = inputrulesModule(b, t, .Debug);
    const scratch = b.createModule(.{ .target = t, .optimize = .Debug });
    const gui = addGuiModules(b, scratch, t, .Debug, inputrules);
    return b.addExecutable(.{
        .name = b.fmt("portal-client-check-{t}", .{t.result.os.tag}),
        .root_module = b.createModule(.{
            .root_source_file = b.path("client/src/main.zig"),
            .target = t,
            .optimize = .Debug,
            .link_libc = true, // Security.framework via dlopen
            .imports = &.{
                .{ .name = "view", .module = gui.view },
                .{ .name = "portal_ui", .module = gui.ui },
                .{ .name = "shared", .module = sharedModule(b, t, .Debug) },
                .{ .name = "inputrules", .module = inputrules },
                .{ .name = "WireGuard", .module = wireguardModule(b, t, .Debug) },
                .{ .name = "tunnel_options", .module = tunnelOptions(b) },
            },
        }),
    });
}

/// "inputrules" (src/inputrules): the input policy, the allowed key names
/// and the input line (answer words, what Send does, refusal texts), shared
/// by the server (src/keymap.zig) and the native clients (client/src,
/// ui/). std only.
fn inputrulesModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{ .root_source_file = b.path("src/inputrules/root.zig"), .target = target, .optimize = optimize });
}

/// "datafeed" (src/datafeed): the Data slice's model (bounded history of
/// what the session pushed, the "new" badge), used by the shared UI
/// (ui/dataview.zig).
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

// ---- fonts ----

/// The Renderer's "Font" module (TrueType parser, rasteriser, cell-width
/// table, system font set, glyph atlas). It imports nothing but std, so the
/// server's terminal emulator (src/vt.zig) uses it without compiling the
/// Renderer's Vulkan module; the native view
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
/// imgdec imports a module equal to Image's own published "Image" (see
/// below for why it is built here).
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
    const image = blk: {
        // The same module as Image's own "Image" (its root, its
        // ImageCheck, the shared Vulkan), but with build options of
        // Portal's: Image's options file has exactly the content of
        // ../Audio's (`vector_bytes = 0`), and stt brings Audio into the
        // same compilation, where one file can't root two modules. The
        // marker makes this file different; the value is Image's default.
        const opts = b.addOptions();
        opts.addOption(usize, "vector_bytes", 0); // 0: suggested for the target, as in Image
        opts.addOption([]const u8, "portal_options_for", "Image");
        break :blk b.createModule(.{
            .root_source_file = dep.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "Vulkan", .module = dep.builder.dependency("Vulkan", .{ .target = target, .optimize = optimize }).module("Vulkan") },
                .{ .name = "build_options", .module = opts.createModule() },
                .{ .name = "ImageCheck", .module = check },
            },
        });
    };
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

const GuiModules = struct { ui: *std.Build.Module, view: *std.Build.Module, client: *std.Build.Module, imgdec: *std.Build.Module, imgcheck: *std.Build.Module, inputrules: *std.Build.Module };

/// "portal_ui" (ui/root.zig): the one Portal UI every native device runs
/// (layout, draw list, shell, panels; colours from shared/theme.zig). A
/// plain module of this build rather than a package, like inputrules,
/// because it shares this compilation's "Font", "shared", "inputrules" and
/// "datafeed" instances (a file may belong to one module per compilation);
/// client/build.zig creates it the same way from ../ui/root.zig.
fn uiModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, inputrules: *std.Build.Module) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("ui/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "Font", .module = fontModule(b, target, optimize) },
            .{ .name = "shared", .module = sharedModule(b, target, optimize) },
            .{ .name = "inputrules", .module = inputrules },
            .{ .name = "datafeed", .module = datafeedModule(b, target, optimize) },
        },
    });
}

/// Adds "portal_ui" (ui/), "view" (client/src/view: window, Vulkan drawing
/// of the UI's draw list via the owner's Renderer, fonts via its Font
/// module; used by `portal run`'s window) and "client" (client/src: the
/// remote viewer behind `portal connect`) to `mod`.
fn addGuiModules(b: *std.Build, mod: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, inputrules: *std.Build.Module) GuiModules {
    const renderer = rendererDep(b, target, optimize);
    // dlopen off Windows. On Windows left unset rather than false: Zig
    // 0.18.0-dev.1005 rejects a module with link_libc = false in a
    // compilation where another module links libc (stt's translate-c'd
    // QNN headers on x86_64 Windows), and false never kept libc out.
    const link_libc: ?bool = if (target.result.os.tag != .windows) true else null;
    const img = imageModules(b, target, optimize);
    const shared = sharedModule(b, target, optimize);
    const ui = uiModule(b, target, optimize, inputrules);
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
            .{ .name = "portal_ui", .module = ui },
        },
    });
    // The hero art for the start-up splash (docs/brand, `zig build brand`).
    view.addAnonymousImport("portal_hero", .{ .root_source_file = b.path(hero_png) });
    const client = b.createModule(.{
        .root_source_file = b.path("client/src/connect.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = link_libc,
        .imports = &.{
            .{ .name = "view", .module = view },
            .{ .name = "portal_ui", .module = ui },
            .{ .name = "shared", .module = shared },
            .{ .name = "inputrules", .module = inputrules },
            .{ .name = "WireGuard", .module = wireguardModule(b, target, optimize) },
            .{ .name = "tunnel_options", .module = tunnelOptions(b) },
        },
    });
    mod.addImport("view", view);
    mod.addImport("portal_ui", ui);
    mod.addImport("client", client);
    // src/vt.zig (a file of the root module) validates transmitted images.
    mod.addImport("imgcheck", img.imgcheck);
    return .{ .ui = ui, .view = view, .client = client, .imgdec = img.imgdec, .imgcheck = img.imgcheck, .inputrules = inputrules };
}

// ---- iPhone app (client/src/ios; docs/ios-native.md) ----

/// The oldest iOS the app runs on (deployment target and both
/// Info.plists' MinimumOSVersion): the dictation engine's Core ML
/// programs target iOS 17.
const ios_min_major = 17;

/// The dictation model bundled into Portal.app (iOS builds only): the
/// SAME base model the desk's stt.Home trains its adapter on (an adapter
/// fits only its own base model), pinned once in src/speech/model_pin.zig
/// (Hugging Face URL at a fixed commit, size, SHA-256). Zig's package
/// fetcher takes only archives and git repositories, so a single file
/// comes through src/tools/fetch_file.zig, run only by the steps that
/// build the app (never by ios-check or test); the build cache keeps it.
/// -Dios-model=<path> uses a local ggml file instead (it must be that
/// same file for home's adapter to apply).
const model_pin = @import("src/speech/model_pin.zig");

/// The iPhone app: the same viewer as `portal connect` (module "client")
/// with the iPhone section (client/src/ios) as its entry.
///
///   zig build ios-check      compile it for aarch64-ios (object only: no
///                            iOS SDK needed; part of `zig build test`)
///   zig build ios            build zig-out/ios/Portal.app (on a Mac: needs
///                            the iOS SDK and MoltenVK, see the options)
///   zig build ios-sign       sign it (env: PORTAL_SIGN_IDENTITY,
///                            PORTAL_PROVISIONING_PROFILE, PORTAL_TEAM_ID,
///                            PORTAL_TUNNEL_PROVISIONING_PROFILE with the
///                            tunnel)
///   zig build ios-kit        zig-out/ios-kit: the unsigned Portal.app, the
///                            signer for aarch64-macos and README.txt, to
///                            build on any host (iOS SDK copied from the
///                            Mac) and sign + install on a Mac without Zig
fn addIos(b: *std.Build, optimize: std.builtin.OptimizeMode, test_step: *std.Build.Step) void {
    const bundle_id = b.option([]const u8, "ios-bundle-id", "iPhone app bundle id (default local.portal.Portal; must match the provisioning profile)") orelse "local.portal.Portal";
    const tunnel = b.option(bool, "ios-tunnel", "iPhone app: control the per-app WireGuard tunnel extension (needs the Network Extension entitlement, paid account)") orelse false;
    const env = &b.graph.environ_map;
    const moltenvk = b.option([]const u8, "moltenvk", "iOS MoltenVK: path to libMoltenVK.dylib or MoltenVK.framework for iOS arm64 (env MOLTENVK_PATH)") orelse env.get("MOLTENVK_PATH");
    const model_path = b.option([]const u8, "ios-model", "iPhone app: a local copy of the pinned base model (src/speech/model_pin.zig) to bundle instead of downloading it");
    const sdk = b.option([]const u8, "ios-sdk", "iPhoneOS SDK path (env IOS_SDK; default: xcrun --sdk iphoneos --show-sdk-path on a Mac)") orelse env.get("IOS_SDK") orelse if (b.graph.host.result.os.tag == .macos)
        std.mem.trim(u8, b.run(&.{ "xcrun", "--sdk", "iphoneos", "--show-sdk-path" }), " \r\n")
    else
        null;

    const t = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64,
        .os_tag = .ios,
        // iOS 17: the Core ML programs of the dictation engine (stt) target
        // it (docs/ios-native.md).
        .os_version_min = .{ .semver = .{ .major = ios_min_major, .minor = 0, .patch = 0 } },
    });

    // Compile check (object): the whole iPhone app and its tunnel extension
    // without the SDK.
    const check = b.addObject(.{ .name = "portal-ios-check", .root_module = iosModule(b, t, .Debug, bundle_id, tunnel) });
    const ext_check = b.addObject(.{ .name = "portal-tunnel-check", .root_module = tunnelExtModule(b, t, .Debug) });
    const ios_check = b.step("ios-check", "Compile the iPhone app and its tunnel extension for aarch64-ios (objects only, no SDK needed)");
    ios_check.dependOn(&check.step);
    ios_check.dependOn(&ext_check.step);
    test_step.dependOn(ios_check);
    // The extension's backend logic (config -> network settings) on this host.
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("client/src/ios/tunnel_ext/backend.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
        .imports = &.{.{ .name = "WireGuard", .module = wireguardModule(b, b.graph.host, .Debug) }},
    }) })).step);

    // The background tunnel's decisions and status line (tunnel.zig's pure
    // part) on this host.
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("client/src/ios/tunnel_note.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
    }) })).step);

    // The app icon (drawn by src/tools/icon_art.zig) and the tools' own tests.
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
    // The same signer for the Mac kit: pure Zig, links against Zig's own
    // libSystem stubs (no macOS SDK) and comes out ad-hoc signed (arm64
    // macOS). `zig build test` links it so it cannot rot.
    // The model download (one pinned file) and the release check of the
    // built executables (stripped, no build-machine paths), with tests.
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = fetchTool(b).root_module })).step);
    const macho_tool = b.addExecutable(.{ .name = "machocheck", .root_module = b.createModule(.{
        .root_source_file = b.path("src/tools/machocheck.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
    }) });
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = macho_tool.root_module })).step);
    const mac_sign_tool = b.addExecutable(.{ .name = "portal-ios-sign", .root_module = b.createModule(.{
        .root_source_file = b.path("src/tools/ios_sign.zig"),
        .target = b.resolveTargetQuery(.{ .cpu_arch = .aarch64, .os_tag = .macos }),
        .optimize = .ReleaseSafe,
    }) });
    test_step.dependOn(&mac_sign_tool.step);

    const ios_step = b.step("ios", "Build zig-out/ios/Portal.app (Mac: iOS SDK + -Dmoltenvk=...)");
    const sign_step = b.step("ios-sign", "Sign zig-out/ios/Portal.app (env PORTAL_SIGN_IDENTITY, PORTAL_PROVISIONING_PROFILE, PORTAL_TEAM_ID, PORTAL_TUNNEL_PROVISIONING_PROFILE)");
    const kit_step = b.step("ios-kit", "Build zig-out/ios-kit (unsigned Portal.app + aarch64-macos signer + README.txt) to sign and install on a Mac without Zig (-Dios-sdk, -Dmoltenvk)");
    const sdk_path = sdk orelse {
        const fail = b.addFail("zig build ios / ios-kit needs the iPhoneOS SDK: run it on a Mac with Xcode, or pass -Dios-sdk=<path to iPhoneOS.sdk> / IOS_SDK (docs/ios-native.md, \"Build on another computer\")");
        ios_step.dependOn(&fail.step);
        sign_step.dependOn(&fail.step);
        kit_step.dependOn(&fail.step);
        return;
    };
    std.Io.Dir.cwd().access(b.graph.io, b.pathJoin(&.{ sdk_path, "usr/lib/libSystem.tbd" }), .{}) catch {
        const fail = b.addFail(b.fmt("no iPhoneOS SDK at {s} (no usr/lib/libSystem.tbd): -Dios-sdk must name the iPhoneOS.sdk folder", .{sdk_path}));
        ios_step.dependOn(&fail.step);
        sign_step.dependOn(&fail.step);
        kit_step.dependOn(&fail.step);
        return;
    };
    const mvk = moltenvk orelse {
        const fail = b.addFail("zig build ios / ios-kit needs MoltenVK for iOS: -Dmoltenvk=<.../MoltenVK.xcframework/ios-arm64/MoltenVK.framework or libMoltenVK.dylib> (or MOLTENVK_PATH); see docs/ios-native.md");
        ios_step.dependOn(&fail.step);
        sign_step.dependOn(&fail.step);
        kit_step.dependOn(&fail.step);
        return;
    };

    const mod = iosModule(b, t, optimize, bundle_id, tunnel);
    // A release build carries no debug info (machocheck below checks it,
    // and that no build-machine path is embedded).
    const release = optimize != .debug;
    if (release) mod.strip = true;
    addIosSdkPaths(b, mod, sdk_path);
    mod.addSystemIncludePath(.{ .cwd_relative = b.pathJoin(&.{ sdk_path, "usr/include" }) });
    for ([_][]const u8{ "UIKit", "QuartzCore", "Foundation", "CoreGraphics", "Metal", "Security", "AVFoundation", "LocalAuthentication" }) |fw|
        mod.linkFramework(fw, .{});
    if (tunnel) mod.linkFramework("NetworkExtension", .{});
    mod.linkSystemLibrary("objc", .{});
    // MoltenVK is opened from the bundle at run time (the Vulkan package's
    // loader); the rpath lets a framework build of MoltenVK find itself.
    mod.addRPathSpecial("@executable_path/Frameworks");
    const exe = b.addExecutable(.{ .name = "Portal", .root_module = mod });
    exe.headerpad_max_install_names = true;
    // The packet tunnel extension (with -Dios-tunnel): Foundation +
    // NetworkExtension, no UIKit window.
    const ext_exe: ?*std.Build.Step.Compile = if (tunnel) blk: {
        const em = tunnelExtModule(b, t, optimize);
        if (release) em.strip = true;
        addIosSdkPaths(b, em, sdk_path);
        em.linkFramework("Foundation", .{});
        em.linkFramework("NetworkExtension", .{});
        em.linkSystemLibrary("objc", .{});
        break :blk b.addExecutable(.{ .name = "PortalTunnel", .root_module = em });
    } else null;
    // This Zig requires darwin_sdk_dir for Darwin targets; it is also the
    // linker's sysroot (absolute install names of re-exported libraries).
    const libc_txt = b.addWriteFiles().add("libc-ios.txt", b.fmt(
        \\include_dir={s}/usr/include
        \\sys_include_dir={s}/usr/include
        \\crt_dir={s}/usr/lib
        \\msvc_lib_dir=
        \\kernel32_lib_dir=
        \\gcc_dir=
        \\darwin_sdk_dir={s}
        \\
    , .{ sdk_path, sdk_path, sdk_path, sdk_path }));
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
    // The dictation model (speech.zig `model_name`) and the notices of what
    // the app bundles (docs/ios-licenses.txt).
    const model_file: std.Build.LazyPath = if (model_path) |p| .{ .cwd_relative = p } else pinnedModel(b);
    _ = app.addCopyFile(model_file, "Portal.app/stt/" ++ model_pin.file_name);
    _ = app.addCopyFile(b.path("docs/ios-licenses.txt"), "Portal.app/Licenses.txt");
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
    // Release: the executables are stripped and embed no build paths.
    const macho_check: ?*std.Build.Step.Run = if (release) blk: {
        const r = b.addRunArtifact(macho_tool);
        r.addFileArg(exe.getEmittedBin());
        if (ext_exe) |e| r.addFileArg(e.getEmittedBin());
        install.step.dependOn(&r.step);
        break :blk r;
    } else null;

    // The Mac kit: build here, sign + install on a Mac that has Xcode but
    // no Zig (docs/ios-native.md, "Build on another computer").
    const kit_app = b.addInstallDirectory(.{ .source_dir = app.getDirectory().path(b, "Portal.app"), .install_dir = .prefix, .install_subdir = "ios-kit/Portal.app" });
    const kit_sign = b.addInstallArtifact(mac_sign_tool, .{ .dest_dir = .{ .override = .{ .custom = "ios-kit" } } });
    const readme = std.mem.replaceOwned(u8, b.allocator, @embedFile("docs/ios-kit-readme.txt"), "@BUNDLE_ID@", bundle_id) catch @panic("OOM");
    const kit_readme = b.addInstallFile(b.addWriteFiles().add("README.txt", b.fmt(
        "Portal for iPhone: bundle id {s}, tunnel extension {s}, {t}.\n\n{s}",
        .{ bundle_id, if (tunnel) "included (PORTAL_TUNNEL_PROVISIONING_PROFILE needed)" else "not included", optimize, readme },
    )), "ios-kit/README.txt");
    kit_step.dependOn(&kit_app.step);
    if (macho_check) |r| kit_step.dependOn(&r.step);
    kit_step.dependOn(&kit_sign.step);
    kit_step.dependOn(&kit_readme.step);

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

/// The iPhoneOS SDK's link stubs (.tbd) for `m`. Besides the public
/// frameworks and usr/lib: PrivateFrameworks and usr/lib/system, where
/// the linker finds libraries the public stubs re-export (UIKit ->
/// UIKitCore, libSystem -> libsystem_*) by name first, before it joins
/// their absolute install names to the sysroot (the libc file's
/// darwin_sdk_dir), so a Windows host does not depend on that join.
fn addIosSdkPaths(b: *std.Build, m: *std.Build.Module, sdk_path: []const u8) void {
    m.addSystemFrameworkPath(.{ .cwd_relative = b.pathJoin(&.{ sdk_path, "System/Library/Frameworks" }) });
    m.addSystemFrameworkPath(.{ .cwd_relative = b.pathJoin(&.{ sdk_path, "System/Library/PrivateFrameworks" }) });
    m.addLibraryPath(.{ .cwd_relative = b.pathJoin(&.{ sdk_path, "usr/lib" }) });
    m.addLibraryPath(.{ .cwd_relative = b.pathJoin(&.{ sdk_path, "usr/lib/system" }) });
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
            // Dictation on the phone (client/src/ios/speech.zig): stt with
            // its Core ML backend (on for Apple targets), and the speech
            // module's headset-first microphone rule (src/speech/mics.zig).
            .{ .name = "stt", .module = iosStt(b, t, optimize) },
            .{ .name = "speech", .module = speechModule(b, t, optimize) },
        },
    });
}

/// stt for the iPhone app, sharing ONE Objective-C binding with the
/// window: stt's Core ML backend (TranslateCoreML) and the Renderer's iOS
/// backend (IosObjC) both build on the MacOS package, but with different
/// optimize modes (stt is always fast), which would make two "MacOS"
/// modules over the same files in one compilation. The Core ML module
/// gets the Renderer's MacOS instead.
fn iosStt(b: *std.Build, t: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const stt = b.dependency("stt", .{ .target = t, .optimize = .fast }).module("stt");
    const mac = rendererDep(b, t, optimize).builder.dependency("MacOS", .{ .target = t, .optimize = optimize }).module("MacOS");
    if (stt.import_table.get("coreml")) |cm| cm.addImport("MacOS", mac);
    return stt;
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
            .{ .name = "WireGuard", .module = wireguardModule(b, t, optimize) },
            .{ .name = "IosObjC", .module = rendererDep(b, t, optimize).module("IosObjC") },
            // The Keychain code the app uses, to read the tunnel key the
            // app stored (tunnel_ext/keyref.zig).
            .{ .name = "credstore", .module = b.createModule(.{ .root_source_file = b.path("client/src/credstore.zig"), .target = t, .optimize = optimize, .link_libc = true }) },
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
        \\    <key>MinimumOSVersion</key><string>{d}.0</string>
        \\    <key>NSExtension</key>
        \\    <dict>
        \\        <key>NSExtensionPointIdentifier</key><string>com.apple.networkextension.packet-tunnel</string>
        \\        <key>NSExtensionPrincipalClass</key><string>PortalPacketTunnelProvider</string>
        \\    </dict>
        \\</dict>
        \\</plist>
    , .{ bundle_id, ios_min_major });
}

/// Info.plist (configuration text, not code): what iOS reads before the
/// app runs. Scene-based (the Renderer's Window backend provides the scene
/// delegate), launch screen without a storyboard, camera and Face ID
/// usage strings, local-network note for the desk on the LAN, the
/// microphone for dictation.
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
        \\    <key>MinimumOSVersion</key><string>{d}.0</string>
        \\    <key>LSRequiresIPhoneOS</key><true/>
        \\    <key>UIDeviceFamily</key><array><integer>1</integer></array>
        \\    <key>UIRequiredDeviceCapabilities</key><array><string>arm64</string><string>metal</string></array>
        \\    <key>UILaunchScreen</key><dict/>
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
        \\    <key>NSMicrophoneUsageDescription</key><string>Portal records while you dictate. It transcribes on this iPhone; with learning on, your corrected samples go to your own desktop through Portal's private tunnel.</string>
        \\    <key>NSLocalNetworkUsageDescription</key><string>Portal connects to the Portal running on your desktop.</string>
        \\</dict>
        \\</plist>
        \\
    , .{ bundle_id, ios_min_major });
}

// ---- speech (src/speech; docs/audio-design.md, docs/stt-sync-contract.md) ----

/// "speech" (src/speech/root.zig): WASAPI capture and the stt engines.
/// stt.Home is linked only for x86_64 Windows (the desktop, NVIDIA GPU);
/// other targets get the capture side and the stt-local client. stt is
/// always built ReleaseFast (inference is ~100x slower in Debug). "Audio"
/// is the instance stt itself uses (one module per compilation).
fn speechModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return speechModuleWith(b, target, optimize, null);
}

/// The speech module; its tests get `fake_stt_local` (the fake program
/// the laptop engine's tests run; "" elsewhere).
fn speechModuleWith(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, fake_stt_local: ?std.Build.LazyPath) *std.Build.Module {
    const home = target.result.os.tag == .windows and target.result.cpu.arch == .x86_64;
    const stt_dep = b.dependency("stt", .{ .target = target, .optimize = .fast });
    const opts = b.addOptions();
    opts.addOption(bool, "home", home);
    // Tests read its testdata and models (skipped when missing).
    opts.addOptionPathUntracked("stt_dir", stt_dep.path("."));
    if (fake_stt_local) |p| opts.addOptionPath("fake_stt_local", p) else opts.addOption([]const u8, "fake_stt_local", "");
    const m = b.createModule(.{
        .root_source_file = b.path("src/speech/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    m.addOptions("speech_options", opts);
    m.addImport("Audio", stt_dep.builder.dependency("Audio", .{ .target = target }).module("Audio"));
    if (home) m.addImport("stt", stt_dep.module("stt"));
    // The PE header check of a delivered stt-local (local.fitsThisMachine).
    m.addAnonymousImport("pecheck", .{ .root_source_file = b.path("src/tools/pecheck.zig"), .target = target, .optimize = optimize });
    return m;
}

/// `zig build voice-packages`: the laptop's speech packages as folders,
/// each exactly what the desk publishes once (docs/stt-sync-contract.md,
/// "Publishing the laptop's engine"):
///   zig-out/voice/stt-local/stt-local.exe      aarch64 Windows (the
///       Snapdragon X), whatever -Dtarget says: the only build that fetches
///       the QAIRT SDK (or -Dsdk / QNN_SDK_ROOT)
///   zig-out/voice/stt-model/<model_pin.file_name>   the pinned base model,
///       the desk's own file (downloaded and checked like the iPhone's)
/// `zig build release` runs it after the desk's release and publishes both
/// with `portalctl voice-publish`, each only when its content changed, so
/// a rebuild of the same engine never asks the laptop to approve a new
/// version (src/tools/release.zig; a failure here never fails the release).
fn addVoicePackages(b: *std.Build, sdk: ?[]const u8) void {
    const step = b.step("voice-packages", "Build the laptop's stt-local (aarch64 Windows) and the pinned model into zig-out/voice (zig build release publishes them)");
    const t = b.resolveTargetQuery(.{ .cpu_arch = .aarch64, .os_tag = .windows });
    const exe = b.dependency("stt", .{ .target = t, .optimize = .fast, .sdk = sdk }).artifact("stt-local");
    step.dependOn(&b.addInstallArtifact(exe, .{
        .dest_dir = .{ .override = .{ .custom = "voice/stt-local" } },
        .pdb_dir = .disabled,
        .implib_dir = .disabled,
    }).step);
    step.dependOn(&b.addInstallFileWithDir(pinnedModel(b), .{ .custom = "voice/stt-model" }, model_pin.file_name).step);
}

/// The pinned base model (src/speech/model_pin.zig), downloaded once by
/// src/tools/fetch_file.zig and kept only if its size and SHA-256 match;
/// the build cache keeps it. Only steps that need the file run it.
fn pinnedModel(b: *std.Build) std.Build.LazyPath {
    const f = b.addRunArtifact(fetchTool(b));
    f.addArgs(&.{ model_pin.url, model_pin.sha256_hex, b.fmt("{d}", .{model_pin.size}) });
    return f.addOutputFileArg(model_pin.file_name);
}

var fetch_tool_exe: ?*std.Build.Step.Compile = null;

fn fetchTool(b: *std.Build) *std.Build.Step.Compile {
    if (fetch_tool_exe) |e| return e;
    fetch_tool_exe = b.addExecutable(.{ .name = "fetch-file", .root_module = b.createModule(.{
        .root_source_file = b.path("src/tools/fetch_file.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
    }) });
    return fetch_tool_exe.?;
}
