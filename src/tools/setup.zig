//! portal-setup.exe: installs Portal for this Windows user, with no typed
//! commands and no administrator (except the desk's one firewall prompt).
//!
//!   portal-setup.exe               the wizard: desk or device, install or
//!                                  upgrade in place, then start Portal
//!   portal-setup.exe --uninstall   remove Portal (Settings > Apps runs this)
//!   portal-setup.exe --version
//!
//! Each build carries one architecture's Portal (the payload module, made
//! by `zig build installer`): portal-setup-x64.exe and
//! portal-setup-arm64.exe. A mismatched one refuses to install.
//!
//! What it does (setup_lib.zig has the layout and the rules, all tested):
//!   * the program as a release in %LOCALAPPDATA%\Portal\releases with the
//!     launchers in ...\Portal\bin: the folder `zig build release` uses, so
//!     release, rollback and mark-good keep working (setup_install.zig);
//!   * a Start-menu shortcut (the window on the desk, `portal connect` on a
//!     device), bin on the user PATH (HKCU\Environment, then a
//!     WM_SETTINGCHANGE broadcast), the Settings > Apps entry (HKCU), and
//!     install.txt (the role, for the uninstaller);
//!   * desk: the firewall rule through `portalctl firewall add`, which asks
//!     for an administrator ONCE (src/firewall.zig); declined, it says how
//!     to add it later. Then the agent hooks (`portalctl hooks install`),
//!     then Portal starts;
//!   * device: Portal starts on its pairing screen (`portal connect`).
//! Re-running upgrades in place and keeps Portal's data. Everything blocks
//! on the user or on a child process; nothing polls.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const lib = @import("releases_lib.zig");
const ops = @import("release_ops.zig");
const setup_lib = @import("setup_lib.zig");
const inst = @import("setup_install.zig");
const sw = @import("setup_win.zig");
const firewall = @import("firewall");
const payload = @import("payload");
const options = @import("setup_options");
const w = @import("win32");

const Role = setup_lib.Role;

/// A role's button id in the dialogs (100 + its index).
fn roleId(r: Role) i32 {
    return 100 + @as(i32, @intFromEnum(r));
}

fn roleFrom(id: i32) ?Role {
    for (std.enums.values(Role)) |r| if (roleId(r) == id) return r;
    return null;
}

const my_arch: setup_lib.Arch = switch (builtin.cpu.arch) {
    .x86_64 => .x86_64,
    .aarch64 => .aarch64,
    else => .other,
};

const exes = toFiles(payload.exes);
const launchers = toFiles(payload.launchers);

fn toFiles(comptime list: anytype) [list.len]inst.File {
    var out: [list.len]inst.File = undefined;
    for (list, 0..) |f, i| out[i] = .{ .name = f[0], .data = f[1] };
    return out;
}

pub fn main(init: std.process.Init) !void {
    if (builtin.os.tag != .windows) @compileError("portal-setup is the Windows installer");
    const gpa = init.gpa;
    var args_list: std.ArrayList([]const u8) = .empty;
    defer args_list.deinit(gpa);
    var it: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |a| try args_list.append(gpa, a);
    const args = args_list.items;

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const s: Setup = .{
        .gpa = gpa,
        .arena = arena_state.allocator(),
        .io = init.io,
        .env = init.environ_map,
    };
    sw.coInit();

    if (args.len > 0 and std.mem.eql(u8, args[0], "--version")) {
        _ = sw.show(gpa, .{ .heading = "Portal setup", .body = s.fmt("Version {s} ({s}), built with Zig {s}.", .{ options.version, @tagName(my_arch), builtin.zig_version_string }) });
        return;
    }
    if (args.len > 0 and std.mem.eql(u8, args[0], "--uninstall")) {
        var wait_pid: ?u32 = null;
        if (args.len >= 3 and std.mem.eql(u8, args[1], "--wait-pid")) wait_pid = std.fmt.parseInt(u32, args[2], 10) catch null;
        return s.uninstall(wait_pid);
    }
    if (args.len > 0) {
        _ = sw.show(gpa, .{ .heading = "Unknown option", .icon = .err, .body = "portal-setup.exe installs Portal (no options), or removes it (--uninstall)." });
        w.ExitProcess(2);
    }
    return s.installWizard();
}

const Setup = struct {
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,

    fn fmt(s: Setup, comptime f: []const u8, a: anytype) []const u8 {
        return std.fmt.allocPrint(s.arena, f, a) catch "";
    }

    fn fail(s: Setup, heading: []const u8, body: []const u8) noreturn {
        _ = sw.show(s.gpa, .{ .heading = heading, .body = body, .icon = .err });
        w.ExitProcess(1);
    }

    fn layout(s: Setup) setup_lib.Layout {
        const lad = s.env.get("LOCALAPPDATA") orelse "";
        const ad = s.env.get("APPDATA") orelse "";
        return setup_lib.Layout.init(s.arena, lad, ad) catch
            s.fail("Portal cannot be installed", "LOCALAPPDATA or APPDATA is not set for this user.");
    }

    fn ctx(s: Setup, l: setup_lib.Layout) ops.Ctx {
        return .{ .gpa = s.gpa, .io = s.io, .env = s.env, .releases = l.releases, .quiet = true };
    }

    fn previous(s: Setup, l: setup_lib.Layout) ?setup_lib.Info {
        const text = std.Io.Dir.cwd().readFileAlloc(s.io, l.info, s.arena, .limited(4096)) catch return null;
        return setup_lib.parseInfo(text);
    }

    /// The current release's portalctl.exe (the real program, not the
    /// launcher: the firewall step runs it elevated).
    fn releaseCtl(s: Setup, c: ops.Ctx) ?[]const u8 {
        const id = ops.readPointer(c, lib.current_file) orelse return null;
        defer s.gpa.free(id);
        const p = std.fs.path.join(s.arena, &.{ c.releases, id, "portalctl.exe" }) catch return null;
        return if (ops.isFile(s.io, p)) p else null;
    }

    fn home(s: Setup) []const u8 {
        return s.env.get("USERPROFILE") orelse "C:\\";
    }

    // ------------------------------------------------------------- install

    fn installWizard(s: Setup) void {
        var mb: [400]u8 = undefined;
        if (setup_lib.archMismatch(&mb, my_arch, sw.nativeArch())) |m| s.fail("This installer does not fit this PC", m);
        const l = s.layout();
        const before = s.previous(l);
        const upgrading = before != null;

        // The question; on an upgrade the role it had is the default.
        var links: [setup_lib.modes.len]sw.Button = undefined;
        var n: usize = 0;
        for (setup_lib.modes) |m| if (m.windows) {
            links[n] = .{ .id = roleId(m.role), .text = m.choice };
            n += 1;
        };
        const answer = sw.show(s.gpa, .{
            .heading = if (upgrading) s.fmt("Upgrade Portal to {s}", .{options.version}) else s.fmt("Install Portal {s}", .{options.version}),
            .body = if (upgrading)
                "Portal is installed for you already. Your devices, keys and settings stay as they are. What is this PC?"
            else
                "Portal is installed for you only, in your own folders: no administrator needed (the desk asks once, for its firewall rule). What is this PC?",
            .links = links[0..n],
            .cancel = true,
            .default = if (before) |b| roleId(b.role) else 0,
            .footer = s.fmt("This installer is for {s} PCs.", .{setup_lib.archLabel(my_arch)}),
        });
        const role = roleFrom(answer.button) orelse return; // cancelled

        const c = s.ctx(l);
        std.Io.Dir.cwd().createDirPath(s.io, l.releases) catch |err|
            s.fail("Portal could not be installed", s.fmt("Cannot create {s}: {t}.", .{ l.releases, err }));
        ops.lock(c) catch |err| switch (err) {
            error.Busy => s.fail("Portal is being updated", "A Portal release (zig build release, rollback or mark-good) or another installer is running. Let it finish, then run this installer again. Nothing was changed."),
            else => s.fail("Portal could not be installed", s.fmt("Cannot lock {s}: {t}. Nothing was changed.", .{ l.releases, err })),
        };

        var now: ops.Now = .{};
        now.get();
        const r = inst.install(c, .{
            .exes = &exes,
            .launchers = &launchers,
            .version = options.version,
            .commit = options.commit,
            .zig_version = builtin.zig_version_string,
        }, .{ .stamp = now.stamp, .iso = now.iso }) catch |err|
            s.fail("Portal could not be installed", s.fmt("Storing the program in {s} failed: {t}. Your current Portal (if any) is unchanged.", .{ l.releases, err }));
        defer s.gpa.free(r.id);

        var notes: std.ArrayList(u8) = .empty;
        const note = struct {
            fn f(st: Setup, list: *std.ArrayList(u8), comptime fm: []const u8, a: anytype) void {
                list.print(st.arena, "\u{2022} " ++ fm ++ "\n", a) catch {};
            }
        }.f;
        note(s, &notes, "{s} in {s}", .{ if (r.reused) "Portal was already installed" else if (upgrading) "Portal upgraded" else "Portal installed", l.root });
        if (r.launcher_failures > 0) note(s, &notes, "{d} launcher(s) in use could not be replaced: close Portal and run this again", .{r.launcher_failures});

        // The uninstaller, for Settings > Apps.
        var self_buf: [1024]u8 = undefined;
        if (firewall.selfExe(&self_buf)) |self| {
            if (!std.ascii.eqlIgnoreCase(self, l.setup_exe)) {
                std.Io.Dir.copyFileAbsolute(self, l.setup_exe, s.io, .{}) catch |err|
                    note(s, &notes, "The uninstaller could not be copied ({t})", .{err});
            }
        }

        // Start menu.
        const portal = l.portalExe(s.arena) catch "";
        std.Io.Dir.cwd().createDirPath(s.io, l.programs) catch {};
        sw.writeShortcut(s.gpa, l.shortcut, portal, setup_lib.shortcutArgs(role), setup_lib.shortcutDescription(role), s.home()) catch |err|
            note(s, &notes, "The Start-menu shortcut could not be made ({t})", .{err});

        // PATH.
        const reg = sw.registry();
        const lad = s.env.get("LOCALAPPDATA") orelse "";
        if (setup_lib.addUserPath(s.gpa, reg, l.bin, lad)) |changed| {
            if (changed) {
                sw.broadcastEnvironment();
                note(s, &notes, "`portal` and `portalctl` work in new terminals", .{});
            }
        } else |err| note(s, &notes, "{s} could not be added to your PATH ({t})", .{ l.bin, err });

        // Settings > Apps, and the role for the uninstaller.
        var size: u64 = 0;
        for (exes) |f| size += f.data.len;
        for (launchers) |f| size += f.data.len * 2;
        if (setup_lib.uninstallEntry(s.arena, .{ .layout = l, .version = options.version, .role = role, .size_kib = @intCast(@min(size / 1024, std.math.maxInt(u32))), .date = now.stamp[0..8] })) |vals| {
            for (vals) |v| reg.set(setup_lib.uninstall_key, v.name, v.value) catch |err| {
                note(s, &notes, "The Settings > Apps entry could not be written ({t})", .{err});
                break;
            };
        } else |_| {}
        if (setup_lib.formatInfo(s.arena, .{ .role = role, .version = options.version })) |t| {
            std.Io.Dir.cwd().writeFile(s.io, .{ .sub_path = l.info, .data = t }) catch {};
        } else |_| {}

        var start_args: []const u8 = setup_lib.shortcutArgs(role);
        if (role == .desk) {
            s.deskSteps(c, &notes);
        } else {
            note(s, &notes, "Next: Portal opens on its pairing screen. Pair this device at the desk (Pair a device…, Ctrl+Shift+P)", .{});
            start_args = "connect";
        }

        const done = sw.show(s.gpa, .{
            .heading = if (upgrading) "Portal is upgraded" else "Portal is installed",
            .body = notes.items,
            .links = &.{
                .{ .id = 100, .text = if (role == .desk) "Start Portal\nThe first start asks what to run in it" else "Start Portal\nIt opens on this device's pairing screen" },
                .{ .id = 101, .text = "Close" },
            },
            .default = 100,
            .footer = "Remove Portal any time in Settings > Apps.",
        });
        if (done.button == 100) sw.startDetached(s.gpa, portal, start_args, s.home()) catch |err| {
            _ = sw.show(s.gpa, .{ .heading = "Portal could not be started", .icon = .err, .body = s.fmt("{s}: {t}", .{ portal, err }) });
        };
    }

    /// The desk's extra steps: the firewall rule (one administrator
    /// prompt, through portalctl) and the agent hooks.
    fn deskSteps(s: Setup, c: ops.Ctx, notes: *std.ArrayList(u8)) void {
        const ctl = s.releaseCtl(c) orelse return;
        const fw = sw.show(s.gpa, .{
            .heading = "Let devices reach this desk through Windows Firewall",
            .body = "Portal's tunnel needs one inbound rule: UDP on its port (51820 unless you change it), every network profile. Windows asks for an administrator once.",
            .icon = .shield,
            .links = &.{
                .{ .id = 100, .text = "Add the firewall rule\nOne administrator prompt" },
                .{ .id = 101, .text = "Not now\nSettings has a Firewall button for later" },
            },
            .default = 100,
        });
        var mb: [300]u8 = undefined;
        if (fw.button == 100) {
            const code = sw.runHidden(s.io, &.{ ctl, "firewall", "add" }) catch 255;
            switch (code) {
                firewall.exit.ok => notes.print(s.arena, "\u{2022} Windows Firewall allows the tunnel's UDP port\n", .{}) catch {},
                firewall.exit.declined => notes.print(s.arena, "\u{2022} The firewall rule was not added (the prompt was declined). Add it later in Settings (Windows Firewall), or in an administrator PowerShell:\n   {s}\n", .{firewall.manualAdd(&mb, 51820)}) catch {},
                else => notes.print(s.arena, "\u{2022} The firewall rule could not be added (exit code {d}). Settings (Windows Firewall) tries again\n", .{code}) catch {},
            }
        } else notes.print(s.arena, "\u{2022} No firewall rule yet: Settings (Windows Firewall) adds it\n", .{}) catch {};

        const bin_ctl = std.fs.path.join(s.arena, &.{ std.fs.path.dirname(c.releases).?, "bin", "portalctl.exe" }) catch return;
        const hooks = sw.runHidden(s.io, &.{ bin_ctl, "hooks", "install" }) catch 255;
        notes.print(s.arena, "\u{2022} {s}\n", .{if (hooks == 0) "Claude Code integration (agent hooks) installed" else "The agent hooks could not be installed: Settings, Claude Code integration"}) catch {};
        notes.print(s.arena, "\u{2022} Next: in Settings, where devices reach this desk (your router's public address or a dynamic-DNS name); Settings walks you through the router\n", .{}) catch {};
    }

    // ----------------------------------------------------------- uninstall

    fn uninstall(s: Setup, wait_pid: ?u32) void {
        const l = s.layout();
        // A running exe cannot delete itself: the copy in the install
        // folder hands over to a copy in %TEMP% and ends.
        var self_buf: [1024]u8 = undefined;
        const self = firewall.selfExe(&self_buf) orelse "";
        if (wait_pid == null and std.ascii.eqlIgnoreCase(self, l.setup_exe)) {
            const tmp = s.env.get("TEMP") orelse s.fail("Portal could not be removed", "TEMP is not set.");
            const copy = std.fs.path.join(s.arena, &.{ tmp, s.fmt("portal-uninstall-{d}.exe", .{w.GetCurrentProcessId()}) }) catch return;
            std.Io.Dir.copyFileAbsolute(self, copy, s.io, .{}) catch |err|
                s.fail("Portal could not be removed", s.fmt("Cannot copy the uninstaller to {s}: {t}.", .{ copy, err }));
            sw.startDetached(s.gpa, copy, s.fmt("--uninstall --wait-pid {d}", .{w.GetCurrentProcessId()}), tmp) catch |err|
                s.fail("Portal could not be removed", s.fmt("Cannot start {s}: {t}.", .{ copy, err }));
            return;
        }
        if (wait_pid) |p| sw.waitForPid(p);

        const role: Role = if (s.previous(l)) |i| i.role else .device;
        const sure = sw.show(s.gpa, .{
            .heading = "Remove Portal?",
            .body = s.fmt("Portal ({t}) is removed from {s}: the program, the Start-menu shortcut, the PATH entry and the Settings > Apps entry.{s}", .{ role, l.root, if (role == .desk) " On the desk also its Windows Firewall rule (one administrator prompt)." else "" }),
            .links = &.{
                .{ .id = 100, .text = "Remove Portal" },
                .{ .id = 101, .text = "Keep it" },
            },
            .default = 101,
            .icon = .warn,
        });
        if (sure.button != 100) return;
        const data = sw.show(s.gpa, .{
            .heading = "Keep your Portal data?",
            .body = s.fmt("Your data: paired devices, keys, settings and logs in {s}, and {s}. Kept, a new install picks it up again.", .{ l.root, l.roaming }),
            .links = &.{
                .{ .id = 100, .text = "Keep my data (recommended)" },
                .{ .id = 101, .text = "Delete my data too\nPaired devices must be paired again" },
            },
            .default = 100,
        });
        const delete_data = data.button == 101;

        const c = s.ctx(l);
        var notes: std.ArrayList(u8) = .empty;
        var mb: [300]u8 = undefined;
        if (s.releaseCtl(c)) |ctl| {
            if (role == .desk) {
                const code = sw.runHidden(s.io, &.{ ctl, "firewall", "remove" }) catch 255;
                if (code != firewall.exit.ok) notes.print(s.arena, "\u{2022} The firewall rule was not removed. In an administrator PowerShell:\n   {s}\n", .{firewall.manual_remove}) catch {};
                const hooks = sw.show(s.gpa, .{
                    .heading = "Remove Portal's hooks from Claude Code too?",
                    .body = "They run Portal's portalctl, which is being removed. Everything else in Claude Code's settings.json stays as it is.",
                    .links = &.{ .{ .id = 100, .text = "Remove the hooks (recommended)" }, .{ .id = 101, .text = "Leave them" } },
                    .default = 100,
                });
                if (hooks.button == 100) {
                    const hc = sw.runHidden(s.io, &.{ ctl, "hooks", "uninstall" }) catch 255;
                    if (hc != 0) notes.print(s.arena, "\u{2022} The agent hooks were not removed (exit code {d})\n", .{hc}) catch {};
                }
            }
            if (delete_data and role == .device) _ = sw.runHidden(s.io, &.{ ctl, "sync-device", "--drop-key" }) catch {};
        }
        _ = &mb;

        // A running Portal holds its exe: ask to close it first.
        while (s.portalRunning(c)) {
            const again = sw.show(s.gpa, .{
                .heading = "Close Portal first",
                .body = "Portal (or portal connect) is still running. Close its window, then choose Try again.",
                .links = &.{ .{ .id = 100, .text = "Try again" }, .{ .id = 101, .text = "Cancel" } },
                .default = 100,
                .icon = .warn,
            });
            if (again.button != 100) return;
        }

        const rm = setup_lib.removal(s.arena, l, delete_data) catch return;
        for (rm.files) |f| std.Io.Dir.cwd().deleteFile(s.io, f) catch |err| switch (err) {
            error.FileNotFound => {},
            else => notes.print(s.arena, "\u{2022} Not removed: {s} ({t})\n", .{ f, err }) catch {},
        };
        for (rm.dirs) |d| std.Io.Dir.cwd().deleteTree(s.io, d) catch |err|
            notes.print(s.arena, "\u{2022} Not fully removed: {s} ({t})\n", .{ d, err }) catch {};
        const reg = sw.registry();
        if (setup_lib.removeUserPath(s.gpa, reg, l.bin, s.env.get("LOCALAPPDATA") orelse "")) |changed| {
            if (changed) sw.broadcastEnvironment();
        } else |_| {}
        reg.deleteKey(setup_lib.uninstall_key) catch {};
        notes.print(s.arena, "\u{2022} {s}\n", .{if (delete_data) "Your Portal data was deleted" else s.fmt("Your data is kept in {s}", .{l.root})}) catch {};
        _ = sw.show(s.gpa, .{ .heading = "Portal is removed", .body = notes.items });
    }

    /// Portal runs: the current release's portal.exe or the launcher in
    /// bin is executing (Windows refuses write access to a running image).
    fn portalRunning(s: Setup, c: ops.Ctx) bool {
        const id = ops.readPointer(c, lib.current_file) orelse return false;
        defer s.gpa.free(id);
        const exe = ops.releaseExe(c, id) catch return false;
        defer s.gpa.free(exe);
        const bin = lib.launcherBinDir(s.gpa, c.releases) catch return false;
        defer s.gpa.free(bin);
        const launcher = std.fs.path.join(s.gpa, &.{ bin, "portal.exe" }) catch return false;
        defer s.gpa.free(launcher);
        return executing(s.gpa, exe) or executing(s.gpa, launcher);
    }

    fn executing(gpa: Allocator, exe: []const u8) bool {
        const p_w = std.unicode.wtf8ToWtf16LeAllocZ(gpa, exe) catch return false;
        defer gpa.free(p_w);
        const h = w.validHandle(w.CreateFileW(p_w.ptr, w.GENERIC_WRITE, w.FILE_SHARE_READ | w.FILE_SHARE_WRITE | w.FILE_SHARE_DELETE, null, w.OPEN_EXISTING, 0, null)) orelse
            return w.GetLastError() == 32; // ERROR_SHARING_VIOLATION
        _ = w.CloseHandle(h);
        return false;
    }
};

test {
    _ = setup_lib;
    _ = inst;
    _ = ops;
}
