//! portal-setup's pure logic (no I/O, all unit tested): where an install
//! lives, the user PATH edit (on a registry abstraction), the Apps-list
//! (uninstall) entry, what an uninstall removes, install.txt, and the
//! architecture check.
//!
//! The layout is the one `zig build release` uses (releases_lib.zig's
//! releasesRoot and launcherBinDir), so release, rollback and mark-good
//! keep working on an installed Portal:
//!
//!   %LOCALAPPDATA%\Portal\
//!     releases\<id>\ portal.exe portalctl.exe portal-show.exe BUILD-INFO.txt
//!     releases\current.txt known-good.txt history.txt
//!     bin\           the launchers (on the user PATH)
//!     portal-setup.exe   the uninstaller (Settings > Apps runs it)
//!     install.txt        role = desk | device, version
//!     ...                Portal's data: settings, devices, keys, logs
//!   %APPDATA%\Portal\    a device's pinned CAs and settings (data)
//!   %APPDATA%\Microsoft\Windows\Start Menu\Programs\Portal.lnk

const std = @import("std");
const Allocator = std.mem.Allocator;
const lib = @import("releases_lib.zig");

pub const Role = enum {
    /// The hub: the window, the tunnel's listening side, the firewall rule,
    /// the agent hooks.
    desk,
    /// A laptop or Surface: `portal connect`.
    device,

    pub fn parse(s: []const u8) ?Role {
        return std.meta.stringToEnum(Role, std.mem.trim(u8, s, " \t\r\n"));
    }
};

/// The installers' one table of what a machine can be: the Windows
/// installer (portal-setup) and the macOS one (mac_setup.zig) both offer
/// the roles marked for them, with these texts. A Mac desk later is one
/// flag here (and its steps), nothing else.
pub const Mode = struct {
    role: Role,
    /// The choice as the installer shows it (a command link: "title\nline").
    choice: []const u8,
    windows: bool,
    macos: bool,
};

pub const modes = [_]Mode{
    .{ .role = .desk, .choice = "This PC is the desk\nThe hub: it runs the sessions, and every device pairs with it", .windows = true, .macos = false },
    .{ .role = .device, .choice = "This PC is a device\nA laptop or Surface that connects to the desk", .windows = true, .macos = true },
};

pub fn modeOf(role: Role) Mode {
    for (modes) |m| if (m.role == role) return m;
    unreachable;
}

/// %TEMP%\<this><16 hex>: the uninstaller's working copy (setup_win
/// freshTempDir).
pub const uninstall_dir_prefix = "portal-uninstall-";

/// Of the folder names in %TEMP%, the uninstall copies left behind (a copy
/// that could not delete itself): exactly the prefix and 16 hex digits.
pub fn isUninstallDir(name: []const u8) bool {
    if (!std.mem.startsWith(u8, name, uninstall_dir_prefix)) return false;
    const rest = name[uninstall_dir_prefix.len..];
    if (rest.len != 16) return false;
    for (rest) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

/// Agent CLI names searched on PATH before the desk installer offers the
/// hooks (it never creates the agent's settings on a PC without it).
pub const agent_exes = [_][]const u8{ "claude.exe", "claude.cmd" };

pub const app_name = "Portal";
pub const setup_exe_name = "portal-setup.exe";
pub const info_name = "install.txt";
pub const shortcut_name = "Portal.lnk";
/// HKCU\<this>: the entry in Settings > Apps.
pub const uninstall_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Portal";
pub const env_key = "Environment";

pub const Layout = struct {
    /// %LOCALAPPDATA%\Portal (program and data).
    root: []const u8,
    releases: []const u8,
    bin: []const u8,
    setup_exe: []const u8,
    info: []const u8,
    /// The Start menu's Programs folder and the shortcut in it.
    programs: []const u8,
    shortcut: []const u8,
    /// %APPDATA%\Portal (a device's data).
    roaming: []const u8,

    /// All strings allocated in `a` (an arena).
    pub fn init(a: Allocator, local_app_data: []const u8, app_data: []const u8) !Layout {
        if (local_app_data.len == 0 or app_data.len == 0) return error.NoAppData;
        const releases = try lib.releasesRoot(a, null, local_app_data);
        const root = std.fs.path.dirname(releases).?;
        const programs = try std.fs.path.join(a, &.{ app_data, "Microsoft", "Windows", "Start Menu", "Programs" });
        return .{
            .root = root,
            .releases = releases,
            .bin = try lib.launcherBinDir(a, releases),
            .setup_exe = try std.fs.path.join(a, &.{ root, setup_exe_name }),
            .info = try std.fs.path.join(a, &.{ root, info_name }),
            .programs = programs,
            .shortcut = try std.fs.path.join(a, &.{ programs, shortcut_name }),
            .roaming = try std.fs.path.join(a, &.{ app_data, app_name }),
        };
    }

    /// The launcher a shortcut, the uninstall entry's icon and the final
    /// "start Portal" use.
    pub fn portalExe(l: Layout, a: Allocator) ![]u8 {
        return std.fs.path.join(a, &.{ l.bin, "portal.exe" });
    }
};

// ------------------------------------------------------------- the shortcut

/// What the Start-menu shortcut runs: the window on the desk, the pairing
/// screen (`portal connect`) on a device.
pub fn shortcutArgs(role: Role) []const u8 {
    return switch (role) {
        .desk => "",
        .device => "connect",
    };
}

pub fn shortcutDescription(role: Role) []const u8 {
    return switch (role) {
        .desk => "Portal: share this desktop's sessions with your paired devices",
        .device => "Portal: connect to your desktop",
    };
}

// ---------------------------------------------------------------- registry

/// A registry value as portal-setup writes and reads it.
pub const Value = union(enum) {
    sz: []const u8,
    expand_sz: []const u8,
    dword: u32,

    pub fn text(v: Value) ?[]const u8 {
        return switch (v) {
            .sz, .expand_sz => |s| s,
            .dword => null,
        };
    }
};

/// HKEY_CURRENT_USER, as portal-setup needs it. The real one is in
/// setup_win.zig; the tests use FakeRegistry.
pub const Registry = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// The value (its text owned by `gpa`), or null if missing.
        get: *const fn (ctx: *anyopaque, gpa: Allocator, key: []const u8, name: []const u8) anyerror!?Value,
        /// Creates the key as needed.
        set: *const fn (ctx: *anyopaque, key: []const u8, name: []const u8, v: Value) anyerror!void,
        /// No error if missing.
        deleteValue: *const fn (ctx: *anyopaque, key: []const u8, name: []const u8) anyerror!void,
        /// The key and everything under it; no error if missing.
        deleteKey: *const fn (ctx: *anyopaque, key: []const u8) anyerror!void,
    };

    pub fn get(r: Registry, gpa: Allocator, key: []const u8, name: []const u8) !?Value {
        return r.vtable.get(r.ctx, gpa, key, name);
    }
    pub fn set(r: Registry, key: []const u8, name: []const u8, v: Value) !void {
        return r.vtable.set(r.ctx, key, name, v);
    }
    pub fn deleteValue(r: Registry, key: []const u8, name: []const u8) !void {
        return r.vtable.deleteValue(r.ctx, key, name);
    }
    pub fn deleteKey(r: Registry, key: []const u8) !void {
        return r.vtable.deleteKey(r.ctx, key);
    }
};

// -------------------------------------------------------------------- PATH

/// `entry` (one item of a PATH value) names `dir`: ASCII case is ignored,
/// so are surrounding quotes and spaces and trailing separators, and a
/// leading %LOCALAPPDATA% stands for `local_app_data`.
pub fn sameDir(entry: []const u8, dir: []const u8, local_app_data: []const u8) bool {
    var e = std.mem.trim(u8, entry, " \"");
    e = trimSeps(e);
    const d = trimSeps(dir);
    const var_name = "%LOCALAPPDATA%";
    if (std.ascii.startsWithIgnoreCase(e, var_name) and local_app_data.len > 0) {
        const rest = e[var_name.len..];
        const base = trimSeps(local_app_data);
        if (d.len != base.len + rest.len) return false;
        return std.ascii.eqlIgnoreCase(d[0..base.len], base) and std.ascii.eqlIgnoreCase(d[base.len..], rest);
    }
    return std.ascii.eqlIgnoreCase(e, d);
}

fn trimSeps(s: []const u8) []const u8 {
    return std.mem.trimEnd(u8, s, "\\/");
}

/// `old` with `dir` appended (`;`-separated), or null if it is there
/// already. Empty items are left as they were.
pub fn pathWith(gpa: Allocator, old: []const u8, dir: []const u8, local_app_data: []const u8) !?[]u8 {
    var it = std.mem.splitScalar(u8, old, ';');
    while (it.next()) |e| if (sameDir(e, dir, local_app_data)) return null;
    const t = std.mem.trimEnd(u8, old, " ");
    if (t.len == 0) return try gpa.dupe(u8, dir);
    const sep: []const u8 = if (t[t.len - 1] == ';') "" else ";";
    return try std.mem.concat(gpa, u8, &.{ t, sep, dir });
}

/// `old` without any item naming `dir`, or null if none did.
pub fn pathWithout(gpa: Allocator, old: []const u8, dir: []const u8, local_app_data: []const u8) !?[]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var removed = false;
    var first = true;
    var it = std.mem.splitScalar(u8, old, ';');
    while (it.next()) |e| {
        if (sameDir(e, dir, local_app_data)) {
            removed = true;
            continue;
        }
        if (!first) try out.append(gpa, ';');
        first = false;
        try out.appendSlice(gpa, e);
    }
    if (!removed) {
        out.deinit(gpa);
        return null;
    }
    return try out.toOwnedSlice(gpa);
}

/// Adds `dir` to HKCU\Environment\Path, keeping its type (REG_EXPAND_SZ
/// when new). True if it changed (the caller then broadcasts
/// WM_SETTINGCHANGE "Environment").
pub fn addUserPath(gpa: Allocator, reg: Registry, dir: []const u8, local_app_data: []const u8) !bool {
    const cur = try reg.get(gpa, env_key, "Path");
    defer if (cur) |c| if (c.text()) |t| gpa.free(t);
    const old: []const u8 = if (cur) |c| c.text() orelse "" else "";
    const new = (try pathWith(gpa, old, dir, local_app_data)) orelse return false;
    defer gpa.free(new);
    try reg.set(env_key, "Path", if (cur != null and cur.? == .sz) .{ .sz = new } else .{ .expand_sz = new });
    return true;
}

/// Removes `dir` from HKCU\Environment\Path (the value goes when nothing
/// is left). True if it changed.
pub fn removeUserPath(gpa: Allocator, reg: Registry, dir: []const u8, local_app_data: []const u8) !bool {
    const cur = (try reg.get(gpa, env_key, "Path")) orelse return false;
    defer if (cur.text()) |t| gpa.free(t);
    const old = cur.text() orelse return false;
    const new = (try pathWithout(gpa, old, dir, local_app_data)) orelse return false;
    defer gpa.free(new);
    if (std.mem.trim(u8, new, " ;").len == 0) {
        try reg.deleteValue(env_key, "Path");
    } else try reg.set(env_key, "Path", if (cur == .sz) .{ .sz = new } else .{ .expand_sz = new });
    return true;
}

// ---------------------------------------------------------- the Apps entry

pub const Named = struct { name: []const u8, value: Value };

pub const EntryInput = struct {
    layout: Layout,
    version: []const u8,
    role: Role,
    /// Installed size in KiB.
    size_kib: u32,
    /// yyyyMMdd.
    date: []const u8,
};

/// The values of HKCU\...\Uninstall\Portal (Settings > Apps). Strings in `a`.
pub fn uninstallEntry(a: Allocator, in: EntryInput) ![]Named {
    var list: std.ArrayList(Named) = .empty;
    const portal = try in.layout.portalExe(a);
    try list.appendSlice(a, &.{
        .{ .name = "DisplayName", .value = .{ .sz = if (in.role == .desk) "Portal (desk)" else "Portal (device)" } },
        .{ .name = "DisplayVersion", .value = .{ .sz = in.version } },
        .{ .name = "DisplayIcon", .value = .{ .sz = try std.fmt.allocPrint(a, "{s},0", .{portal}) } },
        // The program (Portal's data lives next to it, in root).
        .{ .name = "InstallLocation", .value = .{ .sz = in.layout.releases } },
        .{ .name = "UninstallString", .value = .{ .sz = try uninstallCommand(a, in.layout.setup_exe) } },
        .{ .name = "InstallDate", .value = .{ .sz = in.date } },
        .{ .name = "EstimatedSize", .value = .{ .dword = in.size_kib } },
        .{ .name = "NoModify", .value = .{ .dword = 1 } },
        .{ .name = "NoRepair", .value = .{ .dword = 1 } },
        .{ .name = "PortalRole", .value = .{ .sz = @tagName(in.role) } },
    });
    return list.toOwnedSlice(a);
}

pub fn uninstallCommand(a: Allocator, setup_exe: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "\"{s}\" --uninstall", .{setup_exe});
}

// --------------------------------------------------------------- uninstall

pub const Removal = struct {
    /// Folders removed with everything in them, in this order.
    dirs: []const []const u8,
    /// Single files.
    files: []const []const u8,
};

/// What an uninstall deletes. The program always (releases, launchers, the
/// uninstaller, install.txt, the shortcut); Portal's data (paired devices,
/// keys, settings, logs, a device's pins) only with `delete_data`, which
/// the uninstaller asks for and defaults to keeping.
pub fn removal(a: Allocator, l: Layout, delete_data: bool) !Removal {
    var dirs: std.ArrayList([]const u8) = .empty;
    try dirs.appendSlice(a, &.{ l.releases, l.bin });
    if (delete_data) try dirs.appendSlice(a, &.{ l.root, l.roaming });
    return .{
        .dirs = try dirs.toOwnedSlice(a),
        .files = try a.dupe([]const u8, &.{ l.setup_exe, l.info, l.shortcut }),
    };
}

// ------------------------------------------------------------- install.txt

pub const Info = struct {
    role: Role,
    version: []const u8 = "",
};

pub fn formatInfo(a: Allocator, i: Info) ![]u8 {
    return std.fmt.allocPrint(a, "# Written by portal-setup; read by its uninstaller.\r\nrole = {t}\r\nversion = {s}\r\n", .{ i.role, i.version });
}

/// Null if the role is missing or unknown. `version` points into `text`.
pub fn parseInfo(text: []const u8) ?Info {
    var role: ?Role = null;
    var version: []const u8 = "";
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const k = std.mem.trim(u8, line[0..eq], " ");
        const v = std.mem.trim(u8, line[eq + 1 ..], " ");
        if (std.mem.eql(u8, k, "role")) role = Role.parse(v);
        if (std.mem.eql(u8, k, "version")) version = v;
    }
    return .{ .role = role orelse return null, .version = version };
}

// ------------------------------------------------------------ architecture

pub const Arch = enum { x86_64, aarch64, other };

/// IMAGE_FILE_MACHINE_* (IsWow64Process2's native machine).
pub fn archOfMachine(m: u16) Arch {
    return switch (m) {
        0x8664 => .x86_64,
        0xAA64 => .aarch64,
        else => .other,
    };
}

pub fn assetName(a: Arch) []const u8 {
    return switch (a) {
        .x86_64 => "portal-setup-x64.exe",
        .aarch64 => "portal-setup-arm64.exe",
        .other => "(none)",
    };
}

pub fn archLabel(a: Arch) []const u8 {
    return switch (a) {
        .x86_64 => "x64 (Intel or AMD)",
        .aarch64 => "ARM64 (Snapdragon)",
        .other => "an unsupported processor",
    };
}

/// Null when this installer (built for `mine`) fits a machine whose native
/// processor is `native`; otherwise the message that refuses it.
pub fn archMismatch(buf: []u8, mine: Arch, native: Arch) ?[]const u8 {
    if (mine == native) return null;
    if (native == .other) return std.fmt.bufPrint(buf, "Portal runs on x64 and ARM64 Windows only; this PC has {s}.", .{archLabel(native)}) catch "This PC's processor is not supported.";
    return std.fmt.bufPrint(buf, "This is the installer for {s} PCs, but this PC is {s}.\n\nDownload {s} from the same release and run that instead. Nothing was installed.", .{ archLabel(mine), archLabel(native), assetName(native) }) catch "This installer is for another kind of PC. Nothing was installed.";
}

// ------------------------------------------------------------------- tests

const testing = std.testing;

const FakeRegistry = struct {
    gpa: Allocator,
    map: std.StringHashMapUnmanaged(Stored) = .empty,

    const Stored = struct { kind: std.meta.Tag(Value), text: []u8 = &.{}, num: u32 = 0 };

    fn deinit(f: *FakeRegistry) void {
        var it = f.map.iterator();
        while (it.next()) |e| {
            f.gpa.free(e.key_ptr.*);
            f.gpa.free(e.value_ptr.text);
        }
        f.map.deinit(f.gpa);
    }

    fn reg(f: *FakeRegistry) Registry {
        return .{ .ctx = f, .vtable = &.{ .get = get, .set = set, .deleteValue = deleteValue, .deleteKey = deleteKey } };
    }

    fn full(gpa: Allocator, key: []const u8, name: []const u8) ![]u8 {
        return std.fmt.allocPrint(gpa, "{s}\x00{s}", .{ key, name });
    }

    fn self(ctx: *anyopaque) *FakeRegistry {
        return @ptrCast(@alignCast(ctx));
    }

    fn get(ctx: *anyopaque, gpa: Allocator, key: []const u8, name: []const u8) anyerror!?Value {
        const f = self(ctx);
        const k = try full(f.gpa, key, name);
        defer f.gpa.free(k);
        const s = f.map.get(k) orelse return null;
        return switch (s.kind) {
            .sz => .{ .sz = try gpa.dupe(u8, s.text) },
            .expand_sz => .{ .expand_sz = try gpa.dupe(u8, s.text) },
            .dword => .{ .dword = s.num },
        };
    }

    fn set(ctx: *anyopaque, key: []const u8, name: []const u8, v: Value) anyerror!void {
        const f = self(ctx);
        try deleteValue(ctx, key, name);
        const k = try full(f.gpa, key, name);
        const st: Stored = switch (v) {
            .sz => |s| .{ .kind = .sz, .text = try f.gpa.dupe(u8, s) },
            .expand_sz => |s| .{ .kind = .expand_sz, .text = try f.gpa.dupe(u8, s) },
            .dword => |n| .{ .kind = .dword, .num = n },
        };
        try f.map.put(f.gpa, k, st);
    }

    fn deleteValue(ctx: *anyopaque, key: []const u8, name: []const u8) anyerror!void {
        const f = self(ctx);
        const k = try full(f.gpa, key, name);
        defer f.gpa.free(k);
        if (f.map.fetchRemove(k)) |e| {
            f.gpa.free(e.key);
            f.gpa.free(e.value.text);
        }
    }

    fn deleteKey(ctx: *anyopaque, key: []const u8) anyerror!void {
        const f = self(ctx);
        while (true) {
            var it = f.map.iterator();
            const victim = while (it.next()) |e| {
                const k = e.key_ptr.*;
                const z = std.mem.indexOfScalar(u8, k, 0).?;
                if (std.mem.eql(u8, k[0..z], key)) break k;
            } else return;
            const e = f.map.fetchRemove(victim).?;
            f.gpa.free(e.key);
            f.gpa.free(e.value.text);
        }
    }

    fn count(f: *FakeRegistry, key: []const u8) usize {
        var n: usize = 0;
        var it = f.map.iterator();
        while (it.next()) |e| {
            const k = e.key_ptr.*;
            if (std.mem.eql(u8, k[0..std.mem.indexOfScalar(u8, k, 0).?], key)) n += 1;
        }
        return n;
    }
};

const lad = "C:\\Users\\u\\AppData\\Local";

test "setup: the layout is zig build release's" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const l = try Layout.init(arena.allocator(), lad, "C:\\Users\\u\\AppData\\Roaming");
    try testing.expectEqualStrings(lad ++ "\\Portal", l.root);
    try testing.expectEqualStrings(lad ++ "\\Portal\\releases", l.releases);
    try testing.expectEqualStrings(lad ++ "\\Portal\\bin", l.bin);
    try testing.expectEqualStrings(lad ++ "\\Portal\\portal-setup.exe", l.setup_exe);
    try testing.expectEqualStrings(lad ++ "\\Portal\\install.txt", l.info);
    try testing.expectEqualStrings("C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Portal.lnk", l.shortcut);
    try testing.expectEqualStrings("C:\\Users\\u\\AppData\\Roaming\\Portal", l.roaming);
    try testing.expectEqualStrings(lad ++ "\\Portal\\bin\\portal.exe", try l.portalExe(arena.allocator()));
    // The same folders portal-release computes.
    const r = try lib.releasesRoot(arena.allocator(), null, lad);
    try testing.expectEqualStrings(r, l.releases);
    try testing.expectEqualStrings(try lib.launcherBinDir(arena.allocator(), r), l.bin);
    try testing.expectError(error.NoAppData, Layout.init(arena.allocator(), "", "x"));
}

test "setup: PATH edits keep everything else" {
    const a = testing.allocator;
    const bin = lad ++ "\\Portal\\bin";
    {
        const p = (try pathWith(a, "C:\\a;C:\\b", bin, lad)).?;
        defer a.free(p);
        try testing.expectEqualStrings("C:\\a;C:\\b;" ++ bin, p);
    }
    {
        const p = (try pathWith(a, "C:\\a;", bin, lad)).?;
        defer a.free(p);
        try testing.expectEqualStrings("C:\\a;" ++ bin, p);
    }
    {
        const p = (try pathWith(a, "", bin, lad)).?;
        defer a.free(p);
        try testing.expectEqualStrings(bin, p);
    }
    // Already there, in any spelling: unchanged.
    try testing.expect((try pathWith(a, "C:\\a;\"c:\\users\\U\\appdata\\local\\portal\\BIN\\\"", bin, lad)) == null);
    try testing.expect((try pathWith(a, "%LOCALAPPDATA%\\Portal\\bin;C:\\a", bin, lad)) == null);
    {
        const p = (try pathWithout(a, "C:\\a;" ++ bin ++ ";;C:\\b;%LocalAppData%\\Portal\\bin\\", bin, lad)).?;
        defer a.free(p);
        try testing.expectEqualStrings("C:\\a;;C:\\b", p);
    }
    try testing.expect((try pathWithout(a, "C:\\a;C:\\Portal\\bin", bin, lad)) == null);
    try testing.expect(!sameDir("%LOCALAPPDATA%\\Portal\\binx", bin, lad));
    try testing.expect(!sameDir("C:\\Users\\u\\AppData\\Local\\Portal", bin, lad));
}

test "setup: the user PATH on a fake registry: add once, keep the type, remove" {
    const a = testing.allocator;
    var f: FakeRegistry = .{ .gpa = a };
    defer f.deinit();
    const r = f.reg();
    const bin = lad ++ "\\Portal\\bin";
    // No Path yet: created as REG_EXPAND_SZ.
    try testing.expect(try addUserPath(a, r, bin, lad));
    var v = (try r.get(a, env_key, "Path")).?;
    try testing.expectEqualStrings(bin, v.expand_sz);
    a.free(v.expand_sz);
    // Idempotent.
    try testing.expect(!try addUserPath(a, r, bin, lad));
    // Removing it leaves no empty value behind.
    try testing.expect(try removeUserPath(a, r, bin, lad));
    try testing.expect((try r.get(a, env_key, "Path")) == null);
    try testing.expect(!try removeUserPath(a, r, bin, lad));
    // A REG_SZ Path stays REG_SZ, with the user's items intact.
    try r.set(env_key, "Path", .{ .sz = "C:\\tools;%USERPROFILE%\\go\\bin" });
    try testing.expect(try addUserPath(a, r, bin, lad));
    v = (try r.get(a, env_key, "Path")).?;
    try testing.expectEqualStrings("C:\\tools;%USERPROFILE%\\go\\bin;" ++ bin, v.sz);
    a.free(v.sz);
    try testing.expect(try removeUserPath(a, r, bin, lad));
    v = (try r.get(a, env_key, "Path")).?;
    try testing.expectEqualStrings("C:\\tools;%USERPROFILE%\\go\\bin", v.sz);
    a.free(v.sz);
}

test "setup: the Apps entry, written and removed on a fake registry" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    const l = try Layout.init(aa, lad, "C:\\R");
    const vals = try uninstallEntry(aa, .{ .layout = l, .version = "v0.1.0", .role = .desk, .size_kib = 4096, .date = "20261115" });
    var f: FakeRegistry = .{ .gpa = testing.allocator };
    defer f.deinit();
    const r = f.reg();
    for (vals) |v| try r.set(uninstall_key, v.name, v.value);
    for (vals) |v| try r.set(uninstall_key, v.name, v.value); // re-install: same values
    try testing.expectEqual(vals.len, f.count(uninstall_key));
    const us = (try r.get(testing.allocator, uninstall_key, "UninstallString")).?;
    defer testing.allocator.free(us.sz);
    try testing.expectEqualStrings("\"" ++ lad ++ "\\Portal\\portal-setup.exe\" --uninstall", us.sz);
    const icon = (try r.get(testing.allocator, uninstall_key, "DisplayIcon")).?;
    defer testing.allocator.free(icon.sz);
    try testing.expectEqualStrings(lad ++ "\\Portal\\bin\\portal.exe,0", icon.sz);
    try testing.expectEqual(@as(u32, 4096), (try r.get(testing.allocator, uninstall_key, "EstimatedSize")).?.dword);
    const loc = (try r.get(testing.allocator, uninstall_key, "InstallLocation")).?;
    defer testing.allocator.free(loc.sz);
    try testing.expectEqualStrings(lad ++ "\\Portal\\releases", loc.sz);
    try r.deleteKey(uninstall_key);
    try testing.expectEqual(@as(usize, 0), f.count(uninstall_key));
}

test "setup: uninstall removes the program, and data only when asked" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const l = try Layout.init(arena.allocator(), lad, "C:\\R");
    const keep = try removal(arena.allocator(), l, false);
    try testing.expectEqual(@as(usize, 2), keep.dirs.len);
    try testing.expectEqualStrings(l.releases, keep.dirs[0]);
    try testing.expectEqualStrings(l.bin, keep.dirs[1]);
    try testing.expectEqual(@as(usize, 3), keep.files.len);
    try testing.expectEqualStrings(l.setup_exe, keep.files[0]);
    try testing.expectEqualStrings(l.info, keep.files[1]);
    try testing.expectEqualStrings(l.shortcut, keep.files[2]);
    // Keeping data: nothing removed is the data folder or above it.
    for (keep.dirs) |d| {
        try testing.expect(!std.mem.eql(u8, d, l.root));
        try testing.expect(std.mem.startsWith(u8, d, l.root) and d.len > l.root.len);
    }
    const all = try removal(arena.allocator(), l, true);
    try testing.expectEqual(@as(usize, 4), all.dirs.len);
    try testing.expectEqualStrings(l.root, all.dirs[2]);
    try testing.expectEqualStrings(l.roaming, all.dirs[3]);
}

test "setup: install.txt round trip" {
    const a = testing.allocator;
    const t = try formatInfo(a, .{ .role = .device, .version = "v1.2" });
    defer a.free(t);
    const i = parseInfo(t).?;
    try testing.expectEqual(Role.device, i.role);
    try testing.expectEqualStrings("v1.2", i.version);
    try testing.expect(parseInfo("role = hub\r\n") == null);
    try testing.expect(parseInfo("") == null);
    try testing.expectEqual(Role.desk, parseInfo("role=desk").?.role);
    try testing.expectEqualStrings("connect", shortcutArgs(.device));
    try testing.expectEqualStrings("", shortcutArgs(.desk));
}

test "setup: only true uninstall copies count as leftovers" {
    try testing.expect(isUninstallDir("portal-uninstall-0123456789abcdef"));
    try testing.expect(!isUninstallDir("portal-uninstall-0123456789abcde"));
    try testing.expect(!isUninstallDir("portal-uninstall-0123456789abcdeg"));
    try testing.expect(!isUninstallDir("portal-uninstall-0123456789abcdef0"));
    try testing.expect(!isUninstallDir("portal-setup"));
    try testing.expect(!isUninstallDir("other-0123456789abcdef"));
}

test "setup: the mode table: Windows offers desk and device, the Mac device only (for now)" {
    var win: usize = 0;
    var mac: usize = 0;
    for (modes) |m| {
        if (m.windows) win += 1;
        if (m.macos) mac += 1;
        try testing.expect(std.mem.indexOfScalar(u8, m.choice, '\n') != null); // title + line
    }
    try testing.expectEqual(@as(usize, 2), win);
    try testing.expectEqual(@as(usize, 1), mac);
    try testing.expect(modeOf(.device).macos and !modeOf(.desk).macos);
}

test "setup: a mismatched architecture is refused with the right download" {
    var b: [300]u8 = undefined;
    try testing.expect(archMismatch(&b, .x86_64, .x86_64) == null);
    try testing.expect(archMismatch(&b, .aarch64, .aarch64) == null);
    const m = archMismatch(&b, .x86_64, .aarch64).?;
    try testing.expect(std.mem.indexOf(u8, m, "portal-setup-arm64.exe") != null);
    try testing.expect(std.mem.indexOf(u8, m, "Nothing was installed") != null);
    try testing.expect(std.mem.indexOf(u8, archMismatch(&b, .aarch64, .x86_64).?, "portal-setup-x64.exe") != null);
    try testing.expect(archMismatch(&b, .x86_64, .other) != null);
    try testing.expectEqual(Arch.x86_64, archOfMachine(0x8664));
    try testing.expectEqual(Arch.aarch64, archOfMachine(0xAA64));
    try testing.expectEqual(Arch.other, archOfMachine(0x14c));
}
