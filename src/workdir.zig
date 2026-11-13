//! Which directory `portal run` starts the session in.
//!
//!   --cwd DIR given                  -> DIR (must be an existing directory)
//!   started from a terminal          -> the terminal's current directory
//!   double-click / Start menu / shortcut (no terminal of its own)
//!                                    -> %USERPROFILE%
//!   current directory inside %LOCALAPPDATA%\Portal\releases
//!                                    -> %USERPROFILE% (never start work
//!                                       inside a release folder)
//!
//! The window (portal.exe, GUI subsystem) has no console to ask, so it
//! decides by the directory it inherited (guiDefaultCwd): Explorer, the
//! Start menu, shortcuts and the launcher leave it in Portal's own folder
//! or the Windows folder, a terminal leaves it where the user is.

const std = @import("std");
const w = @import("win32.zig");

/// Set by the release launcher (src/tools/launcher.zig) in its child's
/// environment, to the launcher's own process id (decimal): the launcher
/// shares the console, so it is not a terminal. Only trusted when that id
/// is our actual parent process, and removed from Portal's environment
/// once read (takeLauncherFlag) so the session's child never inherits it.
pub const launcher_env = "PORTAL_VIA_LAUNCHER";

/// True if `value` (the launcher variable) names `parent_pid`. Pure, so the
/// check is unit-tested.
pub fn viaLauncher(value: ?[]const u8, parent_pid: ?u32) bool {
    const v = value orelse return false;
    const parent = parent_pid orelse return false;
    if (v.len == 0 or v.len > 10) return false;
    for (v) |c| if (c < '0' or c > '9') return false;
    const pid = std.fmt.parseInt(u32, v, 10) catch return false;
    return pid != 0 and pid == parent;
}

/// Reads the launcher variable (`value`, from the startup environment),
/// verifies it against the real parent process id, and deletes it from
/// this process's environment (childenv.zig drops PORTAL_* from the
/// session's block as well). Call once, before spawning
/// the child.
pub fn takeLauncherFlag(value: ?[]const u8) bool {
    const ok = viaLauncher(value, parentPid());
    _ = w.SetEnvironmentVariableW(std.unicode.utf8ToUtf16LeStringLiteral(launcher_env), null);
    return ok;
}

/// This process's parent process id, or null if it cannot be determined.
fn parentPid() ?u32 {
    var pbi: PROCESS_BASIC_INFORMATION = undefined;
    const current: *anyopaque = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1)))); // GetCurrentProcess()
    if (NtQueryInformationProcess(current, 0, &pbi, @sizeOf(PROCESS_BASIC_INFORMATION), null) != 0) return null;
    return std.math.cast(u32, pbi.InheritedFromUniqueProcessId);
}

const PROCESS_BASIC_INFORMATION = extern struct {
    ExitStatus: i32,
    PebBaseAddress: ?*anyopaque,
    AffinityMask: usize,
    BasePriority: i32,
    UniqueProcessId: usize,
    InheritedFromUniqueProcessId: usize,
};
extern "ntdll" fn NtQueryInformationProcess(process: *anyopaque, class: u32, info: *anyopaque, len: u32, ret_len: ?*u32) callconv(.winapi) i32;

/// The default when --cwd is absent. Null means "inherit Portal's current
/// directory". A pure function, so the policy is unit-tested.
pub fn defaultCwd(has_parent_console: bool, cwd: ?[]const u8, userprofile: ?[]const u8, releases_dir: ?[]const u8) ?[]const u8 {
    const home = userprofile orelse return null;
    if (home.len == 0) return null;
    if (!has_parent_console) return home;
    if (cwd) |c| if (releases_dir) |r| if (pathInside(c, r)) return home;
    return null;
}

/// The window's default when no directory is configured: the inherited
/// one if it looks chosen by the user (a terminal's), else the home folder.
/// It is not a user's choice if it is unknown, Portal's data folder
/// (releases, bin) or below it, the folder of portal.exe itself, or the
/// Windows folder (Run dialog, some shortcuts). Null: inherit `cwd`.
pub fn guiDefaultCwd(cwd: ?[]const u8, exe_dir: ?[]const u8, data_dir: ?[]const u8, windir: ?[]const u8, userprofile: ?[]const u8) ?[]const u8 {
    const home = userprofile orelse return null;
    if (home.len == 0) return null;
    const c = cwd orelse return home;
    for ([_]?[]const u8{ data_dir, exe_dir, windir }) |p| if (p) |dir| if (pathInside(c, dir)) return home;
    return null;
}

/// True if `child` is `parent` or below it. Windows rules: ASCII case
/// folding, '/' and '\' equal, trailing separators ignored.
pub fn pathInside(child: []const u8, parent_in: []const u8) bool {
    var parent = parent_in;
    while (parent.len > 0 and isSep(parent[parent.len - 1])) parent = parent[0 .. parent.len - 1];
    if (parent.len == 0 or child.len < parent.len) return false;
    for (child[0..parent.len], parent) |a, b| {
        if (isSep(a) and isSep(b)) continue;
        if (std.ascii.toLower(a) != std.ascii.toLower(b)) return false;
    }
    return child.len == parent.len or isSep(child[parent.len]);
}

fn isSep(c: u8) bool {
    return c == '\\' or c == '/';
}

/// True if a terminal other than Portal (and its launcher) is attached to
/// this console. A double-clicked console program gets a fresh console of
/// its own, shared with nobody but the launcher. Call before FreeConsole.
pub fn hasParentConsole(via_launcher: bool) bool {
    var pids: [8]u32 = undefined;
    const n = GetConsoleProcessList(&pids, pids.len);
    if (n == 0) return false; // no console at all (detached / service)
    const ours: u32 = if (via_launcher) 2 else 1;
    return n > ours;
}

extern "kernel32" fn GetConsoleProcessList(list: [*]u32, count: u32) callconv(.winapi) u32;

const testing = std.testing;

test "default working directory" {
    const home = "C:\\Users\\me";
    const rel = "C:\\Users\\me\\AppData\\Local\\Portal\\releases";
    // Double-click / shortcut: home, whatever the inherited cwd.
    try testing.expectEqualStrings(home, defaultCwd(false, "C:\\Windows\\System32", home, rel).?);
    try testing.expectEqualStrings(home, defaultCwd(false, null, home, rel).?);
    // From a terminal: keep its directory.
    try testing.expect(defaultCwd(true, "C:\\code\\proj", home, rel) == null);
    // ...unless that is inside the releases folder.
    try testing.expectEqualStrings(home, defaultCwd(true, rel ++ "\\20261111-185919_zig\\source", home, rel).?);
    try testing.expectEqualStrings(home, defaultCwd(true, "c:/users/ME/appdata/local/portal/RELEASES", home, rel ++ "\\").?);
    try testing.expect(defaultCwd(true, rel ++ "-old", home, rel) == null);
    // No USERPROFILE: inherit.
    try testing.expect(defaultCwd(false, "C:\\x", null, rel) == null);
    try testing.expect(defaultCwd(false, "C:\\x", "", rel) == null);
    try testing.expect(defaultCwd(true, rel, home, null) == null);
}

test "window's default working directory" {
    const home = "C:\\Users\\me";
    const data = "C:\\Users\\me\\AppData\\Local\\Portal";
    const exe = "C:\\Users\\me\\code\\Portal\\zig-out\\bin";
    const win = "C:\\Windows";
    // Double-click on the launcher (cwd = bin) or a release: home.
    try testing.expectEqualStrings(home, guiDefaultCwd(data ++ "\\bin", exe, data, win, home).?);
    try testing.expectEqualStrings(home, guiDefaultCwd(data ++ "\\releases\\x", exe, data, win, home).?);
    // Double-click on a dev build: home.
    try testing.expectEqualStrings(home, guiDefaultCwd(exe, exe, data, win, home).?);
    // Run dialog / shortcut without "Start in": home.
    try testing.expectEqualStrings(home, guiDefaultCwd("C:\\Windows\\System32", exe, data, win, home).?);
    try testing.expectEqualStrings(home, guiDefaultCwd(null, exe, data, win, home).?);
    // From a terminal in a project: keep it.
    try testing.expect(guiDefaultCwd("C:\\code\\proj", exe, data, win, home) == null);
    try testing.expect(guiDefaultCwd(home, exe, data, win, home) == null);
    // No home folder: inherit.
    try testing.expect(guiDefaultCwd(data, exe, data, win, null) == null);
}

test "launcher variable is only trusted from the parent process" {
    try testing.expect(viaLauncher("4242", 4242));
    try testing.expect(!viaLauncher("4242", 4243)); // set by someone else
    try testing.expect(!viaLauncher("1", 4242)); // the old fixed value
    try testing.expect(!viaLauncher(null, 4242));
    try testing.expect(!viaLauncher("4242", null));
    try testing.expect(!viaLauncher("", 4242));
    try testing.expect(!viaLauncher("0", 0));
    try testing.expect(!viaLauncher("+4242", 4242));
    try testing.expect(!viaLauncher("4242 ", 4242));
    try testing.expect(!viaLauncher("99999999999", 4242));
}

test "takeLauncherFlag removes the variable from the environment" {
    const name = std.unicode.utf8ToUtf16LeStringLiteral(launcher_env);
    try testing.expect(w.SetEnvironmentVariableW(name, std.unicode.utf8ToUtf16LeStringLiteral("1")) != 0);
    // The test runner's parent is not a launcher with pid 1.
    try testing.expect(!takeLauncherFlag("1"));
    var buf: [16]u16 = undefined;
    try testing.expectEqual(@as(u32, 0), w.GetEnvironmentVariableW(name, &buf, buf.len));
    try testing.expect(parentPid() != null);
}


test "pathInside" {
    try testing.expect(pathInside("C:\\a\\b", "C:\\a"));
    try testing.expect(pathInside("C:\\a", "c:\\A\\"));
    try testing.expect(!pathInside("C:\\ab", "C:\\a"));
    try testing.expect(!pathInside("C:\\", "C:\\a"));
    try testing.expect(!pathInside("C:\\a", ""));
    try testing.expect(!pathInside("C:\\a", "\\\\"));
}
