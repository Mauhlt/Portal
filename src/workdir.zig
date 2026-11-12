//! Which directory `portal run` starts the session in.
//!
//!   --cwd DIR given                  -> DIR (must be an existing directory)
//!   started from a terminal          -> the terminal's current directory
//!   double-click / Start menu / shortcut (no terminal of its own)
//!                                    -> %USERPROFILE%
//!   current directory inside %LOCALAPPDATA%\Portal\releases
//!                                    -> %USERPROFILE% (never start work
//!                                       inside a release folder)

const std = @import("std");

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
/// this process's environment (so CreateProcessW with a null environment,
/// as conpty.zig uses, does not pass it on). Call once, before spawning
/// the child.
pub fn takeLauncherFlag(value: ?[]const u8) bool {
    const ok = viaLauncher(value, parentPid());
    _ = SetEnvironmentVariableW(std.unicode.utf8ToUtf16LeStringLiteral(launcher_env), null);
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
extern "kernel32" fn SetEnvironmentVariableW(name: [*:0]const u16, value: ?[*:0]const u16) callconv(.winapi) i32;

/// The default when --cwd is absent. Null means "inherit Portal's current
/// directory". A pure function, so the policy is unit-tested.
pub fn defaultCwd(has_parent_console: bool, cwd: ?[]const u8, userprofile: ?[]const u8, releases_dir: ?[]const u8) ?[]const u8 {
    const home = userprofile orelse return null;
    if (home.len == 0) return null;
    if (!has_parent_console) return home;
    if (cwd) |c| if (releases_dir) |r| if (pathInside(c, r)) return home;
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
    try testing.expect(SetEnvironmentVariableW(name, std.unicode.utf8ToUtf16LeStringLiteral("1")) != 0);
    // The test runner's parent is not a launcher with pid 1.
    try testing.expect(!takeLauncherFlag("1"));
    var buf: [16]u16 = undefined;
    try testing.expectEqual(@as(u32, 0), GetEnvironmentVariableW(name, &buf, buf.len));
    try testing.expect(parentPid() != null);
}

extern "kernel32" fn GetEnvironmentVariableW(name: [*:0]const u16, buf: [*]u16, size: u32) callconv(.winapi) u32;

test "pathInside" {
    try testing.expect(pathInside("C:\\a\\b", "C:\\a"));
    try testing.expect(pathInside("C:\\a", "c:\\A\\"));
    try testing.expect(!pathInside("C:\\ab", "C:\\a"));
    try testing.expect(!pathInside("C:\\", "C:\\a"));
    try testing.expect(!pathInside("C:\\a", ""));
    try testing.expect(!pathInside("C:\\a", "\\\\"));
}
