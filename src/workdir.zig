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
/// environment: the launcher shares the console, so it is not a terminal.
pub const launcher_env = "PORTAL_VIA_LAUNCHER";

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

test "pathInside" {
    try testing.expect(pathInside("C:\\a\\b", "C:\\a"));
    try testing.expect(pathInside("C:\\a", "c:\\A\\"));
    try testing.expect(!pathInside("C:\\ab", "C:\\a"));
    try testing.expect(!pathInside("C:\\", "C:\\a"));
    try testing.expect(!pathInside("C:\\a", ""));
    try testing.expect(!pathInside("C:\\a", "\\\\"));
}
