//! Window and console titles: "Portal — <project>" (or "No project"),
//! plus the remote viewer count. The one source of every title Portal
//! sets (the GUI window, the console in `portalctl run --console`).
//! Program-set titles (OSC 0/1/2, SetConsoleTitle) are never shown: they
//! leak paths such as "Administrator: C:\Windows\system32\cmd.exe" or the
//! working directory (by default the home folder: the user name).

const std = @import("std");

/// Longest `--project` name, in bytes.
pub const max_project_bytes = 64;

/// True if `s` may be shown as the project name: 1..max_project_bytes bytes
/// of valid UTF-8 on a single line, with no control characters (C0, DEL,
/// C1), line/paragraph separators or bidi overrides (which could make the
/// title read differently from what it is).
pub fn validProject(s: []const u8) bool {
    if (s.len == 0 or s.len > max_project_bytes) return false;
    const v = std.unicode.Utf8View.init(s) catch return false;
    var it = v.iterator();
    while (it.nextCodepoint()) |cp| switch (cp) {
        0x00...0x1F, 0x7F...0x9F, 0x2028, 0x2029, 0x202A...0x202E, 0x2066...0x2069, 0x200E, 0x200F, 0x061C, 0xFEFF => return false,
        else => {},
    };
    return std.mem.trim(u8, s, " ").len > 0;
}

/// "Portal — <project>" or "Portal — No project".
pub fn windowLabel(project: ?[]const u8, buf: []u8) []const u8 {
    const p = project orelse "No project";
    return std.fmt.bufPrint(buf, "Portal \u{2014} {s}", .{p}) catch "Portal";
}

/// The window title: the label, plus " — N REMOTE VIEWER(S)" while anyone
/// watches.
pub fn windowTitle(project: ?[]const u8, viewers: u32, buf: []u8) []const u8 {
    var lbuf: [max_project_bytes + 16]u8 = undefined;
    const label = windowLabel(project, &lbuf);
    if (viewers == 0) return std.fmt.bufPrint(buf, "{s}", .{label}) catch "Portal";
    return std.fmt.bufPrint(buf, "{s} \u{2014} {d} REMOTE VIEWER{s}", .{ label, viewers, if (viewers == 1) "" else "S" }) catch "Portal";
}

/// Room for any title `windowTitle` makes.
pub const max_title_bytes = max_project_bytes + 64;

const testing = std.testing;

test "window title never shows the program's title" {
    var buf: [max_title_bytes]u8 = undefined;
    try testing.expectEqualStrings("Portal \u{2014} No project", windowTitle(null, 0, &buf));
    try testing.expectEqualStrings("Portal \u{2014} acme-api", windowTitle("acme-api", 0, &buf));
    try testing.expectEqualStrings("Portal \u{2014} acme-api \u{2014} 1 REMOTE VIEWER", windowTitle("acme-api", 1, &buf));
    try testing.expectEqualStrings("Portal \u{2014} No project \u{2014} 3 REMOTE VIEWERS", windowTitle(null, 3, &buf));
    // The longest valid project with a huge viewer count still fits.
    const long: [max_project_bytes]u8 = @splat('p');
    try testing.expect(std.mem.endsWith(u8, windowTitle(&long, std.math.maxInt(u32), &buf), "4294967295 REMOTE VIEWERS"));
    var lbuf: [max_project_bytes + 16]u8 = undefined;
    try testing.expectEqualStrings("Portal \u{2014} No project", windowLabel(null, &lbuf));
    try testing.expectEqualStrings("Portal \u{2014} " ++ long, windowLabel(&long, &lbuf));
}

test "validProject" {
    try testing.expect(validProject("acme-api"));
    try testing.expect(validProject("Kundenportal \u{e9}t\u{e9} 2"));
    const max: [max_project_bytes]u8 = @splat('p');
    const over: [max_project_bytes + 1]u8 = @splat('p');
    try testing.expect(validProject(&max));
    try testing.expect(!validProject(&over));
    try testing.expect(!validProject(""));
    try testing.expect(!validProject("   "));
    try testing.expect(!validProject("a\nb"));
    try testing.expect(!validProject("a\rb"));
    try testing.expect(!validProject("a\tb"));
    try testing.expect(!validProject("a\x1b]0;x\x07"));
    try testing.expect(!validProject("a\x7f"));
    try testing.expect(!validProject("a\u{85}b")); // C1 NEL
    try testing.expect(!validProject("a\u{2028}b"));
    try testing.expect(!validProject("abc\u{202e}gpj.exe")); // RLO
    try testing.expect(!validProject("a\u{2067}b"));
    try testing.expect(!validProject("bad\xff"));
}
