//! The Mac's installer is Portal.app itself (Portal-mac.zip from a
//! release): the Mac is a device, so the app is `portal connect`.
//!
//! * First start from anywhere else (Downloads, a translocated copy): the
//!   app copies itself to ~/Applications/Portal.app (per user, no
//!   administrator), replacing an older copy there (an upgrade in place;
//!   Portal's data lives elsewhere and stays), and starts that copy, which
//!   opens on the pairing screen. In /Applications or ~/Applications it
//!   just runs.
//! * `Portal.app/Contents/MacOS/Portal uninstall` (in Terminal) removes the
//!   app, and asks before deleting the data: pinned desktops, pairing,
//!   settings (~/Library/Application Support/Portal) and this Mac's tunnel
//!   key (Keychain). Dragging the app to the Trash removes the app alone.
//!
//! The bundle's layout and Info.plist are defined here once: the bundle
//! tool (src/tools/mac_bundle.zig) writes them at build time. The rules
//! are pure and tested on any OS; only `run` and `uninstall` touch a Mac.

const std = @import("std");
const builtin = @import("builtin");

pub const app_dir = "Portal.app";
pub const exe_name = "Portal";
pub const bundle_id = "local.portal.mac";
pub const icon_name = "Portal.icns";
pub const min_macos = "13.0";
/// Data the app keeps (pins, pairing, settings, sync), under $HOME.
pub const data_dir = "Library/Application Support/Portal";

/// Where each file of the bundle goes, under Portal.app.
pub const paths = struct {
    pub const info_plist = "Contents/Info.plist";
    pub const executable = "Contents/MacOS/" ++ exe_name;
    pub const moltenvk = "Contents/Frameworks/libMoltenVK.dylib";
    pub const icon = "Contents/Resources/" ++ icon_name;
};

/// Files that must be executable (mode 0755) in the bundle.
pub fn isExecutable(rel: []const u8) bool {
    return std.mem.eql(u8, rel, paths.executable) or std.mem.endsWith(u8, rel, ".dylib");
}

pub fn infoPlist(buf: []u8, version: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<plist version="1.0">
        \\<dict>
        \\    <key>CFBundleDevelopmentRegion</key><string>en</string>
        \\    <key>CFBundleExecutable</key><string>{s}</string>
        \\    <key>CFBundleIdentifier</key><string>{s}</string>
        \\    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
        \\    <key>CFBundleName</key><string>Portal</string>
        \\    <key>CFBundleDisplayName</key><string>Portal</string>
        \\    <key>CFBundlePackageType</key><string>APPL</string>
        \\    <key>CFBundleShortVersionString</key><string>{s}</string>
        \\    <key>CFBundleVersion</key><string>{s}</string>
        \\    <key>CFBundleIconFile</key><string>{s}</string>
        \\    <key>CFBundleSupportedPlatforms</key><array><string>MacOSX</string></array>
        \\    <key>LSMinimumSystemVersion</key><string>{s}</string>
        \\    <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
        \\    <key>NSHighResolutionCapable</key><true/>
        \\    <key>NSMicrophoneUsageDescription</key><string>Portal records while you dictate, for your own desktop.</string>
        \\    <key>NSLocalNetworkUsageDescription</key><string>Portal connects to the Portal running on your desktop.</string>
        \\</dict>
        \\</plist>
        \\
    , .{ exe_name, bundle_id, plistVersion(version), plistVersion(version), icon_name, min_macos });
}

/// "v1.2.3" -> "1.2.3"; anything not a dotted number -> "0.0.0".
pub fn plistVersion(v: []const u8) []const u8 {
    const t = if (std.mem.startsWith(u8, v, "v")) v[1..] else v;
    if (t.len == 0) return "0.0.0";
    for (t) |c| if (!std.ascii.isDigit(c) and c != '.') return "0.0.0";
    return t;
}

/// The bundle an executable path belongs to (".../X.app"), or null.
pub fn bundleOf(exe: []const u8) ?[]const u8 {
    const macos = std.fs.path.dirnamePosix(exe) orelse return null;
    if (!std.mem.eql(u8, std.fs.path.basenamePosix(macos), "MacOS")) return null;
    const contents = std.fs.path.dirnamePosix(macos) orelse return null;
    if (!std.mem.eql(u8, std.fs.path.basenamePosix(contents), "Contents")) return null;
    const app = std.fs.path.dirnamePosix(contents) orelse return null;
    if (!std.mem.endsWith(u8, app, ".app")) return null;
    return app;
}

pub const Plan = union(enum) {
    /// Not a bundle (a plain portal-client), or installed already: run.
    run,
    /// Copy `from` (a bundle) to `to` and start the copy.
    install: struct { from: []const u8, to: []const u8 },
};

/// What a start does, given the running executable and $HOME. `to_buf`
/// holds the destination.
pub fn plan(exe: []const u8, home: []const u8, to_buf: []u8) Plan {
    const app = bundleOf(exe) orelse return .run;
    if (home.len == 0) return .run;
    const dest = std.fmt.bufPrint(to_buf, "{s}/Applications/" ++ app_dir, .{std.mem.trimEnd(u8, home, "/")}) catch return .run;
    if (std.mem.eql(u8, app, dest)) return .run;
    // Put in /Applications by hand: that is where the owner wants it.
    if (std.mem.startsWith(u8, app, "/Applications/")) return .run;
    return .{ .install = .{ .from = app, .to = dest } };
}

/// What `uninstall` removes: the app always, the data only when asked.
pub fn removal(buf: *[2][1024]u8, home: []const u8, app: []const u8, delete_data: bool) ![]const []const u8 {
    const S = struct {
        var list: [2][]const u8 = undefined;
    };
    S.list[0] = try std.fmt.bufPrint(&buf[0], "{s}", .{app});
    if (!delete_data) return S.list[0..1];
    S.list[1] = try std.fmt.bufPrint(&buf[1], "{s}/" ++ data_dir, .{std.mem.trimEnd(u8, home, "/")});
    return S.list[0..2];
}

// ------------------------------------------------------------------ macOS

const mac = builtin.os.tag == .macos;

/// Called first thing by portal-client on macOS: installs or upgrades the
/// app in ~/Applications and starts it there (never returns then), or
/// returns to run normally. Any failure: runs from where it is.
pub fn run(io: std.Io, args: []const []const u8) void {
    if (!mac) return;
    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = std.process.executablePath(io, &exe_buf) catch return;
    const exe = exe_buf[0..n];
    const home = std.mem.span(std.c.getenv("HOME") orelse return);
    var to_buf: [1024]u8 = undefined;
    const p = plan(exe, home, &to_buf);
    switch (p) {
        .run => return,
        .install => |i| {
            install(io, i.from, i.to) catch return;
            startCopy(i.to, args);
        },
    }
}

/// Copies the bundle next to `to`, then swaps it in (the old copy, if
/// any, goes aside first and is removed after).
fn install(io: std.Io, from: []const u8, to: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    var nb: [1100]u8 = undefined;
    var ob: [1100]u8 = undefined;
    const tmp = try std.fmt.bufPrint(&nb, "{s}.new", .{to});
    const old = try std.fmt.bufPrint(&ob, "{s}.old", .{to});
    if (std.fs.path.dirnamePosix(to)) |parent| try cwd.createDirPath(io, parent);
    cwd.deleteTree(io, tmp) catch {};
    cwd.deleteTree(io, old) catch {};
    try copyTree(io, from, tmp);
    const had = if (cwd.statFile(io, to, .{})) |_| true else |_| false;
    if (had) try cwd.rename(to, cwd, old, io);
    cwd.rename(tmp, cwd, to, io) catch |err| {
        if (had) cwd.rename(old, cwd, to, io) catch {};
        return err;
    };
    cwd.deleteTree(io, old) catch {};
}

fn copyTree(io: std.Io, from: []const u8, to: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    var src = try cwd.openDir(io, from, .{ .iterate = true });
    defer src.close(io);
    try cwd.createDirPath(io, to);
    var dst = try cwd.openDir(io, to, .{});
    defer dst.close(io);
    var walker = try src.walk(std.heap.page_allocator);
    defer walker.deinit();
    while (try walker.next(io)) |e| switch (e.kind) {
        .directory => try dst.createDirPath(io, e.path),
        // copyFile keeps the mode (the executable bit).
        .file => try src.copyFile(e.path, dst, e.path, io, .{}),
        else => {},
    };
}

/// Replaces this process with the installed copy (same arguments).
fn startCopy(app: []const u8, args: []const []const u8) void {
    var eb: [1100:0]u8 = undefined;
    const exe = printZ(&eb, "{s}/" ++ paths.executable, .{app}) orelse return;
    var argv: [16:null]?[*:0]const u8 = @splat(null);
    argv[0] = exe.ptr;
    var zb: [15][256:0]u8 = undefined;
    for (args[0..@min(args.len, 14)], 0..) |a, i| {
        const z = printZ(&zb[i], "{s}", .{a}) orelse return;
        argv[i + 1] = z.ptr;
    }
    _ = std.c.execve(exe.ptr, &argv, std.c.environ);
}

fn printZ(buf: anytype, comptime f: []const u8, args: anytype) ?[:0]u8 {
    const s = std.fmt.bufPrint(buf[0 .. buf.len - 1], f, args) catch return null;
    buf[s.len] = 0;
    return buf[0..s.len :0];
}

/// `Portal uninstall`: asks on the terminal, then removes. `drop_key`
/// deletes this Mac's tunnel key (the client's tunnel.keys.drop). Returns
/// the exit code.
pub fn uninstall(io: std.Io, drop_key: *const fn () anyerror!void) u8 {
    if (!mac) {
        std.debug.print("portal uninstall: this is the Mac's uninstaller; on Windows use Settings > Apps.\n", .{});
        return 2;
    }
    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = std.process.executablePath(io, &exe_buf) catch return 1;
    const app = bundleOf(exe_buf[0..n]) orelse {
        std.debug.print("portal uninstall: not running from Portal.app\n", .{});
        return 1;
    };
    const home = std.mem.span(std.c.getenv("HOME") orelse return 1);
    if (!ask(io, "Remove {s}? [y/N] ", .{app})) {
        std.debug.print("Nothing was removed.\n", .{});
        return 0;
    }
    const data = ask(io, "Also delete your Portal data (pinned desktops, pairing, settings in ~/" ++ data_dir ++ ", and this Mac's tunnel key)? Paired desktops must then pair it again. [y/N] ", .{});
    var bufs: [2][1024]u8 = undefined;
    const list = removal(&bufs, home, app, data) catch return 1;
    if (data) drop_key() catch |err| std.debug.print("The tunnel key could not be deleted: {t}\n", .{err});
    var failed = false;
    for (list) |p| std.Io.Dir.cwd().deleteTree(io, p) catch |err| {
        std.debug.print("Not removed: {s} ({t})\n", .{ p, err });
        failed = true;
    };
    std.debug.print("{s}\n", .{if (failed) "Portal was partly removed (see above)." else if (data) "Portal and its data are removed." else "Portal is removed; your data is kept."});
    return if (failed) 1 else 0;
}

fn ask(io: std.Io, comptime prompt: []const u8, args: anytype) bool {
    std.debug.print(prompt, args);
    var buf: [64]u8 = undefined;
    var r = std.Io.File.stdin().reader(io, &buf);
    const line = r.interface.takeDelimiterExclusive('\n') catch return false;
    const t = std.mem.trim(u8, line, " \t\r");
    return t.len > 0 and (t[0] == 'y' or t[0] == 'Y');
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "mac: a start from Downloads installs into ~/Applications; installed copies just run" {
    var b: [1024]u8 = undefined;
    const p = plan("/Users/u/Downloads/Portal.app/Contents/MacOS/Portal", "/Users/u", &b);
    try testing.expectEqualStrings("/Users/u/Downloads/Portal.app", p.install.from);
    try testing.expectEqualStrings("/Users/u/Applications/Portal.app", p.install.to);
    // App Translocation runs it from a random read-only path: still installs.
    const t = plan("/private/var/folders/x/AppTranslocation/ABC/d/Portal.app/Contents/MacOS/Portal", "/Users/u/", &b);
    try testing.expectEqualStrings("/Users/u/Applications/Portal.app", t.install.to);
    try testing.expectEqual(Plan.run, plan("/Users/u/Applications/Portal.app/Contents/MacOS/Portal", "/Users/u", &b));
    try testing.expectEqual(Plan.run, plan("/Applications/Portal.app/Contents/MacOS/Portal", "/Users/u", &b));
    // A plain portal-client (no bundle) never installs anything.
    try testing.expectEqual(Plan.run, plan("/usr/local/bin/portal-client", "/Users/u", &b));
    try testing.expectEqual(Plan.run, plan("/x/Portal.app/Contents/Resources/Portal", "/Users/u", &b));
    try testing.expectEqual(Plan.run, plan("/x/Portal.app/Contents/MacOS/Portal", "", &b));
}

test "mac: uninstall removes the app, and the data only when asked" {
    var bufs: [2][1024]u8 = undefined;
    const keep = try removal(&bufs, "/Users/u", "/Users/u/Applications/Portal.app", false);
    try testing.expectEqual(@as(usize, 1), keep.len);
    try testing.expectEqualStrings("/Users/u/Applications/Portal.app", keep[0]);
    const all = try removal(&bufs, "/Users/u/", "/Users/u/Applications/Portal.app", true);
    try testing.expectEqual(@as(usize, 2), all.len);
    try testing.expectEqualStrings("/Users/u/Library/Application Support/Portal", all[1]);
}

test "mac: the bundle layout and Info.plist" {
    var b: [4096]u8 = undefined;
    const p = try infoPlist(&b, "v1.2.3");
    try testing.expect(std.mem.indexOf(u8, p, "<key>CFBundleExecutable</key><string>Portal</string>") != null);
    try testing.expect(std.mem.indexOf(u8, p, "<key>CFBundleIdentifier</key><string>local.portal.mac</string>") != null);
    try testing.expect(std.mem.indexOf(u8, p, "<key>CFBundleShortVersionString</key><string>1.2.3</string>") != null);
    try testing.expect(std.mem.indexOf(u8, p, "<key>CFBundleIconFile</key><string>Portal.icns</string>") != null);
    try testing.expect(std.mem.indexOf(u8, p, "<key>LSMinimumSystemVersion</key><string>13.0</string>") != null);
    try testing.expect(std.mem.indexOf(u8, p, "<key>CFBundlePackageType</key><string>APPL</string>") != null);
    // Well formed: every <key> has its </key>, the dict and plist close.
    try testing.expectEqual(std.mem.count(u8, p, "<key>"), std.mem.count(u8, p, "</key>"));
    try testing.expect(std.mem.endsWith(u8, p, "</dict>\n</plist>\n"));
    try testing.expectEqualStrings("0.0.0", plistVersion("dev"));
    try testing.expectEqualStrings("2", plistVersion("v2"));
    try testing.expectEqualStrings("Contents/MacOS/Portal", paths.executable);
    try testing.expect(isExecutable(paths.executable));
    try testing.expect(isExecutable(paths.moltenvk));
    try testing.expect(!isExecutable(paths.info_plist));
    try testing.expectEqualStrings(bundleOf("/A/Portal.app/Contents/MacOS/Portal").?, "/A/Portal.app");
}
