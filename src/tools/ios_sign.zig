//! `zig build ios-sign` and the Mac kit's `portal-ios-sign` (`zig build
//! ios-kit`): signs the built Portal.app for the owner's iPhone (run on
//! the Mac; codesign is Apple's).
//!
//!   portal-ios-sign [<Portal.app> [<out dir> [<bundle id> [<tunnel 0|1>]]]]
//!
//! Copies the app to <out dir>/Portal.app and signs the copy. Defaults (the
//! kit: works from any directory): <Portal.app> next to this executable,
//! <out dir> = "signed" next to <Portal.app>, the bundle id from the app's
//! Info.plist (a given one must match it), the tunnel when the app holds
//! PlugIns/PortalTunnel.appex.
//!
//! Environment (nothing is stored in the repo):
//!   PORTAL_SIGN_IDENTITY        e.g. "Apple Development: Name (ABCDE12345)"
//!                               (`security find-identity -v -p codesigning`)
//!   PORTAL_PROVISIONING_PROFILE path to the app's development
//!                               .mobileprovision (App ID = the bundle id,
//!                               listing the iPhone; a free Apple ID's
//!                               Xcode-made profile works without the tunnel)
//!   PORTAL_TUNNEL_PROVISIONING_PROFILE
//!                               required when the app holds the extension:
//!                               the extension's development profile (App ID
//!                               <bundle id>.tunnel, Network Extensions)
//!   PORTAL_TEAM_ID              the 10-character team id
//!
//! Steps: check each profile (development, App ID, Network Extensions when
//! needed), make the executables executable (a bundle copied from Windows
//! loses the mode bits), embed the profiles, write the entitlements
//! (application id, team, get-task-allow for a development install, one
//! Keychain group shared by the app and the extension, the packet-tunnel
//! entitlement on both with the tunnel), sign every dylib/framework in
//! Frameworks/, then the extension, then the app, verify.

const std = @import("std");
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    var arena_state: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = init.io;
    const cwd = Io.Dir.cwd();

    var args: std.process.Args.Iterator = try .initAllocator(init.minimal.args, arena);
    defer args.deinit();
    _ = args.next();
    const app_arg = args.next();
    if (app_arg) |a| if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) return usage();
    const app_in = app_arg orelse try std.fs.path.join(arena, &.{ try std.process.executableDirPathAlloc(io, arena), "Portal.app" });
    const out_dir = args.next() orelse try std.fs.path.join(arena, &.{ std.fs.path.dirname(app_in) orelse ".", "signed" });
    const bundle_arg = args.next();
    const tunnel_arg = args.next();

    cwd.access(io, app_in, .{}) catch {
        std.debug.print("ios-sign: no app at {s}\n", .{app_in});
        return usage();
    };
    const in_plist = try cwd.readFileAlloc(io, try std.fs.path.join(arena, &.{ app_in, "Info.plist" }), arena, .limited(1 << 20));
    const plist_id = plistString(in_plist, "CFBundleIdentifier") orelse {
        std.debug.print("ios-sign: {s}/Info.plist has no CFBundleIdentifier\n", .{app_in});
        return error.BadApp;
    };
    const bundle_id = bundle_arg orelse plist_id;
    if (!std.mem.eql(u8, bundle_id, plist_id)) {
        std.debug.print("ios-sign: bundle id {s} does not match the app's Info.plist ({s})\n", .{ bundle_id, plist_id });
        return error.BadApp;
    }
    const has_appex = if (cwd.access(io, try std.fs.path.join(arena, &.{ app_in, "PlugIns", "PortalTunnel.appex" }), .{})) |_| true else |_| false;
    const tunnel = if (tunnel_arg) |t| std.mem.eql(u8, t, "1") else has_appex;

    const env = init.environ_map;
    const identity = env.get("PORTAL_SIGN_IDENTITY") orelse return missing("PORTAL_SIGN_IDENTITY");
    const profile = env.get("PORTAL_PROVISIONING_PROFILE") orelse return missing("PORTAL_PROVISIONING_PROFILE");
    const team = env.get("PORTAL_TEAM_ID") orelse return missing("PORTAL_TEAM_ID");
    const ext_profile: ?[]const u8 = if (has_appex)
        env.get("PORTAL_TUNNEL_PROVISIONING_PROFILE") orelse return missing("PORTAL_TUNNEL_PROVISIONING_PROFILE")
    else
        null;

    const ext_id = try std.fmt.allocPrint(arena, "{s}.tunnel", .{bundle_id});
    try checkProfileFile(arena, io, profile, "PORTAL_PROVISIONING_PROFILE", team, bundle_id, tunnel);
    if (ext_profile) |p| try checkProfileFile(arena, io, p, "PORTAL_TUNNEL_PROVISIONING_PROFILE", team, ext_id, true);

    const app = try std.fs.path.join(arena, &.{ out_dir, "Portal.app" });
    cwd.deleteTree(io, app) catch {};
    try copyTree(arena, io, app_in, app);
    try makeExecutable(io, try std.fs.path.join(arena, &.{ app, "Portal" }));
    try cwd.copyFile(profile, cwd, try std.fs.path.join(arena, &.{ app, "embedded.mobileprovision" }), io, .{});

    const ent_path = try std.fmt.allocPrint(arena, "{s}.entitlements", .{app});
    try cwd.writeFile(io, .{ .sub_path = ent_path, .data = try entitlements(arena, team, bundle_id, bundle_id, tunnel) });

    // Frameworks first (inside out), then the extension, then the app.
    const fw_path = try std.fs.path.join(arena, &.{ app, "Frameworks" });
    if (cwd.openDir(io, fw_path, .{ .iterate = true })) |fw_const| {
        var fw = fw_const;
        defer fw.close(io);
        var it = fw.iterate();
        while (try it.next(io)) |e| {
            const p = try std.fs.path.join(arena, &.{ fw_path, e.name });
            if (std.mem.endsWith(u8, e.name, ".framework")) {
                try makeExecutable(io, try std.fs.path.join(arena, &.{ p, e.name[0 .. e.name.len - ".framework".len] }));
            } else if (std.mem.endsWith(u8, e.name, ".dylib")) {
                try makeExecutable(io, p);
            }
            try run(io, &.{ "codesign", "--force", "--timestamp=none", "--sign", identity, p });
        }
    } else |_| {}

    // The tunnel extension (built with -Dios-tunnel): its own profile and
    // entitlements, the app's Keychain group.
    if (ext_profile) |p| {
        const appex = try std.fs.path.join(arena, &.{ app, "PlugIns", "PortalTunnel.appex" });
        try makeExecutable(io, try std.fs.path.join(arena, &.{ appex, "PortalTunnel" }));
        try cwd.copyFile(p, cwd, try std.fs.path.join(arena, &.{ appex, "embedded.mobileprovision" }), io, .{});
        const ext_ent_path = try std.fmt.allocPrint(arena, "{s}.tunnel.entitlements", .{app});
        try cwd.writeFile(io, .{ .sub_path = ext_ent_path, .data = try entitlements(arena, team, ext_id, bundle_id, true) });
        try run(io, &.{ "codesign", "--force", "--timestamp=none", "--sign", identity, "--entitlements", ext_ent_path, appex });
    }

    try run(io, &.{ "codesign", "--force", "--timestamp=none", "--sign", identity, "--entitlements", ent_path, app });
    try run(io, &.{ "codesign", "--verify", "--deep", "--strict", "--verbose=2", app });
    std.debug.print("ios-sign: signed {s}\n", .{app});
}

fn copyTree(gpa: std.mem.Allocator, io: Io, from_path: []const u8, to_path: []const u8) !void {
    const cwd = Io.Dir.cwd();
    var from = try cwd.openDir(io, from_path, .{ .iterate = true });
    defer from.close(io);
    try cwd.createDirPath(io, to_path);
    var to = try cwd.openDir(io, to_path, .{});
    defer to.close(io);
    var walker = try from.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |e| switch (e.kind) {
        .directory => try to.createDirPath(io, e.path),
        else => try from.copyFile(e.path, to, e.path, io, .{}),
    };
}

/// chmod 755 (nothing to do where files have no mode bits: Windows).
fn makeExecutable(io: Io, path: []const u8) !void {
    if (!Io.File.Permissions.has_executable_bit) return;
    Io.Dir.cwd().setFilePermissions(io, path, .executable_file, .{}) catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    };
}

fn checkProfileFile(gpa: std.mem.Allocator, io: Io, path: []const u8, env_name: []const u8, team: []const u8, app_id: []const u8, network_extension: bool) !void {
    const bytes = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch |err| {
        std.debug.print("ios-sign: {s}: cannot read {s} ({t})\n", .{ env_name, path, err });
        return err;
    };
    checkProfile(bytes, team, app_id, network_extension) catch |err| {
        const why: []const u8 = switch (err) {
            error.NotAProfile => "not a provisioning profile (no application-identifier)",
            error.WrongAppId => "its App ID does not cover this bundle id, or its team differs from PORTAL_TEAM_ID",
            error.NotDevelopment => "not a development profile (get-task-allow is not true)",
            error.NoNetworkExtension => "its App ID lacks the Network Extensions capability (packet-tunnel-provider)",
        };
        std.debug.print("ios-sign: {s} ({s}): {s}; expected App ID {s}.{s}\n", .{ env_name, path, why, team, app_id });
        return err;
    };
}

pub const ProfileError = error{ NotAProfile, WrongAppId, NotDevelopment, NoNetworkExtension };

/// Checks a .mobileprovision (a CMS envelope around a plain XML plist, so
/// the plist is searched in the raw bytes): a development profile whose
/// App ID covers <team>.<app_id> (exactly or as a <team>.* wildcard), with
/// the packet tunnel when `network_extension`.
pub fn checkProfile(bytes: []const u8, team: []const u8, app_id: []const u8, network_extension: bool) ProfileError!void {
    const id = plistString(bytes, "application-identifier") orelse return error.NotAProfile;
    const dot = std.mem.indexOfScalar(u8, id, '.') orelse return error.WrongAppId;
    if (!std.mem.eql(u8, id[0..dot], team)) return error.WrongAppId;
    const pattern = id[dot + 1 ..];
    const covers = if (std.mem.endsWith(u8, pattern, "*"))
        std.mem.startsWith(u8, app_id, pattern[0 .. pattern.len - 1])
    else
        std.mem.eql(u8, pattern, app_id);
    if (!covers) return error.WrongAppId;
    if (!plistTrue(bytes, "get-task-allow")) return error.NotDevelopment;
    if (network_extension and std.mem.indexOf(u8, bytes, "<string>packet-tunnel-provider</string>") == null)
        return error.NoNetworkExtension;
}

/// The string value of the first `<key>key</key>` in an XML plist (or the
/// first string of an array value); null when absent or not a string.
pub fn plistString(text: []const u8, key: []const u8) ?[]const u8 {
    var v = plistValue(text, key) orelse return null;
    if (std.mem.startsWith(u8, v, "<array>")) v = std.mem.trimStart(u8, v["<array>".len..], " \t\r\n");
    if (!std.mem.startsWith(u8, v, "<string>")) return null;
    const rest = v["<string>".len..];
    const end = std.mem.indexOf(u8, rest, "</string>") orelse return null;
    return rest[0..end];
}

fn plistTrue(text: []const u8, key: []const u8) bool {
    const v = plistValue(text, key) orelse return false;
    return std.mem.startsWith(u8, v, "<true/>");
}

/// The text after the first `<key>key</key>`, leading whitespace skipped.
fn plistValue(text: []const u8, key: []const u8) ?[]const u8 {
    var start: usize = 0;
    while (std.mem.indexOfPos(u8, text, start, "<key>")) |k| {
        const name_start = k + "<key>".len;
        const name_end = std.mem.indexOfPos(u8, text, name_start, "</key>") orelse return null;
        start = name_end + "</key>".len;
        if (std.mem.eql(u8, text[name_start..name_end], key))
            return std.mem.trimStart(u8, text[start..], " \t\r\n");
    }
    return null;
}

fn usage() error{Usage} {
    std.debug.print(
        \\usage: portal-ios-sign [<Portal.app> [<out dir> [<bundle id> [<tunnel 0|1>]]]]
        \\  defaults: Portal.app next to this program, out dir "signed" next to the app,
        \\  the app's own bundle id, the tunnel if the app has PlugIns/PortalTunnel.appex
        \\  env: PORTAL_SIGN_IDENTITY, PORTAL_PROVISIONING_PROFILE, PORTAL_TEAM_ID,
        \\       PORTAL_TUNNEL_PROVISIONING_PROFILE (with the tunnel extension)
        \\
    , .{});
    return error.Usage;
}

fn missing(name: []const u8) error{MissingEnvironment} {
    std.debug.print("ios-sign: set {s} (see docs/ios-native.md, \"Build, sign, install\")\n", .{name});
    return error.MissingEnvironment;
}

fn run(io: Io, argv: []const []const u8) !void {
    var child = try std.process.spawn(io, .{ .argv = argv });
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code == 0) return,
        else => {},
    }
    std.debug.print("ios-sign: {s} failed\n", .{argv[0]});
    return error.CommandFailed;
}

/// The development entitlements (an XML property list) of the bundle with
/// id `bundle_id`; `keychain_id` names the Keychain group (the app's
/// bundle id for both the app and its extension, so they share it).
pub fn entitlements(gpa: std.mem.Allocator, team: []const u8, bundle_id: []const u8, keychain_id: []const u8, tunnel: bool) ![]u8 {
    const ne = if (tunnel)
        \\    <key>com.apple.developer.networking.networkextension</key>
        \\    <array>
        \\        <string>packet-tunnel-provider</string>
        \\    </array>
        \\
    else
        "";
    return std.fmt.allocPrint(gpa,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<plist version="1.0">
        \\<dict>
        \\    <key>application-identifier</key>
        \\    <string>{s}.{s}</string>
        \\    <key>com.apple.developer.team-identifier</key>
        \\    <string>{s}</string>
        \\    <key>get-task-allow</key>
        \\    <true/>
        \\    <key>keychain-access-groups</key>
        \\    <array>
        \\        <string>{s}.{s}</string>
        \\    </array>
        \\{s}</dict>
        \\</plist>
        \\
    , .{ team, bundle_id, team, team, keychain_id, ne });
}

const testing = std.testing;

fn expectEntitlements(text: []const u8, app_id: []const u8, keychain_group: []const u8, tunnel: bool) !void {
    try testing.expect(std.mem.startsWith(u8, text, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist"));
    try testing.expectEqualStrings(app_id, plistString(text, "application-identifier").?);
    try testing.expectEqualStrings("ABCDE12345", plistString(text, "com.apple.developer.team-identifier").?);
    try testing.expect(plistTrue(text, "get-task-allow"));
    try testing.expectEqualStrings(keychain_group, plistString(text, "keychain-access-groups").?);
    if (tunnel) {
        try testing.expectEqualStrings("packet-tunnel-provider", plistString(text, "com.apple.developer.networking.networkextension").?);
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "<string>packet-tunnel-provider</string>"));
    } else {
        try testing.expect(std.mem.indexOf(u8, text, "networkextension") == null);
    }
    // Nothing else: no application groups, no distribution keys.
    try testing.expectEqual(@as(usize, if (tunnel) 5 else 4), std.mem.count(u8, text, "<key>"));
}

test "entitlements: app with the tunnel" {
    const t = try entitlements(testing.allocator, "ABCDE12345", "dev.example.portal", "dev.example.portal", true);
    defer testing.allocator.free(t);
    try expectEntitlements(t, "ABCDE12345.dev.example.portal", "ABCDE12345.dev.example.portal", true);
}

test "entitlements: app without the tunnel" {
    const u = try entitlements(testing.allocator, "ABCDE12345", "dev.example.portal", "dev.example.portal", false);
    defer testing.allocator.free(u);
    try expectEntitlements(u, "ABCDE12345.dev.example.portal", "ABCDE12345.dev.example.portal", false);
}

test "entitlements: extension has its own App ID and the app's Keychain group" {
    const e = try entitlements(testing.allocator, "ABCDE12345", "dev.example.portal.tunnel", "dev.example.portal", true);
    defer testing.allocator.free(e);
    try expectEntitlements(e, "ABCDE12345.dev.example.portal.tunnel", "ABCDE12345.dev.example.portal", true);
}

/// A profile's plist as Apple writes it, inside a stand-in for the CMS
/// envelope (abbreviated).
fn testProfile(comptime app_id: []const u8, comptime dev: bool, comptime ne: bool) []const u8 {
    return "\x30\x82\x01\x02cms-header<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n" ++
        "\t<key>AppIDName</key>\n\t<string>Portal</string>\n" ++
        "\t<key>Entitlements</key>\n\t<dict>\n" ++
        (if (ne) "\t\t<key>com.apple.developer.networking.networkextension</key>\n\t\t<array>\n\t\t\t<string>packet-tunnel-provider</string>\n\t\t\t<string>app-proxy-provider</string>\n\t\t</array>\n" else "") ++
        "\t\t<key>application-identifier</key>\n\t\t<string>" ++ app_id ++ "</string>\n" ++
        "\t\t<key>keychain-access-groups</key>\n\t\t<array>\n\t\t\t<string>ABCDE12345.*</string>\n\t\t</array>\n" ++
        "\t\t<key>get-task-allow</key>\n\t\t" ++ (if (dev) "<true/>" else "<false/>") ++ "\n" ++
        "\t\t<key>com.apple.developer.team-identifier</key>\n\t\t<string>ABCDE12345</string>\n" ++
        "\t</dict>\n</dict>\n</plist>\x00\x01trailer";
}

test "checkProfile" {
    const team = "ABCDE12345";
    try checkProfile(testProfile("ABCDE12345.dev.example.portal", true, false), team, "dev.example.portal", false);
    try checkProfile(testProfile("ABCDE12345.dev.example.portal", true, true), team, "dev.example.portal", true);
    try checkProfile(testProfile("ABCDE12345.dev.example.portal.tunnel", true, true), team, "dev.example.portal.tunnel", true);
    try checkProfile(testProfile("ABCDE12345.*", true, false), team, "dev.example.portal", false);
    // The app's profile given for the extension, and the other way round.
    try testing.expectError(error.WrongAppId, checkProfile(testProfile("ABCDE12345.dev.example.portal", true, true), team, "dev.example.portal.tunnel", true));
    try testing.expectError(error.WrongAppId, checkProfile(testProfile("ABCDE12345.dev.example.portal.tunnel", true, true), team, "dev.example.portal", true));
    try testing.expectError(error.WrongAppId, checkProfile(testProfile("ZZZZZ99999.dev.example.portal", true, false), team, "dev.example.portal", false));
    try testing.expectError(error.NotDevelopment, checkProfile(testProfile("ABCDE12345.dev.example.portal", false, false), team, "dev.example.portal", false));
    try testing.expectError(error.NoNetworkExtension, checkProfile(testProfile("ABCDE12345.dev.example.portal.tunnel", true, false), team, "dev.example.portal.tunnel", true));
    try testing.expectError(error.NotAProfile, checkProfile("not a profile", team, "dev.example.portal", false));
}

test "plistString reads the app's Info.plist" {
    const info =
        \\<dict>
        \\    <key>CFBundleExecutable</key><string>Portal</string>
        \\    <key>CFBundleIdentifier</key><string>dev.example.portal</string>
        \\</dict>
    ;
    try testing.expectEqualStrings("dev.example.portal", plistString(info, "CFBundleIdentifier").?);
    try testing.expectEqualStrings("Portal", plistString(info, "CFBundleExecutable").?);
    try testing.expect(plistString(info, "CFBundleName") == null);
}
