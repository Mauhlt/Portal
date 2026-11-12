//! `zig build ios-sign`: signs the built Portal.app for the owner's
//! iPhone (run on the Mac; codesign is Apple's).
//!
//!   ios-sign <Portal.app> <out dir> <bundle id> <tunnel: 0|1>
//!
//! Copies the app to <out dir>/Portal.app and signs the copy.
//!
//! Environment (nothing is stored in the repo):
//!   PORTAL_SIGN_IDENTITY        e.g. "Apple Development: Name (ABCDE12345)"
//!                               (`security find-identity -v -p codesigning`)
//!   PORTAL_PROVISIONING_PROFILE path to the .mobileprovision for the bundle
//!                               id (a development profile listing the
//!                               iPhone; a free Apple ID's Xcode-made
//!                               profile works without the tunnel)
//!   PORTAL_TEAM_ID              the 10-character team id
//!
//! Steps: embed the profile, write the entitlements (application id, team,
//! get-task-allow for a development install, the Keychain group, and the
//! packet-tunnel entitlement only when built with the tunnel), sign every
//! dylib/framework in Frameworks/, sign the app, verify.

const std = @import("std");
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer args.deinit();
    _ = args.next();
    const app_in = args.next() orelse return usage();
    const out_dir = args.next() orelse return usage();
    const bundle_id = args.next() orelse return usage();
    const tunnel = std.mem.eql(u8, args.next() orelse "0", "1");

    const env = init.environ_map;
    const identity = env.get("PORTAL_SIGN_IDENTITY") orelse return missing("PORTAL_SIGN_IDENTITY");
    const profile = env.get("PORTAL_PROVISIONING_PROFILE") orelse return missing("PORTAL_PROVISIONING_PROFILE");
    const team = env.get("PORTAL_TEAM_ID") orelse return missing("PORTAL_TEAM_ID");

    const cwd = Io.Dir.cwd();
    const app = try std.fs.path.join(gpa, &.{ out_dir, "Portal.app" });
    defer gpa.free(app);
    try copyTree(gpa, io, app_in, app);
    const embedded = try std.fs.path.join(gpa, &.{ app, "embedded.mobileprovision" });
    defer gpa.free(embedded);
    try cwd.copyFile(profile, cwd, embedded, io, .{});

    const ent_text = try entitlements(gpa, team, bundle_id, tunnel);
    defer gpa.free(ent_text);
    const ent_path = try std.fmt.allocPrint(gpa, "{s}.entitlements", .{app});
    defer gpa.free(ent_path);
    try cwd.writeFile(io, .{ .sub_path = ent_path, .data = ent_text });

    // The tunnel extension (built with -Dios-tunnel): its own entitlements.
    const appex = try std.fs.path.join(gpa, &.{ app, "PlugIns", "PortalTunnel.appex" });
    defer gpa.free(appex);
    if (cwd.access(io, appex, .{})) |_| {
        const ext_id = try std.fmt.allocPrint(gpa, "{s}.tunnel", .{bundle_id});
        defer gpa.free(ext_id);
        const ext_ent = try entitlements(gpa, team, ext_id, true);
        defer gpa.free(ext_ent);
        const ext_ent_path = try std.fmt.allocPrint(gpa, "{s}.tunnel.entitlements", .{app});
        defer gpa.free(ext_ent_path);
        try cwd.writeFile(io, .{ .sub_path = ext_ent_path, .data = ext_ent });
        try run(io, &.{ "codesign", "--force", "--timestamp=none", "--sign", identity, "--entitlements", ext_ent_path, appex });
    } else |_| {}

    // Frameworks first (inside out), then the app.
    const fw_path = try std.fs.path.join(gpa, &.{ app, "Frameworks" });
    defer gpa.free(fw_path);
    if (cwd.openDir(io, fw_path, .{ .iterate = true })) |fw_const| {
        var fw = fw_const;
        defer fw.close(io);
        var it = fw.iterate();
        while (try it.next(io)) |e| {
            const p = try std.fs.path.join(gpa, &.{ fw_path, e.name });
            defer gpa.free(p);
            try run(io, &.{ "codesign", "--force", "--timestamp=none", "--sign", identity, p });
        }
    } else |_| {}
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

fn usage() error{Usage} {
    std.debug.print("usage: ios-sign <Portal.app> <out dir> <bundle id> <tunnel 0|1>\n", .{});
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

/// The development entitlements (an XML property list).
pub fn entitlements(gpa: std.mem.Allocator, team: []const u8, bundle_id: []const u8, tunnel: bool) ![]u8 {
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
    , .{ team, bundle_id, team, team, bundle_id, ne });
}

test "entitlements" {
    const t = try entitlements(std.testing.allocator, "ABCDE12345", "dev.example.portal", true);
    defer std.testing.allocator.free(t);
    try std.testing.expect(std.mem.indexOf(u8, t, "<string>ABCDE12345.dev.example.portal</string>") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "packet-tunnel-provider") != null);
    const u = try entitlements(std.testing.allocator, "ABCDE12345", "dev.example.portal", false);
    defer std.testing.allocator.free(u);
    try std.testing.expect(std.mem.indexOf(u8, u, "networkextension") == null);
}
