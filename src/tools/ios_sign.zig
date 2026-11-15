//! `zig build ios-sign` and the Mac kit's `portal-ios-sign` (`zig build
//! ios-kit`): signs the built Portal.app for the owner's iPhone and, with
//! --install, puts it on the phone (run on the Mac; codesign, security and
//! devicectl are Apple's).
//!
//!   portal-ios-sign [--config <file>] [--install] [--launch] [--device <id>]
//!                   [--account paid|free] [--team-id <id>] [--identity <name|SHA-1>]
//!                   [--profile <file>] [--tunnel-profile <file>]
//!                   [--bundle-id <id>] [--app <Portal.app>] [--out <dir>]
//!   portal-ios-sign <Portal.app> <out dir> <bundle id> <tunnel 0|1>   (zig build ios-sign)
//!
//! Settings, first found wins: the flags, the config file (--config, else
//! portal-ios.conf in the current directory, else next to this program;
//! docs/portal-ios.conf.example), the environment (PORTAL_TEAM_ID,
//! PORTAL_ACCOUNT, PORTAL_SIGN_IDENTITY, PORTAL_PROVISIONING_PROFILE,
//! PORTAL_TUNNEL_PROVISIONING_PROFILE). Nothing is stored in the repo.
//! Required: the team id and the account (paid: the app and its tunnel
//! extension, when the app holds PlugIns/PortalTunnel.appex; free: the app
//! only). Found when not given: the signing identity (the Apple
//! Development identity the chosen profile was made for), the profiles
//! (the best valid ones in ~/Library/MobileDevice/Provisioning Profiles
//! and ~/Library/Developer/Xcode/UserData/Provisioning Profiles), the
//! iPhone (the only connected one of `devicectl list devices`).
//!
//! Each profile must be a development profile of the team whose App ID
//! covers the bundle id (resp. <bundle id>.tunnel), not expired, made for
//! the identity's certificate, listing the iPhone (with --install), whose
//! keychain-access-groups cover <team>.<bundle id> and, for the tunnel,
//! with the packet-tunnel-provider Network Extension.
//!
//! Steps: copy the app to <out dir>/Portal.app (default "signed" next to
//! the app), clear extended attributes, make the executables executable
//! (a bundle copied from Windows loses the mode bits), embed the profiles,
//! write the entitlements (application id, team, get-task-allow, one
//! Keychain group shared by app and extension, the packet-tunnel
//! entitlement on both with the tunnel), sign every dylib/framework in
//! Frameworks/, then the extension, then the app (which seals every other
//! file as a resource: Info.plist, the icons, stt/ggml-tiny.en.bin,
//! Licenses.txt), verify; with --install install it on the iPhone (and
//! with --launch start it).
//!
//! Everything that decides what to run (settings, identity, profile and
//! device choice, entitlements, every argv) is a pure function with host
//! tests below; main only reads files and runs the commands.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const config_name = "portal-ios.conf";

// ------------------------------------------------------------- settings

pub const Account = enum { paid, free };

/// Everything the owner can set; null = not set at this level.
pub const Settings = struct {
    config: ?[]const u8 = null,
    app: ?[]const u8 = null,
    out: ?[]const u8 = null,
    bundle_id: ?[]const u8 = null,
    team_id: ?[]const u8 = null,
    identity: ?[]const u8 = null,
    account: ?Account = null,
    profile: ?[]const u8 = null,
    tunnel_profile: ?[]const u8 = null,
    device: ?[]const u8 = null,
    install: ?bool = null,
    launch: ?bool = null,
    help: bool = false,

    /// `s` with every unset field taken from `lower`.
    pub fn over(s: Settings, lower: Settings) Settings {
        var r = s;
        const info = @typeInfo(Settings).@"struct";
        inline for (info.field_names, info.field_types) |name, T| {
            if (@typeInfo(T) == .optional and @field(r, name) == null)
                @field(r, name) = @field(lower, name);
        }
        return r;
    }
};

/// What went wrong while parsing, for the message.
pub const Diag = struct {
    line: usize = 0,
    what: []const u8 = "",
};

pub const ParseError = error{ BadConfig, OutOfMemory };

/// The config file: `key = value` lines, `#` comment lines, blank lines;
/// a value may be in double quotes, an empty value is "not set". Relative
/// paths (and `~/`) are resolved against `base_dir` (the file's directory)
/// and `home`.
pub fn parseConfig(arena: Allocator, text: []const u8, base_dir: []const u8, home: ?[]const u8, diag: *Diag) ParseError!Settings {
    var s: Settings = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (lines.next()) |raw| {
        n += 1;
        diag.line = n;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse {
            diag.what = "expected key = value";
            return error.BadConfig;
        };
        const key = std.mem.trim(u8, line[0..eq], " \t");
        var value = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') value = value[1 .. value.len - 1];
        if (std.mem.eql(u8, key, "team_id")) {
            s.team_id = nonEmpty(value);
        } else if (std.mem.eql(u8, key, "account")) {
            if (value.len > 0) s.account = std.meta.stringToEnum(Account, value) orelse {
                diag.what = "account must be paid or free";
                return error.BadConfig;
            };
        } else if (std.mem.eql(u8, key, "bundle_id")) {
            s.bundle_id = nonEmpty(value);
        } else if (std.mem.eql(u8, key, "identity")) {
            s.identity = nonEmpty(value);
        } else if (std.mem.eql(u8, key, "profile")) {
            if (value.len > 0) s.profile = try resolvePath(arena, base_dir, home, value);
        } else if (std.mem.eql(u8, key, "tunnel_profile")) {
            if (value.len > 0) s.tunnel_profile = try resolvePath(arena, base_dir, home, value);
        } else if (std.mem.eql(u8, key, "device")) {
            s.device = nonEmpty(value);
        } else if (std.mem.eql(u8, key, "launch")) {
            if (value.len > 0) s.launch = parseBool(value) orelse {
                diag.what = "launch must be yes or no";
                return error.BadConfig;
            };
        } else {
            diag.what = "unknown key (team_id, account, bundle_id, identity, profile, tunnel_profile, device, launch)";
            return error.BadConfig;
        }
    }
    return s;
}

fn nonEmpty(v: []const u8) ?[]const u8 {
    return if (v.len == 0) null else v;
}

fn parseBool(v: []const u8) ?bool {
    if (std.mem.eql(u8, v, "yes") or std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "1")) return true;
    if (std.mem.eql(u8, v, "no") or std.mem.eql(u8, v, "false") or std.mem.eql(u8, v, "0")) return false;
    return null;
}

/// `~/x` -> `<home>/x`, a relative path -> `<base_dir>/path`, else as is.
pub fn resolvePath(arena: Allocator, base_dir: []const u8, home: ?[]const u8, p: []const u8) Allocator.Error![]const u8 {
    if (std.mem.startsWith(u8, p, "~/")) {
        if (home) |h| return std.fs.path.join(arena, &.{ h, p[2..] });
        return p;
    }
    if (p[0] == '/' or std.fs.path.isAbsolute(p)) return p;
    return std.fs.path.join(arena, &.{ base_dir, p });
}

/// The command line. Positional arguments are `zig build ios-sign`'s:
/// <Portal.app> <out dir> <bundle id> <tunnel 0|1> (1 = paid, 0 = free).
pub fn parseArgs(args: []const []const u8, diag: *Diag) error{BadArgs}!Settings {
    var s: Settings = .{};
    var positional: usize = 0;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        diag.what = a;
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            s.help = true;
        } else if (std.mem.eql(u8, a, "--install")) {
            s.install = true;
        } else if (std.mem.eql(u8, a, "--launch")) {
            s.install = true;
            s.launch = true;
        } else if (std.mem.startsWith(u8, a, "--")) {
            i += 1;
            if (i == args.len) return error.BadArgs;
            const v = args[i];
            const name = a[2..];
            if (std.mem.eql(u8, name, "config")) {
                s.config = v;
            } else if (std.mem.eql(u8, name, "app")) {
                s.app = v;
            } else if (std.mem.eql(u8, name, "out")) {
                s.out = v;
            } else if (std.mem.eql(u8, name, "bundle-id")) {
                s.bundle_id = v;
            } else if (std.mem.eql(u8, name, "team-id")) {
                s.team_id = v;
            } else if (std.mem.eql(u8, name, "identity")) {
                s.identity = v;
            } else if (std.mem.eql(u8, name, "account")) {
                s.account = std.meta.stringToEnum(Account, v) orelse return error.BadArgs;
            } else if (std.mem.eql(u8, name, "profile")) {
                s.profile = v;
            } else if (std.mem.eql(u8, name, "tunnel-profile")) {
                s.tunnel_profile = v;
            } else if (std.mem.eql(u8, name, "device")) {
                s.device = v;
            } else return error.BadArgs;
        } else {
            switch (positional) {
                0 => s.app = a,
                1 => s.out = a,
                2 => s.bundle_id = a,
                3 => s.account = if (std.mem.eql(u8, a, "1")) .paid else if (std.mem.eql(u8, a, "0")) .free else return error.BadArgs,
                else => return error.BadArgs,
            }
            positional += 1;
        }
    }
    return s;
}

/// The environment's settings (what `zig build ios-sign` documented).
pub fn envSettings(env: anytype) Settings {
    return .{
        .team_id = env.get("PORTAL_TEAM_ID"),
        .account = if (env.get("PORTAL_ACCOUNT")) |a| std.meta.stringToEnum(Account, a) else null,
        .identity = env.get("PORTAL_SIGN_IDENTITY"),
        .profile = env.get("PORTAL_PROVISIONING_PROFILE"),
        .tunnel_profile = env.get("PORTAL_TUNNEL_PROVISIONING_PROFILE"),
    };
}

/// A team id is 10 uppercase letters and digits.
pub fn validTeamId(t: []const u8) bool {
    if (t.len != 10) return false;
    for (t) |c| if (!std.ascii.isDigit(c) and !std.ascii.isUpper(c)) return false;
    return true;
}

// ------------------------------------------------------------ identities

pub const Identity = struct {
    /// SHA-1 of the certificate, 40 hex digits (what codesign is given:
    /// unambiguous even with two certificates of the same name).
    hash: []const u8,
    name: []const u8,
};

/// The identities in `security find-identity -v -p codesigning` output:
///   `  1) 0123...CDEF "Apple Development: Name (XXXXXXXXXX)"`
pub fn parseIdentities(arena: Allocator, text: []const u8) Allocator.Error![]const Identity {
    var list: std.ArrayList(Identity) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        const paren = std.mem.indexOf(u8, line, ") ") orelse continue;
        if (paren == 0 or !allOf(line[0..paren], std.ascii.isDigit)) continue;
        const rest = std.mem.trimStart(u8, line[paren + 2 ..], " ");
        if (rest.len < 43 or rest[40] != ' ' or rest[41] != '"' or !allOf(rest[0..40], std.ascii.isHex)) continue;
        const name_end = std.mem.lastIndexOfScalar(u8, rest, '"').?;
        if (name_end <= 41) continue;
        try list.append(arena, .{ .hash = rest[0..40], .name = rest[42..name_end] });
    }
    return list.items;
}

fn allOf(s: []const u8, comptime pred: fn (u8) bool) bool {
    for (s) |c| if (!pred(c)) return false;
    return true;
}

/// Identities that sign development builds for a device.
pub fn isDevelopmentIdentity(id: Identity) bool {
    return std.mem.startsWith(u8, id.name, "Apple Development:") or std.mem.startsWith(u8, id.name, "iPhone Developer:");
}

/// The candidates to sign with: the configured identity (its name or its
/// SHA-1) or every development identity. Empty when none matches.
pub fn candidateIdentities(arena: Allocator, all: []const Identity, wanted: ?[]const u8) Allocator.Error![]const Identity {
    var list: std.ArrayList(Identity) = .empty;
    for (all) |id| {
        const ok = if (wanted) |w| std.mem.eql(u8, id.name, w) or std.ascii.eqlIgnoreCase(id.hash, w) else isDevelopmentIdentity(id);
        if (!ok) continue;
        // `security` lists an identity once per keychain it is in.
        for (list.items) |seen| {
            if (std.ascii.eqlIgnoreCase(seen.hash, id.hash)) break;
        } else try list.append(arena, id);
    }
    return list.items;
}

// -------------------------------------------------------------- profiles

/// What the signer needs from a .mobileprovision (a CMS envelope around a
/// plain XML plist, so the plist is read from the raw bytes).
pub const Profile = struct {
    path: []const u8,
    name: []const u8,
    /// `<team>.<bundle id>` or a `<team>.*`-style wildcard.
    app_id: []const u8,
    team: []const u8,
    /// UTC `YYYY-MM-DDTHH:MM:SSZ` ("" when absent).
    expires: []const u8,
    development: bool,
    packet_tunnel: bool,
    keychain_groups: []const []const u8,
    devices: []const []const u8,
    all_devices: bool,
    /// SHA-1 (lowercase hex) of each certificate the profile was made for.
    certs: []const [40]u8,
};

pub fn parseProfile(arena: Allocator, path: []const u8, bytes: []const u8) error{ NotAProfile, OutOfMemory }!Profile {
    const app_id = plistString(bytes, "application-identifier") orelse return error.NotAProfile;
    const dot = std.mem.indexOfScalar(u8, app_id, '.') orelse return error.NotAProfile;
    var certs: std.ArrayList([40]u8) = .empty;
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    for (try plistArray(arena, bytes, "DeveloperCertificates", "data")) |b64| {
        const der = try arena.alloc(u8, decoder.calcSizeUpperBound(b64.len));
        const len = decoder.decode(der, b64) catch continue;
        var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        std.crypto.hash.Sha1.hash(der[0..len], &digest, .{});
        try certs.append(arena, std.fmt.bytesToHex(digest, .lower));
    }
    const ne = try plistArray(arena, bytes, "com.apple.developer.networking.networkextension", "string");
    return .{
        .path = path,
        .name = plistString(bytes, "Name") orelse "",
        .app_id = app_id,
        .team = plistString(bytes, "TeamIdentifier") orelse app_id[0..dot],
        .expires = plistDate(bytes, "ExpirationDate") orelse "",
        .development = plistTrue(bytes, "get-task-allow"),
        .packet_tunnel = for (ne) |v| {
            if (std.mem.eql(u8, v, "packet-tunnel-provider")) break true;
        } else false,
        .keychain_groups = try plistArray(arena, bytes, "keychain-access-groups", "string"),
        .devices = try plistArray(arena, bytes, "ProvisionedDevices", "string"),
        .all_devices = plistTrue(bytes, "ProvisionsAllDevices"),
        .certs = certs.items,
    };
}

/// What one bundle (the app or its extension) needs from its profile.
pub const Need = struct {
    team: []const u8,
    /// The bundle's id: the app's, or `<app's>.tunnel`.
    app_id: []const u8,
    /// The Keychain group without the team: the app's bundle id for both.
    keychain_id: []const u8,
    tunnel: bool,
    /// The iPhone's UDID when installing (the profile must list it).
    device_udid: ?[]const u8 = null,
    /// UTC now, `YYYY-MM-DDTHH:MM:SSZ`.
    now: []const u8,
};

pub const Problem = enum {
    wrong_team,
    wrong_app_id,
    not_development,
    expired,
    no_network_extension,
    no_keychain_group,
    device_not_listed,
    other_certificate,

    pub fn text(p: Problem) []const u8 {
        return switch (p) {
            .wrong_team => "made for another team",
            .wrong_app_id => "its App ID does not cover this bundle id",
            .not_development => "not a development profile (get-task-allow is not true)",
            .expired => "expired",
            .no_network_extension => "its App ID lacks the Network Extensions capability (packet-tunnel-provider)",
            .no_keychain_group => "its keychain-access-groups do not cover the app's group",
            .device_not_listed => "does not list this iPhone (register it, then make the profile again)",
            .other_certificate => "made for another signing certificate than the identity",
        };
    }
};

/// `pattern` (an App ID or Keychain group, `*` wildcard at the end) covers `value`.
fn covers(pattern: []const u8, value: []const u8) bool {
    if (std.mem.endsWith(u8, pattern, "*")) return std.mem.startsWith(u8, value, pattern[0 .. pattern.len - 1]);
    return std.mem.eql(u8, pattern, value);
}

/// `<team>.<rest>` -> rest, or null when `s` is not of `team`.
fn ofTeam(s: []const u8, team: []const u8) ?[]const u8 {
    if (s.len <= team.len or !std.mem.startsWith(u8, s, team) or s[team.len] != '.') return null;
    return s[team.len + 1 ..];
}

/// Why `p` cannot sign the bundle `need` describes with one of
/// `identities`; null when it can.
pub fn profileProblem(p: Profile, need: Need, identities: []const Identity) ?Problem {
    if (!std.mem.eql(u8, p.team, need.team)) return .wrong_team;
    const pattern = ofTeam(p.app_id, need.team) orelse return .wrong_team;
    if (!covers(pattern, need.app_id)) return .wrong_app_id;
    if (!p.development) return .not_development;
    if (p.expires.len == 0 or !std.mem.lessThan(u8, need.now, p.expires)) return .expired;
    if (need.tunnel and !p.packet_tunnel) return .no_network_extension;
    for (p.keychain_groups) |g| {
        if (ofTeam(g, need.team)) |gp| if (covers(gp, need.keychain_id)) break;
    } else return .no_keychain_group;
    if (need.device_udid) |udid| if (!p.all_devices) {
        for (p.devices) |d| {
            if (std.ascii.eqlIgnoreCase(d, udid)) break;
        } else return .device_not_listed;
    };
    for (identities) |id| for (p.certs) |c| {
        if (std.ascii.eqlIgnoreCase(&c, id.hash)) return null;
    };
    return .other_certificate;
}

pub const Choice = struct { profile: Profile, identity: Identity };

pub const ChooseError = error{ NoProfile, AmbiguousIdentity };

/// The profile to sign `need` with, and the identity: of the profiles
/// without a problem, an explicit App ID before a wildcard, then the one
/// that expires last. AmbiguousIdentity: it was made for more than one of
/// `identities` (the owner names one).
pub fn chooseSigning(profiles: []const Profile, identities: []const Identity, need: Need) ChooseError!Choice {
    var best: ?Profile = null;
    for (profiles) |p| {
        if (profileProblem(p, need, identities) != null) continue;
        if (best) |b| {
            const pw = std.mem.endsWith(u8, p.app_id, "*");
            const bw = std.mem.endsWith(u8, b.app_id, "*");
            if (pw != bw) {
                if (pw) continue;
            } else if (!std.mem.lessThan(u8, b.expires, p.expires)) continue;
        }
        best = p;
    }
    const p = best orelse return error.NoProfile;
    var found: ?Identity = null;
    for (identities) |id| for (p.certs) |c| {
        if (!std.ascii.eqlIgnoreCase(&c, id.hash)) continue;
        if (found != null) return error.AmbiguousIdentity;
        found = id;
    };
    return .{ .profile = p, .identity = found.? };
}

/// `secs` (Unix time) as the profiles' UTC `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utcStamp(buf: *[20]u8, secs: u64) []const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year, md.month.numeric(), @as(u8, md.day_index) + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

// --------------------------------------------------------------- devices

pub const Device = struct {
    /// What devicectl's --device takes.
    identifier: []const u8,
    name: []const u8,
    udid: []const u8,
    available: bool,
};

/// The iPhones (and iPads) in `xcrun devicectl list devices --json-output`.
/// Available: devicectl can reach it now (its tunnel state is not
/// "unavailable"), i.e. connected by cable or on the network.
pub fn parseDevices(arena: Allocator, json: []const u8) error{ BadDeviceList, OutOfMemory }![]const Device {
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.BadDeviceList,
    };
    const devices = field(field(root, "result"), "devices") orelse return error.BadDeviceList;
    if (devices != .array) return error.BadDeviceList;
    var list: std.ArrayList(Device) = .empty;
    for (devices.array.items) |d| {
        const hw = field(d, "hardwareProperties");
        if (!std.mem.eql(u8, str(field(hw, "platform")) orelse "", "iOS")) continue;
        const tunnel_state = str(field(field(d, "connectionProperties"), "tunnelState")) orelse "";
        try list.append(arena, .{
            .identifier = str(field(d, "identifier")) orelse continue,
            .name = str(field(field(d, "deviceProperties"), "name")) orelse "",
            .udid = str(field(hw, "udid")) orelse "",
            .available = !std.mem.eql(u8, tunnel_state, "unavailable"),
        });
    }
    return list.items;
}

fn field(v: ?std.json.Value, name: []const u8) ?std.json.Value {
    const o = v orelse return null;
    if (o != .object) return null;
    return o.object.get(name);
}

fn str(v: ?std.json.Value) ?[]const u8 {
    const s = v orelse return null;
    return if (s == .string) s.string else null;
}

pub const DeviceError = error{ NoDevice, AmbiguousDevice, DeviceNotFound };

/// The iPhone to install on: the wanted one (identifier, UDID or name),
/// else the only available one.
pub fn chooseDevice(devices: []const Device, wanted: ?[]const u8) DeviceError!Device {
    if (wanted) |w| {
        for (devices) |d| {
            if (std.mem.eql(u8, d.identifier, w) or std.ascii.eqlIgnoreCase(d.udid, w) or std.mem.eql(u8, d.name, w)) return d;
        }
        return error.DeviceNotFound;
    }
    var found: ?Device = null;
    for (devices) |d| {
        if (!d.available) continue;
        if (found != null) return error.AmbiguousDevice;
        found = d;
    }
    return found orelse error.NoDevice;
}

// -------------------------------------------------------------- commands

pub const find_identity_argv: []const []const u8 = &.{ "security", "find-identity", "-v", "-p", "codesigning" };

pub fn listDevicesArgv(arena: Allocator, json_path: []const u8) Allocator.Error![]const []const u8 {
    return arena.dupe([]const u8, &.{ "xcrun", "devicectl", "list", "devices", "--quiet", "--json-output", json_path });
}

/// Extended attributes (quarantine, Finder info) make codesign refuse.
pub fn clearAttributesArgv(arena: Allocator, app: []const u8) Allocator.Error![]const []const u8 {
    return arena.dupe([]const u8, &.{ "xattr", "-cr", app });
}

pub fn installArgv(arena: Allocator, device: []const u8, app: []const u8) Allocator.Error![]const []const u8 {
    return arena.dupe([]const u8, &.{ "xcrun", "devicectl", "device", "install", "app", "--device", device, app });
}

pub fn launchArgv(arena: Allocator, device: []const u8, bundle_id: []const u8) Allocator.Error![]const []const u8 {
    return arena.dupe([]const u8, &.{ "xcrun", "devicectl", "device", "process", "launch", "--device", device, bundle_id });
}

/// The signed bundle's parts, by path.
pub const Bundle = struct {
    app: []const u8,
    app_entitlements: []const u8,
    /// Frameworks/ entries (each .framework and .dylib).
    frameworks: []const []const u8,
    /// PlugIns/PortalTunnel.appex and its entitlements (the tunnel).
    appex: ?[]const u8 = null,
    appex_entitlements: ?[]const u8 = null,
};

/// The codesign runs, inside out: each framework, the extension, the app
/// (sealing the rest of the bundle as resources), then a strict verify.
pub fn signCommands(arena: Allocator, identity_hash: []const u8, b: Bundle) Allocator.Error![]const []const []const u8 {
    var cmds: std.ArrayList([]const []const u8) = .empty;
    for (b.frameworks) |fw|
        try cmds.append(arena, try arena.dupe([]const u8, &.{ "codesign", "--force", "--timestamp=none", "--sign", identity_hash, fw }));
    if (b.appex) |x|
        try cmds.append(arena, try arena.dupe([]const u8, &.{ "codesign", "--force", "--timestamp=none", "--sign", identity_hash, "--entitlements", b.appex_entitlements.?, x }));
    try cmds.append(arena, try arena.dupe([]const u8, &.{ "codesign", "--force", "--timestamp=none", "--sign", identity_hash, "--entitlements", b.app_entitlements, b.app }));
    try cmds.append(arena, try arena.dupe([]const u8, &.{ "codesign", "--verify", "--deep", "--strict", "--verbose=2", b.app }));
    return cmds.items;
}

/// The development entitlements (an XML property list) of the bundle with
/// id `bundle_id`; `keychain_id` names the Keychain group (the app's
/// bundle id for both the app and its extension, so they share it).
pub fn entitlements(gpa: Allocator, team: []const u8, bundle_id: []const u8, keychain_id: []const u8, tunnel: bool) ![]u8 {
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

/// What to do after signing (and installing).
pub fn nextSteps(arena: Allocator, account: Account, installed: bool, expires: []const u8, app: []const u8) Allocator.Error![]const u8 {
    const head = if (installed)
        "Installed Portal on the iPhone."
    else
        try std.fmt.allocPrint(arena, "Signed {s}. Add --install to put it on the iPhone.", .{app});
    return std.fmt.allocPrint(arena,
        \\
        \\{s}
        \\
        \\Next:
        \\  1. On the iPhone (once): Settings > Privacy & Security > Developer Mode on.
        \\     If iOS says "Untrusted Developer": Settings > General >
        \\     VPN & Device Management > your Apple ID > Trust.
        \\  2. Open Portal: Face ID, then the first-run screen shows the phone's key
        \\     and check code.
        \\  3. At the desk: Pair a device, check that the code matches.
        \\  4. On the phone: Scan QR code, point it at the desk's pairing code, compare
        \\     the desk's check code, Connect.
        \\The profile expires {s}{s}; sign and install again before then.
        \\Logs: Console.app > the iPhone > Start streaming > search "Portal".
        \\
    , .{ head, expires, if (account == .free) " (a free account's profiles last 7 days)" else "" });
}

// ------------------------------------------------------- plist reading

/// The string value of the first `<key>key</key>` in an XML plist (or the
/// first string of an array value); null when absent or not a string.
pub fn plistString(text: []const u8, key: []const u8) ?[]const u8 {
    var v = plistValue(text, key) orelse return null;
    if (std.mem.startsWith(u8, v, "<array>")) v = std.mem.trimStart(u8, v["<array>".len..], " \t\r\n");
    return element(v, "string");
}

fn plistDate(text: []const u8, key: []const u8) ?[]const u8 {
    return element(plistValue(text, key) orelse return null, "date");
}

/// The content of `v`'s leading `<tag>...</tag>`.
fn element(v: []const u8, comptime tag: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, v, "<" ++ tag ++ ">")) return null;
    const rest = v[tag.len + 2 ..];
    const end = std.mem.indexOf(u8, rest, "</" ++ tag ++ ">") orelse return null;
    return rest[0..end];
}

/// The `<tag>` elements of the array that is `key`'s value (none when
/// absent, empty or not an array).
fn plistArray(arena: Allocator, text: []const u8, key: []const u8, comptime tag: []const u8) Allocator.Error![]const []const u8 {
    const v = plistValue(text, key) orelse return &.{};
    if (!std.mem.startsWith(u8, v, "<array>")) return &.{};
    const end = std.mem.indexOf(u8, v, "</array>") orelse return &.{};
    var body = v["<array>".len..end];
    const open = "<" ++ tag ++ ">";
    const close = "</" ++ tag ++ ">";
    var list: std.ArrayList([]const u8) = .empty;
    while (std.mem.indexOf(u8, body, open)) |s| {
        const e = std.mem.indexOfPos(u8, body, s + open.len, close) orelse break;
        try list.append(arena, body[s + open.len .. e]);
        body = body[e + close.len ..];
    }
    return list.items;
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

// ------------------------------------------------------------------ main

const Fail = error{Reported};

fn fail(comptime fmt: []const u8, args: anytype) Fail {
    std.debug.print("portal-ios-sign: " ++ fmt ++ "\n", args);
    return error.Reported;
}

const where = "put it in " ++ config_name ++ " next to this program (copy portal-ios.conf.example), or pass the flag";

pub fn main(init: std.process.Init) !void {
    var arena_state: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena_state.deinit();
    signAndInstall(arena_state.allocator(), init) catch |err| switch (err) {
        error.Reported => std.process.exit(1),
        else => |e| return e,
    };
}

fn signAndInstall(arena: Allocator, init: std.process.Init) !void {
    const io = init.io;
    const cwd = Io.Dir.cwd();
    const env = init.environ_map;
    const home = env.get("HOME");

    const raw_args = try init.minimal.args.toSlice(arena);
    const args = try arena.alloc([]const u8, raw_args.len -| 1);
    for (args, 0..) |*a, i| a.* = raw_args[i + 1];
    var diag: Diag = .{};
    const flags = parseArgs(args, &diag) catch return fail("bad argument near {s} (--help lists them)", .{diag.what});
    if (flags.help) {
        usage();
        return;
    }

    const exe_dir = try std.process.executableDirPathAlloc(io, arena);

    // The config file.
    const config_path: ?[]const u8 = flags.config orelse for ([_][]const u8{ config_name, try std.fs.path.join(arena, &.{ exe_dir, config_name }) }) |p| {
        if (cwd.access(io, p, .{})) |_| break p else |_| {}
    } else null;
    const from_file: Settings = if (config_path) |p| blk: {
        const text = cwd.readFileAlloc(io, p, arena, .limited(1 << 16)) catch |err|
            return fail("cannot read the config {s} ({t})", .{ p, err });
        break :blk parseConfig(arena, text, std.fs.path.dirname(p) orelse ".", home, &diag) catch |err| switch (err) {
            error.BadConfig => return fail("{s}:{d}: {s}", .{ p, diag.line, diag.what }),
            else => |e| return e,
        };
    } else .{};
    const s = flags.over(from_file).over(envSettings(env));

    // The app.
    const app_in = s.app orelse try std.fs.path.join(arena, &.{ exe_dir, "Portal.app" });
    const in_plist = cwd.readFileAlloc(io, try std.fs.path.join(arena, &.{ app_in, "Info.plist" }), arena, .limited(1 << 20)) catch
        return fail("no app at {s} (pass --app <Portal.app>)", .{app_in});
    const plist_id = plistString(in_plist, "CFBundleIdentifier") orelse return fail("{s}/Info.plist has no CFBundleIdentifier", .{app_in});
    const bundle_id = s.bundle_id orelse plist_id;
    if (!std.mem.eql(u8, bundle_id, plist_id))
        return fail("bundle_id {s} does not match the app's {s} (built with -Dios-bundle-id={s}): rebuild the app or fix bundle_id", .{ bundle_id, plist_id, plist_id });
    const tunnel = if (cwd.access(io, try std.fs.path.join(arena, &.{ app_in, "PlugIns", "PortalTunnel.appex" }), .{})) |_| true else |_| false;

    // Account, team.
    const account = s.account orelse
        return fail("say which Apple account signs: account = paid (the app and its tunnel extension) or account = free (the app only); {s} (--account)", .{where});
    if (account == .free and tunnel)
        return fail("this app holds the tunnel extension, which a free account cannot sign (Network Extension entitlement): use a kit built without -Dios-tunnel, or account = paid", .{});
    const team = s.team_id orelse
        return fail("no team id: team_id = <10 characters>; {s} (--team-id). Paid: developer.apple.com > Account > Membership details; free: Keychain Access > your Apple Development certificate > Organizational Unit", .{where});
    if (!validTeamId(team)) return fail("team id {s} is not 10 uppercase letters and digits", .{team});

    var stamp_buf: [20]u8 = undefined;
    const now = utcStamp(&stamp_buf, @intCast(Io.Timestamp.now(io, .real).toSeconds()));

    const out_dir = s.out orelse try std.fs.path.join(arena, &.{ std.fs.path.dirname(app_in) orelse ".", "signed" });
    try cwd.createDirPath(io, out_dir);

    // The iPhone first: the profiles must list it.
    const device: ?Device = if (s.install orelse false) blk: {
        const json_path = try std.fs.path.join(arena, &.{ out_dir, "devices.json" });
        _ = try capture(arena, io, try listDevicesArgv(arena, json_path), "Xcode (from the App Store; open it once)");
        const json = try cwd.readFileAlloc(io, json_path, arena, .limited(1 << 22));
        const devices = parseDevices(arena, json) catch return fail("cannot read devicectl's device list ({s})", .{json_path});
        break :blk chooseDevice(devices, s.device) catch |err| {
            for (devices) |d| std.debug.print("  {s}  {s}  {s}\n", .{ d.identifier, d.name, if (d.available) "connected" else "not connected" });
            return switch (err) {
                error.NoDevice => fail("no iPhone connected: connect it by cable, unlock it, tap Trust", .{}),
                error.AmbiguousDevice => fail("more than one iPhone connected: device = <identifier from the list above>; {s} (--device)", .{where}),
                error.DeviceNotFound => fail("no iPhone {s} (the list is above)", .{s.device.?}),
            };
        };
    } else null;

    // Identities.
    const all_ids = try parseIdentities(arena, try capture(arena, io, find_identity_argv, "the Xcode command-line tools (xcode-select --install)"));
    const ids = try candidateIdentities(arena, all_ids, s.identity);
    if (ids.len == 0) {
        for (all_ids) |id| std.debug.print("  {s} \"{s}\"\n", .{ id.hash, id.name });
        if (s.identity) |w| return fail("no valid signing identity \"{s}\" in the keychain (the valid ones are above)", .{w});
        return fail("no Apple Development identity in the keychain: Xcode > Settings > Accounts > your Apple ID > Manage Certificates > + > Apple Development", .{});
    }

    // Profiles.
    const profiles = try loadProfiles(arena, io, s.profile, home);
    const app_need: Need = .{ .team = team, .app_id = bundle_id, .keychain_id = bundle_id, .tunnel = tunnel, .device_udid = if (device) |d| d.udid else null, .now = now };
    const app_choice = try choose(arena, profiles, ids, app_need, "profile", account, s.profile != null);
    const ext_id = try std.fmt.allocPrint(arena, "{s}.tunnel", .{bundle_id});
    const ext_choice: ?Choice = if (tunnel) blk: {
        const ext_profiles = if (s.tunnel_profile != null) try loadProfiles(arena, io, s.tunnel_profile, home) else profiles;
        var need = app_need;
        need.app_id = ext_id;
        break :blk try choose(arena, ext_profiles, &.{app_choice.identity}, need, "tunnel_profile", account, s.tunnel_profile != null);
    } else null;
    std.debug.print("portal-ios-sign: identity \"{s}\" ({s})\n  app profile \"{s}\" ({s})\n", .{ app_choice.identity.name, app_choice.identity.hash, app_choice.profile.name, app_choice.profile.path });
    if (ext_choice) |c| std.debug.print("  tunnel profile \"{s}\" ({s})\n", .{ c.profile.name, c.profile.path });
    if (device) |d| std.debug.print("  iPhone \"{s}\" ({s})\n", .{ d.name, d.identifier });

    // Copy, entitlements, sign.
    const app = try std.fs.path.join(arena, &.{ out_dir, "Portal.app" });
    cwd.deleteTree(io, app) catch {};
    try copyTree(arena, io, app_in, app);
    try exec(io, try clearAttributesArgv(arena, app));
    try makeExecutable(io, try std.fs.path.join(arena, &.{ app, "Portal" }));
    try cwd.copyFile(app_choice.profile.path, cwd, try std.fs.path.join(arena, &.{ app, "embedded.mobileprovision" }), io, .{});
    const ent_path = try std.fmt.allocPrint(arena, "{s}.entitlements", .{app});
    try cwd.writeFile(io, .{ .sub_path = ent_path, .data = try entitlements(arena, team, bundle_id, bundle_id, tunnel) });

    var bundle: Bundle = .{ .app = app, .app_entitlements = ent_path, .frameworks = try frameworks(arena, io, app) };
    if (ext_choice) |c| {
        const appex = try std.fs.path.join(arena, &.{ app, "PlugIns", "PortalTunnel.appex" });
        try makeExecutable(io, try std.fs.path.join(arena, &.{ appex, "PortalTunnel" }));
        try cwd.copyFile(c.profile.path, cwd, try std.fs.path.join(arena, &.{ appex, "embedded.mobileprovision" }), io, .{});
        const ext_ent = try std.fmt.allocPrint(arena, "{s}.tunnel.entitlements", .{app});
        try cwd.writeFile(io, .{ .sub_path = ext_ent, .data = try entitlements(arena, team, ext_id, bundle_id, true) });
        bundle.appex = appex;
        bundle.appex_entitlements = ext_ent;
    }
    for (try signCommands(arena, app_choice.identity.hash, bundle)) |cmd| try exec(io, cmd);
    std.debug.print("portal-ios-sign: signed {s}\n", .{app});

    // Install, launch.
    if (device) |d| {
        try exec(io, try installArgv(arena, d.identifier, app));
        if (s.launch orelse false) try exec(io, try launchArgv(arena, d.identifier, bundle_id));
    }
    var expires = app_choice.profile.expires;
    if (ext_choice) |c| if (std.mem.lessThan(u8, c.profile.expires, expires)) {
        expires = c.profile.expires;
    };
    std.debug.print("{s}", .{try nextSteps(arena, account, device != null, expires, app)});
}

/// The profile `path` names, or every profile in the two folders Xcode
/// keeps them in.
fn loadProfiles(arena: Allocator, io: Io, path: ?[]const u8, home: ?[]const u8) ![]const Profile {
    const cwd = Io.Dir.cwd();
    var list: std.ArrayList(Profile) = .empty;
    if (path) |p| {
        const bytes = cwd.readFileAlloc(io, p, arena, .limited(1 << 20)) catch |err| return fail("cannot read the profile {s} ({t})", .{ p, err });
        try list.append(arena, parseProfile(arena, p, bytes) catch |err| switch (err) {
            error.NotAProfile => return fail("{s} is not a provisioning profile", .{p}),
            else => |e| return e,
        });
        return list.items;
    }
    const h = home orelse return list.items;
    for ([_][]const u8{ "Library/MobileDevice/Provisioning Profiles", "Library/Developer/Xcode/UserData/Provisioning Profiles" }) |sub| {
        const dir_path = try std.fs.path.join(arena, &.{ h, sub });
        var dir = cwd.openDir(io, dir_path, .{ .iterate = true }) catch continue;
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            if (!std.mem.endsWith(u8, e.name, ".mobileprovision")) continue;
            const p = try std.fs.path.join(arena, &.{ dir_path, e.name });
            const bytes = cwd.readFileAlloc(io, p, arena, .limited(1 << 20)) catch continue;
            const profile = parseProfile(arena, p, bytes) catch |err| switch (err) {
                error.NotAProfile => continue,
                else => |x| return x,
            };
            try list.append(arena, profile);
        }
    }
    return list.items;
}

/// chooseSigning, or a message saying what each near miss lacks and how
/// to get a profile.
fn choose(arena: Allocator, profiles: []const Profile, ids: []const Identity, need: Need, key: []const u8, account: Account, given: bool) !Choice {
    return chooseSigning(profiles, ids, need) catch |err| switch (err) {
        error.AmbiguousIdentity => {
            for (ids) |id| std.debug.print("  {s} \"{s}\"\n", .{ id.hash, id.name });
            return fail("the profile was made for more than one of these identities: identity = <one of the SHA-1s above>; {s} (--identity)", .{where});
        },
        error.NoProfile => {
            var near = false;
            for (profiles) |p| {
                const problem = profileProblem(p, need, ids) orelse continue;
                // Profiles of other apps are not near misses unless named.
                if (!given and (problem == .wrong_team or problem == .wrong_app_id)) continue;
                near = true;
                std.debug.print("  \"{s}\" ({s}): {s}\n", .{ p.name, p.path, problem.text() });
            }
            const how = switch (account) {
                .paid => try std.fmt.allocPrint(arena, "developer.apple.com > Profiles > + > iOS App Development, App ID {s}.{s}{s}, your certificate, your iPhone; then Xcode > Settings > Accounts > Download Manual Profiles (or double-click the download)", .{
                    need.team, need.app_id, if (need.tunnel) " (with the Network Extensions capability)" else "",
                }),
                .free => try std.fmt.allocPrint(arena, "in Xcode make an iOS app with bundle id {s}, team = your Personal Team, and run it on the iPhone once; Xcode keeps its profile", .{need.app_id}),
            };
            return fail("{s} for {s}.{s}. Get one: {s}. Or name the file: {s} = <path>; {s}", .{
                if (near) "no usable provisioning profile (what each one lacks is above)" else "no provisioning profile", need.team, need.app_id, how, key, where,
            });
        },
    };
}

fn frameworks(arena: Allocator, io: Io, app: []const u8) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    const fw_path = try std.fs.path.join(arena, &.{ app, "Frameworks" });
    var fw = Io.Dir.cwd().openDir(io, fw_path, .{ .iterate = true }) catch return list.items;
    defer fw.close(io);
    var it = fw.iterate();
    while (try it.next(io)) |e| {
        const p = try std.fs.path.join(arena, &.{ fw_path, e.name });
        if (std.mem.endsWith(u8, e.name, ".framework")) {
            try makeExecutable(io, try std.fs.path.join(arena, &.{ p, e.name[0 .. e.name.len - ".framework".len] }));
        } else if (std.mem.endsWith(u8, e.name, ".dylib")) {
            try makeExecutable(io, p);
        } else continue;
        try list.append(arena, p);
    }
    std.mem.sort([]const u8, list.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    return list.items;
}

fn copyTree(gpa: Allocator, io: Io, from_path: []const u8, to_path: []const u8) !void {
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

fn usage() void {
    std.debug.print(
        \\usage: portal-ios-sign [--config <file>] [--install] [--launch] [--device <id>]
        \\         [--account paid|free] [--team-id <id>] [--identity <name or SHA-1>]
        \\         [--profile <file>] [--tunnel-profile <file>] [--bundle-id <id>]
        \\         [--app <Portal.app>] [--out <dir>]
        \\  Signs Portal.app (next to this program) into signed/Portal.app; --install puts
        \\  it on the connected iPhone, --launch also starts it. Settings: the flags, then
        \\  portal-ios.conf (current directory, then next to this program; see
        \\  portal-ios.conf.example), then PORTAL_TEAM_ID, PORTAL_ACCOUNT,
        \\  PORTAL_SIGN_IDENTITY, PORTAL_PROVISIONING_PROFILE,
        \\  PORTAL_TUNNEL_PROVISIONING_PROFILE. The identity, profiles and iPhone are
        \\  found when not given.
        \\
    , .{});
}

/// Runs `argv` in this terminal; fails with a message naming it.
fn exec(io: Io, argv: []const []const u8) !void {
    var child = std.process.spawn(io, .{ .argv = argv }) catch |err|
        return fail("cannot run {s} ({t}): install Xcode, or at least its command-line tools (xcode-select --install)", .{ argv[0], err });
    switch (try child.wait(io)) {
        .exited => |code| if (code == 0) return,
        else => {},
    }
    return fail("{s} {s} failed (its message is above)", .{ argv[0], argv[1] });
}

/// Runs `argv` and returns its stdout; fails with its stderr.
fn capture(arena: Allocator, io: Io, argv: []const []const u8, needs: []const u8) ![]const u8 {
    const r = std.process.run(arena, io, .{ .argv = argv }) catch |err|
        return fail("cannot run {s} ({t}): needs {s}", .{ argv[0], err, needs });
    switch (r.term) {
        .exited => |code| if (code == 0) return r.stdout,
        else => {},
    }
    std.debug.print("{s}", .{r.stderr});
    return fail("{s} {s} failed (above)", .{ argv[0], argv[1] });
}

// ----------------------------------------------------------------- tests

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

const team_fixture = "ABCDE12345";
const now_fixture = "2026-11-14T12:00:00Z";
const udid_fixture = "00008110-000A11112222801E";
/// Stand-ins for the DER certificates a profile embeds.
const cert_a = "test certificate A";
const cert_b = "test certificate B";

fn certHash(comptime der: []const u8) [40]u8 {
    @setEvalBranchQuota(100_000);
    var d: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(der, &d, .{});
    return std.fmt.bytesToHex(d, .lower);
}

const hash_a = certHash(cert_a);
const hash_b = certHash(cert_b);

const FixtureProfile = struct {
    name: []const u8 = "Portal Development",
    app_id: []const u8 = "ABCDE12345.dev.example.portal",
    dev: bool = true,
    ne: bool = false,
    keychain: []const u8 = "ABCDE12345.*",
    expires: []const u8 = "2027-01-01T00:00:00Z",
    devices: []const u8 = udid_fixture,
    certs: []const []const u8 = &.{cert_a},
};

/// A profile's plist laid out as Apple writes it, inside a stand-in for
/// the CMS envelope (abbreviated).
fn fixtureProfile(arena: Allocator, f: FixtureProfile) ![]u8 {
    var certs: std.ArrayList(u8) = .empty;
    for (f.certs) |c| {
        const enc = try arena.alloc(u8, std.base64.standard.Encoder.calcSize(c.len));
        // Apple wraps the base64 lines; the reader must skip the whitespace.
        const b64 = std.base64.standard.Encoder.encode(enc, c);
        try certs.print(arena, "\t\t<data>\n\t\t{s}\n\t\t{s}\n\t\t</data>\n", .{ b64[0..8], b64[8..] });
    }
    const ne = "\t\t<key>com.apple.developer.networking.networkextension</key>\n\t\t<array>\n\t\t\t<string>packet-tunnel-provider</string>\n\t\t\t<string>app-proxy-provider</string>\n\t\t</array>\n";
    return std.fmt.allocPrint(arena, "\x30\x82\x01\x02cms-header<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n" ++
        "\t<key>AppIDName</key>\n\t<string>Portal</string>\n" ++
        "\t<key>DeveloperCertificates</key>\n\t<array>\n{s}\t</array>\n" ++
        "\t<key>Entitlements</key>\n\t<dict>\n{s}" ++
        "\t\t<key>application-identifier</key>\n\t\t<string>{s}</string>\n" ++
        "\t\t<key>keychain-access-groups</key>\n\t\t<array>\n\t\t\t<string>{s}</string>\n\t\t</array>\n" ++
        "\t\t<key>get-task-allow</key>\n\t\t{s}\n" ++
        "\t\t<key>com.apple.developer.team-identifier</key>\n\t\t<string>ABCDE12345</string>\n" ++
        "\t</dict>\n" ++
        "\t<key>ExpirationDate</key>\n\t<date>{s}</date>\n" ++
        "\t<key>Name</key>\n\t<string>{s}</string>\n" ++
        "\t<key>ProvisionedDevices</key>\n\t<array>\n\t\t<string>{s}</string>\n\t</array>\n" ++
        "\t<key>TeamIdentifier</key>\n\t<array>\n\t\t<string>{s}</string>\n\t</array>\n" ++
        "</dict>\n</plist>\x00\x01trailer", .{
        certs.items,
        if (f.ne) ne else "",
        f.app_id,
        f.keychain,
        if (f.dev) "<true/>" else "<false/>",
        f.expires,
        f.name,
        f.devices,
        f.app_id[0..10],
    });
}

fn fixture(arena: Allocator, f: FixtureProfile) !Profile {
    return parseProfile(arena, f.name, try fixtureProfile(arena, f));
}

const owner_name = "Apple Development: Example Owner (QWERTY1234)";
const id_a: Identity = .{ .hash = &hash_a, .name = owner_name };
const id_b: Identity = .{ .hash = &hash_b, .name = owner_name };

fn appNeed(tunnel: bool) Need {
    return .{ .team = team_fixture, .app_id = "dev.example.portal", .keychain_id = "dev.example.portal", .tunnel = tunnel, .device_udid = udid_fixture, .now = now_fixture };
}

fn extNeed() Need {
    var n = appNeed(true);
    n.app_id = "dev.example.portal.tunnel";
    return n;
}

test "parseProfile reads what the signer checks" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const p = try fixture(a.allocator(), .{ .ne = true, .certs = &.{ cert_a, cert_b } });
    try testing.expectEqualStrings("Portal Development", p.name);
    try testing.expectEqualStrings("ABCDE12345.dev.example.portal", p.app_id);
    try testing.expectEqualStrings("ABCDE12345", p.team);
    try testing.expectEqualStrings("2027-01-01T00:00:00Z", p.expires);
    try testing.expect(p.development and p.packet_tunnel and !p.all_devices);
    try testing.expectEqual(@as(usize, 1), p.keychain_groups.len);
    try testing.expectEqualStrings(udid_fixture, p.devices[0]);
    try testing.expectEqual(@as(usize, 2), p.certs.len);
    try testing.expectEqualStrings(&hash_a, &p.certs[0]);
    try testing.expectEqualStrings(&hash_b, &p.certs[1]);
    try testing.expectError(error.NotAProfile, parseProfile(a.allocator(), "x", "not a profile"));
}

test "profileProblem: each requirement" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const ids: []const Identity = &.{id_a};
    const none: ?Problem = null;
    try testing.expectEqual(none, profileProblem(try fixture(ar, .{}), appNeed(false), ids));
    try testing.expectEqual(none, profileProblem(try fixture(ar, .{ .ne = true }), appNeed(true), ids));
    try testing.expectEqual(none, profileProblem(try fixture(ar, .{ .app_id = "ABCDE12345.*" }), appNeed(false), ids));
    try testing.expectEqual(none, profileProblem(try fixture(ar, .{ .keychain = "ABCDE12345.dev.example.portal" }), appNeed(false), ids));
    try testing.expectEqual(none, profileProblem(try fixture(ar, .{ .app_id = "ABCDE12345.dev.example.portal.tunnel", .ne = true }), extNeed(), ids));
    // The extension's profile must cover the app's Keychain group too.
    try testing.expectEqual(@as(?Problem, .no_keychain_group), profileProblem(try fixture(ar, .{ .app_id = "ABCDE12345.dev.example.portal.tunnel", .ne = true, .keychain = "ABCDE12345.dev.example.portal.tunnel" }), extNeed(), ids));
    // The app's profile given for the extension, and the other way round.
    try testing.expectEqual(@as(?Problem, .wrong_app_id), profileProblem(try fixture(ar, .{ .ne = true }), extNeed(), ids));
    try testing.expectEqual(@as(?Problem, .wrong_app_id), profileProblem(try fixture(ar, .{ .app_id = "ABCDE12345.dev.example.portal.tunnel", .ne = true }), appNeed(true), ids));
    try testing.expectEqual(@as(?Problem, .wrong_team), profileProblem(try fixture(ar, .{ .app_id = "ZZZZZ99999.dev.example.portal" }), appNeed(false), ids));
    try testing.expectEqual(@as(?Problem, .not_development), profileProblem(try fixture(ar, .{ .dev = false }), appNeed(false), ids));
    try testing.expectEqual(@as(?Problem, .expired), profileProblem(try fixture(ar, .{ .expires = "2026-11-14T11:59:59Z" }), appNeed(false), ids));
    try testing.expectEqual(@as(?Problem, .no_network_extension), profileProblem(try fixture(ar, .{}), appNeed(true), ids));
    try testing.expectEqual(@as(?Problem, .no_keychain_group), profileProblem(try fixture(ar, .{ .keychain = "ABCDE12345.dev.example.other" }), appNeed(false), ids));
    try testing.expectEqual(@as(?Problem, .no_keychain_group), profileProblem(try fixture(ar, .{ .keychain = "ZZZZZ99999.*" }), appNeed(false), ids));
    try testing.expectEqual(@as(?Problem, .device_not_listed), profileProblem(try fixture(ar, .{ .devices = "00008110-OTHERDEVICE0001" }), appNeed(false), ids));
    var no_device = appNeed(false);
    no_device.device_udid = null; // not installing: the device list does not matter
    try testing.expectEqual(none, profileProblem(try fixture(ar, .{ .devices = "00008110-OTHERDEVICE0001" }), no_device, ids));
    try testing.expectEqual(@as(?Problem, .other_certificate), profileProblem(try fixture(ar, .{ .certs = &.{cert_b} }), appNeed(false), ids));
}

test "chooseSigning: newest explicit profile, the identity it was made for" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const profiles = [_]Profile{
        try fixture(ar, .{ .name = "wildcard", .app_id = "ABCDE12345.*", .expires = "2028-01-01T00:00:00Z" }),
        try fixture(ar, .{ .name = "old", .expires = "2026-12-01T00:00:00Z" }),
        try fixture(ar, .{ .name = "new", .expires = "2027-06-01T00:00:00Z", .certs = &.{cert_b} }),
        try fixture(ar, .{ .name = "expired", .expires = "2026-01-01T00:00:00Z" }),
        try fixture(ar, .{ .name = "tunnel", .app_id = "ABCDE12345.dev.example.portal.tunnel", .ne = true, .expires = "2029-01-01T00:00:00Z" }),
    };
    const both: []const Identity = &.{ id_a, id_b };
    const c = try chooseSigning(&profiles, both, appNeed(false));
    try testing.expectEqualStrings("new", c.profile.name);
    try testing.expectEqualStrings(id_b.hash, c.identity.hash);
    // Only identity A: the newest profile made for it.
    try testing.expectEqualStrings("old", (try chooseSigning(&profiles, &.{id_a}, appNeed(false))).profile.name);
    // The wildcard when it is the only one left.
    try testing.expectEqualStrings("wildcard", (try chooseSigning(profiles[0..1], &.{id_a}, appNeed(false))).profile.name);
    // Another iPhone: no profile lists it.
    var other_phone = appNeed(false);
    other_phone.device_udid = "00008110-OTHERDEVICE0001";
    try testing.expectError(error.NoProfile, chooseSigning(&profiles, both, other_phone));
    // The tunnel needs Network Extensions: none of the app's profiles has it.
    try testing.expectError(error.NoProfile, chooseSigning(&profiles, both, appNeed(true)));
    try testing.expectEqualStrings("tunnel", (try chooseSigning(&profiles, &.{id_a}, extNeed())).profile.name);
    // A profile made for both identities: the owner must name one.
    const shared = [_]Profile{try fixture(ar, .{ .certs = &.{ cert_a, cert_b } })};
    try testing.expectError(error.AmbiguousIdentity, chooseSigning(&shared, both, appNeed(false)));
    try testing.expectEqualStrings(id_a.hash, (try chooseSigning(&shared, &.{id_a}, appNeed(false))).identity.hash);
}

test "parseIdentities and candidateIdentities" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var upper: [40]u8 = undefined;
    const text = try std.fmt.allocPrint(ar,
        \\  1) {s} "{s}"
        \\  2) 0123456789ABCDEF0123456789ABCDEF01234567 "Developer ID Application: Example Org (ABCDE12345)"
        \\  3) {s} "{s}"
        \\  4) {s} "{s}"
        \\     4 valid identities found
        \\
    , .{ std.ascii.upperString(&upper, &hash_a), owner_name, &hash_b, owner_name, &hash_a, owner_name });
    const all = try parseIdentities(ar, text);
    try testing.expectEqual(@as(usize, 4), all.len);
    try testing.expectEqualStrings("Developer ID Application: Example Org (ABCDE12345)", all[1].name);
    try testing.expectEqualStrings(owner_name, all[0].name);
    const dev = try candidateIdentities(ar, all, null);
    try testing.expectEqual(@as(usize, 2), dev.len); // A listed twice (two keychains) counts once
    try testing.expect(std.ascii.eqlIgnoreCase(&hash_a, dev[0].hash));
    try testing.expectEqual(@as(usize, 1), (try candidateIdentities(ar, all, &hash_b)).len);
    // Same name, two certificates: the profile decides.
    try testing.expectEqual(@as(usize, 2), (try candidateIdentities(ar, all, owner_name)).len);
    try testing.expectEqual(@as(usize, 0), (try candidateIdentities(ar, all, "Apple Development: Nobody (AAAAAAAAAA)")).len);
    try testing.expectEqual(@as(usize, 0), (try parseIdentities(ar, "     0 valid identities found\n")).len);
}

test "parseConfig" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var d: Diag = .{};
    const s = try parseConfig(ar,
        \\# comment
        \\team_id = ABCDE12345
        \\account = paid
        \\identity = "Apple Development: Example Owner (QWERTY1234)"
        \\
        \\profile = ~/profiles/Portal.mobileprovision
        \\tunnel_profile = PortalTunnel.mobileprovision
        \\device =
        \\launch = yes
    , "/kit", "/home/owner", &d);
    try testing.expectEqualStrings("ABCDE12345", s.team_id.?);
    try testing.expectEqual(Account.paid, s.account.?);
    try testing.expectEqualStrings(owner_name, s.identity.?);
    try testing.expect(std.mem.endsWith(u8, s.profile.?, "Portal.mobileprovision"));
    try testing.expect(std.mem.startsWith(u8, s.profile.?, "/home/owner"));
    try testing.expect(std.mem.startsWith(u8, s.tunnel_profile.?, "/kit"));
    try testing.expect(s.device == null);
    try testing.expect(s.launch.?);
    try testing.expect(s.bundle_id == null);
    try testing.expectEqualStrings("/abs/P.mobileprovision", (try parseConfig(ar, "profile = /abs/P.mobileprovision", "/kit", null, &d)).profile.?);

    try testing.expectError(error.BadConfig, parseConfig(ar, "team_id = ABCDE12345\naccount = gold\n", "/kit", null, &d));
    try testing.expectEqual(@as(usize, 2), d.line);
    try testing.expectError(error.BadConfig, parseConfig(ar, "teamid = ABCDE12345\n", "/kit", null, &d));
    try testing.expectError(error.BadConfig, parseConfig(ar, "just words\n", "/kit", null, &d));
    try testing.expectError(error.BadConfig, parseConfig(ar, "launch = maybe\n", "/kit", null, &d));
}

test "parseArgs, precedence: flags over the file over the environment" {
    var d: Diag = .{};
    const flags = try parseArgs(&.{ "--config", "x.conf", "--install", "--device", "phone", "--account", "free" }, &d);
    try testing.expectEqualStrings("x.conf", flags.config.?);
    try testing.expect(flags.install.? and flags.launch == null);
    try testing.expectEqualStrings("phone", flags.device.?);
    try testing.expectEqual(Account.free, flags.account.?);
    const launch = try parseArgs(&.{"--launch"}, &d);
    try testing.expect(launch.install.? and launch.launch.?);
    // zig build ios-sign's positional form.
    const legacy = try parseArgs(&.{ "/c/Portal.app", "/c/signed", "dev.example.portal", "1" }, &d);
    try testing.expectEqualStrings("/c/Portal.app", legacy.app.?);
    try testing.expectEqualStrings("/c/signed", legacy.out.?);
    try testing.expectEqualStrings("dev.example.portal", legacy.bundle_id.?);
    try testing.expectEqual(Account.paid, legacy.account.?);
    try testing.expectEqual(Account.free, (try parseArgs(&.{ "a", "b", "c", "0" }, &d)).account.?);
    try testing.expectError(error.BadArgs, parseArgs(&.{"--team-id"}, &d));
    try testing.expectError(error.BadArgs, parseArgs(&.{ "--colour", "x" }, &d));
    try testing.expectError(error.BadArgs, parseArgs(&.{ "--account", "gold" }, &d));
    try testing.expectError(error.BadArgs, parseArgs(&.{ "a", "b", "c", "2" }, &d));

    const file: Settings = .{ .team_id = "FILETEAM00", .account = .paid, .launch = true };
    var env_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer env_map.deinit(testing.allocator);
    try env_map.put(testing.allocator, "PORTAL_TEAM_ID", "ENVTEAM000");
    try env_map.put(testing.allocator, "PORTAL_SIGN_IDENTITY", owner_name);
    const s = flags.over(file).over(envSettings(env_map));
    try testing.expectEqualStrings("FILETEAM00", s.team_id.?);
    try testing.expectEqual(Account.free, s.account.?);
    try testing.expectEqualStrings(owner_name, s.identity.?);
    try testing.expect(s.launch.?);
    try testing.expect(validTeamId("ABCDE12345"));
    try testing.expect(!validTeamId("abcde12345") and !validTeamId("ABCDE1234"));
}

test "parseDevices and chooseDevice" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const json =
        \\{"info":{"outcome":"success"},"result":{"devices":[
        \\ {"identifier":"11111111-2222-3333-4444-555555555555","deviceProperties":{"name":"Example iPhone"},
        \\  "hardwareProperties":{"platform":"iOS","udid":"00008110-000A11112222801E"},
        \\  "connectionProperties":{"pairingState":"paired","tunnelState":"disconnected","transportType":"wired"}},
        \\ {"identifier":"66666666-7777-8888-9999-000000000000","deviceProperties":{"name":"Old iPhone"},
        \\  "hardwareProperties":{"platform":"iOS","udid":"00008030-000B33334444802E"},
        \\  "connectionProperties":{"pairingState":"paired","tunnelState":"unavailable"}},
        \\ {"identifier":"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE","deviceProperties":{"name":"Example Watch"},
        \\  "hardwareProperties":{"platform":"watchOS","udid":"00008301-000C"},
        \\  "connectionProperties":{"tunnelState":"connected"}}
        \\]}}
    ;
    const devs = try parseDevices(ar, json);
    try testing.expectEqual(@as(usize, 2), devs.len);
    const d = try chooseDevice(devs, null);
    try testing.expectEqualStrings("11111111-2222-3333-4444-555555555555", d.identifier);
    try testing.expectEqualStrings(udid_fixture, d.udid);
    try testing.expectEqualStrings("Old iPhone", (try chooseDevice(devs, "Old iPhone")).name);
    try testing.expectEqualStrings("Old iPhone", (try chooseDevice(devs, "00008030-000b33334444802e")).name);
    try testing.expectError(error.DeviceNotFound, chooseDevice(devs, "nope"));
    try testing.expectError(error.NoDevice, chooseDevice(devs[1..], null));
    const two = [_]Device{ devs[0], devs[0] };
    try testing.expectError(error.AmbiguousDevice, chooseDevice(&two, null));
    try testing.expectError(error.BadDeviceList, parseDevices(ar, "not json"));
    try testing.expectError(error.BadDeviceList, parseDevices(ar, "{\"result\":{}}"));
}

fn expectArgv(want: []const []const u8, got: []const []const u8) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| try testing.expectEqualStrings(w, g);
}

test "signCommands: frameworks, extension, app, verify" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const h = "0123456789abcdef0123456789abcdef01234567";
    const cmds = try signCommands(ar, h, .{
        .app = "out/Portal.app",
        .app_entitlements = "out/Portal.app.entitlements",
        .frameworks = &.{"out/Portal.app/Frameworks/MoltenVK.framework"},
        .appex = "out/Portal.app/PlugIns/PortalTunnel.appex",
        .appex_entitlements = "out/Portal.app.tunnel.entitlements",
    });
    try testing.expectEqual(@as(usize, 4), cmds.len);
    try expectArgv(&.{ "codesign", "--force", "--timestamp=none", "--sign", h, "out/Portal.app/Frameworks/MoltenVK.framework" }, cmds[0]);
    try expectArgv(&.{ "codesign", "--force", "--timestamp=none", "--sign", h, "--entitlements", "out/Portal.app.tunnel.entitlements", "out/Portal.app/PlugIns/PortalTunnel.appex" }, cmds[1]);
    try expectArgv(&.{ "codesign", "--force", "--timestamp=none", "--sign", h, "--entitlements", "out/Portal.app.entitlements", "out/Portal.app" }, cmds[2]);
    try expectArgv(&.{ "codesign", "--verify", "--deep", "--strict", "--verbose=2", "out/Portal.app" }, cmds[3]);
    // Free account: no extension.
    const free = try signCommands(ar, h, .{ .app = "out/Portal.app", .app_entitlements = "out/Portal.app.entitlements", .frameworks = &.{"out/Portal.app/Frameworks/libMoltenVK.dylib"} });
    try testing.expectEqual(@as(usize, 3), free.len);
    try expectArgv(&.{ "codesign", "--force", "--timestamp=none", "--sign", h, "out/Portal.app/Frameworks/libMoltenVK.dylib" }, free[0]);
    try expectArgv(&.{ "codesign", "--force", "--timestamp=none", "--sign", h, "--entitlements", "out/Portal.app.entitlements", "out/Portal.app" }, free[1]);
}

test "devicectl, security and xattr argv" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try expectArgv(&.{ "xcrun", "devicectl", "device", "install", "app", "--device", "1111-2222", "out/Portal.app" }, try installArgv(ar, "1111-2222", "out/Portal.app"));
    try expectArgv(&.{ "xcrun", "devicectl", "device", "process", "launch", "--device", "1111-2222", "dev.example.portal" }, try launchArgv(ar, "1111-2222", "dev.example.portal"));
    try expectArgv(&.{ "xcrun", "devicectl", "list", "devices", "--quiet", "--json-output", "out/devices.json" }, try listDevicesArgv(ar, "out/devices.json"));
    try expectArgv(&.{ "xattr", "-cr", "out/Portal.app" }, try clearAttributesArgv(ar, "out/Portal.app"));
    try expectArgv(&.{ "security", "find-identity", "-v", "-p", "codesigning" }, find_identity_argv);
}

test "nextSteps" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const free = try nextSteps(a.allocator(), .free, true, "2026-11-21T12:00:00Z", "out/Portal.app");
    try testing.expect(std.mem.indexOf(u8, free, "Installed Portal") != null);
    try testing.expect(std.mem.indexOf(u8, free, "2026-11-21T12:00:00Z (a free account's profiles last 7 days)") != null);
    const paid = try nextSteps(a.allocator(), .paid, false, "2027-11-14T00:00:00Z", "out/Portal.app");
    try testing.expect(std.mem.indexOf(u8, paid, "Signed out/Portal.app. Add --install") != null);
    try testing.expect(std.mem.indexOf(u8, paid, "7 days") == null);
}

test "utcStamp matches the profiles' date format" {
    var buf: [20]u8 = undefined;
    try testing.expectEqualStrings("1970-01-01T00:00:00Z", utcStamp(&buf, 0));
    try testing.expectEqualStrings("2026-11-14T12:00:00Z", utcStamp(&buf, 1794657600));
    try testing.expectEqualStrings("2028-02-29T23:59:59Z", utcStamp(&buf, 1835481599));
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
