//! portalctl's sync commands (docs/sync-design.md):
//!
//!   desktop
//!     portalctl sync key [show | init [--force]]
//!     portalctl publish <package> <folder> --kind data|executable [--version V] [--min-client V]
//!     portalctl publish --list
//!     portalctl unpublish <package> <version>
//!     portalctl sync subscribe <device> <package>
//!     portalctl sync unsubscribe <device> <package>
//!     portalctl sync subscriptions
//!
//!   device (headless; the same code `portal connect` runs, for tests)
//!     portalctl sync-device [--pairing-code CODE] | --key
//!         [--approve] [--wait-updates SECONDS] [--only PACKAGE]
//!     portalctl sync-device --rollback PACKAGE | --revoke PACKAGE | --status
//!     portalctl sync-device --forget
//!
//!   Each desktop has its own store on the device (client/src/sync/keypin.zig,
//!   desktopRoot); the device reaches its desktop through its own tunnel
//!   (client/src/devicelink.zig), like `portal connect`.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const sync = @import("sync.zig");
const devices = @import("devices.zig");
const client = @import("client");
const manifest = client.sync.manifest;

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("portalctl: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

fn nowUnix(io: Io) i64 {
    return Io.Timestamp.now(io, .real).toSeconds();
}

fn fingerprintText(key: [32]u8, buf: *[95]u8) []const u8 {
    return manifest.formatFingerprint(manifest.fingerprint(key), buf);
}

fn describe(err: anyerror) []const u8 {
    return switch (err) {
        error.NoSyncKey => "no release key yet: run `portalctl sync key init` (Portal also creates one when it starts)",
        error.SyncKeyMismatch, error.BadSyncKey => "the release key in sync-key\\ is damaged (release.key does not match release.pub)",
        error.DpapiUnprotectFailed => "cannot decrypt the release key (it belongs to another Windows account or machine)",
        error.VersionUsed => "that version name was already published for this package (names are never reused)",
        error.EmptyFolder => "the folder has no files",
        error.BadPackageId => "bad package id (a-z, 0-9 and -, at most 32)",
        error.BadVersion => "bad version (0-9, A-Z, a-z, '.', '+', '-', at most 64, no '..')",
        error.BadClientVersion => "bad --min-client (e.g. 0.1.0)",
        error.TooLarge => "the package is over the size limit",
        error.TooManyFiles => "too many files (at most 4096)",
        error.NotPublished => "no such published version",
        error.SyncStoreBusy => "the sync store is held open by an older Portal process; close it and try again",
        else => @errorName(err),
    };
}

// ----------------------------------------------------------------- desktop

pub fn cmdSync(gpa: Allocator, io: Io, paths: sync.Paths, args: []const []const u8) !void {
    const sub = if (args.len > 0) args[0] else "";
    const rest = if (args.len > 0) args[1..] else args;
    if (std.mem.eql(u8, sub, "key")) return cmdKey(gpa, io, paths, rest);
    if (std.mem.eql(u8, sub, "subscribe") or std.mem.eql(u8, sub, "unsubscribe")) {
        if (rest.len != 2) fatal("usage: portalctl sync {s} <device> <package>", .{sub});
        const on = sub[0] == 's';
        if (!devices.validName(rest[0])) fatal("bad device name '{s}'", .{rest[0]});
        if (!manifest.validPackageId(rest[1])) fatal("{s}", .{describe(error.BadPackageId)});
        const changed = sync.subscribe(gpa, io, paths, rest[0], rest[1], on) catch |err| fatal("could not update the subscriptions: {s}", .{describe(err)});
        std.debug.print("{s} '{s}' {s} '{s}'{s}\n", .{
            if (on) "Subscribed" else "Unsubscribed", rest[0], if (on) "to" else "from", rest[1],
            if (changed) "" else " (no change)",
        });
        return;
    }
    if (std.mem.eql(u8, sub, "subscriptions")) {
        const s = sync.readSubs(gpa, io, paths) catch |err| fatal("cannot read the subscriptions: {s}", .{describe(err)});
        if (s.n == 0) std.debug.print("No subscriptions. Add one with `portalctl sync subscribe <device> <package>`.\n", .{});
        for (s.items[0..s.n]) |x| std.debug.print("  {s: <20} {s}\n", .{ x.device.get(), x.package.get() });
        return;
    }
    fatal("usage: portalctl sync key [show|init [--force]] | subscribe <device> <package> | unsubscribe <device> <package> | subscriptions", .{});
}

fn cmdKey(gpa: Allocator, io: Io, paths: sync.Paths, args: []const []const u8) !void {
    var fp: [95]u8 = undefined;
    if (args.len >= 1 and std.mem.eql(u8, args[0], "init")) {
        const force = args.len == 2 and std.mem.eql(u8, args[1], "--force");
        if (args.len > 2 or (args.len == 2 and !force)) fatal("usage: portalctl sync key init [--force]", .{});
        const pk = sync.initKey(gpa, io, paths, force) catch |err| switch (err) {
            error.SyncKeyExists => fatal("a release key already exists (see `portalctl sync key`). Replacing it means every device must be paired again before it accepts packages; add --force to do that.", .{}),
            else => fatal("could not create the release key: {t}", .{err}),
        };
        std.debug.print("Created the sync release key\n  SHA-256 {s}\n", .{fingerprintText(pk, &fp)});
        if (force) std.debug.print("Devices pinned the old key: pair each one again to receive packages.\n", .{});
        return;
    }
    if (args.len > 1 or (args.len == 1 and !std.mem.eql(u8, args[0], "show"))) fatal("usage: portalctl sync key [show | init [--force]]", .{});
    const pk = (sync.loadPublicKey(io, paths) catch |err| fatal("cannot read the release key: {s}", .{describe(err)})) orelse
        fatal("no release key yet: run `portalctl sync key init` (Portal also creates one when it starts)", .{});
    std.debug.print("Sync release key (Ed25519, signs published packages)\n  SHA-256 {s}\n  files   {s}\\sync-key\n" ++
        "  key     DPAPI, current user (separate from the TLS CA key)\n" ++
        "Devices pin this key when they pair; packages signed by any other key are refused.\n", .{ fingerprintText(pk, &fp), paths.dir });
}

pub fn cmdPublish(gpa: Allocator, io: Io, paths: sync.Paths, args: []const []const u8) !void {
    if (args.len == 1 and std.mem.eql(u8, args[0], "--list")) return listPublished(gpa, io, paths);
    const usage = "usage: portalctl publish <package> <folder> --kind data|executable [--version V] [--min-client V] | portalctl publish --list";
    if (args.len < 2) fatal("{s}", .{usage});
    var kind: ?manifest.Kind = null;
    var version: ?[]const u8 = null;
    var min_client: []const u8 = sync.default_min_client;
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (i + 1 >= args.len) fatal("{s}", .{usage});
        i += 1;
        if (std.mem.eql(u8, a, "--kind")) {
            kind = std.meta.stringToEnum(manifest.Kind, args[i]) orelse fatal("--kind is data or executable", .{});
        } else if (std.mem.eql(u8, a, "--version")) {
            version = args[i];
        } else if (std.mem.eql(u8, a, "--min-client")) {
            min_client = args[i];
        } else fatal("{s}", .{usage});
    }
    const k = kind orelse fatal("say what it is: --kind data (installs by itself) or --kind executable (each version approved on the device)", .{});
    _ = sync.ensureKey(gpa, io, paths) catch |err| fatal("no release key: {t}", .{err});
    var problem: [300]u8 = @splat(0);
    const p = sync.publish(gpa, io, paths, .{
        .package = args[0],
        .folder = args[1],
        .kind = k,
        .version = version,
        .min_client = min_client,
        .now = nowUnix(io),
    }, &problem) catch |err| {
        const why = std.mem.sliceTo(&problem, 0);
        if (why.len > 0) fatal("publish refused: {s}", .{why});
        fatal("publish failed: {s}", .{describe(err)});
    };
    var fp: [95]u8 = undefined;
    const pk = (sync.loadPublicKey(io, paths) catch null).?;
    std.debug.print("Published {s} {s} (sequence {d}, {t}, {d} files, {d} bytes)\n  signed by release key SHA-256 {s}\n", .{
        args[0], p.version(), p.sequence, k, p.files, p.size, fingerprintText(pk, &fp),
    });
    if (k == .executable) std.debug.print("Devices ask for approval before installing it.\n", .{});
}

fn listPublished(gpa: Allocator, io: Io, paths: sync.Paths) !void {
    var pkgs = try sync.packages(gpa, io, paths);
    defer {
        for (pkgs.items) |p| gpa.free(p);
        pkgs.deinit(gpa);
    }
    if (pkgs.items.len == 0) std.debug.print("Nothing published. `portalctl publish <package> <folder> --kind data|executable`.\n", .{});
    for (pkgs.items) |p| {
        var v = (sync.latest(gpa, io, paths, p) catch null) orelse continue;
        defer v.deinit(gpa);
        std.debug.print("  {s: <16} {s: <16} sequence {d: <6} {t: <10} {d} files, {d} bytes\n", .{
            p, v.m.version, v.m.sequence, v.m.kind, v.m.files.len, v.m.totalSize(),
        });
    }
}

pub fn cmdUnpublish(io: Io, paths: sync.Paths, args: []const []const u8) !void {
    if (args.len != 2) fatal("usage: portalctl unpublish <package> <version>", .{});
    sync.unpublish(io, paths, args[0], args[1]) catch |err| fatal("unpublish failed: {s}", .{describe(err)});
    std.debug.print("Unpublished {s} {s}. Devices keep what they installed; the name and sequence are never reused.\n", .{ args[0], args[1] });
}

// ------------------------------------------------------------------ device

const Client = client.net_client.Client;
const tunnel = client.tunnel;
const devicelink = client.devicelink;
const engine = client.sync.engine;
const keypin = client.sync.keypin;
const store_mod = client.sync.store;

fn report(_: ?*anyopaque, line: []const u8) void {
    std.debug.print("sync-device: {s}\n", .{line});
}

pub fn cmdSyncDevice(gpa: Allocator, io: Io, args: []const []const u8, client_version: []const u8) !void {
    var code_arg: ?[]const u8 = null;
    var show_key = false;
    var forget = false;
    var status = false;
    var approve = false;
    var wait_s: ?u32 = null;
    var only: ?[]const u8 = null;
    var rollback: ?[]const u8 = null;
    var revoke: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const needs = std.mem.eql(u8, a, "--pairing-code") or std.mem.eql(u8, a, "--wait-updates") or
            std.mem.eql(u8, a, "--only") or std.mem.eql(u8, a, "--rollback") or std.mem.eql(u8, a, "--revoke");
        if (needs) {
            i += 1;
            if (i >= args.len) fatal("{s} needs a value", .{a});
        }
        if (std.mem.eql(u8, a, "--pairing-code")) {
            code_arg = args[i];
        } else if (std.mem.eql(u8, a, "--wait-updates")) {
            wait_s = std.fmt.parseInt(u32, args[i], 10) catch fatal("--wait-updates takes seconds", .{});
        } else if (std.mem.eql(u8, a, "--only")) {
            only = args[i];
        } else if (std.mem.eql(u8, a, "--rollback")) {
            rollback = args[i];
        } else if (std.mem.eql(u8, a, "--revoke")) {
            revoke = args[i];
        } else if (std.mem.eql(u8, a, "--key")) {
            show_key = true;
        } else if (std.mem.eql(u8, a, "--forget")) {
            forget = true;
        } else if (std.mem.eql(u8, a, "--status")) {
            status = true;
        } else if (std.mem.eql(u8, a, "--approve")) {
            approve = true;
        } else fatal("usage: portalctl sync-device [--pairing-code CODE] [--approve] [--wait-updates S] [--only PKG] | --key | --rollback PKG | --revoke PKG | --status | --forget", .{});
    }

    var key = tunnel.keys.loadOrCreate(io) catch |err| fatal("cannot load or create this device's tunnel key: {t}", .{err});
    defer key.wipe();
    if (show_key) {
        std.debug.print("sync-device: key {s} check {s}\n", .{ &key.publicText(), &key.checkCode() });
        return;
    }
    // The pairing code: given now (and saved), or saved earlier.
    const code: devicelink.Code = if (code_arg) |t| blk: {
        const c = devicelink.parse(t) catch |err| fatal("{s}", .{devicelink.describe(err)});
        devicelink.save(io, &c) catch |err| fatal("cannot save the pairing code: {t}", .{err});
        break :blk c;
    } else devicelink.load(io) orelse fatal("not paired: give --pairing-code (the code the desk shows after Pair a device)", .{});
    const host = devicelink.server;

    if (forget) {
        // Both ways: the desktop removes this device first (if reachable).
        const r = client.forgetLinked(gpa, io, &code, &key);
        var mb: [600]u8 = undefined;
        var w: Io.Writer = .fixed(&mb);
        r.describe(&w, host) catch {};
        std.debug.print("sync-device: {s}\n", .{w.buffered()});
        return;
    }

    // This desktop's own store, named after its address and pinned key.
    const pinned_now = keypin.load(io, host) catch |err| fatal("the pinned release key is unreadable: {t}", .{err});
    var root_buf: [client.pin.max_path]u8 = undefined;
    var st_opt: ?store_mod.Store = null;
    if (pinned_now) |k| {
        const root = keypin.desktopRoot(host, k, &root_buf) catch fatal("no LOCALAPPDATA", .{});
        st_opt = store_mod.Store.open(gpa, io, root, manifest.fingerprint(k)) catch |err| fatal("cannot open the sync store {s}: {t}", .{ root, err });
    }
    if ((rollback != null or revoke != null or status) and st_opt == null)
        fatal("no release key pinned for {s}: nothing was synced from it", .{host});
    if (rollback) |pkg| {
        const p = st_opt.?.rollback(pkg) catch |err| fatal("rollback of {s} failed: {t}", .{ pkg, err });
        std.debug.print("sync-device: rolled {s} back to {s} (sequence {d})\n", .{ pkg, p.version(), p.sequence });
        return;
    }
    if (revoke) |pkg| {
        const r = st_opt.?.revoke(pkg) catch |err| fatal("revoke of {s} failed: {t}", .{ pkg, err });
        if (r.now) |p|
            std.debug.print("sync-device: revoked {s}: back to {s} (sequence {d})\n", .{ pkg, p.version(), p.sequence })
        else
            std.debug.print("sync-device: revoked {s}: uninstalled\n", .{pkg});
        return;
    }
    if (status) {
        const st = &st_opt.?;
        var ids: [64][manifest.max_package_id]u8 = undefined;
        var lens: [64]u8 = undefined;
        const n = try st.installedPackages(&ids, &lens);
        for (0..n) |k| {
            const id = ids[k][0..lens[k]];
            const cur = (try st.current(id)).?;
            const prev = try st.previous(id);
            std.debug.print("sync-device: installed {s} {s} (sequence {d}){s}{s}\n", .{ id, cur.version(), cur.sequence, if (prev != null) ", previous " else "", if (prev) |p| p.version() else "" });
        }
        return;
    }

    // The tunnel and the client, exactly as `portal connect` makes them.
    const tun = devicelink.startTunnel(gpa, io, &code, &key) catch |err| fatal("cannot start the tunnel: {t}", .{err});
    defer tun.destroy();
    var ca_buf: [client.x509check_mod.max_cert_len]u8 = undefined;
    const trust = devicelink.trust(io, &code, &ca_buf);
    var shared: client.net_client.Shared = .{};
    var c = Client.init(gpa, io, &shared, host, tun.dialer(), trust) catch fatal("bad desktop address", .{});
    var io_copy = io;
    c.on_pinned = devicelink.savePin;
    c.on_pinned_ctx = &io_copy;

    // Connect once on the interactive channel: pins the CA on a first
    // connection, and says whether this device is still paired. With
    // --wait-updates it stays until the desktop announces updates.
    waitUpdates(gpa, io, &c, wait_s orelse 0, host);

    const pinned = pinned_now orelse blk: {
        // First run after pairing: pin the release key now.
        const k = c.pinReleaseKey() catch |err| fatal("no release key could be pinned: {t}", .{err});
        var fp: [95]u8 = undefined;
        std.debug.print("sync-device: paired; release key pinned: SHA-256 {s}\n", .{fingerprintText(k, &fp)});
        const root = keypin.desktopRoot(host, k, &root_buf) catch fatal("no LOCALAPPDATA", .{});
        st_opt = store_mod.Store.open(gpa, io, root, manifest.fingerprint(k)) catch |err| fatal("cannot open the sync store {s}: {t}", .{ root, err });
        break :blk k;
    };
    var st = st_opt.?;
    const remote = c.syncRemote();
    {
        // A key change on the desktop is refused: only re-pairing re-pins.
        const now_key = engine.fetchKey(&remote) catch |err| fatal("fetching the release key failed: {t}", .{err});
        if (!std.mem.eql(u8, &now_key, &pinned)) {
            var a: [95]u8 = undefined;
            var b: [95]u8 = undefined;
            std.debug.print("sync-device: WARNING: the desktop's release key changed (pinned {s}, desktop {s}); packages signed by it will be rejected until this device is paired again\n", .{ fingerprintText(pinned, &a), fingerprintText(now_key, &b) });
        }
    }

    var rep: engine.Report = .{};
    engine.run(&remote, &st, pinned, .{ .client_version = client_version, .approve_all = approve, .only = only }, &rep, .{ .f = report }) catch |err|
        fatal("sync failed: {s}", .{engine.describe(err)});
    std.debug.print("sync-device: done: {d} installed, {d} up to date, {d} waiting for approval, {d} refused, {d} rejected\n", .{
        rep.count(.installed), rep.count(.up_to_date), rep.count(.pending_approval), rep.count(.refused), rep.count(.rejected),
    });
}

/// The desktop said it no longer has this device (403, or a logout):
/// forget it here too, say why, exit 1.
fn forgetGone(io: Io, host: []const u8) noreturn {
    var r = client.forgetDesktop(io, host);
    r.remote = .gone_by_desktop;
    var mb: [600]u8 = undefined;
    var w: Io.Writer = .fixed(&mb);
    r.describe(&w, host) catch {};
    std.debug.print("sync-device: {s}\n", .{w.buffered()});
    std.process.exit(1);
}

/// Opens the interactive WebSocket (pinning the CA on a first connection)
/// and returns at hello (`secs` 0) or once the desktop says
/// {"t":"updates"} (or after `secs`).
fn waitUpdates(gpa: Allocator, io: Io, c: *Client, secs: u32, host: []const u8) void {
    var wd: client.watchdog.Watchdog = .{ .io = io };
    wd.extend(@as(i64, @max(secs, 15)) * 1000);
    const r = wd.run(waitTask, .{ gpa, io, c, secs, &wd }, null);
    if (wd.expired.load(.acquire)) {
        if (secs == 0) fatal("the desktop did not answer through the tunnel", .{});
        std.debug.print("sync-device: no updates announced within {d} s\n", .{secs});
        return;
    }
    r catch |err| {
        if (err == error.NotPaired or err == error.DeviceGone) forgetGone(io, host);
        fatal("stream failed: {t}", .{err});
    };
    if (secs > 0) std.debug.print("sync-device: desktop announced updates\n", .{});
}

fn waitTask(gpa: Allocator, io: Io, c: *Client, secs: u32, wd: *client.watchdog.Watchdog) anyerror!void {
    var sock = try client.wsclient.Socket.open(gpa, io, c.dialer, c.addr, c.security(), c.host(), .interactive, &wd.stopped);
    defer sock.close();
    if (c.trust == .fingerprint) c.pinFound(sock.conn.caDer());
    while (try sock.next(8 << 20)) |f| {
        if (f.opcode != .text) continue;
        if (std.mem.indexOf(u8, f.payload, "\"t\":\"hello\"") != null) {
            std.debug.print("sync-device: connected through the tunnel\n", .{});
            if (secs == 0) return;
        }
        if (std.mem.indexOf(u8, f.payload, "\"t\":\"updates\"") != null) return;
        if (std.mem.indexOf(u8, f.payload, "\"t\":\"logout\"") != null) return error.DeviceGone;
    }
    return error.ConnectionClosed;
}
