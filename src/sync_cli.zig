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
//!     portalctl sync-device --server IP:PORT --ca FILE [--pair]
//!         [--approve] [--wait-updates SECONDS] [--only PACKAGE]
//!     portalctl sync-device --server IP:PORT --rollback PACKAGE | --revoke PACKAGE | --status
//!     portalctl sync-device --server IP:PORT --forget
//!
//!   Each desktop has its own store on the device (client/src/sync/keypin.zig,
//!   desktopRoot), so every device command names the desktop (--server).

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
        error.SyncStoreBusy => "the sync store is locked by another Portal process; try again",
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

pub fn cmdUnpublish(gpa: Allocator, io: Io, paths: sync.Paths, args: []const []const u8) !void {
    if (args.len != 2) fatal("usage: portalctl unpublish <package> <version>", .{});
    sync.unpublish(gpa, io, paths, args[0], args[1]) catch |err| fatal("unpublish failed: {s}", .{describe(err)});
    std.debug.print("Unpublished {s} {s}. Devices keep what they installed; the name and sequence are never reused.\n", .{ args[0], args[1] });
}

// ------------------------------------------------------------------ device

const Client = client.net_client.Client;
const http = client.net_http;
const engine = client.sync.engine;
const keypin = client.sync.keypin;
const store_mod = client.sync.store;

fn report(_: ?*anyopaque, line: []const u8) void {
    std.debug.print("sync-device: {s}\n", .{line});
}

pub fn cmdSyncDevice(gpa: Allocator, io: Io, args: []const []const u8, client_version: []const u8) !void {
    var server: ?[]const u8 = null;
    var ca_file: ?[]const u8 = null;
    var pair = false;
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
        const needs = std.mem.eql(u8, a, "--server") or std.mem.eql(u8, a, "--ca") or std.mem.eql(u8, a, "--wait-updates") or
            std.mem.eql(u8, a, "--only") or std.mem.eql(u8, a, "--rollback") or std.mem.eql(u8, a, "--revoke");
        if (needs) {
            i += 1;
            if (i >= args.len) fatal("{s} needs a value", .{a});
        }
        if (std.mem.eql(u8, a, "--server")) {
            server = args[i];
        } else if (std.mem.eql(u8, a, "--ca")) {
            ca_file = args[i];
        } else if (std.mem.eql(u8, a, "--wait-updates")) {
            wait_s = std.fmt.parseInt(u32, args[i], 10) catch fatal("--wait-updates takes seconds", .{});
        } else if (std.mem.eql(u8, a, "--only")) {
            only = args[i];
        } else if (std.mem.eql(u8, a, "--rollback")) {
            rollback = args[i];
        } else if (std.mem.eql(u8, a, "--revoke")) {
            revoke = args[i];
        } else if (std.mem.eql(u8, a, "--pair")) {
            pair = true;
        } else if (std.mem.eql(u8, a, "--forget")) {
            forget = true;
        } else if (std.mem.eql(u8, a, "--status")) {
            status = true;
        } else if (std.mem.eql(u8, a, "--approve")) {
            approve = true;
        } else fatal("usage: portalctl sync-device --server IP:PORT [--ca FILE] [--pair] [--approve] [--wait-updates S] [--only PKG] | --rollback PKG | --revoke PKG | --status | --forget", .{});
    }

    const srv = server orelse fatal("--server IP:PORT is required (each desktop has its own sync folder)", .{});
    var hb: [64]u8 = undefined;
    const host = http.canonicalHost(srv, &hb) catch fatal("bad --server '{s}'", .{srv});
    if (forget) {
        const r = client.forgetDesktop(io, host);
        var mb: [400]u8 = undefined;
        var w: Io.Writer = .fixed(&mb);
        r.describe(&w, host) catch {};
        std.debug.print("sync-device: {s}\n", .{w.buffered()});
        return;
    }

    // This desktop's own store, named after the pinned host and key.
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


    const ca_path = ca_file orelse fatal("--ca FILE is required (the Portal CA, portal-ca.pem)", .{});
    var ca_buf: [client.x509check_mod.max_cert_len]u8 = undefined;
    const der = client.pin.readCaFile(io, ca_path, &ca_buf) catch |err| fatal("cannot use {s} as the Portal CA: {t}", .{ ca_path, err });

    var shared: client.net_client.Shared = .{};
    var c = Client.init(gpa, io, &shared, host, .{ .tls = der }) catch fatal("bad --server", .{});
    c.pair_retry_ms = 200;
    c.pair_min_interval_ms = 0;

    if (pair) {
        std.debug.print("sync-device: asking the desk to pair\n", .{});
        switch (c.pairFlow()) {
            .paired => |p| {
                var dev = p.device;
                defer dev.wipe();
                var sess = p.session;
                defer sess.wipe();
                client.credstore_mod.save(c.target(), dev.value()) catch |err| fatal("cannot store the credential: {t}", .{err});
                const key = c.pinReleaseKey(&sess) catch |err| fatal("paired, but no release key could be pinned: {t}", .{err});
                var fp: [95]u8 = undefined;
                std.debug.print("sync-device: paired; release key pinned: SHA-256 {s}\n", .{fingerprintText(key, &fp)});
            },
            .failed => |why| fatal("pairing failed: {s}", .{why}),
            .cancelled => fatal("pairing cancelled", .{}),
        }
        return;
    }

    const pinned = pinned_now orelse fatal("no release key pinned for {s}: pair this device first (--pair)", .{host});
    var st = st_opt.?;
    var session = c.signIn() catch |err| fatal("sign-in failed: {t}", .{err});
    defer session.wipe();
    const remote = c.syncRemote(session.value());
    {
        // A key change on the server is refused: only re-pairing re-pins.
        const now_key = engine.fetchKey(&remote) catch |err| fatal("GET /sync/key failed: {t}", .{err});
        if (!std.mem.eql(u8, &now_key, &pinned)) {
            var a: [95]u8 = undefined;
            var b: [95]u8 = undefined;
            std.debug.print("sync-device: WARNING: the server's release key changed (pinned {s}, server {s}); packages signed by it will be rejected until this device is paired again\n", .{ fingerprintText(pinned, &a), fingerprintText(now_key, &b) });
        }
    }
    if (wait_s) |secs| waitUpdates(gpa, io, &c, &session, secs);

    var rep: engine.Report = .{};
    engine.run(&remote, &st, pinned, .{ .client_version = client_version, .approve_all = approve, .only = only }, &rep, .{ .f = report }) catch |err| switch (err) {
        error.Unauthorized => fatal("the session was refused (401)", .{}),
        else => fatal("sync failed: {s}", .{engine.describe(err)}),
    };
    std.debug.print("sync-device: done: {d} installed, {d} up to date, {d} waiting for approval, {d} refused, {d} rejected\n", .{
        rep.count(.installed), rep.count(.up_to_date), rep.count(.pending_approval), rep.count(.refused), rep.count(.rejected),
    });
}

/// Opens the WebSocket with the session and returns once the server says
/// {"t":"updates"} (or after `secs`).
fn waitUpdates(gpa: Allocator, io: Io, c: *Client, session: *const http.Cookie, secs: u32) void {
    var wd: client.watchdog.Watchdog = .{ .io = io };
    wd.extend(@as(i64, secs) * 1000);
    const r = wd.run(waitTask, .{ gpa, io, c, session, &wd }, null);
    if (wd.expired.load(.acquire)) {
        std.debug.print("sync-device: no updates announced within {d} s\n", .{secs});
        return;
    }
    r catch |err| fatal("stream failed: {t}", .{err});
    std.debug.print("sync-device: server announced updates\n", .{});
}

fn waitTask(gpa: Allocator, io: Io, c: *Client, session: *const http.Cookie, wd: *client.watchdog.Watchdog) anyerror!void {
    const ws = client.net_ws;
    const conn = try client.tlsconn.Conn.openWatched(gpa, io, c.addr, .{ .tls = .{ .ca_der = c.ca_buf[0..c.ca_len], .ip = c.ip_buf[0..c.ip_len] } }, &wd.stopped);
    defer conn.close(gpa);
    var rnd: [16]u8 = undefined;
    try io.randomSecure(&rnd);
    const key = ws.makeKey(rnd);
    var req_buf: [768]u8 = undefined;
    defer std.crypto.secureZero(u8, &req_buf);
    var w: Io.Writer = .fixed(&req_buf);
    try http.writeUpgradeRequest(&w, c.host(), true, session, &key);
    try conn.writeAll(w.buffered());
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    var head_done = false;
    while (true) {
        if (!head_done) {
            if (http.findHeadEnd(buf.items)) |e| {
                const resp = try http.parseResponseHead(buf.items[0..e]);
                if (resp.status != 101) return error.UpgradeRefused;
                std.mem.copyForwards(u8, buf.items[0 .. buf.items.len - e], buf.items[e..]);
                buf.shrinkRetainingCapacity(buf.items.len - e);
                head_done = true;
            } else if (buf.items.len > http.max_head_bytes) return error.ResponseTooLarge;
        }
        if (head_done) while (try ws.parseServerFrame(buf.items, 8 << 20)) |f| {
            if (f.opcode == .text) {
                if (std.mem.indexOf(u8, f.payload, "\"t\":\"hello\"") != null)
                    std.debug.print("sync-device: listening for updates\n", .{});
                if (std.mem.indexOf(u8, f.payload, "\"t\":\"updates\"") != null) return;
            }
            std.mem.copyForwards(u8, buf.items[0 .. buf.items.len - f.len], buf.items[f.len..]);
            buf.shrinkRetainingCapacity(buf.items.len - f.len);
        };
        try buf.ensureUnusedCapacity(gpa, 32 * 1024);
        const n = try conn.read(buf.unusedCapacitySlice());
        if (n == 0) return error.ConnectionClosed;
        buf.items.len += n;
    }
}
