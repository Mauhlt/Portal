//! Portal sync (docs/sync-design.md) end to end, with TLS on: a desktop
//! (`portalctl run --console`) publishes signed packages and a headless
//! device (`portalctl sync-device`, the code `portal connect` runs) pairs,
//! pins the release key, and fetches, verifies and installs them.
//!
//!   * pairing pins the release key (same SHA-256 as `portalctl sync key`);
//!   * publish/subscribe -> {"t":"updates"} on the device's WebSocket ->
//!     fetch -> install (files byte-identical, current pointer);
//!   * an executable waits for approval (--approve stands for the click);
//!   * a tampered file, a tampered manifest, a release key the device did
//!     not pin, and a downgrade are all refused, and nothing changes;
//!   * a manifest with a path traversal is never offered;
//!   * each desktop has its own folder on the device: another desktop's
//!     records (even at a huge sequence) and the old shared store are
//!     never read or written;
//!   * revoking an executable's approval goes back to the previous version,
//!     then uninstalls; a revoked version is not installed again;
//!   * /sync routes: 401 without a session, 404 for packages a device is
//!     not subscribed to, files only by index;
//!   * privacy: no local paths or user names in any sync response.

const std = @import("std");
const Io = std.Io;
const net = @import("net.zig");
const http = @import("http.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const privacy = @import("privacy.zig");
const Runner = @import("runner.zig").Runner;

const run_args = [_][]const u8{ "--input", "keys", "--", "cmd.exe", "/k", "echo PORTAL-SYNC-TEST" };
const other_ip = [4]u8{ 127, 0, 0, 2 };

fn has(s: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, s, needle) != null;
}

const Ctx = struct {
    h: *proc.Harness,
    r: *Runner,
    inst: *proc.Instance,
    dir: []const u8,
    dev: []const u8,
    server_arg: []const u8,
    pem: []const u8,
    /// The device's folder for this desktop:
    /// <dev>\Portal\sync\desktops\<host stem>-<16 hex of the key SHA-256>.
    desk_dir: []const u8 = "",
    leaks: *privacy.Leaks,
    scanned: usize = 0,
    leaked: usize = 0,
    first_leak: [160]u8 = undefined,
    first_len: usize = 0,

    fn look(c: *Ctx, what: []const u8, data: []const u8) void {
        c.scanned += 1;
        const n = c.leaks.find(data) orelse return;
        c.leaked += 1;
        if (c.first_len == 0) c.first_len = (std.fmt.bufPrint(&c.first_leak, "{s} contains '{s}'", .{ what, n }) catch @as([]u8, &.{})).len;
    }

    /// `portalctl <args>` against the desktop's data.
    fn desk(c: *Ctx, args: []const []const u8) !proc.CliResult {
        return c.inst.cli(args);
    }

    /// `portalctl sync-device --server ... --ca ... <extra>` as the device.
    fn device(c: *Ctx, extra: []const []const u8) !proc.CliResult {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(c.h.gpa);
        try argv.appendSlice(c.h.gpa, &.{ "sync-device", "--server", c.server_arg, "--ca", c.pem });
        try argv.appendSlice(c.h.gpa, extra);
        return proc.runCli(c.h, c.dev, argv.items);
    }

    fn deviceLive(c: *Ctx, extra: []const []const u8) !*proc.LiveCli {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(c.h.gpa);
        try argv.appendSlice(c.h.gpa, &.{ "sync-device", "--server", c.server_arg, "--ca", c.pem });
        try argv.appendSlice(c.h.gpa, extra);
        return proc.LiveCli.start(c.h, c.dev, argv.items);
    }

    fn devPath(c: *Ctx, comptime fmt: []const u8, args: anytype) ![]u8 {
        return std.fmt.allocPrint(c.h.gpa, "{s}\\" ++ fmt, .{c.desk_dir} ++ args);
    }

    fn deskPath(c: *Ctx, comptime fmt: []const u8, args: anytype) ![]u8 {
        return std.fmt.allocPrint(c.h.gpa, "{s}\\Portal\\" ++ fmt, .{c.dir} ++ args);
    }

    fn readFile(c: *Ctx, path: []const u8) ?[]u8 {
        return Io.Dir.cwd().readFileAlloc(c.h.io, path, c.h.gpa, .limited(1 << 20)) catch null;
    }

    /// The version the device's record names as current ("" if none).
    fn current(c: *Ctx, pkg: []const u8) []const u8 {
        return c.slot(pkg, "\ncurrent ");
    }

    fn previous(c: *Ctx, pkg: []const u8) []const u8 {
        return c.slot(pkg, "\nprevious ");
    }

    fn slot(c: *Ctx, pkg: []const u8, key: []const u8) []const u8 {
        const p = c.devPath("state\\{s}.txt", .{pkg}) catch return "";
        const text = c.readFile(p) orelse return "";
        const i = std.mem.indexOf(u8, text, key) orelse return "";
        const rest = text[i + key.len ..];
        const line = rest[0 .. std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len];
        if (std.mem.eql(u8, line, "-")) return "";
        return line[0 .. std.mem.indexOfScalar(u8, line, ' ') orelse line.len];
    }

    fn exists(c: *Ctx, path: []const u8) bool {
        Io.Dir.cwd().access(c.h.io, path, .{}) catch return false;
        return true;
    }

    fn writeSource(c: *Ctx, name: []const u8, files: []const [2][]const u8) ![]u8 {
        const src = try std.fmt.allocPrint(c.h.gpa, "{s}\\src-{s}", .{ c.dir, name });
        Io.Dir.cwd().deleteTree(c.h.io, src) catch {};
        for (files) |f| {
            const p = try std.fmt.allocPrint(c.h.gpa, "{s}\\{s}", .{ src, f[0] });
            if (std.fs.path.dirname(p)) |d| try Io.Dir.cwd().createDirPath(c.h.io, d);
            try Io.Dir.cwd().writeFile(c.h.io, .{ .sub_path = p, .data = f[1] });
        }
        return src;
    }

    fn publish(c: *Ctx, pkg: []const u8, src: []const u8, kind: []const u8, version: []const u8) !proc.CliResult {
        return c.desk(&.{ "publish", pkg, src, "--kind", kind, "--version", version });
    }

    /// GET with the probe device's session (from 127.0.0.2).
    fn probeGet(c: *Ctx, path: []const u8, cookie: ?[]const u8) !http.Response {
        return http.request(c.h.gpa, c.inst.port, .{ .path = path, .host = c.inst.host, .cookie = cookie, .source = other_ip, .tls = c.inst.tls });
    }
};

/// Device sign-in from 127.0.0.2 (GET / with the device cookie).
fn probeSignIn(inst: *proc.Instance, device: []const u8) !?client.Creds {
    var r = try http.request(inst.h.gpa, inst.port, .{ .path = "/", .host = inst.host, .cookie = device, .source = other_ip, .tls = inst.tls });
    defer r.deinit();
    if (r.status != 303) return null;
    return client.Creds.fromResponse(&r);
}

/// Pairs a device called `name` from 127.0.0.2 through the desk.
fn pairProbe(inst: *proc.Instance, name: []const u8) !client.Creds {
    const pc = try inst.liveCli(&.{ "pair", name });
    defer pc.deinit();
    if (!pc.waitFor("Waiting for the device", 15_000)) return error.PairCommandFailed;
    if (!client.waitPairOpen(inst, 10_000)) return error.PairWindowNotSeen;
    const rq = try client.requestPair(inst, other_ip);
    if (!rq.waiting()) return error.PairingRefused;
    if (!pc.waitFor("[y/N]", 10_000)) return error.NoDeskPrompt;
    pc.answer("y\r\n");
    const got = try client.collect(inst, rq.cookie(), other_ip, 10_000);
    _ = pc.wait(10_000);
    return switch (got) {
        .creds => |cr| cr,
        else => error.PairingRefused,
    };
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const gpa = h.gpa;
    const dir = try h.dataDir("sync");
    const dev = try h.dataDir("sync-device");
    const inst = try proc.Instance.startTls(h, dir, port, &run_args);
    defer inst.kill();
    var leaks = try privacy.Leaks.standard(h, dir);
    defer leaks.deinit();
    try leaks.add(dev);
    var c: Ctx = .{
        .h = h,
        .r = r,
        .inst = inst,
        .dir = dir,
        .dev = dev,
        .server_arg = inst.host,
        .pem = try std.fmt.allocPrint(gpa, "{s}\\portal-ca.pem", .{inst.ca_dir}),
        .leaks = &leaks,
    };
    // Whatever happens, the device forgets its credential and pins.
    defer _ = c.device(&.{"--forget"}) catch {};

    // ------------------------------------------------- release key, pairing
    const key = try c.desk(&.{ "sync", "key" });
    const fp_at = std.mem.indexOf(u8, key.out, "SHA-256 ") orelse 0;
    const fingerprint = if (fp_at > 0 and key.out.len >= fp_at + 8 + 95) key.out[fp_at + 8 ..][0..95] else "?";
    _ = r.check("the desktop has a release key (created at start, shown by `sync key`)", key.code == 0 and fp_at > 0, "{s}", .{key.out});
    {
        // desktops\127.0.0.1_<port>-<first 16 hex digits of the SHA-256>
        var hex: [16]u8 = undefined;
        var n: usize = 0;
        for (fingerprint) |ch| {
            if (ch == ':') continue;
            if (n == hex.len) break;
            hex[n] = std.ascii.toLower(ch);
            n += 1;
        }
        const colon = std.mem.lastIndexOfScalar(u8, inst.host, ':') orelse 0;
        c.desk_dir = try std.fmt.allocPrint(gpa, "{s}\\Portal\\sync\\desktops\\{s}_{s}-{s}", .{ dev, inst.host[0..colon], inst.host[colon + 1 ..], hex[0..n] });
    }
    {
        const init_again = try c.desk(&.{ "sync", "key", "init" });
        _ = r.check("`sync key init` refuses to replace the key without --force", init_again.code != 0 and has(init_again.out, "--force"), "{s}", .{init_again.out});
    }
    {
        const nopin = try c.device(&.{});
        _ = r.check("an unpaired device refuses to sync (no pinned key)", nopin.code != 0 and has(nopin.out, "pair this device first"), "{s}", .{nopin.out});
    }
    {
        const pc = try inst.liveCli(&.{ "pair", "laptop" });
        defer pc.deinit();
        _ = pc.waitFor("Waiting for the device", 15_000);
        _ = client.waitPairOpen(inst, 10_000);
        const dp = try c.deviceLive(&.{"--pair"});
        defer dp.deinit();
        const asked = pc.waitFor("[y/N]", 15_000);
        pc.answer("y\r\n");
        const code = dp.wait(20_000);
        _ = r.check("sync-device pairs through the desk", asked and code == 0 and dp.has("paired; release key pinned"), "code={?d} {s} / desk: {s}", .{ code, dp.output(), pc.output() });
        _ = r.check("...and pins the desktop's release key (same SHA-256)", dp.has(fingerprint), "want {s}: {s}", .{ fingerprint, dp.output() });
        _ = pc.wait(10_000);
    }
    var probe = pairProbe(inst, "probe") catch |err| {
        _ = r.check("a second device pairs from 127.0.0.2", false, "{t}", .{err});
        return err;
    };

    // ------------------------------------------------- routes and refusals
    const pub1 = try c.writeSource("m1", &.{ .{ "model.bin", "model weights version one" }, .{ "conf/settings.txt", "lang=en" } });
    {
        const p = try c.publish("stt-model", pub1, "data", "1.0");
        _ = r.check("publish signs and stores a data package", p.code == 0 and has(p.out, "Published stt-model 1.0 (sequence 1"), "{s}", .{p.out});
        const l = try c.desk(&.{ "publish", "--list" });
        _ = r.check("publish --list shows it", has(l.out, "stt-model") and has(l.out, "1.0"), "{s}", .{l.out});
    }
    for ([_][]const u8{ "/sync/key", "/sync/index", "/sync/pkg/stt-model/1.0/manifest", "/sync/pkg/stt-model/1.0/file/0" }) |p| {
        var resp = try c.probeGet(p, null);
        defer resp.deinit();
        c.look(p, resp.raw);
        var nb: [96]u8 = undefined;
        _ = r.check(try std.fmt.bufPrint(&nb, "{s} without a session is 401", .{p}), resp.status == 401, "{d}", .{resp.status});
    }
    {
        var resp = try c.probeGet("/sync/key", probe.sessionCookie());
        defer resp.deinit();
        c.look("/sync/key", resp.raw);
        _ = r.check("GET /sync/key with a session: the key and its fingerprint", resp.status == 200 and has(resp.body, "portal-sync-key-v1") and
            std.mem.eql(u8, resp.header("x-portal-sync-key-fingerprint") orelse "", fingerprint), "{d} {s}", .{ resp.status, resp.body });
    }
    {
        var resp = try c.probeGet("/sync/index", probe.sessionCookie());
        defer resp.deinit();
        c.look("/sync/index", resp.raw);
        _ = r.check("an unsubscribed device's index is empty", resp.status == 200 and std.mem.eql(u8, resp.body, "portal-sync-index-v1\nend\n"), "{d} {s}", .{ resp.status, resp.body });
        var m = try c.probeGet("/sync/pkg/stt-model/1.0/manifest", probe.sessionCookie());
        defer m.deinit();
        var f = try c.probeGet("/sync/pkg/stt-model/1.0/file/0", probe.sessionCookie());
        defer f.deinit();
        c.look("unsubscribed manifest", m.raw);
        _ = r.check("an unsubscribed package is refused (404), manifest and files", m.status == 404 and f.status == 404, "{d} {d}", .{ m.status, f.status });
    }
    _ = try c.desk(&.{ "sync", "subscribe", "probe", "stt-model" });
    {
        var m = try c.probeGet("/sync/pkg/stt-model/1.0/manifest", probe.sessionCookie());
        defer m.deinit();
        c.look("manifest", m.raw);
        _ = r.check("subscribed: the manifest, with its signature header", m.status == 200 and std.mem.startsWith(u8, m.body, "portal-manifest-v1\n") and
            (m.header("x-portal-signature") orelse @as([]const u8, "")).len == 128, "{d}", .{m.status});
        var f = try c.probeGet("/sync/pkg/stt-model/1.0/file/1", probe.sessionCookie());
        defer f.deinit();
        c.look("file", f.raw);
        _ = r.check("file 1 by index is model.bin (sorted order), exact bytes", f.status == 200 and std.mem.eql(u8, f.body, "model weights version one"), "{d} '{s}'", .{ f.status, f.body });
        var bad: usize = 0;
        for ([_][]const u8{
            "/sync/pkg/stt-model/1.0/file/2",          "/sync/pkg/stt-model/1.0/file/01",
            "/sync/pkg/stt-model/1.0/file/-1",         "/sync/pkg/stt-model/1.0/file/model.bin",
            "/sync/pkg/stt-model/1.0/files/0",         "/sync/pkg/stt-model/1.0/manifest.txt",
            "/sync/pkg/stt-model/../stt-model/1.0/manifest", "/sync/pkg/stt-model/1.0/file/0/x",
            "/sync/pkg/stt-model/9.9/manifest",        "/sync/pkg/STT-MODEL/1.0/manifest",
            "/sync/pkg/stt-model/1.0/file/..%5c..%5cdevices.txt", "/sync/pkg/npu-probe/1.0/manifest",
        }) |p| {
            var x = try c.probeGet(p, probe.sessionCookie());
            defer x.deinit();
            c.look(p, x.raw);
            if (x.status == 200 or x.setCookieCount() != 0) bad += 1;
        }
        _ = r.check("anything but /sync/pkg/<pkg>/<ver>/{manifest,file/<n>} of a subscribed package is refused", bad == 0, "{d} served", .{bad});
    }

    // ------------------------------------------- per-desktop folders on the device
    // Another desktop's folder with a record for the same package at a huge
    // sequence, and the shared store of earlier versions: neither may block
    // or be touched by this desktop's installs.
    const other_desk = try std.fmt.allocPrint(gpa, "{s}\\Portal\\sync\\desktops\\10.9.9.9_8420-0011223344556677", .{dev});
    const other_rec = "portal-sync-state-v2\nsigner " ++ "abababababababababababababababababababababababababababababababab" ++ "\ncurrent 99.0 999999\nprevious -\nhighest 999999\n";
    const legacy_ptr = try std.fmt.allocPrint(gpa, "{s}\\Portal\\sync\\current\\stt-model.txt", .{dev});
    const legacy_rec = "portal-sync-pointer-v1\nversion 99.0\nsequence 999999\nhighest 999999\n";
    {
        const p = try std.fmt.allocPrint(gpa, "{s}\\state\\stt-model.txt", .{other_desk});
        if (std.fs.path.dirname(p)) |d| try Io.Dir.cwd().createDirPath(h.io, d);
        try Io.Dir.cwd().writeFile(h.io, .{ .sub_path = p, .data = other_rec });
        if (std.fs.path.dirname(legacy_ptr)) |d| try Io.Dir.cwd().createDirPath(h.io, d);
        try Io.Dir.cwd().writeFile(h.io, .{ .sub_path = legacy_ptr, .data = legacy_rec });
    }

    // --------------------------------- publish/subscribe -> updates -> install
    {
        const lc = try c.deviceLive(&.{ "--wait-updates", "30" });
        defer lc.deinit();
        const listening = lc.waitFor("listening for updates", 15_000);
        _ = r.check("the device listens on its WebSocket", listening, "{s}", .{lc.output()});
        const sub = try c.desk(&.{ "sync", "subscribe", "laptop", "stt-model" });
        _ = r.check("sync subscribe", sub.code == 0, "{s}", .{sub.out});
        const code = lc.wait(30_000);
        _ = r.check("subscribing sends the device {\"t\":\"updates\"}", lc.has("server announced updates"), "{s}", .{lc.output()});
        _ = r.check("...and it fetches, verifies and installs the data package", code == 0 and lc.has("installed stt-model 1.0"), "code={?d} {s}", .{ code, lc.output() });
    }
    {
        const p = (try c.devPath("packages\\stt-model\\1.0\\model.bin", .{}));
        const got = c.readFile(p) orelse "";
        _ = r.check("installed files are byte-identical, in packages\\<pkg>\\<ver>", std.mem.eql(u8, got, "model weights version one"), "'{s}'", .{got});
        _ = r.check("state\\stt-model.txt names 1.0 as current", std.mem.eql(u8, c.current("stt-model"), "1.0"), "'{s}'", .{c.current("stt-model")});
        var it_count: usize = 0;
        if (Io.Dir.cwd().openDir(h.io, try c.devPath("staging", .{}), .{ .iterate = true })) |d| {
            var dd = d;
            defer dd.close(h.io);
            var it = dd.iterate();
            while (it.next(h.io) catch null) |_| it_count += 1;
        } else |_| {}
        _ = r.check("staging is empty afterwards", it_count == 0, "{d} entries", .{it_count});
        const op = try std.fmt.allocPrint(gpa, "{s}\\state\\stt-model.txt", .{other_desk});
        const other_now = c.readFile(op) orelse "";
        const legacy_now = c.readFile(legacy_ptr) orelse "";
        _ = r.check("installs land in this desktop's own folder: another desktop's record (sequence 999999) and the old shared store neither block nor change",
            std.mem.eql(u8, other_now, other_rec) and std.mem.eql(u8, legacy_now, legacy_rec) and std.mem.eql(u8, c.current("stt-model"), "1.0"), "other '{s}' legacy '{s}'", .{ other_now, legacy_now });
    }
    {
        const lc = try c.deviceLive(&.{ "--wait-updates", "30" });
        defer lc.deinit();
        _ = lc.waitFor("listening for updates", 15_000);
        const src = try c.writeSource("m2", &.{ .{ "model.bin", "model weights version two" }, .{ "conf/settings.txt", "lang=en" } });
        const p = try c.publish("stt-model", src, "data", "2.0");
        const code = lc.wait(30_000);
        _ = r.check("publishing a new version announces it and the device installs it", p.code == 0 and code == 0 and lc.has("server announced updates") and
            lc.has("installed stt-model 2.0"), "{s} / {s}", .{ p.out, lc.output() });
        _ = r.check("2.0 is current, 1.0 previous, both folders kept", std.mem.eql(u8, c.current("stt-model"), "2.0") and
            c.readFile(try c.devPath("packages\\stt-model\\1.0\\model.bin", .{})) != null, "'{s}'", .{c.current("stt-model")});
        const again = try c.device(&.{});
        _ = r.check("a second pass finds it up to date", has(again.out, "up_to_date stt-model 2.0"), "{s}", .{again.out});
    }

    // ------------------------------------------------- executable approval
    {
        const src = try c.writeSource("probe1", &.{.{ "npu-probe.exe", "MZ not really a program" }});
        const p = try c.publish("npu-probe", src, "executable", "0.1");
        _ = try c.desk(&.{ "sync", "subscribe", "laptop", "npu-probe" });
        const first = try c.device(&.{});
        _ = r.check("an executable is not installed without approval", p.code == 0 and has(first.out, "pending_approval npu-probe 0.1") and
            c.current("npu-probe").len == 0 and c.readFile(try c.devPath("packages\\npu-probe\\0.1\\npu-probe.exe", .{})) == null, "{s} / {s}", .{ p.out, first.out });
        const ok = try c.device(&.{"--approve"});
        _ = r.check("approved (the click, --approve): installed, never run", has(ok.out, "installed npu-probe 0.1") and std.mem.eql(u8, c.current("npu-probe"), "0.1"), "{s}", .{ok.out});
        const s2 = try c.writeSource("probe2", &.{.{ "npu-probe.exe", "MZ version two" }});
        _ = try c.publish("npu-probe", s2, "executable", "0.2");
        const next = try c.device(&.{});
        _ = r.check("every new executable version needs approval again", has(next.out, "pending_approval npu-probe 0.2") and std.mem.eql(u8, c.current("npu-probe"), "0.1"), "{s}", .{next.out});

        // Revoking an approval: back to the previous version, then none.
        const ok2 = try c.device(&.{ "--approve", "--only", "npu-probe" });
        _ = r.check("0.2 approved and installed (0.1 previous)", has(ok2.out, "installed npu-probe 0.2") and std.mem.eql(u8, c.current("npu-probe"), "0.2") and
            std.mem.eql(u8, c.previous("npu-probe"), "0.1"), "{s}", .{ok2.out});
        const rv = try c.device(&.{ "--revoke", "npu-probe" });
        _ = r.check("revoke goes back to the previous version and deletes the revoked one", rv.code == 0 and has(rv.out, "back to 0.1") and
            std.mem.eql(u8, c.current("npu-probe"), "0.1") and c.previous("npu-probe").len == 0 and
            c.readFile(try c.devPath("packages\\npu-probe\\0.2\\npu-probe.exe", .{})) == null, "{s}", .{rv.out});
        const again = try c.device(&.{ "--approve", "--only", "npu-probe" });
        _ = r.check("a revoked version is not installed again, even with approval", has(again.out, "refused npu-probe 0.2") and
            std.mem.eql(u8, c.current("npu-probe"), "0.1"), "{s}", .{again.out});
        const rv2 = try c.device(&.{ "--revoke", "npu-probe" });
        _ = r.check("revoking the last version uninstalls it", rv2.code == 0 and has(rv2.out, "uninstalled") and c.current("npu-probe").len == 0 and
            c.readFile(try c.devPath("packages\\npu-probe\\0.1\\npu-probe.exe", .{})) == null, "{s}", .{rv2.out});
    }

    // ------------------------------------------------------------ tampering
    {
        const src = try c.writeSource("m3", &.{ .{ "model.bin", "model weights version 333" }, .{ "conf/settings.txt", "lang=en" } });
        _ = try c.publish("stt-model", src, "data", "3.0");
        // Same size, one byte different, in the desktop's store.
        const f = try c.deskPath("publish\\stt-model\\3.0\\files\\1", .{});
        try Io.Dir.cwd().writeFile(h.io, .{ .sub_path = f, .data = "model weights version 334" });
        const res = try c.device(&.{ "--only", "stt-model" });
        _ = r.check("a tampered file is rejected (SHA-256) and nothing changes", has(res.out, "REJECTED stt-model 3.0") and has(res.out, "SHA-256") and
            std.mem.eql(u8, c.current("stt-model"), "2.0") and c.readFile(try c.devPath("packages\\stt-model\\3.0\\model.bin", .{})) == null, "{s}", .{res.out});
    }
    {
        const src = try c.writeSource("m4", &.{ .{ "model.bin", "model weights version 4" }, .{ "conf/settings.txt", "lang=en" } });
        _ = try c.publish("stt-model", src, "data", "4.0");
        // Still canonical, still parses: only the signature can tell.
        const mp = try c.deskPath("publish\\stt-model\\4.0\\manifest.txt", .{});
        const text = c.readFile(mp) orelse "";
        const edited = try std.mem.replaceOwned(u8, gpa, text, "kind data", "kind executable");
        try Io.Dir.cwd().writeFile(h.io, .{ .sub_path = mp, .data = edited });
        const res = try c.device(&.{ "--only", "stt-model", "--approve" });
        _ = r.check("a tampered manifest is rejected (bad signature) and nothing changes", has(res.out, "REJECTED stt-model 4.0") and has(res.out, "bad signature") and
            std.mem.eql(u8, c.current("stt-model"), "2.0"), "{s}", .{res.out});
    }
    {
        // A manifest naming a path outside its folder never reaches a
        // device: it does not parse, so it is not offered or served
        // (devices refuse it too: unit tests in client/src/sync).
        const src = try c.writeSource("m5", &.{.{ "model.bin", "evil" }});
        _ = try c.publish("stt-model", src, "data", "5.0");
        const mp = try c.deskPath("publish\\stt-model\\5.0\\manifest.txt", .{});
        const text = c.readFile(mp) orelse "";
        const edited = try std.mem.replaceOwned(u8, gpa, text, " model.bin\n", " ../../current/stt-model.txt\n");
        try Io.Dir.cwd().writeFile(h.io, .{ .sub_path = mp, .data = edited });
        // The server keeps a few sessions only; every sync-device run made
        // one, so the probe signs in again with its device credential.
        probe = (try probeSignIn(inst, probe.deviceCookie())) orelse return error.SignInFailed;
        var m = try c.probeGet("/sync/pkg/stt-model/5.0/manifest", probe.sessionCookie());
        defer m.deinit();
        var idx = try c.probeGet("/sync/index", probe.sessionCookie());
        defer idx.deinit();
        const res = try c.device(&.{ "--only", "stt-model" });
        _ = r.check("a path-traversal manifest is not offered or served, and not installed", m.status == 404 and !has(idx.body, " 5.0 ") and
            !has(res.out, "installed stt-model") and std.mem.eql(u8, c.current("stt-model"), "2.0"), "{d} {s} / {s}", .{ m.status, idx.body, res.out });
    }

    // ------------------------------------------------------------ downgrade
    {
        for ([_][]const u8{ "5.0", "4.0", "3.0", "2.0" }) |v| _ = try c.desk(&.{ "unpublish", "stt-model", v });
        const res = try c.device(&.{ "--only", "stt-model" });
        _ = r.check("a downgrade is refused (the desktop now offers 1.0; 2.0 stays)", has(res.out, "refused stt-model 1.0") and has(res.out, "downgrade") and
            std.mem.eql(u8, c.current("stt-model"), "2.0"), "{s}", .{res.out});
        const again = try c.publish("stt-model", pub1, "data", "2.0");
        _ = r.check("an unpublished version name is never reused", again.code != 0, "{s}", .{again.out});
        const rb = try proc.runCli(h, dev, &.{ "sync-device", "--server", c.server_arg, "--rollback", "stt-model" });
        _ = r.check("the owner can roll back locally", rb.code == 0 and std.mem.eql(u8, c.current("stt-model"), "1.0"), "{s}", .{rb.out});
    }

    // ---------------------------------------------- a key the device didn't pin
    {
        const ki = try c.desk(&.{ "sync", "key", "init", "--force" });
        const src = try c.writeSource("m6", &.{.{ "model.bin", "signed by a new key" }});
        const p = try c.publish("stt-model", src, "data", "6.0");
        const res = try c.device(&.{ "--only", "stt-model" });
        _ = r.check("a package signed by another release key is rejected", ki.code == 0 and p.code == 0 and has(res.out, "REJECTED stt-model 6.0") and
            has(res.out, "bad signature") and std.mem.eql(u8, c.current("stt-model"), "1.0"), "{s} / {s}", .{ p.out, res.out });
    }

    _ = r.check("nothing in any sync response contains paths or user names", c.leaked == 0 and c.scanned > 15, "{d} of {d}; first: {s}", .{ c.leaked, c.scanned, c.first_leak[0..c.first_len] });
    {
        const f = try c.device(&.{"--forget"});
        _ = r.check("the device forgets its credential and pins", f.code == 0, "{s}", .{f.out});
        _ = r.check("...and deletes this desktop's sync folder, only that one", !c.exists(c.desk_dir) and c.exists(other_desk) and
            c.exists(legacy_ptr), "{s}", .{f.out});
    }
    _ = r.ok("portal still running at end of group", inst.alive() and client.alive(inst));
}
