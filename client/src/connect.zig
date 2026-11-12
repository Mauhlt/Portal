//! The remote viewer: `portal connect` (in Portal's own executable) and the
//! standalone `portal-client` both run `main` below. Module "client" in
//! Portal's root build; imports only std and "view".
//!
//!   connect --server 10.8.0.1:8420 --ca portal-ca.pem   pin the CA, connect
//!   connect --server 10.8.0.1:8420                      connect (CA pinned)
//!   connect --server ADDR --forget     delete this device's credential + pin
//!
//! HTTPS/WSS only, with the server certificate pinned to the Portal CA the
//! user imported for that server (net/pin.zig, net/tlsconn.zig); plain HTTP
//! only with an explicit --insecure-plain-http. The device credential lives
//! only in the OS credential store; the session cookie only in memory.
//! Nothing secret is accepted on the command line.

const std = @import("std");
const view = @import("view");
const TermView = view.TermView;
const client_mod = @import("net/client.zig");
const credstore = @import("credstore.zig");
const remote = @import("remote.zig");
const http = @import("net/http.zig");
const pin_mod = @import("net/pin.zig");
const x509check = @import("net/x509check.zig");

const usage =
    \\usage: {s} --server IP:PORT [--ca FILE | --ca-sha256 HEX] [--forget]
    \\
    \\  --server IP:PORT   Portal server address inside the WireGuard tunnel,
    \\                     e.g. 10.8.0.1:8420 (literal IP, no host names)
    \\  --ca FILE          trust the Portal CA in FILE (portal-ca.pem or
    \\                     portal-ca.cer from `portal ca export` on the
    \\                     desktop) for this server, and remember it
    \\  --ca-sha256 HEX    the CA fingerprint `portal ca export` printed.
    \\                     With --ca: the file must match it. Alone: download
    \\                     the CA from the desktop while `portal pair` is
    \\                     open (http://IP:PORT+1/ca.cer), check it against
    \\                     HEX, and remember it
    \\  --forget           delete this device's stored credentials and the
    \\                     remembered CA for this server, and exit
    \\  --insecure-plain-http
    \\                     talk plain HTTP to a server run with --no-tls
    \\                     (tests only: keystrokes and credentials are not
    \\                     encrypted; uses its own credential, never the
    \\                     HTTPS one)
    \\
    \\First run: on the desktop run `portal ca export` and `portal pair <name>`;
    \\here run with --ca (or --ca-sha256), then click Pair. Later runs need
    \\only --server.
    \\
;

const insecure_warning =
    \\
    \\  ********************************************************************
    \\  *  WARNING: --insecure-plain-http                                  *
    \\  *  No TLS. Anyone on the network path can read the screen and your *
    \\  *  keystrokes and steal this device's credential. Use only against *
    \\  *  a test server started with `portal run --no-tls`.               *
    \\  ********************************************************************
    \\
    \\
;

fn fatal(prog: []const u8, comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("{s}: " ++ fmt ++ "\n", .{prog} ++ args);
    std.process.exit(1);
}

const Host = struct {
    tv: *TermView,
    shared: *client_mod.Shared,
    client: *client_mod.Client,
    sink: remote.RemoteSink,
    drawn_version: u64 = std.math.maxInt(u64),
    title_status: ?client_mod.Status = null,

    /// Snapshot status under the lock, build the frame, then present.
    fn frame(h: *Host) void {
        const s = h.shared;
        const version = s.version.load(.acquire);
        var detail_buf: [160]u8 = undefined;
        s.mutex.lockUncancelable(h.client.io);
        const st = s.status;
        const mode = s.mode;
        const detail = detail_buf[0..s.detail_len];
        @memcpy(detail, s.detail());
        const o = remote.overlay(st, mode, detail, h.client.host(), s.grid.cols > 0);
        h.tv.build(&s.grid, o);
        s.mutex.unlock(h.client.io);
        h.tv.present();
        h.sink.mode = mode;
        h.sink.status = st;
        h.drawn_version = version;
        if (h.title_status != st) {
            h.title_status = st;
            var tbuf: [128]u8 = undefined;
            h.tv.setTitle(remote.title(st, h.client.host(), &tbuf));
        }
    }

    fn liveRedraw(ctx: *anyopaque) void {
        const h: *Host = @ptrCast(@alignCast(ctx));
        h.frame();
    }
};

/// Runs the remote viewer until its window is closed, then exits the
/// process (the network thread cannot be joined). `args` excludes the
/// program/subcommand name; `prog` is used in messages ("portal connect").
/// Objects live for the life of the process and are never freed.
pub fn main(gpa: std.mem.Allocator, io: std.Io, prog: []const u8, args: []const []const u8) noreturn {
    var server: ?[]const u8 = null;
    var forget = false;
    var ca_file: ?[]const u8 = null;
    var ca_sha256: ?[]const u8 = null;
    var insecure = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--server")) {
            i += 1;
            if (i >= args.len) fatal(prog, "--server needs a value", .{});
            server = args[i];
        } else if (std.mem.eql(u8, a, "--forget")) {
            forget = true;
        } else if (std.mem.eql(u8, a, "--ca")) {
            i += 1;
            if (i >= args.len) fatal(prog, "--ca needs a file", .{});
            ca_file = args[i];
        } else if (std.mem.eql(u8, a, "--ca-sha256")) {
            i += 1;
            if (i >= args.len) fatal(prog, "--ca-sha256 needs a fingerprint", .{});
            ca_sha256 = args[i];
        } else if (std.mem.eql(u8, a, "--insecure-plain-http")) {
            insecure = true;
        } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            std.debug.print(usage, .{prog});
            std.process.exit(0);
        } else {
            std.debug.print(usage, .{prog});
            fatal(prog, "unknown argument '{s}'", .{a});
        }
    }
    const server_arg = server orelse {
        std.debug.print(usage, .{prog});
        std.process.exit(2);
    };
    var host_buf: [64]u8 = undefined;
    const host = http.canonicalHost(server_arg, &host_buf) catch
        fatal(prog, "bad --server '{s}' (want a literal IP:PORT such as 10.8.0.1:8420)", .{server_arg});

    if (forget) {
        var tbuf: [credstore.max_target]u8 = undefined;
        for ([_]bool{ false, true }) |plain| {
            credstore.delete(credstore.targetName(host, plain, &tbuf)) catch |err|
                fatal(prog, "could not delete the credential: {t}", .{err});
        }
        if (pin_mod.Pin.forHost(host)) |p| {
            p.delete(io) catch |err| fatal(prog, "could not delete {s}: {t}", .{ p.path(), err });
        } else |_| {}
        std.debug.print("{s}: forgot the credentials and the pinned CA for {s}\n", .{ prog, host });
        std.process.exit(0);
    }

    const ca_buf = gpa.create([x509check.max_cert_len]u8) catch fatal(prog, "out of memory", .{});
    const transport: client_mod.Transport = if (insecure) blk: {
        if (ca_file != null or ca_sha256 != null) fatal(prog, "--insecure-plain-http cannot be combined with --ca / --ca-sha256", .{});
        std.debug.print(insecure_warning, .{});
        break :blk .insecure_plain_http;
    } else .{ .tls = pinnedCa(gpa, io, prog, host, ca_file, ca_sha256, ca_buf) };

    const shared = gpa.create(client_mod.Shared) catch fatal(prog, "out of memory", .{});
    shared.* = .{};
    const client = gpa.create(client_mod.Client) catch fatal(prog, "out of memory", .{});
    client.* = client_mod.Client.init(gpa, io, shared, server_arg, transport) catch
        fatal(prog, "bad --server '{s}' (want a literal IP:PORT such as 10.8.0.1:8420)", .{server_arg});

    const tv = TermView.init(gpa, io, .{ .title = "Portal" }) catch |err| fatal(prog, "cannot open the window: {t}", .{err});
    const host_ui = gpa.create(Host) catch fatal(prog, "out of memory", .{});
    host_ui.* = .{ .tv = tv, .shared = shared, .client = client, .sink = .{ .client = client } };
    tv.setLiveRedraw(host_ui, Host.liveRedraw);
    shared.wake_ctx = tv;
    shared.wake_fn = struct {
        fn f(ctx: *anyopaque) void {
            const v: *TermView = @ptrCast(@alignCast(ctx));
            v.wake();
        }
    }.f;

    // The network thread runs for the life of the process (its socket reads
    // cannot be cancelled portably); exiting the process ends it.
    const thread = std.Thread.spawn(.{}, client_mod.Client.run, .{client}) catch fatal(prog, "cannot start the network thread", .{});
    thread.detach();

    while (tv.pollEvents(host_ui.sink.sink())) {
        if (tv.needsRedraw() or shared.version.load(.acquire) != host_ui.drawn_version) host_ui.frame();
        // Event-driven: the network thread wakes us on every Shared change
        // (Client.notify), input wakes us too; no idle polling.
        tv.waitEvents(TermView.forever);
    }
    tv.deinit();
    std.process.exit(0);
}

/// The CA to trust for `host`: imported from --ca, downloaded and checked
/// against --ca-sha256, or the one pinned earlier. Exits with instructions
/// when there is none: the client never trusts a server on first use.
fn pinnedCa(
    gpa: std.mem.Allocator,
    io: std.Io,
    prog: []const u8,
    host: []const u8,
    ca_file: ?[]const u8,
    ca_sha256: ?[]const u8,
    out: *[x509check.max_cert_len]u8,
) []const u8 {
    const p = pin_mod.Pin.forHost(host) catch |err|
        fatal(prog, "no per-user config directory for the pinned CA ({t})", .{err});
    const expected: ?[32]u8 = if (ca_sha256) |t| (x509check.parseFingerprint(t) catch
        fatal(prog, "--ca-sha256 wants the 64 hex digits `portal ca export` prints (AB:CD:...)", .{})) else null;

    var old_buf: [x509check.max_cert_len]u8 = undefined;
    const old: ?[]const u8 = p.load(io, &old_buf) catch |err| blk: {
        if (ca_file == null and ca_sha256 == null)
            fatal(prog, "the pinned CA {s} is unreadable ({t}); re-import it with --ca", .{ p.path(), err });
        break :blk null;
    };

    var der: []const u8 = undefined;
    var source: []const u8 = undefined;
    if (ca_file) |f| {
        der = pin_mod.readCaFile(io, f, out) catch |err|
            fatal(prog, "cannot use {s} as the Portal CA ({t}); pass portal-ca.pem or portal-ca.cer from `portal ca export`", .{ f, err });
        source = f;
    } else if (expected) |want| {
        if (old) |o| if (std.mem.eql(u8, &x509check.fingerprint(o), &want)) {
            @memcpy(out[0..o.len], o);
            return finish(prog, host, p.path(), out[0..o.len], "already pinned");
        };
        std.debug.print("{s}: downloading the CA from the desktop's pairing page (port + 1, open while `portal pair` runs)...\n", .{prog});
        der = client_mod.fetchCaCertificate(gpa, io, host, out) catch |err|
            fatal(prog, "could not download the CA: {s}. Run `portal pair <name>` on the desktop first, or use --ca FILE.", .{client_mod.describe(err)});
        source = "the download";
    } else if (old) |o| {
        @memcpy(out[0..o.len], o);
        return finish(prog, host, p.path(), out[0..o.len], "pinned");
    } else {
        fatal(prog,
            \\no Portal CA is pinned for {s}, so the server cannot be authenticated.
            \\  On the desktop run `portal ca export` (it prints the SHA-256 fingerprint),
            \\  copy portal-ca.pem here and run:
            \\      {s} --server {s} --ca portal-ca.pem
            \\  or, while `portal pair <name>` is open on the desktop:
            \\      {s} --server {s} --ca-sha256 <fingerprint>
        , .{ host, prog, host, prog, host });
    }

    var fp_buf: [95]u8 = undefined;
    const fp = x509check.fingerprint(der);
    if (expected) |want| if (!std.mem.eql(u8, &fp, &want)) {
        fatal(prog, "the CA from {s} has SHA-256 {s}, which is not the --ca-sha256 given. Not trusted.", .{ source, x509check.formatFingerprint(fp, &fp_buf) });
    };
    // A Portal CA is self-signed; this catches passing the server
    // certificate or some unrelated file by mistake.
    const parsed = x509check.parse(der) catch fatal(prog, "{s} is not a usable CA certificate", .{source});
    parsed.verify(parsed, std.Io.Clock.real.now(io).toSeconds()) catch |err|
        fatal(prog, "{s} is not a valid self-signed CA certificate ({t})", .{ source, err });

    if (old) |o| if (!std.mem.eql(u8, o, der)) {
        var ofp: [95]u8 = undefined;
        std.debug.print("{s}: replacing the CA pinned for {s} (was SHA-256 {s})\n", .{ prog, host, x509check.formatFingerprint(x509check.fingerprint(o), &ofp) });
    };
    p.save(io, der) catch |err| fatal(prog, "cannot save the pinned CA to {s}: {t}", .{ p.path(), err });
    return finish(prog, host, p.path(), der, "pinned now");
}

fn finish(prog: []const u8, host: []const u8, path: []const u8, der: []const u8, how: []const u8) []const u8 {
    var fp_buf: [95]u8 = undefined;
    const name = if (x509check.parse(der)) |p| p.commonName() else |_| "?";
    std.debug.print("{s}: https://{s}/ - the server certificate must be signed by\n  {s}, SHA-256 {s}\n  ({s}: {s})\n", .{
        prog, host, name, x509check.formatFingerprint(x509check.fingerprint(der), &fp_buf), how, path,
    });
    return der;
}

test {
    _ = @import("tests.zig");
}
