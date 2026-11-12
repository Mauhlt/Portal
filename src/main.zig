//! Portal: watch (and answer prompts in) a terminal session running on this
//! desktop from a browser elsewhere, over a private network (WireGuard).
//!
//!   portal token                     create or rotate the access token
//!   portal run [options] [-- cmd...] start a session (default cmd: claude)
//!   portal version

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const auth = @import("auth.zig");
const guard = @import("guard.zig");
const cmdline = @import("cmdline.zig");
const input_filter = @import("input_filter.zig");
const conpty = @import("conpty.zig");
const Console = @import("console.zig").Console;
const Session = @import("session.zig").Session;
const Log = @import("log.zig").Log;
const Ring = @import("ring.zig").Ring;
const web = @import("web.zig");

pub const portal_version = "0.1.0";
const default_listen = "127.0.0.1:8420";
const scrollback_bytes = 2 * 1024 * 1024;

const usage =
    \\Portal {s} - remote viewer for a desktop terminal session
    \\
    \\Usage:
    \\  portal token
    \\      Generate a new access token and print it once. Only its hash is
    \\      stored. Restart any running `portal run` for it to take effect.
    \\
    \\  portal run [options] [-- command args...]
    \\      Run `command` (default: claude) in this console and share it.
    \\      --listen IP:PORT   Address to listen on (default {s}).
    \\                         Use your WireGuard address, e.g. 10.8.0.1:8420.
    \\                         Wildcard and public addresses are refused.
    \\      --host NAME[:PORT] Extra Host header value to accept (repeatable).
    \\      --input MODE       none | keys | text   (default: text)
    \\                           none: view only
    \\                           keys: digits, y/n, Enter, Esc, arrows
    \\                           text: typing allowed
    \\      --https            Set when a TLS proxy (e.g. `tailscale serve`)
    \\                         fronts Portal: Secure cookies, https Origin.
    \\
    \\  portal version
    \\
;

pub fn main(init: std.process.Init) !void {
    if (builtin.os.tag != .windows) @compileError("Portal currently supports Windows only (ConPTY).");
    const gpa = init.gpa;
    const io = init.io;

    var args_list: std.ArrayList([]const u8) = .empty;
    defer args_list.deinit(gpa);
    var it: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |a| try args_list.append(gpa, a);
    const args = args_list.items;

    if (args.len == 0) return printUsage();
    const cmd = args[0];
    if (std.mem.eql(u8, cmd, "token")) return cmdToken(gpa, io, init.environ_map);
    if (std.mem.eql(u8, cmd, "run")) return cmdRun(gpa, io, init.environ_map, args[1..]);
    if (std.mem.eql(u8, cmd, "version")) {
        std.debug.print("portal {s} (built with zig {s})\n", .{ portal_version, builtin.zig_version_string });
        return;
    }
    return printUsage();
}

fn printUsage() void {
    std.debug.print(usage, .{ portal_version, default_listen });
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("portal: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

// ------------------------------------------------------------- data paths

fn dataDir(gpa: Allocator, env: *const std.process.Environ.Map) ![]u8 {
    const base = env.get("LOCALAPPDATA") orelse return error.NoLocalAppData;
    return std.fs.path.join(gpa, &.{ base, "Portal" });
}

fn tokenPath(gpa: Allocator, env: *const std.process.Environ.Map) ![]u8 {
    const dir = try dataDir(gpa, env);
    defer gpa.free(dir);
    return std.fs.path.join(gpa, &.{ dir, "token.sha256" });
}

// ------------------------------------------------------------------ token

fn cmdToken(gpa: Allocator, io: Io, env: *const std.process.Environ.Map) !void {
    const dir = try dataDir(gpa, env);
    defer gpa.free(dir);
    try Io.Dir.cwd().createDirPath(io, dir);
    const path = try tokenPath(gpa, env);
    defer gpa.free(path);

    var raw: [auth.secret_bytes]u8 = undefined;
    io.randomSecure(&raw) catch fatal("could not obtain secure randomness", .{});
    var encoded: [auth.encoded_len]u8 = undefined;
    const token = auth.encodeSecret(&raw, &encoded);
    std.crypto.secureZero(u8, &raw);

    var file_buf: [128]u8 = undefined;
    const contents = try auth.formatTokenFile(auth.hashSecret(token), &file_buf);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = contents });

    std.debug.print(
        \\New access token (shown once, store it in your password manager):
        \\
        \\    {s}
        \\
        \\Only its SHA-256 hash was saved to {s}
        \\Restart any running `portal run` to use it; old browser sessions end then.
        \\
    , .{ token, path });
    std.crypto.secureZero(u8, &encoded);
}

fn loadTokenHash(gpa: Allocator, io: Io, env: *const std.process.Environ.Map) !auth.Hash {
    const path = try tokenPath(gpa, env);
    defer gpa.free(path);
    const contents = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4096)) catch |err| switch (err) {
        error.FileNotFound => fatal("no access token yet. Run `portal token` first.", .{}),
        else => return err,
    };
    defer gpa.free(contents);
    return auth.parseTokenFile(contents) catch fatal("token file {s} is corrupt; run `portal token` again.", .{path});
}

// -------------------------------------------------------------------- run

const RunOptions = struct {
    listen: []const u8 = default_listen,
    hosts: std.ArrayList([]const u8) = .empty,
    policy: input_filter.Policy = .text,
    https: bool = false,
    command: []const []const u8 = &.{"claude"},
};

fn parseRunArgs(gpa: Allocator, args: []const []const u8) !RunOptions {
    var o: RunOptions = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--")) {
            if (i + 1 >= args.len) fatal("nothing after --", .{});
            o.command = args[i + 1 ..];
            break;
        }
        const needs_value = std.mem.eql(u8, a, "--listen") or std.mem.eql(u8, a, "--host") or std.mem.eql(u8, a, "--input");
        if (needs_value and i + 1 >= args.len) fatal("{s} needs a value", .{a});
        if (std.mem.eql(u8, a, "--listen")) {
            i += 1;
            o.listen = args[i];
        } else if (std.mem.eql(u8, a, "--host")) {
            i += 1;
            try o.hosts.append(gpa, args[i]);
        } else if (std.mem.eql(u8, a, "--input")) {
            i += 1;
            o.policy = input_filter.Policy.parse(args[i]) orelse fatal("--input must be none, keys or text", .{});
        } else if (std.mem.eql(u8, a, "--https")) {
            o.https = true;
        } else {
            fatal("unknown option {s} (see `portal` for usage)", .{a});
        }
    }
    return o;
}

fn parseListen(text: []const u8) !std.Io.net.IpAddress {
    // Accept "a.b.c.d:port" and "[v6]:port".
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.MissingPort;
    var host = text[0..colon];
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return error.BadPort;
    if (port == 0) return error.BadPort;
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') host = host[1 .. host.len - 1];
    return std.Io.net.IpAddress.parse(host, port);
}

const Threads = struct {
    fn ptyOutput(session: *Session, console: *Console, pty: *conpty.Pty) void {
        var buf: [32 * 1024]u8 = undefined;
        while (true) {
            const n = pty.read(&buf) catch 0;
            if (n == 0) return;
            console.write(buf[0..n]);
            session.appendOutput(buf[0..n]);
        }
    }

    fn consoleInput(session: *Session, console: *Console) void {
        var buf: [4 * 1024]u8 = undefined;
        while (true) {
            const n = console.readInput(&buf) catch return;
            session.writeInput(buf[0..n]);
        }
    }

    fn resizePoller(session: *Session, console: *Console, io: Io) void {
        while (true) {
            io.sleep(.fromMilliseconds(250), .awake) catch return;
            session.setSize(console.size());
        }
    }
};

fn cmdRun(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, args: []const []const u8) !void {
    var opts = try parseRunArgs(gpa, args);
    defer opts.hosts.deinit(gpa);

    const token_hash = try loadTokenHash(gpa, io, env);

    const addr = parseListen(opts.listen) catch fatal("bad --listen value '{s}' (want IP:PORT)", .{opts.listen});
    guard.checkListenAddress(addr) catch |err| switch (err) {
        error.WildcardAddress => fatal("refusing to listen on all interfaces ({s}). Use your WireGuard address.", .{opts.listen}),
        error.PublicAddress => fatal("refusing to listen on a public address ({s}). Use loopback or your WireGuard address.", .{opts.listen}),
    };

    // Host header allowlist: the listen address as browsers write it, plus --host values.
    var listen_host_buf: [64]u8 = undefined;
    const listen_host = try std.fmt.bufPrint(&listen_host_buf, "{f}", .{addr});
    try opts.hosts.append(gpa, listen_host);

    const dir = try dataDir(gpa, env);
    defer gpa.free(dir);
    try Io.Dir.cwd().createDirPath(io, dir);
    const log_path = try std.fs.path.join(gpa, &.{ dir, "portal.log" });
    defer gpa.free(log_path);
    var log = Log.open(gpa, io, log_path);
    defer log.close();

    // Listen before starting the child so a port conflict fails fast.
    const listener = addr.listen(io, .{ .reuse_address = false }) catch |err|
        fatal("cannot listen on {s}: {t}", .{ opts.listen, err });

    var console = Console.init() catch fatal("portal run needs an interactive console (stdin/stdout are redirected)", .{});
    const initial = console.size();

    var resolved = cmdline.resolve(gpa, io, opts.command, env.get("PATH"), env.get("SystemRoot")) catch |err|
        fatal("cannot find program '{s}': {t}", .{ opts.command[0], err });
    defer resolved.deinit(gpa);

    var attr_buf: [256]u8 align(@alignOf(usize)) = undefined;
    var pty = conpty.Pty.spawn(resolved.app, resolved.cmdline, null, initial, &attr_buf) catch |err|
        fatal("could not start '{s}': {t}", .{ opts.command[0], err });

    const ring_buf = try gpa.alloc(u8, scrollback_bytes);
    defer gpa.free(ring_buf);
    var session: Session = .{
        .io = io,
        .pty = &pty,
        .console = &console,
        .policy = opts.policy,
        .ring = Ring.init(ring_buf),
        .size = initial,
    };

    var server: web.Server = .{
        .gpa = gpa,
        .io = io,
        .session = &session,
        .log = &log,
        .listener = listener,
        .cfg = .{
            .allowed_hosts = opts.hosts.items,
            .scheme = if (opts.https) "https" else "http",
            .secure_cookie = opts.https,
            .token_hash = token_hash,
        },
    };

    log.print("start: v{s} zig {s}, listening on {s}, input={t}, command={s}", .{
        portal_version, builtin.zig_version_string, opts.listen, opts.policy, opts.command[0],
    });
    std.debug.print("portal: sharing '{s}' on http://{s}/  (input: {t})\n", .{ opts.command[0], listen_host, opts.policy });

    console.enableRaw() catch fatal("could not switch console to raw mode", .{});
    defer console.restore();
    console.setTitle("Portal - no remote viewers");

    const out_thread = try std.Thread.spawn(.{}, Threads.ptyOutput, .{ &session, &console, &pty });
    const in_thread = try std.Thread.spawn(.{}, Threads.consoleInput, .{ &session, &console });
    in_thread.detach(); // parked in ReadConsoleW; ends with the process
    const resize_thread = try std.Thread.spawn(.{}, Threads.resizePoller, .{ &session, &console, io });
    resize_thread.detach();
    const accept_thread = try std.Thread.spawn(.{}, web.Server.run, .{&server});
    accept_thread.detach();

    const code = pty.wait();
    // Let trailing output drain before tearing down the pseudo console.
    io.sleep(.fromMilliseconds(200), .awake) catch {};
    session.input_mutex.lockUncancelable(io);
    pty.close();
    session.input_mutex.unlock(io);
    out_thread.join();
    session.markClosed(code);
    log.print("stop: child exited with code {d}", .{code});
    // Give viewers a moment to receive the exit notice.
    io.sleep(.fromMilliseconds(500), .awake) catch {};
    // Do NOT close the listener: the accept thread is blocked on it and std
    // hits `unreachable` on the cancelled accept. Process exit reclaims it.
    console.restore();
    std.process.exit(@truncate(code));
}

test {
    _ = @import("ring.zig");
    _ = @import("input_filter.zig");
    _ = @import("auth.zig");
    _ = @import("guard.zig");
    _ = @import("cmdline.zig");
    _ = @import("console.zig");
}

test "parseListen" {
    const a = try parseListen("10.8.0.1:8420");
    try std.testing.expectEqual(@as(u16, 8420), a.getPort());
    _ = try parseListen("[::1]:8420");
    try std.testing.expectError(error.MissingPort, parseListen("10.8.0.1"));
    try std.testing.expectError(error.BadPort, parseListen("10.8.0.1:0"));
    try std.testing.expectError(error.BadPort, parseListen("10.8.0.1:99999"));
}
