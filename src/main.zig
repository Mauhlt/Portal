//! Portal: watch (and answer prompts in) a terminal session running on this
//! desktop from a browser elsewhere, over a private network (WireGuard).
//!
//!   portal token [--force]           create or rotate the access token
//!   portal run [options] [-- cmd...] start a session (default cmd: claude)
//!   portal version

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const auth = @import("auth.zig");
const guard = @import("guard.zig");
const cmdline = @import("cmdline.zig");
const keymap = @import("keymap.zig");
const vt = @import("vt.zig");
const conpty = @import("conpty.zig");
const console_mod = @import("console.zig");
const Console = console_mod.Console;
const Session = @import("session.zig").Session;
const Log = @import("log.zig").Log;
const w = @import("win32.zig");
const web = @import("web.zig");

pub const portal_version = "0.1.0";
const default_listen = "127.0.0.1:8420";

const usage =
    \\Portal {s} - remote viewer for a desktop terminal session
    \\
    \\Usage:
    \\  portal token [--force]
    \\      Generate a new access token and print it once. Only its hash is
    \\      stored. A `portal run` that is already running keeps accepting
    \\      the OLD token until it is restarted.
    \\      Refuses unless stdout and stderr are an interactive console, so
    \\      the token is not captured by a redirect, pipe or agent
    \\      transcript. --force overrides that check.
    \\
    \\  portal run [options] [-- command args...]
    \\      Run `command` (default: claude) in this console and share it.
    \\      --listen IP:PORT   Address to listen on (default {s}).
    \\                         Use your WireGuard address, e.g. 10.8.0.1:8420.
    \\                         Wildcard and public addresses are refused.
    \\      --host NAME[:PORT] Extra Host header value to accept (repeatable).
    \\      --input MODE       none | keys | text   (default: keys)
    \\                           none: view only
    \\                           keys: digits, y/n, Enter, single Esc
    \\                                 (enough to answer prompts)
    \\                           text: FULL REMOTE CONTROL: new prompts,
    \\                                 ! shell commands, slash commands,
    \\                                 permission-mode changes, Ctrl+C exit
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
    if (std.mem.eql(u8, cmd, "token")) return cmdToken(gpa, io, init.environ_map, args[1..]);
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

/// Set (by the main thread only) once the console is in raw mode, so fatal()
/// can put it back before exiting.
var raw_console: ?*Console = null;

/// Exits the process. Safe to call after threads have been spawned: unlike
/// returning an error from cmdRun, it does not unwind the stack (freeing the
/// session, ring buffer, pty...) under threads that are still using them.
fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    if (raw_console) |c| c.restore();
    std.debug.print("portal: " ++ fmt ++ "\n", args);
    w.ExitProcess(1);
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

/// Returns whether --force was given, or null for an unknown argument.
fn parseTokenArgs(args: []const []const u8) ?bool {
    var force = false;
    for (args) |a| {
        if (std.mem.eql(u8, a, "--force")) force = true else return null;
    }
    return force;
}

fn cmdToken(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, args: []const []const u8) !void {
    const force = parseTokenArgs(args) orelse fatal("usage: portal token [--force]", .{});
    // Checked before anything is generated, so a refusal leaves the current
    // token untouched.
    if (!force and !console_mod.stdioIsInteractive()) fatal(
        \\refusing to print a new token: stdout/stderr is not an interactive
        \\console (redirected, piped, or run by a tool or agent), so the token
        \\would end up in a file or transcript. The existing token was NOT changed.
        \\Run `portal token` yourself in a console window, or pass --force.
    , .{});

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

    const log_path = try std.fs.path.join(gpa, &.{ dir, "portal.log" });
    defer gpa.free(log_path);
    if (Log.open(gpa, io, log_path)) |opened| {
        var log = opened;
        defer log.close();
        log.print("token rotated{s}; running instances keep accepting the old token until restarted", .{
            if (force) " (--force: console check skipped)" else "",
        });
    } else |err| {
        std.debug.print("portal: warning: could not open {s} ({t}); the rotation was not logged.\n", .{ log_path, err });
    }

    std.debug.print(
        \\New access token (shown once, store it in your password manager):
        \\
        \\    {s}
        \\
        \\Only its SHA-256 hash was saved to {s}
        \\
        \\IMPORTANT: a `portal run` that is already running keeps accepting the
        \\OLD token (and its logged-in browsers) until you restart it.
        \\
        \\Clear this screen now (Clear-Host / cls) so the token does not stay in
        \\the console scrollback.
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
    /// `keys` by default: a remote viewer can answer prompts but cannot
    /// start new work. `text` (full remote control) must be chosen explicitly.
    policy: keymap.Policy = .keys,
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
            o.policy = keymap.Policy.parse(args[i]) orelse fatal("--input must be none, keys or text", .{});
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

/// Suffix for the log line and banner when the remote side has full control.
fn policyNote(policy: keymap.Policy) []const u8 {
    return if (policy == .text) " (FULL REMOTE CONTROL)" else "";
}

const text_warning =
    \\
    \\  *****************************************************************
    \\  *  WARNING: --input text gives anyone logged in to the web page *
    \\  *  FULL REMOTE CONTROL of this session: new prompts, ! shell    *
    \\  *  commands, slash commands, permission-mode changes, Ctrl+C    *
    \\  *  exit. Use --input keys (the default) to only answer prompts. *
    \\  *****************************************************************
    \\
    \\
;

/// Consecutive non-EOF read failures after which the drain thread gives up
/// (about 10 s at 10 ms apart). Without a limit a permanently failing handle
/// would spin forever; without retries one transient failure would stop
/// draining and could leave ClosePseudoConsole waiting on conhost.
const max_read_failures = 1000;

/// How long shutdown waits for ClosePseudoConsole plus the output drain
/// before exiting anyway (process exit closes the job, which kills the child).
const shutdown_timeout_ms = 10_000;

const Threads = struct {
    fn ptyOutput(session: *Session, console: *Console, pty: *conpty.Pty, io: Io, done: *std.atomic.Value(bool)) void {
        defer done.store(true, .release);
        var buf: [32 * 1024]u8 = undefined;
        var failures: u32 = 0;
        while (true) {
            const n = pty.read(&buf) catch {
                // Keep draining until EOF: see max_read_failures.
                failures +|= 1;
                if (failures >= max_read_failures) return;
                io.sleep(.fromMilliseconds(10), .awake) catch {};
                continue;
            };
            failures = 0;
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

    fn closePty(session: *Session, done: *std.atomic.Value(bool)) void {
        session.shutdownPty();
        done.store(true, .release);
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
    var listen_host_buf: [128]u8 = undefined;
    const listen_host = try std.fmt.bufPrint(&listen_host_buf, "{f}", .{addr});
    try opts.hosts.append(gpa, listen_host);

    const dir = try dataDir(gpa, env);
    defer gpa.free(dir);
    try Io.Dir.cwd().createDirPath(io, dir);
    const log_path = try std.fs.path.join(gpa, &.{ dir, "portal.log" });
    defer gpa.free(log_path);
    // Fail closed: logins and viewer connections must be auditable.
    var log = Log.open(gpa, io, log_path) catch |err|
        fatal("cannot open audit log {s} ({t}); refusing to run without it.", .{ log_path, err });
    defer log.close();

    // Listen before starting the child so a port conflict fails fast.
    // The listener is never closed (see the end of this function).
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
    // From here on the child is running. Exit only via fatal()/ExitProcess:
    // process exit closes the job handle, which kills the child's tree.

    var session: Session = .{
        .io = io,
        .pty = &pty,
        .console = &console,
        .policy = opts.policy,
        // Owned by the session for the life of the process (exit is via
        // ExitProcess, so it is never freed explicitly).
        .term = vt.Terminal.init(gpa, initial.cols, initial.rows) catch fatal("out of memory", .{}),
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

    log.print("start: v{s} zig {s}, listening on {s}, input={t}{s}, command={s}", .{
        portal_version, builtin.zig_version_string, opts.listen, opts.policy, policyNote(opts.policy), opts.command[0],
    });
    if (opts.policy == .text) std.debug.print(text_warning, .{});
    std.debug.print("portal: sharing '{s}' on http://{s}/  (input: {t}{s})\n", .{
        opts.command[0], listen_host, opts.policy, policyNote(opts.policy),
    });

    console.enableRaw() catch fatal("could not switch console to raw mode", .{});
    raw_console = &console;
    console.setTitle("Portal - no remote viewers");

    // ------------------------------------------------------------------
    // Threads below use stack and heap memory owned by this frame. After the
    // first spawn this function must never return (no `try`, no `return`):
    // every exit goes through fatal() or ExitProcess.
    var out_done: std.atomic.Value(bool) = .init(false);
    const out_thread = std.Thread.spawn(.{}, Threads.ptyOutput, .{ &session, &console, &pty, io, &out_done }) catch |err|
        fatal("cannot start output thread: {t}", .{err});
    out_thread.detach(); // waited for via out_done, with a timeout
    const in_thread = std.Thread.spawn(.{}, Threads.consoleInput, .{ &session, &console }) catch |err|
        fatal("cannot start input thread: {t}", .{err});
    in_thread.detach(); // parked in ReadConsoleW; ends with the process
    const resize_thread = std.Thread.spawn(.{}, Threads.resizePoller, .{ &session, &console, io }) catch |err|
        fatal("cannot start resize thread: {t}", .{err});
    resize_thread.detach();
    const accept_thread = std.Thread.spawn(.{}, web.Server.run, .{&server}) catch |err|
        fatal("cannot start web server thread: {t}", .{err});
    accept_thread.detach();

    const code = pty.wait();
    // Let trailing output drain before tearing down the pseudo console.
    io.sleep(.fromMilliseconds(200), .awake) catch {};

    // ClosePseudoConsole can block (pre-24H2 it waits for conhost to flush),
    // so run it on its own thread and stop waiting after a timeout rather
    // than leaving the user's console hung. Session.shutdownPty stops resizes
    // and writes first, so nothing touches the freed HPCON or input pipe.
    var close_done: std.atomic.Value(bool) = .init(false);
    if (std.Thread.spawn(.{}, Threads.closePty, .{ &session, &close_done })) |t| {
        t.detach();
    } else |_| {
        Threads.closePty(&session, &close_done);
    }
    var waited: u32 = 0;
    while (!(close_done.load(.acquire) and out_done.load(.acquire)) and waited < shutdown_timeout_ms) : (waited += 20) {
        io.sleep(.fromMilliseconds(20), .awake) catch {};
    }
    const clean = close_done.load(.acquire) and out_done.load(.acquire);

    session.markClosed(code);
    log.print("stop: child exited with code {d}{s}", .{ code, if (clean) "" else " (pseudo console did not close in time)" });
    // Give viewers a moment to receive the exit notice.
    io.sleep(.fromMilliseconds(500), .awake) catch {};
    // Do NOT close the listener: the accept thread is blocked on it and std
    // hits `unreachable` on the cancelled accept. Process exit reclaims it.
    console.restore();
    // Full 32-bit exit code (std.process.exit takes a u8). Exiting here, not
    // returning, also keeps every thread's memory valid to the very end.
    w.ExitProcess(code);
}

test {
    _ = @import("keymap.zig");
    _ = @import("auth.zig");
    _ = @import("guard.zig");
    _ = @import("cmdline.zig");
    _ = @import("console.zig");
    _ = @import("session.zig");
    _ = @import("log.zig");
    _ = @import("vt.zig");
    _ = @import("web.zig"); // also pulls in http1.zig tests
}

test "parseListen" {
    const a = try parseListen("10.8.0.1:8420");
    try std.testing.expectEqual(@as(u16, 8420), a.getPort());
    _ = try parseListen("[::1]:8420");
    try std.testing.expectError(error.MissingPort, parseListen("10.8.0.1"));
    try std.testing.expectError(error.BadPort, parseListen("10.8.0.1:0"));
    try std.testing.expectError(error.BadPort, parseListen("10.8.0.1:99999"));
}

test "run defaults to keys input" {
    var o = try parseRunArgs(std.testing.allocator, &.{});
    defer o.hosts.deinit(std.testing.allocator);
    try std.testing.expectEqual(keymap.Policy.keys, o.policy);
    var t = try parseRunArgs(std.testing.allocator, &.{ "--input", "text" });
    defer t.hosts.deinit(std.testing.allocator);
    try std.testing.expectEqual(keymap.Policy.text, t.policy);
    try std.testing.expectEqualStrings("", policyNote(.keys));
    try std.testing.expect(std.mem.indexOf(u8, policyNote(.text), "FULL REMOTE CONTROL") != null);
}

test "parseTokenArgs" {
    try std.testing.expectEqual(@as(?bool, false), parseTokenArgs(&.{}));
    try std.testing.expectEqual(@as(?bool, true), parseTokenArgs(&.{"--force"}));
    try std.testing.expectEqual(@as(?bool, null), parseTokenArgs(&.{"--forc"}));
    try std.testing.expectEqual(@as(?bool, null), parseTokenArgs(&.{ "--force", "x" }));
}
