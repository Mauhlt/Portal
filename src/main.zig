//! Portal: watch (and answer prompts in) a terminal session running on this
//! desktop from a browser elsewhere, over a private network (WireGuard).
//!
//!   portal pair <name>               let a device pair (2-minute window)
//!   portal devices                   list paired devices
//!   portal unpair <name>             revoke a device
//!   portal run [options] [-- cmd...] start a session (default cmd: claude)
//!                                    in Portal's own window (gui.zig), or
//!                                    in this console with --console
//!   portal connect --server IP:PORT  view a remote Portal (client/src)
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
const devices = @import("devices.zig");
const w = @import("win32.zig");
const web = @import("web.zig");
const gui = @import("gui.zig");
const workdir = @import("workdir.zig");

pub const portal_version = "0.1.0";
const default_listen = "127.0.0.1:8420";

const usage =
    \\Portal {s} - remote viewer for a desktop terminal session
    \\
    \\Usage:
    \\  portal pair <name> [--minutes N]
    \\      Open a pairing window (default 2 minutes, max 10) for a device
    \\      called <name> (a-z, 0-9, -). On the device, with WireGuard on,
    \\      open http://10.8.0.1:8420/ and tap "Pair this device". Nothing
    \\      to type: the device gets its own credential, which rotates on
    \\      every use and is bound to its WireGuard address.
    \\
    \\  portal devices
    \\      List paired devices (and any open pairing window).
    \\
    \\  portal unpair <name>
    \\      Revoke a device immediately, even while `portal run` is running.
    \\
    \\  portal run [options] [-- command args...]
    \\      Run `command` (default: claude) in a Portal window and share it.
    \\      Closing the window ends the session.
    \\      --console          Run it in this console instead of a window.
    \\      --cwd DIR          Directory to start it in. Default: the
    \\                         terminal's current directory, or your home
    \\                         folder (%USERPROFILE%) when Portal was started
    \\                         without a terminal (double-click, Start menu,
    \\                         shortcut) or from inside its releases folder.
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
    \\  portal connect --server IP:PORT [--forget]
    \\      Watch a Portal running on another machine (pair with it first:
    \\      `portal pair <name>` there, then click Pair here).
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
    if (std.mem.eql(u8, cmd, "pair")) return cmdPair(gpa, io, init.environ_map, args[1..]);
    if (std.mem.eql(u8, cmd, "devices")) return cmdDevices(gpa, io, init.environ_map);
    if (std.mem.eql(u8, cmd, "unpair")) return cmdUnpair(gpa, io, init.environ_map, args[1..]);
    if (std.mem.eql(u8, cmd, "token")) fatal("access tokens were replaced by device pairing: run `portal pair <name>` (see `portal`)", .{});
    if (std.mem.eql(u8, cmd, "run")) return cmdRun(gpa, io, init.environ_map, args[1..]);
    if (std.mem.eql(u8, cmd, "connect")) @import("client").main(gpa, io, "portal connect", args[1..]);
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
/// Set once `portal run` has detached from its console for the window:
/// fatal() then shows a message box, since stderr may lead nowhere.
var console_freed = false;

/// Exits the process. Safe to call after threads have been spawned: unlike
/// returning an error from cmdRun, it does not unwind the stack (freeing the
/// session, ring buffer, pty...) under threads that are still using them.
fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    if (raw_console) |c| c.restore();
    std.debug.print("portal: " ++ fmt ++ "\n", args);
    if (console_freed) {
        var buf: [512]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, fmt, args) catch "Portal stopped because of an error.";
        var wbuf: [513:0]u16 = undefined;
        const n = std.unicode.utf8ToUtf16Le(wbuf[0..512], msg) catch 0;
        wbuf[n] = 0;
        _ = MessageBoxW(null, &wbuf, std.unicode.utf8ToUtf16LeStringLiteral("Portal"), 0x10); // MB_ICONERROR
    }
    w.ExitProcess(1);
}

extern "user32" fn MessageBoxW(hwnd: ?*anyopaque, text: [*:0]const u16, caption: [*:0]const u16, flags: u32) callconv(.winapi) i32;
extern "kernel32" fn FreeConsole() callconv(.winapi) w.BOOL;

// ------------------------------------------------------------- data paths

fn dataDir(gpa: Allocator, env: *const std.process.Environ.Map) ![]u8 {
    const base = env.get("LOCALAPPDATA") orelse return error.NoLocalAppData;
    return std.fs.path.join(gpa, &.{ base, "Portal" });
}

fn devicePaths(gpa: Allocator, io: Io, env: *const std.process.Environ.Map) !devices.Paths {
    const dir = try dataDir(gpa, env);
    try Io.Dir.cwd().createDirPath(io, dir);
    return .{ .dir = dir };
}

fn nowUnix(io: Io) i64 {
    return Io.Timestamp.now(io, .real).toSeconds();
}

fn openLog(gpa: Allocator, paths: devices.Paths, io: Io) ?Log {
    const log_path = std.fs.path.join(gpa, &.{ paths.dir, "portal.log" }) catch return null;
    defer gpa.free(log_path);
    return Log.open(gpa, io, log_path) catch null;
}

// ---------------------------------------------------------------- devices

fn cmdPair(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, args: []const []const u8) !void {
    if (args.len == 0) fatal("usage: portal pair <name> [--minutes N]", .{});
    const name = args[0];
    if (!devices.validName(name)) fatal("device name must be 1-32 characters of a-z, 0-9 and -", .{});
    var minutes: i64 = 2;
    if (args.len == 3 and std.mem.eql(u8, args[1], "--minutes")) {
        minutes = std.fmt.parseInt(i64, args[2], 10) catch fatal("--minutes needs a number", .{});
        if (minutes < 1 or minutes > 10) fatal("--minutes must be 1-10", .{});
    } else if (args.len != 1) fatal("usage: portal pair <name> [--minutes N]", .{});

    const paths = try devicePaths(gpa, io, env);
    defer gpa.free(paths.dir);
    const now = nowUnix(io);
    const Ctx = struct { name: []const u8, now: i64, secs: i64 };
    devices.withStore(gpa, io, paths, now, Ctx{ .name = name, .now = now, .secs = minutes * 60 }, struct {
        fn op(c: Ctx, st: *devices.Store) !bool {
            try st.beginPair(c.name, c.now, c.secs);
            return true;
        }
    }.op) catch |err| fatal("could not open the pairing window: {t}", .{err});
    if (openLog(gpa, paths, io)) |opened| {
        var log = opened;
        defer log.close();
        log.print("pairing window opened for '{s}' ({d} min)", .{ name, minutes });
    }
    std.debug.print(
        \\Pairing open for '{s}' for {d} minute(s).
        \\
        \\On the device: turn WireGuard on, open http://<this desktop's WireGuard
        \\address>:<port>/ (e.g. http://10.8.0.1:8420/), and tap "Pair this device".
        \\If `portal run` is not running yet, start it first.
        \\
    , .{ name, minutes });
}

fn cmdDevices(gpa: Allocator, io: Io, env: *const std.process.Environ.Map) !void {
    const paths = try devicePaths(gpa, io, env);
    defer gpa.free(paths.dir);
    const now = nowUnix(io);
    const Ctx = struct { now: i64 };
    devices.withStore(gpa, io, paths, now, Ctx{ .now = now }, struct {
        fn op(c: Ctx, st: *devices.Store) !bool {
            if (st.count() == 0) std.debug.print("No paired devices. Pair one with `portal pair <name>`.\n", .{});
            for (st.devices) |slot| {
                const d = slot orelse continue;
                std.debug.print("  {s: <20} {s: <18} last used {d} min ago\n", .{
                    d.name.get(), d.ip.get(), @divTrunc(c.now -| d.last_seen, 60),
                });
            }
            if (st.pairingName(c.now)) |n| std.debug.print("Pairing window open for '{s}'.\n", .{n});
            return false;
        }
    }.op) catch |err| fatal("could not read the device list: {t}", .{err});
}

fn cmdUnpair(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, args: []const []const u8) !void {
    if (args.len != 1) fatal("usage: portal unpair <name>", .{});
    const paths = try devicePaths(gpa, io, env);
    defer gpa.free(paths.dir);
    var removed = false;
    const Ctx = struct { name: []const u8, removed: *bool };
    devices.withStore(gpa, io, paths, nowUnix(io), Ctx{ .name = args[0], .removed = &removed }, struct {
        fn op(c: Ctx, st: *devices.Store) !bool {
            c.removed.* = st.remove(c.name);
            return c.removed.*;
        }
    }.op) catch |err| fatal("could not update the device list: {t}", .{err});
    if (!removed) fatal("no paired device named '{s}' (see `portal devices`)", .{args[0]});
    if (openLog(gpa, paths, io)) |opened| {
        var log = opened;
        defer log.close();
        log.print("device '{s}' unpaired from the desktop", .{args[0]});
    }
    std.debug.print("Unpaired '{s}'. Its open viewers are disconnected within a few seconds.\n", .{args[0]});
}

// -------------------------------------------------------------------- run

const RunOptions = struct {
    listen: []const u8 = default_listen,
    hosts: std.ArrayList([]const u8) = .empty,
    /// `keys` by default: a remote viewer can answer prompts but cannot
    /// start new work. `text` (full remote control) must be chosen explicitly.
    policy: keymap.Policy = .keys,
    https: bool = false,
    /// `--console`: the pre-GUI mode, drawn by this process's console.
    console: bool = false,
    /// `--cwd`: the child's working directory (see workdir.zig for the default).
    cwd: ?[]const u8 = null,
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
        const needs_value = std.mem.eql(u8, a, "--listen") or std.mem.eql(u8, a, "--host") or
            std.mem.eql(u8, a, "--input") or std.mem.eql(u8, a, "--cwd");
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
        } else if (std.mem.eql(u8, a, "--console")) {
            o.console = true;
        } else if (std.mem.eql(u8, a, "--cwd")) {
            i += 1;
            o.cwd = args[i];
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

    /// GUI mode: the main thread runs the window, so the child is waited
    /// for here.
    fn waitChild(pty: *conpty.Pty, code: *std.atomic.Value(u32), done: *std.atomic.Value(bool)) void {
        code.store(pty.wait(), .release);
        done.store(true, .release);
    }
};

/// The child's working directory as WTF-16 for CreateProcessW, or null to
/// inherit Portal's. `--cwd` must name an existing directory (relative to
/// Portal's current directory); otherwise workdir.defaultCwd decides.
fn childCwd(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, data_dir: []const u8, arg: ?[]const u8) ?[:0]u16 {
    const here: ?[:0]u8 = std.process.currentPathAlloc(io, gpa) catch null;
    defer if (here) |h| gpa.free(h);
    var chosen: []const u8 = undefined;
    var owned: ?[]u8 = null;
    defer if (owned) |o| gpa.free(o);
    if (arg) |a| {
        if (a.len == 0) fatal("--cwd needs a directory", .{});
        if (std.fs.path.isAbsolute(a)) {
            chosen = a;
        } else {
            const base = here orelse fatal("cannot resolve --cwd '{s}': current directory unknown", .{a});
            owned = std.fs.path.resolve(gpa, &.{ base, a }) catch fatal("out of memory", .{});
            chosen = owned.?;
        }
        var d = Io.Dir.cwd().openDir(io, chosen, .{}) catch |err| fatal("--cwd '{s}' is not an existing directory ({t})", .{ a, err });
        d.close(io);
    } else {
        const releases = std.fs.path.join(gpa, &.{ data_dir, "releases" }) catch null;
        defer if (releases) |r| gpa.free(r);
        const has_parent = workdir.hasParentConsole(env.get(workdir.launcher_env) != null);
        chosen = workdir.defaultCwd(has_parent, here, env.get("USERPROFILE"), releases) orelse return null;
        // A missing home folder is not worth failing over: inherit instead.
        var d = Io.Dir.cwd().openDir(io, chosen, .{}) catch return null;
        d.close(io);
    }
    return std.unicode.wtf8ToWtf16LeAllocZ(gpa, chosen) catch fatal("bad directory name '{s}'", .{chosen});
}

fn cmdRun(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, args: []const []const u8) !void {
    var opts = try parseRunArgs(gpa, args);
    defer opts.hosts.deinit(gpa);

    const paths = devicePaths(gpa, io, env) catch |err| fatal("cannot create the data directory: {t}", .{err});

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

    var resolved = cmdline.resolve(gpa, io, opts.command, env.get("PATH"), env.get("SystemRoot")) catch |err|
        fatal("cannot find program '{s}': {t}", .{ opts.command[0], err });
    defer resolved.deinit(gpa);

    // Working directory (before FreeConsole: the default depends on whether
    // a terminal started us).
    const cwd_w = childCwd(gpa, io, env, dir, opts.cwd);
    defer if (cwd_w) |c| gpa.free(c);

    if (opts.policy == .text) std.debug.print(text_warning, .{});
    std.debug.print("portal: sharing '{s}' on http://{s}/  (input: {t}{s})\n", .{
        opts.command[0], listen_host, opts.policy, policyNote(opts.policy),
    });

    // ---- GUI / console split (see gui.zig) ----------------------------
    // GUI (default): the console is only used for the banner, then freed
    // (Portal is a console-subsystem exe so the CLI commands print and
    // return exit codes normally). The window decides the PTY size.
    var console: Console = undefined;
    var host: ?*gui.LocalHost = null;
    var child_done: std.atomic.Value(bool) = .init(false);
    var child_code: std.atomic.Value(u32) = .init(1);
    var initial: conpty.Size = undefined;
    if (opts.console) {
        console = Console.init() catch fatal("portal run --console needs an interactive console (stdin/stdout are redirected)", .{});
        initial = console.size();
    } else {
        console = Console.detached();
        std.debug.print("portal: opening the Portal window; this console is not used by the session.\n", .{});
        _ = FreeConsole();
        console_freed = true;
        const h = gui.LocalHost.init(gpa, io, .{
            .command_name = std.fs.path.basename(opts.command[0]),
            .listen_host = listen_host,
            .policy = opts.policy,
        }, &child_done) catch |err| fatal("cannot open the Portal window: {t}", .{err});
        const sz = h.initialSize();
        initial = .{ .cols = sz[0], .rows = sz[1] };
        host = h;
    }
    // ---- end GUI / console split --------------------------------------


    var attr_buf: [256]u8 align(@alignOf(usize)) = undefined;
    var pty = conpty.Pty.spawn(resolved.app, resolved.cmdline, cwd_w, initial, &attr_buf) catch |err|
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
    if (host) |h| h.attach(&session);

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
            .devices = paths,
        },
    };

    log.print("start: v{s} zig {s}, listening on {s}, input={t}{s}, command={s}", .{
        portal_version, builtin.zig_version_string, opts.listen, opts.policy, policyNote(opts.policy), opts.command[0],
    });


    if (opts.console) {
        console.enableRaw() catch fatal("could not switch console to raw mode", .{});
        raw_console = &console;
        console.setTitle("Portal - no remote viewers");
    }

    // ------------------------------------------------------------------
    // Threads below use stack and heap memory owned by this frame. After the
    // first spawn this function must never return (no `try`, no `return`):
    // every exit goes through fatal() or ExitProcess.
    var out_done: std.atomic.Value(bool) = .init(false);
    const out_thread = std.Thread.spawn(.{}, Threads.ptyOutput, .{ &session, &console, &pty, io, &out_done }) catch |err|
        fatal("cannot start output thread: {t}", .{err});
    out_thread.detach(); // waited for via out_done, with a timeout
    if (opts.console) {
        const in_thread = std.Thread.spawn(.{}, Threads.consoleInput, .{ &session, &console }) catch |err|
            fatal("cannot start input thread: {t}", .{err});
        in_thread.detach(); // parked in ReadConsoleW; ends with the process
        const resize_thread = std.Thread.spawn(.{}, Threads.resizePoller, .{ &session, &console, io }) catch |err|
            fatal("cannot start resize thread: {t}", .{err});
        resize_thread.detach();
    }
    const accept_thread = std.Thread.spawn(.{}, web.Server.run, .{&server}) catch |err|
        fatal("cannot start web server thread: {t}", .{err});
    accept_thread.detach();

    var code: u32 = undefined;
    var window_closed = false;
    if (host) |h| {
        // GUI: the window owns the main thread; a waiter thread watches
        // the child. Closing the window ends the session the same way the
        // child exiting does (below): ClosePseudoConsole ends the child.
        const waiter = std.Thread.spawn(.{}, Threads.waitChild, .{ &pty, &child_code, &child_done }) catch |err|
            fatal("cannot start child waiter thread: {t}", .{err});
        waiter.detach();
        switch (h.run()) {
            .child_exited => {},
            .window_closed => {
                window_closed = true;
                h.hide();
                log.print("local window closed: ending the session", .{});
            },
        }
        code = child_code.load(.acquire);
    } else {
        code = pty.wait();
    }
    // Let trailing output drain before tearing down the pseudo console.
    if (!window_closed) io.sleep(.fromMilliseconds(200), .awake) catch {};

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
    if (window_closed) {
        // The child was ended by closing its pseudo console; report its
        // own exit code if it has gone within the remaining time.
        while (!child_done.load(.acquire) and waited < shutdown_timeout_ms) : (waited += 20) {
            io.sleep(.fromMilliseconds(20), .awake) catch {};
        }
        code = if (child_done.load(.acquire)) child_code.load(.acquire) else 1;
    }

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
    _ = @import("gui.zig");
    _ = @import("localgrid.zig");
    _ = @import("localinput.zig");
    _ = @import("workdir.zig");
    _ = @import("keymap.zig");
    _ = @import("auth.zig");
    _ = @import("guard.zig");
    _ = @import("cmdline.zig");
    _ = @import("console.zig");
    _ = @import("session.zig");
    _ = @import("log.zig");
    _ = @import("devices.zig");
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
    try std.testing.expect(!o.console);
    var c = try parseRunArgs(std.testing.allocator, &.{ "--console", "--", "cmd.exe" });
    defer c.hosts.deinit(std.testing.allocator);
    try std.testing.expect(c.console);
    try std.testing.expect(c.cwd == null);
    var d = try parseRunArgs(std.testing.allocator, &.{ "--cwd", "C:\\work", "--", "cmd.exe" });
    defer d.hosts.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("C:\\work", d.cwd.?);
    var t = try parseRunArgs(std.testing.allocator, &.{ "--input", "text" });
    defer t.hosts.deinit(std.testing.allocator);
    try std.testing.expectEqual(keymap.Policy.text, t.policy);
    try std.testing.expectEqualStrings("", policyNote(.keys));
    try std.testing.expect(std.mem.indexOf(u8, policyNote(.text), "FULL REMOTE CONTROL") != null);
}

