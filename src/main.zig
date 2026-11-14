//! Portal: watch (and answer prompts in) a terminal session running on this
//! desktop from a laptop or iPhone elsewhere, over a private network (WireGuard).
//!
//! One source, two programs (build option `gui`, see build.zig):
//!
//!   portal.exe (Windows GUI subsystem: never a console window)
//!     portal                           the Portal window with the saved
//!                                      settings (settings.zig); on first
//!                                      run the window asks for them
//!     portal run [options] [-- cmd...] the window, options overriding them
//!     portal connect [--server IP:PORT] view a remote Portal (client/src)
//!   Errors go to a message box. Pairing, devices and the CA export are
//!   panels inside the window (gui.zig, deskui.zig).
//!
//!   portalctl.exe (console, for scripts and tests)
//!     portalctl pair <name>            let a device pair (2-minute window,
//!                                      each request approved at the desk)
//!     portalctl devices                list paired devices
//!     portalctl unpair <name>          revoke a device
//!     portalctl run --console [options] [-- cmd...]
//!                                      a session in this console
//!     portalctl ca [init|export|show]  the private CA behind Portal's HTTPS
//!     portalctl show <file.png>        same as portal-show
//!     portalctl version
//!
//!   portal-show.exe <file.png>         show an image inline (show.zig);
//!                                      runs inside sessions

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const cmdline = @import("cmdline.zig");
const tunneldesk = @import("tunneldesk.zig");
const shared = @import("shared");
const tunnelnet = shared.tunnelnet;
const transport = shared.transport;
const keymap = @import("keymap.zig");
const vt = @import("vt.zig");
const conpty = @import("conpty.zig");
const console_mod = @import("console.zig");
const Console = console_mod.Console;
const Session = @import("session.zig").Session;
const tabs = @import("tabs.zig");
const tabs_wire = @import("shared").tabs;
const projects_wire = @import("shared").projects;
const openreq = @import("openreq.zig");
const hookmsg = @import("hookmsg.zig");
const hookpipe = @import("hookpipe.zig");
const statusline = @import("statusline.zig");
const usage_desk = @import("usage_desk.zig");
const agenthooks = @import("agenthooks.zig");
const Log = @import("log.zig").Log;
const devices = @import("devices.zig");
const fsutil = @import("fsutil.zig");
const w = @import("win32.zig");
const web = @import("web.zig");
const gui = @import("gui.zig");
const title = @import("title.zig");
const workdir = @import("workdir.zig");
const tls_server = @import("tls/server.zig");
const x509 = @import("tls/x509.zig");
const pki = @import("tls/pki.zig");
const settings = @import("settings.zig");
const sysmon = @import("sysmon.zig");
const sync = @import("sync.zig");
const sync_cli = @import("sync_cli.zig");
const ScrubIdentity = @import("convo/scrub.zig").Identity;

/// True in portal.exe (the window), false in portalctl.exe (build.zig).
pub const gui_app = @import("build_options").gui;

/// [fix2/desk] Root panic handler: logs to portal.log, message box in GUI mode.
pub const panic = @import("panic.zig").handler;

pub const portal_version = "0.1.0";


const usage =
    \\Portal {s} - share a desktop terminal session with your own devices
    \\
    \\The Portal window is portal.exe: start it with `portal` (or a
    \\double-click), `portal run [options] [-- command args...]`, or
    \\`portal connect` for the remote viewer. It never opens a console.
    \\This is portalctl, its console tool:
    \\
    \\Usage:
    \\  portalctl pair <name> <device key>
    \\      Pair a device called <name> (a-z, 0-9, -) whose WireGuard public
    \\      key is <device key> (`portal connect` shows it on the device, with
    \\      its check code). Prints the check code of the key you typed and
    \\      asks [y/N]: approve only if the device shows the same code. Then
    \\      prints the pairing code to enter on the device (this desktop's
    \\      key, tunnel endpoint, CA fingerprint and the device's address).
    \\      The device is its key: nothing secret is ever typed. The Portal
    \\      window does the same in Pair a device (Ctrl+Shift+P).
    \\
    \\  portalctl devices
    \\      List paired devices: name, tunnel address, key and check code.
    \\
    \\  portalctl unpair <name>
    \\      Revoke a device immediately, even while Portal is running: its
    \\      key is no longer let into the tunnel.
    \\
    \\  portalctl run --console [options] [-- command args...]
    \\      Run `command` in this console and share it (the window is
    \\      `portal run`, which takes the same options). Without `-- command`
    \\      the program saved by the Portal window (settings.txt) is used;
    \\      there is no built-in default.
    \\      --cwd DIR          Directory to start it in. Default: the
    \\                         terminal's current directory, or your home
    \\                         folder (%USERPROFILE%) when started from
    \\                         inside Portal's own folders.
    \\      --tunnel-port N    Portal's own WireGuard UDP port (default {d}).
    \\                         Devices reach the session only through it,
    \\                         at 10.8.0.1:8420 inside the tunnel.
    \\      --tunnel-endpoint HOST:PORT
    \\                         Where devices reach that port (public IP or
    \\                         DNS name), put into their pairing codes.
    \\      --tunnel-loopback  Tests: the UDP port on 127.0.0.1 only.
    \\      --input MODE       none | keys | instruct | text   (default:
    \\                         instruct; keys when the program is a shell)
    \\                           none: view only
    \\                           keys: digits, y/n, Enter, single Esc
    \\                                 (enough to answer prompts). At an
    \\                                 idle prompt those keys are typed
    \\                                 like any text, so a device can
    \\                                 submit a line of digits/y/n (e.g.
    \\                                 "1", Enter) as a prompt; nothing
    \\                                 else can be typed
    \\                           instruct: keys, plus whole instruction
    \\                                 lines that Portal checks first: no
    \\                                 ! shell escape, no / slash commands,
    \\                                 no # memory, no control characters.
    \\                                 A device's instruction line (typing or
    \\                                 dictation) sends these lines
    \\                           text: FULL REMOTE CONTROL: new prompts,
    \\                                 slash commands, permission-mode
    \\                                 changes, Ctrl+C exit (a leading ! a
    \\                                 device types is still dropped)
    \\      --allow-remote-shell  Allow instruct/text input when the session
    \\                         program is itself a shell (cmd, PowerShell,
    \\                         bash, wsl...). Refused by default: remote
    \\                         typing into a shell is a remote shell.
    \\      --project NAME     Project name for the window title ("Portal -
    \\                         NAME"; printable, one line, at most 64 bytes).
    \\                         Without it the title is "Portal - No project";
    \\                         the program's own title is never shown.
    \\      --allow-elevated   Run even as administrator. Refused by default:
    \\                         the session program, and everything a paired
    \\                         device types into it, would run as admin.

    \\
    \\  portalctl open <folder> [--name NAME]
    \\      Open <folder> as a new project tab in the running Portal (the
    \\      same program, started in that folder). The tab is named after
    \\      the folder (or NAME); remote devices see the name and colour,
    \\      never the path. In the window: Ctrl+Shift+T. Devices can switch
    \\      between open tabs but can never open or close one.
    \\
    \\  portalctl hooks install [--exe PATH] | uninstall | status
    \\      Claude Code integration: add (or remove) Portal's hooks in
    \\      Claude Code's settings.json (%CLAUDE_CONFIG_DIR% or
    \\      %USERPROFILE%\.claude). Each hook runs `portalctl hook`, which
    \\      tells the running Portal over a local, current-user-only pipe
    \\      when Claude in a tab works, waits for an answer or is done.
    \\      Everything else in the file stays as it is; a backup is kept
    \\      next to it. In the window: Settings, "Claude Code integration".
    \\  portalctl hook
    \\      Run by Claude Code (reads the hook's JSON on stdin); does nothing
    \\      outside a Portal tab.
    \\  portalctl statusline
    \\      Claude Code's status line in the sessions Portal starts (Portal
    \\      passes it with --settings; your own settings stay as they are):
    \\      hands the plan's usage percentages to Portal's usage bar.
    \\
    \\  portalctl ca [show]
    \\      Show the private CA that signs Portal's HTTPS certificate.
    \\  portalctl ca init [--permit CIDR]... [--permit-dns NAME]... [--force]
    \\      Create the CA (Portal does this on first use). Its name
    \\      constraints only allow the --permit subnets (default
    \\      10.8.0.0/24 and 127.0.0.1/32) and --permit-dns names (default:
    \\      none). --force replaces an existing CA: every device must then
    \\      trust the new one.
    \\  portalctl ca export [--out DIR]
    \\      Write portal-ca.cer, portal-ca.pem and portal-ca.mobileconfig
    \\      (default: current directory) and print the fingerprint and the
    \\      iPhone trust steps. (In the window: Export certificate.)
    \\
    \\  portalctl show <file.png> [--cols N] [--stdout]
    \\      Same as `portal-show`: show a PNG inline in this terminal (kitty
    \\      graphics). Inside a Portal session the image appears in the window
    \\      and for remote viewers. Reads only the file named.
    \\
    \\  portalctl sync key [show | init [--force]]
    \\      The release key (Ed25519, DPAPI-protected, separate from the CA)
    \\      that signs packages for your devices. Devices pin it when they
    \\      pair; replacing it (--force) means pairing each device again.
    \\  portalctl publish <package> <folder> --kind data|executable
    \\                    [--version V] [--min-client V]
    \\      Hash, sign and publish a folder as a new version of <package>
    \\      (e.g. stt-model, stt-adapter, stt-local, npu-probe). Data installs
    \\      on subscribed devices by itself; executables need approval on
    \\      the device, every version. Nothing is ever run automatically.
    \\  portalctl publish --list
    \\  portalctl unpublish <package> <version>
    \\  portalctl sync subscribe|unsubscribe <device> <package>
    \\  portalctl sync subscriptions
    \\      Which device receives which package.
    \\  portalctl sync-device --pairing-code CODE [--approve]
    \\                    [--wait-updates S] [--only PKG]
    \\      Headless device side (tests): its own tunnel, then fetch, verify
    \\      and install what the desktop offers. --approve stands for the
    \\      approval click in the app. Also --key (print this device's
    \\      key), --status, --rollback PKG and --forget.
    \\
    \\  portalctl startable add <folder> [--name NAME] [--mode ask|plan]
    \\  portalctl startable remove <name>
    \\  portalctl startable list
    \\      The projects a paired device may start (settings.txt, the one
    \\      place they are kept; a running Portal follows the file). Devices
    \\      see the name only, never the folder. --mode is how a device
    \\      start runs Claude Code: ask (default: every edit and command
    \\      needs approval) or plan (read-only planning). In the window:
    \\      Projects (Ctrl+Shift+J).
    \\
    \\  portalctl version
    \\
;

/// What portal.exe shows (in a message box) for anything it doesn't run.
const gui_usage =
    \\Portal {s}
    \\
    \\portal                     open the Portal window (first run: it asks what to run)
    \\portal run [options] [-- program args...]
    \\                           the window, with options overriding the saved settings
    \\                           (--tunnel-port, --input, --project, --cwd,
    \\                            --allow-remote-shell, --allow-elevated)
    \\portal open <folder> [--name NAME]
    \\                           open a folder as a new tab in the running Portal
    \\portal connect             watch a Portal on another machine (through
    \\                           its own WireGuard tunnel; first run: pair)
    \\
    \\Console commands (pair, devices, unpair, ca, show, version, run --console)
    \\are in portalctl.exe, installed next to portal.exe.
;

pub fn main(init: std.process.Init) !void {
    if (builtin.os.tag != .windows) @compileError("Portal currently supports Windows only (ConPTY).");
    const gpa = init.gpa;
    const io = init.io;
    if (gui_app) {
        // No console, ever: errors and panics go to message boxes.
        message_boxes = true;
        @import("panic.zig").gui_mode.store(true, .release);
    }

    var args_list: std.ArrayList([]const u8) = .empty;
    defer args_list.deinit(gpa);
    var it: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |a| try args_list.append(gpa, a);
    const args = args_list.items;

    if (gui_app) return guiMain(gpa, io, init.environ_map, args);
    if (args.len == 0) return printUsage();
    const cmd = args[0];
    // Run by the agent for each hook event: never prints, always exits
    // 0, and does nothing outside a Portal tab (hookpipe.hookCommand).
    if (std.mem.eql(u8, cmd, "hook")) {
        const dir = dataDir(gpa, init.environ_map) catch null;
        hookpipe.hookCommand(io, init.environ_map.get(hookmsg.env_name), dir, init.environ_map.get(hookmsg.guard_env_name));
        std.process.exit(0);
    }
    // The agent's status line in the sessions Portal starts (only those:
    // usage_desk.zig): reads the plan's windows from stdin, hands them to
    // Portal, prints a short line; always exits 0.
    if (std.mem.eql(u8, cmd, "statusline")) {
        const dir = dataDir(gpa, init.environ_map) catch null;
        statusline.command(init.environ_map.get(hookmsg.env_name), dir);
        std.process.exit(0);
    }
    if (std.mem.eql(u8, cmd, "hooks")) std.process.exit(agenthooks.command(gpa, io, init.environ_map, args[1..]));
    if (std.mem.eql(u8, cmd, "pair")) return cmdPair(gpa, io, init.environ_map, args[1..]);
    if (std.mem.eql(u8, cmd, "devices")) return cmdDevices(gpa, io, init.environ_map);
    if (std.mem.eql(u8, cmd, "unpair")) return cmdUnpair(gpa, io, init.environ_map, args[1..]);
    if (std.mem.eql(u8, cmd, "token")) fatal("access tokens were replaced by device pairing: run `portalctl pair <name>` (see `portalctl`)", .{});
    if (std.mem.eql(u8, cmd, "run")) return cmdRun(gpa, io, init.environ_map, args[1..]);
    if (std.mem.eql(u8, cmd, "open")) return cmdOpen(gpa, io, init.environ_map, args[1..]);
    if (std.mem.eql(u8, cmd, "startable")) return cmdStartable(gpa, io, init.environ_map, args[1..]);
    if (std.mem.eql(u8, cmd, "connect")) fatal("the remote viewer is a window: run `portal connect` (portal.exe)", .{});
    if (std.mem.eql(u8, cmd, "ca")) return cmdCa(gpa, io, init.environ_map, args[1..]);
    if (std.mem.eql(u8, cmd, "show")) std.process.exit(@import("show.zig").main(gpa, io, args[1..]));
    if (std.mem.eql(u8, cmd, "sync") or std.mem.eql(u8, cmd, "publish") or std.mem.eql(u8, cmd, "unpublish")) {
        const paths = try devicePaths(gpa, io, init.environ_map);
        const sp: sync.Paths = .{ .dir = paths.dir };
        if (cmd[0] == 's') return sync_cli.cmdSync(gpa, io, sp, args[1..]);
        if (cmd[0] == 'p') return sync_cli.cmdPublish(gpa, io, sp, args[1..]);
        return sync_cli.cmdUnpublish(io, sp, args[1..]);
    }
    if (std.mem.eql(u8, cmd, "sync-device")) return sync_cli.cmdSyncDevice(gpa, io, args[1..], portal_version);
    if (std.mem.eql(u8, cmd, "version")) {
        std.debug.print("portal {s} (built with zig {s})\n", .{ portal_version, builtin.zig_version_string });
        return;
    }
    return printUsage();
}

/// portal.exe: the window (`portal`, `portal run ...`) or the remote
/// viewer (`portal connect ...`). Everything else is portalctl's.
fn guiMain(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, args: []const []const u8) !void {
    if (args.len == 0) return cmdRun(gpa, io, env, args);
    const cmd = args[0];
    if (std.mem.eql(u8, cmd, "run")) return cmdRun(gpa, io, env, args[1..]);
    if (std.mem.eql(u8, cmd, "open")) return cmdOpen(gpa, io, env, args[1..]);
    if (std.mem.startsWith(u8, cmd, "--")) return cmdRun(gpa, io, env, args); // `portal --input ...`
    if (std.mem.eql(u8, cmd, "connect")) {
        const client = @import("client");
        client.report_fn = messageBox;
        client.main(gpa, io, "portal connect", args[1..]);
    }
    if (std.mem.eql(u8, cmd, "show")) {
        // Old habit inside a session: run it on the session's console.
        if (w.AttachConsole(w.ATTACH_PARENT_PROCESS) != 0) std.process.exit(@import("show.zig").main(gpa, io, args[1..]));
        fatal("`show` runs inside a session: use portal-show <file.png>.", .{});
    }
    if (std.mem.eql(u8, cmd, "version")) {
        var buf: [128]u8 = undefined;
        messageBox(std.fmt.bufPrint(&buf, "Portal {s} (built with zig {s})", .{ portal_version, builtin.zig_version_string }) catch "Portal");
        return;
    }
    var buf: [1536]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, gui_usage, .{portal_version}) catch "portal: unknown command";
    var full_buf: [1700]u8 = undefined;
    const known = std.mem.eql(u8, cmd, "pair") or std.mem.eql(u8, cmd, "devices") or std.mem.eql(u8, cmd, "unpair") or std.mem.eql(u8, cmd, "ca");
    const msg = if (known)
        std.fmt.bufPrint(&full_buf, "`{s}` is a console command: run `portalctl {s} ...`.\n\n{s}", .{ cmd, cmd, text }) catch text
    else
        std.fmt.bufPrint(&full_buf, "Unknown command `{s}`.\n\n{s}", .{ cmd, text }) catch text;
    messageBox(msg);
    w.ExitProcess(2);
}


/// An information box (the GUI program's stdout).
fn messageBox(text: []const u8) void {
    showBox(text, 0x40); // MB_ICONINFORMATION
}

fn showBox(text: []const u8, flags: u32) void {
    var wbuf: [2049:0]u16 = undefined;
    const n = std.unicode.utf8ToUtf16Le(wbuf[0..2048], text[0..@min(text.len, 2048)]) catch 0;
    wbuf[n] = 0;
    _ = w.MessageBoxW(null, &wbuf, std.unicode.utf8ToUtf16LeStringLiteral("Portal"), flags);
}

fn printUsage() void {
    std.debug.print(usage, .{ portal_version, tunnelnet.default_udp_port });
}

/// Set (by the main thread only) once the console is in raw mode, so fatal()
/// can put it back before exiting.
var raw_console: ?*Console = null;
/// portal.exe has no console: fatal() shows a message box, since stderr
/// leads nowhere.
var message_boxes = false;

/// Exits the process. Safe to call after threads have been spawned: unlike
/// returning an error from cmdRun, it does not unwind the stack (freeing the
/// session, ring buffer, pty...) under threads that are still using them.
fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    if (raw_console) |c| c.restore();
    std.debug.print("portal: " ++ fmt ++ "\n", args);
    if (message_boxes) {
        var buf: [1024]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, fmt, args) catch "Portal stopped because of an error.";
        showBox(msg, 0x10); // MB_ICONERROR
    }
    w.ExitProcess(1);
}


// ------------------------------------------------------------- data paths

fn dataDir(gpa: Allocator, env: *const std.process.Environ.Map) ![]u8 {
    const base = env.get("LOCALAPPDATA") orelse return error.NoLocalAppData;
    return std.fs.path.join(gpa, &.{ base, "Portal" });
}

/// Portal's status line settings file for the agent (the plan-usage bar,
/// usage_desk.zig), when the program is the agent and passes no
/// `--settings` itself; null (and a log line saying why) otherwise.
fn statusSettings(gpa: Allocator, io: Io, log: *Log, env: *const std.process.Environ.Map, command: []const []const u8) ?[]const u8 {
    if (!cmdline.wantsSettings(command)) {
        if (cmdline.isAgent(command[0])) log.print("usage: the program setting passes --settings itself; no plan-usage bar", .{});
        return null;
    }
    const dir = dataDir(gpa, env) catch return null;
    defer gpa.free(dir);
    var why: []const u8 = "unknown";
    const path = usage_desk.prepare(gpa, io, dir, &why) orelse {
        log.print("usage: no plan-usage bar: {s}", .{why});
        return null;
    };
    if (!cmdline.pathArg(path)) {
        log.print("usage: no plan-usage bar: the data folder's path has characters a command line would misread", .{});
        gpa.free(path);
        return null;
    }
    return path;
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


/// SHA-256 of the Portal CA, if one exists yet (never creates one).
fn caFingerprint(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, out: *[95]u8) ?[]const u8 {
    const store = tlsStore(gpa, io, env) catch return null;
    defer gpa.free(store.dir);
    var ca = (pki.loadCa(store) catch return null) orelse return null;
    defer ca.deinit(gpa);
    return x509.formatFingerprint(x509.fingerprint(ca.der), out);
}

/// "y" / "yes" (any case, surrounding blanks ignored) approves; anything
/// else, including an empty line, denies. A leading UTF-8 byte order mark
/// is ignored: .NET and PowerShell write one at the start of a redirected
/// stdin (`'y' | portalctl pair laptop KEY`), which would otherwise turn the
/// answer into a denial.
pub fn isYes(line: []const u8) bool {
    const bom = "\xEF\xBB\xBF";
    const l = if (std.mem.startsWith(u8, line, bom)) line[bom.len..] else line;
    const t = std.mem.trim(u8, l, " \t\r");
    return std.ascii.eqlIgnoreCase(t, "y") or std.ascii.eqlIgnoreCase(t, "yes");
}

fn pairLog(gpa: Allocator, paths: devices.Paths, io: Io, comptime fmt: []const u8, args: anytype) void {
    if (openLog(gpa, paths, io)) |opened| {
        var log = opened;
        defer log.close();
        log.print(fmt, args);
    }
}

/// What the desk shows a newly paired device: the pairing code (its own
/// key, endpoint, the CA fingerprint and the device's address) and the
/// check code of the desk's key. Shared by `portalctl pair` and the
/// window (gui.zig) so both say the same.
pub const PairingInfo = struct {
    code_buf: [shared.pairqr.max_len_tunnel]u8 = undefined,
    code_len: usize = 0,
    desk_check: [shared.tunnelnet.check_code_len]u8 = undefined,

    pub fn code(p: *const PairingInfo) []const u8 {
        return p.code_buf[0..p.code_len];
    }

    pub fn make(desk_public: *const tunneldesk.Key, endpoint: []const u8, ca_sha256: [32]u8, d: *const devices.Device) !PairingInfo {
        var p: PairingInfo = .{ .desk_check = shared.tunnelnet.checkCode(desk_public) };
        p.code_len = (try tunneldesk.pairingCode(&p.code_buf, desk_public, endpoint, ca_sha256, d)).len;
        return p;
    }
};

/// In a pairing code while no tunnel endpoint is set (Settings): a valid
/// name that says what to do, so the device shows it when it fails.
pub const placeholder_endpoint = "set-the-tunnel-endpoint-in-settings:51820";

/// The CA's SHA-256 (32 bytes), if there is a CA.
fn caSha256(gpa: Allocator, io: Io, env: *const std.process.Environ.Map) ?[32]u8 {
    const store = tlsStore(gpa, io, env) catch return null;
    defer gpa.free(store.dir);
    var ca = (pki.loadCa(store) catch return null) orelse return null;
    defer ca.deinit(gpa);
    return x509.fingerprint(ca.der);
}

/// `portalctl pair <name> <device key>`: the console form of Pair a
/// device. Shows the check code of the key that was typed; only if the
/// owner confirms it matches the device's screen is the device recorded
/// (its key goes into the running Portal's tunnel at once), and the
/// pairing code for the device is printed. Nothing crosses the network.
fn cmdPair(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, args: []const []const u8) !void {
    const usage_pair = "usage: portalctl pair <name> <the device's WireGuard public key, as `portal connect` shows it> [--endpoint HOST:PORT]";
    if (args.len != 2 and args.len != 4) fatal(usage_pair, .{});
    var endpoint_arg: ?[]const u8 = null;
    if (args.len == 4) {
        if (!std.mem.eql(u8, args[2], "--endpoint") or !gui.validEndpoint(args[3])) fatal(usage_pair, .{});
        endpoint_arg = args[3];
    }
    const name = args[0];
    if (!devices.validName(name)) fatal("device name must be 1-32 characters of a-z, 0-9 and -", .{});
    const key = tunneldesk.tunnel.keys.parsePublic(args[1]) orelse fatal("'{s}' is not a WireGuard public key (44 characters ending in =, as the device shows it)", .{args[1]});

    const paths = try devicePaths(gpa, io, env);
    defer gpa.free(paths.dir);
    const desk_public = blk: {
        var kp = tunneldesk.loadOrCreate(gpa, io, paths) catch |err| fatal("cannot load or create this desktop's WireGuard key: {t}", .{err});
        defer kp.wipe();
        break :blk kp.public;
    };
    const ca = caSha256(gpa, io, env) orelse fatal("no Portal CA yet: start Portal once (it creates one), then pair", .{});

    const check = shared.tunnelnet.checkCode(&key);
    std.debug.print("Device '{s}'\n  key        {s}\n  check code {s}\n\nApprove only if the device shows the same check code.\nPair it? [y/N] ", .{ name, args[1], &check });
    var ibuf: [256]u8 = undefined;
    var r = Io.File.stdin().reader(io, &ibuf);
    const line = (r.interface.takeDelimiter('\n') catch null) orelse "";
    if (!isYes(line)) {
        std.debug.print("Not paired.\n", .{});
        std.process.exit(1);
    }
    const desk: devices.Desk = .{ .gpa = gpa, .io = io, .paths = paths };
    const paired = desk.pair(name, key, desk_public) catch |err|
        fatal("could not pair '{s}': {s} ({t})", .{ name, devices.describeError(err), err });
    for (paired.replaced.items()) |old| pairLog(gpa, paths, io, "pairing '{s}' replaced the earlier record of '{s}'", .{ name, old.name.get() });
    var ib: [shared.tunnelnet.max_ip_text]u8 = undefined;
    pairLog(gpa, paths, io, "device '{s}' paired at the desk as {s} (key check code {s})", .{ name, paired.device.ipText(&ib), &check });

    const saved = settings.load(gpa, io, paths.dir);
    const endpoint = endpoint_arg orelse saved.tunnel_endpoint.get() orelse placeholder_endpoint;
    const info = PairingInfo.make(&desk_public, endpoint, ca, &paired.device) catch fatal("the tunnel endpoint in Settings is too long", .{});
    std.debug.print(
        \\Paired '{s}' as {s}.
        \\
        \\On the device, enter this pairing code (or scan it from Pair a device in the window):
        \\  {s}
        \\The device then shows this desktop's key check code: it must be {s}.
        \\
    , .{ name, paired.device.ipText(&ib), info.code(), &info.desk_check });
    if (endpoint_arg == null and saved.tunnel_endpoint.get() == null)
        std.debug.print("Note: set the tunnel endpoint in the Portal window's Settings first (where devices reach this desktop's UDP {d}); the code above has a placeholder.\n", .{saved.tunnelPort()});
}

fn cmdDevices(gpa: Allocator, io: Io, env: *const std.process.Environ.Map) !void {
    const paths = try devicePaths(gpa, io, env);
    defer gpa.free(paths.dir);
    const st = devices.read(gpa, io, paths) catch |err| fatal("could not read the device list: {s} ({t})", .{ devices.describeError(err), err });
    if (st.count() == 0) std.debug.print("No paired devices. Pair one with `portalctl pair <name> <key>`.\n", .{});
    const now = nowUnix(io);
    for (st.devices) |slot| {
        const d = slot orelse continue;
        var ib: [shared.tunnelnet.max_ip_text]u8 = undefined;
        std.debug.print("  {s: <20} {s: <10} {s}  {s}  last used {d} min ago\n", .{
            d.name.get(), d.ipText(&ib), &d.keyText(), &shared.tunnelnet.checkCode(&d.key), @divTrunc(now -| d.last_seen, 60),
        });
    }
}

fn cmdUnpair(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, args: []const []const u8) !void {
    if (args.len != 1) fatal("usage: portalctl unpair <name>", .{});
    const paths = try devicePaths(gpa, io, env);
    defer gpa.free(paths.dir);
    const desk: devices.Desk = .{ .gpa = gpa, .io = io, .paths = paths };
    const removed = desk.unpair(args[0]) catch |err| fatal("could not update the device list: {s} ({t})", .{ devices.describeError(err), err });
    if (removed == null) fatal("no paired device named '{s}' (see `portalctl devices`)", .{args[0]});
    pairLog(gpa, paths, io, "device '{s}' unpaired from the desktop", .{args[0]});
    std.debug.print("Unpaired '{s}'. Its key is no longer let in, and its open connections end within a few seconds.\n", .{args[0]});
}

// --------------------------------------------------------------------- ca

fn tlsStore(gpa: Allocator, io: Io, env: *const std.process.Environ.Map) !pki.Store {
    const dir = try dataDir(gpa, env);
    defer gpa.free(dir);
    const tls_dir = try std.fs.path.join(gpa, &.{ dir, "tls" });
    try Io.Dir.cwd().createDirPath(io, tls_dir);
    return .{ .gpa = gpa, .io = io, .dir = tls_dir };
}

fn printConstraints(c: *const x509.Constraints) void {
    for (c.subnets[0..c.n_subnets]) |s| std.debug.print("    IP  {f}\n", .{s});
    if (c.n_dns == 1 and std.mem.eql(u8, c.dns[0], "invalid")) {
        std.debug.print("    DNS (none: only the reserved name 'invalid')\n", .{});
    } else for (c.dns[0..c.n_dns]) |d| std.debug.print("    DNS {s}\n", .{d});
    if (c.closed_rfc822 and c.closed_uri and c.directory_portal)
        std.debug.print("    email / URI names: none; directory name: O=Portal only\n", .{});
}

fn printDate(label: []const u8, unix_s: i64) void {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(unix_s, 0)) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    std.debug.print("{s}{d}-{d:0>2}-{d:0>2}\n", .{ label, yd.year, md.month.numeric(), @as(u32, md.day_index) + 1 });
}

fn cmdCa(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, args: []const []const u8) !void {
    const store = tlsStore(gpa, io, env) catch |err| fatal("cannot create the TLS directory: {t}", .{err});
    defer gpa.free(store.dir);
    const sub: []const u8 = if (args.len > 0) args[0] else "show";
    const rest = if (args.len > 0) args[1..] else args;

    if (std.mem.eql(u8, sub, "init")) {
        var c: x509.Constraints = .{};
        var force = false;
        var i: usize = 0;
        while (i < rest.len) : (i += 1) {
            const a = rest[i];
            if (std.mem.eql(u8, a, "--force")) {
                force = true;
            } else if (std.mem.eql(u8, a, "--permit") or std.mem.eql(u8, a, "--permit-dns")) {
                if (i + 1 >= rest.len) fatal("{s} needs a value", .{a});
                i += 1;
                if (a.len == "--permit".len) {
                    if (c.n_subnets == x509.max_subnets) fatal("at most {d} --permit subnets", .{x509.max_subnets});
                    c.subnets[c.n_subnets] = x509.Subnet.parse(rest[i]) catch fatal("bad --permit '{s}' (want e.g. 10.8.0.0/24)", .{rest[i]});
                    c.n_subnets += 1;
                } else {
                    if (c.n_dns == x509.max_dns) fatal("at most {d} --permit-dns names", .{x509.max_dns});
                    if (!x509.validDnsName(rest[i])) fatal("bad --permit-dns '{s}'", .{rest[i]});
                    c.dns[c.n_dns] = rest[i];
                    c.n_dns += 1;
                }
            } else fatal("usage: portalctl ca init [--permit CIDR]... [--permit-dns NAME]... [--force]", .{});
        }
        if (c.n_subnets == 0) {
            const d = pki.defaultConstraints();
            c.subnets = d.subnets;
            c.n_subnets = d.n_subnets;
        }
        var ca = pki.initCa(store, &c, nowUnix(io), force) catch |err| switch (err) {
            error.CaExists => fatal("a Portal CA already exists (see `portalctl ca`). Replacing it means re-trusting it on every device; add --force to do that.", .{}),
            else => fatal("could not create the CA: {t}", .{err}),
        };
        defer ca.deinit(gpa);
        var fp: [95]u8 = undefined;
        std.debug.print("Created {s}\n  SHA-256 {s}\n  permitted names:\n", .{ ca.commonName(), x509.formatFingerprint(x509.fingerprint(ca.der), &fp) });
        printConstraints(&ca.constraints);
        std.debug.print("Next: `portalctl ca export` and trust it on each device.\n", .{});
        return;
    }

    var ca = (pki.loadCa(store) catch |err| fatal("cannot read the Portal CA in {s}: {t}", .{ store.dir, err })) orelse
        fatal("no Portal CA yet: run `portalctl ca init` (or just start Portal, which creates one)", .{});
    defer ca.deinit(gpa);
    var fp: [95]u8 = undefined;
    const fingerprint = x509.formatFingerprint(x509.fingerprint(ca.der), &fp);

    if (std.mem.eql(u8, sub, "export")) {
        var out_dir: []const u8 = ".";
        if (rest.len == 2 and std.mem.eql(u8, rest[0], "--out")) {
            out_dir = rest[1];
        } else if (rest.len != 0) fatal("usage: portalctl ca export [--out DIR]", .{});
        _ = pki.exportCa(gpa, io, &ca, out_dir) catch |err| fatal("export to {s} failed: {t}", .{ out_dir, err });
        std.debug.print(
            \\Wrote to {s}:
            \\  portal-ca.cer           DER certificate (Windows, macOS, Android, Linux)
            \\  portal-ca.pem           PEM certificate (Linux, curl --cacert)
            \\  portal-ca.mobileconfig  Apple configuration profile (iPhone, iPad, Mac)
            \\
            \\{s}
            \\SHA-256 fingerprint: {s}
            \\
            \\{s}
            \\Windows: double-click portal-ca.cer > Install Certificate > Current User >
            \\  "Trusted Root Certification Authorities". macOS: open the profile or the
            \\  .cer in Keychain Access and set "Always Trust". Android: Settings >
            \\  Security > Encryption & credentials > Install a certificate > CA certificate.
            \\
        , .{ out_dir, ca.commonName(), fingerprint, pki.iphone_steps });
        return;
    }
    if (!std.mem.eql(u8, sub, "show")) fatal("usage: portalctl ca [show | init ... | export [--out DIR]]", .{});

    std.debug.print("{s}\n  SHA-256 {s}\n  files   {s}\n", .{ ca.commonName(), fingerprint, store.dir });
    printDate("  valid until ", ca.info.not_after);
    const ca_left = ca.secondsLeft(nowUnix(io));
    if (ca_left <= 0) {
        std.debug.print("  EXPIRED: run `portalctl ca init --force` (devices must re-trust)\n", .{});
    } else {
        std.debug.print("  remaining {d} days{s}\n", .{ @divFloor(ca_left, 86400), if (ca_left < pki.ca_warn_before_s) " (renew soon: `portalctl ca init --force`, devices must re-trust)" else "" });
    }
    if (!ca.currentProfile())
        std.debug.print("  old CA profile (no extKeyUsage serverAuth / closed name forms) - run `portalctl ca init --force` to upgrade (devices must re-trust)\n", .{});
    std.debug.print("  key     DPAPI, current user: any program running as you can use it\n", .{});
    std.debug.print("  permitted names (name constraints):\n", .{});
    printConstraints(&ca.constraints);
    const leaf_path = std.fs.path.join(gpa, &.{ store.dir, "leaf.crt" }) catch return;
    defer gpa.free(leaf_path);
    const leaf_der = Io.Dir.cwd().readFileAlloc(io, leaf_path, gpa, .limited(64 * 1024)) catch {
        std.debug.print("  no server certificate yet (issued when Portal starts)\n", .{});
        return;
    };
    defer gpa.free(leaf_der);
    const leaf = x509.parse(leaf_der) catch {
        std.debug.print("  server certificate unreadable (re-issued when Portal next starts)\n", .{});
        return;
    };
    std.debug.print("  server certificate:\n", .{});
    printDate("    valid until ", leaf.not_after);
    var spki_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(leaf.spki_raw, &spki_hash, .{});
    var b64: [44]u8 = undefined;
    std.debug.print("    SPKI SHA-256 (base64) {s}\n", .{std.base64.standard.Encoder.encode(&b64, &spki_hash)});
}

const TlsSetup = struct { ca: pki.Ca, leaf: pki.Leaf };

/// Loads (or on first use creates) the CA and makes sure the server
/// certificate covers the desk's tunnel address.
fn setupTls(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, log: *Log) TlsSetup {
    const store = tlsStore(gpa, io, env) catch |err| fatal("cannot create the TLS directory: {t}", .{err});
    const now = nowUnix(io);
    const ca = (pki.loadCa(store) catch |err|
        fatal("cannot read the Portal CA in {s}: {t} (move the tls folder away to start over)", .{ store.dir, err })) orelse blk: {
        const c = pki.defaultConstraints();
        const created = pki.initCa(store, &c, now, false) catch |err| fatal("cannot create the Portal CA: {t}", .{err});
        std.debug.print("portal: created {s}, limited to 10.8.0.0/24 and 127.0.0.1.\n" ++
            "       Devices pin it from the fingerprint in their pairing code.\n", .{created.commonName()});
        log.print("created {s}", .{created.commonName()});
        break :blk created;
    };
    const ca_left = ca.secondsLeft(now);
    if (ca_left <= 0)
        fatal("the Portal CA has expired. Run `portalctl ca init --force`, then trust the new CA on every device.", .{});
    if (ca_left < pki.ca_warn_before_s) {
        std.debug.print("portal: warning: the Portal CA expires in {d} days; server certificates end with it. " ++
            "Run `portalctl ca init --force` and re-trust it on each device.\n", .{@divFloor(ca_left, 86400)});
        log.print("CA expires in {d} days", .{@divFloor(ca_left, 86400)});
    }
    if (!ca.currentProfile())
        std.debug.print("portal: note: old CA profile - run `portalctl ca init --force` to upgrade (devices must re-trust).\n", .{});

    // The one name devices use: the desk's tunnel address.
    const desk_ip: [16]u8 = tunnelnet.desk_ip ++ @as([12]u8, @splat(0));
    if (!ca.constraints.ipPermitted(desk_ip[0..4])) {
        std.debug.print("permitted by the Portal CA:\n", .{});
        printConstraints(&ca.constraints);
        fatal("the desk's tunnel address (10.8.0.1) is outside the Portal CA's name constraints. Re-create the CA with " ++
            "`portalctl ca init --force` (every device must then be paired again).", .{});
    }
    const sans = [_]x509.SanEntry{.{ .ip = .{ .bytes = desk_ip, .len = 4 } }};
    const leaf = pki.ensureLeaf(store, &ca, &sans, now) catch |err| fatal("cannot issue the server certificate: {t}", .{err});
    if (leaf.renewed) |why| {
        log.print("issued a new server certificate ({s})", .{why});
        std.debug.print("portal: issued a new server certificate ({s}).\n", .{why});
    }
    return .{ .ca = ca, .leaf = leaf };
}

/// The device store watcher, one thread for the life of the process.
/// Sleeps until a file in the data directory is created, renamed or
/// deleted (every device-store change ends in one: a pairing or Unpair at
/// the desk, `portalctl pair/unpair`, a device forgetting this desktop).
/// On each wake it re-reads the store once and applies it to the server
/// and the tunnel in tunneldesk.Applier's order: addresses whose key
/// changed or went are refused and their connections end (with a
/// `logout` saying why) before the tunnel gets the new peer table (only
/// paired keys get in, each only from its own address), and are let in
/// again only once it took it. A failed read changes nothing.
///
/// The window's own pairing and Unpair do not wait for the watch: they
/// call `reload` themselves (gui.Desk.store) and report its result.
const StoreWatch = struct {
    srv: *web.Server,
    tun: *tunneldesk.tunnel.Tunnel,
    /// The data directory's change watch, opened before the thread starts
    /// (Portal refuses to run without it).
    dw: ?fsutil.DirWatch,
    paths: devices.Paths,
    io: Io,
    gpa: Allocator,

    /// Serializes applies (the watch thread, the window's desk actions).
    mutex: Io.Mutex = .init,
    /// What the tunnel's peer table was last made from.
    applier: tunneldesk.Applier = .{},
    /// The change watch is gone (could not be re-opened, or its thread
    /// ended): `portalctl` changes are not seen until Portal restarts.
    lost: std.atomic.Value(bool) = .init(false),
    /// The last apply could not update the tunnel's peer table (changed
    /// addresses stay refused).
    tunnel_failed: std.atomic.Value(bool) = .init(false),

    /// Re-reads the store and applies it. An error if the read or the
    /// tunnel's peer table failed (both logged; the latter also shown on
    /// the desk until an apply succeeds).
    fn reload(sw: *StoreWatch) !void {
        sw.mutex.lockUncancelable(sw.io);
        defer sw.mutex.unlock(sw.io);
        const st = devices.read(sw.gpa, sw.io, sw.paths) catch |err| {
            sw.srv.noteStoreError(err);
            return err;
        };
        sw.applier.apply(sw.srv, sw.tun, &st) catch |err| {
            sw.srv.log.print("ERROR: the tunnel's peer table could not be updated ({t}); the addresses of changed devices stay refused until it is", .{err});
            if (!sw.tunnel_failed.swap(true, .acq_rel)) sw.srv.storeChanged();
            return err;
        };
        if (sw.tunnel_failed.swap(false, .acq_rel)) {
            sw.srv.log.print("the tunnel's peer table is up to date again", .{});
            sw.srv.storeChanged();
        }
    }

    /// Re-arms the change watch; if that fails, re-opens it once. Losing
    /// it ends the watch thread (`watch`, which shows it on the desk).
    fn rearm(sw: *StoreWatch) void {
        var d = sw.dw orelse return;
        d.rearm() catch {
            d.close();
            sw.dw = devices.watchStore(sw.gpa, sw.paths) catch |err| {
                sw.dw = null;
                sw.srv.log.print("ERROR: lost the change watch on {s} ({t})", .{ sw.paths.dir, err });
                return;
            };
            sw.srv.log.print("change watch on {s} was lost and has been re-opened", .{sw.paths.dir});
        };
    }

    fn watch(sw: *StoreWatch) void {
        while (true) {
            const d = sw.dw orelse break;
            if (w.WaitForMultipleObjects(1, &[1]w.HANDLE{d.h}, 0, w.INFINITE) != w.WAIT_OBJECT_0) break;
            _ = sw.srv.pairwatch_wakes.fetchAdd(1, .monotonic);
            sw.rearm(); // before reading: a change made meanwhile signals again
            sw.reload() catch {};
        }
        // `portalctl pair`/`unpair` and devices forgetting this desktop
        // are not seen any more; the window's own actions still apply.
        sw.lost.store(true, .release);
        sw.srv.log.print("ERROR: the device store watcher stopped: `portalctl pair`/`unpair` changes are not applied until Portal restarts", .{});
        sw.srv.storeChanged();
    }

    // gui.Desk.StoreHook
    fn hookReload(ctx: *anyopaque) anyerror!void {
        const sw: *StoreWatch = @ptrCast(@alignCast(ctx));
        return sw.reload();
    }

    fn hookProblem(ctx: *anyopaque) ?[]const u8 {
        const sw: *StoreWatch = @ptrCast(@alignCast(ctx));
        if (sw.tunnel_failed.load(.acquire)) return "Tunnel peer table not updated: changed devices are refused (see the log)";
        if (sw.lost.load(.acquire)) return "Not watching the device list: portalctl pair/unpair need a restart";
        return null;
    }

    fn hook(sw: *StoreWatch) gui.Desk.StoreHook {
        return .{ .ctx = sw, .reload = hookReload, .problem = hookProblem };
    }
};

/// Portal sync, event-driven like StoreWatch: sleeps until a file is
/// created, renamed or deleted in the data directory (the subscriptions
/// and device lists are replaced by rename) or anywhere under publish\
/// (a publish ends in a folder rename). On each wake it hashes every
/// subscribed device's GET /sync/index and hands the digests to the
/// server, whose WebSocket writers send {"t":"updates"} to the devices
/// whose index changed. Nothing polls.
const SyncWatch = struct {
    srv: *web.Server,
    paths: sync.Paths,
    io: Io,
    gpa: Allocator,

    fn refresh(sw: *SyncWatch) void {
        const subs = sync.readSubs(sw.gpa, sw.io, sw.paths) catch |err| {
            sw.srv.log.print("sync: subscriptions unreadable ({t}); keeping the last state", .{err});
            return;
        };
        var list: [devices.max_devices]web.SyncDigest = undefined;
        var n: usize = 0;
        for (subs.items[0..subs.n]) |x| {
            const dev = x.device.get();
            var seen = false;
            for (list[0..n]) |d| seen = seen or std.mem.eql(u8, d.device.get(), dev);
            if (seen or n == list.len) continue;
            const idx = sync.buildIndex(sw.gpa, sw.io, sw.paths, dev) catch continue;
            defer sw.gpa.free(idx);
            list[n] = .{};
            list[n].device.set(dev);
            std.crypto.hash.sha2.Sha256.hash(idx, &list[n].digest, .{});
            n += 1;
        }
        sw.srv.setSyncDigests(list[0..n]);
    }

    fn watch(sw: *SyncWatch) void {
        var pb: [1024]u8 = undefined;
        const publish_dir = sw.paths.join(&pb, &.{"publish"}) catch return;
        Io.Dir.cwd().createDirPath(sw.io, publish_dir) catch {};
        var watches: [2]fsutil.DirWatch = undefined;
        watches[0] = fsutil.DirWatch.open(sw.gpa, sw.paths.dir, .{ .dirs = true }) catch |err| return sw.lost(err);
        watches[1] = fsutil.DirWatch.open(sw.gpa, publish_dir, .{ .dirs = true, .subtree = true }) catch |err| return sw.lost(err);
        const handles = [2]w.HANDLE{ watches[0].h, watches[1].h };
        sw.refresh();
        while (true) {
            const r = w.WaitForMultipleObjects(handles.len, &handles, 0, w.INFINITE);
            if (r >= w.WAIT_OBJECT_0 + handles.len) return sw.lost(error.WaitFailed);
            // Re-arm before re-reading, so a change made meanwhile signals again.
            watches[r - w.WAIT_OBJECT_0].rearm() catch |err| return sw.lost(err);
            sw.refresh();
        }
    }

    fn lost(sw: *SyncWatch, err: anyerror) void {
        sw.srv.log.print("ERROR: sync: cannot watch {s} for changes ({t}); devices learn about new packages only when they reconnect", .{ sw.paths.dir, err });
    }
};

// -------------------------------------------------------------------- run

/// What the command line said. Unset values come from settings.txt
/// (mergeConfig); command-line values win.
const RunOptions = struct {
    /// `--tunnel-port N`: the WireGuard UDP port (default 51820).
    tunnel_port: ?u16 = null,
    /// `--tunnel-endpoint HOST:PORT`: where devices reach that port.
    tunnel_endpoint: ?[]const u8 = null,
    /// `--tunnel-loopback`: bind the UDP port to 127.0.0.1 only (tests:
    /// devices on this machine; never reachable from the network, no
    /// firewall prompt).
    tunnel_loopback: bool = false,
    /// `instruct` unless chosen (here or in settings): a paired device
    /// answers prompts and sends checked instruction lines (no shell escape,
    /// slash commands or memory shortcut). For a shell the default drops to
    /// `keys` (see `defaultPolicy`). `text` (full remote control) must be
    /// chosen explicitly.
    policy: ?keymap.Policy = null,
    /// `--console`: the pre-GUI mode, drawn by this process's console
    /// (portalctl only).
    console: bool = false,
    /// `--cwd`: the child's working directory (see workdir.zig for the default).
    cwd: ?[]const u8 = null,
    /// Allow instruct/text input when the session program is a shell.
    allow_remote_shell: bool = false,
    /// `--project`: shown in the window title (title.validProject).
    project: ?[]const u8 = null,
    /// `--allow-elevated`: run even with an administrator token.
    allow_elevated: bool = false,
    /// After `--`. No default: settings.txt, or the window asks.
    command: ?[]const []const u8 = null,
};

fn parseRunArgs(args: []const []const u8) RunOptions {
    var o: RunOptions = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--")) {
            if (i + 1 >= args.len) fatal("nothing after --", .{});
            o.command = args[i + 1 ..];
            break;
        }
        const needs_value = std.mem.eql(u8, a, "--tunnel-port") or std.mem.eql(u8, a, "--tunnel-endpoint") or
            std.mem.eql(u8, a, "--input") or std.mem.eql(u8, a, "--cwd") or std.mem.eql(u8, a, "--project");
        if (needs_value and i + 1 >= args.len) fatal("{s} needs a value", .{a});
        if (std.mem.eql(u8, a, "--tunnel-port")) {
            i += 1;
            o.tunnel_port = settings.parsePort(args[i]) orelse fatal("--tunnel-port must be 1-65535", .{});
        } else if (std.mem.eql(u8, a, "--tunnel-endpoint")) {
            i += 1;
            if (args[i].len > settings.max_endpoint) fatal("--tunnel-endpoint is too long", .{});
            o.tunnel_endpoint = args[i];
        } else if (std.mem.eql(u8, a, "--tunnel-loopback")) {
            o.tunnel_loopback = true;
        } else if (std.mem.eql(u8, a, "--input")) {
            i += 1;
            o.policy = keymap.Policy.parse(args[i]) orelse fatal("--input must be none, keys, instruct or text", .{});
        } else if (std.mem.eql(u8, a, "--allow-remote-shell")) {
            o.allow_remote_shell = true;
        } else if (std.mem.eql(u8, a, "--allow-elevated")) {
            o.allow_elevated = true;
        } else if (std.mem.eql(u8, a, "--project")) {
            i += 1;
            if (!title.validProject(args[i])) fatal("--project must be 1-{d} bytes of printable text on one line", .{title.max_project_bytes});
            o.project = args[i];
        } else if (std.mem.eql(u8, a, "--listen") or std.mem.eql(u8, a, "--host") or std.mem.eql(u8, a, "--no-tls")) {
            fatal("{s} was removed: devices reach Portal only through its own WireGuard tunnel (--tunnel-port), always over TLS", .{a});
        } else if (std.mem.eql(u8, a, "--console")) {
            o.console = true;
        } else if (std.mem.eql(u8, a, "--cwd")) {
            i += 1;
            o.cwd = args[i];
        } else {
            fatal("unknown option {s} (see `portalctl` for usage)", .{a});
        }
    }
    return o;
}

/// The session's configuration: the command line over settings.txt over
/// the built-in defaults (tunnel port and input mode only: there is no
/// default program).
const RunConfig = struct {
    tunnel_port: u16 = tunnelnet.default_udp_port,
    /// Null: not set yet (pairing codes then carry a placeholder).
    tunnel_endpoint: ?[]const u8 = null,
    policy: keymap.Policy = .instruct,
    /// The default `instruct` was lowered to `keys` for a shell.
    fell_back: bool = false,
    project: ?[]const u8 = null,
    command: ?[]const []const u8 = null,
    cwd: ?[]const u8 = null,
    /// Storage for a command split from settings.txt.
    split_buf: [settings.max_program]u8 = undefined,
    split_args: [settings.max_args][]const u8 = undefined,
};

/// Fills `cfg`. Returns a message if settings.txt has a program that can't
/// be used (it is then treated as unset).
fn mergeConfig(cfg: *RunConfig, cli: *const RunOptions, s: *const settings.Settings) ?[]const u8 {
    var problem: ?[]const u8 = null;
    cfg.tunnel_port = cli.tunnel_port orelse s.tunnelPort();
    cfg.tunnel_endpoint = cli.tunnel_endpoint orelse s.tunnel_endpoint.get();
    cfg.project = cli.project orelse s.project.get();
    cfg.cwd = cli.cwd orelse s.cwd.get();
    cfg.command = cli.command;
    if (cfg.command == null) if (s.program.get()) |text| {
        if (settings.splitCommand(text, &cfg.split_buf, &cfg.split_args)) |argv| {
            cfg.command = argv;
        } else |err| problem = switch (err) {
            error.UnterminatedQuote => "The saved program has an unterminated quote.",
            error.TooManyArguments => "The saved program has too many arguments.",
            error.CommandTooLong => "The saved program is too long.",
            error.EmptyCommand => null,
        };
    };
    // After the command is known: the default depends on it.
    if (cli.policy orelse s.input) |p| {
        cfg.policy = p;
        cfg.fell_back = false;
    } else {
        cfg.policy = defaultPolicy(cfg.command, cli.allow_remote_shell);
        cfg.fell_back = cfg.policy != .instruct;
    }
    return problem;
}

/// `argv` as one command line for the settings field ("a b" quoted).
fn joinCommand(argv: []const []const u8, buf: []u8) []const u8 {
    var w_: Io.Writer = .fixed(buf);
    for (argv, 0..) |a, i| {
        if (i > 0) w_.writeByte(' ') catch break;
        const q = a.len == 0 or std.mem.indexOfAny(u8, a, " \t") != null;
        if (q) w_.writeByte('"') catch break;
        w_.writeAll(a) catch break;
        if (q) w_.writeByte('"') catch break;
    }
    return w_.buffered();
}

/// Everything a session needs that can fail because of the configuration;
/// failures are a message for the setup panel (GUI) or fatal (console).
const Prepared = struct {
    /// The in-process tunnel, its peers the paired devices (`store`).
    tun: *tunneldesk.tunnel.Tunnel,
    /// 10.8.0.1:8420 inside the tunnel. Never closed.
    listener: transport.Listener,
    store: devices.Store,
    resolved: cmdline.Resolved,
};

const PrepareResult = union(enum) { ok: Prepared, problem: []const u8 };

fn prepare(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, paths: devices.Paths, cfg: *const RunConfig, opts: *const RunOptions, err_buf: []u8) PrepareResult {
    const allow_remote_shell = opts.allow_remote_shell;
    const P = PrepareResult;
    const fail_ = struct {
        fn f(buf: []u8, comptime fmt: []const u8, args: anytype) P {
            return .{ .problem = std.fmt.bufPrint(buf, fmt, args) catch "invalid settings" };
        }
    }.f;
    const command = cfg.command orelse return .{ .problem = if (gui_app)
        "Enter the program to run in this window."
    else
        "no program: pass -- <program> [args...] (or save one in the Portal window's first-run screen, settings.txt `program = ...`)" };
    if (cfg.project) |p| if (!title.validProject(p))
        return fail_(err_buf, "The project name must be 1-{d} bytes of printable text on one line.", .{title.max_project_bytes});
    // Remote typing into a shell is a remote shell: refuse unless explicit.
    if ((cfg.policy == .instruct or cfg.policy == .text) and isShellProgram(command[0]) and !allow_remote_shell)
        return fail_(err_buf, "Refusing {t} input for a shell ({s}): remote typing would be a remote shell. Choose keys input, or pass --allow-remote-shell if you really mean it.", .{ cfg.policy, command[0] });
    const resolved = cmdline.resolve(gpa, io, command, env.get("PATH"), env.get("SystemRoot")) catch |err|
        return fail_(err_buf, "Cannot find program '{s}': {t}.", .{ command[0], err });
    // The tunnel before the child, so a busy UDP port fails fast. Only one
    // per process: the setup panel may come back here after a problem.
    if (prepared_tunnel == null) {
        const st = devices.read(gpa, io, paths) catch |err|
            return fail_(err_buf, "Cannot read the device list: {s}.", .{devices.describeError(err)});
        const tun = tunneldesk.start(gpa, io, paths, .{ .udp_port = cfg.tunnel_port, .loopback_only = opts.tunnel_loopback }, &st) catch |err|
            return fail_(err_buf, "Cannot start Portal's WireGuard tunnel on UDP port {d}: {t}. Is another Portal (or WireGuard) using that port? Choose another tunnel port.", .{ cfg.tunnel_port, err });
        const listener = tun.listen(tunnelnet.https_port) catch |err|
            return fail_(err_buf, "Cannot listen on {s} inside the tunnel: {t}.", .{ tunnelnet.desk_server, err });
        prepared_tunnel = .{ .tun = tun, .listener = listener, .store = st };
    }
    const t = prepared_tunnel.?;
    return .{ .ok = .{ .tun = t.tun, .listener = t.listener, .store = t.store, .resolved = resolved } };
}

/// The tunnel `prepare` started (it lives until the process exits).
var prepared_tunnel: ?struct { tun: *tunneldesk.tunnel.Tunnel, listener: transport.Listener, store: devices.Store } = null;

/// Suffix for the log line and banner when the remote side has full control.
fn policyNote(policy: keymap.Policy) []const u8 {
    return switch (policy) {
        .text => " (FULL REMOTE CONTROL)",
        .instruct => " (checked instruction lines)",
        else => "",
    };
}

/// The input policy when neither the command line nor settings chose one.
/// `instruct` is remote typing, so for a shell it falls back to `keys`
/// unless --allow-remote-shell. A chosen mode is never lowered (prepare
/// refuses typing modes for a shell instead).
fn defaultPolicy(command: ?[]const []const u8, allow_remote_shell: bool) keymap.Policy {
    if (command) |c| if (c.len > 0 and isShellProgram(c[0]) and !allow_remote_shell) return .keys;
    return .instruct;
}

/// Shown next to the input mode when the default was lowered for a shell.
fn fallbackNote(cfg: *const RunConfig) []const u8 {
    return if (cfg.fell_back) " (instruct is the default, but not for a shell without --allow-remote-shell)" else "";
}

/// True if `program` (argv[0], any path/extension/case) is an interactive
/// shell. Remote typing into a shell would be a remote shell, so instruct
/// and text input are refused for these unless --allow-remote-shell.
pub fn isShellProgram(program: []const u8) bool {
    const base = std.fs.path.basename(program);
    const stem = if (std.ascii.endsWithIgnoreCase(base, ".exe") or std.ascii.endsWithIgnoreCase(base, ".com"))
        base[0 .. base.len - 4]
    else
        base;
    const shells = [_][]const u8{ "cmd", "powershell", "pwsh", "powershell_ise", "bash", "sh", "zsh", "fish", "dash", "ksh", "tcsh", "csh", "wsl", "nu", "elvish", "xonsh", "conhost", "wt", "windowsterminal" };
    for (shells) |sh| if (std.ascii.eqlIgnoreCase(stem, sh)) return true;
    return false;
}

test "isShellProgram" {
    try std.testing.expect(isShellProgram("cmd.exe"));
    try std.testing.expect(isShellProgram("C:\\Windows\\System32\\CMD.EXE"));
    try std.testing.expect(isShellProgram("pwsh"));
    try std.testing.expect(isShellProgram("/usr/bin/bash"));
    try std.testing.expect(isShellProgram("wsl.exe"));
    try std.testing.expect(!isShellProgram("agent"));
    try std.testing.expect(!isShellProgram("agent.cmd"));
    try std.testing.expect(!isShellProgram("python.exe"));
}

const text_warning =
    \\
    \\  *****************************************************************
    \\  *  WARNING: --input text gives anyone logged in to the web page *
    \\  *  FULL REMOTE CONTROL of this session: new prompts, ! shell    *
    \\  *  commands, slash commands, permission-mode changes, Ctrl+C    *
    \\  *  exit. Use --input keys to only answer prompts.              *
    \\  *****************************************************************
    \\
    \\
;

/// How long viewers get to receive the exit notice and close their end
/// (web.goodbye_ms each, concurrently), plus the TLS close and socket
/// close after it. Shutdown returns as soon as the last viewer socket is
/// closed; this only bounds a viewer that never answers.
const viewer_goodbye_ms = web.goodbye_ms + 1_500;

const Threads = struct {
    /// Console mode: one thread blocks on the console input handle and wakes
    /// only for keystrokes or window size/focus changes (no resize polling).
    /// After a resize event it re-reads the size once more when a single
    /// 150 ms deadline passes: the classic console host can report a buffer
    /// change before the window has finished growing, and growing the
    /// window alone sends no event. With nothing happening it waits forever.
    /// Keystrokes go to the first tab (the one the console shows); every
    /// tab gets the console's size.
    fn consoleInput(hub: *tabs.Hub, session: *Session, console: *Console) void {
        var buf: [Console.events_buf_len]u8 = undefined;
        hub.setSize(console.size());
        var settle_pending = false;
        while (true) {
            const timeout: u32 = if (settle_pending) 150 else std.math.maxInt(u32);
            if (!console.waitInput(timeout)) {
                // Deadline passed with no input: the one follow-up check.
                settle_pending = false;
                hub.setSize(console.size());
                continue;
            }
            const e = console.readEvents(&buf) catch return;
            if (e.n > 0) session.writeInput(buf[0..e.n]);
            if (e.resized) {
                hub.setSize(console.size());
                settle_pending = true;
            }
        }
    }
};

/// settings.txt, event-driven like StoreWatch: wakes when a file in the
/// data folder is created, renamed or deleted (settings.save replaces the
/// file by rename) and hands the startable projects to the hub, which
/// tells devices if they changed. The file stays the one source; nothing
/// polls.
const SettingsWatch = struct {
    hub: *tabs.Hub,
    dir: []const u8,
    io: Io,
    gpa: Allocator,

    fn watch(sw: *SettingsWatch) void {
        var dw = fsutil.DirWatch.open(sw.gpa, sw.dir, .{}) catch |err| {
            sw.hub.log.print("ERROR: cannot watch {s} for settings changes ({t}): startable projects change only when Portal restarts", .{ sw.dir, err });
            return;
        };
        while (true) {
            if (w.WaitForMultipleObjects(1, &[1]w.HANDLE{dw.h}, 0, w.INFINITE) != w.WAIT_OBJECT_0) return;
            dw.rearm() catch return; // before reading: a change made meanwhile signals again
            const s = settings.loadOrNull(sw.gpa, sw.io, sw.dir) orelse continue;
            sw.hub.setStartable(s.startableSlice());
        }
    }
};

/// `portalctl startable add | remove | list`: edits settings.txt (the one
/// place the list is kept); a running Portal follows the file.
fn cmdStartable(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, args: []const []const u8) !void {
    const paths = devicePaths(gpa, io, env) catch |err| fatal("cannot find the data directory: {t}", .{err});
    const sub = if (args.len > 0) args[0] else "list";
    var s = settings.loadOrNull(gpa, io, paths.dir) orelse fatal("{s}\\{s} exists but can't be read; nothing changed", .{ paths.dir, settings.file_name });
    if (std.mem.eql(u8, sub, "list")) {
        if (s.n_startable == 0) std.debug.print("no projects are startable from devices\n", .{});
        for (s.startableSlice()) |*e| std.debug.print("{s}  ({s})  {s}\n", .{ e.name.get() orelse "", e.mode.wire(), e.path.get() orelse "" });
        return;
    }
    if (std.mem.eql(u8, sub, "add")) {
        if (args.len < 2) fatal("usage: portalctl startable add <folder> [--name NAME] [--mode ask|plan]", .{});
        var name: ?[]const u8 = null;
        var mode: projects_wire.Mode = .ask;
        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            if (i + 1 >= args.len) fatal("{s} needs a value", .{args[i]});
            if (std.mem.eql(u8, args[i], "--name")) {
                name = args[i + 1];
            } else if (std.mem.eql(u8, args[i], "--mode")) {
                mode = projects_wire.Mode.fromWire(args[i + 1]) orelse fatal("--mode must be ask or plan (device starts never use a permissive mode)", .{});
            } else fatal("unknown option {s}", .{args[i]});
            i += 1;
        }
        const folder = proc_abs: {
            const f = args[1];
            if (std.fs.path.isAbsolute(f)) break :proc_abs try gpa.dupe(u8, f);
            const here = try std.process.currentPathAlloc(io, gpa);
            defer gpa.free(here);
            break :proc_abs try std.fs.path.resolve(gpa, &.{ here, f });
        };
        defer gpa.free(folder);
        {
            var d = Io.Dir.cwd().openDir(io, folder, .{}) catch fatal("{s} is not an existing folder", .{folder});
            d.close(io);
        }
        var nb: [tabs_wire.max_name]u8 = undefined;
        const n = name orelse tabs.displayName(folder, env.get("USERPROFILE"), env.get("USERNAME"), &nb);
        s.addStartable(n, mode, folder) catch |err| fatal("not added: {s}", .{switch (err) {
            error.BadName => "the name must be 1-64 bytes of printable text without \\ / : | \" and not start with - or .",
            error.BadFolder => "the folder must be an absolute path",
            error.Duplicate => "that name or folder is already startable",
            error.Full => "the list is full",
        }});
        try settings.save(gpa, io, paths.dir, &s);
        std.debug.print("startable from devices: {s} ({s})\n", .{ n, mode.wire() });
        return;
    }
    if (std.mem.eql(u8, sub, "remove")) {
        if (args.len != 2) fatal("usage: portalctl startable remove <name>", .{});
        if (!s.removeStartable(args[1])) fatal("no startable project is named {s}", .{args[1]});
        try settings.save(gpa, io, paths.dir, &s);
        std.debug.print("removed: {s}\n", .{args[1]});
        return;
    }
    fatal("usage: portalctl startable add <folder> [--name NAME] [--mode ask|plan] | remove <name> | list", .{});
}

/// `portal open` / `portalctl open` requests (openreq.zig) for the running
/// Portal: each opens a tab.
const OpenWatch = struct {
    hub: *tabs.Hub,
    log: *Log,
    env: *const std.process.Environ.Map,
    gpa: Allocator,

    fn open(ctx: *anyopaque, req: openreq.Request) ?[]const u8 {
        const ow: *OpenWatch = @ptrCast(@alignCast(ctx));
        return openFolder(ow.gpa, ow.hub, ow.env, req.dir, req.name);
    }

    fn lost(ctx: *anyopaque, err: anyerror) void {
        const ow: *OpenWatch = @ptrCast(@alignCast(ctx));
        ow.log.print("ERROR: cannot watch for `portal open` requests ({t}); open folders with Ctrl+Shift+T in the window", .{err});
    }
};

/// Agent hooks (`portalctl hook`, hookpipe.zig) for the open tabs.
const HookWatch = struct {
    fn message(ctx: *anyopaque, m: *const hookmsg.Message) void {
        const hub: *tabs.Hub = @ptrCast(@alignCast(ctx));
        hub.applyHook(m);
    }

    fn problem(ctx: *anyopaque, what: []const u8) void {
        const hub: *tabs.Hub = @ptrCast(@alignCast(ctx));
        hub.log.print("hooks: {s}", .{what});
    }

    fn usageReport(ctx: *anyopaque, r: *const statusline.Report) void {
        const hub: *tabs.Hub = @ptrCast(@alignCast(ctx));
        hub.applyUsage(r);
    }

    /// Starts the pipe server thread; logs (and runs without hooks) if it
    /// can't.
    fn start(gpa: Allocator, hub: *tabs.Hub, log: *Log, data_dir: []const u8) void {
        var nb: [80:0]u16 = undefined;
        const name = hookpipe.pipeNameW(&nb, data_dir) orelse {
            log.print("hooks: cannot determine this user's SID; Claude Code hooks are not listened to", .{});
            return;
        };
        const ev = hookpipe.Server.events() catch {
            log.print("hooks: cannot create events; Claude Code hooks are not listened to", .{});
            return;
        };
        const srv = gpa.create(hookpipe.Server) catch return;
        srv.* = .{ .stop = ev[0], .conn_ev = ev[1], .read_ev = ev[2], .ctx = hub, .on_message = message, .on_problem = problem, .on_usage = usageReport };
        srv.init(name) catch |err| {
            log.print("hooks: cannot create the hook pipe ({s}); Claude Code hooks are not listened to", .{switch (err) {
                error.NameTaken => "another process holds its name: another Portal with the same data folder?",
                else => @errorName(err),
            }});
            return;
        };
        const t = std.Thread.spawn(.{}, hookpipe.Server.run, .{srv}) catch |err| {
            log.print("hooks: cannot start the hook pipe thread: {t}", .{err});
            return;
        };
        t.detach();
    }
};

/// The user's names and home folders for the conversation scrubber
/// (convo/scrub.zig): %USERNAME%, %USERPROFILE% and the OneDrive folders,
/// each also in its 8.3 short form. Lives as long as the process.
fn scrubIdentity(gpa: Allocator, env: *const std.process.Environ.Map) ScrubIdentity {
    const profile = env.get("USERPROFILE");
    var others: [6]?[]const u8 = @splat(null);
    for ([_][]const u8{ "OneDrive", "OneDriveConsumer", "OneDriveCommercial" }, 0..) |name, i| {
        const d = env.get(name) orelse continue;
        others[2 * i] = d;
        others[2 * i + 1] = shortPath(gpa, d);
    }
    return ScrubIdentity.init(gpa, .{
        .user_name = env.get("USERNAME"),
        .profile = profile,
        .profile_short = if (profile) |p| shortPath(gpa, p) else null,
        .other_homes = &others,
    }) catch .{};
}

/// The 8.3 short form of existing path `p` (`C:\Users\JOHNSM~1`), if
/// it has one that differs.
fn shortPath(gpa: Allocator, p: []const u8) ?[]const u8 {
    const wide = std.unicode.wtf8ToWtf16LeAllocZ(gpa, p) catch return null;
    defer gpa.free(wide);
    var buf: [1024]u16 = undefined;
    const n = w.GetShortPathNameW(wide.ptr, &buf, buf.len);
    if (n == 0 or n >= buf.len) return null;
    const out = std.unicode.wtf16LeToWtf8Alloc(gpa, buf[0..n]) catch return null;
    if (std.ascii.eqlIgnoreCase(out, p)) {
        gpa.free(out);
        return null;
    }
    return out;
}

/// The agent's transcript folder, read (never written) for each tab's
/// Conversation view (src/convo/follow.zig): %PORTAL_AGENT_PROJECTS%
/// (tests point it at a scratch folder; honoured only in Debug builds,
/// build option `test_env`), else %CLAUDE_CONFIG_DIR%\projects, else
/// %USERPROFILE%\.claude\projects. Lives as long as the process.
fn convoProjects(gpa: Allocator, env: *const std.process.Environ.Map) ?[]const u8 {
    if (@import("build_options").test_env) if (env.get("PORTAL_AGENT_PROJECTS")) |p| if (p.len > 0) return p;
    if (env.get("CLAUDE_CONFIG_DIR")) |d| if (d.len > 0) return std.fs.path.join(gpa, &.{ d, "projects" }) catch null;
    const home = env.get("USERPROFILE") orelse return null;
    return std.fs.path.join(gpa, &.{ home, ".claude", "projects" }) catch null;
}

/// Opens `dir` (absolute) as a new tab named `name` (or its display
/// name). Returns null, or why it was not opened (no path in it).
pub fn openFolder(gpa: Allocator, hub: *tabs.Hub, env: *const std.process.Environ.Map, dir: []const u8, name: ?[]const u8) ?[]const u8 {
    if (!std.fs.path.isAbsolute(dir)) return "the folder must be an absolute path";
    {
        var d = Io.Dir.cwd().openDir(hub.io, dir, .{}) catch return "not an existing folder";
        d.close(hub.io);
    }
    var nb: [tabs_wire.max_name]u8 = undefined;
    const tab_name = if (name) |n|
        (if (title.validProject(n)) n else return "the name must be 1-64 bytes of printable text")
    else
        tabs.displayName(dir, env.get("USERPROFILE"), env.get("USERNAME"), &nb);
    const cwd_w = std.unicode.wtf8ToWtf16LeAllocZ(gpa, dir) catch return "bad folder name";
    defer gpa.free(cwd_w);
    _ = hub.open(cwd_w, tab_name, .{}) catch |err| return switch (err) {
        error.TooManyTabs => "too many tabs are open",
        error.Finished => "Portal is shutting down",
        error.OutOfMemory => "out of memory",
        error.SpawnFailed => "the program could not be started there",
        error.UnsafeProgram => unreachable, // only device starts check it
    };
    return null;
}

/// The child's working directory as WTF-16 for CreateProcessW, or null to
/// inherit Portal's. `--cwd` (or settings.txt `cwd`) must name an existing
/// directory (relative to Portal's current directory); otherwise
/// workdir.defaultCwd (console) or workdir.guiDefaultCwd (window) decides.
fn childCwd(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, data_dir: []const u8, arg: ?[]const u8) ?[:0]u16 {
    // [fix2/desk] verify PORTAL_VIA_LAUNCHER against the parent pid and
    // remove it from our environment before the child is spawned.
    const via_launcher = workdir.takeLauncherFlag(env.get(workdir.launcher_env));
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
        var d = Io.Dir.cwd().openDir(io, chosen, .{}) catch |err| fatal("the working directory '{s}' is not an existing directory ({t})", .{ a, err });
        d.close(io);
    } else {
        if (gui_app) {
            // No console to ask: started by Explorer, a shortcut or the
            // launcher, the current directory is Portal's own folder (or
            // System32); from a terminal it is the terminal's.
            var exe_buf: [32768]u16 = undefined;
            const n = w.GetModuleFileNameW(null, &exe_buf, exe_buf.len);
            const exe_path: ?[]u8 = if (n > 0 and n < exe_buf.len) std.unicode.wtf16LeToWtf8Alloc(gpa, exe_buf[0..n]) catch null else null;
            defer if (exe_path) |p| gpa.free(p);
            const exe_dir: ?[]const u8 = if (exe_path) |p| std.fs.path.dirname(p) else null;
            chosen = workdir.guiDefaultCwd(here, exe_dir, data_dir, env.get("SystemRoot"), env.get("USERPROFILE")) orelse return null;
        } else {
            const releases = std.fs.path.join(gpa, &.{ data_dir, "releases" }) catch null;
            defer if (releases) |r| gpa.free(r);
            const has_parent = workdir.hasParentConsole(via_launcher);
            chosen = workdir.defaultCwd(has_parent, here, env.get("USERPROFILE"), releases) orelse return null;
        }
        // A missing home folder is not worth failing over: inherit instead.
        var d = Io.Dir.cwd().openDir(io, chosen, .{}) catch return null;
        d.close(io);
    }
    return std.unicode.wtf8ToWtf16LeAllocZ(gpa, chosen) catch fatal("bad directory name '{s}'", .{chosen});
}


/// Puts the folder of this exe first on PATH in Portal's own environment,
/// which each session's block is built from (childenv.forSession), so
/// `portal-show` (installed next to portal.exe and portalctl.exe) is found
/// inside the session. Only this process and its children see the change.
fn prependOwnDirToPath(gpa: Allocator) void {
    var exe_buf: [32768]u16 = undefined;
    const n = w.GetModuleFileNameW(null, &exe_buf, exe_buf.len);
    if (n == 0 or n >= exe_buf.len) return;
    var end: usize = n;
    while (end > 0 and exe_buf[end - 1] != '\\' and exe_buf[end - 1] != '/') end -= 1;
    if (end <= 1) return;
    const dir = exe_buf[0 .. end - 1];
    const name = std.unicode.utf8ToUtf16LeStringLiteral("PATH");
    const old_len = w.GetEnvironmentVariableW(name, null, 0);
    const old = gpa.alloc(u16, old_len + 1) catch return;
    defer gpa.free(old);
    const got: usize = if (old_len == 0) 0 else w.GetEnvironmentVariableW(name, old.ptr, @intCast(old.len));
    const new = std.mem.concatWithSentinel(gpa, u16, &.{ dir, &[_]u16{';'}, old[0..@min(got, old.len)] }, 0) catch return;
    defer gpa.free(new);
    _ = w.SetEnvironmentVariableW(name, new.ptr);
}

/// The system monitor took a sample: viewers and the window look.
fn hubBroadcast(ctx: *anyopaque) void {
    const h: *tabs.Hub = @ptrCast(@alignCast(ctx));
    h.broadcast();
}

fn cmdRun(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, args: []const []const u8) !void {
    var opts = parseRunArgs(args);
    if (gui_app and opts.console) fatal("--console is the console tool's: run `portalctl run --console ...`. `portal` is the window.", .{});
    if (!gui_app and !opts.console) fatal("the Portal window is portal.exe: run `portal run ...`. For a session in this console: `portalctl run --console ...`.", .{});

    // [fix2/desk] Never run elevated by accident: the child and all remote
    // input would run as administrator.
    const elevation = conpty.elevationCheck(conpty.isElevated(), opts.allow_elevated);
    if (elevation == .refuse) {
        fatal("Portal is running as administrator, so the session program and everything a paired device types would run as administrator. Run Portal from a normal (non-admin) terminal, or pass --allow-elevated if you really mean it.", .{});
    }

    const paths = devicePaths(gpa, io, env) catch |err| fatal("cannot create the data directory: {t}", .{err});
    // Portal sync: the release key devices pin at pairing (created on
    // first use, like the CA). Without it the /sync routes are off.
    const sync_key: ?[32]u8 = sync.ensureKey(gpa, io, .{ .dir = paths.dir }) catch null;
    const dir = paths.dir;
    const log_path = try std.fs.path.join(gpa, &.{ dir, "portal.log" });
    defer gpa.free(log_path);
    // Fail closed: logins and viewer connections must be auditable.
    var log = Log.open(gpa, io, log_path) catch |err|
        fatal("cannot open audit log {s} ({t}); refusing to run without it.", .{ log_path, err });
    defer log.close();

    var saved = settings.load(gpa, io, dir);
    var cfg: RunConfig = .{};
    var problem: ?[]const u8 = mergeConfig(&cfg, &opts, &saved);

    // The window opens before anything else that can fail because of the
    // configuration, so a first run, or a bad address or program, is
    // answered inside it (deskui.zig's setup panel) instead of a dialog.
    var host: ?*gui.LocalHost = null;
    if (gui_app) host = gui.LocalHost.init(gpa, io) catch |err| fatal("cannot open the Portal window: {t}", .{err});

    var err_buf: [512]u8 = undefined;
    var prep: Prepared = undefined;
    while (true) {
        if (host) |h| if (cfg.command == null or problem != null) {
            var prog_buf: [settings.max_program]u8 = undefined;
            const prog_text = if (cfg.command) |c| joinCommand(c, &prog_buf) else (saved.program.get() orelse "");
            var port_buf: [settings.max_port_text]u8 = undefined;
            const v = h.runSetup(.{
                .first_run = cfg.command == null and problem == null,
                .tunnel_port = std.fmt.bufPrint(&port_buf, "{d}", .{cfg.tunnel_port}) catch "",
                .program = prog_text,
                .project = cfg.project orelse "",
                .policy = cfg.policy,
                .problem = problem orelse "",
            }) orelse w.ExitProcess(0); // window closed
            // What the desk typed wins over the command line for this
            // run, and is saved for the next.
            _ = saved.tunnel_port.set(v.tunnel_port);
            _ = saved.program.set(v.program);
            _ = saved.project.set(v.project);
            saved.input = v.policy;
            settings.save(gpa, io, dir, &saved) catch |err| log.print("could not save {s}\\{s}: {t}", .{ dir, settings.file_name, err });
            opts.tunnel_port = null;
            opts.command = null;
            opts.project = null;
            opts.policy = null;
            problem = mergeConfig(&cfg, &opts, &saved);
            if (problem != null) continue;
        };
        switch (prepare(gpa, io, env, paths, &cfg, &opts, &err_buf)) {
            .ok => |p| {
                prep = p;
                break;
            },
            .problem => |msg| {
                if (host == null) fatal("{s}", .{msg});
                problem = msg;
            },
        }
    }
    const command = cfg.command.?;
    // The listener is never closed (see the end of this function).
    const listener = prep.listener;
    // prepare's lookup only checked that the program is there now: every
    // tab finds it again when it opens (tabs.Program, Hub.open).
    var resolved = prep.resolved;
    resolved.deinit(gpa);
    const listen_host = tunnelnet.desk_server;
    const allowed_hosts = [_][]const u8{tunnelnet.desk_server};

    if (elevation == .warn) { // [fix2/desk]
        std.debug.print("portal: WARNING: ELEVATED: remote input runs as administrator (--allow-elevated)\n", .{});
        log.print("start: ELEVATED: remote input runs as administrator (--allow-elevated)", .{});
    }

    // TLS 1.3 inside the tunnel: Portal's CA and a server certificate for
    // 10.8.0.1. The chain carries the CA too, so a device pins it from the
    // fingerprint in its pairing code (no separate download). Everything
    // here lives until the process exits.
    var tls_creds: tls_server.Credentials = undefined;
    var tls_chain: [2][]const u8 = undefined;
    var fp_buf: [95]u8 = undefined;
    const tls_setup = setupTls(gpa, io, env, &log);
    tls_chain = .{ tls_setup.leaf.der, tls_setup.ca.der };
    tls_creds = .{ .chain = &tls_chain, .key = tls_setup.leaf.key };
    const ca_sha256 = x509.fingerprint(tls_setup.ca.der);
    const fingerprint = x509.formatFingerprint(ca_sha256, &fp_buf);
    std.debug.print("portal: TLS with a certificate from {s}\n       CA SHA-256 {s}\n", .{ tls_setup.ca.commonName(), fingerprint });

    // Working directory (before anything changes Portal's environment).
    const cwd_w = childCwd(gpa, io, env, dir, cfg.cwd);
    defer if (cwd_w) |c| gpa.free(c);
    // `portal-show` must be found inside the session.
    prependOwnDirToPath(gpa);

    if (cfg.policy == .text) std.debug.print(text_warning, .{});
    var url_buf: [160]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "https://{s}/", .{listen_host}) catch listen_host;
    std.debug.print("portal: sharing '{s}' through Portal's WireGuard tunnel on UDP {d}{s} (input: {t}{s}{s})\n", .{
        command[0], prep.tun.udpPort(), if (opts.tunnel_loopback) " (127.0.0.1 only)" else "", cfg.policy, policyNote(cfg.policy), fallbackNote(&cfg),
    });

    // ---- GUI / console split (see gui.zig) ----------------------------
    // GUI (portal.exe): no console at all; the window decides the PTY size.
    // Console (portalctl run --console): this console is the terminal.
    var console: Console = undefined;
    var initial: conpty.Size = undefined;
    if (opts.console) {
        console = Console.init() catch fatal("portalctl run --console needs an interactive console (stdin/stdout are redirected)", .{});
        initial = console.size();
    } else {
        console = Console.detached();
        const h = host.?;
        h.configure(.{
            .command_name = std.fs.path.basename(command[0]),
            .listen_host = listen_host,
            .url = url,
            .policy = cfg.policy,
        });
        const sz = h.initialSize();
        initial = .{ .cols = sz[0], .rows = sz[1] };
    }
    // ---- end GUI / console split --------------------------------------

    // Every tab runs the same program; only its folder differs.
    var colors_buf: [settings.max_colors]tabs.Hub.ColorChoice = undefined;
    const hub = gpa.create(tabs.Hub) catch fatal("out of memory", .{});
    hub.* = .{
        .gpa = gpa,
        .io = io,
        .log = &log,
        .console = &console,
        .policy = cfg.policy,
        .program = .{
            .argv = command,
            .path_env = env.get("PATH"),
            .system_root = env.get("SystemRoot"),
            .command_name = std.fs.path.basename(command[0]),
            .session_id = cmdline.wantsSessionId(command),
            .device_start = cmdline.deviceStart(command),
            .settings_file = statusSettings(gpa, io, &log, env, command),
        },
        .colors = saved.colorChoices(&colors_buf),
        .convo_projects = convoProjects(gpa, env),
        .user_name = env.get("USERNAME"),
        .identity = scrubIdentity(gpa, env),
        .size = initial,
        .sysmon_on = saved.system_monitor orelse false,
    };
    // The projects devices may start (settings.txt; SettingsWatch follows
    // the file from here on).
    hub.setStartable(saved.startableSlice());
    if (hub.program.device_start != .ok) {
        var rb: [200]u8 = undefined;
        log.print("start: devices cannot start projects: {s}", .{cmdline.deviceStartText(hub.program.device_start, &rb)});
    }
    if (host) |h| h.attach(hub);
    // The optional system monitor: samples nothing unless the setting is
    // on and a System panel is open (sysmon.zig).
    const sys_backend = gpa.create(sysmon.WinBackend) catch fatal("out of memory", .{});
    sys_backend.* = .{ .gpa = gpa, .hub = hub };
    const monitor = gpa.create(sysmon.Monitor) catch fatal("out of memory", .{});
    monitor.* = .{ .backend = sys_backend.backend(), .notify_ctx = hub, .notify_fn = hubBroadcast };
    monitor.setEnabled(hub.sysmon_on);
    // The first tab: --project, or the folder's name (never a path).
    var first_name_buf: [tabs_wire.max_name]u8 = undefined;
    const first_name: []const u8 = cfg.project orelse blk: {
        const dir_utf8: ?[]u8 = if (cwd_w) |c|
            (std.unicode.wtf16LeToWtf8Alloc(gpa, c) catch null)
        else
            (std.process.currentPathAlloc(io, gpa) catch null);
        const d = dir_utf8 orelse break :blk "Project";
        break :blk tabs.displayName(d, env.get("USERPROFILE"), env.get("USERNAME"), &first_name_buf);
    };
    const first = hub.open(cwd_w, first_name, .{ .mirror = opts.console }) catch |err|
        fatal("could not start '{s}': {t}", .{ command[0], err });
    // From here on the child is running. Exit only via fatal()/ExitProcess:
    // process exit closes the job handles, which kills every tab's tree.

    var server: web.Server = .{
        .gpa = gpa,
        .io = io,
        .hub = hub,
        .log = &log,
        .listener = listener,
        .cfg = .{
            .allowed_hosts = &allowed_hosts,
            .devices = paths,
            .tls = &tls_creds,
            .sync_key = sync_key,
        },
        .sysmon = monitor,
    };
    server.applyStore(&prep.store, &.{});
    var store_watch: StoreWatch = .{
        .srv = &server,
        .tun = prep.tun,
        .applier = .{ .in_tunnel = prep.store },
        // Unpair from `portalctl` must end connections: no watch, no run.
        .dw = devices.watchStore(gpa, paths) catch |err|
            fatal("cannot watch {s} for changes ({t}); Portal needs it to notice pairing and unpairing", .{ paths.dir, err }),
        .paths = paths,
        .io = io,
        .gpa = gpa,
    };
    // A change between prepare's read and the watch opening signalled
    // nobody: read once more now that the watch is open.
    store_watch.reload() catch {};

    // The window's desk panels (pairing, devices, settings with the
    // tunnel) use the device store directly; store changes wake it.
    if (host) |h| {
        const desk_public = (tunneldesk.loadPublic(io, paths) catch null) orelse fatal("this desktop's WireGuard key is missing", .{});
        const home = env.get("USERPROFILE") orelse dir;
        h.attachDesk(.{
            .export_default = std.fs.path.join(gpa, &.{ home, "Downloads", "Portal-CA" }) catch fatal("out of memory", .{}),
            .tls_dir = std.fs.path.join(gpa, &.{ dir, "tls" }) catch fatal("out of memory", .{}),
            .srv = &server,
            .paths = paths,
            .fingerprint = fingerprint,
            .ca_sha256 = ca_sha256,
            .desk_public = desk_public,
            .tunnel_port = prep.tun.udpPort(),
            .saved = saved,
            .open_ctx = env,
            .env = env,
            .open_fn = deskOpen,
            .store = store_watch.hook(),
        });
        server.store_notify_ctx = h;
        server.store_notify_fn = gui.LocalHost.storeNotify;
    }

    log.print("start: v{s} zig {s}, tunnel on UDP {d}{s}, input={t}{s}{s}, command={s}", .{
        portal_version, builtin.zig_version_string, prep.tun.udpPort(), if (opts.tunnel_loopback) " (loopback)" else "", cfg.policy, policyNote(cfg.policy), fallbackNote(&cfg), command[0],
    });

    if (opts.console) {
        console.enableRaw() catch fatal("could not switch console to raw mode", .{});
        raw_console = &console;
        // Project name only, never the program's title or a path; web.zig
        // keeps it current with the viewer count (title.zig).
        var tb: [title.max_title_bytes]u8 = undefined;
        console.setTitle(title.windowTitle(first.name(), 0, &tb));
    }

    // ------------------------------------------------------------------
    // Threads below use stack and heap memory owned by this frame. After the
    // first spawn this function must never return (no `try`, no `return`):
    // every exit goes through fatal() or ExitProcess.
    if (opts.console) {
        const in_thread = std.Thread.spawn(.{}, Threads.consoleInput, .{ hub, &first.session, &console }) catch |err|
            fatal("cannot start input thread: {t}", .{err});
        in_thread.detach(); // parked in ReadConsoleInputW; ends with the process
    }
    const accept_thread = std.Thread.spawn(.{}, web.Server.run, .{&server}) catch |err|
        fatal("cannot start web server thread: {t}", .{err});
    accept_thread.detach();
    {
        const sw = gpa.create(SyncWatch) catch fatal("out of memory", .{});
        sw.* = .{ .srv = &server, .paths = .{ .dir = paths.dir }, .io = io, .gpa = gpa };
        if (sync_key == null) log.print("sync: no release key (DPAPI unavailable?); package delivery is off", .{});
        const st = std.Thread.spawn(.{}, SyncWatch.watch, .{sw}) catch |err|
            fatal("cannot start the sync watcher thread: {t}", .{err});
        st.detach();
        const t = std.Thread.spawn(.{}, StoreWatch.watch, .{&store_watch}) catch |err|
            fatal("cannot start the pairing watcher thread: {t}", .{err});
        t.detach();
        // `portal open <dir>`: requests through the data directory.
        const ow = gpa.create(OpenWatch) catch fatal("out of memory", .{});
        ow.* = .{ .hub = hub, .log = &log, .env = env, .gpa = gpa };
        const owt = gpa.create(openreq.Watch) catch fatal("out of memory", .{});
        owt.* = .{
            .gpa = gpa,
            .io = io,
            .folder = std.fs.path.join(gpa, &.{ dir, openreq.dir_name }) catch fatal("out of memory", .{}),
            .ctx = ow,
            .open_fn = OpenWatch.open,
            .lost_fn = OpenWatch.lost,
        };
        const ot = std.Thread.spawn(.{}, openreq.Watch.run, .{owt}) catch |err|
            fatal("cannot start the open-request watcher thread: {t}", .{err});
        ot.detach();
        // Agent hooks: a current-user-only local pipe.
        HookWatch.start(gpa, hub, &log, dir);
        // settings.txt: the startable projects follow the file.
        const setw = gpa.create(SettingsWatch) catch fatal("out of memory", .{});
        setw.* = .{ .hub = hub, .dir = dir, .io = io, .gpa = gpa };
        const swt = std.Thread.spawn(.{}, SettingsWatch.watch, .{setw}) catch |err|
            fatal("cannot start the settings watcher thread: {t}", .{err});
        swt.detach();
    }

    // Two ways Portal ends, kept apart:
    //   * the last tab's program exits (either mode): each tab closes its
    //     pseudo console at once, drains its output and leaves the list;
    //     viewers get the last program's exit code;
    //   * the window is closed while programs run (GUI): every tab's
    //     pseudo console is closed, the programs' cue to exit, and Portal
    //     WAITS for them, up to tabs.close_timeout_ms; only a program still
    //     running then is ended through its job (tabs.zig).
    if (host) |h| {
        switch (h.run()) {
            .finished => {},
            .window_closed => {
                h.hide();
                log.print("local window closed: asking every tab's program to exit and waiting for them", .{});
                hub.closeAll();
            },
        }
        log.print("local window: {d} wake-ups, {d} frames presented", .{ h.wakeups, h.presents }); // [fix2/desk]
    }
    // Event-driven: each tab's end wakes this thread. Bounded after the
    // window closed (every tab is ending); unbounded in the console mode,
    // which runs until its programs exit.
    const all_ended = hub.waitFinished(if (host != null)
        Io.Clock.awake.now(io).toMilliseconds() + tabs.close_timeout_ms + tabs.terminate_timeout_ms + 2_000
    else
        null);
    hub.mutex.lockUncancelable(io);
    const code: u32 = if (all_ended) hub.last_code else 1;
    hub.mutex.unlock(io);
    // The last tab's program's code (the same line as before tabs).
    if (all_ended) {
        log.print("stop: child exited with code {d} (every tab has ended)", .{code});
    } else log.print("stop: tabs did not end in time, exit code {d}", .{code});
    // Viewers receive the exit notice, then disconnect: wait for that
    // (event-driven), at most viewer_goodbye_ms.
    hub.waitViewersGone(Io.Clock.awake.now(io).toMilliseconds() + viewer_goodbye_ms);
    // Do NOT close the listener: the accept thread is blocked on it and std
    // hits `unreachable` on the cancelled accept. Process exit reclaims it.
    console.restore();
    // Full 32-bit exit code (std.process.exit takes a u8). Exiting here, not
    // returning, also keeps every thread's memory valid to the very end.
    w.ExitProcess(code);
}

/// The window's folder picker (gui.zig): opens a tab like `portal open`.
fn deskOpen(ctx: *const anyopaque, gpa: Allocator, hub: *tabs.Hub, dir: []const u8) ?[]const u8 {
    const env: *const std.process.Environ.Map = @ptrCast(@alignCast(ctx));
    return openFolder(gpa, hub, env, dir, null);
}

/// `portal open <dir>` / `portalctl open <dir>`: asks the running Portal
/// (openreq.zig).
fn cmdOpen(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, args: []const []const u8) !void {
    const paths = devicePaths(gpa, io, env) catch |err| fatal("cannot find the data directory: {t}", .{err});
    const say = struct {
        fn f(text: []const u8) void {
            // The window says nothing when it worked (the tab appears).
            if (gui_app) {
                if (!std.mem.startsWith(u8, text, "opened")) messageBox(text);
            } else std.debug.print("portal: {s}\n", .{text});
        }
    }.f;
    const code = openreq.command(gpa, io, paths.dir, args, say);
    if (gui_app) w.ExitProcess(code);
    std.process.exit(code);
}

test {
    _ = @import("panic.zig");
    _ = @import("conpty.zig");
    _ = @import("gui.zig");
    _ = @import("localgrid.zig");
    _ = @import("localinput.zig");
    _ = @import("workdir.zig");
    _ = @import("settings.zig");
    _ = @import("deskui.zig");
    _ = @import("deskprojects.zig");
    _ = @import("keymap.zig");
    _ = @import("guard.zig");
    _ = @import("tunneldesk.zig");
    _ = @import("cmdline.zig");
    _ = @import("childenv.zig");
    _ = @import("console.zig");
    _ = @import("session.zig");
    _ = @import("tabs.zig");
    _ = @import("projects_ws.zig");
    _ = @import("openreq.zig");
    _ = @import("hookmsg.zig");
    _ = @import("hookpipe.zig");
    _ = @import("statusline.zig");
    _ = @import("usage_desk.zig");
    _ = @import("elevation.zig");
    _ = @import("foryou_extract.zig");
    _ = @import("foryou_desk.zig");
    _ = @import("foryou_ws.zig");
    _ = @import("agenthooks.zig");
    _ = @import("log.zig");
    _ = @import("devices.zig");
    _ = @import("vt.zig");
    _ = @import("show.zig");
    _ = @import("web.zig"); // also pulls in http1.zig tests
    _ = @import("tls/server.zig"); // also server_test.zig
    _ = @import("tls/x509.zig");
    _ = @import("tls/dpapi.zig");
    _ = @import("tls/pki.zig");
    _ = @import("sync.zig");
    _ = @import("sync_cli.zig");
    _ = @import("fsutil.zig");
    _ = @import("bucket.zig");
    _ = @import("ratelimit.zig");
    _ = @import("title.zig");
    _ = @import("convo/scrub.zig");
    _ = @import("convo/transcript.zig");
    _ = @import("convo/model.zig");
    _ = @import("convo/follow.zig");
    _ = @import("convo/activity.zig");
    _ = @import("convo/subtabs.zig");
    _ = @import("convo/subagents.zig");
    _ = @import("sysmon.zig");
}

test "isYes" {
    try std.testing.expect(isYes("y"));
    try std.testing.expect(isYes(" YES "));
    try std.testing.expect(!isYes(""));
    try std.testing.expect(!isYes("n"));
    try std.testing.expect(!isYes("yy"));
    // A byte order mark from a .NET / PowerShell pipe is not part of the answer.
    try std.testing.expect(isYes("\xEF\xBB\xBFy"));
    try std.testing.expect(isYes("\xEF\xBB\xBF yes"));
    try std.testing.expect(!isYes("\xEF\xBB\xBF"));
    try std.testing.expect(!isYes("\xEF\xBB\xBFn"));
}

test "run: --project and --allow-elevated" {
    const o = parseRunArgs(&.{});
    try std.testing.expect(o.project == null);
    try std.testing.expect(!o.allow_elevated);
    const p = parseRunArgs(&.{ "--project", "acme-api", "--allow-elevated", "--", "cmd.exe" });
    try std.testing.expectEqualStrings("acme-api", p.project.?);
    try std.testing.expect(p.allow_elevated);
}

test "run: tunnel options" {
    const o = parseRunArgs(&.{});
    try std.testing.expect(o.tunnel_port == null and !o.tunnel_loopback and o.tunnel_endpoint == null);
    const p = parseRunArgs(&.{ "--tunnel-port", "51999", "--tunnel-loopback", "--tunnel-endpoint", "home.example.org:51999" });
    try std.testing.expectEqual(@as(?u16, 51999), p.tunnel_port);
    try std.testing.expect(p.tunnel_loopback);
    try std.testing.expectEqualStrings("home.example.org:51999", p.tunnel_endpoint.?);
}

test "run config: command line over settings over defaults; no default program" {
    const none = parseRunArgs(&.{});
    var cfg: RunConfig = .{};
    try std.testing.expect(mergeConfig(&cfg, &none, &.{}) == null);
    try std.testing.expect(cfg.command == null); // the window asks
    try std.testing.expectEqual(tunnelnet.default_udp_port, cfg.tunnel_port);
    try std.testing.expect(cfg.tunnel_endpoint == null);

    var s: settings.Settings = .{};
    _ = s.tunnel_port.set("51900");
    _ = s.tunnel_endpoint.set("home.example.org:51900");
    _ = s.program.set("\"C:\\Program Files\\tool\\tool.exe\" --flag");
    _ = s.project.set("acme");
    s.input = .instruct;
    try std.testing.expect(mergeConfig(&cfg, &none, &s) == null);
    try std.testing.expectEqual(@as(u16, 51900), cfg.tunnel_port);
    try std.testing.expectEqualStrings("home.example.org:51900", cfg.tunnel_endpoint.?);
    try std.testing.expectEqual(keymap.Policy.instruct, cfg.policy);
    try std.testing.expectEqualStrings("acme", cfg.project.?);
    try std.testing.expectEqual(@as(usize, 2), cfg.command.?.len);
    try std.testing.expectEqualStrings("C:\\Program Files\\tool\\tool.exe", cfg.command.?[0]);

    const cli = parseRunArgs(&.{ "--tunnel-port", "9", "--input", "none", "--", "cmd.exe", "/k" });
    try std.testing.expect(mergeConfig(&cfg, &cli, &s) == null);
    try std.testing.expectEqual(@as(u16, 9), cfg.tunnel_port);
    try std.testing.expectEqual(keymap.Policy.none, cfg.policy);
    try std.testing.expectEqualStrings("cmd.exe", cfg.command.?[0]);

    _ = s.program.set("\"unterminated");
    try std.testing.expect(mergeConfig(&cfg, &none, &s) != null);
    try std.testing.expect(cfg.command == null);

    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("\"C:\\a b\\x.exe\" -k \"\"", joinCommand(&.{ "C:\\a b\\x.exe", "-k", "" }, &buf));
}

test "run defaults to instruct input; keys for a shell" {
    const o = parseRunArgs(&.{});
    try std.testing.expect(o.policy == null);
    var cfg: RunConfig = .{};
    try std.testing.expect(mergeConfig(&cfg, &o, &.{}) == null);
    try std.testing.expectEqual(keymap.Policy.instruct, cfg.policy);
    try std.testing.expect(!cfg.fell_back);
    {
        const sh = parseRunArgs(&.{ "--", "cmd.exe", "/k" });
        try std.testing.expect(mergeConfig(&cfg, &sh, &.{}) == null);
        try std.testing.expectEqual(keymap.Policy.keys, cfg.policy);
        try std.testing.expect(cfg.fell_back);
        // A saved shell program gets the same fallback.
        var s: settings.Settings = .{};
        _ = s.program.set("powershell.exe -NoLogo");
        try std.testing.expect(mergeConfig(&cfg, &o, &s) == null);
        try std.testing.expectEqual(keymap.Policy.keys, cfg.policy);
        const ok = parseRunArgs(&.{ "--allow-remote-shell", "--", "pwsh" });
        try std.testing.expect(mergeConfig(&cfg, &ok, &.{}) == null);
        try std.testing.expectEqual(keymap.Policy.instruct, cfg.policy);
        // A chosen mode is never lowered (prepare refuses it for a shell).
        const ex = parseRunArgs(&.{ "--input", "instruct", "--", "cmd.exe" });
        try std.testing.expect(mergeConfig(&cfg, &ex, &.{}) == null);
        try std.testing.expectEqual(keymap.Policy.instruct, cfg.policy);
        try std.testing.expect(!cfg.fell_back);
    }
    try std.testing.expect(!o.console);
    const c = parseRunArgs(&.{ "--console", "--", "cmd.exe" });
    try std.testing.expect(c.console);
    try std.testing.expect(c.cwd == null);
    const d = parseRunArgs(&.{ "--cwd", "C:\\work", "--", "cmd.exe" });
    try std.testing.expectEqualStrings("C:\\work", d.cwd.?);
    const t = parseRunArgs(&.{ "--input", "text" });
    try std.testing.expectEqual(keymap.Policy.text, t.policy.?);
    try std.testing.expectEqualStrings("", policyNote(.keys));
    try std.testing.expect(std.mem.indexOf(u8, policyNote(.text), "FULL REMOTE CONTROL") != null);
}
