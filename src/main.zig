//! Portal: watch (and answer prompts in) a terminal session running on this
//! desktop from a browser elsewhere, over a private network (WireGuard).
//!
//!   portal pair <name>               let a device pair (2-minute window,
//!                                    each request approved at the desk)
//!   portal devices                   list paired devices
//!   portal unpair <name>             revoke a device
//!   portal run [options] [-- cmd...] start a session (default cmd: claude)
//!                                    in Portal's own window (gui.zig), or
//!                                    in this console with --console
//!   portal connect --server IP:PORT  view a remote Portal (client/src)
//!   portal ca [init|export|show]     the private CA behind Portal's HTTPS
//!   portal show <file.png>           show an image inline (show.zig)
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
const tls_server = @import("tls/server.zig");
const x509 = @import("tls/x509.zig");
const pki = @import("tls/pki.zig");

/// [fix2/desk] Root panic handler: logs to portal.log, message box in GUI mode.
pub const panic = @import("panic.zig").handler;

pub const portal_version = "0.1.0";
const default_listen = "127.0.0.1:8420";

const usage =
    \\Portal {s} - remote viewer for a desktop terminal session
    \\
    \\Usage:
    \\  portal pair <name> [--minutes N]
    \\      Pair a device called <name> (a-z, 0-9, -). Stays running for the
    \\      window (default 2 minutes, max 10) and asks you, here, about each
    \\      device that asks to pair:
    \\        Pair 'iphone' from 10.8.0.3 (request 7f3a)? [y/N]
    \\      On the device, with WireGuard on, open the address `portal run`
    \\      listens on (e.g. https://10.8.0.1:8420/ after
    \\      `portal run --listen 10.8.0.1:8420`) and tap "Pair this device";
    \\      it shows the same request code. Nothing is typed on the device:
    \\      it gets its own credential, which rotates on every use and is
    \\      bound to its WireGuard address. While the window is open,
    \\      `portal run` also serves the Portal CA certificate on
    \\      http://<address>:<port+1>/; `portal pair` prints the CA's
    \\      SHA-256 and whether that download is actually up.
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
    \\      --listen IP:PORT   Address to listen on (default {s}, which
    \\                         only this desktop can reach). For your other
    \\                         devices give your WireGuard address, e.g.
    \\                         --listen 10.8.0.1:8420. Wildcard and public
    \\                         addresses are refused.
    \\      --host NAME[:PORT] Extra Host header value to accept (repeatable).
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
    \\                                 The browser's input box (typing or
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
    \\      --no-tls           Serve plain HTTP instead of HTTPS (tests and
    \\                         debugging only; WireGuard is then the only
    \\                         protection for cookies and keystrokes).
    \\
    \\  portal ca [show]
    \\      Show the private CA that signs Portal's HTTPS certificate.
    \\  portal ca init [--permit CIDR]... [--permit-dns NAME]... [--force]
    \\      Create the CA (`portal run` does this on first use). Its name
    \\      constraints only allow the --permit subnets (default
    \\      10.8.0.0/24 and 127.0.0.1/32) and --permit-dns names (default:
    \\      none). --force replaces an existing CA: every device must then
    \\      trust the new one.
    \\  portal ca export [--out DIR]
    \\      Write portal-ca.cer, portal-ca.pem and portal-ca.mobileconfig
    \\      (default: current directory) and print the fingerprint and the
    \\      iPhone trust steps.
    \\
    \\  portal connect --server IP:PORT [--forget]
    \\      Watch a Portal running on another machine (pair with it first:
    \\      `portal pair <name>` there, then click Pair here).
    \\
    \\  portal show <file.png> [--cols N] [--stdout]
    \\      Show a PNG inline in this terminal (kitty graphics). Inside a
    \\      Portal session the image appears in the window and for remote
    \\      viewers. Reads only the file named; nothing is sent anywhere else.
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
    if (std.mem.eql(u8, cmd, "ca")) return cmdCa(gpa, io, init.environ_map, args[1..]);
    if (std.mem.eql(u8, cmd, "show")) std.process.exit(@import("show.zig").main(gpa, io, args[1..]));
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

const SYNCHRONIZE: w.DWORD = 0x00100000;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) w.DWORD;
extern "kernel32" fn OpenProcess(access: w.DWORD, inherit: w.BOOL, pid: w.DWORD) callconv(.winapi) ?w.HANDLE;
extern "kernel32" fn CreateEventW(sa: ?*anyopaque, manual: w.BOOL, initial: w.BOOL, name: ?[*:0]const u16) callconv(.winapi) ?w.HANDLE;
extern "kernel32" fn SetEvent(h: w.HANDLE) callconv(.winapi) w.BOOL;
extern "kernel32" fn ResetEvent(h: w.HANDLE) callconv(.winapi) w.BOOL;
extern "kernel32" fn SetConsoleCtrlHandler(handler: ?*const fn (w.DWORD) callconv(.winapi) w.BOOL, add: w.BOOL) callconv(.winapi) w.BOOL;

/// SHA-256 of the Portal CA, if one exists yet (never creates one).
fn caFingerprint(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, out: *[95]u8) ?[]const u8 {
    const store = tlsStore(gpa, io, env) catch return null;
    defer gpa.free(store.dir);
    var ca = (pki.loadCa(store) catch return null) orelse return null;
    defer ca.deinit(gpa);
    return x509.formatFingerprint(x509.fingerprint(ca.der), out);
}

/// Lines typed at the `portal pair` console, handed from a reader thread
/// to the main loop through an event it can wait on with the store watch.
const ConsoleLines = struct {
    ready_ev: w.HANDLE,
    taken_ev: w.HANDLE,
    buf: [256]u8 = undefined,
    len: usize = 0,
    eof: std.atomic.Value(bool) = .init(false),
    ready: std.atomic.Value(bool) = .init(false),

    fn reader(c: *ConsoleLines) void {
        const in = w.GetStdHandle(w.STD_INPUT_HANDLE) orelse {
            c.finish();
            return;
        };
        var line: [256]u8 = undefined;
        var n: usize = 0;
        while (true) {
            var b: [1]u8 = undefined;
            var got: w.DWORD = 0;
            if (w.ReadFile(in, &b, 1, &got, null) == 0 or got == 0) {
                c.finish();
                return;
            }
            if (b[0] == '\r') continue;
            if (b[0] != '\n') {
                if (n < line.len) line[n] = b[0];
                n +|= 1;
                continue;
            }
            const len = @min(n, line.len);
            @memcpy(c.buf[0..len], line[0..len]);
            c.len = len;
            n = 0;
            c.ready.store(true, .release);
            _ = SetEvent(c.ready_ev);
            _ = w.WaitForSingleObject(c.taken_ev, w.INFINITE);
        }
    }

    fn finish(c: *ConsoleLines) void {
        c.eof.store(true, .release);
        _ = SetEvent(c.ready_ev);
    }

    /// The next typed line, if one is waiting (copied into `out`).
    fn take(c: *ConsoleLines, out: []u8) ?[]const u8 {
        if (!c.ready.load(.acquire)) return null;
        const n = @min(c.len, out.len);
        @memcpy(out[0..n], c.buf[0..n]);
        c.ready.store(false, .release);
        _ = ResetEvent(c.ready_ev);
        _ = SetEvent(c.taken_ev);
        return out[0..n];
    }
};

/// "y" / "yes" (any case, surrounding blanks ignored) approves; anything
/// else, including an empty line, denies.
pub fn isYes(line: []const u8) bool {
    const t = std.mem.trim(u8, line, " \t");
    return std.ascii.eqlIgnoreCase(t, "y") or std.ascii.eqlIgnoreCase(t, "yes");
}

/// What Ctrl+C / closing the console must undo: the window this
/// `portal pair` opened.
var pair_cleanup: ?struct { gpa: Allocator, io: Io, paths: devices.Paths, nonce: u64 } = null;

fn pairCtrlHandler(_: w.DWORD) callconv(.winapi) w.BOOL {
    if (pair_cleanup) |c| endWindow(c.gpa, c.io, c.paths, c.nonce);
    std.debug.print("\nPairing cancelled; the window is closed.\n", .{});
    w.ExitProcess(130);
}

fn endWindow(gpa: Allocator, io: Io, paths: devices.Paths, nonce: u64) void {
    devices.withStore(gpa, io, paths, nowUnix(io), nonce, struct {
        fn op(n: u64, st: *devices.Store) !bool {
            return st.endPair(n);
        }
    }.op) catch {};
}

fn pairStoreFail(desk: devices.Desk, nonce: u64, err: anyerror) noreturn {
    desk.cancel(nonce) catch {};
    fatal("device store error: {s} ({t})", .{ devices.describeError(err), err });
}

fn pairLog(gpa: Allocator, paths: devices.Paths, io: Io, comptime fmt: []const u8, args: anytype) void {
    if (openLog(gpa, paths, io)) |opened| {
        var log = opened;
        defer log.close();
        log.print(fmt, args);
    }
}

/// `portal pair <name>`: opens a window, then stays here asking the owner
/// to approve or deny each device that asks (nothing is typed on the
/// device). Event-driven: it sleeps until the device list changes (a
/// device asked, collected its credential, the server reported on the
/// certificate listener), a line is typed, or the window expires.
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
    var fp_buf: [95]u8 = undefined;
    const fingerprint = caFingerprint(gpa, io, env, &fp_buf);

    var nonce_bytes: [8]u8 = undefined;
    io.randomSecure(&nonce_bytes) catch fatal("no entropy", .{});
    const nonce = std.mem.readInt(u64, &nonce_bytes, .little) | 1;
    const pid = GetCurrentProcessId();

    // Watch before opening the window, so no change is missed.
    var dw = devices.DirWatch.open(gpa, paths);
    defer dw.close();

    // `portal pair` is a thin console wrapper over devices.Desk, the same
    // API the Portal window uses (through web.Server.desk*).
    const desk: devices.Desk = .{ .gpa = gpa, .io = io, .paths = paths };
    const now0 = nowUnix(io);
    const replaced = desk.begin(name, minutes * 60, nonce, pid) catch |err|
        fatal("could not open the pairing window: {s} ({t})", .{ devices.describeError(err), err });
    var replaced_buf: [devices.max_name]u8 = undefined;
    var replaced_len: usize = 0;
    if (replaced) |t| {
        replaced_len = t.len;
        @memcpy(replaced_buf[0..t.len], t.get());
    }
    pair_cleanup = .{ .gpa = gpa, .io = io, .paths = paths, .nonce = nonce };
    _ = SetConsoleCtrlHandler(&pairCtrlHandler, 1);
    pairLog(gpa, paths, io, "pairing window opened for '{s}' ({d} min); requests need approval at the desk", .{ name, minutes });

    if (replaced_len > 0) std.debug.print("(Replaced the open pairing window for '{s}'.)\n", .{replaced_buf[0..replaced_len]});
    std.debug.print(
        \\Pairing open for '{s}' for {d} minute(s). Nothing is typed on the device:
        \\you approve it here.
        \\
        \\
    , .{ name, minutes });
    if (fingerprint) |fp| {
        std.debug.print("Portal CA SHA-256: {s}\n", .{fp});
    } else {
        std.debug.print("Portal CA: none yet (the first `portal run` creates it).\n", .{});
    }
    std.debug.print(
        \\
        \\On the device, with WireGuard on:
        \\  1. First time only: open http://<desktop WireGuard address>:<port+1>/
        \\     (e.g. http://10.8.0.1:8421/) and install the Portal certificate. Its
        \\     SHA-256 (shown on that page and in the profile details) must match
        \\     the one above. iPhone/iPad: also enable full trust for it in
        \\     Settings > General > About > Certificate Trust Settings.
        \\  2. Open https://<desktop WireGuard address>:<port>/ (e.g.
        \\     https://10.8.0.1:8420/) and tap "Pair this device".
        \\Each request then appears here with a code, which the device also shows.
        \\Approve only the request whose code and address match your device.
        \\
        \\Waiting for the device... (Ctrl+C cancels)
        \\
    , .{});

    var lines: ConsoleLines = .{
        .ready_ev = CreateEventW(null, 1, 0, null) orelse fatal("cannot create an event", .{}),
        .taken_ev = CreateEventW(null, 0, 0, null) orelse fatal("cannot create an event", .{}),
    };
    const reader = std.Thread.spawn(.{}, ConsoleLines.reader, .{&lines}) catch fatal("cannot start the input thread", .{});
    reader.detach();

    const start_s = nowUnix(io);
    var expires: i64 = now0 + minutes * 60;
    var asked: ?[devices.code_len]u8 = null;
    var announced: [devices.max_requests * 4][devices.code_len]u8 = undefined;
    var n_announced: usize = 0;
    var ca_seen: devices.CaState = .unknown;
    var ca_hint_done = false;
    var first = true;
    while (true) {
        if (!first) dw.rearm();
        first = false;
        const now = nowUnix(io);

        // A typed answer applies to the request currently asked.
        var answer: ?struct { code: [devices.code_len]u8, yes: bool } = null;
        var line_buf: [256]u8 = undefined;
        if (lines.take(&line_buf)) |line| {
            if (asked) |code| {
                answer = .{ .code = code, .yes = isYes(line) };
            } else std.debug.print("(no request is waiting for an answer)\n", .{});
        }
        if (lines.eof.load(.acquire) and !lines.ready.load(.acquire)) {
            endWindow(gpa, io, paths, nonce);
            fatal("input closed: `portal pair` must ask you to approve the device, so run it in a terminal. The window is closed.", .{});
        }

        const Snap = struct {
            lost: bool = false,
            pairing: ?devices.Pairing = null,
            answer_result: ?devices.AnswerResult = null,
            done: ?devices.Request = null,
        };
        var snap: Snap = .{};
        if (answer) |a| snap.answer_result = desk.answer(nonce, &a.code, a.yes) catch |err| pairStoreFail(desk, nonce, err);
        snap.pairing = desk.get(nonce) catch |err| pairStoreFail(desk, nonce, err);
        if (snap.pairing) |p| {
            snap.done = devices.pairedRequest(&p);
            if (snap.done != null) desk.cancel(nonce) catch |err| pairStoreFail(desk, nonce, err);
        } else snap.lost = true;

        if (answer) |a| if (snap.answer_result) |r| {
            const ip: []const u8 = blk: {
                const p = snap.pairing orelse break :blk "?";
                const i = p.findCode(&a.code) orelse break :blk "?";
                break :blk p.requests[i].?.ip.get();
            };
            switch (r) {
                .approved => {
                    std.debug.print("Approved request {s} from {s}. Waiting for the device to collect its credential...\n", .{ &a.code, ip });
                    pairLog(gpa, paths, io, "pairing request {s} for '{s}' from {s} approved at the desk", .{ &a.code, name, ip });
                },
                .denied => {
                    std.debug.print("Denied request {s} from {s}. Further requests from that address are refused in this window.\n", .{ &a.code, ip });
                    pairLog(gpa, paths, io, "pairing request {s} for '{s}' from {s} denied at the desk", .{ &a.code, name, ip });
                },
                .not_pending, .no_such_request => std.debug.print("Request {s} is no longer waiting.\n", .{&a.code}),
                .window_gone => {},
            }
            asked = null;
        };

        if (snap.done) |r| {
            std.debug.print("Paired '{s}' at {s}.\n", .{ name, r.ip.get() });
            return;
        }
        if (snap.lost) {
            if (now > expires) {
                std.debug.print("The pairing window expired; nothing was paired. Run `portal pair {s}` again when the device is ready.\n", .{name});
                pairLog(gpa, paths, io, "pairing window for '{s}' expired; nothing was paired", .{name});
            } else {
                std.debug.print("The pairing window was closed or replaced by another `portal pair`.\n", .{});
            }
            w.ExitProcess(1);
        }
        const p = snap.pairing.?;
        expires = p.expires;

        // What the running server reports about the certificate listener.
        if (p.ca != ca_seen) {
            ca_seen = p.ca;
            switch (p.ca) {
                .up => std.debug.print("Certificate download is up: http://{s}/ (served by `portal run`).\n", .{p.ca_where.get()}),
                .failed => std.debug.print(
                    \\WARNING: `portal run` could NOT open the certificate download listener on
                    \\  {s}. Another program may be using that port: do not install a
                    \\  certificate from that address. Use `portal ca export` instead, and
                    \\  check the SHA-256 above.
                    \\
                , .{p.ca_where.get()}),
                .off => std.debug.print("`portal run` uses --no-tls: no certificate download.\n", .{}),
                .unknown => {},
            }
        }
        if (p.ca == .unknown and !ca_hint_done and now - start_s >= 3) {
            ca_hint_done = true;
            std.debug.print("No running `portal run` has picked up this window yet (start it, as this Windows user).\n", .{});
        }

        // Announce new requests; ask about one at a time, oldest first.
        if (asked) |code| {
            const still = if (p.findCode(&code)) |i| p.requests[i].?.state == .pending else false;
            if (!still) {
                std.debug.print("\nRequest {s} is no longer waiting.\n", .{&code});
                asked = null;
            }
        }
        var order: [devices.max_requests]usize = undefined;
        var n_order: usize = 0;
        for (p.requests, 0..) |slot, i| if (slot != null) {
            order[n_order] = i;
            n_order += 1;
        };
        std.mem.sort(usize, order[0..n_order], &p, struct {
            fn lt(pp: *const devices.Pairing, a: usize, b: usize) bool {
                return pp.requests[a].?.created < pp.requests[b].?.created;
            }
        }.lt);
        for (order[0..n_order]) |i| {
            const r = p.requests[i].?;
            var seen = false;
            for (announced[0..n_announced]) |c| seen = seen or std.mem.eql(u8, &c, &r.code);
            if (seen or r.state != .pending) continue;
            if (n_announced < announced.len) {
                announced[n_announced] = r.code;
                n_announced += 1;
            }
            if (asked != null) std.debug.print("\n  (another request is waiting: '{s}' from {s}, request {s}; asked next)\n", .{ name, r.ip.get(), &r.code });
        }
        if (asked == null and !p.decided()) {
            for (order[0..n_order]) |i| {
                const r = p.requests[i].?;
                if (r.state != .pending) continue;
                std.debug.print("\nPair '{s}' from {s} (request {s})? [y/N] ", .{ name, r.ip.get(), &r.code });
                asked = r.code;
                break;
            }
        }

        var handles: [2]w.HANDLE = undefined;
        var n_h: w.DWORD = 0;
        handles[n_h] = lines.ready_ev;
        n_h += 1;
        if (dw.h) |h| {
            handles[n_h] = h;
            n_h += 1;
        }
        var ms = devices.waitMs(now, expires);
        if (p.ca == .unknown and !ca_hint_done) ms = @min(ms, 3000);
        if (dw.h == null) ms = @min(ms, 1000); // no change notification: re-check each second
        _ = devices.WaitForMultipleObjects(n_h, &handles, 0, ms);
    }
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
            if (st.pairing) |p| if (st.pairingName(c.now) != null) {
                std.debug.print("Pairing window open for '{s}' ({d} s left; answer requests in its `portal pair` console).\n", .{ p.name.get(), p.expires - c.now });
                for (p.requests) |slot| {
                    const r = slot orelse continue;
                    std.debug.print("  request {s} from {s}: {t}\n", .{ &r.code, r.ip.get(), r.state });
                }
            };
            return false;
        }
    }.op) catch |err| fatal("could not read the device list: {s} ({t})", .{ devices.describeError(err), err });
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
    }.op) catch |err| fatal("could not update the device list: {s} ({t})", .{ devices.describeError(err), err });
    if (!removed) fatal("no paired device named '{s}' (see `portal devices`)", .{args[0]});
    pairLog(gpa, paths, io, "device '{s}' unpaired from the desktop", .{args[0]});
    std.debug.print("Unpaired '{s}'. Its open viewers are disconnected within a few seconds.\n", .{args[0]});
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
            } else fatal("usage: portal ca init [--permit CIDR]... [--permit-dns NAME]... [--force]", .{});
        }
        if (c.n_subnets == 0) {
            const d = pki.defaultConstraints();
            c.subnets = d.subnets;
            c.n_subnets = d.n_subnets;
        }
        var ca = pki.initCa(store, &c, nowUnix(io), force) catch |err| switch (err) {
            error.CaExists => fatal("a Portal CA already exists (see `portal ca`). Replacing it means re-trusting it on every device; add --force to do that.", .{}),
            else => fatal("could not create the CA: {t}", .{err}),
        };
        defer ca.deinit(gpa);
        var fp: [95]u8 = undefined;
        std.debug.print("Created {s}\n  SHA-256 {s}\n  permitted names:\n", .{ ca.commonName(), x509.formatFingerprint(x509.fingerprint(ca.der), &fp) });
        printConstraints(&ca.constraints);
        std.debug.print("Next: `portal ca export` and trust it on each device.\n", .{});
        return;
    }

    var ca = (pki.loadCa(store) catch |err| fatal("cannot read the Portal CA in {s}: {t}", .{ store.dir, err })) orelse
        fatal("no Portal CA yet: run `portal ca init` (or just `portal run`, which creates one)", .{});
    defer ca.deinit(gpa);
    var fp: [95]u8 = undefined;
    const fingerprint = x509.formatFingerprint(x509.fingerprint(ca.der), &fp);

    if (std.mem.eql(u8, sub, "export")) {
        var out_dir: []const u8 = ".";
        if (rest.len == 2 and std.mem.eql(u8, rest[0], "--out")) {
            out_dir = rest[1];
        } else if (rest.len != 0) fatal("usage: portal ca export [--out DIR]", .{});
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
    if (!std.mem.eql(u8, sub, "show")) fatal("usage: portal ca [show | init ... | export [--out DIR]]", .{});

    std.debug.print("{s}\n  SHA-256 {s}\n  files   {s}\n", .{ ca.commonName(), fingerprint, store.dir });
    printDate("  valid until ", ca.info.not_after);
    const ca_left = ca.secondsLeft(nowUnix(io));
    if (ca_left <= 0) {
        std.debug.print("  EXPIRED: run `portal ca init --force` (devices must re-trust)\n", .{});
    } else {
        std.debug.print("  remaining {d} days{s}\n", .{ @divFloor(ca_left, 86400), if (ca_left < pki.ca_warn_before_s) " (renew soon: `portal ca init --force`, devices must re-trust)" else "" });
    }
    if (!ca.currentProfile())
        std.debug.print("  old CA profile (no extKeyUsage serverAuth / closed name forms) - run `portal ca init --force` to upgrade (devices must re-trust)\n", .{});
    std.debug.print("  key     DPAPI, current user: any program running as you can use it\n", .{});
    std.debug.print("  permitted names (name constraints):\n", .{});
    printConstraints(&ca.constraints);
    const leaf_path = std.fs.path.join(gpa, &.{ store.dir, "leaf.crt" }) catch return;
    defer gpa.free(leaf_path);
    const leaf_der = Io.Dir.cwd().readFileAlloc(io, leaf_path, gpa, .limited(64 * 1024)) catch {
        std.debug.print("  no server certificate yet (issued by `portal run`)\n", .{});
        return;
    };
    defer gpa.free(leaf_der);
    const leaf = x509.parse(leaf_der) catch {
        std.debug.print("  server certificate unreadable (re-issued by the next `portal run`)\n", .{});
        return;
    };
    std.debug.print("  server certificate:\n", .{});
    printDate("    valid until ", leaf.not_after);
    var spki_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(leaf.spki_raw, &spki_hash, .{});
    var b64: [44]u8 = undefined;
    std.debug.print("    SPKI SHA-256 (base64) {s}\n", .{std.base64.standard.Encoder.encode(&b64, &spki_hash)});
}

/// Host part of a Host-style value: "10.8.0.1:8420" -> "10.8.0.1",
/// "[fd00::1]:8420" -> "fd00::1", "desk" -> "desk".
fn hostOnly(h: []const u8) []const u8 {
    if (h.len > 0 and h[0] == '[') {
        const end = std.mem.indexOfScalar(u8, h, ']') orelse return h;
        return h[1..end];
    }
    if (std.mem.count(u8, h, ":") == 1) return h[0..std.mem.indexOfScalar(u8, h, ':').?];
    return h;
}

/// The same host with `port` (for the certificate download listener's
/// Host allowlist).
fn withPort(gpa: Allocator, h: []const u8, port: u16) ![]u8 {
    const host = hostOnly(h);
    if (std.mem.indexOfScalar(u8, host, ':') != null) return std.fmt.allocPrint(gpa, "[{s}]:{d}", .{ host, port });
    return std.fmt.allocPrint(gpa, "{s}:{d}", .{ host, port });
}

const TlsSetup = struct { ca: pki.Ca, leaf: pki.Leaf };

/// Loads (or on first use creates) the CA and makes sure the server
/// certificate covers the listen address and any permitted --host names.
fn setupTls(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, addr: std.Io.net.IpAddress, hosts: []const []const u8, log: *Log) TlsSetup {
    const store = tlsStore(gpa, io, env) catch |err| fatal("cannot create the TLS directory: {t}", .{err});
    const now = nowUnix(io);
    const ca = (pki.loadCa(store) catch |err|
        fatal("cannot read the Portal CA in {s}: {t} (move the tls folder away to start over)", .{ store.dir, err })) orelse blk: {
        const c = pki.defaultConstraints();
        const created = pki.initCa(store, &c, now, false) catch |err| fatal("cannot create the Portal CA: {t}", .{err});
        std.debug.print("portal: created {s}, limited to 10.8.0.0/24 and 127.0.0.1.\n" ++
            "       Install it on each device first: `portal ca export` (see README).\n", .{created.commonName()});
        log.print("created {s}", .{created.commonName()});
        break :blk created;
    };
    const ca_left = ca.secondsLeft(now);
    if (ca_left <= 0)
        fatal("the Portal CA has expired. Run `portal ca init --force`, then trust the new CA on every device.", .{});
    if (ca_left < pki.ca_warn_before_s) {
        std.debug.print("portal: warning: the Portal CA expires in {d} days; server certificates end with it. " ++
            "Run `portal ca init --force` and re-trust it on each device.\n", .{@divFloor(ca_left, 86400)});
        log.print("CA expires in {d} days", .{@divFloor(ca_left, 86400)});
    }
    if (!ca.currentProfile())
        std.debug.print("portal: note: old CA profile - run `portal ca init --force` to upgrade (devices must re-trust).\n", .{});

    var sans: [1 + 16]x509.SanEntry = undefined;
    var n: usize = 0;
    var listen_ip: [16]u8 = @splat(0);
    const ip_len: u8 = switch (addr) {
        .ip4 => |a| blk: {
            @memcpy(listen_ip[0..4], &a.bytes);
            break :blk 4;
        },
        .ip6 => |a| blk: {
            listen_ip = a.bytes;
            break :blk 16;
        },
    };
    if (!ca.constraints.ipPermitted(listen_ip[0..ip_len])) {
        std.debug.print("permitted by the Portal CA:\n", .{});
        printConstraints(&ca.constraints);
        fatal("the listen address is outside the Portal CA's name constraints. Re-create the CA with " ++
            "`portal ca init --force --permit <subnet>` (every device must then trust it again).", .{});
    }
    sans[n] = .{ .ip = .{ .bytes = listen_ip, .len = ip_len } };
    n += 1;
    for (hosts) |h| {
        if (n == sans.len) break;
        const host = hostOnly(h);
        var entry: ?x509.SanEntry = null;
        if (std.Io.net.IpAddress.parse(host, 0)) |ip| {
            var b: [16]u8 = @splat(0);
            const l: u8 = switch (ip) {
                .ip4 => |a| blk: {
                    @memcpy(b[0..4], &a.bytes);
                    break :blk 4;
                },
                .ip6 => |a| blk: {
                    b = a.bytes;
                    break :blk 16;
                },
            };
            if (ca.constraints.ipPermitted(b[0..l])) entry = .{ .ip = .{ .bytes = b, .len = l } };
        } else |_| {
            if (x509.validDnsName(host) and ca.constraints.dnsPermitted(host)) entry = .{ .dns = host };
        }
        const e = entry orelse {
            std.debug.print("portal: note: --host {s} is outside the CA's name constraints; not in the certificate (HTTPS to that name will fail)\n", .{h});
            continue;
        };
        var dup = false;
        for (sans[0..n]) |s| dup = dup or sanEql(s, e);
        if (!dup) {
            sans[n] = e;
            n += 1;
        }
    }
    const leaf = pki.ensureLeaf(store, &ca, sans[0..n], now) catch |err| fatal("cannot issue the server certificate: {t}", .{err});
    if (leaf.renewed) |why| {
        log.print("issued a new server certificate ({s})", .{why});
        std.debug.print("portal: issued a new server certificate ({s}).\n", .{why});
    }
    return .{ .ca = ca, .leaf = leaf };
}

fn sanEql(a: x509.SanEntry, b: x509.SanEntry) bool {
    return switch (a) {
        .ip => |x| switch (b) {
            .ip => |y| x.len == y.len and std.mem.eql(u8, x.bytes[0..x.len], y.bytes[0..y.len]),
            .dns => false,
        },
        .dns => |x| switch (b) {
            .dns => |y| std.ascii.eqlIgnoreCase(x, y),
            .ip => false,
        },
    };
}

/// The server side of pairing, event-driven: sleeps until a file in the
/// data directory is renamed (every device-store change ends in one), the
/// `portal pair` process that owns the open window exits, or the window
/// expires. On each wake it re-reads the store once and
///   * refreshes the HTTPS server's in-memory pairing view (so requests
///     before sign-in never read the file),
///   * ends the sessions of devices that are no longer paired (`portal
///     unpair` from another process); a failed read revokes nothing,
///   * opens the certificate download listener (plain HTTP, listen port
///     + 1) while a window is open, closes it afterwards, and reports
///     whether it is actually up back into the store, where `portal pair`
///     shows it. A listener that can't be opened (e.g. another program is
///     squatting the port) is logged loudly and reported as failed.
const PairWatch = struct {
    srv: *web.Server,
    /// The certificate download server; null with --no-tls.
    ca_srv: ?*web.Server,
    ca_addr: std.Io.net.IpAddress,
    paths: devices.Paths,
    io: Io,
    gpa: Allocator,

    fn readStore(pw: *PairWatch, out: *devices.Store) !void {
        devices.withStore(pw.gpa, pw.io, pw.paths, nowUnix(pw.io), out, struct {
            fn op(o: *devices.Store, st: *devices.Store) !bool {
                o.* = st.*;
                return false;
            }
        }.op) catch |err| return err;
    }

    /// Records the certificate listener's state for window `nonce`.
    fn report(pw: *PairWatch, nonce: u64, state: devices.CaState, where: []const u8) void {
        const Ctx = struct { nonce: u64, state: devices.CaState, where: []const u8 };
        devices.withStore(pw.gpa, pw.io, pw.paths, nowUnix(pw.io), Ctx{ .nonce = nonce, .state = state, .where = where }, struct {
            fn op(c: Ctx, st: *devices.Store) !bool {
                const p = &(st.pairing orelse return false);
                if (p.nonce != c.nonce or (p.ca == c.state and std.mem.eql(u8, p.ca_where.get(), c.where))) return false;
                p.ca = c.state;
                p.ca_where.set(if (devices.validWhere(c.where)) c.where else "");
                return true;
            }
        }.op) catch |err| pw.srv.noteStoreError(err);
    }

    fn watch(pw: *PairWatch) void {
        const io = pw.io;
        var dw = devices.DirWatch.open(pw.gpa, pw.paths);
        if (dw.h == null) pw.srv.log.print("WARNING: cannot watch {s} for changes; re-reading the device list every 2 s instead", .{pw.paths.dir});
        var where_buf: [80]u8 = undefined;
        const where = std.fmt.bufPrint(&where_buf, "{f}", .{pw.ca_addr}) catch "?";
        var active: ?Io.Future(void) = null;
        var failed_nonce: u64 = 0;
        var proc_h: ?w.HANDLE = null;
        var proc_nonce: u64 = 0;
        var gone_nonce: u64 = 0;
        var first = true;
        while (true) {
            _ = pw.srv.pairwatch_wakes.fetchAdd(1, .monotonic);
            if (!first) dw.rearm(); // before reading: a change made meanwhile signals again
            first = false;
            const read_start = pw.srv.realNowMs();
            const now = nowUnix(io);
            var st: devices.Store = .{};
            var window: ?devices.Pairing = null;
            if (pw.readStore(&st)) |_| {
                pw.srv.applyStore(&st, read_start);
                window = st.pairing;
            } else |err| {
                pw.srv.noteStoreError(err);
                window = pw.srv.pairingSnapshot(now); // keep the last known view
            }

            // Follow the owning `portal pair` process.
            if (window) |p| {
                if (p.nonce != proc_nonce) {
                    if (proc_h) |h| _ = w.CloseHandle(h);
                    proc_nonce = p.nonce;
                    proc_h = OpenProcess(SYNCHRONIZE, 0, p.pid);
                    if (proc_h == null) {
                        gone_nonce = p.nonce;
                        pw.srv.pairingProcessGone(p.nonce);
                        pw.srv.log.print("pairing window closed: its `portal pair` (pid {d}) is not running (error {d})", .{ p.pid, w.GetLastError() });
                    }
                }
            } else if (proc_h) |h| {
                _ = w.CloseHandle(h);
                proc_h = null;
                proc_nonce = 0;
            }
            const open: ?devices.Pairing = if (window) |p|
                (if (now <= p.expires and p.nonce != gone_nonce) p else null)
            else
                null;

            if (pw.ca_srv) |cs| {
                if (open) |p| {
                    if (active == null and failed_nonce != p.nonce) {
                        if (pw.ca_addr.listen(io, .{ .reuse_address = false })) |l| {
                            cs.listener = l;
                            cs.stop.store(false, .release);
                            if (io.concurrent(web.Server.run, .{cs})) |f| {
                                active = f;
                                pw.srv.log.print("pairing window open: certificate download on http://{s}/", .{where});
                            } else |_| {
                                var ll = l;
                                ll.deinit(io);
                            }
                        } else |err| {
                            pw.srv.log.print("PAIRING WARNING: cannot open the certificate download listener on {s}: {t}. " ++
                                "Another program may be using that port; devices must not trust a certificate page served there " ++
                                "(use `portal ca export` and compare SHA-256 fingerprints).", .{ where, err });
                        }
                        if (active == null) failed_nonce = p.nonce;
                    }
                    pw.report(p.nonce, if (active != null) .up else .failed, where);
                } else if (active) |*f| {
                    cs.stop.store(true, .release);
                    f.cancel(io); // interrupts the blocked accept, waits for run() to return
                    active = null;
                    cs.listener.deinit(io);
                    pw.srv.log.print("pairing window closed: certificate download on http://{s}/ stopped", .{where});
                }
            } else if (open) |p| pw.report(p.nonce, .off, "");

            var handles: [2]w.HANDLE = undefined;
            var n: w.DWORD = 0;
            if (dw.h) |h| {
                handles[n] = h;
                n += 1;
            }
            const proc_slot = n;
            if (proc_h) |h| if (open != null) {
                handles[n] = h;
                n += 1;
            };
            var ms = devices.waitMs(now, if (open) |p| p.expires else null);
            if (dw.h == null) ms = @min(ms, 2000);
            const r = if (n == 0) blk: {
                io.sleep(.fromMilliseconds(ms), .awake) catch {};
                break :blk devices.WAIT_TIMEOUT;
            } else devices.WaitForMultipleObjects(n, &handles, 0, ms);
            if (n > proc_slot and r == devices.WAIT_OBJECT_0 + proc_slot) {
                // `portal pair` exited (Ctrl+C, closed console, killed):
                // the window closes now, not at its expiry.
                gone_nonce = proc_nonce;
                pw.srv.pairingProcessGone(proc_nonce);
                pw.srv.log.print("pairing window closed: `portal pair` exited", .{});
                if (proc_h) |h| _ = w.CloseHandle(h);
                proc_h = null;
            }
        }
    }
};

const no_tls_warning =
    \\
    \\  *****************************************************************
    \\  *  --no-tls: PLAIN HTTP. Cookies, device credentials and        *
    \\  *  keystrokes cross the network unencrypted; only WireGuard     *
    \\  *  protects them. Use this for tests and debugging only.        *
    \\  *****************************************************************
    \\
    \\
;

// -------------------------------------------------------------------- run

const RunOptions = struct {
    listen: []const u8 = default_listen,
    hosts: std.ArrayList([]const u8) = .empty,
    /// `instruct` by default: a paired device answers prompts and sends
    /// checked instruction lines (no shell escape, slash commands or memory
    /// shortcut). `keys` and `none` are stricter; `text` (full remote
    /// control) must be chosen explicitly. See `effectivePolicy` for shells.
    policy: keymap.Policy = .instruct,
    /// `--input` was given (the default is not applied to shells).
    policy_set: bool = false,
    /// `--console`: the pre-GUI mode, drawn by this process's console.
    console: bool = false,
    /// `--cwd`: the child's working directory (see workdir.zig for the default).
    cwd: ?[]const u8 = null,
    /// Plain HTTP (tests/debugging). HTTPS is the default.
    no_tls: bool = false,
    /// Allow instruct/text input when the session program is a shell.
    allow_remote_shell: bool = false,
    /// `--project`: shown in the window title (gui.validProject).
    project: ?[]const u8 = null,
    /// `--allow-elevated`: run even with an administrator token.
    allow_elevated: bool = false,
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
            std.mem.eql(u8, a, "--input") or std.mem.eql(u8, a, "--cwd") or std.mem.eql(u8, a, "--project");
        if (needs_value and i + 1 >= args.len) fatal("{s} needs a value", .{a});
        if (std.mem.eql(u8, a, "--listen")) {
            i += 1;
            o.listen = args[i];
        } else if (std.mem.eql(u8, a, "--host")) {
            i += 1;
            try o.hosts.append(gpa, args[i]);
        } else if (std.mem.eql(u8, a, "--input")) {
            i += 1;
            o.policy = keymap.Policy.parse(args[i]) orelse fatal("--input must be none, keys, instruct or text", .{});
            o.policy_set = true;
        } else if (std.mem.eql(u8, a, "--allow-remote-shell")) {
            o.allow_remote_shell = true;
        } else if (std.mem.eql(u8, a, "--allow-elevated")) {
            o.allow_elevated = true;
        } else if (std.mem.eql(u8, a, "--project")) {
            i += 1;
            if (!gui.validProject(args[i])) fatal("--project must be 1-{d} bytes of printable text on one line", .{gui.max_project_bytes});
            o.project = args[i];
        } else if (std.mem.eql(u8, a, "--no-tls")) {
            o.no_tls = true;
        } else if (std.mem.eql(u8, a, "--https")) {
            fatal("--https was removed: Portal now serves HTTPS itself (use --no-tls for plain HTTP)", .{});
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
    return switch (policy) {
        .text => " (FULL REMOTE CONTROL)",
        .instruct => " (checked instruction lines)",
        else => "",
    };
}

/// The input policy to run with. The default (`instruct`) is remote
/// typing, so for a shell it falls back to `keys` unless
/// --allow-remote-shell; an explicit --input is kept (and refused for a
/// shell by cmdRun). `fell_back` says the default was lowered.
fn effectivePolicy(o: RunOptions) struct { policy: keymap.Policy, fell_back: bool } {
    if (!o.policy_set and o.policy == .instruct and isShellProgram(o.command[0]) and !o.allow_remote_shell)
        return .{ .policy = .keys, .fell_back = true };
    return .{ .policy = o.policy, .fell_back = false };
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
    try std.testing.expect(!isShellProgram("claude"));
    try std.testing.expect(!isShellProgram("claude.cmd"));
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

    /// Console mode: one thread blocks on the console input handle and wakes
    /// only for keystrokes or window size/focus changes (no resize polling).
    /// After a resize event it re-reads the size once more when a single
    /// 150 ms deadline passes: the classic console host can report a buffer
    /// change before the window has finished growing, and growing the
    /// window alone sends no event. With nothing happening it waits forever.
    fn consoleInput(session: *Session, console: *Console) void {
        var buf: [4 * 1024]u8 = undefined;
        session.setSize(console.size());
        var settle_pending = false;
        while (true) {
            const timeout: u32 = if (settle_pending) 150 else std.math.maxInt(u32);
            if (!console.waitInput(timeout)) {
                // Deadline passed with no input: the one follow-up check.
                settle_pending = false;
                session.setSize(console.size());
                continue;
            }
            const e = console.readEvents(&buf) catch return;
            if (e.n > 0) session.writeInput(buf[0..e.n]);
            if (e.resized) {
                session.setSize(console.size());
                settle_pending = true;
            }
        }
    }

    fn closePty(session: *Session, done: *std.atomic.Value(bool)) void {
        session.shutdownPty();
        done.store(true, .release);
    }

    /// GUI mode: the main thread runs the window, so the child is waited
    /// for here.
    fn waitChild(pty: *conpty.Pty, code: *std.atomic.Value(u32), done: *std.atomic.Value(bool), host: *gui.LocalHost) void {
        code.store(pty.wait(), .release);
        done.store(true, .release);
        host.wakeChildExited(); // the GUI loop sleeps until woken
    }
};

/// The child's working directory as WTF-16 for CreateProcessW, or null to
/// inherit Portal's. `--cwd` must name an existing directory (relative to
/// Portal's current directory); otherwise workdir.defaultCwd decides.
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
        var d = Io.Dir.cwd().openDir(io, chosen, .{}) catch |err| fatal("--cwd '{s}' is not an existing directory ({t})", .{ a, err });
        d.close(io);
    } else {
        const releases = std.fs.path.join(gpa, &.{ data_dir, "releases" }) catch null;
        defer if (releases) |r| gpa.free(r);
        const has_parent = workdir.hasParentConsole(via_launcher);
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

    // [fix2/desk] Never run elevated by accident: the child and all remote
    // input would run as administrator. A double-clicked Portal's console
    // closes at once, so explain it in a message box too.
    const elevation = conpty.elevationCheck(conpty.isElevated(), opts.allow_elevated);
    if (elevation == .refuse) {
        if (!opts.console) console_freed = true; // fatal() then shows a message box
        fatal("Portal is running as administrator, so the session program and everything a paired device types would run as administrator. Run Portal from a normal (non-admin) terminal, or pass --allow-elevated if you really mean it.", .{});
    }

    // Remote typing into a shell is a remote shell: the default drops to
    // keys for one, and an explicit typing mode is refused unless allowed.
    const effective = effectivePolicy(opts);
    opts.policy = effective.policy;
    const fallback_note: []const u8 = if (effective.fell_back) " (instruct is the default, but not for a shell without --allow-remote-shell)" else "";
    if ((opts.policy == .instruct or opts.policy == .text) and isShellProgram(opts.command[0]) and !opts.allow_remote_shell)
        fatal("refusing --input {t} for a shell ({s}): remote typing would be a remote shell. Use --input keys, or pass --allow-remote-shell if you really mean it.", .{ opts.policy, opts.command[0] });

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
    if (elevation == .warn) { // [fix2/desk]
        std.debug.print("portal: WARNING: ELEVATED: remote input runs as administrator (--allow-elevated)\n", .{});
        log.print("start: ELEVATED: remote input runs as administrator (--allow-elevated)", .{});
    }

    // HTTPS: Portal's CA and a server certificate for the listen address.
    // Everything here lives until the process exits.
    var tls_creds: tls_server.Credentials = undefined;
    var tls_chain: [1][]const u8 = undefined;
    var ca_download: web.CaDownload = undefined;
    var fp_buf: [95]u8 = undefined;
    if (!opts.no_tls) {
        const tls_setup = setupTls(gpa, io, env, addr, opts.hosts.items[0 .. opts.hosts.items.len - 1], &log);
        tls_chain[0] = tls_setup.leaf.der;
        tls_creds = .{ .chain = &tls_chain, .key = tls_setup.leaf.key };
        ca_download = .{
            .cer = tls_setup.ca.der,
            .mobileconfig = pki.mobileconfig(gpa, &tls_setup.ca) catch fatal("out of memory", .{}),
            .fingerprint = x509.formatFingerprint(x509.fingerprint(tls_setup.ca.der), &fp_buf),
            .https_port = addr.getPort(),
        };
        std.debug.print("portal: HTTPS with certificate from {s}\n       CA SHA-256 {s}\n", .{ tls_setup.ca.commonName(), ca_download.fingerprint });
    } else {
        std.debug.print(no_tls_warning, .{});
        log.print("start: --no-tls given: serving plain HTTP", .{});
    }

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
    std.debug.print("portal: sharing '{s}' on {s}://{s}/  (input: {t}{s}{s})\n", .{
        opts.command[0], if (opts.no_tls) "http" else "https", listen_host, opts.policy, policyNote(opts.policy), fallback_note,
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
        @import("panic.zig").gui_mode.store(true, .release); // [fix2/desk] panics show a message box
        const h = gui.LocalHost.init(gpa, io, .{
            .command_name = std.fs.path.basename(opts.command[0]),
            .listen_host = listen_host,
            .policy = opts.policy,
            .project = opts.project,
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
            .scheme = if (opts.no_tls) "http" else "https",
            .secure_cookie = !opts.no_tls,
            .devices = paths,
            .tls = if (opts.no_tls) null else &tls_creds,
            .ca_fingerprint = if (opts.no_tls) null else ca_download.fingerprint,
        },
    };

    // While a pairing window is open: plain HTTP on port+1 serving only
    // the CA certificate, so a new device can install it before its first
    // HTTPS visit. PairWatch (always running) opens and closes it.
    var ca_server: web.Server = undefined;
    var ca_addr = addr;
    const ca_listener_on = !opts.no_tls and addr.getPort() < 65535;
    if (ca_listener_on) {
        ca_addr.setPort(addr.getPort() + 1);
        var ca_hosts: std.ArrayList([]const u8) = .empty;
        for (opts.hosts.items) |h| {
            ca_hosts.append(gpa, withPort(gpa, h, addr.getPort() + 1) catch fatal("out of memory", .{})) catch fatal("out of memory", .{});
        }
        ca_server = .{
            .gpa = gpa,
            .io = io,
            .session = &session,
            .log = &log,
            .listener = undefined,
            .cfg = .{
                .allowed_hosts = ca_hosts.items,
                .scheme = "http",
                .secure_cookie = false,
                .devices = paths,
                .ca_download = &ca_download,
            },
        };
    }
    var pair_watch: PairWatch = .{
        .srv = &server,
        .ca_srv = if (ca_listener_on) &ca_server else null,
        .ca_addr = ca_addr,
        .paths = paths,
        .io = io,
        .gpa = gpa,
    };

    log.print("start: v{s} zig {s}, listening on {s}, input={t}{s}{s}, command={s}", .{
        portal_version, builtin.zig_version_string, opts.listen, opts.policy, policyNote(opts.policy), fallback_note, opts.command[0],
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
        in_thread.detach(); // parked in ReadConsoleInputW; ends with the process
    }
    const accept_thread = std.Thread.spawn(.{}, web.Server.run, .{&server}) catch |err|
        fatal("cannot start web server thread: {t}", .{err});
    accept_thread.detach();
    {
        const t = std.Thread.spawn(.{}, PairWatch.watch, .{&pair_watch}) catch |err|
            fatal("cannot start the pairing watcher thread: {t}", .{err});
        t.detach();
    }

    var code: u32 = undefined;
    var window_closed = false;
    if (host) |h| {
        // GUI: the window owns the main thread; a waiter thread watches
        // the child. Closing the window ends the session the same way the
        // child exiting does (below): ClosePseudoConsole ends the child.
        const waiter = std.Thread.spawn(.{}, Threads.waitChild, .{ &pty, &child_code, &child_done, h }) catch |err|
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
        log.print("local window: {d} wake-ups, {d} frames presented", .{ h.wakeups, h.presents }); // [fix2/desk]
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
    _ = @import("panic.zig");
    _ = @import("conpty.zig");
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
    _ = @import("show.zig");
    _ = @import("web.zig"); // also pulls in http1.zig tests
    _ = @import("tls/server.zig"); // also server_test.zig
    _ = @import("tls/x509.zig");
    _ = @import("tls/der.zig");
    _ = @import("tls/dpapi.zig");
    _ = @import("tls/pki.zig");
}

test "isYes" {
    try std.testing.expect(isYes("y"));
    try std.testing.expect(isYes(" YES "));
    try std.testing.expect(!isYes(""));
    try std.testing.expect(!isYes("n"));
    try std.testing.expect(!isYes("yy"));
}

test "parseListen" {
    const a = try parseListen("10.8.0.1:8420");
    try std.testing.expectEqual(@as(u16, 8420), a.getPort());
    _ = try parseListen("[::1]:8420");
    try std.testing.expectError(error.MissingPort, parseListen("10.8.0.1"));
    try std.testing.expectError(error.BadPort, parseListen("10.8.0.1:0"));
    try std.testing.expectError(error.BadPort, parseListen("10.8.0.1:99999"));
}

test "run: --project and --allow-elevated" {
    var o = try parseRunArgs(std.testing.allocator, &.{});
    defer o.hosts.deinit(std.testing.allocator);
    try std.testing.expect(o.project == null);
    try std.testing.expect(!o.allow_elevated);
    var p = try parseRunArgs(std.testing.allocator, &.{ "--project", "acme-api", "--allow-elevated", "--", "cmd.exe" });
    defer p.hosts.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("acme-api", p.project.?);
    try std.testing.expect(p.allow_elevated);
}

test "run defaults to HTTPS; --https is gone" {
    var o = try parseRunArgs(std.testing.allocator, &.{});
    defer o.hosts.deinit(std.testing.allocator);
    try std.testing.expect(!o.no_tls);
    var p = try parseRunArgs(std.testing.allocator, &.{"--no-tls"});
    defer p.hosts.deinit(std.testing.allocator);
    try std.testing.expect(p.no_tls);
}

test "withPort and host splitting" {
    const gpa = std.testing.allocator;
    const a = try withPort(gpa, "10.8.0.1:8420", 8421);
    defer gpa.free(a);
    try std.testing.expectEqualStrings("10.8.0.1:8421", a);
    const b = try withPort(gpa, "[fd00::1]:8420", 8421);
    defer gpa.free(b);
    try std.testing.expectEqualStrings("[fd00::1]:8421", b);
    const c = try withPort(gpa, "desk.portal.home", 8421);
    defer gpa.free(c);
    try std.testing.expectEqualStrings("desk.portal.home:8421", c);
    try std.testing.expectEqualStrings("fd00::1", hostOnly("[fd00::1]:8420"));
    try std.testing.expectEqualStrings("10.8.0.1", hostOnly("10.8.0.1:8420"));
    try std.testing.expectEqualStrings("desk", hostOnly("desk"));
}

test "run defaults to instruct input; keys for a shell" {
    var o = try parseRunArgs(std.testing.allocator, &.{});
    defer o.hosts.deinit(std.testing.allocator);
    try std.testing.expectEqual(keymap.Policy.instruct, o.policy);
    try std.testing.expectEqual(keymap.Policy.instruct, effectivePolicy(o).policy);
    try std.testing.expect(!effectivePolicy(o).fell_back);
    {
        var sh = try parseRunArgs(std.testing.allocator, &.{ "--", "cmd.exe", "/k" });
        defer sh.hosts.deinit(std.testing.allocator);
        try std.testing.expectEqual(keymap.Policy.keys, effectivePolicy(sh).policy);
        try std.testing.expect(effectivePolicy(sh).fell_back);
        var ok = try parseRunArgs(std.testing.allocator, &.{ "--allow-remote-shell", "--", "pwsh" });
        defer ok.hosts.deinit(std.testing.allocator);
        try std.testing.expectEqual(keymap.Policy.instruct, effectivePolicy(ok).policy);
        // An explicit mode is never changed (cmdRun refuses it for a shell).
        var ex = try parseRunArgs(std.testing.allocator, &.{ "--input", "instruct", "--", "cmd.exe" });
        defer ex.hosts.deinit(std.testing.allocator);
        try std.testing.expectEqual(keymap.Policy.instruct, effectivePolicy(ex).policy);
        var k = try parseRunArgs(std.testing.allocator, &.{ "--input", "keys" });
        defer k.hosts.deinit(std.testing.allocator);
        try std.testing.expectEqual(keymap.Policy.keys, effectivePolicy(k).policy);
    }
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

