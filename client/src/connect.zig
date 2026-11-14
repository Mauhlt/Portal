//! The remote viewer: `portal connect` (in the Portal window's executable,
//! a GUI program with no console) and the standalone `portal-client` both
//! run `main` below. Module "client" in Portal's root build; imports std,
//! "view" (the window), "portal_ui" (the shared UI), "shared" and
//! "inputrules".
//!
//! This file is the device glue: it binds the shared UI's shell
//! (portal_ui.Shell, device `.viewer`) to the network client (net/) and the
//! sync worker: each frame it hands the shell the connection's state and the
//! sync panels; what the shell's input means comes back through `Host`
//! (keys.zig turns keys into protocol frames per the desktop's input mode).
//!
//!   connect                       the paired desktop, or the first-run screen
//!   connect --key                 print this device's tunnel key (and check code)
//!   connect --pairing-code CODE   pair with the code the desk showed
//!   connect --forget              forget the desktop (both ways)
//!
//! Everything goes through the in-process WireGuard tunnel
//! (devicelink.zig, tunnel/root.zig): this device is its tunnel key,
//! generated here and kept in the OS credential store. On a first run the
//! window shows the key; the owner enters it at the desk, compares check
//! codes, and enters the pairing code the desk shows here. Errors that end
//! the program go to `report_fn` (a message box in portal.exe) as well as
//! stderr.
//!
//! TLS 1.3 inside the tunnel, with the server certificate pinned to the
//! Portal CA whose SHA-256 the pairing code carried (net/pin.zig,
//! net/tlsconn.zig). Nothing secret is accepted on the command line.

const std = @import("std");
const view = @import("view");
const Presenter = view.Presenter;
const ui = @import("portal_ui");
const shell_mod = ui.shell;
const keys = @import("keys.zig");
const client_mod = @import("net/client.zig");
const credstore = @import("credstore.zig");
const http = @import("net/http.zig");
const pin_mod = @import("net/pin.zig");
const x509check = @import("net/x509check.zig");
const setup_mod = ui.panels.setup;
/// Portal sync (device side, and the manifest format the desktop shares).
pub const sync = @import("sync/root.zig");
/// The input line and the Data slice, shared with the desk's window.
pub const inputline = ui.inputline;
/// Touch input and the on-screen keyboard (Windows), shared with the desk.
pub const touchkbd = @import("touchkbd.zig");
pub const localtime = @import("localtime.zig");
pub const dataview = ui.dataview;
// For portalctl's headless sync-device (src/sync_cli.zig).
pub const net_client = client_mod;
pub const net_http = http;
pub const net_ws = @import("shared").ws;
pub const tlsconn = @import("net/tlsconn.zig");
pub const watchdog = @import("net/watchdog.zig");
pub const credstore_mod = credstore;
/// The in-process WireGuard tunnel (the desk uses it too: src/tunneldesk.zig).
pub const tunnel = @import("tunnel/root.zig");
/// The device's link to its desktop: pairing code, tunnel, trust.
pub const devicelink = @import("devicelink.zig");
pub const wsclient = @import("net/wsclient.zig");
pub const pin = pin_mod;
pub const x509check_mod = x509check;

/// Called with every message that ends the program (and --forget's
/// confirmation). portal.exe shows a message box: it has no console.
pub var report_fn: ?*const fn (text: []const u8) void = null;

/// What the device section around this shared viewer provides. The
/// defaults are the desktop/laptop behaviour; the iPhone app (client/src/
/// ios) sets its own before calling `main`. Only device glue lives behind
/// these hooks: what the viewer does with them is shared.
pub const Platform = struct {
    /// Run the Portal sync worker (TLS only). Off on the iPhone, which
    /// installs no packages.
    sync: bool = true,
    /// UI thread: the view went off screen (the connection is dropped
    /// meanwhile) / came back (the device may ask for Face ID first).
    on_suspend: ?*const fn () void = null,
    on_resume: ?*const fn () void = null,
    /// UI thread: start scanning the desk's pairing QR code (a camera
    /// view). The text arrives through `take_scanned`; the device wakes
    /// the window when it has one.
    scan_qr: ?*const fn () void = null,
    /// UI thread: a scanned QR text, copied into `buf`, at most once.
    take_scanned: ?*const fn (buf: []u8) ?[]const u8 = null,
    /// UI thread: why scanning did not start (e.g. camera access denied),
    /// copied into `buf`, at most once; shown as the setup screen's note.
    /// The device wakes the window when it has one.
    take_scan_note: ?*const fn (buf: []u8) ?[]const u8 = null,
};
pub var platform: Platform = .{};

const usage =
    \\usage: {s} [--pairing-code CODE] [--key] [--forget]
    \\
    \\  --key              print this device's tunnel key and its check code
    \\                     (to enter at the desk: Pair a device), and exit
    \\  --pairing-code CODE
    \\                     the code the desk showed after approving this
    \\                     device (otherwise the window asks for it once)
    \\  --forget           forget the paired desktop: tell it (through the
    \\                     tunnel), then delete its pairing code, pinned CA
    \\                     and release key, and its sync folder (packages)
    \\
    \\First run: the window shows this device's tunnel key. Enter it at the
    \\desk (Pair a device), compare the check codes, then enter the pairing
    \\code the desk shows. Later runs need nothing.
    \\
;

fn report(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt ++ "\n", args);
    if (report_fn) |f| {
        var buf: [2048]u8 = undefined;
        f(std.fmt.bufPrint(&buf, fmt, args) catch "portal connect: error");
    }
}

fn fatal(prog: []const u8, comptime fmt: []const u8, args: anytype) noreturn {
    report("{s}: " ++ fmt, .{prog} ++ args);
    std.process.exit(1);
}

const Host = struct {
    p: *Presenter,
    shared: *client_mod.Shared,
    client: *client_mod.Client,
    shell: ui.Shell = undefined,
    drawn_version: u64 = std.math.maxInt(u64),
    /// The last {"t":"rejected"} handed to the instruction line.
    seen_rejected: u64 = 0,
    /// The title as last set ("Portal — <project> — <status>").
    title_buf: [160]u8 = undefined,
    title_len: usize = 0,
    /// Copies of the tab list for this frame (built outside the lock's
    /// writers: the network thread replaces Shared.tabs).
    tabs: client_mod.TabList = .{},
    /// This frame's copy of the shown tab's sub-tabs (Shared.subs).
    subs: client_mod.SubList = .{},
    pin_fp_buf: [95]u8 = undefined,
    pin_fp_len: usize = 0,
    sync: *SyncState,
    sync_bufs: sync.ui.Ui.Bufs = .{},
    /// Whether the OS touch keyboard was last asked to show.
    keyboard_shown: bool = false,
    /// This frame's copies of the status panels' data.
    activity: client_mod.Activity = .{},
    sys: client_mod.SysSnapshot = .{},
    /// This frame's copy of the startable projects (the Projects sheet).
    projects: client_mod.ProjectList = .{},
    /// The Conversation view (the devices' default main view): its own
    /// copy of Shared.convo, synced under the lock each frame.
    convo_view: ui.convoview.View = undefined,
    /// Its For-you panel (Shared.foryou, the tab shown), likewise.
    fy_panel: ui.foryou.Panel = undefined,
    /// This frame's tabs with For-you cards that need the desk.
    needs_desk: [@import("shared").tabs.max_tabs]@import("shared").tabs.Id = undefined,
    n_needs_desk: usize = 0,

    /// The panel's frames (`i:`, `r:`) go out like any input.
    fn fySend(ctx: *anyopaque, f: []const u8) bool {
        const c: *client_mod.Client = @ptrCast(@alignCast(ctx));
        return c.sendInput(f);
    }

    /// The view's clock (swipe guard, animations): the awake clock.
    fn clockNow(ctx: ?*anyopaque) i64 {
        const h: *Host = @ptrCast(@alignCast(ctx.?));
        return watchdog.nowMs(h.client.io);
    }

    fn uiStatus(st: client_mod.Status) shell_mod.Status {
        return switch (st) {
            inline else => |t| @field(shell_mod.Status, @tagName(t)),
        };
    }

    /// Snapshot status under the lock, build the frame, then present.
    fn frame(h: *Host) void {
        const s = h.shared;
        const version = s.version.load(.acquire);
        h.shell.touch = touchkbd.query();
        var detail_buf: [160]u8 = undefined;
        s.mutex.lockUncancelable(h.client.io);
        const st = s.status;
        switch (st) {
            .starting, .connecting => {},
            else => h.p.splashDone(),
        }
        const detail = detail_buf[0..s.detail_len];
        @memcpy(detail, s.detail());
        if (s.rejected_gen != h.seen_rejected) {
            h.seen_rejected = s.rejected_gen;
            h.shell.rejected(s.rejected_buf[0..s.rejected_len]);
        }
        // The Data slice: new blobs from the terminal.
        _ = h.shell.data.sync(h.client.gpa, &s.grid.images);
        // The conversation (copied when it changed) and whether answers go.
        h.convo_view.sync(&s.convo);
        // A sub-tab is read-only: its conversation offers no answers.
        h.convo_view.answers = s.sub_shown == null and (if (s.mode) |m| m.acceptsAnswers() else false);
        h.fy_panel.sync(&s.foryou, s.current, if (s.mode) |m| @tagName(m) else null, s.sub_shown == null);
        // The tabs whose For-you cards need the desk (a hidden one makes
        // the "⋯ N hidden" button amber).
        h.n_needs_desk = 0;
        for (s.foryou.lists.items) |*l| if (l.needsDesk() and h.n_needs_desk < h.needs_desk.len) {
            h.needs_desk[h.n_needs_desk] = l.tab;
            h.n_needs_desk += 1;
        };
        h.subs = s.subs;
        // The tabs: what the top bar draws and what its clicks mean.
        h.tabs = s.tabs;
        var pbuf: [64]u8 = undefined;
        const project: ?[]const u8 = if (s.project()) |pj| blk: {
            @memcpy(pbuf[0..pj.len], pj);
            break :blk pbuf[0..pj.len];
        } else null;
        const trust: ?[]const u8 = if (s.last_error) |err| (if (client_mod.isTrustError(err)) client_mod.describe(err) else null) else null;
        h.sync.mutex.lockUncancelable(h.client.io);
        defer h.sync.mutex.unlock(h.client.io);
        const panel = h.sync.ui.panel(&h.sync_bufs);
        // Status panels: copies, so the shell's panel text stays valid while
        // the network thread replaces Shared's.
        h.activity = s.activity;
        if (s.has_sys) h.sys = s.sys;
        h.projects = s.projects;
        const qk = h.convo_view.questionKeys();
        const now_unix = std.Io.Timestamp.now(h.client.io, .real).toSeconds();
        const o = h.shell.overlay(.{
            .tabs = if (st == .connected) h.tabs.slice() else &.{},
            .current = s.current,
            .subs = if (st == .connected) h.subs.slice() else &.{},
            .sub_shown = s.sub_shown,
            .panel = panel,
            .activity = if (s.has_activity) &h.activity else null,
            .sys = if (s.has_sys) &h.sys else null,
            .projects = if (s.has_projects) &h.projects else null,
            .project_answer = s.project_answer,
            .project_answer_gen = s.project_answer_gen,
            .now = now_unix,
            .now_ms = watchdog.nowMs(h.client.io),
            .utc_offset_s = localtime.offsetAt(now_unix),
            .usage = if (s.has_usage) s.usage else null,
            .needs_desk = h.needs_desk[0..h.n_needs_desk],
            .viewer = .{
                .status = uiStatus(st),
                .mode = s.mode,
                .detail = detail,
                .host = h.client.host(),
                .has_grid = s.grid.cols > 0,
                .trust_error = trust,
                .exit_code = s.exit_code,
                .pin_fp = h.pin_fp_buf[0..h.pin_fp_len],
                .question_open = h.convo_view.newestOpenQuestion() != null,
                .question_digits = qk.digits,
                .question_card = qk.card,
            },
        });
        h.p.build(&s.grid, o);
        s.mutex.unlock(h.client.io);
        h.p.present();
        // The panels ignore input until they have really been on screen
        // for a moment (sync/ui.zig, "No accidental approvals").
        // (h.sync.mutex is still held here: the defer above.)
        if (panel != null) h.sync.ui.presented(watchdog.nowMs(h.client.io));
        // The same idea for swipe cards: their guard starts on screen.
        h.convo_view.presented(watchdog.nowMs(h.client.io));
        h.drawn_version = version;
        // The on-screen keyboard follows the input line (touch, no keyboard).
        if (h.shell.keyboard != h.keyboard_shown) {
            h.keyboard_shown = h.shell.keyboard;
            touchkbd.setVisible(h.p.nativeHandle(), h.keyboard_shown);
        }
        var tbuf: [160]u8 = undefined;
        const t = shell_mod.title(uiStatus(st), project, &tbuf);
        if (!std.mem.eql(u8, t, h.title_buf[0..h.title_len])) {
            @memcpy(h.title_buf[0..t.len], t);
            h.title_len = t.len;
            h.p.setTitle(t);
        }
    }

    fn liveRedraw(ctx: *anyopaque) void {
        const h: *Host = @ptrCast(@alignCast(ctx));
        h.frame();
    }

    // ------------------------------------------------ shell.Host: input

    fn self(ctx: *anyopaque) *Host {
        return @ptrCast(@alignCast(ctx));
    }

    fn uiHost(h: *Host) shell_mod.Host {
        return .{ .ctx = h, .vtable = &host_vtable };
    }

    const host_vtable: shell_mod.Host.VTable = .{
        .key = onKey,
        .char = onChar,
        .answer = onAnswer,
        .send = onSend,
        .command = onCommand,
        .shortcut = onShortcut,
    };

    /// A key at the terminal: a protocol frame if the desktop's input mode
    /// allows it (the server filters again).
    fn onKey(ctx: *anyopaque, k: ui.input.Key, m: ui.input.Mods) void {
        const h = self(ctx);
        var buf: [16]u8 = undefined;
        if (keys.keyFrameAt(h.shell.mode, h.shell.waiting, k, m, &buf)) |f| _ = h.client.sendInput(f);
    }

    fn onChar(ctx: *anyopaque, cp: u21, m: ui.input.Mods) void {
        const h = self(ctx);
        var buf: [8]u8 = undefined;
        if (keys.charFrame(h.shell.mode, cp, m, &buf)) |f| _ = h.client.sendInput(f);
    }

    fn onAnswer(ctx: *anyopaque, key: []const u8) void {
        const h = self(ctx);
        var buf: [16]u8 = undefined;
        if (keys.answerFrameAt(h.shell.mode, h.shell.waiting, key, &buf)) |f| _ = h.client.sendInput(f);
    }

    /// The instruction line's frames go out on the connection.
    fn onSend(ctx: *anyopaque, f: []const u8) bool {
        return self(ctx).client.sendInput(f);
    }

    fn onCommand(ctx: *anyopaque, c: shell_mod.Command) void {
        const h = self(ctx);
        switch (c) {
            .select_tab => |i| if (i < h.tabs.len) h.client.selectTab(h.tabs.items[i].id),
            .select_sub => |i| if (i) |j| {
                if (j < h.subs.len) h.client.showSub(h.subs.items[j].id);
            } else h.client.showSub(null),
            // A device opens and closes no tabs, has no selection yet, and
            // the remote grid size is the server's (the view scales to fit).
            .close_tab, .open_tab, .copy, .paste, .button, .resized => {},
            // Slash commands are never sent from a device (the panel offers
            // no such button; this is the second fence).
            .usage_slash => {},
            // The System panel: the desktop samples only while one is open.
            .system_panel => |on| h.client.setSysPanel(on),
            // This device's hidden tabs: stored next to its settings.
            .hidden_changed => saveHidden(h),
        }
    }

    fn saveHidden(h: *Host) void {
        var buf: [ui.hidden_tabs.max_file]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        h.shell.hidden.write(&w) catch return;
        pin_mod.saveHiddenTabs(h.client.io, w.buffered()) catch |err| report("portal: could not store the hidden tabs: {t}", .{err});
    }

    /// Ctrl+Shift+K opens Packages (not over another panel).
    fn onShortcut(ctx: *anyopaque, cp: u21, m: ui.input.Mods, f: shell_mod.Focus) bool {
        if (f == .panel) return false;
        if (!(m.ctrl and m.shift and (cp == 'k' or cp == 'K'))) return false;
        const s = self(ctx).sync;
        s.mutex.lockUncancelable(s.io());
        s.ui.openPackages();
        s.mutex.unlock(s.io());
        s.redraw();
        return true;
    }
};

/// Runs the remote viewer until its window is closed, then exits the
/// process (the network thread cannot be joined). `args` excludes the
/// program/subcommand name; `prog` is used in messages ("portal connect").
/// Objects live for the life of the process and are never freed.
pub fn main(gpa: std.mem.Allocator, io: std.Io, prog: []const u8, args: []const []const u8) noreturn {
    var forget = false;
    var show_key = false;
    var code_arg: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--forget")) {
            forget = true;
        } else if (std.mem.eql(u8, a, "--key")) {
            show_key = true;
        } else if (std.mem.eql(u8, a, "--pairing-code")) {
            i += 1;
            if (i >= args.len) fatal(prog, "--pairing-code needs the code", .{});
            code_arg = args[i];
        } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            report(usage, .{prog});
            std.process.exit(0);
        } else {
            fatal(prog, "unknown argument '{s}'\n\n" ++ usage, .{ a, prog });
        }
    }

    // This device's WireGuard key: made on first use, kept in the OS
    // credential store, wiped from memory once the tunnel has it.
    var key = tunnel.keys.loadOrCreate(io) catch |err|
        fatal(prog, "cannot load or create this device's tunnel key in the OS credential store: {t}", .{err});
    const key_text = key.publicText();
    const key_check = key.checkCode();
    if (show_key) {
        key.wipe();
        report("{s}: this device's tunnel key: {s}  (check code {s})", .{ prog, &key_text, &key_check });
        std.process.exit(0);
    }

    if (forget) {
        const c = devicelink.load(io) orelse {
            key.wipe();
            const r = forgetDesktop(io, devicelink.server);
            var mb: [600]u8 = undefined;
            var w: std.Io.Writer = .fixed(&mb);
            r.describe(&w, devicelink.server) catch {};
            report("{s}: {s}", .{ prog, w.buffered() });
            std.process.exit(if (r.first_error == null) 0 else 1);
        };
        const r = forgetLinked(gpa, io, &c, &key);
        key.wipe();
        var mb: [600]u8 = undefined;
        var w: std.Io.Writer = .fixed(&mb);
        r.describe(&w, devicelink.server) catch {};
        report("{s}: {s}", .{ prog, w.buffered() });
        std.process.exit(if (r.first_error == null) 0 else 1);
    }

    // The window comes first: a first run is answered inside it.
    const tv = Presenter.init(gpa, io, .{ .title = "Portal" }) catch |err| {
        // No monospace font: say which files were tried (on iOS the
        // system font paths are found at run time and may differ).
        if (err == error.NoMonospaceFont)
            fatal(prog, "cannot open the window: no monospace font (tried: {s})", .{view.font.fontset.triedPaths()});
        fatal(prog, "cannot open the window: {t}", .{err});
    };
    // The hero art while connecting (Presenter.beginSplash: ends once
    // connected or the user is needed, at any input, or after a few seconds).
    tv.beginSplash(view.hero_png);

    // The pairing code: given, saved earlier, or asked for in the window.
    const code = gpa.create(devicelink.Code) catch fatal(prog, "out of memory", .{});
    var newly_paired = false;
    if (code_arg) |t| {
        code.* = devicelink.parse(t) catch |err| fatal(prog, "{s}", .{devicelink.describe(err)});
        newly_paired = true;
    } else if (devicelink.load(io)) |c| {
        code.* = c;
    } else {
        var st = setup_mod.Setup.init(key_text, key_check);
        st.scan_offered = platform.scan_qr != null;
        while (true) {
            switch (runSetup(tv, &st)) {
                .closed => std.process.exit(0),
                .submit => {
                    const c = devicelink.parse(st.code.text()) catch |err| {
                        st.setNote("{s}", .{devicelink.describe(err)});
                        continue;
                    };
                    st.askConfirm(c.deskCheck());
                },
                .confirmed => {
                    code.* = devicelink.parse(st.code.text()) catch |err| {
                        st.setNote("{s}", .{devicelink.describe(err)});
                        continue;
                    };
                    newly_paired = true;
                    break;
                },
            }
        }
    }
    if (newly_paired) devicelink.save(io, code) catch |err|
        std.debug.print("portal connect: could not save the pairing code ({t}); it is asked for again next time\n", .{err});

    const tun = devicelink.startTunnel(gpa, io, code, &key) catch |err|
        fatal(prog, "cannot start this device's tunnel: {t}", .{err});
    key.wipe();
    const ca_buf = gpa.create([x509check.max_cert_len]u8) catch fatal(prog, "out of memory", .{});
    const trust = devicelink.trust(io, code, ca_buf);

    const shared = gpa.create(client_mod.Shared) catch fatal(prog, "out of memory", .{});
    shared.* = .{};
    const client = gpa.create(client_mod.Client) catch fatal(prog, "out of memory", .{});
    client.* = client_mod.Client.init(gpa, io, shared, devicelink.server, tun.dialer(), trust) catch
        fatal(prog, "bad desktop address", .{});
    const io_ptr = gpa.create(std.Io) catch fatal(prog, "out of memory", .{});
    io_ptr.* = io;
    client.on_pinned = devicelink.savePin;
    client.on_pinned_ctx = io_ptr;
    // First connection with this code: the sync worker pins the desktop's
    // release key once the CA is pinned (and offers voice packages).
    if (trust == .fingerprint) shared.just_paired.store(true, .release);

    const host_ui = gpa.create(Host) catch fatal(prog, "out of memory", .{});
    const sync_state = gpa.create(SyncState) catch fatal(prog, "out of memory", .{});
    sync_state.* = .{ .client = client, .shared = shared, .code = code };
    host_ui.* = .{ .p = tv, .shared = shared, .client = client, .sync = sync_state };
    host_ui.shell = ui.Shell.init(gpa, .viewer, host_ui.uiHost());
    host_ui.shell.modal = sync_state.modal();
    host_ui.convo_view = ui.convoview.View.init(gpa);
    host_ui.convo_view.clock = .{ .ctx = host_ui, .now = Host.clockNow };
    host_ui.fy_panel = ui.foryou.Panel.init(gpa);
    host_ui.fy_panel.sender = .{ .ctx = client, .send = Host.fySend };
    host_ui.convo_view.foryou = &host_ui.fy_panel;
    {
        var sbuf: [4096]u8 = undefined;
        const text = pin_mod.loadDeviceSettings(io, &sbuf);
        if (ui.convoview.parseSwipeSetting(text)) |side| host_ui.convo_view.yes_side = side;
        // `background_art = off` hides the faint hero art (on by default).
        if (ui.convoview.parseOnOffSetting(text, "background_art")) |on| tv.setBackgroundArt(on);
        // The tabs this device hides (ui/hidden_tabs.zig).
        var hbuf: [ui.hidden_tabs.max_file]u8 = undefined;
        host_ui.shell.hidden = ui.hidden_tabs.List.parse(pin_mod.loadHiddenTabs(io, &hbuf));
    }
    host_ui.shell.conversation = host_ui.convo_view.contentView();
    // Portal sync (docs/sync-design.md): a worker that runs a pass on
    // every (re)connect and {"t":"updates"}; only over TLS, where the
    // release key was pinned at pairing.
    if (platform.sync) {
        if (std.Thread.spawn(.{}, SyncState.run, .{sync_state})) |t| t.detach() else |_| {}
    }
    host_ui.pin_fp_len = x509check.formatFingerprint(code.ca_sha256, &host_ui.pin_fp_buf).len;
    tv.setLiveRedraw(host_ui, Host.liveRedraw);
    shared.wake_ctx = tv;
    shared.wake_fn = struct {
        fn f(ctx: *anyopaque) void {
            const v: *Presenter = @ptrCast(@alignCast(ctx));
            v.wake();
        }
    }.f;

    // The network thread runs for the life of the process (its socket reads
    // cannot be cancelled portably); exiting the process ends it.
    const thread = std.Thread.spawn(.{}, client_mod.Client.run, .{client}) catch fatal(prog, "cannot start the network thread", .{});
    thread.detach();

    var gone_handled = false;
    var suspended = false;
    while (tv.pollEvents(host_ui.shell.sink())) {
        // Off screen (iOS background): no connection until the view is
        // back; the device glue may lock the UI meanwhile.
        if (tv.isSuspended() != suspended) {
            suspended = tv.isSuspended();
            client.setPaused(suspended);
            if (if (suspended) platform.on_suspend else platform.on_resume) |f| f();
        }
        // The desktop no longer has this device: forget it here too (the
        // sync worker does it between operations; without TLS there is no
        // worker and no sync store, so here).
        if (!gone_handled and shared.desktop_gone.load(.acquire)) {
            gone_handled = true;
            if (platform.sync) {
                sync_state.forget_gone.store(true, .release);
                sync_state.pending.store(@backingInt(SyncState.Op.forget), .release);
                shared.sync_wake.set(io);
            } else {
                var r = forgetDesktop(io, client.host());
                r.remote = .gone_by_desktop;
                var w: std.Io.Writer = .fixed(&sync_state.dropped_msg_buf);
                r.describe(&w, client.host()) catch {};
                sync_state.dropped_msg_len = w.buffered().len;
                sync_state.dropped.store(true, .release);
            }
        }
        if (sync_state.dropped.load(.acquire)) {
            tv.deinit();
            report("{s}: {s}", .{ prog, sync_state.dropped_msg_buf[0..sync_state.dropped_msg_len] });
            std.process.exit(0);
        }
        const animating = host_ui.convo_view.frameTimeout();
        if (tv.needsRedraw() or shared.version.load(.acquire) != host_ui.drawn_version or animating != null) host_ui.frame();
        // Event-driven: the network thread wakes us on every Shared change
        // (Client.notify), input wakes us too; no idle polling. Only a
        // swipe card's fly-off / spring-back (at most ~200 ms) sets a
        // frame deadline.
        // The usage toast's end is the other deadline.
        const toast_ms = host_ui.shell.usageDeadline(watchdog.nowMs(io)) orelse Presenter.forever;
        tv.waitEvents(@min(host_ui.convo_view.frameTimeout() orelse Presenter.forever, toast_ms));
    }
    tv.deinit();
    std.process.exit(0);
}

/// The device side of Portal sync inside the viewer: a worker thread for
/// the passes and the panels' state (approval, voice offer, Packages).
///
/// The worker is the only thread that touches the store (this desktop's
/// own folder, keypin.desktopRoot). The UI thread never does: a Roll back,
/// Revoke or Forget is posted as `pending` (an atomic op code; its package
/// in `pending_pkg`, written under `mutex` before the op is published)
/// plus the worker's wake event, and the worker performs it between
/// operations: before a pass, or between two packages of one
/// (engine.Options.between). Forget waits for the pass to end.
const SyncState = struct {
    client: *client_mod.Client,
    shared: *client_mod.Shared,
    /// The pairing code this device connects with.
    code: *const devicelink.Code,
    mutex: std.Io.Mutex = .init,
    ui: sync.ui.Ui = .{},
    /// Worker only.
    store: ?sync.store.Store = null,
    store_key: sync.keypin.Key = undefined,
    root_buf: [pin_mod.max_path]u8 = undefined,
    seen: u64 = 0,
    legacy_noted: bool = false,
    /// A request from the UI thread (Op), 0 = none.
    pending: std.atomic.Value(u8) = .init(0),
    /// Guarded by `mutex`.
    pending_pkg: sync.ui.Pkg = .{},
    /// Set by the worker once Forget this desktop has run: the main loop
    /// tells the user and exits.
    dropped: std.atomic.Value(bool) = .init(false),
    dropped_msg_buf: [600]u8 = undefined,
    dropped_msg_len: usize = 0,
    /// The posted forget is because the desktop no longer has this device
    /// (Shared.desktop_gone): nothing to ask the desktop.
    forget_gone: std.atomic.Value(bool) = .init(false),

    const Op = enum(u8) { none = 0, rollback = 1, revoke = 2, forget = 3 };

    fn io(s: *const SyncState) std.Io {
        return s.client.io;
    }

    /// This desktop's store for `pinned` (worker only).
    fn openStore(s: *SyncState, pinned: sync.keypin.Key) ?*sync.store.Store {
        if (s.store != null and std.mem.eql(u8, &s.store_key, &pinned)) return &s.store.?;
        s.store = null;
        const root = sync.keypin.desktopRoot(s.client.host(), pinned, &s.root_buf) catch return null;
        s.store = sync.store.Store.open(s.client.gpa, s.io(), root, sync.manifest.fingerprint(pinned)) catch |err| {
            std.debug.print("portal connect: sync: cannot open {s}: {t}\n", .{ root, err });
            return null;
        };
        s.store_key = pinned;
        if (!s.legacy_noted) {
            // The shared store of earlier builds is never used: delete it.
            s.legacy_noted = true;
            const r = sync.keypin.removeLegacyStore(s.io()) catch sync.keypin.Dropped{};
            var rb: [pin_mod.max_path]u8 = undefined;
            const old = sync.keypin.syncRoot(&rb) catch "";
            if (r.removed > 0 or r.kept > 0)
                std.debug.print("portal connect: sync: removed the shared store of earlier versions in {s} ({d} removed, {d} still in use: retried on a later start)\n", .{ old, r.removed, r.kept });
            if (r.kept > 0) {
                s.mutex.lockUncancelable(s.io());
                s.ui.setNote("Some packages from before per-desktop folders (in {s}) are still in use; they are removed on a later start.", .{old});
                s.mutex.unlock(s.io());
            }
        }
        return &s.store.?;
    }

    fn loadPin(s: *SyncState) ?sync.keypin.Key {
        return sync.keypin.load(s.io(), s.client.host()) catch null;
    }

    /// Event-driven: sleeps until the network thread bumps sync_gen (a
    /// stream connected, or the desktop said {"t":"updates"}), the user
    /// approved something, or the UI posted an action.
    fn run(s: *SyncState) void {
        while (!s.dropped.load(.acquire)) {
            s.shared.sync_wake.reset();
            if (s.pending.load(.acquire) != 0) {
                s.performPending(true);
                continue;
            }
            const gen = s.shared.sync_gen.load(.acquire);
            if (gen == s.seen) {
                // A long-lived thread, never canceled: nothing to re-arm.
                s.shared.sync_wake.wait(s.io()) catch {};
                continue;
            }
            s.seen = gen;
            s.pass();
        }
    }

    fn redraw(s: *SyncState) void {
        _ = s.shared.version.fetchAdd(1, .release);
        if (s.shared.wake_fn) |f| f(s.shared.wake_ctx.?);
    }

    fn pass(s: *SyncState) void {
        const host = s.client.host();
        // Right after pairing: pin the desktop's release key, over the
        // tunnel and the CA the first connection pinned.
        if (s.shared.just_paired.load(.acquire)) {
            if (s.client.pinReleaseKey()) |_| {} else |err| {
                std.debug.print("portal connect: no release key pinned ({t}); sync stays off until this device is paired again\n", .{err});
            }
        }
        const pinned = s.loadPin() orelse {
            s.mutex.lockUncancelable(s.io());
            s.ui.setNote("Sync is off for {s}: pair this device again to pin the desktop's release key.", .{host});
            s.mutex.unlock(s.io());
            return;
        };
        const st = s.openStore(pinned) orelse return;
        var approvals: [sync.ui.max_marks]sync.engine.Approval = undefined;
        var marks: [sync.ui.max_marks]sync.ui.Mark = undefined;
        var opts: sync.engine.Options = .{ .client_version = client_version, .between = .{ .ctx = s, .f = between } };
        s.mutex.lockUncancelable(s.io());
        if (s.shared.just_paired.swap(false, .acq_rel)) s.ui.startVoiceOffer();
        s.ui.setDesktop(host, pinned);
        const n_marks = s.ui.n_approved;
        @memcpy(marks[0..n_marks], s.ui.approved[0..n_marks]);
        opts.approved = sync.ui.approvalsFrom(marks[0..n_marks], &approvals);
        opts.hold = s.ui.holdList();
        s.mutex.unlock(s.io());
        const rep = s.client.gpa.create(sync.engine.Report) catch return;
        defer s.client.gpa.destroy(rep);
        rep.* = .{};
        const rem = s.client.syncRemote();
        sync.engine.run(&rem, st, pinned, opts, rep, .{ .f = logLine }) catch |err| {
            std.debug.print("portal connect: sync: {s}\n", .{sync.engine.describe(err)});
            return;
        };
        s.mutex.lockUncancelable(s.io());
        s.ui.setReport(rep);
        s.mutex.unlock(s.io());
        s.refreshRows(st);
    }

    /// Between two packages of a pass: a posted rollback / revoke runs now
    /// (Forget waits for the pass to finish).
    fn between(ctx: *anyopaque) void {
        const s: *SyncState = @ptrCast(@alignCast(ctx));
        if (s.pending.load(.acquire) != 0) s.performPending(false);
    }

    fn logLine(_: ?*anyopaque, line: []const u8) void {
        std.debug.print("portal connect: sync: {s}\n", .{line});
    }

    /// Re-reads the installed list from the store (worker only).
    fn refreshRows(s: *SyncState, st: *sync.store.Store) void {
        var rows: [32]sync.ui.Installed = undefined;
        const n = installedRows(st, &rows);
        s.mutex.lockUncancelable(s.io());
        s.ui.setInstalled(rows[0..n]);
        s.mutex.unlock(s.io());
        s.redraw();
    }

    fn installedRows(st: *sync.store.Store, rows: []sync.ui.Installed) usize {
        var ids: [32][sync.manifest.max_package_id]u8 = undefined;
        var lens: [32]u8 = undefined;
        const n = st.installedPackages(&ids, &lens) catch return 0;
        var k: usize = 0;
        for (0..@min(n, rows.len)) |i| {
            const id = ids[i][0..lens[i]];
            const cur = (st.current(id) catch continue) orelse continue;
            const prev = st.previous(id) catch null;
            // Unknown kind: treat it as a program (Revoke, the safe offer).
            const kind = st.kindOf(id, cur.version()) catch .executable;
            rows[k] = sync.ui.Installed.init(id, cur.version(), if (prev) |p| p.version() else null, kind);
            k += 1;
        }
        return k;
    }

    /// Runs the UI's posted action (worker only).
    fn performPending(s: *SyncState, allow_forget: bool) void {
        s.mutex.lockUncancelable(s.io());
        const raw = s.pending.load(.acquire);
        if (raw == @backingInt(Op.forget) and !allow_forget) {
            s.mutex.unlock(s.io());
            return;
        }
        _ = s.pending.swap(0, .acq_rel);
        const pkg = s.pending_pkg;
        s.mutex.unlock(s.io());
        const op: Op = if (raw <= 3) @fromBackingInt(@intCast(raw)) else return;
        switch (op) {
            .none => return,
            .forget => {
                const host = s.client.host();
                var r: Forgotten = undefined;
                if (s.forget_gone.load(.acquire)) {
                    r = forgetDesktop(s.io(), host);
                    r.remote = .gone_by_desktop;
                } else {
                    r = forgetBothWays(s.client);
                }
                s.store = null;
                var w: std.Io.Writer = .fixed(&s.dropped_msg_buf);
                r.describe(&w, host) catch {};
                s.dropped_msg_len = w.buffered().len;
                s.dropped.store(true, .release);
                s.redraw();
                return;
            },
            .rollback, .revoke => {},
        }
        const pinned = s.loadPin() orelse return;
        const st = s.openStore(pinned) orelse return;
        const name = pkg.slice();
        var nb: [200]u8 = undefined;
        const note: []const u8 = switch (op) {
            .rollback => if (st.rollback(name)) |p|
                std.fmt.bufPrint(&nb, "{s} rolled back to {s}.", .{ name, p.version() }) catch ""
            else |err|
                std.fmt.bufPrint(&nb, "Roll back of {s} failed: {s}.", .{ name, sync.engine.describe(err) }) catch "",
            .revoke => if (st.revoke(name)) |r| blk: {
                const kept = if (r.pruned.in_use > 0) " (its folder stays until it stops running)" else "";
                break :blk if (r.now) |p|
                    std.fmt.bufPrint(&nb, "Approval revoked: {s} is back at {s}{s}.", .{ name, p.version(), kept }) catch ""
                else
                    std.fmt.bufPrint(&nb, "Approval revoked: {s} is uninstalled{s}.", .{ name, kept }) catch "";
            } else |err| std.fmt.bufPrint(&nb, "Revoke of {s} failed: {s}.", .{ name, sync.engine.describe(err) }) catch "",
            else => "",
        };
        std.debug.print("portal connect: sync: {s}\n", .{note});
        s.mutex.lockUncancelable(s.io());
        s.ui.setNote("{s}", .{note});
        s.mutex.unlock(s.io());
        s.refreshRows(st);
    }

    /// UI thread: hands an action to the worker (never touches the store).
    fn perform(s: *SyncState, a: sync.ui.Action) void {
        const op: Op, const pkg: sync.ui.Pkg = switch (a) {
            .none => return,
            .rerun => {
                _ = s.shared.sync_gen.fetchAdd(1, .release);
                s.shared.sync_wake.set(s.io());
                s.redraw();
                return;
            },
            .rollback => |p| .{ .rollback, p },
            .revoke => |p| .{ .revoke, p },
            .forget_desktop => .{ .forget, .{} },
        };
        s.mutex.lockUncancelable(s.io());
        if (s.pending.load(.acquire) != 0) {
            s.ui.setNote("Still busy with the last request; try again in a moment.", .{});
        } else {
            s.pending_pkg = pkg;
            s.pending.store(@backingInt(op), .release);
            switch (op) {
                .rollback => s.ui.setNote("Rolling back {s}...", .{pkg.slice()}),
                .revoke => s.ui.setNote("Revoking {s}...", .{pkg.slice()}),
                .forget => s.ui.setNote("Forgetting this desktop...", .{}),
                .none => {},
            }
        }
        s.mutex.unlock(s.io());
        s.shared.sync_wake.set(s.io());
        s.redraw();
    }

    /// The sync panels as the shell's modal layer.
    fn modal(s: *SyncState) shell_mod.Modal {
        return .{ .ctx = s, .active = active, .key = key, .char = char, .button = button };
    }
    fn self(p: *anyopaque) *SyncState {
        return @ptrCast(@alignCast(p));
    }
    fn now(s: *const SyncState) i64 {
        return watchdog.nowMs(s.io());
    }
    fn active(p: *anyopaque) bool {
        const s = self(p);
        s.mutex.lockUncancelable(s.io());
        defer s.mutex.unlock(s.io());
        return s.ui.open();
    }
    fn key(p: *anyopaque, k: ui.input.Key, m: ui.input.Mods) void {
        const s = self(p);
        const t = s.now();
        s.mutex.lockUncancelable(s.io());
        const a = s.ui.key(k, m, t);
        s.mutex.unlock(s.io());
        s.perform(a);
        s.redraw(); // focus moves
    }
    /// Characters never act on the panels (no letter shortcuts): while
    /// one is open they are swallowed, so they can't reach the terminal
    /// either.
    fn char(_: *anyopaque, _: u21, _: ui.input.Mods) void {}
    fn button(p: *anyopaque, b: u32) void {
        const s = self(p);
        const t = s.now();
        s.mutex.lockUncancelable(s.io());
        const a = s.ui.button(b, t);
        s.mutex.unlock(s.io());
        s.perform(a);
        s.redraw();
    }
};

/// What forgetting a desktop removed.
pub const Forgotten = struct {
    first_error: ?anyerror = null,
    folders: sync.keypin.Dropped = .{},
    /// What the desktop's side of the forget did.
    remote: Remote = .not_asked,

    pub const Remote = enum {
        not_asked,
        /// It removed this device ("f:" on the interactive WebSocket).
        forgotten,
        /// It could not be reached: it lists the device until it next
        /// sees it or the owner unpairs it there.
        unreachable_desktop,
        /// The desktop itself said it no longer has this device (it was
        /// unpaired at the desk, or forgotten): forgotten here in turn.
        gone_by_desktop,
    };

    pub fn describe(r: *const Forgotten, w: *std.Io.Writer, host: []const u8) !void {
        if (r.remote == .gone_by_desktop)
            try w.print("{s} no longer has this device paired (it was unpaired at the desk, or forgotten), so this device forgot it too. ", .{host});
        try w.print("Forgot {s}: its pairing code, certificate pin, release-key pin and its sync folder", .{host});
        if (r.folders.kept > 0) try w.print(" (except {d} folder(s) still in use: close the programs running from them, then delete them)", .{r.folders.kept});
        try w.writeAll(".");
        if (r.first_error) |e| try w.print(" Some items could not be removed: {t}.", .{e});
        switch (r.remote) {
            .forgotten => try w.writeAll(" The desktop removed this device too."),
            .gone_by_desktop => try w.writeAll(" The desktop no longer lists this device."),
            .unreachable_desktop, .not_asked => try w.writeAll(" The desktop could not be told: it still lists this device until you unpair it there."),
        }
    }
};

/// Forget this desktop, both ways: first asks the desktop to remove this
/// device (Client.forgetOnDesktop), then forgets it here whatever the
/// answer (an unreachable desktop is reported, not waited for).
pub fn forgetBothWays(c: *client_mod.Client) Forgotten {
    const told: Forgotten.Remote = switch (c.forgetOnDesktop()) {
        .forgotten => .forgotten,
        .unreachable_desktop => .unreachable_desktop,
    };
    var r = forgetDesktop(c.io, c.host());
    r.remote = told;
    return r;
}

/// `connect --forget` / `sync-device --forget`: brings the tunnel up with
/// the saved pairing code to tell the desktop, then forgets it here.
pub fn forgetLinked(gpa: std.mem.Allocator, io: std.Io, code: *const devicelink.Code, key: *const tunnel.keys.KeyPair) Forgotten {
    const tun = devicelink.startTunnel(gpa, io, code, key) catch {
        var r = forgetDesktop(io, devicelink.server);
        r.remote = .unreachable_desktop;
        return r;
    };
    defer tun.destroy();
    var ca_buf: [x509check.max_cert_len]u8 = undefined;
    var shared: client_mod.Shared = .{};
    var c = client_mod.Client.init(gpa, io, &shared, devicelink.server, tun.dialer(), devicelink.trust(io, code, &ca_buf)) catch {
        var r = forgetDesktop(io, devicelink.server);
        r.remote = .unreachable_desktop;
        return r;
    };
    c.quiet = true;
    return forgetBothWays(&c);
}

/// Forgets the paired desktop on this device: its pairing code, the
/// pinned CA, the pinned release key and every sync folder of it. This
/// device's own tunnel key stays (it is the device's identity, for the
/// next pairing). Shared by `connect --forget`, Forget this desktop
/// (Packages) and `portalctl sync-device --forget`.
pub fn forgetDesktop(io: std.Io, host: []const u8) Forgotten {
    var r: Forgotten = .{};
    devicelink.delete(io) catch |err| {
        r.first_error = err;
    };
    if (pin_mod.Pin.forHost(host)) |p| p.delete(io) catch |err| {
        if (r.first_error == null) r.first_error = err;
    } else |_| {}
    sync.keypin.delete(io, host) catch |err| {
        if (r.first_error == null) r.first_error = err;
    };
    r.folders = sync.keypin.deleteDesktopFolders(io, host) catch |err| blk: {
        if (r.first_error == null) r.first_error = err;
        break :blk .{};
    };
    return r;
}

/// The version manifests' min-client is compared with (Portal's version).
pub const client_version = "0.1.0";

const SetupResult = enum { closed, submit, confirmed };

/// The first-run screen's event loop (event-driven), until the user
/// submits a code, confirms one, or closes the window.
fn runSetup(tv: *Presenter, st: *setup_mod.Setup) SetupResult {
    const Ctx = struct {
        st: *setup_mod.Setup,
        tv: *Presenter,
        result: ?SetupResult = null,

        fn on(c: *@This(), e: setup_mod.Event) void {
            switch (e) {
                .none => {},
                .submit => c.result = .submit,
                .confirmed => c.result = .confirmed,
                .scan => if (platform.scan_qr) |f| f(),
                .paste => {
                    const raw = c.tv.window.clipboardText(std.heap.page_allocator, 4096) orelse return;
                    defer std.heap.page_allocator.free(raw);
                    c.st.paste(raw);
                },
            }
        }
        fn self(p: *anyopaque) *@This() {
            return @ptrCast(@alignCast(p));
        }
        fn key(p: *anyopaque, k: ui.input.Key, m: ui.input.Mods) void {
            self(p).on(self(p).st.key(k, m));
        }
        fn char(p: *anyopaque, cp: u21, m: ui.input.Mods) void {
            self(p).on(self(p).st.char(cp, m));
        }
        fn answer(_: *anyopaque, _: []const u8) void {}
        fn button(p: *anyopaque, b: u32) void {
            self(p).on(self(p).st.button(b));
        }
        fn resized(_: *anyopaque, _: u32, _: u32, _: u16, _: u16) void {}
        const vt: ui.input.InputSink.VTable = .{ .key = key, .char = char, .answer = answer, .button = button, .resized = resized };
    };
    var ctx: Ctx = .{ .st = st, .tv = tv };
    const sink: ui.input.InputSink = .{ .ctx = &ctx, .vtable = &Ctx.vt };
    tv.endSplash(); // the first-run screen needs answers
    tv.setTitle("Portal - connect");
    const empty: ui.grid.Grid = .{};
    var bufs: setup_mod.Setup.Bufs = .{};
    while (true) {
        if (!tv.pollEvents(sink)) return .closed;
        if (platform.take_scanned) |take| {
            var qbuf: [512]u8 = undefined;
            // A scan fills the code and checks it at once.
            if (take(&qbuf)) |text| {
                st.fromQr(text);
                return .submit;
            }
        }
        if (platform.take_scan_note) |take| {
            var nbuf: [256]u8 = undefined;
            if (take(&nbuf)) |note| st.setNote("{s}", .{note});
        }
        if (ctx.result) |r| return r;
        tv.build(&empty, shell_mod.standby(null, "not connected", "", st.panel(&bufs)));
        tv.present();
        tv.waitEvents(Presenter.forever);
    }
}

test {
    _ = @import("tests.zig");
    _ = tunnel;
    _ = devicelink;
}
