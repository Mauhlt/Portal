//! The remote viewer: `portal connect` (in the Portal window's executable,
//! a GUI program with no console) and the standalone `portal-client` both
//! run `main` below. Module "client" in Portal's root build; imports only
//! std and "view".
//!
//!   connect                                             the last server, or
//!                                                       the first-run screen
//!   connect --server 10.8.0.1:8420 --ca portal-ca.pem   pin the CA, connect
//!   connect --server 10.8.0.1:8420                      connect (CA pinned)
//!   connect --server ADDR --forget     forget that desktop: credential, pins,
//!                                      its sync folder
//!
//! Everything happens in the window: with no server or no trusted CA yet,
//! a first-run screen (setup.zig) asks for the address and the certificate
//! (file, or the SHA-256 for the pairing-time download), then pairs. Errors
//! that end the program go to `report_fn` (a message box in portal.exe) as
//! well as stderr.
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
const setup_mod = @import("setup.zig");
/// Portal sync (device side, and the manifest format the desktop shares).
pub const sync = @import("sync/root.zig");
/// The input line and the Data slice, shared with the desk's window.
pub const inputline = @import("inputline.zig");
pub const dataview = @import("dataview.zig");
// For portalctl's headless sync-device (src/sync_cli.zig).
pub const net_client = client_mod;
pub const net_http = http;
pub const net_ws = @import("shared").ws;
pub const tlsconn = @import("net/tlsconn.zig");
pub const watchdog = @import("net/watchdog.zig");
pub const credstore_mod = credstore;
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
};
pub var platform: Platform = .{};

const usage =
    \\usage: {s} [--server IP:PORT] [--ca FILE | --ca-sha256 HEX] [--forget]
    \\
    \\  --server IP:PORT   Portal server address inside the WireGuard tunnel,
    \\                     e.g. 10.8.0.1:8420 (literal IP, no host names).
    \\                     Default: the last server; on first use the window
    \\                     asks for it.
    \\  --ca FILE          trust the Portal CA in FILE (portal-ca.pem or
    \\                     portal-ca.cer, from Export certificate in the
    \\                     Portal window or `portalctl ca export`) for this
    \\                     server, and remember it
    \\  --ca-sha256 HEX    the CA fingerprint the desk shows. With --ca: the
    \\                     file must match it. Alone: download the CA from the
    \\                     desktop while a pairing window is open
    \\                     (http://IP:PORT+1/ca.cer), check it against HEX,
    \\                     and remember it
    \\  --forget           forget this server: delete this device's stored
    \\                     credentials, the remembered CA and release key,
    \\                     and its sync folder (packages), and exit
    \\  --insecure-plain-http
    \\                     talk plain HTTP to a server run with --no-tls
    \\                     (tests only: keystrokes and credentials are not
    \\                     encrypted; uses its own credential, never the
    \\                     HTTPS one)
    \\
    \\First run: open Pair a device in the Portal window on the desktop, then
    \\click Pair here. Later runs need nothing.
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
    tv: *TermView,
    shared: *client_mod.Shared,
    client: *client_mod.Client,
    sink: remote.RemoteSink,
    drawn_version: u64 = std.math.maxInt(u64),
    /// The last {"t":"rejected"} handed to the instruction line.
    seen_rejected: u64 = 0,
    title_status: ?client_mod.Status = null,
    bufs: remote.Bufs = .{},
    pin_fp_buf: [95]u8 = undefined,
    pin_fp_len: usize = 0,
    sync: *SyncState,
    sync_bufs: sync.ui.Ui.Bufs = .{},

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
        if (s.rejected_gen != h.seen_rejected) {
            h.seen_rejected = s.rejected_gen;
            h.sink.rejected(s.rejected_buf[0..s.rejected_len]);
        }
        // The Data slice: new blobs from the terminal.
        _ = h.sink.data.sync(h.client.gpa, &s.grid.images);
        const o = remote.overlay(.{
            .status = st,
            .mode = mode,
            .detail = detail,
            .line = h.sink.line.snapshot(),
            .data = h.sink.data.slice(remote.data_toggle_id, remote.data_clear_id),
            .host = h.client.host(),
            .has_grid = s.grid.cols > 0,
            .code = s.pair_code,
            .err = s.last_error,
            .pin_fp = h.pin_fp_buf[0..h.pin_fp_len],
            .exit_code = s.exit_code,
        }, &h.bufs);
        var oo = o;
        h.sync.mutex.lockUncancelable(h.client.io);
        defer h.sync.mutex.unlock(h.client.io);
        if (h.sync.ui.panel(&h.sync_bufs)) |p| oo.panel = p;
        const panel_shown = oo.panel != null;
        h.tv.build(&s.grid, oo);
        s.mutex.unlock(h.client.io);
        h.tv.present();
        // The panels ignore input until they have really been on screen
        // for a moment (sync/ui.zig, "No accidental approvals").
        // (h.sync.mutex is still held here: the defer above.)
        if (panel_shown) h.sync.ui.presented(watchdog.nowMs(h.client.io));
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
            report(usage, .{prog});
            std.process.exit(0);
        } else {
            fatal(prog, "unknown argument '{s}'\n\n" ++ usage, .{ a, prog });
        }
    }
    var last_buf: [64]u8 = undefined;
    if (server == null) server = pin_mod.loadLastServer(io, &last_buf);

    if (forget) {
        const s = server orelse fatal(prog, "--forget needs --server IP:PORT", .{});
        var hb: [64]u8 = undefined;
        const host = http.canonicalHost(s, &hb) catch fatal(prog, "bad --server '{s}' (want a literal IP:PORT such as 10.8.0.1:8420)", .{s});
        const r = forgetHost(gpa, io, host, null);
        var mb: [600]u8 = undefined;
        var w: std.Io.Writer = .fixed(&mb);
        r.describe(&w, host) catch {};
        report("{s}: {s}", .{ prog, w.buffered() });
        std.process.exit(if (r.first_error == null) 0 else 1);
    }
    if (insecure) {
        if (ca_file != null or ca_sha256 != null) fatal(prog, "--insecure-plain-http cannot be combined with --ca / --ca-sha256", .{});
        if (server == null) fatal(prog, "--insecure-plain-http needs --server IP:PORT", .{});
        std.debug.print(insecure_warning, .{});
    }

    // The window comes first: a first run, or a server that can't be
    // trusted yet, is answered inside it.
    const tv = TermView.init(gpa, io, .{ .title = "Portal" }) catch |err| fatal(prog, "cannot open the window: {t}", .{err});

    const ca_buf = gpa.create([x509check.max_cert_len]u8) catch fatal(prog, "out of memory", .{});
    const host_store = gpa.create([64]u8) catch fatal(prog, "out of memory", .{});
    var server_text: []const u8 = server orelse "";
    var transport: client_mod.Transport = .insecure_plain_http;
    var pair_now = false;
    if (!insecure) {
        var why_buf: [600]u8 = undefined;
        var why: ?[]const u8 = null;
        // Try what the command line (or the last run) gave, without asking.
        if (server) |s| {
            const want_pin = ca_file != null or ca_sha256 != null or hasPin(io, s);
            if (want_pin) {
                switch (pinnedCa(gpa, io, s, ca_file, ca_sha256, ca_buf, &why_buf)) {
                    .ok => |der| transport = .{ .tls = der },
                    .problem => |m| why = m,
                }
            } else why = "";
        } else why = "";
        if (why) |first_note| {
            // First-run screen.
            var cert_prefill: []const u8 = ca_file orelse ca_sha256 orelse "";
            var dbuf: [pin_mod.max_path]u8 = undefined;
            if (cert_prefill.len == 0) if (pin_mod.defaultCaFile(&dbuf)) |p| {
                if (std.Io.Dir.cwd().statFile(io, p, .{})) |_| cert_prefill = p else |_| {}
            };
            var st = setup_mod.Setup.init(server orelse "", cert_prefill);
            st.scan_offered = platform.scan_qr != null;
            if (first_note.len > 0) st.setNote("{s}", .{first_note});
            while (true) {
                if (!runSetup(tv, &st)) std.process.exit(0); // window closed
                const s_in = std.mem.trim(u8, st.server.text(), " ");
                var hb: [64]u8 = undefined;
                _ = http.canonicalHost(s_in, &hb) catch {
                    st.setNote("Enter the desktop's address as a literal IP:PORT, e.g. 10.8.0.1:8420.", .{});
                    continue;
                };
                const cert = setup_mod.classify(st.cert.text());
                const file: ?[]const u8 = if (cert == .file) cert.file else null;
                const sha: ?[]const u8 = if (cert == .sha256) cert.sha256 else null;
                if (cert == .pinned and !hasPin(io, s_in)) {
                    st.setNote("Give the Portal certificate (portal-ca.pem from Export certificate at the desk) or the SHA-256 the desk shows.", .{});
                    continue;
                }
                switch (pinnedCa(gpa, io, s_in, file, sha, ca_buf, &why_buf)) {
                    .ok => |der| {
                        transport = .{ .tls = der };
                        @memcpy(host_store[0..s_in.len], s_in);
                        server_text = host_store[0..s_in.len];
                        pair_now = true;
                        break;
                    },
                    .problem => |m| st.setNote("{s}", .{m}),
                }
            }
        }
    }

    const shared = gpa.create(client_mod.Shared) catch fatal(prog, "out of memory", .{});
    shared.* = .{};
    const client = gpa.create(client_mod.Client) catch fatal(prog, "out of memory", .{});
    client.* = client_mod.Client.init(gpa, io, shared, server_text, transport) catch
        fatal(prog, "bad --server '{s}' (want a literal IP:PORT such as 10.8.0.1:8420)", .{server_text});
    pin_mod.saveLastServer(io, client.host()) catch {};

    const host_ui = gpa.create(Host) catch fatal(prog, "out of memory", .{});
    const sync_state = gpa.create(SyncState) catch fatal(prog, "out of memory", .{});
    sync_state.* = .{ .client = client, .shared = shared };
    host_ui.* = .{ .tv = tv, .shared = shared, .client = client, .sink = .{ .client = client, .modal = sync_state.modal() }, .sync = sync_state };
    // Portal sync (docs/sync-design.md): a worker that runs a pass on
    // every (re)connect and {"t":"updates"}; only over TLS, where the
    // release key was pinned at pairing.
    if (transport == .tls and platform.sync) {
        if (std.Thread.spawn(.{}, SyncState.run, .{sync_state})) |t| t.detach() else |_| {}
    }
    switch (transport) {
        .tls => |der| host_ui.pin_fp_len = x509check.formatFingerprint(x509check.fingerprint(der), &host_ui.pin_fp_buf).len,
        .insecure_plain_http => {},
    }
    tv.setLiveRedraw(host_ui, Host.liveRedraw);
    shared.wake_ctx = tv;
    shared.wake_fn = struct {
        fn f(ctx: *anyopaque) void {
            const v: *TermView = @ptrCast(@alignCast(ctx));
            v.wake();
        }
    }.f;
    // The first-run screen's Pair button: pair as soon as we know we must.
    if (pair_now) shared.pair_requested.store(true, .release);

    // The network thread runs for the life of the process (its socket reads
    // cannot be cancelled portably); exiting the process ends it.
    const thread = std.Thread.spawn(.{}, client_mod.Client.run, .{client}) catch fatal(prog, "cannot start the network thread", .{});
    thread.detach();

    var gone_handled = false;
    var suspended = false;
    while (tv.pollEvents(host_ui.sink.sink())) {
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
            if (transport == .tls) {
                sync_state.forget_gone.store(true, .release);
                sync_state.pending.store(@intFromEnum(SyncState.Op.forget), .release);
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
        if (tv.needsRedraw() or shared.version.load(.acquire) != host_ui.drawn_version) host_ui.frame();
        // Event-driven: the network thread wakes us on every Shared change
        // (Client.notify), input wakes us too; no idle polling.
        tv.waitEvents(TermView.forever);
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
        var session: ?client_mod.http_Cookie = null;
        s.shared.mutex.lockUncancelable(s.io());
        session = s.shared.session;
        s.shared.mutex.unlock(s.io());
        var sess = session orelse return;
        defer sess.wipe();
        const host = s.client.host();
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
        const rem = s.client.syncRemote(sess.value());
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
        if (raw == @intFromEnum(Op.forget) and !allow_forget) {
            s.mutex.unlock(s.io());
            return;
        }
        _ = s.pending.swap(0, .acq_rel);
        const pkg = s.pending_pkg;
        s.mutex.unlock(s.io());
        const op: Op = if (raw <= 3) @enumFromInt(raw) else return;
        switch (op) {
            .none => return,
            .forget => {
                const host = s.client.host();
                var r: Forgotten = undefined;
                if (s.forget_gone.load(.acquire)) {
                    r = forgetDesktop(s.io(), host);
                    r.remote = .gone_by_desktop;
                } else {
                    var session: ?client_mod.http_Cookie = null;
                    s.shared.mutex.lockUncancelable(s.io());
                    session = s.shared.session;
                    s.shared.mutex.unlock(s.io());
                    defer if (session) |*x| x.wipe();
                    r = forgetBothWays(s.client, if (session) |*x| x else null);
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
            s.pending.store(@intFromEnum(op), .release);
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

    fn modal(s: *SyncState) remote.RemoteSink.Modal {
        return .{ .ctx = s, .active = active, .key = key, .char = char, .button = button, .shortcut = shortcut };
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
    fn key(p: *anyopaque, k: view.input.Key, m: view.input.Mods) void {
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
    fn char(_: *anyopaque, _: u21, _: view.input.Mods) void {}
    fn button(p: *anyopaque, b: u32) bool {
        if (b < sync.ui.id.approve) return false;
        const s = self(p);
        const t = s.now();
        s.mutex.lockUncancelable(s.io());
        const a = s.ui.button(b, t);
        s.mutex.unlock(s.io());
        s.perform(a);
        s.redraw();
        return true;
    }
    /// Ctrl+Shift+K opens Packages.
    fn shortcut(p: *anyopaque, cp: u21, m: view.input.Mods) bool {
        if (!(m.ctrl and m.shift and (cp == 'k' or cp == 'K'))) return false;
        const s = self(p);
        s.mutex.lockUncancelable(s.io());
        s.ui.openPackages();
        s.mutex.unlock(s.io());
        s.redraw();
        return true;
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
        /// It removed this device (POST /device/forget).
        forgotten,
        /// It no longer had this device.
        already_gone,
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
        try w.print("Forgot {s}: its certificate pin, release-key pin, this device's credential and its sync folder", .{host});
        if (r.folders.kept > 0) try w.print(" (except {d} folder(s) still in use: close the programs running from them, then delete them)", .{r.folders.kept});
        try w.writeAll(".");
        if (r.first_error) |e| try w.print(" Some items could not be removed: {t}.", .{e});
        switch (r.remote) {
            .forgotten => try w.writeAll(" The desktop removed this device too."),
            .already_gone, .gone_by_desktop => try w.writeAll(" The desktop no longer lists this device."),
            .unreachable_desktop, .not_asked => try w.writeAll(" The desktop could not be told: it still lists this device until it next sees it (then it is told this device is gone) or you unpair it there."),
        }
    }
};

/// Forget this desktop, both ways: first asks the desktop to remove this
/// device (Client.forgetOnDesktop, with `session` or a fresh sign-in),
/// then forgets it here whatever the answer (an unreachable desktop is
/// reported, not waited for).
pub fn forgetBothWays(c: *client_mod.Client, session: ?*const http.Cookie) Forgotten {
    const told: Forgotten.Remote = switch (c.forgetOnDesktop(session)) {
        .forgotten => .forgotten,
        .already_gone => .already_gone,
        .unreachable_desktop => .unreachable_desktop,
    };
    var r = forgetDesktop(c.io, c.host());
    r.remote = told;
    return r;
}

/// `connect --forget` / `sync-device --forget`: connects with `ca_der`
/// (sync-device's --ca) or the pinned CA for `host` to tell the desktop,
/// then forgets it here. Without either the desktop can't be reached
/// securely: it is forgotten here only, and the result says so.
pub fn forgetHost(gpa: std.mem.Allocator, io: std.Io, host: []const u8, ca_der: ?[]const u8) Forgotten {
    var ca_buf: [x509check.max_cert_len]u8 = undefined;
    const der: ?[]const u8 = ca_der orelse blk: {
        const p = pin_mod.Pin.forHost(host) catch break :blk null;
        break :blk p.load(io, &ca_buf) catch null;
    };
    if (der) |d| {
        var shared: client_mod.Shared = .{};
        if (client_mod.Client.init(gpa, io, &shared, host, .{ .tls = d })) |cl| {
            var c = cl;
            c.quiet = true;
            return forgetBothWays(&c, null);
        } else |_| {}
    }
    var r = forgetDesktop(io, host);
    r.remote = .unreachable_desktop;
    return r;
}

/// Forgets a paired desktop on this device: both credentials (TLS and
/// plain), the pinned CA, the pinned release key, every sync folder of
/// that host, and the "last server" if it was this one. Shared by
/// `connect --forget`, Forget this desktop (Packages) and
/// `portalctl sync-device --forget`.
pub fn forgetDesktop(io: std.Io, host: []const u8) Forgotten {
    var r: Forgotten = .{};
    var tbuf: [credstore.max_target]u8 = undefined;
    for ([_]bool{ false, true }) |plain| {
        credstore.delete(credstore.targetName(host, plain, &tbuf)) catch |err| {
            if (r.first_error == null) r.first_error = err;
        };
    }
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
    var lb: [64]u8 = undefined;
    if (pin_mod.loadLastServer(io, &lb)) |last| if (std.mem.eql(u8, last, host)) {
        var pb: [pin_mod.max_path]u8 = undefined;
        if (pin_mod.lastServerPath(&pb)) |p| std.Io.Dir.cwd().deleteFile(io, p) catch {} else |_| {}
    };
    return r;
}

/// The version manifests' min-client is compared with (Portal's version).
pub const client_version = "0.1.0";

fn hasPin(io: std.Io, server: []const u8) bool {
    var hb: [64]u8 = undefined;
    const host = http.canonicalHost(server, &hb) catch return false;
    const p = pin_mod.Pin.forHost(host) catch return false;
    var probe: [x509check.max_cert_len]u8 = undefined;
    const got = p.load(io, &probe) catch return false;
    return got != null;
}

/// The first-run screen's event loop (event-driven). False if the window
/// was closed.
fn runSetup(tv: *TermView, st: *setup_mod.Setup) bool {
    const Ctx = struct {
        st: *setup_mod.Setup,
        tv: *TermView,
        submitted: bool = false,

        fn on(c: *@This(), e: setup_mod.Event) void {
            switch (e) {
                .none => {},
                .submit => c.submitted = true,
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
        fn key(p: *anyopaque, k: view.input.Key, m: view.input.Mods) void {
            self(p).on(self(p).st.key(k, m));
        }
        fn char(p: *anyopaque, cp: u21, m: view.input.Mods) void {
            self(p).on(self(p).st.char(cp, m));
        }
        fn answer(_: *anyopaque, _: []const u8) void {}
        fn button(p: *anyopaque, b: u32) void {
            self(p).on(self(p).st.button(b));
        }
        fn resized(_: *anyopaque, _: u32, _: u32, _: u16, _: u16) void {}
        const vt: view.input.InputSink.VTable = .{ .key = key, .char = char, .answer = answer, .button = button, .resized = resized };
    };
    var ctx: Ctx = .{ .st = st, .tv = tv };
    const sink: view.input.InputSink = .{ .ctx = &ctx, .vtable = &Ctx.vt };
    tv.setTitle("Portal - connect");
    const empty: view.grid.Grid = .{};
    var bufs: setup_mod.Setup.Bufs = .{};
    while (true) {
        if (!tv.pollEvents(sink)) return false;
        if (platform.take_scanned) |take| {
            var qbuf: [256]u8 = undefined;
            // A good scan fills the form and pairs at once.
            if (take(&qbuf)) |text| if (st.fromQr(text)) return true;
        }
        if (ctx.submitted) return true;
        tv.build(&empty, .{
            .status = .{ .tone = .warn, .label = "not connected" },
            .panel = st.panel(&bufs),
        });
        tv.present();
        tv.waitEvents(TermView.forever);
    }
}

const PinResult = union(enum) { ok: []const u8, problem: []const u8 };

/// The CA to trust for `server`: imported from `ca_file`, downloaded and
/// checked against `ca_sha256`, or the one pinned earlier. Never trusts a
/// server on first use: with none of these it is a problem to show.
fn pinnedCa(
    gpa: std.mem.Allocator,
    io: std.Io,
    server: []const u8,
    ca_file: ?[]const u8,
    ca_sha256: ?[]const u8,
    out: *[x509check.max_cert_len]u8,
    why_buf: []u8,
) PinResult {
    const P = struct {
        fn f(buf: []u8, comptime fmt: []const u8, args: anytype) PinResult {
            return .{ .problem = std.fmt.bufPrint(buf, fmt, args) catch "cannot use that certificate" };
        }
    };
    var hb: [64]u8 = undefined;
    const host = http.canonicalHost(server, &hb) catch
        return P.f(why_buf, "Bad server address '{s}' (want a literal IP:PORT such as 10.8.0.1:8420).", .{server});
    const p = pin_mod.Pin.forHost(host) catch |err|
        return P.f(why_buf, "No per-user config directory for the pinned CA ({t}).", .{err});
    const expected: ?[32]u8 = if (ca_sha256) |t| (x509check.parseFingerprint(t) catch
        return P.f(why_buf, "The SHA-256 must be the 64 hex digits the desk shows (AB:CD:...).", .{})) else null;

    var old_buf: [x509check.max_cert_len]u8 = undefined;
    const old: ?[]const u8 = p.load(io, &old_buf) catch |err| blk: {
        if (ca_file == null and ca_sha256 == null)
            return P.f(why_buf, "The CA pinned for {s} ({s}) is unreadable ({t}); give the certificate again.", .{ host, p.path(), err });
        break :blk null;
    };

    var der: []const u8 = undefined;
    var source: []const u8 = undefined;
    if (ca_file) |f| {
        der = pin_mod.readCaFile(io, f, out) catch |err|
            return P.f(why_buf, "Cannot use {s} as the Portal CA ({t}): give portal-ca.pem or portal-ca.cer from Export certificate at the desk.", .{ f, err });
        source = f;
    } else if (expected) |want| {
        if (old) |o| if (std.mem.eql(u8, &x509check.fingerprint(o), &want)) {
            @memcpy(out[0..o.len], o);
            return .{ .ok = out[0..o.len] };
        };
        der = client_mod.fetchCaCertificate(gpa, io, host, out) catch |err|
            return P.f(why_buf, "Could not download the CA from the desktop: {s}. Open Pair a device in the Portal window first (the download runs while pairing is open), or give the certificate file.", .{client_mod.describe(err)});
        source = "the download";
    } else if (old) |o| {
        @memcpy(out[0..o.len], o);
        return .{ .ok = out[0..o.len] };
    } else {
        return P.f(why_buf, "No Portal CA is trusted for {s} yet, so the server cannot be authenticated. Give the certificate file or its SHA-256.", .{host});
    }

    var fp_buf: [95]u8 = undefined;
    const fp = x509check.fingerprint(der);
    if (expected) |want| if (!std.mem.eql(u8, &fp, &want)) {
        return P.f(why_buf, "The CA from {s} has SHA-256 {s}, which is not the one given. Not trusted.", .{ source, x509check.formatFingerprint(fp, &fp_buf) });
    };
    // A Portal CA is self-signed; this catches passing the server
    // certificate or some unrelated file by mistake.
    const parsed = x509check.parse(der) catch return P.f(why_buf, "{s} is not a usable CA certificate.", .{source});
    parsed.verify(parsed, std.Io.Clock.real.now(io).toSeconds()) catch |err|
        return P.f(why_buf, "{s} is not a valid self-signed CA certificate ({t}).", .{ source, err });

    if (old) |o| if (!std.mem.eql(u8, o, der)) {
        var ofp: [95]u8 = undefined;
        std.debug.print("portal connect: replacing the CA pinned for {s} (was SHA-256 {s})\n", .{ host, x509check.formatFingerprint(x509check.fingerprint(o), &ofp) });
    };
    p.save(io, der) catch |err| return P.f(why_buf, "Cannot save the pinned CA to {s}: {t}.", .{ p.path(), err });
    std.debug.print("portal connect: https://{s}/ must present a certificate from SHA-256 {s} (pinned: {s})\n", .{ host, x509check.formatFingerprint(fp, &fp_buf), p.path() });
    return .{ .ok = der };
}

test {
    _ = @import("tests.zig");
}
