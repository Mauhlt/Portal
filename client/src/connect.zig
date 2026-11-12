//! The remote viewer: `portal connect` (in the Portal window's executable,
//! a GUI program with no console) and the standalone `portal-client` both
//! run `main` below. Module "client" in Portal's root build; imports only
//! std and "view".
//!
//!   connect                                             the last server, or
//!                                                       the first-run screen
//!   connect --server 10.8.0.1:8420 --ca portal-ca.pem   pin the CA, connect
//!   connect --server 10.8.0.1:8420                      connect (CA pinned)
//!   connect --server ADDR --forget     delete this device's credential + pin
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
// For portalctl's headless sync-device (src/sync_cli.zig).
pub const net_client = client_mod;
pub const net_http = http;
pub const net_ws = @import("net/ws.zig");
pub const tlsconn = @import("net/tlsconn.zig");
pub const watchdog = @import("net/watchdog.zig");
pub const credstore_mod = credstore;
pub const pin = pin_mod;
pub const x509check_mod = x509check;

/// Called with every message that ends the program (and --forget's
/// confirmation). portal.exe shows a message box: it has no console.
pub var report_fn: ?*const fn (text: []const u8) void = null;

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
    \\  --forget           delete this device's stored credentials and the
    \\                     remembered CA for this server, and exit
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
        // The Data column: new blobs from the terminal; whether it fits.
        _ = h.sink.data.sync(h.client.gpa, &s.grid.images);
        const fb = h.tv.window.framebufferSize();
        h.sink.data.setFits(TermView.dataWidth(@floatFromInt(fb[0]), h.tv.window.scale(), (TermView.DataColumn{}).frac) > 0);
        const o = remote.overlay(.{
            .status = st,
            .mode = mode,
            .detail = detail,
            .line = h.sink.line.snapshot(),
            .data = h.sink.data.column(),
            .data_badge = h.sink.data.badge(),
            .host = h.client.host(),
            .has_grid = s.grid.cols > 0,
            .code = s.pair_code,
            .err = s.last_error,
            .pin_fp = h.pin_fp_buf[0..h.pin_fp_len],
        }, &h.bufs);
        var oo = o;
        h.sync.mutex.lockUncancelable(h.client.io);
        defer h.sync.mutex.unlock(h.client.io);
        if (h.sync.ui.panel(&h.sync_bufs)) |p| oo.panel = p;
        h.tv.build(&s.grid, oo);
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
        var tbuf: [credstore.max_target]u8 = undefined;
        for ([_]bool{ false, true }) |plain| {
            credstore.delete(credstore.targetName(host, plain, &tbuf)) catch |err|
                fatal(prog, "could not delete the credential: {t}", .{err});
        }
        if (pin_mod.Pin.forHost(host)) |p| {
            p.delete(io) catch |err| fatal(prog, "could not delete {s}: {t}", .{ p.path(), err });
        } else |_| {}
        report("{s}: forgot the credentials and the pinned CA for {s}", .{ prog, host });
        std.process.exit(0);
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
    if (transport == .tls) {
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

    while (tv.pollEvents(host_ui.sink.sink())) {
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
const SyncState = struct {
    client: *client_mod.Client,
    shared: *client_mod.Shared,
    mutex: std.Io.Mutex = .init,
    ui: sync.ui.Ui = .{},
    store: ?sync.store.Store = null,
    root_buf: [pin_mod.max_path]u8 = undefined,
    seen: u64 = 0,

    fn io(s: *const SyncState) std.Io {
        return s.client.io;
    }

    fn openStore(s: *SyncState) ?*sync.store.Store {
        if (s.store == null) {
            const root = sync.keypin.syncRoot(&s.root_buf) catch return null;
            s.store = sync.store.Store.open(s.client.gpa, s.io(), root) catch return null;
        }
        return &s.store.?;
    }

    /// Event-driven: sleeps until the network thread bumps sync_gen (a
    /// stream connected, or the desktop said {"t":"updates"}) or the user
    /// approved something.
    fn run(s: *SyncState) void {
        while (true) {
            s.shared.sync_wake.reset();
            const gen = s.shared.sync_gen.load(.acquire);
            if (gen == s.seen) {
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
        const st = s.openStore() orelse return;
        var session: ?client_mod.http_Cookie = null;
        s.shared.mutex.lockUncancelable(s.io());
        session = s.shared.session;
        s.shared.mutex.unlock(s.io());
        var sess = session orelse return;
        defer sess.wipe();
        const host = s.client.host();
        const pinned = (sync.keypin.load(s.io(), host) catch null) orelse {
            s.mutex.lockUncancelable(s.io());
            s.ui.setNote("Sync is off for {s}: pair this device again to pin the desktop's release key.", .{host});
            s.mutex.unlock(s.io());
            return;
        };
        var approvals: [sync.ui.max_marks]sync.engine.Approval = undefined;
        var marks: [sync.ui.max_marks]sync.ui.Mark = undefined;
        var opts: sync.engine.Options = .{ .client_version = client_version };
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
        var rows: [32]sync.ui.Installed = undefined;
        const n = installedRows(st, &rows);
        s.mutex.lockUncancelable(s.io());
        s.ui.setReport(rep);
        s.ui.setInstalled(rows[0..n]);
        s.mutex.unlock(s.io());
        s.redraw();
    }

    fn logLine(_: ?*anyopaque, line: []const u8) void {
        std.debug.print("portal connect: sync: {s}\n", .{line});
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
            rows[k] = sync.ui.Installed.init(id, cur.version(), if (prev) |p| p.version() else null);
            k += 1;
        }
        return k;
    }

    fn perform(s: *SyncState, a: sync.ui.Action) void {
        switch (a) {
            .none => {},
            .rerun => {
                _ = s.shared.sync_gen.fetchAdd(1, .release);
                s.shared.sync_wake.set(s.io());
            },
            .rollback => |i| {
                const st = s.openStore() orelse return;
                s.mutex.lockUncancelable(s.io());
                const pkg_row = if (i < s.ui.n_installed) s.ui.installed[i] else null;
                s.mutex.unlock(s.io());
                const row = pkg_row orelse return;
                const r = st.rollback(row.package());
                var rows: [32]sync.ui.Installed = undefined;
                const n = installedRows(st, &rows);
                s.mutex.lockUncancelable(s.io());
                s.ui.setInstalled(rows[0..n]);
                if (r) |p| s.ui.setNote("{s} rolled back to {s}.", .{ row.package(), p.version() }) else |err| s.ui.setNote("Roll back failed: {t}", .{err});
                s.mutex.unlock(s.io());
            },
        }
        s.redraw();
    }

    fn modal(s: *SyncState) remote.RemoteSink.Modal {
        return .{ .ctx = s, .active = active, .key = key, .char = char, .button = button, .shortcut = shortcut };
    }
    fn self(p: *anyopaque) *SyncState {
        return @ptrCast(@alignCast(p));
    }
    fn active(p: *anyopaque) bool {
        const s = self(p);
        s.mutex.lockUncancelable(s.io());
        defer s.mutex.unlock(s.io());
        return s.ui.open();
    }
    fn key(p: *anyopaque, k: view.input.Key, m: view.input.Mods) void {
        const s = self(p);
        s.mutex.lockUncancelable(s.io());
        const a = s.ui.key(k, m);
        s.mutex.unlock(s.io());
        s.perform(a);
    }
    fn char(p: *anyopaque, cp: u21, m: view.input.Mods) void {
        const s = self(p);
        s.mutex.lockUncancelable(s.io());
        const a = s.ui.char(cp, m);
        s.mutex.unlock(s.io());
        s.perform(a);
    }
    fn button(p: *anyopaque, b: u32) bool {
        if (b < sync.ui.id.approve) return false;
        const s = self(p);
        s.mutex.lockUncancelable(s.io());
        const a = s.ui.button(b);
        s.mutex.unlock(s.io());
        s.perform(a);
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
