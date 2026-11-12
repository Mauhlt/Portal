//! The desktop's own Portal window (portal.exe): a GUI terminal for the
//! local session, drawn by the shared view module (client/src/view, the
//! same code as `portal connect`), plus the desk's panels (deskui.zig):
//! first-run settings, pairing approval, the device list and the
//! certificate export. There is no console: everything the desk sees and
//! types goes through this window.
//!
//! Project tabs (tabs.zig): the top bar shows every open project as a
//! coloured tab (amber while its program waits for an answer); the window
//! shows one of them. Ctrl+Shift+T (or "+") opens a folder as a new tab,
//! Ctrl+Shift+W (or a tab's ×) closes the tab shown, Ctrl+Tab /
//! Ctrl+Shift+Tab or a click switches. Only the desk opens and closes
//! tabs; paired devices can only switch between them.
//!
//! Threads: everything here runs on the main thread (window + message
//! loop). Each tab's PTY output thread feeds its `session.term`; this host
//! copies the shown tab's dirty rows into its own Grid under the hub's
//! lock (localgrid.zig), then builds and presents the frame without
//! holding it. Keyboard and paste go to the shown tab's PTY through
//! Session.writeInput; resizes go to every tab (Hub.setSize).
//! Pairing changes (a device asked, the store changed) arrive through
//! web.Server.pairing_notify_fn, which only sets a flag and wakes the loop.
//!
//! The person at the desk has full control (localinput.zig), unlike remote
//! viewers, whose input is filtered by `--input` (keymap.zig).

const std = @import("std");
const view = @import("view");
const TermView = view.TermView;
const input = view.input;
const tabs = @import("tabs.zig");
const tabs_wire = @import("shared").tabs;
const keymap = @import("keymap.zig");
const localgrid = @import("localgrid.zig");
const localinput = @import("localinput.zig");
const deskui = @import("deskui.zig");
const devices = @import("devices.zig");
const settings = @import("settings.zig");
const guard = @import("guard.zig");
const pki = @import("tls/pki.zig");
const web = @import("web.zig");
const sync = @import("sync.zig");
const sync_manifest = @import("client").sync.manifest;

/// Font size of the local terminal, in logical pixels (zoom with Ctrl+= / -).
pub const font_em: f32 = 15;
/// Largest paste accepted, in UTF-16 units of clipboard text.
const max_paste_units = 256 * 1024;

pub const Options = struct {
    /// The session program's name (e.g. the agent CLI). Not shown in the window.
    command_name: []const u8,
    /// e.g. "127.0.0.1:8420".
    listen_host: []const u8,
    /// e.g. "https://127.0.0.1:8420/", shown in the status line.
    url: []const u8 = "",
    policy: keymap.Policy,
};

/// What the first-run (or fix-it) panel starts with.
pub const SetupInput = struct {
    first_run: bool,
    listen: []const u8,
    program: []const u8,
    project: []const u8,
    policy: keymap.Policy,
    /// Why the panel is shown again ("" on a first run).
    problem: []const u8 = "",
};

/// What the desk entered; slices into the host, valid until the next runSetup.
pub const SetupValues = struct {
    listen: []const u8,
    program: []const u8,
    project: []const u8,
    policy: keymap.Policy,
};

/// What the desk panels need from the running server (set once, before
/// any thread starts).
pub const Desk = struct {
    srv: *web.Server,
    paths: devices.Paths,
    /// "AB:CD:..." of the Portal CA; null with --no-tls.
    fingerprint: ?[]const u8,
    /// %USERPROFILE%\Downloads\Portal-CA
    export_default: []const u8,
    /// %LOCALAPPDATA%\Portal\tls
    tls_dir: []const u8,
    /// settings.txt as of startup (the Settings panel edits it).
    saved: settings.Settings,
    /// Opens a folder (absolute) as a new tab: main.openFolder. Returns
    /// null, or why not.
    open_ctx: *const anyopaque,
    open_fn: *const fn (ctx: *const anyopaque, gpa: std.mem.Allocator, hub: *tabs.Hub, dir: []const u8) ?[]const u8,
};

pub const Ended = enum { window_closed, finished };

/// Top bar ids for the tabs: tab_id0 + index selects, tab_close0 + index
/// closes, tab_add opens a folder.
const tab_id0: u32 = 300;
const tab_close0: u32 = 320;
const tab_add: u32 = 340;

const title = @import("title.zig");
const win32 = @import("win32.zig");
const windowLabel = title.windowLabel;
const windowTitle = title.windowTitle;
const max_project_bytes = title.max_project_bytes;
const validProject = title.validProject;

/// Cell selection being made with the mouse (anchor = where the drag began).
const Select = struct {
    anchor: [2]u16 = .{ 0, 0 },
    head: [2]u16 = .{ 0, 0 },
    dragging: bool = false,
    /// True once the pointer moved off the anchor cell (a plain click
    /// selects nothing).
    active: bool = false,

    fn range(s: Select) ?TermView.Selection {
        if (!s.active) return null;
        const a = s.anchor;
        const b = s.head;
        const a_first = a[1] < b[1] or (a[1] == b[1] and a[0] <= b[0]);
        const lo = if (a_first) a else b;
        const hi = if (a_first) b else a;
        return .{ .start_col = lo[0], .start_row = lo[1], .end_col = hi[0], .end_row = hi[1] };
    }
};

/// The top bar's desk actions (keyboard: Ctrl+Shift+P / D / E / S).
const top_buttons = [_]TermView.TopButton{
    .{ .label = "Pair a device\u{2026}", .id = deskui.id.tb_pair },
    .{ .label = "Devices", .id = deskui.id.tb_devices },
    .{ .label = "Export certificate\u{2026}", .id = deskui.id.tb_export },
    .{ .label = "Settings", .id = deskui.id.tb_settings },
};

pub const LocalHost = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    tv: *TermView,
    /// The project tabs (null until attach: the first-run panel comes
    /// before any session).
    hub: ?*tabs.Hub = null,
    /// The tab this window shows and types into, with a reference: it
    /// follows hub.desk_active. Everything goes through this one pointer;
    /// nothing else names a session.
    shown: ?*tabs.Tab = null,
    /// The tab list as of the last frame (for the top bar).
    list: tabs_wire.List = .{},
    list_gen: u64 = 0,
    top_tabs: [tabs.max_tabs]TermView.TopTab = undefined,
    opts: Options = .{ .command_name = "", .listen_host = "", .policy = .keys },
    grid: view.grid.Grid = .{},
    sync: localgrid.Sync = .{},
    select: Select = .{},
    /// Snapshot of session.viewers from the last frame.
    viewers: u32 = 0,
    drawn_viewers: u32 = std.math.maxInt(u32),
    /// Coalesces wake-ups from other threads (Session.notify_fn).
    wake_pending: std.atomic.Value(bool) = .init(false),
    /// Set by pairingNotify (any thread); handled on the main thread.
    pair_dirty: std.atomic.Value(bool) = .init(false),
    title_buf: [title_max]u8 = undefined,
    title_len: usize = 0,
    label_buf: [max_project_bytes + 16]u8 = undefined,
    /// Times the message loop woke up (idle should stay near zero: the
    /// loop is event-driven), and frames presented. Logged at shutdown.
    wakeups: u64 = 0,
    presents: u64 = 0,

    /// The desk panels and what they need.
    ui: deskui.Ui = .{},
    desk: ?Desk = null,
    bufs: deskui.Ui.Bufs = .{},
    until_buf: [16]u8 = undefined,
    until_len: usize = 0,
    /// runSetup: the panel was submitted.
    setup_submitted: bool = false,

    const title_max = title.max_title_bytes;

    pub fn init(gpa: std.mem.Allocator, io: std.Io) !*LocalHost {
        const tv = try TermView.init(gpa, io, .{
            .title = "Portal",
            .width = 1100,
            .height = 700,
            .sizing = .{ .fixed_em = font_em },
        });
        errdefer tv.deinit();
        const h = try gpa.create(LocalHost);
        h.* = .{ .gpa = gpa, .io = io, .tv = tv };
        return h;
    }

    /// The session's options, once known (after any first-run panel).
    pub fn configure(h: *LocalHost, opts: Options) void {
        h.opts = opts;
    }

    /// The desk panels' context. Call before any thread starts.
    pub fn attachDesk(h: *LocalHost, d: Desk) void {
        h.desk = d;
    }

    /// Cells that fit the window now: the PTY's initial size.
    pub fn initialSize(h: *LocalHost) [2]u16 {
        h.tv.build(&h.grid, .{ .top_bar = .{} });
        const c = h.tv.capacity;
        return .{ @max(c[0], 20), @max(c[1], 5) };
    }

    /// Points the window at the tabs and hooks their change notifications.
    /// Call before the first tab starts.
    pub fn attach(h: *LocalHost, hub: *tabs.Hub) void {
        h.hub = hub;
        hub.notify_ctx = h;
        hub.notify_fn = notifyThunk;
        h.tv.reported_capacity = .{ hub.size.cols, hub.size.rows };
        h.tv.setLiveRedraw(h, liveRedraw);
    }

    /// Any thread: something in the session changed.
    fn notifyThunk(ctx: *anyopaque) void {
        const h: *LocalHost = @ptrCast(@alignCast(ctx));
        if (!h.wake_pending.swap(true, .acq_rel)) h.tv.wake();
    }

    /// web.Server.pairing_notify_fn (any thread): the pairing window or
    /// the device store may have changed.
    pub fn pairingNotify(ctx: *anyopaque) void {
        const h: *LocalHost = @ptrCast(@alignCast(ctx));
        h.pair_dirty.store(true, .release);
        notifyThunk(ctx);
    }

    // ------------------------------------------------------------ setup

    /// The first-run panel (or the same panel with `problem` when the
    /// configuration could not be used): runs its own event-driven loop
    /// until the desk submits it, or returns null if the window is closed.
    pub fn runSetup(h: *LocalHost, in: SetupInput) ?SetupValues {
        h.ui.openSetup(in.first_run, in.listen, in.program, in.project, in.policy);
        if (in.problem.len > 0) h.ui.setNote(.bad, "{s}", .{in.problem});
        h.setup_submitted = false;
        h.tv.setTitle(if (in.first_run) "Portal \u{2014} first start" else "Portal \u{2014} settings");
        h.title_len = 0;
        while (true) {
            if (!h.tv.pollEvents(h.sink())) return null;
            if (h.setup_submitted) break;
            const panel = h.ui.panel(&h.bufs, .{});
            h.tv.build(&h.grid, .{
                .top_bar = .{ .title = "Portal" },
                .status = .{ .tone = .warn, .label = "not started", .extra = "the session starts when you click Start" },
                .panel = panel,
            });
            h.tv.present();
            h.tv.waitEvents(TermView.forever);
        }
        h.ui.close();
        return .{
            .listen = std.mem.trim(u8, h.ui.setup.listen.text(), " "),
            .program = std.mem.trim(u8, h.ui.setup.program.text(), " "),
            .project = std.mem.trim(u8, h.ui.setup.project.text(), " "),
            .policy = h.ui.setup.input,
        };
    }

    // ------------------------------------------------------------ run

    /// The message loop. Returns when the window is closed or the child
    /// exited (the caller then runs the common shutdown, which can take
    /// seconds without pumping messages: so the window is hidden and its
    /// swapchain torn down first, rather than left showing "Not
    /// responding" and exiting the process under a live swapchain).
    ///
    /// Purely event-driven: it sleeps until window input or a wake()
    /// (any tab's output, the tab list, viewer count changes, pairing
    /// changes all call notifyThunk). The only timeout is a real deadline:
    /// the expiry of a pairing window this desk opened. Returns
    /// `.finished` once every tab has ended.
    pub fn run(h: *LocalHost) Ended {
        h.updateTitle();
        const ended: Ended = while (true) {
            if (!h.tv.pollEvents(h.sink())) break .window_closed;
            if (h.allEnded()) break .finished;
            const changed = h.checkPairing();
            h.frame(changed);
            h.tv.waitEvents(h.waitMs());
            h.wakeups += 1;
        };
        h.hide();
        h.tv.releaseGpu();
        return ended;
    }

    fn nowUnix(h: *const LocalHost) i64 {
        return std.Io.Timestamp.now(h.io, .real).toSeconds();
    }

    /// Until our pairing window's expiry (plus a second), else forever.
    fn waitMs(h: *LocalHost) u32 {
        const w = h.ui.window orelse return TermView.forever;
        if (h.ui.own_nonce == 0) return TermView.forever;
        const left = w.expires - h.nowUnix() + 1;
        if (left <= 0) {
            h.pair_dirty.store(true, .release);
            return 0;
        }
        return @intCast(@min(left * 1000, 3600 * 1000));
    }

    /// Applies pairing changes reported since the last frame. True if the
    /// panels may look different.
    fn checkPairing(h: *LocalHost) bool {
        const d = h.desk orelse return false;
        var expired = false;
        if (h.ui.window) |w| expired = h.ui.own_nonce != 0 and h.nowUnix() > w.expires;
        if (!h.pair_dirty.swap(false, .acq_rel) and !expired) return false;
        const snap = d.srv.deskWindow();
        h.perform(h.ui.pairingChanged(snap, h.nowUnix()));
        h.updateUntil();
        // The device list follows the store (pairing, `portalctl unpair`).
        if (h.ui.screen == .devices) h.loadDevices();
        return true;
    }

    fn allEnded(h: *LocalHost) bool {
        const hub = h.hub orelse return false;
        hub.mutex.lockUncancelable(h.io);
        defer hub.mutex.unlock(h.io);
        return hub.finished;
    }

    /// Hides the window (shutdown can take a moment; the user already
    /// asked to close, or the program ended).
    pub fn hide(h: *LocalHost) void {
        h.tv.window.hide();
    }

    fn liveRedraw(ctx: *anyopaque) void {
        const h: *LocalHost = @ptrCast(@alignCast(ctx));
        h.tv.reportCapacity(h.sink());
        h.frame(true);
    }

    /// Copies the session's changes into our grid under the lock, then
    /// builds and presents outside it.
    fn frame(h: *LocalHost, force: bool) void {
        h.wake_pending.store(false, .release);
        const hub = h.hub orelse return;
        var old: ?*tabs.Tab = null;
        hub.mutex.lockUncancelable(h.io);
        // Follow the desk's tab (it moves when one is chosen, opened, or
        // the shown one ends).
        if (hub.desk_active) |a| if (a != h.shown) {
            a.acquire();
            old = h.shown;
            h.shown = a;
            // Another screen: copy everything again, drop its images.
            h.sync.deinit(h.gpa);
            h.sync = .{};
            h.grid.deinit(h.gpa);
            h.grid = .{};
            h.select = .{};
        };
        var list_changed = false;
        if (hub.gen != h.list_gen) {
            hub.entriesLocked(&h.list);
            h.list_gen = hub.gen;
            list_changed = true;
        }
        const changed = if (h.shown) |t| h.sync.sync(h.gpa, &h.grid, &t.session.term) else false;
        h.viewers = hub.viewers;
        hub.mutex.unlock(h.io);
        if (old) |o| o.release();

        if (changed) h.clampSelection();
        if (!force and !changed and !list_changed and old == null and !h.tv.needsRedraw() and h.viewers == h.drawn_viewers) return;
        h.drawn_viewers = h.viewers;
        h.updateTitle();

        var right_buf: [64]u8 = undefined;
        var status_buf: [200]u8 = undefined;
        h.tv.build(&h.grid, h.overlay(&right_buf, &status_buf));
        h.tv.present();
        h.presents += 1;
    }

    fn viewerText(n: u32, buf: []u8) []const u8 {
        if (n == 0) return "no remote viewers";
        return std.fmt.bufPrint(buf, "{d} REMOTE VIEWER{s} WATCHING", .{ n, if (n == 1) "" else "S" }) catch "REMOTE VIEWERS WATCHING";
    }

    fn overlay(h: *LocalHost, right_buf: []u8, status_buf: []u8) TermView.Overlay {
        const watching = h.viewers > 0;
        const remote_input: []const u8 = switch (h.opts.policy) {
            .none => "remote: view only",
            .keys => "remote: answer keys only",
            .instruct => "remote: answer keys + checked instructions",
            .text => "remote: FULL CONTROL",
        };
        const d = h.desk;
        const shown_id: ?tabs.Id = if (h.shown) |t| t.id else null;
        for (h.list.slice(), 0..) |*e, i| {
            const c = e.color;
            h.top_tabs[i] = .{
                .label = e.name(),
                .color = .{ @truncate(c >> 16), @truncate(c >> 8), @truncate(c) },
                .active = if (shown_id) |id| std.mem.eql(u8, &id, &e.id) else false,
                .attention = e.state.attention(),
                .id = tab_id0 + @as(u32, @intCast(i)),
                .close_id = tab_close0 + @as(u32, @intCast(i)),
            };
        }
        return .{
            .top_bar = .{
                .title = windowLabel(h.shownName(), &h.label_buf),
                .tabs = h.top_tabs[0..h.list.len],
                .add_id = if (h.list.len < tabs.max_tabs) tab_add else null,
                .right = viewerText(h.viewers, right_buf),
                .right_tone = if (watching) .warn else .muted,
                .right_badge = watching,
                .buttons = if (d != null) &top_buttons else &.{},
            },
            .selection = if (h.ui.open()) null else h.select.range(),
            .status = .{
                .tone = .good,
                .label = "local session",
                .extra = remote_input,
                .extra_tone = if (h.opts.policy == .text) .bad else .muted,
                .right = std.fmt.bufPrint(status_buf, "sharing on {s}", .{h.opts.url}) catch h.opts.url,
            },
            .panel = h.ui.panel(&h.bufs, .{
                .fingerprint = if (d) |x| x.fingerprint else null,
                .url = h.opts.url,
                .until = h.until_buf[0..h.until_len],
                .now = h.nowUnix(),
            }),
        };
    }

    /// The shown tab's name (desk-assigned, never a path).
    fn shownName(h: *const LocalHost) ?[]const u8 {
        const t = h.shown orelse return null;
        return t.name();
    }

    /// The one place the window title is set (see windowTitle).
    fn updateTitle(h: *LocalHost) void {
        var buf: [title_max]u8 = undefined;
        const t = windowTitle(h.shownName(), h.viewers, &buf);
        if (std.mem.eql(u8, t, h.title_buf[0..h.title_len])) return;
        @memcpy(h.title_buf[0..t.len], t);
        h.title_len = t.len;
        h.tv.setTitle(t);
    }

    fn clampSelection(h: *LocalHost) void {
        if (h.grid.cols == 0 or h.grid.rows == 0) {
            h.select = .{};
            return;
        }
        for ([_]*[2]u16{ &h.select.anchor, &h.select.head }) |p| {
            p[0] = @min(p[0], h.grid.cols - 1);
            p[1] = @min(p[1], h.grid.rows - 1);
        }
    }

    /// "14:32" (local time) for our pairing window's expiry.
    fn updateUntil(h: *LocalHost) void {
        h.until_len = 0;
        const w = h.ui.window orelse return;
        h.until_len = localClock(w.expires, &h.until_buf).len;
    }

    // ------------------------------------------------------------ desk actions

    fn perform(h: *LocalHost, a: deskui.Action) void {
        switch (a) {
            .none => {},
            .paste => {
                const raw = h.tv.window.clipboardText(h.gpa, 4096) orelse return;
                defer h.gpa.free(raw);
                h.ui.paste(raw);
            },
            .setup_submit => {
                if (h.hub == null) {
                    h.setup_submitted = true; // runSetup takes it from here
                } else h.saveSettings();
            },
            .setup_cancel => {},
            .begin_pair => {
                const d = h.desk orelse return;
                const nonce = d.srv.deskBegin(h.ui.name.text(), devices.default_pair_window_s) catch |err| {
                    h.ui.pairFailed("Could not open the pairing window: {s}.", .{devices.describeError(err)});
                    return;
                };
                h.perform(h.ui.pairBegun(nonce, d.srv.deskWindow()));
                h.updateUntil();
            },
            .answer => |ans| {
                const d = h.desk orelse return;
                const r = d.srv.deskAnswer(&ans.code, ans.approve) catch |err| {
                    h.ui.setNote(.bad, "Could not record the answer: {s}.", .{devices.describeError(err)});
                    return;
                };
                switch (r) {
                    .approved => h.ui.setNote(.good, "Approved request {s}. Waiting for the device to collect its credential.", .{&ans.code}),
                    .denied => h.ui.setNote(.muted, "Denied request {s}. Further requests from that address are refused in this window.", .{&ans.code}),
                    .not_pending, .no_such_request => h.ui.setNote(.muted, "Request {s} is no longer waiting.", .{&ans.code}),
                    .window_gone => {},
                }
                h.perform(h.ui.pairingChanged(d.srv.deskWindow(), h.nowUnix()));
            },
            .stop_pair => {
                const d = h.desk orelse return;
                d.srv.deskCancel() catch {};
                h.ui.own_nonce = 0;
                h.ui.window = null;
                h.ui.asked = null;
                h.until_len = 0;
            },
            .load_devices => h.loadDevices(),
            .unpair => |i| h.unpair(i),
            .export_ca => h.exportCa(),
            .load_subs => |i| h.loadSubs(i),
            .toggle_sub => |i| h.toggleSub(i),
        }
    }

    /// A device's sync packages: the known ids, everything published, and
    /// anything it is already subscribed to.
    fn loadSubs(h: *LocalHost, i: usize) void {
        const d = h.desk orelse return;
        if (i >= h.ui.n_devs) return;
        const sp: sync.Paths = .{ .dir = d.paths.dir };
        const dev = h.ui.devs[i].name.get();
        const subs = sync.readSubs(h.gpa, h.io, sp) catch |err| {
            h.ui.setNote(.bad, "Could not read the sync subscriptions: {t}.", .{err});
            return;
        };
        var rows: [deskui.max_pkgs]deskui.PkgRow = undefined;
        var n: usize = 0;
        const Add = struct {
            fn f(r: []deskui.PkgRow, k: *usize, name: []const u8) void {
                for (r[0..k.*]) |x| if (std.mem.eql(u8, x.name.get(), name)) return;
                if (k.* == r.len) return;
                r[k.*] = .{};
                r[k.*].name.set(name);
                k.* += 1;
            }
        };
        for (sync_manifest.known_packages) |p| Add.f(&rows, &n, p);
        var published = sync.packages(h.gpa, h.io, sp) catch std.ArrayList([]u8).empty;
        defer {
            for (published.items) |p| h.gpa.free(p);
            published.deinit(h.gpa);
        }
        for (published.items) |p| Add.f(&rows, &n, p);
        var mine_buf: [deskui.max_pkgs][]const u8 = undefined;
        for (subs.forDevice(dev, &mine_buf)) |p| Add.f(&rows, &n, p);
        for (rows[0..n]) |*r| {
            r.on = subs.has(dev, r.name.get());
            if (sync.latest(h.gpa, h.io, sp, r.name.get()) catch null) |v| {
                var vv = v;
                defer vv.deinit(h.gpa);
                var lb: [96]u8 = undefined;
                r.latest.set(std.fmt.bufPrint(&lb, "{s} ({t})", .{ vv.m.version, vv.m.kind }) catch vv.m.version);
            }
        }
        h.ui.setPackages(rows[0..n]);
    }

    fn toggleSub(h: *LocalHost, i: usize) void {
        const d = h.desk orelse return;
        if (i >= h.ui.n_pkgs or h.ui.sub_dev >= h.ui.n_devs) return;
        const dev = h.ui.devs[h.ui.sub_dev].name.get();
        const pkg = h.ui.pkgs[i].name.get();
        const on = !h.ui.pkgs[i].on;
        _ = sync.subscribe(h.gpa, h.io, .{ .dir = d.paths.dir }, dev, pkg, on) catch |err| {
            h.ui.setNote(.bad, "Could not update the subscriptions: {t}.", .{err});
            return;
        };
        d.srv.log.print("sync: '{s}' {s} '{s}' from the Portal window", .{ dev, if (on) "subscribed to" else "unsubscribed from", pkg });
        h.ui.setNote(.good, "{s} '{s}' {s} {s}.", .{ if (on) "Subscribed" else "Unsubscribed", dev, if (on) "to" else "from", pkg });
        h.loadSubs(h.ui.sub_dev);
    }

    fn loadDevices(h: *LocalHost) void {
        const d = h.desk orelse return;
        var rows: [devices.max_devices]deskui.DevRow = undefined;
        var n: usize = 0;
        const Ctx = struct { rows: *[devices.max_devices]deskui.DevRow, n: *usize };
        devices.withStore(h.gpa, h.io, d.paths, h.nowUnix(), Ctx{ .rows = &rows, .n = &n }, struct {
            fn op(c: Ctx, st: *devices.Store) !bool {
                for (st.devices) |slot| {
                    const dev = slot orelse continue;
                    c.rows[c.n.*] = .{ .name = dev.name, .ip = dev.ip, .last_seen = dev.last_seen };
                    c.n.* += 1;
                }
                return false;
            }
        }.op) catch |err| {
            h.ui.setNote(.bad, "Could not read the device list: {s}.", .{devices.describeError(err)});
            return;
        };
        std.mem.sort(deskui.DevRow, rows[0..n], {}, struct {
            fn lt(_: void, a: deskui.DevRow, b: deskui.DevRow) bool {
                return std.mem.lessThan(u8, a.name.get(), b.name.get());
            }
        }.lt);
        if (sync.readSubs(h.gpa, h.io, .{ .dir = d.paths.dir })) |subs| {
            for (rows[0..n]) |*r| {
                var b: [deskui.max_pkgs][]const u8 = undefined;
                r.n_subs = @intCast(subs.forDevice(r.name.get(), &b).len);
            }
        } else |_| {}
        h.ui.setDevices(rows[0..n]);
    }

    fn unpair(h: *LocalHost, i: usize) void {
        const d = h.desk orelse return;
        if (i >= h.ui.n_devs) return;
        const name_t = h.ui.devs[i].name;
        const name = name_t.get();
        var removed = false;
        const Ctx = struct { name: []const u8, removed: *bool };
        devices.withStore(h.gpa, h.io, d.paths, h.nowUnix(), Ctx{ .name = name, .removed = &removed }, struct {
            fn op(c: Ctx, st: *devices.Store) !bool {
                c.removed.* = st.remove(c.name);
                return c.removed.*;
            }
        }.op) catch |err| {
            h.ui.setNote(.bad, "Could not update the device list: {s}.", .{devices.describeError(err)});
            return;
        };
        // The pairing watcher sees the change and ends its sessions.
        if (removed) d.srv.log.print("device '{s}' unpaired from the Portal window", .{name});
        h.loadDevices();
        h.ui.setNote(.good, "Unpaired '{s}'. Its viewers are disconnected.", .{name});
    }

    fn exportCa(h: *LocalHost) void {
        const d = h.desk orelse return;
        const dir = std.mem.trim(u8, h.ui.export_dir.text(), " ");
        const store: pki.Store = .{ .gpa = h.gpa, .io = h.io, .dir = d.tls_dir };
        var ca = (pki.loadCa(store) catch |err| {
            h.ui.setNote(.bad, "Cannot read the Portal CA: {t}.", .{err});
            return;
        }) orelse {
            h.ui.setNote(.bad, "There is no Portal CA (this Portal serves plain HTTP).", .{});
            return;
        };
        defer ca.deinit(h.gpa);
        std.Io.Dir.cwd().createDirPath(h.io, dir) catch |err| {
            h.ui.setNote(.bad, "Cannot create {s}: {t}.", .{ dir, err });
            return;
        };
        _ = pki.exportCa(h.gpa, h.io, &ca, dir) catch |err| {
            h.ui.setNote(.bad, "Export to {s} failed: {t}.", .{ dir, err });
            return;
        };
        d.srv.log.print("CA certificate exported from the Portal window", .{});
        h.ui.exported(dir);
    }

    fn openSettings(h: *LocalHost) void {
        const d = h.desk orelse return;
        const s = &d.saved;
        h.ui.openSetup(false, s.listen.get() orelse h.opts.listen_host, s.program.get() orelse "", s.project.get() orelse "", s.input orelse h.opts.policy);
    }

    /// The Settings panel (during a session): checked, then saved for the
    /// next start.
    fn saveSettings(h: *LocalHost) void {
        const d = &(h.desk orelse return);
        const st = &h.ui.setup;
        const listen = std.mem.trim(u8, st.listen.text(), " ");
        const program = std.mem.trim(u8, st.program.text(), " ");
        const project = std.mem.trim(u8, st.project.text(), " ");
        if (checkListen(listen)) |why| return h.ui.setNote(.bad, "{s}", .{why});
        var split_buf: [settings.max_program]u8 = undefined;
        var split_args: [settings.max_args][]const u8 = undefined;
        _ = settings.splitCommand(program, &split_buf, &split_args) catch
            return h.ui.setNote(.bad, "Enter the program to run (quotes must be closed).", .{});
        if (project.len > 0 and !validProject(project))
            return h.ui.setNote(.bad, "The project name must be 1-{d} bytes of printable text.", .{max_project_bytes});
        var s = d.saved;
        _ = s.listen.set(listen);
        _ = s.program.set(program);
        _ = s.project.set(project);
        s.input = st.input;
        settings.save(h.gpa, h.io, d.paths.dir, &s) catch |err|
            return h.ui.setNote(.bad, "Could not save the settings: {t}.", .{err});
        h.desk.?.saved = s;
        h.ui.close();
    }

    // ------------------------------------------------------------ input

    fn sink(h: *LocalHost) input.InputSink {
        return .{ .ctx = h, .vtable = &vtable };
    }

    const vtable: input.InputSink.VTable = .{
        .key = onKey,
        .char = onChar,
        .answer = onAnswer,
        .button = onButton,
        .resized = onResized,
        .mouse = onMouse,
    };

    fn self(ctx: *anyopaque) *LocalHost {
        return @ptrCast(@alignCast(ctx));
    }

    /// Who gets the keyboard (and the mouse): decided here only. A modal
    /// panel wins over the terminal. A bottom-region input pane (see
    /// TermView.Layout) would be one more target here.
    pub const Focus = enum { terminal, panel };

    fn focus(h: *const LocalHost) Focus {
        return if (h.ui.open()) .panel else .terminal;
    }

    fn onKey(ctx: *anyopaque, key: input.Key, mods: input.Mods) void {
        const h = self(ctx);
        switch (h.focus()) {
            .panel => return h.perform(h.ui.key(key, mods)),
            .terminal => {},
        }
        // Ctrl+Tab / Ctrl+Shift+Tab: the next / previous tab (Ctrl+Tab
        // sends nothing a terminal program would get anyway).
        if (key == .tab and mods.ctrl and !mods.alt) return h.cycleTab(if (mods.shift) -1 else 1);
        const s = h.session() orelse return;
        s.mutex.lockUncancelable(s.io);
        const app_cursor = s.term.appCursor();
        s.mutex.unlock(s.io);
        var buf: [localinput.max_seq]u8 = undefined;
        h.select.active = false;
        s.writeInput(localinput.encodeKey(key, mods, app_cursor, &buf));
    }

    /// The shown tab's session.
    fn session(h: *LocalHost) ?*@import("session.zig").Session {
        const t = h.shown orelse return null;
        return &t.session;
    }

    // ------------------------------------------------------------ tabs

    /// Shows the tab at bar position `i`.
    fn selectTab(h: *LocalHost, i: usize) void {
        const hub = h.hub orelse return;
        if (i >= h.list.len) return;
        hub.mutex.lockUncancelable(h.io);
        if (hub.acquireLocked(h.list.items[i].id)) |t| {
            hub.desk_active = t;
            t.release();
        }
        hub.mutex.unlock(h.io);
        h.frame(true);
    }

    fn cycleTab(h: *LocalHost, step: i32) void {
        const n = h.list.len;
        if (n < 2) return;
        const id = (h.shown orelse return).id;
        const at = h.list.find(id) orelse 0;
        const next = @mod(@as(i64, @intCast(at)) + step, @as(i64, @intCast(n)));
        h.selectTab(@intCast(next));
    }

    /// Closes the tab at bar position `i`: its program is asked to exit
    /// (tabs.Tab.requestClose); the tab goes once it has.
    fn closeTab(h: *LocalHost, i: usize) void {
        const hub = h.hub orelse return;
        if (i >= h.list.len) return;
        hub.mutex.lockUncancelable(h.io);
        const t = hub.acquireLocked(h.list.items[i].id);
        hub.mutex.unlock(h.io);
        const tab = t orelse return;
        hub.log.print("desk closed tab '{s}'", .{tab.name()});
        tab.requestClose();
        tab.release();
    }

    fn closeShown(h: *LocalHost) void {
        const id = (h.shown orelse return).id;
        if (h.list.find(id)) |i| h.closeTab(i);
    }

    /// Ctrl+Shift+T / "+": the folder picker, then a new tab there.
    fn openTab(h: *LocalHost) void {
        const hub = h.hub orelse return;
        const d = h.desk orelse return;
        var buf: [32768]u16 = undefined;
        const dir_w = win32.pickFolder(&buf, std.unicode.utf8ToUtf16LeStringLiteral("Open a project folder in a new Portal tab")) orelse return;
        const dir = std.unicode.wtf16LeToWtf8Alloc(h.gpa, dir_w) catch return;
        defer h.gpa.free(dir);
        if (d.open_fn(d.open_ctx, h.gpa, hub, dir)) |why| {
            var mb: [256]u8 = undefined;
            const text = std.fmt.bufPrint(&mb, "Could not open the folder: {s}.", .{why}) catch "Could not open the folder.";
            var wb: [257:0]u16 = undefined;
            const n = std.unicode.utf8ToUtf16Le(wb[0..256], text) catch 0;
            wb[n] = 0;
            _ = win32.MessageBoxW(null, &wb, std.unicode.utf8ToUtf16LeStringLiteral("Portal"), 0x30);
        }
        h.frame(true);
    }

    fn onChar(ctx: *anyopaque, cp: u21, mods: input.Mods) void {
        const h = self(ctx);
        if (mods.ctrl and mods.shift and !mods.alt) {
            // Desk shortcuts, also while a panel is open (they switch).
            if (h.hub != null and h.desk != null) switch (cp) {
                't', 'T' => return h.openTab(),
                'w', 'W' => if (h.focus() == .terminal) return h.closeShown(),
                'p', 'P' => return h.ui.openPair(),
                'd', 'D' => return h.perform(h.ui.openDevices()),
                'e', 'E' => return h.ui.openExport(h.desk.?.export_default),
                's', 'S' => return h.openSettings(),
                else => {},
            };
            if (h.focus() == .terminal) switch (cp) {
                'c', 'C' => return h.copySelection(),
                'v', 'V' => return h.paste(),
                else => {},
            };
        }
        switch (h.focus()) {
            .panel => return h.perform(h.ui.char(cp, mods)),
            .terminal => {},
        }
        const s = h.session() orelse return;
        var buf: [localinput.max_seq]u8 = undefined;
        h.select.active = false;
        s.writeInput(localinput.encodeChar(cp, mods, &buf));
    }

    fn onAnswer(_: *anyopaque, _: []const u8) void {} // no answer bar locally

    fn onButton(ctx: *anyopaque, b: u32) void {
        const h = self(ctx);
        switch (b) {
            deskui.id.tb_pair => if (h.desk != null) h.ui.openPair(),
            deskui.id.tb_devices => if (h.desk != null) h.perform(h.ui.openDevices()),
            deskui.id.tb_export => if (h.desk) |d| h.ui.openExport(d.export_default),
            deskui.id.tb_settings => h.openSettings(),
            tab_add => if (h.focus() == .terminal) h.openTab(),
            tab_id0...tab_id0 + tabs.max_tabs - 1 => if (h.focus() == .terminal) h.selectTab(b - tab_id0),
            tab_close0...tab_close0 + tabs.max_tabs - 1 => if (h.focus() == .terminal) h.closeTab(b - tab_close0),
            else => if (h.focus() == .panel) h.perform(h.ui.button(b)),
        }
    }

    /// The window decides the PTY size (of every tab); web viewers adapt.
    fn onResized(ctx: *anyopaque, _: u32, _: u32, cols: u16, rows: u16) void {
        const h = self(ctx);
        const hub = h.hub orelse return;
        hub.setSize(.{ .cols = cols, .rows = rows });
    }

    fn onMouse(ctx: *anyopaque, m: input.Mouse) void {
        const h = self(ctx);
        if (h.focus() != .terminal) return; // modal: only its buttons react
        switch (m.button) {
            .left => switch (m.action) {
                .down => {
                    h.select = .{ .anchor = .{ m.col, m.row }, .head = .{ m.col, m.row }, .dragging = m.inside };
                },
                .move => if (h.select.dragging) {
                    h.select.head = .{ m.col, m.row };
                    if (h.select.head[0] != h.select.anchor[0] or h.select.head[1] != h.select.anchor[1]) h.select.active = true;
                },
                .up => h.select.dragging = false,
            },
            // Right-click: copy the selection if there is one, else paste
            // (the Windows console convention).
            .right => if (m.action == .down) {
                if (h.select.active) h.copySelection() else h.paste();
            },
            .middle => {},
        }
    }

    fn copySelection(h: *LocalHost) void {
        const sel = h.select.range() orelse return;
        const text = localgrid.selectionText(h.gpa, &h.grid, sel) catch return;
        defer h.gpa.free(text);
        if (text.len > 0) _ = h.tv.window.setClipboardText(text);
        h.select = .{};
    }

    fn paste(h: *LocalHost) void {
        const s = h.session() orelse return;
        const raw = h.tv.window.clipboardText(h.gpa, max_paste_units) orelse return;
        defer h.gpa.free(raw);
        s.mutex.lockUncancelable(s.io);
        const bracketed = s.term.bracketedPaste();
        s.mutex.unlock(s.io);
        const buf = h.gpa.alloc(u8, raw.len + localinput.paste_start.len + localinput.paste_end.len) catch return;
        defer h.gpa.free(buf);
        var n: usize = 0;
        if (bracketed) {
            @memcpy(buf[0..localinput.paste_start.len], localinput.paste_start);
            n = localinput.paste_start.len;
        }
        const clean = localinput.sanitizePaste(raw, buf[n .. n + raw.len]);
        if (clean.len == 0) return;
        n += clean.len;
        if (bracketed) {
            @memcpy(buf[n..][0..localinput.paste_end.len], localinput.paste_end);
            n += localinput.paste_end.len;
        }
        h.select.active = false;
        s.writeInput(buf[0..n]);
    }
};

/// Why `text` can't be the listen address, or null if it can.
pub fn checkListen(text: []const u8) ?[]const u8 {
    const addr = std.Io.net.IpAddress.parseLiteral(text) catch return "Bad listen address: want IP:PORT, e.g. 127.0.0.1:8420.";
    if (addr.getPort() == 0) return "Bad listen address: the port must be 1-65535.";
    guard.checkListenAddress(addr) catch |err| return switch (err) {
        error.WildcardAddress => "Refusing to listen on all interfaces: use your WireGuard address.",
        error.PublicAddress => "Refusing to listen on a public address: use loopback or your WireGuard address.",
    };
    return null;
}


/// Unix time `t` as local "HH:MM" (empty if it can't be converted).
fn localClock(t: i64, buf: []u8) []const u8 {
    if (t <= 0) return buf[0..0];
    const ticks: u64 = (@as(u64, @intCast(t)) + 11644473600) * 10_000_000;
    const ft: win32.FILETIME = .fromU64(ticks);
    var local: win32.FILETIME = undefined;
    var st: win32.SYSTEMTIME = undefined;
    if (win32.FileTimeToLocalFileTime(&ft, &local) == 0 or win32.FileTimeToSystemTime(&local, &st) == 0) return buf[0..0];
    return std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}", .{ st.wHour, st.wMinute }) catch buf[0..0];
}


test "selection range normalises drag direction" {
    var s: Select = .{ .anchor = .{ 5, 3 }, .head = .{ 2, 1 }, .active = true };
    const r = s.range().?;
    try std.testing.expectEqual(@as(u16, 2), r.start_col);
    try std.testing.expectEqual(@as(u16, 1), r.start_row);
    try std.testing.expectEqual(@as(u16, 5), r.end_col);
    try std.testing.expectEqual(@as(u16, 3), r.end_row);
    s.active = false;
    try std.testing.expect(s.range() == null);
}


test "viewer text" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("no remote viewers", LocalHost.viewerText(0, &buf));
    try std.testing.expectEqualStrings("1 REMOTE VIEWER WATCHING", LocalHost.viewerText(1, &buf));
    try std.testing.expectEqualStrings("3 REMOTE VIEWERS WATCHING", LocalHost.viewerText(3, &buf));
}

test "checkListen" {
    try std.testing.expect(checkListen("127.0.0.1:8420") == null);
    try std.testing.expect(checkListen("10.8.0.1:8420") == null);
    try std.testing.expect(checkListen("0.0.0.0:8420") != null);
    try std.testing.expect(checkListen("8.8.8.8:8420") != null);
    try std.testing.expect(checkListen("10.8.0.1") != null);
    try std.testing.expect(checkListen("10.8.0.1:0") != null);
}
