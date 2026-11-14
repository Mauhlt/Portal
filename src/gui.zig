//! The desktop's own Portal window (portal.exe): device glue that binds
//! the shared UI (module "portal_ui": its shell with device `.desk`, the
//! desk panels) to the local sessions and the server. The UI itself (layout,
//! tabs with + and ×, the desk tools, the Instruct panel, the Data slice,
//! selection, the panels' screens) lives in ui/; this file feeds it the hub's
//! state each frame and performs what it asks: VT bytes to the shown tab's
//! PTY, tab switches, the folder picker, the clipboard, and the desk
//! panels' actions (the in-process desk API in web.zig, the device store,
//! the CA export, settings). There is no console: everything the desk sees
//! and types goes through this window.
//!
//! Project tabs (tabs.zig): Ctrl+Shift+T (or "+") opens a folder as a new
//! tab, Ctrl+Shift+W (or a tab's ×) closes the tab shown, Ctrl+Tab /
//! Ctrl+Shift+Tab or a click switches. Only the desk opens and closes tabs;
//! paired devices can only switch between them.
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
const Presenter = view.Presenter;
const ui = @import("portal_ui");
const shell_mod = ui.shell;
const input = ui.input;
const tabs = @import("tabs.zig");
const tabs_wire = @import("shared").tabs;
const keymap = @import("keymap.zig");
const localgrid = @import("localgrid.zig");
const localinput = @import("localinput.zig");
const deskui = @import("deskui.zig");
const devices = @import("devices.zig");
const settings = @import("settings.zig");
const agenthooks = @import("agenthooks.zig");
const pki = @import("tls/pki.zig");
const tunneldesk = @import("tunneldesk.zig");
const tunnelnet = @import("shared").tunnelnet;
const main = @import("main.zig");
const web = @import("web.zig");
const sync = @import("sync.zig");
const client = @import("client");
const sync_manifest = client.sync.manifest;
const rules = @import("inputrules");
const activity_wire = @import("shared").activity;
const sysinfo = @import("shared").sysinfo;
const subtabs_wire = @import("shared").subtabs;
const convo_wire = @import("shared").convo;
const deskspeech = @import("deskspeech.zig");
const deskprojects = @import("deskprojects.zig");
const projects_panel = ui.panels.projects;

/// The desk's top-bar tools: the desk panels', then Projects.
const desk_tools = deskui.tools ++ [_]ui.frame.TopButton{projects_panel.tool};

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
    tunnel_port: []const u8,
    program: []const u8,
    project: []const u8,
    policy: keymap.Policy,
    /// Why the panel is shown again ("" on a first run).
    problem: []const u8 = "",
};

/// What the desk entered; slices into the host, valid until the next runSetup.
pub const SetupValues = struct {
    tunnel_port: []const u8,
    program: []const u8,
    project: []const u8,
    policy: keymap.Policy,
};

/// What the desk panels need from the running server (set once, before
/// any thread starts).
pub const Desk = struct {
    srv: *web.Server,
    paths: devices.Paths,
    /// "AB:CD:..." of the Portal CA, and its 32 bytes (pairing codes).
    fingerprint: []const u8,
    ca_sha256: [32]u8,
    /// This desktop's WireGuard public key.
    desk_public: tunneldesk.Key,
    /// The UDP port the tunnel listens on.
    tunnel_port: u16,
    /// %USERPROFILE%\Downloads\Portal-CA
    export_default: []const u8,
    /// %LOCALAPPDATA%\Portal\tls
    tls_dir: []const u8,
    /// Filled by attachDesk: the key's text and check code (Settings).
    desk_key_text: [44]u8 = undefined,
    desk_check: [tunnelnet.check_code_len]u8 = undefined,
    /// settings.txt as of startup (the Settings panel edits it).
    saved: settings.Settings,
    /// Opens a folder (absolute) as a new tab: main.openFolder. Returns
    /// null, or why not.
    open_ctx: *const anyopaque,
    open_fn: *const fn (ctx: *const anyopaque, gpa: std.mem.Allocator, hub: *tabs.Hub, dir: []const u8) ?[]const u8,
    /// Portal's environment (where the agent's settings.json and the
    /// installed portalctl are: Settings, "Claude Code integration").
    env: *const std.process.Environ.Map,
};

pub const Ended = enum { window_closed, finished };

const title = @import("title.zig");
const win32 = @import("win32.zig");
const windowLabel = title.windowLabel;
const windowTitle = title.windowTitle;
const max_project_bytes = title.max_project_bytes;
const validProject = title.validProject;

pub const LocalHost = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    p: *Presenter,
    /// The shared UI's Portal screen (device `.desk`).
    shell: ui.Shell = undefined,
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
    opts: Options = .{ .command_name = "", .listen_host = "", .policy = .keys },
    grid: ui.grid.Grid = .{},
    sync: localgrid.Sync = .{},
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
    /// runSetup: the panel was submitted.
    setup_submitted: bool = false,
    /// Whether the OS touch keyboard was last asked to show.
    keyboard_shown: bool = false,
    /// Every tab's background tasks and usage, as of hub.activity_gen.
    act: activity_wire.Activity = .{},
    act_gen: u64 = 0,
    /// The plan's usage as last drawn (Hub.usage).
    usage: @import("shared").planusage.Usage = .{},
    /// The System panel is open here and the monitor accepted it; its
    /// latest sample.
    sys_sub: bool = false,
    sys: sysinfo.Snapshot = .{},
    sys_gen: u64 = 0,
    /// The shown tab's subagent sub-tabs (section 3e) as of `subs_gen`,
    /// and the one shown instead of the terminal (null: none): its
    /// read-only conversation, copied the way a device gets it (the same
    /// `convo` writer and parser) into the desk's Conversation view.
    subs: subtabs_wire.List = .{},
    subs_gen: u64 = 0,
    sub_shown: ?subtabs_wire.Id = null,
    sub_epoch: u32 = 0,
    sub_rev: u64 = 0,
    sub_convo: ui.convo.Conversation = .{},
    convo_view: ui.convoview.View = undefined,
    /// Speech input: the 🎤, the Audio panel, the microphone thread and
    /// stt.Home (deskspeech.zig); null until attachDesk.
    speech: ?*deskspeech.DeskSpeech = null,
    /// The Projects panel (startable projects) and the tabs' "started by"
    /// notes; hub.projects_gen as last drawn.
    projects: deskprojects.DeskProjects = .{},
    projects_gen: u64 = 0,

    const title_max = title.max_title_bytes;

    pub fn init(gpa: std.mem.Allocator, io: std.Io) !*LocalHost {
        const p = try Presenter.init(gpa, io, .{
            .title = "Portal",
            .width = 1100,
            .height = 700,
            .sizing = .{ .fixed_em = font_em },
        });
        errdefer p.deinit();
        // The hero art while the session starts (ends at the first output
        // of the shown tab, or at any input; Presenter.beginSplash).
        p.beginSplash(view.hero_png);
        const h = try gpa.create(LocalHost);
        h.* = .{ .gpa = gpa, .io = io, .p = p };
        h.shell = ui.Shell.init(gpa, .desk, .{ .ctx = h, .vtable = &host_vtable });
        h.shell.modal = .{ .ctx = h, .active = panelActive, .key = panelKey, .char = panelChar, .button = panelButton };
        // Sub-tabs only: the desk's main slice is the terminal otherwise.
        h.convo_view = ui.convoview.View.init(gpa);
        h.convo_view.answers = false;
        h.shell.conversation = h.convo_view.contentView();
        return h;
    }

    /// The session's options, once known (after any first-run panel).
    pub fn configure(h: *LocalHost, opts: Options) void {
        h.opts = opts;
    }

    /// The desk panels' context. Call before any thread starts.
    pub fn attachDesk(h: *LocalHost, d: Desk) void {
        h.desk = d;
        h.desk.?.desk_key_text = @import("WireGuard").device.keys.encode(&d.desk_public);
        h.desk.?.desk_check = tunnelnet.checkCode(&d.desk_public);
        h.p.setBackgroundArt(d.saved.background_art orelse true);
        const s = h.gpa.create(deskspeech.DeskSpeech) catch return;
        s.* = .{ .gpa = h.gpa, .io = h.io, .data_dir = d.paths.dir, .notify_ctx = h, .notify_fn = notifyThunk, .mic = undefined };
        s.start(&h.desk.?.saved);
        h.speech = s;
        h.shell.dictation = s.hooks();
        h.shell.headset_mic = .{ .ctx = s, .present = headsetPresent };
    }

    /// A headset with a microphone is attached (its media button then
    /// toggles dictation).
    fn headsetPresent(ctx: ?*anyopaque) bool {
        const s: *deskspeech.DeskSpeech = @ptrCast(@alignCast(ctx.?));
        return s.snap.list.anyHeadset();
    }

    /// Stops the microphone thread and the speech engine (stt.Home
    /// confirms what is pending and closes).
    fn stopSpeech(h: *LocalHost) void {
        const s = h.speech orelse return;
        h.shell.dictation = null;
        h.shell.headset_mic = null;
        s.deinit();
        h.gpa.destroy(s);
        h.speech = null;
    }

    /// Cells that fit the window now: the PTY's initial size.
    pub fn initialSize(h: *LocalHost) [2]u16 {
        // The same slices as a running frame, so the PTY starts at its size.
        h.p.build(&h.grid, h.overlay());
        const c = h.p.frame.capacity;
        return .{ @max(c[0], 20), @max(c[1], 5) };
    }

    /// Points the window at the tabs and hooks their change notifications.
    /// Call before the first tab starts.
    pub fn attach(h: *LocalHost, hub: *tabs.Hub) void {
        h.hub = hub;
        hub.notify_ctx = h;
        hub.notify_fn = notifyThunk;
        h.p.frame.reported_capacity = .{ hub.size.cols, hub.size.rows };
        h.p.setLiveRedraw(h, liveRedraw);
    }

    /// Any thread: something in the session changed.
    fn notifyThunk(ctx: *anyopaque) void {
        const h: *LocalHost = @ptrCast(@alignCast(ctx));
        if (!h.wake_pending.swap(true, .acq_rel)) h.p.wake();
    }

    /// web.Server.store_notify_fn (any thread): the device store may have
    /// changed.
    pub fn storeNotify(ctx: *anyopaque) void {
        const h: *LocalHost = @ptrCast(@alignCast(ctx));
        h.pair_dirty.store(true, .release);
        notifyThunk(ctx);
    }

    // ------------------------------------------------------------ setup

    /// The first-run panel (or the same panel with `problem` when the
    /// configuration could not be used): runs its own event-driven loop
    /// until the desk submits it, or returns null if the window is closed.
    pub fn runSetup(h: *LocalHost, in: SetupInput) ?SetupValues {
        h.p.endSplash(); // the panel needs answers
        h.ui.openSetup(in.first_run, in.tunnel_port, in.program, in.project, in.policy);
        if (in.problem.len > 0) h.ui.setNote(.bad, "{s}", .{in.problem});
        h.setup_submitted = false;
        h.p.setTitle(if (in.first_run) "Portal \u{2014} first start" else "Portal \u{2014} settings");
        h.title_len = 0;
        while (true) {
            if (!h.p.pollEvents(h.shell.sink())) return null;
            if (h.setup_submitted) break;
            const panel = h.ui.panel(&h.bufs, .{});
            h.p.build(&h.grid, shell_mod.standby("Portal", "not started", "the session starts when you click Start", panel));
            h.p.present();
            h.p.waitEvents(Presenter.forever);
        }
        h.ui.close();
        return .{
            .tunnel_port = std.mem.trim(u8, h.ui.setup.tunnel_port.text(), " "),
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
    /// changes all call notifyThunk). The only timeouts are real
    /// deadlines (an animation, a speech toast). Returns `.finished` once
    /// every tab has ended.
    pub fn run(h: *LocalHost) Ended {
        h.updateTitle();
        const ended: Ended = while (true) {
            if (!h.p.pollEvents(h.shell.sink())) break .window_closed;
            if (h.allEnded()) break .finished;
            const changed = h.checkPairing();
            h.frame(changed);
            // A sub-tab's conversation may animate (scrolling to new
            // items): its real deadline.
            const anim: u32 = if (h.sub_shown != null) (h.convo_view.frameTimeout() orelse Presenter.forever) else Presenter.forever;
            // Speech: a toast ending, the Audio panel's Test (real deadlines).
            const sp: u32 = if (h.speech) |s| (if (s.deadlineMs()) |ms| @intCast(@min(ms, 3600 * 1000)) else Presenter.forever) else Presenter.forever;
            // The usage toast's end.
            const ut: u32 = h.shell.usageDeadline(std.Io.Clock.awake.now(h.io).toMilliseconds()) orelse Presenter.forever;
            h.p.waitEvents(@min(@min(anim, sp), ut));
            h.wakeups += 1;
        };
        h.hide();
        h.stopSpeech();
        h.p.releaseGpu();
        return ended;
    }

    fn nowUnix(h: *const LocalHost) i64 {
        return std.Io.Timestamp.now(h.io, .real).toSeconds();
    }

    /// Applies device store changes reported since the last frame. True if
    /// the panels may look different.
    fn checkPairing(h: *LocalHost) bool {
        if (h.desk == null) return false;
        if (!h.pair_dirty.swap(false, .acq_rel)) return false;
        // The device list (and Settings' peers) follow the store (pairing,
        // `portalctl unpair`, a device forgetting this desktop).
        if (h.ui.screen == .devices or h.ui.screen == .setup) h.loadDevices();
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
        h.p.window.hide();
    }

    fn liveRedraw(ctx: *anyopaque) void {
        const h: *LocalHost = @ptrCast(@alignCast(ctx));
        h.p.reportCapacity(h.shell.sink());
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
            h.shell.select = .{};
            // Its own sub-tabs; none shown.
            h.subs_gen = 0;
            h.sub_shown = null;
        };
        var list_changed = false;
        if (hub.gen != h.list_gen) {
            hub.entriesLocked(&h.list);
            _ = h.projects.notesLocked(hub);
            h.list_gen = hub.gen;
            list_changed = true;
        }
        const projects_changed = hub.projects_gen != h.projects_gen;
        h.projects_gen = hub.projects_gen;
        const changed = if (h.shown) |t| h.sync.sync(h.gpa, &h.grid, &t.session.term) else false;
        // The sub-tabs, and the conversation of the one shown.
        var sub_changed = false;
        var sub_msg: std.Io.Writer.Allocating = .init(h.gpa);
        defer sub_msg.deinit();
        if (h.shown) |t| {
            if (t.subs.gen != h.subs_gen) {
                t.subs.entries(t.id, &h.subs);
                h.subs_gen = t.subs.gen;
                sub_changed = true;
            }
            if (h.sub_shown) |id| {
                if (t.subs.byId(id)) |s| {
                    const cv = &s.convo;
                    if (cv.epoch != h.sub_epoch) {
                        cv.writeSnapshot(&sub_msg.writer, s.id) catch {};
                    } else if (cv.rev != h.sub_rev) {
                        _ = cv.writeSince(&sub_msg.writer, s.id, h.sub_rev) catch {};
                    }
                    h.sub_epoch = cv.epoch;
                    h.sub_rev = cv.rev;
                } else {
                    // It went (the tab's conversation started over).
                    h.sub_shown = null;
                    sub_changed = true;
                }
            }
        } else if (h.subs.len > 0 or h.sub_shown != null) {
            h.subs = .{};
            h.sub_shown = null;
            sub_changed = true;
        }
        h.viewers = hub.viewers;
        var act_changed = false;
        if (hub.activity_gen != h.act_gen or list_changed) {
            hub.activityLocked(&h.act);
            h.act_gen = hub.activity_gen;
            act_changed = true;
        }
        // The plan-usage strip: the desk's own latest values.
        if (!hub.usage.latest.eql(h.usage)) {
            h.usage = hub.usage.latest;
            act_changed = true;
        }
        hub.mutex.unlock(h.io);
        if (h.sys_sub) if (h.desk) |d| if (d.srv.sysmon) |m| if (m.gen.load(.acquire) != h.sys_gen) {
            h.sys_gen = m.latest(&h.sys);
            act_changed = true;
        };
        if (old) |o| o.release();
        if (sub_msg.written().len > 0) {
            h.applySubConvo(sub_msg.written());
            sub_changed = true;
        }
        // Speech: transcripts into the line, the microphone list, toasts.
        const speech_changed = if (h.speech) |s| s.poll(&h.shell) else false;
        // New images become Data items (h.grid is ours: no lock needed).
        if (changed) _ = h.shell.data.sync(h.gpa, &h.grid.images);

        if (changed) h.shell.clampSelection(h.grid.cols, h.grid.rows);
        // The session shows something: the splash may end.
        if (changed and h.shown != null) h.p.splashDone();
        h.shell.touch = client.touchkbd.query();
        if (!force and !changed and !list_changed and !projects_changed and !act_changed and !sub_changed and !speech_changed and old == null and !h.p.needsRedraw() and h.viewers == h.drawn_viewers) return;
        h.drawn_viewers = h.viewers;
        h.updateTitle();

        h.p.build(&h.grid, h.overlay());
        h.p.present();
        h.presents += 1;
        h.convo_view.presented(std.Io.Clock.awake.now(h.io).toMilliseconds());
        // The on-screen keyboard follows the input box (touch, no keyboard).
        if (h.shell.keyboard != h.keyboard_shown) {
            h.keyboard_shown = h.shell.keyboard;
            client.touchkbd.setVisible(h.p.nativeHandle(), h.keyboard_shown);
        }
    }

    /// A `convo` / `convo+` message of the sub-tab shown (written under
    /// the hub's lock from its model): parsed and kept like a device does.
    fn applySubConvo(h: *LocalHost, msg: []const u8) void {
        const scratch = h.gpa.create(convo_wire.Scratch) catch return;
        defer h.gpa.destroy(scratch);
        scratch.text = h.gpa.alloc(u8, msg.len) catch return;
        defer h.gpa.free(scratch.text);
        const m = convo_wire.parse(msg, scratch) orelse return;
        h.sub_convo.apply(h.gpa, m) catch {};
        h.convo_view.sync(&h.sub_convo);
    }

    /// Shows sub-tab `i` of the shown tab (null: its terminal again).
    fn selectSub(h: *LocalHost, i: ?usize) void {
        h.sub_shown = if (i) |j| (if (j < h.subs.len) h.subs.items[j].id else null) else null;
        h.sub_epoch = 0;
        h.sub_rev = 0;
        h.frame(true);
    }

    /// This frame's state for the shell: the tabs, the panel, the
    /// viewers, the remote input policy.
    fn overlay(h: *LocalHost) ui.Overlay {
        const d = h.desk;
        const sp = h.speech;
        const audio_panel: ?ui.frame.Panel = if (sp) |s| s.panel.panel(&s.bufs, s.panelView()) else null;
        var o = h.shell.overlay(.{
            .tabs = h.list.slice(),
            .current = if (h.shown) |t| t.id else null,
            .subs = h.subs.slice(),
            .sub_shown = h.sub_shown,
            .panel = audio_panel orelse h.ui.panel(&h.bufs, .{
                .fingerprint = if (d) |x| x.fingerprint else null,
                .desk_key = if (d) |*x| x.desk_key_text[0..] else "",
                .desk_check = if (d) |*x| x.desk_check[0..] else "",
                .tunnel_port = if (d) |x| x.tunnel_port else 0,
                .now = h.nowUnix(),
            }) orelse h.projectsPanel(),
            .desk = .{
                .title = windowLabel(h.shownName(), &h.label_buf),
                .viewers = h.viewers,
                .policy = h.opts.policy,
                .url = h.opts.url,
                .tools = if (d != null) &desk_tools else &.{},
                .can_add = h.list.len < tabs.max_tabs,
                .notes = h.projects.notes[0..h.projects.n_notes],
            },
            .activity = if (h.hub != null) &h.act else null,
            .sys = if (h.sys_sub and h.sys_gen != 0) &h.sys else null,
            .now = h.nowUnix(),
            .now_ms = std.Io.Clock.awake.now(h.io).toMilliseconds(),
            .utc_offset_s = client.localtime.offsetAt(h.nowUnix()),
            .usage = if (h.usage.week != null or h.usage.five_hour != null) h.usage else null,
        });
        if (sp) |s| if (s.toast()) |t| {
            o.toast = t;
        };
        return o;
    }

    /// The Projects panel, when it is open (refreshed from the hub).
    fn projectsPanel(h: *LocalHost) ?ui.frame.Panel {
        if (!h.projects.panel.open()) return null;
        const hub = h.hub orelse return null;
        h.projects.refresh(hub, h.shown);
        return h.projects.panel.panel(h.projects.view, &h.projects.bufs);
    }

    /// The Projects panel (top bar "Projects", Ctrl+Shift+J).
    fn openProjects(h: *LocalHost) void {
        const hub = h.hub orelse return;
        if (h.desk == null) return;
        if (h.ui.open()) h.ui.close();
        if (h.audioOpen()) h.audioAct(h.speech.?.panel.close());
        h.projects.refresh(hub, h.shown);
        h.projects.panel.show();
        h.frame(true);
    }

    /// Only the Projects panel is open (the others come first).
    fn projectsOnly(h: *const LocalHost) bool {
        return h.projects.panel.open() and !h.ui.open() and !h.audioOpen();
    }

    /// A Projects panel action: settings.txt and the hub (deskprojects).
    fn projectsAct(h: *LocalHost, a: projects_panel.Action) void {
        const hub = h.hub orelse return;
        const d = &(h.desk orelse return);
        h.projects.perform(a, .{ .gpa = h.gpa, .io = h.io, .dir = d.paths.dir, .hub = hub, .shown = h.shown, .saved = &h.desk.?.saved, .env = d.env });
        h.frame(true);
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
        h.p.setTitle(t);
    }


    // ------------------------------------------------------------ desk actions

    fn perform(h: *LocalHost, a: deskui.Action) void {
        switch (a) {
            .none => {},
            .paste => {
                const raw = h.p.window.clipboardText(h.gpa, 4096) orelse return;
                defer h.gpa.free(raw);
                h.ui.paste(raw);
            },
            .setup_submit => {
                if (h.hub == null) {
                    h.setup_submitted = true; // runSetup takes it from here
                } else h.saveSettings();
            },
            .setup_cancel => {},
            .agent_hooks => h.agentHooks(),
            .check_key => {
                const k = tunneldesk.tunnel.keys.parsePublic(h.ui.key_text.text()) orelse
                    return h.ui.setNote(.bad, "That is not a WireGuard public key: 44 characters ending in =, exactly as the device shows it.", .{});
                const d = h.desk orelse return;
                if (std.mem.eql(u8, &k, &d.desk_public)) return h.ui.setNote(.bad, "That is this desktop's own key. Enter the key the device shows.", .{});
                h.ui.keyChecked(tunnelnet.checkCode(&k));
            },
            .approve_pair => h.approvePair(),
            .load_devices => h.loadDevices(),
            .unpair => |i| h.unpair(i),
            .export_ca => h.exportCa(),
            .load_subs => |i| h.loadSubs(i),
            .toggle_sub => |i| h.toggleSub(i),
        }
    }

    /// The owner approved the key's check code: record the device and show
    /// its pairing code. The running tunnel lets the key in as soon as the
    /// store watcher sees the change.
    fn approvePair(h: *LocalHost) void {
        const d = h.desk orelse return;
        const k = tunneldesk.tunnel.keys.parsePublic(h.ui.key_text.text()) orelse return h.ui.pairFailed("The key changed; enter it again.", .{});
        const name = h.ui.name.text();
        const desk: devices.Desk = .{ .gpa = h.gpa, .io = h.io, .paths = d.paths };
        const paired = desk.pair(name, k, d.desk_public) catch |err|
            return h.ui.pairFailed("Could not pair '{s}': {s}.", .{ name, devices.describeError(err) });
        for (paired.replaced.items()) |old| d.srv.log.print("pairing '{s}' replaced the earlier record of '{s}'", .{ name, old.name.get() });
        var ib: [tunnelnet.max_ip_text]u8 = undefined;
        const ip = paired.device.ipText(&ib);
        d.srv.log.print("device '{s}' paired at the desk as {s} (key check code {s})", .{ name, ip, &tunnelnet.checkCode(&k) });
        const endpoint = d.saved.tunnel_endpoint.get() orelse main.placeholder_endpoint;
        const info = main.PairingInfo.make(&d.desk_public, endpoint, d.ca_sha256, &paired.device) catch
            return h.ui.pairFailed("The tunnel endpoint in Settings is too long.", .{});
        h.ui.paired(ip, info.code(), info.desk_check);
        if (d.saved.tunnel_endpoint.get() == null)
            h.ui.setNote(.warn, "Set the tunnel endpoint in Settings (where devices reach this desktop's UDP {d}): the code above has a placeholder.", .{d.tunnel_port});
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
                    var r: deskui.DevRow = .{ .name = dev.name, .last_seen = dev.last_seen };
                    var ib: [tunnelnet.max_ip_text]u8 = undefined;
                    r.ip.set(dev.ipText(&ib));
                    r.key.set(&tunnelnet.checkCode(&dev.key));
                    c.rows[c.n.*] = r;
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
        const desk: devices.Desk = .{ .gpa = h.gpa, .io = h.io, .paths = d.paths };
        const removed = desk.unpair(name) catch |err| {
            h.ui.setNote(.bad, "Could not update the device list: {s}.", .{devices.describeError(err)});
            return;
        };
        // The store watcher sees the change: the key leaves the tunnel and
        // the device's connections end with a logout.
        if (removed != null) d.srv.log.print("device '{s}' unpaired from the Portal window", .{name});
        h.loadDevices();
        h.ui.setNote(.good, "Unpaired '{s}'. Its key is no longer let in; its viewers are disconnected.", .{name});
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
        var pb: [settings.max_port_text]u8 = undefined;
        h.ui.openSetup(false, std.fmt.bufPrint(&pb, "{d}", .{s.tunnelPort()}) catch "", s.program.get() orelse "", s.project.get() orelse "", s.input orelse h.opts.policy);
        h.ui.setup.tunnel_endpoint.set(s.tunnel_endpoint.get() orelse "");
        h.loadDevices(); // the tunnel's peers
        h.ui.setup.sysmon = s.system_monitor orelse false;
        h.ui.setup.bg_art = s.background_art orelse true;
        h.ui.setup.agent = h.agentStatus(false);
    }

    /// The agent's settings.json and the hook command: the installed
    /// launcher (agenthooks.defaultExe).
    fn agentPaths(h: *LocalHost, path: *[]u8, exe: *[]u8) bool {
        const env = (h.desk orelse return false).env;
        path.* = agenthooks.settingsPath(h.gpa, env) catch return false;
        exe.* = agenthooks.defaultExe(h.gpa, env) catch {
            h.gpa.free(path.*);
            return false;
        };
        return true;
    }

    fn agentStatus(h: *LocalHost, note: bool) deskui.AgentHooks {
        var path: []u8 = undefined;
        var exe: []u8 = undefined;
        if (!h.agentPaths(&path, &exe)) return .unreadable;
        defer h.gpa.free(path);
        defer h.gpa.free(exe);
        const r = agenthooks.statusFile(h.gpa, h.io, path, exe) catch |err| {
            if (note) h.ui.setNote(.bad, "Claude Code's settings.json can't be used: {s}.", .{agenthooks.describe(err)});
            return .unreadable;
        };
        return switch (r.state()) {
            .installed => .installed,
            .not_installed => .not_installed,
            .partly => .partly,
            .other_exe => .other_exe,
        };
    }

    /// Settings, "Claude Code integration": install, or remove when
    /// installed. The same code as `portalctl hooks install | uninstall`.
    fn agentHooks(h: *LocalHost) void {
        const before = h.agentStatus(true);
        if (before == .unreadable) {
            h.ui.setup.agent = .unreadable;
            return;
        }
        var path: []u8 = undefined;
        var exe: []u8 = undefined;
        if (!h.agentPaths(&path, &exe)) return;
        defer h.gpa.free(path);
        defer h.gpa.free(exe);
        const op: agenthooks.Op = if (before == .installed) .uninstall else .install;
        const ch = agenthooks.editFile(h.gpa, h.io, path, op, exe) catch |err| {
            h.ui.setNote(.bad, "{s} was not changed: {s}.", .{ path, agenthooks.describe(err) });
            return;
        };
        defer if (ch.backup) |b| h.gpa.free(b);
        h.ui.setup.agent = h.agentStatus(true);
        if (h.desk) |d| d.srv.log.print("settings: Claude Code integration {s}", .{if (op == .install) "installed" else "removed"});
        if (op == .install)
            h.ui.setNote(.good, "Installed. Claude Code sessions in Portal tabs now report their state.{s}", .{if (ch.backup != null) " The previous settings.json is backed up next to it." else ""})
        else
            h.ui.setNote(.good, "Removed. The rest of settings.json is unchanged.", .{});
    }

    /// The Settings panel (during a session): checked, then saved for the
    /// next start.
    fn saveSettings(h: *LocalHost) void {
        const d = &(h.desk orelse return);
        const st = &h.ui.setup;
        const port = std.mem.trim(u8, st.tunnel_port.text(), " ");
        const endpoint = std.mem.trim(u8, st.tunnel_endpoint.text(), " ");
        const program = std.mem.trim(u8, st.program.text(), " ");
        const project = std.mem.trim(u8, st.project.text(), " ");
        if (settings.parsePort(port) == null) return h.ui.setNote(.bad, "The tunnel port must be 1-65535.", .{});
        if (endpoint.len > 0 and !validEndpoint(endpoint))
            return h.ui.setNote(.bad, "The tunnel endpoint is HOST:PORT: a public IP or DNS name, then the UDP port devices reach (e.g. home.example.org:51820).", .{});
        var split_buf: [settings.max_program]u8 = undefined;
        var split_args: [settings.max_args][]const u8 = undefined;
        _ = settings.splitCommand(program, &split_buf, &split_args) catch
            return h.ui.setNote(.bad, "Enter the program to run (quotes must be closed).", .{});
        if (project.len > 0 and !validProject(project))
            return h.ui.setNote(.bad, "The project name must be 1-{d} bytes of printable text.", .{max_project_bytes});
        // Merged into settings.txt as it is now (hand edits stay).
        var s = settings.loadOrNull(h.gpa, h.io, d.paths.dir) orelse d.saved;
        _ = s.tunnel_port.set(port);
        _ = s.tunnel_endpoint.set(endpoint);
        _ = s.program.set(program);
        _ = s.project.set(project);
        s.input = st.input;
        s.system_monitor = st.sysmon;
        s.background_art = st.bg_art;
        settings.save(h.gpa, h.io, d.paths.dir, &s) catch |err|
            return h.ui.setNote(.bad, "Could not save the settings: {t}.", .{err});
        h.desk.?.saved = s;
        // "Show system monitor" applies now: off stops any sampling at
        // once; viewers learn it from the next `activity`.
        if (d.srv.sysmon) |m| m.setEnabled(st.sysmon);
        if (h.hub) |hub| hub.setSysmon(st.sysmon);
        h.p.setBackgroundArt(st.bg_art);
        d.srv.log.print("settings: system monitor {s}", .{if (st.sysmon) "on" else "off"});
        h.ui.close();
    }

    // ------------------------------------------------------------ input

    /// The desk panels as the shell's modal layer: their actions are
    /// performed here.
    fn panelActive(ctx: *anyopaque) bool {
        const h = self(ctx);
        return h.ui.open() or h.audioOpen() or h.projects.panel.open();
    }
    fn panelKey(ctx: *anyopaque, key: input.Key, mods: input.Mods) void {
        const h = self(ctx);
        if (h.audioOpen()) return h.audioAct(h.speech.?.panel.key(key, mods));
        if (h.projectsOnly()) return h.projectsAct(h.projects.panel.key(key, h.projects.view));
        h.perform(h.ui.key(key, mods));
    }
    fn panelChar(ctx: *anyopaque, cp: u21, mods: input.Mods) void {
        const h = self(ctx);
        if (h.audioOpen()) return h.audioAct(h.speech.?.panel.char(cp, mods));
        if (h.projectsOnly()) return; // no text fields, no letter shortcuts
        h.perform(h.ui.char(cp, mods));
    }
    fn panelButton(ctx: *anyopaque, b: u32) void {
        const h = self(ctx);
        if (h.audioOpen()) return h.audioAct(h.speech.?.panel.button(b));
        if (h.projectsOnly()) return h.projectsAct(h.projects.panel.button(b, h.projects.view));
        h.perform(h.ui.button(b));
    }

    fn audioOpen(h: *const LocalHost) bool {
        const s = h.speech orelse return false;
        return s.panel.open();
    }

    /// The Audio panel (top bar "Audio", Ctrl+Shift+A).
    fn openAudio(h: *LocalHost) void {
        const s = h.speech orelse return;
        if (h.ui.open()) h.ui.close();
        h.projects.panel.close();
        s.openPanel();
    }

    /// An Audio panel action; the microphone choice and the model path
    /// are saved with the other settings.
    fn audioAct(h: *LocalHost, a: ui.panels.audio.Action) void {
        const s = h.speech orelse return;
        if (a == .paste) {
            const raw = h.p.window.clipboardText(h.gpa, 4096) orelse return;
            defer h.gpa.free(raw);
            s.panel.paste(raw);
            return;
        }
        const saved = s.act(a);
        const d = &(h.desk orelse return);
        // settings.txt as it is now (the desk may have edited it by hand):
        // only this change is merged in, nothing else is overwritten.
        var st = settings.loadOrNull(h.gpa, h.io, d.paths.dir) orelse d.saved;
        switch (saved) {
            .none => return,
            .reload => {
                // settings.txt again (the desk may have edited it): the
                // speech limits apply now; the rest keeps its own rules.
                const fresh = settings.load(h.gpa, h.io, d.paths.dir);
                s.setLimits(fresh.speech);
                h.desk.?.saved.speech = fresh.speech;
                s.panel.setNote(.good, "Speech limits reloaded from settings.txt.", .{});
                h.frame(true);
                return;
            },
            .mic => |id| if (id) |x| {
                _ = st.mic.set(x);
            } else {
                st.mic = .{};
            },
            .model => |p| _ = st.speech_model.set(p),
            .instruct_mode => |m| {
                st.instruct_mode = m;
                h.shell.instruct_mode = m; // live
            },
            .learning => |on| st.speech_learning = on,
        }
        settings.save(h.gpa, h.io, d.paths.dir, &st) catch |err|
            return s.panel.setNote(.bad, "Could not save the settings: {t}.", .{err});
        h.desk.?.saved = st;
        h.frame(true);
    }

    const host_vtable: shell_mod.Host.VTable = .{
        .key = onKey,
        .char = onChar,
        .answer = onAnswer,
        .send = onSend,
        .command = onCommand,
        .shortcut = onShortcut,
    };

    fn self(ctx: *anyopaque) *LocalHost {
        return @ptrCast(@alignCast(ctx));
    }

    /// The input box's frames ('k:' key names, 't:' text; see inputline)
    /// typed into the local session.
    fn onSend(ctx: *anyopaque, f: []const u8) bool {
        const h = self(ctx);
        const s = h.session() orelse return false;
        if (f.len < 2) return false;
        const body = f[2..];
        switch (f[0]) {
            'k' => s.writeInput(rules.keyBytes(.text, body) orelse return false),
            't' => h.typeText(body),
            else => return false,
        }
        return true;
    }

    /// Types `text` into the session (as a paste when the program asked
    /// for bracketed paste, so it is taken literally).
    fn typeText(h: *LocalHost, text: []const u8) void {
        const s = h.session() orelse return;
        s.mutex.lockUncancelable(s.io);
        const bracketed = s.term.bracketedPaste();
        s.mutex.unlock(s.io);
        if (bracketed) s.writeInput(localinput.paste_start);
        s.writeInput(text);
        if (bracketed) s.writeInput(localinput.paste_end);
    }

    /// A key for the shown tab's terminal: VT bytes.
    fn onKey(ctx: *anyopaque, key: input.Key, mods: input.Mods) void {
        const h = self(ctx);
        const s = h.session() orelse return;
        s.mutex.lockUncancelable(s.io);
        const app_cursor = s.term.appCursor();
        s.mutex.unlock(s.io);
        var buf: [localinput.max_seq]u8 = undefined;
        s.writeInput(localinput.encodeKey(key, mods, app_cursor, &buf));
    }

    fn onChar(ctx: *anyopaque, cp: u21, mods: input.Mods) void {
        const h = self(ctx);
        const s = h.session() orelse return;
        var buf: [localinput.max_seq]u8 = undefined;
        s.writeInput(localinput.encodeChar(cp, mods, &buf));
    }

    /// An answer button: its key, typed into the session.
    fn onAnswer(ctx: *anyopaque, key: []const u8) void {
        const h = self(ctx);
        const s = h.session() orelse return;
        s.writeInput(rules.keyBytes(.text, key) orelse return);
    }

    fn onCommand(ctx: *anyopaque, c: shell_mod.Command) void {
        const h = self(ctx);
        switch (c) {
            .select_tab => |i| h.selectTab(i),
            .select_sub => |i| h.selectSub(i),
            .close_tab => |i| h.closeTab(i),
            .open_tab => h.openTab(),
            .copy => |sel| h.copySelection(sel),
            .paste => h.paste(),
            .pair, .cancel_pair => {},
            .button => |b| switch (b) {
                deskui.id.tb_pair => if (h.desk != null) h.ui.openPair(),
                deskui.id.tb_devices => if (h.desk != null) h.perform(h.ui.openDevices()),
                deskui.id.tb_export => if (h.desk) |d| h.ui.openExport(d.export_default),
                deskui.id.tb_settings => h.openSettings(),
                deskui.id.tb_audio => h.openAudio(),
                projects_panel.id.tool => h.openProjects(),
                else => {},
            },
            // The window decides the PTY size (of every tab); web viewers adapt.
            .resized => |size| if (h.hub) |hub| hub.setSize(.{ .cols = size[0], .rows = size[1] }),
            .usage_slash => |i| h.usageSlash(i),
            .system_panel => |on| h.systemPanel(on),
            // The desk hides no tabs.
            .hidden_changed => {},
        }
    }

    /// The desk's shortcuts (Ctrl+Shift), also while a panel is open
    /// (they switch).
    fn onShortcut(ctx: *anyopaque, cp: u21, _: input.Mods, f: shell_mod.Focus) bool {
        const h = self(ctx);
        if (h.hub == null or h.desk == null) return false;
        switch (cp) {
            't', 'T' => h.openTab(),
            'w', 'W' => if (f == .terminal) h.closeShown() else return false,
            'p', 'P' => h.ui.openPair(),
            'd', 'D' => h.perform(h.ui.openDevices()),
            'e', 'E' => h.ui.openExport(h.desk.?.export_default),
            's', 'S' => h.openSettings(),
            'a', 'A' => h.openAudio(),
            'j', 'J' => h.openProjects(),
            else => return false,
        }
        return true;
    }

    /// The Usage panel's "Open /usage" (desk only): shows tab `i` and types
    /// `/usage` + Enter into it, as the person at the desk would. Plan
    /// limits are only in that screen, never in transcripts; devices are
    /// never offered this (slash commands stay blocked remotely).
    fn usageSlash(h: *LocalHost, i: usize) void {
        const hub = h.hub orelse return;
        if (i >= h.list.len) return;
        hub.mutex.lockUncancelable(h.io);
        const t = hub.acquireLocked(h.list.items[i].id);
        if (t) |tt| hub.desk_active = tt;
        hub.mutex.unlock(h.io);
        const tab = t orelse return;
        defer tab.release();
        hub.log.print("desk: /usage typed into tab '{s}' from the Usage panel", .{tab.name()});
        tab.session.writeInput("/usage");
        tab.session.writeInput("\r");
        h.frame(true);
    }

    /// The System panel opened or closed here: the monitor samples only
    /// while one is open (and only if the setting is on: then subscribe
    /// refuses and nothing is measured).
    fn systemPanel(h: *LocalHost, on: bool) void {
        const d = h.desk orelse return;
        const m = d.srv.sysmon orelse return;
        if (on and !h.sys_sub) {
            h.sys_sub = m.subscribe();
        } else if (!on and h.sys_sub) {
            m.unsubscribe();
            h.sys_sub = false;
            h.sys_gen = 0;
        }
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

    fn copySelection(h: *LocalHost, sel: ui.frame.Selection) void {
        const text = localgrid.selectionText(h.gpa, &h.grid, sel) catch return;
        defer h.gpa.free(text);
        if (text.len > 0) _ = h.p.window.setClipboardText(text);
    }

    fn paste(h: *LocalHost) void {
        const s = h.session() orelse return;
        const raw = h.p.window.clipboardText(h.gpa, max_paste_units) orelse return;
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
        h.shell.select.active = false;
        s.writeInput(buf[0..n]);
    }
};

/// A tunnel endpoint as devices will use it: zwg's own parser decides
/// (an IP literal or a DNS name, a port).
pub fn validEndpoint(text: []const u8) bool {
    _ = @import("WireGuard").device.config.Endpoint.parse(text) catch return false;
    return true;
}



test "validEndpoint" {
    try std.testing.expect(validEndpoint("home.example.org:51820"));
    try std.testing.expect(validEndpoint("203.0.113.7:51820"));
    try std.testing.expect(validEndpoint("[2001:db8::1]:51820"));
    try std.testing.expect(!validEndpoint("home.example.org"));
    try std.testing.expect(!validEndpoint("home example:1"));
    try std.testing.expect(!validEndpoint("h:0"));
}
