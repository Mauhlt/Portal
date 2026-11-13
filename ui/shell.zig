//! The Portal screen: what every device's window shows around and in the
//! main slice, and what its input means. One shell, parameterised by
//! `Device`:
//!
//!   .desk     the desktop's own window: tabs with close boxes and "+",
//!             the desk tools in the top bar, the remote-viewer badge, the
//!             input box with full control (click it to type there), cell
//!             selection with copy and paste.
//!   .viewer   a paired device (`portal connect`, the iPhone app): tabs it
//!             can only switch, the Terminal | Conversation view toggle,
//!             the pairing / trust / ended screens, the instruction line
//!             per the desktop's input mode (module "inputrules").
//!
//! Devices open on the Conversation view (ui/convoview.zig) in its minimal
//! form: top bar, the conversation (questions carry their own controls:
//! swipe cards for two options, numbered buttons for more), the Data
//! strip, and at the bottom only Instruct (the instruction line + Send, and
//! dictation once a device has it: `toggleDictation`). No answer keys at
//! all there: Esc and Enter live in the Terminal view (the power mode),
//! which keeps the full answer bar and, in `instruct` mode, the line. The
//! desk keeps the terminal.
//!
//! Layout (frame.zig): top bar (+ tabs), main slice (a pluggable content
//! view: the terminal, or the conversation once a device provides one),
//! Data slice, interaction slice (answers, input box + Send), status line,
//! with the device's panels (desk panels, sync panels, ...) as a modal
//! layer.
//!
//! On both: each tab's badge counts its running background tasks, the
//! status line says what runs in the tab shown, and the top bar's Usage
//! (and, while the desk's "Show system monitor" is on, System) open the
//! status panels (panels/status.zig), which the shell owns: they stay
//! open until closed and take the keyboard like any panel. The desk's
//! Usage panel offers "Open /usage" per tab (Command.usage_slash); a
//! device's never does.
//!
//! The device's glue feeds a `State` each frame (`overlay`) and receives
//! what input means through `Host`: terminal keys and characters, answer
//! keys, input-line frames and `Command`s (switch / close / open a tab,
//! copy, paste, pair, the device's own buttons). The keyboard goes to one
//! place at a time (`focus`): an open panel, the pairing screens, the input
//! line, or the terminal.

const std = @import("std");
const rules = @import("inputrules");
const tabs_wire = @import("shared").tabs;
const theme = @import("shared").theme;
const frame = @import("frame.zig");
const input = @import("input.zig");
const inputline = @import("inputline.zig");
const dataview = @import("dataview.zig");
const activity_wire = @import("shared").activity;
const sysinfo = @import("shared").sysinfo;
const status_panels = @import("panels/status.zig");

pub const Device = enum { desk, viewer };

/// Ids of the shell's own controls, clear of the panels' ranges (desk
/// panels 1-13, 100-279; setup 1-101; sync 301-699; status panels
/// 1500-1521; content view 1300-1399). Ids it doesn't know
/// go to the host (Command.button), e.g. the desk tools.
pub const ids = struct {
    pub const line: u32 = 900;
    pub const send: u32 = 901;
    pub const data_toggle: u32 = 902;
    pub const data_clear: u32 = 903;
    pub const tab_add: u32 = 904;
    pub const view_terminal: u32 = 905;
    pub const view_conversation: u32 = 906;
    pub const pair: u32 = 907;
    pub const cancel_pair: u32 = 908;
    /// The interaction bar's on-screen keyboard button (touch).
    pub const keyboard: u32 = 909;
    /// The Conversation view's bottom row: open the instruction line (and
    /// dictation), show the full answer bar.
    pub const instruct: u32 = 910;
    /// The content view's own buttons (ui/convoview.zig ids).
    pub const view0: u32 = 1300;
    pub const view_last: u32 = 1399;
    /// The top bar's Usage and System, the status line's task summary.
    pub const usage: u32 = 913;
    pub const system: u32 = 914;
    pub const tasks: u32 = 915;
    /// badge0 + position: that tab's background-task badge.
    pub const badge0: u32 = 1200;
    /// tab0 + position: show that tab; close0 + position: close it.
    pub const tab0: u32 = 1000;
    pub const close0: u32 = 1100;
};

/// What the main slice shows (the top bar's view toggle on devices).
pub const MainView = enum { terminal, conversation };

/// A connection's state as the viewer shows it (the network client's
/// statuses, mapped by name in the device glue).
pub const Status = enum {
    starting,
    need_pairing,
    pairing,
    pair_waiting,
    pair_closed,
    refreshing,
    connecting,
    connected,
    retrying,
    session_ended,
    desktop_offline,
    network_error,
    store_unavailable,
    /// Off screen (iOS background): no connection until it is back.
    paused,
};

/// The user-facing sentences for the session-ended and offline states.
pub fn endedText(code: i64, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "Session ended on the desktop (exit code {d})", .{code}) catch "Session ended on the desktop";
}
pub const offline_text = "Desktop offline \u{2014} reconnects automatically";

pub fn statusWord(st: Status) []const u8 {
    return switch (st) {
        .starting => "starting",
        .need_pairing, .pair_closed => "not paired",
        .pairing => "pairing",
        .pair_waiting => "waiting for the desk",
        .refreshing => "signing in",
        .connecting => "connecting",
        .connected => "connected",
        .retrying => "reconnecting",
        .session_ended => "session ended",
        .desktop_offline => "desktop offline",
        .network_error => "network error",
        .store_unavailable => "credential store unavailable",
        .paused => "paused",
    };
}

/// A device's window title: "Portal — <project> — <status>" (the tab
/// shown), or "Portal — <status>" before the desktop has said. No
/// addresses: the status line shows the host.
pub fn title(st: Status, project: ?[]const u8, buf: []u8) []const u8 {
    if (project) |p| return std.fmt.bufPrint(buf, "Portal \u{2014} {s} \u{2014} {s}", .{ p, statusWord(st) }) catch "Portal";
    return std.fmt.bufPrint(buf, "Portal \u{2014} {s}", .{statusWord(st)}) catch "Portal";
}

/// "no remote viewers", "1 REMOTE VIEWER WATCHING", ...
pub fn viewerText(n: u32, buf: []u8) []const u8 {
    if (n == 0) return "no remote viewers";
    return std.fmt.bufPrint(buf, "{d} REMOTE VIEWER{s} WATCHING", .{ n, if (n == 1) "" else "S" }) catch "REMOTE VIEWERS WATCHING";
}

/// Before there is a session or a connection (a first-run panel): an
/// optional bar with `bar_title`, a status line saying why nothing runs
/// yet, and the panel.
pub fn standby(bar_title: ?[]const u8, label: []const u8, extra: []const u8, panel: ?frame.Panel) frame.Overlay {
    return .{
        .top_bar = if (bar_title) |t| .{ .title = t } else null,
        .status = .{ .tone = .warn, .label = label, .extra = extra },
        .panel = panel,
    };
}

/// What the device's input hardware offers (the glue asks the OS each
/// frame; client/src/touchkbd.zig on Windows).
pub const Touch = struct {
    /// A touch screen: finger-sized targets.
    enabled: bool = false,
    /// No hardware keyboard attached (tablet posture): offer the on-screen
    /// keyboard (a button in the interaction bar; shown when the input line
    /// is tapped, hidden when it loses the keyboard).
    on_screen_keyboard: bool = false,
};

/// What the desk's window shows besides the tabs.
pub const Desk = struct {
    /// The top bar's text when there are no tabs yet.
    title: []const u8 = "Portal",
    /// Remote viewers watching now.
    viewers: u32 = 0,
    /// What paired devices may type (--input).
    policy: rules.Policy = .keys,
    /// e.g. "https://10.8.0.1:8420/" (the status line).
    url: []const u8 = "",
    /// The desk tools (Pair a device…, Devices, ...): clicks go to the
    /// host as Command.button(id).
    tools: []const frame.TopButton = &.{},
    /// Room for another tab ("+").
    can_add: bool = true,
};

/// What a device's window shows about its connection.
pub const Viewer = struct {
    status: Status = .starting,
    /// The desktop's input mode (hello's `input`; null before hello).
    mode: ?rules.Policy = null,
    detail: []const u8 = "",
    /// The desktop's address (status line).
    host: []const u8 = "",
    /// A picture of the terminal exists.
    has_grid: bool = false,
    /// The request code while waiting for the desk.
    code: ?[4]u8 = null,
    /// The connection error's description when it is a trust error (not
    /// the Portal we pinned, or not Portal's TLS).
    trust_error: ?[]const u8 = null,
    /// The ended session's exit code, kept while the desktop is offline.
    exit_code: ?i64 = null,
    /// "AB:CD:..." of the pinned Portal CA ("" without TLS).
    pin_fp: []const u8 = "",
};

/// One frame's input from the device glue.
pub const State = struct {
    /// The open project tabs and the one shown (protocol v2 / the hub).
    tabs: []const tabs_wire.Entry = &.{},
    current: ?tabs_wire.Id = null,
    /// The device's modal panel to draw now, if any.
    panel: ?frame.Panel = null,
    desk: Desk = .{},
    viewer: Viewer = .{},
    /// Every tab's background tasks and usage (`activity`); null: not
    /// known (no Usage button, no badges).
    activity: ?*const activity_wire.Activity = null,
    /// The latest system monitor sample, if any.
    sys: ?*const sysinfo.Snapshot = null,
    /// Unix seconds now (task ages in the panel).
    now: i64 = 0,
};

/// Who gets the keyboard, decided here only. `view`: the Conversation view
/// on a device (scrolling and its cards' keys; nothing reaches the
/// terminal from there).
pub const Focus = enum { panel, pair_screen, wait_screen, line, terminal, view };

/// Where a device's speech-to-text plugs in (future: Portal's mic capture
/// from ../Audio, then stt, typing into the instruction line for review;
/// the user sends). Dictation toggles: `start`, then `stop`.
pub const Dictation = struct {
    ctx: *anyopaque,
    start: *const fn (ctx: *anyopaque) void,
    stop: *const fn (ctx: *anyopaque) void,
};

/// Whether a headset with a microphone is attached (the audio work
/// implements it: ../Audio, IMMDevice form factor). Its media button
/// toggles dictation only then.
pub const HeadsetMic = struct {
    ctx: ?*anyopaque = null,
    present: *const fn (ctx: ?*anyopaque) bool,
};

pub const Command = union(enum) {
    /// Show / close the tab at top-bar position i; open a new one (desk).
    select_tab: usize,
    close_tab: usize,
    open_tab,
    /// Copy the selected cells (desk), paste the clipboard into the terminal.
    copy: frame.Selection,
    paste,
    /// The pairing screen's Pair, and Cancel while waiting (devices).
    pair,
    cancel_pair,
    /// A button the shell doesn't own (the desk tools).
    button: u32,
    /// The cells that fit the main slice changed (desk: the PTY's size).
    resized: [2]u16,
    /// Desk only: type `/usage` + Enter into the tab at bar position i
    /// (the Usage panel's "Open /usage"; plan limits are only there).
    usage_slash: usize,
    /// The System panel opened (true) or closed: the glue subscribes to
    /// the system monitor (desk) or sends `y:on` / `y:off` (devices).
    system_panel: bool,
};

/// The device's side: what the shell's input turns into.
pub const Host = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// A key / character for the shown tab's terminal (desk: VT bytes
        /// to the PTY; devices: a protocol frame per the input mode).
        key: *const fn (ctx: *anyopaque, k: input.Key, m: input.Mods) void,
        char: *const fn (ctx: *anyopaque, cp: u21, m: input.Mods) void,
        /// An answer button (a protocol key name).
        answer: *const fn (ctx: *anyopaque, key: []const u8) void,
        /// An input-line frame ("k:<key>", "t:<text>", "l:<line>"); false
        /// if it could not be delivered.
        send: *const fn (ctx: *anyopaque, frame: []const u8) bool,
        command: *const fn (ctx: *anyopaque, c: Command) void,
        /// The device's own Ctrl+Shift shortcuts; true: consumed.
        shortcut: *const fn (ctx: *anyopaque, cp: u21, m: input.Mods, focus: Focus) bool,
    };
};

/// A modal layer (the device's panels): while `active` it has the
/// keyboard and its buttons.
pub const Modal = struct {
    ctx: *anyopaque,
    active: *const fn (ctx: *anyopaque) bool,
    key: *const fn (ctx: *anyopaque, k: input.Key, m: input.Mods) void,
    char: *const fn (ctx: *anyopaque, cp: u21, m: input.Mods) void,
    button: *const fn (ctx: *anyopaque, id: u32) void,
};

/// Cell selection being made with the mouse (anchor = where the drag began).
pub const Select = struct {
    anchor: [2]u16 = .{ 0, 0 },
    head: [2]u16 = .{ 0, 0 },
    dragging: bool = false,
    /// True once the pointer moved off the anchor cell (a plain click
    /// selects nothing).
    active: bool = false,

    pub fn range(s: Select) ?frame.Selection {
        if (!s.active) return null;
        const a = s.anchor;
        const b = s.head;
        const a_first = a[1] < b[1] or (a[1] == b[1] and a[0] <= b[0]);
        const lo = if (a_first) a else b;
        const hi = if (a_first) b else a;
        return .{ .start_col = lo[0], .start_row = lo[1], .end_col = hi[0], .end_row = hi[1] };
    }
};

pub const Shell = struct {
    gpa: std.mem.Allocator,
    device: Device,
    host: Host,
    modal: ?Modal = null,
    /// The interaction slice's input line: `text` policy on the desk (full
    /// control), `instruct` checks on devices.
    line: inputline.Line,
    /// Desk: the input box has the keyboard (a click on it; Esc on an
    /// empty box or a click elsewhere gives it back to the terminal).
    /// Devices: the line has it whenever the mode is `instruct`.
    line_focus: bool = false,
    data: dataview.DataView = .{},
    select: Select = .{},
    /// What the main slice shows: the terminal on the desk, the
    /// conversation on devices (the owner's default; the top bar toggles).
    main: MainView = .terminal,
    /// The conversation view, once the device has one (ui/convoview).
    conversation: ?frame.ContentView = null,
    /// The last overlay showed the conversation view (its input routing).
    view_shown: bool = false,
    /// Conversation view on a device: the instruction line is open
    /// (Instruct).
    instructing: bool = false,
    /// Speech-to-text, when the device has it (toggleDictation).
    dictation: ?Dictation = null,
    /// Dictation is running (the bottom row shows "Listening…").
    dictating: bool = false,
    /// The headset predicate (headsetMicPresent); none yet: false.
    headset_mic: ?HeadsetMic = null,
    /// Set by the glue from the OS (Touch).
    touch: Touch = .{},
    /// The on-screen keyboard should be up: the glue shows or hides the
    /// OS keyboard when this changes (after a frame).
    keyboard: bool = false,
    /// As of the last overlay: the viewer's status and mode, the tab count
    /// and the one shown.
    status: Status = .starting,
    mode: ?rules.Policy = null,
    n_tabs: usize = 0,
    shown: ?usize = null,
    /// The status panel open (panels/status.zig), and the tab whose badge
    /// opened it.
    info: status_panels.Screen = .none,
    info_first: ?tabs_wire.Id = null,
    /// The tabs' ids as of the last overlay (badge clicks name a position).
    tab_ids: [tabs_wire.max_tabs]tabs_wire.Id = undefined,
    bufs: Bufs = .{},

    const Bufs = struct {
        txt: [4][200]u8 = undefined,
        lines: [4][]const u8 = undefined,
        title: [48]u8 = undefined,
        extra: [256]u8 = undefined,
        right: [128]u8 = undefined,
        panes: [2]frame.Pane = undefined,
        row: [2]frame.PanelButton = undefined,
        top_tabs: [tabs_wire.max_tabs]frame.TopTab = undefined,
        buttons: [8]frame.TopButton = undefined,
        badges: [tabs_wire.max_tabs][8]u8 = undefined,
        tasks: [64]u8 = undefined,
        info: status_panels.Bufs = .{},
    };

    pub fn init(gpa: std.mem.Allocator, device: Device, host: Host) Shell {
        return .{
            .gpa = gpa,
            .device = device,
            .host = host,
            .line = .{ .policy = if (device == .desk) .text else .instruct },
            .main = if (device == .viewer) .conversation else .terminal,
        };
    }

    pub fn deinit(sh: *Shell) void {
        sh.data.deinit(sh.gpa);
    }

    fn modalActive(sh: *const Shell) ?Modal {
        const m = sh.modal orelse return null;
        return if (m.active(m.ctx)) m else null;
    }

    pub fn focus(sh: *const Shell) Focus {
        if (sh.modalActive() != null or sh.info != .none) return .panel;
        switch (sh.device) {
            .desk => return if (sh.line_focus) .line else .terminal,
            .viewer => {
                if (sh.status == .need_pairing or sh.status == .pair_closed) return .pair_screen;
                if (sh.status == .pairing or sh.status == .pair_waiting) return .wait_screen;
                return viewerFocus(sh.main == .conversation and sh.conversation != null, sh.status, sh.mode, sh.instructing);
            },
        }
    }

    fn viewerFocus(conversation: bool, st: Status, mode: ?rules.Policy, instructing: bool) Focus {
        if (conversation) return if (st == .connected and mode == .instruct and instructing) .line else .view;
        if (st == .connected and mode == .instruct) return .line;
        return .terminal;
    }

    /// Instruct: opens the instruction line with the keyboard (the touch
    /// keyboard on a tablet without one) and starts dictation when the
    /// device has it. Esc, or a sent line, closes it again.
    pub fn startDictation(sh: *Shell) void {
        if (sh.device != .viewer or sh.mode != .instruct) return;
        sh.instructing = true;
        if (sh.touch.on_screen_keyboard) sh.keyboard = true;
        if (sh.dictating) return;
        if (sh.dictation) |d| {
            d.start(d.ctx);
            sh.dictating = true;
        }
    }

    /// Stops dictation; its text stays in the line for review.
    pub fn stopDictation(sh: *Shell) void {
        if (!sh.dictating) return;
        sh.dictating = false;
        if (sh.dictation) |d| d.stop(d.ctx);
    }

    /// The `toggle_dictation` action (Space with no text field focused,
    /// the Instruct / Listening button, a headset's media button).
    pub fn toggleDictation(sh: *Shell) void {
        if (sh.dictating) sh.stopDictation() else sh.startDictation();
    }

    /// A headset with a microphone is attached (false until the audio
    /// work provides the predicate).
    pub fn headsetMicPresent(sh: *const Shell) bool {
        const h = sh.headset_mic orelse return false;
        return h.present(h.ctx);
    }

    fn closeInstruct(sh: *Shell) void {
        sh.stopDictation();
        sh.instructing = false;
        sh.keyboard = false;
    }

    /// The server refused an instruction line ({"t":"rejected"}).
    pub fn rejected(sh: *Shell, reason: []const u8) void {
        sh.line.rejected(reason);
    }

    /// The grid changed size: keep the selection on it.
    pub fn clampSelection(sh: *Shell, cols: u16, rows: u16) void {
        if (cols == 0 or rows == 0) {
            sh.select = .{};
            return;
        }
        for ([_]*[2]u16{ &sh.select.anchor, &sh.select.head }) |p| {
            p[0] = @min(p[0], cols - 1);
            p[1] = @min(p[1], rows - 1);
        }
    }

    // ------------------------------------------------------------ overlay

    /// The frame's description for `st`. Strings live in the shell, the
    /// line, the data view and `st`.
    pub fn overlay(sh: *Shell, st: State) frame.Overlay {
        sh.status = st.viewer.status;
        sh.mode = st.viewer.mode;
        sh.n_tabs = 0;
        sh.shown = null;
        if (sh.mode != .instruct and sh.instructing) sh.closeInstruct();
        // A status panel needs what it shows: System the desk's setting,
        // any of them a connection (devices).
        const sysmon = if (st.activity) |a| a.sysmon else false;
        const live = sh.device == .desk or st.viewer.status == .connected;
        if (!live or st.activity == null) sh.setInfo(.none) else if (sh.info == .system and !sysmon) sh.setInfo(.none);
        var o = switch (sh.device) {
            .desk => sh.deskOverlay(st),
            .viewer => sh.viewerOverlay(st),
        };
        sh.view_shown = o.screen == .view;
        o.panel = st.panel;
        if (o.panel == null) o.panel = status_panels.panel(sh.info, .{
            .desk = sh.device == .desk,
            .tabs = st.tabs,
            .first = sh.info_first,
            .activity = st.activity,
            .sys = st.sys,
            .now = st.now,
        }, &sh.bufs.info);
        if (o.panel != null) o.selection = null;
        o.touch = sh.touch.enabled;
        // The keyboard goes when the line loses the keyboard (or a hardware
        // one is attached).
        if (sh.keyboard and (!sh.touch.on_screen_keyboard or sh.focusFor(st) != .line)) sh.keyboard = false;
        return o;
    }

    /// `focus` as of `st` (without asking the modal: the glue may hold its
    /// lock while building the overlay).
    fn focusFor(sh: *const Shell, st: State) Focus {
        if (st.panel != null or sh.info != .none) return .panel;
        return switch (sh.device) {
            .desk => if (sh.line_focus) .line else .terminal,
            .viewer => viewerFocus(sh.main == .conversation and sh.conversation != null, st.viewer.status, st.viewer.mode, sh.instructing),
        };
    }

    fn tabBar(sh: *Shell, st: State, closable: bool) []const frame.TopTab {
        const n = @min(st.tabs.len, sh.bufs.top_tabs.len);
        for (st.tabs[0..n], 0..) |*e, i| {
            const active = if (st.current) |id| std.mem.eql(u8, &id, &e.id) else false;
            if (active) sh.shown = i;
            sh.tab_ids[i] = e.id;
            const act: ?*const activity_wire.Tab = if (st.activity) |a| a.find(e.id) else null;
            sh.bufs.top_tabs[i] = .{
                .label = e.name(),
                .color = theme.fromU32(e.color),
                .active = active,
                .attention = e.state.attention(),
                .id = ids.tab0 + @as(u32, @intCast(i)),
                .close_id = if (closable) ids.close0 + @as(u32, @intCast(i)) else null,
                .badge = if (act) |t| status_panels.badgeText(t, &sh.bufs.badges[i]) else "",
                .badge_id = ids.badge0 + @as(u32, @intCast(i)),
            };
        }
        sh.n_tabs = n;
        return sh.bufs.top_tabs[0..n];
    }

    /// "2 shells · 1 monitor" for the tab shown ("" if nothing runs).
    fn shownTasks(sh: *Shell, st: State) []const u8 {
        const a = st.activity orelse return "";
        const id = st.current orelse return "";
        const t = a.find(id) orelse return "";
        return status_panels.tasksText(t, &sh.bufs.tasks);
    }

    /// The top bar's status buttons after `before` (Usage; System while
    /// the desk's setting is on), in `bufs.buttons`.
    fn statusButtons(sh: *Shell, st: State, before: []const frame.TopButton) []const frame.TopButton {
        var n: usize = 0;
        for (before) |b| if (n < sh.bufs.buttons.len) {
            sh.bufs.buttons[n] = b;
            n += 1;
        };
        if (st.activity) |a| {
            if (n < sh.bufs.buttons.len) {
                sh.bufs.buttons[n] = .{ .label = "Usage", .id = ids.usage, .active = sh.info == .usage };
                n += 1;
            }
            if (a.sysmon and n < sh.bufs.buttons.len) {
                sh.bufs.buttons[n] = .{ .label = "System", .id = ids.system, .active = sh.info == .system };
                n += 1;
            }
        }
        return sh.bufs.buttons[0..n];
    }

    /// Opens (or closes) a status panel; the System panel's opening and
    /// closing go to the host (the monitor samples only while one is open).
    fn setInfo(sh: *Shell, to: status_panels.Screen) void {
        if (sh.info == to) return;
        const was_sys = sh.info == .system;
        sh.info = to;
        if (to == .none) sh.info_first = null;
        if (was_sys) sh.command(.{ .system_panel = false });
        if (to == .system) sh.command(.{ .system_panel = true });
    }

    fn toggleInfo(sh: *Shell, to: status_panels.Screen, first: ?tabs_wire.Id) void {
        if (sh.info == to and (first == null or sh.info_first == null or std.mem.eql(u8, &first.?, &sh.info_first.?))) return sh.setInfo(.none);
        sh.info_first = first;
        sh.setInfo(to);
    }

    fn linePane(sh: *Shell, hint: []const u8, focused: bool) []const frame.Pane {
        sh.bufs.panes[0] = sh.lineField(hint, focused);
        return sh.bufs.panes[0..1];
    }

    fn lineField(sh: *Shell, hint: []const u8, focused: bool) frame.Pane {
        return .{ .content = .{ .field = .{
            .label = "",
            .value = sh.line.text(),
            .hint = hint,
            .id = ids.line,
            .focused = focused,
        } }, .send = .{ .label = "Send", .id = ids.send }, .keyboard = if (sh.touch.on_screen_keyboard) .{ .label = "Keyboard", .id = ids.keyboard, .focused = sh.keyboard } else null };
    }

    /// The Conversation view's bottom (devices): the Instruct button, or
    /// the open instruction line (with its dictation toggle).
    fn conversationBottom(sh: *Shell, mode: rules.Policy) []const frame.Pane {
        const b = &sh.bufs;
        if (sh.instructing and mode == .instruct) {
            var n: usize = 0;
            // With speech-to-text: its toggle, and the recording indicator.
            if (sh.dictation != null) {
                b.row[0] = if (sh.dictating)
                    .{ .label = "\u{25CF} Listening\u{2026}  (stop)", .id = ids.instruct, .tone = .bad }
                else
                    .{ .label = "\u{1F3A4} Dictate", .id = ids.instruct, .tone = .good };
                b.panes[n] = .{ .content = .{ .buttons = b.row[0..1] } };
                n += 1;
            }
            b.panes[n] = sh.lineField(if (sh.dictating) "Listening \u{2014} the text lands here; Send when ready (Esc closes)" else if (sh.dictation != null) "Type, or Dictate (Esc closes)" else "Type an instruction, then Enter or Send (Esc closes) \u{00B7} speech coming soon", true);
            n += 1;
            return b.panes[0..n];
        }
        var n: usize = 0;
        if (mode == .instruct) {
            b.row[n] = .{ .label = "\u{1F3A4} Instruct", .id = ids.instruct, .tone = .good };
            n += 1;
        }
        if (n == 0) return &.{};
        b.panes[0] = .{ .content = .{ .buttons = b.row[0..n] } };
        return b.panes[0..1];
    }

    fn noteTone(t: rules.Tone) frame.Tone {
        return switch (t) {
            .neutral => .normal,
            .ok => .good,
            .bad => .bad,
        };
    }

    fn deskOverlay(sh: *Shell, st: State) frame.Overlay {
        const d = st.desk;
        const watching = d.viewers > 0;
        const remote_input: []const u8 = switch (d.policy) {
            .none => "remote: view only",
            .keys => "remote: answer keys only",
            .instruct => "remote: answer keys + checked instructions",
            .text => "remote: FULL CONTROL",
        };
        const lv = sh.line.snapshot();
        const line_note = sh.line_focus and lv.note.len > 0;
        return .{
            .data = sh.data.slice(ids.data_toggle, ids.data_clear),
            .show_answers = true,
            .bottom = sh.linePane(if (sh.line_focus) "Type, then Enter or Send (Esc: back to the terminal)" else "Click here to type an instruction (keys go to the terminal)", sh.line_focus),
            .top_bar = .{
                .title = d.title,
                .tabs = sh.tabBar(st, true),
                .add_id = if (d.can_add) ids.tab_add else null,
                .right = viewerText(d.viewers, &sh.bufs.right),
                .right_tone = if (watching) .warn else .muted,
                .right_badge = watching,
                .buttons = sh.statusButtons(st, d.tools),
            },
            .selection = sh.select.range(),
            .status = .{
                .tone = .good,
                .label = "local session",
                .extra = if (line_note) lv.note else remote_input,
                .extra_tone = if (line_note) noteTone(lv.note_tone) else if (d.policy == .text) .bad else .muted,
                .right = std.fmt.bufPrint(&sh.bufs.extra, "sharing on {s}", .{d.url}) catch d.url,
                .tasks = sh.shownTasks(st),
                .tasks_id = ids.tasks,
            },
        };
    }

    const pair_lines = [_][]const u8{
        "1. At the desktop, in the Portal window: Pair a device\u{2026} (Ctrl+Shift+P).",
        "   (In a terminal there: portalctl pair <name>.)",
        "2. Within 2 minutes, click Pair below (or press P). The desk then approves this device.",
    };

    fn viewerOverlay(sh: *Shell, st: State) frame.Overlay {
        const v = st.viewer;
        const b = &sh.bufs;
        var o: frame.Overlay = .{};
        const s = v.status;
        o.status = .{
            .label = statusWord(s),
            .right = v.host,
            .tone = switch (s) {
                .connected => .good,
                .need_pairing, .pair_closed, .store_unavailable => .bad,
                else => .warn,
            },
        };
        switch (s) {
            .need_pairing, .pair_closed => {
                o.screen = .{ .message = .{
                    .title = "Pair this device",
                    .lines = &pair_lines,
                    .button = .{ .label = "Pair", .id = ids.pair },
                    .detail = v.detail,
                    .detail_tone = if (s == .pair_closed) .warn else .muted,
                } };
                return o;
            },
            .pairing, .pair_waiting => {
                const t = if (v.code) |c| std.fmt.bufPrint(&b.title, "Request code {s}", .{&c}) catch "Waiting for the desk" else "Asking the desk\u{2026}";
                var n: usize = 0;
                b.lines[n] = "Waiting for approval in the Portal window on the desktop.";
                n += 1;
                if (v.code) |c| {
                    b.lines[n] = std.fmt.bufPrint(&b.txt[0], "Approve it there only if the desk shows the same code, {s}.", .{&c}) catch "";
                    n += 1;
                }
                b.lines[n] = "Press Esc to stop waiting.";
                n += 1;
                o.screen = .{ .message = .{
                    .title = t,
                    .title_tone = .warn,
                    .lines = b.lines[0..n],
                    .button = .{ .label = "Cancel", .id = ids.cancel_pair },
                    .detail = v.detail,
                } };
                return o;
            },
            .store_unavailable => {
                o.screen = .{ .message = .{ .title = "Cannot store the device credential", .title_tone = .bad, .detail = v.detail } };
                return o;
            },
            // A clear end state instead of the last picture behind a status
            // word: what ended, and whether the desktop is still there.
            .session_ended, .desktop_offline => {
                const t = if (v.exit_code) |code| endedText(code, &b.txt[3]) else offline_text;
                b.lines[0] = if (s == .session_ended)
                    "Waiting for the desktop to start a new session."
                else if (v.exit_code != null)
                    offline_text ++ "."
                else
                    "Portal is not answering on the desktop; this window resumes when it runs again.";
                o.screen = .{ .message = .{ .title = t, .title_tone = .warn, .lines = b.lines[0..1] } };
                return o;
            },
            .connected => if (v.mode) |mode| {
                o.show_answers = mode.acceptsAnswers();
                o.status.extra = mode.label();
                o.status.extra_tone = if (mode == .text) .warn else .normal;
                // The Conversation view: questions carry their own controls;
                // the answer bar and the line come on request.
                const minimal = sh.main == .conversation and sh.conversation != null and v.has_grid;
                if (minimal) {
                    o.show_answers = false;
                    o.bottom = sh.conversationBottom(mode);
                }
                if (mode == .instruct) {
                    if (!minimal) o.bottom = sh.linePane(rules.placeholder(.instruct), true);
                    const lv = sh.line.snapshot();
                    if (lv.note.len > 0) {
                        o.status.extra = std.fmt.bufPrint(&b.extra, "{s}: {s}", .{ mode.label(), lv.note }) catch mode.label();
                        o.status.extra_tone = noteTone(lv.note_tone);
                    }
                }
            },
            else => o.status.extra = v.detail,
        }
        // Certificate / pinning trouble: say so in the window, prominently,
        // instead of retrying silently behind an old picture.
        if (s != .connected) if (v.trust_error) |why| {
            var n: usize = 0;
            b.lines[n] = std.fmt.bufPrint(&b.txt[0], "{s}.", .{why}) catch "";
            n += 1;
            if (v.pin_fp.len > 0) {
                b.lines[n] = std.fmt.bufPrint(&b.txt[1], "Trusted for {s}: the Portal CA with SHA-256 {s}", .{ v.host, v.pin_fp }) catch "";
                n += 1;
            }
            b.lines[n] = std.fmt.bufPrint(&b.txt[2], "If the desktop's CA was replaced: portal connect --server {s} --forget, then pair again with its new certificate.", .{v.host}) catch "";
            n += 1;
            o.screen = .{ .message = .{
                .title = "Cannot verify this Portal",
                .title_tone = .bad,
                .lines = b.lines[0..n],
                .detail = v.detail,
                .detail_tone = .warn,
            } };
            o.status.tone = .bad;
            return o;
        };
        // The tabs (connected only): a device switches, never opens or closes.
        if (s == .connected and st.tabs.len > 0) {
            const toggle = [_]frame.TopButton{
                .{ .label = "Terminal", .id = ids.view_terminal, .active = sh.main == .terminal },
                .{ .label = "Conversation", .id = ids.view_conversation, .active = sh.main == .conversation },
            };
            o.top_bar = .{ .tabs = sh.tabBar(st, false), .buttons = sh.statusButtons(st, &toggle) };
            o.status.tasks = sh.shownTasks(st);
            o.status.tasks_id = ids.tasks;
        }
        if (!v.has_grid) {
            o.screen = .{ .message = .{ .title = statusWord(s), .title_tone = .muted, .detail = v.detail } };
            return o;
        }
        o.data = sh.data.slice(ids.data_toggle, ids.data_clear);
        if (sh.main == .conversation) o.screen = if (sh.conversation) |c| .{ .view = c } else .{ .message = .{
            .title = "Conversation",
            .title_tone = .muted,
            .lines = &.{"The conversation view is not available from this desktop yet."},
            .detail = "Terminal (in the top bar) shows the session.",
        } };
        return o;
    }

    // ------------------------------------------------------------ input

    pub fn sink(sh: *Shell) input.InputSink {
        return .{ .ctx = sh, .vtable = &sink_vtable };
    }

    const sink_vtable: input.InputSink.VTable = .{
        .key = onKey,
        .char = onChar,
        .answer = onAnswer,
        .button = onButton,
        .resized = onResized,
        .mouse = onMouse,
        .scroll = onScroll,
        .drag = onDrag,
        .action = onAction,
    };

    fn onAction(ctx: *anyopaque, a: input.Action) void {
        const sh = self(ctx);
        if (sh.device != .viewer or sh.modalActive() != null) return;
        switch (a) {
            .toggle_dictation => sh.toggleDictation(),
            // A headset's play / pause button: only with its microphone.
            .media_play_pause => if (sh.headsetMicPresent()) sh.toggleDictation(),
        }
    }

    fn self(ctx: *anyopaque) *Shell {
        return @ptrCast(@alignCast(ctx));
    }

    /// The line's frames go to the host.
    const LineSender = struct {
        sh: *Shell,
        pub fn send(ls: LineSender, f: []const u8) bool {
            return ls.sh.host.vtable.send(ls.sh.host.ctx, f);
        }
    };

    fn command(sh: *Shell, c: Command) void {
        sh.host.vtable.command(sh.host.ctx, c);
    }

    /// Shows the tab `step` places on (Ctrl+Tab / Ctrl+Shift+Tab).
    fn cycleTab(sh: *Shell, step: i32) void {
        if (sh.n_tabs < 2) return;
        const at: i64 = @intCast(sh.shown orelse 0);
        const next = @mod(at + step, @as(i64, @intCast(sh.n_tabs)));
        sh.command(.{ .select_tab = @intCast(next) });
    }

    fn onKey(ctx: *anyopaque, key: input.Key, mods: input.Mods) void {
        const sh = self(ctx);
        if (sh.modalActive()) |m| return m.key(m.ctx, key, mods);
        // A status panel: Esc or Enter closes it; nothing else is typed.
        if (sh.info != .none) {
            if (key == .escape or key == .enter) sh.setInfo(.none);
            return;
        }
        // F2 (never sent anywhere): collapse / open the Data slice.
        if (key == .f2 and !mods.ctrl and !mods.alt and !mods.super) return sh.data.toggle();
        // Ctrl+Tab / Ctrl+Shift+Tab: the next / previous tab, wherever the
        // keyboard is (a terminal program gets nothing for Ctrl+Tab anyway).
        if (key == .tab and mods.ctrl and !mods.alt) return sh.cycleTab(if (mods.shift) -1 else 1);
        const f = sh.focus();
        // The conversation's navigation: PageUp / PageDown also while the
        // line is open (Home / End then edit the line).
        if (sh.view_shown and (f == .view or (f == .line and (key == .page_up or key == .page_down)))) {
            if (sh.viewKey(key, mods)) return;
        }
        switch (f) {
            .panel => {},
            .pair_screen => if (key == .enter) sh.command(.pair),
            .wait_screen => if (key == .escape) sh.command(.cancel_pair),
            .view => {},
            .line => {
                // Desk: Esc on an empty box gives the keyboard back.
                if (sh.device == .desk and key == .escape and sh.line.text().len == 0) {
                    sh.line_focus = false;
                    return;
                }
                // The Conversation view's line: Esc closes it.
                if (sh.device == .viewer and sh.instructing and key == .escape) return sh.closeInstruct();
                _ = sh.line.onKey(key, mods, LineSender{ .sh = sh });
                // Sent: back to the minimal view.
                if (sh.instructing and key == .enter and sh.line.text().len == 0) sh.closeInstruct();
            },
            .terminal => {
                sh.select.active = false;
                sh.host.vtable.key(sh.host.ctx, key, mods);
            },
        }
    }

    /// A key for the conversation view; true if it took it (an answer from
    /// a Yes/No card goes out like an answer button).
    fn viewKey(sh: *Shell, key: input.Key, mods: input.Mods) bool {
        const c = sh.conversation orelse return false;
        const f = c.key orelse return false;
        switch (f(c.ctx, key, mods)) {
            .ignored => return false,
            .consumed => return true,
            .answer => |a| {
                sh.host.vtable.answer(sh.host.ctx, a);
                return true;
            },
        }
    }

    fn onScroll(ctx: *anyopaque, dy: f32) void {
        const sh = self(ctx);
        if (!sh.view_shown or sh.modalActive() != null) return;
        const c = sh.conversation orelse return;
        if (c.scroll) |f| f(c.ctx, dy);
    }

    fn onDrag(ctx: *anyopaque, d: input.Drag) void {
        const sh = self(ctx);
        if (!sh.view_shown or sh.modalActive() != null) return;
        const c = sh.conversation orelse return;
        const f = c.drag orelse return;
        // A committed swipe: its answer key, through the answer path.
        if (f(c.ctx, d)) |key| sh.host.vtable.answer(sh.host.ctx, key);
    }

    fn onChar(ctx: *anyopaque, cp: u21, mods: input.Mods) void {
        const sh = self(ctx);
        const f = sh.focus();
        if (mods.ctrl and mods.shift and !mods.alt) {
            // The device's shortcuts (the desk's also while a panel is open).
            if (sh.host.vtable.shortcut(sh.host.ctx, cp, mods, f)) return;
            if (sh.device == .desk and f == .terminal) switch (cp) {
                'c', 'C' => return sh.copy(),
                'v', 'V' => return sh.command(.paste),
                else => {},
            };
        }
        switch (f) {
            .panel => if (sh.modalActive()) |m| m.char(m.ctx, cp, mods),
            .pair_screen => if (!mods.ctrl and (cp == 'p' or cp == 'P')) sh.command(.pair),
            .wait_screen => {},
            // Space with no text field focused: dictation on / off.
            .view => if (cp == ' ' and !mods.ctrl and !mods.alt and !mods.super) sh.toggleDictation(),
            .line => _ = sh.line.onChar(cp, mods),
            .terminal => {
                sh.select.active = false;
                sh.host.vtable.char(sh.host.ctx, cp, mods);
            },
        }
    }

    fn onAnswer(ctx: *anyopaque, key: []const u8) void {
        const sh = self(ctx);
        if (sh.modalActive() != null or sh.info != .none) return;
        sh.select.active = false;
        sh.host.vtable.answer(sh.host.ctx, key);
    }

    fn onButton(ctx: *anyopaque, id: u32) void {
        const sh = self(ctx);
        if (sh.modalActive()) |m| return m.button(m.ctx, id);
        switch (id) {
            ids.tab0...ids.tab0 + tabs_wire.max_tabs - 1 => if (id - ids.tab0 < sh.n_tabs) sh.command(.{ .select_tab = id - ids.tab0 }),
            ids.close0...ids.close0 + tabs_wire.max_tabs - 1 => if (id - ids.close0 < sh.n_tabs) sh.command(.{ .close_tab = id - ids.close0 }),
            ids.tab_add => sh.command(.open_tab),
            // A tap on the line: it takes the keyboard (desk), and on a
            // touch device without a keyboard the on-screen one comes up.
            ids.line => {
                if (sh.device == .desk) sh.line_focus = true;
                if (sh.touch.on_screen_keyboard and sh.focus() == .line) sh.keyboard = true;
            },
            ids.keyboard => {
                if (sh.device == .desk) sh.line_focus = true;
                sh.keyboard = !sh.keyboard and sh.focus() == .line;
            },
            // Send: what Enter in the line does.
            ids.send => if (sh.focus() == .line or sh.device == .desk) {
                _ = sh.line.onKey(.enter, .{}, LineSender{ .sh = sh });
                if (sh.instructing and sh.line.text().len == 0) sh.closeInstruct();
            },
            ids.data_toggle => sh.data.toggle(),
            ids.data_clear => sh.data.clear(sh.gpa),
            ids.view_terminal => {
                sh.main = .terminal;
                sh.instructing = false;
            },
            ids.view_conversation => sh.main = .conversation,
            ids.instruct => if (sh.instructing) sh.toggleDictation() else sh.startDictation(),
            ids.view0...ids.view_last => if (sh.conversation) |c| if (c.button) |f| {
                _ = f(c.ctx, id);
            },
            ids.pair => sh.command(.pair),
            ids.cancel_pair => sh.command(.cancel_pair),
            ids.usage => sh.toggleInfo(.usage, null),
            ids.system => sh.toggleInfo(.system, null),
            ids.tasks => sh.toggleInfo(.tasks, if (sh.shown) |i| sh.tab_ids[i] else null),
            ids.badge0...ids.badge0 + tabs_wire.max_tabs - 1 => if (id - ids.badge0 < sh.n_tabs) sh.toggleInfo(.tasks, sh.tab_ids[id - ids.badge0]),
            status_panels.ids.close => sh.setInfo(.none),
            // Desk only, from its Usage panel: the panel closes and the
            // tab gets `/usage` (a device's panel has no such button, and
            // a stray id from one does nothing).
            status_panels.ids.slash0...status_panels.ids.slash0 + tabs_wire.max_tabs - 1 => if (sh.device == .desk and sh.info == .usage and id - status_panels.ids.slash0 < sh.n_tabs) {
                sh.setInfo(.none);
                sh.command(.{ .usage_slash = id - status_panels.ids.slash0 });
            },
            else => sh.command(.{ .button = id }),
        }
    }

    fn onResized(ctx: *anyopaque, _: u32, _: u32, cols: u16, rows: u16) void {
        self(ctx).command(.{ .resized = .{ cols, rows } });
    }

    fn onMouse(ctx: *anyopaque, m: input.Mouse) void {
        const sh = self(ctx);
        if (sh.device != .desk) return; // no selection on devices yet
        if (sh.modalActive() != null or sh.info != .none) return; // modal: only its buttons react
        // A click outside the controls gives the keyboard back to the terminal.
        if (m.action == .down) sh.line_focus = false;
        switch (m.button) {
            .left => switch (m.action) {
                .down => {
                    sh.select = .{ .anchor = .{ m.col, m.row }, .head = .{ m.col, m.row }, .dragging = m.inside };
                },
                .move => if (sh.select.dragging) {
                    sh.select.head = .{ m.col, m.row };
                    if (sh.select.head[0] != sh.select.anchor[0] or sh.select.head[1] != sh.select.anchor[1]) sh.select.active = true;
                },
                .up => sh.select.dragging = false,
            },
            // Right-click: copy the selection if there is one, else paste
            // (the Windows console convention).
            .right => if (m.action == .down) {
                if (sh.select.active) sh.copy() else sh.command(.paste);
            },
            .middle => {},
        }
    }

    fn copy(sh: *Shell) void {
        const sel = sh.select.range() orelse return;
        sh.command(.{ .copy = sel });
        sh.select = .{};
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

const Rec = struct {
    keys: usize = 0,
    chars: usize = 0,
    answers: usize = 0,
    frames: [8][64]u8 = undefined,
    lens: [8]usize = undefined,
    n_frames: usize = 0,
    cmds: [8]Command = undefined,
    n_cmds: usize = 0,
    shortcuts: bool = false,

    fn of(p: *anyopaque) *Rec {
        return @ptrCast(@alignCast(p));
    }
    fn key(p: *anyopaque, _: input.Key, _: input.Mods) void {
        of(p).keys += 1;
    }
    fn char(p: *anyopaque, _: u21, _: input.Mods) void {
        of(p).chars += 1;
    }
    fn answer(p: *anyopaque, _: []const u8) void {
        of(p).answers += 1;
    }
    fn send(p: *anyopaque, f: []const u8) bool {
        const r = of(p);
        @memcpy(r.frames[r.n_frames][0..f.len], f);
        r.lens[r.n_frames] = f.len;
        r.n_frames += 1;
        return true;
    }
    fn command(p: *anyopaque, c: Command) void {
        const r = of(p);
        r.cmds[r.n_cmds] = c;
        r.n_cmds += 1;
    }
    fn shortcut(p: *anyopaque, _: u21, _: input.Mods, _: Focus) bool {
        return of(p).shortcuts;
    }
    const vt: Host.VTable = .{ .key = key, .char = char, .answer = answer, .send = send, .command = command, .shortcut = shortcut };
    fn host(r: *Rec) Host {
        return .{ .ctx = r, .vtable = &vt };
    }
    fn lastFrame(r: *const Rec) []const u8 {
        return r.frames[r.n_frames - 1][0..r.lens[r.n_frames - 1]];
    }
};

test "viewer: waiting shows the request code; trust errors are explained" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .viewer, r.host());
    defer sh.deinit();
    sh.main = .terminal;
    const w = sh.overlay(.{ .viewer = .{ .status = .pair_waiting, .host = "10.8.0.1:8420", .code = "7f3a".* } });
    try testing.expectEqualStrings("Request code 7f3a", w.screen.message.title);
    try testing.expectEqual(ids.cancel_pair, w.screen.message.button.?.id);
    const t = sh.overlay(.{ .viewer = .{ .status = .retrying, .detail = "retrying in 2 s", .host = "10.8.0.1:8420", .has_grid = true, .trust_error = "not issued by the pinned Portal CA", .pin_fp = "AB:CD" } });
    try testing.expectEqualStrings("Cannot verify this Portal", t.screen.message.title);
    try testing.expect(std.mem.indexOf(u8, t.screen.message.lines[0], "pinned Portal CA") != null);
    // A plain network error keeps the picture and says it in the status line.
    const n = sh.overlay(.{ .viewer = .{ .status = .retrying, .detail = "refused", .host = "h", .has_grid = true } });
    try testing.expect(n.screen == .grid);
    try testing.expectEqualStrings("refused", n.status.extra);
}

test "viewer per input mode: the same features as the browser" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .viewer, r.host());
    defer sh.deinit();
    // The Terminal view (the Conversation view's rules: further down).
    sh.main = .terminal;
    var v: Viewer = .{ .status = .connected, .host = "h", .has_grid = true, .mode = .none };
    // view only: no answer bar, no line.
    var o = sh.overlay(.{ .viewer = v });
    try testing.expect(!o.show_answers);
    try testing.expectEqual(@as(usize, 0), o.bottom.len);
    try testing.expectEqualStrings("view only", o.status.extra);
    // keys and text: the answer bar, no line.
    for ([_]rules.Policy{ .keys, .text }) |p| {
        v.mode = p;
        o = sh.overlay(.{ .viewer = v });
        try testing.expect(o.show_answers);
        try testing.expectEqual(@as(usize, 0), o.bottom.len);
        try testing.expectEqual(Focus.terminal, sh.focus());
    }
    // instruct (the default): answer bar plus the instruction line, which
    // has the keyboard; its note shows in the status line.
    v.mode = .instruct;
    _ = sh.overlay(.{ .viewer = v });
    try testing.expectEqual(Focus.line, sh.focus());
    for ("fix it") |c| Shell.onChar(&sh, c, .{});
    o = sh.overlay(.{ .viewer = v });
    try testing.expect(o.show_answers);
    try testing.expectEqual(@as(usize, 1), o.bottom.len);
    try testing.expectEqualStrings("fix it", o.bottom[0].content.field.value);
    try testing.expect(o.bottom[0].content.field.focused);
    try testing.expectEqual(ids.send, o.bottom[0].send.?.id);
    Shell.onButton(&sh, ids.send);
    try testing.expectEqualStrings("l:fix it", r.lastFrame());
    o = sh.overlay(.{ .viewer = v });
    try testing.expectEqualStrings("instructions: Sent.", o.status.extra);
    try testing.expectEqual(frame.Tone.good, o.status.extra_tone);
    // Not connected: the terminal (keys go nowhere useful), pairing screens.
    v.status = .retrying;
    _ = sh.overlay(.{ .viewer = v });
    try testing.expectEqual(Focus.terminal, sh.focus());
    v.status = .need_pairing;
    _ = sh.overlay(.{ .viewer = v });
    try testing.expectEqual(Focus.pair_screen, sh.focus());
    Shell.onKey(&sh, .enter, .{});
    try testing.expect(r.cmds[r.n_cmds - 1] == .pair);
}

test "viewer: the Data slice under the terminal, not on pairing screens" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .viewer, r.host());
    defer sh.deinit();
    sh.data.shown = false;
    var v: Viewer = .{ .status = .connected, .mode = .instruct, .host = "h", .has_grid = true };
    const o = sh.overlay(.{ .viewer = v });
    try testing.expect(o.data.?.collapsed);
    try testing.expectEqualStrings("h", o.status.right);
    v.status = .need_pairing;
    try testing.expect(sh.overlay(.{ .viewer = v }).data == null);
}

test "viewer top bar: the desktop's tabs, the one shown active, no open or close; the view toggle" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .viewer, r.host());
    defer sh.deinit();
    var list: [2]tabs_wire.Entry = .{ .{ .id = @splat(1), .color = 0x3366CC }, .{ .id = @splat(2), .color = 0x10B981, .state = .waiting } };
    list[0].setName("Alpha");
    list[1].setName("Beta");
    const v: Viewer = .{ .status = .connected, .mode = .keys, .host = "h", .has_grid = true };
    const tb = sh.overlay(.{ .viewer = v, .tabs = &list, .current = @splat(2) }).top_bar.?;
    try testing.expectEqual(@as(usize, 2), tb.tabs.len);
    try testing.expectEqualStrings("Alpha", tb.tabs[0].label);
    try testing.expect(!tb.tabs[0].active and tb.tabs[1].active);
    try testing.expect(tb.tabs[1].attention and !tb.tabs[0].attention);
    try testing.expect(tb.tabs[0].close_id == null and tb.add_id == null);
    try testing.expectEqual(ids.tab0 + 1, tb.tabs[1].id);
    try testing.expectEqual(theme.fromU32(0x3366CC), tb.tabs[0].color);
    // The view toggle: Conversation chosen (the devices' default; without
    // a view, its placeholder), Terminal one click away.
    try testing.expectEqual(@as(usize, 2), tb.buttons.len);
    try testing.expect(!tb.buttons[0].active and tb.buttons[1].active);
    const conv = sh.overlay(.{ .viewer = v, .tabs = &list, .current = @splat(2) });
    try testing.expect(conv.screen == .message);
    Shell.onButton(&sh, ids.view_terminal);
    const term = sh.overlay(.{ .viewer = v, .tabs = &list, .current = @splat(2) });
    try testing.expect(term.screen == .grid and term.top_bar.?.buttons[0].active);
    // Ctrl+Tab cycles, a click switches.
    Shell.onKey(&sh, .tab, .{ .ctrl = true });
    try testing.expectEqual(@as(usize, 0), r.cmds[r.n_cmds - 1].select_tab);
    Shell.onButton(&sh, ids.tab0 + 1);
    try testing.expectEqual(@as(usize, 1), r.cmds[r.n_cmds - 1].select_tab);
    // Even one tab shows its name; none (an old desktop): no bar.
    try testing.expectEqual(@as(usize, 1), sh.overlay(.{ .viewer = v, .tabs = list[0..1] }).top_bar.?.tabs.len);
    try testing.expect(sh.overlay(.{ .viewer = v }).top_bar == null);
    var tbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("Portal \u{2014} Beta \u{2014} connected", title(.connected, "Beta", &tbuf));
    try testing.expectEqualStrings("Portal \u{2014} reconnecting", title(.retrying, null, &tbuf));
}

test "viewer: session ended, then desktop offline, are explicit screens" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .viewer, r.host());
    defer sh.deinit();
    sh.main = .terminal;
    const ended = sh.overlay(.{ .viewer = .{ .status = .session_ended, .mode = .keys, .host = "h", .has_grid = true, .exit_code = 1 } });
    try testing.expectEqualStrings("session ended", ended.status.label);
    try testing.expectEqualStrings("Session ended on the desktop (exit code 1)", ended.screen.message.title);
    try testing.expectEqualStrings("Waiting for the desktop to start a new session.", ended.screen.message.lines[0]);
    try testing.expect(!ended.show_answers);
    const off = sh.overlay(.{ .viewer = .{ .status = .desktop_offline, .host = "h", .has_grid = true, .exit_code = 1 } });
    try testing.expectEqualStrings("desktop offline", off.status.label);
    try testing.expectEqualStrings("Session ended on the desktop (exit code 1)", off.screen.message.title);
    try testing.expectEqualStrings("Desktop offline \u{2014} reconnects automatically.", off.screen.message.lines[0]);
    const cold = sh.overlay(.{ .viewer = .{ .status = .desktop_offline, .host = "h" } });
    try testing.expectEqualStrings("Desktop offline \u{2014} reconnects automatically", cold.screen.message.title);
    const net_err = sh.overlay(.{ .viewer = .{ .status = .network_error, .detail = "Network error: network unreachable", .host = "h", .has_grid = true } });
    try testing.expectEqualStrings("network error", net_err.status.label);
    try testing.expect(net_err.screen == .grid);
    try testing.expectEqualStrings("Network error: network unreachable", net_err.status.extra);
}

test "desk: tabs with close and +, viewer badge, the input box takes the keyboard on a click" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .desk, r.host());
    defer sh.deinit();
    var list: [1]tabs_wire.Entry = .{.{ .id = @splat(1), .color = 0x3366CC }};
    list[0].setName("Alpha");
    const tools = [_]frame.TopButton{.{ .label = "Devices", .id = 11 }};
    const st: State = .{ .tabs = &list, .current = @splat(1), .desk = .{ .viewers = 2, .url = "https://x/", .tools = &tools } };
    const o = sh.overlay(st);
    const tb = o.top_bar.?;
    try testing.expectEqual(ids.close0, tb.tabs[0].close_id.?);
    try testing.expectEqual(ids.tab_add, tb.add_id.?);
    try testing.expectEqualStrings("2 REMOTE VIEWERS WATCHING", tb.right);
    try testing.expect(tb.right_badge);
    try testing.expectEqualStrings("sharing on https://x/", o.status.right);
    try testing.expect(o.show_answers);
    // Keys go to the terminal until the box is clicked; Esc on an empty
    // box gives them back.
    Shell.onKey(&sh, .enter, .{});
    try testing.expectEqual(@as(usize, 1), r.keys);
    Shell.onButton(&sh, ids.line);
    try testing.expectEqual(Focus.line, sh.focus());
    for ("/help") |c| Shell.onChar(&sh, c, .{});
    Shell.onButton(&sh, ids.send);
    try testing.expectEqualStrings("k:enter", r.lastFrame());
    try testing.expectEqualStrings("t:/help", r.frames[0][0..r.lens[0]]);
    Shell.onKey(&sh, .escape, .{});
    try testing.expectEqual(Focus.terminal, sh.focus());
    // A tool button goes to the host; a tab's close box closes it.
    Shell.onButton(&sh, 11);
    try testing.expectEqual(@as(u32, 11), r.cmds[r.n_cmds - 1].button);
    Shell.onButton(&sh, ids.close0);
    try testing.expectEqual(@as(usize, 0), r.cmds[r.n_cmds - 1].close_tab);
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("no remote viewers", viewerText(0, &buf));
    try testing.expectEqualStrings("1 REMOTE VIEWER WATCHING", viewerText(1, &buf));
}

test "touch: the keyboard button, the keyboard follows the line's focus" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .desk, r.host());
    defer sh.deinit();
    sh.touch = .{ .enabled = true, .on_screen_keyboard = true };
    var o = sh.overlay(.{});
    try testing.expect(o.touch);
    try testing.expectEqual(ids.keyboard, o.bottom[0].keyboard.?.id);
    Shell.onButton(&sh, ids.line);
    try testing.expect(sh.keyboard and sh.focus() == .line);
    _ = sh.overlay(.{});
    try testing.expect(sh.keyboard);
    // Esc on the empty line: back to the terminal, the keyboard goes.
    Shell.onKey(&sh, .escape, .{});
    _ = sh.overlay(.{});
    try testing.expect(!sh.keyboard);
    // The button toggles it (and gives the line the keyboard).
    Shell.onButton(&sh, ids.keyboard);
    try testing.expect(sh.keyboard);
    Shell.onButton(&sh, ids.keyboard);
    try testing.expect(!sh.keyboard);
    // A hardware keyboard attached: no button.
    sh.touch.on_screen_keyboard = false;
    o = sh.overlay(.{});
    try testing.expect(o.bottom[0].keyboard == null);
}

test "desk: drag selects, right-click copies, Ctrl+Shift+V pastes" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .desk, r.host());
    defer sh.deinit();
    Shell.onMouse(&sh, .{ .action = .down, .button = .left, .col = 5, .row = 3, .inside = true });
    Shell.onMouse(&sh, .{ .action = .move, .button = .left, .col = 2, .row = 1, .inside = true });
    Shell.onMouse(&sh, .{ .action = .up, .button = .left, .col = 2, .row = 1, .inside = true });
    const sel = sh.select.range().?;
    try testing.expectEqual(@as(u16, 2), sel.start_col);
    try testing.expectEqual(@as(u16, 1), sel.start_row);
    try testing.expectEqual(@as(u16, 5), sel.end_col);
    try testing.expectEqual(@as(u16, 3), sel.end_row);
    Shell.onMouse(&sh, .{ .action = .down, .button = .right, .col = 0, .row = 0, .inside = true });
    try testing.expect(r.cmds[r.n_cmds - 1] == .copy);
    try testing.expect(sh.select.range() == null);
    Shell.onChar(&sh, 'v', .{ .ctrl = true, .shift = true });
    try testing.expect(r.cmds[r.n_cmds - 1] == .paste);
}

fn activityFixture(list: *[2]tabs_wire.Entry, a: *activity_wire.Activity) void {
    list[0] = .{ .id = @splat(1), .color = 0x3366CC };
    list[0].setName("Alpha");
    list[1] = .{ .id = @splat(2), .color = 0x10B981 };
    list[1].setName("Beta");
    a.* = .{ .len = 2 };
    a.tabs[0] = .{ .id = @splat(1) };
    a.tabs[0].tasks[0] = .{ .kind = .shell, .state = .running };
    a.tabs[0].tasks[1] = .{ .kind = .shell, .state = .running };
    a.tabs[0].tasks[2] = .{ .kind = .monitor, .state = .running };
    a.tabs[0].tasks[3] = .{ .kind = .shell, .state = .done };
    a.tabs[0].n_tasks = 4;
    a.tabs[1] = .{ .id = @splat(2) };
}

test "badges and the status line: running tasks only, hidden when none" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .viewer, r.host());
    defer sh.deinit();
    var list: [2]tabs_wire.Entry = undefined;
    var a: activity_wire.Activity = undefined;
    activityFixture(&list, &a);
    const v: Viewer = .{ .status = .connected, .mode = .keys, .host = "h", .has_grid = true };
    var o = sh.overlay(.{ .viewer = v, .tabs = &list, .current = @splat(1), .activity = &a });
    const tb = o.top_bar.?;
    try testing.expectEqualStrings("3", tb.tabs[0].badge);
    try testing.expectEqualStrings("", tb.tabs[1].badge);
    try testing.expectEqual(ids.badge0 + 1, tb.tabs[1].badge_id.?);
    try testing.expectEqualStrings("2 shells \u{00B7} 1 monitor", o.status.tasks);
    try testing.expectEqual(ids.tasks, o.status.tasks_id.?);
    // Usage always; System only while the desk's setting is on.
    try testing.expectEqual(@as(usize, 3), tb.buttons.len);
    try testing.expectEqual(ids.usage, tb.buttons[2].id);
    a.sysmon = true;
    o = sh.overlay(.{ .viewer = v, .tabs = &list, .current = @splat(1), .activity = &a });
    try testing.expectEqual(ids.system, o.top_bar.?.buttons[3].id);
    // The other tab, with nothing running: no summary.
    o = sh.overlay(.{ .viewer = v, .tabs = &list, .current = @splat(2), .activity = &a });
    try testing.expectEqualStrings("", o.status.tasks);
    // No activity known (an older desktop): no Usage, no badges.
    o = sh.overlay(.{ .viewer = v, .tabs = &list, .current = @splat(1) });
    try testing.expectEqual(@as(usize, 2), o.top_bar.?.buttons.len);
    try testing.expectEqualStrings("", o.top_bar.?.tabs[0].badge);
}

test "status panels: open from a badge, the status line or the top bar; Esc closes; System tells the host" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .viewer, r.host());
    defer sh.deinit();
    var list: [2]tabs_wire.Entry = undefined;
    var a: activity_wire.Activity = undefined;
    activityFixture(&list, &a);
    a.sysmon = true;
    const v: Viewer = .{ .status = .connected, .mode = .instruct, .host = "h", .has_grid = true };
    const st: State = .{ .viewer = v, .tabs = &list, .current = @splat(2), .activity = &a };
    _ = sh.overlay(st);
    Shell.onButton(&sh, ids.badge0); // Alpha's badge
    var o = sh.overlay(st);
    try testing.expectEqualStrings("Background tasks", o.panel.?.title);
    try testing.expect(std.mem.startsWith(u8, o.panel.?.rows[0].text, "Alpha"));
    try testing.expectEqual(Focus.panel, sh.focus());
    // Keys and answers go nowhere while it is open.
    Shell.onChar(&sh, 'x', .{});
    Shell.onAnswer(&sh, "y");
    try testing.expectEqual(@as(usize, 0), r.answers);
    try testing.expectEqualStrings("", sh.line.text());
    Shell.onKey(&sh, .escape, .{});
    try testing.expect(sh.overlay(st).panel == null);
    try testing.expectEqual(Focus.line, sh.focus());
    // The status line's summary opens it too; its Close button closes.
    Shell.onButton(&sh, ids.tasks);
    try testing.expect(sh.overlay(st).panel != null);
    Shell.onButton(&sh, status_panels.ids.close);
    try testing.expect(sh.overlay(st).panel == null);
    // Usage: a device's panel has no Open /usage, and its id does nothing.
    Shell.onButton(&sh, ids.usage);
    o = sh.overlay(st);
    try testing.expectEqualStrings("Usage", o.panel.?.title);
    for (o.panel.?.rows) |row| try testing.expect(row.button == null);
    const before = r.n_cmds;
    Shell.onButton(&sh, status_panels.ids.slash0);
    try testing.expectEqual(before, r.n_cmds);
    // System: the host hears it open and close (subscribe / unsubscribe).
    Shell.onButton(&sh, ids.system);
    try testing.expect(r.cmds[r.n_cmds - 1].system_panel);
    _ = sh.overlay(st);
    Shell.onButton(&sh, ids.usage); // another panel instead: System closes
    try testing.expect(!r.cmds[r.n_cmds - 1].system_panel);
    Shell.onButton(&sh, ids.system);
    try testing.expect(r.cmds[r.n_cmds - 1].system_panel);
    // The desk turns the setting off: the panel closes and the host hears it.
    a.sysmon = false;
    o = sh.overlay(st);
    try testing.expect(o.panel == null);
    try testing.expect(!r.cmds[r.n_cmds - 1].system_panel);
    // Disconnected: panels close.
    Shell.onButton(&sh, ids.usage);
    _ = sh.overlay(.{ .viewer = .{ .status = .retrying, .host = "h", .has_grid = true }, .activity = &a });
    try testing.expectEqual(status_panels.Screen.none, sh.info);
}

test "desk: Open /usage types into that tab (desk only), from the Usage panel" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .desk, r.host());
    defer sh.deinit();
    var list: [2]tabs_wire.Entry = undefined;
    var a: activity_wire.Activity = undefined;
    activityFixture(&list, &a);
    const tools = [_]frame.TopButton{.{ .label = "Devices", .id = 11 }};
    const st: State = .{ .tabs = &list, .current = @splat(1), .activity = &a, .desk = .{ .tools = &tools } };
    var o = sh.overlay(st);
    try testing.expectEqual(@as(usize, 2), o.top_bar.?.buttons.len); // Devices, Usage
    // Not open: its ids do nothing.
    Shell.onButton(&sh, status_panels.ids.slash0 + 1);
    try testing.expectEqual(@as(usize, 0), r.n_cmds);
    Shell.onButton(&sh, ids.usage);
    o = sh.overlay(st);
    try testing.expectEqual(status_panels.ids.slash0 + 1, o.panel.?.rows[2].button.?.id);
    Shell.onButton(&sh, status_panels.ids.slash0 + 1);
    try testing.expectEqual(@as(usize, 1), r.cmds[r.n_cmds - 1].usage_slash);
    try testing.expect(sh.overlay(st).panel == null);
    // The usage button toggles.
    Shell.onButton(&sh, ids.usage);
    Shell.onButton(&sh, ids.usage);
    try testing.expect(sh.overlay(st).panel == null);
}

const StubView = struct {
    scrolled: f32 = 0,
    keys: usize = 0,
    buttons: usize = 0,
    fn of(p: *anyopaque) *StubView {
        return @ptrCast(@alignCast(p));
    }
    fn draw(_: *anyopaque, _: *frame.Painter, _: frame.Rect) void {}
    fn scroll(p: *anyopaque, dy: f32) void {
        of(p).scrolled += dy;
    }
    fn key(p: *anyopaque, k: input.Key, _: input.Mods) frame.ViewInput {
        of(p).keys += 1;
        return switch (k) {
            .right => .{ .answer = "1" },
            .page_up, .page_down, .home, .end => .consumed,
            else => .ignored,
        };
    }
    fn button(p: *anyopaque, _: u32) bool {
        of(p).buttons += 1;
        return true;
    }
    fn drag(_: *anyopaque, d: input.Drag) ?[]const u8 {
        return if (d.phase == .up and d.x > 100) "esc" else null;
    }
    fn view(sv: *StubView) frame.ContentView {
        return .{ .ctx = sv, .draw = draw, .scroll = scroll, .key = key, .button = button, .drag = drag };
    }
};

const DictRec = struct {
    started: usize = 0,
    fn start(p: *anyopaque) void {
        const d: *DictRec = @ptrCast(@alignCast(p));
        d.started += 1;
    }
    fn stop(_: *anyopaque) void {}
};

test "conversation view (devices): the default, no answer keys, only Instruct at the bottom" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .viewer, r.host());
    defer sh.deinit();
    var sv: StubView = .{};
    sh.conversation = sv.view();
    var dict: DictRec = .{};
    sh.dictation = .{ .ctx = &dict, .start = DictRec.start, .stop = DictRec.stop };
    var v: Viewer = .{ .status = .connected, .mode = .instruct, .host = "h", .has_grid = true };
    var o = sh.overlay(.{ .viewer = v });
    try testing.expectEqual(MainView.conversation, sh.main);
    try testing.expect(o.screen == .view);
    // Minimal: no answer bar, no line; only Instruct, at the bottom.
    try testing.expect(!o.show_answers);
    try testing.expectEqual(@as(usize, 1), o.bottom.len);
    const row = o.bottom[0].content.buttons;
    try testing.expectEqual(@as(usize, 1), row.len);
    try testing.expectEqual(ids.instruct, row[0].id);
    try testing.expectEqual(Focus.view, sh.focus());
    // Typing reaches nothing from the view (no stray answers).
    Shell.onChar(&sh, 'y', .{});
    Shell.onKey(&sh, .enter, .{});
    try testing.expectEqual(@as(usize, 0), r.chars + r.keys + r.answers + r.n_frames);
    // Instruct: the line with the keyboard, dictation started.
    Shell.onButton(&sh, ids.instruct);
    try testing.expectEqual(@as(usize, 1), dict.started);
    o = sh.overlay(.{ .viewer = v });
    try testing.expectEqual(Focus.line, sh.focus());
    const line = o.bottom[o.bottom.len - 1];
    try testing.expect(line.content == .field and line.content.field.focused);
    // Esc closes it; Send closes it after sending.
    Shell.onKey(&sh, .escape, .{});
    try testing.expect(!sh.instructing);
    try testing.expectEqual(Focus.view, sh.focus());
    sh.startDictation();
    for ("run the tests") |c| Shell.onChar(&sh, c, .{});
    Shell.onButton(&sh, ids.send);
    try testing.expectEqualStrings("l:run the tests", r.lastFrame());
    try testing.expect(!sh.instructing);
    o = sh.overlay(.{ .viewer = v });
    try testing.expectEqual(ids.instruct, o.bottom[0].content.buttons[0].id);
    try testing.expectEqualStrings("instructions: Sent.", o.status.extra);
    // keys / text / view-only modes: no Instruct, nothing at the bottom,
    // never the answer bar.
    for ([_]rules.Policy{ .keys, .text, .none }) |m| {
        v.mode = m;
        o = sh.overlay(.{ .viewer = v });
        try testing.expectEqual(@as(usize, 0), o.bottom.len);
        try testing.expect(!o.show_answers);
    }
    v.mode = .keys;
    _ = sh.overlay(.{ .viewer = v });
    sh.startDictation();
    try testing.expect(!sh.instructing);
    // The Terminal view keeps the full bar and the line.
    v.mode = .instruct;
    Shell.onButton(&sh, ids.view_terminal);
    o = sh.overlay(.{ .viewer = v });
    try testing.expect(o.screen == .grid and o.show_answers);
    try testing.expect(o.bottom[0].content == .field);
    try testing.expectEqual(Focus.line, sh.focus());
}

test "conversation view input: navigation keys, scroll, a swipe's and a card key's answer through the answer path" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .viewer, r.host());
    defer sh.deinit();
    var sv: StubView = .{};
    sh.conversation = sv.view();
    const v: Viewer = .{ .status = .connected, .mode = .instruct, .host = "h", .has_grid = true };
    _ = sh.overlay(.{ .viewer = v });
    Shell.onKey(&sh, .page_up, .{});
    Shell.onKey(&sh, .right, .{});
    try testing.expectEqual(@as(usize, 2), sv.keys);
    try testing.expectEqual(@as(usize, 1), r.answers);
    Shell.onScroll(&sh, 30);
    try testing.expectEqual(@as(f32, 30), sv.scrolled);
    Shell.onDrag(&sh, .{ .phase = .down, .x = 10, .y = 10 });
    Shell.onDrag(&sh, .{ .phase = .up, .x = 200, .y = 10 });
    try testing.expectEqual(@as(usize, 2), r.answers);
    Shell.onButton(&sh, ids.view0);
    try testing.expectEqual(@as(usize, 1), sv.buttons);
    // While the line is open, PageUp still scrolls; Home edits the line.
    sh.startDictation();
    Shell.onKey(&sh, .page_down, .{});
    Shell.onKey(&sh, .home, .{});
    try testing.expectEqual(@as(usize, 3), sv.keys);
    // The terminal shown: nothing reaches the view.
    Shell.onButton(&sh, ids.view_terminal);
    _ = sh.overlay(.{ .viewer = v });
    Shell.onScroll(&sh, 30);
    try testing.expectEqual(@as(f32, 30), sv.scrolled);
}

test "desk: the terminal stays the default" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .desk, r.host());
    defer sh.deinit();
    try testing.expectEqual(MainView.terminal, sh.main);
    try testing.expect(sh.overlay(.{}).screen == .grid);
}

const DictToggle = struct {
    starts: usize = 0,
    stops: usize = 0,
    fn of(p: *anyopaque) *DictToggle {
        return @ptrCast(@alignCast(p));
    }
    fn start(p: *anyopaque) void {
        of(p).starts += 1;
    }
    fn stop(p: *anyopaque) void {
        of(p).stops += 1;
    }
    fn yes(_: ?*anyopaque) bool {
        return true;
    }
};

fn hasLabel(o: frame.Overlay, needle: []const u8) bool {
    for (o.bottom) |p| if (p.content == .buttons) for (p.content.buttons) |b| {
        if (std.mem.indexOf(u8, b.label, needle) != null) return true;
    };
    return false;
}

test "dictation toggles: Space only without a focused field, the media key only with a headset mic, the indicator" {
    var r: Rec = .{};
    var sh = Shell.init(testing.allocator, .viewer, r.host());
    defer sh.deinit();
    var sv: StubView = .{};
    sh.conversation = sv.view();
    var d: DictToggle = .{};
    sh.dictation = .{ .ctx = &d, .start = DictToggle.start, .stop = DictToggle.stop };
    const v: Viewer = .{ .status = .connected, .mode = .instruct, .host = "h", .has_grid = true };
    var o = sh.overlay(.{ .viewer = v });
    try testing.expect(!hasLabel(o, "Listening"));
    // Space in the conversation (no field focused): starts; the line opens
    // with the indicator above it.
    Shell.onChar(&sh, ' ', .{});
    try testing.expect(sh.dictating and sh.instructing);
    try testing.expectEqual(@as(usize, 1), d.starts);
    o = sh.overlay(.{ .viewer = v });
    try testing.expect(hasLabel(o, "Listening"));
    try testing.expectEqual(@as(usize, 2), o.bottom.len);
    try testing.expect(o.bottom[1].content == .field);
    // The line has the keyboard now: Space types a space.
    Shell.onChar(&sh, 'a', .{});
    Shell.onChar(&sh, ' ', .{});
    try testing.expectEqualStrings("a ", sh.line.text());
    try testing.expect(sh.dictating);
    // The indicator's button stops it; the text stays for review.
    Shell.onButton(&sh, ids.instruct);
    try testing.expect(!sh.dictating and sh.instructing);
    try testing.expectEqual(@as(usize, 1), d.stops);
    o = sh.overlay(.{ .viewer = v });
    try testing.expect(!hasLabel(o, "Listening") and hasLabel(o, "Dictate"));
    try testing.expectEqualStrings("a ", sh.line.text());
    // Esc closes the line (stopping dictation if it ran).
    Shell.onButton(&sh, ids.instruct);
    try testing.expect(sh.dictating);
    Shell.onKey(&sh, .escape, .{});
    try testing.expect(!sh.dictating and !sh.instructing);
    try testing.expectEqual(@as(usize, 2), d.stops);
    // The headset's media button: ignored without a headset mic ...
    try testing.expect(!sh.headsetMicPresent());
    Shell.onAction(&sh, .media_play_pause);
    try testing.expect(!sh.dictating);
    // ... toggles with one; the toggle action always does.
    sh.headset_mic = .{ .present = DictToggle.yes };
    Shell.onAction(&sh, .media_play_pause);
    try testing.expect(sh.dictating);
    Shell.onAction(&sh, .toggle_dictation);
    try testing.expect(!sh.dictating);
    // Not in the Terminal view: Space goes to the terminal there.
    Shell.onKey(&sh, .escape, .{});
    Shell.onButton(&sh, ids.view_terminal);
    _ = sh.overlay(.{ .viewer = .{ .status = .connected, .mode = .text, .host = "h", .has_grid = true } });
    Shell.onChar(&sh, ' ', .{});
    try testing.expect(!sh.dictating);
    try testing.expectEqual(@as(usize, 1), r.chars);
}
