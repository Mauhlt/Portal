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
//! Layout (frame.zig): top bar (+ tabs), main slice (a pluggable content
//! view: the terminal, or the conversation once a device provides one),
//! Data slice, interaction slice (answers, input box + Send), status line,
//! with the device's panels (desk panels, sync panels, ...) as a modal
//! layer.
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

pub const Device = enum { desk, viewer };

/// Ids of the shell's own controls, clear of the panels' ranges (desk
/// panels 1-13, 100-279; setup 1-101; sync 301-699). Ids it doesn't know
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
};

/// Who gets the keyboard, decided here only.
pub const Focus = enum { panel, pair_screen, wait_screen, line, terminal };

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
    main: MainView = .terminal,
    /// The conversation view, once the device has one (ui/convo).
    conversation: ?frame.ContentView = null,
    /// As of the last overlay: the viewer's status and mode, the tab count
    /// and the one shown.
    status: Status = .starting,
    mode: ?rules.Policy = null,
    n_tabs: usize = 0,
    shown: ?usize = null,
    bufs: Bufs = .{},

    const Bufs = struct {
        txt: [4][200]u8 = undefined,
        lines: [4][]const u8 = undefined,
        title: [48]u8 = undefined,
        extra: [256]u8 = undefined,
        right: [128]u8 = undefined,
        panes: [1]frame.Pane = undefined,
        top_tabs: [tabs_wire.max_tabs]frame.TopTab = undefined,
        buttons: [8]frame.TopButton = undefined,
    };

    pub fn init(gpa: std.mem.Allocator, device: Device, host: Host) Shell {
        return .{
            .gpa = gpa,
            .device = device,
            .host = host,
            .line = .{ .policy = if (device == .desk) .text else .instruct },
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
        if (sh.modalActive() != null) return .panel;
        switch (sh.device) {
            .desk => return if (sh.line_focus) .line else .terminal,
            .viewer => {
                if (sh.status == .need_pairing or sh.status == .pair_closed) return .pair_screen;
                if (sh.status == .pairing or sh.status == .pair_waiting) return .wait_screen;
                if (sh.status == .connected and sh.mode == .instruct) return .line;
                return .terminal;
            },
        }
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
        var o = switch (sh.device) {
            .desk => sh.deskOverlay(st),
            .viewer => sh.viewerOverlay(st),
        };
        o.panel = st.panel;
        if (o.panel != null) o.selection = null;
        return o;
    }

    fn tabBar(sh: *Shell, st: State, closable: bool) []const frame.TopTab {
        const n = @min(st.tabs.len, sh.bufs.top_tabs.len);
        for (st.tabs[0..n], 0..) |*e, i| {
            const active = if (st.current) |id| std.mem.eql(u8, &id, &e.id) else false;
            if (active) sh.shown = i;
            sh.bufs.top_tabs[i] = .{
                .label = e.name(),
                .color = theme.fromU32(e.color),
                .active = active,
                .attention = e.state.attention(),
                .id = ids.tab0 + @as(u32, @intCast(i)),
                .close_id = if (closable) ids.close0 + @as(u32, @intCast(i)) else null,
            };
        }
        sh.n_tabs = n;
        return sh.bufs.top_tabs[0..n];
    }

    fn linePane(sh: *Shell, hint: []const u8, focused: bool) []const frame.Pane {
        sh.bufs.panes[0] = .{ .content = .{ .field = .{
            .label = "",
            .value = sh.line.text(),
            .hint = hint,
            .id = ids.line,
            .focused = focused,
        } }, .send = .{ .label = "Send", .id = ids.send } };
        return sh.bufs.panes[0..1];
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
                .buttons = d.tools,
            },
            .selection = sh.select.range(),
            .status = .{
                .tone = .good,
                .label = "local session",
                .extra = if (line_note) lv.note else remote_input,
                .extra_tone = if (line_note) noteTone(lv.note_tone) else if (d.policy == .text) .bad else .muted,
                .right = std.fmt.bufPrint(&sh.bufs.extra, "sharing on {s}", .{d.url}) catch d.url,
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
                if (mode == .instruct) {
                    o.bottom = sh.linePane(rules.placeholder(.instruct), true);
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
            b.buttons[0] = .{ .label = "Terminal", .id = ids.view_terminal, .active = sh.main == .terminal };
            b.buttons[1] = .{ .label = "Conversation", .id = ids.view_conversation, .active = sh.main == .conversation };
            o.top_bar = .{ .tabs = sh.tabBar(st, false), .buttons = b.buttons[0..2] };
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
    };

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
        // F2 (never sent anywhere): collapse / open the Data slice.
        if (key == .f2 and !mods.ctrl and !mods.alt and !mods.super) return sh.data.toggle();
        // Ctrl+Tab / Ctrl+Shift+Tab: the next / previous tab, wherever the
        // keyboard is (a terminal program gets nothing for Ctrl+Tab anyway).
        if (key == .tab and mods.ctrl and !mods.alt) return sh.cycleTab(if (mods.shift) -1 else 1);
        switch (sh.focus()) {
            .panel => {},
            .pair_screen => if (key == .enter) sh.command(.pair),
            .wait_screen => if (key == .escape) sh.command(.cancel_pair),
            .line => {
                // Desk: Esc on an empty box gives the keyboard back.
                if (sh.device == .desk and key == .escape and sh.line.text().len == 0) {
                    sh.line_focus = false;
                    return;
                }
                _ = sh.line.onKey(key, mods, LineSender{ .sh = sh });
            },
            .terminal => {
                sh.select.active = false;
                sh.host.vtable.key(sh.host.ctx, key, mods);
            },
        }
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
            .panel => {
                const m = sh.modalActive().?;
                m.char(m.ctx, cp, mods);
            },
            .pair_screen => if (!mods.ctrl and (cp == 'p' or cp == 'P')) sh.command(.pair),
            .wait_screen => {},
            .line => _ = sh.line.onChar(cp, mods),
            .terminal => {
                sh.select.active = false;
                sh.host.vtable.char(sh.host.ctx, cp, mods);
            },
        }
    }

    fn onAnswer(ctx: *anyopaque, key: []const u8) void {
        const sh = self(ctx);
        if (sh.modalActive() != null) return;
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
            ids.line => if (sh.device == .desk) {
                sh.line_focus = true;
            },
            // Send: what Enter in the line does.
            ids.send => if (sh.focus() == .line or sh.device == .desk) {
                _ = sh.line.onKey(.enter, .{}, LineSender{ .sh = sh });
            },
            ids.data_toggle => sh.data.toggle(),
            ids.data_clear => sh.data.clear(sh.gpa),
            ids.view_terminal => sh.main = .terminal,
            ids.view_conversation => sh.main = .conversation,
            ids.pair => sh.command(.pair),
            ids.cancel_pair => sh.command(.cancel_pair),
            else => sh.command(.{ .button = id }),
        }
    }

    fn onResized(ctx: *anyopaque, _: u32, _: u32, cols: u16, rows: u16) void {
        self(ctx).command(.{ .resized = .{ cols, rows } });
    }

    fn onMouse(ctx: *anyopaque, m: input.Mouse) void {
        const sh = self(ctx);
        if (sh.device != .desk) return; // no selection on devices yet
        if (sh.modalActive() != null) return; // modal: only its buttons react
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
    // The view toggle: Terminal chosen; Conversation shows its placeholder.
    try testing.expectEqual(@as(usize, 2), tb.buttons.len);
    try testing.expect(tb.buttons[0].active and !tb.buttons[1].active);
    Shell.onButton(&sh, ids.view_conversation);
    const conv = sh.overlay(.{ .viewer = v, .tabs = &list, .current = @splat(2) });
    try testing.expect(conv.screen == .message and conv.top_bar.?.buttons[1].active);
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
