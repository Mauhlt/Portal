//! The Portal window's own panels (desk side), as a state machine with no
//! drawing and no I/O: first-run / Settings, "Pair a device…" with the
//! approval question, the Devices list with Unpair, and "Export
//! certificate…". gui.zig feeds it keys, characters, button clicks and
//! pairing-window snapshots, performs the `Action`s it returns (the
//! in-process desk API in web.zig, the device store, the CA export) and
//! draws `panel()` with TermView.
//!
//! Approval is explicit: nothing approves by default. In the question the
//! focus starts on Deny, Enter answers whatever is focused, `y` approves
//! and `n` denies, like the [y/N] prompt of `portalctl pair`.

const std = @import("std");
const view = @import("view");
const TermView = view.TermView;
const form = view.form;
const input = view.input;
const devices = @import("devices.zig");
const keymap = @import("keymap.zig");

pub const Screen = enum { none, setup, pair_name, pairing, pair_result, devices, export_form, export_done };

/// Button and field ids (TermView reports clicks by id).
pub const id = struct {
    pub const tb_pair: u32 = 10;
    pub const tb_devices: u32 = 11;
    pub const tb_export: u32 = 12;
    pub const tb_settings: u32 = 13;

    pub const ok: u32 = 1;
    pub const cancel: u32 = 2;
    pub const approve: u32 = 3;
    pub const deny: u32 = 4;
    pub const stop: u32 = 5;
    pub const again: u32 = 6;
    pub const export_: u32 = 7;
    pub const start: u32 = 8;
    pub const open_pair: u32 = 9;
    /// Text fields: field0 + index.
    pub const field0: u32 = 100;
    /// Device rows' Unpair buttons: row0 + index.
    pub const row0: u32 = 200;
};

pub const Action = union(enum) {
    none,
    /// Open a pairing window for `ui.name`.
    begin_pair,
    answer: struct { code: [devices.code_len]u8, approve: bool },
    /// Close our pairing window.
    stop_pair,
    /// (Re)read the paired devices into `ui.devs` (setDevices).
    load_devices,
    /// Unpair `ui.devs[i]`.
    unpair: usize,
    /// Write the CA files to `ui.export_dir`.
    export_ca,
    /// The setup values in `ui.setup` were submitted.
    setup_submit,
    setup_cancel,
    /// Read the clipboard and call `paste`.
    paste,
};

pub const DevRow = struct {
    name: devices.Text = .{},
    ip: devices.Text = .{},
    last_seen: i64 = 0,
};

pub const PairResult = enum { paired, expired, closed, failed };

pub const Setup = struct {
    /// First run: there is no session yet, the button says Start and the
    /// panel can't be dismissed. Otherwise (Settings…) it saves for the
    /// next start.
    first_run: bool = true,
    listen: form.TextField(64) = .{},
    program: form.TextField(1024) = .{},
    project: form.TextField(64) = .{},
    input: keymap.Policy = .keys,
};

pub const Ui = struct {
    screen: Screen = .none,
    focus: form.Focus = .{},
    /// Error or progress line under the fields.
    note_buf: [240]u8 = undefined,
    note_len: usize = 0,
    note_tone: TermView.Tone = .bad,

    setup: Setup = .{},

    // ---- pairing
    name: form.TextField(devices.max_name) = .{},
    /// Our window, once open (0: none).
    own_nonce: u64 = 0,
    window: ?devices.Pairing = null,
    /// The pending request being asked about (oldest first).
    asked: ?[devices.code_len]u8 = null,
    result: PairResult = .paired,
    result_ip: devices.Text = .{},
    result_name: devices.Text = .{},

    // ---- devices
    devs: [devices.max_devices]DevRow = undefined,
    n_devs: usize = 0,
    confirm: ?usize = null,

    // ---- export
    export_dir: form.TextField(512) = .{},
    exported_to: form.TextField(512) = .{},

    pub fn open(ui: *const Ui) bool {
        return ui.screen != .none;
    }

    pub fn note(ui: *const Ui) []const u8 {
        return ui.note_buf[0..ui.note_len];
    }

    pub fn setNote(ui: *Ui, t: TermView.Tone, comptime fmt: []const u8, args: anytype) void {
        const s = std.fmt.bufPrint(&ui.note_buf, fmt, args) catch ui.note_buf[0..0];
        ui.note_len = s.len;
        ui.note_tone = t;
    }

    fn show(ui: *Ui, s: Screen) void {
        ui.screen = s;
        ui.note_len = 0;
        ui.confirm = null;
        ui.focus.reset(ui.focusCount(), ui.defaultFocus());
    }

    pub fn close(ui: *Ui) void {
        ui.screen = .none;
        ui.note_len = 0;
    }

    // ------------------------------------------------------- entry points

    /// First-run or Settings panel, prefilled with `listen`, `program`,
    /// `project`, `policy`.
    pub fn openSetup(ui: *Ui, first_run: bool, listen: []const u8, program: []const u8, project: []const u8, policy: keymap.Policy) void {
        ui.setup.first_run = first_run;
        ui.setup.listen.set(listen);
        ui.setup.program.set(program);
        ui.setup.project.set(project);
        ui.setup.input = policy;
        ui.show(.setup);
        // Start in the first empty field (the program, on a first run).
        if (ui.setup.listen.len == 0) {
            ui.focus.index = 0;
        } else if (ui.setup.program.len == 0) {
            ui.focus.index = 1;
        }
    }

    /// "Pair a device…". While our window is open this shows it instead.
    pub fn openPair(ui: *Ui) void {
        if (ui.own_nonce != 0 and ui.window != null) return ui.show(.pairing);
        ui.show(.pair_name);
    }

    pub fn openDevices(ui: *Ui) Action {
        ui.show(.devices);
        return .load_devices;
    }

    pub fn openExport(ui: *Ui, default_dir: []const u8) void {
        if (ui.export_dir.len == 0) ui.export_dir.set(default_dir);
        ui.show(.export_form);
    }

    // ------------------------------------------------------- host results

    /// Our window `nonce` was opened.
    pub fn pairBegun(ui: *Ui, nonce: u64, snapshot: ?devices.Pairing) Action {
        ui.own_nonce = nonce;
        ui.window = null;
        ui.asked = null;
        ui.show(.pairing);
        return ui.pairingChanged(snapshot, std.math.minInt(i64));
    }

    /// The pairing view may have changed (`snapshot` is the open window,
    /// if any; `now` in unix seconds). Returns `.stop_pair` once our device
    /// has collected its credential (the window has done its job).
    pub fn pairingChanged(ui: *Ui, snapshot: ?devices.Pairing, now: i64) Action {
        if (ui.own_nonce == 0) return .none;
        const p: ?devices.Pairing = if (snapshot) |s| (if (s.nonce == ui.own_nonce) s else null) else null;
        if (p) |win| {
            ui.window = win;
            if (devices.pairedRequest(&win)) |r| {
                ui.finish(.paired, r.ip.get());
                return .stop_pair;
            }
            // Keep asking about the same request while it is pending;
            // otherwise ask about the oldest pending one.
            if (ui.asked) |code| {
                const still = if (win.findCode(&code)) |i| win.requests[i].?.state == .pending else false;
                if (!still) ui.asked = null;
            }
            if (ui.asked == null and !win.decided()) {
                var best: ?devices.Request = null;
                for (win.requests) |slot| {
                    const r = slot orelse continue;
                    if (r.state != .pending) continue;
                    if (best == null or r.created < best.?.created) best = r;
                }
                if (best) |b| {
                    ui.asked = b.code;
                    if (ui.screen == .pairing) ui.focus.reset(ui.focusCount(), ui.defaultFocus());
                }
            }
            return .none;
        }
        // Our window is gone.
        if (ui.window) |old| {
            ui.finish(if (now >= old.expires) .expired else .closed, "");
        } else if (now != std.math.minInt(i64)) {
            ui.finish(.closed, "");
        }
        return .none;
    }

    fn finish(ui: *Ui, r: PairResult, ip: []const u8) void {
        const was_shown = ui.screen == .pairing or ui.screen == .pair_name or ui.screen == .pair_result;
        ui.result = r;
        ui.result_ip.set(ip);
        ui.result_name.set(if (ui.window) |win| win.name.get() else ui.name.text());
        ui.own_nonce = 0;
        ui.window = null;
        ui.asked = null;
        // Tell the desk the outcome even if the panel was put away.
        if (was_shown or r == .paired or r == .expired) ui.show(.pair_result);
    }

    /// The pairing window could not be opened or answered.
    pub fn pairFailed(ui: *Ui, comptime fmt: []const u8, args: anytype) void {
        ui.own_nonce = 0;
        ui.window = null;
        ui.asked = null;
        ui.result = .failed;
        ui.show(.pair_result);
        ui.setNote(.bad, fmt, args);
    }

    pub fn setDevices(ui: *Ui, rows: []const DevRow) void {
        const n = @min(rows.len, ui.devs.len);
        @memcpy(ui.devs[0..n], rows[0..n]);
        ui.n_devs = n;
        if (ui.confirm) |c| if (c >= n) {
            ui.confirm = null;
        };
        if (ui.screen == .devices) ui.focus.reset(ui.focusCount(), @min(ui.focus.index, ui.focusCount() - 1));
    }

    pub fn exported(ui: *Ui, dir: []const u8) void {
        ui.exported_to.set(dir);
        ui.show(.export_done);
    }

    /// Text from the clipboard for the focused field.
    pub fn paste(ui: *Ui, text: []const u8) void {
        if (ui.focusedField()) |f| switch (f) {
            .text => |t| _ = t.insert_text(t.ctx, text),
            .choice => {},
        };
    }

    // ------------------------------------------------------- focus model

    const FieldRef = union(enum) {
        text: struct { ctx: *anyopaque, insert_cp: *const fn (*anyopaque, u21) bool, insert_text: *const fn (*anyopaque, []const u8) usize, back: *const fn (*anyopaque) void },
        choice,
    };

    fn ref(comptime cap: usize, f: *form.TextField(cap)) FieldRef {
        const T = form.TextField(cap);
        const S = struct {
            fn cp(c: *anyopaque, x: u21) bool {
                return @as(*T, @ptrCast(@alignCast(c))).insert(x);
            }
            fn txt(c: *anyopaque, s: []const u8) usize {
                return @as(*T, @ptrCast(@alignCast(c))).insertText(s);
            }
            fn bs(c: *anyopaque) void {
                @as(*T, @ptrCast(@alignCast(c))).backspace();
            }
        };
        return .{ .text = .{ .ctx = f, .insert_cp = S.cp, .insert_text = S.txt, .back = S.bs } };
    }

    fn nameRef(ui: *Ui) FieldRef {
        const S = struct {
            fn cp(c: *anyopaque, x: u21) bool {
                const f: *form.TextField(devices.max_name) = @ptrCast(@alignCast(c));
                // Device names are a-z, 0-9 and '-': lower-case as typed.
                const l: u21 = if (x >= 'A' and x <= 'Z') x + 32 else x;
                if (!((l >= 'a' and l <= 'z') or (l >= '0' and l <= '9') or l == '-')) return false;
                return f.insert(l);
            }
            fn txt(c: *anyopaque, s: []const u8) usize {
                var n: usize = 0;
                for (s) |ch| {
                    if (ch == '\r' or ch == '\n') break;
                    if (cp(c, ch)) n += 1;
                }
                return n;
            }
            fn bs(c: *anyopaque) void {
                @as(*form.TextField(devices.max_name), @ptrCast(@alignCast(c))).backspace();
            }
        };
        return .{ .text = .{ .ctx = &ui.name, .insert_cp = S.cp, .insert_text = S.txt, .back = S.bs } };
    }

    /// Fields of the current screen, in focus order (fields come first).
    fn fieldCount(ui: *const Ui) u8 {
        return switch (ui.screen) {
            .setup => 4,
            .pair_name, .export_form => 1,
            else => 0,
        };
    }

    fn fieldAt(ui: *Ui, i: u8) FieldRef {
        return switch (ui.screen) {
            .setup => switch (i) {
                0 => ref(64, &ui.setup.listen),
                1 => ref(1024, &ui.setup.program),
                2 => ref(64, &ui.setup.project),
                else => .choice,
            },
            .pair_name => ui.nameRef(),
            .export_form => ref(512, &ui.export_dir),
            else => unreachable,
        };
    }

    fn focusedField(ui: *Ui) ?FieldRef {
        if (ui.focus.index >= ui.fieldCount()) return null;
        return ui.fieldAt(ui.focus.index);
    }

    /// Buttons of the current screen, in focus order (after the fields).
    pub fn buttonIds(ui: *const Ui, out: *[4]u32) []const u32 {
        var n: usize = 0;
        const add = struct {
            fn f(o: *[4]u32, k: *usize, v: u32) void {
                o[k.*] = v;
                k.* += 1;
            }
        }.f;
        switch (ui.screen) {
            .none => {},
            .setup => {
                if (!ui.setup.first_run) add(out, &n, id.cancel);
                add(out, &n, id.start);
            },
            .pair_name => {
                add(out, &n, id.cancel);
                add(out, &n, id.open_pair);
            },
            .pairing => {
                add(out, &n, id.stop);
                if (ui.asked != null) {
                    add(out, &n, id.deny);
                    add(out, &n, id.approve);
                }
            },
            .pair_result => switch (ui.result) {
                .paired => add(out, &n, id.ok),
                else => {
                    add(out, &n, id.ok);
                    add(out, &n, id.again);
                },
            },
            .devices => add(out, &n, id.ok),
            .export_form => {
                add(out, &n, id.cancel);
                add(out, &n, id.export_);
            },
            .export_done => add(out, &n, id.ok),
        }
        return out[0..n];
    }

    /// Device rows take focus too (before the Close button).
    fn rowCount(ui: *const Ui) u8 {
        return if (ui.screen == .devices) @intCast(ui.n_devs) else 0;
    }

    fn focusCount(ui: *const Ui) u8 {
        var b: [4]u32 = undefined;
        return ui.fieldCount() + ui.rowCount() + @as(u8, @intCast(ui.buttonIds(&b).len));
    }

    fn defaultFocus(ui: *const Ui) u8 {
        var b: [4]u32 = undefined;
        const ids = ui.buttonIds(&b);
        const base = ui.fieldCount() + ui.rowCount();
        // Pairing question: Deny. Otherwise the first field, or the last
        // (primary) button.
        for (ids, 0..) |x, i| if (x == id.deny) return base + @as(u8, @intCast(i));
        if (ui.fieldCount() > 0) return 0;
        if (ui.rowCount() > 0) return 0;
        return base + @as(u8, @intCast(ids.len)) -| 1;
    }

    /// The focused button id, if a button has the focus.
    fn focusedButton(ui: *const Ui) ?u32 {
        var b: [4]u32 = undefined;
        const ids = ui.buttonIds(&b);
        const base = ui.fieldCount() + ui.rowCount();
        if (ui.focus.index < base) return null;
        const i = ui.focus.index - base;
        return if (i < ids.len) ids[i] else null;
    }

    fn focusedRow(ui: *const Ui) ?usize {
        if (ui.screen != .devices) return null;
        if (ui.focus.index < ui.rowCount()) return ui.focus.index;
        return null;
    }

    // ------------------------------------------------------- input

    pub fn key(ui: *Ui, k: input.Key, mods: input.Mods) Action {
        switch (k) {
            .escape => return ui.escape(),
            .tab => {
                if (mods.shift) ui.focus.prev() else ui.focus.next();
                return .none;
            },
            .up => {
                ui.focus.prev();
                return .none;
            },
            .down => {
                ui.focus.next();
                return .none;
            },
            .left, .right => {
                if (ui.screen == .setup and ui.focus.index == 3) {
                    ui.setup.input = cyclePolicy(ui.setup.input, k == .right);
                } else if (ui.focusedField() == null) {
                    if (k == .left) ui.focus.prev() else ui.focus.next();
                }
                return .none;
            },
            .backspace => {
                if (ui.focusedField()) |f| switch (f) {
                    .text => |t| t.back(t.ctx),
                    .choice => {},
                };
                return .none;
            },
            .delete => {
                if (ui.focusedRow()) |r| ui.confirm = r;
                return .none;
            },
            .enter => return ui.enter(),
            else => return .none,
        }
    }

    pub fn char(ui: *Ui, cp: u21, mods: input.Mods) Action {
        if (mods.ctrl and !mods.alt and (cp == 'v' or cp == 'V')) return if (ui.focusedField() != null) .paste else .none;
        if (mods.ctrl or mods.alt) return .none;
        if (ui.focusedField()) |f| {
            switch (f) {
                .text => |t| _ = t.insert_cp(t.ctx, cp),
                .choice => if (cp == ' ') {
                    ui.setup.input = cyclePolicy(ui.setup.input, true);
                },
            }
            return .none;
        }
        // The approval question answers to y / n like `portalctl pair`.
        if (ui.screen == .pairing) if (ui.asked) |code| {
            if (cp == 'y' or cp == 'Y') return .{ .answer = .{ .code = code, .approve = true } };
            if (cp == 'n' or cp == 'N') return .{ .answer = .{ .code = code, .approve = false } };
        };
        return .none;
    }

    /// A click on a panel button or field (TermView reports both by id).
    pub fn button(ui: *Ui, b: u32) Action {
        if (b >= id.field0 and b < id.field0 + ui.fieldCount()) {
            const i: u8 = @intCast(b - id.field0);
            if (ui.screen == .setup and i == 3 and ui.focus.index == 3) ui.setup.input = cyclePolicy(ui.setup.input, true);
            ui.focus.index = i;
            return .none;
        }
        if (b >= id.row0 and b < id.row0 + ui.n_devs and ui.screen == .devices) {
            const r = b - id.row0;
            ui.focus.index = @intCast(r);
            if (ui.confirm == r) {
                ui.confirm = null;
                return .{ .unpair = r };
            }
            ui.confirm = r;
            return .none;
        }
        return ui.activate(b);
    }

    fn escape(ui: *Ui) Action {
        switch (ui.screen) {
            .none => {},
            .setup => if (!ui.setup.first_run) {
                ui.close();
                return .setup_cancel;
            },
            .pairing => {
                ui.close();
                return .stop_pair;
            },
            .devices => if (ui.confirm != null) {
                ui.confirm = null;
            } else ui.close(),
            else => ui.close(),
        }
        return .none;
    }

    fn enter(ui: *Ui) Action {
        if (ui.focusedField() != null) {
            // Enter in a field: on to the next one; in the last one, the
            // primary (last) button.
            if (ui.focus.index + 1 < ui.fieldCount()) {
                ui.focus.next();
                return .none;
            }
            var b: [4]u32 = undefined;
            const ids = ui.buttonIds(&b);
            if (ids.len == 0) return .none;
            return ui.activate(ids[ids.len - 1]);
        }
        if (ui.focusedRow()) |r| {
            if (ui.confirm == r) {
                ui.confirm = null;
                return .{ .unpair = r };
            }
            ui.confirm = r;
            return .none;
        }
        if (ui.focusedButton()) |b| return ui.activate(b);
        return .none;
    }

    fn activate(ui: *Ui, b: u32) Action {
        switch (b) {
            id.cancel => {
                const was_setup = ui.screen == .setup;
                ui.close();
                if (was_setup) return .setup_cancel;
            },
            id.ok => ui.close(),
            id.start => if (ui.screen == .setup) return .setup_submit,
            id.open_pair => if (ui.screen == .pair_name) {
                if (!devices.validName(ui.name.text())) {
                    ui.setNote(.bad, "Give the device a name: 1-32 characters of a-z, 0-9 and -.", .{});
                    return .none;
                }
                return .begin_pair;
            },
            id.again => {
                ui.show(.pair_name);
            },
            id.stop => if (ui.screen == .pairing) {
                ui.close();
                return .stop_pair;
            },
            id.approve, id.deny => if (ui.screen == .pairing) if (ui.asked) |code| {
                return .{ .answer = .{ .code = code, .approve = b == id.approve } };
            },
            id.export_ => if (ui.screen == .export_form) {
                if (std.mem.trim(u8, ui.export_dir.text(), " ").len == 0) {
                    ui.setNote(.bad, "Enter a folder to write the certificate files to.", .{});
                    return .none;
                }
                return .export_ca;
            },
            else => {},
        }
        return .none;
    }

    // ------------------------------------------------------- drawing

    pub const Ctx = struct {
        /// "AB:CD:..." SHA-256 of the Portal CA, if there is one.
        fingerprint: ?[]const u8 = null,
        /// e.g. "https://10.8.0.1:8420/".
        url: []const u8 = "",
        /// Local time the open window closes, e.g. "14:32".
        until: []const u8 = "",
        now: i64 = 0,
    };

    pub const Bufs = struct {
        lines: [14]TermView.PanelText = undefined,
        after: [6]TermView.PanelText = undefined,
        rows: [devices.max_devices]TermView.PanelRow = undefined,
        fields: [4]TermView.PanelField = undefined,
        buttons: [4]TermView.PanelButton = undefined,
        txt: [14][200]u8 = undefined,
        row_txt: [devices.max_devices][120]u8 = undefined,
        n_txt: usize = 0,

        fn fmt(b: *Bufs, comptime f: []const u8, args: anytype) []const u8 {
            if (b.n_txt == b.txt.len) return "";
            const s = std.fmt.bufPrint(&b.txt[b.n_txt], f, args) catch b.txt[b.n_txt][0..0];
            b.n_txt += 1;
            return s;
        }
    };

    fn label(b: u32) []const u8 {
        return switch (b) {
            id.ok => "OK",
            id.cancel => "Cancel",
            id.approve => "Approve",
            id.deny => "Deny",
            id.stop => "Stop pairing",
            id.again => "Try again",
            id.export_ => "Export",
            id.start => "Start",
            id.open_pair => "Open pairing",
            else => "?",
        };
    }

    fn tone(b: u32) TermView.Tone {
        return switch (b) {
            id.approve => .good,
            id.deny => .bad,
            else => .normal,
        };
    }

    /// The panel to draw now, or null. Strings live in `bufs` and `ui`.
    pub fn panel(ui: *const Ui, bufs: *Bufs, c: Ctx) ?TermView.Panel {
        bufs.n_txt = 0;
        var nl: usize = 0;
        var na: usize = 0;
        const L = struct {
            fn add(arr: []TermView.PanelText, n: *usize, t: TermView.PanelText) void {
                if (n.* < arr.len) {
                    arr[n.*] = t;
                    n.* += 1;
                }
            }
        };
        var p: TermView.Panel = .{ .title = "" };
        switch (ui.screen) {
            .none => return null,
            .setup => {
                p.title = if (ui.setup.first_run) "Welcome to Portal" else "Settings";
                if (ui.setup.first_run) {
                    L.add(&bufs.lines, &nl, .{ .text = "Portal runs one program in this window and shares it with your paired devices. Choose what to run and where devices reach it." });
                } else {
                    L.add(&bufs.lines, &nl, .{ .text = "Saved for the next time Portal starts (command-line options still win)." });
                }
                const f = ui.focus.index;
                bufs.fields[0] = .{ .label = "Listen address (IP:PORT)", .value = ui.setup.listen.text(), .hint = "127.0.0.1:8420 (this desktop only) or your WireGuard address, e.g. 10.8.0.1:8420", .id = id.field0, .focused = f == 0 };
                bufs.fields[1] = .{ .label = "Program to run", .value = ui.setup.program.text(), .hint = "the program and its arguments, e.g. the agent CLI's name", .id = id.field0 + 1, .focused = f == 1 };
                bufs.fields[2] = .{ .label = "Project name (optional, shown in the title)", .value = ui.setup.project.text(), .hint = "e.g. acme-api", .id = id.field0 + 2, .focused = f == 2 };
                bufs.fields[3] = .{ .label = "Remote input (Left/Right to change)", .value = policyLabel(ui.setup.input), .id = id.field0 + 3, .focused = f == 3, .choice = true };
                p.fields = bufs.fields[0..4];
                L.add(&bufs.after, &na, .{ .text = policyHelp(ui.setup.input), .tone = if (ui.setup.input == .text) .bad else .muted });
            },
            .pair_name => {
                p.title = "Pair a device";
                L.add(&bufs.lines, &nl, .{ .text = "Name the device you are about to pair. A 2-minute pairing window opens; every device that asks appears here for you to approve." });
                bufs.fields[0] = .{ .label = "Device name (a-z, 0-9, -)", .value = ui.name.text(), .hint = "e.g. laptop, iphone", .id = id.field0, .focused = ui.focus.index == 0 };
                p.fields = bufs.fields[0..1];
                ui.caLines(bufs, &bufs.after, &na, c);
            },
            .pairing => {
                const win = ui.window;
                const name = if (win) |w| w.name.get() else ui.name.text();
                if (ui.asked) |code| {
                    const ip = blk: {
                        const w = win orelse break :blk "?";
                        const i = w.findCode(&code) orelse break :blk "?";
                        break :blk w.requests[i].?.ip.get();
                    };
                    p.title = bufs.fmt("Pair '{s}' from {s}, code {s}?", .{ name, ip, &code });
                    p.title_tone = .warn;
                    L.add(&bufs.lines, &nl, .{ .text = bufs.fmt("Approve only if the device shows request code {s} and {s} is its address. Anyone else who reached Portal during the window can ask too.", .{ &code, ip }), .tone = .normal });
                    L.add(&bufs.lines, &nl, .{ .text = "Y approves, N denies." });
                } else {
                    p.title = bufs.fmt("Pairing open for '{s}'", .{name});
                    p.title_tone = .good;
                    if (c.until.len > 0) L.add(&bufs.lines, &nl, .{ .text = bufs.fmt("Open until {s}. Nothing is typed on the device: you approve it here.", .{c.until}) });
                    L.add(&bufs.lines, &nl, .{ .text = "" });
                    L.add(&bufs.lines, &nl, .{ .text = "On the device, with WireGuard on:", .tone = .normal, .bold = true });
                    if (c.url.len > 0) {
                        L.add(&bufs.lines, &nl, .{ .text = bufs.fmt("Browser: open {s} and tap \"Pair this device\".", .{c.url}) });
                    }
                    L.add(&bufs.lines, &nl, .{ .text = "Portal on a laptop: enter this address, pick or check the certificate, and click Pair." });
                    if (win) |w| switch (w.ca) {
                        .up => L.add(&bufs.lines, &nl, .{ .text = bufs.fmt("First time only: the certificate download is at http://{s}/ (compare the SHA-256 below).", .{w.ca_where.get()}) }),
                        .failed => L.add(&bufs.lines, &nl, .{ .text = bufs.fmt("WARNING: the certificate download on {s} could not be opened (another program may hold that port). Do not install a certificate from that address; use Export certificate instead.", .{w.ca_where.get()}), .tone = .bad }),
                        .off => L.add(&bufs.lines, &nl, .{ .text = "This Portal serves plain HTTP (--no-tls): no certificate to install.", .tone = .warn }),
                        .unknown => {},
                    };
                }
                ui.caLines(bufs, &bufs.after, &na, c);
                // Requests seen in this window.
                var nr: usize = 0;
                if (win) |w| for (w.requests) |slot| {
                    const r = slot orelse continue;
                    if (nr == bufs.rows.len) break;
                    const st: []const u8 = switch (r.state) {
                        .pending => "waiting for you",
                        .approved => "approved, collecting its credential",
                        .denied => "denied",
                        .done => "paired",
                    };
                    const t = std.fmt.bufPrint(&bufs.row_txt[nr], "request {s} from {s}: {s}", .{ &r.code, r.ip.get(), st }) catch "";
                    bufs.rows[nr] = .{ .text = t, .tone = switch (r.state) {
                        .pending => .warn,
                        .denied => .muted,
                        else => .good,
                    } };
                    nr += 1;
                };
                p.rows = bufs.rows[0..nr];
            },
            .pair_result => {
                switch (ui.result) {
                    .paired => {
                        p.title = bufs.fmt("Paired '{s}'", .{ui.result_name.get()});
                        p.title_tone = .good;
                        L.add(&bufs.lines, &nl, .{ .text = bufs.fmt("The device at {s} has its own credential now and signs in by itself. Unpair it any time from Devices.", .{ui.result_ip.get()}) });
                    },
                    .expired => {
                        p.title = "The pairing window expired";
                        p.title_tone = .warn;
                        L.add(&bufs.lines, &nl, .{ .text = "Nothing was paired." });
                    },
                    .closed => {
                        p.title = "Pairing stopped";
                        L.add(&bufs.lines, &nl, .{ .text = "The pairing window was closed or replaced (e.g. by portalctl pair). Nothing was paired from here." });
                    },
                    .failed => {
                        p.title = "Pairing failed";
                        p.title_tone = .bad;
                    },
                }
            },
            .devices => {
                p.title = "Paired devices";
                if (ui.n_devs == 0) L.add(&bufs.lines, &nl, .{ .text = "No paired devices yet. Use Pair a device (Ctrl+Shift+P)." });
                if (ui.n_devs > 0) L.add(&bufs.lines, &nl, .{ .text = "Unpair revokes a device at once and disconnects its viewers. Enter or Delete on a row asks to confirm." });
                for (ui.devs[0..ui.n_devs], 0..) |d, i| {
                    var ago_buf: [32]u8 = undefined;
                    const t = std.fmt.bufPrint(&bufs.row_txt[i], "{s: <16} {s: <16} last used {s}", .{ d.name.get(), d.ip.get(), ago(c.now, d.last_seen, &ago_buf) }) catch "";
                    const confirming = ui.confirm == i;
                    bufs.rows[i] = .{
                        .text = t,
                        .selected = ui.focus.index == i,
                        .button = .{ .label = if (confirming) "Confirm unpair" else "Unpair", .id = id.row0 + @as(u32, @intCast(i)), .tone = if (confirming) .bad else .normal, .focused = confirming },
                    };
                }
                p.rows = bufs.rows[0..ui.n_devs];
            },
            .export_form => {
                p.title = "Export certificate";
                L.add(&bufs.lines, &nl, .{ .text = "Writes portal-ca.cer, portal-ca.pem and portal-ca.mobileconfig: the Portal CA that each device must trust once. The files hold no secret." });
                bufs.fields[0] = .{ .label = "Folder", .value = ui.export_dir.text(), .id = id.field0, .focused = ui.focus.index == 0 };
                p.fields = bufs.fields[0..1];
                ui.caLines(bufs, &bufs.after, &na, c);
            },
            .export_done => {
                p.title = "Certificate exported";
                p.title_tone = .good;
                L.add(&bufs.lines, &nl, .{ .text = bufs.fmt("Wrote portal-ca.cer, portal-ca.pem and portal-ca.mobileconfig to {s}.", .{ui.exported_to.text()}) });
                L.add(&bufs.lines, &nl, .{ .text = "Windows: double-click portal-ca.cer, Install Certificate, Current User, Trusted Root Certification Authorities. iPhone/iPad: install the profile, then enable full trust in Settings > General > About > Certificate Trust Settings. Portal on a laptop: pick portal-ca.pem when it asks." });
                ui.caLines(bufs, &bufs.after, &na, c);
            },
        }
        p.lines = bufs.lines[0..nl];
        p.after = bufs.after[0..na];
        if (ui.note_len > 0) p.note = .{ .text = ui.note(), .tone = ui.note_tone };
        var ib: [4]u32 = undefined;
        const ids = ui.buttonIds(&ib);
        const base = ui.fieldCount() + ui.rowCount();
        for (ids, 0..) |b, i| bufs.buttons[i] = .{ .label = label(b), .id = b, .tone = tone(b), .focused = ui.focus.index == base + i };
        p.buttons = bufs.buttons[0..ids.len];
        return p;
    }

    fn caLines(ui: *const Ui, bufs: *Bufs, arr: []TermView.PanelText, n: *usize, c: Ctx) void {
        _ = ui;
        if (n.* >= arr.len) return;
        if (c.fingerprint) |fp| {
            arr[n.*] = .{ .text = bufs.fmt("Portal CA SHA-256: {s}", .{fp}), .tone = .normal };
        } else {
            arr[n.*] = .{ .text = "No Portal CA (plain HTTP)." };
        }
        n.* += 1;
    }
};

pub fn cyclePolicy(p: keymap.Policy, forward: bool) keymap.Policy {
    const all = [_]keymap.Policy{ .none, .keys, .instruct, .text };
    const i = std.mem.indexOfScalar(keymap.Policy, &all, p) orelse 1;
    return all[if (forward) (i + 1) % all.len else (i + all.len - 1) % all.len];
}

pub fn policyLabel(p: keymap.Policy) []const u8 {
    return switch (p) {
        .none => "none: view only",
        .keys => "keys: answer prompts (digits, y/n, Enter, Esc)",
        .instruct => "instruct: answer keys + checked instruction lines",
        .text => "text: FULL REMOTE CONTROL",
    };
}

fn policyHelp(p: keymap.Policy) []const u8 {
    return switch (p) {
        .none => "Devices can watch but not type.",
        .keys => "Devices can answer numbered and yes/no prompts. At an idle prompt those keys are typed like any text.",
        .instruct => "Devices can also send whole lines, which Portal checks first (no ! shell escape, no / commands, no # memory).",
        .text => "Anyone signed in on a paired device can type anything: new prompts, slash commands, mode changes.",
    };
}

/// "5 min ago", "3 h ago", "2 days ago", "just now".
pub fn ago(now: i64, then: i64, buf: []u8) []const u8 {
    const d = now -| then;
    if (then == 0) return "never";
    if (d < 60) return "just now";
    if (d < 3600) return std.fmt.bufPrint(buf, "{d} min ago", .{@divTrunc(d, 60)}) catch "?";
    if (d < 2 * 86400) return std.fmt.bufPrint(buf, "{d} h ago", .{@divTrunc(d, 3600)}) catch "?";
    return std.fmt.bufPrint(buf, "{d} days ago", .{@divTrunc(d, 86400)}) catch "?";
}

// ------------------------------------------------------------------ tests

const testing = std.testing;
const auth = @import("auth.zig");

fn typeText(ui: *Ui, s: []const u8) void {
    for (s) |ch| _ = ui.char(ch, .{});
}

fn window(nonce: u64, expires: i64) devices.Pairing {
    var p: devices.Pairing = .{ .nonce = nonce, .expires = expires };
    p.name.set("iphone");
    return p;
}

fn request(code: *const [4]u8, ip: []const u8, created: i64, state: devices.ReqState) devices.Request {
    var r: devices.Request = .{ .code = code.*, .token = auth.hashSecret(code), .created = created, .state = state };
    r.ip.set(ip);
    return r;
}

test "pairing: name, open, ask oldest first, approve, collected" {
    var ui: Ui = .{};
    ui.openPair();
    try testing.expectEqual(Screen.pair_name, ui.screen);
    // An invalid name is refused with a note, not an action.
    try testing.expectEqual(Action.none, ui.key(.enter, .{}));
    try testing.expect(ui.note().len > 0);
    typeText(&ui, "iPhone!");
    try testing.expectEqualStrings("iphone", ui.name.text());
    try testing.expectEqual(Action.begin_pair, ui.key(.enter, .{}));

    var w = window(77, 1000);
    try testing.expectEqual(Action.none, ui.pairBegun(77, w));
    try testing.expectEqual(Screen.pairing, ui.screen);
    try testing.expect(ui.asked == null);

    // Two requests: the older one is asked first; focus starts on Deny.
    w.requests[0] = request("bbbb", "10.8.0.4", 20, .pending);
    w.requests[1] = request("aaaa", "10.8.0.3", 10, .pending);
    _ = ui.pairingChanged(w, 100);
    try testing.expectEqualStrings("aaaa", &ui.asked.?);
    var bufs: Ui.Bufs = .{};
    const p = ui.panel(&bufs, .{ .now = 100 }).?;
    try testing.expectEqualStrings("Pair 'iphone' from 10.8.0.3, code aaaa?", p.title);
    var focused: ?u32 = null;
    for (p.buttons) |b| if (b.focused) {
        focused = b.id;
    };
    try testing.expectEqual(@as(?u32, id.deny), focused);
    // Enter answers what is focused: deny. 'y' approves.
    const a1 = ui.key(.enter, .{});
    try testing.expect(a1 == .answer and !a1.answer.approve and std.mem.eql(u8, &a1.answer.code, "aaaa"));
    const a2 = ui.char('y', .{});
    try testing.expect(a2 == .answer and a2.answer.approve);

    // The desk denied aaaa: bbbb is asked next.
    w.requests[1].?.state = .denied;
    _ = ui.pairingChanged(w, 101);
    try testing.expectEqualStrings("bbbb", &ui.asked.?);
    // Approved, then collected: the result screen, and the window is closed.
    w.requests[0].?.state = .approved;
    _ = ui.pairingChanged(w, 102);
    try testing.expect(ui.asked == null);
    w.requests[0].?.state = .done;
    try testing.expectEqual(Action.stop_pair, ui.pairingChanged(w, 103));
    try testing.expectEqual(Screen.pair_result, ui.screen);
    try testing.expectEqual(PairResult.paired, ui.result);
    try testing.expectEqualStrings("10.8.0.4", ui.result_ip.get());
    try testing.expectEqual(@as(u64, 0), ui.own_nonce);
    _ = ui.key(.enter, .{});
    try testing.expectEqual(Screen.none, ui.screen);
}

test "pairing: expiry, foreign windows, Esc stops" {
    var ui: Ui = .{};
    ui.openPair();
    typeText(&ui, "laptop");
    _ = ui.pairBegun(5, window(5, 200));
    // Another process replaced the window: ours is closed.
    _ = ui.pairingChanged(window(6, 300), 150);
    try testing.expectEqual(Screen.pair_result, ui.screen);
    try testing.expectEqual(PairResult.closed, ui.result);

    _ = ui.pairBegun(7, window(7, 200));
    _ = ui.pairingChanged(null, 201);
    try testing.expectEqual(PairResult.expired, ui.result);
    // "Try again" goes back to the name.
    try testing.expectEqual(Action.none, ui.button(id.again));
    try testing.expectEqual(Screen.pair_name, ui.screen);

    _ = ui.pairBegun(8, window(8, 200));
    try testing.expectEqual(Action.stop_pair, ui.key(.escape, .{}));
    try testing.expectEqual(Screen.none, ui.screen);
    // No window of ours: snapshots change nothing.
    ui.own_nonce = 0;
    try testing.expectEqual(Action.none, ui.pairingChanged(window(9, 500), 10));
    try testing.expectEqual(Screen.none, ui.screen);
}

test "devices: confirm before unpair" {
    var ui: Ui = .{};
    try testing.expectEqual(Action.load_devices, ui.openDevices());
    var rows: [2]DevRow = .{ .{}, .{} };
    rows[0].name.set("laptop");
    rows[0].ip.set("10.8.0.2");
    rows[1].name.set("iphone");
    rows[1].ip.set("10.8.0.3");
    ui.setDevices(&rows);
    // Focus is on the first row; Enter asks, Enter again unpairs.
    try testing.expectEqual(Action.none, ui.key(.enter, .{}));
    try testing.expectEqual(@as(?usize, 0), ui.confirm);
    const a = ui.key(.enter, .{});
    try testing.expect(a == .unpair and a.unpair == 0);
    // Clicking a row's button also asks first; Esc backs out.
    try testing.expectEqual(Action.none, ui.button(id.row0 + 1));
    try testing.expectEqual(@as(?usize, 1), ui.confirm);
    _ = ui.key(.escape, .{});
    try testing.expect(ui.confirm == null);
    try testing.expectEqual(Screen.devices, ui.screen);
    _ = ui.key(.escape, .{});
    try testing.expectEqual(Screen.none, ui.screen);
}

test "setup: fields, choice, submit; settings can be cancelled" {
    var ui: Ui = .{};
    ui.openSetup(true, "127.0.0.1:8420", "", "", .keys);
    try testing.expectEqual(@as(u8, 1), ui.focus.index); // the empty program
    typeText(&ui, "cmd.exe /k");
    try testing.expectEqualStrings("cmd.exe /k", ui.setup.program.text());
    _ = ui.key(.backspace, .{});
    try testing.expectEqualStrings("cmd.exe /", ui.setup.program.text());
    // First run: Esc does nothing (the window close button quits).
    try testing.expectEqual(Action.none, ui.key(.escape, .{}));
    try testing.expectEqual(Screen.setup, ui.screen);
    _ = ui.key(.tab, .{});
    _ = ui.key(.tab, .{});
    try testing.expectEqual(@as(u8, 3), ui.focus.index);
    _ = ui.key(.right, .{});
    try testing.expectEqual(keymap.Policy.instruct, ui.setup.input);
    _ = ui.key(.left, .{});
    _ = ui.key(.left, .{});
    try testing.expectEqual(keymap.Policy.none, ui.setup.input);
    try testing.expectEqual(Action.setup_submit, ui.key(.enter, .{}));
    _ = ui.button(id.field0); // click: focus the listen field
    try testing.expectEqual(Action.paste, ui.char('v', .{ .ctrl = true }));
    ui.paste("x\ny");
    try testing.expectEqualStrings("127.0.0.1:8420x", ui.setup.listen.text());

    var s: Ui = .{};
    s.openSetup(false, "a", "b", "c", .text);
    try testing.expectEqual(Action.setup_cancel, s.key(.escape, .{}));
    try testing.expectEqual(Screen.none, s.screen);
}

test "export: needs a folder" {
    var ui: Ui = .{};
    ui.openExport("C:\\Users\\me\\Downloads\\Portal-CA");
    try testing.expectEqual(Action.export_ca, ui.key(.enter, .{}));
    ui.export_dir.clear();
    try testing.expectEqual(Action.none, ui.key(.enter, .{}));
    try testing.expect(ui.note().len > 0);
    ui.exported("D:\\x");
    try testing.expectEqual(Screen.export_done, ui.screen);
}

test "ago" {
    var b: [32]u8 = undefined;
    try testing.expectEqualStrings("just now", ago(100, 90, &b));
    try testing.expectEqualStrings("5 min ago", ago(400, 100, &b));
    try testing.expectEqualStrings("3 h ago", ago(3 * 3600 + 10, 10, &b));
    try testing.expectEqualStrings("4 days ago", ago(4 * 86400 + 10, 10, &b));
    try testing.expectEqualStrings("never", ago(100, 0, &b));
}
