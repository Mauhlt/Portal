//! The desk's panels, as a state machine with no drawing and no I/O:
//! first-run / Settings, "Pair a device…" with the approval question, the
//! Devices list with Unpair (and a device's sync packages), and "Export
//! certificate…". The desk's window glue (src/gui.zig) feeds it keys,
//! characters, button clicks and pairing-window snapshots, performs the
//! `Action`s it returns (the in-process desk API, the device store, the CA
//! export) and draws `panel()` with the frame.
//!
//! Generic over the desk's device store module (`devices`: Pairing,
//! Request, Text, code_len, max_name, max_devices, validName,
//! pairedRequest), so the pairing rules stay defined once, in the store
//! (src/devices.zig); src/deskui.zig binds it and holds the tests.
//!
//! Approval is explicit: nothing approves by default. In the question the
//! focus starts on Deny, Enter answers whatever is focused, `y` approves
//! and `n` denies, like the [y/N] prompt of `portalctl pair`.

const std = @import("std");
const rules = @import("inputrules");
const frame = @import("../frame.zig");
const form = @import("../form.zig");
const input = @import("../input.zig");
const qr = @import("../qr.zig");
const pairqr = @import("shared").pairqr;

pub fn Panels(comptime devices: type) type {
    return struct {
        pub const Screen = enum { none, setup, pair_name, pairing, pair_result, devices, dev_packages, export_form, export_done };

        /// Button and field ids (the frame reports clicks by id).
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
            /// Package rows' Subscribe / Unsubscribe buttons: pkg0 + index.
            pub const pkg0: u32 = 260;
        };

        /// The top bar's desk tools (keyboard: Ctrl+Shift+P / D / E / S): the
        /// shell draws them on the desk only; clicks come back to the glue.
        pub const tools = [_]frame.TopButton{
            .{ .label = "Pair a device\u{2026}", .id = id.tb_pair },
            .{ .label = "Devices", .id = id.tb_devices },
            .{ .label = "Export certificate\u{2026}", .id = id.tb_export },
            .{ .label = "Settings", .id = id.tb_settings },
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
            /// Fill `ui.pkgs` for `ui.devs[i]` (setPackages): Portal sync.
            load_subs: usize,
            /// Flip the subscription of `ui.devs[ui.sub_dev]` to `ui.pkgs[i]`.
            toggle_sub: usize,
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
            /// Sync packages the device is subscribed to.
            n_subs: u8 = 0,
        };

        /// One package in a device's sync subscriptions screen.
        pub const PkgRow = struct {
            name: devices.Text = .{},
            on: bool = false,
            /// Latest published version, "" if none.
            latest: devices.Text = .{},
        };
        pub const max_pkgs = 16;

        pub const PairResult = enum { paired, expired, closed, failed };

        pub const Setup = struct {
            /// First run: there is no session yet, the button says Start and the
            /// panel can't be dismissed. Otherwise (Settings…) it saves for the
            /// next start.
            first_run: bool = true,
            listen: form.TextField(64) = .{},
            program: form.TextField(1024) = .{},
            project: form.TextField(64) = .{},
            input: rules.Policy = .keys,
            /// "Show system monitor" (Settings only, not the first run):
            /// the System button and its sampling (src/sysmon.zig).
            sysmon: bool = false,
        };

        pub const Ui = struct {
            screen: Screen = .none,
            focus: form.Focus = .{},
            /// Error or progress line under the fields.
            note_buf: [240]u8 = undefined,
            note_len: usize = 0,
            note_tone: frame.Tone = .bad,

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
            /// The device whose sync packages are shown (dev_packages).
            sub_dev: usize = 0,
            pkgs: [max_pkgs]PkgRow = undefined,
            n_pkgs: usize = 0,

            // ---- export
            export_dir: form.TextField(512) = .{},
            exported_to: form.TextField(512) = .{},

            pub fn open(ui: *const Ui) bool {
                return ui.screen != .none;
            }

            pub fn note(ui: *const Ui) []const u8 {
                return ui.note_buf[0..ui.note_len];
            }

            pub fn setNote(ui: *Ui, t: frame.Tone, comptime fmt: []const u8, args: anytype) void {
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
            pub fn openSetup(ui: *Ui, first_run: bool, listen: []const u8, program: []const u8, project: []const u8, policy: rules.Policy) void {
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

            pub fn setPackages(ui: *Ui, rows: []const PkgRow) void {
                const n = @min(rows.len, ui.pkgs.len);
                @memcpy(ui.pkgs[0..n], rows[0..n]);
                ui.n_pkgs = n;
                if (ui.screen == .dev_packages) ui.focus.reset(ui.focusCount(), @min(ui.focus.index, ui.focusCount() - 1));
            }

            fn openPackages(ui: *Ui, row: usize) Action {
                ui.sub_dev = row;
                ui.n_pkgs = 0;
                ui.show(.dev_packages);
                return .{ .load_subs = row };
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
                    .setup => if (ui.setup.first_run) 4 else 5,
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
                    .devices, .dev_packages => add(out, &n, id.ok),
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
                return switch (ui.screen) {
                    .devices => @intCast(ui.n_devs),
                    .dev_packages => @intCast(ui.n_pkgs),
                    else => 0,
                };
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
                if (ui.screen != .devices and ui.screen != .dev_packages) return null;
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
                        } else if (ui.screen == .setup and ui.focus.index == 4) {
                            ui.setup.sysmon = !ui.setup.sysmon;
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
                            if (ui.focus.index == 4) ui.setup.sysmon = !ui.setup.sysmon else ui.setup.input = cyclePolicy(ui.setup.input, true);
                        },
                    }
                    return .none;
                }
                // P on a device row: its sync packages.
                if (ui.screen == .devices and (cp == 'p' or cp == 'P')) if (ui.focusedRow()) |r| return ui.openPackages(r);
                // The approval question answers to y / n like `portalctl pair`.
                if (ui.screen == .pairing) if (ui.asked) |code| {
                    if (cp == 'y' or cp == 'Y') return .{ .answer = .{ .code = code, .approve = true } };
                    if (cp == 'n' or cp == 'N') return .{ .answer = .{ .code = code, .approve = false } };
                };
                return .none;
            }

            /// A click on a panel button or field (the frame reports both by id).
            pub fn button(ui: *Ui, b: u32) Action {
                if (b >= id.field0 and b < id.field0 + ui.fieldCount()) {
                    const i: u8 = @intCast(b - id.field0);
                    if (ui.screen == .setup and i == 3 and ui.focus.index == 3) ui.setup.input = cyclePolicy(ui.setup.input, true);
                    if (ui.screen == .setup and i == 4 and ui.focus.index == 4) ui.setup.sysmon = !ui.setup.sysmon;
                    ui.focus.index = i;
                    return .none;
                }
                if (b >= id.pkg0 and b < id.pkg0 + ui.n_pkgs and ui.screen == .dev_packages) {
                    ui.focus.index = @intCast(b - id.pkg0);
                    return .{ .toggle_sub = b - id.pkg0 };
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
                    .dev_packages => {
                        ui.show(.devices);
                        return .load_devices;
                    },
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
                    if (ui.screen == .dev_packages) return .{ .toggle_sub = r };
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
                    id.ok => if (ui.screen == .dev_packages) {
                        ui.show(.devices);
                        return .load_devices;
                    } else ui.close(),
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
                lines: [14]frame.PanelText = undefined,
                after: [6]frame.PanelText = undefined,
                rows: [@max(devices.max_devices, max_pkgs)]frame.PanelRow = undefined,
                fields: [5]frame.PanelField = undefined,
                buttons: [4]frame.PanelButton = undefined,
                txt: [14][200]u8 = undefined,
                row_txt: [@max(devices.max_devices, max_pkgs)][120]u8 = undefined,
                n_txt: usize = 0,
                /// The pairing QR code (address + CA fingerprint) for the
                /// iPhone app.
                qr_code: qr.Code = .{},
                qr_modules: [qr.max_size * qr.max_size]u8 = undefined,
                qr_text: [pairqr.max_len]u8 = undefined,

                /// Encodes the pairing QR for `c` (TLS only: it carries the
                /// CA fingerprint). Null if there is nothing to show.
                fn pairQr(b: *Bufs, c: Ctx) ?frame.PanelQr {
                    const fp_text = c.fingerprint orelse return null;
                    const fp = pairqr.parseFingerprint(fp_text) orelse return null;
                    const host = hostOfUrl(c.url) orelse return null;
                    const text = pairqr.format(&b.qr_text, host, fp) catch return null;
                    b.qr_code.encode(text) catch return null;
                    const n: usize = b.qr_code.size;
                    for (0..n) |y| for (0..n) |x| {
                        b.qr_modules[y * n + x] = @intFromBool(b.qr_code.get(x, y));
                    };
                    return .{ .size = b.qr_code.size, .modules = b.qr_modules[0 .. n * n] };
                }

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

            fn tone(b: u32) frame.Tone {
                return switch (b) {
                    id.approve => .good,
                    id.deny => .bad,
                    else => .normal,
                };
            }

            /// The panel to draw now, or null. Strings live in `bufs` and `ui`.
            pub fn panel(ui: *const Ui, bufs: *Bufs, c: Ctx) ?frame.Panel {
                bufs.n_txt = 0;
                var nl: usize = 0;
                var na: usize = 0;
                const L = struct {
                    fn add(arr: []frame.PanelText, n: *usize, t: frame.PanelText) void {
                        if (n.* < arr.len) {
                            arr[n.*] = t;
                            n.* += 1;
                        }
                    }
                };
                var p: frame.Panel = .{ .title = "" };
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
                        if (!ui.setup.first_run) {
                            bufs.fields[4] = .{ .label = "Show system monitor (Left/Right to change; applies now)", .value = if (ui.setup.sysmon) "On: a System button shows CPU, memory, GPU and each tab's load" else "Off", .id = id.field0 + 4, .focused = f == 4, .choice = true };
                            p.fields = bufs.fields[0..5];
                        }
                        L.add(&bufs.after, &na, .{ .text = policyHelp(ui.setup.input), .tone = if (ui.setup.input == .text) .bad else .muted });
                        if (ui.setup.sysmon and !ui.setup.first_run) L.add(&bufs.after, &na, .{ .text = "The monitor measures only while a System panel is open (once a second); off, it never measures." });
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
                            if (bufs.pairQr(c)) |code| {
                                L.add(&bufs.lines, &nl, .{ .text = "Portal on an iPhone: tap Scan QR code and point the camera here (it carries this address and the certificate's SHA-256, nothing secret)." });
                                p.qr = code;
                            }
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
                        if (ui.n_devs > 0) L.add(&bufs.lines, &nl, .{ .text = "Unpair revokes a device at once and disconnects its viewers. Enter or Delete on a row asks to confirm. P on a row: the packages it receives (Portal sync)." });
                        for (ui.devs[0..ui.n_devs], 0..) |d, i| {
                            var ago_buf: [32]u8 = undefined;
                            const t = std.fmt.bufPrint(&bufs.row_txt[i], "{s: <16} {s: <16} last used {s}, {d} package{s}", .{ d.name.get(), d.ip.get(), ago(c.now, d.last_seen, &ago_buf), d.n_subs, if (d.n_subs == 1) "" else "s" }) catch "";
                            const confirming = ui.confirm == i;
                            bufs.rows[i] = .{
                                .text = t,
                                .selected = ui.focus.index == i,
                                .button = .{ .label = if (confirming) "Confirm unpair" else "Unpair", .id = id.row0 + @as(u32, @intCast(i)), .tone = if (confirming) .bad else .normal, .focused = confirming },
                            };
                        }
                        p.rows = bufs.rows[0..ui.n_devs];
                    },
                    .dev_packages => {
                        const dev = if (ui.sub_dev < ui.n_devs) ui.devs[ui.sub_dev].name.get() else "?";
                        p.title = bufs.fmt("Packages for {s}", .{dev});
                        L.add(&bufs.lines, &nl, .{ .text = "Signed with this desktop's release key and delivered when you publish (portalctl publish). Data installs by itself; programs wait for approval on the device. Voice packages are offered right after pairing." });
                        for (ui.pkgs[0..ui.n_pkgs], 0..) |pk, i| {
                            const t = std.fmt.bufPrint(&bufs.row_txt[i], "{s: <16} {s: <14} {s}", .{ pk.name.get(), if (pk.on) "subscribed" else "-", if (pk.latest.len > 0) pk.latest.get() else "not published" }) catch "";
                            bufs.rows[i] = .{
                                .text = t,
                                .tone = if (pk.on) .normal else .muted,
                                .selected = ui.focus.index == i,
                                .button = .{ .label = if (pk.on) "Unsubscribe" else "Subscribe", .id = id.pkg0 + @as(u32, @intCast(i)), .tone = if (pk.on) .normal else .good },
                            };
                        }
                        p.rows = bufs.rows[0..ui.n_pkgs];
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

            fn caLines(ui: *const Ui, bufs: *Bufs, arr: []frame.PanelText, n: *usize, c: Ctx) void {
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

        pub fn cyclePolicy(p: rules.Policy, forward: bool) rules.Policy {
            const all = [_]rules.Policy{ .none, .keys, .instruct, .text };
            const i = std.mem.indexOfScalar(rules.Policy, &all, p) orelse 1;
            return all[if (forward) (i + 1) % all.len else (i + all.len - 1) % all.len];
        }

        pub fn policyLabel(p: rules.Policy) []const u8 {
            return switch (p) {
                .none => "none: view only",
                .keys => "keys: answer prompts (digits, y/n, Enter, Esc)",
                .instruct => "instruct: answer keys + checked instruction lines",
                .text => "text: FULL REMOTE CONTROL",
            };
        }

        fn policyHelp(p: rules.Policy) []const u8 {
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
    };
}

/// "IP:PORT" of "https://IP:PORT/" (the desk's sharing URL); null for
/// anything else (plain HTTP has no CA to put in the QR).
pub fn hostOfUrl(url: []const u8) ?[]const u8 {
    const prefix = "https://";
    if (!std.mem.startsWith(u8, url, prefix)) return null;
    const rest = url[prefix.len..];
    const end = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    if (end == 0) return null;
    return rest[0..end];
}

test "hostOfUrl" {
    try std.testing.expectEqualStrings("10.8.0.1:8420", hostOfUrl("https://10.8.0.1:8420/").?);
    try std.testing.expectEqualStrings("[fd00::1]:8420", hostOfUrl("https://[fd00::1]:8420/").?);
    try std.testing.expect(hostOfUrl("http://10.8.0.1:8420/") == null);
}
