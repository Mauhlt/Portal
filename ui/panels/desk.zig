//! The desk's panels, as a state machine with no drawing and no I/O:
//! first-run / Settings (with the tunnel: this desktop's key, port,
//! endpoint and its peers), "Pair a device…" with the check-code
//! question, and the Devices list with Unpair (and a device's sync
//! packages). The desk's window glue (src/gui.zig) feeds it keys,
//! characters and button clicks, performs the `Action`s it returns (the
//! device store) and draws `panel()` with the frame.
//!
//! Generic over the desk's device store module (`devices`: Text,
//! max_name, max_devices, validName), so the pairing rules stay defined
//! once, in the store (src/devices.zig); src/deskui.zig binds it and holds
//! the tests.
//!
//! Pairing: the owner types (or pastes) the name and the device's
//! WireGuard public key; the glue checks the key and the panel shows its
//! check code, to compare with the device's screen. Approval is explicit:
//! nothing approves by default. In the question the focus starts on Deny,
//! Enter answers whatever is focused, `y` approves and `n` denies, like
//! the [y/N] prompt of `portalctl pair`. Approved, the panel shows the
//! pairing code for the device (text and QR).

const std = @import("std");
const rules = @import("inputrules");
const frame = @import("../frame.zig");
const form = @import("../form.zig");
const input = @import("../input.zig");
const qr = @import("../qr.zig");
const pairqr = @import("shared").pairqr;

pub fn Panels(comptime devices: type) type {
    return struct {
        pub const Screen = enum { none, setup, pair_name, pair_check, pair_result, devices, dev_packages };

        /// Button and field ids (the frame reports clicks by id).
        pub const id = struct {
            pub const tb_pair: u32 = 10;
            pub const tb_devices: u32 = 11;
            pub const tb_settings: u32 = 13;
            /// The Audio panel (ui/panels/audio.zig; Ctrl+Shift+A).
            pub const tb_audio: u32 = 14;

            pub const ok: u32 = 1;
            pub const cancel: u32 = 2;
            pub const approve: u32 = 3;
            pub const deny: u32 = 4;
            pub const again: u32 = 6;
            pub const start: u32 = 8;
            pub const open_pair: u32 = 9;
            pub const save: u32 = 10;
            /// Text fields: field0 + index.
            pub const field0: u32 = 100;
            /// Device rows' Unpair buttons: row0 + index.
            pub const row0: u32 = 200;
            /// Package rows' Subscribe / Unsubscribe buttons: pkg0 + index.
            pub const pkg0: u32 = 260;
        };

        /// The top bar's desk tools (keyboard: Ctrl+Shift+P / D / S / A): the
        /// shell draws them on the desk only; clicks come back to the glue.
        pub const tools = [_]frame.TopButton{
            .{ .label = "Pair a device\u{2026}", .id = id.tb_pair },
            .{ .label = "Devices", .id = id.tb_devices },
            .{ .label = "Settings", .id = id.tb_settings },
            .{ .label = "Audio", .id = id.tb_audio },
        };

        pub const Action = union(enum) {
            none,
            /// Check the key in `ui.key` (keyChecked, or a note).
            check_key,
            /// The owner approved `ui.name` with `ui.key` (paired, or
            /// pairFailed).
            approve_pair,
            /// (Re)read the paired devices into `ui.devs` (setDevices).
            load_devices,
            /// Unpair `ui.devs[i]`.
            unpair: usize,
            /// Fill `ui.pkgs` for `ui.devs[i]` (setPackages): Portal sync.
            load_subs: usize,
            /// Flip the subscription of `ui.devs[ui.sub_dev]` to `ui.pkgs[i]`.
            toggle_sub: usize,
            /// The setup values in `ui.setup` were submitted.
            setup_submit,
            setup_cancel,
            /// Read the clipboard and call `paste`.
            paste,
            /// "Claude Code integration": install Portal's hooks in the agent's
            /// settings.json, or remove them when installed
            /// (src/agenthooks.zig); the glue sets `ui.setup.agent`.
            agent_hooks,
        };

        /// What the desk found in the agent's settings.json.
        pub const AgentHooks = enum { unknown, not_installed, installed, partly, other_exe, unreadable };

        pub const DevRow = struct {
            /// The record (Unpair removes exactly this one, never a
            /// record paired again under the same name meanwhile).
            id: devices.DeviceId = @splat(0),
            name: devices.Text = .{},
            ip: devices.Text = .{},
            /// Its WireGuard key's check code.
            key: devices.Text = .{},
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

        pub const PairResult = enum { paired, failed };
        /// shared/tunnelnet.zig checkCode.
        pub const check_len = @import("shared").tunnelnet.check_code_len;
        pub const key_text_len = 44;

        pub const Setup = struct {
            /// First run: there is no session yet, the button says Start and the
            /// panel can't be dismissed. Otherwise (Settings…) it saves for the
            /// next start.
            first_run: bool = true,
            /// The tunnel's UDP port.
            tunnel_port: form.TextField(5) = .{},
            /// Where devices reach it (Settings only).
            tunnel_endpoint: form.TextField(259) = .{},
            program: form.TextField(1024) = .{},
            project: form.TextField(64) = .{},
            input: rules.Policy = .keys,
            /// "Show system monitor" (Settings only, not the first run):
            /// the System button and its sampling (src/sysmon.zig).
            sysmon: bool = false,
            /// "Background art" (Settings only): the hero art, faint,
            /// behind the window's content.
            bg_art: bool = true,
            /// "Claude Code integration" (Settings only): applies at once
            /// (Action.agent_hooks), not with the other settings.
            agent: AgentHooks = .unknown,
            /// "Admin prompts at the desk" (Settings only): settings.txt's
            /// `block_elevation_desk`; the agent's hook reads it each time,
            /// so it applies as soon as it is saved.
            block_elevation: bool = false,
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
            /// The device's WireGuard public key, as typed or pasted.
            key_text: form.TextField(64) = .{},
            /// The check code of `key` (set by keyChecked).
            check: [check_len]u8 = @splat(' '),
            result: PairResult = .paired,
            result_ip: devices.Text = .{},
            result_name: devices.Text = .{},
            /// The pairing code for the device (shared/pairqr.zig v2) and the
            /// check code of the desk's key it carries.
            result_code: [pairqr.max_len_tunnel]u8 = undefined,
            result_code_len: usize = 0,
            result_desk_check: [check_len]u8 = @splat(' '),

            // ---- devices
            devs: [devices.max_devices]DevRow = undefined,
            n_devs: usize = 0,
            confirm: ?usize = null,
            /// The device whose sync packages are shown (dev_packages).
            sub_dev: usize = 0,
            pkgs: [max_pkgs]PkgRow = undefined,
            n_pkgs: usize = 0,

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
            pub fn openSetup(ui: *Ui, first_run: bool, tunnel_port: []const u8, program: []const u8, project: []const u8, policy: rules.Policy) void {
                ui.setup.first_run = first_run;
                ui.setup.tunnel_port.set(tunnel_port);
                ui.setup.program.set(program);
                ui.setup.project.set(project);
                ui.setup.input = policy;
                ui.show(.setup);
                // Start in the first empty field (the program, on a first run).
                if (ui.setup.tunnel_port.len == 0) {
                    ui.focus.index = 0;
                } else if (ui.setup.program.len == 0) {
                    ui.focus.index = 1;
                }
            }

            /// "Pair a device…".
            pub fn openPair(ui: *Ui) void {
                ui.show(.pair_name);
            }

            pub fn openDevices(ui: *Ui) Action {
                ui.show(.devices);
                return .load_devices;
            }

            // ------------------------------------------------------- host results

            /// The key in `ui.key` is a WireGuard public key with check code
            /// `code`: ask the owner to compare it with the device's.
            pub fn keyChecked(ui: *Ui, code: [check_len]u8) void {
                ui.check = code;
                ui.show(.pair_check);
            }

            /// The device was recorded: show its pairing code.
            pub fn paired(ui: *Ui, ip: []const u8, code: []const u8, desk_check: [check_len]u8) void {
                ui.result = .paired;
                ui.result_name.set(ui.name.text());
                ui.result_ip.set(ip);
                const n = @min(code.len, ui.result_code.len);
                @memcpy(ui.result_code[0..n], code[0..n]);
                ui.result_code_len = n;
                ui.result_desk_check = desk_check;
                ui.key_text.set("");
                ui.show(.pair_result);
            }

            pub fn resultCode(ui: *const Ui) []const u8 {
                return ui.result_code[0..ui.result_code_len];
            }

            /// The device could not be recorded.
            pub fn pairFailed(ui: *Ui, comptime fmt: []const u8, args: anytype) void {
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
                    .setup => if (ui.setup.first_run) 4 else 9,
                    .pair_name => 2,
                    else => 0,
                };
            }

            fn fieldAt(ui: *Ui, i: u8) FieldRef {
                return switch (ui.screen) {
                    .setup => switch (i) {
                        0 => ref(5, &ui.setup.tunnel_port),
                        1 => ref(1024, &ui.setup.program),
                        2 => ref(64, &ui.setup.project),
                        8 => ref(259, &ui.setup.tunnel_endpoint),
                        else => .choice,
                    },
                    .pair_name => if (i == 0) ui.nameRef() else ref(64, &ui.key_text),
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
                        add(out, &n, if (ui.setup.first_run) id.start else id.save);
                    },
                    .pair_name => {
                        add(out, &n, id.cancel);
                        add(out, &n, id.open_pair);
                    },
                    .pair_check => {
                        add(out, &n, id.deny);
                        add(out, &n, id.approve);
                    },
                    .pair_result => switch (ui.result) {
                        .paired => add(out, &n, id.ok),
                        else => {
                            add(out, &n, id.ok);
                            add(out, &n, id.again);
                        },
                    },
                    .devices, .dev_packages => add(out, &n, id.ok),
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
                        } else if (ui.screen == .setup and ui.focus.index == 5) {
                            ui.setup.bg_art = !ui.setup.bg_art;
                        } else if (ui.screen == .setup and ui.focus.index == 6) {
                            return .agent_hooks;
                        } else if (ui.screen == .setup and ui.focus.index == 7) {
                            ui.setup.block_elevation = !ui.setup.block_elevation;
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
                            if (ui.focus.index == 6) return .agent_hooks;
                            switch (ui.focus.index) {
                                4 => ui.setup.sysmon = !ui.setup.sysmon,
                                5 => ui.setup.bg_art = !ui.setup.bg_art,
                                7 => ui.setup.block_elevation = !ui.setup.block_elevation,
                                else => ui.setup.input = cyclePolicy(ui.setup.input, true),
                            }
                        },
                    }
                    return .none;
                }
                // P on a device row: its sync packages.
                if (ui.screen == .devices and (cp == 'p' or cp == 'P')) if (ui.focusedRow()) |r| return ui.openPackages(r);
                // The approval question answers to y / n like `portalctl pair`.
                if (ui.screen == .pair_check) {
                    if (cp == 'y' or cp == 'Y') return ui.activate(id.approve);
                    if (cp == 'n' or cp == 'N') return ui.activate(id.deny);
                }
                return .none;
            }

            /// A click on a panel button or field (the frame reports both by id).
            pub fn button(ui: *Ui, b: u32) Action {
                if (b >= id.field0 and b < id.field0 + ui.fieldCount()) {
                    const i: u8 = @intCast(b - id.field0);
                    if (ui.screen == .setup and i == 3 and ui.focus.index == 3) ui.setup.input = cyclePolicy(ui.setup.input, true);
                    if (ui.screen == .setup and i == 4 and ui.focus.index == 4) ui.setup.sysmon = !ui.setup.sysmon;
                    if (ui.screen == .setup and i == 5 and ui.focus.index == 5) ui.setup.bg_art = !ui.setup.bg_art;
                    if (ui.screen == .setup and i == 7 and ui.focus.index == 7) ui.setup.block_elevation = !ui.setup.block_elevation;
                    const act: Action = if (ui.screen == .setup and i == 6 and ui.focus.index == 6) .agent_hooks else .none;
                    ui.focus.index = i;
                    return act;
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
                    .pair_check => ui.show(.pair_name),
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
                    id.start, id.save => if (ui.screen == .setup) return .setup_submit,
                    id.open_pair => if (ui.screen == .pair_name) {
                        if (!devices.validName(ui.name.text())) {
                            ui.setNote(.bad, "Give the device a name: 1-32 characters of a-z, 0-9 and -.", .{});
                            return .none;
                        }
                        return .check_key;
                    },
                    id.again => {
                        ui.show(.pair_name);
                    },
                    id.approve => if (ui.screen == .pair_check) return .approve_pair,
                    id.deny => if (ui.screen == .pair_check) {
                        ui.show(.pair_name);
                        ui.setNote(.bad, "Not paired: the check codes did not match. Copy the key from the device again.", .{});
                    },
                    else => {},
                }
                return .none;
            }

            // ------------------------------------------------------- drawing

            pub const Ctx = struct {
                /// This desktop's WireGuard public key and its check code.
                desk_key: []const u8 = "",
                desk_check: []const u8 = "",
                /// The UDP port the tunnel listens on now.
                tunnel_port: u16 = 0,
                now: i64 = 0,
            };

            pub const Bufs = struct {
                lines: [14]frame.PanelText = undefined,
                after: [8 + devices.max_devices]frame.PanelText = undefined,
                rows: [@max(devices.max_devices, max_pkgs)]frame.PanelRow = undefined,
                fields: [9]frame.PanelField = undefined,
                buttons: [4]frame.PanelButton = undefined,
                txt: [14 + devices.max_devices][200]u8 = undefined,
                row_txt: [@max(devices.max_devices, max_pkgs)][120]u8 = undefined,
                n_txt: usize = 0,
                /// The pairing code's QR (shared/pairqr.zig v2) for the
                /// device's camera.
                qr_code: qr.Code = .{},
                qr_modules: [qr.max_size * qr.max_size]u8 = undefined,

                /// Encodes `text` as the panel's QR. Null if it does not fit.
                fn pairQr(b: *Bufs, text: []const u8) ?frame.PanelQr {
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
                    id.again => "Try again",
                    id.start => "Start",
                    id.save => "Save",
                    id.open_pair => "Check key",
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

            fn agentLabel(c: AgentHooks) []const u8 {
                return switch (c) {
                    .unknown => "Unknown",
                    .not_installed => "Not installed: [Install]",
                    .installed => "Installed: tabs show when Claude works, waits or is done [Remove]",
                    .partly => "Partly installed: [Install] completes it",
                    .other_exe => "Installed for another Portal: [Install] points it here",
                    .unreadable => "Claude Code's settings.json could not be read (see the note)",
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
                        bufs.fields[0] = .{ .label = "Tunnel UDP port (Portal's own WireGuard; devices reach it here)", .value = ui.setup.tunnel_port.text(), .hint = "51820", .id = id.field0, .focused = f == 0 };
                        bufs.fields[1] = .{ .label = "Program to run", .value = ui.setup.program.text(), .hint = "the program and its arguments, e.g. the agent CLI's name", .id = id.field0 + 1, .focused = f == 1 };
                        bufs.fields[2] = .{ .label = "Project name (optional, shown in the title)", .value = ui.setup.project.text(), .hint = "e.g. acme-api", .id = id.field0 + 2, .focused = f == 2 };
                        bufs.fields[3] = .{ .label = "Remote input (Left/Right to change)", .value = policyLabel(ui.setup.input), .id = id.field0 + 3, .focused = f == 3, .choice = true };
                        p.fields = bufs.fields[0..4];
                        if (!ui.setup.first_run) {
                            bufs.fields[4] = .{ .label = "Show system monitor (Left/Right to change; applies now)", .value = if (ui.setup.sysmon) "On: a System button shows CPU, memory, GPU and each tab's load" else "Off", .id = id.field0 + 4, .focused = f == 4, .choice = true };
                            bufs.fields[5] = .{ .label = "Background art (Left/Right to change; applies now)", .value = if (ui.setup.bg_art) "On: the Portal art, faint, behind the terminal" else "Off", .id = id.field0 + 5, .focused = f == 5, .choice = true };
                            bufs.fields[6] = .{ .label = "Claude Code integration (Left/Right or click to install or remove; applies now)", .value = agentLabel(ui.setup.agent), .id = id.field0 + 6, .focused = f == 6, .choice = true };
                            bufs.fields[7] = .{ .label = "Admin prompts at the desk (Left/Right to change; applies now)", .value = if (ui.setup.block_elevation) "Refused: also refuse admin-prompt commands in projects started at the desk" else "Allowed: they run, and the tab asks for you at the desk", .id = id.field0 + 7, .focused = f == 7, .choice = true };
                            bufs.fields[8] = .{ .label = "Tunnel endpoint for devices (HOST:PORT)", .value = ui.setup.tunnel_endpoint.text(), .hint = "your public IP or dynamic-DNS name, and the port the router forwards, e.g. home.example.org:51820", .id = id.field0 + 8, .focused = f == 8 };
                            p.fields = bufs.fields[0..9];
                            ui.tunnelLines(bufs, &na, c);
                        }
                        L.add(&bufs.after, &na, .{ .text = policyHelp(ui.setup.input), .tone = if (ui.setup.input == .text) .bad else .muted });
                        if (!ui.setup.first_run and f == 6) L.add(&bufs.after, &na, .{ .text = "Adds Portal's hooks to Claude Code's settings.json (a backup is kept next to it): each runs `portalctl hook`, which tells this Portal, over a pipe only you can open, when Claude in a tab works, waits for an answer or is done. Nothing is sent outside this computer." });
                        if (!ui.setup.first_run and f == 7) L.add(&bufs.after, &na, .{ .text = "Also refuse admin-prompt commands in projects started at the desk. Off, such a command runs and its tab shows a card until you answer the Windows prompt here. Projects a device started always refuse them: nobody may be at the desk to answer." });
                        if (ui.setup.sysmon and !ui.setup.first_run) L.add(&bufs.after, &na, .{ .text = "The monitor measures only while a System panel is open (once a second); off, it never measures." });
                    },
                    .pair_name => {
                        p.title = "Pair a device";
                        L.add(&bufs.lines, &nl, .{ .text = "On the device, start Portal (portal connect): it shows its tunnel key and that key's check code. Enter a name for it and its key here (type it, or paste it if you copied it over)." });
                        L.add(&bufs.lines, &nl, .{ .text = "Nothing is sent anywhere before you approve: the key decides which device may enter this desktop's tunnel." });
                        bufs.fields[0] = .{ .label = "Device name (a-z, 0-9, -)", .value = ui.name.text(), .hint = "e.g. laptop, iphone, surface", .id = id.field0, .focused = ui.focus.index == 0 };
                        bufs.fields[1] = .{ .label = "The device's tunnel key (44 characters ending in =)", .value = ui.key_text.text(), .hint = "as the device shows it", .id = id.field0 + 1, .focused = ui.focus.index == 1 };
                        p.fields = bufs.fields[0..2];
                    },
                    .pair_check => {
                        p.title = bufs.fmt("Pair '{s}': check code {s}?", .{ ui.name.text(), &ui.check });
                        p.title_tone = .warn;
                        L.add(&bufs.lines, &nl, .{ .text = bufs.fmt("The key you entered has the check code {s}. Approve only if the device shows exactly this code.", .{&ui.check}), .tone = .normal });
                        L.add(&bufs.lines, &nl, .{ .text = "A different code means the key was changed on the way (a mistyped key, or someone else's): deny and copy it again." });
                        L.add(&bufs.lines, &nl, .{ .text = "Y approves, N denies." });
                    },
                    .pair_result => {
                        switch (ui.result) {
                            .paired => {
                                p.title = bufs.fmt("Paired '{s}' as {s}", .{ ui.result_name.get(), ui.result_ip.get() });
                                p.title_tone = .good;
                                L.add(&bufs.lines, &nl, .{ .text = "On the device, enter this pairing code (or scan the QR code):", .tone = .normal, .bold = true });
                                L.add(&bufs.lines, &nl, .{ .text = ui.resultCode(), .tone = .normal });
                                L.add(&bufs.lines, &nl, .{ .text = bufs.fmt("The device then shows this desktop's check code: it must be {s}.", .{&ui.result_desk_check}) });
                                L.add(&bufs.lines, &nl, .{ .text = "The code holds nothing secret (this desktop's public key, where to reach it, the certificate's SHA-256 and the device's tunnel address). Unpair the device any time from Devices." });
                                if (bufs.pairQr(ui.resultCode())) |code| p.qr = code;
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

            /// Settings' tunnel section: this desktop's key and port, and
            /// its peers (the paired devices, `ui.devs`).
            fn tunnelLines(ui: *const Ui, bufs: *Bufs, n: *usize, c: Ctx) void {
                const arr = &bufs.after;
                const add = struct {
                    fn f(a: []frame.PanelText, k: *usize, t: frame.PanelText) void {
                        if (k.* < a.len) {
                            a[k.*] = t;
                            k.* += 1;
                        }
                    }
                }.f;
                add(arr, n, .{ .text = "Tunnel", .tone = .normal, .bold = true });
                add(arr, n, .{ .text = bufs.fmt("This desktop's key: {s}  (check code {s})", .{ c.desk_key, c.desk_check }), .tone = .normal });
                add(arr, n, .{ .text = bufs.fmt("Listening on UDP {d}; devices reach 10.8.0.1 inside the tunnel. A changed port applies at the next start.", .{c.tunnel_port}) });
                if (ui.n_devs == 0) add(arr, n, .{ .text = "Peers: none yet (Pair a device)." });
                for (ui.devs[0..ui.n_devs]) |d| add(arr, n, .{ .text = bufs.fmt("Peer {s: <16} {s: <10} key {s}", .{ d.name.get(), d.ip.get(), d.key.get() }) });
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
