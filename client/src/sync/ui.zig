//! The sync panels of `portal connect` (docs/sync-design.md), as a state
//! machine with no I/O and no drawing, like setup.zig:
//!
//!   * approval: "Install <pkg> <ver> from <desktop>?" with the publisher
//!     key fingerprint and the size, for every new version of an
//!     executable package. Reject is focused first; nothing is approved by
//!     default;
//!   * "Install voice model?" right after pairing, when the desktop offers
//!     voice packages (stt-local, stt-model, stt-adapter);
//!   * Packages (Ctrl+Shift+K): installed versions with Roll back, and
//!     versions waiting for approval.
//!
//! connect.zig feeds it each sync pass's report and the store's installed
//! list, performs the Actions it returns, and draws `panel()`.

const std = @import("std");
const view = @import("view");
const TermView = view.TermView;
const input = view.input;
const engine = @import("engine.zig");
const manifest = @import("manifest.zig");

pub const Screen = enum { none, approve, voice, packages };

pub const id = struct {
    pub const approve: u32 = 301;
    pub const reject: u32 = 302;
    pub const install_voice: u32 = 303;
    pub const later: u32 = 304;
    pub const close: u32 = 305;
    /// Installed rows' Roll back buttons: rollback0 + row.
    pub const rollback0: u32 = 400;
    /// Pending rows' Approve buttons: pending0 + report item index.
    pub const pending0: u32 = 500;
};

pub const Action = union(enum) {
    none,
    /// Run a sync pass now (an approval was given).
    rerun,
    /// Roll `installed[i]` back to its previous version.
    rollback: usize,
};

pub const Installed = struct {
    pkg: [manifest.max_package_id]u8 = undefined,
    pkg_len: u8 = 0,
    cur: [manifest.max_version]u8 = undefined,
    cur_len: u8 = 0,
    prev: [manifest.max_version]u8 = undefined,
    prev_len: u8 = 0,

    pub fn init(pkg: []const u8, cur: []const u8, prev: ?[]const u8) Installed {
        var r: Installed = .{};
        @memcpy(r.pkg[0..pkg.len], pkg);
        r.pkg_len = @intCast(pkg.len);
        @memcpy(r.cur[0..cur.len], cur);
        r.cur_len = @intCast(cur.len);
        if (prev) |p| {
            @memcpy(r.prev[0..p.len], p);
            r.prev_len = @intCast(p.len);
        }
        return r;
    }
    pub fn package(r: *const Installed) []const u8 {
        return r.pkg[0..r.pkg_len];
    }
    pub fn current(r: *const Installed) []const u8 {
        return r.cur[0..r.cur_len];
    }
    pub fn previous(r: *const Installed) []const u8 {
        return r.prev[0..r.prev_len];
    }
};

pub const Mark = struct {
    pkg: [manifest.max_package_id]u8 = undefined,
    pkg_len: u8 = 0,
    sequence: u64 = 0,
    sha: [32]u8 = @splat(0),

    fn of(it: *const engine.Item) Mark {
        var m: Mark = .{ .sequence = it.sequence, .sha = it.manifest_sha256 };
        @memcpy(m.pkg[0..it.package_len], it.package());
        m.pkg_len = it.package_len;
        return m;
    }
    fn matches(m: *const Mark, it: *const engine.Item) bool {
        return std.mem.eql(u8, m.pkg[0..m.pkg_len], it.package()) and m.sequence == it.sequence and std.mem.eql(u8, &m.sha, &it.manifest_sha256);
    }
};

pub const max_marks = 32;

/// Approvals for engine.Options; the names point into `marks`.
pub fn approvalsFrom(marks: []const Mark, out: []engine.Approval) []engine.Approval {
    const n = @min(out.len, marks.len);
    for (marks[0..n], 0..) |*m, i| out[i] = .{ .package = m.pkg[0..m.pkg_len], .sequence = m.sequence, .manifest_sha256 = m.sha };
    return out[0..n];
}

pub const Ui = struct {
    screen: Screen = .none,
    report: engine.Report = .{},
    installed: [32]Installed = undefined,
    n_installed: usize = 0,
    approved: [max_marks]Mark = undefined,
    n_approved: usize = 0,
    rejected: [max_marks]Mark = undefined,
    n_rejected: usize = 0,
    /// The report item the approval panel asks about.
    asking: ?usize = null,
    voice: enum { none, offering, accepted, declined } = .none,
    /// "10.8.0.1:8420" and the pinned release key's fingerprint.
    desktop_buf: [64]u8 = undefined,
    desktop_len: usize = 0,
    key_fp: [95]u8 = @splat(' '),
    note_buf: [160]u8 = undefined,
    note_len: usize = 0,
    /// Index into the current screen's buttons.
    focus: u8 = 0,

    pub fn setDesktop(ui: *Ui, host: []const u8, release_key: ?[32]u8) void {
        const n = @min(host.len, ui.desktop_buf.len);
        @memcpy(ui.desktop_buf[0..n], host[0..n]);
        ui.desktop_len = n;
        if (release_key) |k| _ = manifest.formatFingerprint(manifest.fingerprint(k), &ui.key_fp);
    }

    fn desktop(ui: *const Ui) []const u8 {
        return ui.desktop_buf[0..ui.desktop_len];
    }

    pub fn setNote(ui: *Ui, comptime fmt: []const u8, args: anytype) void {
        ui.note_len = (std.fmt.bufPrint(&ui.note_buf, fmt, args) catch @as([]u8, &.{})).len;
    }

    pub fn open(ui: *const Ui) bool {
        return ui.screen != .none;
    }

    /// Right after pairing: hold the voice packages for the offer.
    pub fn startVoiceOffer(ui: *Ui) void {
        if (ui.voice == .none) ui.voice = .offering;
    }

    /// Packages the next pass must not install yet.
    pub fn holdList(ui: *const Ui) []const []const u8 {
        return switch (ui.voice) {
            .offering, .declined => &manifest.voice_packages,
            else => &.{},
        };
    }

    /// Exact manifests approved in this app (for Options.approved).
    pub fn approvals(ui: *const Ui, out: []engine.Approval) []engine.Approval {
        return approvalsFrom(ui.approved[0..ui.n_approved], out);
    }

    pub fn setInstalled(ui: *Ui, rows: []const Installed) void {
        const n = @min(rows.len, ui.installed.len);
        @memcpy(ui.installed[0..n], rows[0..n]);
        ui.n_installed = n;
    }

    fn isRejected(ui: *const Ui, it: *const engine.Item) bool {
        for (ui.rejected[0..ui.n_rejected]) |*m| if (m.matches(it)) return true;
        return false;
    }

    fn nextPending(ui: *const Ui) ?usize {
        for (ui.report.slice(), 0..) |*it, i| {
            if (it.outcome == .pending_approval and !ui.isRejected(it)) return i;
        }
        return null;
    }

    /// A sync pass finished: decide what to show.
    pub fn setReport(ui: *Ui, rep: *const engine.Report) void {
        ui.report = rep.*;
        if (ui.asking) |a| if (a >= ui.report.n or ui.report.items[a].outcome != .pending_approval) {
            ui.asking = null;
        };
        if (ui.voice == .offering and ui.report.count(.offered) == 0) ui.voice = .none;
        if (ui.screen != .none and ui.screen != .packages) ui.screen = .none;
        if (ui.screen == .packages) return;
        if (ui.voice == .offering) return ui.show(.voice);
        if (ui.nextPending()) |i| {
            ui.asking = i;
            ui.show(.approve);
        }
    }

    fn show(ui: *Ui, s: Screen) void {
        ui.screen = s;
        ui.focus = 0; // Reject / Not now / Close: the safe button first
    }

    pub fn openPackages(ui: *Ui) void {
        ui.show(.packages);
    }

    pub fn close(ui: *Ui) void {
        ui.screen = .none;
    }

    fn mark(list: []Mark, n: *usize, it: *const engine.Item) void {
        for (list[0..n.*]) |*m| if (m.matches(it)) return;
        if (n.* == list.len) {
            std.mem.copyForwards(Mark, list[0 .. list.len - 1], list[1..]);
            n.* -= 1;
        }
        list[n.*] = Mark.of(it);
        n.* += 1;
    }

    fn approveItem(ui: *Ui, i: usize) Action {
        if (i >= ui.report.n) return .none;
        const it = &ui.report.items[i];
        if (it.outcome != .pending_approval) return .none;
        mark(&ui.approved, &ui.n_approved, it);
        it.outcome = .installed; // optimistic; the pass reports the truth
        it.setDetailText("approved: installing");
        ui.close();
        return .rerun;
    }

    // ------------------------------------------------------------ input

    pub fn buttonIds(ui: *const Ui, out: *[3]u32) []const u32 {
        return switch (ui.screen) {
            .none => out[0..0],
            .approve => blk: {
                out[0] = id.reject;
                out[1] = id.approve;
                break :blk out[0..2];
            },
            .voice => blk: {
                out[0] = id.later;
                out[1] = id.install_voice;
                break :blk out[0..2];
            },
            .packages => blk: {
                out[0] = id.close;
                break :blk out[0..1];
            },
        };
    }

    pub fn key(ui: *Ui, k: input.Key, mods: input.Mods) Action {
        var b: [3]u32 = undefined;
        const ids = ui.buttonIds(&b);
        switch (k) {
            .escape => return ui.button(switch (ui.screen) {
                .approve => id.reject,
                .voice => id.later,
                else => id.close,
            }),
            .tab, .right, .down => {
                if (ids.len > 0) ui.focus = if (mods.shift) (ui.focus + @as(u8, @intCast(ids.len)) - 1) % @as(u8, @intCast(ids.len)) else (ui.focus + 1) % @as(u8, @intCast(ids.len));
            },
            .left, .up => {
                if (ids.len > 0) ui.focus = (ui.focus + @as(u8, @intCast(ids.len)) - 1) % @as(u8, @intCast(ids.len));
            },
            .enter => if (ui.focus < ids.len) return ui.button(ids[ui.focus]),
            else => {},
        }
        return .none;
    }

    pub fn char(ui: *Ui, cp: u21, mods: input.Mods) Action {
        if (mods.ctrl or mods.alt) return .none;
        if (ui.screen == .approve) {
            if (cp == 'y' or cp == 'Y') return ui.button(id.approve);
            if (cp == 'n' or cp == 'N') return ui.button(id.reject);
        }
        return .none;
    }

    pub fn button(ui: *Ui, b: u32) Action {
        switch (b) {
            id.approve => if (ui.screen == .approve) if (ui.asking) |i| return ui.approveItem(i),
            id.reject => if (ui.screen == .approve) {
                if (ui.asking) |i| mark(&ui.rejected, &ui.n_rejected, &ui.report.items[i]);
                ui.asking = null;
                ui.close();
                if (ui.nextPending()) |n| {
                    ui.asking = n;
                    ui.show(.approve);
                }
            },
            id.install_voice => if (ui.screen == .voice) {
                ui.voice = .accepted;
                // Accepting the offer approves the voice program too.
                for (ui.report.slice()) |*it| if (it.outcome == .offered and it.kind == .executable) mark(&ui.approved, &ui.n_approved, it);
                ui.close();
                return .rerun;
            },
            id.later => if (ui.screen == .voice) {
                ui.voice = .declined;
                ui.close();
            },
            id.close => ui.close(),
            else => {
                if (ui.screen == .packages and b >= id.rollback0 and b < id.rollback0 + ui.n_installed and ui.installed[b - id.rollback0].prev_len > 0) return .{ .rollback = b - id.rollback0 };
                if (ui.screen == .packages and b >= id.pending0 and b < id.pending0 + ui.report.n) return ui.approveItem(b - id.pending0);
            },
        }
        return .none;
    }

    // ---------------------------------------------------------- drawing

    pub const Bufs = struct {
        lines: [8]TermView.PanelText = undefined,
        rows: [48]TermView.PanelRow = undefined,
        buttons: [3]TermView.PanelButton = undefined,
        txt: [8][240]u8 = undefined,
        row_txt: [48][160]u8 = undefined,
    };

    fn size(b: u64, buf: []u8) []const u8 {
        if (b >= 10 << 20) return std.fmt.bufPrint(buf, "{d} MB", .{b >> 20}) catch "";
        if (b >= 10 << 10) return std.fmt.bufPrint(buf, "{d} KB", .{b >> 10}) catch "";
        return std.fmt.bufPrint(buf, "{d} bytes", .{b}) catch "";
    }

    pub fn panel(ui: *const Ui, b: *Bufs) ?TermView.Panel {
        var p: TermView.Panel = .{ .title = "" };
        var nl: usize = 0;
        var nr: usize = 0;
        switch (ui.screen) {
            .none => return null,
            .approve => {
                const i = ui.asking orelse return null;
                const it = &ui.report.items[i];
                var sb: [32]u8 = undefined;
                p.title = std.fmt.bufPrint(&b.txt[0], "Install {s} {s} from {s}?", .{ it.package(), it.version(), ui.desktop() }) catch "Install?";
                p.title_tone = .warn;
                b.lines[nl] = .{ .text = std.fmt.bufPrint(&b.txt[1], "A program, {s}, signed with the release key you pinned when pairing:", .{size(it.size, &sb)}) catch "" };
                nl += 1;
                b.lines[nl] = .{ .text = std.fmt.bufPrint(&b.txt[2], "publisher key SHA-256 {s}", .{&ui.key_fp}) catch "", .tone = .normal };
                nl += 1;
                b.lines[nl] = .{ .text = "Approve installs this version (it is not run). Every new version asks again." };
                nl += 1;
            },
            .voice => {
                p.title = "Install voice model?";
                b.lines[nl] = .{ .text = std.fmt.bufPrint(&b.txt[0], "{s} offers speech-to-text for this device, signed with the release key pinned at pairing:", .{ui.desktop()}) catch "" };
                nl += 1;
                for (ui.report.slice()) |*it| {
                    if (it.outcome != .offered or nr == b.rows.len) continue;
                    var sb: [32]u8 = undefined;
                    b.rows[nr] = .{ .text = std.fmt.bufPrint(&b.row_txt[nr], "{s} {s}  ({t}, {s})", .{ it.package(), it.version(), it.kind, size(it.size, &sb) }) catch "" };
                    nr += 1;
                }
                b.lines[nl] = .{ .text = "Install downloads and verifies them; nothing is run. Later updates (a newly trained adapter) arrive by themselves." };
                nl += 1;
            },
            .packages => {
                p.title = "Packages";
                b.lines[nl] = .{ .text = std.fmt.bufPrint(&b.txt[0], "From {s}, publisher key SHA-256 {s}", .{ ui.desktop(), &ui.key_fp }) catch "" };
                nl += 1;
                if (ui.n_installed == 0 and ui.report.count(.pending_approval) == 0)
                    b.lines[nl] = .{ .text = "Nothing installed yet." }
                else
                    b.lines[nl] = .{ .text = "Roll back switches to the previous version; it stays until the desktop publishes a newer one." };
                nl += 1;
                for (ui.installed[0..ui.n_installed], 0..) |*r, i| {
                    if (nr == b.rows.len) break;
                    b.rows[nr] = .{
                        .text = std.fmt.bufPrint(&b.row_txt[nr], "{s: <14} {s}{s}{s}", .{ r.package(), r.current(), if (r.prev_len > 0) "   previous " else "", r.previous() }) catch "",
                        .button = if (r.prev_len > 0) .{ .label = "Roll back", .id = id.rollback0 + @as(u32, @intCast(i)) } else null,
                    };
                    nr += 1;
                }
                for (ui.report.slice(), 0..) |*it, i| {
                    if (nr == b.rows.len) break;
                    switch (it.outcome) {
                        .pending_approval => b.rows[nr] = .{
                            .text = std.fmt.bufPrint(&b.row_txt[nr], "{s: <14} {s}   waiting for approval", .{ it.package(), it.version() }) catch "",
                            .tone = .warn,
                            .button = .{ .label = "Approve", .id = id.pending0 + @as(u32, @intCast(i)), .tone = .good },
                        },
                        .rejected, .refused => b.rows[nr] = .{
                            .text = std.fmt.bufPrint(&b.row_txt[nr], "{s: <14} {s}   {s}", .{ it.package(), it.version(), it.detail() }) catch "",
                            .tone = .bad,
                        },
                        else => continue,
                    }
                    nr += 1;
                }
            },
        }
        p.lines = b.lines[0..nl];
        p.rows = b.rows[0..nr];
        if (ui.note_len > 0) p.note = .{ .text = ui.note_buf[0..ui.note_len], .tone = .warn };
        var ib: [3]u32 = undefined;
        const ids = ui.buttonIds(&ib);
        for (ids, 0..) |bid, i| b.buttons[i] = .{
            .label = switch (bid) {
                id.approve => "Approve",
                id.reject => "Reject",
                id.install_voice => "Install",
                id.later => "Not now",
                else => "Close",
            },
            .id = bid,
            .focused = ui.focus == i,
            .tone = switch (bid) {
                id.approve, id.install_voice => .good,
                id.reject => .bad,
                else => .normal,
            },
        };
        p.buttons = b.buttons[0..ids.len];
        return p;
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn item(pkg: []const u8, ver: []const u8, seq: u64, kind: manifest.Kind, outcome: engine.Outcome) engine.Item {
    var it: engine.Item = .{ .sequence = seq, .kind = kind, .outcome = outcome, .size = 4096 };
    @memcpy(it.package_buf[0..pkg.len], pkg);
    it.package_len = @intCast(pkg.len);
    @memcpy(it.version_buf[0..ver.len], ver);
    it.version_len = @intCast(ver.len);
    it.manifest_sha256 = @splat(@intCast(seq));
    return it;
}

test "approval: Reject is focused first; approve marks the exact manifest and reruns" {
    var ui: Ui = .{};
    ui.setDesktop("10.8.0.1:8420", @splat(1));
    var rep: engine.Report = .{};
    rep.items[0] = item("stt-model", "3", 3, .data, .installed);
    rep.items[1] = item("npu-probe", "0.2", 2, .executable, .pending_approval);
    rep.n = 2;
    ui.setReport(&rep);
    try testing.expectEqual(Screen.approve, ui.screen);
    var b: Ui.Bufs = .{};
    const p = ui.panel(&b).?;
    try testing.expectEqualStrings("Install npu-probe 0.2 from 10.8.0.1:8420?", p.title);
    try testing.expect(p.buttons[0].focused and p.buttons[0].id == id.reject);
    // Enter on the default focus rejects.
    try testing.expectEqual(Action.none, ui.key(.enter, .{}));
    try testing.expectEqual(Screen.none, ui.screen);
    var ab: [4]engine.Approval = undefined;
    try testing.expectEqual(@as(usize, 0), ui.approvals(&ab).len);
    // The same version is not asked about again; Packages still offers it.
    ui.setReport(&rep);
    try testing.expectEqual(Screen.none, ui.screen);
    ui.openPackages();
    const pp = ui.panel(&b).?;
    try testing.expectEqual(@as(u32, id.pending0 + 1), pp.rows[0].button.?.id);
    try testing.expectEqual(Action.rerun, ui.button(id.pending0 + 1));
    const a = ui.approvals(&ab);
    try testing.expectEqual(@as(usize, 1), a.len);
    try testing.expectEqualStrings("npu-probe", a[0].package);
    try testing.expectEqual(@as(u64, 2), a[0].sequence);
}

test "approval by y; a new version asks again" {
    var ui: Ui = .{};
    var rep: engine.Report = .{};
    rep.items[0] = item("stt-local", "1", 1, .executable, .pending_approval);
    rep.n = 1;
    ui.setReport(&rep);
    try testing.expectEqual(Action.rerun, ui.char('y', .{}));
    rep.items[0] = item("stt-local", "2", 2, .executable, .pending_approval);
    ui.setReport(&rep);
    try testing.expectEqual(Screen.approve, ui.screen);
}

test "voice offer after pairing: held, then Install approves the voice program" {
    var ui: Ui = .{};
    ui.startVoiceOffer();
    try testing.expectEqual(@as(usize, 3), ui.holdList().len);
    var rep: engine.Report = .{};
    rep.items[0] = item("stt-model", "1", 1, .data, .offered);
    rep.items[1] = item("stt-local", "1", 1, .executable, .offered);
    rep.n = 2;
    ui.setReport(&rep);
    try testing.expectEqual(Screen.voice, ui.screen);
    var b: Ui.Bufs = .{};
    try testing.expectEqualStrings("Install voice model?", ui.panel(&b).?.title);
    try testing.expectEqual(Action.rerun, ui.button(id.install_voice));
    try testing.expectEqual(@as(usize, 0), ui.holdList().len);
    var ab: [4]engine.Approval = undefined;
    try testing.expectEqualStrings("stt-local", ui.approvals(&ab)[0].package);

    var later: Ui = .{};
    later.startVoiceOffer();
    later.setReport(&rep);
    try testing.expectEqual(Action.none, later.key(.escape, .{}));
    try testing.expectEqual(@as(usize, 3), later.holdList().len); // stays held this session

    // No voice packages offered: no question.
    var none: Ui = .{};
    none.startVoiceOffer();
    var r2: engine.Report = .{};
    r2.items[0] = item("npu-probe", "1", 1, .executable, .installed);
    r2.n = 1;
    none.setReport(&r2);
    try testing.expectEqual(Screen.none, none.screen);
    try testing.expectEqual(@as(usize, 0), none.holdList().len);
}

test "packages: roll back buttons only where a previous version exists" {
    var ui: Ui = .{};
    ui.setInstalled(&.{ Installed.init("stt-model", "3", "2"), Installed.init("npu-probe", "1", null) });
    ui.openPackages();
    var b: Ui.Bufs = .{};
    const p = ui.panel(&b).?;
    try testing.expectEqual(@as(usize, 2), p.rows.len);
    try testing.expectEqual(@as(u32, id.rollback0), p.rows[0].button.?.id);
    try testing.expect(p.rows[1].button == null);
    try testing.expectEqual(Action{ .rollback = 0 }, ui.button(id.rollback0));
    try testing.expectEqual(Action.none, ui.button(id.rollback0 + 1));
}
