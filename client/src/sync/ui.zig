//! The sync panels of `portal connect` (docs/sync-design.md), as a state
//! machine with no I/O and no drawing, like setup.zig:
//!
//!   * approval: "Install <pkg> <ver> from <desktop>?" with the publisher
//!     key fingerprint and the size, for every new version of an
//!     executable package. Reject is focused first; nothing is approved by
//!     default;
//!   * "Install voice model?" right after pairing, when the desktop offers
//!     voice packages (stt-local, stt-model, stt-adapter);
//!   * Packages (Ctrl+Shift+K): installed versions with Roll back (data) or
//!     Revoke (executables: withdraw the approval, back to the previous
//!     version or uninstalled), versions waiting for approval, and Forget
//!     this desktop; Revoke and Forget ask for confirmation first.
//!
//! No accidental approvals. The approval panel can open by itself after a
//! background pass, while the user is typing into the remote terminal, so:
//!   * there are no letter shortcuts (no y/n): only Approve, activated as a
//!     button (a click, or Enter after moving the focus to it), approves;
//!   * the focus starts on the safe button (Reject / Not now / Close /
//!     Cancel);
//!   * every input (keys and clicks) is ignored until the panel has been on
//!     screen for `guard_ms`, measured from when it was really presented
//!     (`presented`, called by the host after the frame showing it), so a
//!     keystroke or click already on its way cannot land on it. No timer:
//!     each input event compares its own time with the presentation time.
//!
//! connect.zig feeds it each sync pass's report and the store's installed
//! list, hands the Actions it returns to the sync worker, and draws
//! `panel()`.

const std = @import("std");
const view = @import("view");
const TermView = view.TermView;
const input = view.input;
const engine = @import("engine.zig");
const manifest = @import("manifest.zig");

pub const Screen = enum { none, approve, voice, packages, confirm };

/// Input is ignored for this long after a panel appears.
pub const guard_ms: i64 = 600;

pub const id = struct {
    pub const approve: u32 = 301;
    pub const reject: u32 = 302;
    pub const install_voice: u32 = 303;
    pub const later: u32 = 304;
    pub const close: u32 = 305;
    /// The confirmation's destructive button (Revoke / Forget desktop).
    pub const confirm: u32 = 306;
    pub const cancel: u32 = 307;
    /// Packages: "Forget this desktop".
    pub const forget: u32 = 308;
    /// Installed data rows' Roll back buttons: rollback0 + row.
    pub const rollback0: u32 = 400;
    /// Pending rows' Approve buttons: pending0 + report item index.
    pub const pending0: u32 = 500;
    /// Installed executable rows' Revoke buttons: revoke0 + row.
    pub const revoke0: u32 = 600;
};

/// A package id, by value (rows can change before the worker gets to it).
pub const Pkg = struct {
    buf: [manifest.max_package_id]u8 = undefined,
    len: u8 = 0,

    pub fn of(s: []const u8) Pkg {
        var p: Pkg = .{};
        const n = @min(s.len, p.buf.len);
        @memcpy(p.buf[0..n], s[0..n]);
        p.len = @intCast(n);
        return p;
    }
    pub fn slice(p: *const Pkg) []const u8 {
        return p.buf[0..p.len];
    }
};

pub const Action = union(enum) {
    none,
    /// Run a sync pass now (an approval was given).
    rerun,
    /// Roll the package back to its previous version.
    rollback: Pkg,
    /// Withdraw an executable's approval: previous version, or uninstall.
    revoke: Pkg,
    /// Forget this desktop: pins, credential and its sync folder.
    forget_desktop,
};

pub const Installed = struct {
    pkg: [manifest.max_package_id]u8 = undefined,
    pkg_len: u8 = 0,
    cur: [manifest.max_version]u8 = undefined,
    cur_len: u8 = 0,
    prev: [manifest.max_version]u8 = undefined,
    prev_len: u8 = 0,
    kind: manifest.Kind = .data,

    pub fn init(pkg: []const u8, cur: []const u8, prev: ?[]const u8, kind: manifest.Kind) Installed {
        var r: Installed = .{ .kind = kind };
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
    /// What the confirmation screen asks about.
    confirming: union(enum) { revoke: Installed, forget } = .forget,
    /// "10.8.0.1:8420" and the pinned release key's fingerprint.
    desktop_buf: [64]u8 = undefined,
    desktop_len: usize = 0,
    key_fp: [95]u8 = @splat(' '),
    note_buf: [160]u8 = undefined,
    note_len: usize = 0,
    /// Index into the current screen's buttons.
    focus: u8 = 0,
    /// When the current screen was first presented (awake-clock ms); null
    /// until the host reports it. Input before `shown_at + guard_ms` is
    /// ignored.
    shown_at: ?i64 = null,

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

    /// The host presented a frame with the panel at `now_ms` (awake clock).
    /// Only the first presentation of a screen counts.
    pub fn presented(ui: *Ui, now_ms: i64) void {
        if (ui.screen != .none and ui.shown_at == null) ui.shown_at = now_ms;
    }

    /// Whether input at `now_ms` may act on the panel.
    fn armed(ui: *const Ui, now_ms: i64) bool {
        const t = ui.shown_at orelse return false;
        return now_ms -| t >= guard_ms;
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

    /// A sync pass finished: decide what to show. A panel that stays the
    /// same (the same question) keeps its focus and its presentation time.
    pub fn setReport(ui: *Ui, rep: *const engine.Report) void {
        const was_asking: ?Mark = if (ui.screen == .approve) if (ui.asking) |a| Mark.of(&ui.report.items[a]) else null else null;
        ui.report = rep.*;
        ui.asking = null;
        if (ui.voice == .offering and ui.report.count(.offered) == 0) ui.voice = .none;
        switch (ui.screen) {
            .packages, .confirm => return, // the user's own screens
            .none, .approve, .voice => {},
        }
        if (ui.voice == .offering) return ui.show(.voice);
        if (ui.nextPending()) |i| {
            ui.asking = i;
            const same = if (was_asking) |m| m.matches(&ui.report.items[i]) else false;
            if (!same) ui.screen = .none; // a new question: fresh guard
            return ui.show(.approve);
        }
        ui.close();
    }

    fn show(ui: *Ui, s: Screen) void {
        if (ui.screen == s) return;
        ui.screen = s;
        ui.focus = 0; // Reject / Not now / Close / Cancel: the safe button first
        ui.shown_at = null;
    }

    pub fn openPackages(ui: *Ui) void {
        ui.show(.packages);
    }

    pub fn close(ui: *Ui) void {
        ui.screen = .none;
        ui.shown_at = null;
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

    /// Drops this app's approvals of `pkg` (all versions).
    fn unmark(ui: *Ui, pkg: []const u8) void {
        var k: usize = 0;
        for (ui.approved[0..ui.n_approved]) |m| {
            if (std.mem.eql(u8, m.pkg[0..m.pkg_len], pkg)) continue;
            ui.approved[k] = m;
            k += 1;
        }
        ui.n_approved = k;
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

    fn confirm(ui: *Ui, what: @FieldType(Ui, "confirming")) void {
        ui.confirming = what;
        ui.show(.confirm);
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
                out[1] = id.forget;
                break :blk out[0..2];
            },
            .confirm => blk: {
                out[0] = id.cancel;
                out[1] = id.confirm;
                break :blk out[0..2];
            },
        };
    }

    /// A key while a panel is open (it has the keyboard). Nothing happens
    /// before the guard time; letters never act.
    pub fn key(ui: *Ui, k: input.Key, mods: input.Mods, now_ms: i64) Action {
        if (!ui.armed(now_ms)) return .none;
        var b: [3]u32 = undefined;
        const ids = ui.buttonIds(&b);
        switch (k) {
            .escape => return ui.button(switch (ui.screen) {
                .approve => id.reject,
                .voice => id.later,
                .confirm => id.cancel,
                else => id.close,
            }, now_ms),
            .tab, .right, .down => {
                if (ids.len > 0) ui.focus = if (mods.shift) (ui.focus + @as(u8, @intCast(ids.len)) - 1) % @as(u8, @intCast(ids.len)) else (ui.focus + 1) % @as(u8, @intCast(ids.len));
            },
            .left, .up => {
                if (ids.len > 0) ui.focus = (ui.focus + @as(u8, @intCast(ids.len)) - 1) % @as(u8, @intCast(ids.len));
            },
            .enter => if (ui.focus < ids.len) return ui.button(ids[ui.focus], now_ms),
            else => {},
        }
        return .none;
    }

    /// A button activated (clicked, or Enter on the focused one) at
    /// `now_ms`. Ignored before the guard time.
    pub fn button(ui: *Ui, b: u32, now_ms: i64) Action {
        if (!ui.armed(now_ms)) return .none;
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
            id.forget => if (ui.screen == .packages) ui.confirm(.forget),
            id.cancel => if (ui.screen == .confirm) {
                ui.close();
                ui.show(.packages);
            },
            id.confirm => if (ui.screen == .confirm) {
                ui.close();
                switch (ui.confirming) {
                    .forget => return .forget_desktop,
                    .revoke => |row| {
                        ui.unmark(row.package());
                        ui.show(.packages);
                        return .{ .revoke = .of(row.package()) };
                    },
                }
            },
            else => if (ui.screen == .packages) {
                if (b >= id.rollback0 and b < id.rollback0 + ui.n_installed) {
                    const row = &ui.installed[b - id.rollback0];
                    if (row.kind == .data and row.prev_len > 0) return .{ .rollback = .of(row.package()) };
                }
                if (b >= id.revoke0 and b < id.revoke0 + ui.n_installed) {
                    const row = ui.installed[b - id.revoke0];
                    if (row.kind == .executable) ui.confirm(.{ .revoke = row });
                }
                if (b >= id.pending0 and b < id.pending0 + ui.report.n) return ui.approveItem(b - id.pending0);
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
                b.lines[nl] = .{ .text = "Approve installs this version (it is not run). Every new version asks again; Revoke in Packages (Ctrl+Shift+K) withdraws it." };
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
            .confirm => switch (ui.confirming) {
                .revoke => |row| {
                    p.title = std.fmt.bufPrint(&b.txt[0], "Revoke {s} {s}?", .{ row.package(), row.current() }) catch "Revoke?";
                    p.title_tone = .warn;
                    b.lines[nl] = .{ .text = if (row.prev_len > 0)
                        std.fmt.bufPrint(&b.txt[1], "Withdraws your approval: {s} goes back to {s}, and {s} is deleted once nothing runs from it.", .{ row.package(), row.previous(), row.current() }) catch ""
                    else
                        std.fmt.bufPrint(&b.txt[1], "Withdraws your approval: {s} is uninstalled (no earlier version is kept), its folder deleted once nothing runs from it.", .{row.package()}) catch "" };
                    nl += 1;
                    b.lines[nl] = .{ .text = std.fmt.bufPrint(&b.txt[2], "{s} {s} is never installed again; a newer version from the desktop asks for approval again.", .{ row.package(), row.current() }) catch "" };
                    nl += 1;
                },
                .forget => {
                    p.title = std.fmt.bufPrint(&b.txt[0], "Forget {s}?", .{ui.desktop()}) catch "Forget this desktop?";
                    p.title_tone = .bad;
                    b.lines[nl] = .{ .text = "Deletes from this device: the desktop's certificate pin and release-key pin, this device's credential for it, and its sync folder with every package it sent." };
                    nl += 1;
                    b.lines[nl] = .{ .text = "The desktop still lists this device until you unpair it there. Portal closes afterwards; pairing again starts from scratch." };
                    nl += 1;
                },
            },
            .packages => {
                p.title = "Packages";
                b.lines[nl] = .{ .text = std.fmt.bufPrint(&b.txt[0], "From {s}, publisher key SHA-256 {s}", .{ ui.desktop(), &ui.key_fp }) catch "" };
                nl += 1;
                if (ui.n_installed == 0 and ui.report.count(.pending_approval) == 0)
                    b.lines[nl] = .{ .text = "Nothing installed yet." }
                else
                    b.lines[nl] = .{ .text = "Roll back switches data to its previous version; Revoke withdraws a program's approval. Neither version comes back until the desktop publishes a newer one." };
                nl += 1;
                for (ui.installed[0..ui.n_installed], 0..) |*r, i| {
                    if (nr == b.rows.len) break;
                    const bi: u32 = @intCast(i);
                    b.rows[nr] = .{
                        .text = std.fmt.bufPrint(&b.row_txt[nr], "{s: <14} {s}{s}{s}", .{ r.package(), r.current(), if (r.prev_len > 0) "   previous " else "", r.previous() }) catch "",
                        .button = switch (r.kind) {
                            .executable => .{ .label = "Revoke", .id = id.revoke0 + bi, .tone = .bad },
                            .data => if (r.prev_len > 0) .{ .label = "Roll back", .id = id.rollback0 + bi } else null,
                        },
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
                id.cancel => "Cancel",
                id.forget => "Forget this desktop",
                id.confirm => switch (ui.confirming) {
                    .forget => "Forget desktop",
                    .revoke => "Revoke",
                },
                else => "Close",
            },
            .id = bid,
            .focused = ui.focus == i,
            .tone = switch (bid) {
                id.approve, id.install_voice => .good,
                id.reject, id.confirm, id.forget => .bad,
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

/// Presents the current screen at t=1000 and returns a time past the guard.
fn shown(ui: *Ui) i64 {
    ui.presented(1000);
    return 1000 + guard_ms;
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
    const t = shown(&ui);
    try testing.expectEqual(Action.none, ui.key(.enter, .{}, t));
    try testing.expectEqual(Screen.none, ui.screen);
    var ab: [4]engine.Approval = undefined;
    try testing.expectEqual(@as(usize, 0), ui.approvals(&ab).len);
    // The same version is not asked about again; Packages still offers it.
    ui.setReport(&rep);
    try testing.expectEqual(Screen.none, ui.screen);
    ui.openPackages();
    const pp = ui.panel(&b).?;
    try testing.expectEqual(@as(u32, id.pending0 + 1), pp.rows[0].button.?.id);
    const t2 = shown(&ui);
    try testing.expectEqual(Action.rerun, ui.button(id.pending0 + 1, t2));
    const a = ui.approvals(&ab);
    try testing.expectEqual(@as(usize, 1), a.len);
    try testing.expectEqualStrings("npu-probe", a[0].package);
    try testing.expectEqual(@as(u64, 2), a[0].sequence);
}

test "no accidental approval: no letter keys, a guard after the panel appears, only the button approves" {
    var ui: Ui = .{};
    var rep: engine.Report = .{};
    rep.items[0] = item("stt-local", "1", 1, .executable, .pending_approval);
    rep.n = 1;
    ui.setReport(&rep);
    try testing.expectEqual(Screen.approve, ui.screen);
    // Not yet presented: nothing acts, not even a click on Approve.
    try testing.expectEqual(Action.none, ui.button(id.approve, 50_000));
    try testing.expectEqual(Action.none, ui.key(.escape, .{}, 50_000));
    try testing.expectEqual(Screen.approve, ui.screen);
    ui.presented(1000);
    ui.presented(1400); // only the first presentation counts
    try testing.expectEqual(@as(?i64, 1000), ui.shown_at);
    // Within the guard: a click on Approve and Tab+Enter are ignored.
    try testing.expectEqual(Action.none, ui.button(id.approve, 1000 + guard_ms - 1));
    _ = ui.key(.tab, .{}, 1000 + guard_ms - 1);
    try testing.expectEqual(@as(u8, 0), ui.focus);
    try testing.expectEqual(Action.none, ui.key(.enter, .{}, 1000 + guard_ms - 1));
    try testing.expectEqual(Screen.approve, ui.screen);
    // There is no ui.char: letters ('y') cannot reach the panel at all.
    try testing.expect(!@hasDecl(Ui, "char"));
    // After the guard: Tab to Approve, Enter approves (a button activation).
    const t = 1000 + guard_ms;
    _ = ui.key(.tab, .{}, t);
    try testing.expectEqual(@as(u8, 1), ui.focus);
    try testing.expectEqual(Action.rerun, ui.key(.enter, .{}, t));
    // A new version asks again, with a fresh guard.
    rep.items[0] = item("stt-local", "2", 2, .executable, .pending_approval);
    ui.setReport(&rep);
    try testing.expectEqual(Screen.approve, ui.screen);
    try testing.expect(ui.shown_at == null);
    try testing.expectEqual(Action.none, ui.button(id.approve, t + 10_000));
}

test "a later pass asking the same question keeps the guard already served" {
    var ui: Ui = .{};
    var rep: engine.Report = .{};
    rep.items[0] = item("npu-probe", "1", 1, .executable, .pending_approval);
    rep.n = 1;
    ui.setReport(&rep);
    const t = shown(&ui);
    ui.setReport(&rep); // e.g. another {"t":"updates"}
    try testing.expectEqual(@as(?i64, 1000), ui.shown_at);
    try testing.expectEqual(Action.rerun, ui.button(id.approve, t));
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
    try testing.expectEqual(Action.none, ui.button(id.install_voice, 0)); // not presented yet
    const t = shown(&ui);
    try testing.expectEqual(Action.rerun, ui.button(id.install_voice, t));
    try testing.expectEqual(@as(usize, 0), ui.holdList().len);
    var ab: [4]engine.Approval = undefined;
    try testing.expectEqualStrings("stt-local", ui.approvals(&ab)[0].package);

    var later: Ui = .{};
    later.startVoiceOffer();
    later.setReport(&rep);
    const t2 = shown(&later);
    try testing.expectEqual(Action.none, later.key(.escape, .{}, t2));
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

test "packages: Roll back for data with a previous version, Revoke for programs (confirmed)" {
    var ui: Ui = .{};
    ui.setInstalled(&.{ Installed.init("stt-model", "3", "2", .data), Installed.init("npu-probe", "2", "1", .executable), Installed.init("stt-adapter", "1", null, .data) });
    ui.openPackages();
    var b: Ui.Bufs = .{};
    const p = ui.panel(&b).?;
    try testing.expectEqual(@as(usize, 3), p.rows.len);
    try testing.expectEqual(@as(u32, id.rollback0), p.rows[0].button.?.id);
    try testing.expectEqual(@as(u32, id.revoke0 + 1), p.rows[1].button.?.id);
    try testing.expect(p.rows[2].button == null);
    const t = shown(&ui);
    const rb = ui.button(id.rollback0, t);
    try testing.expectEqualStrings("stt-model", rb.rollback.slice());
    try testing.expectEqual(Action.none, ui.button(id.rollback0 + 1, t)); // a program: Revoke, not Roll back
    try testing.expectEqual(Action.none, ui.button(id.rollback0 + 2, t)); // nothing to roll back to

    // Revoke asks first; Cancel is focused and goes back to Packages.
    try testing.expectEqual(Action.none, ui.button(id.revoke0 + 1, t));
    try testing.expectEqual(Screen.confirm, ui.screen);
    const c = ui.panel(&b).?;
    try testing.expectEqualStrings("Revoke npu-probe 2?", c.title);
    try testing.expect(c.buttons[0].focused and c.buttons[0].id == id.cancel);
    try testing.expectEqual(Action.none, ui.key(.enter, .{}, t + 10_000)); // guard: not presented yet
    const t2 = shown(&ui);
    try testing.expectEqual(Action.none, ui.key(.enter, .{}, t2)); // Enter = Cancel
    try testing.expectEqual(Screen.packages, ui.screen);
    _ = ui.button(id.revoke0 + 1, shown(&ui));
    const a = ui.button(id.confirm, shown(&ui));
    try testing.expectEqualStrings("npu-probe", a.revoke.slice());
    try testing.expectEqual(Screen.packages, ui.screen);
}

test "forget this desktop: confirmed, Cancel first" {
    var ui: Ui = .{};
    ui.setDesktop("10.8.0.1:8420", null);
    ui.openPackages();
    var b: Ui.Bufs = .{};
    const p = ui.panel(&b).?;
    try testing.expectEqual(@as(u32, id.forget), p.buttons[1].id);
    try testing.expectEqual(Action.none, ui.button(id.forget, shown(&ui)));
    try testing.expectEqual(Screen.confirm, ui.screen);
    try testing.expectEqualStrings("Forget 10.8.0.1:8420?", ui.panel(&b).?.title);
    const t = shown(&ui);
    try testing.expectEqual(Action.none, ui.key(.escape, .{}, t));
    try testing.expectEqual(Screen.packages, ui.screen);
    _ = ui.button(id.forget, shown(&ui));
    try testing.expectEqual(Action.forget_desktop, ui.button(id.confirm, shown(&ui)));
}
