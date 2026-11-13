//! The sync panels (portal_ui's panels.sync) bound to this client's sync
//! engine and manifest format, and their tests.

const std = @import("std");
const engine = @import("engine.zig");
const manifest = @import("manifest.zig");
const P = @import("portal_ui").panels.sync.Panels(engine, manifest);

pub const Screen = P.Screen;
pub const guard_ms = P.guard_ms;
pub const id = P.id;
pub const Pkg = P.Pkg;
pub const Action = P.Action;
pub const Installed = P.Installed;
pub const Mark = P.Mark;
pub const max_marks = P.max_marks;
pub const approvalsFrom = P.approvalsFrom;
pub const Ui = P.Ui;

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
