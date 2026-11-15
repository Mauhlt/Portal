//! The desk's panels (portal_ui's panels.desk: first-run / Settings,
//! pairing approval, Devices) bound to the device
//! store's types (devices.zig), and their tests. The window glue (gui.zig)
//! performs the panels' actions.

const std = @import("std");
const rules = @import("inputrules");
const devices = @import("devices.zig");
const P = @import("portal_ui").panels.desk.Panels(devices);

pub const Screen = P.Screen;
pub const id = P.id;
pub const tools = P.tools;
pub const Action = P.Action;
pub const DevRow = P.DevRow;
pub const PkgRow = P.PkgRow;
pub const max_pkgs = P.max_pkgs;
pub const PairResult = P.PairResult;
pub const Setup = P.Setup;
pub const Ui = P.Ui;
pub const MoveRow = P.MoveRow;
pub const AgentHooks = P.AgentHooks;
pub const cyclePolicy = P.cyclePolicy;
pub const policyLabel = P.policyLabel;
pub const ago = P.ago;

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn typeText(ui: *Ui, s: []const u8) void {
    for (s) |ch| _ = ui.char(ch, .{});
}

test "pairing: name and key, check code, approve with y, pairing code shown" {
    var ui: Ui = .{};
    ui.openPair();
    try testing.expectEqual(Screen.pair_name, ui.screen);
    // An invalid name is refused with a note, not an action.
    _ = ui.key(.tab, .{});
    try testing.expectEqual(Action.none, ui.key(.enter, .{}));
    try testing.expect(ui.note().len > 0);
    _ = ui.key(.tab, .{}); // back to the name (wraps through the buttons)
    ui.focus.index = 0;
    typeText(&ui, "Laptop!");
    try testing.expectEqualStrings("laptop", ui.name.text());
    try testing.expectEqual(Action.none, ui.key(.enter, .{})); // on to the key
    try testing.expectEqual(Action.paste, ui.char('v', .{ .ctrl = true }));
    ui.paste("hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=");
    try testing.expectEqual(Action.check_key, ui.key(.enter, .{}));
    ui.keyChecked("ABCD-EFGH-JKMN-PQRS".*);
    try testing.expectEqual(Screen.pair_check, ui.screen);
    var bufs: Ui.Bufs = .{};
    const q = ui.panel(&bufs, .{}).?;
    try testing.expect(std.mem.indexOf(u8, q.title, "ABCD-EFGH-JKMN-PQRS") != null);
    // Deny has the focus: Enter denies; y approves.
    try testing.expectEqualStrings("Deny", q.buttons[0].label);
    try testing.expect(q.buttons[0].focused);
    try testing.expectEqual(Action.approve_pair, ui.char('y', .{}));
    const code = "portal-pair 2 10.8.0.1:8420 " ++ "00070E151C232A31383F464D545B626970777E858C939AA1A8AFB6BDC4CBD2D9 home.example.org:51820 hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo= 10.8.0.2";
    ui.paired("10.8.0.2", code, "KLMN-PQRS-TVWX-YZ01".*);
    try testing.expectEqual(Screen.pair_result, ui.screen);
    const r = ui.panel(&bufs, .{}).?;
    try testing.expect(std.mem.indexOf(u8, r.title, "10.8.0.2") != null);
    try testing.expect(r.qr != null);
    try testing.expectEqualStrings("", ui.key_text.text()); // the key field is cleared
}

test "pairing: deny goes back with a note; Esc in the question goes back" {
    var ui: Ui = .{};
    ui.openPair();
    typeText(&ui, "iphone");
    ui.keyChecked("ABCD-EFGH-JKMN-PQRS".*);
    _ = ui.key(.enter, .{}); // Deny is focused
    try testing.expectEqual(Screen.pair_name, ui.screen);
    try testing.expect(ui.note().len > 0);
    ui.keyChecked("ABCD-EFGH-JKMN-PQRS".*);
    _ = ui.key(.escape, .{});
    try testing.expectEqual(Screen.pair_name, ui.screen);
    ui.pairFailed("no", .{});
    try testing.expectEqual(PairResult.failed, ui.result);
    try testing.expectEqual(Action.none, ui.button(id.again));
    try testing.expectEqual(Screen.pair_name, ui.screen);
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

test "devices: P opens a device's sync packages; Enter or a click toggles" {
    var ui: Ui = .{};
    _ = ui.openDevices();
    var rows: [1]DevRow = .{.{}};
    rows[0].name.set("laptop");
    ui.setDevices(&rows);
    const a = ui.char('p', .{});
    try testing.expect(a == .load_subs and a.load_subs == 0);
    try testing.expectEqual(Screen.dev_packages, ui.screen);
    var pk: [2]PkgRow = .{ .{}, .{} };
    pk[0].name.set("stt-model");
    pk[0].on = true;
    pk[1].name.set("npu-probe");
    ui.setPackages(&pk);
    const t = ui.key(.enter, .{});
    try testing.expect(t == .toggle_sub and t.toggle_sub == 0);
    const c = ui.button(id.pkg0 + 1);
    try testing.expect(c == .toggle_sub and c.toggle_sub == 1);
    var b: Ui.Bufs = .{};
    const p = ui.panel(&b, .{}).?;
    try testing.expectEqualStrings("Packages for laptop", p.title);
    try testing.expectEqualStrings("Unsubscribe", p.rows[0].button.?.label);
    try testing.expectEqual(Action.load_devices, ui.key(.escape, .{}));
    try testing.expectEqual(Screen.devices, ui.screen);
}

test "setup: fields, choice, submit; settings can be cancelled" {
    var ui: Ui = .{};
    ui.openSetup(true, "51820", "", "", .keys);
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
    try testing.expectEqual(rules.Policy.instruct, ui.setup.input);
    _ = ui.key(.left, .{});
    _ = ui.key(.left, .{});
    try testing.expectEqual(rules.Policy.none, ui.setup.input);
    try testing.expectEqual(Action.setup_submit, ui.key(.enter, .{}));
    _ = ui.button(id.field0); // click: focus the tunnel port field
    try testing.expectEqual(Action.paste, ui.char('v', .{ .ctrl = true }));
    _ = ui.key(.backspace, .{});
    ui.paste("9\ny");
    try testing.expectEqualStrings("51829", ui.setup.tunnel_port.text());

    var s: Ui = .{};
    s.openSetup(false, "a", "b", "c", .text);
    try testing.expectEqual(Action.setup_cancel, s.key(.escape, .{}));
    try testing.expectEqual(Screen.none, s.screen);
}

test "settings: Show system monitor is a fifth choice (not on the first run), off by default" {
    var ui: Ui = .{};
    ui.openSetup(true, "a", "b", "c", .keys);
    var b: Ui.Bufs = .{};
    try testing.expectEqual(@as(usize, 4), ui.panel(&b, .{}).?.fields.len);
    var s: Ui = .{};
    s.openSetup(false, "a", "b", "c", .keys);
    try testing.expect(!s.setup.sysmon);
    var b2: Ui.Bufs = .{};
    const p = s.panel(&b2, .{}).?;
    try testing.expectEqual(@as(usize, 9), p.fields.len);
    try testing.expectEqualStrings("Off", p.fields[4].value);
    // A click focuses it, a second click flips it; Left/Right and space too.
    _ = s.button(id.field0 + 4);
    try testing.expect(!s.setup.sysmon);
    _ = s.button(id.field0 + 4);
    try testing.expect(s.setup.sysmon);
    _ = s.key(.left, .{});
    try testing.expect(!s.setup.sysmon);
    _ = s.char(' ', .{});
    try testing.expect(s.setup.sysmon);
    try testing.expectEqual(rules.Policy.keys, s.setup.input); // the policy is untouched
    // Enter: on to "Background art", "Claude Code integration", "Admin
    // prompts at the desk", the tunnel endpoint, then submit.
    try testing.expectEqual(Action.none, s.key(.enter, .{}));
    try testing.expectEqual(Action.none, s.key(.enter, .{}));
    try testing.expectEqual(Action.none, s.key(.enter, .{}));
    try testing.expectEqual(Action.none, s.key(.enter, .{}));
    try testing.expectEqual(Action.setup_submit, s.key(.enter, .{}));
}

test "settings: Background art is a sixth choice, on by default" {
    var s: Ui = .{};
    s.openSetup(false, "a", "b", "c", .keys);
    try testing.expect(s.setup.bg_art);
    var b: Ui.Bufs = .{};
    const p = s.panel(&b, .{}).?;
    try testing.expect(std.mem.startsWith(u8, p.fields[5].value, "On"));
    _ = s.button(id.field0 + 5);
    _ = s.button(id.field0 + 5);
    try testing.expect(!s.setup.bg_art);
    _ = s.key(.right, .{});
    try testing.expect(s.setup.bg_art);
    try testing.expect(s.setup.sysmon == false); // the monitor is untouched
}

test "ago" {
    var b: [32]u8 = undefined;
    try testing.expectEqualStrings("just now", ago(100, 90, &b));
    try testing.expectEqualStrings("5 min ago", ago(400, 100, &b));
    try testing.expectEqualStrings("3 h ago", ago(3 * 3600 + 10, 10, &b));
    try testing.expectEqualStrings("4 days ago", ago(4 * 86400 + 10, 10, &b));
    try testing.expectEqualStrings("never", ago(100, 0, &b));
}

test "settings: agent integration is a seventh choice that acts at once (not on the first run)" {
    var s: Ui = .{};
    s.openSetup(false, "a", "b", "c", .keys);
    s.setup.agent = .not_installed;
    var b: Ui.Bufs = .{};
    var p = s.panel(&b, .{}).?;
    try testing.expect(std.mem.indexOf(u8, p.fields[6].value, "Not installed") != null);
    // The first click focuses it, the second asks the glue to act.
    try testing.expectEqual(Action.none, s.button(id.field0 + 6));
    try testing.expectEqual(Action.agent_hooks, s.button(id.field0 + 6));
    try testing.expectEqual(Action.agent_hooks, s.key(.right, .{}));
    try testing.expectEqual(Action.agent_hooks, s.char(' ', .{}));
    s.setup.agent = .installed;
    p = s.panel(&b, .{}).?;
    try testing.expect(std.mem.indexOf(u8, p.fields[6].value, "Remove") != null);
    // Nothing else changed.
    try testing.expect(!s.setup.sysmon and s.setup.bg_art);
    // Not on the first run.
    var f: Ui = .{};
    f.openSetup(true, "a", "b", "c", .keys);
    var fb: Ui.Bufs = .{};
    try testing.expectEqual(@as(usize, 4), f.panel(&fb, .{}).?.fields.len);
}

test "settings: admin prompts at the desk is a choice next to the agent integration, off by default" {
    var s: Ui = .{};
    s.openSetup(false, "a", "b", "c", .keys);
    var b: Ui.Bufs = .{};
    var p = s.panel(&b, .{}).?;
    try testing.expectEqual(@as(usize, 9), p.fields.len);
    try testing.expect(p.fields[7].choice);
    try testing.expect(std.mem.startsWith(u8, p.fields[7].value, "Allowed"));
    try testing.expect(!s.setup.block_elevation);
    // The first click focuses it, the second flips it; keys and space too.
    _ = s.button(id.field0 + 7);
    try testing.expect(!s.setup.block_elevation);
    _ = s.button(id.field0 + 7);
    try testing.expect(s.setup.block_elevation);
    p = s.panel(&b, .{}).?;
    try testing.expect(std.mem.indexOf(u8, p.fields[7].value, "also refuse admin-prompt commands in projects started at the desk") != null);
    var explained = false;
    for (p.after) |t| explained = explained or std.mem.startsWith(u8, t.text, "Also refuse admin-prompt commands in projects started at the desk");
    try testing.expect(explained);
    try testing.expectEqual(Action.none, s.key(.left, .{}));
    try testing.expect(!s.setup.block_elevation);
    try testing.expectEqual(Action.none, s.char(' ', .{}));
    try testing.expect(s.setup.block_elevation);
    // Nothing else changed; the tunnel endpoint is the text field after it.
    try testing.expect(!s.setup.sysmon and s.setup.bg_art and s.setup.input == .keys);
    _ = s.key(.down, .{});
    typeText(&s, "home.example.org:51820");
    try testing.expectEqualStrings("home.example.org:51820", s.setup.tunnel_endpoint.text());
    try testing.expectEqual(Action.setup_submit, s.button(id.save));
}

test "setup: the button says Start on first run and Save in Settings" {
    var b: Ui.Bufs = .{};
    var first: Ui = .{};
    first.openSetup(true, "51820", "", "", .keys);
    const p1 = first.panel(&b, .{}).?;
    try testing.expectEqualStrings("Start", p1.buttons[p1.buttons.len - 1].label);
    var later: Ui = .{};
    later.openSetup(false, "51820", "cmd.exe", "", .keys);
    const p2 = later.panel(&b, .{}).?;
    try testing.expectEqualStrings("Save", p2.buttons[p2.buttons.len - 1].label);
    try testing.expectEqual(Action.setup_submit, later.button(id.save));
}

test "moving the tunnel: confirm with the router warning, then per-device outcome" {
    var ui: Ui = .{};
    ui.openMoveConfirm(51820, 51821, "home.example.org:51821");
    try testing.expectEqual(Screen.move_confirm, ui.screen);
    var b: Ui.Bufs = .{};
    const p = ui.panel(&b, .{}).?;
    var warned = false;
    for (p.lines) |l| warned = warned or std.mem.indexOf(u8, l.text, "Forward UDP 51821 on your router before switching") != null;
    try testing.expect(warned);
    // Nothing moves by default: Enter on the default (last) button is
    // "Switch now" only after the owner reads it; Escape cancels.
    try testing.expectEqual(@as(usize, 2), p.buttons.len);
    try testing.expectEqualStrings("Switch now", p.buttons[1].label);
    try testing.expectEqual(Action.move_tunnel, ui.button(id.move_go));
    ui.moveStarted();
    try testing.expectEqual(@as(usize, 0), ui.panel(&b, .{}).?.buttons.len);
    var rows: [2]MoveRow = .{ .{ .state = .moved }, .{ .state = .offline } };
    rows[0].name.set("laptop");
    rows[1].name.set("iphone");
    ui.moveDone(true, &rows);
    const r = ui.panel(&b, .{}).?;
    try testing.expectEqualStrings("The tunnel listens on UDP 51821", r.title);
    var moved = false;
    var offline = false;
    for (r.lines) |l| {
        moved = moved or (std.mem.indexOf(u8, l.text, "laptop") != null and std.mem.indexOf(u8, l.text, "moved") != null);
        offline = offline or (std.mem.indexOf(u8, l.text, "iphone") != null and std.mem.indexOf(u8, l.text, "not yet (offline)") != null);
    }
    try testing.expect(moved and offline);
    ui.openMoveConfirm(51820, 51821, "");
    _ = ui.button(id.cancel);
    try testing.expectEqual(Screen.none, ui.screen);
}
