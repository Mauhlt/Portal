//! The desk's panels (portal_ui's panels.desk: first-run / Settings,
//! pairing approval, Devices, Export certificate) bound to the device
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
pub const cyclePolicy = P.cyclePolicy;
pub const policyLabel = P.policyLabel;
pub const ago = P.ago;

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

test "pairing: the open window shows the pairing QR code over TLS only" {
    var ui: Ui = .{};
    ui.openPair();
    typeText(&ui, "iphone");
    _ = ui.key(.enter, .{});
    _ = ui.pairBegun(5, window(5, 1000));
    var bufs: Ui.Bufs = .{};
    const fp = "00:07:0E:15:1C:23:2A:31:38:3F:46:4D:54:5B:62:69:70:77:7E:85:8C:93:9A:A1:A8:AF:B6:BD:C4:CB:D2:D9";
    const p = ui.panel(&bufs, .{ .now = 100, .url = "https://10.8.0.1:8420/", .fingerprint = fp }).?;
    const q = p.qr.?;
    try testing.expect(q.size >= 21);
    try testing.expectEqual(@as(usize, q.size) * q.size, q.modules.len);
    // Plain HTTP: no CA, no QR.
    try testing.expect(ui.panel(&bufs, .{ .now = 100, .url = "http://10.8.0.1:8420/" }).?.qr == null);
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
    try testing.expectEqual(rules.Policy.instruct, ui.setup.input);
    _ = ui.key(.left, .{});
    _ = ui.key(.left, .{});
    try testing.expectEqual(rules.Policy.none, ui.setup.input);
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
    try testing.expectEqual(@as(usize, 6), p.fields.len);
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
    // Enter: on to "Background art", then submit.
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
