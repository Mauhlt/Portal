//! A device's first-run panel (`portal connect`, the iPhone app): pairing
//! with a desktop through Portal's own WireGuard tunnel. A state machine
//! with no I/O; the client (client/src/connect.zig) checks what was
//! entered and shows any problem in `note`.
//!
//!   1. The panel shows this device's tunnel key and its check code: the
//!      owner enters the key at the desk (Pair a device), where the same
//!      check code must appear.
//!   2. The desk then shows a pairing code (its own key, where to reach
//!      it, the certificate's SHA-256, this device's tunnel address): the
//!      owner types, pastes or scans it here and presses Connect.
//!   3. The panel shows the desk key's check code from that code
//!      (`askConfirm`); the owner compares it with the desk's screen and
//!      presses Connect again (`confirmed`). Nothing is trusted on first
//!      use, and nothing secret is typed.

const std = @import("std");
const frame = @import("../frame.zig");
const form = @import("../form.zig");
const input = @import("../input.zig");
const pairqr = @import("shared").pairqr;

pub const id_code: u32 = 100;
pub const id_pair: u32 = 1;
pub const id_scan: u32 = 2;

pub const check_len = 11;

/// `submit`: check the code (then `askConfirm`, or a note); `confirmed`:
/// the owner compared the desk's check code; `scan`: the user asked to scan
/// the desk's QR code (only where the platform has a camera scanner,
/// `Setup.scan_offered`).
pub const Event = enum { none, submit, confirmed, paste, scan };

pub const Setup = struct {
    code: form.TextField(pairqr.max_len_tunnel) = .{},
    /// 0 the code, 1 the Connect button.
    focus: form.Focus = .{ .index = 0, .count = 2 },
    note_buf: [300]u8 = undefined,
    note_len: usize = 0,
    /// Show "Scan QR code" (the iPhone app; see connect.Platform).
    scan_offered: bool = false,
    /// This device's tunnel key and its check code (set by the client).
    device_key: [44]u8 = @splat(' '),
    device_check: [check_len]u8 = @splat(' '),
    /// After a valid code: the desk key's check code, to compare.
    confirm: ?[check_len]u8 = null,

    pub fn init(device_key: [44]u8, device_check: [check_len]u8) Setup {
        return .{ .device_key = device_key, .device_check = device_check };
    }

    pub fn setNote(s: *Setup, comptime fmt: []const u8, args: anytype) void {
        s.note_len = if (std.fmt.bufPrint(&s.note_buf, fmt, args)) |t| t.len else |_| 0;
    }

    /// The code entered is valid: ask the owner to compare its desk key's
    /// check code with the desk.
    pub fn askConfirm(s: *Setup, desk_check: [check_len]u8) void {
        s.confirm = desk_check;
        s.note_len = 0;
        s.focus.index = 1;
    }

    fn edited(s: *Setup) void {
        s.confirm = null; // a changed code is checked again
    }

    pub fn paste(s: *Setup, text: []const u8) void {
        if (s.focus.index != 0) return;
        _ = s.code.insertText(std.mem.trim(u8, text, " \r\n"));
        s.edited();
    }

    pub fn key(s: *Setup, k: input.Key, mods: input.Mods) Event {
        switch (k) {
            .tab => if (mods.shift) s.focus.prev() else s.focus.next(),
            .up => s.focus.prev(),
            .down => s.focus.next(),
            .backspace => if (s.focus.index == 0) {
                s.code.backspace();
                s.edited();
            },
            .enter => return s.press(),
            else => {},
        }
        return .none;
    }

    fn press(s: *Setup) Event {
        return if (s.confirm != null) .confirmed else .submit;
    }

    pub fn char(s: *Setup, cp: u21, mods: input.Mods) Event {
        if (mods.ctrl and !mods.alt and (cp == 'v' or cp == 'V')) return if (s.focus.index == 0) .paste else .none;
        if (mods.ctrl or mods.alt) return .none;
        if (s.focus.index == 0) {
            _ = s.code.insert(cp);
            s.edited();
        }
        return .none;
    }

    pub fn button(s: *Setup, b: u32) Event {
        switch (b) {
            id_code => s.focus.index = 0,
            id_pair => return s.press(),
            id_scan => if (s.scan_offered) return .scan,
            else => {},
        }
        return .none;
    }

    /// Fills the code from a scanned QR text (connect.zig checks it like a
    /// typed one).
    pub fn fromQr(s: *Setup, text: []const u8) void {
        s.code.set(std.mem.trim(u8, text, " \r\n"));
        s.edited();
        s.note_len = 0;
    }

    pub const Bufs = struct {
        fields: [1]frame.PanelField = undefined,
        buttons: [2]frame.PanelButton = undefined,
        lines: [5]frame.PanelText = undefined,
        txt: [3][160]u8 = undefined,
    };

    pub fn panel(s: *const Setup, b: *Bufs) frame.Panel {
        var nl: usize = 0;
        b.lines[nl] = .{ .text = "This window shows a Portal session running on your desktop, through Portal's own encrypted tunnel. This device is known to the desktop by its tunnel key." };
        nl += 1;
        b.lines[nl] = .{ .text = std.fmt.bufPrint(&b.txt[0], "This device's tunnel key: {s}", .{&s.device_key}) catch "", .tone = .normal, .bold = true };
        nl += 1;
        b.lines[nl] = .{ .text = std.fmt.bufPrint(&b.txt[1], "Its check code: {s}. At the desk, open Pair a device and enter this key; the desk must show the same check code.", .{&s.device_check}) catch "" };
        nl += 1;
        b.lines[nl] = .{ .text = "Then enter the pairing code the desk shows (or scan it), and press Connect." };
        nl += 1;
        if (s.confirm) |cc| {
            b.lines[nl] = .{ .text = std.fmt.bufPrint(&b.txt[2], "The desktop's check code in this pairing code is {s}. Press Connect only if the desk shows exactly this code.", .{&cc}) catch "", .tone = .warn, .bold = true };
            nl += 1;
        }
        b.fields[0] = .{ .label = "Pairing code from the desk", .value = s.code.text(), .hint = "portal-pair 2 10.8.0.1:8420 ... (the part after 10.8.0.1:8420 is enough)", .id = id_code, .focused = s.focus.index == 0 };
        var nb: usize = 0;
        if (s.scan_offered) {
            b.buttons[nb] = .{ .label = "Scan QR code", .id = id_scan };
            nb += 1;
        }
        b.buttons[nb] = .{ .label = "Connect", .id = id_pair, .focused = s.focus.index == 1, .tone = .good };
        nb += 1;
        return .{
            .title = "Connect to a Portal",
            .lines = b.lines[0..nl],
            .fields = &b.fields,
            .note = .{ .text = s.note_buf[0..s.note_len], .tone = .bad },
            .buttons = b.buttons[0..nb],
        };
    }
};

const testing = std.testing;

test "setup: key shown, code entered, checked, confirmed" {
    var s = Setup.init("hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=".*, "ABCDE-FGHJK".*);
    var b: Setup.Bufs = .{};
    const p = s.panel(&b);
    try testing.expect(std.mem.indexOf(u8, p.lines[1].text, "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=") != null);
    try testing.expect(std.mem.indexOf(u8, p.lines[2].text, "ABCDE-FGHJK") != null);
    for ("abc") |c| _ = s.char(c, .{});
    try testing.expectEqual(Event.submit, s.key(.enter, .{}));
    s.askConfirm("KLMNP-QRSTV".*);
    try testing.expect(std.mem.indexOf(u8, s.panel(&b).lines[4].text, "KLMNP-QRSTV") != null);
    try testing.expectEqual(Event.confirmed, s.button(id_pair));
    // Editing the code asks again.
    _ = s.button(id_code);
    _ = s.key(.backspace, .{});
    try testing.expectEqual(Event.submit, s.key(.enter, .{}));
    try testing.expectEqual(Event.paste, s.char('v', .{ .ctrl = true }));
    try testing.expectEqual(Event.none, s.button(id_scan)); // not offered
}

test "setup from a scanned pairing QR code" {
    var s = Setup.init(@splat('k'), @splat('c'));
    s.scan_offered = true;
    try testing.expectEqual(Event.scan, s.button(id_scan));
    var b: Setup.Bufs = .{};
    try testing.expectEqual(@as(usize, 2), s.panel(&b).buttons.len);
    s.fromQr(" portal-pair 2 x \n");
    try testing.expectEqualStrings("portal-pair 2 x", s.code.text());
    try testing.expect(s.confirm == null);
}
