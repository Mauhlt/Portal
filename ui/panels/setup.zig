//! A device's first-run panel (`portal connect`, the iPhone app): the
//! desktop's address and the Portal CA to trust (a .pem/.cer file exported
//! at the desk, or the SHA-256 fingerprint the desk shows, to download the
//! CA while a pairing window is open). A state machine with no I/O; the
//! client (client/src/connect.zig) checks what was entered and shows any
//! problem in `note`.

const std = @import("std");
const frame = @import("../frame.zig");
const form = @import("../form.zig");
const input = @import("../input.zig");

pub const id_server: u32 = 100;
pub const id_cert: u32 = 101;
pub const id_pair: u32 = 1;

pub const Event = enum { none, submit, paste };

pub const Setup = struct {
    server: form.TextField(64) = .{},
    cert: form.TextField(1024) = .{},
    /// 0 server, 1 certificate, 2 the Pair button.
    focus: form.Focus = .{ .index = 0, .count = 3 },
    note_buf: [300]u8 = undefined,
    note_len: usize = 0,

    pub fn init(server: []const u8, cert: []const u8) Setup {
        var s: Setup = .{};
        s.server.set(server);
        s.cert.set(cert);
        s.focus.index = if (server.len == 0) 0 else 1;
        return s;
    }

    pub fn setNote(s: *Setup, comptime fmt: []const u8, args: anytype) void {
        s.note_len = if (std.fmt.bufPrint(&s.note_buf, fmt, args)) |t| t.len else |_| 0;
    }

    fn field(s: *Setup) ?*anyopaque {
        return switch (s.focus.index) {
            0 => &s.server,
            1 => &s.cert,
            else => null,
        };
    }

    fn insert(s: *Setup, cp: u21) void {
        switch (s.focus.index) {
            0 => _ = s.server.insert(cp),
            1 => _ = s.cert.insert(cp),
            else => {},
        }
    }

    pub fn paste(s: *Setup, text: []const u8) void {
        switch (s.focus.index) {
            0 => _ = s.server.insertText(std.mem.trim(u8, text, " \r\n")),
            1 => _ = s.cert.insertText(std.mem.trim(u8, text, " \r\n")),
            else => {},
        }
    }

    pub fn key(s: *Setup, k: input.Key, mods: input.Mods) Event {
        switch (k) {
            .tab => if (mods.shift) s.focus.prev() else s.focus.next(),
            .up => s.focus.prev(),
            .down => s.focus.next(),
            .backspace => switch (s.focus.index) {
                0 => s.server.backspace(),
                1 => s.cert.backspace(),
                else => {},
            },
            .enter => {
                if (s.focus.index == 0) {
                    s.focus.next();
                    return .none;
                }
                return .submit;
            },
            else => {},
        }
        return .none;
    }

    pub fn char(s: *Setup, cp: u21, mods: input.Mods) Event {
        if (mods.ctrl and !mods.alt and (cp == 'v' or cp == 'V')) return if (s.field() != null) .paste else .none;
        if (mods.ctrl or mods.alt) return .none;
        s.insert(cp);
        return .none;
    }

    pub fn button(s: *Setup, b: u32) Event {
        switch (b) {
            id_server => s.focus.index = 0,
            id_cert => s.focus.index = 1,
            id_pair => return .submit,
            else => {},
        }
        return .none;
    }

    pub const Bufs = struct {
        fields: [2]frame.PanelField = undefined,
        buttons: [1]frame.PanelButton = undefined,
    };

    pub fn panel(s: *const Setup, b: *Bufs) frame.Panel {
        b.fields[0] = .{ .label = "Desktop address (IP:PORT inside the tunnel)", .value = s.server.text(), .hint = "e.g. 10.8.0.1:8420", .id = id_server, .focused = s.focus.index == 0 };
        b.fields[1] = .{ .label = "Portal certificate: a portal-ca.pem / .cer file, or its SHA-256", .value = s.cert.text(), .hint = "path to portal-ca.pem, or AB:CD:... as the desk shows it (empty: the one trusted before)", .id = id_cert, .focused = s.focus.index == 1 };
        b.buttons[0] = .{ .label = "Pair", .id = id_pair, .focused = s.focus.index == 2, .tone = .good };
        return .{
            .title = "Connect to a Portal",
            .lines = &lines,
            .fields = &b.fields,
            .note = .{ .text = s.note_buf[0..s.note_len], .tone = .bad },
            .buttons = &b.buttons,
        };
    }

    const lines = [_]frame.PanelText{
        .{ .text = "This window shows a Portal session running on your desktop. Nothing is trusted on first use: give it the certificate exported there (Export certificate in the Portal window), or the SHA-256 the desk shows while pairing to download it then." },
        .{ .text = "Then open Pair a device in the Portal window on the desktop and click Pair here. The desk approves this device; nothing secret is typed here." },
    };
};

const testing = std.testing;

test "setup form" {
    var s = Setup.init("", "");
    try testing.expectEqual(@as(u8, 0), s.focus.index);
    for ("10.8.0.1:8420") |c| _ = s.char(c, .{});
    try testing.expectEqual(Event.none, s.key(.enter, .{}));
    try testing.expectEqual(@as(u8, 1), s.focus.index);
    try testing.expectEqual(Event.paste, s.char('v', .{ .ctrl = true }));
    s.paste("  /home/me/portal-ca.pem\n");
    try testing.expectEqualStrings("/home/me/portal-ca.pem", s.cert.text());
    try testing.expectEqual(Event.submit, s.key(.enter, .{}));
    try testing.expectEqual(Event.submit, s.button(id_pair));
    _ = s.button(id_server);
    _ = s.key(.backspace, .{});
    try testing.expectEqualStrings("10.8.0.1:842", s.server.text());
    var b: Setup.Bufs = .{};
    const p = s.panel(&b);
    try testing.expect(p.fields[0].focused);
    try testing.expectEqual(@as(usize, 1), p.buttons.len);
}
