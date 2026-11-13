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
const pairqr = @import("shared").pairqr;

pub const id_server: u32 = 100;
pub const id_cert: u32 = 101;
pub const id_pair: u32 = 1;
pub const id_scan: u32 = 2;

/// `scan`: the user asked to scan the desk's pairing QR code (only offered
/// where the platform has a camera scanner, `Setup.scan_offered`).
pub const Event = enum { none, submit, paste, scan };

pub const Setup = struct {
    server: form.TextField(64) = .{},
    cert: form.TextField(1024) = .{},
    /// 0 server, 1 certificate, 2 the Pair button.
    focus: form.Focus = .{ .index = 0, .count = 3 },
    note_buf: [300]u8 = undefined,
    note_len: usize = 0,
    /// Show "Scan QR code" (the iPhone app; see connect.Platform).
    scan_offered: bool = false,

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
            id_scan => if (s.scan_offered) return .scan,
            else => {},
        }
        return .none;
    }

    /// Fills the form from a scanned pairing QR code (shared/pairqr.zig):
    /// the address and the CA's SHA-256, which connect.zig then checks
    /// like typed ones. False (with a note) if it is not Portal's.
    pub fn fromQr(s: *Setup, text: []const u8) bool {
        const p = pairqr.parse(text) catch |err| {
            s.setNote("{s}", .{switch (err) {
                error.NotPortal => "That QR code is not a Portal pairing code. Scan the one in Pair a device on the desk.",
                error.UnsupportedVersion => "That pairing code is from a newer Portal; update this app.",
                error.Malformed => "That pairing code is damaged; scan it again.",
            }});
            return false;
        };
        s.server.set(p.server);
        s.cert.set(p.ca_sha256);
        s.focus.index = 2;
        s.note_len = 0;
        return true;
    }

    pub const Bufs = struct {
        fields: [2]frame.PanelField = undefined,
        buttons: [2]frame.PanelButton = undefined,
    };

    pub fn panel(s: *const Setup, b: *Bufs) frame.Panel {
        b.fields[0] = .{ .label = "Desktop address (IP:PORT inside the tunnel)", .value = s.server.text(), .hint = "e.g. 10.8.0.1:8420", .id = id_server, .focused = s.focus.index == 0 };
        b.fields[1] = .{ .label = "Portal certificate: a portal-ca.pem / .cer file, or its SHA-256", .value = s.cert.text(), .hint = "path to portal-ca.pem, or AB:CD:... as the desk shows it (empty: the one trusted before)", .id = id_cert, .focused = s.focus.index == 1 };
        var nb: usize = 0;
        if (s.scan_offered) {
            b.buttons[nb] = .{ .label = "Scan QR code", .id = id_scan };
            nb += 1;
        }
        b.buttons[nb] = .{ .label = "Pair", .id = id_pair, .focused = s.focus.index == 2, .tone = .good };
        nb += 1;
        return .{
            .title = "Connect to a Portal",
            .lines = &lines,
            .fields = &b.fields,
            .note = .{ .text = s.note_buf[0..s.note_len], .tone = .bad },
            .buttons = b.buttons[0..nb],
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
    try testing.expectEqual(Event.none, s.button(id_scan)); // not offered
}

test "setup from a scanned pairing QR code" {
    var s = Setup.init("", "");
    s.scan_offered = true;
    try testing.expectEqual(Event.scan, s.button(id_scan));
    var b: Setup.Bufs = .{};
    try testing.expectEqual(@as(usize, 2), s.panel(&b).buttons.len);
    try testing.expect(!s.fromQr("https://example.com/"));
    try testing.expect(s.note_len > 0);
    const fp = "00070E151C232A31383F464D545B626970777E858C939AA1A8AFB6BDC4CBD2D9";
    try testing.expect(s.fromQr("portal-pair 1 10.8.0.1:8420 " ++ fp));
    try testing.expectEqualStrings("10.8.0.1:8420", s.server.text());
    try testing.expectEqualStrings(fp, s.cert.text());
    try testing.expectEqual(@as(usize, 0), s.note_len);
}
