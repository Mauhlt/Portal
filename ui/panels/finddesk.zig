//! A device's "Change where this device finds the desktop" panel, opened
//! from the "Desktop offline" screen (`portal connect`, the iPhone app):
//! when the desktop moved its tunnel port while this device was away, the
//! owner types the new port (or HOST:PORT) here. A state machine with no
//! I/O; the device glue (client/src/connect.zig) checks and saves it
//! (devicelink.Follower.setEndpoint) and shows any problem in `note`.
//!
//! It changes only where THIS device looks for the desktop: the device's
//! own saved pairing code, nothing on the desktop (no device message can
//! change the desktop's port). The keys stay, so there is no pairing
//! again.

const std = @import("std");
const frame = @import("../frame.zig");
const form = @import("../form.zig");
const input = @import("../input.zig");
const pairqr = @import("shared").pairqr;

pub const id_field: u32 = 500;
pub const id_use: u32 = 501;
pub const id_cancel: u32 = 502;

/// `submit`: check and save `text()`; `paste`: read the clipboard.
pub const Event = enum { none, submit, paste, closed };

pub const FindDesk = struct {
    open: bool = false,
    field: form.TextField(pairqr.max_endpoint) = .{},
    /// 0 the field, 1 Cancel, 2 Use this address.
    focus: form.Focus = .{ .index = 0, .count = 3 },
    /// Where this device looks now (shown for reference).
    current_buf: [pairqr.max_endpoint]u8 = undefined,
    current_len: usize = 0,
    note_buf: [240]u8 = undefined,
    note_len: usize = 0,
    note_tone: frame.Tone = .bad,

    pub fn show(f: *FindDesk, current: []const u8) void {
        f.* = .{ .open = true };
        const n = @min(current.len, f.current_buf.len);
        @memcpy(f.current_buf[0..n], current[0..n]);
        f.current_len = n;
    }

    pub fn close(f: *FindDesk) void {
        f.open = false;
    }

    pub fn text(f: *const FindDesk) []const u8 {
        return f.field.text();
    }

    pub fn setNote(f: *FindDesk, tone: frame.Tone, comptime fmt: []const u8, args: anytype) void {
        f.note_len = if (std.fmt.bufPrint(&f.note_buf, fmt, args)) |t| t.len else |_| 0;
        f.note_tone = tone;
    }

    pub fn paste(f: *FindDesk, t: []const u8) void {
        if (f.focus.index != 0) return;
        _ = f.field.insertText(std.mem.trim(u8, t, " \r\n"));
    }

    pub fn key(f: *FindDesk, k: input.Key, mods: input.Mods) Event {
        switch (k) {
            .escape => {
                f.close();
                return .closed;
            },
            .tab => if (mods.shift) f.focus.prev() else f.focus.next(),
            .up => f.focus.prev(),
            .down => f.focus.next(),
            .backspace => if (f.focus.index == 0) f.field.backspace(),
            .enter => return if (f.focus.index == 1) f.cancel() else .submit,
            else => {},
        }
        return .none;
    }

    pub fn char(f: *FindDesk, cp: u21, mods: input.Mods) Event {
        if (mods.ctrl and !mods.alt and (cp == 'v' or cp == 'V')) return if (f.focus.index == 0) .paste else .none;
        if (mods.ctrl or mods.alt) return .none;
        if (f.focus.index == 0 and cp > ' ' and cp < 0x7f) _ = f.field.insert(cp);
        return .none;
    }

    pub fn button(f: *FindDesk, b: u32) Event {
        switch (b) {
            id_field => f.focus.index = 0,
            id_use => return .submit,
            id_cancel => return f.cancel(),
            else => {},
        }
        return .none;
    }

    fn cancel(f: *FindDesk) Event {
        f.close();
        return .closed;
    }

    pub const Bufs = struct {
        fields: [1]frame.PanelField = undefined,
        buttons: [2]frame.PanelButton = undefined,
        lines: [3]frame.PanelText = undefined,
        txt: [300]u8 = undefined,
    };

    pub fn panel(f: *const FindDesk, b: *Bufs) ?frame.Panel {
        if (!f.open) return null;
        b.lines[0] = .{ .text = "If the desktop's tunnel port was changed while this device was away, enter the new port (or HOST:PORT) here. This changes only where this device looks for the desktop; it changes nothing on the desktop, and the keys stay the same, so there is no pairing again." };
        b.lines[1] = .{ .text = std.fmt.bufPrint(&b.txt, "This device looks for the desktop at {s}.", .{f.current_buf[0..f.current_len]}) catch "", .tone = .normal };
        b.lines[2] = .{ .text = "The desktop's own port is changed only at the desktop (Settings, Tunnel UDP port)." };
        b.fields[0] = .{ .label = "Where this device finds the desktop (PORT or HOST:PORT)", .value = f.field.text(), .hint = "e.g. 51821, or home.example.org:51821", .id = id_field, .focused = f.focus.index == 0 };
        b.buttons[0] = .{ .label = "Cancel", .id = id_cancel, .focused = f.focus.index == 1 };
        b.buttons[1] = .{ .label = "Use this address", .id = id_use, .focused = f.focus.index == 2, .tone = .good };
        return .{
            .title = "Change where this device finds the desktop",
            .lines = &b.lines,
            .fields = &b.fields,
            .note = .{ .text = f.note_buf[0..f.note_len], .tone = f.note_tone },
            .buttons = &b.buttons,
        };
    }
};

const testing = std.testing;

test "find the desktop: typed, submitted, cancelled; it says it changes only this device" {
    var f: FindDesk = .{};
    var b: FindDesk.Bufs = .{};
    try testing.expect(f.panel(&b) == null);
    f.show("home.example.org:51820");
    const p = f.panel(&b).?;
    try testing.expect(std.mem.indexOf(u8, p.lines[0].text, "only where this device looks") != null);
    try testing.expect(std.mem.indexOf(u8, p.lines[0].text, "changes nothing on the desktop") != null);
    try testing.expect(std.mem.indexOf(u8, p.lines[1].text, "home.example.org:51820") != null);
    for ("51821") |c| _ = f.char(c, .{});
    _ = f.char(' ', .{}); // no spaces
    try testing.expectEqualStrings("51821", f.text());
    try testing.expectEqual(Event.submit, f.key(.enter, .{}));
    try testing.expectEqual(Event.submit, f.button(id_use));
    try testing.expectEqual(Event.paste, f.char('v', .{ .ctrl = true }));
    try testing.expectEqual(Event.closed, f.button(id_cancel));
    try testing.expect(!f.open);
    f.show("h:1");
    try testing.expectEqual(@as(usize, 0), f.text().len);
    try testing.expectEqual(Event.closed, f.key(.escape, .{}));
}
