//! Hidden tabs (docs/layout-design.md, "Hidden tabs"; docs/protocol.md
//! section 5): a device may hide tabs from its own tab bar. A view
//! preference of this device only, not a security control: nothing about
//! it is sent, every tab stays open at the desk and on other devices, and
//! a hidden tab still gets every message.
//!
//!   * Hide: a long press (or right-click) on a tab opens its menu, "Hide
//!     this tab" (and "Close (desk only)", shown disabled); Ctrl+Shift+H
//!     hides the tab shown.
//!   * The tab strip then shows "••• N hidden", amber with a dot while a
//!     hidden tab waits for an answer or has For-you items that need the
//!     desk. It opens the sheet listing them (colour, name, waiting /
//!     working / idle) with Show, which puts the tab back and switches to it.
//!   * The list: tab names (what the desk calls them; the device has
//!     nothing else that lasts), at most `max` (the oldest dropped), kept
//!     in `hidden-tabs.txt` next to the device's settings file, one name
//!     per line (client/src/net/pin.zig). Names of closed projects may stay.
//!
//! This file is the model and the panels; the shell (shell.zig) routes
//! the input and the glue stores the list.

const std = @import("std");
const shared = @import("shared");
const tabs_wire = shared.tabs;
const theme = shared.theme;
const frame = @import("frame.zig");

pub const max = 64;
pub const max_name = tabs_wire.max_name;
pub const file_name = "hidden-tabs.txt";
/// Largest file read: `max` names and their line ends.
pub const max_file = max * (max_name + 2);

pub const List = struct {
    /// Oldest first.
    names: [max][max_name]u8 = undefined,
    lens: [max]u8 = undefined,
    n: usize = 0,

    pub fn name(l: *const List, i: usize) []const u8 {
        return l.names[i][0..l.lens[i]];
    }

    pub fn find(l: *const List, s: []const u8) ?usize {
        for (0..l.n) |i| if (std.mem.eql(u8, l.name(i), s)) return i;
        return null;
    }

    pub fn contains(l: *const List, s: []const u8) bool {
        return l.find(s) != null;
    }

    /// Hides `s` (the newest entry; full: the oldest goes). False if it is
    /// not a tab name or already hidden.
    pub fn hide(l: *List, s: []const u8) bool {
        if (!tabs_wire.validName(s) or l.contains(s)) return false;
        if (l.n == max) l.removeAt(0);
        @memcpy(l.names[l.n][0..s.len], s);
        l.lens[l.n] = @intCast(s.len);
        l.n += 1;
        return true;
    }

    /// Shows `s` again. False if it was not hidden.
    pub fn show(l: *List, s: []const u8) bool {
        const i = l.find(s) orelse return false;
        l.removeAt(i);
        return true;
    }

    fn removeAt(l: *List, i: usize) void {
        var k = i;
        while (k + 1 < l.n) : (k += 1) {
            l.names[k] = l.names[k + 1];
            l.lens[k] = l.lens[k + 1];
        }
        l.n -= 1;
    }

    /// The stored list: one name per line, oldest first. Lines that are
    /// not tab names (and repeats) are skipped; past `max`, the oldest go.
    pub fn parse(text: []const u8) List {
        var l: List = .{};
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |raw| {
            const line = std.mem.trimEnd(u8, raw, "\r");
            if (line.len == 0) continue;
            _ = l.hide(line);
        }
        return l;
    }

    pub fn write(l: *const List, w: *std.Io.Writer) !void {
        for (0..l.n) |i| try w.print("{s}\n", .{l.name(i)});
    }
};

/// The open tabs that are hidden, and whether any of them wants the user
/// now (the button's amber): `waiting`, or For-you items for the desk.
pub const Summary = struct {
    count: usize = 0,
    waiting: usize = 0,
    alert: bool = false,
};

/// `needs_desk`: tabs with For-you items that need the desk (empty when
/// the device has none).
pub fn summarize(l: *const List, tabs: []const tabs_wire.Entry, needs_desk: []const tabs_wire.Id) Summary {
    var s: Summary = .{};
    for (tabs) |*e| {
        if (!l.contains(e.name())) continue;
        s.count += 1;
        if (e.state == .waiting) s.waiting += 1;
        if (e.state == .waiting or inList(e.id, needs_desk)) s.alert = true;
    }
    return s;
}

fn inList(id: tabs_wire.Id, list: []const tabs_wire.Id) bool {
    for (list) |x| if (std.mem.eql(u8, &x, &id)) return true;
    return false;
}

/// "⋯ 3 hidden".
pub fn buttonLabel(s: Summary, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, frame.more_label ++ " {d} hidden", .{s.count}) catch (frame.more_label ++ " hidden");
}

/// What the sheet is showing.
pub const Sheet = union(enum) {
    none,
    /// The hidden tabs.
    list,
    /// The menu of the tab at bar position i.
    menu: usize,
};

/// Button ids (1900-1949), clear of the shell's and the other panels'
/// ranges (the desk's Audio panel has 1700-1799, Projects 1800-1899).
pub const ids = struct {
    pub const button: u32 = 1900;
    pub const close: u32 = 1901;
    pub const hide: u32 = 1902;
    pub const desk_close: u32 = 1903;
    /// Show the hidden tab at bar position i: show0 + i.
    pub const show0: u32 = 1910;
    /// The menu of the tab at bar position i: menu0 + i.
    pub const menu0: u32 = 1930;
};

pub const Bufs = struct {
    rows: [tabs_wire.max_tabs]frame.PanelRow = undefined,
    row_txt: [tabs_wire.max_tabs][max_name + 40]u8 = undefined,
    buttons: [3]frame.PanelButton = undefined,
    title: [max_name + 16]u8 = undefined,
};

/// The word for a hidden tab's state in the sheet, and its tone.
pub fn stateText(st: tabs_wire.State) struct { text: []const u8, tone: frame.Tone } {
    return switch (st) {
        .waiting => .{ .text = "waiting for your answer", .tone = .warn },
        .working => .{ .text = "working", .tone = .normal },
        else => .{ .text = "idle", .tone = .muted },
    };
}

/// The sheet's panel: the hidden tabs with Show, or a tab's menu.
pub fn panel(sheet: Sheet, l: *const List, tabs: []const tabs_wire.Entry, needs_desk: []const tabs_wire.Id, b: *Bufs) ?frame.Panel {
    switch (sheet) {
        .none => return null,
        .list => {
            var n: usize = 0;
            for (tabs, 0..) |*e, i| {
                if (!l.contains(e.name())) continue;
                if (n == b.rows.len) break;
                const st = stateText(e.state);
                const desk = e.state != .waiting and inList(e.id, needs_desk);
                b.rows[n] = .{
                    .text = std.fmt.bufPrint(&b.row_txt[n], "{s} \u{00B7} {s}", .{ e.name(), if (desk) "needs the desk" else st.text }) catch e.name(),
                    .tone = if (desk) .warn else st.tone,
                    .dot = theme.fromU32(e.color),
                    .button = .{ .label = "Show", .id = ids.show0 + @as(u32, @intCast(i)) },
                };
                n += 1;
            }
            b.buttons[0] = .{ .label = "Close", .id = ids.close };
            return .{
                .title = "Hidden on this device",
                .rows = b.rows[0..n],
                .note = .{ .text = "Hiding only tidies this device's tab bar: the desk and your other devices still show every tab. Long-press (or right-click) a tab to hide it; Ctrl+Shift+H hides the tab shown." },
                .buttons = b.buttons[0..1],
            };
        },
        .menu => |i| {
            if (i >= tabs.len) return null;
            b.buttons[0] = .{ .label = "Hide this tab", .id = ids.hide, .tone = .good };
            b.buttons[1] = .{ .label = "Close (desk only)", .id = ids.desk_close, .disabled = true };
            b.buttons[2] = .{ .label = "Cancel", .id = ids.close };
            return .{
                .title = std.fmt.bufPrint(&b.title, "{s}", .{tabs[i].name()}) catch "Tab",
                .lines = &.{.{ .text = "Hide it on this device only. Tabs are closed at the desk." }},
                .buttons = b.buttons[0..3],
            };
        },
    }
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn entry(name: []const u8, id_byte: u8, st: tabs_wire.State) tabs_wire.Entry {
    var e: tabs_wire.Entry = .{ .id = @splat(id_byte), .state = st };
    @memcpy(e.name_buf[0..name.len], name);
    e.name_len = @intCast(name.len);
    return e;
}

test "List: hide, show, cap (the oldest go), persistence, unknown names" {
    var l: List = .{};
    try testing.expect(l.hide("Portal"));
    try testing.expect(!l.hide("Portal"));
    try testing.expect(!l.hide(""));
    try testing.expect(!l.hide("bad\nname"));
    try testing.expect(l.hide("Audio"));
    try testing.expect(l.contains("Audio"));
    try testing.expect(!l.contains("audio"));
    try testing.expect(l.show("Portal"));
    try testing.expect(!l.show("Portal"));
    // The cap: 64 names; the 65th pushes out the oldest.
    l = .{};
    var nb: [16]u8 = undefined;
    for (0..max + 1) |i| try testing.expect(l.hide(std.fmt.bufPrint(&nb, "p{d}", .{i}) catch unreachable));
    try testing.expectEqual(@as(usize, max), l.n);
    try testing.expect(!l.contains("p0"));
    try testing.expect(l.contains("p1"));
    try testing.expect(l.contains("p64"));
    // Persistence: written and read back, in order.
    var buf: [max_file]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try l.write(&w);
    const back = List.parse(w.buffered());
    try testing.expectEqual(l.n, back.n);
    for (0..l.n) |i| try testing.expectEqualStrings(l.name(i), back.name(i));
    // A hand-edited file: CRLF, blanks, repeats, control bytes, too many.
    const p = List.parse("Portal\r\n\r\nAudio\nPortal\nbad\x01name\n  \nSpeech To Text\n");
    try testing.expectEqual(@as(usize, 3), p.n);
    try testing.expectEqualStrings("Speech To Text", p.name(2));
    try testing.expectEqual(@as(usize, 0), List.parse("").n);
}

test "summarize: open hidden tabs only; amber for waiting or needs-desk" {
    var l: List = .{};
    _ = l.hide("A");
    _ = l.hide("B");
    _ = l.hide("Closed"); // a project that is not open: not counted
    const tabs = [_]tabs_wire.Entry{ entry("A", 1, .working), entry("B", 2, .idle), entry("C", 3, .waiting) };
    var s = summarize(&l, &tabs, &.{});
    try testing.expectEqual(@as(usize, 2), s.count);
    try testing.expect(!s.alert);
    // A visible tab waiting does not make the button amber; a hidden one does.
    const tabs2 = [_]tabs_wire.Entry{ entry("A", 1, .waiting), entry("B", 2, .idle), entry("C", 3, .waiting) };
    s = summarize(&l, &tabs2, &.{});
    try testing.expect(s.alert);
    try testing.expectEqual(@as(usize, 1), s.waiting);
    // For-you items that need the desk, in a hidden tab.
    s = summarize(&l, &tabs, &.{@as(tabs_wire.Id, @splat(2))});
    try testing.expect(s.alert);
    s = summarize(&l, &tabs, &.{@as(tabs_wire.Id, @splat(3))});
    try testing.expect(!s.alert);
    var lb: [32]u8 = undefined;
    try testing.expectEqualStrings("\u{2022}\u{2022}\u{2022} 2 hidden", buttonLabel(.{ .count = 2 }, &lb));
}

test "panel: the sheet lists the hidden tabs with Show; the menu" {
    var l: List = .{};
    _ = l.hide("B");
    const tabs = [_]tabs_wire.Entry{ entry("A", 1, .working), entry("B", 2, .waiting) };
    var b: Bufs = .{};
    const p = panel(.list, &l, &tabs, &.{}, &b).?;
    try testing.expectEqual(@as(usize, 1), p.rows.len);
    try testing.expectEqualStrings("B \u{00B7} waiting for your answer", p.rows[0].text);
    try testing.expectEqual(ids.show0 + 1, p.rows[0].button.?.id);
    try testing.expect(p.rows[0].dot != null);
    const m = panel(.{ .menu = 0 }, &l, &tabs, &.{}, &b).?;
    try testing.expectEqualStrings("A", m.title);
    try testing.expectEqual(ids.hide, m.buttons[0].id);
    try testing.expect(m.buttons[1].disabled);
    try testing.expect(panel(.{ .menu = 5 }, &l, &tabs, &.{}, &b) == null);
    try testing.expect(panel(.none, &l, &tabs, &.{}, &b) == null);
}
