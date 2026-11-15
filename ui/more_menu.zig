//! The top bar's "⋯" menu (docs/layout-design.md, "Implementation notes"):
//! short of room the frame puts the top bar's buttons, but for the view
//! toggle, behind one "⋯" button (frame.collapseButtons). It opens this
//! small sheet listing them; choosing one does what its button does (the
//! shell sends its id on as if the button had been clicked) and closes it.
//! Up / Down choose, Enter opens, Esc closes.
//!
//! The shell (shell.zig) keeps a `Menu`, refreshes its items from the top
//! bar each frame (`set`) and routes the input.

const std = @import("std");
const frame = @import("frame.zig");

pub const max_items = 16;

/// Clear of the other panels' ranges (shell.ids lists them).
pub const ids = struct {
    pub const button: u32 = 1960;
    pub const close: u32 = 1961;
    /// The item at position i: item0 + i.
    pub const item0: u32 = 1970;
};

pub const Bufs = struct {
    rows: [max_items]frame.PanelRow = undefined,
    buttons: [1]frame.PanelButton = undefined,
};

pub const Menu = struct {
    open: bool = false,
    sel: usize = 0,
    items: [max_items]frame.TopButton = undefined,
    n: usize = 0,

    /// The top bar's buttons; the menu lists those not in the view toggle.
    pub fn set(m: *Menu, buttons: []const frame.TopButton) void {
        m.n = 0;
        for (buttons) |b| if (!b.toggle and m.n < max_items) {
            m.items[m.n] = b;
            m.n += 1;
        };
        if (m.n == 0) m.open = false;
        if (m.sel >= m.n) m.sel = 0;
    }

    pub fn toggle(m: *Menu) void {
        m.open = !m.open and m.n > 0;
        m.sel = 0;
    }

    /// A key while open: the id to send on (Enter), or null.
    pub fn key(m: *Menu, k: @import("input.zig").Key) ?u32 {
        switch (k) {
            .escape => m.open = false,
            .up => m.sel = if (m.sel == 0) m.n -| 1 else m.sel - 1,
            .down, .tab => m.sel = if (m.sel + 1 >= m.n) 0 else m.sel + 1,
            .enter => if (m.sel < m.n) {
                m.open = false;
                return m.items[m.sel].id;
            },
            else => {},
        }
        return null;
    }

    /// One of the menu's own ids: the item's id to send on (the menu
    /// closes), or null.
    pub fn button(m: *Menu, id: u32) ?u32 {
        if (id == ids.close) {
            m.open = false;
            return null;
        }
        if (id < ids.item0 or id - ids.item0 >= m.n) return null;
        m.open = false;
        return m.items[id - ids.item0].id;
    }

    pub fn panel(m: *const Menu, b: *Bufs) ?frame.Panel {
        if (!m.open or m.n == 0) return null;
        for (m.items[0..m.n], 0..) |it, i| b.rows[i] = .{
            .text = it.label,
            .tone = if (it.active) .good else .normal,
            .selected = i == m.sel,
            .button = .{ .label = "Open", .id = ids.item0 + @as(u32, @intCast(i)), .focused = i == m.sel },
        };
        b.buttons[0] = .{ .label = "Close", .id = ids.close };
        return .{ .title = "More", .rows = b.rows[0..m.n], .buttons = &b.buttons };
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "menu: lists the buttons but the view toggle; keys and clicks send the item's id on" {
    var m: Menu = .{};
    m.set(&.{
        .{ .label = "Projects", .id = 916 },
        .{ .label = "Terminal", .id = 905, .toggle = true, .short = "Term" },
        .{ .label = "Conversation", .id = 906, .toggle = true, .short = "Chat" },
        .{ .label = "Usage", .id = 913, .active = true },
    });
    try testing.expectEqual(@as(usize, 2), m.n);
    var b: Bufs = .{};
    try testing.expect(m.panel(&b) == null);
    m.toggle();
    const p = m.panel(&b).?;
    try testing.expectEqual(@as(usize, 2), p.rows.len);
    try testing.expectEqualStrings("Projects", p.rows[0].text);
    try testing.expect(p.rows[0].selected and !p.rows[1].selected);
    // Keys: Down, then Enter sends Usage on and closes.
    try testing.expect(m.key(.down) == null);
    try testing.expectEqual(@as(?u32, 913), m.key(.enter));
    try testing.expect(!m.open);
    // A click on an item's button; Close; ids out of range do nothing.
    m.toggle();
    try testing.expectEqual(@as(?u32, 916), m.button(ids.item0));
    try testing.expect(!m.open);
    m.toggle();
    try testing.expect(m.button(ids.item0 + 5) == null);
    try testing.expect(m.open);
    try testing.expect(m.button(ids.close) == null);
    try testing.expect(!m.open);
    // Esc closes; with nothing to list it never opens.
    m.toggle();
    _ = m.key(.escape);
    try testing.expect(!m.open);
    m.set(&.{.{ .label = "Terminal", .id = 905, .toggle = true }});
    m.toggle();
    try testing.expect(!m.open);
}
