//! The desk's Projects panel (top bar "Projects", Ctrl+Shift+J): which
//! project folders a paired device may start, and how a device start runs
//! each (Ask: the agent asks before every edit and command; Plan: read and
//! plan only). docs/tabs-design.md, "Starting projects from a device".
//!
//! A state machine with no drawing and no I/O, like the other desk panels:
//! the glue (src/gui.zig) feeds it the list as settings.txt has it
//! (`View`), performs the `Action`s it returns (the folder picker, the
//! settings file, the hub) and draws `panel()`. The folders are shown here,
//! on the desk only; devices only ever see the names.
//!
//! Keyboard: Up / Down choose a row, Enter switches its mode (Ask / Plan),
//! Delete removes it, Insert adds a folder, Esc closes. Mouse and touch:
//! the rows' buttons and the panel's.

const std = @import("std");
const shared = @import("shared");
const projects = shared.projects;
const theme = shared.theme;
const frame = @import("../frame.zig");
const input = @import("../input.zig");

/// Ids (clear of the other panels' and the shell's ranges).
pub const id = struct {
    /// The top bar's tool.
    pub const tool: u32 = 1850;
    pub const close: u32 = 1851;
    pub const add: u32 = 1852;
    pub const add_shown: u32 = 1853;
    /// mode0 + row: switch Ask / Plan.
    pub const mode0: u32 = 1860;
    /// remove0 + row.
    pub const remove0: u32 = 1880;
};

comptime {
    std.debug.assert(id.mode0 + projects.max_projects <= id.remove0);
    std.debug.assert(id.remove0 + projects.max_projects <= 1900);
}

/// The desk's top-bar tool (the glue adds it after the other desk tools).
pub const tool: frame.TopButton = .{ .label = "Projects", .id = id.tool };

/// One startable project as the desk shows it.
pub const Row = struct {
    name: []const u8,
    mode: projects.Mode,
    folder: []const u8,
    color: u32 = 0,
    /// "running", "started by iPhone", "stopped by iPhone"; "" not running.
    state: []const u8 = "",
};

pub const View = struct {
    rows: []const Row = &.{},
    /// Why devices cannot start projects now ("" they can): the program
    /// setting (cmdline.deviceStartText).
    unsafe: []const u8 = "",
    /// The tab shown at the desk can be added (it has a folder that is not
    /// in the list yet).
    can_add_shown: bool = false,
};

pub const Action = union(enum) {
    none,
    closed,
    /// The folder picker, then add what was chosen.
    add_folder,
    /// Add the folder of the tab shown at the desk, under its name.
    add_shown,
    /// Row i's mode becomes this.
    set_mode: struct { row: usize, mode: projects.Mode },
    remove: usize,
};

pub const Bufs = struct {
    lines: [2]frame.PanelText = undefined,
    rows: [projects.max_projects]frame.PanelRow = undefined,
    row_txt: [projects.max_projects][320]u8 = undefined,
    after: [1]frame.PanelText = undefined,
    buttons: [3]frame.PanelButton = undefined,
};

pub const Panel = struct {
    is_open: bool = false,
    sel: usize = 0,
    note: []const u8 = "",
    note_tone: frame.Tone = .muted,
    note_buf: [200]u8 = undefined,

    pub fn open(p: *const Panel) bool {
        return p.is_open;
    }

    pub fn show(p: *Panel) void {
        p.is_open = true;
        p.note = "";
    }

    pub fn close(p: *Panel) void {
        p.is_open = false;
    }

    /// The outcome of the last action, under the title.
    pub fn setNote(p: *Panel, tone: frame.Tone, comptime fmt: []const u8, args: anytype) void {
        p.note = std.fmt.bufPrint(&p.note_buf, fmt, args) catch fmt;
        p.note_tone = tone;
    }

    pub fn key(p: *Panel, k: input.Key, v: View) Action {
        const n = v.rows.len;
        if (n == 0) p.sel = 0 else p.sel = @min(p.sel, n - 1);
        switch (k) {
            .escape => {
                p.close();
                return .closed;
            },
            .up => if (p.sel > 0) {
                p.sel -= 1;
            },
            .down => if (p.sel + 1 < n) {
                p.sel += 1;
            },
            .enter => if (p.sel < n) return flip(p.sel, v),
            .delete => if (p.sel < n) return .{ .remove = p.sel },
            .insert => return .add_folder,
            else => {},
        }
        return .none;
    }

    pub fn button(p: *Panel, b: u32, v: View) Action {
        const n = v.rows.len;
        switch (b) {
            id.close => {
                p.close();
                return .closed;
            },
            id.add => return .add_folder,
            id.add_shown => return if (v.can_add_shown) .add_shown else .none,
            id.mode0...id.mode0 + projects.max_projects - 1 => if (b - id.mode0 < n) {
                p.sel = b - id.mode0;
                return flip(p.sel, v);
            },
            id.remove0...id.remove0 + projects.max_projects - 1 => if (b - id.remove0 < n) {
                p.sel = b - id.remove0;
                return .{ .remove = p.sel };
            },
            else => {},
        }
        return .none;
    }

    fn flip(i: usize, v: View) Action {
        return .{ .set_mode = .{ .row = i, .mode = switch (v.rows[i].mode) {
            .ask => .plan,
            .plan => .ask,
        } } };
    }

    pub fn panel(p: *const Panel, v: View, b: *Bufs) frame.Panel {
        const n = @min(v.rows.len, projects.max_projects);
        for (v.rows[0..n], 0..) |r, i| {
            const at: u32 = @intCast(i);
            const text = std.fmt.bufPrint(&b.row_txt[i], "{s}  \u{00B7}  {s}{s}{s}", .{
                r.name, r.folder, if (r.state.len > 0) "  \u{00B7}  " else "", r.state,
            }) catch r.name;
            b.rows[i] = .{
                .text = text,
                .selected = i == p.sel,
                .dot = theme.fromU32(r.color),
                .button = .{ .label = "Remove", .id = id.remove0 + at },
                .button2 = .{ .label = if (r.mode == .ask) "Ask" else "Plan", .id = id.mode0 + at, .focused = i == p.sel },
            };
        }
        var nl: usize = 0;
        if (v.unsafe.len > 0) {
            b.lines[nl] = .{ .text = v.unsafe, .tone = .bad };
            nl += 1;
        }
        b.lines[nl] = if (p.note.len > 0)
            .{ .text = p.note, .tone = p.note_tone }
        else if (n == 0)
            .{ .text = "No project can be started from a device. Add a folder to allow it." }
        else
            .{ .text = "Enter switches Ask / Plan, Delete removes, Insert adds a folder, Esc closes." };
        nl += 1;
        b.after[0] = .{ .text = "Devices see only each project's name, colour and mode, never its folder. A device start runs Claude Code with the mode chosen here (Ask: every edit and command needs approval; Plan: read-only planning), never a permissive one, and a device may stop only a session a device started. Kept in settings.txt (`startable`; also `portalctl startable`)." };
        var nb: usize = 0;
        b.buttons[nb] = .{ .label = "Add folder\u{2026}", .id = id.add, .tone = .good };
        nb += 1;
        if (v.can_add_shown) {
            b.buttons[nb] = .{ .label = "Add this tab's folder", .id = id.add_shown };
            nb += 1;
        }
        b.buttons[nb] = .{ .label = "Close", .id = id.close };
        nb += 1;
        return .{
            .title = "Projects devices may start",
            .lines = b.lines[0..nl],
            .rows = b.rows[0..n],
            .after = &b.after,
            .buttons = b.buttons[0..nb],
        };
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "projects panel: rows, keys, buttons" {
    const rows = [_]Row{
        .{ .name = "acme", .mode = .ask, .folder = "C:\\code\\acme", .state = "started by iPhone" },
        .{ .name = "notes", .mode = .plan, .folder = "D:\\notes" },
    };
    const v: View = .{ .rows = &rows };
    var p: Panel = .{};
    p.show();
    var b: Bufs = .{};
    const fp = p.panel(v, &b);
    try testing.expectEqual(@as(usize, 2), fp.rows.len);
    try testing.expect(std.mem.indexOf(u8, fp.rows[0].text, "started by iPhone") != null);
    try testing.expectEqualStrings("Ask", fp.rows[0].button2.?.label);
    try testing.expectEqualStrings("Plan", fp.rows[1].button2.?.label);
    // Enter flips the chosen row's mode.
    const a = p.key(.enter, v);
    try testing.expect(a.set_mode.row == 0 and a.set_mode.mode == .plan);
    _ = p.key(.down, v);
    _ = p.key(.down, v);
    try testing.expectEqual(@as(usize, 1), p.sel);
    try testing.expectEqual(@as(usize, 1), p.key(.delete, v).remove);
    try testing.expect(p.key(.insert, v) == .add_folder);
    try testing.expect(p.button(id.mode0 + 1, v).set_mode.mode == .ask);
    try testing.expectEqual(@as(usize, 0), p.button(id.remove0, v).remove);
    try testing.expect(p.button(id.remove0 + 5, v) == .none);
    // "Add this tab's folder" only when there is one to add.
    try testing.expect(p.button(id.add_shown, v) == .none);
    try testing.expect(p.button(id.add_shown, .{ .rows = &rows, .can_add_shown = true }) == .add_shown);
    // The program setting is not safe: said first, in red.
    const u = p.panel(.{ .rows = &rows, .unsafe = "not Claude Code" }, &b);
    try testing.expectEqual(frame.Tone.bad, u.lines[0].tone);
    try testing.expect(p.key(.escape, v) == .closed);
    try testing.expect(!p.open());
}
