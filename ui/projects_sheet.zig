//! The Projects sheet on a paired device (docs/protocol.md section 3f;
//! the owner's mockup, screen 3): the projects the desk allowed, each with
//! its colour, its Ask / Plan badge and whether it runs, and per row
//! Start (not running), Open (running) and Stop (only for a session a
//! device started). The top bar's Projects opens it; the shell (shell.zig)
//! owns it like the status panels, on every device (Windows, Linux, macOS,
//! iOS).
//!
//! Touch and mouse: the rows' buttons. Keyboard: Up / Down choose a row,
//! Enter starts or opens it, Delete stops it, Esc closes the sheet.
//!
//! Nothing here decides anything: Start and Stop send `p:start <name>` /
//! `p:stop <name>` with the desk's own name for the row, and the desk
//! answers (`project`), which the sheet shows. A start the desk accepted
//! (or one already running) switches the view on the desk's side; the
//! sheet then closes.

const std = @import("std");
const shared = @import("shared");
const projects = shared.projects;
const tabs_wire = shared.tabs;
const theme = shared.theme;
const frame = @import("frame.zig");
const input = @import("input.zig");

/// Button ids (clear of the shell's and the other panels' ranges).
pub const ids = struct {
    pub const close: u32 = 1800;
    /// open0 + row: Start or Open.
    pub const open0: u32 = 1810;
    /// stop0 + row: Stop.
    pub const stop0: u32 = 1830;
};

comptime {
    std.debug.assert(ids.open0 + projects.max_projects <= ids.stop0);
}

/// What the sheet shows this frame (the device's copies).
pub const Input = struct {
    list: *const projects.List,
    /// The open tabs (Open on a running project shows its tab when one
    /// has the project's name).
    tabs: []const tabs_wire.Entry = &.{},
    /// The desk's latest `project` answer and its count (a new count is a
    /// new answer).
    answer: ?projects.Answer = null,
    answer_gen: u64 = 0,
};

/// What the shell does for the sheet.
pub const Effect = union(enum) {
    none,
    /// Send this frame (`p:start <name>` / `p:stop <name>`).
    send: []const u8,
    /// Show the tab at bar position i.
    select_tab: usize,
};

pub const Bufs = struct {
    rows: [projects.max_projects]frame.PanelRow = undefined,
    row_txt: [projects.max_projects][projects.max_name + 80]u8 = undefined,
    lines: [1]frame.PanelText = undefined,
    after: [1]frame.PanelText = undefined,
    buttons: [1]frame.PanelButton = undefined,
};

pub const Sheet = struct {
    open: bool = false,
    /// The row Enter / Delete act on.
    sel: usize = 0,
    /// The note under the title: the last answer, or what was asked.
    note: []const u8 = "",
    note_tone: frame.Tone = .muted,
    /// The answer count already shown.
    seen: u64 = 0,
    frame_buf: [projects.max_name + 8]u8 = undefined,
    note_buf: [projects.max_name + 48]u8 = undefined,

    pub fn toggle(s: *Sheet) void {
        if (s.open) s.close() else {
            s.open = true;
            s.note = "";
        }
    }

    pub fn close(s: *Sheet) void {
        s.open = false;
    }

    /// A new answer from the desk: its sentence; a start it accepted
    /// (started, or already running) closes the sheet, the desk having
    /// switched the view to it. Call every frame.
    pub fn sync(s: *Sheet, in: Input) void {
        if (in.list.len == 0) s.sel = 0 else s.sel = @min(s.sel, in.list.len - 1);
        if (in.answer_gen == s.seen) return;
        s.seen = in.answer_gen;
        const a = in.answer orelse return;
        s.note = a.result.text();
        s.note_tone = if (a.result.ok()) .good else if (a.result == .rate_limited or a.result == .not_running) .warn else .bad;
        if (a.op == .start and a.result.ok()) s.open = false;
    }

    pub fn panel(s: *const Sheet, in: Input, b: *Bufs) frame.Panel {
        const l = in.list.slice();
        for (l, 0..) |*e, i| {
            const mode = switch (e.mode) {
                .ask => "Ask",
                .plan => "Plan",
            };
            const state = if (!e.running)
                (if (e.mode == .plan) "not running \u{00B7} read-only planning" else "not running")
            else if (e.stoppable) "running \u{00B7} started from a device" else "running";
            const text = std.fmt.bufPrint(&b.row_txt[i], "{s}  [{s}]  \u{00B7}  {s}", .{ e.name(), mode, state }) catch e.name();
            const at: u32 = @intCast(i);
            b.rows[i] = .{
                .text = text,
                .tone = if (e.running) .normal else .muted,
                .selected = i == s.sel,
                .dot = theme.fromU32(e.color),
                .button = if (e.running)
                    .{ .label = "Open", .id = ids.open0 + at, .focused = i == s.sel }
                else
                    .{ .label = "Start", .id = ids.open0 + at, .tone = .good, .focused = i == s.sel },
                .button2 = if (e.stoppable) .{ .label = "Stop", .id = ids.stop0 + at, .tone = .bad } else null,
            };
        }
        b.lines[0] = if (s.note.len > 0)
            .{ .text = s.note, .tone = s.note_tone }
        else if (l.len == 0)
            .{ .text = "The desk has not allowed any project to be started from a device." }
        else
            .{ .text = "Enter starts or opens the chosen project, Delete stops it, Esc closes." };
        b.after[0] = .{ .text = "Names only: this device never sees a project's folder. The desk picks each project's mode (Ask: Claude asks before every edit and command; Plan: read and plan only). Stop is offered only for sessions a device started. At most 3 starts a minute." };
        b.buttons[0] = .{ .label = "Close", .id = ids.close };
        return .{
            .title = "Projects you allowed at the desk",
            .lines = &b.lines,
            .rows = b.rows[0..l.len],
            .after = &b.after,
            .buttons = &b.buttons,
        };
    }

    /// A key while the sheet is open.
    pub fn key(s: *Sheet, k: input.Key, in: Input) Effect {
        const n = in.list.len;
        switch (k) {
            .escape => s.close(),
            .up => if (s.sel > 0) {
                s.sel -= 1;
            },
            .down => if (s.sel + 1 < n) {
                s.sel += 1;
            },
            .enter => if (s.sel < n) return s.primary(s.sel, in),
            .delete => if (s.sel < n) return s.stop(s.sel, in),
            else => {},
        }
        return .none;
    }

    /// One of the sheet's buttons (ids); null if the id is not the sheet's.
    pub fn button(s: *Sheet, id: u32, in: Input) ?Effect {
        const n = in.list.len;
        if (id == ids.close) {
            s.close();
            return .none;
        }
        if (id >= ids.open0 and id < ids.open0 + projects.max_projects) {
            const i = id - ids.open0;
            if (i >= n) return .none;
            s.sel = i;
            return s.primary(i, in);
        }
        if (id >= ids.stop0 and id < ids.stop0 + projects.max_projects) {
            const i = id - ids.stop0;
            if (i >= n) return .none;
            s.sel = i;
            return s.stop(i, in);
        }
        return null;
    }

    /// Start (not running), or Open: its tab when one carries its name,
    /// else a start, which the desk answers `switched` (showing it).
    fn primary(s: *Sheet, i: usize, in: Input) Effect {
        const e = &in.list.items[i];
        if (e.running) for (in.tabs, 0..) |*t, k| if (std.mem.eql(u8, t.name(), e.name())) {
            s.close();
            return .{ .select_tab = k };
        };
        return s.request(.start, e.name());
    }

    fn stop(s: *Sheet, i: usize, in: Input) Effect {
        const e = &in.list.items[i];
        if (!e.stoppable) return .none;
        return s.request(.stop, e.name());
    }

    fn request(s: *Sheet, op: projects.Op, name: []const u8) Effect {
        const f = projects.requestFrame(op, name, &s.frame_buf) orelse return .none;
        s.note = std.fmt.bufPrint(&s.note_buf, "{s} {s}\u{2026}", .{ if (op == .start) "Starting" else "Stopping", name }) catch "";
        s.note_tone = .muted;
        return .{ .send = f };
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn sample() projects.List {
    var l: projects.List = .{};
    l.items[0] = .{ .color = 0x4DA3FF, .mode = .ask, .running = true };
    l.items[0].setName("Portal");
    l.items[1] = .{ .color = 0x22D3EE, .mode = .ask };
    l.items[1].setName("SpeechToText");
    l.items[2] = .{ .color = 0xFFC940, .mode = .plan, .running = true, .stoppable = true };
    l.items[2].setName("Notes");
    l.len = 3;
    return l;
}

test "rows: dot, badge, state; Start, Open, and Stop only for a device-started session" {
    const l = sample();
    var s: Sheet = .{ .open = true };
    var b: Bufs = .{};
    const p = s.panel(.{ .list = &l }, &b);
    try testing.expectEqual(@as(usize, 3), p.rows.len);
    try testing.expectEqualStrings("Open", p.rows[0].button.?.label);
    try testing.expect(p.rows[0].button2 == null);
    try testing.expectEqualStrings("Start", p.rows[1].button.?.label);
    try testing.expect(p.rows[1].button2 == null);
    try testing.expectEqualStrings("Open", p.rows[2].button.?.label);
    try testing.expectEqualStrings("Stop", p.rows[2].button2.?.label);
    try testing.expect(std.mem.indexOf(u8, p.rows[2].text, "[Plan]") != null);
    try testing.expect(std.mem.indexOf(u8, p.rows[1].text, "[Ask]") != null);
    try testing.expect(p.rows[0].dot != null and p.rows[0].selected);
}

test "keys and buttons send the desk's names; Open shows a tab of that name" {
    const l = sample();
    var tabs: tabs_wire.List = .{};
    tabs.items[0] = .{ .id = @splat(7), .color = 0, .state = .idle };
    tabs.items[0].setName("Portal");
    tabs.len = 1;
    const in: Input = .{ .list = &l, .tabs = tabs.slice() };
    var s: Sheet = .{ .open = true };
    // Row 0 runs and has a tab: Open shows it and closes the sheet.
    try testing.expectEqual(@as(usize, 0), s.key(.enter, in).select_tab);
    try testing.expect(!s.open);
    s.open = true;
    _ = s.key(.down, in);
    try testing.expectEqualStrings("p:start SpeechToText", s.key(.enter, in).send);
    // Delete on a session the desk started: nothing.
    try testing.expect(s.key(.delete, in) == .none);
    _ = s.key(.down, in);
    _ = s.key(.down, in); // stays on the last row
    try testing.expectEqual(@as(usize, 2), s.sel);
    try testing.expectEqualStrings("p:stop Notes", s.key(.delete, in).send);
    // Notes runs without a tab of its name here: Open asks the desk.
    try testing.expectEqualStrings("p:start Notes", s.button(ids.open0 + 2, in).?.send);
    try testing.expectEqualStrings("p:stop Notes", s.button(ids.stop0 + 2, in).?.send);
    try testing.expect(s.button(ids.stop0 + 1, in).? == .none);
    try testing.expect(s.button(ids.open0 + 9, in).? == .none);
    try testing.expect(s.button(999, in) == null);
    _ = s.key(.escape, in);
    try testing.expect(!s.open);
}

test "answers: shown once; an accepted start closes the sheet" {
    const l = sample();
    var s: Sheet = .{ .open = true };
    var a: projects.Answer = .{ .op = .start, .result = .rate_limited };
    s.sync(.{ .list = &l, .answer = a, .answer_gen = 1 });
    try testing.expect(s.open);
    try testing.expectEqualStrings(projects.Result.rate_limited.text(), s.note);
    a.result = .started;
    s.sync(.{ .list = &l, .answer = a, .answer_gen = 2 });
    try testing.expect(!s.open);
    // The same answer again (same count) changes nothing.
    s.open = true;
    s.sync(.{ .list = &l, .answer = a, .answer_gen = 2 });
    try testing.expect(s.open);
}
