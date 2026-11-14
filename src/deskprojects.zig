//! The desk window's side of startable projects (docs/tabs-design.md,
//! "Starting projects from a device"): the Projects panel's data and
//! actions (ui/panels/projects.zig draws and drives it), and the "started
//! by <device>" / "stopped by <device>" notes on the desk's tabs. The list
//! is kept in settings.txt only: every change here loads the file again,
//! changes that one entry, saves it, and hands the result to the hub (which
//! tells devices); SettingsWatch (main.zig) follows edits made elsewhere.

const std = @import("std");
const Io = std.Io;
const ui = @import("portal_ui");
const P = ui.panels.projects;
const projects_wire = @import("shared").projects;
const tabs_wire = @import("shared").tabs;
const tabs = @import("tabs.zig");
const settings = @import("settings.zig");
const cmdline = @import("cmdline.zig");
const win32 = @import("win32.zig");

const max = settings.max_startable;
const max_note = 80;

/// What an action needs from the desk.
pub const Ctx = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// The data directory (settings.txt).
    dir: []const u8,
    hub: *tabs.Hub,
    /// The tab shown at the desk ("Add this tab's folder").
    shown: ?*tabs.Tab,
    /// The desk's copy of settings.txt, kept current.
    saved: *settings.Settings,
    env: *const std.process.Environ.Map,
};

pub const DeskProjects = struct {
    panel: P.Panel = .{},
    bufs: P.Bufs = .{},
    /// Copies of the hub's list, the rows pointing into them.
    entries: [max]settings.StartableEntry = undefined,
    states: [max][max_note]u8 = undefined,
    rows: [max]P.Row = undefined,
    unsafe_buf: [240]u8 = undefined,
    view: P.View = .{},
    /// The desk's tab notes ("started by iPhone"), in bar order.
    note_bufs: [tabs_wire.max_tabs][max_note]u8 = undefined,
    notes: [tabs_wire.max_tabs][]const u8 = undefined,
    n_notes: usize = 0,

    /// The panel's view as the hub has it now (call before drawing it or
    /// handing it input).
    pub fn refresh(d: *DeskProjects, hub: *tabs.Hub, shown: ?*tabs.Tab) void {
        hub.mutex.lockUncancelable(hub.io);
        defer hub.mutex.unlock(hub.io);
        const n = hub.n_startable;
        var shown_listed = false;
        for (hub.startable[0..n], 0..) |*e, i| {
            d.entries[i] = e.*;
            const c = &d.entries[i];
            const name = c.name.get() orelse "";
            var state: []const u8 = "";
            if (hub.runningLocked(c)) |t| {
                const note = t.deskNoteLocked(&d.states[i]);
                state = if (note.len > 0) note else "running";
            }
            if (shown) |t| if (settings.samePath(t.cwd, c.path.get() orelse "")) {
                shown_listed = true;
            };
            d.rows[i] = .{ .name = name, .mode = c.mode, .folder = c.path.get() orelse "", .color = hub.colorFor(name), .state = state };
        }
        const unsafe = if (hub.program.device_start == .ok) "" else blk: {
            var rb: [200]u8 = undefined;
            const why = cmdline.deviceStartText(hub.program.device_start, &rb);
            break :blk std.fmt.bufPrint(&d.unsafe_buf, "Devices cannot start projects now: {s}.", .{why}) catch "Devices cannot start projects now.";
        };
        d.view = .{
            .rows = d.rows[0..n],
            .unsafe = unsafe,
            .can_add_shown = if (shown) |t| !shown_listed and t.cwd.len > 0 and projects_wire.startableName(t.name()) and n < max else false,
        };
    }

    /// Caller holds hub.mutex. The desk's tab notes, in bar order (the
    /// hub's tab order, as entriesLocked lists them).
    pub fn notesLocked(d: *DeskProjects, hub: *tabs.Hub) []const []const u8 {
        d.n_notes = @min(hub.n, tabs_wire.max_tabs);
        for (hub.tabs[0..d.n_notes], 0..) |t, i| d.notes[i] = t.deskNoteLocked(&d.note_bufs[i]);
        return d.notes[0..d.n_notes];
    }

    /// Performs a panel action (after `refresh`).
    pub fn perform(d: *DeskProjects, a: P.Action, c: Ctx) void {
        switch (a) {
            .none, .closed => {},
            .add_folder => {
                var buf: [32768]u16 = undefined;
                const dir_w = win32.pickFolder(&buf, std.unicode.utf8ToUtf16LeStringLiteral("Choose a project folder a paired device may start")) orelse return;
                const dir = std.unicode.wtf16LeToWtf8Alloc(c.gpa, dir_w) catch return;
                defer c.gpa.free(dir);
                var nb: [tabs_wire.max_name]u8 = undefined;
                const name = tabs.displayName(dir, c.env.get("USERPROFILE"), c.env.get("USERNAME"), &nb);
                d.add(c, name, dir);
            },
            .add_shown => {
                const t = c.shown orelse return;
                d.add(c, t.name(), t.cwd);
            },
            .set_mode => |m| {
                if (m.row >= d.view.rows.len) return;
                const name = d.view.rows[m.row].name;
                var s = load(c);
                const i = s.findStartable(name) orelse return d.panel.setNote(.warn, "{s} is no longer in settings.txt.", .{name});
                s.startable[i].mode = m.mode;
                if (d.save(c, &s)) d.panel.setNote(.good, "{s}: a device start now runs in {s} mode.", .{ name, if (m.mode == .ask) "Ask" else "Plan" });
            },
            .remove => |i| {
                if (i >= d.view.rows.len) return;
                const name = d.view.rows[i].name;
                var s = load(c);
                if (!s.removeStartable(name)) return d.panel.setNote(.warn, "{s} is no longer in settings.txt.", .{name});
                if (d.save(c, &s)) d.panel.setNote(.good, "Removed {s}: devices can no longer start it (a running session goes on).", .{name});
            },
        }
        d.refresh(c.hub, c.shown);
    }

    fn add(d: *DeskProjects, c: Ctx, name: []const u8, folder: []const u8) void {
        var s = load(c);
        s.addStartable(name, .ask, folder) catch |err| return d.panel.setNote(.bad, "Not added: {s}", .{switch (err) {
            error.BadName => "its name can't be a project name (1-64 bytes without \\ / : | \" and not starting with - or .). Use portalctl startable add <folder> --name NAME.",
            error.BadFolder => "the folder must be an absolute path.",
            error.Duplicate => "that name or folder is already in the list.",
            error.Full => "the list is full.",
        }});
        if (d.save(c, &s)) d.panel.setNote(.good, "Added {s} (Ask mode; Enter switches it to Plan).", .{name});
    }

    /// settings.txt as it is now (it may have been edited elsewhere).
    fn load(c: Ctx) settings.Settings {
        return settings.loadOrNull(c.gpa, c.io, c.dir) orelse c.saved.*;
    }

    fn save(d: *DeskProjects, c: Ctx, s: *const settings.Settings) bool {
        settings.save(c.gpa, c.io, c.dir, s) catch |err| {
            d.panel.setNote(.bad, "Could not save the settings: {t}.", .{err});
            return false;
        };
        c.saved.* = s.*;
        c.hub.setStartable(s.startableSlice());
        return true;
    }
};
