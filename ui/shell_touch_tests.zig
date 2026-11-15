//! The touch path on a phone: Shell and Frame driven together by finger
//! presses (Frame.pointerDown / pointerMove / pointerUp with Frame.touch)
//! at iPhone size (430 x 932 points at 3x, the safe area as Frame.insets),
//! the way the device glue (client/src/connect.zig) wires them: the
//! Conversation view with its For-you panel as the shell's content view,
//! the shell's input sink behind the frame.
//!
//! After every frame built here: nothing is drawn under the insets, and
//! every tap target is at least `frame.touch_target` logical px tall and
//! wide.

const std = @import("std");
const testing = std.testing;
const Font = @import("Font");
const shared = @import("shared");
const tabs_wire = shared.tabs;
const planusage = shared.planusage;
const shell = @import("shell.zig");
const frame = @import("frame.zig");
const grid_mod = @import("grid.zig");
const input = @import("input.zig");
const foryou = @import("foryou.zig");
const cv = @import("convoview.zig");
const projects_sheet = @import("projects_sheet.zig");
const hidden_tabs = @import("hidden_tabs.zig");
const more_menu = @import("more_menu.zig");

const ids = shell.ids;

/// iPhone (Pro Max class): 430 x 932 points at 3x; the safe area's top
/// (the Dynamic Island) and bottom (the home indicator), in points.
const scale: f32 = 3;
const fb: [2]u32 = .{ 430 * 3, 932 * 3 };
const safe: frame.Insets = .{ .top = 59 * scale, .bottom = 34 * scale };
/// The system keyboard over the bottom (points), while the line has it.
const keyboard_pt: f32 = 336;

/// What reached the device's side of the shell.
const HostRec = struct {
    answers: usize = 0,
    sent: [8][64]u8 = undefined,
    sent_len: [8]usize = undefined,
    n_sent: usize = 0,
    cmds: [8]shell.Command = undefined,
    n_cmds: usize = 0,

    fn of(p: *anyopaque) *HostRec {
        return @ptrCast(@alignCast(p));
    }
    fn key(_: *anyopaque, _: input.Key, _: input.Mods) void {}
    fn char(_: *anyopaque, _: u21, _: input.Mods) void {}
    fn answer(p: *anyopaque, _: []const u8) void {
        of(p).answers += 1;
    }
    fn send(p: *anyopaque, f: []const u8) bool {
        const r = of(p);
        const i = r.n_sent % r.sent.len;
        @memcpy(r.sent[i][0..f.len], f);
        r.sent_len[i] = f.len;
        r.n_sent += 1;
        return true;
    }
    fn command(p: *anyopaque, c: shell.Command) void {
        const r = of(p);
        r.cmds[r.n_cmds % r.cmds.len] = c;
        r.n_cmds += 1;
    }
    fn shortcut(_: *anyopaque, _: u21, _: input.Mods, _: shell.Focus) bool {
        return false;
    }
    const vt: shell.Host.VTable = .{ .key = key, .char = char, .answer = answer, .send = send, .command = command, .shortcut = shortcut };

    fn lastSent(r: *const HostRec) []const u8 {
        const i = (r.n_sent - 1) % r.sent.len;
        return r.sent[i][0..r.sent_len[i]];
    }
    fn lastCmd(r: *const HostRec) shell.Command {
        return r.cmds[(r.n_cmds - 1) % r.cmds.len];
    }
};

const DictRec = struct {
    starts: usize = 0,
    stops: usize = 0,
    fn of(p: *anyopaque) *DictRec {
        return @ptrCast(@alignCast(p));
    }
    fn start(p: *anyopaque) bool {
        of(p).starts += 1;
        return true;
    }
    fn stop(p: *anyopaque) void {
        of(p).stops += 1;
    }
};

/// The phone: the shell, the frame, and the For-you rig (foryou.Rig: a
/// conversation, the panel's store, its sender and the view's clock).
const Phone = struct {
    fonts: *Font.fontset.FontSet,
    f: frame.Frame,
    g: grid_mod.Grid = .{},
    sh: shell.Shell,
    host: HostRec = .{},
    fy: foryou.Rig,
    dict: DictRec = .{},
    tabs: [3]tabs_wire.Entry = undefined,
    st: shell.State = .{},
    o: frame.Overlay = .{},

    /// The tab the For-you rig shows (foryou.Rig's).
    const tab: tabs_wire.Id = @splat(0xa);

    fn init(ph: *Phone, gpa: std.mem.Allocator, fonts: *Font.fontset.FontSet) !void {
        ph.* = .{ .fonts = fonts, .f = frame.Frame.init(gpa, .fit_grid), .sh = undefined, .fy = undefined };
        try ph.fy.init(gpa, "instruct", &foryou.reply);
        ph.sh = shell.Shell.init(gpa, .viewer, .{ .ctx = &ph.host, .vtable = &HostRec.vt });
        // What the iPhone's glue sets: touch (client/src/touchkbd.zig), the
        // frame's touch presses (the Presenter), the safe area.
        ph.sh.touch = .{ .enabled = true };
        ph.f.touch = true;
        ph.f.insets = safe;
        ph.sh.conversation = ph.fy.v.contentView();
        ph.sh.dictation = .{ .ctx = &ph.dict, .start = DictRec.start, .stop = DictRec.stop };
        ph.sh.setSpeechReady(true);
        const names = [_][]const u8{ "Alpha", "Beta", "Gamma" };
        for (&ph.tabs, names, 0..) |*t, n, i| {
            t.* = .{ .id = @splat(@intCast(0xa + i)), .color = 0x3366CC };
            t.setName(n);
        }
        ph.st = .{
            .viewer = .{ .status = .connected, .mode = .instruct, .host = "desk", .has_grid = true },
            .tabs = &ph.tabs,
            .current = tab,
        };
    }

    fn deinit(ph: *Phone, gpa: std.mem.Allocator) void {
        ph.sh.deinit();
        ph.f.deinit();
        ph.fy.deinit(gpa);
    }

    fn now(ph: *const Phone) i64 {
        return ph.fy.clk.t;
    }

    /// One frame as the glue makes it: the shell's overlay, the frame,
    /// then the view's swipe guard starts on screen.
    fn frameNow(ph: *Phone) !void {
        ph.st.now_ms = ph.now();
        ph.o = ph.sh.overlay(ph.st);
        ph.f.now_ms = ph.now();
        ph.f.build(ph.fonts, fb, scale, &ph.g, ph.o);
        ph.fy.v.presented(ph.now());
        try expectClearOfInsets(&ph.f);
        try expectTouchSized(&ph.f);
    }

    fn centre(ph: *const Phone, id: u32) ![2]f32 {
        return frame.hitCentre(&ph.f, id) orelse {
            std.debug.print("no tap target {d}\n", .{id});
            return error.TestUnexpectedResult;
        };
    }

    /// A finger down and up on button `id` (held `hold_ms`), then a frame.
    fn tapHeld(ph: *Phone, id: u32, hold_ms: i64) !void {
        const c = try ph.centre(id);
        const sink = ph.sh.sink();
        ph.f.now_ms = ph.now();
        ph.f.pointerDown(c[0], c[1], .left, .{}, sink);
        ph.fy.clk.t += hold_ms;
        ph.f.now_ms = ph.now();
        ph.f.pointerUp(c[0], c[1], .left, sink);
        try ph.frameNow();
    }

    fn tap(ph: *Phone, id: u32) !void {
        try ph.tapHeld(id, 80);
    }

    /// A horizontal swipe across button `id`'s target: from the far side
    /// of the screen to `dx` (window pixels) past it.
    fn swipe(ph: *Phone, id: u32, dx: f32) !void {
        const c = try ph.centre(id);
        const w: f32 = @floatFromInt(fb[0]);
        const x0 = if (dx < 0) w * 0.85 else w * 0.15;
        const sink = ph.sh.sink();
        ph.f.pointerDown(x0, c[1], .left, .{}, sink);
        ph.fy.clk.t += 60;
        ph.f.pointerMove(x0 + dx / 4, c[1], sink);
        ph.fy.clk.t += 60;
        ph.f.pointerMove(x0 + dx, c[1], sink);
        ph.f.pointerUp(x0 + dx, c[1], .left, sink);
        try ph.frameNow();
    }
};

/// Every draw command lies inside the window minus its insets.
fn expectClearOfInsets(f: *const frame.Frame) !void {
    const x0 = f.insets.left;
    const y0 = f.insets.top;
    const x1 = @as(f32, @floatFromInt(fb[0])) - f.insets.right;
    const y1 = @as(f32, @floatFromInt(fb[1])) - f.insets.bottom;
    const eps = 0.5;
    for (f.list.cmds.items) |cmd| {
        const box: [4]f32 = switch (cmd) {
            .rect => |r| .{ r.x, r.y, r.x + r.w, r.y + r.h },
            .glyph => |g| .{ g.x, g.y, g.x, g.y },
            .text => |t| blk: {
                const lh: f32 = @floatFromInt(f.list.fonts[t.font].cell_h);
                var b: [4]f32 = .{ t.x, t.y, t.x, t.y + lh };
                if (t.clip) |c| b = .{ @max(b[0], c[0]), @max(b[1], c[1]), @min(b[2], c[2]), @min(b[3], c[3]) };
                break :blk b;
            },
            .image => |im| im.clip,
        };
        // Clipped away entirely: nothing shows.
        if (box[2] < box[0] or box[3] < box[1]) continue;
        if (box[0] < x0 - eps or box[1] < y0 - eps or box[2] > x1 + eps or box[3] > y1 + eps) {
            std.debug.print("drawn under the insets: {any} (clear: {d},{d} .. {d},{d})\n", .{ box, x0, y0, x1, y1 });
            return error.TestUnexpectedResult;
        }
    }
    for (f.hits[0..f.n_hits]) |h| {
        if (h.x < x0 - eps or h.y < y0 - eps or h.x + h.w > x1 + eps or h.y + h.h > y1 + eps) {
            std.debug.print("tap target under the insets: {any}\n", .{h});
            return error.TestUnexpectedResult;
        }
    }
}

/// Every tap target is at least the touch minimum both ways.
fn expectTouchSized(f: *const frame.Frame) !void {
    const min = frame.touch_target * scale - 0.5;
    var small = false;
    for (f.hits[0..f.n_hits]) |h| if (h.w < min or h.h < min) {
        std.debug.print("tap target under {d} px: {any}\n", .{ min, h });
        small = true;
    };
    if (small) return error.TestUnexpectedResult;
}

fn hasPanel(o: frame.Overlay, title: []const u8) bool {
    return if (o.panel) |p| std.mem.eql(u8, p.title, title) else false;
}

fn loadFonts(gpa: std.mem.Allocator) !Font.fontset.FontSet {
    return Font.fontset.FontSet.load(gpa, testing.io) catch error.SkipZigTest;
}

test "phone For you: a swipe left answers Yes, right No, a tap toggles the full card, the 600 ms guard holds" {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts);
    defer ph.deinit(gpa);
    // The rig's rows were first on screen at 1000.
    try ph.frameNow();
    try testing.expect(ph.o.screen == .view);
    const row1 = foryou.ids.row0 + 1;
    const row2 = foryou.ids.row0 + 2;
    // Within the guard: a swipe answers nothing.
    ph.fy.clk.t = 1000 + cv.swipe_guard_ms - 200;
    try ph.swipe(row1, -900);
    try testing.expectEqual(@as(usize, 0), ph.fy.sent.n);
    // A tap opens the full card (taller), another folds it.
    ph.fy.clk.t = 3000;
    const folded = ph.fy.p.rowRect(1, ph.fy.v.fonts.?).h;
    try ph.tap(row1);
    try testing.expect(ph.fy.p.rows[1].open);
    try testing.expect(ph.fy.p.rowRect(1, ph.fy.v.fonts.?).h > folded);
    try ph.tap(row1);
    try testing.expect(!ph.fy.p.rows[1].open);
    try testing.expectEqual(@as(usize, 0), ph.fy.sent.n);
    // Past the guard: left is Yes (as the row's frame, never a key).
    try ph.swipe(row1, -900);
    try testing.expectEqualStrings("i:yes 02020202020202020202020202020202", ph.fy.sent.last());
    ph.fy.clk.t += 1000;
    try ph.frameNow();
    // Right is No.
    try ph.swipe(row2, 900);
    try testing.expectEqualStrings("i:no 03030303030303030303030303030303", ph.fy.sent.last());
    try testing.expectEqual(@as(usize, 2), ph.fy.sent.n);
    // No swipe reached the terminal as an answer key.
    try testing.expectEqual(@as(usize, 0), ph.host.answers);
}

test "phone For you: the Recap button" {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts);
    defer ph.deinit(gpa);
    try ph.frameNow();
    try testing.expect(ph.fy.p.recapOffered());
    try ph.tap(foryou.ids.recap);
    try testing.expectEqualStrings("r:recap 0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", ph.fy.sent.last());
}

test "phone hidden tabs: a long press opens a tab's menu, Hide; the hidden button's sheet, Show" {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts);
    defer ph.deinit(gpa);
    try ph.frameNow();
    // A short tap on Beta switches to it.
    try ph.tap(ids.tab0 + 1);
    try testing.expectEqual(@as(usize, 1), ph.host.lastCmd().select_tab);
    // A long press: Beta's menu; Hide.
    try ph.tapHeld(ids.tab0 + 1, frame.long_press_ms);
    try testing.expect(hasPanel(ph.o, "Beta"));
    try ph.tap(hidden_tabs.ids.hide);
    try testing.expect(ph.sh.hidden.contains("Beta"));
    try testing.expect(ph.host.lastCmd() == .hidden_changed);
    try testing.expect(ph.o.panel == null);
    try testing.expect(frame.hitCentre(&ph.f, ids.tab0 + 1) == null);
    // The "••• 1 hidden" button: the sheet; Show puts Beta back.
    try ph.tap(hidden_tabs.ids.button);
    try testing.expect(ph.o.panel != null);
    try ph.tap(hidden_tabs.ids.show0 + 1);
    try testing.expect(!ph.sh.hidden.contains("Beta"));
    try testing.expectEqual(@as(usize, 1), ph.host.lastCmd().select_tab);
    try testing.expect(frame.hitCentre(&ph.f, ids.tab0 + 1) != null);
}

test "phone Projects sheet: open it from the top bar, Start, Stop" {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts);
    defer ph.deinit(gpa);
    // Portal (running), SpeechToText (not running), Notes (device-started).
    const pl = projects_sheet.sample();
    ph.st.projects = &pl;
    try ph.frameNow();
    // At phone width the Projects button may sit behind "•••".
    if (frame.hitCentre(&ph.f, ids.projects) != null) {
        try ph.tap(ids.projects);
    } else {
        try ph.tap(more_menu.ids.button);
        try ph.tap(more_menu.ids.item0);
    }
    try testing.expect(hasPanel(ph.o, "Projects you allowed at the desk"));
    try ph.tap(projects_sheet.ids.open0 + 1);
    try testing.expectEqualStrings("p:start SpeechToText", ph.host.lastSent());
    try ph.tap(projects_sheet.ids.stop0 + 2);
    try testing.expectEqualStrings("p:stop Notes", ph.host.lastSent());
    try ph.tap(projects_sheet.ids.close);
    try testing.expect(ph.o.panel == null);
}

test "phone usage bar: a tap shows its detail, another hides it" {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts);
    defer ph.deinit(gpa);
    ph.st.usage = .{ .week = .{ .pct = 40 }, .five_hour = .{ .pct = 10 } };
    try ph.frameNow();
    try testing.expectEqual(@as(usize, 0), ph.o.usage.?.rows.len);
    try ph.tap(ids.usage_strip);
    try testing.expectEqual(@as(usize, 2), ph.o.usage.?.rows.len);
    try ph.tap(ids.usage_strip);
    try testing.expectEqual(@as(usize, 0), ph.o.usage.?.rows.len);
}

test "phone ••• menu: opening it and choosing an item" {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts);
    defer ph.deinit(gpa);
    var a: shared.activity.Activity = .{ .len = 1 };
    a.tabs[0] = .{ .id = Phone.tab };
    ph.st.activity = &a;
    // Names too long for the bar at phone width: the buttons go behind
    // "•••".
    for (&ph.tabs, [_][]const u8{ "Alpha-the-first-project", "Beta-the-second-one", "Gamma-the-third-one" }) |*t, n| t.setName(n);
    try ph.frameNow();
    try testing.expectEqual(@as(?u32, more_menu.ids.button), ph.o.top_bar.?.more_id);
    try ph.tap(more_menu.ids.button);
    try testing.expect(hasPanel(ph.o, "More"));
    const first = ph.o.panel.?.rows[0].text;
    try testing.expectEqualStrings("Usage", first);
    try ph.tap(more_menu.ids.item0);
    try testing.expect(hasPanel(ph.o, "Usage"));
    try testing.expect(!ph.sh.more.open);
}

test "phone input line: Instruct, tap the line, type, Send; with the keyboard up too" {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts);
    defer ph.deinit(gpa);
    ph.sh.dictation = null; // typing only here (the next test dictates)
    try ph.frameNow();
    try testing.expect(ph.f.text_slot == null);
    try ph.tap(ids.instruct);
    try testing.expect(ph.sh.instructing);
    // The line is focused: its slot is where the native field goes.
    try testing.expect(ph.f.text_slot != null);
    // The system keyboard comes up over the bottom.
    ph.f.insets.bottom = keyboard_pt * scale;
    try ph.frameNow();
    try ph.tap(ids.line);
    try testing.expectEqual(shell.Focus.line, ph.sh.focus());
    // The native field's text arrives as characters (Presenter).
    const sink = ph.sh.sink();
    for ("run the tests") |c| sink.char(c, .{});
    try ph.frameNow();
    try testing.expectEqualStrings("run the tests", ph.f.text_slot.?.value());
    try ph.tap(ids.send);
    try testing.expectEqualStrings("l:run the tests", ph.host.lastSent());
    try testing.expect(!ph.sh.instructing);
    ph.f.insets = safe;
    try ph.frameNow();
    try testing.expect(ph.f.text_slot == null);
}

test "phone dictation: Instruct records, the mic button stops and starts it, Close" {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts);
    defer ph.deinit(gpa);
    try ph.frameNow();
    try ph.tap(ids.instruct);
    try testing.expectEqual(@as(usize, 1), ph.dict.starts);
    try testing.expect(ph.sh.dictating);
    // In the panel the same id is the 🎤 toggle.
    try ph.tap(ids.instruct);
    try testing.expectEqual(@as(usize, 1), ph.dict.stops);
    try testing.expect(!ph.sh.dictating);
    try ph.tap(ids.instruct);
    try testing.expectEqual(@as(usize, 2), ph.dict.starts);
    try ph.tap(ids.instruct_close);
    try testing.expect(!ph.sh.instructing and !ph.sh.dictating);
}
