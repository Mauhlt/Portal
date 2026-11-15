//! The touch path on a phone: Shell and Frame driven together by finger
//! presses (Frame.pointerDown / pointerMove / pointerUp with Frame.touch)
//! at iPhone size, the way the device glue (client/src/connect.zig) wires
//! them: the Conversation view with its For-you panel as the shell's
//! content view, the shell's input sink behind the frame.
//!
//! Every feature runs on every screen (`screens`): portrait (430 x 932
//! points at 3x) and landscape (932 x 430), the safe area as Frame.insets.
//! Turning the phone between frames (`Phone.turn`: the window layer's
//! .resize and .insets, as the Presenter hands them on) is tested in the
//! middle of a swipe, with the input line focused, with a sheet open, with
//! the usage strip expanded and with hidden tabs.
//!
//! After every frame built here: nothing is drawn or tappable under the
//! insets, and every tap target is at least `frame.touch_target` logical
//! px (Apple's 44 pt) tall and wide.

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

/// iPhone (Pro Max class) at 3x.
const scale: f32 = 3;

/// A way the phone is held: the window (pixels), its safe area (pixels),
/// and the system keyboard's height over the bottom (points) while the
/// input line has it.
const Screen = struct {
    name: []const u8,
    fb: [2]u32,
    safe: frame.Insets,
    keyboard_pt: f32,

    /// The insets with the keyboard up (the window layer's bottomClear).
    fn withKeyboard(scr: Screen) frame.Insets {
        var i = scr.safe;
        i.bottom = @max(i.bottom, scr.keyboard_pt * scale);
        return i;
    }
};

/// Portrait: the Dynamic Island's top and the home indicator's bottom.
const portrait: Screen = .{ .name = "portrait", .fb = .{ 430 * 3, 932 * 3 }, .safe = .{ .top = 59 * scale, .bottom = 34 * scale }, .keyboard_pt = 336 };
/// Landscape, either way round (LandscapeLeft and LandscapeRight report
/// the same on these phones): both sides kept clear of the island, the
/// home indicator's bottom, no top.
const landscape: Screen = .{ .name = "landscape", .fb = .{ 932 * 3, 430 * 3 }, .safe = .{ .left = 59 * scale, .right = 59 * scale, .bottom = 21 * scale }, .keyboard_pt = 200 };
/// The mirrored pair with the island's side only (the island left, then
/// right): the layout must honour each edge on its own, and turning from
/// one to the other moves the origin at the same window size.
const island_left: Screen = .{ .name = "landscape, island left", .fb = landscape.fb, .safe = .{ .left = 59 * scale, .bottom = 21 * scale }, .keyboard_pt = 200 };
const island_right: Screen = .{ .name = "landscape, island right", .fb = landscape.fb, .safe = .{ .right = 59 * scale, .bottom = 21 * scale }, .keyboard_pt = 200 };

const screens = [_]Screen{ portrait, landscape, island_left, island_right };

/// Runs `body` on every screen; a failure says which.
fn onEvery(comptime body: fn (Screen) anyerror!void) !void {
    for (screens) |scr| body(scr) catch |e| {
        if (e != error.SkipZigTest) std.debug.print("(on the {s} screen)\n", .{scr.name});
        return e;
    };
}

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
    scr: Screen,
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

    fn init(ph: *Phone, gpa: std.mem.Allocator, fonts: *Font.fontset.FontSet, scr: Screen) !void {
        ph.* = .{ .fonts = fonts, .scr = scr, .f = frame.Frame.init(gpa, .fit_grid), .sh = undefined, .fy = undefined };
        try ph.fy.init(gpa, "instruct", &foryou.reply);
        ph.sh = shell.Shell.init(gpa, .viewer, .{ .ctx = &ph.host, .vtable = &HostRec.vt });
        // What the iPhone's glue sets: touch (client/src/touchkbd.zig), the
        // frame's touch presses (the Presenter), the safe area.
        ph.sh.touch = .{ .enabled = true };
        ph.f.touch = true;
        ph.f.insets = scr.safe;
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
        ph.f.build(ph.fonts, ph.scr.fb, scale, &ph.g, ph.o);
        ph.fy.v.presented(ph.now());
        try expectClearOfInsets(&ph.f, ph.scr.fb);
        try expectTouchSized(&ph.f);
    }

    /// The phone turns to `to` (the keyboard up or not) between frames:
    /// what the window layer sends (.resize, then .insets) as the
    /// Presenter hands it on (Frame.layoutChanged; the insets at the next
    /// build), then the next frame.
    fn turn(ph: *Phone, to: Screen, keyboard: bool) !void {
        ph.scr = to;
        ph.f.layoutChanged(to.fb, ph.sh.sink());
        ph.f.insets = if (keyboard) to.withKeyboard() else to.safe;
        try ph.frameNow();
    }

    fn width(ph: *const Phone) f32 {
        return @floatFromInt(ph.scr.fb[0]);
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

    /// Drags the content view down (towards older items) until button
    /// `id` is a tap target.
    fn reveal(ph: *Phone, id: u32) !void {
        var n: usize = 0;
        while (frame.hitCentre(&ph.f, id) == null) : (n += 1) {
            if (n == 20) return error.TestUnexpectedResult;
            const t = ph.f.regions.terminal;
            const x = t.x + t.w / 2;
            const y = t.y + t.h / 4;
            const sink = ph.sh.sink();
            ph.f.pointerDown(x, y, .left, .{}, sink);
            ph.f.pointerMove(x, y + t.h / 8, sink);
            ph.f.pointerMove(x, y + t.h / 2, sink);
            ph.f.pointerUp(x, y + t.h / 2, .left, sink);
            ph.fy.clk.t += 100;
            try ph.frameNow();
        }
    }

    /// Drags the open panel up (further down its contents) until button
    /// `id` is a tap target.
    fn revealInPanel(ph: *Phone, id: u32) !void {
        var n: usize = 0;
        while (frame.hitCentre(&ph.f, id) == null) : (n += 1) {
            if (n == 20) return error.TestUnexpectedResult;
            const b = ph.f.panel_box orelse return error.TestUnexpectedResult;
            const x = b.x + b.w / 2;
            const sink = ph.sh.sink();
            ph.f.pointerDown(x, b.y + b.h * 0.6, .left, .{}, sink);
            ph.f.pointerMove(x, b.y + b.h * 0.5, sink);
            ph.f.pointerMove(x, b.y + b.h * 0.3, sink);
            ph.f.pointerUp(x, b.y + b.h * 0.3, .left, sink);
            try ph.frameNow();
        }
    }

    fn tap(ph: *Phone, id: u32) !void {
        try ph.tapHeld(id, 80);
    }

    /// A horizontal swipe across button `id`'s target: from the far side
    /// of the screen across `share` of its width (< 0: to the left).
    fn swipe(ph: *Phone, id: u32, share: f32) !void {
        const c = try ph.centre(id);
        const w = ph.width();
        const dx = share * w;
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

/// Every draw command, tap target and the native field's slot lies inside
/// the window (`fb`) minus its insets.
fn expectClearOfInsets(f: *const frame.Frame, fb: [2]u32) !void {
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
    if (f.text_slot) |t| if (t.rect.x < x0 - eps or t.rect.y < y0 - eps or t.rect.x + t.rect.w > x1 + eps or t.rect.y + t.rect.h > y1 + eps) {
        std.debug.print("text field under the insets: {any}\n", .{t.rect});
        return error.TestUnexpectedResult;
    };
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

/// The room inside a screen's safe area (pixels).
fn clearArea(scr: Screen) [2]f32 {
    return .{
        @as(f32, @floatFromInt(scr.fb[0])) - scr.safe.left - scr.safe.right,
        @as(f32, @floatFromInt(scr.fb[1])) - scr.safe.top - scr.safe.bottom,
    };
}

fn hasPanel(o: frame.Overlay, title: []const u8) bool {
    return if (o.panel) |p| std.mem.eql(u8, p.title, title) else false;
}

fn loadFonts(gpa: std.mem.Allocator) !Font.fontset.FontSet {
    return Font.fontset.FontSet.load(gpa, testing.io) catch error.SkipZigTest;
}

fn feature1(scr: Screen) !void {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts, scr);
    defer ph.deinit(gpa);
    // The rig's rows were first on screen at 1000.
    try ph.frameNow();
    try testing.expect(ph.o.screen == .view);
    const row1 = foryou.ids.row0 + 1;
    const row2 = foryou.ids.row0 + 2;
    // Within the guard: a swipe answers nothing.
    ph.fy.clk.t = 1000 + cv.swipe_guard_ms - 200;
    try ph.swipe(row1, -0.7);
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
    try ph.swipe(row1, -0.7);
    try testing.expectEqualStrings("i:yes 02020202020202020202020202020202", ph.fy.sent.last());
    ph.fy.clk.t += 1000;
    try ph.frameNow();
    // Right is No.
    try ph.swipe(row2, 0.7);
    try testing.expectEqualStrings("i:no 03030303030303030303030303030303", ph.fy.sent.last());
    try testing.expectEqual(@as(usize, 2), ph.fy.sent.n);
    // No swipe reached the terminal as an answer key.
    try testing.expectEqual(@as(usize, 0), ph.host.answers);
}

test "phone For you: a swipe left answers Yes, right No, a tap toggles the full card, the 600 ms guard holds" {
    try onEvery(feature1);
}

fn feature2(scr: Screen) !void {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts, scr);
    defer ph.deinit(gpa);
    try ph.frameNow();
    try testing.expect(ph.fy.p.recapOffered());
    // Landscape: the panel's top is scrolled out of the short view (a cut
    // button is no target); a drag down brings it in.
    try ph.reveal(foryou.ids.recap);
    try ph.tap(foryou.ids.recap);
    try testing.expectEqualStrings("r:recap 0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", ph.fy.sent.last());
}

test "phone For you: the Recap button" {
    try onEvery(feature2);
}

fn feature3(scr: Screen) !void {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts, scr);
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

test "phone hidden tabs: a long press opens a tab's menu, Hide; the hidden button's sheet, Show" {
    try onEvery(feature3);
}

fn feature4(scr: Screen) !void {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts, scr);
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

test "phone Projects sheet: open it from the top bar, Start, Stop" {
    try onEvery(feature4);
}

fn feature5(scr: Screen) !void {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts, scr);
    defer ph.deinit(gpa);
    ph.st.usage = .{ .week = .{ .pct = 40 }, .five_hour = .{ .pct = 10 } };
    try ph.frameNow();
    try testing.expectEqual(@as(usize, 0), ph.o.usage.?.rows.len);
    try ph.tap(ids.usage_strip);
    try testing.expectEqual(@as(usize, 2), ph.o.usage.?.rows.len);
    try ph.tap(ids.usage_strip);
    try testing.expectEqual(@as(usize, 0), ph.o.usage.?.rows.len);
}

test "phone usage bar: a tap shows its detail, another hides it" {
    try onEvery(feature5);
}

fn feature6(scr: Screen) !void {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts, scr);
    defer ph.deinit(gpa);
    var a: shared.activity.Activity = .{ .len = 1 };
    a.tabs[0] = .{ .id = Phone.tab };
    ph.st.activity = &a;
    // Names too long for the bar at portrait width: the buttons go behind
    // "•••" (frame.topButtonLevel).
    for (&ph.tabs, [_][]const u8{ "Alpha-the-first-project", "Beta-the-second-one", "Gamma-the-third-one" }) |*t, n| t.setName(n);
    try ph.frameNow();
    try testing.expectEqual(@as(?u32, more_menu.ids.button), ph.o.top_bar.?.more_id);
    if (scr.fb[0] > scr.fb[1]) {
        // Landscape's 932 pt hold them and every button: nothing collapses.
        try testing.expect(frame.hitCentre(&ph.f, more_menu.ids.button) == null);
        for (ph.o.top_bar.?.buttons) |b| try testing.expect(frame.hitCentre(&ph.f, b.id) != null);
        for (0..ph.tabs.len) |i| try testing.expect(frame.hitCentre(&ph.f, ids.tab0 + @as(u32, @intCast(i))) != null);
        // Longer still: "•••" in landscape too, the tabs all on the bar.
        for (&ph.tabs, [_][]const u8{ "Alpha-the-first-project-with-a-long-name", "Beta-the-second-one-with-a-long-name", "Gamma-the-third-one-with-a-long-name" }) |*t, n| t.setName(n);
        try ph.frameNow();
        for (0..ph.tabs.len) |i| try testing.expect(frame.hitCentre(&ph.f, ids.tab0 + @as(u32, @intCast(i))) != null);
    }
    try ph.tap(more_menu.ids.button);
    try testing.expect(hasPanel(ph.o, "More"));
    const first = ph.o.panel.?.rows[0].text;
    try testing.expectEqualStrings("Usage", first);
    try ph.tap(more_menu.ids.item0);
    try testing.expect(hasPanel(ph.o, "Usage"));
    try testing.expect(!ph.sh.more.open);
}

test "phone ••• menu: opening it and choosing an item" {
    try onEvery(feature6);
}

fn feature7(scr: Screen) !void {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts, scr);
    defer ph.deinit(gpa);
    ph.sh.dictation = null; // typing only here (the next test dictates)
    try ph.frameNow();
    try testing.expect(ph.f.text_slot == null);
    try ph.tap(ids.instruct);
    try testing.expect(ph.sh.instructing);
    // The line is focused: its slot is where the native field goes.
    try testing.expect(ph.f.text_slot != null);
    // The system keyboard comes up over the bottom.
    ph.f.insets = scr.withKeyboard();
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
    ph.f.insets = scr.safe;
    try ph.frameNow();
    try testing.expect(ph.f.text_slot == null);
}

test "phone input line: Instruct, tap the line, type, Send; with the keyboard up too" {
    try onEvery(feature7);
}

fn feature8(scr: Screen) !void {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts, scr);
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

test "phone dictation: Instruct records, the mic button stops and starts it, Close" {
    try onEvery(feature8);
}

// ------------------------------------------------------------ turning

/// The ways the phone turns between frames: portrait to landscape and
/// back, and between the mirrored landscapes (the same window size, the
/// origin moves).
const turns = [_][2]Screen{ .{ portrait, landscape }, .{ landscape, portrait }, .{ island_left, island_right } };

/// Runs `body` for every turn; a failure says which.
fn onEveryTurn(comptime body: fn (Screen, Screen) anyerror!void) !void {
    for (turns) |t| body(t[0], t[1]) catch |e| {
        if (e != error.SkipZigTest) std.debug.print("(turning {s} -> {s})\n", .{ t[0].name, t[1].name });
        return e;
    };
}

/// A For-you swipe interrupted by a turn: the finger went down and moved
/// on a row, the phone turned, then (`move_after`) the finger moved on in
/// the new layout's space before it lifted. Nothing is answered (the
/// press is cancelled and the row springs back); a fresh swipe in the new
/// layout answers the row it is on.
fn swipeAcrossTurn(from: Screen, to: Screen, move_after: bool) !void {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts, from);
    defer ph.deinit(gpa);
    try ph.frameNow();
    ph.fy.clk.t = 3000; // past the guard
    try ph.frameNow();
    const row1 = foryou.ids.row0 + 1;
    const c = try ph.centre(row1);
    const sink = ph.sh.sink();
    const w0 = ph.width();
    ph.f.pointerDown(w0 * 0.85, c[1], .left, .{}, sink);
    ph.fy.clk.t += 60;
    ph.f.pointerMove(w0 * 0.7, c[1], sink);
    try testing.expect(ph.fy.v.held());
    try testing.expect(ph.fy.v.swipe.row != null);
    try ph.frameNow();
    // The phone turns with the finger still down.
    try ph.turn(to, false);
    const w1 = ph.width();
    if (move_after) {
        // In the new space this would read as a long fling to the left.
        ph.fy.clk.t += 60;
        ph.f.pointerMove(w1 * 0.05, c[1], sink);
    }
    ph.f.pointerUp(w1 * 0.05, c[1], .left, sink);
    try testing.expect(!ph.fy.v.held());
    ph.fy.clk.t += 1000;
    try ph.frameNow();
    try testing.expectEqual(@as(usize, 0), ph.fy.sent.n);
    try testing.expectEqual(@as(usize, 0), ph.host.answers);
    // A swipe in the new layout answers the row under it.
    try ph.swipe(row1, -0.7);
    try testing.expectEqualStrings("i:yes 02020202020202020202020202020202", ph.fy.sent.last());
    try testing.expectEqual(@as(usize, 1), ph.fy.sent.n);
}

fn swipeTurnMoving(from: Screen, to: Screen) !void {
    try swipeAcrossTurn(from, to, true);
}
fn swipeTurnLifting(from: Screen, to: Screen) !void {
    try swipeAcrossTurn(from, to, false);
}

test "turning mid-swipe: the press is cancelled, nothing is answered; the next swipe answers the row it is on" {
    try onEveryTurn(swipeTurnMoving);
    try onEveryTurn(swipeTurnLifting);
}

/// A tap begun before a turn and released after it on the same button
/// where the new layout put it: no tap.
fn tapAcrossTurn(from: Screen, to: Screen) !void {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts, from);
    defer ph.deinit(gpa);
    try ph.frameNow();
    const c = try ph.centre(ids.instruct);
    const sink = ph.sh.sink();
    ph.f.pointerDown(c[0], c[1], .left, .{}, sink);
    try ph.turn(to, false);
    const c1 = try ph.centre(ids.instruct);
    ph.f.pointerUp(c1[0], c1[1], .left, sink);
    try ph.frameNow();
    try testing.expect(!ph.sh.instructing);
    // A tap in the new layout works.
    try ph.tap(ids.instruct);
    try testing.expect(ph.sh.instructing);
}

test "turning mid-tap: the press is cancelled, no button fires" {
    try onEveryTurn(tapAcrossTurn);
}

/// The input line focused with text, the keyboard up, through a turn:
/// the text and the focus stay, the native field's slot (the same field
/// id, so the Presenter moves the field without raising the keyboard
/// again: raisesKeyboard) follows the new layout; Send sends it.
fn lineAcrossTurn(from: Screen, to: Screen) !void {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts, from);
    defer ph.deinit(gpa);
    ph.sh.dictation = null;
    try ph.frameNow();
    try ph.tap(ids.instruct);
    ph.f.insets = from.withKeyboard();
    try ph.frameNow();
    try ph.tap(ids.line);
    const sink = ph.sh.sink();
    for ("check the build") |ch| sink.char(ch, .{});
    try ph.frameNow();
    const before = ph.f.text_slot.?;
    try ph.turn(to, true);
    const after = ph.f.text_slot orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("check the build", after.value());
    try testing.expectEqual(before.id, after.id);
    try testing.expectEqual(shell.Focus.line, ph.sh.focus());
    try testing.expect(!std.meta.eql(before.rect, after.rect));
    // The keyboard goes down in the new layout: the field stays.
    ph.f.insets = to.safe;
    try ph.frameNow();
    try testing.expectEqualStrings("check the build", ph.f.text_slot.?.value());
    // And back.
    try ph.turn(from, true);
    try testing.expectEqualStrings("check the build", ph.f.text_slot.?.value());
    try testing.expectEqual(shell.Focus.line, ph.sh.focus());
    try ph.tap(ids.send);
    try testing.expectEqualStrings("l:check the build", ph.host.lastSent());
}

test "turning with the input line focused: the text and focus stay, the field moves to the new layout" {
    try onEveryTurn(lineAcrossTurn);
}

/// The Projects sheet open, its selected row near the end, through turns:
/// it stays open and re-lays out, its scroll stays within what it has, the
/// selected row is in view after each turn (also after a drag scrolled
/// away from it), its buttons work.
fn sheetAcrossTurn(from: Screen, to: Screen) !void {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts, from);
    defer ph.deinit(gpa);
    // More projects than a landscape screen holds.
    var pl: shared.projects.List = .{};
    var names: [12][16]u8 = undefined;
    for (0..12) |i| {
        pl.items[i] = .{ .color = 0x4DA3FF, .mode = .ask };
        pl.items[i].setName(std.fmt.bufPrint(&names[i], "Project{d}", .{i}) catch unreachable);
    }
    pl.len = 12;
    ph.st.projects = &pl;
    try ph.frameNow();
    ph.sh.proj_sheet.toggle();
    ph.sh.proj_sheet.sel = 10;
    try ph.frameNow();
    const title = "Projects you allowed at the desk";
    try testing.expect(hasPanel(ph.o, title));
    const sel_open = projects_sheet.ids.open0 + 10;
    try testing.expect(frame.hitCentre(&ph.f, sel_open) != null);
    var scrolled = false;
    for ([_]Screen{ to, from, to }) |scr| {
        const area0 = clearArea(ph.scr);
        const scroll0 = ph.f.panel_scroll;
        try ph.turn(scr, false);
        try testing.expect(hasPanel(ph.o, title));
        try testing.expect(ph.f.panel_scroll >= 0 and ph.f.panel_scroll <= ph.f.panel_max);
        if (std.meta.eql(area0, clearArea(scr))) {
            // The same room (the mirrored landscapes): only moved, the
            // scroll the finger chose stays.
            try testing.expectEqual(scroll0, ph.f.panel_scroll);
        } else {
            // Re-laid out: the selected row is in view again.
            try testing.expect(frame.hitCentre(&ph.f, sel_open) != null);
        }
        // Scrolled away from it by a drag (where the panel scrolls): the
        // next turn that re-lays it out brings it back.
        if (ph.f.panel_max > 0) {
            const b = ph.f.panel_box.?;
            const sink = ph.sh.sink();
            const x = b.x + b.w / 2;
            const s0 = ph.f.panel_scroll;
            ph.f.pointerDown(x, b.y + b.h * 0.2, .left, .{}, sink);
            ph.f.pointerMove(x, b.y + b.h * 0.4, sink);
            ph.f.pointerMove(x, b.y + b.h * 0.9, sink);
            ph.f.pointerUp(x, b.y + b.h * 0.9, .left, sink);
            try ph.frameNow();
            try testing.expect(if (s0 > 0) ph.f.panel_scroll < s0 else ph.f.panel_scroll == 0);
            scrolled = true;
        }
    }
    // Landscape is too short for twelve rows: it scrolled.
    try testing.expect(scrolled or std.meta.eql(from.fb, to.fb));
    try ph.turn(from, false);
    try ph.revealInPanel(sel_open);
    try ph.tap(sel_open);
    try testing.expectEqualStrings("p:start Project10", ph.host.lastSent());
    try ph.tap(projects_sheet.ids.close);
    try testing.expect(ph.o.panel == null);
}

test "turning with a sheet open: it re-lays out, keeps its scroll in range and its selected row in view" {
    try onEveryTurn(sheetAcrossTurn);
}

/// The usage strip expanded and a tab hidden, through a turn: both stay
/// as they were, and their buttons work in the new layout.
fn stripAcrossTurn(from: Screen, to: Screen) !void {
    const gpa = testing.allocator;
    var fonts = try loadFonts(gpa);
    defer fonts.deinit();
    var ph: Phone = undefined;
    try ph.init(gpa, &fonts, from);
    defer ph.deinit(gpa);
    ph.st.usage = .{ .week = .{ .pct = 80 }, .five_hour = .{ .pct = 95 } };
    try ph.frameNow();
    try ph.tap(ids.usage_strip);
    try testing.expectEqual(@as(usize, 2), ph.o.usage.?.rows.len);
    try ph.tapHeld(ids.tab0 + 2, frame.long_press_ms);
    try ph.tap(hidden_tabs.ids.hide);
    try testing.expect(ph.sh.hidden.contains("Gamma"));
    try ph.turn(to, false);
    try testing.expectEqual(@as(usize, 2), ph.o.usage.?.rows.len);
    try testing.expect(ph.sh.hidden.contains("Gamma"));
    try testing.expect(frame.hitCentre(&ph.f, ids.tab0 + 2) == null);
    try testing.expect(frame.hitCentre(&ph.f, ids.tab0) != null);
    // The strip sits above the top bar in the new layout too.
    try testing.expect(ph.f.regions.usage.y + ph.f.regions.usage.h <= ph.f.regions.top.y + 0.5);
    try ph.tap(ids.usage_strip);
    try testing.expectEqual(@as(usize, 0), ph.o.usage.?.rows.len);
    try ph.tap(hidden_tabs.ids.button);
    try ph.tap(hidden_tabs.ids.show0 + 2);
    try testing.expect(!ph.sh.hidden.contains("Gamma"));
    try ph.turn(from, false);
    try testing.expect(frame.hitCentre(&ph.f, ids.tab0 + 2) != null);
}

test "turning with the usage strip expanded and a tab hidden: both stay, their buttons work" {
    try onEveryTurn(stripAcrossTurn);
}
