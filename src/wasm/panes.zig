//! Page layout, editor style: three panes stacked in the visible viewport.
//!
//!   ┌──────────────────────┐  header (status, mode, Fit A− A+, Unpair)
//!   │ terminal (canvas)    │  everything left over; layout.zig fits the
//!   │                      │  grid inside it
//!   ├──────────────────────┤
//!   │ input box <textarea> │  native, so the phone keyboard's dictation
//!   │ note line            │  mic and Win+H dictation fill it
//!   ├──────────────────────┤
//!   │ Yes No 1 2 3 Esc ... │  button row (one or two rows)
//!   └──────────────────────┘  safe-area pad (home indicator)
//!
//! The page follows the *visual* viewport: when the on-screen keyboard
//! opens, iOS shrinks it (and may scroll it), so the panes are sized to it
//! and the input and buttons stay right above the keyboard. Pure math in
//! CSS pixels; main.zig turns the result into CSS variables and classes.

const std = @import("std");
const layout = @import("layout.zig");
const sane = layout.sane;

pub const Input = struct {
    /// window.innerWidth / innerHeight (the layout viewport).
    inner_w: f64,
    inner_h: f64,
    /// visualViewport width, height and offsetTop.
    vv_w: f64,
    vv_h: f64,
    vv_top: f64,
    /// env(safe-area-inset-top / bottom).
    safe_top: f64 = 0,
    safe_bottom: f64 = 0,
    /// Coarse pointer (phone, tablet).
    touch: bool,
    /// The server accepts some input (box and buttons shown).
    input: bool = true,
};

pub const Panes = struct {
    /// Height and top of the page box (follows the visual viewport).
    app_h: i32 = 0,
    app_top: i32 = 0,
    /// Header bar height without the safe-area pad, and that pad.
    head_h: i32 = 0,
    head_pad: i32 = 0,
    /// Terminal pane (the canvas's container).
    term_h: i32 = 0,
    /// The textarea's height, the note line under it, and the whole pane
    /// (box + note + padding).
    box_h: i32 = 0,
    note_h: i32 = 0,
    input_h: i32 = 0,
    /// Button row: grid of `cols` x `rows` buttons of `btn_h`.
    bar_h: i32 = 0,
    btn_h: i32 = 0,
    cols: u32 = 0,
    rows: u32 = 0,
    buttons: u32 = 0,
    /// Space kept free under the buttons (home indicator); 0 while the
    /// keyboard covers it.
    pad_bottom: i32 = 0,
    keyboard: bool = false,
    /// Header hidden to make room (short screen with the keyboard open).
    no_head: bool = false,

    pub fn eql(a: Panes, b: Panes) bool {
        return std.meta.eql(a, b);
    }
};

/// The visual viewport is this much shorter than the layout viewport:
/// the on-screen keyboard is open (the URL bar alone is well under it).
pub const keyboard_threshold: f64 = 120;
pub const gap: i32 = 6;
/// Yes No 1 2 3 Esc Enter Send (inputbox.Button).
pub const button_count: u32 = 8;
pub const pane_pad: i32 = 6;
/// Smallest terminal pane worth keeping before shrinking the others.
pub const min_term: i32 = 120;
/// Text line inside the textarea (16 px font: smaller makes iOS zoom in on
/// focus) and the note line.
pub const box_line: i32 = 22;
pub const box_chrome: i32 = 14; // padding + border
pub const note_line: i32 = 18;

fn px(v: f64) i32 {
    return @intFromFloat(@round(v));
}

pub fn compute(in: Input) Panes {
    var p: Panes = .{};
    const inner_w = sane(in.inner_w, 1, layout.max_side);
    const inner_h = sane(in.inner_h, 1, layout.max_side);
    const vv_w = sane(in.vv_w, 1, layout.max_side);
    var vv_h = sane(in.vv_h, 1, layout.max_side);
    var vv_top = sane(in.vv_top, 0, layout.max_side);
    // Pinch-zoomed (visual viewport narrower than the page): the visual
    // viewport is a magnified window onto the page, not the space left by
    // the keyboard, so lay out the whole page and let the user pan.
    const zoomed = vv_w < inner_w - 2;
    if (zoomed or vv_h > inner_h) {
        vv_h = inner_h;
        vv_top = 0;
    }
    p.keyboard = in.touch and !zoomed and inner_h - vv_h > keyboard_threshold;
    p.app_h = px(vv_h);
    p.app_top = px(vv_top);
    const safe_top = px(sane(in.safe_top, 0, 200));
    const safe_bottom = px(sane(in.safe_bottom, 0, 200));
    p.pad_bottom = if (p.keyboard) 0 else safe_bottom;
    p.head_h = if (in.touch) 44 else 36;
    p.head_pad = safe_top;

    if (in.input) {
        // Buttons: one row if each still gets a comfortable target.
        p.buttons = button_count;
        p.btn_h = if (in.touch) 44 else 32;
        const min_w: f64 = if (in.touch) 40 else 56;
        const n: f64 = @floatFromInt(p.buttons);
        const avail = vv_w - 2 * @as(f64, pane_pad) - (n - 1) * @as(f64, gap);
        if (avail / n >= min_w) {
            p.cols = p.buttons;
            p.rows = 1;
        } else {
            p.cols = (p.buttons + 1) / 2;
            p.rows = 2;
        }
        // Textarea: 3 lines on a phone with room, 2 otherwise.
        var lines: i32 = if (in.touch and !p.keyboard) 3 else 2;
        p.note_h = note_line;
        while (true) {
            p.box_h = lines * box_line + box_chrome;
            p.input_h = pane_pad + p.box_h + p.note_h + 2;
            p.bar_h = @as(i32, @intCast(p.rows)) * p.btn_h + (@as(i32, @intCast(p.rows)) - 1) * gap + 2 * pane_pad;
            const head = if (p.no_head) 0 else p.head_h + p.head_pad;
            p.term_h = p.app_h - head - p.input_h - p.bar_h - p.pad_bottom;
            if (p.term_h >= min_term) break;
            // Too tight (keyboard open, landscape, tiny window): shed the
            // header while typing, then textarea lines, then the note.
            if (p.keyboard and !p.no_head) {
                p.no_head = true;
            } else if (lines > 1) {
                lines -= 1;
            } else if (p.note_h > 0) {
                p.note_h = 0;
            } else break;
        }
    } else {
        const head = p.head_h + p.head_pad;
        p.term_h = p.app_h - head - p.pad_bottom;
    }
    p.term_h = @max(0, p.term_h);
    return p;
}

/// CSS custom properties for the page (index.html / app.css read them).
pub fn css(p: Panes, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "--app-h:{d}px;--app-top:{d}px;--head-h:{d}px;--head-pad:{d}px;" ++
        "--box-h:{d}px;--note-h:{d}px;--input-h:{d}px;--bar-h:{d}px;--btn-h:{d}px;--cols:{d};--pad-b:{d}px", .{
        p.app_h,  p.app_top, p.head_h, p.head_pad, p.box_h, p.note_h,
        p.input_h, p.bar_h,  p.btn_h,  p.cols,     p.pad_bottom,
    }) catch "";
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

const Phone = struct { name: []const u8, w: f64, h: f64, safe_top: f64, safe_bottom: f64, kb: f64 };

/// Safari's layout viewport (URL bar shown) and a typical keyboard height
/// (with the QuickType bar) for several iPhones, portrait.
const phones = [_]Phone{
    .{ .name = "SE (3rd gen)", .w = 375, .h = 548, .safe_top = 0, .safe_bottom = 0, .kb = 260 },
    .{ .name = "13 mini", .w = 375, .h = 629, .safe_top = 50, .safe_bottom = 34, .kb = 336 },
    .{ .name = "15", .w = 393, .h = 659, .safe_top = 59, .safe_bottom = 34, .kb = 336 },
    .{ .name = "14 / 13", .w = 390, .h = 664, .safe_top = 47, .safe_bottom = 34, .kb = 336 },
    .{ .name = "15 Pro Max", .w = 430, .h = 739, .safe_top = 59, .safe_bottom = 34, .kb = 346 },
    .{ .name = "14 home screen app", .w = 390, .h = 844, .safe_top = 47, .safe_bottom = 34, .kb = 336 },
};

fn phone(ph: Phone, keyboard: bool) Input {
    const vv_h = if (keyboard) ph.h - ph.kb else ph.h;
    return .{
        .inner_w = ph.w,
        .inner_h = ph.h,
        .vv_w = ph.w,
        .vv_h = vv_h,
        .vv_top = if (keyboard) 120 else 0, // Safari scrolls to the caret
        .safe_top = ph.safe_top,
        .safe_bottom = ph.safe_bottom,
        .touch = true,
    };
}

fn expectFits(p: Panes) !void {
    const head = if (p.no_head) 0 else p.head_h + p.head_pad;
    try testing.expectEqual(p.app_h, head + p.term_h + p.input_h + p.bar_h + p.pad_bottom);
    try testing.expect(p.term_h >= 0 and p.box_h >= box_line + box_chrome);
    try testing.expectEqual(p.buttons, p.cols * p.rows);
}

test "iPhones, portrait, keyboard closed: three panes, room for the terminal" {
    for (phones) |ph| {
        const p = compute(phone(ph, false));
        try expectFits(p);
        try testing.expect(!p.keyboard);
        try testing.expect(!p.no_head);
        try testing.expectEqual(@as(i32, @intFromFloat(ph.h)), p.app_h);
        try testing.expectEqual(@as(i32, 0), p.app_top);
        try testing.expectEqual(@as(i32, @intFromFloat(ph.safe_bottom)), p.pad_bottom);
        // One row of 8 buttons of at least 40 px; 3-line box.
        try testing.expectEqual(@as(u32, 1), p.rows);
        try testing.expectEqual(@as(u32, 8), p.cols);
        try testing.expectEqual(@as(i32, 44), p.btn_h);
        try testing.expectEqual(3 * box_line + box_chrome, p.box_h);
        // The terminal keeps most of the screen.
        try testing.expect(p.term_h * 2 >= p.app_h);
    }
}

test "iPhones, keyboard open: panes sit on the keyboard, terminal still visible" {
    for (phones) |ph| {
        const p = compute(phone(ph, true));
        try expectFits(p);
        try testing.expect(p.keyboard);
        try testing.expectEqual(@as(i32, @intFromFloat(ph.h - ph.kb)), p.app_h);
        try testing.expectEqual(@as(i32, 120), p.app_top);
        // The keyboard covers the home indicator: no pad under the buttons.
        try testing.expectEqual(@as(i32, 0), p.pad_bottom);
        // Box and buttons end exactly at the keyboard's top edge.
        const head = if (p.no_head) 0 else p.head_h + p.head_pad;
        try testing.expectEqual(p.app_h, head + p.term_h + p.input_h + p.bar_h);
        try testing.expect(p.box_h <= 2 * box_line + box_chrome);
        try testing.expect(p.term_h >= 0);
        try testing.expectEqual(@as(i32, 44), p.btn_h);
    }
    // The 14: 664 - 336 = 328 px left. Header goes, terminal keeps >= 120.
    const p = compute(phone(phones[3], true));
    try testing.expectEqual(@as(i32, 328), p.app_h);
    try testing.expect(p.no_head);
    try testing.expect(p.term_h >= min_term);
}

test "landscape with the keyboard: everything shrinks, nothing negative" {
    const p = compute(.{ .inner_w = 844, .inner_h = 340, .vv_w = 844, .vv_h = 150, .vv_top = 40, .safe_top = 0, .safe_bottom = 21, .touch = true });
    try expectFits(p);
    try testing.expect(p.keyboard and p.no_head);
    try testing.expectEqual(box_line + box_chrome, p.box_h); // one line
    try testing.expectEqual(@as(i32, 0), p.note_h);
    try testing.expectEqual(@as(u32, 1), p.rows);
    try testing.expect(p.term_h > 0);
    // Landscape without it.
    const q = compute(.{ .inner_w = 844, .inner_h = 340, .vv_w = 844, .vv_h = 340, .vv_top = 0, .safe_bottom = 21, .touch = true });
    try expectFits(q);
    try testing.expect(!q.keyboard);
}

test "narrow screens wrap the buttons into two rows" {
    const p = compute(.{ .inner_w = 320, .inner_h = 568, .vv_w = 320, .vv_h = 568, .vv_top = 0, .touch = true });
    try expectFits(p);
    try testing.expectEqual(@as(u32, 8), p.buttons);
    try testing.expectEqual(@as(u32, 2), p.rows);
    try testing.expectEqual(@as(u32, 4), p.cols);
    try testing.expectEqual(2 * 44 + gap + 2 * pane_pad, p.bar_h);
    try testing.expect(p.term_h >= min_term);
}

test "laptop browser: same panes, compact, no keyboard logic" {
    const p = compute(.{ .inner_w = 1440, .inner_h = 820, .vv_w = 1440, .vv_h = 820, .vv_top = 0, .touch = false });
    try expectFits(p);
    try testing.expect(!p.keyboard);
    try testing.expectEqual(@as(i32, 36), p.head_h);
    try testing.expectEqual(@as(i32, 32), p.btn_h);
    try testing.expectEqual(2 * box_line + box_chrome, p.box_h);
    try testing.expectEqual(@as(u32, 1), p.rows);
    // A short desktop window (devtools open) is not "keyboard open".
    const q = compute(.{ .inner_w = 1440, .inner_h = 820, .vv_w = 1440, .vv_h = 400, .vv_top = 0, .touch = false });
    try testing.expect(!q.keyboard and !q.no_head);
}

test "view only: no box, no buttons" {
    const p = compute(.{ .inner_w = 390, .inner_h = 664, .vv_w = 390, .vv_h = 664, .vv_top = 0, .safe_top = 47, .safe_bottom = 34, .touch = true, .input = false });
    try testing.expectEqual(@as(i32, 0), p.input_h);
    try testing.expectEqual(@as(i32, 0), p.bar_h);
    try testing.expectEqual(@as(i32, 664 - 44 - 47 - 34), p.term_h);
}

test "pinch zoom is not a keyboard" {
    const p = compute(.{ .inner_w = 390, .inner_h = 664, .vv_w = 195, .vv_h = 332, .vv_top = 100, .touch = true });
    try testing.expect(!p.keyboard);
    try testing.expectEqual(@as(i32, 664), p.app_h);
    try testing.expectEqual(@as(i32, 0), p.app_top);
}

test "hostile viewport values" {
    const bad = [_]f64{ std.math.nan(f64), std.math.inf(f64), -std.math.inf(f64), -5, 0, 1e300 };
    for (bad) |x| for ([_]bool{ false, true }) |t| {
        const p = compute(.{ .inner_w = x, .inner_h = x, .vv_w = x, .vv_h = x, .vv_top = x, .safe_top = x, .safe_bottom = x, .touch = t });
        try testing.expect(p.term_h >= 0 and p.app_h >= 1 and p.app_h <= layout.max_side);
        var buf: [512]u8 = undefined;
        try testing.expect(css(p, &buf).len > 0);
    };
}

test "css variables" {
    const p = compute(phone(phones[3], false));
    var buf: [512]u8 = undefined;
    const s = css(p, &buf);
    try testing.expect(std.mem.startsWith(u8, s, "--app-h:664px;--app-top:0px;"));
    try testing.expect(std.mem.indexOf(u8, s, "--cols:8;") != null);
    try testing.expect(std.mem.endsWith(u8, s, "--pad-b:34px"));
}
