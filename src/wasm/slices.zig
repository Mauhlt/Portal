//! Page layout as slices: the same three on every device as on the native
//! windows (docs/layout-design.md), stacked top to bottom:
//!
//!   ┌──────────────────────────────┐
//!   │ header: controls, status     │  (shed while typing on a short screen)
//!   ├──────────────────────────────┤
//!   │ terminal (canvas)            │  the biggest share
//!   ├──────────────────────────────┤
//!   │ Data · nothing yet    [Hide] │  data: a header strip; its canvas
//!   │ (images, newest first, →)    │  grows when there is something to
//!   ├──────────────────────────────┤  show, up to datafeed.max_share
//!   │ input box                    │  interaction: the input box (a native
//!   │ note                         │  textarea, so keyboard dictation and
//!   │ [Yes][No][1][2][3][Esc]...   │  Win+H fill it), its note line and
//!   └──────────────────────────────┘  big buttons, pinned at the bottom
//!
//! The page follows the *visual* viewport: when the on-screen keyboard
//! opens, iOS shrinks it (and may scroll it), so the slices are sized to it
//! and the interaction slice stays right above the keyboard. Pure math in
//! CSS pixels; main.zig turns the result into CSS variables and classes.

const std = @import("std");
const datafeed = @import("datafeed");
const layout = @import("layout.zig");
const sane = layout.sane;
pub const Rect = layout.Rect;

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
    /// The server accepts some input (interaction slice shown).
    input: bool = true,
    /// The Up/Down buttons are shown too (instruct mode while the shown
    /// tab waits for an answer: rules.showMenuButtons).
    menu: bool = false,
    /// What the Data slice's items would like under its header (CSS px;
    /// 0: nothing to show), and the user's collapse toggle.
    data_content: f64 = 0,
    data_collapsed: bool = false,
};

pub const Slices = struct {
    /// Height and top of the page box (follows the visual viewport).
    app_h: i32 = 0,
    app_top: i32 = 0,
    /// Header (controls row + status line) over the terminal slice.
    head: Rect = .{},
    term: Rect = .{},
    /// The Data slice: its header strip (`dhead_h`) and, below it, the
    /// data canvas.
    data: Rect = .{},
    inter: Rect = .{},
    head_pad: i32 = 0,
    ctl_h: i32 = 0,
    status_h: i32 = 0,
    dhead_h: i32 = 0,
    /// Interaction slice internals: textarea, note line, button grid.
    box_h: i32 = 0,
    note_h: i32 = 0,
    btn_h: i32 = 0,
    /// Buttons in the grid (`button_count`, or `menu_button_count`).
    buttons: u32 = 0,
    cols: u32 = 0,
    rows: u32 = 0,
    /// Space kept free under the buttons (home indicator); 0 while the
    /// keyboard covers it.
    pad_bottom: i32 = 0,
    keyboard: bool = false,
    /// Header hidden to make room (short screen with the keyboard open).
    no_head: bool = false,
    /// Data slice hidden to make room (the same).
    no_data: bool = false,

    pub fn eql(a: Slices, b: Slices) bool {
        return std.meta.eql(a, b);
    }

    /// The data canvas (under the Data header) has room to draw in.
    pub fn dataOpen(s: Slices) bool {
        return s.data.h > s.dhead_h;
    }
};

/// The visual viewport is this much shorter than the layout viewport:
/// the on-screen keyboard is open (the URL bar alone is well under it).
pub const keyboard_threshold: f64 = 120;
pub const gap: i32 = 6;
pub const pane_pad: i32 = 6;
/// Yes No 1 2 3 Esc Enter Send (inputbox.Button).
pub const button_count: u32 = 8;
/// ... then Up and Down, while they are shown (Input.menu).
pub const menu_button_count: u32 = 10;
/// Answer buttons: thumb-sized on touch screens, comfortable with a mouse.
pub const btn_touch: i32 = 52;
pub const btn_mouse: i32 = 44;
/// Narrowest button that still takes a single row (else two rows of four).
pub const min_btn_touch: f64 = 44;
pub const min_btn_mouse: f64 = 64;
/// Smallest terminal slice worth keeping before shrinking the others.
pub const min_term: i32 = 120;
/// Text line inside the textarea (16 px font: smaller makes iOS zoom in on
/// focus) and the note line.
pub const box_line: i32 = 22;
pub const box_chrome: i32 = 14; // padding + border
pub const note_line: i32 = 18;
pub const status_line: i32 = 20;
/// The Data slice's header strip.
pub const dhead_touch: i32 = 36;
pub const dhead_mouse: i32 = 30;

fn px(v: f64) i32 {
    return @intFromFloat(@round(v));
}

pub fn compute(in: Input) Slices {
    var s: Slices = .{};
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
    s.keyboard = in.touch and !zoomed and inner_h - vv_h > keyboard_threshold;
    s.app_h = px(vv_h);
    s.app_top = px(vv_top);
    const W = px(inner_w);
    const H = s.app_h;
    s.pad_bottom = if (s.keyboard) 0 else px(sane(in.safe_bottom, 0, 200));
    s.head_pad = px(sane(in.safe_top, 0, 200));
    s.ctl_h = if (in.touch) 44 else 36;
    s.status_h = status_line;
    s.dhead_h = if (in.touch) dhead_touch else dhead_mouse;

    // Interaction slice at the bottom; the Data slice above it; the
    // terminal gets what is left under the header.
    var inter_h: i32 = 0;
    var lines: i32 = 2;
    if (in.input) {
        s.btn_h = if (in.touch) btn_touch else btn_mouse;
        const min_w = if (in.touch) min_btn_touch else min_btn_mouse;
        s.buttons = if (in.menu) menu_button_count else button_count;
        const n: f64 = @floatFromInt(s.buttons);
        const avail = @as(f64, @floatFromInt(W)) - 2 * @as(f64, pane_pad) - (n - 1) * @as(f64, gap);
        if (avail / n >= min_w) {
            s.cols = s.buttons;
            s.rows = 1;
        } else {
            s.cols = (s.buttons + 1) / 2;
            s.rows = 2;
        }
        s.note_h = note_line;
    }
    var head_h: i32 = 0;
    var data_h: i32 = 0;
    var term_h: i32 = 0;
    while (true) {
        if (in.input) {
            s.box_h = lines * box_line + box_chrome;
            const rows: i32 = @intCast(s.rows);
            const bar_h = rows * s.btn_h + (rows - 1) * gap + 2 * pane_pad;
            inter_h = pane_pad + s.box_h + s.note_h + 2 + bar_h + s.pad_bottom;
        } else inter_h = s.pad_bottom;
        head_h = if (s.no_head) 0 else s.head_pad + s.ctl_h + s.status_h;
        const rest = H - head_h - inter_h;
        data_h = if (s.no_data) 0 else px(datafeed.sliceHeight(@floatFromInt(@max(0, rest)), @floatFromInt(s.dhead_h), sane(in.data_content, 0, layout.max_side), in.data_collapsed));
        term_h = rest - data_h;
        if (term_h >= min_term) break;
        // Too tight (keyboard open, landscape, tiny window): while typing,
        // shed the header and the Data slice first; then textarea lines,
        // then the note; the Data slice last otherwise.
        if (s.keyboard and !s.no_head) {
            s.no_head = true;
        } else if (s.keyboard and !s.no_data) {
            s.no_data = true;
        } else if (in.input and lines > 1) {
            lines -= 1;
        } else if (in.input and s.note_h > 0) {
            s.note_h = 0;
        } else if (!s.no_data) {
            s.no_data = true;
        } else break;
    }
    term_h = @max(0, term_h);
    s.head = .{ .x = 0, .y = 0, .w = W, .h = head_h };
    s.term = .{ .x = 0, .y = head_h, .w = W, .h = term_h };
    s.data = .{ .x = 0, .y = head_h + term_h, .w = W, .h = data_h };
    s.inter = .{ .x = 0, .y = head_h + term_h + data_h, .w = W, .h = @max(0, H - head_h - term_h - data_h) };
    return s;
}

/// CSS custom properties for the page (index.html / app.css read them).
pub fn css(s: Slices, buf: []u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.print("--app-h:{d}px;--app-top:{d}px;--head-pad:{d}px;--ctl-h:{d}px;--status-h:{d}px;--dhead-h:{d}px;" ++
        "--box-h:{d}px;--note-h:{d}px;--btn-h:{d}px;--cols:{d};--pad-b:{d}px", .{
        s.app_h, s.app_top, s.head_pad, s.ctl_h, s.status_h, s.dhead_h, s.box_h, s.note_h, s.btn_h, s.cols, s.pad_bottom,
    }) catch return "";
    const named = [_]struct { []const u8, Rect }{
        .{ "head", s.head }, .{ "term", s.term }, .{ "data", s.data }, .{ "inter", s.inter },
    };
    for (named) |n| w.print(";--{s}-x:{d}px;--{s}-y:{d}px;--{s}-w:{d}px;--{s}-h:{d}px", .{
        n[0], n[1].x, n[0], n[1].y, n[0], n[1].w, n[0], n[1].h,
    }) catch return "";
    return w.buffered();
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

/// Slices tile the page top to bottom: head, term, data, inter.
fn expectTiles(s: Slices) !void {
    try testing.expectEqual(@as(i32, 0), s.head.y);
    try testing.expectEqual(s.head.bottom(), s.term.y);
    try testing.expectEqual(s.term.bottom(), s.data.y);
    try testing.expectEqual(s.data.bottom(), s.inter.y);
    try testing.expectEqual(s.app_h, s.inter.bottom());
    try testing.expect(s.term.h >= 0 and s.data.h >= 0 and s.inter.h >= 0);
    try testing.expectEqual(s.head.w, s.term.w);
    try testing.expectEqual(s.term.w, s.data.w);
    try testing.expectEqual(s.term.w, s.inter.w);
    if (s.cols > 0) try testing.expectEqual(s.buttons, s.cols * s.rows);
}

test "the Up/Down buttons join the grid while shown" {
    const s = compute(.{ .inner_w = 390, .inner_h = 664, .vv_w = 390, .vv_h = 664, .vv_top = 0, .touch = true, .menu = true });
    try expectTiles(s);
    try testing.expectEqual(menu_button_count, s.buttons);
    try testing.expectEqual(@as(u32, 5), s.cols);
    const wide = compute(.{ .inner_w = 1400, .inner_h = 800, .vv_w = 1400, .vv_h = 800, .vv_top = 0, .touch = false, .menu = true });
    try expectTiles(wide);
    try testing.expectEqual(menu_button_count, wide.cols);
    const off = compute(.{ .inner_w = 1400, .inner_h = 800, .vv_w = 1400, .vv_h = 800, .vv_top = 0, .touch = false });
    try testing.expectEqual(button_count, off.cols);
}

test "iPhones, portrait, keyboard closed: terminal, data strip, interaction pinned at the bottom" {
    for (phones) |ph| {
        const s = compute(phone(ph, false));
        try expectTiles(s);
        try testing.expect(!s.keyboard and !s.no_head and !s.no_data);
        try testing.expectEqual(@as(i32, @intFromFloat(ph.h)), s.app_h);
        try testing.expectEqual(@as(i32, 0), s.app_top);
        try testing.expectEqual(@as(i32, @intFromFloat(ph.safe_bottom)), s.pad_bottom);
        // Header: safe area + controls + status line.
        try testing.expectEqual(@as(i32, @intFromFloat(ph.safe_top)) + 44 + status_line, s.head.h);
        // Nothing to show: the Data slice is just its header strip.
        try testing.expectEqual(dhead_touch, s.data.h);
        try testing.expect(!s.dataOpen());
        // Thumb-sized buttons; 2-line box.
        try testing.expectEqual(btn_touch, s.btn_h);
        try testing.expectEqual(2 * box_line + box_chrome, s.box_h);
        // The terminal keeps a good share next to the big buttons.
        try testing.expect(s.term.h + s.data.h >= s.inter.h and s.term.h >= min_term);
    }
    // 390 wide: two rows of four buttons (each ~90 px wide); 430: one row.
    try testing.expectEqual(@as(u32, 2), compute(phone(phones[3], false)).rows);
    try testing.expectEqual(@as(u32, 1), compute(phone(phones[4], false)).rows);
}

test "data arrives: the slice grows to its share, shrinks back when collapsed or cleared" {
    var in = phone(phones[5], false);
    const empty = compute(in);
    in.data_content = 2000;
    const full = compute(in);
    try expectTiles(full);
    try testing.expect(full.dataOpen());
    const shared = empty.term.h + empty.data.h;
    try testing.expectEqual(@as(i32, @intFromFloat(@floor(@as(f64, @floatFromInt(shared)) * datafeed.max_share))), full.data.h);
    try testing.expect(full.term.h > full.data.h);
    // A small image: only what it needs.
    in.data_content = 60;
    try testing.expectEqual(dhead_touch + 60, compute(in).data.h);
    // Collapsed: the header strip again.
    in.data_content = 2000;
    in.data_collapsed = true;
    try testing.expectEqual(empty.data, compute(in).data);
}

test "iPhones, keyboard open: interaction sits on the keyboard, terminal still visible" {
    for (phones) |ph| {
        var in = phone(ph, true);
        in.data_content = 500;
        const s = compute(in);
        try expectTiles(s);
        try testing.expect(s.keyboard);
        try testing.expectEqual(@as(i32, @intFromFloat(ph.h - ph.kb)), s.app_h);
        try testing.expectEqual(@as(i32, 120), s.app_top);
        // The keyboard covers the home indicator: no pad under the buttons,
        // and the interaction slice ends exactly at the keyboard's edge.
        try testing.expectEqual(@as(i32, 0), s.pad_bottom);
        try testing.expectEqual(s.app_h, s.inter.bottom());
        try testing.expect(s.box_h <= 2 * box_line + box_chrome);
        try testing.expectEqual(btn_touch, s.btn_h);
        try testing.expect(s.term.h >= min_term);
    }
    // The 14: 664 - 336 = 328 px left: header and data go while typing.
    const s = compute(phone(phones[3], true));
    try testing.expectEqual(@as(i32, 328), s.app_h);
    try testing.expect(s.no_head and s.no_data);
    try testing.expectEqual(@as(i32, 0), s.head.h);
    try testing.expectEqual(@as(i32, 0), s.data.h);
}

test "landscape with the keyboard: everything shrinks, nothing negative" {
    const s = compute(.{ .inner_w = 844, .inner_h = 340, .vv_w = 844, .vv_h = 150, .vv_top = 40, .safe_bottom = 21, .touch = true });
    try expectTiles(s);
    try testing.expect(s.keyboard and s.no_head and s.no_data);
    try testing.expectEqual(box_line + box_chrome, s.box_h); // one line
    try testing.expectEqual(@as(i32, 0), s.note_h);
    const q = compute(.{ .inner_w = 844, .inner_h = 340, .vv_w = 844, .vv_h = 340, .vv_top = 0, .safe_bottom = 21, .touch = true });
    try expectTiles(q);
    try testing.expect(!q.keyboard);
}

test "narrow screens wrap the buttons into two rows" {
    const s = compute(.{ .inner_w = 320, .inner_h = 568, .vv_w = 320, .vv_h = 568, .vv_top = 0, .touch = true });
    try expectTiles(s);
    try testing.expectEqual(@as(u32, 2), s.rows);
    try testing.expectEqual(@as(u32, 4), s.cols);
    try testing.expect(s.term.h >= min_term);
}

test "laptop browser: the same vertical slices, bigger buttons in one row" {
    const s = compute(.{ .inner_w = 1440, .inner_h = 820, .vv_w = 1440, .vv_h = 820, .vv_top = 0, .touch = false });
    try expectTiles(s);
    try testing.expect(!s.keyboard);
    try testing.expectEqual(@as(i32, 36), s.ctl_h);
    try testing.expectEqual(btn_mouse, s.btn_h);
    try testing.expectEqual(@as(u32, 1), s.rows);
    try testing.expectEqual(2 * box_line + box_chrome, s.box_h);
    try testing.expectEqual(dhead_mouse, s.data.h);
    try testing.expectEqual(@as(i32, 1440), s.data.w);
    // A short desktop window (devtools open) is not "keyboard open".
    const q = compute(.{ .inner_w = 1440, .inner_h = 820, .vv_w = 1440, .vv_h = 400, .vv_top = 0, .touch = false });
    try testing.expect(!q.keyboard and !q.no_head);
}

test "iPad landscape with the keyboard: interaction above it" {
    const s = compute(.{ .inner_w = 1180, .inner_h = 820, .vv_w = 1180, .vv_h = 820 - 400, .vv_top = 0, .safe_top = 24, .safe_bottom = 20, .touch = true });
    try expectTiles(s);
    try testing.expect(s.keyboard);
    try testing.expectEqual(@as(i32, 420), s.inter.bottom());
}

test "view only: no interaction slice" {
    const s = compute(.{ .inner_w = 390, .inner_h = 664, .vv_w = 390, .vv_h = 664, .vv_top = 0, .safe_top = 47, .safe_bottom = 34, .touch = true, .input = false });
    try expectTiles(s);
    try testing.expectEqual(@as(i32, 34), s.inter.h); // only the home-indicator pad
}

test "hostile viewport numbers stay in range" {
    const bad = [_]f64{ std.math.nan(f64), std.math.inf(f64), -std.math.inf(f64), -5, 0, 1e300 };
    for (bad) |x| {
        const s = compute(.{ .inner_w = x, .inner_h = x, .vv_w = x, .vv_h = x, .vv_top = x, .safe_top = x, .safe_bottom = x, .touch = true, .data_content = x });
        try testing.expect(s.term.h >= 0 and s.inter.h >= 0 and s.data.h >= 0);
        var buf: [1024]u8 = undefined;
        try testing.expect(css(s, &buf).len > 0);
    }
}
