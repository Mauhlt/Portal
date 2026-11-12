//! Page layout as slices: every platform gets the same three, arranged to
//! fit the screen.
//!
//!   terminal     the live terminal (canvas), under a header with a status
//!                line (project, viewer state, session state) and controls
//!   interaction  the input box (a native textarea, so keyboard dictation
//!                and Win+H fill it), its note line, and the button row
//!   data         whatever data the session pushed (images today; tables
//!                and charts later), drawn by data.zig on its own canvas
//!
//! Arrangements:
//!
//!   tabs (narrow: phones, small windows)      columns (wide: laptop, desktop)
//!   ┌──────────────────────┐                  ┌───────────────┬┬─────────┐
//!   │ [Terminal|Data•] ... │ header           │ header        ││ data    │
//!   │ status line          │                  ├───────────────┤│         │
//!   ├──────────────────────┤                  │ terminal      ││         │
//!   │ terminal OR data     │ (same rect,      │               ││         │
//!   │ (segmented control)  │  one visible)    ├───────────────┤│         │
//!   ├──────────────────────┤                  │ interaction   ││         │
//!   │ interaction (pinned) │                  └───────────────┴┴─────────┘
//!   └──────────────────────┘                            splitter ^ (drag)
//!
//! The page follows the *visual* viewport: when the on-screen keyboard
//! opens, iOS shrinks it (and may scroll it), so the slices are sized to it
//! and the interaction slice stays right above the keyboard. Pure math in
//! CSS pixels; main.zig turns the result into CSS variables and classes.

const std = @import("std");
const layout = @import("layout.zig");
const sane = layout.sane;
pub const Rect = layout.Rect;

pub const Arrangement = enum { tabs, columns };
/// What the top of the tabs arrangement shows.
pub const Tab = enum(u32) { terminal = 0, data = 1 };

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
    tab: Tab = .terminal,
    /// Share of the width given to the data column (columns arrangement).
    data_frac: f64 = default_data_frac,
};

pub const Slices = struct {
    /// Height and top of the page box (follows the visual viewport).
    app_h: i32 = 0,
    app_top: i32 = 0,
    arrangement: Arrangement = .tabs,
    tab: Tab = .terminal,
    /// Header (controls row + status line) over the terminal slice.
    head: Rect = .{},
    term: Rect = .{},
    data: Rect = .{},
    inter: Rect = .{},
    /// The drag handle between the left column and the data column.
    split: Rect = .{},
    head_pad: i32 = 0,
    ctl_h: i32 = 0,
    status_h: i32 = 0,
    /// Interaction slice internals: textarea, note line, button grid.
    box_h: i32 = 0,
    note_h: i32 = 0,
    btn_h: i32 = 0,
    cols: u32 = 0,
    rows: u32 = 0,
    /// Space kept free under the buttons (home indicator); 0 while the
    /// keyboard covers it.
    pad_bottom: i32 = 0,
    keyboard: bool = false,
    /// Header hidden to make room (short screen with the keyboard open).
    no_head: bool = false,

    pub fn eql(a: Slices, b: Slices) bool {
        return std.meta.eql(a, b);
    }
};

/// The visual viewport is this much shorter than the layout viewport:
/// the on-screen keyboard is open (the URL bar alone is well under it).
pub const keyboard_threshold: f64 = 120;
/// From this width on, data gets its own column.
pub const columns_min_w: i32 = 900;
pub const default_data_frac: f64 = 0.36;
pub const min_data_frac: f64 = 0.2;
pub const max_data_frac: f64 = 0.7;
pub const min_data_w: i32 = 260;
pub const min_left_w: i32 = 480;
pub const split_w: i32 = 8;
pub const gap: i32 = 6;
pub const pane_pad: i32 = 6;
/// Yes No 1 2 3 Esc Enter Send (inputbox.Button).
pub const button_count: u32 = 8;
/// Smallest terminal slice worth keeping before shrinking the others.
pub const min_term: i32 = 120;
/// Text line inside the textarea (16 px font: smaller makes iOS zoom in on
/// focus) and the note line.
pub const box_line: i32 = 22;
pub const box_chrome: i32 = 14; // padding + border
pub const note_line: i32 = 18;
pub const status_line: i32 = 20;

fn px(v: f64) i32 {
    return @intFromFloat(@round(v));
}

/// Data column share from a splitter drag to CSS x `x` in a page `w` wide.
pub fn dragFrac(x: f64, w: f64) f64 {
    const W = sane(w, 1, layout.max_side);
    const frac = (W - sane(x, -1e6, 1e6) - @as(f64, split_w) / 2) / W;
    return std.math.clamp(frac, min_data_frac, max_data_frac);
}

pub fn compute(in: Input) Slices {
    var s: Slices = .{ .tab = in.tab };
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

    // Columns: the data column on the right, everything else on the left.
    var left_w = W;
    if (W >= columns_min_w) {
        s.arrangement = .columns;
        const frac = std.math.clamp(sane(in.data_frac, min_data_frac, max_data_frac), min_data_frac, max_data_frac);
        const data_w = std.math.clamp(px(@as(f64, @floatFromInt(W)) * frac), min_data_w, @max(min_data_w, W - split_w - min_left_w));
        left_w = W - data_w - split_w;
        s.split = .{ .x = left_w, .y = 0, .w = split_w, .h = H };
        s.data = .{ .x = left_w + split_w, .y = 0, .w = data_w, .h = H };
    }

    // Interaction slice at the bottom of the left column, then the
    // terminal gets what is left under the header.
    var inter_h: i32 = 0;
    var lines: i32 = if (in.touch and !s.keyboard) 3 else 2;
    if (in.input) {
        s.btn_h = if (in.touch) 44 else 32;
        const min_w: f64 = if (in.touch) 40 else 56;
        const n: f64 = @floatFromInt(button_count);
        const avail = @as(f64, @floatFromInt(left_w)) - 2 * @as(f64, pane_pad) - (n - 1) * @as(f64, gap);
        if (avail / n >= min_w) {
            s.cols = button_count;
            s.rows = 1;
        } else {
            s.cols = (button_count + 1) / 2;
            s.rows = 2;
        }
        s.note_h = note_line;
    }
    var head_h: i32 = 0;
    var term_h: i32 = 0;
    while (true) {
        if (in.input) {
            s.box_h = lines * box_line + box_chrome;
            const rows: i32 = @intCast(s.rows);
            const bar_h = rows * s.btn_h + (rows - 1) * gap + 2 * pane_pad;
            inter_h = pane_pad + s.box_h + s.note_h + 2 + bar_h + s.pad_bottom;
        } else inter_h = s.pad_bottom;
        head_h = if (s.no_head) 0 else s.head_pad + s.ctl_h + s.status_h;
        term_h = H - head_h - inter_h;
        if (term_h >= min_term or !in.input) break;
        // Too tight (keyboard open, landscape, tiny window): shed the
        // header while typing, then textarea lines, then the note.
        if (s.keyboard and !s.no_head) {
            s.no_head = true;
        } else if (lines > 1) {
            lines -= 1;
        } else if (s.note_h > 0) {
            s.note_h = 0;
        } else break;
    }
    term_h = @max(0, term_h);
    s.head = .{ .x = 0, .y = 0, .w = left_w, .h = head_h };
    s.term = .{ .x = 0, .y = head_h, .w = left_w, .h = term_h };
    s.inter = .{ .x = 0, .y = head_h + term_h, .w = left_w, .h = @max(0, H - head_h - term_h) };
    // Tabs: data shares the terminal's rect; one of them is visible.
    if (s.arrangement == .tabs) s.data = s.term;
    return s;
}

/// CSS custom properties for the page (index.html / app.css read them).
pub fn css(s: Slices, buf: []u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.print("--app-h:{d}px;--app-top:{d}px;--head-pad:{d}px;--ctl-h:{d}px;--status-h:{d}px;" ++
        "--box-h:{d}px;--note-h:{d}px;--btn-h:{d}px;--cols:{d};--pad-b:{d}px", .{
        s.app_h, s.app_top, s.head_pad, s.ctl_h, s.status_h, s.box_h, s.note_h, s.btn_h, s.cols, s.pad_bottom,
    }) catch return "";
    const named = [_]struct { []const u8, Rect }{
        .{ "head", s.head }, .{ "term", s.term }, .{ "data", s.data }, .{ "inter", s.inter }, .{ "split", s.split },
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

/// Slices tile the page: the left column stacks head, term, inter exactly.
fn expectTiles(s: Slices) !void {
    try testing.expectEqual(@as(i32, 0), s.head.y);
    try testing.expectEqual(s.head.bottom(), s.term.y);
    try testing.expectEqual(s.term.bottom(), s.inter.y);
    try testing.expectEqual(s.app_h, s.inter.bottom());
    try testing.expect(s.term.h >= 0 and s.inter.h >= 0);
    try testing.expectEqual(s.head.w, s.term.w);
    try testing.expectEqual(s.term.w, s.inter.w);
    switch (s.arrangement) {
        .tabs => try testing.expectEqual(s.term, s.data),
        .columns => {
            try testing.expectEqual(s.term.right(), s.split.x);
            try testing.expectEqual(s.split.right(), s.data.x);
            try testing.expectEqual(s.data.h, s.app_h);
            try testing.expect(s.data.w >= min_data_w and s.term.w >= min_left_w);
        },
    }
    if (s.cols > 0) try testing.expectEqual(button_count, s.cols * s.rows);
}

test "iPhones, portrait, keyboard closed: tabs, interaction pinned at the bottom" {
    for (phones) |ph| {
        const s = compute(phone(ph, false));
        try expectTiles(s);
        try testing.expectEqual(Arrangement.tabs, s.arrangement);
        try testing.expect(!s.keyboard and !s.no_head);
        try testing.expectEqual(@as(i32, @intFromFloat(ph.h)), s.app_h);
        try testing.expectEqual(@as(i32, 0), s.app_top);
        try testing.expectEqual(@as(i32, @intFromFloat(ph.safe_bottom)), s.pad_bottom);
        // Header: safe area + controls + status line.
        try testing.expectEqual(@as(i32, @intFromFloat(ph.safe_top)) + 44 + status_line, s.head.h);
        // One row of 8 buttons of 44 px; 3-line box.
        try testing.expectEqual(@as(u32, 1), s.rows);
        try testing.expectEqual(@as(i32, 44), s.btn_h);
        try testing.expectEqual(3 * box_line + box_chrome, s.box_h);
        // The terminal (or data) keeps the biggest share.
        try testing.expect(s.term.h >= s.inter.h and s.term.h >= min_term);
    }
}

test "iPhones, keyboard open: interaction sits on the keyboard, terminal still visible" {
    for (phones) |ph| {
        const s = compute(phone(ph, true));
        try expectTiles(s);
        try testing.expect(s.keyboard);
        try testing.expectEqual(@as(i32, @intFromFloat(ph.h - ph.kb)), s.app_h);
        try testing.expectEqual(@as(i32, 120), s.app_top);
        // The keyboard covers the home indicator: no pad under the buttons,
        // and the interaction slice ends exactly at the keyboard's edge.
        try testing.expectEqual(@as(i32, 0), s.pad_bottom);
        try testing.expectEqual(s.app_h, s.inter.bottom());
        try testing.expect(s.box_h <= 2 * box_line + box_chrome);
        try testing.expectEqual(@as(i32, 44), s.btn_h);
        try testing.expect(s.term.h >= min_term);
    }
    // The 14: 664 - 336 = 328 px left: the header goes while typing.
    const s = compute(phone(phones[3], true));
    try testing.expectEqual(@as(i32, 328), s.app_h);
    try testing.expect(s.no_head);
    try testing.expectEqual(@as(i32, 0), s.head.h);
}

test "landscape with the keyboard: everything shrinks, nothing negative" {
    const s = compute(.{ .inner_w = 844, .inner_h = 340, .vv_w = 844, .vv_h = 150, .vv_top = 40, .safe_bottom = 21, .touch = true });
    try expectTiles(s);
    try testing.expectEqual(Arrangement.tabs, s.arrangement);
    try testing.expect(s.keyboard and s.no_head);
    try testing.expectEqual(box_line + box_chrome, s.box_h); // one line
    try testing.expectEqual(@as(i32, 0), s.note_h);
    try testing.expect(s.term.h > 0);
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

test "tabs: the data tab takes the terminal's place" {
    var in = phone(phones[3], false);
    in.tab = .data;
    const s = compute(in);
    try expectTiles(s);
    try testing.expectEqual(Tab.data, s.tab);
    try testing.expectEqual(compute(phone(phones[3], false)).term, s.data);
}

test "laptop: data is a resizable right column" {
    const in: Input = .{ .inner_w = 1440, .inner_h = 820, .vv_w = 1440, .vv_h = 820, .vv_top = 0, .touch = false };
    const s = compute(in);
    try expectTiles(s);
    try testing.expectEqual(Arrangement.columns, s.arrangement);
    try testing.expect(!s.keyboard);
    try testing.expectEqual(@as(i32, 36), s.ctl_h);
    try testing.expectEqual(@as(i32, 32), s.btn_h);
    try testing.expectEqual(2 * box_line + box_chrome, s.box_h);
    try testing.expectEqual(@as(i32, @intFromFloat(@round(1440 * default_data_frac))), s.data.w);
    try testing.expectEqual(@as(i32, 1440), s.data.right());
    // Dragging the splitter to x = 1000 leaves the data column ~436 px.
    var dragged = in;
    dragged.data_frac = dragFrac(1000, 1440);
    const d = compute(dragged);
    try expectTiles(d);
    try testing.expectEqual(@as(i32, 1000), d.split.x + split_w / 2);
    // Drags are clamped: neither column can vanish.
    for ([_]f64{ -500, 0, 300, 1439, 5000, std.math.nan(f64) }) |x| {
        var e = in;
        e.data_frac = dragFrac(x, 1440);
        try expectTiles(compute(e));
    }
    // A short desktop window (devtools open) is not "keyboard open".
    const q = compute(.{ .inner_w = 1440, .inner_h = 820, .vv_w = 1440, .vv_h = 400, .vv_top = 0, .touch = false });
    try testing.expect(!q.keyboard and !q.no_head);
    // Right at the threshold: columns; just under: tabs.
    try testing.expectEqual(Arrangement.columns, compute(.{ .inner_w = 900, .inner_h = 700, .vv_w = 900, .vv_h = 700, .vv_top = 0, .touch = false }).arrangement);
    try testing.expectEqual(Arrangement.tabs, compute(.{ .inner_w = 899, .inner_h = 700, .vv_w = 899, .vv_h = 700, .vv_top = 0, .touch = false }).arrangement);
}

test "iPad landscape with the keyboard: columns, interaction above it" {
    const s = compute(.{ .inner_w = 1180, .inner_h = 820, .vv_w = 1180, .vv_h = 820 - 400, .vv_top = 0, .safe_top = 24, .safe_bottom = 20, .touch = true });
    try expectTiles(s);
    try testing.expectEqual(Arrangement.columns, s.arrangement);
    try testing.expect(s.keyboard);
    try testing.expectEqual(@as(i32, 420), s.inter.bottom());
}

test "view only: no interaction slice" {
    const s = compute(.{ .inner_w = 390, .inner_h = 664, .vv_w = 390, .vv_h = 664, .vv_top = 0, .safe_top = 47, .safe_bottom = 34, .touch = true, .input = false });
    try expectTiles(s);
    try testing.expectEqual(@as(i32, 34), s.inter.h); // only the home-indicator pad
    try testing.expectEqual(@as(i32, 664 - (47 + 44 + status_line) - 34), s.term.h);
}

test "pinch zoom is not a keyboard" {
    const s = compute(.{ .inner_w = 390, .inner_h = 664, .vv_w = 195, .vv_h = 332, .vv_top = 100, .touch = true });
    try testing.expect(!s.keyboard);
    try testing.expectEqual(@as(i32, 664), s.app_h);
    try testing.expectEqual(@as(i32, 0), s.app_top);
}

test "hostile viewport values" {
    const bad = [_]f64{ std.math.nan(f64), std.math.inf(f64), -std.math.inf(f64), -5, 0, 1e300 };
    for (bad) |x| for ([_]bool{ false, true }) |t| {
        const s = compute(.{ .inner_w = x, .inner_h = x, .vv_w = x, .vv_h = x, .vv_top = x, .safe_top = x, .safe_bottom = x, .touch = t, .data_frac = x });
        try testing.expect(s.term.h >= 0 and s.app_h >= 1 and s.app_h <= layout.max_side);
        var buf: [1024]u8 = undefined;
        try testing.expect(css(s, &buf).len > 0);
    };
}

test "css variables" {
    const s = compute(phone(phones[3], false));
    var buf: [1024]u8 = undefined;
    const c = css(s, &buf);
    try testing.expect(std.mem.startsWith(u8, c, "--app-h:664px;--app-top:0px;"));
    try testing.expect(std.mem.indexOf(u8, c, "--cols:8;") != null);
    try testing.expect(std.mem.indexOf(u8, c, ";--term-x:0px;--term-y:111px;--term-w:390px;") != null);
    try testing.expect(std.mem.endsWith(u8, c, "--split-h:0px"));
}
