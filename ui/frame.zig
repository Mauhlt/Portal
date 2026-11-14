//! The frame: layout, widgets and draw-list generation for one window of
//! the shared UI, plus hit-testing of what it drew. Knows nothing about
//! windows, GPUs, PTYs or networking: the caller hands it the font set, the
//! window's pixel size and scale, a terminal `Grid` and an `Overlay` (the
//! description of everything around and over the content), and gets a
//! `draw.DrawList` back (`Frame.list`). Pointer input is mapped back
//! through what the last frame drew (`pointerDown` / `mouseAt`).
//!
//! Layout (`Layout`, kept in `regions`), the same vertical slices on every
//! device (docs/layout-design.md), top to bottom: top bar (optional,
//! `Overlay.top_bar`), the main slice (`Overlay.screen`: the terminal grid,
//! a centred notice, or a pluggable content view such as the conversation),
//! the Data slice (`Overlay.data`: a thin header strip that grows when there
//! is something to show), the interaction slice (`Overlay.bottom`: stacked
//! panes such as Instruct or its panel, the line with Send and a key row,
//! drawn large enough to read and hit), status line. A modal `Overlay.panel` is drawn as
//! a layer over all of them.
//!
//! Colours come from the theme (shared/theme.zig) only.

const std = @import("std");
const Font = @import("Font");
const wcwidth = Font.wcwidth;
const fontset = Font.fontset;
const datafeed = @import("datafeed");
const theme = @import("shared").theme;
const draw = @import("draw.zig");
const input = @import("input.zig");
const grid_mod = @import("grid.zig");

const Rgb = theme.Rgb;
const Grid = grid_mod.Grid;
pub const Metrics = fontset.Metrics;

pub const Tone = enum { normal, muted, good, warn, bad };

pub const Message = struct {
    title: []const u8,
    title_tone: Tone = .normal,
    lines: []const []const u8 = &.{},
    button: ?struct { label: []const u8, id: u32 } = null,
    detail: []const u8 = "",
    detail_tone: Tone = .muted,
};

pub const StatusLine = struct {
    tone: Tone = .muted,
    label: []const u8 = "",
    extra: []const u8 = "",
    extra_tone: Tone = .muted,
    right: []const u8 = "",
    /// The shown tab's background work ("2 shells \u{00B7} 1 monitor"),
    /// after `extra`; "" hides it. A click reaches the sink as
    /// InputSink.button(tasks_id).
    tasks: []const u8 = "",
    tasks_id: ?u32 = null,
};

/// The strip above the main slice: the project tabs (one per session,
/// coloured per project; `title` instead when there are none), the
/// remote-viewer badge and the host's buttons.
pub const TopBar = struct {
    title: []const u8 = "",
    /// Project tabs, left to right. A click reaches the sink as
    /// InputSink.button(tab.id) (or tab.close_id on its close box).
    tabs: []const TopTab = &.{},
    /// A "+" after the tabs (the desk's "open a project"); null: none.
    add_id: ?u32 = null,
    /// Coloured strip at the left edge.
    accent: ?Rgb = null,
    right: []const u8 = "",
    right_tone: Tone = .muted,
    /// Draw `right` as a filled, high-contrast badge (someone is watching).
    right_badge: bool = false,
    /// Clickable actions, drawn right-aligned left of `right`; a click
    /// reaches the sink as InputSink.button(id).
    buttons: []const TopButton = &.{},
};

pub const TopButton = struct {
    label: []const u8,
    id: u32,
    /// Drawn as the chosen one (the view toggle).
    active: bool = false,
};

/// One project tab in the top bar.
pub const TopTab = struct {
    label: []const u8,
    color: Rgb,
    active: bool = false,
    /// Its program waits for an answer (OSC 7501): drawn highlighted.
    attention: bool = false,
    id: u32,
    /// A close box (the desk only; remote viewers can't close tabs).
    close_id: ?u32 = null,
    /// A small count after the label (background tasks running); ""
    /// hides it. A click on it reaches the sink as InputSink.button(badge_id).
    badge: []const u8 = "",
    badge_id: ?u32 = null,
};

/// A line of panel text. Long lines wrap at spaces.
pub const PanelText = struct {
    text: []const u8,
    tone: Tone = .muted,
    bold: bool = false,
};

/// A one-line text field (the host owns the text and the editing). A
/// click reaches the sink as InputSink.button(id). `choice` draws it as a
/// selector ("< value >") that the host cycles.
pub const PanelField = struct {
    label: []const u8,
    value: []const u8,
    hint: []const u8 = "",
    id: u32,
    focused: bool = false,
    choice: bool = false,
};

pub const PanelButton = struct {
    label: []const u8,
    id: u32,
    focused: bool = false,
    tone: Tone = .normal,
};

/// A list entry (e.g. a paired device) with an optional button at its right.
pub const PanelRow = struct {
    text: []const u8,
    tone: Tone = .normal,
    selected: bool = false,
    button: ?PanelButton = null,
};

/// A QR code to show in a panel: `size` x `size` modules, row-major, 1 =
/// dark (drawn with a light quiet zone).
pub const PanelQr = struct {
    size: u16,
    modules: []const u8,
};

/// A modal box drawn over everything else (pairing approval, device list,
/// first-run settings). Layout, top to bottom: title, lines, qr, rows,
/// fields, after, note, buttons.
pub const Panel = struct {
    title: []const u8,
    title_tone: Tone = .normal,
    lines: []const PanelText = &.{},
    qr: ?PanelQr = null,
    rows: []const PanelRow = &.{},
    fields: []const PanelField = &.{},
    after: []const PanelText = &.{},
    note: PanelText = .{ .text = "" },
    buttons: []const PanelButton = &.{},
};

/// A linear (reading-order) cell selection, inclusive, start <= end.
pub const Selection = struct {
    start_col: u16,
    start_row: u16,
    end_col: u16,
    end_row: u16,

    pub fn contains(s: Selection, col: usize, row: usize) bool {
        if (row < s.start_row or row > s.end_row) return false;
        if (row == s.start_row and col < s.start_col) return false;
        if (row == s.end_row and col > s.end_col) return false;
        return true;
    }
};

/// A pixel rectangle of the window.
pub const Rect = struct {
    x: f32 = 0,
    y: f32 = 0,
    w: f32 = 0,
    h: f32 = 0,

    pub fn contains(r: Rect, px: f32, py: f32) bool {
        return px >= r.x and px < r.x + r.w and py >= r.y and py < r.y + r.h;
    }
};

/// The window's regions for one frame, top to bottom: top bar, main slice
/// (`terminal`), the Data slice, the bottom region (`Overlay.bottom`, its
/// panes stacked in order: the interaction slice), status line. A modal
/// `Overlay.panel` is a layer over all of them, not a region.
pub const Layout = struct {
    top: Rect = .{},
    terminal: Rect = .{},
    bottom: Rect = .{},
    status: Rect = .{},
    /// The Data slice (Overlay.data), full width between the main slice and
    /// the bottom region; zero-sized without one.
    data: Rect = .{},
    /// Each bottom pane's rectangle (same order as Overlay.bottom).
    panes: [max_panes]Rect = @splat(.{}),
    n_panes: usize = 0,
};

pub const max_panes = 4;

/// One horizontal pane of the bottom region. Panes are drawn in order
/// from the top of the region down; their clicks reach the sink through
/// InputSink.button / .answer like every other button.
pub const Pane = struct {
    /// Height in logical pixels (scaled with the window's DPI); 0 picks the
    /// content's natural height.
    height: f32 = 0,
    /// A button at the right end of a `.field` pane (the input box's Send).
    send: ?PanelButton = null,
    /// A button left of Send that brings up the on-screen keyboard (touch
    /// devices without a hardware keyboard).
    keyboard: ?PanelButton = null,
    content: union(enum) {
        /// A row of answer buttons (the instruct panel's key row; in `keys`
        /// mode the whole input.answers): InputSink.answer.
        answers: []const input.Answer,
        /// A centred row of buttons: InputSink.button(id).
        buttons: []const PanelButton,
        /// A text box (e.g. an input line): drawn like a panel field; a
        /// click reports its id. The host owns the text and the editing.
        field: PanelField,
    },
};

/// One entry of the Data slice, newest first.
pub const DataItem = struct {
    caption: []const u8,
    /// Image id in `DataSlice.images` (null: caption only).
    image: ?u32 = null,
    /// The image's pixel size (0 if unknown), for fitting.
    w: u32 = 0,
    h: u32 = 0,
};

/// The Data slice (docs/layout-design.md): a strip under the main slice,
/// full width. Its header line is always there ("Data · nothing yet", the
/// Hide/Show and Clear buttons); below it the items, newest first, left to
/// right. Its height follows `dataHeight` (module "datafeed"'s rule): just
/// the header while empty or collapsed, growing
/// with the items up to datafeed.max_share. Images are looked up by id in
/// `images` (a store separate from the grid's, so its ids never collide
/// with the terminal's images).
pub const DataSlice = struct {
    title: []const u8 = "Data",
    /// Text after the title ("nothing yet", "2 images", "1 new").
    summary: []const u8 = "",
    summary_tone: Tone = .muted,
    items: []const DataItem = &.{},
    images: ?*const grid_mod.Images = null,
    /// Collapsed by the user: the header strip only.
    collapsed: bool = false,
    /// Header buttons (right-aligned): clicks reach InputSink.button(id).
    /// A click elsewhere on the header reports `toggle`'s id too.
    toggle: ?PanelButton = null,
    clear: ?PanelButton = null,
};

/// The Data slice's height in a column `avail` high (datafeed.sliceHeight):
/// the header strip while empty or collapsed, else header + `content`, at
/// most datafeed.max_share of `avail`.
pub fn dataHeight(avail: f32, header: f32, content: f32, collapsed: bool) f32 {
    return @floatCast(datafeed.sliceHeight(avail, header, content, collapsed));
}

/// Font size (logical px) of the interaction slice's buttons and input box:
/// larger than the rest of the chrome, so they are easy to read and hit.
pub const action_em: f32 = 16;
/// Font size (logical px) of the chrome: bars, panels, the Data slice.
pub const chrome_em: f32 = 13;

/// A pluggable main-slice view (e.g. the conversation): draws itself into
/// `r` with the painter's primitives. Its buttons report through the sink
/// (Painter.tapAnswer / tapButton: on release, unless the press became a
/// drag). Presses over the main slice reach it as drags (InputSink.drag),
/// the wheel as InputSink.scroll; the shell hands both to it.
pub const ContentView = struct {
    ctx: *anyopaque,
    draw: *const fn (ctx: *anyopaque, p: *Painter, r: Rect) void,
    /// Scroll by `dy` pixels (> 0: towards the top, older content).
    scroll: ?*const fn (ctx: *anyopaque, dy: f32) void = null,
    /// A press, move or release over the view (scrolling, swiping). It may
    /// return an answer key, which the shell sends like an answer button.
    drag: ?*const fn (ctx: *anyopaque, d: input.Drag) ?[]const u8 = null,
    /// A key while the view has the keyboard (or a navigation key while
    /// the input line has it).
    key: ?*const fn (ctx: *anyopaque, k: input.Key, m: input.Mods) ViewInput = null,
    /// One of the view's own button ids (Painter.tapButton); true: its own.
    button: ?*const fn (ctx: *anyopaque, id: u32) bool = null,
};

/// What a content view made of a key: nothing, something of its own, or
/// an answer to send (an answer key, through the answer path).
pub const ViewInput = union(enum) { ignored, consumed, answer: []const u8 };

pub const Overlay = struct {
    /// What the main slice shows: the grid (if it has cells), a centred
    /// notice, or a content view.
    screen: union(enum) { grid, message: Message, view: ContentView } = .grid,
    /// The Data slice under the main slice.
    data: ?DataSlice = null,
    top_bar: ?TopBar = null,
    selection: ?Selection = null,
    /// The bottom region under the main slice (at most `max_panes`).
    bottom: []const Pane = &.{},
    status: StatusLine = .{},
    /// A modal layer over the whole layout (pairing, devices, settings).
    panel: ?Panel = null,
    /// Touch input: finger-sized targets (tabs at least `touch_target`
    /// logical px tall).
    touch: bool = false,
    /// A short notice over the bottom right of the main slice (a headset
    /// connected); the glue removes it at its own deadline.
    toast: ?Toast = null,
};

pub const Toast = struct {
    text: []const u8,
    tone: Tone = .normal,
};

/// Smallest height (logical px) of a tab's hit area on touch devices.
pub const touch_target: f32 = 40;

pub const Sizing = union(enum) {
    /// Scale the font to the host's grid (remote view): its columns fill the
    /// main slice's width, with a readable minimum (see `fitEm`); rows that
    /// do not fit then scroll to follow the cursor (`followTop`).
    fit_grid,
    /// Fixed font size in logical pixels; the window decides cols x rows
    /// (reported through InputSink.resized; local terminal hosts).
    fixed_em: f32,
};

const Hit = struct {
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    action: union(enum) { answer: []const u8, button: u32 },
    /// A content view's button: fires on release when the press did not
    /// turn into a drag (scrolling over a card never presses its buttons).
    tap: bool = false,
};

/// A press in a content view: a tap on one of its buttons, or a drag that
/// scrolls it. On a touch screen (`Frame.touch`) every press: a tap on any
/// button, or a drag (the grid's rows scroll under it).
const Press = struct {
    active: bool = false,
    x0: f32 = 0,
    y0: f32 = 0,
    moved: bool = false,
    /// It began over the content view (its drags go to InputSink.drag).
    in_view: bool = true,
    /// Touch, begun over the grid: its drags scroll the rows (the last y,
    /// and rows not yet scrolled).
    pan: bool = false,
    last_y: f32 = 0,
    pan_acc: f32 = 0,
    /// What the press began on (answer keys copied: the view's strings may
    /// change before the release).
    action: union(enum) { none, answer: struct { buf: [16]u8 = undefined, len: u8 = 0 }, button: u32 } = .none,

    fn setAction(pr: *Press, a: @FieldType(Hit, "action")) void {
        switch (a) {
            .answer => |k| if (k.len <= 16) {
                pr.action = .{ .answer = .{ .len = @intCast(k.len) } };
                @memcpy(pr.action.answer.buf[0..k.len], k);
            },
            .button => |id| pr.action = .{ .button = id },
        }
    }
};

fn toneColor(t: Tone) Rgb {
    return switch (t) {
        .normal => theme.ui.text,
        .muted => theme.ui.dim,
        .good => theme.ui.good,
        .warn => theme.ui.warn,
        .bad => theme.ui.bad,
    };
}

/// Where the last grid was drawn (pixels), for pointer -> cell.
pub const CellLayout = struct { ox: f32 = 0, oy: f32 = 0, cw: f32 = 1, ch: f32 = 1, cols: u16 = 0, rows: u16 = 0, first_row: u16 = 0 };

pub const Zoom = enum { in, out, reset };

/// Window edges the UI must keep clear (pixels): the iPhone's safe area and
/// on-screen keyboard; zero on desktops.
pub const Insets = struct { left: f32 = 0, top: f32 = 0, right: f32 = 0, bottom: f32 = 0 };

/// The focused text field of the last frame (pixels): where a platform's
/// native text field goes (iOS: dictation and the system keyboard), and
/// what it should contain.
pub const TextSlot = struct {
    rect: Rect,
    id: u32,
    font_px: f32,
    value_buf: [cap]u8 = undefined,
    value_len: usize = 0,

    pub const cap = 1024;

    pub fn value(t: *const TextSlot) []const u8 {
        return t.value_buf[0..t.value_len];
    }
};

/// Turning `old` into `new` by editing at the end: how many code points
/// to delete from `old`, then what to append. A native text field's edits
/// reach the UI as these Backspaces and characters.
pub fn textEdit(old: []const u8, new: []const u8) struct { deletes: usize, insert: []const u8 } {
    var p: usize = 0;
    while (p < old.len and p < new.len and old[p] == new[p]) p += 1;
    // Back to a code point boundary in both.
    while (p > 0 and ((p < old.len and (old[p] & 0xC0) == 0x80) or (p < new.len and (new[p] & 0xC0) == 0x80))) p -= 1;
    const removed = std.unicode.utf8CountCodepoints(old[p..]) catch old.len - p;
    return .{ .deletes = removed, .insert = new[p..] };
}

pub const Frame = struct {
    gpa: std.mem.Allocator,
    /// The last built frame.
    list: draw.DrawList = .{},
    sizing: Sizing,
    term: theme.Terminal = theme.terminal,
    hits: [96]Hit = undefined,
    n_hits: usize = 0,
    zoom_steps: i32 = 0,
    /// Cells that fit the main slice at the current font size (fixed_em).
    capacity: [2]u16 = .{ 0, 0 },
    reported_capacity: [2]u16 = .{ 0, 0 },
    /// The regions of the last built frame (see Layout).
    regions: Layout = .{},
    cells: CellLayout = .{},
    /// Edges to keep clear, set by the window layer before build.
    insets: Insets = .{},
    /// The focused text field of the last frame (see TextSlot).
    text_slot: ?TextSlot = null,
    /// Grid rows scrolled back above the followed rows (see followTop)
    /// when the grid does not fit: a drag on a touch screen or the wheel.
    /// Clamped while drawing; 0 follows the cursor again.
    scroll_back: u16 = 0,
    /// Set during build.
    fonts: *const fontset.FontSet = undefined,
    scale: f32 = 1,
    /// The last frame's main slice showed a content view (Overlay.screen
    /// = .view): presses there tap or drag, the wheel scrolls it.
    view_shown: bool = false,
    /// Pixels one wheel notch scrolls (three lines of the chrome font).
    wheel_px: f32 = 48,
    press: Press = .{},
    /// A touch screen (iOS; the window delivers one finger as the
    /// pointer): nothing acts on a press, every button is a tap (fires on
    /// release if the finger did not move off it or drag), and a drag over
    /// the grid scrolls its rows.
    touch: bool = false,

    pub fn init(gpa: std.mem.Allocator, sizing: Sizing) Frame {
        return .{ .gpa = gpa, .sizing = sizing };
    }

    pub fn deinit(f: *Frame) void {
        f.list.deinit(f.gpa);
    }

    // ------------------------------------------------------------ input

    /// Ctrl+= / - / 0.
    pub fn zoom(f: *Frame, z: Zoom) void {
        f.zoom_steps = switch (z) {
            .in => @min(f.zoom_steps + 1, 20),
            .out => @max(f.zoom_steps - 1, -10),
            .reset => 0,
        };
    }

    /// A pointer press at window pixel (x, y): a button of the last frame
    /// (left button only), else mouse input over the grid.
    /// Scrolls the grid by `rows` (> 0: back towards the top) when it has
    /// rows out of view; `scroll_back` is clamped on the next build.
    pub fn scrollRows(f: *Frame, rows: i32) void {
        const now: i32 = f.scroll_back;
        f.scroll_back = @intCast(std.math.clamp(now + rows, 0, std.math.maxInt(u16)));
    }

    /// In a content view: a press, then a pointer move past this many
    /// logical pixels, is a drag (scroll), not a tap.
    pub const drag_slop: f32 = 8;

    pub fn pointerDown(f: *Frame, x: f32, y: f32, button: input.MouseButton, mods: input.Mods, sink: input.InputSink) void {
        f.press = .{};
        const hit = if (button == .left) f.hitFull(x, y) else null;
        if (f.touch and button == .left) {
            const in_view = f.view_shown and f.regions.terminal.contains(x, y);
            const pan = !in_view and f.regions.terminal.contains(x, y);
            f.press = .{ .active = true, .x0 = x, .y0 = y, .in_view = in_view, .pan = pan, .last_y = y };
            if (hit) |h| f.press.setAction(h.action);
            if (in_view) sink.drag(.{ .phase = .down, .x = x, .y = y, .scale = f.scale });
            return;
        }
        if (hit) |h| if (!h.tap) {
            switch (h.action) {
                .answer => |a| sink.answer(a),
                .button => |id| sink.button(id),
            }
            return;
        };
        if (button == .left and f.view_shown and f.regions.terminal.contains(x, y)) {
            f.press = .{ .active = true, .x0 = x, .y0 = y };
            sink.drag(.{ .phase = .down, .x = x, .y = y, .scale = f.scale });
            if (hit) |h| f.press.setAction(h.action);
            return;
        }
        sink.mouse(f.mouseAt(.down, button, x, y, mods));
    }

    pub fn pointerMove(f: *Frame, x: f32, y: f32, sink: input.InputSink) void {
        if (f.press.active) {
            if (!f.press.moved and @max(@abs(x - f.press.x0), @abs(y - f.press.y0)) > drag_slop * f.scale) f.press.moved = true;
            if (f.press.in_view) {
                sink.drag(.{ .phase = .move, .x = x, .y = y, .scale = f.scale });
            } else if (f.press.moved and f.press.pan) {
                // Touch, over the grid: finger down = earlier rows.
                f.press.pan_acc += (y - f.press.last_y) / @max(f.cells.ch, 1);
                f.press.last_y = y;
                const rows = @trunc(f.press.pan_acc);
                if (rows != 0) {
                    f.press.pan_acc -= rows;
                    f.scrollRows(@intFromFloat(rows));
                }
            }
            return;
        }
        sink.mouse(f.mouseAt(.move, .left, x, y, .{}));
    }

    pub fn pointerUp(f: *Frame, x: f32, y: f32, button: input.MouseButton, sink: input.InputSink) void {
        if (f.press.active) {
            const pr = f.press;
            f.press = .{};
            if (pr.in_view) sink.drag(.{ .phase = .up, .x = x, .y = y, .scale = f.scale });
            if (pr.moved) return;
            // A tap: what it began on, if the release is still on it.
            const h = f.hitFull(x, y) orelse return;
            if (!h.tap and !f.touch) return;
            switch (pr.action) {
                .none => {},
                .answer => |a| if (h.action == .answer and std.mem.eql(u8, h.action.answer, a.buf[0..a.len])) sink.answer(a.buf[0..a.len]),
                .button => |id| if (h.action == .button and h.action.button == id) sink.button(id),
            }
            return;
        }
        sink.mouse(f.mouseAt(.up, button, x, y, .{}));
    }

    /// The OS took the press away (iOS touchesCancelled): it ends without
    /// acting on it. A content view's drag is released where it began (a
    /// swipe springs back), and no button fires.
    pub fn pointerCancel(f: *Frame, sink: input.InputSink) void {
        const pr = f.press;
        f.press = .{};
        if (pr.active and pr.in_view) sink.drag(.{ .phase = .up, .x = pr.x0, .y = pr.y0, .scale = f.scale });
    }

    /// A wheel turn of `notches` (> 0: away from the user) at (x, y): scrolls
    /// a content view under the pointer. False if nothing scrolled.
    pub fn wheel(f: *Frame, x: f32, y: f32, notches: f32, sink: input.InputSink) bool {
        if (!f.view_shown or notches == 0 or !f.regions.terminal.contains(x, y)) return false;
        sink.scroll(notches * f.wheel_px);
        return true;
    }

    fn hitFull(f: *const Frame, x: f32, y: f32) ?Hit {
        for (f.hits[0..f.n_hits]) |b| {
            if (x >= b.x and x < b.x + b.w and y >= b.y and y < b.y + b.h) return b;
        }
        return null;
    }

    fn hitAt(f: *const Frame, x: f32, y: f32) ?@FieldType(Hit, "action") {
        const h = f.hitFull(x, y) orelse return null;
        return h.action;
    }

    /// Tells the sink if the cells that fit the window changed since the
    /// last report (`fb`: the window's pixel size).
    pub fn reportCapacity(f: *Frame, sink: input.InputSink, fb: [2]u32) void {
        if (f.capacity[0] == 0 or f.capacity[1] == 0) return;
        if (f.capacity[0] != f.reported_capacity[0] or f.capacity[1] != f.reported_capacity[1]) {
            f.reported_capacity = f.capacity;
            sink.resized(fb[0], fb[1], f.capacity[0], f.capacity[1]);
        }
    }

    /// Maps a window pixel to a grid cell of the last built frame.
    pub fn mouseAt(f: *const Frame, action: @FieldType(input.Mouse, "action"), button: input.MouseButton, x: f32, y: f32, mods: input.Mods) input.Mouse {
        const l = f.cells;
        const fx = (x - l.ox) / l.cw;
        // Rows above first_row are scrolled out of the slice.
        const top: f32 = @floatFromInt(l.first_row);
        const fy = (y - l.oy) / l.ch + top;
        const inside = l.cols > 0 and l.rows > 0 and fx >= 0 and fy >= top and
            fx < @as(f32, @floatFromInt(l.cols)) and fy < @as(f32, @floatFromInt(l.rows));
        return .{
            .action = action,
            .button = button,
            .col = clampCell(fx, l.cols),
            .row = clampCell(fy, l.rows),
            .inside = inside,
            .mods = mods,
        };
    }

    // ------------------------------------------------------------ build

    /// Builds the frame from `grid` and `overlay` into `list` for a window
    /// of `fb` pixels at `scale` (1.0 = 96 dpi). CPU only.
    pub fn build(f: *Frame, fonts: *const fontset.FontSet, fb: [2]u32, scale: f32, grid: *const Grid, overlay: Overlay) void {
        f.fonts = fonts;
        f.scale = scale;
        f.list.reset();
        f.list.clear = f.term.bg;
        f.n_hits = 0;
        f.text_slot = null;
        // Lay out inside the insets (all zero on desktops), then shift.
        const ins = f.insets;
        defer f.shift(ins.left, ins.top);
        const W: f32 = @max(0, @as(f32, @floatFromInt(fb[0])) - ins.left - ins.right);
        const H: f32 = @max(0, @as(f32, @floatFromInt(fb[1])) - ins.top - ins.bottom);
        if (W < 1 or H < 1) return;
        const s = scale;
        const ui = fonts.metrics(@round(chrome_em * s));
        const act = fonts.metrics(@round(action_em * s));
        const status_h: f32 = @round(@as(f32, @floatFromInt(ui.cell_h)) * 1.6);
        const top_h: f32 = if (overlay.top_bar != null) topBarHeight(ui, overlay.touch, s) else 0;
        // The bottom region (interaction slice): its panes' heights, but never
        // more than half the window (the main slice and data keep the rest).
        var panes: [max_panes]Pane = undefined;
        var n_panes: usize = 0;
        for (overlay.bottom) |p| if (n_panes < max_panes) {
            panes[n_panes] = p;
            n_panes += 1;
        };
        var heights: [max_panes]f32 = undefined;
        var bar_h: f32 = 0;
        for (panes[0..n_panes], 0..) |p, i| {
            heights[i] = paneHeight(act, p, s);
            bar_h += heights[i];
        }
        const room = @max(0, H - status_h - top_h);
        if (bar_h > room / 2) {
            const k = (room / 2) / bar_h;
            bar_h = 0;
            for (heights[0..n_panes]) |*h| {
                h.* = @floor(h.* * k);
                bar_h += h.*;
            }
        }
        // The main slice and the Data slice share what is left: data takes
        // its header strip, or more while it has something to show.
        const middle = @max(0, room - bar_h);
        const data_h: f32 = if (overlay.data) |d| dataHeight(middle, dataHeaderHeight(ui), dataContentHeight(ui, d, W, s), d.collapsed) else 0;
        const grid_h = @max(0, middle - data_h);
        f.regions = .{
            .top = .{ .w = W, .h = top_h },
            .terminal = .{ .y = top_h, .w = W, .h = grid_h },
            .data = .{ .y = top_h + grid_h, .w = W, .h = data_h },
            .bottom = .{ .y = top_h + middle, .w = W, .h = bar_h },
            .status = .{ .y = H - status_h, .w = W, .h = status_h },
            .n_panes = n_panes,
        };
        var py = top_h + middle;
        for (heights[0..n_panes], 0..) |h, i| {
            f.regions.panes[i] = .{ .y = py, .w = W, .h = h };
            py += h;
        }

        f.cells.cols = 0;
        f.cells.rows = 0;
        f.cells.first_row = 0;
        f.view_shown = overlay.screen == .view and overlay.panel == null;
        f.wheel_px = @round(@as(f32, @floatFromInt(ui.cell_h)) * 1.35) * 3;
        switch (overlay.screen) {
            .grid => {
                const m = f.cellMetrics(grid, W, grid_h, s);
                f.capacity = fitCells(W, grid_h, m.cell_w, m.cell_h, 4 * s);
                if (grid.cols > 0 and grid.rows > 0) f.drawGrid(grid, overlay.selection, m, W, top_h, grid_h, s);
            },
            .message => |msg| f.drawMessage(ui, msg, W, top_h, grid_h, s),
            .view => |v| {
                var p: Painter = .{ .f = f, .ui = ui, .act = act, .s = s };
                v.draw(v.ctx, &p, f.regions.terminal);
            },
        }
        if (overlay.top_bar) |tb| f.drawTopBar(ui, tb, W, top_h, s);
        if (overlay.data) |d| if (data_h > 0) f.drawData(ui, d, f.regions.data, s);
        for (panes[0..n_panes], 0..) |p, i| f.drawPane(act, p, f.regions.panes[i], s);
        f.drawStatus(ui, overlay.status, H - status_h, W, status_h, s);
        if (overlay.toast) |t| f.drawToast(ui, t, W, top_h + middle, s);
        if (overlay.panel) |p| {
            // Modal: buttons (and the text field) under the panel stop reacting.
            f.n_hits = 0;
            f.text_slot = null;
            f.drawPanel(ui, p, W, H, s);
        }
    }

    /// Moves everything built this frame by (dx, dy) (see Insets).
    fn shift(f: *Frame, dx: f32, dy: f32) void {
        if (dx == 0 and dy == 0) return;
        for (f.list.cmds.items) |*c| switch (c.*) {
            inline .rect, .glyph => |*v| {
                v.x += dx;
                v.y += dy;
            },
            .text => |*v| {
                v.x += dx;
                v.y += dy;
                if (v.clip) |*cl| {
                    cl[0] += dx;
                    cl[1] += dy;
                    cl[2] += dx;
                    cl[3] += dy;
                }
            },
            .image => |*v| {
                v.x += dx;
                v.y += dy;
                v.clip[0] += dx;
                v.clip[1] += dy;
                v.clip[2] += dx;
                v.clip[3] += dy;
            },
        };
        for (f.hits[0..f.n_hits]) |*b| {
            b.x += dx;
            b.y += dy;
        }
        const rs = [_]*Rect{ &f.regions.top, &f.regions.terminal, &f.regions.bottom, &f.regions.status, &f.regions.data };
        for (rs) |r| {
            r.x += dx;
            r.y += dy;
        }
        for (f.regions.panes[0..f.regions.n_panes]) |*r| {
            r.x += dx;
            r.y += dy;
        }
        f.cells.ox += dx;
        f.cells.oy += dy;
        if (f.text_slot) |*t| {
            t.rect.x += dx;
            t.rect.y += dy;
        }
    }

    /// Remembers the focused text field being drawn (see text_slot).
    fn noteTextField(f: *Frame, r: Rect, id: u32, value: []const u8, font_px: f32) void {
        var t: TextSlot = .{ .rect = r, .id = id, .font_px = font_px };
        const n = @min(value.len, t.value_buf.len);
        @memcpy(t.value_buf[0..n], value[0..n]);
        t.value_len = n;
        f.text_slot = t;
    }

    /// A QR code centred in a `w` wide column at `y`, whole pixels per
    /// module, light quiet zone of 4 modules. Returns the height used.
    fn drawQr(f: *Frame, q: PanelQr, x: f32, y: f32, w: f32, lh: f32, paint: bool) f32 {
        if (q.size == 0 or q.modules.len < @as(usize, q.size) * q.size) return 0;
        const n: f32 = @floatFromInt(q.size + 8);
        const side_max = @min(w, lh * 14);
        const m = @max(1, @floor(side_max / n));
        const side = m * n;
        const gap = @round(lh * 0.4);
        if (paint) {
            const ox = x + @round((w - side) / 2);
            const oy = y + gap;
            // A QR code is dark on light whatever the theme.
            f.rect(ox, oy, side, side, .{ 0xFF, 0xFF, 0xFF });
            const qs: usize = q.size;
            for (0..qs) |r| {
                // One quad per run of dark modules.
                var c: usize = 0;
                while (c < qs) {
                    if (q.modules[r * qs + c] == 0) {
                        c += 1;
                        continue;
                    }
                    const start = c;
                    while (c < qs and q.modules[r * qs + c] != 0) c += 1;
                    const fx: f32 = @floatFromInt(start + 4);
                    const fy: f32 = @floatFromInt(r + 4);
                    const run: f32 = @floatFromInt(c - start);
                    f.rect(ox + fx * m, oy + fy * m, run * m, m, .{ 0, 0, 0 });
                }
            }
        }
        return gap + side + gap;
    }

    // ------------------------------------------------------------ primitives

    fn font(f: *Frame, m: Metrics) u8 {
        return f.list.font(m);
    }

    fn rectA(f: *Frame, x: f32, y: f32, w: f32, h: f32, c: Rgb, a: u8) void {
        f.list.push(f.gpa, .{ .rect = .{ .x = x, .y = y, .w = w, .h = h, .color = draw.rgba(c, a) } });
    }

    fn rect(f: *Frame, x: f32, y: f32, w: f32, h: f32, c: Rgb) void {
        f.rectA(x, y, w, h, c, 255);
    }

    /// Draws `s` from (x0, y); returns where it ends.
    fn text(f: *Frame, m: Metrics, x0: f32, y: f32, s: []const u8, c: Rgb, bold: bool) f32 {
        var x = x0;
        var it = (std.unicode.Utf8View.init(s) catch return x).iterator();
        while (it.nextCodepoint()) |cp| x += @floatFromInt(wcwidth.of(cp) * m.cell_w);
        f.list.pushText(f.gpa, x0, y, s, f.font(m), bold, draw.rgba(c, 255));
        return x;
    }

    /// A bar in the brand's accent gradient (the hero's neon ring: blue,
    /// cyan, green from left to right), drawn as narrow slices.
    fn accentBar(f: *Frame, x: f32, y: f32, w: f32, h: f32) void {
        const stops = theme.ui.accent;
        const n: usize = std.math.clamp(@as(usize, @intFromFloat(@max(w, 0) / 6)), 1, 32);
        const nf: f32 = @floatFromInt(n);
        var x0 = x;
        for (0..n) |i| {
            const x1 = if (i + 1 == n) x + w else @round(x + w * @as(f32, @floatFromInt(i + 1)) / nf);
            const t = (@as(f32, @floatFromInt(i)) + 0.5) / nf * @as(f32, @floatFromInt(stops.len - 1));
            const k: usize = @min(@as(usize, @intFromFloat(t)), stops.len - 2);
            f.rect(x0, y, x1 - x0, h, mixBy(stops[k], stops[k + 1], t - @as(f32, @floatFromInt(k))));
            x0 = x1;
        }
    }

    fn outline(f: *Frame, x: f32, y: f32, w: f32, h: f32, t: f32, c: Rgb) void {
        f.rect(x, y, w, t, c);
        f.rect(x, y + h - t, w, t, c);
        f.rect(x, y, t, h, c);
        f.rect(x + w - t, y, t, h, c);
    }

    fn registerButton(f: *Frame, x: f32, y: f32, w: f32, h: f32, id: u32) void {
        f.addHit(.{ .x = x, .y = y, .w = w, .h = h, .action = .{ .button = id } });
    }

    fn addHit(f: *Frame, h: Hit) void {
        if (f.n_hits >= f.hits.len) return;
        f.hits[f.n_hits] = h;
        f.n_hits += 1;
    }

    fn addButton(f: *Frame, m: Metrics, x: f32, y: f32, h: f32, label: []const u8, id: u32, bg: Rgb) f32 {
        const pad: f32 = @floatFromInt(m.cell_w);
        const w = textWidth(m, label) + 2 * pad;
        f.rect(x, y, w, h, bg);
        _ = f.text(m, x + pad, y + (h - @as(f32, @floatFromInt(m.cell_h))) / 2, label, theme.ui.button_text, true);
        f.registerButton(x, y, w, h, id);
        return w;
    }

    fn image(f: *Frame, m: Metrics, store: *const grid_mod.Images, id: u32, x: f32, y: f32, w: f32, h: f32, dw: u32, dh: u32, clip: [4]f32) void {
        f.list.push(f.gpa, .{ .image = .{
            .store = store,
            .id = id,
            .x = x,
            .y = y,
            .w = w,
            .h = h,
            .disp_w = dw,
            .disp_h = dh,
            .clip = clip,
            .font = f.font(m),
            .placeholder = draw.rgba(toneColor(.muted), 255),
        } });
    }

    // ------------------------------------------------------------ data slice

    /// The Data slice: the header strip (title, summary, buttons), then the
    /// items left to right, newest first, each a caption over its image,
    /// clipped to the slice.
    fn drawData(f: *Frame, ui: Metrics, d: DataSlice, r: Rect, s: f32) void {
        f.rect(r.x, r.y, r.w, r.h, theme.ui.panel);
        f.rect(r.x, r.y, r.w, @max(1, @round(s)), theme.ui.border); // the edge to the main slice
        const pad = @round(10 * s);
        const lh: f32 = @floatFromInt(ui.cell_h);
        const head_h = @min(r.h, dataHeaderHeight(ui));
        const ty = r.y + @round((head_h - lh) / 2);
        const x0 = r.x + pad;
        // Header buttons, right to left; the rest of the header toggles.
        var bx = r.x + r.w - pad;
        const bh = @round(head_h * 0.76);
        const by = r.y + @round((head_h - bh) / 2);
        for ([_]?PanelButton{ d.toggle, d.clear }) |ob| if (ob) |b| {
            const bw = f.panelButton(ui, 0, 0, bh, b, s, false);
            if (bx - bw < x0 + lh * 8) break;
            bx -= bw;
            _ = f.panelButton(ui, bx, by, bh, b, s, true);
            bx -= @round(6 * s);
        };
        const tx = f.text(ui, x0, ty, clipText(ui, d.title, @max(0, bx - x0), false), theme.ui.text, true);
        if (d.summary.len > 0) {
            const room = bx - tx - lh;
            if (room > 0) _ = f.text(ui, tx + lh, ty, clipText(ui, d.summary, room, false), toneColor(d.summary_tone), false);
        }
        if (d.toggle) |t| f.registerButton(r.x, r.y, @max(0, bx - r.x), head_h, t.id);
        if (d.collapsed or d.items.len == 0) return;
        // Items, left to right.
        const top = r.y + head_h;
        const bottom = r.y + r.h;
        const right = r.x + r.w - pad;
        const img_y = top + @round(lh * 1.3);
        const img_h = bottom - pad - img_y;
        if (img_h < lh) return;
        var x = x0;
        for (d.items) |it| {
            const room = right - x;
            if (room < lh * 4) break;
            const fit: [2]f32 = if (it.image != null and d.images != null)
                fitImage(it.w, it.h, @min(room, @max(lh * 4, r.w * 0.6)), img_h)
            else
                .{ 0, 0 };
            const cap_w = @min(room, @max(fit[0], @min(textWidth(ui, it.caption), lh * 12)));
            _ = f.text(ui, x, top, clipText(ui, it.caption, cap_w, false), toneColor(.muted), false);
            if (fit[0] >= 1 and fit[1] >= 1) f.image(ui, d.images.?, it.image.?, x, img_y, fit[0], fit[1], @intFromFloat(fit[0]), @intFromFloat(fit[1]), .{ r.x, top, right, bottom });
            x += @max(fit[0], cap_w) + pad * 2;
        }
    }

    // ------------------------------------------------------------ top bar

    /// The top bar (see `TopBar`).
    fn drawTopBar(f: *Frame, ui: Metrics, tb: TopBar, W: f32, h: f32, s: f32) void {
        f.rect(0, 0, W, h, theme.ui.bar);
        const pad = @round(8 * s);
        var x: f32 = pad;
        if (tb.accent) |a| {
            f.rect(0, 0, @round(4 * s), h, a);
            x += @round(4 * s);
        }
        const ty = @round((h - @as(f32, @floatFromInt(ui.cell_h))) / 2);
        var right_w: f32 = 0;
        // Buttons first (right to left), then the right-hand text left of them.
        if (tb.buttons.len > 0) {
            const bh = @round(h * 0.78);
            const by = @round((h - bh) / 2);
            var bx = W - pad;
            var i = tb.buttons.len;
            while (i > 0) {
                i -= 1;
                const b = tb.buttons[i];
                const bw = textWidth(ui, b.label) + 2 * @as(f32, @floatFromInt(ui.cell_w));
                bx -= bw;
                _ = f.addButton(ui, bx, by, bh, b.label, b.id, if (b.active) theme.ui.button_active else theme.ui.button);
                if (b.active) f.accentBar(bx, by + bh - @max(2, @round(2 * s)), bw, @max(2, @round(2 * s)));
                bx -= @round(6 * s);
            }
            right_w = W - bx;
        }
        if (tb.right.len > 0) {
            const tw = textWidth(ui, tb.right);
            if (tb.right_badge) {
                const bw = tw + 2 * pad;
                const bh = @round(h * 0.8);
                const bx = W - right_w - pad - bw;
                f.rect(bx, @round((h - bh) / 2), bw, bh, theme.ui.badge_bg);
                _ = f.text(ui, bx + pad, ty, tb.right, theme.ui.badge_fg, true);
                right_w += bw + pad;
            } else {
                _ = f.text(ui, W - right_w - pad - tw, ty, tb.right, toneColor(tb.right_tone), false);
                right_w += tw + pad;
            }
        }
        if (tb.tabs.len > 0 or tb.add_id != null) return f.drawTabs(ui, tb, x, W - right_w - pad, h, s);
        // Title, cut to the space left of the right-hand text.
        const avail = W - x - right_w - 2 * pad;
        _ = f.text(ui, x, ty, clipText(ui, tb.title, avail, false), theme.ui.text, true);
    }

    /// The project tabs from `x0` to `x1`: each a dot in its project colour
    /// (in the warm attention colour while its program waits for an
    /// answer) and its name; the active one on a pill a step lighter than
    /// the bar with the neon accent underline, the others text only and
    /// dimmer; a neutral count pill for background tasks, an optional
    /// close box, then the optional "+". No outlines. Tabs share the room
    /// when it is short.
    fn drawTabs(f: *Frame, ui: Metrics, tb: TopBar, x0: f32, x1: f32, h: f32, s: f32) void {
        const cw: f32 = @floatFromInt(ui.cell_w);
        const gap = @round(4 * s);
        const th = @round(h * 0.8);
        const ty = h - th;
        const add_w: f32 = if (tb.add_id != null) 3 * cw else 0;
        const room = @max(0, x1 - x0 - add_w - gap);
        const n: f32 = @floatFromInt(@max(tb.tabs.len, 1));
        const max_each = @max(4 * cw, room / n - gap);
        var x = x0;
        for (tb.tabs) |t| {
            const close_w: f32 = if (t.close_id != null) 2 * cw else 0;
            const dot_w: f32 = 2 * cw;
            const badge_w: f32 = if (t.badge.len > 0) textWidth(ui, t.badge) + 2 * cw else 0;
            const natural = textWidth(ui, t.label) + 2 * cw + close_w + dot_w + badge_w;
            const w = @min(natural, @max(max_each, 3 * cw));
            if (x + w > x1) break;
            // The active tab: a pill a step lighter than the bar with a
            // neon underline; the others are text only. No outlines.
            if (t.active) {
                f.rect(x, ty, w, th, theme.ui.tab_active);
                f.accentBar(x, ty + th - @max(2, @round(2 * s)), w, @max(2, @round(2 * s)));
            }
            var tx = x + cw;
            const text_y = ty + @round((th - @as(f32, @floatFromInt(ui.cell_h))) / 2);
            // The project's dot; in the warm sun colour while its program
            // waits for an answer.
            const dot: Rgb = if (t.attention) theme.ui.attention else if (t.active) t.color else mixBy(t.color, theme.ui.bar, 0.35);
            _ = f.text(ui, tx, text_y, "\u{25CF}", dot, true);
            tx += 2 * cw;
            const label_room = @max(0, x + w - cw - close_w - badge_w - tx);
            const fg: Rgb = if (t.active) theme.ui.tab_text else theme.ui.tab_text_inactive;
            _ = f.text(ui, tx, text_y, clipText(ui, t.label, label_room, false), fg, t.active);
            f.registerButton(x, ty, w - close_w - badge_w, th, t.id);
            if (t.badge.len > 0) {
                // A filled pill left of the close box: the tab's running
                // background tasks.
                const bx = x + w - close_w - badge_w + @round(cw / 4);
                const bw = badge_w - @round(cw / 2);
                const bh = @round(@as(f32, @floatFromInt(ui.cell_h)) * 1.1);
                const by = ty + @round((th - bh) / 2);
                f.rect(bx, by, bw, bh, theme.ui.pill_bg);
                _ = f.text(ui, bx + @round((bw - textWidth(ui, t.badge)) / 2), text_y, t.badge, theme.ui.pill_fg, true);
                f.registerButton(x + w - close_w - badge_w, ty, badge_w, th, t.badge_id orelse t.id);
            }
            if (t.close_id) |cid| {
                const cx = x + w - close_w;
                _ = f.text(ui, cx + @round(cw / 2), text_y, "\u{00D7}", fg, false);
                f.registerButton(cx, ty, close_w, th, cid);
            }
            x += w + gap;
        }
        if (tb.add_id) |aid| if (x + add_w <= x1 + gap) {
            f.rect(x, ty, add_w, th, theme.ui.button);
            const text_y = ty + @round((th - @as(f32, @floatFromInt(ui.cell_h))) / 2);
            _ = f.text(ui, x + cw, text_y, "+", theme.ui.button_text, true);
            f.registerButton(x, ty, add_w, th, aid);
        };
    }

    // ------------------------------------------------------------ terminal

    fn zoomed(f: *const Frame, em: f32) f32 {
        if (f.zoom_steps == 0) return em;
        const z = std.math.pow(f32, 1.1, @floatFromInt(f.zoom_steps));
        return std.math.clamp(@round(em * z * 2) / 2, 5, 120);
    }

    /// Font metrics for the grid: fitted to the remote grid (fitEm), or the
    /// fixed size.
    fn cellMetrics(f: *Frame, grid: *const Grid, w: f32, h: f32, s: f32) Metrics {
        switch (f.sizing) {
            .fixed_em => |em| return f.fonts.metrics(f.zoomed(@round(em * s * 2) / 2)),
            .fit_grid => {},
        }
        const cols = @max(grid.cols, 1);
        const asp = f.fonts.aspect();
        const pad = 4 * s;
        const aw = @max(1, w - 2 * pad);
        var em = fitEm(aw, @max(1, h - 2 * pad), cols, @max(grid.rows, 1), asp.w_per_em, asp.h_per_em, s);
        var m = f.fonts.metrics(em);
        // Rounding must never push the columns past the edge.
        while (em > 5 and @as(f32, @floatFromInt(m.cell_w * cols)) > aw) {
            em -= 0.5;
            m = f.fonts.metrics(em);
        }
        if (f.zoom_steps != 0) m = f.fonts.metrics(f.zoomed(em));
        return m;
    }

    fn drawGrid(f: *Frame, g: *const Grid, sel: ?Selection, m: Metrics, W: f32, y0: f32, area_h: f32, s: f32) void {
        const cw: f32 = @floatFromInt(m.cell_w);
        const ch: f32 = @floatFromInt(m.cell_h);
        const gw = cw * @as(f32, @floatFromInt(g.cols));
        const pad = @round(4 * s);
        // Rows that fit; the rest scroll out at the top (followTop).
        const fit_rows: u16 = @intFromFloat(std.math.clamp(@floor((area_h - 2 * pad) / ch), 1, @as(f32, @floatFromInt(g.rows))));
        const follow = followTop(g.rows, fit_rows, g.cursor_y, lastContentRow(g));
        f.scroll_back = @min(f.scroll_back, follow);
        const first = follow - f.scroll_back;
        const gh = ch * @as(f32, @floatFromInt(g.rows - first));
        // Centred across, top-aligned (no empty band above the terminal);
        // pinned to the left when zoomed past the window.
        const ox = @round(@max(pad, (W - gw) / 2));
        const oy = y0 + pad;
        const H = y0 + area_h;
        f.cells = .{ .ox = ox, .oy = oy, .cw = cw, .ch = ch, .cols = g.cols, .rows = g.rows, .first_row = first };
        const t = f.term;
        const fi = f.font(m);
        // Pass 1: cell backgrounds (cursor and selection come later, over images).
        for (first..g.rows) |y| {
            const py = oy + ch * @as(f32, @floatFromInt(y - first));
            if (py >= H) break;
            for (g.row(y), 0..) |c, x| {
                if (c.kind == .continuation) continue;
                const px = ox + cw * @as(f32, @floatFromInt(x));
                if (px >= W) break;
                const cells: u32 = if (c.kind == .wide) 2 else 1;
                const bg = t.resolveBg(c.bg);
                const hpx = @min(ch, H - py);
                if (!std.mem.eql(u8, &bg, &t.bg)) f.rect(px, py, cw * @as(f32, @floatFromInt(cells)), hpx, bg);
            }
        }
        // Pass 2: inline images, clipped to the grid and the window.
        const has_images = f.drawImages(g, m, ox, oy - ch * @as(f32, @floatFromInt(first)), oy, @min(ox + gw, W), @min(oy + gh, H));
        // Pass 3: cursor, selection, glyphs and decorations.
        for (first..g.rows) |y| {
            const py = oy + ch * @as(f32, @floatFromInt(y - first));
            if (py >= H) break;
            for (g.row(y), 0..) |c, x| {
                if (c.kind == .continuation) continue;
                const px = ox + cw * @as(f32, @floatFromInt(x));
                if (px >= W) break;
                const cells: u32 = if (c.kind == .wide) 2 else 1;
                var fg = t.resolveFg(c.fg);
                var bg = t.resolveBg(c.bg);
                var over: ?u8 = null; // alpha of a cursor / selection fill
                if (g.cursor_visible and x == g.cursor_x and y == g.cursor_y) {
                    fg = t.bg;
                    bg = t.cursor;
                    over = 255;
                } else if (sel) |sl| if (sl.contains(x, y)) {
                    bg = t.selection;
                    // Translucent where images could be under it.
                    over = if (has_images) 170 else 255;
                };
                if (c.attrs.dim) fg = mix(fg, bg);
                const wpx = cw * @as(f32, @floatFromInt(cells));
                // Clip the last row/column to the grid area (zoomed past the window).
                const hpx = @min(ch, H - py);
                if (over) |a| f.rectA(px, py, wpx, hpx, bg, a);
                if (c.cp != ' ') f.list.push(f.gpa, .{ .glyph = .{
                    .x = px,
                    .y = py,
                    .cp = c.cp,
                    .cells = @intCast(cells),
                    .style = .{ .bold = c.attrs.bold, .italic = c.attrs.italic },
                    .font = fi,
                    .color = draw.rgba(fg, 255),
                } });
                const stroke: f32 = @floatFromInt(m.stroke);
                if (c.attrs.underline) f.rect(px, py + @as(f32, @floatFromInt(m.underline_y)), wpx, stroke, fg);
                if (c.attrs.strike) f.rect(px, py + @round(m.baseline * 0.62), wpx, stroke, fg);
            }
        }
    }

    /// Emits the grid's image placements (above backgrounds, below text).
    /// (ox, oy): row 0's corner (above the slice when rows scrolled out);
    /// clip_y0: the top of the first row drawn. True if any is in view.
    fn drawImages(f: *Frame, g: *const Grid, m: Metrics, ox: f32, oy: f32, clip_y0: f32, clip_x1: f32, clip_y1: f32) bool {
        const cw: f32 = @floatFromInt(m.cell_w);
        const ch: f32 = @floatFromInt(m.cell_h);
        var any = false;
        for (g.images.placements.items) |p| {
            const x = ox + cw * @as(f32, @floatFromInt(p.col));
            const y = oy + ch * @as(f32, @floatFromInt(p.row));
            const w = cw * @as(f32, @floatFromInt(p.cols));
            const h = ch * @as(f32, @floatFromInt(p.rows));
            if (x >= clip_x1 or y >= clip_y1 or x + w <= ox or y + h <= clip_y0) continue;
            const dw: u32 = @intCast(@min(@as(u64, m.cell_w) * p.cols, 1 << 16));
            const dh: u32 = @intCast(@min(@as(u64, m.cell_h) * p.rows, 1 << 16));
            f.image(m, &g.images, p.id, x, y, w, h, dw, dh, .{ ox, clip_y0, clip_x1, clip_y1 });
            any = true;
        }
        return any;
    }

    fn drawMessage(f: *Frame, ui: Metrics, msg: Message, W: f32, y0: f32, H: f32, s: f32) void {
        const big = f.fonts.metrics(@round(20 * s));
        const lh: f32 = @floatFromInt(ui.cell_h);
        var y = y0 + @round(H * 0.28);
        _ = f.text(big, centreX(W, textWidth(big, msg.title)), y, msg.title, toneColor(msg.title_tone), true);
        y += @as(f32, @floatFromInt(big.cell_h)) + lh;
        for (msg.lines) |l| {
            _ = f.text(ui, centreX(W, textWidth(ui, l)), y, l, toneColor(.muted), false);
            y += lh * 1.4;
        }
        if (msg.button) |b| {
            y += lh;
            const bh = @round(lh * 2.2);
            const bw = textWidth(ui, b.label) + 2 * @as(f32, @floatFromInt(ui.cell_w));
            _ = f.addButton(ui, centreX(W, bw), y, bh, b.label, b.id, theme.ui.button);
            y += bh + lh;
        }
        if (msg.detail.len > 0) _ = f.text(ui, centreX(W, textWidth(ui, msg.detail)), y, msg.detail, toneColor(msg.detail_tone), false);
    }

    // ------------------------------------------------------------ bottom

    /// The answer buttons: one row, centred, all the same width (at least
    /// five cells), sized from the pane so they are easy to hit.
    fn drawAnswerBar(f: *Frame, m: Metrics, y: f32, W: f32, h: f32, s: f32, shown: []const input.Answer) void {
        f.rect(0, y, W, h, theme.ui.bar);
        const gap = @round(8 * s);
        const bh = @round(h * 0.78);
        const by = y + @round((h - bh) / 2);
        const cw: f32 = @floatFromInt(m.cell_w);
        if (shown.len == 0) return;
        var bw: f32 = cw * 5;
        for (shown) |a| bw = @max(bw, textWidth(m, a.label) + 2 * cw);
        const n: f32 = @floatFromInt(shown.len);
        // Narrow window: shrink to fit.
        bw = @max(cw * 2, @min(bw, @floor((W - gap * (n + 1)) / n)));
        var x = @round(@max(gap, (W - (bw * n + gap * (n - 1))) / 2));
        for (shown) |a| {
            f.rect(x, by, bw, bh, theme.ui.button);
            const lw = textWidth(m, a.label);
            _ = f.text(m, x + @round(@max(0, (bw - lw) / 2)), by + @round((bh - @as(f32, @floatFromInt(m.cell_h))) / 2), clipText(m, a.label, bw, false), theme.ui.button_text, true);
            f.addHit(.{ .x = x, .y = by, .w = bw, .h = bh, .action = .{ .answer = a.key } });
            x += bw + gap;
        }
    }

    fn drawStatus(f: *Frame, ui: Metrics, st: StatusLine, y: f32, W: f32, h: f32, s: f32) void {
        f.rect(0, y, W, h, theme.ui.bar);
        const ty = y + @round((h - @as(f32, @floatFromInt(ui.cell_h))) / 2);
        const pad = @round(8 * s);
        const dot = @round(@as(f32, @floatFromInt(ui.cell_h)) * 0.45);
        f.rect(pad, y + @round((h - dot) / 2), dot, dot, toneColor(st.tone));
        var x = pad + dot + pad;
        x = f.text(ui, x, ty, st.label, theme.ui.text, true);
        if (st.extra.len > 0) {
            x = f.text(ui, x, ty, "  \u{00B7}  ", toneColor(.muted), false);
            x = f.text(ui, x, ty, st.extra, toneColor(st.extra_tone), false);
        }
        if (st.tasks.len > 0) {
            x = f.text(ui, x, ty, "  \u{00B7}  ", toneColor(.muted), false);
            const x0 = x;
            x = f.text(ui, x, ty, st.tasks, theme.ui.focus, true);
            if (st.tasks_id) |tid| {
                f.rect(x0, ty + @as(f32, @floatFromInt(ui.cell_h)) - @max(1, @round(s)), x - x0, @max(1, @round(s)), theme.ui.focus);
                f.registerButton(x0, y, x - x0, h, tid);
            }
        }
        if (st.right.len > 0) _ = f.text(ui, W - pad - textWidth(ui, st.right), ty, st.right, toneColor(.muted), false);
    }

    /// A boxed line right-aligned just above `bottom` (no hit area).
    fn drawToast(f: *Frame, ui: Metrics, t: Toast, W: f32, bottom: f32, s: f32) void {
        const pad = @round(10 * s);
        const ch: f32 = @floatFromInt(ui.cell_h);
        const text_s = clipText(ui, t.text, @max(0, W - 4 * pad), false);
        const w = textWidth(ui, text_s) + 2 * pad;
        const h = @round(ch * 1.8);
        const x = @max(0, W - w - pad);
        const y = @max(0, bottom - h - pad);
        f.rect(x, y, w, h, theme.ui.bar);
        f.outline(x, y, w, h, @max(1, @round(s)), toneColor(if (t.tone == .normal) .muted else t.tone));
        _ = f.text(ui, x + pad, y + @round((h - ch) / 2), text_s, toneColor(t.tone), false);
    }

    fn panelButton(f: *Frame, m: Metrics, x: f32, y: f32, h: f32, b: PanelButton, s: f32, paint: bool) f32 {
        const pad: f32 = @floatFromInt(m.cell_w * 2);
        const w = textWidth(m, b.label) + 2 * pad;
        if (!paint) return w;
        const bg: Rgb = switch (b.tone) {
            .good => theme.ui.approve,
            .bad => theme.ui.deny,
            .warn => theme.ui.caution,
            else => theme.ui.button,
        };
        f.rect(x, y, w, h, bg);
        if (b.focused) f.outline(x, y, w, h, @max(2, @round(2 * s)), theme.ui.focus);
        _ = f.text(m, x + pad, y + @round((h - @as(f32, @floatFromInt(m.cell_h))) / 2), b.label, theme.ui.button_text, true);
        f.registerButton(x, y, w, h, b.id);
        return w;
    }

    /// The input box's Send: a `w` wide button, label centred.
    fn sendButton(f: *Frame, m: Metrics, x: f32, y: f32, w: f32, h: f32, b: PanelButton, s: f32) void {
        f.rect(x, y, w, h, theme.ui.button_active);
        f.accentBar(x, y + h - @max(2, @round(2 * s)), w, @max(2, @round(2 * s)));
        if (b.focused) f.outline(x, y, w, h, @max(2, @round(2 * s)), theme.ui.focus);
        const lw = textWidth(m, b.label);
        _ = f.text(m, x + @round(@max(0, (w - lw) / 2)), y + @round((h - @as(f32, @floatFromInt(m.cell_h))) / 2), clipText(m, b.label, w, false), theme.ui.button_text, true);
        f.registerButton(x, y, w, h, b.id);
    }

    /// A pane's height in pixels: its own, or its content's natural height.
    fn paneHeight(m: Metrics, p: Pane, s: f32) f32 {
        if (p.height > 0) return @round(p.height * s);
        const ch: f32 = @floatFromInt(m.cell_h);
        return switch (p.content) {
            .answers, .buttons => @round(ch * 2.6),
            .field => @round(ch * 2.8),
        };
    }

    fn drawPane(f: *Frame, ui: Metrics, p: Pane, r: Rect, s: f32) void {
        if (r.h < 1) return;
        switch (p.content) {
            .answers => |list| f.drawAnswerBar(ui, r.y, r.w, r.h, s, list),
            .buttons => |bs| {
                f.rect(r.x, r.y, r.w, r.h, theme.ui.bar);
                const gap = @round(6 * s);
                const bh = @min(@round(r.h * 0.72), @round(@as(f32, @floatFromInt(ui.cell_h)) * 2));
                const by = r.y + @round((r.h - bh) / 2);
                var total: f32 = 0;
                for (bs) |b| total += f.panelButton(ui, 0, 0, bh, b, s, false) + gap;
                var x = r.x + @round(@max(gap, (r.w - total + gap) / 2));
                for (bs) |b| x += f.panelButton(ui, x, by, bh, b, s, true) + gap;
            },
            .field => |fl| {
                f.rect(r.x, r.y, r.w, r.h, theme.ui.bar);
                const pad = @round(8 * s);
                // Send at the right end, as tall as the box.
                var send_w: f32 = 0;
                if (p.send) |b| {
                    const bh = @max(1, r.h - 2 * pad);
                    const bw = @max(textWidth(ui, b.label) + 4 * @as(f32, @floatFromInt(ui.cell_w)), @as(f32, @floatFromInt(ui.cell_w)) * 8);
                    f.sendButton(ui, r.x + r.w - pad - bw, r.y + pad, bw, bh, b, s);
                    send_w = bw + pad;
                }
                if (p.keyboard) |b| {
                    const bh = @max(1, r.h - 2 * pad);
                    const bw = textWidth(ui, b.label) + 4 * @as(f32, @floatFromInt(ui.cell_w));
                    _ = f.panelButton(ui, r.x + r.w - pad - send_w - bw, r.y + pad, bh, b, s, true);
                    send_w += bw + pad;
                }
                const box: Rect = .{ .x = r.x + pad, .y = r.y + pad, .w = @max(1, r.w - 2 * pad - send_w), .h = @max(1, r.h - 2 * pad) };
                f.rect(box.x, box.y, box.w, box.h, theme.ui.field);
                f.outline(box.x, box.y, box.w, box.h, if (fl.focused) @max(2, @round(2 * s)) else @max(1, @round(s)), if (fl.focused) theme.ui.focus else theme.ui.border);
                const cw: f32 = @floatFromInt(ui.cell_w);
                const lh: f32 = @floatFromInt(ui.cell_h);
                const tx = box.x + cw;
                const ty = box.y + @round((box.h - lh) / 2);
                const inner = box.w - 2 * cw;
                if (fl.value.len == 0) {
                    // The hint stays visible in an empty focused box, after the cursor.
                    const cur = if (fl.focused) @max(2, @round(2 * s)) else 0;
                    if (fl.focused) f.rect(tx, ty, cur, lh, theme.ui.focus);
                    _ = f.text(ui, tx + cur * 2, ty, clipText(ui, fl.hint, inner - cur * 2, false), toneColor(.muted), false);
                } else {
                    const end = f.text(ui, tx, ty, clipText(ui, fl.value, inner - cw, true), theme.ui.text, false);
                    if (fl.focused) f.rect(end, ty, @max(2, @round(2 * s)), lh, theme.ui.focus);
                }
                f.registerButton(box.x, box.y, box.w, box.h, fl.id);
                if (fl.focused) f.noteTextField(box, fl.id, fl.value, lh);
            },
        }
    }

    // ------------------------------------------------------------ panel

    /// Draws (or, with `paint` false, only measures) wrapped text; returns
    /// the height used.
    fn wrapped(f: *Frame, m: Metrics, x: f32, y0: f32, max_w: f32, t: PanelText, paint: bool) f32 {
        const lh: f32 = @round(@as(f32, @floatFromInt(m.cell_h)) * 1.35);
        var y = y0;
        var rest = t.text;
        if (rest.len == 0) return @round(lh * 0.5); // an empty line is a small gap
        while (rest.len > 0) {
            const n = wrapLen(m.cell_w, rest, max_w);
            if (paint) _ = f.text(m, x, y, std.mem.trimEnd(u8, rest[0..n], " "), toneColor(t.tone), t.bold);
            y += lh;
            rest = std.mem.trimStart(u8, rest[n..], " ");
        }
        return y - y0;
    }

    /// One layout pass over the panel's contents, inside the box at (x, y0)
    /// with inner width `w`. Returns the height used. Measuring and drawing
    /// share this code so they always agree.
    fn panelBody(f: *Frame, ui: Metrics, big: Metrics, p: Panel, x: f32, y0: f32, w: f32, s: f32, paint: bool) f32 {
        var y = y0;
        const lh: f32 = @floatFromInt(ui.cell_h);
        y += f.wrapped(big, x, y, w, .{ .text = p.title, .tone = p.title_tone, .bold = true }, paint);
        y += @round(lh * 0.4);
        for (p.lines) |l| y += f.wrapped(ui, x, y, w, l, paint);
        if (p.qr) |q| y += f.drawQr(q, x, y, w, lh, paint);
        // Rows: text on the left, an optional button on the right.
        if (p.rows.len > 0) {
            y += @round(lh * 0.4);
            const rh = @round(lh * 1.9);
            for (p.rows) |r| {
                if (paint and r.selected) f.rect(x - @round(4 * s), y, w + @round(8 * s), rh, theme.ui.selected_row);
                var tw = w;
                if (r.button) |b| {
                    const bh = @round(rh * 0.8);
                    const bw = f.panelButton(ui, 0, 0, bh, b, s, false);
                    _ = f.panelButton(ui, x + w - bw, y + @round((rh - bh) / 2), bh, b, s, paint);
                    tw = w - bw - @round(8 * s);
                }
                if (paint) _ = f.text(ui, x, y + @round((rh - lh) / 2), clipText(ui, r.text, tw, false), toneColor(r.tone), false);
                y += rh;
            }
        }
        // Fields: a label above a boxed value.
        if (p.fields.len > 0) y += @round(lh * 0.5);
        for (p.fields) |fl| {
            if (paint) _ = f.text(ui, x, y, fl.label, toneColor(.normal), true);
            y += @round(lh * 1.3);
            const fh = @round(lh * 1.9);
            if (paint) {
                f.rect(x, y, w, fh, theme.ui.field);
                f.outline(x, y, w, fh, if (fl.focused) @max(2, @round(2 * s)) else @max(1, @round(s)), if (fl.focused) theme.ui.focus else theme.ui.border);
                const cw: f32 = @floatFromInt(ui.cell_w);
                const tx = x + cw;
                const ty = y + @round((fh - lh) / 2);
                const inner = w - 2 * cw;
                if (fl.choice) {
                    var buf: [96]u8 = undefined;
                    const v = std.fmt.bufPrint(&buf, "\u{2039} {s} \u{203A}", .{fl.value}) catch fl.value;
                    _ = f.text(ui, tx, ty, v, theme.ui.text, true);
                } else if (fl.value.len == 0 and !fl.focused) {
                    _ = f.text(ui, tx, ty, clipText(ui, fl.hint, inner, false), toneColor(.muted), false);
                } else {
                    const shown = clipText(ui, fl.value, inner - cw, true);
                    const end = f.text(ui, tx, ty, shown, theme.ui.text, false);
                    if (fl.focused) f.rect(end, ty, @max(2, @round(2 * s)), lh, theme.ui.focus); // caret
                }
                f.registerButton(x, y, w, fh, fl.id);
                if (fl.focused and !fl.choice) f.noteTextField(.{ .x = x, .y = y, .w = w, .h = fh }, fl.id, fl.value, lh);
            }
            y += fh + @round(lh * 0.5);
        }
        for (p.after) |l| y += f.wrapped(ui, x, y, w, l, paint);
        if (p.note.text.len > 0) {
            y += @round(lh * 0.3);
            y += f.wrapped(ui, x, y, w, p.note, paint);
        }
        // Buttons, right-aligned on one row.
        if (p.buttons.len > 0) {
            y += @round(lh * 0.8);
            const bh = @round(lh * 2.1);
            const gap = @round(8 * s);
            var total: f32 = 0;
            for (p.buttons) |b| total += f.panelButton(ui, 0, 0, bh, b, s, false) + gap;
            var bx = x + w - total + gap;
            for (p.buttons) |b| bx += f.panelButton(ui, bx, y, bh, b, s, paint) + gap;
            y += bh;
        }
        return y - y0;
    }

    fn drawPanel(f: *Frame, ui: Metrics, p: Panel, W: f32, H: f32, s: f32) void {
        // Dim everything behind the panel.
        f.rectA(0, 0, W, H, theme.palette.bg, theme.ui.scrim_alpha);
        const big = f.fonts.metrics(@round(17 * s));
        const pad = @round(20 * s);
        const margin = @round(16 * s);
        const max_inner: f32 = @floatFromInt(ui.cell_w * 78);
        const w = @max(1, @min(W - 2 * margin - 2 * pad, max_inner));
        const h = f.panelBody(ui, big, p, 0, 0, w, s, false);
        const bw = w + 2 * pad;
        const bh = h + 2 * pad;
        const bx = @round(@max(0, (W - bw) / 2));
        const by = @round(@max(0, (H - bh) / 2));
        f.rect(bx, by, bw, bh, theme.ui.panel);
        f.outline(bx, by, bw, bh, @max(1, @round(s)), theme.ui.border);
        _ = f.panelBody(ui, big, p, bx + pad, by + pad, w, s, true);
    }
};

/// What a ContentView draws with: the frame's primitives in its fonts and
/// colours. Buttons report their id through InputSink.button.
pub const Painter = struct {
    f: *Frame,
    /// The chrome's font and the interaction font.
    ui: Metrics,
    act: Metrics,
    /// Device pixels per logical pixel.
    s: f32,
    /// What `fill`, `run` and the tap targets are clipped to (x0, y0, x1,
    /// y1; null: nothing).
    clip: ?[4]f32 = null,

    /// Font metrics for `em` logical pixels, zoomed with Ctrl+= / - like
    /// the terminal.
    pub fn metrics(p: *Painter, em: f32) Metrics {
        return p.f.fonts.metrics(p.f.zoomed(@round(em * p.s * 2) / 2));
    }
    fn clipRect(p: *const Painter, x: f32, y: f32, w: f32, h: f32) ?Rect {
        const c = p.clip orelse return .{ .x = x, .y = y, .w = w, .h = h };
        const x0 = @max(x, c[0]);
        const y0 = @max(y, c[1]);
        const x1 = @min(x + w, c[2]);
        const y1 = @min(y + h, c[3]);
        if (!(x1 > x0 and y1 > y0)) return null;
        return .{ .x = x0, .y = y0, .w = x1 - x0, .h = y1 - y0 };
    }
    /// A filled rectangle, clipped.
    pub fn fill(p: *Painter, x: f32, y: f32, w: f32, h: f32, c: Rgb) void {
        const r = p.clipRect(x, y, w, h) orelse return;
        p.f.rect(r.x, r.y, r.w, r.h, c);
    }
    /// A rectangle outline `t` thick, clipped.
    pub fn frameRect(p: *Painter, x: f32, y: f32, w: f32, h: f32, t: f32, c: Rgb) void {
        p.fill(x, y, w, t, c);
        p.fill(x, y + h - t, w, t, c);
        p.fill(x, y, t, h, c);
        p.fill(x + w - t, y, t, h, c);
    }
    /// Text in any colour and style, clipped (also at `x1` across, when
    /// given). Returns where it ends.
    pub fn run(p: *Painter, m: Metrics, x: f32, y: f32, s: []const u8, c: Rgb, bold: bool, italic: bool, x1: ?f32) f32 {
        var cl: [4]f32 = p.clip orelse .{ -1e9, -1e9, 1e9, 1e9 };
        if (x1) |e| cl[2] = @min(cl[2], e);
        const lh: f32 = @floatFromInt(m.cell_h);
        const end = x + textWidth(m, s);
        if (s.len == 0 or y >= cl[3] or y + lh <= cl[1] or x >= cl[2] or end <= cl[0]) return end;
        const inside = y >= cl[1] and y + lh <= cl[3] and x >= cl[0] and end <= cl[2];
        p.f.list.pushTextStyled(p.f.gpa, x, y, s, p.f.font(m), .{ .bold = bold, .italic = italic }, draw.rgba(c, 255), if (inside) null else cl);
        return end;
    }
    /// A tap target that answers `key` (InputSink.answer), clipped.
    pub fn tapAnswer(p: *Painter, x: f32, y: f32, w: f32, h: f32, key: []const u8) void {
        const r = p.clipRect(x, y, w, h) orelse return;
        p.f.addHit(.{ .x = r.x, .y = r.y, .w = r.w, .h = r.h, .action = .{ .answer = key }, .tap = true });
    }
    /// A tap target that reports `id` (InputSink.button), clipped.
    pub fn tapButton(p: *Painter, x: f32, y: f32, w: f32, h: f32, id: u32) void {
        const r = p.clipRect(x, y, w, h) orelse return;
        p.f.addHit(.{ .x = r.x, .y = r.y, .w = r.w, .h = r.h, .action = .{ .button = id }, .tap = true });
    }

    pub fn rect(p: *Painter, r: Rect, c: Rgb) void {
        p.f.rect(r.x, r.y, r.w, r.h, c);
    }
    /// Text from (x, y) in `tone`; returns where it ends.
    pub fn text(p: *Painter, m: Metrics, x: f32, y: f32, s: []const u8, tone: Tone, bold: bool) f32 {
        return p.f.text(m, x, y, s, toneColor(tone), bold);
    }
    /// Wrapped text in `max_w`; returns the height used.
    pub fn wrapped(p: *Painter, m: Metrics, x: f32, y: f32, max_w: f32, t: PanelText) f32 {
        return p.f.wrapped(m, x, y, max_w, t, true);
    }
    pub fn button(p: *Painter, m: Metrics, x: f32, y: f32, h: f32, b: PanelButton) f32 {
        return p.f.panelButton(m, x, y, h, b, p.s, true);
    }
    /// A centred notice in `r` (like Overlay.screen = .message).
    pub fn message(p: *Painter, r: Rect, msg: Message) void {
        p.f.drawMessage(p.ui, msg, r.w, r.y, r.h, p.s);
    }
};

// ------------------------------------------------------------ pure helpers

fn clampCell(f: f32, n: u16) u16 {
    if (n == 0 or !(f > 0)) return 0; // also catches NaN
    const max: f32 = @floatFromInt(n - 1);
    return @intFromFloat(@min(@floor(f), max));
}

/// How many cells of `cell_w` x `cell_h` pixels fit in `w` x `h` pixels
/// with `pad` pixels on every side. At least 1 x 1, at most 1000 x 1000.
pub fn fitCells(w: f32, h: f32, cell_w: u32, cell_h: u32, pad: f32) [2]u16 {
    const cw: f32 = @floatFromInt(@max(cell_w, 1));
    const ch: f32 = @floatFromInt(@max(cell_h, 1));
    return .{ fitCount((w - 2 * pad) / cw), fitCount((h - 2 * pad) / ch) };
}

fn fitCount(f: f32) u16 {
    if (!(f >= 1)) return 1; // also NaN
    if (f >= 1000) return 1000;
    return @intFromFloat(@floor(f));
}

/// The answer bar's button height at its natural pane height (paneHeight
/// of `.answers`, drawAnswerBar): the hit target size content views match.
pub fn answerButtonHeight(act: Metrics) f32 {
    return @round(@round(@as(f32, @floatFromInt(act.cell_h)) * 2.6) * 0.78);
}

/// The Data slice's header strip.
fn dataHeaderHeight(ui: Metrics) f32 {
    return @round(@as(f32, @floatFromInt(ui.cell_h)) * 2.0);
}

/// What the Data slice's items would like under its header (0: nothing to
/// show): a caption line and the tallest image at up to 1 image pixel per
/// logical pixel, no wider than the slice; at least a few lines.
fn dataContentHeight(ui: Metrics, d: DataSlice, W: f32, s: f32) f32 {
    if (d.items.len == 0) return 0;
    const lh: f32 = @floatFromInt(ui.cell_h);
    const pad = @round(10 * s);
    const inner = @max(1, W - 2 * pad);
    var tallest: f32 = lh * 3;
    for (d.items) |it| {
        if (it.image == null) continue;
        if (it.w == 0 or it.h == 0) {
            tallest = @max(tallest, lh * 6);
            continue;
        }
        const fw: f32 = @floatFromInt(it.w);
        const fh: f32 = @floatFromInt(it.h);
        const k = @min(s, inner / fw);
        tallest = @max(tallest, @round(fh * k));
    }
    return pad + @round(lh * 1.3) + tallest + pad;
}

/// Fits a `w x h` image into `box_w x box_h` keeping its aspect ratio,
/// never more than 2 pixels per image pixel. Unknown size: a 4:3 box.
pub fn fitImage(w: u32, h: u32, box_w: f32, box_h: f32) [2]f32 {
    if (box_w < 1 or box_h < 1) return .{ 0, 0 };
    if (w == 0 or h == 0) return .{ @round(@min(box_w, box_h * 4 / 3)), @round(@min(box_h, box_w * 3 / 4)) };
    const fw: f32 = @floatFromInt(w);
    const fh: f32 = @floatFromInt(h);
    const k = @min(@min(box_w / fw, box_h / fh), 2);
    return .{ @max(1, @round(fw * k)), @max(1, @round(fh * k)) };
}

/// The top bar's height; on touch, tall enough that the tabs (80% of it)
/// are at least `touch_target` logical px.
fn topBarHeight(ui: Metrics, touch: bool, s: f32) f32 {
    const h = @round(@as(f32, @floatFromInt(ui.cell_h)) * 1.8);
    return if (touch) @max(h, @ceil(touch_target * s / 0.8)) else h;
}

/// Mixes `c` towards `to` by `k` (0..1).
fn mixBy(c: Rgb, to: Rgb, k: f32) Rgb {
    var out: Rgb = undefined;
    for (0..3) |i| {
        const a: f32 = @floatFromInt(c[i]);
        const b: f32 = @floatFromInt(to[i]);
        out[i] = @intFromFloat(@round(a + (b - a) * k));
    }
    return out;
}

/// Smallest font size (logical px) `fitEm` shrinks to for the rows' sake.
pub const readable_em: f32 = 12;

/// The remote grid's font size (em, device px) in a `w x h` px main
/// slice: the size at which its columns fill the width, made smaller to
/// show every row too, but not below `readable_em` (then the rows scroll,
/// see `followTop`; the columns always fit). Between 5 px and 32 logical px.
pub fn fitEm(w: f32, h: f32, cols: u16, rows: u16, w_per_em: f32, h_per_em: f32, s: f32) f32 {
    const by_w = w / (@as(f32, @floatFromInt(@max(cols, 1))) * @max(w_per_em, 0.01));
    const by_h = h / (@as(f32, @floatFromInt(@max(rows, 1))) * @max(h_per_em, 0.01));
    // Unknown width (NaN, inf, <= 0): the smallest size.
    if (!std.math.isFinite(by_w) or !(by_w > 0)) return 5;
    const em = @min(by_w, @max(if (std.math.isFinite(by_h)) by_h else 0, readable_em * s));
    return std.math.clamp(@floor(em * 2) / 2, 5, @max(5, 32 * s));
}

/// The first grid row to show when only `visible` of `rows` fit: the
/// lowest rows with content (`last`: the last non-blank row), keeping the
/// cursor in view; 0 when everything fits.
pub fn followTop(rows: u16, visible: u16, cursor: u16, last: u16) u16 {
    if (visible == 0 or visible >= rows) return 0;
    const bottom = @max(cursor, last);
    var first = (bottom + 1) -| visible;
    first = @min(first, rows - visible);
    return @min(first, cursor);
}

/// The last row of `g` with a visible character (0 if none).
fn lastContentRow(g: *const Grid) u16 {
    var y: usize = g.rows;
    while (y > 0) {
        y -= 1;
        for (g.row(y)) |c| if (c.cp != ' ' and c.cp != 0) return @intCast(y);
    }
    return 0;
}

fn mix(a: Rgb, b: Rgb) Rgb {
    return .{
        @intCast((@as(u16, a[0]) + b[0]) / 2),
        @intCast((@as(u16, a[1]) + b[1]) / 2),
        @intCast((@as(u16, a[2]) + b[2]) / 2),
    };
}

fn centreX(w: f32, tw: f32) f32 {
    return @round(@max(0, (w - tw) / 2));
}

/// Width of `s` in pixels in font `m` (cell widths from wcwidth).
pub fn textWidth(m: Metrics, s: []const u8) f32 {
    var n: u32 = 0;
    var it = (std.unicode.Utf8View.init(s) catch return 0).iterator();
    while (it.nextCodepoint()) |cp| n += wcwidth.of(cp);
    return @floatFromInt(n * m.cell_w);
}

/// Byte length of the next line of `s` that fits `max_w` pixels: breaks
/// after the last space that fits, or mid-word if a word alone is too
/// long. Always at least one codepoint (no endless loop in a narrow box).
pub fn wrapLen(cell_w: u32, s: []const u8, max_w: f32) usize {
    var used: f32 = 0;
    var last_space: ?usize = null;
    var i: usize = 0;
    while (i < s.len) {
        const n = std.unicode.utf8ByteSequenceLength(s[i]) catch 1;
        const end = @min(i + n, s.len);
        const cp = std.unicode.utf8Decode(s[i..end]) catch 0xFFFD;
        const cw: f32 = @floatFromInt(wcwidth.of(cp) * cell_w);
        if (used + cw > max_w and i > 0) return last_space orelse i;
        if (cp == ' ') last_space = end;
        used += cw;
        i = end;
    }
    return s.len;
}

/// `s` cut to `max_w` pixels, keeping its end (typed text, paths) when
/// `keep_end`, else its start.
pub fn clipText(m: Metrics, s: []const u8, max_w: f32, keep_end: bool) []const u8 {
    if (textWidth(m, s) <= max_w) return s;
    if (!keep_end) return s[0..fitLen(m.cell_w, s, max_w)];
    var start: usize = 0;
    while (start < s.len and textWidth(m, s[start..]) > max_w) {
        start += std.unicode.utf8ByteSequenceLength(s[start]) catch 1;
    }
    return s[@min(start, s.len)..];
}

/// Bytes of `s` whose text fits `max_w` pixels.
fn fitLen(cell_w: u32, s: []const u8, max_w: f32) usize {
    var used: f32 = 0;
    var i: usize = 0;
    while (i < s.len) {
        const n = std.unicode.utf8ByteSequenceLength(s[i]) catch 1;
        const end = @min(i + n, s.len);
        const cp = std.unicode.utf8Decode(s[i..end]) catch 0xFFFD;
        const cw: f32 = @floatFromInt(wcwidth.of(cp) * cell_w);
        if (used + cw > max_w) return i;
        used += cw;
        i = end;
    }
    return s.len;
}

// ------------------------------------------------------------------ tests

test "fitCells" {
    try std.testing.expectEqual([2]u16{ 80, 24 }, fitCells(808, 488, 10, 20, 4));
    try std.testing.expectEqual([2]u16{ 79, 23 }, fitCells(807, 487, 10, 20, 4));
    try std.testing.expectEqual([2]u16{ 1, 1 }, fitCells(0, 0, 10, 20, 4));
    try std.testing.expectEqual([2]u16{ 1, 1 }, fitCells(-50, std.math.nan(f32), 10, 20, 4));
    try std.testing.expectEqual([2]u16{ 1000, 1000 }, fitCells(1e9, 1e9, 1, 1, 0));
    try std.testing.expectEqual([2]u16{ 100, 50 }, fitCells(100, 50, 0, 0, 0));
}

test "selection contains" {
    const s: Selection = .{ .start_col = 5, .start_row = 1, .end_col = 2, .end_row = 3 };
    try std.testing.expect(!s.contains(4, 1));
    try std.testing.expect(s.contains(5, 1));
    try std.testing.expect(s.contains(0, 2));
    try std.testing.expect(s.contains(2, 3));
    try std.testing.expect(!s.contains(3, 3));
    try std.testing.expect(!s.contains(0, 0));
}

test "wrapLen" {
    try std.testing.expectEqual(@as(usize, 11), wrapLen(1, "hello world", 20));
    try std.testing.expectEqual(@as(usize, 6), wrapLen(1, "hello world", 8));
    try std.testing.expectEqual(@as(usize, 3), wrapLen(1, "abcdef", 3));
    try std.testing.expectEqual(@as(usize, 1), wrapLen(10, "abc", 1));
    try std.testing.expectEqual(@as(usize, 0), wrapLen(1, "", 5));
}

test "data slice sizing (datafeed's rule) and image fitting" {
    // A header strip while empty or collapsed; grows with content, capped.
    try std.testing.expectEqual(@as(f32, 26), dataHeight(500, 26, 0, false));
    try std.testing.expectEqual(@as(f32, 26), dataHeight(500, 26, 300, true));
    try std.testing.expectEqual(@as(f32, 26 + 80), dataHeight(500, 26, 80, false));
    try std.testing.expectEqual(@as(f32, @floatCast(@floor(500 * datafeed.max_share))), dataHeight(500, 26, 900, false));
    // Aspect kept, at most 2x, fits the box.
    try std.testing.expectEqual([2]f32{ 8, 4 }, fitImage(4, 2, 300, 300));
    try std.testing.expectEqual([2]f32{ 300, 150 }, fitImage(640, 320, 300, 300));
    try std.testing.expectEqual([2]f32{ 100, 200 }, fitImage(320, 640, 300, 200));
    const unknown = fitImage(0, 0, 300, 300);
    try std.testing.expect(unknown[0] <= 300 and unknown[1] <= 300 and unknown[0] > 0);
    try std.testing.expectEqual([2]f32{ 0, 0 }, fitImage(4, 4, 0, 10));
}

test "Rect contains" {
    const r: Rect = .{ .x = 10, .y = 20, .w = 5, .h = 5 };
    try std.testing.expect(r.contains(10, 20));
    try std.testing.expect(!r.contains(15, 20));
    try std.testing.expect(!r.contains(9.9, 22));
}

test "remote grid font: fills the width, readable minimum, rows follow the cursor" {
    // 120 x 40 cells (0.6 x 1.2 em) in 990 x 470 px at scale 1: the width
    // allows 13.75, the height 9.79: the readable minimum (12) wins and the
    // rows scroll.
    try std.testing.expectEqual(@as(f32, 12), fitEm(990, 470, 120, 40, 0.6, 1.2, 1));
    // Plenty of height: the width decides.
    try std.testing.expectEqual(@as(f32, 13.5), fitEm(990, 2000, 120, 40, 0.6, 1.2, 1));
    // Small grid: capped at 32 logical px.
    try std.testing.expectEqual(@as(f32, 32), fitEm(2000, 2000, 20, 5, 0.6, 1.2, 1));
    try std.testing.expectEqual(@as(f32, 64), fitEm(4000, 4000, 20, 5, 0.6, 1.2, 2));
    // Very narrow: the columns still fit (below the readable size).
    try std.testing.expectEqual(@as(f32, 5), fitEm(100, 500, 120, 40, 0.6, 1.2, 1));
    try std.testing.expectEqual(@as(f32, 5), fitEm(std.math.nan(f32), 0, 0, 0, 0, 0, 1));
    // Everything fits: from the top.
    try std.testing.expectEqual(@as(u16, 0), followTop(30, 30, 29, 29));
    try std.testing.expectEqual(@as(u16, 0), followTop(30, 40, 5, 5));
    // A fresh screen, cursor near the top: the top.
    try std.testing.expectEqual(@as(u16, 0), followTop(40, 25, 3, 3));
    // Content to the bottom: the bottom rows.
    try std.testing.expectEqual(@as(u16, 15), followTop(40, 25, 30, 39));
    // Content below the cursor, but the cursor stays in view.
    try std.testing.expectEqual(@as(u16, 10), followTop(40, 5, 10, 39));
}

test "textEdit: append, delete, replace in the middle, multibyte" {
    var e = textEdit("ab", "abc");
    try std.testing.expectEqual(@as(usize, 0), e.deletes);
    try std.testing.expectEqualStrings("c", e.insert);
    e = textEdit("abc", "ab");
    try std.testing.expectEqual(@as(usize, 1), e.deletes);
    e = textEdit("hello world", "help world");
    try std.testing.expectEqual(@as(usize, 8), e.deletes);
    try std.testing.expectEqualStrings("p world", e.insert);
    e = textEdit("caf\u{e9}", "caf\u{e8}");
    try std.testing.expectEqual(@as(usize, 1), e.deletes);
    try std.testing.expectEqualStrings("\u{e8}", e.insert);
}

test "touch: tabs at least 40 logical px tall" {
    const m: Metrics = .{ .em = 13, .cell_w = 8, .cell_h = 16, .baseline = 12, .underline_y = 14, .stroke = 1 };
    for ([_]f32{ 1, 1.5, 2 }) |s| try std.testing.expect(@round(topBarHeight(m, true, s) * 0.8) >= touch_target * s);
    try std.testing.expectEqual(@round(16 * 1.8), topBarHeight(m, false, 1));
}

const TapRec = struct {
    answers: [4][16]u8 = undefined,
    answer_lens: [4]usize = undefined,
    n_answers: usize = 0,
    buttons: usize = 0,
    scrolled: f32 = 0,
    drags: [3]usize = .{ 0, 0, 0 },
    last_drag: input.Drag = .{ .phase = .up, .x = 0, .y = 0 },
    mice: usize = 0,
    fn of(p: *anyopaque) *TapRec {
        return @ptrCast(@alignCast(p));
    }
    fn key(_: *anyopaque, _: input.Key, _: input.Mods) void {}
    fn char(_: *anyopaque, _: u21, _: input.Mods) void {}
    fn answer(p: *anyopaque, k: []const u8) void {
        const r = of(p);
        @memcpy(r.answers[r.n_answers][0..k.len], k);
        r.answer_lens[r.n_answers] = k.len;
        r.n_answers += 1;
    }
    fn button(p: *anyopaque, _: u32) void {
        of(p).buttons += 1;
    }
    fn resized(_: *anyopaque, _: u32, _: u32, _: u16, _: u16) void {}
    fn mouse(p: *anyopaque, _: input.Mouse) void {
        of(p).mice += 1;
    }
    fn scroll(p: *anyopaque, dy: f32) void {
        of(p).scrolled += dy;
    }
    fn drag(p: *anyopaque, d: input.Drag) void {
        of(p).drags[@intFromEnum(d.phase)] += 1;
        of(p).last_drag = d;
    }
    const vt: input.InputSink.VTable = .{ .key = key, .char = char, .answer = answer, .button = button, .resized = resized, .mouse = mouse, .scroll = scroll, .drag = drag };
};

test "content view: a tap on its button answers on release, a drag goes to the view instead, the wheel scrolls" {
    var f = Frame.init(std.testing.allocator, .fit_grid);
    defer f.deinit();
    var r: TapRec = .{};
    const sink: input.InputSink = .{ .ctx = &r, .vtable = &TapRec.vt };
    f.view_shown = true;
    f.regions.terminal = .{ .x = 0, .y = 0, .w = 400, .h = 300 };
    f.addHit(.{ .x = 10, .y = 10, .w = 100, .h = 40, .action = .{ .answer = "2" }, .tap = true });
    // Tap: nothing on the press, the answer on the release.
    f.pointerDown(20, 20, .left, .{}, sink);
    try std.testing.expectEqual(@as(usize, 0), r.n_answers);
    f.pointerMove(22, 23, sink);
    f.pointerUp(22, 23, .left, sink);
    try std.testing.expectEqual(@as(usize, 1), r.n_answers);
    try std.testing.expectEqualStrings("2", r.answers[0][0..r.answer_lens[0]]);
    try std.testing.expectEqual([3]usize{ 1, 1, 1 }, r.drags);
    // A drag starting on the button (down, or sideways): the view gets it,
    // the button never answers.
    f.pointerDown(20, 20, .left, .{}, sink);
    f.pointerMove(20, 60, sink);
    f.pointerMove(20, 100, sink);
    f.pointerUp(20, 20, .left, sink);
    f.pointerDown(20, 20, .left, .{}, sink);
    f.pointerMove(90, 22, sink);
    try std.testing.expectEqual(@as(f32, 90), r.last_drag.x);
    f.pointerUp(20, 20, .left, sink);
    try std.testing.expectEqual(@as(usize, 1), r.n_answers);
    try std.testing.expectEqual([3]usize{ 3, 4, 3 }, r.drags);
    // Released elsewhere: nothing.
    f.pointerDown(20, 20, .left, .{}, sink);
    f.pointerUp(300, 20, .left, sink);
    try std.testing.expectEqual(@as(usize, 1), r.n_answers);
    try std.testing.expectEqual(@as(usize, 0), r.mice);
    // The wheel over the view scrolls; outside, or without a view, not.
    try std.testing.expect(f.wheel(50, 50, 1, sink));
    try std.testing.expectEqual(@as(f32, 48), r.scrolled);
    try std.testing.expect(!f.wheel(50, 350, 1, sink));
    f.view_shown = false;
    try std.testing.expect(!f.wheel(50, 50, 1, sink));
    // Not a view: plain mouse input for the grid.
    f.pointerDown(300, 200, .left, .{}, sink);
    try std.testing.expectEqual(@as(usize, 1), r.mice);
}

test "touch: nothing acts on a press; buttons are taps; a cancel never taps; drags over the grid scroll its rows" {
    var f = Frame.init(std.testing.allocator, .fit_grid);
    defer f.deinit();
    var r: TapRec = .{};
    const sink: input.InputSink = .{ .ctx = &r, .vtable = &TapRec.vt };
    f.touch = true;
    f.regions.terminal = .{ .x = 0, .y = 0, .w = 400, .h = 300 };
    f.cells = .{ .ch = 20 };
    // An answer-bar button (fires on press with a mouse): on touch only on
    // release, and only without moving off it.
    f.addHit(.{ .x = 10, .y = 320, .w = 100, .h = 40, .action = .{ .answer = "1" } });
    f.pointerDown(20, 330, .left, .{}, sink);
    try std.testing.expectEqual(@as(usize, 0), r.n_answers);
    f.pointerUp(22, 332, .left, sink);
    try std.testing.expectEqual(@as(usize, 1), r.n_answers);
    try std.testing.expectEqualStrings("1", r.answers[0][0..r.answer_lens[0]]);
    // A drag that starts on it (scrolling) answers nothing.
    f.pointerDown(20, 330, .left, .{}, sink);
    f.pointerMove(20, 290, sink);
    f.pointerMove(20, 330, sink);
    f.pointerUp(20, 330, .left, sink);
    // Cancelled by the system: nothing, even without moving.
    f.pointerDown(20, 330, .left, .{}, sink);
    f.pointerCancel(sink);
    try std.testing.expectEqual(@as(usize, 1), r.n_answers);
    // A drag over the grid scrolls its rows (finger down: earlier rows).
    f.pointerDown(200, 100, .left, .{}, sink);
    f.pointerMove(200, 105, sink);
    try std.testing.expectEqual(@as(u16, 0), f.scroll_back);
    f.pointerMove(200, 150, sink);
    try std.testing.expectEqual(@as(u16, 2), f.scroll_back);
    f.pointerMove(200, 100, sink);
    try std.testing.expectEqual(@as(u16, 0), f.scroll_back);
    f.pointerUp(200, 100, .left, sink);
    try std.testing.expectEqual(@as(usize, 0), r.mice);
    try std.testing.expectEqual([3]usize{ 0, 0, 0 }, r.drags);
    // Over a content view: its drags; a cancel releases where it began.
    f.view_shown = true;
    f.pointerDown(200, 100, .left, .{}, sink);
    f.pointerMove(300, 100, sink);
    try std.testing.expectEqual(@as(f32, 300), r.last_drag.x);
    f.pointerCancel(sink);
    try std.testing.expect(r.last_drag.phase == .up);
    try std.testing.expectEqual(@as(f32, 200), r.last_drag.x);
    try std.testing.expectEqual([3]usize{ 1, 1, 1 }, r.drags);
    f.pointerUp(300, 100, .left, sink); // the window's own up after a cancel: nothing more
    try std.testing.expectEqual([3]usize{ 1, 1, 1 }, r.drags);
    try std.testing.expectEqual(@as(usize, 1), r.n_answers);
}


test "hit-testing maps clicks to what the last frame drew" {
    var f = Frame.init(std.testing.allocator, .fit_grid);
    defer f.deinit();
    f.addHit(.{ .x = 10, .y = 10, .w = 20, .h = 10, .action = .{ .button = 7 } });
    f.addHit(.{ .x = 40, .y = 10, .w = 20, .h = 10, .action = .{ .answer = "y" } });
    try std.testing.expectEqual(@as(u32, 7), f.hitAt(15, 12).?.button);
    try std.testing.expectEqualStrings("y", f.hitAt(45, 12).?.answer);
    try std.testing.expect(f.hitAt(35, 12) == null);
    f.cells = .{ .ox = 0, .oy = 0, .cw = 10, .ch = 20, .cols = 80, .rows = 24 };
    const m = f.mouseAt(.down, .left, 25, 45, .{});
    try std.testing.expectEqual(@as(u16, 2), m.col);
    try std.testing.expectEqual(@as(u16, 2), m.row);
    try std.testing.expect(m.inside);
}

test "scrollRows never goes below following the cursor" {
    var f = Frame.init(std.testing.allocator, .fit_grid);
    defer f.deinit();
    f.scrollRows(3);
    try std.testing.expectEqual(@as(u16, 3), f.scroll_back);
    f.scrollRows(-5);
    try std.testing.expectEqual(@as(u16, 0), f.scroll_back);
}

fn expectHits(f: *const Frame, want: []const u32, absent: []const u32) !void {
    for (want) |w| {
        var seen = false;
        for (f.hits[0..f.n_hits]) |h| switch (h.action) {
            .button => |id| if (id == w) {
                seen = true;
                // The centre of what was registered maps back to it.
                try std.testing.expectEqual(id, f.hitAt(h.x + h.w / 2, h.y + h.h / 2).?.button);
            },
            else => {},
        };
        if (!seen) {
            std.debug.print("not hit-testable: {d}\n", .{w});
            return error.TestUnexpectedResult;
        }
    }
    for (f.hits[0..f.n_hits]) |h| switch (h.action) {
        .button => |id| for (absent) |x| try std.testing.expect(id != x),
        else => {},
    };
}

test "badges, the status line's task summary and panel buttons are hit by what was drawn" {
    const gpa = std.testing.allocator;
    var fs = fontset.FontSet.load(gpa, std.testing.io) catch return error.SkipZigTest;
    defer fs.deinit();
    var f = Frame.init(gpa, .{ .fixed_em = 14 });
    defer f.deinit();
    var g: Grid = .{};
    const tabs_ = [_]TopTab{
        .{ .label = "Alpha", .color = .{ 0x33, 0x66, 0xCC }, .active = true, .id = 1000, .close_id = 1100, .badge = "3", .badge_id = 1200 },
        .{ .label = "Beta", .color = .{ 0x10, 0xB9, 0x81 }, .id = 1001, .badge_id = 1201 },
    };
    const rows = [_]PanelRow{.{ .text = "Alpha", .button = .{ .label = "Open /usage", .id = 1310 } }};
    const buttons = [_]PanelButton{.{ .label = "Close", .id = 1300 }};
    var o: Overlay = .{
        .top_bar = .{ .tabs = &tabs_, .buttons = &.{.{ .label = "Usage", .id = 910 }} },
        .status = .{ .label = "local session", .tasks = "2 shells \u{00B7} 1 monitor", .tasks_id = 912 },
    };
    f.build(&fs, .{ 1200, 800 }, 1, &g, o);
    // A tab without tasks has no badge to click.
    try expectHits(&f, &.{ 1000, 1001, 1100, 1200, 912, 910 }, &.{1201});
    // An open panel is modal: only its own buttons react.
    o.panel = .{ .title = "Usage", .rows = &rows, .buttons = &buttons };
    f.build(&fs, .{ 1200, 800 }, 1, &g, o);
    try expectHits(&f, &.{ 1310, 1300 }, &.{ 1000, 1200, 912, 910 });
}
