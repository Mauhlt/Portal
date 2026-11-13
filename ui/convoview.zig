//! The Conversation view: the main slice's readable alternative to the
//! terminal (a frame.ContentView). It shows the items of the tab shown
//! (ui/convo.zig, kept by the device from `convo` / `convo+` messages) as
//! a vertical list, newest at the bottom:
//!
//!   user       the owner's prompt: a tinted bubble, right-aligned
//!   assistant  full width, word-wrapped; ``` fenced code in a monospaced
//!              block on the panel colour, not wrapped but clipped
//!   tool       a small dim one-liner after a "▸"
//!   error      red, after a "×"
//!   status     small, dim, italic, centred
//!   question   a card: the question, then its options as large buttons
//!              (the interaction bar's hit-target height) that answer with
//!              the option's key through the answer path (Host.answer,
//!              "k:<key>" and nothing else); a Yes/No question instead is a
//!              swipe card (by default left: Yes, right: No, the owner
//!              being left-handed; `yes_side`, the device setting
//!              `swipe = left-yes | right-yes`; the Left / Right arrows
//!              follow it) with a small "⋯" that reveals its two buttons;
//!              once answered the text stays and the controls go
//!
//! A tab without a transcript ("on": false) shows a friendly empty state
//! with a way to the terminal.
//!
//! Scrolling: the wheel, a vertical drag (touch or mouse), PageUp /
//! PageDown / Home / End. At the bottom the view follows new items; scrolled
//! up it keeps its place (anchored on the item at the top) and a pill
//! offers to jump to the newest.
//!
//! Swiping (the owner's "Tinder for agent questions"), guarded against
//! accidental approvals: only the newest open question, only Yes/No ones
//! (`yesNo`), only a drag whose horizontal movement dominates (`classify`;
//! vertical ones scroll), not within `swipe_guard_ms` of the card really
//! appearing on screen (`presented`), and only past 40% of the card width
//! and `swipe_min_px` (`commitSide`). Released earlier the card springs
//! back. Fly-off and spring-back are short animations with real deadlines
//! (`frameTimeout`); nothing ticks while idle.
//!
//! The view keeps its own copy of the items (`sync`, under the device's
//! lock), so drawing and input never read the network thread's memory.
//! Each item's wrapped layout is cached and redone only when the item
//! changes or the column width / font size does. Allocation happens on
//! changes only, never per frame.

const std = @import("std");
const Font = @import("Font");
const theme = @import("shared").theme;
const wire = @import("shared").convo;
const frame = @import("frame.zig");
const input = @import("input.zig");
const convo = @import("convo.zig");

const Metrics = frame.Metrics;
const Rgb = theme.Rgb;
const Kind = wire.Kind;
const textWidth = frame.textWidth;

/// The view's own button ids (shell.ids.view0 ..): the pill, a card's "⋯".
pub const ids = struct {
    pub const base: u32 = 1300;
    pub const pill: u32 = base;
    pub const reveal: u32 = base + 1;
    /// The empty state's Terminal button (shell.ids.view_terminal).
    pub const terminal: u32 = 905;
};

/// No swipe during this long after a card first appeared on screen.
pub const swipe_guard_ms: i64 = 600;
/// A swipe answers only past this share of the card width ...
pub const swipe_share: f32 = 0.4;
/// ... and at least this many logical pixels.
pub const swipe_min_px: f32 = 96;
/// Fly-off and spring-back durations.
pub const fly_ms: i64 = 180;
pub const spring_ms: i64 = 160;
/// An animation frame's deadline (about the display rate).
pub const anim_frame_ms: u32 = 16;
/// Text sizes (logical px): the conversation and its small lines.
pub const body_em: f32 = 14;
pub const small_em: f32 = 12;

pub const Clock = struct {
    ctx: ?*anyopaque = null,
    now: *const fn (ctx: ?*anyopaque) i64 = zero,
    fn zero(_: ?*anyopaque) i64 {
        return 0;
    }
    fn ms(c: Clock) i64 {
        return c.now(c.ctx);
    }
};

/// The fonts a layout is made with (device pixels).
pub const Fonts = struct { body: Metrics, small: Metrics, act: Metrics, s: f32 };

// ------------------------------------------------------------ pure parts

/// One source line of an item's text: plain text, a line inside a ```
/// block, or a fence.
pub const Block = struct { kind: enum { text, code, fence }, line: []const u8 };

/// Splits text into lines and finds ``` fenced code blocks (a fence is a
/// line starting with ``` after optional spaces; an unclosed block runs to
/// the end).
pub const Blocks = struct {
    rest: ?[]const u8,
    in_code: bool = false,

    pub fn init(t: []const u8) Blocks {
        return .{ .rest = t };
    }

    pub fn next(b: *Blocks) ?Block {
        const r = b.rest orelse return null;
        const nl = std.mem.indexOfScalar(u8, r, '\n');
        const line = if (nl) |i| r[0..i] else r;
        b.rest = if (nl) |i| r[i + 1 ..] else null;
        if (std.mem.startsWith(u8, std.mem.trimStart(u8, line, " "), "```")) {
            b.in_code = !b.in_code;
            return .{ .kind = .fence, .line = line };
        }
        return .{ .kind = if (b.in_code) .code else .text, .line = line };
    }
};

/// The answer keys of a Yes/No question: exactly two options (not a
/// multi-choice), one reading "yes", the other "no" (a permission prompt is
/// Yes = `1`, No = `esc`). Null: not swipeable, buttons only.
pub fn yesNo(it: anytype) ?struct { yes: []const u8, no: []const u8 } {
    if (it.kind != .question or it.multi or it.options.len != 2) return null;
    const a = answerWord(it.options[0].label);
    const b = answerWord(it.options[1].label);
    if (a == .yes and b == .no) return .{ .yes = it.options[0].key, .no = it.options[1].key };
    if (a == .no and b == .yes) return .{ .yes = it.options[1].key, .no = it.options[0].key };
    return null;
}

const Word = enum { yes, no, other };

/// "Yes", "1. Yes", "yes, proceed", "No", "No (esc)" ... (a word, not a
/// prefix of another: "Nothing" is not "no").
fn answerWord(label: []const u8) Word {
    var t = std.mem.trimStart(u8, label, " ");
    // A leading "1." / "2)" numbering.
    var i: usize = 0;
    while (i < t.len and std.ascii.isDigit(t[i])) i += 1;
    if (i > 0 and i < t.len and (t[i] == '.' or t[i] == ')')) t = std.mem.trimStart(u8, t[i + 1 ..], " ");
    for ([_]struct { w: []const u8, v: Word }{ .{ .w = "yes", .v = .yes }, .{ .w = "no", .v = .no } }) |c| {
        if (t.len < c.w.len or !std.ascii.eqlIgnoreCase(t[0..c.w.len], c.w)) continue;
        if (t.len == c.w.len or !std.ascii.isAlphanumeric(t[c.w.len])) return c.v;
    }
    return .other;
}

pub const Direction = enum { undecided, horizontal, vertical };

/// What a drag is, once it moved past `slop` pixels: sideways (a swipe)
/// only when the horizontal movement clearly dominates (twice the
/// vertical), anything else scrolls.
pub fn classify(dx: f32, dy: f32, slop: f32) Direction {
    if (@max(@abs(dx), @abs(dy)) <= slop) return .undecided;
    return if (@abs(dx) > 2 * @abs(dy)) .horizontal else .vertical;
}

pub const Side = enum { yes, no };
pub const Dir = enum { left, right };

/// Which way a swipe says Yes (the other way says No): the device setting
/// `swipe = left-yes` (the default) or `right-yes`.
pub const YesSide = enum {
    left,
    right,

    /// The answer a swipe (or arrow key) towards `d` gives.
    pub fn answer(y: YesSide, d: Dir) Side {
        return if ((d == .left) == (y == .left)) .yes else .no;
    }
};

/// `swipe = left-yes | right-yes` from a settings file's text (null: not
/// set or not understood; blank lines and '#' comments ignored).
pub fn parseSwipeSetting(text: []const u8) ?YesSide {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var out: ?YesSide = null;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        if (!std.mem.eql(u8, std.mem.trim(u8, line[0..eq], " \t"), "swipe")) continue;
        const val = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(val, "left-yes")) out = .left else if (std.ascii.eqlIgnoreCase(val, "right-yes")) out = .right;
    }
    return out;
}

/// Whether a released swipe of `offset` px on a `card_w` wide card answers,
/// and which way it went: past `swipe_share` of the width and
/// `swipe_min_px` logical px.
pub fn commitSide(offset: f32, card_w: f32, s: f32) ?Dir {
    const need = @max(card_w * swipe_share, swipe_min_px * s);
    if (offset >= need) return .right;
    if (offset <= -need) return .left;
    return null;
}

/// Swipes are allowed `swipe_guard_ms` after the card appeared.
pub fn guardPassed(appeared_ms: ?i64, press_ms: i64) bool {
    const a = appeared_ms orelse return false;
    return press_ms - a >= swipe_guard_ms;
}

fn mix(c: Rgb, to: Rgb, k: f32) Rgb {
    var out: Rgb = undefined;
    for (0..3) |i| {
        const a: f32 = @floatFromInt(c[i]);
        const b: f32 = @floatFromInt(to[i]);
        out[i] = @intFromFloat(@round(a + (b - a) * std.math.clamp(k, 0, 1)));
    }
    return out;
}

const colors = struct {
    const bubble = mix(theme.palette.blue, theme.palette.bg, 0.78);
    const code_bg = theme.ui.panel;
    const code_fg = theme.palette.cyan_cooler;
    const card = mix(theme.palette.yellow_warmer, theme.palette.bg, 0.9);
    const card_closed = theme.ui.panel;
    const yes = theme.palette.green;
    const no = theme.palette.red;
};

// ------------------------------------------------------------ the view

const FontSel = enum { body, small, act };

/// One laid-out run of text, relative to its item (x from the column's
/// left edge, y from the item's top).
const Line = struct {
    str: []const u8,
    x: f32,
    y: f32,
    font: FontSel = .body,
    color: Rgb = theme.ui.text,
    bold: bool = false,
    italic: bool = false,
    /// Clip at this x (code lines, button labels); null: none.
    x1: ?f32 = null,
    /// Part of option button `opt` (hidden with the buttons).
    opt: ?u8 = null,
};

const Box = struct {
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    color: Rgb,
    kind: enum { fill, outline, card, option, reveal } = .fill,
    opt: u8 = 0,
};

const Entry = struct {
    n: u32,
    kind: Kind,
    open: bool,
    multi: bool,
    text: []u8,
    options: []wire.Option,
    hash: u64,
    /// The layout (valid while `laid`).
    lines: std.ArrayList(Line) = .empty,
    boxes: std.ArrayList(Box) = .empty,
    height: f32 = 0,
    laid: bool = false,
    /// Top in the content (set each prepare).
    y: f32 = 0,

    fn deinit(e: *Entry, gpa: std.mem.Allocator) void {
        gpa.free(e.text);
        for (e.options) |o| {
            gpa.free(o.label);
            gpa.free(o.key);
        }
        gpa.free(e.options);
        e.lines.deinit(gpa);
        e.boxes.deinit(gpa);
    }
};

fn itemHash(it: wire.Item) u64 {
    var h = std.hash.Wyhash.init(0x5eed);
    h.update(&.{ @intFromEnum(it.kind), @intFromBool(it.open), @intFromBool(it.multi) });
    h.update(it.text);
    for (it.options) |o| {
        h.update(o.label);
        h.update(&.{0});
        h.update(o.key);
        h.update(&.{0});
    }
    return h.final();
}

/// Copies item text for drawing: tabs as four spaces, other controls (but
/// line feeds) dropped, surrounding blank lines trimmed.
fn normalize(gpa: std.mem.Allocator, t: []const u8) ![]u8 {
    const src = std.mem.trim(u8, t, "\n\r ");
    var n: usize = 0;
    for (src) |c| n += if (c == '\t') 4 else if (c < 0x20 and c != '\n') 0 else 1;
    const out = try gpa.alloc(u8, n);
    var i: usize = 0;
    for (src) |c| {
        if (c == '\t') {
            @memcpy(out[i..][0..4], "    ");
            i += 4;
        } else if (c >= 0x20 or c == '\n') {
            out[i] = c;
            i += 1;
        }
    }
    return out;
}

fn copyEntry(gpa: std.mem.Allocator, it: wire.Item) !Entry {
    const text = try normalize(gpa, it.text);
    errdefer gpa.free(text);
    const opts = try gpa.alloc(wire.Option, it.options.len);
    var k: usize = 0;
    errdefer {
        for (opts[0..k]) |o| {
            gpa.free(o.label);
            gpa.free(o.key);
        }
        gpa.free(opts);
    }
    for (it.options) |o| {
        const label = try gpa.dupe(u8, o.label);
        errdefer gpa.free(label);
        opts[k] = .{ .label = label, .key = try gpa.dupe(u8, o.key) };
        k += 1;
    }
    return .{ .n = it.n, .kind = it.kind, .open = it.open, .multi = it.multi, .text = text, .options = opts, .hash = itemHash(it) };
}

/// Spacing for one set of fonts.
const Geo = struct {
    s: f32,
    pad: f32,
    gap: f32,
    lh: f32,
    slh: f32,
    code_lh: f32,
    cpad: f32,
    bpad: f32,
    qpad: f32,
    bh: f32,
    bgap: f32,

    fn of(f: Fonts) Geo {
        const s = f.s;
        return .{
            .s = s,
            .pad = @round(14 * s),
            .gap = @round(12 * s),
            .lh = @round(@as(f32, @floatFromInt(f.body.cell_h)) * 1.3),
            .slh = @round(@as(f32, @floatFromInt(f.small.cell_h)) * 1.3),
            .code_lh = @as(f32, @floatFromInt(f.body.cell_h)) + @round(2 * s),
            .cpad = @round(8 * s),
            .bpad = @round(10 * s),
            .qpad = @round(12 * s),
            .bh = frame.answerButtonHeight(f.act),
            .bgap = @round(8 * s),
        };
    }
};

const LayoutKey = struct { colw: f32 = -1, body: [2]u32 = .{ 0, 0 }, small: [2]u32 = .{ 0, 0 }, act: [2]u32 = .{ 0, 0 }, s: f32 = 0, yes_side: YesSide = .left };

/// A swipe in progress, or its animation.
const Swipe = struct {
    phase: enum { idle, pending, scrolling, swiping, flying, springing } = .idle,
    /// The card being swiped (null: the press was not on a swipeable card).
    n: ?u32 = null,
    x0: f32 = 0,
    y0: f32 = 0,
    last_y: f32 = 0,
    offset: f32 = 0,
    /// Animation: from offset `from` to `to`, starting at `t0`.
    from: f32 = 0,
    to: f32 = 0,
    t0: i64 = 0,
};

pub const Hit = union(enum) { answer: []const u8, button: u32 };

pub const View = struct {
    gpa: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    /// The tab shown and whether it has a transcript.
    id: ?wire.Id = null,
    on: bool = false,
    /// As of the last sync: the source's generation.
    src_gen: u64 = std.math.maxInt(u64),
    /// The desktop's input mode accepts answers (set by the glue).
    answers: bool = true,
    /// Which way a swipe says Yes (device setting; default left).
    yes_side: YesSide = .left,
    clock: Clock = .{},

    // Layout.
    key: LayoutKey = .{},
    fonts: ?Fonts = null,
    rect: frame.Rect = .{},
    col_x: f32 = 0,
    colw: f32 = 0,
    total_h: f32 = 0,

    // Scrolling: following the bottom, or anchored on the item at the top.
    pinned: bool = true,
    anchor_n: u32 = 0,
    anchor_off: f32 = 0,
    top: f32 = 0,
    /// Items arrived while scrolled up (the pill says "New messages").
    unseen: bool = false,

    // Swiping.
    swipe: Swipe = .{},
    /// The newest open question as last drawn, and when it first was on
    /// screen (presented).
    shown_q: ?u32 = null,
    appear_n: ?u32 = null,
    appear_ms: ?i64 = null,
    /// A card whose answer was sent here (its controls go until the
    /// desktop updates it).
    sent_n: ?u32 = null,
    /// A swipe card whose "⋯" revealed its buttons.
    revealed_n: ?u32 = null,

    pub fn init(gpa: std.mem.Allocator) View {
        return .{ .gpa = gpa };
    }

    pub fn deinit(v: *View) void {
        for (v.entries.items) |*e| e.deinit(v.gpa);
        v.entries.deinit(v.gpa);
    }

    pub fn contentView(v: *View) frame.ContentView {
        return .{ .ctx = v, .draw = drawThunk, .scroll = scrollThunk, .key = keyThunk, .button = buttonThunk, .drag = dragThunk };
    }

    fn of(ctx: *anyopaque) *View {
        return @ptrCast(@alignCast(ctx));
    }
    fn drawThunk(ctx: *anyopaque, p: *frame.Painter, r: frame.Rect) void {
        of(ctx).draw(p, r);
    }
    fn scrollThunk(ctx: *anyopaque, dy: f32) void {
        of(ctx).scrollBy(dy);
    }
    fn keyThunk(ctx: *anyopaque, k: input.Key, m: input.Mods) frame.ViewInput {
        const v = of(ctx);
        const r = v.onKey(k, m);
        return switch (r) {
            .ignored => .ignored,
            .scrolled => .consumed,
            .answer_yes, .answer_no => if (v.keyAnswer(r)) |key| .{ .answer = key } else .consumed,
        };
    }
    fn buttonThunk(ctx: *anyopaque, id: u32) bool {
        return of(ctx).button(id);
    }
    fn dragThunk(ctx: *anyopaque, d: input.Drag) ?[]const u8 {
        return of(ctx).drag(d);
    }

    // ------------------------------------------------------------ sync

    /// Takes over what changed in `src` (call under the lock that guards
    /// it). Unchanged items keep their layout.
    pub fn sync(v: *View, src: *const convo.Conversation) void {
        if (src.generation == v.src_gen) return;
        v.src_gen = src.generation;
        const same_tab = if (v.id) |a| (if (src.id) |b| std.mem.eql(u8, &a, &b) else false) else false;
        v.id = src.id;
        v.on = src.on;
        if (!same_tab) {
            v.pinned = true;
            v.unseen = false;
            v.swipe = .{};
            v.sent_n = null;
            v.revealed_n = null;
        }
        const old_max: ?u32 = if (v.entries.items.len > 0) v.entries.items[v.entries.items.len - 1].n else null;
        var next: std.ArrayList(Entry) = .empty;
        next.ensureTotalCapacity(v.gpa, src.items.items.len) catch return;
        var j: usize = 0;
        const old = v.entries.items;
        for (src.items.items) |it| {
            while (j < old.len and old[j].n < it.n) : (j += 1) old[j].deinit(v.gpa);
            if (j < old.len and old[j].n == it.n and old[j].hash == itemHash(it)) {
                next.appendAssumeCapacity(old[j]);
                j += 1;
                continue;
            }
            if (j < old.len and old[j].n == it.n) {
                if (v.sent_n == it.n) v.sent_n = null;
                old[j].deinit(v.gpa);
                j += 1;
            }
            const e = copyEntry(v.gpa, it) catch continue;
            next.appendAssumeCapacity(e);
        }
        while (j < old.len) : (j += 1) old[j].deinit(v.gpa);
        v.entries.deinit(v.gpa);
        v.entries = next;
        const new_max: ?u32 = if (next.items.len > 0) next.items[next.items.len - 1].n else null;
        const appended = if (new_max) |nm| (if (old_max) |om| nm > om else true) else false;
        if (appended and !v.pinned and same_tab) v.unseen = true;
        // A swipe on a card that changed or went: drop it.
        if (v.swipe.n) |n| if (v.find(n) == null or !v.isSwipeable(n)) {
            v.swipe = .{};
        };
    }

    fn find(v: *const View, n: u32) ?usize {
        for (v.entries.items, 0..) |e, i| if (e.n == n) return i;
        return null;
    }

    /// The newest open question, if any.
    pub fn newestOpenQuestion(v: *const View) ?u32 {
        var i = v.entries.items.len;
        while (i > 0) {
            i -= 1;
            const e = v.entries.items[i];
            if (e.kind == .question and e.open) return e.n;
        }
        return null;
    }

    /// Item `n` can be swiped now: the newest open question, Yes/No, its
    /// answer not sent yet, answers accepted.
    fn isSwipeable(v: *const View, n: u32) bool {
        if (!v.answers or v.sent_n == n) return false;
        if (v.newestOpenQuestion() != n) return false;
        const i = v.find(n) orelse return false;
        return yesNo(v.entries.items[i]) != null;
    }

    /// Whether card `e` shows option buttons: open, not answered here, and
    /// not a swipe card (unless its "⋯" revealed them).
    fn showsButtons(v: *const View, e: *const Entry) bool {
        if (e.kind != .question or !e.open or e.options.len == 0 or v.sent_n == e.n) return false;
        if (yesNo(e.*) != null and v.revealed_n != e.n) return false;
        return true;
    }

    // ------------------------------------------------------------ layout

    fn metricsOf(f: Fonts, sel: FontSel) Metrics {
        return switch (sel) {
            .body => f.body,
            .small => f.small,
            .act => f.act,
        };
    }

    /// Word-wrapped text with ``` blocks at (x0, y0) in `width`; returns
    /// the height used and the widest line.
    fn layoutText(v: *View, e: *Entry, f: Fonts, g: Geo, text: []const u8, x0: f32, y0: f32, width: f32, color: Rgb, sel: FontSel, italic: bool) struct { h: f32, w: f32 } {
        const m = metricsOf(f, sel);
        const lh = if (sel == .body) g.lh else g.slh;
        var y = y0;
        var max_w: f32 = 0;
        var code_y: ?f32 = null;
        var it = Blocks.init(text);
        while (it.next()) |b| switch (b.kind) {
            .fence => if (it.in_code) {
                code_y = y;
                y += g.cpad;
            } else if (code_y) |cy| {
                e.boxes.append(v.gpa, .{ .x = x0, .y = cy, .w = width, .h = y + g.cpad - cy, .color = colors.code_bg }) catch {};
                y += g.cpad + @round(4 * g.s);
                code_y = null;
                max_w = width;
            },
            .code => {
                const str = std.mem.trimEnd(u8, b.line, " ");
                e.lines.append(v.gpa, .{ .str = str, .x = x0 + g.cpad, .y = y + @round((g.code_lh - @as(f32, @floatFromInt(f.body.cell_h))) / 2), .color = colors.code_fg, .x1 = x0 + width - g.cpad }) catch {};
                y += g.code_lh;
            },
            .text => {
                if (std.mem.trim(u8, b.line, " ").len == 0) {
                    y += @round(lh * 0.5);
                    continue;
                }
                var rest = std.mem.trimEnd(u8, b.line, " ");
                while (rest.len > 0) {
                    const n = frame.wrapLen(m.cell_w, rest, width);
                    const seg = std.mem.trimEnd(u8, rest[0..n], " ");
                    e.lines.append(v.gpa, .{ .str = seg, .x = x0, .y = y, .font = sel, .color = color, .italic = italic }) catch {};
                    max_w = @max(max_w, textWidth(m, seg));
                    y += lh;
                    rest = std.mem.trimStart(u8, rest[n..], " ");
                }
            },
        };
        if (code_y) |cy| {
            y += g.cpad;
            e.boxes.append(v.gpa, .{ .x = x0, .y = cy, .w = width, .h = y - cy, .color = colors.code_bg }) catch {};
            max_w = width;
        }
        return .{ .h = y - y0, .w = max_w };
    }

    fn layout(v: *View, e: *Entry, f: Fonts) void {
        const g = Geo.of(f);
        e.lines.clearRetainingCapacity();
        e.boxes.clearRetainingCapacity();
        const W = v.colw;
        switch (e.kind) {
            .assistant => e.height = v.layoutText(e, f, g, e.text, 0, 0, W, theme.ui.text, .body, false).h,
            .user => {
                const max_w = @round(W * 0.82);
                const inner = @max(1, max_w - 2 * g.bpad);
                const r = v.layoutText(e, f, g, e.text, 0, 0, inner, theme.ui.text, .body, false);
                const bw = @min(max_w, r.w + 2 * g.bpad);
                const dx = W - bw + g.bpad;
                for (e.lines.items) |*l| {
                    l.x += dx;
                    l.y += g.bpad;
                    if (l.x1) |*x1| x1.* += dx;
                }
                for (e.boxes.items) |*b| {
                    b.x += dx;
                    b.y += g.bpad;
                }
                e.boxes.insert(v.gpa, 0, .{ .x = W - bw, .y = 0, .w = bw, .h = r.h + 2 * g.bpad, .color = colors.bubble }) catch {};
                e.height = r.h + 2 * g.bpad;
            },
            .tool, .@"error" => {
                const sel: FontSel = if (e.kind == .tool) .small else .body;
                const m = metricsOf(f, sel);
                const c: Rgb = if (e.kind == .tool) theme.ui.dim else theme.ui.bad;
                const icon_w: f32 = @floatFromInt(2 * m.cell_w);
                e.lines.append(v.gpa, .{ .str = if (e.kind == .tool) "\u{25B8}" else "\u{00D7}", .x = 0, .y = 0, .font = sel, .color = c, .bold = true }) catch {};
                e.height = v.layoutText(e, f, g, e.text, icon_w, 0, @max(1, W - icon_w), c, sel, false).h;
            },
            .status => {
                const first = e.lines.items.len;
                e.height = v.layoutText(e, f, g, e.text, 0, 0, W, theme.ui.dim, .small, true).h;
                for (e.lines.items[first..]) |*l| l.x = @round((W - textWidth(f.small, l.str)) / 2);
            },
            .question => v.layoutQuestion(e, f, g),
        }
    }

    fn layoutQuestion(v: *View, e: *Entry, f: Fonts, g: Geo) void {
        const W = v.colw;
        const inner = @max(1, W - 2 * g.qpad);
        const binary = yesNo(e.*) != null;
        e.boxes.append(v.gpa, .{ .x = 0, .y = 0, .w = W, .h = 0, .color = if (e.open) colors.card else colors.card_closed, .kind = .card }) catch {};
        e.boxes.append(v.gpa, .{ .x = 0, .y = 0, .w = W, .h = 0, .color = if (e.open) theme.ui.attention else theme.ui.border, .kind = .outline }) catch {};
        var y = g.qpad;
        const head: []const u8 = if (!e.open) "Question \u{00B7} answered" else if (binary) (if (v.yes_side == .left) "Question \u{00B7} swipe left for Yes, right for No" else "Question \u{00B7} swipe right for Yes, left for No") else "Question \u{00B7} waiting for your answer";
        e.lines.append(v.gpa, .{ .str = frame.clipText(f.small, head, inner - 4 * @as(f32, @floatFromInt(f.small.cell_w)), false), .x = g.qpad, .y = y, .font = .small, .color = if (e.open) theme.ui.attention else theme.ui.dim, .bold = true }) catch {};
        // The "⋯" of a swipe card (reveals its Yes / No buttons).
        if (e.open and binary) {
            const rw = @as(f32, @floatFromInt(4 * f.small.cell_w));
            const rh = g.slh + g.cpad;
            e.boxes.append(v.gpa, .{ .x = W - g.qpad + @round(4 * g.s) - rw, .y = g.qpad - @round(g.cpad / 2), .w = rw, .h = rh, .color = theme.ui.button, .kind = .reveal }) catch {};
            e.lines.append(v.gpa, .{ .str = "\u{22EF}", .x = W - g.qpad + @round(4 * g.s) - rw + @round((rw - @as(f32, @floatFromInt(f.small.cell_w))) / 2), .y = g.qpad, .font = .small, .color = theme.ui.text, .bold = true }) catch {};
        }
        y += g.slh + @round(4 * g.s);
        y += v.layoutText(e, f, g, e.text, g.qpad, y, inner, theme.ui.text, .body, false).h;
        if (e.open and e.multi) {
            e.lines.append(v.gpa, .{ .str = "Choose any, then Enter.", .x = g.qpad, .y = y, .font = .small, .color = theme.ui.dim }) catch {};
            y += g.slh;
        }
        if (e.open and e.options.len > 0) {
            // Laid out always; drawn only while shown (showsButtons).
            y += g.bgap;
            const cw: f32 = @floatFromInt(f.act.cell_w);
            var x = g.qpad;
            for (e.options, 0..) |o, i| {
                const w = @min(inner, @max(textWidth(f.act, o.label) + 4 * cw, 6 * cw));
                if (x + w > g.qpad + inner + 0.5 and x > g.qpad) {
                    x = g.qpad;
                    y += g.bh + g.bgap;
                }
                const opt: u8 = @intCast(i);
                e.boxes.append(v.gpa, .{ .x = x, .y = y, .w = w, .h = g.bh, .color = theme.ui.button, .kind = .option, .opt = opt }) catch {};
                const label = frame.clipText(f.act, o.label, w - 2 * cw, false);
                e.lines.append(v.gpa, .{ .str = label, .x = x + @round((w - textWidth(f.act, label)) / 2), .y = y + @round((g.bh - @as(f32, @floatFromInt(f.act.cell_h))) / 2), .font = .act, .color = theme.ui.button_text, .bold = true, .opt = opt }) catch {};
                x += w + g.bgap;
            }
            y += g.bh;
        } else if (e.open) {
            e.lines.append(v.gpa, .{ .str = "Answer with Keys (below) or in the Terminal.", .x = g.qpad, .y = y + @round(4 * g.s), .font = .small, .color = theme.ui.dim }) catch {};
            y += g.slh + @round(4 * g.s);
        }
        y += g.qpad;
        if (e.boxes.items.len >= 2) {
            e.boxes.items[0].h = y;
            e.boxes.items[1].h = y;
        }
        e.height = y;
    }

    /// Lays out (what changed) for the slice `r` and resolves the scroll
    /// position. Cheap when nothing changed: no allocation.
    pub fn prepare(v: *View, r: frame.Rect, f: Fonts) void {
        const g = Geo.of(f);
        const colw = @max(1, @min(r.w - 2 * g.pad, @as(f32, @floatFromInt(f.body.cell_w * 104))));
        const k: LayoutKey = .{ .colw = colw, .body = .{ f.body.cell_w, f.body.cell_h }, .small = .{ f.small.cell_w, f.small.cell_h }, .act = .{ f.act.cell_w, f.act.cell_h }, .s = f.s, .yes_side = v.yes_side };
        if (!std.meta.eql(k, v.key)) {
            v.key = k;
            for (v.entries.items) |*e| e.laid = false;
        }
        v.fonts = f;
        v.colw = colw;
        v.rect = r;
        v.col_x = r.x + @round((r.w - colw) / 2);
        var y = g.pad;
        for (v.entries.items) |*e| {
            if (!e.laid) {
                v.layout(e, f);
                e.laid = true;
            }
            e.y = y;
            y += e.height + g.gap;
        }
        v.total_h = if (v.entries.items.len > 0) y - g.gap + g.pad else 0;
        v.resolveTop();
    }

    fn maxTop(v: *const View) f32 {
        return @max(0, v.total_h - v.rect.h);
    }

    fn resolveTop(v: *View) void {
        if (v.pinned) {
            v.top = v.maxTop();
            return;
        }
        var t: f32 = 0;
        for (v.entries.items) |e| if (e.n >= v.anchor_n) {
            t = e.y + v.anchor_off;
            break;
        } else {
            t = v.total_h;
        };
        v.setTop(t);
    }

    fn setTop(v: *View, t: f32) void {
        const mt = v.maxTop();
        v.top = std.math.clamp(t, 0, mt);
        v.pinned = v.top >= mt - 0.5;
        if (v.pinned) v.unseen = false;
        // Anchor on the item at the top.
        v.anchor_n = 0;
        v.anchor_off = 0;
        for (v.entries.items) |e| {
            if (e.y + e.height > v.top or e.n == v.entries.items[v.entries.items.len - 1].n) {
                v.anchor_n = e.n;
                v.anchor_off = v.top - e.y;
                break;
            }
        }
    }

    /// Scrolls by `dy` px (> 0: up, towards older items).
    pub fn scrollBy(v: *View, dy: f32) void {
        if (v.rect.h <= 0) return;
        v.setTop(v.top - dy);
    }

    pub fn jumpToBottom(v: *View) void {
        v.pinned = true;
        v.unseen = false;
        v.top = v.maxTop();
    }

    pub const KeyResult = enum { ignored, scrolled, answer_yes, answer_no };

    /// PageUp / PageDown / Home / End scroll; Left / Right answer the
    /// newest Yes/No card like a swipe that way (`yes_side`), with its
    /// fly-off, under the same guard (`keyAnswer` has the key).
    pub fn onKey(v: *View, k: input.Key, m: input.Mods) KeyResult {
        if (m.alt or m.super) return .ignored;
        const g = if (v.fonts) |f| Geo.of(f) else return .ignored;
        const page = @max(g.lh, v.rect.h - 2 * g.lh);
        switch (k) {
            .page_up => v.scrollBy(page),
            .page_down => v.scrollBy(-page),
            .home => v.setTop(0),
            .end => v.jumpToBottom(),
            .left, .right => {
                if (m.ctrl or m.shift) return .ignored;
                const n = v.newestOpenQuestion() orelse return .ignored;
                if (!v.isSwipeable(n) or !guardPassed(if (v.appear_n == n) v.appear_ms else null, v.clock.ms())) return .ignored;
                const card_w = v.colw;
                v.swipe = .{ .n = n, .offset = 0 };
                const dir: Dir = if (k == .right) .right else .left;
                v.fly(if (dir == .right) card_w else -card_w);
                return if (v.yes_side.answer(dir) == .yes) .answer_yes else .answer_no;
            },
            else => return .ignored,
        }
        return .scrolled;
    }

    /// The key a Left / Right answered with (after onKey), if any.
    pub fn keyAnswer(v: *const View, r: KeyResult) ?[]const u8 {
        const n = v.sent_n orelse return null;
        const i = v.find(n) orelse return null;
        const yn = yesNo(v.entries.items[i]) orelse return null;
        return switch (r) {
            .answer_yes => yn.yes,
            .answer_no => yn.no,
            else => null,
        };
    }

    pub fn button(v: *View, id: u32) bool {
        switch (id) {
            ids.pill => v.jumpToBottom(),
            ids.reveal => {
                const n = v.newestOpenQuestion() orelse return true;
                v.revealed_n = if (v.revealed_n == n) null else n;
            },
            else => return false,
        }
        return true;
    }

    // ------------------------------------------------------------ swiping

    /// The card box of item `i` in window pixels (as last prepared).
    fn cardRect(v: *const View, i: usize) frame.Rect {
        const e = v.entries.items[i];
        return .{ .x = v.col_x, .y = v.rect.y + e.y - v.top, .w = v.colw, .h = e.height };
    }

    fn fly(v: *View, to: f32) void {
        const n = v.swipe.n orelse return;
        v.sent_n = n;
        v.revealed_n = null;
        v.swipe.phase = .flying;
        v.swipe.from = v.swipe.offset;
        v.swipe.to = to;
        v.swipe.t0 = v.clock.ms();
    }

    /// A press over the view, its moves and release: scrolls, or swipes the
    /// newest Yes/No card. Returns the answer key a committed swipe sends.
    pub fn drag(v: *View, d: input.Drag) ?[]const u8 {
        switch (d.phase) {
            .down => {
                if (v.swipe.phase == .flying or v.swipe.phase == .springing) v.swipe = .{};
                v.swipe = .{ .phase = .pending, .x0 = d.x, .y0 = d.y, .last_y = d.y };
                // On the newest open Yes/No card, shown long enough?
                const n = v.newestOpenQuestion() orelse return null;
                if (!v.isSwipeable(n)) return null;
                if (!guardPassed(if (v.appear_n == n) v.appear_ms else null, v.clock.ms())) return null;
                const i = v.find(n).?;
                if (!v.cardRect(i).contains(d.x, d.y)) return null;
                v.swipe.n = n;
                return null;
            },
            .move => switch (v.swipe.phase) {
                .pending => {
                    const dir = classify(d.x - v.swipe.x0, d.y - v.swipe.y0, frame.Frame.drag_slop * d.scale);
                    switch (dir) {
                        .undecided => {},
                        .horizontal => if (v.swipe.n != null) {
                            v.swipe.phase = .swiping;
                            v.swipe.offset = d.x - v.swipe.x0;
                        } else {
                            v.swipe.phase = .scrolling;
                        },
                        .vertical => {
                            v.swipe.phase = .scrolling;
                            v.swipe.n = null;
                            v.scrollBy(d.y - v.swipe.last_y);
                            v.swipe.last_y = d.y;
                        },
                    }
                },
                .scrolling => {
                    v.scrollBy(d.y - v.swipe.last_y);
                    v.swipe.last_y = d.y;
                },
                .swiping => v.swipe.offset = d.x - v.swipe.x0,
                else => {},
            },
            .up => switch (v.swipe.phase) {
                .swiping => {
                    v.swipe.offset = d.x - v.swipe.x0;
                    const n = v.swipe.n.?;
                    const dir = commitSide(v.swipe.offset, v.colw, d.scale);
                    // Still the newest open Yes/No card?
                    if (dir != null and v.isSwipeable(n)) {
                        const yn = yesNo(v.entries.items[v.find(n).?]).?;
                        v.fly(if (dir.? == .right) v.rect.w else -v.rect.w);
                        return if (v.yes_side.answer(dir.?) == .yes) yn.yes else yn.no;
                    }
                    v.swipe.phase = .springing;
                    v.swipe.from = v.swipe.offset;
                    v.swipe.to = 0;
                    v.swipe.t0 = v.clock.ms();
                },
                else => v.swipe = .{},
            },
        }
        return null;
    }

    /// The swiped card's offset now (animations advance with the clock and
    /// end themselves).
    fn swipeOffset(v: *View) f32 {
        switch (v.swipe.phase) {
            .swiping => return v.swipe.offset,
            .flying, .springing => {
                const dur = if (v.swipe.phase == .flying) fly_ms else spring_ms;
                const t = std.math.clamp(@as(f32, @floatFromInt(v.clock.ms() - v.swipe.t0)) / @as(f32, @floatFromInt(dur)), 0, 1);
                if (t >= 1) {
                    v.swipe = .{};
                    return 0;
                }
                const e = 1 - (1 - t) * (1 - t); // ease out
                return v.swipe.from + (v.swipe.to - v.swipe.from) * e;
            },
            else => return 0,
        }
    }

    /// An animation runs: draw again within this many ms (null: idle,
    /// wait for events only).
    pub fn frameTimeout(v: *const View) ?u32 {
        return switch (v.swipe.phase) {
            .flying, .springing => anim_frame_ms,
            else => null,
        };
    }

    /// The last built frame reached the screen at `now_ms`: the newest open
    /// question's appearance time starts there (the swipe guard).
    pub fn presented(v: *View, now_ms: i64) void {
        const n = v.shown_q orelse return;
        if (v.appear_n != n) {
            v.appear_n = n;
            v.appear_ms = now_ms;
        }
    }

    // ------------------------------------------------------------ drawing

    /// The empty state, when there is one.
    pub fn emptyState(v: *const View) ?frame.Message {
        if (!v.on) return .{
            .title = "No conversation log for this tab \u{2014} use Terminal",
            .title_tone = .muted,
            .lines = &.{"Portal shows the conversation of Claude Code sessions; this tab has none to read."},
            .button = .{ .label = "Terminal", .id = ids.terminal },
        };
        if (v.entries.items.len == 0) return .{ .title = "No messages yet", .title_tone = .muted, .lines = &.{"The conversation appears here as it happens."} };
        return null;
    }

    fn pillRect(v: *const View) ?struct { r: frame.Rect, label: []const u8 } {
        if (v.pinned) return null;
        const f = v.fonts orelse return null;
        const label: []const u8 = if (v.unseen) "\u{2193} New messages" else "\u{2193} Latest";
        const cw: f32 = @floatFromInt(f.small.cell_w);
        const w = textWidth(f.small, label) + 4 * cw;
        const h = @round(@as(f32, @floatFromInt(f.small.cell_h)) * 2.2);
        return .{ .r = .{ .x = v.rect.x + @round((v.rect.w - w) / 2), .y = v.rect.y + v.rect.h - h - @round(10 * f.s), .w = w, .h = h }, .label = label };
    }

    fn visible(v: *const View, e: Entry) bool {
        return e.y + e.height > v.top and e.y < v.top + v.rect.h;
    }

    /// What a tap at (x, y) would do (the same geometry as `draw`).
    pub fn hitAt(v: *const View, x: f32, y: f32) ?Hit {
        if (!v.rect.contains(x, y)) return null;
        if (v.emptyState() != null) return null;
        if (v.pillRect()) |p| if (p.r.contains(x, y)) return .{ .button = ids.pill };
        for (v.entries.items) |*e| {
            if (!v.visible(e.*) or e.kind != .question) continue;
            const ox = v.col_x;
            const oy = v.rect.y + e.y - v.top;
            for (e.boxes.items) |b| {
                const r: frame.Rect = .{ .x = ox + b.x, .y = oy + b.y, .w = b.w, .h = b.h };
                if (!r.contains(x, y)) continue;
                if (b.kind == .option and v.answers and v.showsButtons(e)) return .{ .answer = e.options[b.opt].key };
                if (b.kind == .reveal and v.answers and e.open and v.sent_n != e.n) return .{ .button = ids.reveal };
            }
        }
        return null;
    }

    pub fn draw(v: *View, p: *frame.Painter, r: frame.Rect) void {
        const f: Fonts = .{ .body = p.metrics(body_em), .small = p.metrics(small_em), .act = p.act, .s = p.s };
        v.prepare(r, f);
        v.shown_q = null;
        if (v.emptyState()) |msg| return p.message(r, msg);
        const saved = p.clip;
        defer p.clip = saved;
        p.clip = .{ r.x, r.y, r.x + r.w, r.y + r.h };
        const offset = v.swipeOffset();
        const newest_q = v.newestOpenQuestion();
        for (v.entries.items) |*e| {
            if (!v.visible(e.*)) continue;
            if (newest_q == e.n) v.shown_q = e.n;
            const swiped = v.swipe.n == e.n and offset != 0;
            v.paintEntry(p, e, f, v.col_x, r.y + e.y - v.top, if (swiped) offset else 0);
        }
        if (v.pillRect()) |pl| {
            p.fill(pl.r.x, pl.r.y, pl.r.w, pl.r.h, theme.ui.button_active);
            p.frameRect(pl.r.x, pl.r.y, pl.r.w, pl.r.h, @max(1, @round(p.s)), theme.ui.focus);
            _ = p.run(f.small, pl.r.x + @round((pl.r.w - textWidth(f.small, pl.label)) / 2), pl.r.y + @round((pl.r.h - @as(f32, @floatFromInt(f.small.cell_h))) / 2), pl.label, theme.ui.text, true, false, null);
            p.tapButton(pl.r.x, pl.r.y, pl.r.w, pl.r.h, ids.pill);
        }
    }

    /// Paints item `e` at (ox, oy); a swiped card moves by `dx` and tilts
    /// (a shear about its centre, rows shifted in proportion), tints towards
    /// its side and shows the YES / NO stamp.
    fn paintEntry(v: *View, p: *frame.Painter, e: *Entry, f: Fonts, ox: f32, oy: f32, dx: f32) void {
        const g = Geo.of(f);
        const buttons = v.showsButtons(e);
        const tilt = if (dx == 0) 0 else std.math.clamp(dx / @max(1, v.colw), -1.5, 1.5) * 0.12;
        const cy = e.height / 2;
        const k = if (dx == 0) 0 else std.math.clamp(@abs(dx) / @max(1, @max(v.colw * swipe_share, swipe_min_px * f.s)), 0, 1);
        const towards: Side = v.yes_side.answer(if (dx > 0) .right else .left);
        const side_c: Rgb = if (towards == .yes) colors.yes else colors.no;
        const shift = struct {
            fn at(d: f32, t: f32, c: f32, y: f32) f32 {
                return @round(d + t * (y - c));
            }
        }.at;
        for (e.boxes.items) |b| {
            if (b.kind == .option and !buttons) continue;
            if (b.kind == .reveal and (!e.open or v.sent_n == e.n or !v.answers)) continue;
            var c = b.color;
            if (b.kind == .card and dx != 0) c = mix(c, side_c, k * 0.45);
            if (b.kind == .outline) {
                const t = @max(1, @round(f.s * (if (e.open) @as(f32, 2) else 1)));
                const oc = if (dx != 0) mix(c, side_c, k) else c;
                if (dx == 0) {
                    p.frameRect(ox + b.x, oy + b.y, b.w, b.h, t, oc);
                } else {
                    p.fill(ox + b.x + shift(dx, tilt, cy, b.y), oy + b.y, b.w, t, oc);
                    p.fill(ox + b.x + shift(dx, tilt, cy, b.y + b.h), oy + b.y + b.h - t, b.w, t, oc);
                    v.slices(p, ox + b.x, oy, b.y, t, b.h, dx, tilt, cy, oc, f.s);
                    v.slices(p, ox + b.x + b.w - t, oy, b.y, t, b.h, dx, tilt, cy, oc, f.s);
                }
                continue;
            }
            if (dx == 0) {
                p.fill(ox + b.x, oy + b.y, b.w, b.h, c);
                if (b.kind == .option and !v.answers) p.frameRect(ox + b.x, oy + b.y, b.w, b.h, @max(1, @round(f.s)), theme.ui.border);
            } else {
                v.slices(p, ox + b.x, oy, b.y, b.w, b.h, dx, tilt, cy, c, f.s);
            }
            if (b.kind == .option and v.answers and dx == 0) p.tapAnswer(ox + b.x, oy + b.y, b.w, b.h, e.options[b.opt].key);
            if (b.kind == .reveal and dx == 0) p.tapButton(ox + b.x, oy + b.y, b.w, b.h, ids.reveal);
        }
        for (e.lines.items) |l| {
            if (l.opt != null and !buttons) continue;
            const m = metricsOf(f, l.font);
            const sx = if (dx == 0) 0 else shift(dx, tilt, cy, l.y + @as(f32, @floatFromInt(m.cell_h)) / 2);
            const color = if (l.opt != null and !v.answers) theme.ui.dim else l.color;
            _ = p.run(m, ox + l.x + sx, oy + l.y, l.str, color, l.bold, l.italic, if (l.x1) |x1| ox + x1 + sx else null);
        }
        // The stamp.
        if (dx != 0 and e.kind == .question) {
            const big = p.metrics(22);
            const word: []const u8 = if (towards == .yes) "YES" else "NO";
            const a: u8 = @intFromFloat(@round(255 * k));
            const sw = textWidth(big, word) + 2 * @as(f32, @floatFromInt(big.cell_w));
            const sh = @as(f32, @floatFromInt(big.cell_h)) + @round(10 * f.s);
            const sy = g.qpad + g.slh + @round(4 * f.s);
            const sx = if (dx > 0) g.qpad else v.colw - g.qpad - sw;
            const x = ox + sx + shift(dx, tilt, cy, sy + sh / 2);
            const fade = mix(theme.palette.bg, side_c, @as(f32, @floatFromInt(a)) / 255);
            p.fill(x, oy + sy, sw, sh, mix(colors.card, theme.palette.bg, 0.3));
            p.frameRect(x, oy + sy, sw, sh, @max(2, @round(3 * f.s)), fade);
            _ = p.run(big, x + @as(f32, @floatFromInt(big.cell_w)), oy + sy + @round((sh - @as(f32, @floatFromInt(big.cell_h))) / 2), word, fade, true, false, null);
        }
    }

    /// A box drawn as horizontal strips, each shifted by the tilt at its
    /// height (a rotation's look with axis-aligned rectangles).
    fn slices(_: *View, p: *frame.Painter, x: f32, oy: f32, y0: f32, w: f32, h: f32, dx: f32, tilt: f32, cy: f32, c: Rgb, s: f32) void {
        const step = @max(2, @round(3 * s));
        var y = y0;
        while (y < y0 + h) : (y += step) {
            const sh = @min(step, y0 + h - y);
            p.fill(x + @round(dx + tilt * (y + sh / 2 - cy)), oy + y, w, sh, c);
        }
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

const tm = struct {
    const body: Metrics = .{ .em = 14, .cell_w = 8, .cell_h = 16, .baseline = 12, .underline_y = 14, .stroke = 1 };
    const small: Metrics = .{ .em = 12, .cell_w = 7, .cell_h = 14, .baseline = 11, .underline_y = 12, .stroke = 1 };
    const act: Metrics = .{ .em = 16, .cell_w = 9, .cell_h = 18, .baseline = 14, .underline_y = 16, .stroke = 1 };
    const fonts: Fonts = .{ .body = body, .small = small, .act = act, .s = 1 };
};

const TestClock = struct {
    t: i64 = 0,
    fn now(ctx: ?*anyopaque) i64 {
        const c: *TestClock = @ptrCast(@alignCast(ctx.?));
        return c.t;
    }
    fn clock(c: *TestClock) Clock {
        return .{ .ctx = c, .now = now };
    }
};

fn testConvo(gpa: std.mem.Allocator, c: *convo.Conversation, snapshot: bool, items: []const wire.Item) !void {
    try c.apply(gpa, .{ .snapshot = snapshot, .id = @splat(7), .on = true, .items = @constCast(items) });
}

test "blocks: fenced code detection, unclosed fence" {
    var b = Blocks.init("Here:\n```zig\nconst x = 1;\n  y\n```\ndone\n```\nopen");
    const want = [_]struct { k: @FieldType(Block, "kind"), l: []const u8 }{
        .{ .k = .text, .l = "Here:" },     .{ .k = .fence, .l = "```zig" }, .{ .k = .code, .l = "const x = 1;" },
        .{ .k = .code, .l = "  y" },       .{ .k = .fence, .l = "```" },    .{ .k = .text, .l = "done" },
        .{ .k = .fence, .l = "```" },      .{ .k = .code, .l = "open" },
    };
    for (want) |w| {
        const got = b.next().?;
        try testing.expectEqual(w.k, got.kind);
        try testing.expectEqualStrings(w.l, got.line);
    }
    try testing.expect(b.next() == null);
}

test "wrapping: words, wide characters, code lines unwrapped and clipped" {
    const gpa = testing.allocator;
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    // 20 cells of 8 px = 160 px column (+ 2 * 14 padding).
    try testConvo(gpa, &c, true, &.{
        .{ .n = 1, .kind = .assistant, .text = "the quick brown fox jumps over the lazy dog\n```\nlet a_very_long_code_line = 1;\n```" },
        .{ .n = 2, .kind = .assistant, .text = "\u{4F60}\u{597D}\u{4E16}\u{754C}\u{4F60}\u{597D}\u{4E16}\u{754C}\u{4F60}\u{597D}\u{4E16}" },
    });
    var v = View.init(gpa);
    defer v.deinit();
    v.sync(&c);
    v.prepare(.{ .w = 160 + 28, .h = 400 }, tm.fonts);
    const e = v.entries.items[0];
    // Text lines fit 20 cells and break at spaces.
    var text_lines: usize = 0;
    for (e.lines.items) |l| {
        if (l.x1 != null) continue;
        text_lines += 1;
        try testing.expect(textWidth(tm.body, l.str) <= 160);
        try testing.expect(l.str[0] != ' ' and l.str[l.str.len - 1] != ' ');
    }
    try testing.expectEqualStrings("the quick brown fox", e.lines.items[0].str);
    try testing.expect(text_lines == 3);
    // The code line: one line, whole, clipped at the block's edge, on the
    // panel colour.
    const code = e.lines.items[e.lines.items.len - 1];
    try testing.expectEqualStrings("let a_very_long_code_line = 1;", code.str);
    try testing.expect(code.x1.? <= 160);
    try testing.expectEqual(@as(usize, 1), e.boxes.items.len);
    try testing.expectEqual(colors.code_bg, e.boxes.items[0].color);
    // Wide characters count two cells: 11 of them make 10 + 1.
    const wide = v.entries.items[1];
    try testing.expectEqual(@as(usize, 2), wide.lines.items.len);
    try testing.expectEqual(@as(f32, 160), textWidth(tm.body, wide.lines.items[0].str));
    // The layout is cached; a width change redoes it.
    const lines_ptr = e.lines.items.ptr;
    v.prepare(.{ .w = 160 + 28, .h = 300 }, tm.fonts);
    try testing.expect(v.entries.items[0].laid and v.entries.items[0].lines.items.ptr == lines_ptr);
    v.prepare(.{ .w = 400, .h = 300 }, tm.fonts);
    try testing.expect(v.entries.items[0].lines.items.len < e.lines.items.len + 1);
    try testing.expectEqualStrings("the quick brown fox jumps over the lazy dog", v.entries.items[0].lines.items[0].str);
}

test "user prompts are right-aligned bubbles; tool, error, status styles" {
    const gpa = testing.allocator;
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    try testConvo(gpa, &c, true, &.{
        .{ .n = 1, .kind = .user, .text = "fix\tit" },
        .{ .n = 2, .kind = .tool, .text = "Edited 2 files" },
        .{ .n = 3, .kind = .@"error", .text = "Build failed" },
        .{ .n = 4, .kind = .status, .text = "Conversation compacted" },
    });
    var v = View.init(gpa);
    defer v.deinit();
    v.sync(&c);
    v.prepare(.{ .w = 428, .h = 400 }, tm.fonts);
    const u = v.entries.items[0];
    try testing.expectEqualStrings("fix    it", u.text); // tabs expanded
    const bubble = u.boxes.items[0];
    try testing.expectEqual(v.colw, bubble.x + bubble.w); // right edge
    try testing.expect(bubble.x > v.colw / 2);
    try testing.expectEqual(colors.bubble, bubble.color);
    try testing.expectEqual(FontSel.small, v.entries.items[1].lines.items[1].font);
    try testing.expectEqual(theme.ui.dim, v.entries.items[1].lines.items[1].color);
    try testing.expectEqual(theme.ui.bad, v.entries.items[2].lines.items[1].color);
    try testing.expect(v.entries.items[3].lines.items[0].italic);
}

test "scroll anchoring: follows the bottom, keeps its place scrolled up, the pill" {
    const gpa = testing.allocator;
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    var items: [30]wire.Item = undefined;
    for (&items, 0..) |*it, i| it.* = .{ .n = @intCast(i + 1), .kind = .assistant, .text = "a line of text" };
    try testConvo(gpa, &c, true, &items);
    var v = View.init(gpa);
    defer v.deinit();
    v.sync(&c);
    const r: frame.Rect = .{ .w = 428, .h = 200 };
    v.prepare(r, tm.fonts);
    try testing.expect(v.pinned);
    try testing.expectEqual(v.total_h - 200, v.top);
    // New item while at the bottom: still at the bottom.
    try testConvo(gpa, &c, false, &.{.{ .n = 31, .kind = .assistant, .text = "new" }});
    v.sync(&c);
    v.prepare(r, tm.fonts);
    try testing.expect(v.pinned and !v.unseen);
    try testing.expectEqual(v.total_h - 200, v.top);
    // Scrolled up: the position stays when more arrive (and when the first
    // item is evicted / removed), and the pill says so.
    v.scrollBy(300);
    try testing.expect(!v.pinned);
    const anchor = v.anchor_n;
    const off = v.anchor_off;
    try testConvo(gpa, &c, false, &.{ .{ .n = 32, .kind = .assistant, .text = "newer" }, .{ .n = 1, .kind = .assistant, .text = "" } });
    v.sync(&c);
    v.prepare(r, tm.fonts);
    try testing.expect(!v.pinned and v.unseen);
    try testing.expectEqual(anchor, v.anchor_n);
    try testing.expectEqual(off, v.anchor_off);
    const e = v.entries.items[v.find(anchor).?];
    try testing.expectEqual(e.y + off, v.top);
    try testing.expectEqualStrings("\u{2193} New messages", v.pillRect().?.label);
    // The pill jumps down.
    const pr = v.pillRect().?.r;
    const hit = v.hitAt(pr.x + 2, pr.y + 2).?;
    try testing.expectEqual(ids.pill, hit.button);
    try testing.expect(v.button(ids.pill));
    v.prepare(r, tm.fonts);
    try testing.expect(v.pinned and !v.unseen and v.pillRect() == null);
    // Keys: Home to the top, End back down, PageUp moves up.
    try testing.expectEqual(View.KeyResult.scrolled, v.onKey(.home, .{}));
    try testing.expectEqual(@as(f32, 0), v.top);
    _ = v.onKey(.end, .{});
    try testing.expect(v.pinned);
    _ = v.onKey(.page_up, .{});
    try testing.expect(!v.pinned and v.top < v.total_h - 200);
    // Narrower: re-wrapped, still anchored on the same item.
    const a2 = v.anchor_n;
    v.prepare(.{ .w = 120, .h = 200 }, tm.fonts);
    try testing.expectEqual(a2, v.anchor_n);
    try testing.expectEqual(View.KeyResult.ignored, v.onKey(.up, .{}));
}

test "update and remove semantics keep unchanged layouts; another tab starts over" {
    const gpa = testing.allocator;
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    try testConvo(gpa, &c, true, &.{ .{ .n = 1, .kind = .assistant, .text = "one" }, .{ .n = 2, .kind = .assistant, .text = "two" }, .{ .n = 3, .kind = .assistant, .text = "three" } });
    var v = View.init(gpa);
    defer v.deinit();
    v.sync(&c);
    v.prepare(.{ .w = 428, .h = 400 }, tm.fonts);
    const kept = v.entries.items[0].lines.items.ptr;
    try testConvo(gpa, &c, false, &.{ .{ .n = 2, .kind = .assistant, .text = "TWO" }, .{ .n = 3, .kind = .assistant, .text = "" } });
    v.sync(&c);
    try testing.expectEqual(@as(usize, 2), v.entries.items.len);
    try testing.expect(v.entries.items[0].laid and v.entries.items[0].lines.items.ptr == kept);
    try testing.expect(!v.entries.items[1].laid);
    try testing.expectEqualStrings("TWO", v.entries.items[1].text);
    // Same generation: nothing to do.
    v.sync(&c);
    // Another tab's snapshot.
    v.scrollBy(10);
    try c.apply(gpa, .{ .snapshot = true, .id = @splat(9), .on = true, .items = &.{} });
    v.sync(&c);
    try testing.expectEqual(@as(usize, 0), v.entries.items.len);
    try testing.expect(v.pinned);
}

test "empty states: no transcript, no messages yet" {
    const gpa = testing.allocator;
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    var v = View.init(gpa);
    defer v.deinit();
    v.sync(&c);
    const msg = v.emptyState().?;
    try testing.expectEqualStrings("No conversation log for this tab \u{2014} use Terminal", msg.title);
    try testing.expectEqual(ids.terminal, msg.button.?.id);
    try testConvo(gpa, &c, true, &.{});
    v.sync(&c);
    try testing.expectEqualStrings("No messages yet", v.emptyState().?.title);
    try testConvo(gpa, &c, false, &.{.{ .n = 1, .kind = .assistant, .text = "hi" }});
    v.sync(&c);
    try testing.expect(v.emptyState() == null);
}

test "question cards: buttons answer with the option's key; closed cards keep text, lose buttons" {
    const gpa = testing.allocator;
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    const opts = [_]wire.Option{ .{ .label = "Postgres", .key = "1" }, .{ .label = "SQLite", .key = "2" }, .{ .label = "Neither", .key = "3" } };
    try testConvo(gpa, &c, true, &.{.{ .n = 5, .kind = .question, .text = "Which DB?", .open = true, .options = &opts }});
    var v = View.init(gpa);
    defer v.deinit();
    v.sync(&c);
    const r: frame.Rect = .{ .y = 40, .w = 428, .h = 400 };
    v.prepare(r, tm.fonts);
    const e = &v.entries.items[0];
    try testing.expect(yesNo(e.*) == null);
    var found: usize = 0;
    for (e.boxes.items) |b| if (b.kind == .option) {
        found += 1;
        try testing.expectEqual(frame.answerButtonHeight(tm.act), b.h);
        const x = v.col_x + b.x + b.w / 2;
        const y = r.y + e.y - v.top + b.y + b.h / 2;
        try testing.expectEqualStrings(opts[b.opt].key, v.hitAt(x, y).?.answer);
    };
    try testing.expectEqual(@as(usize, 3), found);
    // View only: no answers.
    v.answers = false;
    const b0 = e.boxes.items[2];
    try testing.expect(v.hitAt(v.col_x + b0.x + 4, r.y + e.y - v.top + b0.y + 4) == null);
    v.answers = true;
    // Closed: the text stays, the buttons go.
    try testConvo(gpa, &c, false, &.{.{ .n = 5, .kind = .question, .text = "Which DB?", .open = false, .options = &opts }});
    v.sync(&c);
    v.prepare(r, tm.fonts);
    const closed = &v.entries.items[0];
    for (closed.boxes.items) |b| try testing.expect(b.kind != .option);
    var has_text = false;
    for (closed.lines.items) |l| has_text = has_text or std.mem.eql(u8, l.str, "Which DB?");
    try testing.expect(has_text);
    try testing.expect(v.hitAt(v.col_x + b0.x + 4, r.y + closed.y - v.top + b0.y + 4) == null);
}

test "yes/no mapping: permission prompts and two-option questions only" {
    const yn = struct {
        fn q(opts: []const wire.Option, multi: bool) wire.Item {
            return .{ .n = 1, .kind = .question, .text = "?", .open = true, .multi = multi, .options = opts };
        }
    };
    const perm = [_]wire.Option{ .{ .label = "Yes", .key = "1" }, .{ .label = "No", .key = "esc" } };
    const m = yesNo(yn.q(&perm, false)).?;
    try testing.expectEqualStrings("1", m.yes);
    try testing.expectEqualStrings("esc", m.no);
    const rev = [_]wire.Option{ .{ .label = "2. No, stop", .key = "2" }, .{ .label = "1. yes", .key = "1" } };
    try testing.expectEqualStrings("1", yesNo(yn.q(&rev, false)).?.yes);
    try testing.expectEqualStrings("2", yesNo(yn.q(&rev, false)).?.no);
    const db = [_]wire.Option{ .{ .label = "Postgres", .key = "1" }, .{ .label = "SQLite", .key = "2" } };
    try testing.expect(yesNo(yn.q(&db, false)) == null);
    const tricky = [_]wire.Option{ .{ .label = "Yesterday", .key = "1" }, .{ .label = "Nothing", .key = "2" } };
    try testing.expect(yesNo(yn.q(&tricky, false)) == null);
    const three = [_]wire.Option{ .{ .label = "Yes", .key = "1" }, .{ .label = "Yes, always", .key = "2" }, .{ .label = "No", .key = "3" } };
    try testing.expect(yesNo(yn.q(&three, false)) == null);
    try testing.expect(yesNo(yn.q(&perm, true)) == null);
}

test "gesture classifier and threshold" {
    try testing.expectEqual(Direction.undecided, classify(5, 3, 8));
    try testing.expectEqual(Direction.horizontal, classify(30, 5, 8));
    try testing.expectEqual(Direction.vertical, classify(30, 20, 8)); // not dominant enough
    try testing.expectEqual(Direction.vertical, classify(2, -40, 8));
    // 40% of a 400 px card = 160 px; small cards need swipe_min_px.
    try testing.expect(commitSide(159, 400, 1) == null);
    try testing.expectEqual(Dir.right, commitSide(160, 400, 1).?);
    try testing.expectEqual(Dir.left, commitSide(-170, 400, 1).?);
    try testing.expect(commitSide(90, 100, 1) == null);
    try testing.expectEqual(Dir.right, commitSide(96, 100, 1).?);
    // The direction setting: left-yes (default) and right-yes.
    try testing.expectEqual(Side.yes, YesSide.left.answer(.left));
    try testing.expectEqual(Side.no, YesSide.left.answer(.right));
    try testing.expectEqual(Side.yes, YesSide.right.answer(.right));
    try testing.expectEqual(Side.no, YesSide.right.answer(.left));
    try testing.expectEqual(YesSide.right, parseSwipeSetting("# device\r\nswipe = right-yes\r\n").?);
    try testing.expectEqual(YesSide.left, parseSwipeSetting("swipe=LEFT-YES").?);
    try testing.expect(parseSwipeSetting("swipe = up\nother = 1") == null);
    try testing.expect(parseSwipeSetting("") == null);
    try testing.expect(!guardPassed(null, 10_000));
    try testing.expect(!guardPassed(1000, 1599));
    try testing.expect(guardPassed(1000, 1600));
}

fn swipeSetup(gpa: std.mem.Allocator, c: *convo.Conversation, v: *View, clk: *TestClock) !frame.Rect {
    const perm = [_]wire.Option{ .{ .label = "Yes", .key = "1" }, .{ .label = "No", .key = "esc" } };
    try testConvo(gpa, c, true, &.{ .{ .n = 1, .kind = .assistant, .text = "May I run the tests?" }, .{ .n = 2, .kind = .question, .text = "Run npm test?", .open = true, .options = &perm } });
    v.clock = clk.clock();
    v.sync(c);
    const r: frame.Rect = .{ .w = 428, .h = 400 };
    v.prepare(r, tm.fonts);
    v.shown_q = v.newestOpenQuestion();
    clk.t = 1000;
    v.presented(clk.t);
    return r;
}

test "swipe (left-yes default): left answers Yes past the threshold, springs back before it, guards" {
    const gpa = testing.allocator;
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    var v = View.init(gpa);
    defer v.deinit();
    var clk: TestClock = .{};
    _ = try swipeSetup(gpa, &c, &v, &clk);
    const card = v.cardRect(1);
    const cx = card.x + card.w / 2;
    const cy = card.y + card.h / 2;
    // A swipe card shows no Yes/No buttons, only "⋯".
    try testing.expect(!v.showsButtons(&v.entries.items[1]));
    // Too early after the card appeared: a sideways drag does nothing.
    clk.t = 1300;
    try testing.expect(v.drag(.{ .phase = .down, .x = cx, .y = cy }) == null);
    _ = v.drag(.{ .phase = .move, .x = cx + 300, .y = cy });
    try testing.expect(v.drag(.{ .phase = .up, .x = cx + 300, .y = cy }) == null);
    try testing.expect(v.sent_n == null);
    // Later: short of the threshold springs back (an animation, then idle).
    clk.t = 2000;
    _ = v.drag(.{ .phase = .down, .x = cx, .y = cy });
    _ = v.drag(.{ .phase = .move, .x = cx - 60, .y = cy + 4 });
    try testing.expectEqual(@as(f32, -60), v.swipeOffset());
    try testing.expect(v.drag(.{ .phase = .up, .x = cx - 100, .y = cy }) == null);
    try testing.expectEqual(@as(?u32, anim_frame_ms), v.frameTimeout());
    clk.t += spring_ms;
    try testing.expectEqual(@as(f32, 0), v.swipeOffset());
    try testing.expect(v.frameTimeout() == null);
    // A vertical drag on the card scrolls, never answers.
    _ = v.drag(.{ .phase = .down, .x = cx, .y = cy });
    _ = v.drag(.{ .phase = .move, .x = cx + 20, .y = cy + 60 });
    _ = v.drag(.{ .phase = .move, .x = cx + 300, .y = cy + 60 });
    try testing.expect(v.drag(.{ .phase = .up, .x = cx + 300, .y = cy + 60 }) == null);
    // Past 40% to the left: Yes ("1"), the card flies off, its controls go.
    _ = v.drag(.{ .phase = .down, .x = cx, .y = cy });
    _ = v.drag(.{ .phase = .move, .x = cx - 40, .y = cy });
    try testing.expectEqualStrings("1", v.drag(.{ .phase = .up, .x = cx - 200, .y = cy }).?);
    try testing.expectEqual(@as(?u32, 2), v.sent_n);
    try testing.expect(v.frameTimeout() != null);
    clk.t += fly_ms;
    _ = v.swipeOffset();
    try testing.expect(v.frameTimeout() == null);
    // Answered here: no second swipe on it.
    _ = v.drag(.{ .phase = .down, .x = cx, .y = cy });
    _ = v.drag(.{ .phase = .move, .x = cx - 300, .y = cy });
    try testing.expect(v.drag(.{ .phase = .up, .x = cx - 300, .y = cy }) == null);
}

test "swipe: right answers No; only the newest open question; not off the card; arrows; right-yes" {
    const gpa = testing.allocator;
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    var v = View.init(gpa);
    defer v.deinit();
    var clk: TestClock = .{};
    const r = try swipeSetup(gpa, &c, &v, &clk);
    clk.t = 5000;
    var card = v.cardRect(1);
    var cx = card.x + card.w / 2;
    var cy = card.y + card.h / 2;
    // Starting off the card: scrolls only.
    _ = v.drag(.{ .phase = .down, .x = cx, .y = r.y + r.h - 1 });
    _ = v.drag(.{ .phase = .move, .x = cx - 300, .y = r.y + r.h - 1 });
    try testing.expect(v.drag(.{ .phase = .up, .x = cx - 300, .y = r.y + r.h - 1 }) == null);
    // A newer open question arrives (not Yes/No): the old card is no longer
    // swipeable, the new one is not either.
    const db = [_]wire.Option{ .{ .label = "A", .key = "1" }, .{ .label = "B", .key = "2" } };
    try testConvo(gpa, &c, false, &.{.{ .n = 3, .kind = .question, .text = "Pick", .open = true, .options = &db }});
    v.sync(&c);
    v.prepare(r, tm.fonts);
    card = v.cardRect(1);
    cx = card.x + card.w / 2;
    cy = card.y + card.h / 2;
    _ = v.drag(.{ .phase = .down, .x = cx, .y = cy });
    _ = v.drag(.{ .phase = .move, .x = cx - 300, .y = cy });
    try testing.expect(v.drag(.{ .phase = .up, .x = cx - 300, .y = cy }) == null);
    try testing.expectEqual(View.KeyResult.ignored, v.onKey(.left, .{}));
    // It is answered and closes: the Yes/No card is the newest open again.
    try testConvo(gpa, &c, false, &.{.{ .n = 3, .kind = .question, .text = "Pick", .open = false, .options = &db }});
    v.sync(&c);
    v.prepare(r, tm.fonts);
    v.shown_q = v.newestOpenQuestion();
    v.presented(clk.t); // same card as before: keeps its first appearance
    card = v.cardRect(1);
    cx = card.x + card.w / 2;
    cy = card.y + card.h / 2;
    _ = v.drag(.{ .phase = .down, .x = cx, .y = cy });
    _ = v.drag(.{ .phase = .move, .x = cx + 50, .y = cy });
    try testing.expectEqualStrings("esc", v.drag(.{ .phase = .up, .x = cx + 250, .y = cy }).?);
    // Arrow keys on a fresh card follow the setting: Left = Yes.
    const perm = [_]wire.Option{ .{ .label = "Yes", .key = "1" }, .{ .label = "No", .key = "esc" } };
    try testConvo(gpa, &c, false, &.{.{ .n = 4, .kind = .question, .text = "Again?", .open = true, .options = &perm }});
    v.sync(&c);
    v.prepare(r, tm.fonts);
    v.shown_q = v.newestOpenQuestion();
    v.presented(clk.t);
    try testing.expectEqual(View.KeyResult.ignored, v.onKey(.left, .{})); // too early
    clk.t += swipe_guard_ms;
    const kr = v.onKey(.left, .{});
    try testing.expectEqual(View.KeyResult.answer_yes, kr);
    try testing.expectEqualStrings("1", v.keyAnswer(kr).?);
    // right-yes: a right swipe on the next card says Yes.
    v.yes_side = .right;
    try testConvo(gpa, &c, false, &.{.{ .n = 6, .kind = .question, .text = "Once more?", .open = true, .options = &perm }});
    v.sync(&c);
    v.prepare(r, tm.fonts);
    v.shown_q = v.newestOpenQuestion();
    v.presented(clk.t);
    clk.t += swipe_guard_ms;
    card = v.cardRect(v.find(6).?);
    cx = card.x + card.w / 2;
    cy = card.y + card.h / 2;
    _ = v.drag(.{ .phase = .down, .x = cx, .y = cy });
    _ = v.drag(.{ .phase = .move, .x = cx + 50, .y = cy });
    try testing.expectEqualStrings("1", v.drag(.{ .phase = .up, .x = cx + 250, .y = cy }).?);
    const kn = v.onKey(.left, .{});
    try testing.expectEqual(View.KeyResult.ignored, kn); // answered: no more
}

test "the reveal button shows a swipe card's Yes / No buttons" {
    const gpa = testing.allocator;
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    var v = View.init(gpa);
    defer v.deinit();
    var clk: TestClock = .{};
    const r = try swipeSetup(gpa, &c, &v, &clk);
    const e = &v.entries.items[1];
    var reveal: ?Box = null;
    for (e.boxes.items) |b| if (b.kind == .reveal) {
        reveal = b;
    };
    const rb = reveal.?;
    try testing.expectEqual(ids.reveal, v.hitAt(v.col_x + rb.x + 2, r.y + e.y - v.top + rb.y + 2).?.button);
    try testing.expect(v.button(ids.reveal));
    try testing.expect(v.showsButtons(e));
    for (e.boxes.items) |b| if (b.kind == .option) {
        try testing.expect(v.hitAt(v.col_x + b.x + 2, r.y + e.y - v.top + b.y + 2) != null);
    };
}
