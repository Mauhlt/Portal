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
//!   question   a card. A question with exactly two options is a swipe
//!              card and has no buttons at all: Yes/No ones answer Yes on
//!              one side and No on the other (by default left: Yes, right:
//!              No, the owner being left-handed; `yes_side`, the device
//!              setting `swipe = left-yes | right-yes`), other pairs choose
//!              the first option on the Yes side, the second on the other
//!              (the card says which); the Left / Right arrows follow the
//!              same mapping. More than two options (or a multi-choice,
//!              which also gets Done = Enter) show large numbered buttons
//!              (the interaction bar's hit-target height) that answer with
//!              the option's key through the answer path (Host.answer,
//!              "k:<key>" and nothing else). Once answered the text stays
//!              and the controls go
//!
//! A tab without a transcript ("on": false) shows a friendly empty state
//! with a way to the terminal.
//!
//! Scrolling: the wheel, a vertical drag (touch or mouse), PageUp /
//! PageDown / Home / End. At the bottom the view follows new items; scrolled
//! up it keeps its place (anchored on the item at the top) and a pill
//! offers to jump to the newest.
//!
//! Swiping (the owner's "Tinder for agent questions"): a press on the card
//! grabs it (it grows to `grab_scale` and gives a short shake, plus a light
//! haptic through `haptic` on the iPhone); dragged sideways it follows the
//! pointer with a slight tilt, its colour moving from the held neutral light
//! towards green (the Yes side) or red (the No side), full at the threshold
//! (`swipeTint`; colour only, no text, no transparency). Guarded against
//! accidental approvals: only the newest open question, only two-option
//! ones (`swipeMap`), only a drag whose horizontal movement dominates (`classify`;
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

/// The view's own button ids (shell.ids.view0 ..): the new-messages pill.
pub const ids = struct {
    pub const base: u32 = 1300;
    pub const pill: u32 = base;
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
/// Grab feedback: the held card's size, reached in `grab_in_ms`, and a
/// shake of three small rotations (`shake_deg`) decaying over `shake_ms`.
pub const grab_scale: f32 = 1.045;
pub const grab_in_ms: i64 = 120;
pub const shake_ms: i64 = 180;
pub const shake_deg: f32 = 2;
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

/// What a swipe card's two sides answer: `yes` on the Yes side, `no` on
/// the other. A Yes/No question maps its Yes and No options; any other
/// two-option question its first option to the Yes side, its second to the
/// other (`yes_no` false: shown as a choice, not as approval). Null: not a
/// swipe card (no options, one, more than two, or a multi-choice).
pub const SwipeMap = struct {
    yes: []const u8,
    no: []const u8,
    yes_label: []const u8,
    no_label: []const u8,
    yes_no: bool,
};

pub fn swipeMap(it: anytype) ?SwipeMap {
    if (it.kind != .question or it.multi or it.options.len != 2) return null;
    const o = it.options;
    if (yesNo(it)) |yn| {
        const first_yes = std.mem.eql(u8, yn.yes, o[0].key);
        return .{ .yes = yn.yes, .no = yn.no, .yes_label = if (first_yes) o[0].label else o[1].label, .no_label = if (first_yes) o[1].label else o[0].label, .yes_no = true };
    }
    return .{ .yes = o[0].key, .no = o[1].key, .yes_label = o[0].label, .no_label = o[1].label, .yes_no = false };
}

/// The key of option button `opt` of `e` (one past the options: Done =
/// Enter, a multi-choice's submit).
fn optionKey(e: anytype, opt: u8) []const u8 {
    return if (opt < e.options.len) e.options[opt].key else "enter";
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

/// `key = on | off` from a settings file's text (null: not set or not
/// understood).
pub fn parseOnOffSetting(text: []const u8, key: []const u8) ?bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var out: ?bool = null;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        if (!std.mem.eql(u8, std.mem.trim(u8, line[0..eq], " \t"), key)) continue;
        const val = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(val, "on")) out = true else if (std.ascii.eqlIgnoreCase(val, "off")) out = false;
    }
    return out;
}

test "on/off settings" {
    try testing.expectEqual(@as(?bool, false), parseOnOffSetting("swipe = left-yes\r\nbackground_art = off\r\n", "background_art"));
    try testing.expectEqual(@as(?bool, true), parseOnOffSetting("background_art=ON", "background_art"));
    try testing.expectEqual(@as(?bool, null), parseOnOffSetting("# background_art = off\nbackground_art = maybe", "background_art"));
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

/// The held card's scale `since` ms after the grab (eased in).
pub fn grabScale(since: i64) f32 {
    const t = std.math.clamp(@as(f32, @floatFromInt(since)) / @as(f32, @floatFromInt(grab_in_ms)), 0, 1);
    return 1 + (grab_scale - 1) * (1 - (1 - t) * (1 - t));
}

/// The grab shake's rotation (radians) `since` ms after the grab: three
/// quick swings, decaying to nothing at `shake_ms`.
pub fn grabShake(since: i64) f32 {
    if (since <= 0 or since >= shake_ms) return 0;
    const t = @as(f32, @floatFromInt(since)) / @as(f32, @floatFromInt(shake_ms));
    return shake_deg * std.math.pi / 180 * @sin(2 * std.math.pi * 3 * t) * (1 - t);
}

/// A held swipe card's colours at `offset` px (threshold `need` px):
/// a neutral light border at rest, towards meadow green on the Yes side and
/// sunset red on the No side, fully there at the threshold; the fill is the
/// border tinting the card. Opaque: colour only.
pub const Tint = struct { border: Rgb, fill: Rgb };
pub fn swipeTint(offset: f32, need: f32, ys: YesSide, yes_no: bool) Tint {
    const hold = theme.ui.swipe_hold;
    const k = if (offset == 0 or !(need > 0)) 0 else std.math.clamp(@abs(offset) / need, 0, 1);
    const target: Rgb = if (!yes_no) theme.ui.swipe_choice else if (ys.answer(if (offset > 0) .right else .left) == .yes) theme.ui.swipe_yes else theme.ui.swipe_no;
    const border = mix(hold, target, k);
    return .{ .border = border, .fill = mix(border, theme.ui.card, 0.82) };
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
    const card = theme.ui.card;
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
    kind: enum { fill, outline, card, option } = .fill,
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
    /// A question card's header line (owned; laid out with it).
    head: []u8 = &.{},
    /// Top in the content (set each prepare).
    y: f32 = 0,

    fn deinit(e: *Entry, gpa: std.mem.Allocator) void {
        gpa.free(e.text);
        for (e.options) |o| {
            gpa.free(o.label);
            gpa.free(o.key);
        }
        gpa.free(e.options);
        gpa.free(e.head);
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

/// An option's label for a card header or button: cut at the first scrub
/// placeholder ("[path]", "[user]": the desktop removed a path or name
/// there, and "Beta in [path]" reads as noise), then without trailing
/// joiner words ("in", "at", "for", "from", "to", "on", "of") and
/// punctuation. Nothing left: the label as it was.
pub fn shortLabel(label: []const u8) []const u8 {
    var end = label.len;
    for ([_][]const u8{ "[path]", "[user]" }) |mark| {
        if (std.mem.indexOf(u8, label[0..end], mark)) |i| end = i;
    }
    if (end == label.len) return label;
    var s = label[0..end];
    const joiners = [_][]const u8{ "in", "at", "for", "from", "to", "on", "of", "by", "with" };
    while (true) {
        const before = s.len;
        s = std.mem.trimEnd(u8, s, " \t,;:.-()\"'");
        const sp = std.mem.lastIndexOfScalar(u8, s, ' ');
        const word = std.mem.trimStart(u8, if (sp) |k| s[k + 1 ..] else s, "(\"'");
        for (joiners) |w| if (std.ascii.eqlIgnoreCase(word, w)) {
            s = s[0 .. sp orelse 0];
            break;
        };
        if (s.len == before) break;
    }
    return if (s.len == 0) label else s;
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
        const label = try gpa.dupe(u8, shortLabel(o.label));
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
    /// When the card was grabbed (its feedback; the answer guard counts
    /// from the card's appearance to this press).
    grab_t0: i64 = 0,
    /// The card's scale when released: a fly-off keeps it, a spring-back
    /// returns from it.
    rel_k: f32 = 1,
};

/// A light haptic tap on grabbing a card (the iPhone's
/// UIImpactFeedbackGenerator .light, through the device's window layer);
/// none on desktops.
pub const Haptic = struct {
    ctx: ?*anyopaque = null,
    grab: *const fn (ctx: ?*anyopaque) void,
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
    /// The device's grab haptic (hapticGrab), if any.
    haptic: ?Haptic = null,

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

    /// The newest open question's numbered options ("1".."9" keys, from
    /// the first; 0 without one), and whether its card answers it on
    /// screen (a swipe card or option buttons). The shell's instruct
    /// panel offers the number keys only when no card does.
    pub fn questionKeys(v: *const View) struct { digits: u8, card: bool } {
        const n = v.newestOpenQuestion() orelse return .{ .digits = 0, .card = false };
        const e = &v.entries.items[v.find(n) orelse return .{ .digits = 0, .card = false }];
        var d: u8 = 0;
        for (e.options) |o| {
            if (o.key.len != 1 or o.key[0] != '1' + d or d == 9) break;
            d += 1;
        }
        const card = v.answers and v.sent_n != n and (swipeMap(e.*) != null or v.showsButtons(e));
        return .{ .digits = d, .card = card };
    }

    /// Item `n` can be swiped now: the newest open question, two options,
    /// its answer not sent yet, answers accepted.
    fn isSwipeable(v: *const View, n: u32) bool {
        if (!v.answers or v.sent_n == n) return false;
        if (v.newestOpenQuestion() != n) return false;
        const i = v.find(n) orelse return false;
        return swipeMap(v.entries.items[i]) != null;
    }

    /// Whether card `e` shows option buttons: open, not answered here, and
    /// not a swipe card (two options never get buttons).
    fn showsButtons(v: *const View, e: *const Entry) bool {
        if (e.kind != .question or !e.open or e.options.len == 0 or v.sent_n == e.n) return false;
        return swipeMap(e.*) == null;
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
        const map = swipeMap(e.*);
        e.boxes.append(v.gpa, .{ .x = 0, .y = 0, .w = W, .h = 0, .color = if (e.open) colors.card else colors.card_closed, .kind = .card }) catch {};
        e.boxes.append(v.gpa, .{ .x = 0, .y = 0, .w = W, .h = 0, .color = if (e.open) theme.ui.question else theme.ui.border, .kind = .outline }) catch {};
        var y = g.qpad;
        // The header: what the card is waiting for (a swipe card says which
        // way gives which answer).
        v.gpa.free(e.head);
        e.head = &.{};
        const yes_dir: []const u8 = if (v.yes_side == .left) "left" else "right";
        const no_dir: []const u8 = if (v.yes_side == .left) "right" else "left";
        e.head = if (!e.open)
            v.gpa.dupe(u8, "Question \u{00B7} answered") catch &.{}
        else if (map) |sm| (if (sm.yes_no)
            std.fmt.allocPrint(v.gpa, "Question \u{00B7} swipe {s} for Yes, {s} for No", .{ yes_dir, no_dir }) catch &.{}
        else
            std.fmt.allocPrint(v.gpa, "Question \u{00B7} swipe {s}: {s} \u{00B7} {s}: {s}", .{ yes_dir, sm.yes_label, no_dir, sm.no_label }) catch &.{})
        else
            v.gpa.dupe(u8, "Question \u{00B7} waiting for your answer") catch &.{};
        e.lines.append(v.gpa, .{ .str = frame.clipText(f.small, e.head, inner, false), .x = g.qpad, .y = y, .font = .small, .color = if (e.open) theme.ui.question_head else theme.ui.dim, .bold = true }) catch {};
        y += g.slh + @round(4 * g.s);
        y += v.layoutText(e, f, g, e.text, g.qpad, y, inner, theme.ui.text, .body, false).h;
        if (e.open and e.multi) {
            e.lines.append(v.gpa, .{ .str = "Choose any, then Enter.", .x = g.qpad, .y = y, .font = .small, .color = theme.ui.dim }) catch {};
            y += g.slh;
        }
        if (v.showsButtons(e)) {
            y += g.bgap;
            const cw: f32 = @floatFromInt(f.act.cell_w);
            var x = g.qpad;
            // A multi-choice submits with Done (Enter).
            const n_buttons = e.options.len + @intFromBool(e.multi);
            for (0..n_buttons) |i| {
                const o: wire.Option = if (i < e.options.len) e.options[i] else .{ .label = "Done", .key = "enter" };
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
        } else if (e.open and e.options.len == 0) {
            e.lines.append(v.gpa, .{ .str = "Answer it in the Terminal view.", .x = g.qpad, .y = y + @round(4 * g.s), .font = .small, .color = theme.ui.dim }) catch {};
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
        const yn = swipeMap(v.entries.items[i]) orelse return null;
        return switch (r) {
            .answer_yes => yn.yes,
            .answer_no => yn.no,
            else => null,
        };
    }

    pub fn button(v: *View, id: u32) bool {
        switch (id) {
            ids.pill => v.jumpToBottom(),
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

    /// Item `n` is laid out again (its controls changed).
    fn invalidate(v: *View, n: ?u32) void {
        const i = v.find(n orelse return) orelse return;
        v.entries.items[i].laid = false;
    }

    fn fly(v: *View, to: f32) void {
        const n = v.swipe.n orelse return;
        v.invalidate(n);
        v.sent_n = n;
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
                v.swipe = .{ .phase = .pending, .x0 = d.x, .y0 = d.y, .last_y = d.y };
                // On the newest open Yes/No card: grab it (the feedback
                // comes at once; the guard applies to answering).
                const n = v.newestOpenQuestion() orelse return null;
                if (!v.isSwipeable(n)) return null;
                const i = v.find(n).?;
                if (!v.cardRect(i).contains(d.x, d.y)) return null;
                v.swipe.n = n;
                v.swipe.grab_t0 = v.clock.ms();
                v.hapticGrab();
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
                    v.swipe.rel_k = v.cardScale();
                    const dir = commitSide(v.swipe.offset, v.colw, d.scale);
                    // Past the threshold, shown long enough before the
                    // press, and still the newest open Yes/No card?
                    const shown = guardPassed(if (v.appear_n == n) v.appear_ms else null, v.swipe.grab_t0);
                    if (dir != null and shown and v.isSwipeable(n)) {
                        const yn = swipeMap(v.entries.items[v.find(n).?]).?;
                        v.fly(if (dir.? == .right) v.rect.w else -v.rect.w);
                        return if (v.yes_side.answer(dir.?) == .yes) yn.yes else yn.no;
                    }
                    v.springBack();
                },
                // Grabbed and let go without a drag: back to size.
                .pending => if (v.swipe.n != null) {
                    v.swipe.rel_k = v.cardScale();
                    v.springBack();
                } else {
                    v.swipe = .{};
                },
                else => v.swipe = .{},
            },
        }
        return null;
    }

    fn springBack(v: *View) void {
        v.swipe.phase = .springing;
        v.swipe.from = v.swipe.offset;
        v.swipe.to = 0;
        v.swipe.t0 = v.clock.ms();
    }

    /// The device's grab haptic, if it has one.
    pub fn hapticGrab(v: *const View) void {
        if (v.haptic) |h| h.grab(h.ctx);
    }

    /// The grabbed card is held (pressed, maybe dragging).
    pub fn held(v: *const View) bool {
        return v.swipe.n != null and (v.swipe.phase == .pending or v.swipe.phase == .swiping);
    }

    fn animT(v: *const View) f32 {
        const dur = if (v.swipe.phase == .flying) fly_ms else spring_ms;
        return std.math.clamp(@as(f32, @floatFromInt(v.clock.ms() - v.swipe.t0)) / @as(f32, @floatFromInt(dur)), 0, 1);
    }

    /// The grabbed card's scale now: growing while held, kept by a fly-off,
    /// back to 1 with a spring-back.
    pub fn cardScale(v: *const View) f32 {
        if (v.swipe.n == null) return 1;
        return switch (v.swipe.phase) {
            .pending, .swiping => grabScale(v.clock.ms() - v.swipe.grab_t0),
            .flying => v.swipe.rel_k,
            .springing => blk: {
                const t = v.animT();
                break :blk v.swipe.rel_k + (1 - v.swipe.rel_k) * (1 - (1 - t) * (1 - t));
            },
            else => 1,
        };
    }

    /// The grab shake's rotation now (radians).
    pub fn cardShake(v: *const View) f32 {
        if (v.swipe.n == null or v.swipe.phase == .idle or v.swipe.phase == .scrolling) return 0;
        return grabShake(v.clock.ms() - v.swipe.grab_t0);
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
            // The grab's scale-in and shake; then frames follow the pointer.
            .pending, .swiping => if (v.swipe.n != null and v.clock.ms() - v.swipe.grab_t0 < @max(grab_in_ms, shake_ms)) anim_frame_ms else null,
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
                if (b.kind == .option and v.answers and v.showsButtons(e)) return .{ .answer = optionKey(e, b.opt) };
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
        const k = v.cardScale();
        const shake = v.cardShake();
        const newest_q = v.newestOpenQuestion();
        for (v.entries.items) |*e| {
            if (!v.visible(e.*)) continue;
            if (newest_q == e.n) v.shown_q = e.n;
            if (v.swipe.n == e.n and (v.held() or offset != 0 or k != 1)) {
                // The grabbed card: moved, tilted, scaled, tinted.
                const fk: Fonts = if (k == 1) f else .{ .body = p.metrics(body_em * k), .small = p.metrics(small_em * k), .act = p.metrics(frame.action_em * k), .s = f.s };
                const need = @max(v.colw * swipe_share, swipe_min_px * f.s);
                const tilt = std.math.clamp(offset / @max(1, v.colw), -1.5, 1.5) * 0.12 + shake;
                v.paintEntry(p, e, fk, v.col_x, r.y + e.y - v.top, .{ .dx = offset, .tilt = tilt, .k = k, .cx = v.colw / 2, .cy = e.height / 2, .tint = swipeTint(offset, need, v.yes_side, if (swipeMap(e.*)) |sm| sm.yes_no else true) });
            } else {
                v.paintEntry(p, e, f, v.col_x, r.y + e.y - v.top, .{});
            }
        }
        if (v.pillRect()) |pl| {
            p.fill(pl.r.x, pl.r.y, pl.r.w, pl.r.h, theme.ui.button_active);
            p.frameRect(pl.r.x, pl.r.y, pl.r.w, pl.r.h, @max(1, @round(p.s)), theme.ui.focus);
            _ = p.run(f.small, pl.r.x + @round((pl.r.w - textWidth(f.small, pl.label)) / 2), pl.r.y + @round((pl.r.h - @as(f32, @floatFromInt(f.small.cell_h))) / 2), pl.label, theme.ui.text, true, false, null);
            p.tapButton(pl.r.x, pl.r.y, pl.r.w, pl.r.h, ids.pill);
        }
    }

    /// Paints item `e` at (ox, oy), transformed by `xf` (the grabbed card).
    fn paintEntry(v: *View, p: *frame.Painter, e: *Entry, f: Fonts, ox: f32, oy: f32, xf: Xform) void {
        const buttons = v.showsButtons(e);
        const plain = xf.plain() and xf.tint == null;
        for (e.boxes.items) |b| {
            if (b.kind == .option and !buttons) continue;
            var c = b.color;
            if (xf.tint) |t| switch (b.kind) {
                .card => c = t.fill,
                .outline => c = t.border,
                else => {},
            };
            if (b.kind == .outline) {
                const th = @max(1, @round(f.s * (if (e.open) @as(f32, 2) else 1)));
                if (xf.plain()) {
                    p.frameRect(ox + b.x, oy + b.y, b.w, b.h, th, c);
                } else {
                    const y0 = xf.ty(b.y);
                    const y1 = xf.ty(b.y + b.h);
                    p.fill(ox + xf.tx(b.x, y0), oy + y0, b.w * xf.k, th, c);
                    p.fill(ox + xf.tx(b.x, y1), oy + y1 - th, b.w * xf.k, th, c);
                    slices(p, ox, oy, b.x, b.y, th / xf.k, b.h, xf, c, f.s);
                    slices(p, ox, oy, b.x + b.w - th / xf.k, b.y, th / xf.k, b.h, xf, c, f.s);
                }
                continue;
            }
            if (xf.plain()) {
                p.fill(ox + b.x, oy + b.y, b.w, b.h, c);
                if (b.kind == .option and !v.answers) p.frameRect(ox + b.x, oy + b.y, b.w, b.h, @max(1, @round(f.s)), theme.ui.border);
            } else {
                slices(p, ox, oy, b.x, b.y, b.w, b.h, xf, c, f.s);
            }
            if (!plain) continue;
            if (b.kind == .option and v.answers) p.tapAnswer(ox + b.x, oy + b.y, b.w, b.h, optionKey(e, b.opt));
        }
        for (e.lines.items) |l| {
            if (l.opt != null and !buttons) continue;
            const m = metricsOf(f, l.font);
            const color = if (l.opt != null and !v.answers) theme.ui.dim else l.color;
            if (xf.plain()) {
                _ = p.run(m, ox + l.x, oy + l.y, l.str, color, l.bold, l.italic, if (l.x1) |x1| ox + x1 else null);
                continue;
            }
            const y = xf.ty(l.y);
            const mid = y + @as(f32, @floatFromInt(m.cell_h)) / 2;
            _ = p.run(m, @round(ox + xf.tx(l.x, mid)), @round(oy + y), l.str, color, l.bold, l.italic, if (l.x1) |x1| ox + xf.tx(x1, mid) else null);
        }
    }
};

/// The grabbed card's transform, in item coordinates (x from the column's
/// left, y from the item's top): scaled by `k` about (cx, cy), moved by
/// `dx`, tilted (rows shifted in proportion to their height: a small
/// rotation's look with axis-aligned rectangles), tinted.
const Xform = struct {
    dx: f32 = 0,
    tilt: f32 = 0,
    k: f32 = 1,
    cx: f32 = 0,
    cy: f32 = 0,
    tint: ?Tint = null,

    fn plain(t: Xform) bool {
        return t.dx == 0 and t.tilt == 0 and t.k == 1;
    }
    /// A y after the transform.
    fn ty(t: Xform, y: f32) f32 {
        return t.cy + (y - t.cy) * t.k;
    }
    /// An x after the transform, on the (transformed) row `y_t`.
    fn tx(t: Xform, x: f32, y_t: f32) f32 {
        return t.cx + (x - t.cx) * t.k + t.dx + t.tilt * (y_t - t.cy);
    }
};

/// A box (item coordinates) drawn transformed, as horizontal strips each
/// shifted by the tilt at its height.
fn slices(p: *frame.Painter, ox: f32, oy: f32, x: f32, y: f32, w: f32, h: f32, xf: Xform, c: Rgb, s: f32) void {
    const step = @max(2, @round(3 * s));
    const y0 = xf.ty(y);
    const y1 = xf.ty(y + h);
    var yy = y0;
    while (yy < y1) : (yy += step) {
        const sh = @min(step, y1 - yy);
        p.fill(@round(ox + xf.tx(x, yy + sh / 2)), @round(oy + yy), @round(w * xf.k), sh, c);
    }
}

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
        .{ .k = .text, .l = "Here:" }, .{ .k = .fence, .l = "```zig" }, .{ .k = .code, .l = "const x = 1;" },
        .{ .k = .code, .l = "  y" },   .{ .k = .fence, .l = "```" },    .{ .k = .text, .l = "done" },
        .{ .k = .fence, .l = "```" },  .{ .k = .code, .l = "open" },
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
    // A swipe card shows no Yes/No buttons.
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

test "no answer without a committed swipe: short drags either way, re-synced (reconnected) and fresh (restarted) views, stray releases" {
    const gpa = testing.allocator;
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    var v = View.init(gpa);
    defer v.deinit();
    var clk: TestClock = .{};
    const r = try swipeSetup(gpa, &c, &v, &clk);
    clk.t = 5000;
    const card = v.cardRect(1);
    const cx = card.x + card.w / 2;
    const cy = card.y + card.h / 2;
    const need = @max(card.w * swipe_share, swipe_min_px);
    // Released short, right and left, at every distance below the
    // threshold (and moved past it, then back): never an answer.
    var off: f32 = 4;
    while (off < need) : (off += 7) {
        for ([_]f32{ off, -off }) |dx| {
            try testing.expect(v.drag(.{ .phase = .down, .x = cx, .y = cy }) == null);
            try testing.expect(v.drag(.{ .phase = .move, .x = cx + dx / 2, .y = cy + 1 }) == null);
            try testing.expect(v.drag(.{ .phase = .move, .x = cx + dx * 3, .y = cy + 1 }) == null);
            try testing.expect(v.drag(.{ .phase = .move, .x = cx + dx, .y = cy + 2 }) == null);
            try testing.expect(v.drag(.{ .phase = .up, .x = cx + dx, .y = cy + 2 }) == null);
            clk.t += spring_ms;
        }
    }
    try testing.expect(v.sent_n == null);
    // Held while the conversation is sent again (a reconnect's snapshot),
    // then released short: nothing; a stray release or move: nothing.
    _ = v.drag(.{ .phase = .down, .x = cx, .y = cy });
    _ = v.drag(.{ .phase = .move, .x = cx + 60, .y = cy });
    const perm = [_]wire.Option{ .{ .label = "Yes", .key = "1" }, .{ .label = "No", .key = "esc" } };
    try testConvo(gpa, &c, true, &.{ .{ .n = 1, .kind = .assistant, .text = "May I run the tests?" }, .{ .n = 2, .kind = .question, .text = "Run npm test?", .open = true, .options = &perm } });
    v.sync(&c);
    v.prepare(r, tm.fonts);
    try testing.expect(v.drag(.{ .phase = .up, .x = cx + 60, .y = cy }) == null);
    try testing.expect(v.drag(.{ .phase = .up, .x = cx - 300, .y = cy }) == null);
    try testing.expect(v.drag(.{ .phase = .move, .x = cx - 300, .y = cy }) == null);
    try testing.expect(v.drag(.{ .phase = .up, .x = cx - 300, .y = cy }) == null);
    try testing.expect(v.sent_n == null);
    // A fresh view (the client restarted) on the same open question: a
    // release without a press, then a press and a short release.
    var v2 = View.init(gpa);
    defer v2.deinit();
    v2.clock = clk.clock();
    v2.sync(&c);
    v2.prepare(r, tm.fonts);
    v2.shown_q = v2.newestOpenQuestion();
    v2.presented(clk.t);
    try testing.expect(v2.drag(.{ .phase = .up, .x = cx - 300, .y = cy }) == null);
    clk.t += swipe_guard_ms;
    _ = v2.drag(.{ .phase = .down, .x = cx, .y = cy });
    _ = v2.drag(.{ .phase = .move, .x = cx + 40, .y = cy });
    try testing.expect(v2.drag(.{ .phase = .up, .x = cx + 40, .y = cy }) == null);
    try testing.expectEqual(View.KeyResult.ignored, v2.onKey(.up, .{}));
    try testing.expect(v2.sent_n == null);
}


test "two options never get buttons (Yes/No or a choice); more than two do; multi-choice gets Done" {
    const gpa = testing.allocator;
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    var v = View.init(gpa);
    defer v.deinit();
    var clk: TestClock = .{};
    const r = try swipeSetup(gpa, &c, &v, &clk);
    const yn = &v.entries.items[1];
    for (yn.boxes.items) |b| try testing.expect(b.kind != .option);
    try testing.expect(!v.showsButtons(yn));
    // A two-option choice: a swipe card too, first option on the Yes side.
    const db = [_]wire.Option{ .{ .label = "Postgres", .key = "1" }, .{ .label = "SQLite", .key = "2" } };
    const three = [_]wire.Option{ .{ .label = "A", .key = "1" }, .{ .label = "B", .key = "2" }, .{ .label = "C", .key = "3" } };
    const multi = [_]wire.Option{ .{ .label = "X", .key = "1" }, .{ .label = "Y", .key = "2" } };
    try testConvo(gpa, &c, false, &.{
        .{ .n = 3, .kind = .question, .text = "Which DB?", .open = true, .options = &db },
        .{ .n = 4, .kind = .question, .text = "Pick", .open = true, .options = &three },
        .{ .n = 5, .kind = .question, .text = "Any?", .open = true, .multi = true, .options = &multi },
    });
    v.sync(&c);
    v.prepare(r, tm.fonts);
    const sm = swipeMap(v.entries.items[2]).?;
    try testing.expect(!sm.yes_no);
    try testing.expectEqualStrings("1", sm.yes);
    try testing.expectEqualStrings("Postgres", sm.yes_label);
    try testing.expectEqualStrings("Question \u{00B7} swipe left: Postgres \u{00B7} right: SQLite", v.entries.items[2].head);
    for (v.entries.items[2].boxes.items) |b| try testing.expect(b.kind != .option);
    // Its tint is the neutral choice colour on both sides.
    try testing.expectEqual(theme.ui.swipe_choice, swipeTint(-300, 200, .left, false).border);
    try testing.expectEqual(theme.ui.swipe_choice, swipeTint(300, 200, .left, false).border);
    var count = [_]usize{ 0, 0 };
    for (v.entries.items[3].boxes.items) |b| count[0] += @intFromBool(b.kind == .option);
    for (v.entries.items[4].boxes.items) |b| count[1] += @intFromBool(b.kind == .option);
    try testing.expectEqual(@as(usize, 3), count[0]);
    try testing.expectEqual(@as(usize, 3), count[1]); // X, Y, Done
    // Done sends Enter.
    const e5 = &v.entries.items[4];
    const done = e5.boxes.items[e5.boxes.items.len - 1];
    try testing.expectEqualStrings("enter", v.hitAt(v.col_x + done.x + 2, r.y + e5.y - v.top + done.y + 2).?.answer);
}

test "swipe tint: neutral held, towards green on the Yes side, red on the No side, full at the threshold" {
    const need: f32 = 200;
    const hold = theme.ui.swipe_hold;
    try testing.expectEqual(hold, swipeTint(0, need, .left, true).border);
    // left-yes: left goes green, right goes red.
    try testing.expectEqual(mix(hold, theme.ui.swipe_yes, 0.5), swipeTint(-100, need, .left, true).border);
    try testing.expectEqual(theme.ui.swipe_yes, swipeTint(-200, need, .left, true).border);
    try testing.expectEqual(theme.ui.swipe_yes, swipeTint(-500, need, .left, true).border);
    try testing.expectEqual(mix(hold, theme.ui.swipe_no, 0.5), swipeTint(100, need, .left, true).border);
    try testing.expectEqual(theme.ui.swipe_no, swipeTint(200, need, .left, true).border);
    // right-yes: the other way round.
    try testing.expectEqual(theme.ui.swipe_yes, swipeTint(200, need, .right, true).border);
    try testing.expectEqual(theme.ui.swipe_no, swipeTint(-200, need, .right, true).border);
    // The fill is the border tinting the card (opaque).
    try testing.expectEqual(mix(theme.ui.swipe_no, theme.ui.card, 0.82), swipeTint(200, need, .left, true).fill);
}

test "grab: scaled and shaking at once, enlarged while held, springs back to 1, flies off from the enlarged size" {
    const gpa = testing.allocator;
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    var v = View.init(gpa);
    defer v.deinit();
    var clk: TestClock = .{};
    _ = try swipeSetup(gpa, &c, &v, &clk);
    const Hap = struct {
        var n: usize = 0;
        fn grab(_: ?*anyopaque) void {
            n += 1;
        }
    };
    v.haptic = .{ .grab = Hap.grab };
    // Grabbed within the guard: the feedback comes anyway.
    clk.t = 1100;
    const card = v.cardRect(1);
    const cx = card.x + card.w / 2;
    const cy = card.y + card.h / 2;
    _ = v.drag(.{ .phase = .down, .x = cx, .y = cy });
    try testing.expect(v.held());
    try testing.expectEqual(@as(usize, 1), Hap.n);
    try testing.expectEqual(@as(f32, 1), v.cardScale());
    try testing.expectEqual(@as(?u32, anim_frame_ms), v.frameTimeout());
    clk.t += 40;
    try testing.expect(v.cardScale() > 1 and v.cardScale() < grab_scale);
    try testing.expect(v.cardShake() != 0 and @abs(v.cardShake()) <= shake_deg * std.math.pi / 180);
    clk.t += 200;
    try testing.expectEqual(grab_scale, v.cardScale());
    try testing.expectEqual(@as(f32, 0), v.cardShake());
    try testing.expect(v.frameTimeout() == null); // held still: no frames
    // Dragged past the threshold but pressed too early: springs back.
    _ = v.drag(.{ .phase = .move, .x = cx - 50, .y = cy });
    try testing.expect(v.drag(.{ .phase = .up, .x = cx - 300, .y = cy }) == null);
    try testing.expectEqual(grab_scale, v.cardScale());
    clk.t += spring_ms / 2;
    try testing.expect(v.cardScale() > 1 and v.cardScale() < grab_scale);
    clk.t += spring_ms;
    _ = v.swipeOffset();
    try testing.expectEqual(@as(f32, 1), v.cardScale());
    try testing.expect(v.frameTimeout() == null);
    // A tap on the card (no drag): grows, then back to size.
    _ = v.drag(.{ .phase = .down, .x = cx, .y = cy });
    clk.t += 150;
    try testing.expect(v.drag(.{ .phase = .up, .x = cx, .y = cy }) == null);
    try testing.expect(v.frameTimeout() != null);
    clk.t += spring_ms;
    _ = v.swipeOffset();
    try testing.expectEqual(@as(f32, 1), v.cardScale());
    // Later: below the threshold springs back, past it flies off enlarged.
    _ = v.drag(.{ .phase = .down, .x = cx, .y = cy });
    clk.t += 150;
    _ = v.drag(.{ .phase = .move, .x = cx - 50, .y = cy });
    try testing.expect(v.drag(.{ .phase = .up, .x = cx - 120, .y = cy }) == null);
    clk.t += spring_ms;
    _ = v.swipeOffset();
    try testing.expect(!v.held() and v.cardScale() == 1);
    _ = v.drag(.{ .phase = .down, .x = cx, .y = cy });
    clk.t += 150;
    _ = v.drag(.{ .phase = .move, .x = cx - 50, .y = cy });
    try testing.expectEqualStrings("1", v.drag(.{ .phase = .up, .x = cx - 400, .y = cy }).?);
    try testing.expectEqual(grab_scale, v.cardScale());
    clk.t += fly_ms / 2;
    try testing.expectEqual(grab_scale, v.cardScale());
    try testing.expectEqual(@as(usize, 4), Hap.n);
}

test "drawing a held card: tinted, enlarged, no text stamp, opaque" {
    const gpa = testing.allocator;
    var fonts = Font.fontset.FontSet.load(gpa, testing.io) catch return error.SkipZigTest;
    defer fonts.deinit();
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    var v = View.init(gpa);
    defer v.deinit();
    var clk: TestClock = .{};
    const perm = [_]wire.Option{ .{ .label = "Yes", .key = "1" }, .{ .label = "No", .key = "esc" } };
    try testConvo(gpa, &c, true, &.{.{ .n = 2, .kind = .question, .text = "Run npm test?", .open = true, .options = &perm }});
    v.clock = clk.clock();
    v.sync(&c);
    var fr = frame.Frame.init(gpa, .fit_grid);
    defer fr.deinit();
    var g: @import("grid.zig").Grid = .{};
    const o: frame.Overlay = .{ .screen = .{ .view = v.contentView() } };
    fr.build(&fonts, .{ 1200, 600 }, 1, &g, o);
    v.presented(0);
    const card = v.cardRect(0);
    clk.t = 2000;
    _ = v.drag(.{ .phase = .down, .x = card.x + 40, .y = card.y + 20 });
    clk.t += 300;
    _ = v.drag(.{ .phase = .move, .x = card.x + 40 - 100, .y = card.y + 20 });
    fr.build(&fonts, .{ 1200, 600 }, 1, &g, o);
    const need = @max(v.colw * swipe_share, swipe_min_px);
    const want = swipeTint(-100, need, .left, true).border;
    var tinted = false;
    var widest: f32 = 0;
    for (fr.list.cmds.items) |cmd| switch (cmd) {
        .rect => |r| {
            try testing.expectEqual(@as(u8, 255), r.color[3]);
            if (r.color[0] == want[0] and r.color[1] == want[1] and r.color[2] == want[2]) {
                tinted = true;
                widest = @max(widest, r.w);
            }
        },
        .text => |t| {
            try testing.expectEqual(@as(u8, 255), t.color[3]);
            const str = fr.list.textOf(t);
            try testing.expect(!std.mem.eql(u8, str, "YES") and !std.mem.eql(u8, str, "NO"));
        },
        else => {},
    };
    try testing.expect(tinted);
    // The border's top edge: the card's width, enlarged.
    try testing.expect(widest > v.colw);
}

test "option labels: cut at a scrub placeholder, no trailing joiner words" {
    try testing.expectEqualStrings("Beta", shortLabel("Beta in [path]"));
    try testing.expectEqualStrings("Ask", shortLabel("Ask [user]"));
    try testing.expectEqualStrings("Copy the file", shortLabel("Copy the file from [path] to [path]"));
    try testing.expectEqualStrings("Open it", shortLabel("Open it, at: [path]"));
    try testing.expectEqualStrings("Save", shortLabel("Save to (in [path])"));
    // No placeholder: unchanged, joiner words and all.
    try testing.expectEqualStrings("Log in", shortLabel("Log in"));
    try testing.expectEqualStrings("Alpha", shortLabel("Alpha"));
    // Nothing left: the label as it was.
    try testing.expectEqualStrings("[path]", shortLabel("[path]"));
    try testing.expectEqualStrings("in [path]", shortLabel("in [path]"));
    // The card header uses the short labels.
    const gpa = testing.allocator;
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    var v = View.init(gpa);
    defer v.deinit();
    const opts = [_]wire.Option{ .{ .label = "Alpha", .key = "1" }, .{ .label = "Beta in [path]", .key = "2" } };
    try testConvo(gpa, &c, true, &.{.{ .n = 1, .kind = .question, .text = "Which?", .open = true, .options = &opts }});
    v.sync(&c);
    try testing.expectEqualStrings("Beta", v.entries.items[0].options[1].label);
    const sm = swipeMap(v.entries.items[0]).?;
    try testing.expectEqualStrings("Beta", sm.no_label);
}

test "questionKeys: numbered options, and whether a card answers them" {
    const gpa = testing.allocator;
    var c: convo.Conversation = .{};
    defer c.deinit(gpa);
    var v = View.init(gpa);
    defer v.deinit();
    try testing.expectEqual(@as(u8, 0), v.questionKeys().digits);
    const three = [_]wire.Option{ .{ .label = "A", .key = "1" }, .{ .label = "B", .key = "2" }, .{ .label = "C", .key = "3" } };
    const perm = [_]wire.Option{ .{ .label = "Yes", .key = "1" }, .{ .label = "No", .key = "esc" } };
    try testConvo(gpa, &c, true, &.{.{ .n = 1, .kind = .question, .text = "Pick", .open = true, .options = &three }});
    v.sync(&c);
    var q = v.questionKeys();
    try testing.expectEqual(@as(u8, 3), q.digits);
    try testing.expect(q.card); // option buttons on the card
    v.answers = false; // view only: no card answers
    try testing.expect(!v.questionKeys().card);
    v.answers = true;
    // A permission prompt: one numbered option ("1"), a swipe card.
    try testConvo(gpa, &c, true, &.{.{ .n = 2, .kind = .question, .text = "Allow?", .open = true, .options = &perm }});
    v.sync(&c);
    q = v.questionKeys();
    try testing.expectEqual(@as(u8, 1), q.digits);
    try testing.expect(q.card);
    // A wait without options: nothing numbered, no card controls.
    try testConvo(gpa, &c, true, &.{.{ .n = 3, .kind = .question, .text = "Waiting", .open = true }});
    v.sync(&c);
    q = v.questionKeys();
    try testing.expectEqual(@as(u8, 0), q.digits);
    try testing.expect(!q.card);
}
