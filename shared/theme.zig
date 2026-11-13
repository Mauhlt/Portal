//! Portal's colour scheme, defined once: every window (desk, laptop,
//! iPhone) draws with it through the shared UI (module "portal_ui"), the
//! server resolves the terminal's 16 ANSI colours with it (src/vt.zig) and
//! derives project tab colours from it (tabs.zig). It lives in "shared"
//! because all three reach this module and nothing else in common.
//!
//! Another theme is a one-file change: write another `Palette` and point
//! `palette` at it. Everything else here (ANSI table, terminal defaults,
//! tab accents, the UI roles) is derived from the palette.

const std = @import("std");

pub const Rgb = [3]u8;

fn hex(comptime v: u24) Rgb {
    return .{ @truncate(v >> 16), @truncate(v >> 8), @truncate(v) };
}

pub const Palette = struct {
    /// Window and terminal background.
    bg: Rgb,
    /// Bars, panels, the Data and interaction slices.
    panel: Rgb,
    /// Buttons and inactive surfaces.
    inactive: Rgb,
    fg: Rgb,
    /// Secondary text.
    dim: Rgb,
    border: Rgb,
    selection: Rgb,
    /// The active (pressed, chosen, main) button.
    active: Rgb,
    red: Rgb,
    green: Rgb,
    yellow: Rgb,
    blue: Rgb,
    magenta: Rgb,
    cyan: Rgb,
    red_warmer: Rgb,
    green_cooler: Rgb,
    yellow_warmer: Rgb,
    blue_warmer: Rgb,
    magenta_cooler: Rgb,
    cyan_cooler: Rgb,
    /// A warning badge: text on background.
    warn_fg: Rgb,
    warn_bg: Rgb,
    /// Approve / deny buttons.
    approve: Rgb,
    deny: Rgb,
    /// The accent gradient (focus, the active tab, Send / Instruct), left
    /// to right.
    ring_blue: Rgb,
    ring_cyan: Rgb,
    ring_green: Rgb,
};

/// "Portal night": the colours of the hero art (docs/brand/portal-hero.jpg;
/// hexes and contrast notes in docs/brand/README.md). Deep navy night for
/// backgrounds (panels a step lighter), the neon ring's blue -> cyan ->
/// green as the accent, the moon's cool blue, the sun's gold -> orange ->
/// red for warnings, meadow green for success, halo / rainbow hues for the
/// rest. Every text colour is >= 7:1 on `bg` (WCAG AAA), `dim` 8:1, UI
/// lines >= 3:1; red and green also differ in lightness (L 0.33 vs 0.51).
pub const portal_night: Palette = .{
    .bg = hex(0x060B1E),
    .panel = hex(0x0E1633),
    .inactive = hex(0x1F2B5C),
    .fg = hex(0xE8EEFF),
    .dim = hex(0x94A3CC),
    .border = hex(0x5B6AA3),
    .selection = hex(0x27407F),
    .active = hex(0x0B4FCC),
    .red = hex(0xFF6B6B),
    .green = hex(0x4FD67A),
    .yellow = hex(0xFFC940),
    .blue = hex(0x4DA3FF),
    .magenta = hex(0xD29BFF),
    .cyan = hex(0x22D3EE),
    .red_warmer = hex(0xFF9447),
    .green_cooler = hex(0x2EF0B4),
    .yellow_warmer = hex(0xFFAA33),
    .blue_warmer = hex(0x93B8FF),
    .magenta_cooler = hex(0xA5B4FC),
    .cyan_cooler = hex(0x8AE8FF),
    .warn_fg = hex(0xFFC940),
    .warn_bg = hex(0x5C4200),
    .approve = hex(0x17733A),
    .deny = hex(0xA8262B),
    .ring_blue = hex(0x1F6BFF),
    .ring_cyan = hex(0x00C8FF),
    .ring_green = hex(0x7DFF5C),
};

/// The scheme in use.
pub const palette: Palette = portal_night;

pub fn toU32(c: Rgb) u32 {
    return (@as(u32, c[0]) << 16) | (@as(u32, c[1]) << 8) | c[2];
}

pub fn fromU32(v: u32) Rgb {
    return .{ @truncate(v >> 16), @truncate(v >> 8), @truncate(v) };
}

// ------------------------------------------------------------- terminal

/// The 16 ANSI colours (SGR 30-37 / 90-97, palette 0-15) as 0xRRGGBB.
pub const ansi16 = blk: {
    const p = palette;
    const list = [16]Rgb{
        p.bg,      p.red,        p.green,        p.yellow,        p.blue,        p.magenta,        p.cyan,        p.dim,
        p.border,  p.red_warmer, p.green_cooler, p.yellow_warmer, p.blue_warmer, p.magenta_cooler, p.cyan_cooler, p.fg,
    };
    var out: [16]u32 = undefined;
    for (list, 0..) |c, i| out[i] = toU32(c);
    break :blk out;
};

/// Colour sentinels of the screen model (src/vt.zig, docs/protocol.md):
/// the default colours, resolved by each client with `Terminal`.
pub const color_default: u32 = 0xFF000000;
/// Default background used as a foreground (inverse video).
pub const color_default_bg_as_fg: u32 = 0xFF000002;
/// Default foreground used as a background (inverse video).
pub const color_default_fg_as_bg: u32 = 0xFF000003;

/// The terminal's default colours, cursor and selection.
pub const Terminal = struct {
    fg: Rgb = palette.fg,
    bg: Rgb = palette.bg,
    cursor: Rgb = palette.fg,
    /// Background of selected cells.
    selection: Rgb = palette.selection,

    pub fn resolveFg(t: Terminal, v: u32) Rgb {
        if (v == color_default_bg_as_fg) return t.bg;
        if (v >> 24 != 0) return t.fg; // default, or an unknown sentinel
        return fromU32(v);
    }

    pub fn resolveBg(t: Terminal, v: u32) Rgb {
        if (v == color_default_fg_as_bg) return t.fg;
        if (v >> 24 != 0) return t.bg;
        return fromU32(v);
    }
};

pub const terminal: Terminal = .{};

// ------------------------------------------------------------- tabs

/// The accent set project tabs are coloured from (by name, tabs.zig).
pub const accents = blk: {
    const p = palette;
    const list = [_]Rgb{
        p.blue,        p.green,         p.yellow,      p.magenta,        p.cyan,        p.red,
        p.blue_warmer, p.green_cooler,  p.yellow_warmer, p.magenta_cooler, p.cyan_cooler, p.red_warmer,
    };
    var out: [list.len]u32 = undefined;
    for (list, 0..) |c, i| out[i] = toU32(c);
    break :blk out;
};

/// A stable tab colour for a project name (FNV-1a over the bytes, ASCII
/// case ignored, into `accents`).
pub fn tabColor(name: []const u8) u32 {
    var h: u32 = 0x811C9DC5;
    for (name) |c| {
        h ^= std.ascii.toLower(c);
        h *%= 0x01000193;
    }
    return accents[h % accents.len];
}

// ------------------------------------------------------------- UI roles

/// What each part of the UI is drawn with (portal_ui reads only these).
pub const ui = struct {
    pub const bar = palette.panel;
    pub const panel = palette.panel;
    pub const border = palette.border;
    pub const button = palette.inactive;
    pub const button_text = palette.fg;
    /// Send, the chosen view, the focused row.
    pub const button_active = palette.active;
    pub const field = palette.bg;
    pub const focus = palette.ring_cyan;
    /// The accent gradient's stops (Frame draws it as slices).
    pub const accent = [_]Rgb{ palette.ring_blue, palette.ring_cyan, palette.ring_green };
    pub const text = palette.fg;
    pub const dim = palette.dim;
    pub const good = palette.green;
    pub const warn = palette.yellow;
    pub const bad = palette.red;
    pub const badge_fg = palette.warn_fg;
    pub const badge_bg = palette.warn_bg;
    pub const approve = palette.approve;
    pub const deny = palette.deny;
    pub const caution = palette.warn_bg;
    pub const selected_row = palette.inactive;
    /// A tab whose program waits for an answer.
    pub const attention = palette.warn_fg;
    /// A swipe card (Yes/No question) while held: its neutral colour, and
    /// the colours it moves towards on the Yes and the No side (full at the
    /// answer threshold). Its fill is the colour mixed into the background.
    pub const swipe_hold = palette.yellow; // sun gold
    pub const swipe_yes = palette.green; // meadow
    pub const swipe_no = palette.red; // sunset
    /// A swipe card choosing between two options that are not Yes / No:
    /// both sides move towards this (neither is "good" or "bad").
    pub const swipe_choice = palette.blue;
    pub const tab_text = palette.fg;
    pub const tab_text_inactive = palette.dim;
    /// The modal layer's dimming of what is behind it (alpha).
    pub const scrim_alpha: u8 = 150;
};

test "palette roles and derived tables" {
    try std.testing.expectEqual(@as(u32, 0x060B1E), ansi16[0]);
    try std.testing.expectEqual(@as(u32, 0xFF6B6B), ansi16[1]);
    try std.testing.expectEqual(@as(u32, 0xE8EEFF), ansi16[15]);
    try std.testing.expectEqual(palette.bg, terminal.resolveBg(color_default));
    try std.testing.expectEqual(palette.fg, terminal.resolveFg(color_default));
    try std.testing.expectEqual(terminal.bg, terminal.resolveFg(color_default_bg_as_fg));
    try std.testing.expectEqual(terminal.fg, terminal.resolveBg(color_default_fg_as_bg));
    try std.testing.expectEqual(Rgb{ 0x12, 0x34, 0x56 }, terminal.resolveFg(0x00123456));
    try std.testing.expectEqual(terminal.fg, terminal.resolveFg(0xFF000005));
    try std.testing.expectEqual(tabColor("Alpha"), tabColor("alpha"));
    for (accents) |a| try std.testing.expect(a != toU32(palette.bg));
}
