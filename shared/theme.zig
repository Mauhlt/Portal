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
};

/// Modus Vivendi–style dark.
pub const modus_vivendi: Palette = .{
    .bg = hex(0x000000),
    .panel = hex(0x1e1e1e),
    .inactive = hex(0x303030),
    .fg = hex(0xffffff),
    .dim = hex(0x989898),
    .border = hex(0x646464),
    .selection = hex(0x5a5a5a),
    .active = hex(0x535353),
    .red = hex(0xff5f59),
    .green = hex(0x44bc44),
    .yellow = hex(0xd0bc00),
    .blue = hex(0x2fafff),
    .magenta = hex(0xfeacd0),
    .cyan = hex(0x00d3d0),
    .red_warmer = hex(0xff6b55),
    .green_cooler = hex(0x00c06f),
    .yellow_warmer = hex(0xfec43f),
    .blue_warmer = hex(0x79a8ff),
    .magenta_cooler = hex(0xb6a0ff),
    .cyan_cooler = hex(0x6ae4b9),
    .warn_fg = hex(0xfec43f),
    .warn_bg = hex(0x7a6100),
    .approve = hex(0x2f822f),
    .deny = hex(0x9d1f1f),
};

/// The scheme in use.
pub const palette: Palette = modus_vivendi;

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
    pub const focus = palette.blue;
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
    pub const swipe_hold = palette.yellow_warmer;
    pub const swipe_yes = palette.green;
    pub const swipe_no = palette.red;
    pub const tab_text = palette.fg;
    pub const tab_text_inactive = palette.dim;
    /// The modal layer's dimming of what is behind it (alpha).
    pub const scrim_alpha: u8 = 150;
};

test "palette roles and derived tables" {
    try std.testing.expectEqual(@as(u32, 0x000000), ansi16[0]);
    try std.testing.expectEqual(@as(u32, 0xff5f59), ansi16[1]);
    try std.testing.expectEqual(@as(u32, 0xffffff), ansi16[15]);
    try std.testing.expectEqual(Rgb{ 0, 0, 0 }, terminal.resolveBg(color_default));
    try std.testing.expectEqual(Rgb{ 0xff, 0xff, 0xff }, terminal.resolveFg(color_default));
    try std.testing.expectEqual(terminal.bg, terminal.resolveFg(color_default_bg_as_fg));
    try std.testing.expectEqual(terminal.fg, terminal.resolveBg(color_default_fg_as_bg));
    try std.testing.expectEqual(Rgb{ 0x12, 0x34, 0x56 }, terminal.resolveFg(0x00123456));
    try std.testing.expectEqual(terminal.fg, terminal.resolveFg(0xFF000005));
    try std.testing.expectEqual(tabColor("Alpha"), tabColor("alpha"));
    for (accents) |a| try std.testing.expect(a != toU32(palette.bg));
}
