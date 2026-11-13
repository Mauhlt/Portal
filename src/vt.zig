//! Display-only VT terminal emulator core.
//!
//! The ConPTY output stream is fed in on the desktop; web viewers receive a
//! compact pre-rendered grid (see `Terminal.encodeRows`) and never interpret
//! escape sequences themselves.
//!
//! The byte stream can be influenced by untrusted content (files the child
//! program prints), so this is an attack surface. Rules kept throughout:
//!   * No input can panic, overflow, hit `unreachable` or index out of bounds.
//!   * Memory is bounded: dimensions are clamped to 1..1000, OSC payloads to
//!     `max_osc_bytes`, CSI parameters to `max_params` values of at most
//!     65535 each. `feed` allocates only for inline images (vt_gfx.zig:
//!     kitty graphics, stored as PNG bytes under hard limits, never decoded
//!     here); an allocation failure there drops the image, nothing else.
//!   * Nothing is written back except the fixed OSC 7501 feature-detection
//!     reply (`takeReplies`): no DSR/DA replies, no answerback, nothing that
//!     echoes any byte of the stream.
//!
//! The parser is Paul Williams' DEC ANSI state machine
//! (https://vt100.net/emu/dec_ansi_parser) with UTF-8 decoding in the ground
//! state and colon sub-parameters tolerated in CSI. It is a pure byte-at-a-time
//! machine, so splitting input across `feed` calls never changes the result.
//! Not thread-safe: the owner serialises access.

const std = @import("std");
const Allocator = std.mem.Allocator;
const width = @import("Font").wcwidth; // the Renderer's Font module
/// Inline images (kitty graphics subset): store, placements, wire frames.
pub const gfx = @import("vt_gfx.zig");
/// Cell width of a code point (0, 1 or 2). Public so the browser client
/// (src/wasm), which imports this file as a module, lays out wide
/// characters with exactly the table the emulator used.
pub const cellWidth = width.of;

pub const min_dim: u16 = 1;
pub const max_dim: u16 = 1000;
pub const max_params = 16;
pub const max_param_value: u32 = 65535;
/// Raw OSC payload bytes kept; the rest of a longer string is discarded.
pub const max_osc_bytes = 512;
/// Sanitised title bytes kept (valid UTF-8, no controls).
pub const max_title_bytes = 256;
/// Upper bound for REP (CSI b) before the screen-size bound applies.
pub const max_repeat: u32 = 65535;

/// Colour sentinels used in the wire format. Real colours are 0x00RRGGBB.
///   0xFF000000  default: in the fg slot the default foreground colour, in
///               the bg slot the default background colour.
///   0xFF000001  reserved, never emitted.
///   0xFF000002  (fg slot only) the default *background* colour, used as
///               foreground: an inverse (SGR 7) cell whose bg was default.
///   0xFF000003  (bg slot only) the default *foreground* colour, used as
///               background: an inverse cell whose fg was default.
pub const color_default: u32 = 0xFF000000;
pub const color_reserved: u32 = 0xFF000001;
pub const color_default_bg_as_fg: u32 = 0xFF000002;
pub const color_default_fg_as_bg: u32 = 0xFF000003;

/// Wire attribute bits.
pub const attr_bold: u8 = 1;
pub const attr_dim: u8 = 2;
pub const attr_italic: u8 = 4;
pub const attr_underline: u8 = 8;
pub const attr_strike: u8 = 16;
const attr_wire_mask: u8 = 0x1F;
// Internal-only bits, resolved before encoding.
const attr_inverse: u8 = 32;
const attr_hidden: u8 = 64;

pub const Cursor = struct { x: u16, y: u16, visible: bool };

const Wide = enum(u2) { narrow, lead, cont };

const Cell = struct {
    cp: u21 = ' ',
    wide: Wide = .narrow,
    attrs: u8 = 0,
    fg: u32 = color_default,
    bg: u32 = color_default,

    fn isDefaultBlank(c: Cell) bool {
        return c.cp == ' ' and c.wide == .narrow and c.attrs == 0 and
            c.fg == color_default and c.bg == color_default;
    }
};

const Pen = struct {
    fg: u32 = color_default,
    bg: u32 = color_default,
    attrs: u8 = 0,
};

const Charset = enum(u1) { ascii, dec_graphics };

const CursorState = struct {
    x: u16 = 0,
    y: u16 = 0,
    /// xterm "do_wrap": the last column was just written; the next printable
    /// wraps first.
    pending_wrap: bool = false,
    pen: Pen = .{},
    origin: bool = false,
    g: [2]Charset = .{ .ascii, .ascii },
    gl: u1 = 0,
};

/// One screen buffer. Rows are reached through `map` (logical -> physical)
/// so scrolling rotates a small index array instead of moving cells.
const Screen = struct {
    cells: []Cell,
    map: []u16,

    fn init(gpa: Allocator, cols: u16, rows: u16) !Screen {
        const cells = try gpa.alloc(Cell, @as(usize, cols) * rows);
        errdefer gpa.free(cells);
        const map = try gpa.alloc(u16, rows);
        @memset(cells, .{});
        for (map, 0..) |*m, i| m.* = @intCast(i);
        return .{ .cells = cells, .map = map };
    }

    fn deinit(s: *Screen, gpa: Allocator) void {
        gpa.free(s.cells);
        gpa.free(s.map);
    }

    fn line(s: *const Screen, cols: u16, y: u16) []Cell {
        const phys: usize = s.map[y];
        return s.cells[phys * cols ..][0..cols];
    }
};

const State = enum {
    ground,
    escape,
    escape_intermediate,
    csi_entry,
    csi_param,
    csi_intermediate,
    csi_ignore,
    dcs_entry,
    dcs_param,
    dcs_intermediate,
    dcs_passthrough,
    dcs_ignore,
    osc_string,
    sos_pm_apc_string,
    /// After ESC _: a 'G' starts a graphics command, anything else is an
    /// APC string to discard.
    apc_start,
    /// Inside a graphics command (APC G... or OSC 7070;G...).
    gfx_string,
};

/// Incremental UTF-8 decoder (WHATWG algorithm: rejects overlongs,
/// surrogates and values above U+10FFFF).
const Utf8 = struct {
    cp: u32 = 0,
    need: u8 = 0,
    lower: u8 = 0x80,
    upper: u8 = 0xBF,

    const Step = union(enum) {
        pending,
        done: u21,
        /// Invalid; the byte was consumed. Emit U+FFFD.
        bad,
        /// Invalid; emit U+FFFD and process this byte again from scratch.
        bad_reprocess,
    };

    fn step(d: *Utf8, b: u8) Step {
        if (d.need == 0) {
            switch (b) {
                0x00...0x7F => return .{ .done = b },
                0xC2...0xDF => {
                    d.need = 1;
                    d.cp = b & 0x1F;
                },
                0xE0...0xEF => {
                    if (b == 0xE0) d.lower = 0xA0;
                    if (b == 0xED) d.upper = 0x9F;
                    d.need = 2;
                    d.cp = b & 0x0F;
                },
                0xF0...0xF4 => {
                    if (b == 0xF0) d.lower = 0x90;
                    if (b == 0xF4) d.upper = 0x8F;
                    d.need = 3;
                    d.cp = b & 0x07;
                },
                else => return .bad,
            }
            return .pending;
        }
        if (b < d.lower or b > d.upper) {
            d.* = .{};
            return .bad_reprocess;
        }
        d.lower = 0x80;
        d.upper = 0xBF;
        d.cp = (d.cp << 6) | (b & 0x3F);
        d.need -= 1;
        if (d.need > 0) return .pending;
        const cp = d.cp;
        d.* = .{};
        if (cp > 0x10FFFF) return .bad; // unreachable by construction; stay safe
        return .{ .done = @intCast(cp) };
    }
};

const Parser = struct {
    state: State = .ground,
    utf8: Utf8 = .{},
    params: [max_params]u16 = @splat(0),
    /// subs[i]: params[i] was introduced by ':' (a sub-parameter).
    subs: [max_params]bool = @splat(false),
    n_params: u8 = 0,
    cur_param: u32 = 0,
    cur_sub: bool = false,
    param_seen: bool = false,
    private: u8 = 0,
    inter: [2]u8 = .{ 0, 0 },
    /// Number of intermediates; > inter.len means "too many, ignore".
    n_inter: u8 = 0,
    osc: [max_osc_bytes]u8 = @splat(0),
    osc_len: u16 = 0,

    fn clear(p: *Parser) void {
        p.n_params = 0;
        p.cur_param = 0;
        p.cur_sub = false;
        p.param_seen = false;
        p.private = 0;
        p.n_inter = 0;
    }

    fn collect(p: *Parser, b: u8) void {
        if (p.n_inter < p.inter.len) p.inter[p.n_inter] = b;
        if (p.n_inter <= p.inter.len) p.n_inter += 1;
    }

    fn param(p: *Parser, b: u8) void {
        p.param_seen = true;
        if (b >= '0' and b <= '9') {
            p.cur_param = @min(p.cur_param * 10 + (b - '0'), max_param_value);
            return;
        }
        // ';' or ':' ends the current parameter.
        p.pushParam();
        p.cur_sub = b == ':';
    }

    fn pushParam(p: *Parser) void {
        if (p.n_params < max_params) {
            p.params[p.n_params] = @intCast(p.cur_param);
            p.subs[p.n_params] = p.cur_sub;
            p.n_params += 1;
        }
        p.cur_param = 0;
        p.cur_sub = false;
    }

    fn finishParams(p: *Parser) void {
        if (p.param_seen) p.pushParam();
        p.param_seen = false;
    }

    fn oscPut(p: *Parser, b: u8) void {
        if (p.osc_len < p.osc.len) {
            p.osc[p.osc_len] = b;
            p.osc_len += 1;
        }
    }
};

fn clampDim(v: u16) u16 {
    return std.math.clamp(v, min_dim, max_dim);
}

/// The 16 ANSI colours: Portal's theme (shared/theme.zig), so every
/// client shows the scheme the UI is drawn in.
const ansi16 = @import("shared").theme.ansi16;

/// The 256-colour palette resolved to 0x00RRGGBB: the theme's 16 ANSI
/// colours, then xterm's colour cube and grey ramp.
pub fn paletteColor(n: u8) u32 {
    if (n < 16) return ansi16[n];
    if (n < 232) {
        const levels = [6]u32{ 0, 95, 135, 175, 215, 255 };
        const i = n - 16;
        return (levels[i / 36] << 16) | (levels[(i / 6) % 6] << 8) | levels[i % 6];
    }
    const v: u32 = 8 + @as(u32, n - 232) * 10;
    return (v << 16) | (v << 8) | v;
}

fn rgb(r: u16, g: u16, b: u16) u32 {
    return (@as(u32, @min(r, 255)) << 16) | (@as(u32, @min(g, 255)) << 8) | @min(b, 255);
}

/// DEC Special Graphics for 0x5F..0x7E.
const dec_graphics = [32]u21{
    ' ',    0x25C6, 0x2592, 0x2409, 0x240C, 0x240D, 0x240A, 0x00B0,
    0x00B1, 0x2424, 0x240B, 0x2518, 0x2510, 0x250C, 0x2514, 0x253C,
    0x23BA, 0x23BB, 0x2500, 0x23BC, 0x23BD, 0x251C, 0x2524, 0x2534,
    0x252C, 0x2502, 0x2264, 0x2265, 0x03C0, 0x2260, 0x00A3, 0x00B7,
};

fn isControl(cp: u21) bool {
    return cp < 0x20 or (cp >= 0x7F and cp < 0xA0);
}

/// Clears orphaned halves of wide characters in a row (after any operation
/// that may have split one).
fn fixWide(row: []Cell) void {
    for (row, 0..) |*c, i| {
        switch (c.wide) {
            .narrow => {},
            .lead => if (i + 1 >= row.len or row[i + 1].wide != .cont) {
                c.cp = ' ';
                c.wide = .narrow;
            },
            .cont => if (i == 0 or row[i - 1].wide != .lead) {
                c.cp = ' ';
                c.wide = .narrow;
            },
        }
    }
}

/// OSC 7501 program status (docs/tabs-design.md): `ESC ] 7501 ; state=<s>
/// [:kind=<k>][:app=<name>][:msg=<base64>] ST`, as described at
/// https://mitchellh.com/writing/program-status-osc7501. Only the state and
/// the kind (as an enum) are kept; app and msg are program-controlled
/// strings and are dropped.
///
/// Feature detection (spec revision 0.4, "Feature detection",
/// https://www.superlogical.com/rex/docs/build/program-status): the program
/// sends `OSC 7501 ; ? ST` (the agent sends `ESC ] 7501 ; ? BEL`, followed
/// by a primary device attributes request `CSI c` as a sentinel: if the DA
/// reply arrives first, it treats the protocol as unsupported and never
/// reports its state; under ConPTY conhost answers that DA itself, at once,
/// so it always does: docs/protocol.md, "Program status (OSC 7501)").
/// A supporting terminal MUST reply `OSC 7501 ; ? ST`; it
/// MAY add `:states=...:kinds=...`, and a reply without them means exactly
/// idle, working, done, blocked, error and permission, question, auth,
/// which is what Portal understands, so the reply is just `?`. The reply is
/// fixed bytes (`status_reply_bel` / `status_reply_st`, echoing the query's
/// terminator as xterm does for its own queries) and carries nothing from
/// the stream; under ConPTY it is typed as key records (`takeReplies`).
pub const ProgramState = enum { unknown, working, waiting, idle, done, failed };

/// What a blocked program waits for (`kind=`): the Conversation view offers
/// answer buttons for a permission prompt (src/convo/model.zig).
pub const ProgramKind = enum { none, permission, question, auth, other };

/// The kind in an OSC 7501 payload: `none` without one, `other` for one
/// Portal does not know.
pub fn parseProgramKind(payload: []const u8) ProgramKind {
    var it = std.mem.tokenizeAny(u8, payload, ":;");
    while (it.next()) |f| {
        if (!std.mem.startsWith(u8, f, "kind=")) continue;
        const v = f["kind=".len..];
        if (std.mem.eql(u8, v, "permission")) return .permission;
        if (std.mem.eql(u8, v, "question")) return .question;
        if (std.mem.eql(u8, v, "auth")) return .auth;
        return .other;
    }
    return .none;
}

/// The state in an OSC 7501 payload (after "7501;"). Fields are separated
/// by ':' or ';'; an unknown or missing state is `unknown`.
pub fn parseProgramState(payload: []const u8) ProgramState {
    var it = std.mem.tokenizeAny(u8, payload, ":;");
    while (it.next()) |f| {
        if (!std.mem.startsWith(u8, f, "state=")) continue;
        const v = f["state=".len..];
        const map = [_]struct { []const u8, ProgramState }{
            .{ "working", .working }, .{ "blocked", .waiting }, .{ "idle", .idle },
            .{ "done", .done },       .{ "error", .failed },
        };
        for (map) |m| if (std.mem.eql(u8, v, m[0])) return m[1];
        return .unknown;
    }
    return .unknown;
}

/// The OSC 7501 feature-detection reply (see above), per query terminator.
pub const status_reply_bel = "\x1b]7501;?\x07";
pub const status_reply_st = "\x1b]7501;?\x1b\\";
/// Feature-detection queries answered per `takeReplies` call at most: a
/// program has no reason to ask twice in one read, and output it merely
/// relays (a file it prints) cannot make Portal type more than this.
pub const max_pending_replies = 2;
/// One input byte as win32-input-mode key records (see `takeReplies`):
/// a key down and a key up, `CSI Vk ; Sc ; Uc ; Kd ; Cs ; Rc _` each.
const max_win32_record_bytes = 2 * "\x1b[0;0;255;1;0;1_".len;
/// Room for `max_pending_replies` replies, encoded either way.
pub const max_reply_bytes = max_pending_replies * status_reply_st.len * max_win32_record_bytes;

/// Appends `byte` as typed by a key (no virtual key, no scan code: just the
/// character), key down then key up, in win32-input-mode form.
fn putWin32Key(out: []u8, n: *usize, byte: u8) void {
    for ([_]u8{ 1, 0 }) |down| {
        const s = std.fmt.bufPrint(out[n.*..], "\x1b[0;0;{d};{d};0;1_", .{ byte, down }) catch return; // sized by max_reply_bytes
        n.* += s.len;
    }
}

pub const Terminal = struct {
    gpa: Allocator,
    cols: u16,
    rows: u16,
    /// Bumped on every visible change (cells, cursor, title, size).
    gen: u64 = 0,
    row_gen: []u64,
    main: Screen,
    alt: Screen,
    alt_active: bool = false,
    tabs: []bool,
    cur: CursorState = .{},
    /// DECSC slots: [0] main screen, [1] alternate screen.
    saved: [2]CursorState = .{ .{}, .{} },
    top: u16 = 0,
    bot: u16,
    autowrap: bool = true,
    cursor_visible: bool = true,
    app_cursor: bool = false,
    /// DECSET 2004: the application wants pasted text bracketed.
    bracketed_paste: bool = false,
    /// Last printed graphic character, for REP; null after anything else.
    last_cp: ?u21 = null,
    parser: Parser = .{},
    title_buf: [max_title_bytes]u8 = @splat(0),
    title_len: u16 = 0,
    /// The program's last OSC 7501 status, and a counter bumped whenever it
    /// changes (see `setProgramState`).
    program_state: ProgramState = .unknown,
    program_kind: ProgramKind = .none,
    program_state_gen: u64 = 0,
    /// OSC 7501 feature-detection queries (`OSC 7501 ; ? ST`) seen since
    /// the last `takeReplies`, with each one's terminator (true: ST,
    /// false: BEL); at most `max_pending_replies`, later ones dropped.
    pending_replies: u8 = 0,
    pending_reply_st: [max_pending_replies]bool = @splat(false),
    /// DECSET 9001 (win32-input-mode): ConPTY's conhost asks for it when
    /// it starts and then reads every input sequence it does not know (an
    /// OSC, such as the reply above) as nothing at all. Input written while
    /// it is on must be key records instead. Not cleared by RIS: conhost,
    /// not the program, owns the input side.
    win32_input: bool = false,
    /// Inline images and their placements (per screen).
    images: gfx.Graphics = .{},

    pub fn init(gpa: Allocator, cols_in: u16, rows_in: u16) !Terminal {
        const cols = clampDim(cols_in);
        const rows = clampDim(rows_in);
        var main = try Screen.init(gpa, cols, rows);
        errdefer main.deinit(gpa);
        var alt = try Screen.init(gpa, cols, rows);
        errdefer alt.deinit(gpa);
        const row_gen = try gpa.alloc(u64, rows);
        errdefer gpa.free(row_gen);
        const tabs = try gpa.alloc(bool, cols);
        @memset(row_gen, 0);
        for (tabs, 0..) |*s, i| s.* = i % 8 == 0;
        return .{
            .gpa = gpa,
            .cols = cols,
            .rows = rows,
            .row_gen = row_gen,
            .main = main,
            .alt = alt,
            .tabs = tabs,
            .bot = rows - 1,
        };
    }

    pub fn deinit(t: *Terminal) void {
        t.main.deinit(t.gpa);
        t.alt.deinit(t.gpa);
        t.gpa.free(t.row_gen);
        t.gpa.free(t.tabs);
        t.images.deinit(t.gpa);
        t.* = undefined;
    }

    /// Image placements on the visible screen (cells; rows may be negative
    /// once partly scrolled off the top).
    pub fn placements(t: *const Terminal) []const gfx.Placement {
        return t.images.placements(t.alt_active);
    }

    /// Changes whenever images or placements change (or the screen switches).
    pub fn imagesGen(t: *const Terminal) u64 {
        return t.images.gen;
    }

    /// The PNG bytes of an image by wire id, while it is stored.
    pub fn imagePng(t: *const Terminal, image: u32) ?[]const u8 {
        const s = t.images.find(image) orelse return null;
        return s.png;
    }

    pub fn rowGen(t: *const Terminal, row: u16) u64 {
        if (row >= t.rows) return 0;
        return t.row_gen[row];
    }

    pub fn cursor(t: *const Terminal) Cursor {
        return .{
            .x = @min(t.cur.x, t.cols - 1),
            .y = @min(t.cur.y, t.rows - 1),
            .visible = t.cursor_visible,
        };
    }

    pub fn title(t: *const Terminal) []const u8 {
        return t.title_buf[0..t.title_len];
    }

    /// DECCKM (CSI ? 1 h): cursor keys send SS3 instead of CSI.
    pub fn appCursor(t: *const Terminal) bool {
        return t.app_cursor;
    }

    /// CSI ? 2004 h: pasted text should be wrapped in ESC[200~ / ESC[201~.
    pub fn bracketedPaste(t: *const Terminal) bool {
        return t.bracketed_paste;
    }

    pub const VisibleWide = enum(u2) { narrow, lead, cont };

    /// One cell as a viewer should draw it: the same resolution as
    /// `encodeRows` (inverse applied, hidden shown as a space, controls as
    /// U+FFFD, broken wide pairs as spaces, wire attribute bits only).
    pub const VisibleCell = struct {
        cp: u21 = ' ',
        wide: VisibleWide = .narrow,
        attrs: u8 = 0,
        fg: u32 = color_default,
        bg: u32 = color_default,
    };

    /// Fills `out` with row `y` (as many cells as fit) and returns the
    /// count. Out-of-range rows give 0. Never panics.
    pub fn visibleRow(t: *const Terminal, y: u16, out: []VisibleCell) usize {
        if (y >= t.rows) return 0;
        const row = t.screenConst().line(t.cols, y);
        const n = @min(row.len, out.len);
        for (row[0..n], out[0..n], 0..) |cell, *o, x| {
            var cp = cell.cp;
            var wide: VisibleWide = .narrow;
            switch (cell.wide) {
                .narrow => {},
                .lead => {
                    if (x + 1 < row.len and row[x + 1].wide == .cont) wide = .lead else cp = ' ';
                },
                .cont => {
                    if (x > 0 and row[x - 1].wide == .lead) wide = .cont;
                    cp = ' ';
                },
            }
            var fg = cell.fg;
            var bg = cell.bg;
            if (cell.attrs & attr_inverse != 0) {
                fg = if (cell.bg == color_default) color_default_bg_as_fg else cell.bg;
                bg = if (cell.fg == color_default) color_default_fg_as_bg else cell.fg;
            }
            if (cell.attrs & attr_hidden != 0) {
                cp = ' ';
            } else if (isControl(cp)) cp = 0xFFFD;
            o.* = .{ .cp = cp, .wide = wide, .attrs = cell.attrs & attr_wire_mask, .fg = fg, .bg = bg };
        }
        return n;
    }

    /// Feed raw PTY output. Sequences and UTF-8 may be split across calls.
    pub fn feed(t: *Terminal, bytes: []const u8) void {
        const before = t.cursor();
        const images_before = t.images.gen;
        for (bytes) |b| t.step(b);
        const after = t.cursor();
        if (before.x != after.x or before.y != after.y or before.visible != after.visible or images_before != t.images.gen)
            t.bumpGen();
    }

    /// The bytes to write into the program's input in answer to the OSC
    /// 7501 feature-detection queries fed since the last call (empty if
    /// there were none), and forgets them. Only ever the fixed reply, as
    /// is, or (while conhost has win32-input-mode on) typed key by key as
    /// win32-input-mode records, which conhost hands to the program as the
    /// same bytes.
    pub fn takeReplies(t: *Terminal, buf: *[max_reply_bytes]u8) []const u8 {
        var n: usize = 0;
        for (t.pending_reply_st[0..t.pending_replies]) |st| {
            const r = if (st) status_reply_st else status_reply_bel;
            if (t.win32_input) {
                for (r) |b| putWin32Key(buf, &n, b);
            } else {
                @memcpy(buf[n..][0..r.len], r);
                n += r.len;
            }
        }
        t.pending_replies = 0;
        return buf[0..n];
    }

    /// Keeps content anchored top-left; clamps the cursor; resets margins.
    pub fn resize(t: *Terminal, cols_in: u16, rows_in: u16) !void {
        const cols = clampDim(cols_in);
        const rows = clampDim(rows_in);
        if (cols == t.cols and rows == t.rows) return;
        const gpa = t.gpa;
        var main = try Screen.init(gpa, cols, rows);
        errdefer main.deinit(gpa);
        var alt = try Screen.init(gpa, cols, rows);
        errdefer alt.deinit(gpa);
        const row_gen = try gpa.alloc(u64, rows);
        errdefer gpa.free(row_gen);
        const tabs = try gpa.alloc(bool, cols);

        copyScreen(&main, cols, rows, &t.main, t.cols, t.rows);
        copyScreen(&alt, cols, rows, &t.alt, t.cols, t.rows);
        for (tabs, 0..) |*s, i| s.* = if (i < t.tabs.len) t.tabs[i] else i % 8 == 0;

        t.main.deinit(gpa);
        t.alt.deinit(gpa);
        gpa.free(t.row_gen);
        gpa.free(t.tabs);
        t.main = main;
        t.alt = alt;
        t.row_gen = row_gen;
        t.tabs = tabs;
        t.cols = cols;
        t.rows = rows;
        t.top = 0;
        t.bot = rows - 1;
        t.clampCursor(&t.cur);
        t.cur.pending_wrap = false;
        for (&t.saved) |*s| t.clampCursor(s);
        t.images.resize(cols, rows);
        t.markAll();
    }

    fn copyScreen(dst: *Screen, cols: u16, rows: u16, src: *const Screen, old_cols: u16, old_rows: u16) void {
        const n = @min(cols, old_cols);
        for (0..@min(rows, old_rows)) |y| {
            const d = dst.line(cols, @intCast(y));
            @memcpy(d[0..n], src.line(old_cols, @intCast(y))[0..n]);
            fixWide(d);
        }
    }

    fn clampCursor(t: *const Terminal, c: *CursorState) void {
        c.x = @min(c.x, t.cols - 1);
        c.y = @min(c.y, t.rows - 1);
    }

    // ---- change tracking ------------------------------------------------

    fn bumpGen(t: *Terminal) void {
        t.gen +%= 1;
    }

    fn markRow(t: *Terminal, y: u16) void {
        t.bumpGen();
        if (y < t.rows) t.row_gen[y] = t.gen;
    }

    fn markRange(t: *Terminal, from: u16, to_inclusive: u16) void {
        t.bumpGen();
        var y = from;
        while (y <= to_inclusive and y < t.rows) : (y += 1) t.row_gen[y] = t.gen;
    }

    fn markAll(t: *Terminal) void {
        t.markRange(0, t.rows - 1);
    }

    // ---- screen helpers -------------------------------------------------

    fn screen(t: *Terminal) *Screen {
        return if (t.alt_active) &t.alt else &t.main;
    }

    fn screenConst(t: *const Terminal) *const Screen {
        return if (t.alt_active) &t.alt else &t.main;
    }

    fn line(t: *Terminal, y: u16) []Cell {
        return t.screen().line(t.cols, @min(y, t.rows - 1));
    }

    /// Erased cells take the current background (xterm "BCE").
    fn blank(t: *const Terminal) Cell {
        return .{ .bg = t.cur.pen.bg };
    }

    fn eraseCells(t: *Terminal, y: u16, from: usize, to: usize) void {
        const row = t.line(y);
        const a = @min(from, row.len);
        const b = @min(to, row.len);
        if (a < b) {
            @memset(row[a..b], t.blank());
            t.images.erase(t.alt_active, @min(y, t.rows - 1), a, b);
        }
        fixWide(row);
        t.markRow(y);
    }

    /// Rows that scrolled in: blank, without touching image placements
    /// (an image extending below the screen keeps scrolling up into view).
    fn blankRows(t: *Terminal, from: u16, to_exclusive: u16) void {
        var y = from;
        while (y < to_exclusive and y < t.rows) : (y += 1) {
            const row = t.line(y);
            @memset(row, t.blank());
            t.markRow(y);
        }
    }

    fn eraseRows(t: *Terminal, from: u16, to_exclusive: u16) void {
        var y = from;
        while (y < to_exclusive and y < t.rows) : (y += 1) t.eraseCells(y, 0, t.cols);
    }

    /// Scrolls logical rows [top, bot] up by n, blank rows enter at bot.
    fn scrollUpIn(t: *Terminal, top: u16, bot: u16, n_in: u32) void {
        if (top > bot or bot >= t.rows) return;
        const height: u32 = @as(u32, bot - top) + 1;
        const n: u16 = @intCast(@min(n_in, height));
        if (n == 0) return;
        const map = t.screen().map[top .. @as(usize, bot) + 1];
        std.mem.rotate(u16, map, n);
        t.images.scroll(t.alt_active, top, bot, -@as(i32, n));
        t.blankRows(bot + 1 - n, bot + 1);
        t.markRange(top, bot);
    }

    /// Scrolls logical rows [top, bot] down by n, blank rows enter at top.
    fn scrollDownIn(t: *Terminal, top: u16, bot: u16, n_in: u32) void {
        if (top > bot or bot >= t.rows) return;
        const height: u32 = @as(u32, bot - top) + 1;
        const n: u16 = @intCast(@min(n_in, height));
        if (n == 0) return;
        const map = t.screen().map[top .. @as(usize, bot) + 1];
        std.mem.rotate(u16, map, map.len - n);
        t.images.scroll(t.alt_active, top, bot, n);
        t.blankRows(top, top + n);
        t.markRange(top, bot);
    }

    fn index(t: *Terminal) void {
        t.cur.pending_wrap = false;
        if (t.cur.y == t.bot) {
            t.scrollUpIn(t.top, t.bot, 1);
        } else if (t.cur.y + 1 < t.rows) {
            t.cur.y += 1;
        }
    }

    fn reverseIndex(t: *Terminal) void {
        t.cur.pending_wrap = false;
        if (t.cur.y == t.top) {
            t.scrollDownIn(t.top, t.bot, 1);
        } else if (t.cur.y > 0) {
            t.cur.y -= 1;
        }
    }

    // ---- printing -------------------------------------------------------

    /// Puts `c` at x, first clearing the other half of any wide char it hits.
    fn putCell(row: []Cell, x: usize, c: Cell) void {
        if (x >= row.len) return;
        switch (row[x].wide) {
            .narrow => {},
            .lead => if (x + 1 < row.len) {
                row[x + 1].cp = ' ';
                row[x + 1].wide = .narrow;
            },
            .cont => if (x > 0) {
                row[x - 1].cp = ' ';
                row[x - 1].wide = .narrow;
            },
        }
        row[x] = c;
    }

    fn print(t: *Terminal, cp_in: u21) void {
        var cp = cp_in;
        if (cp >= 0x5F and cp <= 0x7E and t.cur.g[t.cur.gl] == .dec_graphics)
            cp = dec_graphics[cp - 0x5F];
        if (isControl(cp)) return;
        const w = width.of(cp);
        if (w == 0) return; // combining / zero-width: dropped
        if (w == 2 and t.cols < 2) return; // can never fit
        if (t.cur.pending_wrap) {
            t.cur.pending_wrap = false;
            if (t.autowrap) {
                t.cur.x = 0;
                t.index();
            }
        }
        if (w == 2) {
            if (t.cur.x + 1 >= t.cols) {
                if (!t.autowrap) return;
                t.cur.x = 0;
                t.index();
            }
        }
        const x: usize = t.cur.x;
        const row = t.line(t.cur.y);
        const pen = t.cur.pen;
        t.images.erase(t.alt_active, t.cur.y, x, x + w);
        if (w == 2) {
            putCell(row, x, .{ .cp = cp, .wide = .lead, .attrs = pen.attrs, .fg = pen.fg, .bg = pen.bg });
            putCell(row, x + 1, .{ .cp = ' ', .wide = .cont, .attrs = pen.attrs, .fg = pen.fg, .bg = pen.bg });
        } else {
            putCell(row, x, .{ .cp = cp, .attrs = pen.attrs, .fg = pen.fg, .bg = pen.bg });
        }
        t.markRow(t.cur.y);
        t.last_cp = cp;
        if (x + w >= t.cols) {
            t.cur.x = t.cols - 1;
            t.cur.pending_wrap = t.autowrap;
        } else {
            t.cur.x += w;
        }
    }

    // ---- parser ---------------------------------------------------------

    fn step(t: *Terminal, b: u8) void {
        const p = &t.parser;
        if (p.utf8.need > 0) {
            switch (p.utf8.step(b)) {
                .pending => return,
                .done => |cp| return t.print(cp),
                .bad => return t.print(0xFFFD),
                .bad_reprocess => t.print(0xFFFD), // then handle b below
            }
        }

        // "Anywhere" transitions.
        switch (b) {
            0x18, 0x1A => { // CAN, SUB: abort any sequence
                if (p.state == .gfx_string) t.images.abort(t.gpa);
                p.state = .ground;
                return;
            },
            0x1B => {
                if (p.state == .osc_string) t.oscEnd(true);
                if (p.state == .gfx_string) t.gfxEnd();
                p.clear();
                p.state = .escape;
                return;
            },
            else => {},
        }

        switch (p.state) {
            .ground => switch (b) {
                0x00...0x1F => t.execute(b),
                0x20...0x7E => t.print(b),
                0x7F => {},
                0x80...0xFF => switch (p.utf8.step(b)) {
                    .pending => {},
                    .done => |cp| t.print(cp),
                    .bad, .bad_reprocess => t.print(0xFFFD),
                },
            },
            .escape => switch (b) {
                0x00...0x1F => t.execute(b),
                0x20...0x2F => {
                    p.collect(b);
                    p.state = .escape_intermediate;
                },
                'P' => {
                    p.clear();
                    p.state = .dcs_entry;
                },
                'X', '^' => p.state = .sos_pm_apc_string,
                '_' => p.state = .apc_start,
                '[' => {
                    p.clear();
                    p.state = .csi_entry;
                },
                ']' => {
                    p.osc_len = 0;
                    p.state = .osc_string;
                },
                0x30...0x4F, 0x51...0x57, 0x59, 0x5A, 0x5C, 0x60...0x7E => {
                    p.state = .ground;
                    t.escDispatch(b);
                },
                0x7F => {},
                0x80...0xFF => t.abortToGround(b),
            },
            .escape_intermediate => switch (b) {
                0x00...0x1F => t.execute(b),
                0x20...0x2F => p.collect(b),
                0x30...0x7E => {
                    p.state = .ground;
                    t.escDispatch(b);
                },
                0x7F => {},
                0x80...0xFF => t.abortToGround(b),
            },
            .csi_entry => switch (b) {
                0x00...0x1F => t.execute(b),
                0x20...0x2F => {
                    p.collect(b);
                    p.state = .csi_intermediate;
                },
                0x30...0x3B => {
                    p.param(b);
                    p.state = .csi_param;
                },
                0x3C...0x3F => {
                    p.private = b;
                    p.state = .csi_param;
                },
                0x40...0x7E => {
                    p.state = .ground;
                    t.csiDispatch(b);
                },
                0x7F => {},
                0x80...0xFF => t.abortToGround(b),
            },
            .csi_param => switch (b) {
                0x00...0x1F => t.execute(b),
                0x30...0x3B => p.param(b),
                0x3C...0x3F => p.state = .csi_ignore,
                0x20...0x2F => {
                    p.collect(b);
                    p.state = .csi_intermediate;
                },
                0x40...0x7E => {
                    p.state = .ground;
                    t.csiDispatch(b);
                },
                0x7F => {},
                0x80...0xFF => t.abortToGround(b),
            },
            .csi_intermediate => switch (b) {
                0x00...0x1F => t.execute(b),
                0x20...0x2F => p.collect(b),
                0x30...0x3F => p.state = .csi_ignore,
                0x40...0x7E => {
                    p.state = .ground;
                    t.csiDispatch(b);
                },
                0x7F => {},
                0x80...0xFF => t.abortToGround(b),
            },
            .csi_ignore => switch (b) {
                0x00...0x1F => t.execute(b),
                0x20...0x3F, 0x7F => {},
                0x40...0x7E => p.state = .ground,
                0x80...0xFF => t.abortToGround(b),
            },
            .dcs_entry => switch (b) {
                0x00...0x1F, 0x7F => {},
                0x20...0x2F => p.state = .dcs_intermediate,
                0x3A => p.state = .dcs_ignore,
                0x30...0x39, 0x3B...0x3F => p.state = .dcs_param,
                0x40...0x7E => p.state = .dcs_passthrough,
                0x80...0xFF => t.abortToGround(b),
            },
            .dcs_param => switch (b) {
                0x00...0x1F, 0x7F => {},
                0x30...0x39, 0x3B => {},
                0x3A, 0x3C...0x3F => p.state = .dcs_ignore,
                0x20...0x2F => p.state = .dcs_intermediate,
                0x40...0x7E => p.state = .dcs_passthrough,
                0x80...0xFF => t.abortToGround(b),
            },
            .dcs_intermediate => switch (b) {
                0x00...0x1F, 0x7F, 0x20...0x2F => {},
                0x30...0x3F => p.state = .dcs_ignore,
                0x40...0x7E => p.state = .dcs_passthrough,
                0x80...0xFF => t.abortToGround(b),
            },
            // Payloads are discarded. BEL also terminates them (lenient
            // recovery from unterminated strings).
            .dcs_passthrough, .dcs_ignore, .sos_pm_apc_string => {
                if (b == 0x07) p.state = .ground;
            },
            .apc_start => {
                if (b == 'G') {
                    t.images.begin();
                    p.state = .gfx_string;
                } else if (b == 0x07) {
                    p.state = .ground;
                } else p.state = .sos_pm_apc_string;
            },
            .gfx_string => {
                if (b == 0x07) {
                    t.gfxEnd();
                    p.state = .ground;
                } else t.images.put(t.gpa, b);
            },
            .osc_string => switch (b) {
                0x07 => {
                    t.oscEnd(false);
                    p.state = .ground;
                },
                0x00...0x06, 0x08...0x1F => {},
                0x20...0xFF => {
                    p.oscPut(b);
                    // OSC 7070;G...: a graphics command (ConPTY passes
                    // unknown OSCs through but drops APC strings).
                    if (p.osc_len == gfx.osc_number.len + 2 and
                        std.mem.eql(u8, p.osc[0..gfx.osc_number.len], gfx.osc_number) and
                        p.osc[gfx.osc_number.len] == ';' and p.osc[gfx.osc_number.len + 1] == 'G')
                    {
                        p.osc_len = 0;
                        t.images.begin();
                        p.state = .gfx_string;
                    }
                },
            },
        }
    }

    /// A non-ASCII byte inside an escape/control sequence: drop the sequence
    /// and treat the byte as text.
    fn abortToGround(t: *Terminal, b: u8) void {
        t.parser.state = .ground;
        t.parser.clear();
        t.step(b);
    }

    fn execute(t: *Terminal, b: u8) void {
        t.last_cp = null;
        switch (b) {
            0x08 => { // BS
                t.cur.pending_wrap = false;
                if (t.cur.x > 0) t.cur.x -= 1;
            },
            0x09 => t.tabForward(1),
            0x0A, 0x0B, 0x0C => t.index(),
            0x0D => {
                t.cur.pending_wrap = false;
                t.cur.x = 0;
            },
            0x0E => t.cur.gl = 1, // SO
            0x0F => t.cur.gl = 0, // SI
            else => {}, // BEL and the rest: ignored
        }
    }

    fn tabForward(t: *Terminal, n: u32) void {
        t.cur.pending_wrap = false;
        var left = @max(n, 1);
        while (left > 0 and t.cur.x + 1 < t.cols) : (left -= 1) {
            var x = t.cur.x + 1;
            while (x + 1 < t.cols and !t.tabs[x]) x += 1;
            t.cur.x = x;
        }
    }

    fn tabBackward(t: *Terminal, n: u32) void {
        t.cur.pending_wrap = false;
        var left = @max(n, 1);
        while (left > 0 and t.cur.x > 0) : (left -= 1) {
            var x = t.cur.x - 1;
            while (x > 0 and !t.tabs[x]) x -= 1;
            t.cur.x = x;
        }
    }

    fn escDispatch(t: *Terminal, b: u8) void {
        t.last_cp = null;
        const p = &t.parser;
        if (p.n_inter == 1) {
            switch (p.inter[0]) {
                '(', ')' => {
                    const slot: usize = if (p.inter[0] == '(') 0 else 1;
                    t.cur.g[slot] = if (b == '0') .dec_graphics else .ascii;
                },
                '#' => if (b == '8') t.decaln(),
                else => {},
            }
            return;
        }
        if (p.n_inter != 0) return;
        switch (b) {
            '7' => t.saveCursor(),
            '8' => t.restoreCursor(),
            'D' => t.index(),
            'E' => {
                t.cur.x = 0;
                t.index();
            },
            'M' => t.reverseIndex(),
            'H' => t.tabs[t.cur.x] = true,
            'c' => t.fullReset(),
            else => {}, // '=', '>', '\\' (ST), unknown
        }
    }

    fn saveCursor(t: *Terminal) void {
        t.saved[@intFromBool(t.alt_active)] = t.cur;
    }

    fn restoreCursor(t: *Terminal) void {
        var c = t.saved[@intFromBool(t.alt_active)];
        t.clampCursor(&c);
        if (!t.autowrap) c.pending_wrap = false;
        t.cur = c;
    }

    fn decaln(t: *Terminal) void {
        t.images.clearScreen(t.alt_active);
        for (0..t.rows) |y| {
            const row = t.line(@intCast(y));
            @memset(row, .{ .cp = 'E' });
        }
        t.top = 0;
        t.bot = t.rows - 1;
        t.cur.x = 0;
        t.cur.y = 0;
        t.cur.pending_wrap = false;
        t.markAll();
    }

    fn fullReset(t: *Terminal) void {
        @memset(t.main.cells, .{});
        @memset(t.alt.cells, .{});
        for (t.main.map, t.alt.map, 0..) |*a, *b, i| {
            a.* = @intCast(i);
            b.* = @intCast(i);
        }
        for (t.tabs, 0..) |*s, i| s.* = i % 8 == 0;
        t.images.reset(t.gpa);
        t.alt_active = false;
        t.cur = .{};
        t.saved = .{ .{}, .{} };
        t.top = 0;
        t.bot = t.rows - 1;
        t.autowrap = true;
        t.cursor_visible = true;
        t.app_cursor = false;
        t.bracketed_paste = false;
        t.last_cp = null;
        t.markAll();
    }

    fn softReset(t: *Terminal) void {
        t.cur.pen = .{};
        t.cur.origin = false;
        t.cur.g = .{ .ascii, .ascii };
        t.cur.gl = 0;
        t.cur.pending_wrap = false;
        t.saved = .{ .{}, .{} };
        t.top = 0;
        t.bot = t.rows - 1;
        t.autowrap = true;
        t.cursor_visible = true;
        t.app_cursor = false;
    }

    /// End of a graphics command: store / place / delete, then move the
    /// cursor past a new placement as kitty does (unless C=1): down to the
    /// image's last row (scrolling as needed), and to the column after it.
    fn gfxEnd(t: *Terminal) void {
        const placed = t.images.end(t.gpa, .{
            .cols = t.cols,
            .rows = t.rows,
            .x = @min(t.cur.x, t.cols - 1),
            .y = @min(t.cur.y, t.rows - 1),
            .alt = t.alt_active,
        }) orelse return;
        if (!placed.move_cursor) return;
        var n = placed.rows;
        while (n > 1) : (n -= 1) t.index();
        t.cur.pending_wrap = false;
        t.cur.x = @intCast(@min(@as(u32, placed.col) + placed.cols, @as(u32, t.cols) - 1));
    }

    /// `st`: the string ended with ESC (ST) rather than BEL.
    fn oscEnd(t: *Terminal, st: bool) void {
        const p = &t.parser;
        const data = p.osc[0..p.osc_len];
        p.osc_len = 0;
        const semi = std.mem.indexOfScalar(u8, data, ';') orelse return;
        const cmd = data[0..semi];
        if (std.mem.eql(u8, cmd, "7501")) {
            const body = data[semi + 1 ..];
            if (std.mem.eql(u8, body, "?")) return t.statusQuery(st);
            return t.setProgramState(parseProgramState(body), parseProgramKind(body));
        }
        if (!std.mem.eql(u8, cmd, "0") and !std.mem.eql(u8, cmd, "2")) return;
        t.setTitle(data[semi + 1 ..]);
    }

    /// OSC 7501 feature detection: queue the fixed reply (`takeReplies`).
    fn statusQuery(t: *Terminal, st: bool) void {
        if (t.pending_replies >= max_pending_replies) return;
        t.pending_reply_st[t.pending_replies] = st;
        t.pending_replies += 1;
    }

    /// OSC 7501 (program status): what the program says it is doing.
    /// Untrusted (any output can contain it): it only changes a tab's
    /// highlight. Not a visible change, so `gen` is not bumped.
    fn setProgramState(t: *Terminal, s: ProgramState, k: ProgramKind) void {
        const kind: ProgramKind = if (s == .waiting) k else .none;
        if (s == t.program_state and kind == t.program_kind) return;
        t.program_state = s;
        t.program_kind = kind;
        t.program_state_gen +%= 1;
    }

    /// Stores a sanitised copy: valid UTF-8, no controls or zero-width
    /// characters, at most `max_title_bytes`.
    fn setTitle(t: *Terminal, raw: []const u8) void {
        var d: Utf8 = .{};
        var len: usize = 0;
        var i: usize = 0;
        while (i < raw.len) {
            const cp: u21 = switch (d.step(raw[i])) {
                .pending => {
                    i += 1;
                    continue;
                },
                .done => |c| blk: {
                    i += 1;
                    break :blk c;
                },
                .bad => blk: {
                    i += 1;
                    break :blk 0xFFFD;
                },
                .bad_reprocess => 0xFFFD, // do not advance
            };
            if (isControl(cp) or width.of(cp) == 0) continue;
            var buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(cp, &buf) catch continue;
            if (len + n > t.title_buf.len) break;
            @memcpy(t.title_buf[len..][0..n], buf[0..n]);
            len += n;
        }
        // An incomplete sequence at the end (e.g. cut by the OSC cap) is dropped.
        t.title_len = @intCast(len);
        t.bumpGen();
    }

    // ---- CSI ------------------------------------------------------------

    fn csiDispatch(t: *Terminal, final: u8) void {
        const p = &t.parser;
        p.finishParams();
        const params = p.params[0..p.n_params];
        const subs = p.subs[0..p.n_params];
        const is_rep = final == 'b' and p.private == 0 and p.n_inter == 0;
        const rep_cp = t.last_cp;
        t.last_cp = null;

        if (p.n_inter > 1) return;
        if (p.private == '?') {
            if (p.n_inter != 0) return;
            switch (final) {
                'h' => for (params) |v| t.setMode(v, true),
                'l' => for (params) |v| t.setMode(v, false),
                else => {},
            }
            return;
        }
        if (p.private != 0) return;
        if (p.n_inter == 1) {
            if (p.inter[0] == '!' and final == 'p') t.softReset();
            return; // DECSCUSR (SP q) and the rest: ignored
        }

        const p0: u32 = arg(params, 0, 1);
        switch (final) {
            'A' => t.cursorUp(p0),
            'B', 'e' => t.cursorDown(p0),
            'C', 'a' => t.cursorRight(p0),
            'D' => t.cursorLeft(p0),
            'E' => {
                t.cursorDown(p0);
                t.cur.x = 0;
            },
            'F' => {
                t.cursorUp(p0);
                t.cur.x = 0;
            },
            'G', '`' => t.setX(p0),
            'H', 'f' => {
                t.setY(p0);
                t.setX(arg(params, 1, 1));
            },
            'd' => t.setY(p0),
            'I' => t.tabForward(p0),
            'Z' => t.tabBackward(p0),
            'J' => t.eraseDisplay(arg(params, 0, 0)),
            'K' => t.eraseLine(arg(params, 0, 0)),
            'X' => {
                t.cur.pending_wrap = false;
                t.eraseCells(t.cur.y, t.cur.x, @as(usize, t.cur.x) + p0);
            },
            '@' => t.insertChars(p0),
            'P' => t.deleteChars(p0),
            'L' => t.insertLines(p0),
            'M' => t.deleteLines(p0),
            'S' => t.scrollUpIn(t.top, t.bot, p0),
            'T' => if (params.len <= 1) t.scrollDownIn(t.top, t.bot, p0), // >1 params: mouse tracking
            'r' => t.setMargins(arg(params, 0, 1), arg(params, 1, t.rows)),
            's' => t.saveCursor(),
            'u' => t.restoreCursor(),
            'g' => switch (arg(params, 0, 0)) {
                0 => t.tabs[t.cur.x] = false,
                3 => @memset(t.tabs, false),
                else => {},
            },
            'b' => if (is_rep) {
                if (rep_cp) |cp| {
                    const screen_cells = @as(u32, t.cols) * t.rows;
                    var n = @min(p0, max_repeat, screen_cells);
                    while (n > 0) : (n -= 1) t.print(cp);
                }
            },
            'm' => t.sgr(params, subs),
            else => {}, // h/l (ANSI modes), n (DSR), c (DA), t, ...: ignored
        }
    }

    /// params[i], or `default` if missing or 0 (VT convention).
    fn arg(params: []const u16, i: usize, default: u16) u16 {
        if (i < params.len and params[i] != 0) return params[i];
        return default;
    }

    fn cursorUp(t: *Terminal, n: u32) void {
        t.cur.pending_wrap = false;
        const lim: u16 = if (t.cur.y >= t.top) t.top else 0;
        const ny = @as(i64, t.cur.y) - n;
        t.cur.y = @intCast(@max(ny, lim));
    }

    fn cursorDown(t: *Terminal, n: u32) void {
        t.cur.pending_wrap = false;
        const lim: u16 = if (t.cur.y <= t.bot) t.bot else t.rows - 1;
        const ny = @as(u64, t.cur.y) + n;
        t.cur.y = @intCast(@min(ny, lim));
    }

    fn cursorRight(t: *Terminal, n: u32) void {
        t.cur.pending_wrap = false;
        const nx = @as(u64, t.cur.x) + n;
        t.cur.x = @intCast(@min(nx, t.cols - 1));
    }

    fn cursorLeft(t: *Terminal, n: u32) void {
        t.cur.pending_wrap = false;
        const nx = @as(i64, t.cur.x) - n;
        t.cur.x = @intCast(@max(nx, 0));
    }

    /// 1-based column.
    fn setX(t: *Terminal, col: u32) void {
        t.cur.pending_wrap = false;
        t.cur.x = @intCast(@min(@max(col, 1) - 1, t.cols - 1));
    }

    /// 1-based row, relative to the top margin in origin mode.
    fn setY(t: *Terminal, row: u32) void {
        t.cur.pending_wrap = false;
        const r0 = @max(row, 1) - 1;
        if (t.cur.origin) {
            t.cur.y = @intCast(@min(@as(u64, t.top) + r0, t.bot));
        } else {
            t.cur.y = @intCast(@min(r0, t.rows - 1));
        }
    }

    fn home(t: *Terminal) void {
        t.cur.x = 0;
        t.cur.y = if (t.cur.origin) t.top else 0;
        t.cur.pending_wrap = false;
    }

    fn setMargins(t: *Terminal, top1: u16, bot1_in: u16) void {
        const bot1 = @min(bot1_in, t.rows);
        if (top1 < 1 or top1 >= bot1) return;
        t.top = top1 - 1;
        t.bot = bot1 - 1;
        t.home();
    }

    fn eraseDisplay(t: *Terminal, mode: u16) void {
        switch (mode) {
            0 => {
                t.cur.pending_wrap = false;
                t.eraseCells(t.cur.y, t.cur.x, t.cols);
                t.eraseRows(t.cur.y + 1, t.rows);
            },
            1 => {
                t.eraseRows(0, t.cur.y);
                t.eraseCells(t.cur.y, 0, @as(usize, t.cur.x) + 1);
            },
            2 => t.eraseRows(0, t.rows),
            else => {}, // 3: scrollback only; there is none
        }
    }

    fn eraseLine(t: *Terminal, mode: u16) void {
        switch (mode) {
            0 => {
                t.cur.pending_wrap = false;
                t.eraseCells(t.cur.y, t.cur.x, t.cols);
            },
            1 => t.eraseCells(t.cur.y, 0, @as(usize, t.cur.x) + 1),
            2 => t.eraseCells(t.cur.y, 0, t.cols),
            else => {},
        }
    }

    fn insertChars(t: *Terminal, n_in: u32) void {
        t.cur.pending_wrap = false;
        const row = t.line(t.cur.y);
        const x: usize = t.cur.x;
        const n: usize = @min(n_in, row.len - x);
        t.images.erase(t.alt_active, t.cur.y, x, row.len);
        std.mem.copyBackwards(Cell, row[x + n ..], row[x .. row.len - n]);
        @memset(row[x .. x + n], t.blank());
        fixWide(row);
        t.markRow(t.cur.y);
    }

    fn deleteChars(t: *Terminal, n_in: u32) void {
        t.cur.pending_wrap = false;
        const row = t.line(t.cur.y);
        const x: usize = t.cur.x;
        const n: usize = @min(n_in, row.len - x);
        t.images.erase(t.alt_active, t.cur.y, x, row.len);
        std.mem.copyForwards(Cell, row[x .. row.len - n], row[x + n ..]);
        @memset(row[row.len - n ..], t.blank());
        fixWide(row);
        t.markRow(t.cur.y);
    }

    fn insertLines(t: *Terminal, n: u32) void {
        if (t.cur.y < t.top or t.cur.y > t.bot) return;
        t.scrollDownIn(t.cur.y, t.bot, n);
        t.cur.x = 0;
        t.cur.pending_wrap = false;
    }

    fn deleteLines(t: *Terminal, n: u32) void {
        if (t.cur.y < t.top or t.cur.y > t.bot) return;
        t.scrollUpIn(t.cur.y, t.bot, n);
        t.cur.x = 0;
        t.cur.pending_wrap = false;
    }

    fn setMode(t: *Terminal, mode: u16, on: bool) void {
        switch (mode) {
            1 => t.app_cursor = on,
            6 => {
                t.cur.origin = on;
                t.home();
            },
            7 => {
                t.autowrap = on;
                if (!on) t.cur.pending_wrap = false;
            },
            25 => t.cursor_visible = on,
            47 => t.switchScreen(on),
            1047 => {
                if (!on and t.alt_active) t.clearScreen(&t.alt);
                t.switchScreen(on);
            },
            1049 => if (on) {
                if (!t.alt_active) {
                    t.saveCursor();
                    t.switchScreen(true);
                    t.clearScreen(&t.alt);
                }
            } else if (t.alt_active) {
                t.switchScreen(false);
                t.restoreCursor();
            },
            2004 => t.bracketed_paste = on,
            9001 => t.win32_input = on,
            else => {}, // 1004 focus, mouse...
        }
    }

    fn clearScreen(t: *Terminal, s: *Screen) void {
        @memset(s.cells, t.blank());
        t.images.clearScreen(s == &t.alt);
        t.markAll();
    }

    fn switchScreen(t: *Terminal, alt: bool) void {
        if (t.alt_active == alt) return;
        t.alt_active = alt;
        t.images.gen +%= 1; // the visible placement list changed
        t.markAll();
    }

    fn sgr(t: *Terminal, params: []const u16, subs: []const bool) void {
        const pen = &t.cur.pen;
        if (params.len == 0) {
            pen.* = .{};
            return;
        }
        var i: usize = 0;
        while (i < params.len) : (i += 1) {
            if (subs[i]) continue; // stray sub-parameter of something handled
            const v = params[i];
            switch (v) {
                0 => pen.* = .{},
                1 => pen.attrs |= attr_bold,
                2 => pen.attrs |= attr_dim,
                3 => pen.attrs |= attr_italic,
                4 => {
                    // 4:0 means "no underline"; 4:n (curly etc.) underline.
                    const off = i + 1 < params.len and subs[i + 1] and params[i + 1] == 0;
                    if (off) pen.attrs &= ~attr_underline else pen.attrs |= attr_underline;
                },
                7 => pen.attrs |= attr_inverse,
                8 => pen.attrs |= attr_hidden,
                9 => pen.attrs |= attr_strike,
                21 => pen.attrs |= attr_underline,
                22 => pen.attrs &= ~(attr_bold | attr_dim),
                23 => pen.attrs &= ~attr_italic,
                24 => pen.attrs &= ~attr_underline,
                27 => pen.attrs &= ~attr_inverse,
                28 => pen.attrs &= ~attr_hidden,
                29 => pen.attrs &= ~attr_strike,
                30...37 => pen.fg = ansi16[v - 30],
                39 => pen.fg = color_default,
                40...47 => pen.bg = ansi16[v - 40],
                49 => pen.bg = color_default,
                90...97 => pen.fg = ansi16[v - 90 + 8],
                100...107 => pen.bg = ansi16[v - 100 + 8],
                38, 48, 58 => {
                    var used: usize = 0;
                    const c = extColor(params, subs, i, &used);
                    i += used;
                    if (c) |col| switch (v) {
                        38 => pen.fg = col,
                        48 => pen.bg = col,
                        else => {}, // 58: underline colour, unsupported
                    };
                },
                else => {}, // 5/6 blink, 53 overline, ...: ignored
            }
        }
    }

    /// Parses the colour following params[i] (38/48/58) in either the
    /// `;5;n` / `;2;r;g;b` form or the colon form (`:5:n`, `:2:cs:r:g:b`,
    /// `:2:r:g:b`). `used` is how many params after i were consumed.
    fn extColor(params: []const u16, subs: []const bool, i: usize, used: *usize) ?u32 {
        used.* = 0;
        if (i + 1 >= params.len) return null;
        if (subs[i + 1]) {
            var j = i + 1;
            while (j < params.len and subs[j]) j += 1;
            const g = params[i + 1 .. j];
            used.* = g.len;
            if (g[0] == 5 and g.len >= 2) return if (g[1] <= 255) paletteColor(@intCast(g[1])) else null;
            if (g[0] == 2 and g.len >= 5) return rgb(g[2], g[3], g[4]);
            if (g[0] == 2 and g.len == 4) return rgb(g[1], g[2], g[3]);
            return null;
        }
        switch (params[i + 1]) {
            5 => {
                if (i + 2 >= params.len) {
                    used.* = 1;
                    return null;
                }
                used.* = 2;
                const n = params[i + 2];
                return if (n <= 255) paletteColor(@intCast(n)) else null;
            },
            2 => {
                if (i + 4 >= params.len) {
                    used.* = params.len - i - 1;
                    return null;
                }
                used.* = 4;
                return rgb(params[i + 2], params[i + 3], params[i + 4]);
            },
            else => {
                used.* = 1;
                return null;
            },
        }
    }

    // ---- encoding -------------------------------------------------------

    /// Append the binary grid encoding of `rows_to_send` (row indices) to
    /// `out`. Out-of-range indices are skipped. Little-endian:
    ///   u8 'G'; u16 cols; u16 rows; u16 cursor_x; u16 cursor_y;
    ///   u8 cursor_visible; u16 n_rows; then per row:
    ///   u16 row_index; u16 n_runs; then per run:
    ///   u32 fg; u32 bg; u8 attrs; u16 text_len; text_len bytes of UTF-8.
    /// Colours: see `color_default` and the other sentinels. Inverse is
    /// already applied; hidden cells are spaces. A wide character appears
    /// once and covers two cells. Trailing default blanks are trimmed.
    pub fn encodeRows(t: *const Terminal, rows_to_send: []const u16, out: *std.ArrayList(u8), gpa: Allocator) !void {
        const start = out.items.len;
        errdefer out.shrinkRetainingCapacity(start);
        const c = t.cursor();
        try out.append(gpa, 'G');
        try put16(out, gpa, t.cols);
        try put16(out, gpa, t.rows);
        try put16(out, gpa, c.x);
        try put16(out, gpa, c.y);
        try out.append(gpa, @intFromBool(c.visible));
        const n_rows_pos = out.items.len;
        try put16(out, gpa, 0);
        var n_rows: u16 = 0;
        for (rows_to_send) |y| {
            if (y >= t.rows) continue;
            if (n_rows == std.math.maxInt(u16)) break;
            try t.encodeRow(y, out, gpa);
            n_rows += 1;
        }
        patch16(out, n_rows_pos, n_rows);
    }

    fn encodeRow(t: *const Terminal, y: u16, out: *std.ArrayList(u8), gpa: Allocator) !void {
        const row = t.screenConst().line(t.cols, y);
        var end: usize = row.len;
        while (end > 0 and row[end - 1].isDefaultBlank()) end -= 1;

        try put16(out, gpa, y);
        const n_runs_pos = out.items.len;
        try put16(out, gpa, 0);
        var n_runs: u16 = 0;
        var len_pos: usize = 0;
        var text_len: usize = 0;
        var run_fg: u32 = 0;
        var run_bg: u32 = 0;
        var run_attrs: u8 = 0;

        for (row[0..end], 0..) |cell, x| {
            var cp = cell.cp;
            var cells: u2 = 1;
            switch (cell.wide) {
                .narrow => {},
                .lead => {
                    if (x + 1 < row.len and row[x + 1].wide == .cont) cells = 2 else cp = ' ';
                },
                .cont => {
                    if (x > 0 and row[x - 1].wide == .lead) continue;
                    cp = ' ';
                },
            }
            var fg = cell.fg;
            var bg = cell.bg;
            if (cell.attrs & attr_inverse != 0) {
                fg = if (cell.bg == color_default) color_default_bg_as_fg else cell.bg;
                bg = if (cell.fg == color_default) color_default_fg_as_bg else cell.fg;
            }
            const attrs = cell.attrs & attr_wire_mask;
            if (n_runs == 0 or fg != run_fg or bg != run_bg or attrs != run_attrs) {
                if (n_runs > 0) patch16(out, len_pos, @intCast(text_len));
                try put32(out, gpa, fg);
                try put32(out, gpa, bg);
                try out.append(gpa, attrs);
                len_pos = out.items.len;
                try put16(out, gpa, 0);
                text_len = 0;
                n_runs += 1;
                run_fg = fg;
                run_bg = bg;
                run_attrs = attrs;
            }
            if (cell.attrs & attr_hidden != 0) {
                try out.appendNTimes(gpa, ' ', cells);
                text_len += cells;
                continue;
            }
            if (isControl(cp)) cp = 0xFFFD;
            var buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(cp, &buf) catch blk: {
                @memcpy(buf[0..3], "\u{FFFD}");
                break :blk 3;
            };
            try out.appendSlice(gpa, buf[0..n]);
            text_len += n;
        }
        if (n_runs > 0) patch16(out, len_pos, @intCast(text_len));
        patch16(out, n_runs_pos, n_runs);
    }

    fn put16(out: *std.ArrayList(u8), gpa: Allocator, v: u16) !void {
        var b: [2]u8 = undefined;
        std.mem.writeInt(u16, &b, v, .little);
        try out.appendSlice(gpa, &b);
    }

    fn put32(out: *std.ArrayList(u8), gpa: Allocator, v: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        try out.appendSlice(gpa, &b);
    }

    fn patch16(out: *std.ArrayList(u8), pos: usize, v: u16) void {
        std.mem.writeInt(u16, out.items[pos..][0..2], v, .little);
    }
};

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

fn newTerm(cols: u16, rows: u16) !Terminal {
    return Terminal.init(testing.allocator, cols, rows);
}

/// Row text with continuation cells skipped and trailing spaces trimmed.
fn rowText(t: *Terminal, y: u16, buf: []u8) []const u8 {
    const row = t.line(y);
    var len: usize = 0;
    for (row) |c| {
        if (c.wide == .cont) continue;
        const n = std.unicode.utf8Encode(c.cp, buf[len..][0..4]) catch 0;
        len += n;
    }
    while (len > 0 and buf[len - 1] == ' ') len -= 1;
    return buf[0..len];
}

fn expectRow(t: *Terminal, y: u16, want: []const u8) !void {
    var buf: [4096]u8 = undefined;
    try testing.expectEqualStrings(want, rowText(t, y, &buf));
}

fn expectCursor(t: *const Terminal, x: u16, y: u16) !void {
    const c = t.cursor();
    try testing.expectEqual(x, c.x);
    try testing.expectEqual(y, c.y);
}

fn cellAt(t: *Terminal, x: u16, y: u16) Cell {
    return t.line(y)[x];
}

test "print and cursor movement with clamping" {
    var t = try newTerm(10, 5);
    defer t.deinit();
    t.feed("abc");
    try expectRow(&t, 0, "abc");
    try expectCursor(&t, 3, 0);
    t.feed("\x1b[3;4H");
    try expectCursor(&t, 3, 2);
    t.feed("\x1b[100A");
    try expectCursor(&t, 3, 0);
    t.feed("\x1b[100B");
    try expectCursor(&t, 3, 4);
    t.feed("\x1b[100C");
    try expectCursor(&t, 9, 4);
    t.feed("\x1b[100D");
    try expectCursor(&t, 0, 4);
    t.feed("\x1b[65535;65535H");
    try expectCursor(&t, 9, 4);
    t.feed("\x1b[H");
    try expectCursor(&t, 0, 0);
    t.feed("\x1b[0;0f");
    try expectCursor(&t, 0, 0);
    t.feed("\x1b[5G");
    try expectCursor(&t, 4, 0);
    t.feed("\x1b[3d");
    try expectCursor(&t, 4, 2);
    t.feed("\x1b[2`");
    try expectCursor(&t, 1, 2);
    t.feed("\x1b[3a");
    try expectCursor(&t, 4, 2);
    t.feed("\x1b[e");
    try expectCursor(&t, 4, 3);
    t.feed("\x1b[2F");
    try expectCursor(&t, 0, 1);
    t.feed("\x1b[E");
    try expectCursor(&t, 0, 2);
    t.feed("\x1b[99999999999999999999C"); // saturating params
    try expectCursor(&t, 9, 2);
    t.feed("x\x08\x08\x08y");
    try expectCursor(&t, 7, 2);
    t.feed("\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08");
    try expectCursor(&t, 0, 2);
    t.feed("\r\n\n\n\n\n");
    try expectCursor(&t, 0, 4);
}

test "tabs" {
    var t = try newTerm(20, 2);
    defer t.deinit();
    t.feed("\tA");
    try expectCursor(&t, 9, 0);
    t.feed("\t\t\t");
    try expectCursor(&t, 19, 0);
    t.feed("\r\x1b[3C\x1bH\r\t");
    try expectCursor(&t, 3, 0);
    t.feed("\x1b[g\r\t");
    try expectCursor(&t, 8, 0);
    t.feed("\x1b[3g\r\t");
    try expectCursor(&t, 19, 0);
    t.feed("\x1b[Z");
    try expectCursor(&t, 0, 0);
}

test "wrap and deferred wrap" {
    var t = try newTerm(5, 3);
    defer t.deinit();
    t.feed("abcde");
    try expectCursor(&t, 4, 0); // pending wrap: cursor stays on last column
    try expectRow(&t, 1, "");
    t.feed("f");
    try expectRow(&t, 0, "abcde");
    try expectRow(&t, 1, "f");
    try expectCursor(&t, 1, 1);

    // CR clears pending wrap.
    t.feed("\x1b[H12345\rX");
    try expectRow(&t, 0, "X2345");
    try expectCursor(&t, 1, 0);

    // Cursor movement clears pending wrap; a char then overwrites.
    t.feed("\x1b[1;1Habcde\x1b[1;5Hz");
    try expectRow(&t, 0, "abcdz");
    try expectRow(&t, 1, "f");

    // Autowrap off: overwrite last column.
    t.feed("\x1b[?7l\x1b[3;1Hvwxyz123");
    try expectRow(&t, 2, "vwxy3");
    try expectCursor(&t, 4, 2);
    t.feed("\x1b[?7h");

    // Wrap at the bottom scrolls.
    t.feed("\x1b[3;1H12345Q");
    try expectRow(&t, 1, "12345");
    try expectRow(&t, 2, "Q");
}

test "scrolling with and without regions" {
    var t = try newTerm(4, 5);
    defer t.deinit();
    t.feed("a\r\nb\r\nc\r\nd\r\ne");
    t.feed("\n");
    try expectRow(&t, 0, "b");
    try expectRow(&t, 3, "e");
    try expectRow(&t, 4, "");

    // Region rows 2..4 (1-based).
    t.feed("\x1b[2;4r");
    try expectCursor(&t, 0, 0); // DECSTBM homes the cursor
    t.feed("\x1b[4;1H\n");
    try expectRow(&t, 0, "b");
    try expectRow(&t, 1, "d");
    try expectRow(&t, 2, "e");
    try expectRow(&t, 3, "");
    try expectRow(&t, 4, "");
    // RI at top of region scrolls region down.
    t.feed("\x1b[2;1H\x1bM");
    try expectRow(&t, 1, "");
    try expectRow(&t, 2, "d");
    try expectRow(&t, 3, "e");
    try expectRow(&t, 0, "b");
    // SU / SD within region.
    t.feed("\x1b[2S");
    try expectRow(&t, 1, "e");
    try expectRow(&t, 2, "");
    t.feed("\x1b[T");
    try expectRow(&t, 1, "");
    try expectRow(&t, 2, "e");
    // LF below region at last row does not scroll.
    t.feed("\x1b[5;1HZ\n");
    try expectCursor(&t, 1, 4);
    try expectRow(&t, 4, "Z");
    try expectRow(&t, 0, "b");
    // Invalid region ignored.
    t.feed("\x1b[4;2r");
    try testing.expectEqual(@as(u16, 1), t.top);
    try testing.expectEqual(@as(u16, 3), t.bot);
    t.feed("\x1b[r");
    try testing.expectEqual(@as(u16, 0), t.top);
    try testing.expectEqual(@as(u16, 4), t.bot);
    // Huge SU clears everything.
    t.feed("\x1b[65535S");
    for (0..5) |y| try expectRow(&t, @intCast(y), "");
    // ESC D / ESC E
    t.feed("\x1b[1;3Hq\x1bDw\x1bEe");
    try expectRow(&t, 0, "  q");
    try expectRow(&t, 1, "   w");
    try expectRow(&t, 2, "e");
}

test "origin mode" {
    var t = try newTerm(10, 6);
    defer t.deinit();
    t.feed("\x1b[2;4r\x1b[?6h");
    try expectCursor(&t, 0, 1);
    t.feed("\x1b[2;3H");
    try expectCursor(&t, 2, 2);
    t.feed("\x1b[9;1H");
    try expectCursor(&t, 0, 3); // clamped to bottom margin
    t.feed("\x1b[?6l");
    try expectCursor(&t, 0, 0);
}

test "erase variants" {
    var t = try newTerm(5, 3);
    defer t.deinit();
    const fill = "\x1b[1;1Habcde\x1b[2;1Hfghij\x1b[3;1Hklmno";
    t.feed(fill);
    t.feed("\x1b[2;3H\x1b[K");
    try expectRow(&t, 1, "fg");
    t.feed(fill ++ "\x1b[2;3H\x1b[1K");
    try expectRow(&t, 1, "   ij");
    t.feed(fill ++ "\x1b[2;3H\x1b[2K");
    try expectRow(&t, 1, "");
    try expectRow(&t, 0, "abcde");
    t.feed(fill ++ "\x1b[2;3H\x1b[J");
    try expectRow(&t, 0, "abcde");
    try expectRow(&t, 1, "fg");
    try expectRow(&t, 2, "");
    t.feed(fill ++ "\x1b[2;3H\x1b[1J");
    try expectRow(&t, 0, "");
    try expectRow(&t, 1, "   ij");
    try expectRow(&t, 2, "klmno");
    t.feed(fill ++ "\x1b[2;3H\x1b[2J");
    for (0..3) |y| try expectRow(&t, @intCast(y), "");
    try expectCursor(&t, 2, 1); // ED does not move the cursor
    t.feed(fill ++ "\x1b[3J");
    try expectRow(&t, 0, "abcde");
    t.feed("\x1b[1;2H\x1b[2X");
    try expectRow(&t, 0, "a  de");
    t.feed("\x1b[1;4H\x1b[999X");
    try expectRow(&t, 0, "a");
    // Erase uses the current background colour.
    t.feed("\x1b[44m\x1b[2;1H\x1b[K\x1b[m");
    try testing.expectEqual(paletteColor(4), cellAt(&t, 4, 1).bg);
}

test "insert and delete chars and lines" {
    var t = try newTerm(6, 4);
    defer t.deinit();
    t.feed("abcdef\x1b[1;3H\x1b[2@");
    try expectRow(&t, 0, "ab  cd");
    t.feed("\x1b[1;3H\x1b[3P");
    try expectRow(&t, 0, "abd");
    t.feed("\x1b[1;1H\x1b[999P");
    try expectRow(&t, 0, "");
    t.feed("\x1b[1;1Habcdef\x1b[1;2H\x1b[999@");
    try expectRow(&t, 0, "a");

    t.feed("\x1b[H\x1b[2J1\r\n2\r\n3\r\n4");
    t.feed("\x1b[2;3H\x1b[L");
    try expectCursor(&t, 0, 1);
    try expectRow(&t, 0, "1");
    try expectRow(&t, 1, "");
    try expectRow(&t, 2, "2");
    try expectRow(&t, 3, "3");
    t.feed("\x1b[2M");
    try expectRow(&t, 1, "3");
    try expectRow(&t, 2, "");
    // IL/DL respect the scroll region and are ignored outside it.
    t.feed("\x1b[H\x1b[2J1\r\n2\r\n3\r\n4\x1b[1;3r\x1b[4;1H\x1b[L");
    try expectRow(&t, 3, "4");
    t.feed("\x1b[1;1H\x1b[5L");
    for (0..3) |y| try expectRow(&t, @intCast(y), "");
    try expectRow(&t, 3, "4");
}

test "SGR combos and palette resolution" {
    var t = try newTerm(20, 2);
    defer t.deinit();
    t.feed("\x1b[1;3;4;9;31;42mA");
    var c = cellAt(&t, 0, 0);
    try testing.expectEqual(attr_bold | attr_italic | attr_underline | attr_strike, c.attrs);
    try testing.expectEqual(ansi16[1], c.fg);
    try testing.expectEqual(ansi16[2], c.bg);
    t.feed("\x1b[22;23;24;29;39;49mB");
    c = cellAt(&t, 1, 0);
    try testing.expectEqual(@as(u8, 0), c.attrs);
    try testing.expectEqual(color_default, c.fg);
    try testing.expectEqual(color_default, c.bg);
    t.feed("\x1b[38;5;196;48;5;21mC");
    c = cellAt(&t, 2, 0);
    try testing.expectEqual(@as(u32, 0xFF0000), c.fg);
    try testing.expectEqual(@as(u32, 0x0000FF), c.bg);
    t.feed("\x1b[38;2;1;2;3;48;2;300;5;6mD");
    c = cellAt(&t, 3, 0);
    try testing.expectEqual(@as(u32, 0x010203), c.fg);
    try testing.expectEqual(@as(u32, 0xFF0506), c.bg);
    t.feed("\x1b[0;38:2::10:20:30;48:5:232mE");
    c = cellAt(&t, 4, 0);
    try testing.expectEqual(@as(u32, 0x0A141E), c.fg);
    try testing.expectEqual(@as(u32, 0x080808), c.bg);
    t.feed("\x1b[38:2:7:8:9mF");
    try testing.expectEqual(@as(u32, 0x070809), cellAt(&t, 5, 0).fg);
    t.feed("\x1b[0;95;105mG");
    c = cellAt(&t, 6, 0);
    try testing.expectEqual(ansi16[13], c.fg);
    try testing.expectEqual(ansi16[13], c.bg);
    t.feed("\x1b[m\x1b[2;5;21mH");
    try testing.expectEqual(attr_dim | attr_underline, cellAt(&t, 7, 0).attrs);
    t.feed("\x1b[4:0mI");
    try testing.expectEqual(attr_dim, cellAt(&t, 8, 0).attrs);
    // 58 (underline colour) consumes its arguments rather than applying them.
    t.feed("\x1b[0;58;2;1;31;7mJ");
    c = cellAt(&t, 9, 0);
    try testing.expectEqual(color_default, c.fg);
    try testing.expectEqual(@as(u8, 0), c.attrs);
    // Truncated extended colours are ignored safely.
    t.feed("\x1b[38;5m\x1b[38;2;1m\x1b[48m\x1b[38:5mK");
    // Palette spot checks.
    try testing.expectEqual(@as(u32, 0x000000), paletteColor(16));
    try testing.expectEqual(@as(u32, 0xFFFFFF), paletteColor(231));
    try testing.expectEqual(@as(u32, 0x5F87AF), paletteColor(67));
    try testing.expectEqual(@as(u32, 0xEEEEEE), paletteColor(255));
    try testing.expectEqual(ansi16[12], paletteColor(12));
    // 256+ index ignored.
    t.feed("\x1b[0;31;38;5;300mL");
    try testing.expectEqual(ansi16[1], cellAt(&t, 11, 0).fg);
}

// --- test decoder for the wire format -------------------------------------

const DecodedRun = struct { fg: u32, bg: u32, attrs: u8, text: []const u8 };
const DecodedRow = struct { index: u16, runs: []DecodedRun };
const Decoded = struct {
    cols: u16,
    rows: u16,
    cx: u16,
    cy: u16,
    visible: bool,
    rows_list: []DecodedRow,
    arena: std.heap.ArenaAllocator,

    fn deinit(d: *Decoded) void {
        d.arena.deinit();
    }
};

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,
    fn bytes(r: *Reader, n: usize) ![]const u8 {
        if (r.buf.len - r.pos < n) return error.Truncated;
        defer r.pos += n;
        return r.buf[r.pos..][0..n];
    }
    fn u8_(r: *Reader) !u8 {
        return (try r.bytes(1))[0];
    }
    fn u16_(r: *Reader) !u16 {
        return std.mem.readInt(u16, (try r.bytes(2))[0..2], .little);
    }
    fn u32_(r: *Reader) !u32 {
        return std.mem.readInt(u32, (try r.bytes(4))[0..4], .little);
    }
};

/// Decodes and validates one frame: UTF-8 validity, no controls, run width
/// within cols, attrs within the wire mask.
fn decodeFrame(buf: []const u8) !Decoded {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    var r: Reader = .{ .buf = buf };
    if (try r.u8_() != 'G') return error.BadMagic;
    var d: Decoded = .{
        .cols = try r.u16_(),
        .rows = try r.u16_(),
        .cx = try r.u16_(),
        .cy = try r.u16_(),
        .visible = switch (try r.u8_()) {
            0 => false,
            1 => true,
            else => return error.BadVisible,
        },
        .rows_list = &.{},
        .arena = undefined,
    };
    if (d.cx >= d.cols or d.cy >= d.rows) return error.CursorOutOfBounds;
    const n_rows = try r.u16_();
    const rows = try a.alloc(DecodedRow, n_rows);
    for (rows) |*row| {
        row.index = try r.u16_();
        if (row.index >= d.rows) return error.RowOutOfBounds;
        const n_runs = try r.u16_();
        row.runs = try a.alloc(DecodedRun, n_runs);
        var cells: usize = 0;
        for (row.runs) |*run| {
            run.fg = try r.u32_();
            run.bg = try r.u32_();
            run.attrs = try r.u8_();
            if (run.attrs & ~attr_wire_mask != 0) return error.BadAttrs;
            if (run.fg == color_reserved or run.fg == color_default_fg_as_bg) return error.BadFg;
            if (run.bg == color_reserved or run.bg == color_default_bg_as_fg) return error.BadBg;
            if (run.fg >> 24 != 0 and run.fg >> 24 != 0xFF) return error.BadFg;
            if (run.bg >> 24 != 0 and run.bg >> 24 != 0xFF) return error.BadBg;
            const len = try r.u16_();
            run.text = try r.bytes(len);
            if (!std.unicode.utf8ValidateSlice(run.text)) return error.BadUtf8;
            var it = std.unicode.Utf8View.initUnchecked(run.text).iterator();
            while (it.nextCodepoint()) |cp| {
                if (isControl(cp)) return error.ControlInText;
                const w = width.of(cp);
                if (w == 0) return error.ZeroWidthInText;
                cells += w;
            }
        }
        if (cells > d.cols) return error.RowTooWide;
    }
    if (r.pos != buf.len) return error.TrailingBytes;
    d.rows_list = rows;
    d.arena = arena;
    return d;
}

fn encodeAll(t: *const Terminal, out: *std.ArrayList(u8)) !void {
    var idx: [max_dim]u16 = undefined;
    for (0..t.rows) |i| idx[i] = @intCast(i);
    try t.encodeRows(idx[0..t.rows], out, testing.allocator);
}

test "encodeRows round-trip" {
    var t = try newTerm(12, 3);
    defer t.deinit();
    t.feed("ab\x1b[1;31mcd\x1b[m  \x1b[44mx\x1b[m");
    t.feed("\x1b[2;1H\x1b[7mI\x1b[38;2;1;2;3mJ\x1b[27m\x1b[8mK\x1b[28m中Z");
    t.feed("\x1b[3;1H\x1b[?25l");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try out.appendSlice(testing.allocator, "prefix");
    try t.encodeRows(&.{ 0, 1, 2, 999 }, &out, testing.allocator);
    try testing.expectEqualStrings("prefix", out.items[0..6]);
    var d = try decodeFrame(out.items[6..]);
    defer d.deinit();
    try testing.expectEqual(@as(u16, 12), d.cols);
    try testing.expectEqual(@as(u16, 3), d.rows);
    try testing.expectEqual(@as(u16, 0), d.cx);
    try testing.expectEqual(@as(u16, 2), d.cy);
    try testing.expect(!d.visible);
    try testing.expectEqual(@as(usize, 3), d.rows_list.len); // 999 skipped

    const r0 = d.rows_list[0].runs;
    try testing.expectEqual(@as(usize, 4), r0.len);
    try testing.expectEqualStrings("ab", r0[0].text);
    try testing.expectEqual(color_default, r0[0].fg);
    try testing.expectEqualStrings("cd", r0[1].text);
    try testing.expectEqual(ansi16[1], r0[1].fg);
    try testing.expectEqual(attr_bold, r0[1].attrs);
    try testing.expectEqualStrings("  ", r0[2].text);
    try testing.expectEqualStrings("x", r0[3].text);
    try testing.expectEqual(paletteColor(4), r0[3].bg);

    const r1 = d.rows_list[1].runs;
    try testing.expectEqual(@as(usize, 3), r1.len);
    // Inverse with default colours uses the sentinels.
    try testing.expectEqualStrings("I", r1[0].text);
    try testing.expectEqual(color_default_bg_as_fg, r1[0].fg);
    try testing.expectEqual(color_default_fg_as_bg, r1[0].bg);
    // Inverse with an explicit fg: bg becomes that colour.
    try testing.expectEqualStrings("J", r1[1].text);
    try testing.expectEqual(color_default_bg_as_fg, r1[1].fg);
    try testing.expectEqual(@as(u32, 0x010203), r1[1].bg);
    // Hidden renders as a space; hidden is not a wire attribute, so it
    // shares a run with the following visible text of the same style.
    try testing.expectEqualStrings(" 中Z", r1[2].text);
    try testing.expectEqual(@as(u32, 0x010203), r1[2].fg);
    try testing.expectEqual(color_default, r1[2].bg);

    try testing.expectEqual(@as(usize, 0), d.rows_list[2].runs.len);
}

test "inverse with explicit colours swaps" {
    var t = try newTerm(4, 1);
    defer t.deinit();
    t.feed("\x1b[31;42;7mA\x1b[27;8m\xe4\xb8\xadB");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try encodeAll(&t, &out);
    var d = try decodeFrame(out.items);
    defer d.deinit();
    const runs = d.rows_list[0].runs;
    try testing.expectEqual(ansi16[2], runs[0].fg);
    try testing.expectEqual(ansi16[1], runs[0].bg);
    try testing.expectEqualStrings("   ", runs[1].text); // hidden wide = 2 spaces
}

test "alt screen save and restore" {
    var t = try newTerm(10, 4);
    defer t.deinit();
    t.feed("main\x1b[2;3H\x1b[1;32m");
    t.feed("\x1b[?1049h");
    try expectRow(&t, 0, "");
    try testing.expect(t.alt_active);
    t.feed("\x1b[m\x1b[Halt\x1b[4;4H");
    try expectRow(&t, 0, "alt");
    t.feed("\x1b[?1049l");
    try testing.expect(!t.alt_active);
    try expectRow(&t, 0, "main");
    try expectCursor(&t, 2, 1);
    try testing.expectEqual(attr_bold, t.cur.pen.attrs);
    // Re-entering clears the alt screen.
    t.feed("\x1b[?1049h");
    try expectRow(&t, 0, "");
    t.feed("x\x1b[?1049l");
    // 47 keeps cursor and alt content; 1047 clears alt on exit.
    t.feed("\x1b[?47h\x1b[Hkeep\x1b[?47l\x1b[?47h");
    try expectRow(&t, 0, "keep");
    t.feed("\x1b[?1047l\x1b[?1047h");
    try expectRow(&t, 0, "");
    t.feed("\x1b[?1047l");
    try expectRow(&t, 0, "main");
    // Double 1049l is harmless.
    t.feed("\x1b[?1049l\x1b[?1049l");
    try expectRow(&t, 0, "main");
}

test "save and restore cursor" {
    var t = try newTerm(10, 4);
    defer t.deinit();
    t.feed("\x1b[2;5H\x1b[31m\x1b7\x1b[H\x1b[m\x1b8X");
    try expectCursor(&t, 5, 1);
    try testing.expectEqual(ansi16[1], cellAt(&t, 4, 1).fg);
    t.feed("\x1b[3;3H\x1b[s\x1b[H\x1b[u");
    try expectCursor(&t, 2, 2);
    t.feed("\x1b[?25l");
    try testing.expect(!t.cursor().visible);
    t.feed("\x1b[?25h\x1b[?1h\x1b[?2004h\x1b[?9001h\x1b[?1004h");
    try testing.expect(t.cursor().visible);
    try testing.expect(t.app_cursor);
}

test "mode accessors and visibleRow" {
    var t = try newTerm(6, 2);
    defer t.deinit();
    try testing.expect(!t.appCursor());
    try testing.expect(!t.bracketedPaste());
    t.feed("\x1b[?1h\x1b[?2004h");
    try testing.expect(t.appCursor());
    try testing.expect(t.bracketedPaste());
    t.feed("\x1bc");
    try testing.expect(!t.appCursor());
    try testing.expect(!t.bracketedPaste());

    t.feed("\x1b[7ma\x1b[m\x1b[8mb\x1b[m\u{4E2D}");
    var row: [8]Terminal.VisibleCell = undefined;
    try testing.expectEqual(@as(usize, 6), t.visibleRow(0, &row));
    try testing.expectEqual(@as(u21, 'a'), row[0].cp);
    try testing.expectEqual(color_default_bg_as_fg, row[0].fg);
    try testing.expectEqual(color_default_fg_as_bg, row[0].bg);
    try testing.expectEqual(@as(u21, ' '), row[1].cp); // hidden
    try testing.expectEqual(@as(u21, 0x4E2D), row[2].cp);
    try testing.expectEqual(Terminal.VisibleWide.lead, row[2].wide);
    try testing.expectEqual(Terminal.VisibleWide.cont, row[3].wide);
    try testing.expectEqual(@as(usize, 0), t.visibleRow(5, &row));
    var short: [2]Terminal.VisibleCell = undefined;
    try testing.expectEqual(@as(usize, 2), t.visibleRow(1, &short));
}

test "DEC special graphics" {
    var t = try newTerm(10, 2);
    defer t.deinit();
    t.feed("\x1b(0lqk\x1b(Bq");
    try expectRow(&t, 0, "┌─┐q");
    t.feed("\r\n\x1b)0a\x0eqx\x0fq");
    try expectRow(&t, 1, "a─│q");
}

test "REP" {
    var t = try newTerm(10, 3);
    defer t.deinit();
    t.feed("a\x1b[3b");
    try expectRow(&t, 0, "aaaa");
    t.feed("\r\n\x1b[5b"); // no preceding graphic char
    try expectRow(&t, 1, "");
    t.feed("z\x1b[65535b");
    // 1 + 30 (screen-size cap) z's: wrapped and scrolled.
    try expectRow(&t, 1, "zzzzzzzzzz");
    try expectRow(&t, 2, "z");
}

test "split UTF-8 and invalid sequences" {
    var t = try newTerm(20, 2);
    defer t.deinit();
    const s = "é中😀";
    for (s) |b| t.feed(&.{b});
    try expectRow(&t, 0, "é中😀");
    try expectCursor(&t, 5, 0);
    t.feed("\r\n\xff\xc3\x28\xe0\x80\xaf\xed\xa0\x80\xf4\x90\x80\x80A");
    var buf: [256]u8 = undefined;
    const got = rowText(&t, 1, &buf);
    try testing.expect(std.unicode.utf8ValidateSlice(got));
    try testing.expect(std.mem.endsWith(u8, got, "A"));
    try testing.expect(std.mem.indexOf(u8, got, "(") != null);
    // Truncated UTF-8 followed by an escape sequence.
    t.feed("\x1b[2;1H\xe4\xb8\x1b[Kok");
    try expectRow(&t, 1, "\u{FFFD}ok");
    // Combining marks and C1 code points are dropped.
    t.feed("\x1b[2;1H\x1b[Ke\xcc\x81\xc2\x9bx");
    try expectRow(&t, 1, "ex");
}

test "wide chars at the right margin" {
    var t = try newTerm(5, 3);
    defer t.deinit();
    t.feed("abcd中");
    try expectRow(&t, 0, "abcd");
    try expectRow(&t, 1, "中");
    try expectCursor(&t, 2, 1);
    t.feed("\x1b[3;1Habc中");
    try expectRow(&t, 2, "abc中");
    try expectCursor(&t, 4, 2);
    // Overwriting half a wide char blanks the other half.
    t.feed("\x1b[2;2Hx");
    try expectRow(&t, 1, " x");
    try testing.expectEqual(Wide.narrow, cellAt(&t, 0, 1).wide);
    t.feed("\x1b[2;1H中\x1b[2;1Hy");
    try expectRow(&t, 1, "y");
    // Autowrap off: a wide char that does not fit is dropped.
    t.feed("\x1b[?7l\x1b[1;5H中");
    try expectRow(&t, 0, "abcd");
    t.feed("\x1b[?7h");
    // ICH/DCH split wide chars cleanly.
    t.feed("\x1b[2;1H\x1b[2K中中\x1b[2;2H\x1b[P");
    try expectRow(&t, 1, " 中");
    // One-column terminal can never hold a wide char.
    var t1 = try newTerm(1, 2);
    defer t1.deinit();
    t1.feed("中a中");
    try expectRow(&t1, 0, "a");
}

test "resize larger and smaller" {
    var t = try newTerm(6, 3);
    defer t.deinit();
    t.feed("abcdef\r\nghi\r\njkl");
    try t.resize(10, 5);
    try testing.expectEqual(@as(u16, 10), t.cols);
    try expectRow(&t, 0, "abcdef");
    try expectRow(&t, 2, "jkl");
    try expectCursor(&t, 3, 2);
    t.feed("\x1b[5;10HZ");
    try expectRow(&t, 4, "         Z");
    try t.resize(2, 2);
    try expectRow(&t, 0, "ab");
    try expectRow(&t, 1, "gh");
    try expectCursor(&t, 1, 1);
    try t.resize(0, 0);
    try testing.expectEqual(@as(u16, 1), t.cols);
    try testing.expectEqual(@as(u16, 1), t.rows);
    try expectRow(&t, 0, "a");
    try t.resize(65535, 3);
    try testing.expectEqual(max_dim, t.cols);
    // Wide char cut by the new right edge is blanked.
    try t.resize(3, 1);
    t.feed("\x1b[Hx中");
    try t.resize(2, 1);
    try expectRow(&t, 0, "x");
    // Resize while in the alt screen keeps both buffers.
    var u = try newTerm(4, 2);
    defer u.deinit();
    u.feed("m\x1b[?1049ha");
    try u.resize(5, 3);
    try expectRow(&u, 0, " a"); // 1049 keeps the cursor column
    u.feed("\x1b[?1049l");
    try expectRow(&u, 0, "m");
    // Generation bumps all rows.
    const g = u.gen;
    try u.resize(6, 3);
    try testing.expect(u.gen > g);
    try testing.expectEqual(u.gen, u.rowGen(2));
}

test "generations" {
    var t = try newTerm(5, 3);
    defer t.deinit();
    const g0 = t.gen;
    t.feed("\x1b[2;1Hx");
    try testing.expect(t.gen > g0);
    try testing.expect(t.rowGen(1) > g0);
    try testing.expectEqual(@as(u64, 0), t.rowGen(0));
    try testing.expectEqual(@as(u64, 0), t.rowGen(999));
    const g1 = t.gen;
    t.feed("\x1b[3;3H"); // cursor-only change still bumps gen
    try testing.expect(t.gen > g1);
    try testing.expect(t.rowGen(2) <= g1);
    const g2 = t.gen;
    t.feed("\x1b[3;3H\x1b[?2004h"); // no visible change
    try testing.expectEqual(g2, t.gen);
}

test "OSC 7501 program state" {
    var t = try Terminal.init(testing.allocator, 20, 3);
    defer t.deinit();
    try testing.expectEqual(ProgramState.unknown, t.program_state);
    const g0 = t.gen;
    t.feed("\x1b]7501;state=blocked:kind=permission:app=claude\x07");
    try testing.expectEqual(ProgramState.waiting, t.program_state);
    try testing.expectEqual(ProgramKind.permission, t.program_kind);
    try testing.expectEqual(@as(u64, 1), t.program_state_gen);
    try testing.expectEqual(g0, t.gen); // not a visible change
    try testing.expectEqualStrings("", t.title()); // nothing leaks into the title
    t.feed("\x1b]7501;state=working\x1b\\");
    try testing.expectEqual(ProgramState.working, t.program_state);
    try testing.expectEqual(ProgramKind.none, t.program_kind);
    t.feed("\x1b]7501;state=working\x07"); // unchanged: no bump
    try testing.expectEqual(@as(u64, 2), t.program_state_gen);
    t.feed("\x1b]7501;app=x;state=error\x07");
    try testing.expectEqual(ProgramState.failed, t.program_state);
    t.feed("\x1b]7501;state=evil\x07");
    try testing.expectEqual(ProgramState.unknown, t.program_state);
    try testing.expectEqual(ProgramState.done, parseProgramState("state=done:msg=aGk="));
    try testing.expectEqual(ProgramState.idle, parseProgramState("state=idle"));
    try testing.expectEqual(ProgramState.unknown, parseProgramState("kind=permission"));
    try testing.expectEqual(ProgramKind.permission, parseProgramKind("state=blocked:kind=permission:app=claude"));
    try testing.expectEqual(ProgramKind.question, parseProgramKind("state=blocked;kind=question"));
    try testing.expectEqual(ProgramKind.other, parseProgramKind("state=blocked:kind=../../etc"));
    try testing.expectEqual(ProgramKind.none, parseProgramKind("state=blocked"));
    try testing.expectEqual(ProgramState.unknown, parseProgramState(""));
}

test "OSC title and truncation" {
    var t = try newTerm(10, 2);
    defer t.deinit();
    t.feed("\x1b]0;hello\x07");
    try testing.expectEqualStrings("hello", t.title());
    t.feed("\x1b]2;wo\x1b]rld\x1b\\");
    try testing.expectEqualStrings("wo", t.title()); // ESC ends the first OSC
    t.feed("\x1b]2;a\x01b\xc2\x9bc\xe2\x80\xaed\x1b\\");
    try testing.expectEqualStrings("abcd", t.title()); // controls/bidi stripped
    t.feed("\x1b]1;icon\x07\x1b]8;;http://x\x07link\x1b]8;;\x07");
    try testing.expectEqualStrings("abcd", t.title());
    try expectRow(&t, 0, "link");
    // Long title: bounded, valid UTF-8, text after it is unaffected.
    t.feed("\x1b]0;");
    for (0..10000) |_| t.feed("é");
    t.feed("\x07Q");
    try testing.expect(t.title().len <= max_title_bytes);
    try testing.expect(t.title().len > 200);
    try testing.expect(std.unicode.utf8ValidateSlice(t.title()));
    try expectRow(&t, 0, "linkQ");
    // OSC truncated mid UTF-8 by the cap does not leave a broken tail.
    t.feed("\x1b]0;");
    for (0..max_osc_bytes - 2) |_| t.feed("a");
    t.feed("\xe4\xb8\xad\x07");
    try testing.expect(std.unicode.utf8ValidateSlice(t.title()));
    // CAN aborts an OSC.
    t.feed("\x1b]0;zzz\x18Y");
    try testing.expect(!std.mem.startsWith(u8, t.title(), "zzz"));
    try expectRow(&t, 0, "linkQY");
}

test "DCS, APC, PM, SOS are discarded" {
    var t = try newTerm(20, 2);
    defer t.deinit();
    t.feed("\x1bPq#0;2;0;0;0#0~~@@vv\x1b\\A");
    t.feed("\x1b_Gsecret\x1b\\B\x1b^pm\x07C\x1bXsos\x1b\\D");
    t.feed("\x1bP1$r\x07E");
    try expectRow(&t, 0, "ABCDE");
}

test "unknown sequences do not corrupt state" {
    var t = try newTerm(20, 2);
    defer t.deinit();
    t.feed("\x1b[31m");
    t.feed("\x1b[>4;2m\x1b[?1;2;3$p\x1b[=5h\x1b[1 q\x1b[6n\x1b[c\x1b[>c\x1b%G\x1b#3\x1bZ\x1b[1;2;3;4;5;6;7;8;9;10;11;12;13;14;15;16;17;18;19;20m");
    t.feed("\x1b[!p"); // DECSTR resets pen
    t.feed("\x1b[1;32m\x1b[12;3$zA");
    try expectRow(&t, 0, "A");
    try testing.expectEqual(ansi16[2], cellAt(&t, 0, 0).fg);
    // C0 inside CSI executes, sequence continues.
    t.feed("\x1b[2\r;3HB");
    try expectCursor(&t, 3, 1);
    try expectRow(&t, 1, "  B");
    // ESC # 8 (DECALN) fills with E.
    t.feed("\x1b#8");
    try expectRow(&t, 1, "EEEEEEEEEEEEEEEEEEEE");
    // RIS.
    t.feed("\x1b]0;keep\x07\x1b[?25l\x1b[5;10r\x1bc");
    try expectRow(&t, 0, "");
    try expectCursor(&t, 0, 0);
    try testing.expect(t.cursor().visible);
    try testing.expectEqual(@as(u16, 1), t.bot);
    // Non-ASCII byte inside CSI aborts it and prints.
    t.feed("\x1b[3\xc3\xa9x");
    try expectRow(&t, 0, "éx");
}

/// Grid, cursor and title equality between two terminals.
fn expectSameState(a: *Terminal, b: *Terminal) !void {
    var ea: std.ArrayList(u8) = .empty;
    defer ea.deinit(testing.allocator);
    var eb: std.ArrayList(u8) = .empty;
    defer eb.deinit(testing.allocator);
    try encodeAll(a, &ea);
    try encodeAll(b, &eb);
    try testing.expectEqualSlices(u8, ea.items, eb.items);
    try testing.expectEqualStrings(a.title(), b.title());
    try testing.expect(std.meta.eql(a.cur, b.cur));
    try testing.expectEqual(a.alt_active, b.alt_active);
}

const corpus = [_][]const u8{
    "plain text\r\nline two\r\n",
    "\x1b[?25l\x1b[2J\x1b[m\x1b[H\x1b]0;C:\\WINDOWS\\system32\\cmd.exe\x07\x1b[?25h",
    "\x1b[38;2;215;119;87m\xe2\x95\xad\xe2\x94\x80\xe2\x94\x80\x1b[39m \x1b[1mAgent\x1b[22m",
    "\x1b[?1049h\x1b[22;1H\x1b[48;5;236m  > \x1b[K\x1b[m\x1b[?1049l",
    "\x1b[3;5H\xe4\xb8\xad\xe6\x96\x87\xf0\x9f\x98\x80 emoji \x1b[7minv\x1b[27m",
    "\x1b(0lqqqk\x1b(B\x0e\x1b)0xx\x0f",
    "\x1b]2;title with \xc3\xa9\x1b\\\x1bP1$r0m\x1b\\after",
    "\x1b[2;4r\x1b[4;1H\n\n\x1bM\x1bM\x1b[L\x1b[2M\x1b[r",
    "\x1b[10X\x1b[3@\x1b[2P\x1b[1K\x1b[0J\x1b[5;5f\x1b[1J",
    "\x1b[38:2::1:2:3mcolon\x1b[4:3mcurly\x1b[0m",
    "wrapwrapwrapwrapwrapwrapwrapwrapwrapwrapwrapwrapwrap\x1b[?7lnowrapnowrapnowrapnowrap\x1b[?7h",
    "\x1b7\x1b[20;20H\x1b[31mX\x1b8Y\x1b[s\x1b[u\x1b[5b",
    "\xff\xfe\xc0\x80\xed\xa0\x80bad utf8\xe2\x82",
};

test "feeding byte-by-byte equals feeding all at once" {
    for (corpus) |s| {
        var a = try newTerm(30, 8);
        defer a.deinit();
        var b = try newTerm(30, 8);
        defer b.deinit();
        a.feed(s);
        for (s) |byte| b.feed(&.{byte});
        try expectSameState(&a, &b);
    }
    // Whole corpus concatenated, split at every possible single point.
    var all: std.ArrayList(u8) = .empty;
    defer all.deinit(testing.allocator);
    for (corpus) |s| try all.appendSlice(testing.allocator, s);
    var ref = try newTerm(30, 8);
    defer ref.deinit();
    ref.feed(all.items);
    var cut: usize = 0;
    while (cut <= all.items.len) : (cut += 7) {
        var b = try newTerm(30, 8);
        defer b.deinit();
        b.feed(all.items[0..cut]);
        b.feed(all.items[cut..]);
        try expectSameState(&ref, &b);
    }
}

/// Generates a stream of mixed garbage and plausible sequences.
fn genChunk(rand: std.Random, out: *std.ArrayList(u8)) !void {
    const gpa = testing.allocator;
    var buf: [64]u8 = undefined;
    switch (rand.uintLessThan(u8, 14)) {
        0, 1 => { // random bytes
            const n = rand.uintLessThan(usize, 32) + 1;
            rand.bytes(buf[0..n]);
            try out.appendSlice(gpa, buf[0..n]);
        },
        2 => { // random CSI
            try out.appendSlice(gpa, "\x1b[");
            if (rand.boolean()) try out.append(gpa, "?<=>"[rand.uintLessThan(usize, 4)]);
            const np = rand.uintLessThan(usize, 20);
            for (0..np) |i| {
                if (i > 0) try out.append(gpa, if (rand.uintLessThan(u8, 5) == 0) ':' else ';');
                const v = switch (rand.uintLessThan(u8, 4)) {
                    0 => rand.uintLessThan(u32, 10),
                    1 => rand.uintLessThan(u32, 300),
                    2 => rand.uintLessThan(u32, 2000),
                    else => rand.int(u32),
                };
                const s = std.fmt.bufPrint(&buf, "{d}", .{v}) catch unreachable;
                try out.appendSlice(gpa, s);
            }
            if (rand.uintLessThan(u8, 8) == 0) try out.append(gpa, 0x20 + rand.uintLessThan(u8, 16));
            try out.append(gpa, 0x40 + rand.uintLessThan(u8, 0x3F));
        },
        3 => { // SGR
            const sgrs = [_][]const u8{ "\x1b[0m", "\x1b[1;31m", "\x1b[7m", "\x1b[8m", "\x1b[38;2;10;20;30m", "\x1b[48;5;200m", "\x1b[27;28m", "\x1b[38:2::1:2:3m", "\x1b[4:3m", "\x1b[m" };
            try out.appendSlice(gpa, sgrs[rand.uintLessThan(usize, sgrs.len)]);
        },
        4 => { // modes
            const modes = [_][]const u8{ "\x1b[?1049h", "\x1b[?1049l", "\x1b[?47h", "\x1b[?1047l", "\x1b[?7l", "\x1b[?7h", "\x1b[?6h", "\x1b[?6l", "\x1b[?25l", "\x1b[?25h", "\x1b[2;5r", "\x1b[r", "\x1b7", "\x1b8", "\x1bc", "\x1b#8", "\x1b(0", "\x1b(B", "\x0e", "\x0f" };
            try out.appendSlice(gpa, modes[rand.uintLessThan(usize, modes.len)]);
        },
        5 => { // OSC / string sequences
            const heads = [_][]const u8{ "\x1b]0;", "\x1b]2;", "\x1b]8;;", "\x1bP", "\x1b_", "\x1b^", "\x1bX" };
            try out.appendSlice(gpa, heads[rand.uintLessThan(usize, heads.len)]);
            const n = rand.uintLessThan(usize, 40);
            rand.bytes(buf[0..n]);
            try out.appendSlice(gpa, buf[0..n]);
            const ends = [_][]const u8{ "\x07", "\x1b\\", "", "\x18" };
            try out.appendSlice(gpa, ends[rand.uintLessThan(usize, ends.len)]);
        },
        6, 7 => { // text including wide and combining chars
            const texts = [_][]const u8{ "hello ", "中文", "😀", "e\xcc\x81", "\t", "\r\n", "\n", "\x08", "x", "abcdefghijklmnopqrstuvwxyz", "\u{FF21}\u{FF22}", "\x1b[b" };
            try out.appendSlice(gpa, texts[rand.uintLessThan(usize, texts.len)]);
        },
        8 => { // cursor positioning
            const s = std.fmt.bufPrint(&buf, "\x1b[{d};{d}H", .{ rand.uintLessThan(u32, 70), rand.uintLessThan(u32, 140) }) catch unreachable;
            try out.appendSlice(gpa, s);
        },
        9 => { // edits
            const eds = [_][]const u8{ "\x1b[K", "\x1b[1K", "\x1b[2K", "\x1b[J", "\x1b[1J", "\x1b[2J", "\x1b[3J", "\x1b[5X", "\x1b[3@", "\x1b[2P", "\x1b[2L", "\x1b[3M", "\x1b[2S", "\x1b[2T", "\x1bM", "\x1bD", "\x1bE", "\x1b[5b", "\x1b[200b" };
            try out.appendSlice(gpa, eds[rand.uintLessThan(usize, eds.len)]);
        },
        10 => { // truncated sequence fragments
            const frags = [_][]const u8{ "\x1b", "\x1b[", "\x1b[3", "\x1b[38;2", "\x1b]", "\xe4", "\xe4\xb8", "\xf0\x9f", "\x1bP", "\x1b(" };
            try out.appendSlice(gpa, frags[rand.uintLessThan(usize, frags.len)]);
        },
        11 => { // printable ASCII run
            const n = rand.uintLessThan(usize, 60) + 1;
            for (buf[0..n]) |*c| c.* = 0x20 + rand.uintLessThan(u8, 0x5F);
            try out.appendSlice(gpa, buf[0..n]);
        },
        12 => { // high bytes
            const n = rand.uintLessThan(usize, 16) + 1;
            for (buf[0..n]) |*c| c.* = 0x80 | rand.int(u8);
            try out.appendSlice(gpa, buf[0..n]);
        },
        else => { // C0 controls
            const n = rand.uintLessThan(usize, 8) + 1;
            for (buf[0..n]) |*c| c.* = rand.uintLessThan(u8, 0x20);
            try out.appendSlice(gpa, buf[0..n]);
        },
    }
}

fn checkInvariants(t: *Terminal) !void {
    const c = t.cursor();
    try testing.expect(c.x < t.cols and c.y < t.rows);
    try testing.expect(t.cur.x < t.cols and t.cur.y < t.rows);
    try testing.expect(t.top <= t.bot and t.bot < t.rows);
    try testing.expect(t.title().len <= max_title_bytes);
    try testing.expect(std.unicode.utf8ValidateSlice(t.title()));
    for (0..t.rows) |y| {
        const row = t.line(@intCast(y));
        for (row, 0..) |cell, x| {
            switch (cell.wide) {
                .narrow => {},
                .lead => try testing.expect(x + 1 < row.len and row[x + 1].wide == .cont),
                .cont => try testing.expect(x > 0 and row[x - 1].wide == .lead),
            }
        }
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try encodeAll(t, &out);
    var d = try decodeFrame(out.items);
    d.deinit();
}

test "fuzz: random input never panics and keeps invariants" {
    var prng = std.Random.DefaultPrng.init(0x5EED_7E57);
    const rand = prng.random();
    var t = try newTerm(80, 24);
    defer t.deinit();
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(testing.allocator);
    var total: usize = 0;
    var round: usize = 0;
    while (total < 2 * 1024 * 1024) : (round += 1) {
        stream.clearRetainingCapacity();
        while (stream.items.len < 2048) try genChunk(rand, &stream);
        total += stream.items.len;
        // Feed in random-sized pieces.
        var rest = stream.items;
        while (rest.len > 0) {
            const n = @min(rest.len, rand.uintLessThan(usize, 300) + 1);
            t.feed(rest[0..n]);
            rest = rest[n..];
        }
        if (rand.uintLessThan(u8, 16) == 0) {
            const cols = if (rand.uintLessThan(u8, 20) == 0) rand.int(u16) else rand.uintLessThan(u16, 130);
            const rows = if (rand.uintLessThan(u8, 20) == 0) rand.int(u16) else rand.uintLessThan(u16, 60);
            // Keep the fuzz fast: very large sizes are exercised briefly.
            try t.resize(cols, rows);
            if (t.cols > 200 or t.rows > 100) {
                try checkInvariants(&t);
                try t.resize(rand.uintLessThan(u16, 130), rand.uintLessThan(u16, 60));
            }
        }
        if (round % 4 == 0) try checkInvariants(&t);
    }
    try checkInvariants(&t);
}

test "fuzz: split points never change the result" {
    var prng = std.Random.DefaultPrng.init(42);
    const rand = prng.random();
    for (0..40) |_| {
        var stream: std.ArrayList(u8) = .empty;
        defer stream.deinit(testing.allocator);
        while (stream.items.len < 4000) try genChunk(rand, &stream);
        var a = try newTerm(40, 12);
        defer a.deinit();
        var b = try newTerm(40, 12);
        defer b.deinit();
        a.feed(stream.items);
        var rest = stream.items;
        while (rest.len > 0) {
            const n = @min(rest.len, rand.uintLessThan(usize, 5) + 1);
            b.feed(rest[0..n]);
            rest = rest[n..];
        }
        try expectSameState(&a, &b);
    }
}

test "OSC 7501 feature detection: the probe gets the fixed reply" {
    var t = try newTerm(20, 3);
    defer t.deinit();
    var buf: [max_reply_bytes]u8 = undefined;
    try testing.expectEqualStrings("", t.takeReplies(&buf)); // nothing unasked
    // The agent's probe: BEL-terminated, then a DA1 sentinel (never answered).
    t.feed("\x1b]7501;?\x07\x1b[c");
    try testing.expectEqualStrings("\x1b]7501;?\x07", t.takeReplies(&buf));
    try testing.expectEqualStrings("", t.takeReplies(&buf)); // answered once
    // ST-terminated: the reply ends with ST too.
    t.feed("\x1b]7501;?\x1b\\");
    try testing.expectEqualStrings("\x1b]7501;?\x1b\\", t.takeReplies(&buf));
    // Split across chunks at every byte.
    const probe = "ab\x1b]7501;?\x1b\\cd";
    for (1..probe.len) |cut| {
        t.feed(probe[0..cut]);
        t.feed(probe[cut..]);
        try testing.expectEqualStrings(status_reply_st, t.takeReplies(&buf));
    }
    // Not a probe: reports, other OSCs, near misses, a probe inside a title.
    t.feed("\x1b]7501;state=working\x07\x1b]7501;??\x07\x1b]7501;? \x07\x1b]7501;\x07");
    t.feed("\x1b]0;7501;?\x07\x1b]75011;?\x07\x1b]7501?\x07 ]7501;? \x1bP7501;?\x1b\\");
    try testing.expectEqualStrings("", t.takeReplies(&buf));
    t.feed("\x1b]7501;state=working\x07\x1b]7501;?\x07"); // the probe is no state
    try testing.expectEqual(ProgramState.working, t.program_state);
    try testing.expectEqualStrings(status_reply_bel, t.takeReplies(&buf));
    // A flood is capped: at most max_pending_replies per take.
    for (0..50) |_| t.feed("\x1b]7501;?\x07");
    try testing.expectEqualStrings(status_reply_bel ++ status_reply_bel, t.takeReplies(&buf));
    try testing.expectEqual(2, max_pending_replies);
    // The reply never echoes the stream: only these fixed bytes exist.
    try testing.expectEqualStrings("\x1b]7501;?\x1b\\", status_reply_st);
    // Under ConPTY (conhost turned win32-input-mode on): the same bytes,
    // typed as key records (key down, key up), split or not.
    t.feed("\x1b[?9001h\x1b]75");
    t.feed("01;?\x07");
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(testing.allocator);
    for (status_reply_bel) |b| try want.print(testing.allocator, "\x1b[0;0;{d};1;0;1_\x1b[0;0;{d};0;0;1_", .{ b, b });
    try testing.expectEqualStrings(want.items, t.takeReplies(&buf));
    try testing.expectEqualStrings("\x1b[0;0;27;1;0;1_\x1b[0;0;27;0;0;1_\x1b[0;0;93;1;0;1_", want.items[0..45]);
    // The largest possible take fits.
    for (0..3) |_| t.feed("\x1b]7501;?\x1b\\");
    const most = t.takeReplies(&buf);
    try testing.expect(std.mem.count(u8, most, "_") == 2 * 2 * status_reply_st.len and most.len <= max_reply_bytes);
    t.feed("\x1b[?9001l\x1b]7501;?\x07");
    try testing.expectEqualStrings(status_reply_bel, t.takeReplies(&buf));
}

test "realistic ConPTY-style redraw corpus" {
    // Synthesised from what conhost emits for a TUI like the agent:
    // mode requests, title, cursor hiding, CUP-heavy partial redraws with
    // truecolor SGR, EL/ECH padding, alt screen.
    var t = try newTerm(60, 10);
    defer t.deinit();
    t.feed("\x1b[?9001h\x1b[?1004h\x1b[6n"); // no reply must be produced
    t.feed("\x1b[?25l\x1b[2J\x1b[m\x1b[H\x1b]0;Agent CLI\x07\x1b[?25h");
    t.feed("\x1b[?25l\x1b[1;1H\x1b[38;2;215;119;87m\xe2\x95\xad\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x95\xae\x1b[m\x1b[K");
    t.feed("\x1b[2;1H\x1b[38;2;215;119;87m\xe2\x94\x82\x1b[m \x1b[1mWelcome\x1b[22m\x1b[2;5H\x1b[38;2;215;119;87m\xe2\x94\x82\x1b[m");
    t.feed("\x1b[3;1H\x1b[38;2;136;136;136m> \x1b[39mtype here\x1b[10X\x1b[3;12H");
    t.feed("\x1b[?25h");
    try testing.expectEqualStrings("Agent CLI", t.title());
    try expectRow(&t, 0, "╭───╮");
    try expectRow(&t, 1, "│ We│come"); // the later CUP overwrote column 5
    try expectRow(&t, 2, "> type here");
    try expectCursor(&t, 11, 2);
    try testing.expect(t.cursor().visible);
    try testing.expectEqual(@as(u32, 0xD77757), cellAt(&t, 0, 0).fg);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try encodeAll(&t, &out);
    var d = try decodeFrame(out.items);
    defer d.deinit();
    try testing.expectEqual(@as(u32, 0xD77757), d.rows_list[0].runs[0].fg);
    try testing.expectEqualStrings("╭───╮", d.rows_list[0].runs[0].text);
    try testing.expectEqual(attr_bold, d.rows_list[1].runs[2].attrs);

    // Full-screen app.
    t.feed("\x1b[?1049h\x1b[H\x1b[48;5;236m\x1b[2Kstatus\x1b[m\x1b[10;1Hbottom\x1b[?1049l");
    try expectRow(&t, 0, "╭───╮");
}

test {
    _ = @import("vt_gfx_test.zig");
}
