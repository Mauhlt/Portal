//! The "For you" panel (the owner's mockup, screen 1): what the tab shown
//! needs from the owner, or what its agent suggests, under the
//! conversation's latest reply (the Conversation view draws it after its
//! items: convoview.View.foryou). The desk builds the cards and decides
//! what an answer does (docs/protocol.md section 3g); a device only shows
//! them and sends `i:yes <id>` / `i:no <id>`.
//!
//!   * a header, "FOR YOU", with the ↺ Recap button (`r:recap <tab>`;
//!     only where the desk's input mode allows a recap);
//!   * one row per card: a one-line summary after its kind ("waiting",
//!     "run", "go to", "answer", ...), amber for the ones that block the
//!     agent (a permission prompt, the desk's admin prompt);
//!   * SWIPE a row to answer it directly, the Yes side per the device's
//!     `swipe = left-yes | right-yes` setting (left by default), or TAP it
//!     to toggle the full card (what it waits for, the question, the
//!     command, why), which swipes the same way; a tap or Esc folds it
//!     back. The swipe itself is the Conversation view's one gesture
//!     (convoview.zig: the guard, the lean colours, spring-back and
//!     fly-off); this file only says what a row is and what its answer
//!     sends;
//!   * ←/→ answer the focused row or card like a swipe, ↑/↓ move the focus,
//!     Enter toggles;
//!   * in input mode `none` rows are shown but not swipeable;
//!   * the last answer's result in the header line.
//!
//! Allocation happens on changes only (a new list, a new width), never
//! per frame.

const std = @import("std");
const shared = @import("shared");
const foryou = shared.foryou;
const recap = shared.recap;
const tabs_wire = shared.tabs;
const theme = shared.theme;
const frame = @import("frame.zig");
const cv = @import("convoview.zig");

pub const Id = foryou.Id;
pub const Item = foryou.Item;
pub const Kind = foryou.Kind;

/// The panel's button ids (in the content view's range, convoview.ids):
/// row0 + i toggles row i, recap asks for a recap.
pub const ids = struct {
    pub const row0: u32 = cv.ids.base + 10;
    pub const recap: u32 = cv.ids.base + 30;
};

// ------------------------------------------------------------ the store

/// What a device keeps of `foryou`, `item` and `recap` messages: every
/// open tab's cards (heap: the lists are large), and the last answer's
/// text. The network thread writes it under the device's lock; the panel
/// copies the shown tab's list when it changed. The desk's window keeps
/// one too, filled in process from the tabs' own cards (`put`) and its
/// answers (`applyResult`), with no network.
pub const Store = struct {
    lists: std.ArrayList(foryou.List) = .empty,
    /// Bumped on every change.
    generation: u64 = 0,
    /// The desk's last answer to an `i:` or `r:` request, as a device
    /// shows it (foryou.Result.text / recap.Result.text); `result_ok`:
    /// it went through.
    result_buf: [96]u8 = undefined,
    result_len: usize = 0,
    result_ok: bool = false,

    pub fn deinit(s: *Store, gpa: std.mem.Allocator) void {
        s.lists.deinit(gpa);
        s.* = .{};
    }

    /// A `foryou` message: replaces that tab's cards (strict parse;
    /// malformed: ignored). False if nothing changed.
    pub fn apply(s: *Store, gpa: std.mem.Allocator, text: []const u8) bool {
        const l = gpa.create(foryou.List) catch return false;
        defer gpa.destroy(l);
        if (!foryou.parse(text, l)) return false;
        return s.put(gpa, l);
    }

    /// Tab `l.tab`'s cards are `l` now. False if they could not be kept.
    pub fn put(s: *Store, gpa: std.mem.Allocator, l: *const foryou.List) bool {
        for (s.lists.items) |*have| if (std.mem.eql(u8, &have.tab, &l.tab)) {
            have.* = l.*;
            s.generation +%= 1;
            return true;
        };
        if (s.lists.items.len >= tabs_wire.max_tabs) _ = s.lists.orderedRemove(0);
        s.lists.append(gpa, l.*) catch return false;
        s.generation +%= 1;
        return true;
    }

    /// An `item` or `recap` answer: its text for the panel.
    pub fn applyResult(s: *Store, text: []const u8) bool {
        const t: []const u8, const ok = if (foryou.parseResult(text)) |a|
            .{ a.result.text(), a.result.ok() }
        else if (recap.parseResult(text)) |a|
            .{ a.result.text(), a.result == .ok }
        else
            return false;
        @memcpy(s.result_buf[0..t.len], t);
        s.result_len = t.len;
        s.result_ok = ok;
        s.generation +%= 1;
        return true;
    }

    /// Only the tabs still open keep their cards (a tab gone from `tabs`
    /// takes them with it).
    pub fn retain(s: *Store, open: []const tabs_wire.Entry) void {
        var i: usize = 0;
        while (i < s.lists.items.len) {
            var keep = false;
            for (open) |e| keep = keep or std.mem.eql(u8, &e.id, &s.lists.items[i].tab);
            if (keep) {
                i += 1;
            } else {
                _ = s.lists.orderedRemove(i);
                s.generation +%= 1;
            }
        }
    }

    pub fn get(s: *const Store, tab: Id) ?*const foryou.List {
        for (s.lists.items) |*l| if (std.mem.eql(u8, &l.tab, &tab)) return l;
        return null;
    }

    pub fn result(s: *const Store) []const u8 {
        return s.result_buf[0..s.result_len];
    }
};

test "store: put replaces a tab's cards or adds them; the desk's own feed" {
    const gpa = std.testing.allocator;
    var s: Store = .{};
    defer s.deinit(gpa);
    const a: Id = @splat(1);
    const b: Id = @splat(2);
    var l = testList(a);
    const g0 = s.generation;
    try std.testing.expect(s.put(gpa, &l));
    try std.testing.expect(s.generation != g0);
    try std.testing.expectEqual(l.len, s.get(a).?.len);
    var l2: foryou.List = .{ .tab = a };
    try std.testing.expect(s.put(gpa, &l2));
    try std.testing.expectEqual(@as(usize, 0), s.get(a).?.len);
    try std.testing.expectEqual(@as(usize, 1), s.lists.items.len);
    var lb: foryou.List = .{ .tab = b };
    try std.testing.expect(s.put(gpa, &lb));
    try std.testing.expectEqual(@as(usize, 2), s.lists.items.len);
    // The desk's answers' texts land as a device's do.
    var w_buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&w_buf);
    try foryou.writeResult(&w, .yes, .sent, null);
    try std.testing.expect(s.applyResult(w.buffered()));
    try std.testing.expect(s.result_ok);
}

// ------------------------------------------------------------ the panel

/// How the panel sends its frames (the device's interactive WebSocket).
pub const Sender = struct {
    ctx: *anyopaque,
    send: *const fn (ctx: *anyopaque, frame: []const u8) bool,
};

/// What a kind is called on its row, and the full card's head.
pub fn label(k: Kind) []const u8 {
    return switch (k) {
        .waiting_permission => "waiting",
        .needs_desk => "desk",
        .long_running => "long run",
        .answer => "answer",
        .suggest_run => "run",
        .suggest_goto => "go to",
    };
}

fn head(k: Kind) []const u8 {
    return switch (k) {
        .waiting_permission => "Claude is waiting \u{00B7} permission",
        .needs_desk => "Claude needs the desk",
        .long_running => "A long run",
        .answer => "Claude asked you",
        .suggest_run, .suggest_goto => "Suggested \u{00B7} ask Claude to do it",
    };
}

fn question(it: *const Item) []const u8 {
    return switch (it.kind) {
        .suggest_run => "Ask Claude to run this?",
        .suggest_goto => "Ask Claude to switch projects?",
        else => it.summary(),
    };
}

/// The why line when the desk sent none.
fn defaultWhy(k: Kind) []const u8 {
    return switch (k) {
        .waiting_permission => "Yes lets Claude go ahead; No denies it.",
        .answer => "Your answer goes straight to Claude.",
        // What Yes does, nothing more: whether the agent then asks
        // before acting depends on the tab's permission mode.
        .suggest_run => "Yes asks Claude to run exactly this command; No dismisses it.",
        .suggest_goto => "Yes asks Claude to switch projects; No dismisses it.",
        .needs_desk, .long_running => "Either way dismisses this card.",
    };
}

/// Amber: the agent is blocked on it.
pub fn amber(k: Kind) bool {
    return k == .waiting_permission or k == .needs_desk;
}

/// Swiping answers (input modes other than `none`).
pub fn swipeableIn(mode: ?[]const u8) bool {
    const m = mode orelse return false;
    return !std.mem.eql(u8, m, "none");
}

const Row = struct {
    lines: std.ArrayList(cv.Line) = .empty,
    boxes: std.ArrayList(cv.Box) = .empty,
    /// Top and height in the panel; the row's own coordinates start at
    /// (pad, y).
    y: f32 = 0,
    h: f32 = 0,
    w: f32 = 0,
    open: bool = false,

    fn deinit(r: *Row, gpa: std.mem.Allocator) void {
        r.lines.deinit(gpa);
        r.boxes.deinit(gpa);
    }
};

pub const Panel = struct {
    gpa: std.mem.Allocator,
    /// The shown tab and its cards (a copy).
    tab: ?Id = null,
    list: foryou.List = .{},
    src_gen: u64 = std.math.maxInt(u64),
    /// The desk's input mode for devices (hello.input), and whether the
    /// tab shown takes input at all (a sub-tab doesn't).
    mode_buf: [16]u8 = undefined,
    mode_len: usize = 0,
    input: bool = false,
    sender: ?Sender = null,
    /// Which way a swipe says Yes (set by the view from the device setting).
    yes_side: cv.YesSide = .left,
    /// The card shown in full (tap to toggle), and the row the keyboard is
    /// on (shown once a key moved it).
    open: ?Id = null,
    focus: usize = 0,
    /// The card the focus is on (it follows the card when the list changes).
    focus_id: ?Id = null,
    focus_shown: bool = false,
    /// A card answered here: its controls go until the desk updates it.
    sent: ?Id = null,
    /// When each card was first on screen (the swipe guard), by id.
    seen_ids: [foryou.max_items]Id = undefined,
    seen_ms: [foryou.max_items]i64 = undefined,
    n_seen: usize = 0,
    /// The last result's text (copied).
    note_buf: [96]u8 = undefined,
    note_len: usize = 0,
    note_ok: bool = false,

    // Layout (panel coordinates: x from the column's left, y from its top).
    rows: [foryou.max_items]Row = @splat(.{}),
    chrome: Row = .{},
    height: f32 = 0,
    /// The panel's top in the conversation's content (set by the view).
    y: f32 = 0,
    recap_box: ?frame.Rect = null,
    laid: bool = false,
    laid_w: f32 = -1,
    laid_fonts: [3]u32 = .{ 0, 0, 0 },

    pub fn init(gpa: std.mem.Allocator) Panel {
        return .{ .gpa = gpa };
    }

    pub fn deinit(p: *Panel) void {
        for (&p.rows) |*r| r.deinit(p.gpa);
        p.chrome.deinit(p.gpa);
    }

    pub fn mode(p: *const Panel) ?[]const u8 {
        return if (p.mode_len == 0) null else p.mode_buf[0..p.mode_len];
    }

    /// Takes over the shown tab's cards and the mode (call under the lock
    /// that guards `store`). `input`: the view shows the tab's own
    /// conversation (not a read-only sub-tab).
    pub fn sync(p: *Panel, store: *const Store, tab: ?Id, mode_name: ?[]const u8, input: bool) void {
        const m = mode_name orelse "";
        const same_mode = std.mem.eql(u8, m, p.mode_buf[0..p.mode_len]) and input == p.input;
        const same_tab = if (p.tab) |a| (if (tab) |b| std.mem.eql(u8, &a, &b) else false) else tab == null;
        if (same_mode and same_tab and store.generation == p.src_gen) return;
        p.src_gen = store.generation;
        const n = @min(m.len, p.mode_buf.len);
        @memcpy(p.mode_buf[0..n], m[0..n]);
        p.mode_len = n;
        p.input = input;
        if (!same_tab) {
            p.open = null;
            p.focus = 0;
            p.focus_id = null;
            p.focus_shown = false;
            p.sent = null;
            p.n_seen = 0;
            p.note_len = 0;
        }
        p.tab = tab;
        p.list = if (tab) |t| (if (store.get(t)) |l| l.* else .{ .tab = t }) else .{};
        if (p.open) |o| if (p.list.find(o) == null) {
            p.open = null;
        };
        if (p.sent) |s| if (p.list.find(s) == null) {
            p.sent = null;
        };
        // The focus follows its card, not its place: a card gone (or
        // another in its place) leaves no row focused, so ←/→ can't
        // answer a card the owner never put the focus on.
        if (p.focus_id) |fid| {
            if (p.list.find(fid)) |i| {
                p.focus = i;
            } else {
                p.focus_id = null;
                p.focus = 0;
                p.focus_shown = false;
            }
        }
        if (p.focus >= p.list.len) p.focus = if (p.list.len == 0) 0 else p.list.len - 1;
        if (same_tab and store.result_len > 0) {
            @memcpy(p.note_buf[0..store.result_len], store.result());
            p.note_len = store.result_len;
            p.note_ok = store.result_ok;
        }
        p.laid = false;
    }

    /// Recap is offered (instruct or text mode, the tab's own view).
    pub fn recapOffered(p: *const Panel) bool {
        const m = p.mode() orelse return false;
        return p.input and p.tab != null and (std.mem.eql(u8, m, "instruct") or std.mem.eql(u8, m, "text"));
    }

    /// The panel is drawn at all: it has cards, or offers a recap.
    pub fn visible(p: *const Panel) bool {
        return p.tab != null and (p.list.len > 0 or p.recapOffered());
    }

    /// Rows answer with a swipe (or ←/→).
    pub fn swipeable(p: *const Panel) bool {
        return p.input and swipeableIn(p.mode());
    }

    /// The tab waits on a permission prompt: its card answers it, so the
    /// Conversation view hides its own permission card (one approval UI).
    pub fn hasWaitingPermission(p: *const Panel) bool {
        for (p.list.slice()) |*it| if (it.kind == .waiting_permission) return true;
        return false;
    }

    /// Row `i` can be swiped now (not answered here yet).
    pub fn rowSwipeable(p: *const Panel, id: Id) bool {
        if (!p.swipeable()) return false;
        if (p.sent) |s| if (std.mem.eql(u8, &s, &id)) return false;
        return p.list.find(id) != null;
    }

    pub fn index(p: *const Panel, id: Id) ?usize {
        return p.list.find(id);
    }

    /// When card `id` was first on screen, if it was.
    pub fn appeared(p: *const Panel, id: Id) ?i64 {
        for (p.seen_ids[0..p.n_seen], 0..) |s, i| if (std.mem.eql(u8, &s, &id)) return p.seen_ms[i];
        return null;
    }

    /// The last frame reached the screen at `now`: cards not seen before
    /// start their swipe guard there.
    pub fn presented(p: *Panel, now_ms: i64) void {
        if (!p.visible()) return;
        var ids_now: [foryou.max_items]Id = undefined;
        var ms_now: [foryou.max_items]i64 = undefined;
        for (p.list.slice(), 0..) |*it, i| {
            ids_now[i] = it.id;
            ms_now[i] = p.appeared(it.id) orelse now_ms;
        }
        @memcpy(p.seen_ids[0..p.list.len], ids_now[0..p.list.len]);
        @memcpy(p.seen_ms[0..p.list.len], ms_now[0..p.list.len]);
        p.n_seen = p.list.len;
    }

    /// The frame answering card `id` with `op` ("i:yes <hex>"), sent; or,
    /// when the desk's input mode does not allow it, the refusal shown
    /// and false (the row springs back).
    pub fn answer(p: *Panel, id: Id, side: cv.Side) bool {
        const i = p.list.find(id) orelse return false;
        const op: foryou.Op = if (side == .yes) .yes else .no;
        if (!p.list.items[i].kind.effect(op).allowedIn(p.mode() orelse "none")) {
            p.setNote(foryou.Result.refused.text(), false);
            return false;
        }
        var b: [6 + tabs_wire.hex_len]u8 = undefined;
        const f = foryou.requestFrame(op, id, &b);
        const s = p.sender orelse return false;
        if (!s.send(s.ctx, f)) return false;
        p.sent = id;
        if (p.open) |o| if (std.mem.eql(u8, &o, &id)) {
            p.open = null;
        };
        p.laid = false;
        return true;
    }

    fn setNote(p: *Panel, t: []const u8, ok: bool) void {
        const n = @min(t.len, p.note_buf.len);
        @memcpy(p.note_buf[0..n], t[0..n]);
        p.note_len = n;
        p.note_ok = ok;
        p.laid = false;
    }

    /// Row `i` between its summary and its full card.
    pub fn toggle(p: *Panel, i: usize) void {
        if (i >= p.list.len) return;
        const id = p.list.items[i].id;
        p.open = if (p.open) |o| (if (std.mem.eql(u8, &o, &id)) null else id) else id;
        p.setFocus(i);
        p.laid = false;
    }

    /// Esc: the full card folds back. True if one was open.
    pub fn fold(p: *Panel) bool {
        if (p.open == null) return false;
        p.open = null;
        p.laid = false;
        return true;
    }

    /// ↑ / ↓ (`delta` -1 / +1): the focus moves. True if it did.
    pub fn moveFocus(p: *Panel, delta: i32) bool {
        if (p.list.len == 0) return false;
        const at: i64 = @intCast(p.focus);
        const next = std.math.clamp(at + delta, 0, @as(i64, @intCast(p.list.len - 1)));
        const moved = next != at or !p.focus_shown;
        p.setFocus(@intCast(next));
        p.focus_shown = true;
        p.laid = false;
        return moved;
    }

    /// The focused card's id: the card ↑/↓, Enter or a tap put the focus
    /// on, while it is still listed (null: none).
    pub fn focused(p: *const Panel) ?Id {
        const fid = p.focus_id orelse return null;
        return if (p.list.find(fid) != null) fid else null;
    }

    fn setFocus(p: *Panel, i: usize) void {
        p.focus = i;
        p.focus_id = if (i < p.list.len) p.list.items[i].id else null;
    }

    /// One of the panel's buttons (a tap on a row toggles it; Recap asks
    /// the desk). True if it was the panel's.
    pub fn button(p: *Panel, id: u32) bool {
        if (id == ids.recap) {
            if (!p.recapOffered()) return true;
            const s = p.sender orelse return true;
            const f = recap.requestFrame(p.tab.?);
            _ = s.send(s.ctx, &f);
            return true;
        }
        if (id >= ids.row0 and id < ids.row0 + foryou.max_items) {
            p.toggle(id - ids.row0);
            return true;
        }
        return false;
    }

    // -------------------------------------------------------- layout

    /// Lays the panel out for a column `colw` wide (what changed only);
    /// returns its height.
    pub fn layout(p: *Panel, f: cv.Fonts, colw: f32) f32 {
        const key: [3]u32 = .{ f.body.cell_h, f.small.cell_h, f.act.cell_h };
        if (p.laid and p.laid_w == colw and std.mem.eql(u32, &key, &p.laid_fonts)) return p.height;
        p.laid = true;
        p.laid_w = colw;
        p.laid_fonts = key;
        const s = f.s;
        const pad = @round(10 * s);
        const gap = @round(6 * s);
        const slh = @round(@as(f32, @floatFromInt(f.small.cell_h)) * 1.3);
        const ch = &p.chrome;
        ch.lines.clearRetainingCapacity();
        ch.boxes.clearRetainingCapacity();
        // The panel: card colour, a quiet outline (sized at the end).
        ch.boxes.append(p.gpa, .{ .x = 0, .y = 0, .w = colw, .h = 0, .color = theme.ui.card, .kind = .card }) catch {};
        ch.boxes.append(p.gpa, .{ .x = 0, .y = 0, .w = colw, .h = 0, .color = theme.ui.pill_bg, .kind = .outline }) catch {};
        var y = pad;
        ch.lines.append(p.gpa, .{ .str = "FOR YOU", .x = pad, .y = y, .font = .small, .color = theme.ui.question_head, .bold = true }) catch {};
        p.recap_box = null;
        var head_h = slh;
        if (p.recapOffered()) {
            const lbl = "\u{21BA} Recap";
            const cw: f32 = @floatFromInt(f.small.cell_w);
            const bw = frame.textWidth(f.small, lbl) + 3 * cw;
            const bh = @round(slh * 1.6);
            const bx = colw - pad - bw;
            ch.boxes.append(p.gpa, .{ .x = bx, .y = y - @round((bh - slh) / 2), .w = bw, .h = bh, .color = theme.ui.button }) catch {};
            ch.lines.append(p.gpa, .{ .str = lbl, .x = bx + @round((bw - frame.textWidth(f.small, lbl)) / 2), .y = y + @round((slh - @as(f32, @floatFromInt(f.small.cell_h))) / 2), .font = .small, .color = theme.ui.question_head, .bold = true }) catch {};
            p.recap_box = .{ .x = bx, .y = y - @round((bh - slh) / 2), .w = bw, .h = bh };
            head_h = @max(head_h, bh);
        }
        y += head_h + gap;
        if (p.note_len > 0) {
            ch.lines.append(p.gpa, .{ .str = frame.clipText(f.small, p.note_buf[0..p.note_len], colw - 2 * pad, false), .x = pad, .y = y, .font = .small, .color = if (p.note_ok) theme.ui.good else theme.ui.dim }) catch {};
            y += slh + gap;
        }
        const rw = colw - 2 * pad;
        for (p.list.slice(), 0..) |*it, i| {
            const r = &p.rows[i];
            r.y = y;
            r.w = rw;
            r.open = if (p.open) |o| std.mem.eql(u8, &o, &it.id) else false;
            if (r.open) p.layoutCard(r, it, f, rw) else p.layoutRow(r, it, i, f, rw);
            y += r.h + gap;
        }
        const note: []const u8 = if (p.list.len == 0)
            "Nothing needs you right now."
        else if (!p.swipeable())
            "View only: answer these at the desk."
        else
            "Swipe a row to answer, or tap it to toggle the details. Amber = Claude is waiting right now.";
        y = wrapInto(p.gpa, &ch.lines, f, note, pad, y, rw, .small, theme.ui.dim, false);
        y += pad;
        ch.boxes.items[0].h = y;
        ch.boxes.items[1].h = y;
        p.height = y;
        return y;
    }

    fn layoutRow(p: *Panel, r: *Row, it: *const Item, i: usize, f: cv.Fonts, w: f32) void {
        r.lines.clearRetainingCapacity();
        r.boxes.clearRetainingCapacity();
        const s = f.s;
        const rpad = @round(9 * s);
        const h1 = @max(frame.answerButtonHeight(f.act), @round(@as(f32, @floatFromInt(f.body.cell_h)) * 1.3) + 2 * @round(7 * s));
        const warm = amber(it.kind);
        const focus = p.focus_shown and p.focus == i;
        const sc: f32 = @floatFromInt(f.small.cell_w);
        const lbl_w = @max(frame.textWidth(f.small, label(it.kind)), 8 * sc);
        const chev = "\u{203A}";
        const chev_w = frame.textWidth(f.body, chev);
        const tx = rpad + lbl_w + sc;
        const text_x1 = w - rpad - chev_w - sc;
        const sent = if (p.sent) |sn| std.mem.eql(u8, &sn, &it.id) else false;
        const text: []const u8 = if (sent) "Sending\u{2026}" else it.summary();
        const code = it.kind == .suggest_run and !sent;
        // A suggested command is shown whole, wrapped (a swipe sends all
        // of it); any other summary is one line, cut at the chevron.
        var h = h1;
        var by = @round((h1 - @as(f32, @floatFromInt(f.body.cell_h))) / 2);
        if (code) {
            const end = codeInto(p.gpa, &r.lines, f, text, tx, by, @max(1, text_x1 - tx));
            h = @max(h1, end + by - @round(2 * s));
        } else {
            r.lines.append(p.gpa, .{ .str = text, .x = tx, .y = by, .color = theme.ui.text, .x1 = text_x1 }) catch {};
        }
        if (h != h1) by = @round((h - @as(f32, @floatFromInt(f.body.cell_h))) / 2);
        const sy = @round((h - @as(f32, @floatFromInt(f.small.cell_h))) / 2);
        r.lines.append(p.gpa, .{ .str = label(it.kind), .x = rpad, .y = sy, .font = .small, .color = if (warm) theme.ui.attention else theme.ui.dim, .bold = warm }) catch {};
        r.lines.append(p.gpa, .{ .str = chev, .x = w - rpad - chev_w, .y = by, .color = theme.ui.dim }) catch {};
        r.boxes.append(p.gpa, .{ .x = 0, .y = 0, .w = w, .h = h, .color = theme.ui.panel, .kind = .card }) catch {};
        r.boxes.append(p.gpa, .{ .x = 0, .y = 0, .w = w, .h = h, .color = if (focus) theme.ui.focus else if (warm) theme.ui.attention else theme.ui.pill_bg, .kind = .outline }) catch {};
        r.h = h;
    }

    fn layoutCard(p: *Panel, r: *Row, it: *const Item, f: cv.Fonts, w: f32) void {
        r.lines.clearRetainingCapacity();
        r.boxes.clearRetainingCapacity();
        const s = f.s;
        const q = @round(12 * s);
        const slh = @round(@as(f32, @floatFromInt(f.small.cell_h)) * 1.3);
        const inner = @max(1, w - 2 * q);
        r.boxes.append(p.gpa, .{ .x = 0, .y = 0, .w = w, .h = 0, .color = theme.ui.card, .kind = .card }) catch {};
        r.boxes.append(p.gpa, .{ .x = 0, .y = 0, .w = w, .h = 0, .color = if (amber(it.kind)) theme.ui.attention else theme.ui.question, .kind = .outline }) catch {};
        var y = q;
        r.lines.append(p.gpa, .{ .str = frame.clipText(f.small, head(it.kind), inner, false), .x = q, .y = y, .font = .small, .color = if (amber(it.kind)) theme.ui.attention else theme.ui.question_head, .bold = true }) catch {};
        y += slh + @round(4 * s);
        y = wrapInto(p.gpa, &r.lines, f, question(it), q, y, inner, .body, theme.ui.text, false);
        const shown_cmd: []const u8 = if (it.cmd().len > 0) it.cmd() else if (it.kind == .suggest_goto) it.project() else "";
        if (shown_cmd.len > 0) {
            const cp = @round(6 * s);
            y += @round(6 * s);
            const top = y;
            const box_i = r.boxes.items.len;
            r.boxes.append(p.gpa, .{ .x = q, .y = top, .w = inner, .h = 0, .color = cv.colors.code_bg }) catch {};
            y = codeInto(p.gpa, &r.lines, f, shown_cmd, q + cp, top + cp, inner - 2 * cp) + cp;
            if (box_i < r.boxes.items.len) r.boxes.items[box_i].h = y - top;
        }
        y += @round(6 * s);
        y = wrapInto(p.gpa, &r.lines, f, if (it.why().len > 0) it.why() else defaultWhy(it.kind), q, y, inner, .small, theme.ui.dim, false);
        y += @round(6 * s);
        const keys: []const u8 = if (!p.swipeable())
            "View only \u{00B7} tap to fold back"
        else if (it.kind.effect(.yes) == .dismiss and it.kind.effect(.no) == .dismiss)
            "Swipe either way to dismiss \u{00B7} tap to fold back"
        else if (p.yes_side == .left)
            "Swipe left = Yes \u{00B7} right = No \u{00B7} tap to fold back"
        else
            "Swipe right = Yes \u{00B7} left = No \u{00B7} tap to fold back";
        r.lines.append(p.gpa, .{ .str = frame.clipText(f.small, keys, inner, false), .x = q, .y = y, .font = .small, .color = theme.ui.dim }) catch {};
        y += slh + q;
        r.boxes.items[0].h = y;
        r.boxes.items[1].h = y;
        r.h = y;
    }

    /// Row `i`'s rectangle in the panel.
    pub fn rowRect(p: *const Panel, i: usize, f: cv.Fonts) frame.Rect {
        const pad = @round(10 * f.s);
        const r = &p.rows[i];
        return .{ .x = pad, .y = r.y, .w = r.w, .h = r.h };
    }

    /// The card under panel point (x, y), if any.
    pub fn rowAt(p: *const Panel, x: f32, y: f32, f: cv.Fonts) ?Id {
        for (p.list.slice(), 0..) |*it, i| if (p.rowRect(i, f).contains(x, y)) return it.id;
        return null;
    }

    pub fn rowParts(p: *const Panel, i: usize) cv.Parts {
        const r = &p.rows[i];
        return .{ .boxes = r.boxes.items, .lines = r.lines.items, .thick = if (r.open) 2 else 1 };
    }

    /// Paints the panel at (ox, oy) (the panel's top left in the window);
    /// the grabbed row (if any) is painted by the view with its transform
    /// (`skip`).
    pub fn paint(p: *Panel, pt: *frame.Painter, f: cv.Fonts, ox: f32, oy: f32, skip: ?usize) void {
        cv.paintParts(pt, f, .{ .boxes = p.chrome.boxes.items, .lines = p.chrome.lines.items }, ox, oy, .{});
        if (p.recap_box) |b| pt.tapButton(ox + b.x, oy + b.y, b.w, b.h, ids.recap);
        for (p.list.slice(), 0..) |_, i| {
            const rr = p.rowRect(i, f);
            if (skip != i) cv.paintParts(pt, f, p.rowParts(i), ox + rr.x, oy + rr.y, .{});
            pt.tapButton(ox + rr.x, oy + rr.y, rr.w, rr.h, ids.row0 + @as(u32, @intCast(i)));
        }
    }
};

/// Word-wrapped text into `lines` at (x, y) in `width`; returns the y
/// after it.
fn wrapInto(gpa: std.mem.Allocator, lines: *std.ArrayList(cv.Line), f: cv.Fonts, text: []const u8, x: f32, y0: f32, width: f32, sel: cv.FontSel, color: theme.Rgb, bold: bool) f32 {
    const m = if (sel == .small) f.small else f.body;
    const lh = @round(@as(f32, @floatFromInt(m.cell_h)) * 1.3);
    var y = y0;
    var rest = std.mem.trim(u8, text, " ");
    while (rest.len > 0) {
        const n = @max(1, frame.wrapLen(m.cell_w, rest, width));
        lines.append(gpa, .{ .str = std.mem.trimEnd(u8, rest[0..n], " "), .x = x, .y = y, .font = sel, .color = color, .bold = bold }) catch {};
        y += lh;
        rest = std.mem.trimStart(u8, rest[n..], " ");
    }
    return y;
}

/// A command broken anywhere (whole UTF-8 sequences), monospaced colour,
/// at (x, y) in `width`; its own line breaks kept. Returns the y after it.
fn codeInto(gpa: std.mem.Allocator, lines: *std.ArrayList(cv.Line), f: cv.Fonts, text: []const u8, x: f32, y0: f32, width: f32) f32 {
    const m = f.body;
    const lh = @as(f32, @floatFromInt(m.cell_h)) + @round(2 * f.s);
    const per: usize = @max(1, @as(usize, @intFromFloat(@max(1, width / @as(f32, @floatFromInt(@max(m.cell_w, 1)))))));
    var y = y0;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line_raw| {
        var rest = line_raw;
        if (rest.len == 0) y += lh;
        while (rest.len > 0) {
            var n = @min(rest.len, per);
            while (n < rest.len and n > 1 and (rest[n] & 0xC0) == 0x80) n -= 1;
            lines.append(gpa, .{ .str = rest[0..n], .x = x, .y = y, .color = cv.colors.code_fg }) catch {};
            y += lh;
            rest = rest[n..];
        }
    }
    return y;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

pub const test_fonts = struct {
    const Metrics = frame.Metrics;
    const body: Metrics = .{ .em = 14, .cell_w = 8, .cell_h = 16, .baseline = 12, .underline_y = 14, .stroke = 1 };
    const small: Metrics = .{ .em = 12, .cell_w = 7, .cell_h = 14, .baseline = 11, .underline_y = 12, .stroke = 1 };
    const act: Metrics = .{ .em = 16, .cell_w = 9, .cell_h = 18, .baseline = 14, .underline_y = 16, .stroke = 1 };
    pub const fonts: cv.Fonts = .{ .body = body, .small = small, .act = act, .s = 1 };
};

pub fn testList(tab: Id) foryou.List {
    var l: foryou.List = .{ .tab = tab };
    l.items[0] = .{ .id = @splat(1), .kind = .waiting_permission };
    l.items[0].setSummary("Claude wants to run a command. Allow it?");
    l.items[1] = .{ .id = @splat(2), .kind = .suggest_run };
    l.items[1].setSummary("zig build run");
    l.items[1].setCmd("zig build run");
    l.items[1].setWhy("Claude suggested trying the build afterwards.");
    l.items[2] = .{ .id = @splat(3), .kind = .answer };
    l.items[2].setSummary("Keep UDP 51820?");
    l.len = 3;
    return l;
}

fn storeWith(gpa: std.mem.Allocator, s: *Store, l: *const foryou.List) !void {
    var buf: [foryou.max_message]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try foryou.write(&w, l.tab, l.slice());
    try testing.expect(s.apply(gpa, w.buffered()));
}

test "store: per tab, replaced whole, malformed ignored, results, closed tabs drop theirs" {
    const gpa = testing.allocator;
    var s: Store = .{};
    defer s.deinit(gpa);
    const a = testList(@splat(0xa));
    try storeWith(gpa, &s, &a);
    var b = testList(@splat(0xb));
    b.len = 1;
    try storeWith(gpa, &s, &b);
    try testing.expectEqual(@as(usize, 3), s.get(@splat(0xa)).?.len);
    try testing.expectEqual(@as(usize, 1), s.get(@splat(0xb)).?.len);
    b.len = 0;
    try storeWith(gpa, &s, &b);
    try testing.expectEqual(@as(usize, 0), s.get(@splat(0xb)).?.len);
    try testing.expect(!s.apply(gpa, "{\"t\":\"foryou\",\"id\":\"x\",\"items\":[]}"));
    try testing.expect(s.applyResult("{\"t\":\"item\",\"op\":\"yes\",\"result\":\"stale\"}"));
    try testing.expectEqualStrings(foryou.Result.stale.text(), s.result());
    try testing.expect(s.applyResult("{\"t\":\"recap\",\"op\":\"recap\",\"result\":\"ok\"}"));
    try testing.expect(s.result_ok);
    var open: [1]tabs_wire.Entry = .{.{ .id = @splat(0xb) }};
    s.retain(&open);
    try testing.expect(s.get(@splat(0xa)) == null);
    try testing.expect(s.get(@splat(0xb)) != null);
}

pub const Sent = struct {
    frames: [8][64]u8 = undefined,
    lens: [8]usize = @splat(0),
    n: usize = 0,
    fn send(ctx: *anyopaque, f: []const u8) bool {
        const t: *Sent = @ptrCast(@alignCast(ctx));
        @memcpy(t.frames[t.n][0..f.len], f);
        t.lens[t.n] = f.len;
        t.n += 1;
        return true;
    }
    pub fn last(t: *const Sent) []const u8 {
        return t.frames[t.n - 1][0..t.lens[t.n - 1]];
    }
};

test "panel: rows, toggle to the card and back, answers by mode, recap" {
    const gpa = testing.allocator;
    var s: Store = .{};
    defer s.deinit(gpa);
    const tab: Id = @splat(0xa);
    const l = testList(tab);
    try storeWith(gpa, &s, &l);
    var p = Panel.init(gpa);
    defer p.deinit();
    var sent: Sent = .{};
    p.sender = .{ .ctx = &sent, .send = Sent.send };
    p.sync(&s, tab, "keys", true);
    try testing.expect(p.visible() and p.swipeable() and !p.recapOffered());
    try testing.expect(p.hasWaitingPermission());
    const f = test_fonts.fonts;
    const h1 = p.layout(f, 400);
    // Tap row 1: its full card (taller); again: folded.
    try testing.expect(p.button(ids.row0 + 1));
    const h2 = p.layout(f, 400);
    try testing.expect(h2 > h1);
    try testing.expect(p.rows[1].open);
    var has_cmd = false;
    for (p.rows[1].lines.items) |ln| has_cmd = has_cmd or std.mem.eql(u8, ln.str, "zig build run");
    try testing.expect(has_cmd);
    try testing.expect(p.button(ids.row0 + 1));
    try testing.expectEqual(h1, p.layout(f, 400));
    _ = p.button(ids.row0 + 1);
    try testing.expect(p.fold());
    try testing.expect(!p.fold());
    // keys mode: a run suggestion's Yes is refused here (shown), No dismisses.
    try testing.expect(!p.answer(@splat(2), .yes));
    try testing.expectEqualStrings(foryou.Result.refused.text(), p.note_buf[0..p.note_len]);
    try testing.expect(p.answer(@splat(2), .no));
    try testing.expectEqualStrings("i:no 02020202020202020202020202020202", sent.last());
    try testing.expect(!p.rowSwipeable(@splat(2))); // answered here
    try testing.expect(p.answer(@splat(1), .yes));
    try testing.expectEqualStrings("i:yes 01010101010101010101010101010101", sent.last());
    // instruct: Recap offered and sent for the tab.
    p.sync(&s, tab, "instruct", true);
    _ = p.layout(f, 400);
    try testing.expect(p.recapOffered() and p.recap_box != null);
    try testing.expect(p.button(ids.recap));
    try testing.expectEqualStrings("r:recap 0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", sent.last());
    // none: shown, not swipeable; a sub-tab: no input either.
    p.sync(&s, tab, "none", true);
    try testing.expect(p.visible() and !p.swipeable() and !p.rowSwipeable(@splat(3)));
    p.sync(&s, tab, "text", false);
    try testing.expect(!p.swipeable() and !p.recapOffered());
}

test "panel: focus keys, the swipe guard's first sight, rows by point" {
    const gpa = testing.allocator;
    var s: Store = .{};
    defer s.deinit(gpa);
    const tab: Id = @splat(0xa);
    const l = testList(tab);
    try storeWith(gpa, &s, &l);
    var p = Panel.init(gpa);
    defer p.deinit();
    p.sync(&s, tab, "instruct", true);
    const f = test_fonts.fonts;
    _ = p.layout(f, 400);
    try testing.expect(p.appeared(@splat(1)) == null);
    p.presented(500);
    p.presented(900);
    try testing.expectEqual(@as(?i64, 500), p.appeared(@splat(1)));
    try testing.expect(p.moveFocus(1)); // shows the focus on row 0..1
    try testing.expectEqual(@as(usize, 1), p.focus);
    _ = p.moveFocus(1);
    try testing.expect(!p.moveFocus(1)); // at the end
    try testing.expectEqual(@as(Id, @splat(3)), p.focused().?);
    const r = p.rowRect(0, f);
    try testing.expectEqual(@as(Id, @splat(1)), p.rowAt(r.x + 5, r.y + 5, f).?);
    try testing.expect(p.rowAt(r.x + 5, r.y - 2, f) == null);
    // Another tab: the open card and the focus start over.
    p.toggle(0);
    p.sync(&s, @splat(0xb), "instruct", true);
    try testing.expect(p.open == null and p.visible() and p.list.len == 0);
}

// ------------------------------------------- with the Conversation view

const convo = @import("convo.zig");
const convo_wire = shared.convo;

pub const Clock = struct {
    t: i64 = 0,
    fn now(ctx: ?*anyopaque) i64 {
        const c: *Clock = @ptrCast(@alignCast(ctx.?));
        return c.t;
    }
};

pub const Rig = struct {
    c: convo.Conversation = .{},
    s: Store = .{},
    v: cv.View,
    p: Panel,
    sent: Sent = .{},
    clk: Clock = .{},

    pub fn init(r: *Rig, gpa: std.mem.Allocator, mode_name: []const u8, items: []const convo_wire.Item) !void {
        r.* = .{ .v = cv.View.init(gpa), .p = Panel.init(gpa) };
        try r.c.apply(gpa, .{ .snapshot = true, .id = @splat(0xa), .on = true, .items = @constCast(items) });
        const l = testList(@splat(0xa));
        try storeWith(gpa, &r.s, &l);
        r.p.sender = .{ .ctx = &r.sent, .send = Sent.send };
        r.p.sync(&r.s, @splat(0xa), mode_name, true);
        r.v.clock = .{ .ctx = &r.clk, .now = Clock.now };
        r.v.foryou = &r.p;
        r.v.sync(&r.c);
        r.v.prepare(.{ .w = 428, .h = 2000 }, test_fonts.fonts);
        r.v.shown_q = r.v.newestOpenQuestion();
        r.clk.t = 1000;
        r.v.presented(r.clk.t);
    }

    pub fn deinit(r: *Rig, gpa: std.mem.Allocator) void {
        r.v.deinit();
        r.p.deinit();
        r.s.deinit(gpa);
        r.c.deinit(gpa);
    }

    /// Row `i`'s centre in window pixels.
    fn rowCentre(r: *Rig, i: usize) [2]f32 {
        const rr = r.p.rowRect(i, test_fonts.fonts);
        return .{ r.v.col_x + rr.x + rr.w / 2, r.v.rect.y + r.p.y - r.v.top + rr.y + rr.h / 2 };
    }

    fn swipe(r: *Rig, i: usize, dx: f32) ?[]const u8 {
        const c = r.rowCentre(i);
        _ = r.v.drag(.{ .phase = .down, .x = c[0], .y = c[1] });
        _ = r.v.drag(.{ .phase = .move, .x = c[0] + dx / 4, .y = c[1] });
        return r.v.drag(.{ .phase = .up, .x = c[0] + dx, .y = c[1] });
    }
};

pub const reply = [_]convo_wire.Item{.{ .n = 1, .kind = .assistant, .text = "Run `zig build run` next. Keep UDP 51820?" }};

test "rows swipe with the view's gesture: left = Yes, guarded, springs back short, flies off" {
    const gpa = testing.allocator;
    var r: Rig = undefined;
    try r.init(gpa, "instruct", &reply);
    defer r.deinit(gpa);
    // Too early after the row appeared: nothing sent.
    r.clk.t = 1300;
    try testing.expect(r.swipe(1, -300) == null);
    try testing.expectEqual(@as(usize, 0), r.sent.n);
    // Later, short of the threshold: springs back, nothing sent.
    r.clk.t = 3000;
    try testing.expect(r.swipe(1, -40) == null);
    try testing.expectEqual(@as(usize, 0), r.sent.n);
    try testing.expect(r.v.frameTimeout() != null);
    r.clk.t += cv.spring_ms;
    _ = r.v.cardScale();
    // Past it to the left: Yes, as the row's own frame (never a key).
    r.clk.t += 1000;
    try testing.expect(r.swipe(1, -300) == null);
    try testing.expectEqualStrings("i:yes 02020202020202020202020202020202", r.sent.last());
    try testing.expect(r.v.frameTimeout() != null); // flying off
    // Answered here: no second swipe on it.
    r.clk.t += 1000;
    _ = r.swipe(1, -300);
    try testing.expectEqual(@as(usize, 1), r.sent.n);
    // Right on another row: No.
    _ = r.swipe(2, 300);
    try testing.expectEqualStrings("i:no 03030303030303030303030303030303", r.sent.last());
}

test "the full card swipes the same way; tap toggles; right-yes flips the sides" {
    const gpa = testing.allocator;
    var r: Rig = undefined;
    try r.init(gpa, "instruct", &reply);
    defer r.deinit(gpa);
    r.v.yes_side = .right;
    const folded = r.p.rowRect(1, test_fonts.fonts).h;
    try testing.expect(r.v.button(ids.row0 + 1));
    r.v.prepare(.{ .w = 428, .h = 2000 }, test_fonts.fonts);
    try testing.expect(r.p.rowRect(1, test_fonts.fonts).h > folded);
    r.clk.t = 5000;
    try testing.expect(r.swipe(1, 300) == null);
    try testing.expectEqualStrings("i:yes 02020202020202020202020202020202", r.sent.last());
    // Sent: the card folds; a tap on another opens it, Esc folds it.
    try testing.expect(r.p.open == null);
    try testing.expect(r.v.button(ids.row0 + 2));
    r.v.prepare(.{ .w = 428, .h = 2000 }, test_fonts.fonts);
    try testing.expectEqual(cv.View.KeyResult.scrolled, r.v.onKey(.escape, .{}));
    try testing.expect(r.p.open == null);
}

test "keys: arrows answer the focused row, up/down move, enter toggles; none mode: shown, not swipeable" {
    const gpa = testing.allocator;
    var r: Rig = undefined;
    try r.init(gpa, "instruct", &reply);
    defer r.deinit(gpa);
    r.clk.t = 5000;
    try testing.expectEqual(cv.View.KeyResult.scrolled, r.v.onKey(.down, .{}));
    try testing.expectEqual(cv.View.KeyResult.scrolled, r.v.onKey(.enter, .{}));
    try testing.expect(r.p.open != null);
    try testing.expectEqual(cv.View.KeyResult.row, r.v.onKey(.left, .{}));
    try testing.expectEqualStrings("i:yes 02020202020202020202020202020202", r.sent.last());
    var n: Rig = undefined;
    try n.init(gpa, "none", &reply);
    defer n.deinit(gpa);
    n.clk.t = 5000;
    try testing.expect(n.swipe(1, -300) == null);
    try testing.expectEqual(cv.View.KeyResult.ignored, n.v.onKey(.left, .{}));
    try testing.expectEqual(@as(usize, 0), n.sent.n);
    try testing.expect(n.p.visible());
}

test "one approval UI: the conversation's permission card gives way to the waiting row" {
    const gpa = testing.allocator;
    const perm = [_]convo_wire.Option{ .{ .label = "Yes", .key = "1" }, .{ .label = "No", .key = "esc" } };
    const items = [_]convo_wire.Item{
        .{ .n = 1, .kind = .assistant, .text = "Next I run the tests." },
        .{ .n = 2, .kind = .question, .text = "Claude wants to run a command. Allow it?", .open = true, .options = &perm },
    };
    var r: Rig = undefined;
    try r.init(gpa, "keys", &items);
    defer r.deinit(gpa);
    try testing.expect(r.v.questionKeys().card);
    // The question card takes no swipe; the waiting row does.
    r.clk.t = 5000;
    try testing.expect(r.swipe(0, -300) == null);
    try testing.expectEqualStrings("i:yes 01010101010101010101010101010101", r.sent.last());
    // Without the For-you panel the card is the conversation's again.
    var plain = cv.View.init(gpa);
    defer plain.deinit();
    plain.sync(&r.c);
    plain.prepare(.{ .w = 428, .h = 2000 }, test_fonts.fonts);
    plain.shown_q = plain.newestOpenQuestion();
    plain.clock = .{ .ctx = &r.clk, .now = Clock.now };
    plain.presented(0);
    try testing.expectEqual(cv.View.KeyResult.answer_yes, plain.onKey(.left, .{}));
}

test "focus follows its card; a card gone takes the focus with it" {
    const gpa = testing.allocator;
    var s: Store = .{};
    defer s.deinit(gpa);
    const tab: Id = @splat(0xa);
    var l = testList(tab);
    try storeWith(gpa, &s, &l);
    var p = Panel.init(gpa);
    defer p.deinit();
    p.sync(&s, tab, "instruct", true);
    // No key pressed yet: nothing is focused, ←/→ answer nothing.
    try testing.expect(p.focused() == null);
    _ = p.moveFocus(1); // row 1: the suggestion
    try testing.expectEqual(@as(Id, @splat(2)), p.focused().?);
    // The waiting card above it goes: the focus stays on the suggestion.
    l.items[0] = l.items[1];
    l.items[1] = l.items[2];
    l.len = 2;
    try storeWith(gpa, &s, &l);
    p.sync(&s, tab, "instruct", true);
    try testing.expectEqual(@as(usize, 0), p.focus);
    try testing.expectEqual(@as(Id, @splat(2)), p.focused().?);
    // The focused card goes: no focus, not the card now in its place.
    l.items[0] = l.items[1];
    l.len = 1;
    try storeWith(gpa, &s, &l);
    p.sync(&s, tab, "instruct", true);
    try testing.expect(p.focused() == null and !p.focus_shown);
}

test "a suggested command's row shows all of it" {
    const gpa = testing.allocator;
    var s: Store = .{};
    defer s.deinit(gpa);
    const tab: Id = @splat(0xa);
    var l: foryou.List = .{ .tab = tab };
    const cmd = "zig build test -Dtest-filter=a-rather-long-filter-name -Doptimize=ReleaseSafe --summary all";
    l.items[0] = .{ .id = @splat(1), .kind = .suggest_run };
    l.items[0].setSummary(cmd);
    l.items[0].setCmd(cmd);
    l.len = 1;
    try storeWith(gpa, &s, &l);
    var p = Panel.init(gpa);
    defer p.deinit();
    p.sync(&s, tab, "instruct", true);
    _ = p.layout(test_fonts.fonts, 300);
    var shown: std.ArrayList(u8) = .empty;
    defer shown.deinit(gpa);
    var lines: usize = 0;
    for (p.rows[0].lines.items) |ln| if (ln.font == .body and !std.mem.eql(u8, ln.str, "\u{203A}")) {
        try testing.expect(ln.x1 == null);
        try shown.appendSlice(gpa, ln.str);
        lines += 1;
    };
    try testing.expectEqualStrings(cmd, shown.items);
    try testing.expect(lines > 1);
    try testing.expect(p.rows[0].h > p.rows[0].lines.items[0].y);
}
