//! The desktop's own Portal window (`portal run` without --console): a
//! GUI terminal for the local session, drawn by the shared view module
//! (client/src/view, the same code as `portal connect`).
//!
//! Threads: everything here runs on the main thread (window + message
//! loop). The PTY output thread feeds `session.term`; this host copies the
//! dirty rows into its own Grid under `session.mutex` (localgrid.zig), then
//! builds and presents the frame without holding the lock. Keyboard, paste
//! and resizes go to the PTY through Session.writeInput / Session.setSize.
//!
//! The person at the desk has full control (localinput.zig), unlike remote
//! viewers, whose input is filtered by `--input` (keymap.zig).

const std = @import("std");
const view = @import("view");
const TermView = view.TermView;
const input = view.input;
const Session = @import("session.zig").Session;
const keymap = @import("keymap.zig");
const localgrid = @import("localgrid.zig");
const localinput = @import("localinput.zig");

/// Font size of the local terminal, in logical pixels (zoom with Ctrl+= / -).
pub const font_em: f32 = 15;
/// Largest paste accepted, in UTF-16 units of clipboard text.
const max_paste_units = 256 * 1024;

pub const Options = struct {
    /// The session program's name (e.g. the agent CLI). Not shown in the window.
    command_name: []const u8,
    /// `--project NAME` (checked with validProject), shown as
    /// "Portal — NAME". Null: "Portal — No project". (Tabs will supply
    /// per-project names later.)
    project: ?[]const u8 = null,
    /// e.g. "127.0.0.1:8420", shown in the status line.
    listen_host: []const u8,
    policy: keymap.Policy,
};

pub const Ended = enum { window_closed, child_exited };

/// Longest `--project` name, in bytes.
pub const max_project_bytes = 64;

/// True if `s` may be shown as the project name: 1..max_project_bytes bytes
/// of valid UTF-8 on a single line, with no control characters (C0, DEL,
/// C1), line/paragraph separators or bidi overrides (which could make the
/// title read differently from what it is).
pub fn validProject(s: []const u8) bool {
    if (s.len == 0 or s.len > max_project_bytes) return false;
    const v = std.unicode.Utf8View.init(s) catch return false;
    var it = v.iterator();
    while (it.nextCodepoint()) |cp| switch (cp) {
        0x00...0x1F, 0x7F...0x9F, 0x2028, 0x2029, 0x202A...0x202E, 0x2066...0x2069, 0x200E, 0x200F, 0x061C, 0xFEFF => return false,
        else => {},
    };
    return std.mem.trim(u8, s, " ").len > 0;
}

/// "Portal — <project>" or "Portal — No project". Program-set titles (OSC
/// 0/2) are never shown: they leak paths such as
/// "Administrator: C:\Windows\system32\cmd.exe". Not derived from the
/// working directory either (by default the home folder: the user name).
pub fn windowLabel(project: ?[]const u8, buf: []u8) []const u8 {
    const p = project orelse "No project";
    return std.fmt.bufPrint(buf, "Portal \u{2014} {s}", .{p}) catch "Portal";
}

/// The window title: the label, plus " — N REMOTE VIEWER(S)" while anyone
/// watches.
pub fn windowTitle(project: ?[]const u8, viewers: u32, buf: []u8) []const u8 {
    var lbuf: [max_project_bytes + 16]u8 = undefined;
    const label = windowLabel(project, &lbuf);
    if (viewers == 0) return std.fmt.bufPrint(buf, "{s}", .{label}) catch "Portal";
    return std.fmt.bufPrint(buf, "{s} \u{2014} {d} REMOTE VIEWER{s}", .{ label, viewers, if (viewers == 1) "" else "S" }) catch "Portal";
}

/// Cell selection being made with the mouse (anchor = where the drag began).
const Select = struct {
    anchor: [2]u16 = .{ 0, 0 },
    head: [2]u16 = .{ 0, 0 },
    dragging: bool = false,
    /// True once the pointer moved off the anchor cell (a plain click
    /// selects nothing).
    active: bool = false,

    fn range(s: Select) ?TermView.Selection {
        if (!s.active) return null;
        const a = s.anchor;
        const b = s.head;
        const a_first = a[1] < b[1] or (a[1] == b[1] and a[0] <= b[0]);
        const lo = if (a_first) a else b;
        const hi = if (a_first) b else a;
        return .{ .start_col = lo[0], .start_row = lo[1], .end_col = hi[0], .end_row = hi[1] };
    }
};

pub const LocalHost = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    tv: *TermView,
    /// The session this window shows and types into. Everything below goes
    /// through this one pointer so a later tab strip (one session per
    /// project) can switch it; nothing else names a session.
    session: *Session,
    opts: Options,
    grid: view.grid.Grid = .{},
    sync: localgrid.Sync = .{},
    select: Select = .{},
    /// Snapshot of session.viewers from the last frame.
    viewers: u32 = 0,
    drawn_viewers: u32 = std.math.maxInt(u32),
    /// Coalesces wake-ups from other threads (Session.notify_fn).
    wake_pending: std.atomic.Value(bool) = .init(false),
    title_buf: [title_max]u8 = undefined,
    title_len: usize = 0,
    label_buf: [max_project_bytes + 16]u8 = undefined,
    /// Times the message loop woke up (idle should stay near zero: the
    /// loop is event-driven), and frames presented. Logged at shutdown.
    wakeups: u64 = 0,
    presents: u64 = 0,
    /// Set by the child-exit waiter thread.
    child_done: *const std.atomic.Value(bool),

    const title_max = max_project_bytes + 64;

    pub fn init(gpa: std.mem.Allocator, io: std.Io, opts: Options, child_done: *const std.atomic.Value(bool)) !*LocalHost {
        const tv = try TermView.init(gpa, io, .{
            .title = "Portal",
            .width = 1100,
            .height = 700,
            .sizing = .{ .fixed_em = font_em },
        });
        errdefer tv.deinit();
        const h = try gpa.create(LocalHost);
        h.* = .{ .gpa = gpa, .io = io, .tv = tv, .session = undefined, .opts = opts, .child_done = child_done };
        return h;
    }

    /// Cells that fit the window now: the PTY's initial size.
    pub fn initialSize(h: *LocalHost) [2]u16 {
        h.tv.build(&h.grid, .{ .top_bar = .{} });
        const c = h.tv.capacity;
        return .{ @max(c[0], 20), @max(c[1], 5) };
    }

    /// Points the window at `s` and hooks its change notifications. Call
    /// before any thread that touches the session starts.
    pub fn attach(h: *LocalHost, s: *Session) void {
        h.session = s;
        s.notify_ctx = h;
        s.notify_fn = notifyThunk;
        h.tv.reported_capacity = .{ s.size.cols, s.size.rows };
        h.tv.setLiveRedraw(h, liveRedraw);
    }

    /// Any thread: something in the session changed.
    fn notifyThunk(ctx: *anyopaque) void {
        const h: *LocalHost = @ptrCast(@alignCast(ctx));
        if (!h.wake_pending.swap(true, .acq_rel)) h.tv.wake();
    }

    /// The message loop. Returns when the window is closed or the child
    /// exited (the caller then runs the common shutdown, which can take
    /// seconds without pumping messages: so the window is hidden and its
    /// swapchain torn down first, rather than left showing "Not
    /// responding" and exiting the process under a live swapchain).
    ///
    /// Purely event-driven: it sleeps until window input or a wake()
    /// (session output, viewer count changes and child exit all call
    /// notifyThunk), never on a timer.
    pub fn run(h: *LocalHost) Ended {
        h.updateTitle();
        const ended: Ended = while (true) {
            if (!h.tv.pollEvents(h.sink())) break .window_closed;
            if (h.child_done.load(.acquire)) break .child_exited;
            h.frame(false);
            h.tv.waitEvents(TermView.forever);
            h.wakeups += 1;
        };
        h.hide();
        h.tv.releaseGpu();
        return ended;
    }

    /// Any thread: the child exited (child_done is set); ends the wait in
    /// run().
    pub fn wakeChildExited(h: *LocalHost) void {
        notifyThunk(h);
    }

    /// Hides the window (shutdown can take a moment; the user already
    /// asked to close, or the program ended).
    pub fn hide(h: *LocalHost) void {
        _ = ShowWindow(@ptrCast(h.tv.window.hwnd), 0);
    }

    fn liveRedraw(ctx: *anyopaque) void {
        const h: *LocalHost = @ptrCast(@alignCast(ctx));
        h.tv.reportCapacity(h.sink());
        h.frame(true);
    }

    /// Copies the session's changes into our grid under the lock, then
    /// builds and presents outside it.
    fn frame(h: *LocalHost, force: bool) void {
        h.wake_pending.store(false, .release);
        const s = h.session;
        s.mutex.lockUncancelable(s.io);
        const changed = h.sync.sync(h.gpa, &h.grid, &s.term);
        h.viewers = s.viewers;
        s.mutex.unlock(s.io);

        if (changed) h.clampSelection();
        if (!force and !changed and !h.tv.needsRedraw() and h.viewers == h.drawn_viewers) return;
        h.drawn_viewers = h.viewers;
        h.updateTitle();

        var right_buf: [64]u8 = undefined;
        var status_buf: [96]u8 = undefined;
        h.tv.build(&h.grid, h.overlay(&right_buf, &status_buf));
        h.tv.present();
        h.presents += 1;
    }

    fn viewerText(n: u32, buf: []u8) []const u8 {
        if (n == 0) return "no remote viewers";
        return std.fmt.bufPrint(buf, "{d} REMOTE VIEWER{s} WATCHING", .{ n, if (n == 1) "" else "S" }) catch "REMOTE VIEWERS WATCHING";
    }

    fn overlay(h: *LocalHost, right_buf: []u8, status_buf: []u8) TermView.Overlay {
        const watching = h.viewers > 0;
        const remote_input: []const u8 = switch (h.opts.policy) {
            .none => "remote: view only",
            .keys => "remote: answer keys only",
            .instruct => "remote: answer keys + checked instructions",
            .text => "remote: FULL CONTROL",
        };
        return .{
            .top_bar = .{
                .title = windowLabel(h.opts.project, &h.label_buf),
                .right = viewerText(h.viewers, right_buf),
                .right_tone = if (watching) .warn else .muted,
                .right_badge = watching,
            },
            .selection = h.select.range(),
            .status = .{
                .tone = .good,
                .label = "local session",
                .extra = remote_input,
                .extra_tone = if (h.opts.policy == .text) .bad else .muted,
                .right = std.fmt.bufPrint(status_buf, "sharing on http://{s}/", .{h.opts.listen_host}) catch h.opts.listen_host,
            },
        };
    }

    /// The one place the window title is set (see windowTitle).
    fn updateTitle(h: *LocalHost) void {
        var buf: [title_max]u8 = undefined;
        const t = windowTitle(h.opts.project, h.viewers, &buf);
        if (std.mem.eql(u8, t, h.title_buf[0..h.title_len])) return;
        @memcpy(h.title_buf[0..t.len], t);
        h.title_len = t.len;
        h.tv.setTitle(t);
    }

    fn clampSelection(h: *LocalHost) void {
        if (h.grid.cols == 0 or h.grid.rows == 0) {
            h.select = .{};
            return;
        }
        for ([_]*[2]u16{ &h.select.anchor, &h.select.head }) |p| {
            p[0] = @min(p[0], h.grid.cols - 1);
            p[1] = @min(p[1], h.grid.rows - 1);
        }
    }

    // ------------------------------------------------------------ input

    fn sink(h: *LocalHost) input.InputSink {
        return .{ .ctx = h, .vtable = &vtable };
    }

    const vtable: input.InputSink.VTable = .{
        .key = onKey,
        .char = onChar,
        .answer = onAnswer,
        .button = onButton,
        .resized = onResized,
        .mouse = onMouse,
    };

    fn self(ctx: *anyopaque) *LocalHost {
        return @ptrCast(@alignCast(ctx));
    }

    fn onKey(ctx: *anyopaque, key: input.Key, mods: input.Mods) void {
        const h = self(ctx);
        const s = h.session;
        s.mutex.lockUncancelable(s.io);
        const app_cursor = s.term.appCursor();
        s.mutex.unlock(s.io);
        var buf: [localinput.max_seq]u8 = undefined;
        h.select.active = false;
        s.writeInput(localinput.encodeKey(key, mods, app_cursor, &buf));
    }

    fn onChar(ctx: *anyopaque, cp: u21, mods: input.Mods) void {
        const h = self(ctx);
        if (mods.ctrl and mods.shift and !mods.alt) {
            switch (cp) {
                'c', 'C' => return h.copySelection(),
                'v', 'V' => return h.paste(),
                else => {},
            }
        }
        var buf: [localinput.max_seq]u8 = undefined;
        h.select.active = false;
        h.session.writeInput(localinput.encodeChar(cp, mods, &buf));
    }

    fn onAnswer(_: *anyopaque, _: []const u8) void {} // no answer bar locally
    fn onButton(_: *anyopaque, _: u32) void {}

    /// The window decides the PTY size; web viewers adapt.
    fn onResized(ctx: *anyopaque, _: u32, _: u32, cols: u16, rows: u16) void {
        const h = self(ctx);
        h.session.setSize(.{ .cols = cols, .rows = rows });
    }

    fn onMouse(ctx: *anyopaque, m: input.Mouse) void {
        const h = self(ctx);
        switch (m.button) {
            .left => switch (m.action) {
                .down => {
                    h.select = .{ .anchor = .{ m.col, m.row }, .head = .{ m.col, m.row }, .dragging = m.inside };
                },
                .move => if (h.select.dragging) {
                    h.select.head = .{ m.col, m.row };
                    if (h.select.head[0] != h.select.anchor[0] or h.select.head[1] != h.select.anchor[1]) h.select.active = true;
                },
                .up => h.select.dragging = false,
            },
            // Right-click: copy the selection if there is one, else paste
            // (the Windows console convention).
            .right => if (m.action == .down) {
                if (h.select.active) h.copySelection() else h.paste();
            },
            .middle => {},
        }
    }

    fn copySelection(h: *LocalHost) void {
        const sel = h.select.range() orelse return;
        const text = localgrid.selectionText(h.gpa, &h.grid, sel) catch return;
        defer h.gpa.free(text);
        if (text.len > 0) _ = h.tv.window.setClipboardText(text);
        h.select = .{};
    }

    fn paste(h: *LocalHost) void {
        const raw = h.tv.window.clipboardText(h.gpa, max_paste_units) orelse return;
        defer h.gpa.free(raw);
        const s = h.session;
        s.mutex.lockUncancelable(s.io);
        const bracketed = s.term.bracketedPaste();
        s.mutex.unlock(s.io);
        const buf = h.gpa.alloc(u8, raw.len + localinput.paste_start.len + localinput.paste_end.len) catch return;
        defer h.gpa.free(buf);
        var n: usize = 0;
        if (bracketed) {
            @memcpy(buf[0..localinput.paste_start.len], localinput.paste_start);
            n = localinput.paste_start.len;
        }
        const clean = localinput.sanitizePaste(raw, buf[n .. n + raw.len]);
        if (clean.len == 0) return;
        n += clean.len;
        if (bracketed) {
            @memcpy(buf[n..][0..localinput.paste_end.len], localinput.paste_end);
            n += localinput.paste_end.len;
        }
        h.select.active = false;
        s.writeInput(buf[0..n]);
    }
};

extern "user32" fn ShowWindow(hwnd: *anyopaque, cmd: i32) callconv(.winapi) i32;

test "selection range normalises drag direction" {
    var s: Select = .{ .anchor = .{ 5, 3 }, .head = .{ 2, 1 }, .active = true };
    const r = s.range().?;
    try std.testing.expectEqual(@as(u16, 2), r.start_col);
    try std.testing.expectEqual(@as(u16, 1), r.start_row);
    try std.testing.expectEqual(@as(u16, 5), r.end_col);
    try std.testing.expectEqual(@as(u16, 3), r.end_row);
    s.active = false;
    try std.testing.expect(s.range() == null);
}

test "window title never shows the program's title" {
    var buf: [LocalHost.title_max]u8 = undefined;
    try std.testing.expectEqualStrings("Portal \u{2014} No project", windowTitle(null, 0, &buf));
    try std.testing.expectEqualStrings("Portal \u{2014} acme-api", windowTitle("acme-api", 0, &buf));
    try std.testing.expectEqualStrings("Portal \u{2014} acme-api \u{2014} 1 REMOTE VIEWER", windowTitle("acme-api", 1, &buf));
    try std.testing.expectEqualStrings("Portal \u{2014} No project \u{2014} 3 REMOTE VIEWERS", windowTitle(null, 3, &buf));
    // The longest valid project with a huge viewer count still fits.
    const long: [max_project_bytes]u8 = @splat('p');
    try std.testing.expect(std.mem.endsWith(u8, windowTitle(&long, std.math.maxInt(u32), &buf), "4294967295 REMOTE VIEWERS"));
    var lbuf: [max_project_bytes + 16]u8 = undefined;
    try std.testing.expectEqualStrings("Portal \u{2014} No project", windowLabel(null, &lbuf));
    try std.testing.expectEqualStrings("Portal \u{2014} " ++ long, windowLabel(&long, &lbuf));
}

test "validProject" {
    try std.testing.expect(validProject("acme-api"));
    try std.testing.expect(validProject("Kundenportal \u{e9}t\u{e9} 2"));
    const max: [max_project_bytes]u8 = @splat('p');
    const over: [max_project_bytes + 1]u8 = @splat('p');
    try std.testing.expect(validProject(&max));
    try std.testing.expect(!validProject(&over));
    try std.testing.expect(!validProject(""));
    try std.testing.expect(!validProject("   "));
    try std.testing.expect(!validProject("a\nb"));
    try std.testing.expect(!validProject("a\rb"));
    try std.testing.expect(!validProject("a\tb"));
    try std.testing.expect(!validProject("a\x1b]0;x\x07"));
    try std.testing.expect(!validProject("a\x7f"));
    try std.testing.expect(!validProject("a\u{85}b")); // C1 NEL
    try std.testing.expect(!validProject("a\u{2028}b"));
    try std.testing.expect(!validProject("abc\u{202e}gpj.exe")); // RLO
    try std.testing.expect(!validProject("a\u{2067}b"));
    try std.testing.expect(!validProject("bad\xff"));
}

test "viewer text" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("no remote viewers", LocalHost.viewerText(0, &buf));
    try std.testing.expectEqualStrings("1 REMOTE VIEWER WATCHING", LocalHost.viewerText(1, &buf));
    try std.testing.expectEqualStrings("3 REMOTE VIEWERS WATCHING", LocalHost.viewerText(3, &buf));
}
