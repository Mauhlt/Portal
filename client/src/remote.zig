//! Remote host for TermView (`portal connect`): turns view input into
//! protocol frames for the connection thread, and the connection status
//! into TermView's overlay (pairing screens with the request code, trust
//! errors, status line, answer bar).

const std = @import("std");
const view = @import("view");
const TermView = view.TermView;
const input = view.input;
const keys = @import("keys.zig");
const client_mod = @import("net/client.zig");

pub const pair_button_id = 1;
pub const cancel_button_id = 2;

/// InputSink that sends protocol key names / text per the server's
/// `hello.input` mode.
pub const RemoteSink = struct {
    client: *client_mod.Client,
    /// A modal layer above the terminal (the sync panels): while it is
    /// active it gets the keyboard and its buttons.
    modal: ?Modal = null,
    /// Snapshot of the mode/status, refreshed each frame by the main loop.
    mode: keys.Mode = .unknown,
    status: client_mod.Status = .starting,

    pub fn sink(r: *RemoteSink) input.InputSink {
        return .{ .ctx = r, .vtable = &vtable };
    }

    const vtable: input.InputSink.VTable = .{
        .key = onKey,
        .char = onChar,
        .answer = onAnswer,
        .button = onButton,
        .resized = onResized,
    };

    fn canPair(r: *const RemoteSink) bool {
        return r.status == .need_pairing or r.status == .pair_closed;
    }

    fn waiting(r: *const RemoteSink) bool {
        return r.status == .pairing or r.status == .pair_waiting;
    }

    /// Who gets the keyboard: decided here only. The pairing screens
    /// take it while shown; otherwise the remote terminal. A bottom-region
    /// input pane (TermView.Layout) would be one more target here.
    pub const Focus = enum { pair_screen, wait_screen, terminal };

    pub fn focus(r: *const RemoteSink) Focus {
        if (r.canPair()) return .pair_screen;
        if (r.waiting()) return .wait_screen;
        return .terminal;
    }

    pub const Modal = struct {
        ctx: *anyopaque,
        active: *const fn (*anyopaque) bool,
        key: *const fn (*anyopaque, input.Key, input.Mods) void,
        char: *const fn (*anyopaque, u21, input.Mods) void,
        /// True if the id was the modal's.
        button: *const fn (*anyopaque, u32) bool,
        /// A shortcut that opens it from the terminal (true: consumed).
        shortcut: *const fn (*anyopaque, u21, input.Mods) bool,
    };

    fn modalActive(r: *const RemoteSink) ?Modal {
        const m = r.modal orelse return null;
        return if (m.active(m.ctx)) m else null;
    }

    fn onKey(ctx: *anyopaque, key: input.Key, mods: input.Mods) void {
        const r: *RemoteSink = @ptrCast(@alignCast(ctx));
        if (r.modalActive()) |m| return m.key(m.ctx, key, mods);
        switch (r.focus()) {
            .pair_screen => if (key == .enter) r.client.requestPairing(),
            .wait_screen => if (key == .escape) r.client.cancelPairing(),
            .terminal => if (keys.keyFrame(r.mode, key, mods)) |f| {
                _ = r.client.sendInput(f);
            },
        }
    }

    fn onChar(ctx: *anyopaque, cp: u21, mods: input.Mods) void {
        const r: *RemoteSink = @ptrCast(@alignCast(ctx));
        if (r.modalActive()) |m| return m.char(m.ctx, cp, mods);
        if (r.modal) |m| if (m.shortcut(m.ctx, cp, mods)) return;
        switch (r.focus()) {
            .pair_screen => if (!mods.ctrl and (cp == 'p' or cp == 'P')) r.client.requestPairing(),
            .wait_screen => {},
            .terminal => {
                var buf: [8]u8 = undefined;
                if (keys.charFrame(r.mode, cp, mods, &buf)) |f| _ = r.client.sendInput(f);
            },
        }
    }

    fn onAnswer(ctx: *anyopaque, key: []const u8) void {
        const r: *RemoteSink = @ptrCast(@alignCast(ctx));
        if (keys.answerFrame(r.mode, key)) |f| _ = r.client.sendInput(f);
    }

    fn onButton(ctx: *anyopaque, id: u32) void {
        const r: *RemoteSink = @ptrCast(@alignCast(ctx));
        if (r.modal) |m| if (m.button(m.ctx, id)) return;
        if (id == pair_button_id) r.client.requestPairing();
        if (id == cancel_button_id) r.client.cancelPairing();
    }

    fn onResized(_: *anyopaque, _: u32, _: u32, _: u16, _: u16) void {
        // The remote grid size is the server's; the view scales to fit.
    }
};

fn statusWord(st: client_mod.Status) []const u8 {
    return switch (st) {
        .starting => "starting",
        .need_pairing, .pair_closed => "not paired",
        .pairing => "pairing",
        .pair_waiting => "waiting for the desk",
        .refreshing => "signing in",
        .connecting => "connecting",
        .connected => "connected",
        .retrying => "reconnecting",
        .session_ended => "session ended",
        .store_unavailable => "credential store unavailable",
    };
}

pub fn title(st: client_mod.Status, host: []const u8, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "Portal - {s} - {s}", .{ host, statusWord(st) }) catch "Portal";
}

/// Errors that mean "this is not the Portal we trust" (or not Portal's
/// TLS at all), as opposed to the network being down.
pub fn isTrustError(err: anyerror) bool {
    const list = [_]anyerror{
        error.NotIssuedByPinnedCa,    error.HostMismatch,          error.CertificateExpired,
        error.CertificateNotYetValid, error.CaExpired,             error.BadCertificate,
        error.UnsupportedCertificate, error.NotTls13,              error.UnsupportedCipherSuite,
        error.HelloRetryRequest,      error.TlsHandshakeMalformed, error.TlsUnexpectedMessage,
        error.TlsDecodeError,         error.TlsAlert,              error.TlsConnectionTruncated,
        error.NoServerCertificate,
    };
    for (list) |e| if (e == err) return true;
    return false;
}

const pair_lines = [_][]const u8{
    "1. At the desktop, in the Portal window: Pair a device\u{2026} (Ctrl+Shift+P).",
    "   (In a terminal there: portalctl pair <name>.)",
    "2. Within 2 minutes, click Pair below (or press P). The desk then approves this device.",
};

/// What the overlay is built from (a snapshot taken under the lock).
pub const View = struct {
    status: client_mod.Status,
    mode: keys.Mode,
    /// Must outlive TermView.build.
    detail: []const u8,
    host: []const u8,
    has_grid: bool,
    /// The request code while waiting for the desk.
    code: ?[4]u8 = null,
    /// The last connection error, if any.
    err: ?anyerror = null,
    /// "AB:CD:..." of the pinned Portal CA ("" without TLS).
    pin_fp: []const u8 = "",
};

/// Text storage for overlay(); must outlive TermView.build.
pub const Bufs = struct {
    txt: [4][200]u8 = undefined,
    lines: [4][]const u8 = undefined,
    title: [48]u8 = undefined,
};

/// Builds the overlay from a status snapshot.
pub fn overlay(v: View, b: *Bufs) TermView.Overlay {
    var o: TermView.Overlay = .{};
    const st = v.status;
    o.status = .{
        .label = statusWord(st),
        .right = v.host,
        .tone = switch (st) {
            .connected => .good,
            .need_pairing, .pair_closed, .store_unavailable => .bad,
            else => .warn,
        },
    };
    switch (st) {
        .need_pairing, .pair_closed => {
            o.screen = .{ .message = .{
                .title = "Pair this device",
                .lines = &pair_lines,
                .button = .{ .label = "Pair", .id = pair_button_id },
                .detail = v.detail,
                .detail_tone = if (st == .pair_closed) .warn else .muted,
            } };
            return o;
        },
        .pairing, .pair_waiting => {
            const t = if (v.code) |c| std.fmt.bufPrint(&b.title, "Request code {s}", .{&c}) catch "Waiting for the desk" else "Asking the desk\u{2026}";
            var n: usize = 0;
            b.lines[n] = "Waiting for approval in the Portal window on the desktop.";
            n += 1;
            if (v.code) |c| {
                b.lines[n] = std.fmt.bufPrint(&b.txt[0], "Approve it there only if the desk shows the same code, {s}.", .{&c}) catch "";
                n += 1;
            }
            b.lines[n] = "Press Esc to stop waiting.";
            n += 1;
            o.screen = .{ .message = .{
                .title = t,
                .title_tone = .warn,
                .lines = b.lines[0..n],
                .button = .{ .label = "Cancel", .id = cancel_button_id },
                .detail = v.detail,
            } };
            return o;
        },
        .store_unavailable => {
            o.screen = .{ .message = .{ .title = "Cannot store the device credential", .title_tone = .bad, .detail = v.detail } };
            return o;
        },
        .connected => {
            o.show_answers = v.mode.acceptsAnswers();
            if (v.mode != .unknown) {
                o.status.extra = v.mode.label();
                o.status.extra_tone = if (v.mode == .text) .warn else .normal;
            }
        },
        else => o.status.extra = v.detail,
    }
    // Certificate / pinning trouble: say so in the window, prominently,
    // instead of retrying silently behind an old picture.
    if (st != .connected) if (v.err) |err| if (isTrustError(err)) {
        var n: usize = 0;
        b.lines[n] = std.fmt.bufPrint(&b.txt[0], "{s}.", .{client_mod.describe(err)}) catch "";
        n += 1;
        if (v.pin_fp.len > 0) {
            b.lines[n] = std.fmt.bufPrint(&b.txt[1], "Trusted for {s}: the Portal CA with SHA-256 {s}", .{ v.host, v.pin_fp }) catch "";
            n += 1;
        }
        b.lines[n] = std.fmt.bufPrint(&b.txt[2], "If the desktop's CA was replaced: portal connect --server {s} --forget, then pair again with its new certificate.", .{v.host}) catch "";
        n += 1;
        o.screen = .{ .message = .{
            .title = "Cannot verify this Portal",
            .title_tone = .bad,
            .lines = b.lines[0..n],
            .detail = v.detail,
            .detail_tone = .warn,
        } };
        o.status.tone = .bad;
        return o;
    };
    if (!v.has_grid) o.screen = .{ .message = .{ .title = statusWord(st), .title_tone = .muted, .detail = v.detail } };
    return o;
}

test "overlay: waiting shows the request code; trust errors are explained" {
    var b: Bufs = .{};
    const w = overlay(.{ .status = .pair_waiting, .mode = .unknown, .detail = "", .host = "10.8.0.1:8420", .has_grid = false, .code = "7f3a".* }, &b);
    try std.testing.expectEqualStrings("Request code 7f3a", w.screen.message.title);
    try std.testing.expectEqual(@as(u32, cancel_button_id), w.screen.message.button.?.id);
    const t = overlay(.{ .status = .retrying, .mode = .unknown, .detail = "retrying in 2 s", .host = "10.8.0.1:8420", .has_grid = true, .err = error.NotIssuedByPinnedCa, .pin_fp = "AB:CD" }, &b);
    try std.testing.expectEqualStrings("Cannot verify this Portal", t.screen.message.title);
    try std.testing.expect(std.mem.indexOf(u8, t.screen.message.lines[0], "pinned Portal CA") != null);
    // A plain network error keeps the picture and says it in the status line.
    const n = overlay(.{ .status = .retrying, .mode = .unknown, .detail = "refused", .host = "h", .has_grid = true, .err = error.ConnectionRefused }, &b);
    try std.testing.expect(n.screen == .grid);
    try std.testing.expectEqualStrings("refused", n.status.extra);
    try std.testing.expect(isTrustError(error.HostMismatch));
    try std.testing.expect(!isTrustError(error.TimedOut));
}
