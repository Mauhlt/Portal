//! Remote host for TermView (`portal connect`): turns view input into
//! protocol frames for the connection thread, and the connection status
//! into TermView's overlay (pairing screen, status line, answer bar).

const std = @import("std");
const view = @import("view");
const TermView = view.TermView;
const input = view.input;
const keys = @import("keys.zig");
const client_mod = @import("net/client.zig");

pub const pair_button_id = 1;

/// InputSink that sends protocol key names / text per the server's
/// `hello.input` mode.
pub const RemoteSink = struct {
    client: *client_mod.Client,
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

    fn pairing(r: *const RemoteSink) bool {
        return r.status == .need_pairing or r.status == .pair_closed;
    }

    fn onKey(ctx: *anyopaque, key: input.Key, mods: input.Mods) void {
        const r: *RemoteSink = @ptrCast(@alignCast(ctx));
        if (r.pairing() and key == .enter) return r.client.requestPairing();
        if (keys.keyFrame(r.mode, key, mods)) |f| _ = r.client.sendInput(f);
    }

    fn onChar(ctx: *anyopaque, cp: u21, mods: input.Mods) void {
        const r: *RemoteSink = @ptrCast(@alignCast(ctx));
        if (r.pairing() and !mods.ctrl and (cp == 'p' or cp == 'P')) return r.client.requestPairing();
        var buf: [8]u8 = undefined;
        if (keys.charFrame(r.mode, cp, mods, &buf)) |f| _ = r.client.sendInput(f);
    }

    fn onAnswer(ctx: *anyopaque, key: []const u8) void {
        const r: *RemoteSink = @ptrCast(@alignCast(ctx));
        if (keys.answerFrame(r.mode, key)) |f| _ = r.client.sendInput(f);
    }

    fn onButton(ctx: *anyopaque, id: u32) void {
        const r: *RemoteSink = @ptrCast(@alignCast(ctx));
        if (id == pair_button_id) r.client.requestPairing();
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

const pair_lines = [_][]const u8{
    "1. At the desktop, run:   portal pair <name>",
    "2. Within 2 minutes, click Pair below (or press P).",
};

/// Builds the overlay from a status snapshot. `detail` must outlive the
/// call to TermView.build.
pub fn overlay(st: client_mod.Status, mode: keys.Mode, detail: []const u8, host: []const u8, has_grid: bool) TermView.Overlay {
    var o: TermView.Overlay = .{};
    o.status = .{
        .label = statusWord(st),
        .right = host,
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
                .detail = detail,
                .detail_tone = if (st == .pair_closed) .warn else .muted,
            } };
            return o;
        },
        .store_unavailable => {
            o.screen = .{ .message = .{ .title = "Cannot store the device credential", .title_tone = .bad, .detail = detail } };
            return o;
        },
        .connected => {
            o.show_answers = mode.acceptsAnswers();
            if (mode != .unknown) {
                o.status.extra = mode.label();
                o.status.extra_tone = if (mode == .text) .warn else .normal;
            }
        },
        else => o.status.extra = detail,
    }
    if (!has_grid) o.screen = .{ .message = .{ .title = statusWord(st), .title_tone = .muted, .detail = detail } };
    return o;
}
