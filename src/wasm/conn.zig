//! Connection lifecycle: open, reconnect with backoff, re-check sign-in,
//! and the status text shown in the header (docs/protocol.md §5).
//!
//! Pure state machine: every event returns the effect the caller (main.zig)
//! performs through the bridge, so the whole policy is unit-testable.
//!
//!   start ─▶ connecting ─open─▶ live ─close─▶ waiting (backoff timer)
//!                ▲                              │ timer
//!                └──── signed in ◀── checking ◀─┘ (GET /, follow redirects)
//!                                       │ ended on /pair
//!                                       ▼
//!                                    leaving (navigate to /pair)
//!
//! Alongside the state: the exit code of a session that ended
//! ({"t":"exit"}, kept until a stream is live again) and what the last
//! sign-in check said about reaching the desktop. A session that ended
//! keeps reconnecting with the same backoff, so a Portal started again is
//! picked up (GET / signs in again with the device cookie); meanwhile the
//! status says the session ended and whether the desktop is offline or
//! this device's network is down.

const std = @import("std");
const proto = @import("proto.zig");

pub const first_retry_ms: u32 = 1000;
pub const max_retry_ms: u32 = 15000;

pub const State = enum { idle, connecting, live, waiting, checking, leaving };

const offline_note = "Desktop offline \u{2014} reconnects automatically.";
const network_note = "Network error: this device is offline \u{2014} reconnects automatically.";

pub const Effect = union(enum) {
    none,
    /// Open the WebSocket.
    open,
    /// Start the reconnect timer.
    timer: u32,
    /// Ask the server whether we are still signed in (GET /).
    check,
    /// Close the socket (if any) and go to /pair.
    leave,
};

/// Result of the sign-in check, as reported by the bridge.
pub const Check = struct {
    /// HTTP status of the final response; 0 when the request failed.
    status: u32,
    /// Path of the final URL after redirects, e.g. "/" or "/pair".
    path: []const u8,
    /// The browser says it has no network (navigator.onLine false).
    device_offline: bool = false,
};

/// What the last sign-in check said about reaching the desktop.
pub const Reach = enum {
    unknown,
    ok,
    /// The request failed while this device is online: nothing answers
    /// at the desktop's address (Portal not running, machine off).
    desktop_offline,
    /// The request failed and the browser reports no network.
    network_error,
};

pub const Status = enum { neutral, ok, bad };

pub const Conn = struct {
    state: State = .idle,
    retry_ms: u32 = first_retry_ms,
    /// The ended session's exit code, until a stream is live again.
    exit_code: ?i64 = null,
    reach: Reach = .unknown,

    pub fn start(c: *Conn) Effect {
        if (c.state != .idle) return .none;
        c.state = .connecting;
        return .open;
    }

    pub fn onOpen(c: *Conn) Effect {
        if (c.state != .connecting) return .none;
        c.state = .live;
        c.retry_ms = first_retry_ms;
        c.reach = .ok;
        // A new session (or the ended one's exit notice again, which
        // sets this back).
        c.exit_code = null;
        return .none;
    }

    pub fn onClose(c: *Conn) Effect {
        switch (c.state) {
            .connecting, .live => {
                c.state = .waiting;
                const delay = c.retry_ms;
                c.retry_ms = @min(c.retry_ms *| 2, max_retry_ms);
                return .{ .timer = delay };
            },
            else => return .none,
        }
    }

    pub fn onTimer(c: *Conn) Effect {
        if (c.state != .waiting) return .none;
        c.state = .checking;
        return .check;
    }

    pub fn onCheck(c: *Conn, r: Check) Effect {
        if (c.state != .checking) return .none;
        // GET / ends on /pair when the device is unknown, revoked or its
        // credential was rejected: sign-in is impossible, pair again.
        if (std.mem.eql(u8, r.path, "/pair") or std.mem.startsWith(u8, r.path, "/pair?")) {
            c.state = .leaving;
            return .leave;
        }
        c.reach = if (r.status != 0) .ok else if (r.device_offline) .network_error else .desktop_offline;
        // Signed in again (or the network failed: just try the socket,
        // its failure brings us back here after the next backoff step).
        c.state = .connecting;
        return .open;
    }

    /// The program ended. The server closes the stream next; reconnecting
    /// then goes on as after any close (the desktop may start a new
    /// session, or go away), while the status keeps saying it ended.
    pub fn onExit(c: *Conn, code: i64) Effect {
        if (c.state == .leaving) return .none;
        c.exit_code = code;
        return .none;
    }

    /// Input can go to a running session.
    pub fn canSend(c: *const Conn) bool {
        return c.state == .live and c.exit_code == null;
    }

    pub fn onLogout(c: *Conn) Effect {
        if (c.state == .leaving) return .none;
        c.state = .leaving;
        return .leave;
    }

    /// Header status text (short); `buf` holds formatted variants.
    pub fn statusText(c: *const Conn, buf: []u8) struct { text: []const u8, kind: Status } {
        if (c.state == .leaving) return .{ .text = "signed out", .kind = .bad };
        if (c.state != .live) switch (c.reach) {
            .desktop_offline => return .{ .text = "desktop offline", .kind = .bad },
            .network_error => return .{ .text = "network error", .kind = .bad },
            .unknown, .ok => {},
        };
        if (c.exit_code) |code| return .{
            .text = std.fmt.bufPrint(buf, "session ended (exit {d})", .{code}) catch "session ended",
            .kind = .bad,
        };
        return switch (c.state) {
            .idle, .connecting => .{ .text = "connecting…", .kind = .neutral },
            .live => .{ .text = "live", .kind = .ok },
            .waiting, .checking => .{ .text = "reconnecting…", .kind = .bad },
            .leaving => .{ .text = "signed out", .kind = .bad },
        };
    }

    /// The full sentence for the note under the input box while the
    /// session is ended or the desktop is unreachable (null otherwise).
    pub fn noteText(c: *const Conn, buf: []u8) ?[]const u8 {
        if (c.state == .leaving) return null;
        const reach: Reach = if (c.state == .live) .ok else c.reach;
        if (c.exit_code) |code| return switch (reach) {
            .desktop_offline => std.fmt.bufPrint(buf, "Session ended on the desktop (exit code {d}). " ++ offline_note, .{code}) catch null,
            .network_error => std.fmt.bufPrint(buf, "Session ended on the desktop (exit code {d}). " ++ network_note, .{code}) catch null,
            .unknown, .ok => std.fmt.bufPrint(buf, "Session ended on the desktop (exit code {d}).", .{code}) catch null,
        };
        return switch (reach) {
            .desktop_offline => offline_note,
            .network_error => network_note,
            .unknown, .ok => null,
        };
    }
};

pub fn modeText(p: proto.Policy) []const u8 {
    return p.label();
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "backoff doubles to 15 s and resets once live" {
    var c: Conn = .{};
    try testing.expectEqual(Effect.open, c.start());
    try testing.expectEqual(Effect.none, c.start()); // idempotent
    const expected = [_]u32{ 1000, 2000, 4000, 8000, 15000, 15000 };
    for (expected) |ms| {
        try testing.expectEqual(Effect{ .timer = ms }, c.onClose());
        try testing.expectEqual(Effect.check, c.onTimer());
        try testing.expectEqual(Effect.open, c.onCheck(.{ .status = 200, .path = "/" }));
    }
    try testing.expectEqual(Effect.none, c.onOpen());
    try testing.expectEqual(State.live, c.state);
    try testing.expectEqual(Effect{ .timer = 1000 }, c.onClose());
}

test "failed sign-in check goes to /pair; network errors retry" {
    var c: Conn = .{};
    _ = c.start();
    _ = c.onClose();
    _ = c.onTimer();
    try testing.expectEqual(Effect.open, c.onCheck(.{ .status = 0, .path = "" }));
    _ = c.onClose();
    _ = c.onTimer();
    try testing.expectEqual(Effect.leave, c.onCheck(.{ .status = 200, .path = "/pair" }));
    try testing.expectEqual(State.leaving, c.state);
    // Nothing reopens once leaving.
    try testing.expectEqual(Effect.none, c.onClose());
    try testing.expectEqual(Effect.none, c.onTimer());
    var c2: Conn = .{ .state = .checking };
    try testing.expectEqual(Effect.leave, c2.onCheck(.{ .status = 200, .path = "/pair?e=revoked" }));
    var c3: Conn = .{ .state = .checking };
    try testing.expectEqual(Effect.open, c3.onCheck(.{ .status = 200, .path = "/pairing-not-really" }));
}

test "exit: ended, then desktop offline, then a new session resumes" {
    var c: Conn = .{};
    var buf: [160]u8 = undefined;
    _ = c.start();
    _ = c.onOpen();
    try testing.expectEqual(@as(?[]const u8, null), c.noteText(&buf));
    _ = c.onExit(3);
    try testing.expectEqualStrings("session ended (exit 3)", c.statusText(&buf).text);
    try testing.expectEqualStrings("Session ended on the desktop (exit code 3).", c.noteText(&buf).?);
    // The server closes the stream; reconnecting goes on (event-driven
    // timer, same backoff), still saying the session ended.
    try testing.expectEqual(Effect{ .timer = 1000 }, c.onClose());
    try testing.expectEqualStrings("session ended (exit 3)", c.statusText(&buf).text);
    try testing.expectEqual(Effect.check, c.onTimer());
    // Portal exited: the check fails while this device is online.
    try testing.expectEqual(Effect.open, c.onCheck(.{ .status = 0, .path = "" }));
    try testing.expectEqualStrings("desktop offline", c.statusText(&buf).text);
    try testing.expectEqualStrings("Session ended on the desktop (exit code 3). Desktop offline \u{2014} reconnects automatically.", c.noteText(&buf).?);
    try testing.expectEqual(Effect{ .timer = 2000 }, c.onClose());
    try testing.expectEqualStrings("desktop offline", c.statusText(&buf).text);
    _ = c.onTimer();
    // This device lost its network instead.
    _ = c.onCheck(.{ .status = 0, .path = "", .device_offline = true });
    try testing.expectEqualStrings("network error", c.statusText(&buf).text);
    _ = c.onClose();
    _ = c.onTimer();
    // Portal runs again: GET / signs in again (device cookie), the
    // stream opens, and the ended session is history.
    try testing.expectEqual(Effect.open, c.onCheck(.{ .status = 200, .path = "/" }));
    try testing.expectEqualStrings("session ended (exit 3)", c.statusText(&buf).text);
    _ = c.onOpen();
    try testing.expectEqualStrings("live", c.statusText(&buf).text);
    try testing.expectEqual(@as(?[]const u8, null), c.noteText(&buf));
    // Offline from the start (no session ended).
    var o: Conn = .{ .state = .checking };
    _ = o.onCheck(.{ .status = 0, .path = "" });
    try testing.expectEqualStrings("Desktop offline \u{2014} reconnects automatically.", o.noteText(&buf).?);
}

test "logout leaves" {
    var buf: [64]u8 = undefined;
    var d: Conn = .{};
    _ = d.start();
    _ = d.onOpen();
    try testing.expectEqualStrings("live", d.statusText(&buf).text);
    try testing.expectEqual(Effect.leave, d.onLogout());
    try testing.expectEqual(Effect.none, d.onClose());
    try testing.expectEqual(Effect.none, d.onLogout());
}

test "stale events are ignored" {
    var c: Conn = .{};
    try testing.expectEqual(Effect.none, c.onOpen());
    try testing.expectEqual(Effect.none, c.onTimer());
    try testing.expectEqual(Effect.none, c.onCheck(.{ .status = 200, .path = "/" }));
    try testing.expectEqual(Effect.none, c.onClose());
    try testing.expectEqualStrings("view only", modeText(.none));
    try testing.expectEqualStrings("answer keys", modeText(.keys));
    try testing.expectEqualStrings("instructions", modeText(.instruct));
}
