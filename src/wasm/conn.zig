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

const std = @import("std");
const proto = @import("proto.zig");

pub const first_retry_ms: u32 = 1000;
pub const max_retry_ms: u32 = 15000;

pub const State = enum { idle, connecting, live, waiting, checking, ended, leaving };

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
};

pub const Status = enum { neutral, ok, bad };

pub const Conn = struct {
    state: State = .idle,
    retry_ms: u32 = first_retry_ms,
    exit_code: i64 = 0,

    pub fn start(c: *Conn) Effect {
        if (c.state != .idle) return .none;
        c.state = .connecting;
        return .open;
    }

    pub fn onOpen(c: *Conn) Effect {
        if (c.state != .connecting) return .none;
        c.state = .live;
        c.retry_ms = first_retry_ms;
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
        // Signed in again (or the network failed: just try the socket,
        // its failure brings us back here after the next backoff step).
        c.state = .connecting;
        return .open;
    }

    pub fn onExit(c: *Conn, code: i64) Effect {
        if (c.state == .leaving) return .none;
        c.state = .ended;
        c.exit_code = code;
        return .none;
    }

    pub fn onLogout(c: *Conn) Effect {
        if (c.state == .leaving) return .none;
        c.state = .leaving;
        return .leave;
    }

    /// Header status text; `buf` holds formatted variants.
    pub fn statusText(c: *const Conn, buf: []u8) struct { text: []const u8, kind: Status } {
        return switch (c.state) {
            .idle, .connecting => .{ .text = "connecting…", .kind = .neutral },
            .live => .{ .text = "live", .kind = .ok },
            .waiting, .checking => .{ .text = "reconnecting…", .kind = .bad },
            .ended => .{
                .text = std.fmt.bufPrint(buf, "session ended (exit {d})", .{c.exit_code}) catch "session ended",
                .kind = .bad,
            },
            .leaving => .{ .text = "signed out", .kind = .bad },
        };
    }
};

pub fn modeText(p: proto.Policy) []const u8 {
    return switch (p) {
        .none => "view only",
        .keys => "answer keys",
        .instruct => "instructions",
        .text => "typing allowed",
    };
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

test "exit stops reconnecting; logout leaves" {
    var c: Conn = .{};
    _ = c.start();
    _ = c.onOpen();
    _ = c.onExit(3);
    try testing.expectEqual(Effect.none, c.onClose());
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("session ended (exit 3)", c.statusText(&buf).text);
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
