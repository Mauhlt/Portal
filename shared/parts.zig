//! Large messages on the interactive WebSocket (`/ws`), desk -> device
//! (docs/protocol.md section 3, "Messages in parts"). A message (text or
//! binary) of more than `max_part` bytes goes out as a run of binary 'M'
//! frames of at most `max_part` payload bytes each (the bulk channel's
//! chunk, shared/bulk.zig), so the desk can send a screen update ('G')
//! between two parts: a big conversation never holds a keystroke echo
//! back by more than one part. WebSocket fragmentation cannot do this:
//! no data frame of another message may come between the fragments of
//! one (RFC 6455 section 5.4), and Portal's profile has none (ws.zig).
//!
//!   u8   'M'
//!   u8   flags   bit 0: the last part; bit 1: the message is binary
//!                (else text); the other bits are 0
//!   ...  the message's next bytes: exactly `max_data` in every part but
//!        the last, 1 to `max_data` in the last
//!
//! One message is in parts at a time: whole frames of other messages may
//! come between its parts, parts of another message never. A message of
//! at most `max_part` bytes is always one frame (so the first part is
//! never the last). The reassembled message is handled exactly like the
//! same message in one frame; a binary one never starts with 'M'.
//! Anything else is an error (the client reconnects), never a panic.

const std = @import("std");
const bulk = @import("bulk.zig");
const ws = @import("ws.zig");

pub const tag = 'M';
pub const header_len = 2;
/// Largest payload of one frame, 'M' or whole: messages over this go in
/// parts.
pub const max_part = bulk.chunk;
/// Message bytes in each part but the last.
pub const max_data = max_part - header_len;

const flag_last: u8 = 1;
const flag_binary: u8 = 2;

/// Whether a message of `len` bytes goes in parts.
pub fn inParts(len: usize) bool {
    return len > max_part;
}

/// The desk's side: the parts of one message, in order.
pub const Splitter = struct {
    msg: []const u8,
    binary: bool,
    off: usize = 0,

    pub const Part = struct {
        header: [header_len]u8,
        data: []const u8,
        last: bool,
    };

    pub fn init(msg: []const u8, opcode: ws.Opcode) Splitter {
        std.debug.assert(inParts(msg.len));
        std.debug.assert(opcode == .text or opcode == .binary);
        return .{ .msg = msg, .binary = opcode == .binary };
    }

    pub fn next(s: *Splitter) ?Part {
        if (s.off >= s.msg.len) return null;
        const n = @min(max_data, s.msg.len - s.off);
        const data = s.msg[s.off..][0..n];
        s.off += n;
        const last = s.off == s.msg.len;
        const flags: u8 = (if (last) flag_last else 0) | (if (s.binary) flag_binary else 0);
        return .{ .header = .{ tag, flags }, .data = data, .last = last };
    }
};

/// Sends `msg` (over `max_part` bytes) in parts: `ctx.frame(header, data)`
/// writes one 'M' frame, and `ctx.between()` runs after every part but the
/// last (the desk's screen update). False as soon as either one is.
pub fn send(msg: []const u8, opcode: ws.Opcode, ctx: anytype) bool {
    var s: Splitter = .init(msg, opcode);
    while (s.next()) |p| {
        if (!ctx.frame(&p.header, p.data)) return false;
        if (!p.last and !ctx.between()) return false;
    }
    return true;
}

/// The device's side: reassembles parts; every other frame passes through.
pub const Assembler = struct {
    buf: std.ArrayList(u8) = .empty,
    /// A message is being reassembled.
    active: bool = false,
    binary: bool = false,
    /// Largest reassembled message (the client's frame limit).
    limit: usize,

    pub const Error = error{ BadPart, TooLarge, OutOfMemory };

    pub fn deinit(a: *Assembler, gpa: std.mem.Allocator) void {
        std.crypto.secureZero(u8, a.buf.allocatedSlice());
        a.buf.deinit(gpa);
    }

    /// A new stream: forget a half message.
    pub fn reset(a: *Assembler) void {
        a.buf.clearRetainingCapacity();
        a.active = false;
    }

    /// `f` itself if it is not a part; null if it was a part and the
    /// message is not complete yet; the whole message (as a frame of its
    /// own opcode, with `f.len`) at its last part. The returned payload is
    /// valid until the next call.
    pub fn filter(a: *Assembler, gpa: std.mem.Allocator, f: ws.Frame) Error!?ws.Frame {
        if (f.opcode != .binary or f.payload.len == 0 or f.payload[0] != tag) return f;
        if (f.payload.len < header_len + 1) return error.BadPart;
        const flags = f.payload[1];
        if (flags & ~(flag_last | flag_binary) != 0) return error.BadPart;
        const last = flags & flag_last != 0;
        const binary = flags & flag_binary != 0;
        const data = f.payload[header_len..];
        if (!a.active) {
            if (last) return error.BadPart; // fits in one frame: never in parts
            if (binary and data[0] == tag) return error.BadPart; // no nesting
            a.buf.clearRetainingCapacity();
            a.active = true;
            a.binary = binary;
        } else if (binary != a.binary) return error.BadPart;
        if (!last and data.len != max_data) return error.BadPart;
        if (a.buf.items.len + data.len > a.limit) return error.TooLarge;
        try a.buf.appendSlice(gpa, data);
        if (!last) return null;
        a.active = false;
        return .{ .opcode = if (a.binary) .binary else .text, .payload = a.buf.items, .len = f.len };
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn partFrame(p: Splitter.Part, out: *std.ArrayList(u8)) !ws.Frame {
    out.clearRetainingCapacity();
    try out.appendSlice(testing.allocator, &p.header);
    try out.appendSlice(testing.allocator, p.data);
    return .{ .opcode = .binary, .payload = out.items, .len = out.items.len + 4 };
}

test "a message over max_part round-trips in parts; whole frames pass through between them" {
    const gpa = testing.allocator;
    const msg = try gpa.alloc(u8, 3 * max_data + 5);
    defer gpa.free(msg);
    for (msg, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    msg[0] = '{';
    var a: Assembler = .{ .limit = 1 << 20 };
    defer a.deinit(gpa);
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(gpa);
    var s: Splitter = .init(msg, .text);
    var parts: usize = 0;
    while (s.next()) |p| {
        parts += 1;
        try testing.expect(header_len + p.data.len <= max_part);
        const f = try partFrame(p, &scratch);
        const got = try a.filter(gpa, f);
        if (!p.last) {
            try testing.expect(got == null);
            // A screen frame between two parts passes through untouched.
            const g: ws.Frame = .{ .opcode = .binary, .payload = "G\x00", .len = 4 };
            try testing.expectEqualStrings("G\x00", (try a.filter(gpa, g)).?.payload);
        } else {
            const m = got.?;
            try testing.expectEqual(ws.Opcode.text, m.opcode);
            try testing.expectEqualSlices(u8, msg, m.payload);
            try testing.expectEqual(f.len, m.len);
        }
    }
    try testing.expectEqual(@as(usize, 4), parts);
    // Binary messages keep their opcode.
    msg[0] = 'I';
    s = .init(msg, .binary);
    var last: ?ws.Frame = null;
    while (s.next()) |p| last = try a.filter(gpa, try partFrame(p, &scratch));
    try testing.expectEqual(ws.Opcode.binary, last.?.opcode);
    try testing.expectEqualSlices(u8, msg, last.?.payload);
}

test "send: the screen goes between every two parts, never after the last" {
    const Rec = struct {
        log: [16]u8 = undefined,
        n: usize = 0,
        fail_at: ?usize = null,
        fn frame(r: *@This(), header: []const u8, data: []const u8) bool {
            if (header.len + data.len > max_part) return false;
            return r.put(if (header[1] & flag_last != 0) 'L' else 'p');
        }
        fn between(r: *@This()) bool {
            return r.put('G');
        }
        fn put(r: *@This(), c: u8) bool {
            if (r.fail_at == r.n) return false;
            r.log[r.n] = c;
            r.n += 1;
            return true;
        }
    };
    const msg: [2 * max_data + 1]u8 = @splat('x');
    var r: Rec = .{};
    try testing.expect(send(&msg, .text, &r));
    try testing.expectEqualStrings("pGpGL", r.log[0..r.n]);
    // A failed write or screen update stops the message.
    r = .{ .fail_at = 1 };
    try testing.expect(!send(&msg, .text, &r));
    try testing.expectEqualStrings("p", r.log[0..r.n]);
}

test "only messages over max_part go in parts" {
    try testing.expect(!inParts(max_part));
    try testing.expect(inParts(max_part + 1));
    const msg: [max_part + 1]u8 = @splat('x');
    var s: Splitter = .init(&msg, .text);
    try testing.expectEqual(max_data, s.next().?.data.len);
    const p = s.next().?;
    try testing.expect(p.last);
    try testing.expectEqual(@as(usize, 3), p.data.len);
    try testing.expect(s.next() == null);
}

test "malformed parts are errors" {
    const gpa = testing.allocator;
    var a: Assembler = .{ .limit = 4 * max_data };
    defer a.deinit(gpa);
    const full: [header_len + max_data]u8 = .{ tag, 0 } ++ @as([max_data]u8, @splat('a'));
    const bin: [header_len + max_data]u8 = .{ tag, flag_binary } ++ @as([max_data]u8, @splat('a'));
    const f = struct {
        fn f(p: []const u8) ws.Frame {
            return .{ .opcode = .binary, .payload = p, .len = p.len };
        }
    }.f;
    // A whole message as one "last" part, an empty part, unknown flags.
    try testing.expectError(error.BadPart, a.filter(gpa, f(&.{ tag, flag_last, 'x' })));
    try testing.expectError(error.BadPart, a.filter(gpa, f(&.{ tag, 0 })));
    try testing.expectError(error.BadPart, a.filter(gpa, f(&.{ tag, 4, 'x' })));
    // A short middle part.
    try testing.expect(try a.filter(gpa, f(&full)) == null);
    try testing.expectError(error.BadPart, a.filter(gpa, f(&.{ tag, 0, 'x' })));
    // Text and binary parts mixed in one message.
    a.reset();
    try testing.expect(try a.filter(gpa, f(&full)) == null);
    try testing.expectError(error.BadPart, a.filter(gpa, f(&.{ tag, flag_binary | flag_last, 'x' })));
    // A binary message that is itself a part.
    a.reset();
    var nested = bin;
    nested[header_len] = tag;
    try testing.expectError(error.BadPart, a.filter(gpa, f(&nested)));
    // Over the limit.
    a.reset();
    for (0..4) |_| try testing.expect(try a.filter(gpa, f(&full)) == null);
    try testing.expectError(error.TooLarge, a.filter(gpa, f(&full)));
    // Text frames and other binary frames pass through.
    const t: ws.Frame = .{ .opcode = .text, .payload = "M", .len = 3 };
    try testing.expectEqualStrings("M", (try a.filter(gpa, t)).?.payload);
}
