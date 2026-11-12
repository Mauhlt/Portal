//! WebSocket (RFC 6455) framing for both directions, used by the server
//! (src/web.zig: masked client frames in, unmasked frames out), the native
//! client (client/src/net/client.zig, src/sync_cli.zig: the reverse) and
//! the e2e tests.
//!
//! Portal's profile is strict, and the same in every program: no
//! extensions (RSV bits are an error), no fragmentation (FIN always set,
//! no continuation frames), known opcodes only, control frames of at most
//! 125 bytes, minimal length encodings, a 64-bit length with its top bit
//! clear, frames from a client masked and frames from a server not.
//! Anything else is an error, never a panic.

const std = @import("std");

pub const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Protocol limit for client text frames (docs/protocol.md section 4).
pub const max_client_payload = 4096;

/// Longest frame header: 2 + 8 (64-bit length) + 4 (mask).
pub const max_header_len = 14;

pub const Opcode = enum(u4) {
    continuation = 0,
    text = 1,
    binary = 2,
    close = 8,
    ping = 9,
    pong = 10,
    _,

    pub fn isControl(op: Opcode) bool {
        return @intFromEnum(op) >= 8;
    }
};

/// Who sent the frames being parsed: clients must mask, servers must not.
pub const Sender = enum { client, server };

pub const FrameError = error{
    /// RSV bits, a reserved opcode, an oversized control frame, a
    /// non-minimal or 64-bit-overflowing length.
    ProtocolError,
    /// FIN clear, or a continuation frame.
    Fragmented,
    /// A client frame without a mask, or a server frame with one.
    BadMask,
    /// Over the caller's payload limit.
    TooLarge,
};

pub const Header = struct {
    opcode: Opcode,
    payload_len: usize,
    /// The masking key (frames from a client), null for server frames.
    mask: ?[4]u8,
    /// Bytes of header before the payload.
    len: usize,
};

/// Parses the frame header at the start of `buf`, or returns null if more
/// bytes are needed for it (the payload may still be incomplete).
pub fn parseHeader(buf: []const u8, from: Sender, max_payload: usize) FrameError!?Header {
    if (buf.len < 2) return null;
    const b0 = buf[0];
    const b1 = buf[1];
    if (b0 & 0x70 != 0) return error.ProtocolError; // RSV bits: no extensions negotiated
    const opcode: Opcode = @enumFromInt(@as(u4, @truncate(b0)));
    switch (opcode) {
        .text, .binary, .close, .ping, .pong => {},
        .continuation => return error.Fragmented,
        _ => return error.ProtocolError,
    }
    if (b0 & 0x80 == 0) return error.Fragmented;
    const masked = b1 & 0x80 != 0;
    if (masked != (from == .client)) return error.BadMask;
    const len7: u8 = b1 & 0x7f;
    var len: u64 = len7;
    var off: usize = 2;
    if (len7 == 126) {
        if (buf.len < 4) return null;
        len = std.mem.readInt(u16, buf[2..4], .big);
        if (len < 126) return error.ProtocolError; // non-minimal
        off = 4;
    } else if (len7 == 127) {
        if (buf.len < 10) return null;
        len = std.mem.readInt(u64, buf[2..10], .big);
        if (len >> 63 != 0 or len <= 0xffff) return error.ProtocolError; // MSB set, or non-minimal
        off = 10;
    }
    if (opcode.isControl() and len > 125) return error.ProtocolError;
    if (len > max_payload) return error.TooLarge;
    var mask: ?[4]u8 = null;
    if (masked) {
        if (buf.len < off + 4) return null;
        mask = buf[off..][0..4].*;
        off += 4;
    }
    return .{ .opcode = opcode, .payload_len = @intCast(len), .mask = mask, .len = off };
}

pub const Frame = struct {
    opcode: Opcode,
    payload: []const u8,
    /// Bytes consumed from the input buffer.
    len: usize,
};

/// Parses one complete unmasked server frame at the start of `buf`, or
/// returns null if more bytes are needed.
pub fn parseServerFrame(buf: []const u8, max_payload: usize) FrameError!?Frame {
    const h = (try parseHeader(buf, .server, max_payload)) orelse return null;
    if (buf.len - h.len < h.payload_len) return null;
    return .{ .opcode = h.opcode, .payload = buf[h.len..][0..h.payload_len], .len = h.len + h.payload_len };
}

/// XORs `payload` with the masking key, in place (masks and unmasks).
pub fn applyMask(payload: []u8, mask: [4]u8) void {
    for (payload, 0..) |*b, i| b.* ^= mask[i & 3];
}

/// Encodes a frame header (FIN set, minimal length) into `out` and returns
/// it. With `mask` the frame is a client frame and the key is included.
pub fn encodeHeader(out: *[max_header_len]u8, opcode: Opcode, payload_len: usize, mask: ?[4]u8) error{TooLarge}![]u8 {
    if (opcode.isControl() and payload_len > 125) return error.TooLarge;
    const m: u8 = if (mask != null) 0x80 else 0;
    out[0] = 0x80 | @as(u8, @intFromEnum(opcode));
    var n: usize = 2;
    if (payload_len < 126) {
        out[1] = m | @as(u8, @intCast(payload_len));
    } else if (payload_len <= 0xffff) {
        out[1] = m | 126;
        std.mem.writeInt(u16, out[2..4], @intCast(payload_len), .big);
        n = 4;
    } else {
        out[1] = m | 127;
        std.mem.writeInt(u64, out[2..10], payload_len, .big);
        n = 10;
    }
    if (mask) |k| {
        out[n..][0..4].* = k;
        n += 4;
    }
    return out[0..n];
}

/// Encodes one masked client frame into `out` and returns the used slice.
pub fn encodeClientFrame(out: []u8, opcode: Opcode, payload: []const u8, mask: [4]u8) error{ TooLarge, NoSpaceLeft }![]u8 {
    var hbuf: [max_header_len]u8 = undefined;
    const h = try encodeHeader(&hbuf, opcode, payload.len, mask);
    if (out.len < h.len + payload.len) return error.NoSpaceLeft;
    @memcpy(out[0..h.len], h);
    const body = out[h.len..][0..payload.len];
    @memcpy(body, payload);
    applyMask(body, mask);
    return out[0 .. h.len + payload.len];
}

/// Writes one unmasked server frame and flushes.
pub fn writeServerFrame(w: *std.Io.Writer, opcode: Opcode, payload: []const u8) !void {
    var hbuf: [max_header_len]u8 = undefined;
    try w.writeAll(try encodeHeader(&hbuf, opcode, payload.len, null));
    try w.writeAll(payload);
    try w.flush();
}

/// Sec-WebSocket-Key from 16 random bytes.
pub fn makeKey(random16: [16]u8) [24]u8 {
    var out: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &random16);
    return out;
}

/// The Sec-WebSocket-Accept value for `key`, which must be the base64 of
/// 16 bytes (RFC 6455 4.2.1): servers refuse other keys, and a client
/// only ever computes it for its own `makeKey`.
pub fn accept(key: []const u8) error{BadKey}![28]u8 {
    var decoded: [16]u8 = undefined;
    if (key.len != 24) return error.BadKey;
    std.base64.standard.Decoder.decode(&decoded, key) catch return error.BadKey;
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(key);
    sha.update(guid);
    var digest: [20]u8 = undefined;
    sha.final(&digest);
    var out: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &digest);
    return out;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "client frames are masked and round-trip through the server parser" {
    var buf: [8192]u8 = undefined;
    const mask = [4]u8{ 0x37, 0xfa, 0x21, 0x3d };
    // RFC 6455 section 5.7: masked "Hello".
    const f = try encodeClientFrame(&buf, .text, "Hello", mask);
    try testing.expectEqualSlices(u8, &.{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 }, f);
    const h = (try parseHeader(f, .client, 4096)).?;
    try testing.expectEqual(@as(usize, 6), h.len);
    try testing.expectEqual(@as(usize, 5), h.payload_len);
    applyMask(f[h.len..], h.mask.?);
    try testing.expectEqualStrings("Hello", f[h.len..]);

    var big: [4096]u8 = undefined;
    @memset(&big, 'k');
    const f2 = try encodeClientFrame(&buf, .text, &big, mask);
    try testing.expectEqual(@as(u8, 0x80 | 126), f2[1]);
    const h2 = (try parseHeader(f2, .client, 4096)).?;
    try testing.expectEqual(@as(usize, 8), h2.len);
    applyMask(f2[h2.len..], h2.mask.?);
    try testing.expectEqualSlices(u8, &big, f2[h2.len..]);

    try testing.expectError(error.NoSpaceLeft, encodeClientFrame(buf[0..10], .text, "Hello", mask));
    try testing.expectError(error.TooLarge, encodeClientFrame(&buf, .ping, &big, mask));
}

test "server frames: writing and parsing" {
    var buf: [70000]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeServerFrame(&w, .text, "hi");
    try testing.expectEqualSlices(u8, &.{ 0x81, 2, 'h', 'i' }, w.buffered());
    var w2: std.Io.Writer = .fixed(&buf);
    const p: [200]u8 = @splat('x');
    try writeServerFrame(&w2, .binary, &p);
    try testing.expectEqualSlices(u8, &.{ 0x82, 126, 0, 200 }, w2.buffered()[0..4]);
    try testing.expectEqual(@as(usize, 200), (try parseServerFrame(w2.buffered(), 1 << 20)).?.payload.len);
    var w3: std.Io.Writer = .fixed(&buf);
    const p3: [0x10000]u8 = @splat('y');
    try writeServerFrame(&w3, .binary, &p3);
    try testing.expectEqualSlices(u8, &.{ 0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0 }, w3.buffered()[0..10]);
    try testing.expectEqual(@as(usize, 0x10000), (try parseServerFrame(w3.buffered(), 1 << 20)).?.payload.len);

    const max = 1 << 20;
    // Unmasked text "Hi" followed by part of the next frame.
    const f = try parseServerFrame(&.{ 0x81, 0x02, 'H', 'i', 0x82 }, max);
    try testing.expectEqual(Opcode.text, f.?.opcode);
    try testing.expectEqualStrings("Hi", f.?.payload);
    try testing.expectEqual(@as(usize, 4), f.?.len);
    // Incomplete.
    try testing.expectEqual(@as(?Frame, null), try parseServerFrame(&.{0x82}, max));
    try testing.expectEqual(@as(?Frame, null), try parseServerFrame(&.{ 0x82, 0x05, 1, 2 }, max));
    try testing.expectEqual(@as(?Frame, null), try parseServerFrame(&.{ 0x82, 126, 0x01 }, max));
}

test "every rule applies in both directions" {
    const max = 4096;
    for ([_]Sender{ .client, .server }) |from| {
        const m: u8 = if (from == .client) 0x80 else 0;
        const k = [_]u8{ 0, 0, 0, 0 };
        try testing.expectEqual(@as(?Header, null), try parseHeader(&.{0x81}, from, max));
        try testing.expectError(error.BadMask, parseHeader(&.{ 0x81, 0x02 ^ 0x80 ^ m, 0, 0, 0, 0 }, from, max));
        try testing.expectError(error.Fragmented, parseHeader(&[_]u8{ 0x01, m } ++ k, from, max));
        try testing.expectError(error.Fragmented, parseHeader(&[_]u8{ 0x80, m } ++ k, from, max));
        try testing.expectError(error.ProtocolError, parseHeader(&[_]u8{ 0xC1, m } ++ k, from, max)); // RSV1
        try testing.expectError(error.ProtocolError, parseHeader(&[_]u8{ 0x83, m } ++ k, from, max)); // reserved opcode
        try testing.expectError(error.ProtocolError, parseHeader(&[_]u8{ 0x89, m | 126, 0, 200 } ++ k, from, max)); // big ping
        try testing.expectError(error.ProtocolError, parseHeader(&[_]u8{ 0x82, m | 126, 0, 5 } ++ k, from, max)); // non-minimal 16
        try testing.expectError(error.ProtocolError, parseHeader(&[_]u8{ 0x82, m | 127, 0, 0, 0, 0, 0, 0, 0xff, 0xff } ++ k, from, max)); // non-minimal 64
        try testing.expectError(error.ProtocolError, parseHeader(&[_]u8{ 0x82, m | 127, 0x80, 0, 0, 0, 0, 0, 0, 0 } ++ k, from, max)); // MSB
        try testing.expectError(error.TooLarge, parseHeader(&[_]u8{ 0x82, m | 127, 0, 0, 0, 1, 0, 0, 0, 0 } ++ k, from, max));
        try testing.expectError(error.TooLarge, parseHeader(&[_]u8{ 0x82, m | 126, 0x20, 0x00 } ++ k, from, max));
    }
    // A client header is incomplete until its mask is there.
    try testing.expectEqual(@as(?Header, null), try parseHeader(&.{ 0x81, 0x82, 1, 2, 3 }, .client, max));
}

test "fuzz: arbitrary bytes never panic" {
    var prng = std.Random.DefaultPrng.init(1);
    const rand = prng.random();
    var buf: [64]u8 = undefined;
    for (0..100000) |_| {
        const n = rand.uintLessThan(usize, buf.len);
        rand.bytes(buf[0..n]);
        if (parseServerFrame(buf[0..n], 32)) |maybe| {
            if (maybe) |fr| try testing.expect(fr.len <= n and fr.payload.len <= 32);
        } else |_| {}
        if (parseHeader(buf[0..n], .client, 32)) |maybe| {
            if (maybe) |h| try testing.expect(h.len <= n and h.payload_len <= 32 and h.mask != null);
        } else |_| {}
    }
}

test "handshake key and accept (RFC 6455 section 1.3)" {
    const a = try accept("dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &a);
    const k = makeKey(.{ 0x74, 0x68, 0x65, 0x20, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6e, 0x6f, 0x6e, 0x63, 0x65 });
    try testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", &k);
    try testing.expectError(error.BadKey, accept("short"));
    try testing.expectError(error.BadKey, accept("!!!!!!!!!!!!!!!!!!!!!!=="));
}
