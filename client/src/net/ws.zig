//! WebSocket (RFC 6455) client framing.
//!
//! Client frames are always masked with a fresh random key. Server frames are
//! parsed incrementally from a byte buffer; anything unexpected (masked server
//! frames, RSV bits, fragmentation, reserved opcodes, oversized payloads) is
//! an error, never a panic.

const std = @import("std");

pub const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Protocol limit for client text frames (docs/protocol.md section 4).
pub const max_client_payload = 4096;

pub const Opcode = enum(u4) {
    continuation = 0,
    text = 1,
    binary = 2,
    close = 8,
    ping = 9,
    pong = 10,
    _,
};

pub const FrameError = error{ ProtocolError, MaskedServerFrame, Fragmented, TooLarge };

/// Encodes one masked client frame into `out` and returns the used slice.
pub fn encodeClientFrame(out: []u8, opcode: Opcode, payload: []const u8, mask: [4]u8) error{ TooLarge, NoSpaceLeft }![]u8 {
    if (payload.len > 0xffff) return error.TooLarge; // never needed by this client
    const is_control = @intFromEnum(opcode) >= 8;
    if (is_control and payload.len > 125) return error.TooLarge;
    const hlen: usize = if (payload.len < 126) 2 else 4;
    const total = hlen + 4 + payload.len;
    if (out.len < total) return error.NoSpaceLeft;
    out[0] = 0x80 | @as(u8, @intFromEnum(opcode));
    if (payload.len < 126) {
        out[1] = 0x80 | @as(u8, @intCast(payload.len));
    } else {
        out[1] = 0x80 | 126;
        std.mem.writeInt(u16, out[2..4], @intCast(payload.len), .big);
    }
    @memcpy(out[hlen..][0..4], &mask);
    const body = out[hlen + 4 ..][0..payload.len];
    for (payload, 0..) |b, i| body[i] = b ^ mask[i & 3];
    return out[0..total];
}

pub const Frame = struct {
    opcode: Opcode,
    payload: []const u8,
    /// Bytes consumed from the input buffer.
    len: usize,
};

/// Parses one complete server frame at the start of `buf`, or returns null if
/// more bytes are needed.
pub fn parseServerFrame(buf: []const u8, max_payload: usize) FrameError!?Frame {
    if (buf.len < 2) return null;
    const b0 = buf[0];
    const b1 = buf[1];
    if (b0 & 0x70 != 0) return error.ProtocolError;
    const opcode: Opcode = @enumFromInt(@as(u4, @truncate(b0)));
    switch (opcode) {
        .text, .binary, .close, .ping, .pong => {},
        .continuation => return error.Fragmented,
        _ => return error.ProtocolError,
    }
    if (b0 & 0x80 == 0) return error.Fragmented;
    if (b1 & 0x80 != 0) return error.MaskedServerFrame;
    const len7: u8 = b1 & 0x7f;
    var len: u64 = len7;
    var off: usize = 2;
    if (len7 == 126) {
        if (buf.len < 4) return null;
        len = std.mem.readInt(u16, buf[2..4], .big);
        if (len < 126) return error.ProtocolError; // non-minimal encoding
        off = 4;
    } else if (len7 == 127) {
        if (buf.len < 10) return null;
        len = std.mem.readInt(u64, buf[2..10], .big);
        if (len >> 63 != 0 or len <= 0xffff) return error.ProtocolError;
        off = 10;
    }
    if (@intFromEnum(opcode) >= 8 and len > 125) return error.ProtocolError;
    if (len > max_payload) return error.TooLarge;
    const n: usize = @intCast(len);
    if (buf.len - off < n) return null;
    return .{ .opcode = opcode, .payload = buf[off..][0..n], .len = off + n };
}

/// Sec-WebSocket-Key from 16 random bytes.
pub fn makeKey(random16: [16]u8) [24]u8 {
    var out: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &random16);
    return out;
}

/// The Sec-WebSocket-Accept value the server must answer with.
pub fn expectedAccept(key: []const u8) [28]u8 {
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

fn unmaskClientFrame(frame: []const u8, out: []u8) ![]u8 {
    // Minimal server-side decoder used only to check our encoder.
    try testing.expect(frame[1] & 0x80 != 0);
    var len: usize = frame[1] & 0x7f;
    var off: usize = 2;
    if (len == 126) {
        len = std.mem.readInt(u16, frame[2..4], .big);
        off = 4;
    }
    const mask = frame[off..][0..4];
    off += 4;
    try testing.expectEqual(frame.len, off + len);
    for (frame[off..], 0..) |b, i| out[i] = b ^ mask[i & 3];
    return out[0..len];
}

test "client frames are masked and round-trip" {
    var buf: [8192]u8 = undefined;
    var back: [8192]u8 = undefined;
    const mask = [4]u8{ 0x37, 0xfa, 0x21, 0x3d };
    // RFC 6455 section 5.7: masked "Hello".
    const f = try encodeClientFrame(&buf, .text, "Hello", mask);
    try testing.expectEqualSlices(u8, &.{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 }, f);
    try testing.expectEqualStrings("Hello", try unmaskClientFrame(f, &back));

    var big: [4096]u8 = undefined;
    @memset(&big, 'k');
    const f2 = try encodeClientFrame(&buf, .text, &big, mask);
    try testing.expectEqual(@as(u8, 0x80 | 126), f2[1]);
    try testing.expectEqualSlices(u8, &big, try unmaskClientFrame(f2, &back));

    try testing.expectError(error.NoSpaceLeft, encodeClientFrame(buf[0..10], .text, "Hello", mask));
    try testing.expectError(error.TooLarge, encodeClientFrame(&buf, .ping, &big, mask));
}

test "server frame parsing" {
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
    // 16-bit length.
    var long: [4 + 300]u8 = undefined;
    long[0] = 0x82;
    long[1] = 126;
    std.mem.writeInt(u16, long[2..4], 300, .big);
    try testing.expectEqual(@as(usize, 300), (try parseServerFrame(&long, max)).?.payload.len);
    // Errors.
    try testing.expectError(error.MaskedServerFrame, parseServerFrame(&.{ 0x81, 0x82, 0, 0, 0, 0, 1, 2 }, max));
    try testing.expectError(error.Fragmented, parseServerFrame(&.{ 0x01, 0x00 }, max));
    try testing.expectError(error.Fragmented, parseServerFrame(&.{ 0x80, 0x00 }, max));
    try testing.expectError(error.ProtocolError, parseServerFrame(&.{ 0xC1, 0x00 }, max));
    try testing.expectError(error.ProtocolError, parseServerFrame(&.{ 0x83, 0x00 }, max));
    try testing.expectError(error.ProtocolError, parseServerFrame(&.{ 0x89, 126, 0, 200 }, max));
    try testing.expectError(error.ProtocolError, parseServerFrame(&.{ 0x82, 126, 0, 5 }, max));
    try testing.expectError(error.TooLarge, parseServerFrame(&.{ 0x82, 127, 0, 0, 0, 1, 0, 0, 0, 0 }, max));
    try testing.expectError(error.ProtocolError, parseServerFrame(&.{ 0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0 }, max));
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
    }
}

test "handshake accept (RFC 6455 section 1.3)" {
    const a = expectedAccept("dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &a);
    const k = makeKey(.{ 0x74, 0x68, 0x65, 0x20, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6e, 0x6f, 0x6e, 0x63, 0x65 });
    try testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", &k);
}
