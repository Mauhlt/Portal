//! PEM (RFC 7468) for one certificate: writing (`portal ca export`, the
//! native client's pinned CA file) and reading a CA file a person gives.

const std = @import("std");

pub const begin = "-----BEGIN CERTIFICATE-----";
pub const end = "-----END CERTIFICATE-----";

/// Writes `der` as one CERTIFICATE block with 64-column lines.
pub fn write(w: *std.Io.Writer, der: []const u8) std.Io.Writer.Error!void {
    try w.writeAll(begin ++ "\n");
    var i: usize = 0;
    while (i < der.len) {
        const chunk = der[i..@min(der.len, i + 48)];
        var line: [64]u8 = undefined;
        try w.writeAll(std.base64.standard.Encoder.encode(&line, chunk));
        try w.writeAll("\n");
        i += chunk.len;
    }
    try w.writeAll(end ++ "\n");
}

/// `write` into a new allocation.
pub fn alloc(gpa: std.mem.Allocator, der: []const u8) error{OutOfMemory}![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    write(&out.writer, der) catch return error.OutOfMemory;
    return out.toOwnedSlice();
}

pub const DecodeError = error{ NotPem, MoreThanOneCertificate, TooLarge, BadBase64 };

/// Whether `data` holds a PEM certificate block (else it may be DER).
pub fn isPem(data: []const u8) bool {
    return std.mem.indexOf(u8, data, begin) != null;
}

/// Decodes the one CERTIFICATE block in `data` into `out`. Line breaks
/// (LF or CRLF) and spaces inside the block are ignored; a second block is
/// an error.
pub fn decode(data: []const u8, out: []u8) DecodeError![]u8 {
    const b = std.mem.indexOf(u8, data, begin) orelse return error.NotPem;
    const body_start = b + begin.len;
    const e = std.mem.indexOfPos(u8, data, body_start, end) orelse return error.NotPem;
    if (std.mem.indexOfPos(u8, data, e, begin) != null) return error.MoreThanOneCertificate;
    const dec = std.base64.standard.Decoder;
    // Decode in 4-character groups so no whole-body copy is needed.
    var quad: [4]u8 = undefined;
    var q: usize = 0;
    var n: usize = 0;
    var done = false;
    for (data[body_start..e]) |ch| {
        if (ch == '\r' or ch == '\n' or ch == ' ' or ch == '\t') continue;
        if (done) return error.BadBase64; // data after the padding
        quad[q] = ch;
        q += 1;
        if (q < 4) continue;
        q = 0;
        const len = dec.calcSizeForSlice(&quad) catch return error.BadBase64;
        if (len > out.len - n) return error.TooLarge;
        dec.decode(out[n..][0..len], &quad) catch return error.BadBase64;
        n += len;
        done = len < 3;
    }
    if (q != 0 or n == 0) return error.BadBase64;
    return out[0..n];
}

const testing = std.testing;

test "write and decode round-trip" {
    var der: [300]u8 = undefined;
    for (&der, 0..) |*x, i| x.* = @truncate(i * 7);
    for ([_]usize{ 1, 2, 3, 47, 48, 49, 300 }) |len| {
        var buf: [1024]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try write(&w, der[0..len]);
        try testing.expect(isPem(w.buffered()));
        var back: [300]u8 = undefined;
        try testing.expectEqualSlices(u8, der[0..len], try decode(w.buffered(), &back));
        const a = try alloc(testing.allocator, der[0..len]);
        defer testing.allocator.free(a);
        try testing.expectEqualStrings(w.buffered(), a);
        var small: [1]u8 = undefined;
        if (len > 1) try testing.expectError(error.TooLarge, decode(w.buffered(), &small));
    }
    var out: [16]u8 = undefined;
    try testing.expectError(error.NotPem, decode("hello", &out));
    try testing.expectError(error.BadBase64, decode(begin ++ "\n!!!!\n" ++ end, &out));
    try testing.expectError(error.BadBase64, decode(begin ++ "\nQUJD\nQQ\n" ++ end, &out));
    try testing.expectError(error.BadBase64, decode(begin ++ "\nQQ==QUJD\n" ++ end, &out));
    try testing.expectError(error.BadBase64, decode(begin ++ "\n" ++ end, &out));
    try testing.expectError(error.MoreThanOneCertificate, decode(begin ++ "\nQUJD\n" ++ end ++ begin ++ "\nQUJD\n" ++ end, &out));
    try testing.expectEqualStrings("ABC", try decode(begin ++ "\r\nQU\r\nJD\r\n" ++ end, &out));
}
