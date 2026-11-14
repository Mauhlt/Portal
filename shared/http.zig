//! HTTP/1.1 pieces both ends of Portal's HTTP share: the syntax checks the
//! server's request parser (src/http1.zig) and the native client's
//! response parser (client/src/net/http.zig) both apply. Requests and responses are still parsed separately;
//! they genuinely differ. Pure functions over byte slices.

const std = @import("std");

/// The length of the head including its terminating CRLFCRLF, or null if
/// it is not complete yet.
pub fn findHeadEnd(buf: []const u8) ?usize {
    const i = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse return null;
    return i + 4;
}

/// tchar (RFC 9110 5.6.2): the characters of methods and header names.
pub fn isTokenChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

/// A non-empty token.
pub fn isToken(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!isTokenChar(c)) return false;
    return true;
}

/// A header field value (already trimmed): no control characters but tab,
/// so no CR / LF (response splitting, request smuggling) and no NUL.
pub fn validValue(v: []const u8) bool {
    for (v) |c| {
        if (c == '\t') continue;
        if (c < 0x20 or c == 0x7f) return false;
    }
    return true;
}

const testing = std.testing;

test "head end, tokens, values" {
    try testing.expectEqual(@as(?usize, null), findHeadEnd("GET / HTTP/1.1\r\nA\r\n"));
    try testing.expectEqual(@as(?usize, 18), findHeadEnd("GET / HTTP/1.1\r\n\r\nrest"));
    try testing.expect(isToken("Content-Length") and isToken("x!#$%&'*+-.^_`|~9"));
    try testing.expect(!isToken("") and !isToken("Bad Name") and !isToken("a:b") and !isToken("a\tb"));
    try testing.expect(validValue("a b\tc") and validValue(""));
    try testing.expect(!validValue("a\r\nb") and !validValue("a\x00") and !validValue("\x7f"));
}

