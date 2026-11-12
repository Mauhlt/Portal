//! Keyboard input from the desktop's own Portal window, encoded as the VT
//! bytes a terminal would send (xterm conventions). Unlike remote viewers
//! (keymap.zig), the person at the desk has full control, so nothing is
//! filtered here; pasted text is only sanitised so it cannot smuggle escape
//! sequences (e.g. a fake end-of-paste marker) into the program.
//!
//! Pure functions, no I/O: the GUI host (gui.zig) writes the results with
//! Session.writeInput.

const std = @import("std");
const input = @import("portal_ui").input;
const Key = input.Key;
const Mods = input.Mods;

/// Large enough for any sequence produced here.
pub const max_seq = 16;

/// xterm modifier parameter: 1 + shift + 2*alt + 4*ctrl (1 = none).
fn modParam(m: Mods) u8 {
    var p: u8 = 1;
    if (m.shift) p += 1;
    if (m.alt) p += 2;
    if (m.ctrl) p += 4;
    return p;
}

/// Bytes for a special key. `app_cursor` is DECCKM (vt.Terminal.appCursor).
/// Returns an empty slice for keys that send nothing.
pub fn encodeKey(key: Key, mods: Mods, app_cursor: bool, out: *[max_seq]u8) []const u8 {
    const mp = modParam(.{ .shift = mods.shift, .alt = mods.alt, .ctrl = mods.ctrl });
    switch (key) {
        .enter => return withAlt(mods, "\r", out),
        .escape => return withAlt(mods, "\x1b", out),
        .backspace => return withAlt(mods, if (mods.ctrl) "\x08" else "\x7f", out),
        .tab => {
            if (mods.shift) return copy("\x1b[Z", out);
            return withAlt(mods, "\t", out);
        },
        .up => return cursorKey('A', mp, app_cursor, out),
        .down => return cursorKey('B', mp, app_cursor, out),
        .right => return cursorKey('C', mp, app_cursor, out),
        .left => return cursorKey('D', mp, app_cursor, out),
        .home => return cursorKey('H', mp, app_cursor, out),
        .end => return cursorKey('F', mp, app_cursor, out),
        .insert => return tildeKey(2, mp, out),
        .delete => return tildeKey(3, mp, out),
        .page_up => return tildeKey(5, mp, out),
        .page_down => return tildeKey(6, mp, out),
        .f1 => return ss3Key('P', mp, out),
        .f2 => return ss3Key('Q', mp, out),
        .f3 => return ss3Key('R', mp, out),
        .f4 => return ss3Key('S', mp, out),
        .f5 => return tildeKey(15, mp, out),
        .f6 => return tildeKey(17, mp, out),
        .f7 => return tildeKey(18, mp, out),
        .f8 => return tildeKey(19, mp, out),
        .f9 => return tildeKey(20, mp, out),
        .f10 => return tildeKey(21, mp, out),
        .f11 => return tildeKey(23, mp, out),
        .f12 => return tildeKey(24, mp, out),
    }
}

fn copy(s: []const u8, out: *[max_seq]u8) []const u8 {
    @memcpy(out[0..s.len], s);
    return out[0..s.len];
}

fn withAlt(mods: Mods, s: []const u8, out: *[max_seq]u8) []const u8 {
    if (!mods.alt) return copy(s, out);
    out[0] = 0x1b;
    @memcpy(out[1..][0..s.len], s);
    return out[0 .. 1 + s.len];
}

/// Arrows, Home, End: CSI x / SS3 x (DECCKM), CSI 1;m x with modifiers.
fn cursorKey(final: u8, mp: u8, app_cursor: bool, out: *[max_seq]u8) []const u8 {
    if (mp != 1) return std.fmt.bufPrint(out, "\x1b[1;{d}{c}", .{ mp, final }) catch out[0..0];
    out[0] = 0x1b;
    out[1] = if (app_cursor) 'O' else '[';
    out[2] = final;
    return out[0..3];
}

/// F1-F4: SS3 x, CSI 1;m x with modifiers.
fn ss3Key(final: u8, mp: u8, out: *[max_seq]u8) []const u8 {
    if (mp != 1) return std.fmt.bufPrint(out, "\x1b[1;{d}{c}", .{ mp, final }) catch out[0..0];
    return std.fmt.bufPrint(out, "\x1bO{c}", .{final}) catch out[0..0];
}

/// CSI n ~, CSI n;m ~ with modifiers.
fn tildeKey(n: u8, mp: u8, out: *[max_seq]u8) []const u8 {
    if (mp != 1) return std.fmt.bufPrint(out, "\x1b[{d};{d}~", .{ n, mp }) catch out[0..0];
    return std.fmt.bufPrint(out, "\x1b[{d}~", .{n}) catch out[0..0];
}

/// Bytes for a typed character. Ctrl+letter (and Ctrl+@ [ \ ] ^ _ space /)
/// become C0 controls; Alt prefixes ESC. Returns an empty slice for
/// characters that send nothing (surrogates, controls, Ctrl+other).
pub fn encodeChar(cp: u21, mods: Mods, out: *[max_seq]u8) []const u8 {
    if (cp >= 0xD800 and cp <= 0xDFFF) return out[0..0];
    if (cp > 0x10FFFF) return out[0..0];
    var start: usize = 0;
    if (mods.alt) {
        out[0] = 0x1b;
        start = 1;
    }
    if (mods.ctrl) {
        const c: ?u8 = switch (cp) {
            'a'...'z' => @intCast(cp - 'a' + 1),
            'A'...'Z' => @intCast(cp - 'A' + 1),
            '@', ' ', '2' => 0x00,
            '[', '3' => 0x1b,
            '\\', '4' => 0x1c,
            ']', '5' => 0x1d,
            '^', '6' => 0x1e,
            '_', '/', '7' => 0x1f,
            '?', '8' => 0x7f,
            else => null,
        };
        const b = c orelse return out[0..0];
        out[start] = b;
        return out[0 .. start + 1];
    }
    if (cp < 0x20 or cp == 0x7f or (cp >= 0x80 and cp < 0xa0)) return out[0..0];
    const n = std.unicode.utf8Encode(cp, out[start..]) catch return out[0..0];
    return out[0 .. start + n];
}

pub const paste_start = "\x1b[200~";
pub const paste_end = "\x1b[201~";

/// Cleans pasted text for the PTY: keeps printable UTF-8, tab and line
/// breaks (CR LF and lone LF become CR, as terminals send Enter); drops
/// every other C0/C1 control (ESC included, so a paste cannot end the
/// bracketed-paste block early or inject sequences), DEL and invalid UTF-8.
/// `out` must be at least `in.len` bytes; returns the used part.
pub fn sanitizePaste(in: []const u8, out: []u8) []u8 {
    var o: usize = 0;
    var i: usize = 0;
    while (i < in.len and o < out.len) {
        const b = in[i];
        if (b < 0x80) {
            i += 1;
            switch (b) {
                '\t' => {
                    out[o] = b;
                    o += 1;
                },
                '\r' => {
                    if (i < in.len and in[i] == '\n') i += 1;
                    out[o] = '\r';
                    o += 1;
                },
                '\n' => {
                    out[o] = '\r';
                    o += 1;
                },
                0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => {},
                else => {
                    out[o] = b;
                    o += 1;
                },
            }
            continue;
        }
        const len = std.unicode.utf8ByteSequenceLength(b) catch {
            i += 1;
            continue;
        };
        if (i + len > in.len) break;
        const cp = std.unicode.utf8Decode(in[i..][0..len]) catch {
            i += 1;
            continue;
        };
        if (cp >= 0x80 and cp < 0xa0) {
            i += len; // C1 control
            continue;
        }
        if (o + len > out.len) break;
        @memcpy(out[o..][0..len], in[i..][0..len]);
        o += len;
        i += len;
    }
    return out[0..o];
}

const testing = std.testing;

fn tkey(k: Key, m: Mods, app: bool) []const u8 {
    const S = struct {
        var buf: [max_seq]u8 = undefined;
    };
    return encodeKey(k, m, app, &S.buf);
}

fn tchar(cp: u21, m: Mods) []const u8 {
    const S = struct {
        var buf: [max_seq]u8 = undefined;
    };
    return encodeChar(cp, m, &S.buf);
}

test "special keys" {
    try testing.expectEqualStrings("\r", tkey(.enter, .{}, false));
    try testing.expectEqualStrings("\x7f", tkey(.backspace, .{}, false));
    try testing.expectEqualStrings("\x08", tkey(.backspace, .{ .ctrl = true }, false));
    try testing.expectEqualStrings("\x1b\x7f", tkey(.backspace, .{ .alt = true }, false));
    try testing.expectEqualStrings("\t", tkey(.tab, .{}, false));
    try testing.expectEqualStrings("\x1b[Z", tkey(.tab, .{ .shift = true }, false));
    try testing.expectEqualStrings("\x1b", tkey(.escape, .{}, false));
    try testing.expectEqualStrings("\x1b[A", tkey(.up, .{}, false));
    try testing.expectEqualStrings("\x1bOA", tkey(.up, .{}, true));
    try testing.expectEqualStrings("\x1b[1;5C", tkey(.right, .{ .ctrl = true }, true));
    try testing.expectEqualStrings("\x1b[1;2D", tkey(.left, .{ .shift = true }, false));
    try testing.expectEqualStrings("\x1b[1;3B", tkey(.down, .{ .alt = true }, false));
    try testing.expectEqualStrings("\x1b[H", tkey(.home, .{}, false));
    try testing.expectEqualStrings("\x1bOF", tkey(.end, .{}, true));
    try testing.expectEqualStrings("\x1b[2~", tkey(.insert, .{}, false));
    try testing.expectEqualStrings("\x1b[3~", tkey(.delete, .{}, false));
    try testing.expectEqualStrings("\x1b[3;5~", tkey(.delete, .{ .ctrl = true }, false));
    try testing.expectEqualStrings("\x1b[5~", tkey(.page_up, .{}, false));
    try testing.expectEqualStrings("\x1b[6~", tkey(.page_down, .{}, false));
    try testing.expectEqualStrings("\x1bOP", tkey(.f1, .{}, false));
    try testing.expectEqualStrings("\x1bOS", tkey(.f4, .{}, false));
    try testing.expectEqualStrings("\x1b[1;2P", tkey(.f1, .{ .shift = true }, false));
    try testing.expectEqualStrings("\x1b[15~", tkey(.f5, .{}, false));
    try testing.expectEqualStrings("\x1b[21~", tkey(.f10, .{}, false));
    try testing.expectEqualStrings("\x1b[24;8~", tkey(.f12, .{ .ctrl = true, .alt = true, .shift = true }, false));
    // Every key encodes without overflowing the buffer.
    for (std.enums.values(Key)) |k| {
        for (0..8) |bits| {
            const m: Mods = .{ .shift = bits & 1 != 0, .alt = bits & 2 != 0, .ctrl = bits & 4 != 0 };
            try testing.expect(tkey(k, m, bits & 1 != 0).len > 0);
        }
    }
}

test "characters" {
    try testing.expectEqualStrings("a", tchar('a', .{}));
    try testing.expectEqualStrings("\xE4\xB8\xAD", tchar(0x4E2D, .{}));
    try testing.expectEqualStrings("\xF0\x9F\x98\x80", tchar(0x1F600, .{}));
    try testing.expectEqualStrings("\x03", tchar('c', .{ .ctrl = true }));
    try testing.expectEqualStrings("\x1a", tchar('Z', .{ .ctrl = true, .shift = true }));
    try testing.expectEqualStrings("\x00", tchar(' ', .{ .ctrl = true }));
    try testing.expectEqualStrings("\x1b", tchar('[', .{ .ctrl = true }));
    try testing.expectEqualStrings("\x1f", tchar('/', .{ .ctrl = true }));
    try testing.expectEqualStrings("\x1bx", tchar('x', .{ .alt = true }));
    try testing.expectEqualStrings("\x1b\x18", tchar('x', .{ .alt = true, .ctrl = true }));
    try testing.expectEqualStrings("", tchar(0x1b, .{}));
    try testing.expectEqualStrings("", tchar(0x85, .{}));
    try testing.expectEqualStrings("", tchar(0xD800, .{}));
    try testing.expectEqualStrings("", tchar(',', .{ .ctrl = true }));
}

test "paste sanitiser" {
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("echo hi\rnext\r\tx", sanitizePaste("echo hi\r\nnext\n\tx", &out));
    // ESC is dropped, so an embedded end marker becomes harmless text.
    try testing.expectEqualStrings("[201~rm", sanitizePaste("\x1b[201~rm", &out));
    try testing.expectEqualStrings("ok", sanitizePaste("o\x00\x07\x08\x7fk", &out));
    try testing.expectEqualStrings("\u{4E2D}x", sanitizePaste("\u{4E2D}\u{0085}\u{009B}x", &out));
    try testing.expectEqualStrings("ab", sanitizePaste("a\xFF\xC0b", &out));
    try testing.expectEqualStrings("a", sanitizePaste("a\xE4\xB8", &out)); // truncated
    try testing.expectEqualStrings("\r\r", sanitizePaste("\r\r", &out));
    try testing.expectEqualStrings("", sanitizePaste("", &out));
    // Never writes past `out`.
    var small: [3]u8 = undefined;
    try testing.expectEqualStrings("ab", sanitizePaste("ab\u{4E2D}", &small));
}

test "paste sanitiser fuzz: output is clean and bounded" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rand = prng.random();
    var in: [256]u8 = undefined;
    var out: [256]u8 = undefined;
    for (0..2000) |_| {
        const n = rand.uintLessThan(usize, in.len);
        rand.bytes(in[0..n]);
        const r = sanitizePaste(in[0..n], &out);
        try testing.expect(r.len <= n);
        try testing.expect(std.unicode.utf8ValidateSlice(r));
        var view_it = std.unicode.Utf8View.initUnchecked(r).iterator();
        while (view_it.nextCodepoint()) |cp| {
            const ok = cp == '\t' or cp == '\r' or (cp >= 0x20 and cp != 0x7f and !(cp >= 0x80 and cp < 0xa0));
            try testing.expect(ok);
        }
    }
}
