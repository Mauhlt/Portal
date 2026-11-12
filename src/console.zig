//! The desktop's own console window: raw VT mode so the local user can keep
//! using the agent normally while Portal mirrors it.

const std = @import("std");
const w = @import("win32.zig");
const Size = @import("conpty.zig").Size;

pub const Console = struct {
    in: w.HANDLE,
    out: w.HANDLE,
    saved_in_mode: w.DWORD,
    saved_out_mode: w.DWORD,
    saved_in_cp: u32,
    saved_out_cp: u32,
    /// High surrogate carried across ReadConsoleInputW calls.
    pending_high: ?u16 = null,
    /// True for `detached()`: every method is a no-op (GUI mode, where
    /// Portal has freed its console).
    is_detached: bool = false,

    /// A stand-in for the GUI: no handles, every method does nothing.
    pub fn detached() Console {
        const invalid: w.HANDLE = @ptrFromInt(w.INVALID_HANDLE_VALUE);
        return .{
            .in = invalid,
            .out = invalid,
            .saved_in_mode = 0,
            .saved_out_mode = 0,
            .saved_in_cp = 0,
            .saved_out_cp = 0,
            .is_detached = true,
        };
    }

    pub fn init() !Console {
        const in = w.validHandle(w.GetStdHandle(w.STD_INPUT_HANDLE)) orelse return error.NoConsole;
        const out = w.validHandle(w.GetStdHandle(w.STD_OUTPUT_HANDLE)) orelse return error.NoConsole;
        var in_mode: w.DWORD = 0;
        var out_mode: w.DWORD = 0;
        // Fails if stdin/stdout are redirected: Portal needs a real console.
        if (w.GetConsoleMode(in, &in_mode) == 0) return error.NoConsole;
        if (w.GetConsoleMode(out, &out_mode) == 0) return error.NoConsole;
        return .{
            .in = in,
            .out = out,
            .saved_in_mode = in_mode,
            .saved_out_mode = out_mode,
            .saved_in_cp = w.GetConsoleCP(),
            .saved_out_cp = w.GetConsoleOutputCP(),
        };
    }

    pub fn enableRaw(c: *Console) !void {
        if (c.is_detached) return;
        // Keys arrive as VT sequences; Ctrl+C arrives as 0x03 and is passed to
        // the child rather than killing Portal.
        var in_mode = c.saved_in_mode;
        in_mode &= ~(w.ENABLE_PROCESSED_INPUT | w.ENABLE_LINE_INPUT | w.ENABLE_ECHO_INPUT |
            w.ENABLE_MOUSE_INPUT | w.ENABLE_QUICK_EDIT_MODE);
        // ENABLE_WINDOW_INPUT: size changes arrive as input records, so the
        // input thread wakes on resizes (no polling).
        in_mode |= w.ENABLE_VIRTUAL_TERMINAL_INPUT | w.ENABLE_EXTENDED_FLAGS | w.ENABLE_WINDOW_INPUT;
        if (w.SetConsoleMode(c.in, in_mode) == 0) return error.ConsoleModeFailed;

        const out_mode = c.saved_out_mode | w.ENABLE_PROCESSED_OUTPUT |
            w.ENABLE_VIRTUAL_TERMINAL_PROCESSING | w.DISABLE_NEWLINE_AUTO_RETURN;
        if (w.SetConsoleMode(c.out, out_mode) == 0) return error.ConsoleModeFailed;
        _ = w.SetConsoleOutputCP(w.CP_UTF8);
        _ = w.SetConsoleCP(w.CP_UTF8);
    }

    pub fn restore(c: *Console) void {
        if (c.is_detached) return;
        _ = w.SetConsoleMode(c.in, c.saved_in_mode);
        _ = w.SetConsoleMode(c.out, c.saved_out_mode);
        _ = w.SetConsoleCP(c.saved_in_cp);
        _ = w.SetConsoleOutputCP(c.saved_out_cp);
    }

    pub fn size(c: *Console) Size {
        if (c.is_detached) return .{ .cols = 120, .rows = 30 };
        var info: w.CONSOLE_SCREEN_BUFFER_INFO = undefined;
        if (w.GetConsoleScreenBufferInfo(c.out, &info) == 0) return .{ .cols = 120, .rows = 30 };
        const cols = @as(i32, info.srWindow.Right) - info.srWindow.Left + 1;
        const rows = @as(i32, info.srWindow.Bottom) - info.srWindow.Top + 1;
        return .{
            .cols = @intCast(std.math.clamp(cols, 20, 1000)),
            .rows = @intCast(std.math.clamp(rows, 5, 1000)),
        };
    }

    pub const Events = struct {
        /// UTF-8 keystroke bytes written to `out`.
        n: usize,
        /// The console window may have changed size: re-check `size()`.
        resized: bool,
    };

    /// Blocking, event-driven read of local console input: returns when the
    /// user types, or when the console reports a window-size, focus or menu
    /// change. No timer is involved. `out` must hold at least 4 * 512 bytes.
    ///
    /// Windows Terminal reports every resize as WINDOW_BUFFER_SIZE_EVENT. The
    /// classic console host only reports buffer changes, so with scrollback a
    /// height-only change may not arrive until the next focus change or
    /// keystroke, which also re-check the size.
    pub fn readEvents(c: *Console, out: []u8) !Events {
        if (c.is_detached) return error.ReadFailed;
        std.debug.assert(out.len >= 4 * 512);
        var recs: [128]w.INPUT_RECORD = undefined;
        var got: w.DWORD = 0;
        if (w.ReadConsoleInputW(c.in, &recs, recs.len, &got) == 0) return error.ReadFailed;
        return c.decodeRecords(recs[0..@min(got, recs.len)], out);
    }

    /// Waits until console input is available or `timeout_ms` passes
    /// (std.math.maxInt(u32) = forever). Returns true if input is ready.
    pub fn waitInput(c: *Console, timeout_ms: u32) bool {
        if (c.is_detached) return false;
        return w.WaitForSingleObject(c.in, timeout_ms) == w.WAIT_OBJECT_0;
    }

    /// Pure part of readEvents (unit-tested): key-down characters become
    /// UTF-8 (surrogate pairs may span calls), and size/focus/menu events
    /// set `resized`.
    fn decodeRecords(c: *Console, recs: []const w.INPUT_RECORD, out: []u8) Events {
        var units: [512 + 1]u16 = undefined;
        var nu: usize = 0;
        if (c.pending_high) |h| {
            units[0] = h;
            nu = 1;
            c.pending_high = null;
        }
        var resized = false;
        for (recs) |r| switch (r.EventType) {
            w.KEY_EVENT => {
                const k = r.Event.KeyEvent;
                if (k.bKeyDown == 0 or k.UnicodeChar == 0) continue;
                var rep: usize = @max(1, @min(k.wRepeatCount, 32));
                while (rep > 0 and nu < units.len) : (rep -= 1) {
                    units[nu] = k.UnicodeChar;
                    nu += 1;
                }
            },
            w.WINDOW_BUFFER_SIZE_EVENT, w.FOCUS_EVENT, w.MENU_EVENT => resized = true,
            else => {},
        };
        var slice = units[0..nu];
        if (slice.len > 0 and std.unicode.utf16IsHighSurrogate(slice[slice.len - 1])) {
            c.pending_high = slice[slice.len - 1];
            slice = slice[0 .. slice.len - 1];
        }
        // 513 units * 3 bytes <= 4 * 512 is guaranteed by the assert in readEvents.
        return .{ .n = utf16ToUtf8Lossy(slice, out), .resized = resized };
    }

    pub fn write(c: *Console, data: []const u8) void {
        if (c.is_detached) return;
        var rest = data;
        while (rest.len > 0) {
            var n: w.DWORD = 0;
            const len: w.DWORD = @intCast(@min(rest.len, 1 << 20));
            if (w.WriteFile(c.out, rest.ptr, len, &n, null) == 0) return;
            rest = rest[n..];
        }
    }

    pub fn setTitle(c: *Console, title: []const u8) void {
        if (c.is_detached) return;
        var buf: [256]u16 = undefined;
        var i: usize = 0;
        for (title) |ch| {
            if (i >= buf.len - 1) break;
            buf[i] = if (ch < 0x80) ch else '?';
            i += 1;
        }
        buf[i] = 0;
        _ = w.SetConsoleTitleW(buf[0..i :0]);
    }
};

/// True only if both stdout and stderr are attached to a real console
/// (GetConsoleMode succeeds). False when either is redirected to a file or
/// pipe, which is how agents, CI and `> file` capture output: anything
/// printed then ends up in a transcript or on disk.
pub fn stdioIsInteractive() bool {
    return isConsole(w.STD_OUTPUT_HANDLE) and isConsole(w.STD_ERROR_HANDLE);
}

fn isConsole(which: w.DWORD) bool {
    const h = w.validHandle(w.GetStdHandle(which)) orelse return false;
    var mode: w.DWORD = 0;
    return w.GetConsoleMode(h, &mode) != 0;
}

/// UTF-16 to UTF-8, replacing unpaired surrogates with U+FFFD.
fn utf16ToUtf8Lossy(units: []const u16, out: []u8) usize {
    var o: usize = 0;
    var i: usize = 0;
    while (i < units.len) {
        var cp: u21 = 0xFFFD;
        const u = units[i];
        if (std.unicode.utf16IsHighSurrogate(u) and i + 1 < units.len and std.unicode.utf16IsLowSurrogate(units[i + 1])) {
            cp = std.unicode.utf16DecodeSurrogatePair(units[i .. i + 2]) catch 0xFFFD;
            i += 2;
        } else {
            if (!std.unicode.utf16IsHighSurrogate(u) and !std.unicode.utf16IsLowSurrogate(u)) cp = u;
            i += 1;
        }
        o += std.unicode.utf8Encode(cp, out[o..]) catch 0;
    }
    return o;
}

test "utf16 to utf8 lossy" {
    var out: [32]u8 = undefined;
    const hello = [_]u16{ 'h', 'i' };
    try std.testing.expectEqualStrings("hi", out[0..utf16ToUtf8Lossy(&hello, &out)]);
    const emoji = [_]u16{ 0xD83D, 0xDE00 };
    try std.testing.expectEqualStrings("\u{1F600}", out[0..utf16ToUtf8Lossy(&emoji, &out)]);
    const lone = [_]u16{0xDE00};
    try std.testing.expectEqualStrings("\u{FFFD}", out[0..utf16ToUtf8Lossy(&lone, &out)]);
}

fn keyRec(ch: u16, down: bool, rep: u16) w.INPUT_RECORD {
    return .{ .EventType = w.KEY_EVENT, .Event = .{ .KeyEvent = .{
        .bKeyDown = @intFromBool(down),
        .wRepeatCount = rep,
        .wVirtualKeyCode = 0,
        .wVirtualScanCode = 0,
        .UnicodeChar = ch,
        .dwControlKeyState = 0,
    } } };
}

test "decodeRecords: keys, repeats, key-ups, resize" {
    var c: Console = Console.detached();
    var out: [4 * 512]u8 = undefined;
    const recs = [_]w.INPUT_RECORD{
        keyRec('h', true, 1),
        keyRec('h', false, 1), // key-up: ignored
        keyRec('i', true, 2), // repeat count
        .{ .EventType = w.WINDOW_BUFFER_SIZE_EVENT, .Event = .{ .WindowBufferSizeEvent = .{ .dwSize = .{ .X = 100, .Y = 40 } } } },
        keyRec(0, true, 1), // no character (e.g. Shift alone)
        keyRec(0x1b, true, 1), // ESC from a VT sequence
        keyRec('[', true, 1),
        keyRec('A', true, 1),
    };
    const e = c.decodeRecords(&recs, &out);
    try std.testing.expectEqualStrings("hii\x1b[A", out[0..e.n]);
    try std.testing.expect(e.resized);
}

test "decodeRecords: surrogate pair split across reads; focus counts as resize check" {
    var c: Console = Console.detached();
    var out: [4 * 512]u8 = undefined;
    const a = [_]w.INPUT_RECORD{keyRec(0xD83D, true, 1)};
    const e1 = c.decodeRecords(&a, &out);
    try std.testing.expectEqual(@as(usize, 0), e1.n);
    try std.testing.expect(!e1.resized);
    const b = [_]w.INPUT_RECORD{ keyRec(0xDE00, true, 1), .{ .EventType = w.FOCUS_EVENT, .Event = .{ .raw = @splat(0) } } };
    const e2 = c.decodeRecords(&b, &out);
    try std.testing.expectEqualStrings("\u{1F600}", out[0..e2.n]);
    try std.testing.expect(e2.resized);
}

test "decodeRecords: never overflows the output buffer" {
    var c: Console = Console.detached();
    var out: [4 * 512]u8 = undefined;
    var recs: [128]w.INPUT_RECORD = undefined;
    for (&recs) |*r| r.* = keyRec(0x4E2D, true, 32); // 3-byte char, max repeat
    const e = c.decodeRecords(&recs, &out);
    try std.testing.expect(e.n <= out.len);
}
