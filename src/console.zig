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
    /// High surrogate carried across ReadConsoleW calls.
    pending_high: ?u16 = null,

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
        // Keys arrive as VT sequences; Ctrl+C arrives as 0x03 and is passed to
        // the child rather than killing Portal.
        var in_mode = c.saved_in_mode;
        in_mode &= ~(w.ENABLE_PROCESSED_INPUT | w.ENABLE_LINE_INPUT | w.ENABLE_ECHO_INPUT |
            w.ENABLE_WINDOW_INPUT | w.ENABLE_MOUSE_INPUT | w.ENABLE_QUICK_EDIT_MODE);
        in_mode |= w.ENABLE_VIRTUAL_TERMINAL_INPUT | w.ENABLE_EXTENDED_FLAGS;
        if (w.SetConsoleMode(c.in, in_mode) == 0) return error.ConsoleModeFailed;

        const out_mode = c.saved_out_mode | w.ENABLE_PROCESSED_OUTPUT |
            w.ENABLE_VIRTUAL_TERMINAL_PROCESSING | w.DISABLE_NEWLINE_AUTO_RETURN;
        if (w.SetConsoleMode(c.out, out_mode) == 0) return error.ConsoleModeFailed;
        _ = w.SetConsoleOutputCP(w.CP_UTF8);
        _ = w.SetConsoleCP(w.CP_UTF8);
    }

    pub fn restore(c: *Console) void {
        _ = w.SetConsoleMode(c.in, c.saved_in_mode);
        _ = w.SetConsoleMode(c.out, c.saved_out_mode);
        _ = w.SetConsoleCP(c.saved_in_cp);
        _ = w.SetConsoleOutputCP(c.saved_out_cp);
    }

    pub fn size(c: *Console) Size {
        var info: w.CONSOLE_SCREEN_BUFFER_INFO = undefined;
        if (w.GetConsoleScreenBufferInfo(c.out, &info) == 0) return .{ .cols = 120, .rows = 30 };
        const cols = @as(i32, info.srWindow.Right) - info.srWindow.Left + 1;
        const rows = @as(i32, info.srWindow.Bottom) - info.srWindow.Top + 1;
        return .{
            .cols = @intCast(std.math.clamp(cols, 20, 1000)),
            .rows = @intCast(std.math.clamp(rows, 5, 1000)),
        };
    }

    /// Blocking read of local keystrokes as UTF-8. `out` must hold at least
    /// 4 * 512 bytes.
    pub fn readInput(c: *Console, out: []u8) !usize {
        std.debug.assert(out.len >= 4 * 512);
        var wbuf: [512]u16 = undefined;
        var start: usize = 0;
        if (c.pending_high) |h| {
            wbuf[0] = h;
            start = 1;
            c.pending_high = null;
        }
        var n: w.DWORD = 0;
        if (w.ReadConsoleW(c.in, wbuf[start..].ptr, @intCast(wbuf.len - start), &n, null) == 0) return error.ReadFailed;
        var units = wbuf[0 .. start + n];
        if (units.len > 0 and std.unicode.utf16IsHighSurrogate(units[units.len - 1])) {
            c.pending_high = units[units.len - 1];
            units = units[0 .. units.len - 1];
        }
        return utf16ToUtf8Lossy(units, out);
    }

    pub fn write(c: *Console, data: []const u8) void {
        var rest = data;
        while (rest.len > 0) {
            var n: w.DWORD = 0;
            const len: w.DWORD = @intCast(@min(rest.len, 1 << 20));
            if (w.WriteFile(c.out, rest.ptr, len, &n, null) == 0) return;
            rest = rest[n..];
        }
    }

    pub fn setTitle(c: *Console, title: []const u8) void {
        _ = c;
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
