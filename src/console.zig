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
    /// Strips program-set titles from the mirrored output (`mirror`).
    title_filter: TitleFilter = .{},
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

    /// Largest number of input records read at once.
    pub const max_records = 128;
    /// Key repeats taken from one record (a held key reports a count).
    const max_repeat = 32;
    /// Every unit one read can produce, plus a carried high surrogate.
    const max_units = max_records * max_repeat + 1;
    /// What `readEvents` needs in `out`: each UTF-16 unit makes at most
    /// 3 bytes of UTF-8 (a surrogate pair, 2 units, makes 4).
    pub const events_buf_len = 3 * max_units;

    /// Blocking, event-driven read of local console input: returns when the
    /// user types, or when the console reports a window-size, focus or menu
    /// change. No timer is involved. `out` must hold `events_buf_len` bytes,
    /// so every keystroke read is delivered (none is dropped).
    ///
    /// Windows Terminal reports every resize as WINDOW_BUFFER_SIZE_EVENT. The
    /// classic console host only reports buffer changes, so with scrollback a
    /// height-only change may not arrive until the next focus change or
    /// keystroke, which also re-check the size.
    pub fn readEvents(c: *Console, out: []u8) !Events {
        if (c.is_detached) return error.ReadFailed;
        std.debug.assert(out.len >= events_buf_len);
        var recs: [max_records]w.INPUT_RECORD = undefined;
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
        std.debug.assert(recs.len <= max_records);
        var units: [max_units]u16 = undefined;
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
                var rep: usize = @max(1, @min(k.wRepeatCount, max_repeat));
                while (rep > 0) : (rep -= 1) {
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
        // max_units * 3 bytes fit: the assert in readEvents.
        return .{ .n = utf16ToUtf8Lossy(slice, out), .resized = resized };
    }

    /// Copies the session's output to this console, minus program-set
    /// titles (OSC 0/1/2: TitleFilter), so the console keeps Portal's
    /// title instead of one with paths in it.
    pub fn mirror(c: *Console, data: []const u8) void {
        if (c.is_detached) return;
        var out: [4096 + TitleFilter.max_held]u8 = undefined;
        var rest = data;
        while (rest.len > 0) {
            const n = @min(rest.len, 4096);
            c.write(c.title_filter.filter(rest[0..n], &out));
            rest = rest[n..];
        }
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

    /// Sets the console title (UTF-8; see title.zig for what it says).
    pub fn setTitle(c: *Console, title: []const u8) void {
        if (c.is_detached) return;
        var buf: [256:0]u16 = undefined;
        const n = std.unicode.utf8ToUtf16Le(buf[0..255], title[0..@min(title.len, 255)]) catch return;
        buf[n] = 0;
        _ = w.SetConsoleTitleW(buf[0..n :0]);
    }
};

/// Removes OSC 0, 1 and 2 (set window title / icon name) from a VT byte
/// stream, across chunk boundaries; every other byte, including every
/// other OSC, passes through unchanged and in order. Sequences end with
/// BEL or ST (ESC \); CAN and SUB abort them, as in a terminal.
pub const TitleFilter = struct {
    /// Bytes held back while deciding (ESC ] and up to max_digits digits).
    pub const max_held = 2 + max_digits;
    const max_digits = 4;

    state: enum { ground, esc, osc_number, drop, drop_esc } = .ground,
    held: [max_held]u8 = undefined,
    held_len: u8 = 0,

    /// Filters `in` into `out` (which must hold in.len + max_held bytes)
    /// and returns the part of `out` to pass on.
    pub fn filter(f: *TitleFilter, in: []const u8, out: []u8) []const u8 {
        std.debug.assert(out.len >= in.len + max_held);
        var n: usize = 0;
        for (in) |b| f.step(b, out, &n);
        return out[0..n];
    }

    fn hold(f: *TitleFilter, b: u8) void {
        f.held[f.held_len] = b;
        f.held_len += 1;
    }

    fn release(f: *TitleFilter, out: []u8, n: *usize) void {
        @memcpy(out[n.*..][0..f.held_len], f.held[0..f.held_len]);
        n.* += f.held_len;
        f.held_len = 0;
    }

    fn isTitle(digits: []const u8) bool {
        return digits.len == 1 and digits[0] >= '0' and digits[0] <= '2';
    }

    fn step(f: *TitleFilter, b: u8, out: []u8, n: *usize) void {
        switch (f.state) {
            .ground => {
                if (b == 0x1B) {
                    f.hold(b);
                    f.state = .esc;
                } else {
                    out[n.*] = b;
                    n.* += 1;
                }
            },
            .esc => {
                if (b == ']') {
                    f.hold(b);
                    f.state = .osc_number;
                } else {
                    f.release(out, n);
                    f.state = .ground;
                    f.step(b, out, n);
                }
            },
            .osc_number => switch (b) {
                '0'...'9' => if (f.held_len < max_held) f.hold(b) else {
                    // Too long to be a title number: pass it on.
                    f.release(out, n);
                    f.state = .ground;
                    f.step(b, out, n);
                },
                ';', 0x07, 0x1B, 0x18, 0x1A => {
                    if (isTitle(f.held[2..f.held_len])) {
                        f.held_len = 0;
                        f.state = switch (b) {
                            ';' => .drop,
                            0x1B => .drop_esc,
                            else => .ground, // BEL ended it, CAN/SUB aborted it
                        };
                    } else {
                        f.release(out, n);
                        f.state = .ground;
                        f.step(b, out, n);
                    }
                },
                else => {
                    f.release(out, n);
                    f.state = .ground;
                    f.step(b, out, n);
                },
            },
            .drop => switch (b) {
                0x07, 0x18, 0x1A => f.state = .ground,
                0x1B => f.state = .drop_esc,
                else => {},
            },
            .drop_esc => {
                if (b == '\\') {
                    f.state = .ground; // ST ended the title
                } else {
                    // ESC aborted the title and starts something new.
                    f.state = .ground;
                    f.step(0x1B, out, n);
                    f.step(b, out, n);
                }
            },
        }
    }
};

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

test "decodeRecords: a full read of repeated keys is delivered whole" {
    var c: Console = Console.detached();
    var out: [Console.events_buf_len]u8 = undefined;
    var recs: [Console.max_records]w.INPUT_RECORD = undefined;
    for (&recs) |*r| r.* = keyRec(0x4E2D, true, 32); // 3-byte char, max repeat
    const e = c.decodeRecords(&recs, &out);
    // 128 records x 32 repeats, none dropped (the old 513-unit buffer
    // kept only the first 513).
    try std.testing.expectEqual(@as(usize, Console.max_records * 32 * 3), e.n);
    // With a carried high surrogate too, it still fits.
    c.pending_high = 0xD83D;
    recs[0] = keyRec(0xDE00, true, 1);
    const e2 = c.decodeRecords(&recs, &out);
    try std.testing.expect(e2.n <= out.len);
    try std.testing.expectEqualStrings("\u{1F600}", out[0..4]);
}

fn filterAll(f: *TitleFilter, chunks: []const []const u8, out: *std.ArrayList(u8)) !void {
    for (chunks) |chunk| {
        var buf: [256]u8 = undefined;
        try out.appendSlice(std.testing.allocator, f.filter(chunk, &buf));
    }
}

test "TitleFilter drops OSC 0/1/2 and keeps everything else" {
    const cases = [_]struct { in: []const u8, want: []const u8 }{
        .{ .in = "a\x1b]0;C:\\Users\\me\\secret\x07b", .want = "ab" },
        .{ .in = "a\x1b]2;Administrator: cmd.exe\x1b\\b", .want = "ab" },
        .{ .in = "\x1b]1;icon\x07", .want = "" },
        .{ .in = "\x1b]8;;https://x\x1b\\link\x1b]8;;\x1b\\", .want = "\x1b]8;;https://x\x1b\\link\x1b]8;;\x1b\\" },
        .{ .in = "\x1b]10;?\x07\x1b]7070;G...\x07", .want = "\x1b]10;?\x07\x1b]7070;G...\x07" },
        .{ .in = "\x1b[31mred\x1b[0m\x1bM", .want = "\x1b[31mred\x1b[0m\x1bM" },
        .{ .in = "\x1b]0;x\x18after", .want = "after" }, // CAN aborts
        .{ .in = "\x1b]2;x\x1b[1mbold", .want = "\x1b[1mbold" }, // ESC aborts, then a CSI
        .{ .in = "\x1b]02;x\x07", .want = "\x1b]02;x\x07" }, // not a title number
        .{ .in = "\x1b\x1b]0;t\x07z", .want = "\x1bz" },
    };
    for (cases) |c| {
        var f: TitleFilter = .{};
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(std.testing.allocator);
        try filterAll(&f, &.{c.in}, &out);
        try std.testing.expectEqualStrings(c.want, out.items);
        // Byte by byte (any chunking) gives the same result.
        var g: TitleFilter = .{};
        var out2: std.ArrayList(u8) = .empty;
        defer out2.deinit(std.testing.allocator);
        for (0..c.in.len) |i| try filterAll(&g, &.{c.in[i .. i + 1]}, &out2);
        try std.testing.expectEqualStrings(c.want, out2.items);
    }
}
