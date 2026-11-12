//! Root panic handler (`pub const panic` in main.zig).
//!
//! After `portal run` frees its console for the window, std's default panic
//! output (stderr) leads nowhere and a crash would vanish silently. This
//! handler, best-effort and without allocating:
//!
//!   1. appends one line to %LOCALAPPDATA%\Portal\portal.log (the audit log
//!      file, opened FILE_APPEND_DATA like log.zig) with the message, the
//!      thread id and the return address (also as portal.exe+offset, which
//!      survives ASLR, for symbolising against the release's .pdb);
//!   2. writes the same line to stderr;
//!   3. shows a MessageBoxW when the console was freed (`gui_mode`);
//!   4. ends the process with ExitProcess(3) (the job object then ends the
//!      child's tree, as on every other exit).
//!
//! Safe from any thread and re-entrantly: the first panic wins; a nested
//! panic on the same thread (e.g. inside the MessageBox) exits at once,
//! and panics on other threads park until the first one exits.

const std = @import("std");

const WINAPI: std.builtin.CallingConvention = .winapi;
const HANDLE = *anyopaque;
const BOOL = i32;
const DWORD = u32;

const SYSTEMTIME = extern struct {
    wYear: u16,
    wMonth: u16,
    wDayOfWeek: u16,
    wDay: u16,
    wHour: u16,
    wMinute: u16,
    wSecond: u16,
    wMilliseconds: u16,
};

extern "kernel32" fn GetEnvironmentVariableW(name: [*:0]const u16, buf: [*]u16, size: DWORD) callconv(WINAPI) DWORD;
extern "kernel32" fn CreateFileW(name: [*:0]const u16, access: DWORD, share: DWORD, sa: ?*anyopaque, disp: DWORD, flags: DWORD, template: ?HANDLE) callconv(WINAPI) HANDLE;
extern "kernel32" fn WriteFile(h: HANDLE, buf: [*]const u8, len: DWORD, written: ?*DWORD, overlapped: ?*anyopaque) callconv(WINAPI) BOOL;
extern "kernel32" fn CloseHandle(h: HANDLE) callconv(WINAPI) BOOL;
extern "kernel32" fn GetStdHandle(which: DWORD) callconv(WINAPI) ?HANDLE;
extern "kernel32" fn GetCurrentThreadId() callconv(WINAPI) DWORD;
extern "kernel32" fn GetModuleHandleW(name: ?[*:0]const u16) callconv(WINAPI) ?*anyopaque;
extern "kernel32" fn GetSystemTime(t: *SYSTEMTIME) callconv(WINAPI) void;
extern "kernel32" fn Sleep(ms: DWORD) callconv(WINAPI) void;
extern "kernel32" fn ExitProcess(code: u32) callconv(WINAPI) noreturn;
extern "user32" fn MessageBoxW(hwnd: ?*anyopaque, text: [*:0]const u16, caption: [*:0]const u16, flags: u32) callconv(WINAPI) i32;

const FILE_APPEND_DATA: DWORD = 0x0004;
const FILE_SHARE_READ: DWORD = 0x1;
const FILE_SHARE_WRITE: DWORD = 0x2;
const OPEN_ALWAYS: DWORD = 4;
const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;
const STD_ERROR_HANDLE: DWORD = @bitCast(@as(i32, -12));
const INVALID_HANDLE: usize = @bitCast(@as(isize, -1));
const MB_ICONERROR: u32 = 0x10;
const MB_SETFOREGROUND: u32 = 0x10000;
const MB_TOPMOST: u32 = 0x40000;

/// The exit code of a panicking Portal.
pub const exit_code: u32 = 3;

/// Set by main once the console has been freed for the GUI window: the
/// handler then also shows a message box.
pub var gui_mode: std.atomic.Value(bool) = .init(false);

/// Thread id of the first panicking thread (0 = none yet).
var owner: std.atomic.Value(DWORD) = .init(0);

/// The root panic namespace (main.zig: `pub const panic = @import("panic.zig").handler;`).
pub const handler = std.debug.FullPanic(panicFn);

fn panicFn(msg: []const u8, first_trace_addr: ?usize) noreturn {
    @branchHint(.cold);
    const tid = GetCurrentThreadId();
    if (owner.cmpxchgStrong(0, tid, .acq_rel, .acquire)) |first| {
        // Already panicking. Same thread: the report itself failed; get
        // out now. Another thread: let the first one finish and exit.
        if (first == tid) ExitProcess(exit_code);
        while (true) Sleep(0xFFFFFFFF);
    }
    var buf: [1536]u8 = undefined;
    var st: SYSTEMTIME = undefined;
    GetSystemTime(&st);
    const ra = first_trace_addr orelse @returnAddress();
    const base = if (GetModuleHandleW(null)) |m| @intFromPtr(m) else 0;
    const line = formatReport(&buf, .{
        .msg = msg,
        .thread_id = tid,
        .return_address = ra,
        .module_base = base,
        .time = .{ st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond },
    });
    appendToLog(line);
    if (GetStdHandle(STD_ERROR_HANDLE)) |h| {
        if (@intFromPtr(h) != INVALID_HANDLE) _ = WriteFile(h, line.ptr, @intCast(line.len), null, null);
    }
    if (gui_mode.load(.acquire)) {
        var wbuf: [1024]u16 = undefined;
        var mbuf: [900]u8 = undefined;
        const text = std.fmt.bufPrint(&mbuf, "Portal stopped because of an internal error.\n\n{s}\n\nDetails were written to %LOCALAPPDATA%\\Portal\\portal.log.", .{msg}) catch
            "Portal stopped because of an internal error. Details were written to %LOCALAPPDATA%\\Portal\\portal.log.";
        utf16Lossy(text, &wbuf);
        _ = MessageBoxW(null, @ptrCast(&wbuf), std.unicode.utf8ToUtf16LeStringLiteral("Portal"), MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
    }
    ExitProcess(exit_code);
}

pub const Report = struct {
    msg: []const u8,
    thread_id: u32,
    return_address: usize,
    module_base: usize,
    /// UTC year, month, day, hour, minute, second.
    time: [6]u16,
};

/// One log line in log.zig's format ("<ISO time> <entry>\r\n"). The
/// message is truncated (with "...") to fit `buf`; CR/LF and other control
/// characters in it become spaces so it stays a single line.
pub fn formatReport(buf: []u8, r: Report) []const u8 {
    const t = r.time;
    const head = std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z PANIC thread {d}: ", .{ t[0], t[1], t[2], t[3], t[4], t[5], r.thread_id }) catch return buf[0..0];
    var tail_buf: [80]u8 = undefined;
    const tail = (if (r.module_base != 0 and r.return_address >= r.module_base)
        std.fmt.bufPrint(&tail_buf, " (at 0x{x}, portal.exe+0x{x})\r\n", .{ r.return_address, r.return_address - r.module_base })
    else
        std.fmt.bufPrint(&tail_buf, " (at 0x{x})\r\n", .{r.return_address})) catch "\r\n";
    var n = head.len;
    const room = buf.len -| (n + tail.len);
    var m = r.msg;
    var cut = false;
    if (m.len > room) {
        m = m[0..room -| 3];
        cut = true;
    }
    for (m) |c| {
        buf[n] = if (c < 0x20 or c == 0x7f) ' ' else c;
        n += 1;
    }
    if (cut and n + 3 + tail.len <= buf.len) {
        @memcpy(buf[n..][0..3], "...");
        n += 3;
    }
    if (n + tail.len > buf.len) return buf[0..n];
    @memcpy(buf[n..][0..tail.len], tail);
    return buf[0 .. n + tail.len];
}

/// UTF-8 -> NUL-terminated UTF-16 that never writes past `out`: stops at
/// the limit on a code point boundary; invalid bytes become U+FFFD.
pub fn utf16Lossy(s: []const u8, out: []u16) void {
    if (out.len == 0) return;
    const cap = out.len - 1; // room for the NUL
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        var cp: u21 = 0xFFFD;
        var adv: usize = 1;
        if (std.unicode.utf8ByteSequenceLength(s[i])) |len| {
            if (i + len <= s.len) {
                if (std.unicode.utf8Decode(s[i..][0..len])) |c| {
                    cp = c;
                    adv = len;
                } else |_| {}
            }
        } else |_| {}
        i += adv;
        if (cp >= 0x10000) {
            if (n + 2 > cap) break;
            const v = cp - 0x10000;
            out[n] = @intCast(0xD800 + (v >> 10));
            out[n + 1] = @intCast(0xDC00 + (v & 0x3FF));
            n += 2;
        } else {
            if (n + 1 > cap) break;
            out[n] = @intCast(cp);
            n += 1;
        }
    }
    out[n] = 0;
}

fn appendToLog(line: []const u8) void {
    var path: [600:0]u16 = undefined;
    const suffix = std.unicode.utf8ToUtf16LeStringLiteral("\\Portal\\portal.log");
    const max_base = path.len - suffix.len - 1;
    const n = GetEnvironmentVariableW(std.unicode.utf8ToUtf16LeStringLiteral("LOCALAPPDATA"), &path, @intCast(max_base));
    // 0: unset; >= max_base: did not fit (the return is the size needed).
    if (n == 0 or n >= max_base) return;
    @memcpy(path[n..][0..suffix.len], suffix);
    path[n + suffix.len] = 0;
    const h = CreateFileW(&path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, null, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, null);
    if (@intFromPtr(h) == INVALID_HANDLE) return;
    _ = WriteFile(h, line.ptr, @intCast(line.len), null, null);
    _ = CloseHandle(h);
}

test "formatReport: one line with time, thread, message and addresses" {
    var buf: [256]u8 = undefined;
    const line = formatReport(&buf, .{
        .msg = "index out of bounds:\r\nindex 5, len 3",
        .thread_id = 1234,
        .return_address = 0x7ff600001234,
        .module_base = 0x7ff600000000,
        .time = .{ 2026, 11, 11, 9, 5, 7 },
    });
    try std.testing.expectEqualStrings("2026-11-11T09:05:07Z PANIC thread 1234: index out of bounds:  index 5, len 3 (at 0x7ff600001234, portal.exe+0x1234)\r\n", line);
}

test "formatReport: long messages are truncated, never overflow" {
    var buf: [128]u8 = undefined;
    var msg: [1000]u8 = undefined;
    @memset(&msg, 'x');
    const line = formatReport(&buf, .{ .msg = &msg, .thread_id = 1, .return_address = 0x10, .module_base = 0, .time = .{ 2026, 1, 2, 3, 4, 5 } });
    try std.testing.expect(line.len <= buf.len);
    try std.testing.expect(std.mem.endsWith(u8, line, "... (at 0x10)\r\n"));
    try std.testing.expect(std.mem.startsWith(u8, line, "2026-01-02T03:04:05Z PANIC thread 1: xxx"));
    // A buffer too small for anything still returns safely.
    var tiny: [8]u8 = undefined;
    _ = formatReport(&tiny, .{ .msg = &msg, .thread_id = 1, .return_address = 0x10, .module_base = 0, .time = .{ 2026, 1, 2, 3, 4, 5 } });
}

test "utf16Lossy stays inside its buffer" {
    var out: [8]u16 = undefined;
    utf16Lossy("abcdefghijkl", &out);
    try std.testing.expectEqualSlices(u16, &.{ 'a', 'b', 'c', 'd', 'e', 'f', 'g', 0 }, &out);
    // An astral character that would need the last unit is dropped whole.
    utf16Lossy("abcdef\u{1F600}", &out);
    try std.testing.expectEqualSlices(u16, &.{ 'a', 'b', 'c', 'd', 'e', 'f', 0 }, out[0..7]);
    utf16Lossy("a\xffb", &out);
    try std.testing.expectEqualSlices(u16, &.{ 'a', 0xFFFD, 'b', 0 }, out[0..4]);
}
