//! Console mode is event-driven: resizes and local typing reach the session
//! through ReadConsoleInputW, with no resize polling. A detached helper
//! (this same exe with `--inject`) attaches to the portal --console instance's
//! console, resizes it and types into it; a remote viewer then has to see
//! the new grid size and the typed command's output.

const std = @import("std");
const w = @import("win.zig");
const net = @import("net.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;

const cmd_child = [_][]const u8{ "--", "cmd.exe", "/k" };

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    var dump_buf: [4096]u8 = undefined;
    const dir = try h.dataDir("console");
    const inst = try proc.Instance.start(h, dir, port, &cmd_child);
    defer inst.kill();
    const creds = try client.pair(inst, "laptop");
    const v = try client.Viewer.open(inst, creds.sessionCookie());
    defer v.deinit();
    _ = v.settle(300, 3000);
    const pid = w.GetProcessId(inst.process.?);

    for ([_][2]i16{ .{ 101, 33 }, .{ 86, 27 } }) |size| {
        const ok = inject(h.gpa, pid, size[0], size[1], null);
        _ = r.check("helper resized the console", ok, "pid {d}", .{pid});
        const reached = v.pumpUntil(5000, size, struct {
            fn f(s: [2]i16, vv: *client.Viewer) bool {
                return vv.g.cols == @as(u16, @intCast(s[0])) and vv.g.rows == @as(u16, @intCast(s[1]));
            }
        }.f);
        var name_buf: [80]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "console resize to {d}x{d} reaches the grid (event-driven)", .{ size[0], size[1] }) catch "console resize reaches the grid";
        _ = r.check(name, reached, "grid {d}x{d}", .{ v.g.cols, v.g.rows });
    }

    _ = r.ok("helper typed into the console", inject(h.gpa, pid, 0, 0, "echo CONSOLE-INJECT-%OS%\r"));
    _ = r.check("local console typing reaches the session", v.waitFor("CONSOLE-INJECT-Windows_NT", 5000), "{s}", .{v.dump(&dump_buf)});
    _ = r.ok("portal still running", inst.alive() and client.alive(inst));
}

/// Runs this exe as a detached helper: `--inject <pid> <cols> <rows> [text]`.
/// cols/rows 0 = don't resize.
fn inject(gpa: std.mem.Allocator, pid: u32, cols: i16, rows: i16, text: ?[]const u8) bool {
    var self_buf: [1024]u16 = undefined;
    const n = w.GetModuleFileNameW(null, &self_buf, self_buf.len);
    if (n == 0 or n >= self_buf.len) return false;
    const self_utf8 = std.unicode.utf16LeToUtf8Alloc(gpa, self_buf[0..n]) catch return false;
    defer gpa.free(self_utf8);
    const line = std.fmt.allocPrint(gpa, "\"{s}\" --inject {d} {d} {d} \"{s}\"", .{ self_utf8, pid, cols, rows, text orelse "" }) catch return false;
    defer gpa.free(line);
    const line_w = std.unicode.utf8ToUtf16LeAllocZ(gpa, line) catch return false;
    defer gpa.free(line_w);
    var si: w.STARTUPINFOW = .{ .cb = @sizeOf(w.STARTUPINFOW) };
    var pi: w.PROCESS_INFORMATION = undefined;
    if (w.CreateProcessW(null, line_w.ptr, null, null, 0, w.DETACHED_PROCESS, null, null, @ptrCast(&si), &pi) == 0) return false;
    defer _ = w.CloseHandle(pi.hProcess);
    defer _ = w.CloseHandle(pi.hThread);
    if (w.WaitForSingleObject(pi.hProcess, 10_000) != w.WAIT_OBJECT_0) return false;
    var code: w.DWORD = 1;
    _ = w.GetExitCodeProcess(pi.hProcess, &code);
    return code == 0;
}

/// Helper side (runs in the detached child). Returns the exit code.
pub fn injectMain(args: []const []const u8) u8 {
    if (args.len < 3) return 2;
    const pid = std.fmt.parseInt(u32, args[0], 10) catch return 2;
    const cols = std.fmt.parseInt(i16, args[1], 10) catch return 2;
    const rows = std.fmt.parseInt(i16, args[2], 10) catch return 2;
    const text = if (args.len > 3) args[3] else "";
    _ = w.FreeConsole();
    if (w.AttachConsole(pid) == 0) return 3;
    const in_h = w.CreateFileW(std.unicode.utf8ToUtf16LeStringLiteral("CONIN$"), w.GENERIC_READ_WRITE, w.FILE_SHARE_RW, null, w.OPEN_EXISTING_, 0, null);
    const out_h = w.CreateFileW(std.unicode.utf8ToUtf16LeStringLiteral("CONOUT$"), w.GENERIC_READ_WRITE, w.FILE_SHARE_RW, null, w.OPEN_EXISTING_, 0, null);
    if (@intFromPtr(in_h) == std.math.maxInt(usize) or @intFromPtr(out_h) == std.math.maxInt(usize)) return 4;

    if (cols > 0 and rows > 0) {
        var info: w.CONSOLE_SCREEN_BUFFER_INFO = undefined;
        if (w.GetConsoleScreenBufferInfo(out_h, &info) == 0) return 5;
        const cur_w = info.srWindow.Right - info.srWindow.Left + 1;
        const cur_h = info.srWindow.Bottom - info.srWindow.Top + 1;
        // Shrink the window first (it must fit in the buffer), then size
        // the buffer, then grow the window to fill it: the buffer change is
        // what the console reports as WINDOW_BUFFER_SIZE_EVENT.
        const small: w.SMALL_RECT = .{ .Left = 0, .Top = 0, .Right = @min(cur_w, cols) - 1, .Bottom = @min(cur_h, rows) - 1 };
        _ = w.SetConsoleWindowInfo(out_h, 1, &small);
        if (w.SetConsoleScreenBufferSize(out_h, .{ .X = cols, .Y = rows }) == 0) return 6;
        const full: w.SMALL_RECT = .{ .Left = 0, .Top = 0, .Right = cols - 1, .Bottom = rows - 1 };
        if (w.SetConsoleWindowInfo(out_h, 1, &full) == 0) return 7;
    }

    var recs: [256]w.INPUT_RECORD = undefined;
    var nr: usize = 0;
    var it = std.unicode.Utf8View.initUnchecked(text).iterator();
    while (it.nextCodepoint()) |cp| {
        if (cp > 0xFFFF or nr + 2 > recs.len) continue;
        for ([_]c_int{ 1, 0 }) |down| {
            recs[nr] = .{ .EventType = 1, .Event = .{ .KeyEvent = .{
                .bKeyDown = down,
                .wRepeatCount = 1,
                .wVirtualKeyCode = 0,
                .wVirtualScanCode = 0,
                .UnicodeChar = @intCast(cp),
                .dwControlKeyState = 0,
            } } };
            nr += 1;
        }
    }
    if (nr > 0) {
        var written: w.DWORD = 0;
        if (w.WriteConsoleInputW(in_h, &recs, @intCast(nr), &written) == 0 or written != nr) return 8;
    }
    return 0;
}
