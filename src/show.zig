//! `portal-show <file.png> [--cols N] [--stdout]`: shows a PNG inline in
//! the terminal by writing a kitty graphics command, so a user, or the agent CLI
//! through its shell tool, can put an image into the session.
//!
//! It reads exactly the one local file it is given, and writes only to the
//! terminal. Portal's viewers then see the image because a program inside
//! the session emitted it (docs/tabs-design.md, privacy rules); there is
//! no network access here and no way for a viewer to ask for a file.
//!
//! Two output forms:
//!   * Console (stdout is a console, or stdout is redirected and the
//!     process still has one: the agent CLI's shell tool captures stdout): the
//!     command goes to the console as OSC 7070 (Windows ConPTY drops APC
//!     strings but passes unknown OSCs through). Under ConPTY the cursor
//!     can't be trusted at the moment the OSC reaches Portal, so this form
//!     first reserves the image's rows with newlines, waits for ConPTY to
//!     render them, then places the image at an explicit cell (Portal's j /
//!     l keys) without moving the cursor (C=1).
//!   * --stdout, or no console at all: plain kitty APC on stdout, cursor
//!     moved by the terminal, for real kitty-protocol terminals and pipes.

const std = @import("std");
const w = @import("win32.zig");
const pngcheck = @import("pngcheck");
const gfx = @import("vt_gfx.zig");

const usage =
    \\usage: portal-show <file.png> [--cols N] [--stdout]
    \\  Shows a PNG inline in the terminal (kitty graphics protocol).
    \\  --cols N   width in terminal columns (default: from the image size)
    \\  --stdout   write the plain kitty sequence to stdout
    \\
;

/// base64 characters per chunk, as kitty recommends.
const chunk_b64 = 4096;


pub fn main(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) u8 {
    var path: ?[]const u8 = null;
    var cols_arg: ?u32 = null;
    var force_stdout = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--cols")) {
            i += 1;
            if (i >= args.len) return fail("--cols needs a number", .{});
            cols_arg = std.fmt.parseInt(u32, args[i], 10) catch return fail("--cols: not a number: {s}", .{args[i]});
            if (cols_arg.? == 0 or cols_arg.? > 1000) return fail("--cols must be 1..1000", .{});
        } else if (std.mem.eql(u8, a, "--stdout")) {
            force_stdout = true;
        } else if (std.mem.startsWith(u8, a, "--")) {
            return fail("unknown option {s}\n{s}", .{ a, usage });
        } else if (path == null) {
            path = a;
        } else return fail("{s}", .{usage});
    }
    const file = path orelse return fail("{s}", .{usage});

    const png = std.Io.Dir.cwd().readFileAlloc(io, file, gpa, .limited(pngcheck.max_file_bytes)) catch |err| switch (err) {
        error.StreamTooLong => return fail("{s}: larger than {d} bytes", .{ file, pngcheck.max_file_bytes }),
        else => return fail("{s}: {t}", .{ file, err }),
    };
    defer gpa.free(png);
    const info = pngcheck.validate(png) catch |err| switch (err) {
        error.TooLarge => return fail("{s}: too large (at most {d}x{d} and {d} megapixels)", .{ file, pngcheck.max_side, pngcheck.max_side, pngcheck.max_pixels >> 20 }),
        else => return fail("{s}: not a valid PNG ({t})", .{ file, err }),
    };

    const b64 = gpa.alloc(u8, std.base64.standard.Encoder.calcSize(png.len)) catch return fail("out of memory", .{});
    defer gpa.free(b64);
    _ = std.base64.standard.Encoder.encode(b64, png);

    if (!force_stdout) {
        if (Console.open()) |con| {
            defer con.close();
            return con.show(gpa, info, cols_arg, b64);
        }
    }
    return showStdout(gpa, info, cols_arg, b64);
}

fn fail(comptime fmt: []const u8, args: anytype) u8 {
    std.debug.print("portal-show: " ++ fmt ++ "\n", args);
    return 1;
}

/// Cells for an image `info` at most `max_cols` x `max_rows`, from `--cols`
/// or the image's pixel size at kitty's nominal cell size, keeping the
/// aspect ratio (cells are twice as tall as wide).
pub fn cellSize(info: pngcheck.Info, cols_arg: ?u32, max_cols: u32, max_rows: u32) [2]u32 {
    const iw: u64 = @max(info.width, 1);
    const ih: u64 = @max(info.height, 1);
    const cw = gfx.nominal_cell_w;
    const ch = gfx.nominal_cell_h;
    var c: u64 = cols_arg orelse @intCast((iw + cw - 1) / cw);
    c = std.math.clamp(c, 1, @max(max_cols, 1));
    var r: u64 = @max(1, (c * ih * cw + iw * ch / 2) / (iw * ch));
    if (r > max_rows) {
        r = @max(max_rows, 1);
        c = std.math.clamp((r * iw * ch + ih * cw / 2) / (ih * cw), 1, @max(max_cols, 1));
    }
    return .{ @intCast(c), @intCast(r) };
}

fn writeAll(h: w.HANDLE, data: []const u8) bool {
    var rest = data;
    while (rest.len > 0) {
        var n: w.DWORD = 0;
        const len: w.DWORD = @intCast(@min(rest.len, 1 << 20));
        if (w.WriteFile(h, rest.ptr, len, &n, null) == 0 or n == 0) return false;
        rest = rest[n..];
    }
    return true;
}

/// Appends the command as chunks: `prefix` + keys (first chunk only) +
/// m=0/1 + ';' + base64 + `suffix`.
fn appendChunks(out: *std.ArrayList(u8), gpa: std.mem.Allocator, prefix: []const u8, keys: []const u8, b64: []const u8, suffix: []const u8) !void {
    var off: usize = 0;
    var first = true;
    while (true) {
        const n = @min(chunk_b64, b64.len - off);
        const more = off + n < b64.len;
        try out.appendSlice(gpa, prefix);
        if (first) {
            try out.appendSlice(gpa, keys);
            try out.append(gpa, ',');
        }
        try out.appendSlice(gpa, if (more) "m=1;" else "m=0;");
        try out.appendSlice(gpa, b64[off..][0..n]);
        try out.appendSlice(gpa, suffix);
        off += n;
        first = false;
        if (!more) return;
    }
}

fn showStdout(gpa: std.mem.Allocator, info: pngcheck.Info, cols_arg: ?u32, b64: []const u8) u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var keys_buf: [96]u8 = undefined;
    const keys = if (cols_arg) |c| blk: {
        const cr = cellSize(info, c, 1000, 1000);
        break :blk std.fmt.bufPrint(&keys_buf, "a=T,f=100,t=d,q=2,c={d},r={d}", .{ cr[0], cr[1] }) catch unreachable;
    } else "a=T,f=100,t=d,q=2";
    appendChunks(&out, gpa, "\x1b_G", keys, b64, "\x1b\\") catch return fail("out of memory", .{});
    out.append(gpa, '\n') catch return fail("out of memory", .{});
    const h = w.validHandle(w.GetStdHandle(w.STD_OUTPUT_HANDLE)) orelse return fail("no stdout", .{});
    if (!writeAll(h, out.items)) return fail("write failed", .{});
    return 0;
}

const Console = struct {
    h: w.HANDLE,
    owned: bool,
    mode: w.DWORD,

    const GENERIC_READ: w.DWORD = 0x80000000;
    const OPEN_EXISTING: w.DWORD = 3;

    /// stdout if it is a console, else the process's console (CONOUT$),
    /// else null.
    fn open() ?Console {
        var mode: w.DWORD = 0;
        if (w.validHandle(w.GetStdHandle(w.STD_OUTPUT_HANDLE))) |h| {
            if (w.GetConsoleMode(h, &mode) != 0) return .{ .h = h, .owned = false, .mode = mode };
        }
        const name = std.unicode.utf8ToUtf16LeStringLiteral("CONOUT$");
        const h = w.validHandle(w.CreateFileW(name, GENERIC_READ | w.GENERIC_WRITE, w.FILE_SHARE_READ | w.FILE_SHARE_WRITE, null, OPEN_EXISTING, 0, null)) orelse return null;
        if (w.GetConsoleMode(h, &mode) == 0) {
            _ = w.CloseHandle(h);
            return null;
        }
        return .{ .h = h, .owned = true, .mode = mode };
    }

    fn close(c: Console) void {
        _ = w.SetConsoleMode(c.h, c.mode);
        if (c.owned) _ = w.CloseHandle(c.h);
    }

    fn info(c: Console) ?w.CONSOLE_SCREEN_BUFFER_INFO {
        var i: w.CONSOLE_SCREEN_BUFFER_INFO = undefined;
        if (w.GetConsoleScreenBufferInfo(c.h, &i) == 0) return null;
        return i;
    }

    fn show(c: Console, gpa: std.mem.Allocator, img: pngcheck.Info, cols_arg: ?u32, b64: []const u8) u8 {
        // Escape sequences must reach the terminal, not be printed.
        _ = w.SetConsoleMode(c.h, c.mode | w.ENABLE_PROCESSED_OUTPUT | w.ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        const before = c.info() orelse return fail("cannot read the console size", .{});
        const win = before.srWindow;
        const scr_cols: u32 = @intCast(@max(1, @as(i32, win.Right) - win.Left + 1));
        const scr_rows: u32 = @intCast(@max(2, @as(i32, win.Bottom) - win.Top + 1));
        const cr = cellSize(img, cols_arg, scr_cols, scr_rows - 1);

        // Reserve the rows: start on a fresh line, then one newline per
        // image row, so the image sits on the lines above the cursor and
        // whatever comes next is printed below it.
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        if (before.dwCursorPosition.X != 0) out.appendSlice(gpa, "\r\n") catch return fail("out of memory", .{});
        out.appendNTimes(gpa, '\n', cr[1]) catch return fail("out of memory", .{});
        out.append(gpa, '\r') catch return fail("out of memory", .{});
        if (!writeAll(c.h, out.items)) return fail("write failed", .{});
        const after = c.info() orelse return fail("cannot read the console cursor", .{});
        const cur_row: i32 = @as(i32, after.dwCursorPosition.Y) - after.srWindow.Top;
        const anchor: u32 = @intCast(@max(0, cur_row - @as(i32, @intCast(cr[1]))));
        // Let ConPTY render (and scroll) those lines before the image
        // arrives: it passes OSCs through immediately but paints text on
        // its own schedule.
        w.Sleep(150);

        out.clearRetainingCapacity();
        var keys_buf: [128]u8 = undefined;
        const keys = std.fmt.bufPrint(&keys_buf, "a=T,f=100,t=d,q=2,C=1,c={d},r={d},j=0,l={d}", .{ cr[0], cr[1], anchor }) catch unreachable;
        appendChunks(&out, gpa, "\x1b]" ++ gfx.osc_number ++ ";G", keys, b64, "\x07") catch return fail("out of memory", .{});
        if (!writeAll(c.h, out.items)) return fail("write failed", .{});
        return 0;
    }
};

test "cellSize keeps the aspect ratio and fits" {
    const info: pngcheck.Info = .{ .width = 200, .height = 100, .bit_depth = 8, .color_type = 6, .interlaced = false };
    try std.testing.expectEqual([2]u32{ 20, 5 }, cellSize(info, null, 80, 24));
    try std.testing.expectEqual([2]u32{ 40, 10 }, cellSize(info, 40, 80, 24));
    try std.testing.expectEqual([2]u32{ 10, 3 }, cellSize(info, null, 10, 24));
    // Too tall for the screen: rows capped, columns follow.
    const tall: pngcheck.Info = .{ .width = 100, .height = 1000, .bit_depth = 8, .color_type = 6, .interlaced = false };
    try std.testing.expectEqual([2]u32{ 2, 10 }, cellSize(tall, null, 80, 10));
}
