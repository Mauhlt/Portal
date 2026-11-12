//! `portal open <dir>` / `portalctl open <dir>`: ask the running Portal to
//! open a folder as a new project tab (docs/tabs-design.md).
//!
//! The request travels through the data directory, the same local channel
//! `portalctl pair` and `unpair` use: only the current user can write to
//! %LOCALAPPDATA%\Portal, and nothing a remote device sends can create a
//! file there. The command writes `open\<16 hex>.req` atomically:
//!
//!   portal-open-v1
//!   dir=<absolute folder>
//!   name=<display name, optional>
//!
//! The running Portal's watcher (`Watch`, event-driven on the folder)
//! takes each request, deletes it, opens the tab and answers in
//! `<same>.res` with `ok` or `error: <why>`. The command waits for that
//! answer (also event-driven) for at most `answer_timeout_ms`, then says
//! that no Portal took the request and withdraws it.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const fsutil = @import("fsutil.zig");
const w = @import("win32.zig");

pub const dir_name = "open";
pub const header = "portal-open-v1";
pub const answer_timeout_ms = 10_000;
const max_request = 4096;

pub const Request = struct {
    dir: []const u8,
    name: ?[]const u8,
};

pub fn format(buf: []u8, r: Request) ![]const u8 {
    if (std.mem.indexOfAny(u8, r.dir, "\r\n") != null) return error.BadRequest;
    if (r.name) |n| if (std.mem.indexOfAny(u8, n, "\r\n") != null) return error.BadRequest;
    return std.fmt.bufPrint(buf, "{s}\ndir={s}\nname={s}\n", .{ header, r.dir, r.name orelse "" });
}

pub fn parse(text: []const u8) ?Request {
    var it = std.mem.splitScalar(u8, text, '\n');
    if (!std.mem.eql(u8, std.mem.trimEnd(u8, it.next() orelse return null, "\r"), header)) return null;
    var dir: ?[]const u8 = null;
    var name: ?[]const u8 = null;
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (std.mem.startsWith(u8, line, "dir=")) dir = line[4..];
        if (std.mem.startsWith(u8, line, "name=")) name = if (line.len > 5) line[5..] else null;
    }
    const d = dir orelse return null;
    if (d.len == 0) return null;
    return .{ .dir = d, .name = name };
}

/// `open <dir> [--name NAME]`, run by a second Portal process. `say`
/// prints (console) or shows (window) a line. Returns the exit code.
pub fn command(gpa: Allocator, io: Io, data_dir: []const u8, args: []const []const u8, say: *const fn ([]const u8) void) u8 {
    var dir_arg: ?[]const u8 = null;
    var name: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--name") and i + 1 < args.len) {
            i += 1;
            name = args[i];
        } else if (dir_arg == null and !std.mem.startsWith(u8, args[i], "--")) {
            dir_arg = args[i];
        } else {
            say("usage: open <folder> [--name NAME]");
            return 2;
        }
    }
    var msg: [1400]u8 = undefined;
    const arg = dir_arg orelse {
        say("usage: open <folder> [--name NAME]");
        return 2;
    };
    // Absolute and existing: the running Portal may have another current
    // directory.
    const here = std.process.currentPathAlloc(io, gpa) catch {
        say("cannot read the current directory");
        return 1;
    };
    defer gpa.free(here);
    const abs = std.fs.path.resolve(gpa, &.{ here, arg }) catch {
        say("out of memory");
        return 1;
    };
    defer gpa.free(abs);
    var d = Io.Dir.cwd().openDir(io, abs, .{}) catch |err| {
        say(std.fmt.bufPrint(&msg, "'{s}' is not an existing folder ({t})", .{ arg, err }) catch "not a folder");
        return 1;
    };
    d.close(io);

    var pb: [1100]u8 = undefined;
    const folder = fsutil.join(&pb, &.{ data_dir, dir_name }) catch return 1;
    Io.Dir.cwd().createDirPath(io, folder) catch {
        say("cannot create the request folder in Portal's data directory");
        return 1;
    };
    var rnd: [8]u8 = undefined;
    io.random(&rnd);
    const stem = std.fmt.bytesToHex(rnd, .lower);
    var rb: [1100]u8 = undefined;
    var ab: [1100]u8 = undefined;
    const req_path = std.fmt.bufPrint(&rb, "{s}\\{s}.req", .{ folder, &stem }) catch return 1;
    const res_path = std.fmt.bufPrint(&ab, "{s}\\{s}.res", .{ folder, &stem }) catch return 1;

    var watch = fsutil.DirWatch.open(gpa, folder, .{}) catch {
        say("cannot watch Portal's request folder");
        return 1;
    };
    defer watch.close();
    var body_buf: [max_request]u8 = undefined;
    const body = format(&body_buf, .{ .dir = abs, .name = name }) catch {
        say("the folder name is not usable");
        return 1;
    };
    fsutil.writeAtomic(gpa, io, req_path, body) catch |err| {
        say(std.fmt.bufPrint(&msg, "cannot write the request: {t}", .{err}) catch "cannot write the request");
        return 1;
    };
    const deadline = Io.Clock.awake.now(io).toMilliseconds() + answer_timeout_ms;
    while (true) {
        if (Io.Dir.cwd().readFileAlloc(io, res_path, gpa, .limited(1024))) |ans| {
            defer gpa.free(ans);
            Io.Dir.cwd().deleteFile(io, res_path) catch {};
            const a = std.mem.trim(u8, ans, " \r\n");
            if (std.mem.eql(u8, a, "ok")) {
                say(std.fmt.bufPrint(&msg, "opened '{s}' in Portal", .{abs}) catch "opened");
                return 0;
            }
            say(std.fmt.bufPrint(&msg, "Portal did not open it: {s}", .{a}) catch "Portal refused");
            return 1;
        } else |_| {}
        const left = deadline - Io.Clock.awake.now(io).toMilliseconds();
        if (left <= 0) break;
        const r = w.WaitForSingleObject(watch.h, @intCast(left));
        if (r != w.WAIT_OBJECT_0) continue;
        watch.rearm() catch break;
    }
    // Nobody took it: withdraw it (a Portal started later must not act on
    // a stale request).
    Io.Dir.cwd().deleteFile(io, req_path) catch {};
    say("no running Portal took the request (is the Portal window open?)");
    return 1;
}

/// The running Portal's side: waits for requests and hands each to
/// `open_fn`, which returns null (opened) or why not.
pub const Watch = struct {
    gpa: Allocator,
    io: Io,
    folder: []const u8,
    ctx: *anyopaque,
    open_fn: *const fn (ctx: *anyopaque, req: Request) ?[]const u8,
    lost_fn: *const fn (ctx: *anyopaque, err: anyerror) void,

    pub fn run(wt: *Watch) void {
        Io.Dir.cwd().createDirPath(wt.io, wt.folder) catch |err| return wt.lost_fn(wt.ctx, err);
        var watch = fsutil.DirWatch.open(wt.gpa, wt.folder, .{}) catch |err| return wt.lost_fn(wt.ctx, err);
        defer watch.close();
        // Requests left by a previous run are stale: their command gave up.
        wt.sweep(true);
        while (true) {
            if (w.WaitForSingleObject(watch.h, w.INFINITE) != w.WAIT_OBJECT_0) return wt.lost_fn(wt.ctx, error.WaitFailed);
            watch.rearm() catch |err| return wt.lost_fn(wt.ctx, err);
            wt.sweep(false);
        }
    }

    /// Handles (or, at startup, discards) every pending request.
    fn sweep(wt: *Watch, discard: bool) void {
        var dir = Io.Dir.cwd().openDir(wt.io, wt.folder, .{ .iterate = true }) catch return;
        defer dir.close(wt.io);
        var names: [16][32]u8 = undefined;
        var lens: [16]usize = undefined;
        var n: usize = 0;
        var it = dir.iterate();
        while (it.next(wt.io) catch null) |e| {
            if (n == names.len) break;
            if (e.kind != .file or !std.mem.endsWith(u8, e.name, ".req") or e.name.len > 32) continue;
            @memcpy(names[n][0..e.name.len], e.name);
            lens[n] = e.name.len;
            n += 1;
        }
        for (names[0..n], lens[0..n]) |*nm, len| {
            const name = nm[0..len];
            var buf: [max_request]u8 = undefined;
            const text = dir.readFile(wt.io, name, &buf) catch continue;
            dir.deleteFile(wt.io, name) catch continue; // taken by someone else
            if (discard) continue;
            const why: ?[]const u8 = if (parse(text)) |req| wt.open_fn(wt.ctx, req) else "malformed request";
            var res_name: [32]u8 = undefined;
            const stem = name[0 .. name.len - 4];
            const rn = std.fmt.bufPrint(&res_name, "{s}.res", .{stem}) catch continue;
            var ans: [256]u8 = undefined;
            const body = if (why) |y| std.fmt.bufPrint(&ans, "error: {s}\n", .{y}) catch "error\n" else "ok\n";
            var pb: [1100]u8 = undefined;
            const full = std.fmt.bufPrint(&pb, "{s}\\{s}", .{ wt.folder, rn }) catch continue;
            fsutil.writeAtomic(wt.gpa, wt.io, full, body) catch {};
        }
    }
};

test "request format round trip" {
    var buf: [256]u8 = undefined;
    const t = try format(&buf, .{ .dir = "C:\\code\\acme", .name = "Acme" });
    const r = parse(t).?;
    try std.testing.expectEqualStrings("C:\\code\\acme", r.dir);
    try std.testing.expectEqualStrings("Acme", r.name.?);
    const u = parse(try format(&buf, .{ .dir = "D:\\x", .name = null })).?;
    try std.testing.expect(u.name == null);
    try std.testing.expect(parse("bogus\ndir=C:\\x\n") == null);
    try std.testing.expect(parse(header ++ "\nname=x\n") == null);
    try std.testing.expectError(error.BadRequest, format(&buf, .{ .dir = "C:\\a\nb", .name = null }));
}
