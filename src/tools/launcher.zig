//! portal-launcher: installed by `portal-release release` as
//! %LOCALAPPDATA%\Portal\bin\portal.exe. Runs the currently promoted release:
//!
//!   1. reads <releases>\current.txt (never an inherited variable) and
//!      validates the id against the release id pattern,
//!   2. checks <releases>\<id>\portal.exe exists,
//!   3. runs it with this process's command line tail passed through verbatim,
//!      sharing the console and standard handles,
//!   4. exits with the child's full 32-bit exit code.
//!
//! <releases> is %LOCALAPPDATA%\Portal\releases, or PORTAL_RELEASES_DIR (an
//! absolute path, for testing; honoured only when PORTAL_TESTING=1 is also
//! set, with a warning).

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const lib = @import("releases_lib.zig");
const w = @import("win32_tools.zig");

pub fn main(init: std.process.Init) !void {
    if (builtin.os.tag != .windows) @compileError("portal-launcher supports Windows only.");
    const gpa = init.gpa;
    const io = init.io;
    const env = init.environ_map;

    // PORTAL_RELEASES_DIR picks which portal.exe runs, so it is honoured
    // only together with PORTAL_TESTING=1, and always announced.
    const override: ?[]const u8 = switch (lib.releasesOverride(env.get(lib.override_env), env.get(lib.testing_env))) {
        .none => null,
        .ignored => |o| blk: {
            std.debug.print("portal: warning: ignoring PORTAL_RELEASES_DIR={s} (it is honoured only with PORTAL_TESTING=1)\n", .{o});
            break :blk null;
        },
        .active => |o| o,
    };
    const releases = lib.releasesRoot(gpa, override, env.get("LOCALAPPDATA")) catch |err| switch (err) {
        error.NoLocalAppData => fail("LOCALAPPDATA is not set.", .{}),
        error.RelativeOverride => fail("PORTAL_RELEASES_DIR must be an absolute path.", .{}),
        error.OutOfMemory => return err,
    };
    defer gpa.free(releases);
    if (override != null)
        std.debug.print("portal: warning: TESTING override PORTAL_RELEASES_DIR in effect, running releases from {s}\n", .{releases});

    const id = readCurrent(gpa, io, releases) orelse fail(
        "{s}\\{s} is missing or invalid. In the Portal repo run `zig build release` (or `zig build rollback`).",
        .{ releases, lib.current_file },
    );
    defer gpa.free(id);

    const exe = try std.fs.path.join(gpa, &.{ releases, id, "portal.exe" });
    defer gpa.free(exe);
    const st = Io.Dir.cwd().statFile(io, exe, .{}) catch
        fail("release {s} has no portal.exe ({s}). Run `zig build rollback` or `zig build release`.", .{ id, exe });
    if (st.kind != .file) fail("{s} is not a file.", .{exe});

    const code = run(gpa, exe) catch |err| fail("could not start {s}: {t}", .{ exe, err });
    w.ExitProcess(code);
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("portal: " ++ fmt ++ "\n", args);
    w.ExitProcess(1);
}

/// Returns an owned copy of the validated id in current.txt, or null.
fn readCurrent(gpa: Allocator, io: Io, releases: []const u8) ?[]u8 {
    const path = std.fs.path.join(gpa, &.{ releases, lib.current_file }) catch return null;
    defer gpa.free(path);
    const contents = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(lib.max_pointer_bytes)) catch return null;
    defer gpa.free(contents);
    const id = lib.parsePointer(contents) orelse return null;
    return gpa.dupe(u8, id) catch null;
}

/// Ctrl+C / Ctrl+Break reach every process on the console. Let the child
/// decide what they mean; the launcher just keeps waiting for it. (A handler
/// function, unlike SetConsoleCtrlHandler(null, TRUE), is not inherited.)
fn ignoreCtrl(ctrl_type: w.DWORD) callconv(.winapi) w.BOOL {
    return @intFromBool(ctrl_type == w.CTRL_C_EVENT or ctrl_type == w.CTRL_BREAK_EVENT);
}

extern "kernel32" fn SetEnvironmentVariableW(name: [*:0]const u16, value: ?[*:0]const u16) callconv(.winapi) w.BOOL;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) w.DWORD;

fn run(gpa: Allocator, exe: []const u8) !u32 {
    const exe_w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, exe);
    defer gpa.free(exe_w);

    // Pass our own arguments through verbatim (like cmd's %*): no re-quoting.
    const own = std.mem.span(w.GetCommandLineW());
    const tail = lib.commandTail(u16, own);
    var cmd: std.ArrayList(u16) = .empty;
    defer cmd.deinit(gpa);
    try cmd.append(gpa, '"');
    try cmd.appendSlice(gpa, exe_w);
    try cmd.append(gpa, '"');
    if (tail.len > 0) {
        try cmd.append(gpa, ' ');
        try cmd.appendSlice(gpa, tail);
    }
    const cmd_z = try cmd.toOwnedSliceSentinel(gpa, 0);
    defer gpa.free(cmd_z);

    _ = w.SetConsoleCtrlHandler(ignoreCtrl, 1);
    // Tells portal.exe that the launcher (not a terminal) shares its
    // console, so a double-clicked launcher still counts as "no terminal"
    // for the default working directory (src/workdir.zig). The value is our
    // pid: portal.exe trusts it only if we are its parent, then deletes it
    // from its own environment so its session child does not inherit it.
    var pid_buf: [16]u16 = undefined;
    _ = SetEnvironmentVariableW(std.unicode.utf8ToUtf16LeStringLiteral("PORTAL_VIA_LAUNCHER"), lib.pidWide(GetCurrentProcessId(), &pid_buf));

    var si: w.STARTUPINFOW = .{ .cb = @sizeOf(w.STARTUPINFOW) };
    var pi: w.PROCESS_INFORMATION = undefined;
    // bInheritHandles so redirected (non-console) standard handles stay valid
    // in the child, as with cmd.exe.
    if (w.CreateProcessW(exe_w.ptr, cmd_z.ptr, null, null, 1, 0, null, null, &si, &pi) == 0) {
        std.debug.print("portal: CreateProcessW failed, error {d}\n", .{w.GetLastError()});
        return error.CreateProcessFailed;
    }
    _ = w.CloseHandle(pi.hThread);
    if (w.WaitForSingleObject(pi.hProcess, w.INFINITE) == w.WAIT_FAILED) return error.WaitFailed;
    var code: w.DWORD = 1;
    if (w.GetExitCodeProcess(pi.hProcess, &code) == 0) return error.NoExitCode;
    _ = w.CloseHandle(pi.hProcess);
    return code;
}
