//! Windows pseudo console (ConPTY): runs the child program attached to a
//! virtual terminal whose input/output Portal owns.

const std = @import("std");
const w = @import("win32.zig");

pub const Size = struct {
    cols: u16,
    rows: u16,

    fn coord(s: Size) w.COORD {
        return .{ .X = @intCast(@min(s.cols, 0x7fff)), .Y = @intCast(@min(s.rows, 0x7fff)) };
    }
};

pub const Pty = struct {
    hpc: w.HPCON,
    /// Portal writes keystrokes here.
    in_write: w.HANDLE,
    /// Portal reads terminal output here.
    out_read: w.HANDLE,
    /// Owned by the one thread that calls `waitExit` (which closes it);
    /// nothing else touches it, so no wait can race a CloseHandle.
    process: w.HANDLE,
    /// Job object with KILL_ON_JOB_CLOSE: if Portal dies for any reason, the
    /// child and everything it spawned die with it. No orphaned sessions that
    /// keep running unobserved.
    job: w.HANDLE,
    closed: bool = false,

    pub fn spawn(
        app: [:0]const u16,
        cmdline: [:0]u16,
        cwd: ?[:0]const u16,
        /// The child's environment block (childenv.zig; sorted, WTF-16).
        env: [:0]const u16,
        size: Size,
        attr_buf: []align(@alignOf(usize)) u8,
    ) !Pty {
        var in_read: w.HANDLE = undefined;
        var in_write: w.HANDLE = undefined;
        var out_read: w.HANDLE = undefined;
        var out_write: w.HANDLE = undefined;
        if (w.CreatePipe(&in_read, &in_write, null, 0) == 0) return error.CreatePipeFailed;
        errdefer _ = w.CloseHandle(in_write);
        defer _ = w.CloseHandle(in_read); // ConPTY duplicates what it needs
        if (w.CreatePipe(&out_read, &out_write, null, 0) == 0) return error.CreatePipeFailed;
        errdefer _ = w.CloseHandle(out_read);
        defer _ = w.CloseHandle(out_write);

        var hpc: w.HPCON = undefined;
        if (w.CreatePseudoConsole(size.coord(), in_read, out_write, 0, &hpc) < 0) return error.CreatePseudoConsoleFailed;
        errdefer w.ClosePseudoConsole(hpc);

        var attr_size: usize = 0;
        _ = w.InitializeProcThreadAttributeList(null, 1, 0, &attr_size);
        if (attr_size == 0 or attr_size > attr_buf.len) return error.AttributeListTooLarge;
        const attr_list: *anyopaque = attr_buf.ptr;
        if (w.InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size) == 0) return error.AttributeListFailed;
        defer w.DeleteProcThreadAttributeList(attr_list);
        // The attribute value is the HPCON itself (not a pointer to it).
        if (w.UpdateProcThreadAttribute(attr_list, 0, w.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hpc, @sizeOf(w.HPCON), null, null) == 0)
            return error.AttributeListFailed;

        const job = w.CreateJobObjectW(null, null) orelse return error.JobObjectFailed;
        errdefer _ = w.CloseHandle(job);
        var limits: w.JOBOBJECT_EXTENDED_LIMIT_INFORMATION = .{};
        limits.BasicLimitInformation.LimitFlags = w.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (w.SetInformationJobObject(job, w.JobObjectExtendedLimitInformation, &limits, @sizeOf(@TypeOf(limits))) == 0)
            return error.JobObjectFailed;

        // STARTF_USESTDHANDLES with null handles: the child must use the
        // pseudo console for stdin/stdout/stderr. Without it, a child of a
        // Portal with no console (the GUI) or with redirected std handles
        // inherits those handles instead and exits or writes past the PTY.
        var si: w.STARTUPINFOEXW = .{
            .StartupInfo = .{ .cb = @sizeOf(w.STARTUPINFOEXW), .dwFlags = w.STARTF_USESTDHANDLES },
            .lpAttributeList = attr_list,
        };
        var pi: w.PROCESS_INFORMATION = undefined;
        // Suspended so it can join the job before it can spawn grandchildren.
        // bInheritHandles = FALSE: the child gets no Portal handles (sockets etc.).
        if (w.CreateProcessW(
            app.ptr,
            cmdline.ptr,
            null,
            null,
            0,
            w.EXTENDED_STARTUPINFO_PRESENT | w.CREATE_SUSPENDED | w.CREATE_UNICODE_ENVIRONMENT,
            @ptrCast(@constCast(env.ptr)),
            if (cwd) |c| c.ptr else null,
            &si,
            &pi,
        ) == 0) return error.CreateProcessFailed;
        defer _ = w.CloseHandle(pi.hThread);
        if (w.AssignProcessToJobObject(job, pi.hProcess) == 0) {
            _ = w.TerminateProcess(pi.hProcess, 1);
            _ = w.CloseHandle(pi.hProcess);
            return error.JobObjectFailed;
        }
        // A child that never starts would otherwise sit suspended forever,
        // with Portal waiting for it to exit.
        if (w.ResumeThread(pi.hThread) == std.math.maxInt(w.DWORD)) {
            _ = w.TerminateProcess(pi.hProcess, 1);
            _ = w.CloseHandle(pi.hProcess);
            return error.ResumeThreadFailed;
        }

        return .{ .hpc = hpc, .in_write = in_write, .out_read = out_read, .process = pi.hProcess, .job = job };
    }

    /// Blocking read of terminal output. Returns 0 at end of stream (the
    /// pseudo console closed its end). Any other failure is error.ReadFailed,
    /// which the caller should treat as transient and keep reading: the
    /// output pipe must be drained until EOF or ClosePseudoConsole can hang.
    pub fn read(p: *Pty, buf: []u8) !usize {
        var n: w.DWORD = 0;
        const len: w.DWORD = @intCast(@min(buf.len, std.math.maxInt(w.DWORD)));
        if (w.ReadFile(p.out_read, buf.ptr, len, &n, null) == 0) {
            const err = w.GetLastError();
            // INVALID_HANDLE: the handle is gone, so no further data can come.
            if (err == w.ERROR_BROKEN_PIPE or err == w.ERROR_INVALID_HANDLE) return 0;
            return error.ReadFailed;
        }
        return n;
    }

    /// Writes all of `data` as keystrokes. Caller serialises concurrent writers.
    pub fn write(p: *Pty, data: []const u8) !void {
        var rest = data;
        while (rest.len > 0) {
            var n: w.DWORD = 0;
            const len: w.DWORD = @intCast(@min(rest.len, 1 << 20));
            if (w.WriteFile(p.in_write, rest.ptr, len, &n, null) == 0) return error.WriteFailed;
            rest = rest[n..];
        }
    }

    /// Caller must guarantee `close` has not started (Session.pty_live).
    pub fn resize(p: *Pty, size: Size) void {
        _ = w.ResizePseudoConsole(p.hpc, size.coord());
    }

    /// Blocks until the child exits; returns its exit code and closes the
    /// process handle. Call exactly once, from the one thread that waits
    /// for the child (the caller owns `process` from then on).
    pub fn waitExit(p: *Pty) u32 {
        _ = w.WaitForSingleObject(p.process, w.INFINITE);
        var code: w.DWORD = 1;
        _ = w.GetExitCodeProcess(p.process, &code);
        _ = w.CloseHandle(p.process);
        return code;
    }

    /// Closes the pseudo console: the output stream ends (once conhost has
    /// flushed it), and a child still running sees its console go away
    /// (CTRL_CLOSE_EVENT), its cue to exit. The job and the process handle
    /// stay: whoever waits for the child still needs them, and process exit
    /// closes the job (KILL_ON_JOB_CLOSE). The output reader must still be
    /// draining when this is called, or ClosePseudoConsole can block
    /// (before Windows 11 24H2 it waits for conhost to flush all output).
    /// Not thread safe: the caller must first stop every resize
    /// (Session.pty_live) and every write (Session.input_open), since HPCON
    /// and in_write are freed here.
    pub fn closeConsole(p: *Pty) void {
        if (p.closed) return;
        p.closed = true;
        w.ClosePseudoConsole(p.hpc);
        _ = w.CloseHandle(p.in_write);
    }

    /// Ends the child and everything it started, at once (the job). For a
    /// child that did not exit in time after `closeConsole`. Safe from any
    /// thread while `waitExit` runs: the job handle is never closed before
    /// the process exits.
    pub fn terminate(p: *Pty) void {
        _ = w.TerminateJobObject(p.job, 1);
    }

    /// After the child has exited and the output has drained (a closed
    /// tab): closes the output pipe and the job, which ends anything the
    /// program left running (KILL_ON_JOB_CLOSE).
    pub fn release(p: *Pty) void {
        _ = w.CloseHandle(p.out_read);
        _ = w.CloseHandle(p.job);
    }
};

// ------------------------------------------------------------- elevation

/// What `portal run` does about its own token. The child (and so every
/// key a paired device sends it) runs with Portal's token: elevated Portal
/// means remote input runs as administrator.
pub const ElevationCheck = enum {
    /// Not elevated: run.
    ok,
    /// Elevated (or unknown) without --allow-elevated: refuse to start.
    refuse,
    /// Elevated with --allow-elevated: run, with a loud warning.
    warn,
};

/// `elevated` is null when the token could not be queried; that counts as
/// elevated (fail closed).
pub fn elevationCheck(elevated: ?bool, allow_elevated: bool) ElevationCheck {
    const e = elevated orelse true;
    if (!e) return .ok;
    return if (allow_elevated) .warn else .refuse;
}

/// True if this process runs with an elevated token (TokenElevation), null
/// if that cannot be determined.
pub fn isElevated() ?bool {
    var token: ?w.HANDLE = null;
    const current: w.HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1)))); // GetCurrentProcess()
    if (OpenProcessToken(current, TOKEN_QUERY, &token) == 0) return null;
    const t = token orelse return null;
    defer _ = w.CloseHandle(t);
    var elevation: u32 = 0;
    var len: u32 = 0;
    if (GetTokenInformation(t, TokenElevation, &elevation, @sizeOf(u32), &len) == 0) return null;
    return elevation != 0;
}

const TOKEN_QUERY: u32 = 0x0008;
const TokenElevation: u32 = 20;
extern "advapi32" fn OpenProcessToken(process: w.HANDLE, access: u32, token: *?w.HANDLE) callconv(.winapi) w.BOOL;
extern "advapi32" fn GetTokenInformation(token: w.HANDLE, class: u32, info: ?*anyopaque, len: u32, ret_len: *u32) callconv(.winapi) w.BOOL;

test "elevation check" {
    try std.testing.expectEqual(ElevationCheck.ok, elevationCheck(false, false));
    try std.testing.expectEqual(ElevationCheck.ok, elevationCheck(false, true));
    try std.testing.expectEqual(ElevationCheck.refuse, elevationCheck(true, false));
    try std.testing.expectEqual(ElevationCheck.warn, elevationCheck(true, true));
    // Unknown token state fails closed.
    try std.testing.expectEqual(ElevationCheck.refuse, elevationCheck(null, false));
    try std.testing.expectEqual(ElevationCheck.warn, elevationCheck(null, true));
    // The query itself works here (the test shell's elevation is whatever it is).
    try std.testing.expect(isElevated() != null);
}
