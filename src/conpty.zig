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

        var si: w.STARTUPINFOEXW = .{
            .StartupInfo = .{ .cb = @sizeOf(w.STARTUPINFOEXW) },
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
            null,
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
        _ = w.ResumeThread(pi.hThread);

        return .{ .hpc = hpc, .in_write = in_write, .out_read = out_read, .process = pi.hProcess, .job = job };
    }

    /// Blocking read of terminal output. Returns 0 at end of stream.
    pub fn read(p: *Pty, buf: []u8) !usize {
        var n: w.DWORD = 0;
        const len: w.DWORD = @intCast(@min(buf.len, std.math.maxInt(w.DWORD)));
        if (w.ReadFile(p.out_read, buf.ptr, len, &n, null) == 0) {
            const err = w.GetLastError();
            if (err == w.ERROR_BROKEN_PIPE) return 0;
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

    pub fn resize(p: *Pty, size: Size) void {
        _ = w.ResizePseudoConsole(p.hpc, size.coord());
    }

    /// Blocks until the child exits; returns its exit code.
    pub fn wait(p: *Pty) u32 {
        _ = w.WaitForSingleObject(p.process, w.INFINITE);
        var code: w.DWORD = 1;
        _ = w.GetExitCodeProcess(p.process, &code);
        return code;
    }

    /// Closes the pseudo console (which ends the output stream) and kills
    /// anything left in the job. The output reader must still be draining
    /// when this is called, or ClosePseudoConsole can block.
    pub fn close(p: *Pty) void {
        if (p.closed) return;
        p.closed = true;
        w.ClosePseudoConsole(p.hpc);
        _ = w.CloseHandle(p.in_write);
        _ = w.CloseHandle(p.job); // KILL_ON_JOB_CLOSE
        _ = w.CloseHandle(p.process);
    }
};
