//! Starting and stopping Portal instances for the end-to-end tests.
//!
//! * Every child goes into one job object with KILL_ON_JOB_CLOSE, so all of
//!   them die when the harness exits, however it exits (failure, panic,
//!   Ctrl+C). Instances are also killed explicitly at the end of each group.
//! * The exe under test is portalctl.exe, the console tool (portal.exe is
//!   the GUI window and has no console). `portalctl run --console` needs a
//!   real console: it is started with CREATE_NEW_CONSOLE and a hidden
//!   window (STARTF_USESHOWWINDOW + SW_HIDE) so it does not steal focus.
//!   std.process.spawn exposes neither, hence CreateProcessW.
//! * Each instance gets a scratch data directory by setting LOCALAPPDATA in
//!   the child's environment block only. The harness's own environment is
//!   never modified.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const w = @import("win.zig");
const net = @import("net.zig");
const http = @import("http.zig");
const tlsnet = @import("tlsnet.zig");

pub const Harness = struct {
    gpa: Allocator,
    io: Io,
    env: *const std.process.Environ.Map,
    exe: []const u8,
    /// %TEMP%\portal-e2e-<random>
    root: []const u8,
    job: ?w.HANDLE,
    mutex: w.Mutex = .{},
    live: std.ArrayList(*Instance) = .empty,

    pub fn init(gpa: Allocator, io: Io, env: *const std.process.Environ.Map, exe: []const u8) !Harness {
        const temp = env.get("TEMP") orelse env.get("TMP") orelse return error.NoTemp;
        var rnd: [4]u8 = undefined;
        io.random(&rnd);
        const root = try std.fmt.allocPrint(gpa, "{s}\\portal-e2e-{x}", .{ temp, &rnd });
        try Io.Dir.cwd().createDirPath(io, root);

        // Kill everything we start when this process ends, however it ends.
        const job = w.CreateJobObjectW(null, null);
        if (job) |j| {
            var info: w.JOBOBJECT_EXTENDED_LIMIT_INFORMATION = .{};
            info.BasicLimitInformation.LimitFlags = w.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            _ = w.SetInformationJobObject(j, w.JobObjectExtendedLimitInformation, &info, @sizeOf(w.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        }
        return .{ .gpa = gpa, .io = io, .env = env, .exe = try absolutePath(gpa, exe), .root = root, .job = job };
    }

    /// Kills every instance still running and deletes the scratch tree.
    pub fn deinit(h: *Harness) void {
        h.mutex.lock();
        const list = h.live.items;
        h.mutex.unlock();
        for (list) |inst| inst.kill();
        // Files can stay locked for a moment after the processes die.
        var tries: u32 = 0;
        while (tries < 20) : (tries += 1) {
            Io.Dir.cwd().deleteTree(h.io, h.root) catch {
                net.sleep(250);
                continue;
            };
            break;
        }
        if (tries == 20) std.debug.print("note: could not delete {s}\n", .{h.root});
    }

    pub fn dataDir(h: *Harness, name: []const u8) ![]u8 {
        const d = try std.fmt.allocPrint(h.gpa, "{s}\\{s}", .{ h.root, name });
        try Io.Dir.cwd().createDirPath(h.io, d);
        return d;
    }

    /// Environment block: the harness's environment with LOCALAPPDATA
    /// pointing at `local_app_data`, a short cmd.exe prompt, and no
    /// ZIG_PROGRESS.
    fn envBlock(h: *Harness, local_app_data: []const u8) ![:0]const u16 {
        var m = try h.env.clone(h.gpa);
        defer m.deinit();
        _ = m.swapRemove("ZIG_PROGRESS");
        try m.put("LOCALAPPDATA", local_app_data);
        try m.put("PROMPT", "E2E$G");
        const block = try m.createWindowsBlock(h.gpa, .{});
        return block.slice;
    }

    fn track(h: *Harness, inst: *Instance) void {
        h.mutex.lock();
        defer h.mutex.unlock();
        h.live.append(h.gpa, inst) catch {};
    }
};

/// Absolute form of `path` (the build passes a cwd-relative exe path, and
/// children run in their own directory).
pub fn absolutePath(gpa: Allocator, path: []const u8) ![]u8 {
    const in = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, path);
    defer gpa.free(in);
    var buf: [32768]u16 = undefined;
    const n = w.GetFullPathNameW(in.ptr, buf.len, &buf, null);
    if (n == 0 or n >= buf.len) return error.BadPath;
    return std.unicode.wtf16LeToWtf8Alloc(gpa, buf[0..n]);
}

fn appendQuoted(list: *std.ArrayList(u8), gpa: Allocator, arg: []const u8) !void {
    const needs_quotes = arg.len == 0 or std.mem.indexOfAny(u8, arg, " \t\n\x0b\"") != null;
    if (!needs_quotes) return list.appendSlice(gpa, arg);
    try list.append(gpa, '"');
    var backslashes: usize = 0;
    for (arg) |c| {
        if (c == '\\') {
            backslashes += 1;
            continue;
        }
        try list.appendNTimes(gpa, '\\', if (c == '"') backslashes * 2 + 1 else backslashes);
        backslashes = 0;
        try list.append(gpa, c);
    }
    try list.appendNTimes(gpa, '\\', backslashes * 2);
    try list.append(gpa, '"');
}

const SpawnMode = union(enum) {
    /// New hidden console window.
    console,
    /// No window; stdout and stderr go to `out` (an inheritable pipe
    /// handle), stdin comes from `in` if set.
    capture: struct { out: w.HANDLE, in: ?w.HANDLE = null },
};

fn spawn(h: *Harness, argv: []const []const u8, local_app_data: []const u8, mode: SpawnMode) !w.PROCESS_INFORMATION {
    const gpa = h.gpa;
    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(gpa);
    try appendQuoted(&line, gpa, h.exe);
    for (argv) |a| {
        try line.append(gpa, ' ');
        try appendQuoted(&line, gpa, a);
    }
    const app_w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, h.exe);
    defer gpa.free(app_w);
    const line_w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, line.items);
    defer gpa.free(line_w);
    const cwd_w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, local_app_data);
    defer gpa.free(cwd_w);
    const env = try h.envBlock(local_app_data);
    defer gpa.free(env);

    var si: w.STARTUPINFOEXW = .{ .StartupInfo = .{ .cb = @sizeOf(w.STARTUPINFOEXW) } };
    var flags: w.DWORD = w.CREATE_SUSPENDED | w.CREATE_UNICODE_ENVIRONMENT | w.EXTENDED_STARTUPINFO_PRESENT;
    var inherit: w.BOOL = 0;
    var attr_mem: ?[]align(16) u8 = null;
    defer if (attr_mem) |m| {
        w.DeleteProcThreadAttributeList(m.ptr);
        gpa.free(m);
    };
    var handles: [2]w.HANDLE = undefined;
    switch (mode) {
        .console => {
            flags |= w.CREATE_NEW_CONSOLE;
            si.StartupInfo.dwFlags = w.STARTF_USESHOWWINDOW;
            si.StartupInfo.wShowWindow = w.SW_HIDE;
        },
        .capture => |pipes| {
            flags |= w.CREATE_NO_WINDOW;
            si.StartupInfo.dwFlags = w.STARTF_USESTDHANDLES;
            si.StartupInfo.hStdOutput = pipes.out;
            si.StartupInfo.hStdError = pipes.out;
            if (pipes.in) |in| si.StartupInfo.hStdInput = in;
            inherit = 1;
            // Inherit only the pipes, never the harness's sockets.
            handles[0] = pipes.out;
            var n_handles: usize = 1;
            if (pipes.in) |in| {
                handles[1] = in;
                n_handles = 2;
            }
            var size: usize = 0;
            _ = w.InitializeProcThreadAttributeList(null, 1, 0, &size);
            const m = try gpa.alignedAlloc(u8, .@"16", size);
            attr_mem = m;
            if (w.InitializeProcThreadAttributeList(m.ptr, 1, 0, &size) == 0) {
                gpa.free(m);
                attr_mem = null;
                return error.AttributeList;
            }
            if (w.UpdateProcThreadAttribute(m.ptr, 0, w.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &handles, n_handles * @sizeOf(w.HANDLE), null, null) == 0)
                return error.AttributeList;
            si.lpAttributeList = m.ptr;
        },
    }
    var pi: w.PROCESS_INFORMATION = undefined;
    if (w.CreateProcessW(app_w.ptr, line_w.ptr, null, null, inherit, flags, @ptrCast(@constCast(env.ptr)), cwd_w.ptr, &si, &pi) == 0) {
        std.debug.print("CreateProcessW failed: {d}\n", .{w.GetLastError()});
        return error.SpawnFailed;
    }
    if (h.job) |j| _ = w.AssignProcessToJobObject(j, pi.hProcess);
    _ = w.ResumeThread(pi.hThread);
    _ = w.CloseHandle(pi.hThread);
    return pi;
}

pub const CliResult = struct {
    code: u32,
    /// stdout and stderr together (Portal prints to stderr).
    out: []u8,

    pub fn has(r: CliResult, needle: []const u8) bool {
        return std.mem.indexOf(u8, r.out, needle) != null;
    }
};

/// Runs `portal <args>` with LOCALAPPDATA = `local_app_data` and captures
/// its output.
pub fn runCli(h: *Harness, local_app_data: []const u8, args: []const []const u8) !CliResult {
    var sa: w.SECURITY_ATTRIBUTES = .{ .bInheritHandle = 1 };
    var rd: w.HANDLE = undefined;
    var wr: w.HANDLE = undefined;
    if (w.CreatePipe(&rd, &wr, &sa, 64 * 1024) == 0) return error.PipeFailed;
    defer _ = w.CloseHandle(rd);
    _ = w.SetHandleInformation(rd, w.HANDLE_FLAG_INHERIT, 0);
    const pi = spawn(h, args, local_app_data, .{ .capture = .{ .out = wr } }) catch |err| {
        _ = w.CloseHandle(wr);
        return err;
    };
    _ = w.CloseHandle(wr);
    defer _ = w.CloseHandle(pi.hProcess);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(h.gpa);
    if (w.WaitForSingleObject(pi.hProcess, 20_000) != w.WAIT_OBJECT_0) {
        _ = w.TerminateProcess(pi.hProcess, 1);
        return error.CliTimeout;
    }
    var buf: [4096]u8 = undefined;
    while (true) {
        var n: w.DWORD = 0;
        if (w.ReadFile(rd, &buf, buf.len, &n, null) == 0 or n == 0) break;
        try out.appendSlice(h.gpa, buf[0..n]);
    }
    var code: w.DWORD = 1;
    _ = w.GetExitCodeProcess(pi.hProcess, &code);
    return .{ .code = code, .out = try out.toOwnedSlice(h.gpa) };
}

/// A long-running CLI child (`portal pair`) whose output can be watched
/// while it runs and which can be answered through its stdin.
pub const LiveCli = struct {
    h: *Harness,
    process: ?w.HANDLE,
    out_rd: w.HANDLE,
    in_wr: ?w.HANDLE,
    out: std.ArrayList(u8) = .empty,
    code: ?u32 = null,

    pub fn start(h: *Harness, local_app_data: []const u8, args: []const []const u8) !*LiveCli {
        var sa: w.SECURITY_ATTRIBUTES = .{ .bInheritHandle = 1 };
        var out_rd: w.HANDLE = undefined;
        var out_wr: w.HANDLE = undefined;
        if (w.CreatePipe(&out_rd, &out_wr, &sa, 64 * 1024) == 0) return error.PipeFailed;
        _ = w.SetHandleInformation(out_rd, w.HANDLE_FLAG_INHERIT, 0);
        var in_rd: w.HANDLE = undefined;
        var in_wr: w.HANDLE = undefined;
        if (w.CreatePipe(&in_rd, &in_wr, &sa, 4096) == 0) return error.PipeFailed;
        _ = w.SetHandleInformation(in_wr, w.HANDLE_FLAG_INHERIT, 0);
        const pi = spawn(h, args, local_app_data, .{ .capture = .{ .out = out_wr, .in = in_rd } }) catch |err| {
            for ([_]w.HANDLE{ out_rd, out_wr, in_rd, in_wr }) |x| _ = w.CloseHandle(x);
            return err;
        };
        _ = w.CloseHandle(out_wr);
        _ = w.CloseHandle(in_rd);
        const c = try h.gpa.create(LiveCli);
        c.* = .{ .h = h, .process = pi.hProcess, .out_rd = out_rd, .in_wr = in_wr };
        return c;
    }

    /// Reads whatever output is available without blocking.
    fn drain(c: *LiveCli) void {
        var buf: [4096]u8 = undefined;
        while (true) {
            var avail: w.DWORD = 0;
            if (w.PeekNamedPipe(c.out_rd, null, 0, null, &avail, null) == 0 or avail == 0) return;
            var n: w.DWORD = 0;
            if (w.ReadFile(c.out_rd, &buf, @min(avail, buf.len), &n, null) == 0 or n == 0) return;
            c.out.appendSlice(c.h.gpa, buf[0..n]) catch return;
        }
    }

    pub fn output(c: *LiveCli) []const u8 {
        c.drain();
        return c.out.items;
    }

    pub fn has(c: *LiveCli, needle: []const u8) bool {
        return std.mem.indexOf(u8, c.output(), needle) != null;
    }

    pub fn count(c: *LiveCli, needle: []const u8) usize {
        return std.mem.count(u8, c.output(), needle);
    }

    /// Waits until the output contains `needle` at least `n` times.
    pub fn waitForCount(c: *LiveCli, needle: []const u8, n: usize, ms: u32) bool {
        const deadline = net.now() + ms;
        while (true) {
            if (c.count(needle) >= n) return true;
            if (net.now() >= deadline or !c.alive()) return c.count(needle) >= n;
            net.sleep(20);
        }
    }

    pub fn waitFor(c: *LiveCli, needle: []const u8, ms: u32) bool {
        return c.waitForCount(needle, 1, ms);
    }

    /// Text after the last `prefix` in the output, up to `len` bytes.
    pub fn lastAfter(c: *LiveCli, prefix: []const u8, len: usize) ?[]const u8 {
        const o = c.output();
        const i = std.mem.lastIndexOf(u8, o, prefix) orelse return null;
        const s = i + prefix.len;
        if (o.len < s + len) return null;
        return o[s .. s + len];
    }

    /// Types a line into its stdin.
    pub fn answer(c: *LiveCli, line: []const u8) void {
        const h = c.in_wr orelse return;
        var n: w.DWORD = 0;
        _ = w.WriteFile(h, line.ptr, @intCast(line.len), &n, null);
    }

    pub fn closeInput(c: *LiveCli) void {
        if (c.in_wr) |h| _ = w.CloseHandle(h);
        c.in_wr = null;
    }

    pub fn alive(c: *LiveCli) bool {
        const p = c.process orelse return false;
        return w.WaitForSingleObject(p, 0) == w.WAIT_TIMEOUT;
    }

    /// Exit code once it has exited within `ms`, else null.
    pub fn wait(c: *LiveCli, ms: u32) ?u32 {
        if (c.code) |code| return code;
        const p = c.process orelse return null;
        const deadline = net.now() + ms;
        while (w.WaitForSingleObject(p, 20) != w.WAIT_OBJECT_0) {
            c.drain();
            if (net.now() >= deadline) return null;
        }
        c.drain();
        var code: w.DWORD = 1;
        _ = w.GetExitCodeProcess(p, &code);
        c.code = code;
        return code;
    }

    pub fn kill(c: *LiveCli) void {
        const p = c.process orelse return;
        if (c.alive()) _ = w.TerminateProcess(p, 1);
        _ = w.WaitForSingleObject(p, 10_000);
        c.drain();
    }

    pub fn deinit(c: *LiveCli) void {
        c.kill();
        if (c.process) |p| _ = w.CloseHandle(p);
        c.closeInput();
        _ = w.CloseHandle(c.out_rd);
        c.out.deinit(c.h.gpa);
        c.h.gpa.destroy(c);
    }
};

pub const Instance = struct {
    h: *Harness,
    port: u16,
    /// LOCALAPPDATA of the instance; Portal keeps its files in <this>\Portal.
    data_dir: []const u8,
    process: ?w.HANDLE = null,
    host_buf: [32]u8 = undefined,
    origin_buf: [40]u8 = undefined,
    host: []const u8 = "",
    origin: []const u8 = "",
    /// Set by startTls: HTTPS/WSS trusting only this instance's exported CA.
    tls: ?*tlsnet.Trust = null,
    /// startTls: where `portal ca export` wrote the CA files.
    ca_dir: []const u8 = "",

    /// Starts `portalctl run --console --listen 127.0.0.1:<port> <run_args...>`
    /// and waits until it answers HTTP.
    pub fn start(h: *Harness, data_dir: []const u8, port: u16, run_args: []const []const u8) !*Instance {
        const inst = try h.gpa.create(Instance);
        inst.* = .{ .h = h, .port = port, .data_dir = data_dir };
        inst.host = try std.fmt.bufPrint(&inst.host_buf, "127.0.0.1:{d}", .{port});
        inst.origin = try std.fmt.bufPrint(&inst.origin_buf, "http://127.0.0.1:{d}", .{port});

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(h.gpa);
        // --console: the e2e suite tests the server, not the GUI window.
        // --no-tls: the harness speaks plain HTTP (TLS has its own tests).
        try argv.appendSlice(h.gpa, &.{ "run", "--console", "--no-tls", "--listen", inst.host });
        try argv.appendSlice(h.gpa, run_args);
        const pi = try spawn(h, argv.items, data_dir, .console);
        inst.process = pi.hProcess;
        h.track(inst);

        const deadline = net.now() + 15_000;
        while (net.now() < deadline) {
            if (!inst.alive()) return error.PortalExited;
            if (http.request(h.gpa, port, .{ .path = "/pair", .host = inst.host })) |r| {
                var resp = r;
                defer resp.deinit();
                if (resp.status == 200) return inst;
            } else |_| {}
            net.sleep(100);
        }
        return error.PortalDidNotStart;
    }

    /// Like `start`, but with TLS on (Portal's default: no `--no-tls`).
    /// Once the port listens (the CA exists by then), exports the CA with
    /// `portal ca export --out <data_dir>\ca-export` and trusts only that
    /// for every request made through this instance; waits until
    /// GET /pair answers 200 over HTTPS.
    pub fn startTls(h: *Harness, data_dir: []const u8, port: u16, run_args: []const []const u8) !*Instance {
        const inst = try h.gpa.create(Instance);
        inst.* = .{ .h = h, .port = port, .data_dir = data_dir };
        inst.host = try std.fmt.bufPrint(&inst.host_buf, "127.0.0.1:{d}", .{port});
        inst.origin = try std.fmt.bufPrint(&inst.origin_buf, "https://127.0.0.1:{d}", .{port});

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(h.gpa);
        try argv.appendSlice(h.gpa, &.{ "run", "--console", "--listen", inst.host });
        try argv.appendSlice(h.gpa, run_args);
        const pi = try spawn(h, argv.items, data_dir, .console);
        inst.process = pi.hProcess;
        h.track(inst);

        const deadline = net.now() + 20_000;
        while (true) : (net.sleep(100)) {
            if (!inst.alive()) return error.PortalExited;
            if (net.now() >= deadline) return error.PortalDidNotStart;
            var s = net.Socket.connect(port, .{}) catch continue;
            s.close();
            break;
        }
        inst.ca_dir = try std.fmt.allocPrint(h.gpa, "{s}\\ca-export", .{data_dir});
        const ex = try runCli(h, data_dir, &.{ "ca", "export", "--out", inst.ca_dir });
        if (ex.code != 0) {
            std.debug.print("portal ca export failed:\n{s}\n", .{ex.out});
            return error.CaExportFailed;
        }
        const pem = try std.fmt.allocPrint(h.gpa, "{s}\\portal-ca.pem", .{inst.ca_dir});
        defer h.gpa.free(pem);
        inst.tls = try tlsnet.Trust.load(h.gpa, h.io, pem);
        while (net.now() < deadline) : (net.sleep(100)) {
            if (!inst.alive()) return error.PortalExited;
            var resp = http.request(h.gpa, port, .{ .path = "/pair", .host = inst.host, .tls = inst.tls }) catch continue;
            defer resp.deinit();
            if (resp.status == 200) return inst;
        }
        return error.PortalDidNotStart;
    }

    pub fn alive(inst: *const Instance) bool {
        const p = inst.process orelse return false;
        return w.WaitForSingleObject(p, 0) == w.WAIT_TIMEOUT;
    }

    pub fn kill(inst: *Instance) void {
        const p = inst.process orelse return;
        _ = w.TerminateProcess(p, 1);
        _ = w.WaitForSingleObject(p, 10_000);
        _ = w.CloseHandle(p);
        inst.process = null;
    }

    pub fn cli(inst: *Instance, args: []const []const u8) !CliResult {
        return runCli(inst.h, inst.data_dir, args);
    }

    /// Starts a long-running CLI command (e.g. `portal pair`) for this instance.
    pub fn liveCli(inst: *Instance, args: []const []const u8) !*LiveCli {
        return LiveCli.start(inst.h, inst.data_dir, args);
    }

    /// Current contents of portal.log.
    pub fn log(inst: *Instance) ![]u8 {
        const path = try std.fmt.allocPrint(inst.h.gpa, "{s}\\Portal\\portal.log", .{inst.data_dir});
        defer inst.h.gpa.free(path);
        return Io.Dir.cwd().readFileAlloc(inst.h.io, path, inst.h.gpa, .limited(16 * 1024 * 1024));
    }

    pub fn logHas(inst: *Instance, needle: []const u8) bool {
        const text = inst.log() catch return false;
        defer inst.h.gpa.free(text);
        return std.mem.indexOf(u8, text, needle) != null;
    }
};
