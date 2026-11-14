//! Hand-declared Win32 surface used by the end-to-end harness.
//!
//! Same policy as src/win32.zig: std's Windows bindings and Io networking
//! churn between Zig releases, and the harness needs things std does not
//! expose (CREATE_NEW_CONSOLE with a hidden window, job objects, raw sockets
//! with receive timeouts and tiny receive buffers). Signatures mirror the
//! Microsoft documentation.

pub const HANDLE = *anyopaque;
pub const BOOL = c_int;
pub const DWORD = u32;
pub const WORD = u16;

pub const INFINITE: DWORD = 0xFFFFFFFF;
pub const WAIT_OBJECT_0: DWORD = 0;
pub const WAIT_TIMEOUT: DWORD = 258;

pub const CREATE_SUSPENDED: DWORD = 0x00000004;
pub const CREATE_NEW_CONSOLE: DWORD = 0x00000010;
pub const CREATE_UNICODE_ENVIRONMENT: DWORD = 0x00000400;
pub const CREATE_NO_WINDOW: DWORD = 0x08000000;
pub const EXTENDED_STARTUPINFO_PRESENT: DWORD = 0x00080000;
pub const STARTF_USESHOWWINDOW: DWORD = 0x00000001;
pub const STARTF_USESTDHANDLES: DWORD = 0x00000100;
pub const SW_HIDE: WORD = 0;
pub const HANDLE_FLAG_INHERIT: DWORD = 0x1;
pub const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x00020002;

pub const JobObjectExtendedLimitInformation: c_int = 9;
pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x00002000;

pub const SECURITY_ATTRIBUTES = extern struct {
    nLength: DWORD = @sizeOf(SECURITY_ATTRIBUTES),
    lpSecurityDescriptor: ?*anyopaque = null,
    bInheritHandle: BOOL = 0,
};

pub const STARTUPINFOW = extern struct {
    cb: DWORD,
    lpReserved: ?[*:0]u16 = null,
    lpDesktop: ?[*:0]u16 = null,
    lpTitle: ?[*:0]u16 = null,
    dwX: DWORD = 0,
    dwY: DWORD = 0,
    dwXSize: DWORD = 0,
    dwYSize: DWORD = 0,
    dwXCountChars: DWORD = 0,
    dwYCountChars: DWORD = 0,
    dwFillAttribute: DWORD = 0,
    dwFlags: DWORD = 0,
    wShowWindow: WORD = 0,
    cbReserved2: WORD = 0,
    lpReserved2: ?*u8 = null,
    hStdInput: ?HANDLE = null,
    hStdOutput: ?HANDLE = null,
    hStdError: ?HANDLE = null,
};

pub const STARTUPINFOEXW = extern struct {
    StartupInfo: STARTUPINFOW,
    lpAttributeList: ?*anyopaque = null,
};

pub const PROCESS_INFORMATION = extern struct {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: DWORD,
    dwThreadId: DWORD,
};

pub const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
    PerProcessUserTimeLimit: i64 = 0,
    PerJobUserTimeLimit: i64 = 0,
    LimitFlags: DWORD = 0,
    MinimumWorkingSetSize: usize = 0,
    MaximumWorkingSetSize: usize = 0,
    ActiveProcessLimit: DWORD = 0,
    Affinity: usize = 0,
    PriorityClass: DWORD = 0,
    SchedulingClass: DWORD = 0,
};

pub const IO_COUNTERS = extern struct {
    ReadOperationCount: u64 = 0,
    WriteOperationCount: u64 = 0,
    OtherOperationCount: u64 = 0,
    ReadTransferCount: u64 = 0,
    WriteTransferCount: u64 = 0,
    OtherTransferCount: u64 = 0,
};

pub const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION = .{},
    IoInfo: IO_COUNTERS = .{},
    ProcessMemoryLimit: usize = 0,
    JobMemoryLimit: usize = 0,
    PeakProcessMemoryUsed: usize = 0,
    PeakJobMemoryUsed: usize = 0,
};

pub extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;
pub extern "kernel32" fn CloseHandle(h: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn CreatePipe(read: *HANDLE, write: *HANDLE, sa: ?*const SECURITY_ATTRIBUTES, size: DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn SetHandleInformation(h: HANDLE, mask: DWORD, flags: DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn ReadFile(h: HANDLE, buf: [*]u8, len: DWORD, read: ?*DWORD, overlapped: ?*anyopaque) callconv(.winapi) BOOL;
pub extern "kernel32" fn WriteFile(h: HANDLE, buf: [*]const u8, len: DWORD, written: ?*DWORD, overlapped: ?*anyopaque) callconv(.winapi) BOOL;
pub extern "kernel32" fn PeekNamedPipe(h: HANDLE, buf: ?[*]u8, len: DWORD, read: ?*DWORD, avail: ?*DWORD, left: ?*DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn CreateProcessW(
    app: ?[*:0]const u16,
    cmdline: ?[*:0]u16,
    proc_attrs: ?*anyopaque,
    thread_attrs: ?*anyopaque,
    inherit: BOOL,
    flags: DWORD,
    env: ?*anyopaque,
    cwd: ?[*:0]const u16,
    si: *STARTUPINFOEXW,
    pi: *PROCESS_INFORMATION,
) callconv(.winapi) BOOL;
pub extern "kernel32" fn InitializeProcThreadAttributeList(list: ?*anyopaque, count: DWORD, flags: DWORD, size: *usize) callconv(.winapi) BOOL;
pub extern "kernel32" fn UpdateProcThreadAttribute(list: *anyopaque, flags: DWORD, attribute: usize, value: ?*const anyopaque, size: usize, prev: ?*anyopaque, ret_size: ?*usize) callconv(.winapi) BOOL;
pub extern "kernel32" fn DeleteProcThreadAttributeList(list: *anyopaque) callconv(.winapi) void;
pub extern "kernel32" fn ResumeThread(h: HANDLE) callconv(.winapi) DWORD;
pub extern "kernel32" fn TerminateProcess(h: HANDLE, code: u32) callconv(.winapi) BOOL;
pub extern "kernel32" fn WaitForSingleObject(h: HANDLE, ms: DWORD) callconv(.winapi) DWORD;
pub extern "kernel32" fn GetExitCodeProcess(h: HANDLE, code: *DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn CreateJobObjectW(attrs: ?*anyopaque, name: ?[*:0]const u16) callconv(.winapi) ?HANDLE;
pub extern "kernel32" fn SetInformationJobObject(job: HANDLE, class: c_int, info: *const anyopaque, len: DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn AssignProcessToJobObject(job: HANDLE, process: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetTickCount64() callconv(.winapi) u64;
pub extern "kernel32" fn Sleep(ms: DWORD) callconv(.winapi) void;
pub extern "kernel32" fn ExitProcess(code: u32) callconv(.winapi) noreturn;

// ---------------------------------------------------------------- winsock

pub const SOCKET = usize;
pub const INVALID_SOCKET: SOCKET = ~@as(usize, 0);
pub const AF_INET: c_int = 2;
pub const SOCK_STREAM: c_int = 1;
pub const IPPROTO_TCP: c_int = 6;
pub const WSA_FLAG_OVERLAPPED: DWORD = 0x01;
pub const WSA_FLAG_NO_HANDLE_INHERIT: DWORD = 0x80;
pub const SOL_SOCKET: c_int = 0xffff;
pub const SO_RCVBUF: c_int = 0x1002;
pub const SO_SNDTIMEO: c_int = 0x1005;
pub const SO_RCVTIMEO: c_int = 0x1006;
pub const TCP_NODELAY: c_int = 1;
pub const SD_SEND: c_int = 1;
pub const WSAETIMEDOUT: c_int = 10060;
pub const WSAECONNRESET: c_int = 10054;
pub const WSAECONNABORTED: c_int = 10053;

pub const sockaddr_in = extern struct {
    family: u16 = @intCast(AF_INET),
    port_be: u16,
    addr: [4]u8,
    zero: [8]u8 = @splat(0),
};

pub extern "ws2_32" fn WSAStartup(version: WORD, data: *anyopaque) callconv(.winapi) c_int;
pub extern "ws2_32" fn WSAGetLastError() callconv(.winapi) c_int;
pub extern "ws2_32" fn WSASocketW(af: c_int, kind: c_int, protocol: c_int, info: ?*anyopaque, g: u32, flags: DWORD) callconv(.winapi) SOCKET;
pub extern "ws2_32" fn connect(s: SOCKET, name: *const anyopaque, len: c_int) callconv(.winapi) c_int;
pub extern "ws2_32" fn bind(s: SOCKET, name: *const anyopaque, len: c_int) callconv(.winapi) c_int;
pub extern "ws2_32" fn send(s: SOCKET, buf: [*]const u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
pub extern "ws2_32" fn recv(s: SOCKET, buf: [*]u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
pub extern "ws2_32" fn setsockopt(s: SOCKET, level: c_int, name: c_int, val: *const anyopaque, len: c_int) callconv(.winapi) c_int;
pub extern "ws2_32" fn shutdown(s: SOCKET, how: c_int) callconv(.winapi) c_int;
pub extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) c_int;

// ------------------------------------------------------------------ locks

pub const SRWLOCK = extern struct { ptr: ?*anyopaque = null };
pub extern "kernel32" fn AcquireSRWLockExclusive(l: *SRWLOCK) callconv(.winapi) void;
pub extern "kernel32" fn ReleaseSRWLockExclusive(l: *SRWLOCK) callconv(.winapi) void;

/// std.Thread.Mutex is gone in 0.18 (std.Io.Mutex needs an Io); the
/// harness threads only need a plain lock.
pub const Mutex = struct {
    l: SRWLOCK = .{},
    pub fn lock(m: *Mutex) void {
        AcquireSRWLockExclusive(&m.l);
    }
    pub fn unlock(m: *Mutex) void {
        ReleaseSRWLockExclusive(&m.l);
    }
};

pub extern "kernel32" fn GetFullPathNameW(name: [*:0]const u16, len: DWORD, buf: [*]u16, file_part: ?*?[*:0]u16) callconv(.winapi) DWORD;

// Console injection (tests/e2e/console_tests.zig): a detached helper attaches
// to a portal --console instance and resizes / types into its console.
pub const COORD = extern struct { X: i16, Y: i16 };
pub const SMALL_RECT = extern struct { Left: i16, Top: i16, Right: i16, Bottom: i16 };
pub const CONSOLE_SCREEN_BUFFER_INFO = extern struct {
    dwSize: COORD,
    dwCursorPosition: COORD,
    wAttributes: WORD,
    srWindow: SMALL_RECT,
    dwMaximumWindowSize: COORD,
};
pub const KEY_EVENT_RECORD = extern struct {
    bKeyDown: BOOL,
    wRepeatCount: WORD,
    wVirtualKeyCode: WORD,
    wVirtualScanCode: WORD,
    UnicodeChar: u16,
    dwControlKeyState: DWORD,
};
pub const INPUT_RECORD = extern struct {
    EventType: WORD,
    Event: extern union { KeyEvent: KEY_EVENT_RECORD, raw: [16]u8 },
};
pub const DETACHED_PROCESS: DWORD = 0x00000008;
pub const GENERIC_READ_WRITE: DWORD = 0x80000000 | 0x40000000;
pub const FILE_SHARE_RW: DWORD = 0x1 | 0x2;
pub const OPEN_EXISTING_: DWORD = 3;
pub extern "kernel32" fn AttachConsole(pid: DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn FreeConsole() callconv(.winapi) BOOL;
pub extern "kernel32" fn GetProcessId(h: HANDLE) callconv(.winapi) DWORD;
pub extern "kernel32" fn GetModuleFileNameW(module: ?HANDLE, buf: [*]u16, len: DWORD) callconv(.winapi) DWORD;
pub extern "kernel32" fn CreateFileW(name: [*:0]const u16, access: DWORD, share: DWORD, sa: ?*anyopaque, disposition: DWORD, flags: DWORD, template: ?HANDLE) callconv(.winapi) HANDLE;
pub extern "kernel32" fn GetConsoleScreenBufferInfo(h: HANDLE, info: *CONSOLE_SCREEN_BUFFER_INFO) callconv(.winapi) BOOL;
pub extern "kernel32" fn SetConsoleScreenBufferSize(h: HANDLE, size: COORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn SetConsoleWindowInfo(h: HANDLE, absolute: BOOL, rect: *const SMALL_RECT) callconv(.winapi) BOOL;
pub extern "kernel32" fn WriteConsoleInputW(h: HANDLE, recs: [*]const INPUT_RECORD, n: DWORD, written: *DWORD) callconv(.winapi) BOOL;
