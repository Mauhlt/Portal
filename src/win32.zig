//! Minimal hand-declared Win32 surface used by Portal.
//!
//! Declared locally on purpose: std.os.windows bindings churn between Zig
//! releases (kernel32 wrappers are being removed in favour of ntdll). Owning
//! these ~30 declarations keeps Portal building across compiler upgrades.
//! Every signature here mirrors the Microsoft documentation exactly.

pub const HANDLE = *anyopaque;
pub const BOOL = c_int;
pub const DWORD = u32;
pub const WORD = u16;
pub const HRESULT = i32;
pub const HPCON = *anyopaque;

pub const INVALID_HANDLE_VALUE: usize = @bitCast(@as(isize, -1));
pub const INFINITE: DWORD = 0xFFFFFFFF;
pub const WAIT_OBJECT_0: DWORD = 0;
pub const WAIT_TIMEOUT: DWORD = 258;
pub const WAIT_FAILED: DWORD = 0xFFFFFFFF;

pub const STARTF_USESTDHANDLES: DWORD = 0x00000100;
pub const STD_INPUT_HANDLE: DWORD = @bitCast(@as(i32, -10));
pub const STD_OUTPUT_HANDLE: DWORD = @bitCast(@as(i32, -11));
pub const STD_ERROR_HANDLE: DWORD = @bitCast(@as(i32, -12));

// Console input modes
pub const ENABLE_PROCESSED_INPUT: DWORD = 0x0001;
pub const ENABLE_LINE_INPUT: DWORD = 0x0002;
pub const ENABLE_ECHO_INPUT: DWORD = 0x0004;
pub const ENABLE_WINDOW_INPUT: DWORD = 0x0008;
pub const ENABLE_MOUSE_INPUT: DWORD = 0x0010;
pub const ENABLE_QUICK_EDIT_MODE: DWORD = 0x0040;
pub const ENABLE_EXTENDED_FLAGS: DWORD = 0x0080;
pub const ENABLE_VIRTUAL_TERMINAL_INPUT: DWORD = 0x0200;
// Console output modes
pub const ENABLE_PROCESSED_OUTPUT: DWORD = 0x0001;
pub const ENABLE_VIRTUAL_TERMINAL_PROCESSING: DWORD = 0x0004;
pub const DISABLE_NEWLINE_AUTO_RETURN: DWORD = 0x0008;

pub const CP_UTF8: u32 = 65001;

pub const EXTENDED_STARTUPINFO_PRESENT: DWORD = 0x00080000;
pub const CREATE_SUSPENDED: DWORD = 0x00000004;
pub const CREATE_UNICODE_ENVIRONMENT: DWORD = 0x00000400;
pub const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x00020016;

pub const JobObjectExtendedLimitInformation: c_int = 9;
pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x00002000;

pub const ERROR_BROKEN_PIPE: DWORD = 109;
pub const ERROR_OPERATION_ABORTED: DWORD = 995;
pub const ERROR_INVALID_HANDLE: DWORD = 6;

pub const COORD = extern struct { X: i16, Y: i16 };
pub const SMALL_RECT = extern struct { Left: i16, Top: i16, Right: i16, Bottom: i16 };

pub const CONSOLE_SCREEN_BUFFER_INFO = extern struct {
    dwSize: COORD,
    dwCursorPosition: COORD,
    wAttributes: WORD,
    srWindow: SMALL_RECT,
    dwMaximumWindowSize: COORD,
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
    lpAttributeList: ?*anyopaque,
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
pub extern "kernel32" fn CreatePipe(read: *HANDLE, write: *HANDLE, sa: ?*anyopaque, size: DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn PeekNamedPipe(h: HANDLE, buf: ?[*]u8, len: DWORD, read: ?*DWORD, avail: ?*DWORD, left: ?*DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn ReadFile(h: HANDLE, buf: [*]u8, len: DWORD, read: ?*DWORD, overlapped: ?*anyopaque) callconv(.winapi) BOOL;
pub extern "kernel32" fn WriteFile(h: HANDLE, buf: [*]const u8, len: DWORD, written: ?*DWORD, overlapped: ?*anyopaque) callconv(.winapi) BOOL;

pub extern "kernel32" fn CreatePseudoConsole(size: COORD, in: HANDLE, out: HANDLE, flags: DWORD, hpc: *HPCON) callconv(.winapi) HRESULT;
pub extern "kernel32" fn ResizePseudoConsole(hpc: HPCON, size: COORD) callconv(.winapi) HRESULT;
pub extern "kernel32" fn ClosePseudoConsole(hpc: HPCON) callconv(.winapi) void;

pub extern "kernel32" fn InitializeProcThreadAttributeList(list: ?*anyopaque, count: DWORD, flags: DWORD, size: *usize) callconv(.winapi) BOOL;
pub extern "kernel32" fn UpdateProcThreadAttribute(list: *anyopaque, flags: DWORD, attribute: usize, value: ?*const anyopaque, size: usize, prev: ?*anyopaque, ret_size: ?*usize) callconv(.winapi) BOOL;
pub extern "kernel32" fn DeleteProcThreadAttributeList(list: *anyopaque) callconv(.winapi) void;

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
pub extern "kernel32" fn ResumeThread(h: HANDLE) callconv(.winapi) DWORD;
pub extern "kernel32" fn TerminateProcess(h: HANDLE, code: u32) callconv(.winapi) BOOL;
pub extern "kernel32" fn WaitForSingleObject(h: HANDLE, ms: DWORD) callconv(.winapi) DWORD;
pub extern "kernel32" fn WaitForMultipleObjects(n: DWORD, handles: [*]const HANDLE, all: BOOL, ms: DWORD) callconv(.winapi) DWORD;
pub extern "kernel32" fn GetExitCodeProcess(h: HANDLE, code: *DWORD) callconv(.winapi) BOOL;
/// Used instead of std.process.exit, which only takes a u8: Windows exit
/// codes are 32 bits and Portal passes the child's code through unchanged.
pub extern "kernel32" fn ExitProcess(code: u32) callconv(.winapi) noreturn;

pub extern "kernel32" fn CreateJobObjectW(attrs: ?*anyopaque, name: ?[*:0]const u16) callconv(.winapi) ?HANDLE;
pub extern "kernel32" fn SetInformationJobObject(job: HANDLE, class: c_int, info: *const anyopaque, len: DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn AssignProcessToJobObject(job: HANDLE, process: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn TerminateJobObject(job: HANDLE, code: u32) callconv(.winapi) BOOL;

pub extern "kernel32" fn GetStdHandle(which: DWORD) callconv(.winapi) ?HANDLE;
pub extern "kernel32" fn GetConsoleMode(h: HANDLE, mode: *DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn SetConsoleMode(h: HANDLE, mode: DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetConsoleScreenBufferInfo(h: HANDLE, info: *CONSOLE_SCREEN_BUFFER_INFO) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetConsoleCP() callconv(.winapi) u32;
pub extern "kernel32" fn GetConsoleOutputCP() callconv(.winapi) u32;
pub extern "kernel32" fn SetConsoleCP(cp: u32) callconv(.winapi) BOOL;
pub extern "kernel32" fn SetConsoleOutputCP(cp: u32) callconv(.winapi) BOOL;
pub extern "kernel32" fn SetConsoleTitleW(title: [*:0]const u16) callconv(.winapi) BOOL;

pub fn validHandle(h: ?HANDLE) ?HANDLE {
    const v = h orelse return null;
    if (@intFromPtr(v) == INVALID_HANDLE_VALUE) return null;
    return v;
}

pub const FILE_APPEND_DATA: DWORD = 0x0004;
pub const FILE_SHARE_READ: DWORD = 0x0001;
pub const FILE_SHARE_WRITE: DWORD = 0x0002;
pub const MOVEFILE_REPLACE_EXISTING: DWORD = 0x1;
pub const OPEN_ALWAYS: DWORD = 4;
pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;

pub extern "kernel32" fn CreateFileW(
    name: [*:0]const u16,
    access: DWORD,
    share: DWORD,
    sa: ?*anyopaque,
    disposition: DWORD,
    flags: DWORD,
    template: ?HANDLE,
) callconv(.winapi) ?HANDLE;
// Directory change notifications (fsutil.DirWatch).
pub const FILE_NOTIFY_CHANGE_FILE_NAME: DWORD = 0x1;
pub const FILE_NOTIFY_CHANGE_DIR_NAME: DWORD = 0x2;
pub extern "kernel32" fn FindFirstChangeNotificationW(path: [*:0]const u16, subtree: BOOL, filter: DWORD) callconv(.winapi) ?HANDLE;
pub extern "kernel32" fn FindNextChangeNotification(h: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn FindCloseChangeNotification(h: HANDLE) callconv(.winapi) BOOL;

pub extern "kernel32" fn GetFileSizeEx(h: HANDLE, size: *i64) callconv(.winapi) BOOL;
pub extern "kernel32" fn MoveFileExW(from: [*:0]const u16, to: [*:0]const u16, flags: DWORD) callconv(.winapi) BOOL;

pub const GENERIC_WRITE: DWORD = 0x40000000;
pub const MOVEFILE_WRITE_THROUGH: DWORD = 0x8;

// Console input records (ReadConsoleInputW): keystrokes and window-size
// changes arrive through the same blocking wait, so console mode needs no
// resize polling.
pub const KEY_EVENT: WORD = 0x0001;
pub const MOUSE_EVENT: WORD = 0x0002;
pub const WINDOW_BUFFER_SIZE_EVENT: WORD = 0x0004;
pub const MENU_EVENT: WORD = 0x0008;
pub const FOCUS_EVENT: WORD = 0x0010;

pub const KEY_EVENT_RECORD = extern struct {
    bKeyDown: BOOL,
    wRepeatCount: WORD,
    wVirtualKeyCode: WORD,
    wVirtualScanCode: WORD,
    /// union { WCHAR UnicodeChar; CHAR AsciiChar; } — we use the W API.
    UnicodeChar: u16,
    dwControlKeyState: DWORD,
};

pub const INPUT_RECORD = extern struct {
    EventType: WORD,
    Event: extern union {
        KeyEvent: KEY_EVENT_RECORD,
        WindowBufferSizeEvent: extern struct { dwSize: COORD },
        raw: [16]u8,
    },
};

comptime {
    // Layout from wincon.h: 4-byte aligned union after the WORD tag.
    if (@sizeOf(KEY_EVENT_RECORD) != 16 or @sizeOf(INPUT_RECORD) != 20) @compileError("INPUT_RECORD layout");
}

pub extern "kernel32" fn ReadConsoleInputW(h: HANDLE, buf: [*]INPUT_RECORD, len: DWORD, read: *DWORD) callconv(.winapi) BOOL;
