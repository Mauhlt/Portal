//! Hand-declared Win32 surface used by portal-release and portal-launcher.
//!
//! Same policy as src/win32.zig: owning these declarations keeps the tools
//! building across std churn. Signatures mirror the Microsoft documentation.

pub const HANDLE = *anyopaque;
pub const BOOL = c_int;
pub const DWORD = u32;
pub const WORD = u16;

pub const INFINITE: DWORD = 0xFFFFFFFF;
pub const WAIT_FAILED: DWORD = 0xFFFFFFFF;

pub const MOVEFILE_REPLACE_EXISTING: DWORD = 0x1;
pub const MOVEFILE_WRITE_THROUGH: DWORD = 0x8;

pub const CTRL_C_EVENT: DWORD = 0;
pub const CTRL_BREAK_EVENT: DWORD = 1;

pub const FILETIME = extern struct {
    dwLowDateTime: DWORD,
    dwHighDateTime: DWORD,

    pub fn toU64(ft: FILETIME) u64 {
        return (@as(u64, ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    }
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

pub const PROCESS_INFORMATION = extern struct {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: DWORD,
    dwThreadId: DWORD,
};

pub const HandlerRoutine = *const fn (ctrl_type: DWORD) callconv(.winapi) BOOL;

pub extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;
pub extern "kernel32" fn CloseHandle(h: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn ExitProcess(code: u32) callconv(.winapi) noreturn;
pub extern "kernel32" fn GetCommandLineW() callconv(.winapi) [*:0]u16;
pub extern "kernel32" fn MoveFileExW(existing: [*:0]const u16, new: ?[*:0]const u16, flags: DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetSystemTimeAsFileTime(ft: *FILETIME) callconv(.winapi) void;
pub extern "kernel32" fn FileTimeToLocalFileTime(ft: *const FILETIME, local: *FILETIME) callconv(.winapi) BOOL;
pub extern "kernel32" fn SetConsoleCtrlHandler(handler: ?HandlerRoutine, add: BOOL) callconv(.winapi) BOOL;
pub extern "kernel32" fn CreateProcessW(
    app: ?[*:0]const u16,
    cmdline: ?[*:0]u16,
    proc_attrs: ?*anyopaque,
    thread_attrs: ?*anyopaque,
    inherit: BOOL,
    flags: DWORD,
    env: ?*anyopaque,
    cwd: ?[*:0]const u16,
    si: *STARTUPINFOW,
    pi: *PROCESS_INFORMATION,
) callconv(.winapi) BOOL;
pub extern "kernel32" fn WaitForSingleObject(h: HANDLE, ms: DWORD) callconv(.winapi) DWORD;
pub extern "kernel32" fn GetExitCodeProcess(h: HANDLE, code: *DWORD) callconv(.winapi) BOOL;
