//! The few kernel32 pieces the speech module's threads use (events, waits,
//! a lock). Declared here because src/win32.zig belongs to Portal's root
//! module and a file can be in only one module.

const std = @import("std");

pub const HANDLE = *anyopaque;
pub const BOOL = c_int;
pub const DWORD = u32;
pub const INFINITE: DWORD = 0xFFFFFFFF;
pub const WAIT_OBJECT_0: DWORD = 0;
pub const WAIT_TIMEOUT: DWORD = 258;

pub extern "kernel32" fn CreateEventW(attrs: ?*anyopaque, manual_reset: BOOL, initial: BOOL, name: ?[*:0]const u16) callconv(.winapi) ?HANDLE;
pub extern "kernel32" fn SetEvent(h: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn ResetEvent(h: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn CloseHandle(h: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn WaitForSingleObject(h: HANDLE, ms: DWORD) callconv(.winapi) DWORD;
pub extern "kernel32" fn WaitForMultipleObjects(n: DWORD, handles: [*]const HANDLE, all: BOOL, ms: DWORD) callconv(.winapi) DWORD;
extern "kernel32" fn AcquireSRWLockExclusive(l: *?*anyopaque) callconv(.winapi) void;
extern "kernel32" fn ReleaseSRWLockExclusive(l: *?*anyopaque) callconv(.winapi) void;

/// An auto-reset event (false: none could be created).
pub fn autoEvent() !HANDLE {
    return CreateEventW(null, 0, 0, null) orelse error.NoEvent;
}

/// A plain lock usable from any thread without an Io (SRW, exclusive).
pub const Lock = struct {
    srw: ?*anyopaque = null,
    pub fn lock(l: *Lock) void {
        AcquireSRWLockExclusive(&l.srw);
    }
    pub fn unlock(l: *Lock) void {
        ReleaseSRWLockExclusive(&l.srw);
    }
};

/// Milliseconds from now until `deadline_ms` (unix ms), for a wait:
/// 0 if it has passed, INFINITE for null, capped below INFINITE.
pub fn msUntil(deadline_ms: ?i64, now_ms: i64) DWORD {
    const d = deadline_ms orelse return INFINITE;
    if (d <= now_ms) return 0;
    return @intCast(@min(d - now_ms, INFINITE - 1));
}

test "msUntil" {
    try std.testing.expectEqual(INFINITE, msUntil(null, 5));
    try std.testing.expectEqual(@as(DWORD, 0), msUntil(4, 5));
    try std.testing.expectEqual(@as(DWORD, 95), msUntil(100, 5));
}
