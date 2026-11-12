//! PASS/FAIL bookkeeping. Thread-safe: background probes record results too.

const std = @import("std");
const net = @import("net.zig");
const Allocator = std.mem.Allocator;

pub const Runner = struct {
    gpa: Allocator,
    mutex: @import("win.zig").Mutex = .{},
    passed: usize = 0,
    failed: usize = 0,
    skipped: usize = 0,
    failures: std.ArrayList([]const u8) = .empty,
    group_name: []const u8 = "",
    group_start: u64 = 0,

    pub fn group(r: *Runner, name: []const u8) void {
        r.mutex.lock();
        defer r.mutex.unlock();
        r.group_name = name;
        r.group_start = net.now();
        std.debug.print("\n== {s}\n", .{name});
    }

    pub fn endGroup(r: *Runner) void {
        r.mutex.lock();
        defer r.mutex.unlock();
        std.debug.print("   ({s}: {d:.1}s)\n", .{ r.group_name, @as(f64, @floatFromInt(net.now() - r.group_start)) / 1000.0 });
    }

    /// Records a check. `detail` is printed only on failure.
    pub fn check(r: *Runner, name: []const u8, passed: bool, comptime fmt: []const u8, args: anytype) bool {
        r.mutex.lock();
        defer r.mutex.unlock();
        if (passed) {
            r.passed += 1;
            std.debug.print("PASS {s}\n", .{name});
        } else {
            r.failed += 1;
            var buf: [1024]u8 = undefined;
            const detail: []const u8 = std.fmt.bufPrint(&buf, fmt, args) catch &buf;
            std.debug.print("FAIL {s}  [{s}]\n", .{ name, detail });
            const line = std.fmt.allocPrint(r.gpa, "{s}: {s}", .{ r.group_name, name }) catch name;
            r.failures.append(r.gpa, line) catch {};
        }
        return passed;
    }

    pub fn ok(r: *Runner, name: []const u8, cond: bool) bool {
        return r.check(name, cond, "", .{});
    }

    /// A scenario that cannot run here; counted, not failed.
    pub fn skip(r: *Runner, name: []const u8, comptime why: []const u8, args: anytype) void {
        r.mutex.lock();
        defer r.mutex.unlock();
        r.skipped += 1;
        std.debug.print("SKIP {s}  (" ++ why ++ ")\n", .{name} ++ args);
    }

    /// An unexpected error that ends a group early.
    pub fn abort(r: *Runner, err: anyerror) void {
        _ = r.check("group ran to completion", false, "aborted: {t}", .{err});
    }
};
