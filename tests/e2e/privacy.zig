//! Privacy: what must never appear in anything Portal sends a device
//! outside the terminal grid (file-system paths, the data directory, the
//! user and machine names). The groups check every WebSocket message
//! against `Leaks`.

const std = @import("std");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;

/// A session program that prints a banner, then idles (ping).
pub const ping_child = [_][]const u8{ "--", "cmd.exe", "/c", "echo PORTAL-SMOKE-TEST & ping -n 600 127.0.0.1" };

pub const Leaks = struct {
    needles: std.ArrayList([]const u8) = .empty,
    gpa: std.mem.Allocator,

    pub fn add(l: *Leaks, s: []const u8) !void {
        if (s.len >= 4) try l.needles.append(l.gpa, s);
    }

    /// First needle found (case-insensitive), or null.
    pub fn find(l: *const Leaks, data: []const u8) ?[]const u8 {
        for (l.needles.items) |n| if (client.containsIgnoreCase(data, n)) return n;
        return null;
    }

    pub fn deinit(l: *Leaks) void {
        l.needles.deinit(l.gpa);
    }

    /// What must never appear in anything Portal sends outside the grid,
    /// for an instance whose LOCALAPPDATA is `dir`.
    pub fn standard(h: *proc.Harness, dir: []const u8) !Leaks {
        var l: Leaks = .{ .gpa = h.gpa };
        errdefer l.deinit();
        try l.add(dir);
        try l.add(h.root);
        try l.add("\\Portal\\");
        try l.add("LOCALAPPDATA");
        try l.add("USERPROFILE");
        try l.add(":\\Users\\");
        try l.add(":/Users/");
        try l.add("\\AppData\\");
        try l.add("\\code\\zig");
        try l.add("/code/zig");
        if (h.env.get("USERPROFILE")) |v| try l.add(v);
        if (h.env.get("USERNAME")) |v| if (v.len >= 4) try l.add(v);
        if (h.env.get("COMPUTERNAME")) |v| try l.add(v);
        return l;
    }
};

/// One check: no text message `v` got (hello included) carries any of
/// `leaks`' needles. The grid is not checked (the terminal is the
/// program's own output).
pub fn checkMessages(r: *Runner, v: *const client.Viewer, leaks: *const Leaks, what: []const u8) void {
    var dirty: ?[]const u8 = null;
    var where: []const u8 = "";
    if (leaks.find(v.helloText())) |n| {
        dirty = n;
        where = v.helloText();
    }
    for (v.texts.items) |t| if (leaks.find(t)) |n| {
        dirty = n;
        where = t;
    };
    _ = r.check(what, dirty == null, "{?s} in {s}", .{ dirty, where[0..@min(where.len, 400)] });
}
