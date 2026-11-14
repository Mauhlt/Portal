//! Portal's `--settings` layer for the sessions it launches (the agent's
//! command-line settings: above the user's, the project's and the local
//! file, below managed settings; read once at the session's start). One
//! file per kind of launch in Portal's data folder, checked against what
//! Portal would write (and rewritten if it differs) right before every
//! launch (tabs.Hub.open), so nothing written there meanwhile is trusted:
//!
//!   * desk (`agent-statusline.json`): only `statusLine` = `portalctl
//!     statusline` (the plan-usage bar, usage_desk.zig); no file at all
//!     when there is no status line command.
//!   * a device start, Ask or Plan (`agent-device-ask.json`,
//!     `agent-device-plan.json`): the status line if there is one, plus
//!     `"disableAllHooks": false` (a project file's `true` is a lower layer
//!     and can't switch the guard off) and one PreToolUse group for every
//!     tool (`"matcher": "*"`), in agenthooks' exec form, running
//!     `portalctl.exe hook --device ask|plan`: the hook's own arguments
//!     carry the desk's mode, so nothing a session can set (its
//!     environment, a settings file) changes it (hookpipe.modeDecision).
//!     Without that hook a device start is refused (Hub.open).
//!
//! The user's own files are never touched; keys the layer leaves out keep
//! their values, and hook groups merge across layers.

const std = @import("std");
const builtin = @import("builtin");
const agenthooks = @import("agenthooks.zig");
const hookmsg = @import("hookmsg.zig");
const usage_desk = @import("usage_desk.zig");
const projects_wire = @import("shared").projects;

pub const Kind = enum {
    desk,
    ask,
    plan,

    pub fn of(device_mode: ?projects_wire.Mode) Kind {
        const m = device_mode orelse return .desk;
        return switch (m) {
            .ask => .ask,
            .plan => .plan,
        };
    }

    pub fn fileName(k: Kind) []const u8 {
        return switch (k) {
            .desk => usage_desk.settings_name,
            .ask => "agent-device-ask.json",
            .plan => "agent-device-plan.json",
        };
    }
};

pub const Layer = struct {
    /// Portal's data folder (a cmdline.pathArg), where the files go; null:
    /// no layer at all.
    dir: ?[]const u8 = null,
    /// The status line command (usage_desk.commandFor); null: no bar.
    statusline: ?[]const u8 = null,
    /// `portalctl.exe`'s full path, for the guard hook; null: device
    /// starts are refused.
    hook_exe: ?[]const u8 = null,

    pub const Error = error{ NoGuard, NoLayer };

    /// The file's content for `k`; null for a desk launch with nothing to
    /// add. NoGuard: a device start without the guard hook.
    pub fn json(l: *const Layer, k: Kind, w: *std.Io.Writer) (Error || std.Io.Writer.Error)!bool {
        if (k == .desk) {
            const cmd = l.statusline orelse return false;
            try w.writeAll("{");
            try usage_desk.writeStatusLine(w, cmd);
            try w.writeAll("}\n");
            return true;
        }
        const exe = l.hook_exe orelse return error.NoGuard;
        try w.writeAll("{");
        if (l.statusline) |cmd| {
            try usage_desk.writeStatusLine(w, cmd);
            try w.writeAll(",");
        }
        try w.writeAll("\"disableAllHooks\":false,\"hooks\":{\"PreToolUse\":[");
        try agenthooks.writeCompactGroup(w, "*", exe, &.{ "hook", hookmsg.device_flag, if (k == .ask) "ask" else "plan" });
        try w.writeAll("]}}\n");
        return true;
    }

    /// Makes the file for `k` hold exactly what `json` says (left alone
    /// when it already does) and returns its path (caller frees); null: a
    /// desk launch with nothing to add.
    pub fn prepare(l: *const Layer, gpa: std.mem.Allocator, io: std.Io, k: Kind) !?[]u8 {
        const dir = l.dir orelse return if (k == .desk) null else error.NoLayer;
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        if (!(l.json(k, &aw.writer) catch |err| switch (err) {
            error.WriteFailed => return error.OutOfMemory,
            else => |e| return e,
        })) return null;
        const want = aw.written();
        const path = try std.fs.path.join(gpa, &.{ dir, k.fileName() });
        errdefer gpa.free(path);
        const same = blk: {
            const have = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(want.len + 1)) catch break :blk false;
            defer gpa.free(have);
            break :blk std.mem.eql(u8, have, want);
        };
        if (!same) try @import("fsutil.zig").writeAtomic(gpa, io, path, want);
        return path;
    }
};

/// The layer for this Portal: `portalctl.exe` next to this program, in
/// `data_dir`. Null fields (and the reason in `why`, for the log) when a
/// part is not available. The strings live as long as the process.
pub fn init(gpa: std.mem.Allocator, io: std.Io, data_dir: []const u8, why: *[]const u8) Layer {
    var l: Layer = .{ .dir = data_dir };
    if (builtin.os.tag != .windows) return l;
    const w = @import("win32.zig");
    var exe_w: [1024]u16 = undefined;
    const n = w.GetModuleFileNameW(null, &exe_w, exe_w.len);
    if (n == 0 or n >= exe_w.len) {
        why.* = "this program's path is unknown";
        return l;
    }
    const self = std.unicode.wtf16LeToWtf8Alloc(gpa, exe_w[0..n]) catch return l;
    defer gpa.free(self);
    const dir = std.fs.path.dirname(self) orelse return l;
    const exe = std.fs.path.join(gpa, &.{ dir, agenthooks.exe_name }) catch return l;
    std.Io.Dir.cwd().access(io, exe, .{}) catch {
        why.* = "portalctl.exe is not next to this program";
        gpa.free(exe);
        return l;
    };
    l.hook_exe = exe;
    const cb = gpa.alloc(u8, exe.len + 16) catch return l;
    if (usage_desk.commandFor(exe, cb)) |cmd| {
        l.statusline = cmd;
    } else {
        gpa.free(cb);
        why.* = "portalctl.exe's path has characters a shell would misread";
    }
    return l;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn render(l: *const Layer, k: Kind, buf: []u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    if (!try l.json(k, &w)) return "";
    return w.buffered();
}

test "the desk layer: the status line only, or nothing" {
    var buf: [2048]u8 = undefined;
    const l: Layer = .{ .dir = "C:\\d", .statusline = "C:/p/portalctl.exe statusline", .hook_exe = "C:\\p\\portalctl.exe" };
    const j = try render(&l, .desk, &buf);
    try testing.expectEqualStrings("{\"statusLine\":{\"type\":\"command\",\"command\":\"C:/p/portalctl.exe statusline\",\"padding\":0}}\n", j);
    const none: Layer = .{ .dir = "C:\\d", .hook_exe = "C:\\p\\portalctl.exe" };
    try testing.expectEqualStrings("", try render(&none, .desk, &buf));
}

test "the device layers: the guard for every tool, hooks on, the mode in the hook's own arguments" {
    var buf: [2048]u8 = undefined;
    const l: Layer = .{ .dir = "C:\\d", .statusline = "C:/p/portalctl.exe statusline", .hook_exe = "C:\\Program Files (x)\\p\\portalctl.exe" };
    for ([_]Kind{ .ask, .plan }) |k| {
        const j = try render(&l, k, &buf);
        const v = try std.json.parseFromSlice(std.json.Value, testing.allocator, j, .{});
        defer v.deinit();
        const o = v.value.object;
        try testing.expectEqual(false, o.get("disableAllHooks").?.bool);
        try testing.expect(o.get("statusLine") != null);
        const groups = o.get("hooks").?.object.get("PreToolUse").?.array.items;
        try testing.expectEqual(@as(usize, 1), groups.len);
        try testing.expectEqualStrings("*", groups[0].object.get("matcher").?.string);
        const h = groups[0].object.get("hooks").?.array.items[0].object;
        try testing.expectEqualStrings("command", h.get("type").?.string);
        try testing.expectEqualStrings("C:\\Program Files (x)\\p\\portalctl.exe", h.get("command").?.string);
        const args = h.get("args").?.array.items;
        try testing.expectEqual(@as(usize, 3), args.len);
        try testing.expectEqualStrings("hook", args[0].string);
        try testing.expectEqualStrings(hookmsg.device_flag, args[1].string);
        try testing.expectEqualStrings(if (k == .ask) "ask" else "plan", args[2].string);
    }
    // No status line: the guard all the same. No portalctl.exe: refused.
    const bare: Layer = .{ .dir = "C:\\d", .hook_exe = "C:\\p\\portalctl.exe" };
    try testing.expect(std.mem.indexOf(u8, try render(&bare, .plan, &buf), "statusLine") == null);
    const no_hook: Layer = .{ .dir = "C:\\d", .statusline = "x statusline" };
    try testing.expectError(error.NoGuard, render(&no_hook, .ask, &buf));
    try testing.expectEqual(Kind.desk, Kind.of(null));
    try testing.expectEqual(Kind.plan, Kind.of(.plan));
}

test "prepare: written, rewritten when changed meanwhile, left alone when equal" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [1024]u8 = undefined;
    const dir = pb[0..try tmp.dir.realPath(io, &pb)];
    const l: Layer = .{ .dir = dir, .hook_exe = "C:\\p\\portalctl.exe" };
    const p = (try l.prepare(gpa, io, .plan)).?;
    defer gpa.free(p);
    const first = try std.Io.Dir.cwd().readFileAlloc(io, p, gpa, .limited(4096));
    defer gpa.free(first);
    try testing.expect(std.mem.indexOf(u8, first, "\"plan\"") != null);
    // Someone rewrites it: the next launch puts Portal's content back.
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = "{\"disableAllHooks\":true}" });
    const p2 = (try l.prepare(gpa, io, .plan)).?;
    defer gpa.free(p2);
    const back = try std.Io.Dir.cwd().readFileAlloc(io, p2, gpa, .limited(4096));
    defer gpa.free(back);
    try testing.expectEqualStrings(first, back);
    // A desk launch without a status line: no file, no argument.
    try testing.expect((try l.prepare(gpa, io, .desk)) == null);
    const none: Layer = .{};
    try testing.expectError(error.NoLayer, none.prepare(gpa, io, .ask));
}
