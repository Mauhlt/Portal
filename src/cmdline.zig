//! Building the child process command line on Windows.
//!
//! The command comes only from the desktop operator's own `portal run -- ...`
//! invocation; nothing from the web reaches this code.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

/// Appends `arg` quoted per the CommandLineToArgvW / MSVCRT rules.
pub fn appendQuoted(list: *std.ArrayList(u8), gpa: Allocator, arg: []const u8) !void {
    const needs_quotes = arg.len == 0 or std.mem.indexOfAny(u8, arg, " \t\n\x0b\"") != null;
    if (!needs_quotes) return list.appendSlice(gpa, arg);

    try list.append(gpa, '"');
    var backslashes: usize = 0;
    for (arg) |c| {
        if (c == '\\') {
            backslashes += 1;
            continue;
        }
        if (c == '"') {
            try list.appendNTimes(gpa, '\\', backslashes * 2 + 1);
        } else {
            try list.appendNTimes(gpa, '\\', backslashes);
        }
        backslashes = 0;
        try list.append(gpa, c);
    }
    try list.appendNTimes(gpa, '\\', backslashes * 2);
    try list.append(gpa, '"');
}

pub fn join(gpa: Allocator, argv: []const []const u8) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    for (argv, 0..) |arg, i| {
        if (i != 0) try list.append(gpa, ' ');
        try appendQuoted(&list, gpa, arg);
    }
    return list.toOwnedSlice(gpa);
}

pub const Resolved = struct {
    /// Absolute path passed as lpApplicationName (no search path games).
    app: [:0]u16,
    /// Mutable command line for CreateProcessW.
    cmdline: [:0]u16,

    pub fn deinit(r: *Resolved, gpa: Allocator) void {
        gpa.free(r.app);
        gpa.free(r.cmdline);
    }
};

fn isBatch(path: []const u8) bool {
    return std.ascii.endsWithIgnoreCase(path, ".cmd") or std.ascii.endsWithIgnoreCase(path, ".bat");
}

fn hasDirPart(name: []const u8) bool {
    return std.mem.indexOfAny(u8, name, "\\/:") != null;
}

fn fileExists(io: Io, path: []const u8) bool {
    Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

/// Finds argv[0] on PATH (never the current directory, to avoid picking up
/// a planted binary from whatever project folder Portal was started in).
fn findProgram(gpa: Allocator, io: Io, name: []const u8, path_env: ?[]const u8) ![]u8 {
    if (hasDirPart(name)) {
        if (!fileExists(io, name)) return error.ProgramNotFound;
        return gpa.dupe(u8, name);
    }
    const exts_with = [_][]const u8{""};
    const exts_without = [_][]const u8{ ".exe", ".com", ".cmd", ".bat" };
    const has_ext = std.fs.path.extension(name).len > 0;
    const exts: []const []const u8 = if (has_ext) &exts_with else &exts_without;

    var it = std.mem.tokenizeScalar(u8, path_env orelse return error.ProgramNotFound, ';');
    while (it.next()) |dir_raw| {
        const dir = std.mem.trim(u8, dir_raw, " \"");
        if (dir.len == 0 or !std.fs.path.isAbsolute(dir)) continue; // skip relative PATH entries
        for (exts) |ext| {
            const candidate = try std.fmt.allocPrint(gpa, "{s}\\{s}{s}", .{ std.mem.trimEnd(u8, dir, "\\/"), name, ext });
            if (fileExists(io, candidate)) return candidate;
            gpa.free(candidate);
        }
    }
    return error.ProgramNotFound;
}

pub fn resolve(
    gpa: Allocator,
    io: Io,
    argv: []const []const u8,
    path_env: ?[]const u8,
    system_root: ?[]const u8,
) !Resolved {
    std.debug.assert(argv.len > 0);
    const program = try findProgram(gpa, io, argv[0], path_env);
    defer gpa.free(program);

    var app_utf8: []u8 = undefined;
    var line_utf8: []u8 = undefined;
    if (isBatch(program)) {
        // .cmd/.bat (e.g. an npm-installed `claude.cmd`) must run under cmd.exe.
        const root = system_root orelse "C:\\Windows";
        app_utf8 = try std.fmt.allocPrint(gpa, "{s}\\System32\\cmd.exe", .{root});
        errdefer gpa.free(app_utf8);
        var inner_argv = try gpa.alloc([]const u8, argv.len);
        defer gpa.free(inner_argv);
        inner_argv[0] = program;
        @memcpy(inner_argv[1..], argv[1..]);
        const inner = try join(gpa, inner_argv);
        defer gpa.free(inner);
        // /d: skip AutoRun registry commands. /s /c "...": run the inner line verbatim.
        line_utf8 = try std.fmt.allocPrint(gpa, "cmd.exe /d /s /c \"{s}\"", .{inner});
    } else {
        app_utf8 = try gpa.dupe(u8, program);
        errdefer gpa.free(app_utf8);
        var full_argv = try gpa.alloc([]const u8, argv.len);
        defer gpa.free(full_argv);
        full_argv[0] = program;
        @memcpy(full_argv[1..], argv[1..]);
        line_utf8 = try join(gpa, full_argv);
    }
    defer gpa.free(app_utf8);
    defer gpa.free(line_utf8);

    const app = try std.unicode.utf8ToUtf16LeAllocZ(gpa, app_utf8);
    errdefer gpa.free(app);
    const cmdline = try std.unicode.utf8ToUtf16LeAllocZ(gpa, line_utf8);
    return .{ .app = app, .cmdline = cmdline };
}

const testing = std.testing;

fn expectJoined(argv: []const []const u8, expected: []const u8) !void {
    const got = try join(testing.allocator, argv);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(expected, got);
}

test "quoting follows CommandLineToArgvW rules" {
    try expectJoined(&.{ "claude", "--help" }, "claude --help");
    try expectJoined(&.{ "a b", "" }, "\"a b\" \"\"");
    try expectJoined(&.{"say \"hi\""}, "\"say \\\"hi\\\"\"");
    try expectJoined(&.{"C:\\dir with space\\"}, "\"C:\\dir with space\\\\\"");
    try expectJoined(&.{"a\\\\\"b"}, "\"a\\\\\\\\\\\"b\"");
    try expectJoined(&.{"C:\\no\\space"}, "C:\\no\\space");
}

test "batch detection" {
    try testing.expect(isBatch("C:\\x\\claude.cmd"));
    try testing.expect(isBatch("C:\\x\\run.BAT"));
    try testing.expect(!isBatch("C:\\x\\claude.exe"));
}
