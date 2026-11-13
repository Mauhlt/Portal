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

fn batchSafe(arg: []const u8) bool {
    return std.mem.indexOfAny(u8, arg, "&|<>^%!\"()\r\n") == null;
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
        // cmd.exe ignores MSVCRT `\"` escaping and expands %VAR% even inside
        // quotes ("BatBadBut"), so no quoting scheme is safe: refuse any
        // character cmd.exe treats specially instead.
        if (!batchSafe(program)) return error.UnsafeBatchArgument;
        for (argv[1..]) |a| if (!batchSafe(a)) return error.UnsafeBatchArgument;
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

/// The agent (`claude`, `claude.exe`, `claude.cmd`, any case) whose
/// configured arguments do not already pick a session (`--session-id`,
/// `--resume`/`-r`, `--continue`/`-c`, in any `--x=v` form or short-flag
/// group): Portal then gives each tab's launch its own `--session-id
/// <uuid>`, so the tab's transcript is known exactly (src/convo/follow.zig).
pub fn wantsSessionId(argv: []const []const u8) bool {
    if (argv.len == 0) return false;
    const base = std.fs.path.basenameWindows(argv[0]);
    const ok_names = [_][]const u8{ "claude", "claude.exe", "claude.cmd" };
    var is_agent = false;
    for (ok_names) |n| if (std.ascii.eqlIgnoreCase(base, n)) {
        is_agent = true;
    };
    if (!is_agent) return false;
    for (argv[1..]) |a| {
        if (std.mem.eql(u8, a, "--")) break;
        for ([_][]const u8{ "--session-id", "--resume", "--continue" }) |long| {
            if (std.mem.eql(u8, a, long) or (std.mem.startsWith(u8, a, long) and a.len > long.len and a[long.len] == '=')) return false;
        }
        if (a.len >= 2 and a[0] == '-' and a[1] != '-') {
            for (a[1..]) |c| if (c == 'r' or c == 'c') return false;
        }
    }
    return true;
}

/// A random version 4 UUID, lower-case: `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`.
pub fn uuidV4(random: [16]u8) [36]u8 {
    var b = random;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const hex = std.fmt.bytesToHex(b, .lower);
    var out: [36]u8 = undefined;
    @memcpy(out[0..8], hex[0..8]);
    out[8] = '-';
    @memcpy(out[9..13], hex[8..12]);
    out[13] = '-';
    @memcpy(out[14..18], hex[12..16]);
    out[18] = '-';
    @memcpy(out[19..23], hex[16..20]);
    out[23] = '-';
    @memcpy(out[24..36], hex[20..32]);
    return out;
}

/// `line` (a Resolved command line) with ` --session-id <id>` appended to
/// the program's arguments: inside the quotes of a `cmd.exe /d /s /c "..."`
/// line (a .cmd program), else at the end. The id is hex and dashes only,
/// so it needs no quoting and is safe for cmd.exe.
pub fn withSessionId(gpa: Allocator, line: []const u16, id: *const [36]u8) ![:0]u16 {
    var extra: [14 + 36]u16 = undefined;
    for (" --session-id ", 0..) |c, i| extra[i] = c;
    for (id, 0..) |c, i| extra[14 + i] = c;
    const add = extra[0 .. 14 + 36];
    const batch_prefix = std.unicode.utf8ToUtf16LeStringLiteral("cmd.exe /d /s /c \"");
    const batch = std.mem.startsWith(u16, line, batch_prefix) and line.len > batch_prefix.len and line[line.len - 1] == '"';
    const cut = if (batch) line.len - 1 else line.len;
    const out = try gpa.allocSentinel(u16, line.len + add.len, 0);
    @memcpy(out[0..cut], line[0..cut]);
    @memcpy(out[cut..][0..add.len], add);
    @memcpy(out[cut + add.len ..], line[cut..]);
    return out;
}

const testing = std.testing;

test "wantsSessionId: the agent only, and not when the arguments pick a session" {
    try testing.expect(wantsSessionId(&.{"claude"}));
    try testing.expect(wantsSessionId(&.{ "C:\\x\\Claude.EXE", "--model", "opus" }));
    try testing.expect(wantsSessionId(&.{ "claude.cmd", "-p", "--verbose" }));
    try testing.expect(!wantsSessionId(&.{"cmd.exe"}));
    try testing.expect(!wantsSessionId(&.{"claude-code"}));
    try testing.expect(!wantsSessionId(&.{"claudex.exe"}));
    try testing.expect(!wantsSessionId(&.{ "claude", "--session-id", "abc" }));
    try testing.expect(!wantsSessionId(&.{ "claude", "--session-id=abc" }));
    try testing.expect(!wantsSessionId(&.{ "claude", "--resume" }));
    try testing.expect(!wantsSessionId(&.{ "claude", "--resume=abc" }));
    try testing.expect(!wantsSessionId(&.{ "claude", "-r", "abc" }));
    try testing.expect(!wantsSessionId(&.{ "claude", "--continue" }));
    try testing.expect(!wantsSessionId(&.{ "claude", "-c" }));
    try testing.expect(!wantsSessionId(&.{ "claude", "-pc" }));
    // A prompt after "--" is not a flag.
    try testing.expect(wantsSessionId(&.{ "claude", "--", "-c" }));
    try testing.expect(wantsSessionId(&.{ "claude", "--resumex" }));
}

test "uuidV4" {
    const u = uuidV4(@splat(0xff));
    try testing.expectEqualStrings("ffffffff-ffff-4fff-bfff-ffffffffffff", &u);
    const z = uuidV4(@splat(0));
    try testing.expectEqualStrings("00000000-0000-4000-8000-000000000000", &z);
}

test "withSessionId: appended to the arguments, inside cmd.exe's quotes for a .cmd" {
    const gpa = testing.allocator;
    const id = "0123abcd-0000-4000-8000-00000000beef";
    const plain = std.unicode.utf8ToUtf16LeStringLiteral("C:\\x\\claude.exe --model \"a b\"");
    const got = try withSessionId(gpa, plain, id);
    defer gpa.free(got);
    const want = std.unicode.utf8ToUtf16LeStringLiteral("C:\\x\\claude.exe --model \"a b\" --session-id 0123abcd-0000-4000-8000-00000000beef");
    try testing.expectEqualSlices(u16, want, got);
    const bat = std.unicode.utf8ToUtf16LeStringLiteral("cmd.exe /d /s /c \"C:\\npm\\claude.cmd --verbose\"");
    const got2 = try withSessionId(gpa, bat, id);
    defer gpa.free(got2);
    const want2 = std.unicode.utf8ToUtf16LeStringLiteral("cmd.exe /d /s /c \"C:\\npm\\claude.cmd --verbose --session-id 0123abcd-0000-4000-8000-00000000beef\"");
    try testing.expectEqualSlices(u16, want2, got2);
}

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

test "batch argument safety" {
    try testing.expect(batchSafe("--model"));
    try testing.expect(batchSafe("C:\\Program Files\\x"));
    try testing.expect(!batchSafe("a&calc"));
    try testing.expect(!batchSafe("x \" & calc"));
    try testing.expect(!batchSafe("%PATH%"));
    try testing.expect(!batchSafe("a|b"));
    try testing.expect(!batchSafe("line\nbreak"));
}

test "batch detection" {
    try testing.expect(isBatch("C:\\x\\claude.cmd"));
    try testing.expect(isBatch("C:\\x\\run.BAT"));
    try testing.expect(!isBatch("C:\\x\\claude.exe"));
}
