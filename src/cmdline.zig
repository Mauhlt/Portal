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
    /// The program found for argv[0] (UTF-8; for a .cmd program the
    /// script, not cmd.exe): what deviceStartResolved checks.
    program: []u8,

    pub fn deinit(r: *Resolved, gpa: Allocator) void {
        gpa.free(r.app);
        gpa.free(r.cmdline);
        gpa.free(r.program);
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
    errdefer gpa.free(program);

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
    return .{ .app = app, .cmdline = cmdline, .program = program };
}

/// The agent (`claude`, `claude.exe`, `claude.cmd`, any case, any folder).
pub fn isAgent(argv0: []const u8) bool {
    const base = std.fs.path.basenameWindows(argv0);
    const ok_names = [_][]const u8{ "claude", "claude.exe", "claude.cmd" };
    for (ok_names) |n| if (std.ascii.eqlIgnoreCase(base, n)) return true;
    return false;
}

/// The agent whose configured arguments do not already pick a session
/// (`--session-id`, `--resume`/`-r`, `--continue`/`-c`, in any `--x=v`
/// form or short-flag group): Portal then gives each tab's launch its own
/// `--session-id <uuid>`, so the tab's transcript is known exactly
/// (src/convo/follow.zig).
pub fn wantsSessionId(argv: []const []const u8) bool {
    if (argv.len == 0 or !isAgent(argv[0])) return false;
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

/// Whether sessions may be started from a device with the desk's program
/// setting (docs/tabs-design.md, "Starting projects from a device"): only
/// the agent, whose permission mode Portal sets at launch
/// (`--permission-mode default|plan`, launchArgs), and only when its
/// configured arguments contain nothing that skips, widens or pre-answers
/// permission prompts, or that picks a mode Portal would then fight with.
pub const DeviceStart = union(enum) {
    ok,
    /// Not the agent: Portal can't fix its permission mode.
    not_agent,
    /// The configured arguments hold this flag (one of permissive_flags,
    /// or anything `--dangerously-*` / `--allow-dangerously-*`).
    permissive: []const u8,
};

/// Flags of the agent that make a session less careful than "ask for
/// every edit and command", that choose the mode themselves, or that
/// bring in settings, folders, tools or agents Portal did not choose
/// (another settings layer could replace Portal's guard hook; Portal's
/// own `--settings` is added by launchArgs, never configured).
pub const permissive_flags = [_][]const u8{
    "--dangerously-skip-permissions",
    "--allow-dangerously-skip-permissions",
    "--permission-mode",
    "--allowedTools",
    "--allowed-tools",
    "--permission-prompt-tool",
    "--settings",
    "--setting-sources",
    "--add-dir",
    "--mcp-config",
    "--plugin-dir",
    "--agents",
};

pub fn deviceStart(argv: []const []const u8) DeviceStart {
    if (argv.len == 0) return .not_agent;
    return deviceStartResolved(argv[0], argv[1..]);
}

/// deviceStart for the program as resolved for this launch (Resolved.
/// program, found again on every tab open) and the configured arguments:
/// a PATH change that makes `claude` another program refuses the start.
pub fn deviceStartResolved(program: []const u8, args: []const []const u8) DeviceStart {
    if (!isAgent(program)) return .not_agent;
    for (args) |a| {
        if (std.mem.eql(u8, a, "--")) break;
        const flag = if (std.mem.indexOfScalar(u8, a, '=')) |eq| a[0..eq] else a;
        for (permissive_flags) |p| if (std.ascii.eqlIgnoreCase(flag, p)) return .{ .permissive = p };
        if (std.ascii.startsWithIgnoreCase(flag, "--dangerously") or std.ascii.startsWithIgnoreCase(flag, "--allow-dangerously")) return .{ .permissive = "--dangerously-*" };
    }
    return .ok;
}

/// Why `deviceStart` refused, for the desk's log and panels.
pub fn deviceStartText(d: DeviceStart, buf: []u8) []const u8 {
    return switch (d) {
        .ok => "",
        .not_agent => "the program setting is not Claude Code, so Portal cannot make device starts ask for every edit and command",
        .permissive => |f| std.fmt.bufPrint(buf, "the program setting contains {s}; device starts never run with permissive permissions or settings Portal did not choose", .{f}) catch "the program setting contains a permissive flag",
    };
}

/// The agent whose configured arguments pass no `--settings` of their
/// own: Portal then layers its status line settings file over the user's
/// (usage_desk.zig; the plan-usage bar).
pub fn wantsSettings(argv: []const []const u8) bool {
    if (argv.len == 0 or !isAgent(argv[0])) return false;
    for (argv[1..]) |a| {
        if (std.mem.eql(u8, a, "--")) break;
        if (std.mem.eql(u8, a, "--settings") or std.mem.startsWith(u8, a, "--settings=")) return false;
    }
    return true;
}

/// The one place a tab's launch arguments are decided (tabs.Hub.open):
/// `--permission-mode <mode>` for a device start (the agent's value, from
/// shared/projects.zig Mode.agentArg), then `--session-id <id>` when
/// Portal picks the session, then `--settings <file>` (Portal's status
/// line, usage_desk.zig). For withArgs.
pub fn launchArgs(buf: *[6][]const u8, permission_mode: ?[]const u8, session_id: ?*const [36]u8, settings_file: ?[]const u8) []const []const u8 {
    var n: usize = 0;
    if (permission_mode) |m| {
        buf[n] = "--permission-mode";
        buf[n + 1] = m;
        n += 2;
    }
    if (session_id) |id| {
        buf[n] = "--session-id";
        buf[n + 1] = id;
        n += 2;
    }
    if (settings_file) |f| {
        buf[n] = "--settings";
        buf[n + 1] = f;
        n += 2;
    }
    return buf[0..n];
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

/// `line` (a Resolved command line) with `args` inserted right after the
/// program (argv[0]; inside the quotes of a `cmd.exe /d /s /c "..."` line
/// for a .cmd program), before the configured arguments: a configured
/// `--` (after which everything is the prompt) can never turn Portal's
/// flags into prompt text. Each argument must be letters,
/// digits and dashes only (Portal's own: a mode name, a UUID), so it needs
/// no quoting and is safe for cmd.exe, or a Windows path of Portal's own
/// (pathArg: letters, digits, spaces and `\ : . _ - ( )`), which goes in
/// double quotes; anything else is refused.
pub fn withArgs(gpa: Allocator, line: []const u16, args: []const []const u8) ![:0]u16 {
    var add_len: usize = 0;
    for (args) |a| {
        if (a.len == 0) return error.UnsafeArgument;
        if (plainArg(a)) {
            add_len += 1 + a.len;
        } else if (pathArg(a)) {
            add_len += 3 + a.len;
        } else return error.UnsafeArgument;
    }
    const batch_prefix = std.unicode.utf8ToUtf16LeStringLiteral("cmd.exe /d /s /c \"");
    const batch = std.mem.startsWith(u16, line, batch_prefix) and line.len > batch_prefix.len and line[line.len - 1] == '"';
    const start = if (batch) batch_prefix.len else 0;
    const cut = start + programEnd(line[start..if (batch) line.len - 1 else line.len]);
    const out = try gpa.allocSentinel(u16, line.len + add_len, 0);
    @memcpy(out[0..cut], line[0..cut]);
    var at = cut;
    for (args) |a| {
        out[at] = ' ';
        at += 1;
        const quote = !plainArg(a);
        if (quote) {
            out[at] = '"';
            at += 1;
        }
        for (a) |c| {
            out[at] = c;
            at += 1;
        }
        if (quote) {
            out[at] = '"';
            at += 1;
        }
    }
    @memcpy(out[at..], line[cut..]);
    return out;
}

/// Where the program (the first argument, as `join` quotes it) ends in
/// `line`: after its closing quote, else at the first space. A Windows
/// path never holds a `"`, so the first quote after the opening one
/// closes it.
fn programEnd(line: []const u16) usize {
    if (line.len > 0 and line[0] == '"') {
        const close = std.mem.indexOfScalarPos(u16, line, 1, '"') orelse return line.len;
        return close + 1;
    }
    return std.mem.indexOfScalar(u16, line, ' ') orelse line.len;
}

fn plainArg(a: []const u8) bool {
    for (a) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
    return a.len > 0;
}

/// An absolute Windows path safe in double quotes for CreateProcess and
/// cmd.exe: no quote, `%`, `^`, `&`, `|`, `<`, `>`, `!`, no control or
/// non-ASCII character, and no trailing backslash (it would escape the
/// closing quote).
pub fn pathArg(a: []const u8) bool {
    if (a.len < 3 or a.len > 1024 or !std.ascii.isAlphabetic(a[0]) or a[1] != ':' or a[2] != '\\') return false;
    if (a[a.len - 1] == '\\') return false;
    for (a) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', ' ', '\\', ':', '.', '_', '-', '(', ')' => {},
        else => return false,
    };
    return true;
}

/// `line` with ` --session-id <id>` appended (withArgs).
pub fn withSessionId(gpa: Allocator, line: []const u16, id: *const [36]u8) ![:0]u16 {
    return withArgs(gpa, line, &.{ "--session-id", id });
}

const testing = std.testing;

test "deviceStart: the agent only, never with a permissive flag" {
    try testing.expect(deviceStart(&.{"claude"}) == .ok);
    try testing.expect(deviceStart(&.{ "C:\\x\\claude.exe", "--model", "opus", "--verbose" }) == .ok);
    try testing.expect(deviceStart(&.{"cmd.exe"}) == .not_agent);
    try testing.expect(deviceStart(&.{}) == .not_agent);
    try testing.expect(deviceStart(&.{"claude-code"}) == .not_agent);
    for ([_][]const u8{
        "--dangerously-skip-permissions",      "--allow-dangerously-skip-permissions", "--permission-mode",
        "--permission-mode=bypassPermissions", "--PERMISSION-MODE",                    "--allowedTools",
        "--allowed-tools=Bash",                "--permission-prompt-tool",             "--dangerously-anything-new",
        "--settings",                          "--settings={}",                        "--setting-sources=project",
        "--add-dir",                           "--mcp-config",                         "--plugin-dir",
        "--agents",
    }) |f| try testing.expect(deviceStart(&.{ "claude", "--model", "x", f, "acceptEdits" }) == .permissive);
    // A prompt after "--" is not a flag.
    try testing.expect(deviceStart(&.{ "claude", "--", "--dangerously-skip-permissions" }) == .ok);
    // As found on PATH for this launch: the npm shim or the native
    // program is the agent; anything else PATH now finds is not.
    try testing.expect(deviceStartResolved("C:\\npm\\claude.cmd", &.{"--verbose"}) == .ok);
    try testing.expect(deviceStartResolved("C:\\Users\\x\\.local\\bin\\claude.exe", &.{}) == .ok);
    try testing.expect(deviceStartResolved("C:\\evil\\claude.bat", &.{}) == .not_agent);
    try testing.expect(deviceStartResolved("C:\\x\\claude.exe", &.{"--permission-mode=acceptEdits"}) == .permissive);
    var buf: [160]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, deviceStartText(deviceStart(&.{ "claude", "--permission-mode", "acceptEdits" }), &buf), "--permission-mode") != null);
}

test "launchArgs + withArgs: the permission mode, then the session id; nothing unsafe" {
    @setEvalBranchQuota(10_000);
    const gpa = testing.allocator;
    var ab: [6][]const u8 = undefined;
    const id = "0123abcd-0000-4000-8000-00000000beef";
    const a = launchArgs(&ab, "plan", id, null);
    const plain = std.unicode.utf8ToUtf16LeStringLiteral("C:\\x\\claude.exe --model opus");
    const got = try withArgs(gpa, plain, a);
    defer gpa.free(got);
    try testing.expectEqualSlices(u16, std.unicode.utf8ToUtf16LeStringLiteral("C:\\x\\claude.exe --permission-mode plan --session-id 0123abcd-0000-4000-8000-00000000beef --model opus"), got);
    // Right after the program: a configured `--` (the rest is the
    // prompt) never swallows Portal's flags; a quoted program path too.
    const dashes = std.unicode.utf8ToUtf16LeStringLiteral("\"C:\\a b\\claude.exe\" --model opus -- hello");
    const got4 = try withArgs(gpa, dashes, launchArgs(&ab, "plan", null, null));
    defer gpa.free(got4);
    try testing.expectEqualSlices(u16, std.unicode.utf8ToUtf16LeStringLiteral("\"C:\\a b\\claude.exe\" --permission-mode plan --model opus -- hello"), got4);
    const bat_dashes = std.unicode.utf8ToUtf16LeStringLiteral("cmd.exe /d /s /c \"C:\\npm\\claude.cmd -- hi\"");
    const got5 = try withArgs(gpa, bat_dashes, launchArgs(&ab, "default", null, null));
    defer gpa.free(got5);
    try testing.expectEqualSlices(u16, std.unicode.utf8ToUtf16LeStringLiteral("cmd.exe /d /s /c \"C:\\npm\\claude.cmd --permission-mode default -- hi\""), got5);
    const bat = std.unicode.utf8ToUtf16LeStringLiteral("cmd.exe /d /s /c \"C:\\npm\\claude.cmd\"");
    const got2 = try withArgs(gpa, bat, launchArgs(&ab, "default", null, null));
    defer gpa.free(got2);
    try testing.expectEqualSlices(u16, std.unicode.utf8ToUtf16LeStringLiteral("cmd.exe /d /s /c \"C:\\npm\\claude.cmd --permission-mode default\""), got2);
    try testing.expectEqual(@as(usize, 0), launchArgs(&ab, null, null, null).len);
    // The status line settings file: a quoted path, inside a .cmd's quotes too.
    const set = launchArgs(&ab, null, null, "C:\\Users\\Bo B\\AppData\\Local\\Portal\\agent-statusline.json");
    const got3 = try withArgs(gpa, bat, set);
    defer gpa.free(got3);
    try testing.expectEqualSlices(u16, std.unicode.utf8ToUtf16LeStringLiteral("cmd.exe /d /s /c \"C:\\npm\\claude.cmd --settings \"C:\\Users\\Bo B\\AppData\\Local\\Portal\\agent-statusline.json\"\""), got3);
    for ([_][]const u8{ "C:\\a\"b", "C:\\a%b", "C:\\a&b", "C:\\a^b", "C:\\a!b", "C:\\dir\\", "relative\\x", "C:\\a\nb", "C:\\caf\xc3\xa9" }) |bad| {
        try testing.expect(!pathArg(bad));
        try testing.expectError(error.UnsafeArgument, withArgs(gpa, plain, &.{ "--settings", bad }));
    }
    try testing.expect(wantsSettings(&.{"claude"}));
    try testing.expect(!wantsSettings(&.{ "claude", "--settings", "x.json" }));
    try testing.expect(!wantsSettings(&.{ "claude", "--settings={}" }));
    try testing.expect(wantsSettings(&.{ "claude", "--", "--settings" }));
    try testing.expect(!wantsSettings(&.{"cmd.exe"}));
    try testing.expectError(error.UnsafeArgument, withArgs(gpa, plain, &.{"a b"}));
    try testing.expectError(error.UnsafeArgument, withArgs(gpa, plain, &.{"x&calc"}));
    try testing.expectError(error.UnsafeArgument, withArgs(gpa, plain, &.{""}));
}

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

test "withSessionId: right after the program, inside cmd.exe's quotes for a .cmd" {
    const gpa = testing.allocator;
    const id = "0123abcd-0000-4000-8000-00000000beef";
    const plain = std.unicode.utf8ToUtf16LeStringLiteral("C:\\x\\claude.exe --model \"a b\"");
    const got = try withSessionId(gpa, plain, id);
    defer gpa.free(got);
    const want = std.unicode.utf8ToUtf16LeStringLiteral("C:\\x\\claude.exe --session-id 0123abcd-0000-4000-8000-00000000beef --model \"a b\"");
    try testing.expectEqualSlices(u16, want, got);
    const bat = std.unicode.utf8ToUtf16LeStringLiteral("cmd.exe /d /s /c \"C:\\npm\\claude.cmd --verbose\"");
    const got2 = try withSessionId(gpa, bat, id);
    defer gpa.free(got2);
    const want2 = std.unicode.utf8ToUtf16LeStringLiteral("cmd.exe /d /s /c \"C:\\npm\\claude.cmd --session-id 0123abcd-0000-4000-8000-00000000beef --verbose\"");
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
