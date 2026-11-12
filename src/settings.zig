//! What the Portal window starts with when no arguments say otherwise
//! (double-click, Start menu): %LOCALAPPDATA%\Portal\settings.txt, written
//! by the window's first-run and Settings panels.
//!
//!   # Portal settings
//!   listen = 10.8.0.1:8420
//!   input = keys
//!   project = acme-api
//!   program = agent --some-flag
//!   cwd = C:\code\acme-api
//!
//! One `key = value` per line; blank lines and lines starting with '#' are
//! ignored, so are unknown keys and values that are too long. `program` is
//! a command line (split by splitCommand). Command-line options always win
//! over the file. There is deliberately no default program: if none is
//! configured, the window asks for one.

const std = @import("std");
const Io = std.Io;
const keymap = @import("keymap.zig");
const w = @import("win32.zig");

pub const file_name = "settings.txt";

pub const max_listen = 64;
pub const max_project = 64;
pub const max_program = 1024;
pub const max_cwd = 1024;
pub const max_args = 64;

fn Str(comptime cap: usize) type {
    return struct {
        const Self = @This();
        buf: [cap]u8 = undefined,
        len: usize = 0,

        pub fn get(s: *const Self) ?[]const u8 {
            return if (s.len == 0) null else s.buf[0..s.len];
        }
        /// False (and unchanged) if `v` is too long or has a line break.
        pub fn set(s: *Self, v: []const u8) bool {
            if (v.len > cap or std.mem.indexOfAny(u8, v, "\r\n") != null) return false;
            @memcpy(s.buf[0..v.len], v);
            s.len = v.len;
            return true;
        }
    };
}

pub const Settings = struct {
    listen: Str(max_listen) = .{},
    input: ?keymap.Policy = null,
    project: Str(max_project) = .{},
    program: Str(max_program) = .{},
    cwd: Str(max_cwd) = .{},

    pub fn parse(text: []const u8) Settings {
        var s: Settings = .{};
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
            const key = std.mem.trim(u8, line[0..eq], " \t");
            const val = std.mem.trim(u8, line[eq + 1 ..], " \t");
            if (val.len == 0) continue;
            if (std.mem.eql(u8, key, "listen")) {
                _ = s.listen.set(val);
            } else if (std.mem.eql(u8, key, "input")) {
                s.input = keymap.Policy.parse(val);
            } else if (std.mem.eql(u8, key, "project")) {
                _ = s.project.set(val);
            } else if (std.mem.eql(u8, key, "program")) {
                _ = s.program.set(val);
            } else if (std.mem.eql(u8, key, "cwd")) {
                _ = s.cwd.set(val);
            }
        }
        return s;
    }

    pub fn format(s: *const Settings, out: *Io.Writer) !void {
        try out.writeAll("# Portal settings (written by the Portal window; command-line options win)\r\n");
        if (s.listen.get()) |v| try out.print("listen = {s}\r\n", .{v});
        if (s.input) |v| try out.print("input = {t}\r\n", .{v});
        if (s.project.get()) |v| try out.print("project = {s}\r\n", .{v});
        if (s.program.get()) |v| try out.print("program = {s}\r\n", .{v});
        if (s.cwd.get()) |v| try out.print("cwd = {s}\r\n", .{v});
    }
};

/// Reads `<dir>\settings.txt`; a missing or unreadable file is empty settings.
pub fn load(gpa: std.mem.Allocator, io: Io, dir: []const u8) Settings {
    const path = std.fs.path.join(gpa, &.{ dir, file_name }) catch return .{};
    defer gpa.free(path);
    const text = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 * 1024)) catch return .{};
    defer gpa.free(text);
    return Settings.parse(text);
}

/// Writes `<dir>\settings.txt` atomically (a temporary file renamed over it).
pub fn save(gpa: std.mem.Allocator, io: Io, dir: []const u8, s: *const Settings) !void {
    var buf: [4096]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try s.format(&out);
    const path = try std.fs.path.join(gpa, &.{ dir, file_name });
    defer gpa.free(path);
    const tmp = try std.fmt.allocPrint(gpa, "{s}.tmp", .{path});
    defer gpa.free(tmp);
    try Io.Dir.cwd().createDirPath(io, dir);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = tmp, .data = out.buffered() });
    const tmp_w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, tmp);
    defer gpa.free(tmp_w);
    const path_w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, path);
    defer gpa.free(path_w);
    if (w.MoveFileExW(tmp_w.ptr, path_w.ptr, w.MOVEFILE_REPLACE_EXISTING | w.MOVEFILE_WRITE_THROUGH) == 0)
        return error.SettingsWriteFailed;
}

pub const SplitError = error{ EmptyCommand, UnterminatedQuote, TooManyArguments, CommandTooLong };

/// Splits a command line into arguments: blanks separate them, double
/// quotes group (and are removed). No other escapes, so Windows paths
/// keep their backslashes. Arguments are copied into `buf`; the returned
/// slices point into it.
pub fn splitCommand(text: []const u8, buf: []u8, args: *[max_args][]const u8) SplitError![]const []const u8 {
    var n_args: usize = 0;
    var used: usize = 0;
    var i: usize = 0;
    while (true) {
        while (i < text.len and (text[i] == ' ' or text[i] == '\t')) i += 1;
        if (i >= text.len) break;
        if (n_args == max_args) return error.TooManyArguments;
        const start = used;
        var quoted = false;
        while (i < text.len) : (i += 1) {
            const c = text[i];
            if (c == '"') {
                quoted = !quoted;
                continue;
            }
            if (!quoted and (c == ' ' or c == '\t')) break;
            if (used == buf.len) return error.CommandTooLong;
            buf[used] = c;
            used += 1;
        }
        if (quoted) return error.UnterminatedQuote;
        args[n_args] = buf[start..used];
        n_args += 1;
    }
    if (n_args == 0 or args[0].len == 0) return error.EmptyCommand;
    return args[0..n_args];
}

const testing = std.testing;

test "settings parse and format round trip" {
    const text =
        \\# comment
        \\listen = 10.8.0.1:8420
        \\input=instruct
        \\
        \\project =  acme api
        \\program = "C:\Program Files\tool\tool.exe" --flag
        \\cwd = C:\code\acme
        \\unknown = whatever
        \\no equals sign
        \\input2 = text
    ;
    const s = Settings.parse(text);
    try testing.expectEqualStrings("10.8.0.1:8420", s.listen.get().?);
    try testing.expectEqual(keymap.Policy.instruct, s.input.?);
    try testing.expectEqualStrings("acme api", s.project.get().?);
    try testing.expectEqualStrings("\"C:\\Program Files\\tool\\tool.exe\" --flag", s.program.get().?);
    try testing.expectEqualStrings("C:\\code\\acme", s.cwd.get().?);

    var buf: [2048]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try s.format(&out);
    const again = Settings.parse(out.buffered());
    try testing.expectEqualStrings(s.listen.get().?, again.listen.get().?);
    try testing.expectEqual(s.input, again.input);
    try testing.expectEqualStrings(s.project.get().?, again.project.get().?);
    try testing.expectEqualStrings(s.program.get().?, again.program.get().?);
    try testing.expectEqualStrings(s.cwd.get().?, again.cwd.get().?);
}

test "settings: bad values are ignored, nothing defaults" {
    const empty = Settings.parse("");
    try testing.expect(empty.listen.get() == null);
    try testing.expect(empty.input == null);
    try testing.expect(empty.program.get() == null); // no default program
    const long: [max_project + 1]u8 = @splat('p');
    const s = Settings.parse("input = everything\r\nlisten =\r\nproject = " ++ long ++ "\r\n");
    try testing.expect(s.input == null);
    try testing.expect(s.listen.get() == null);
    try testing.expect(s.project.get() == null);
    var t: Settings = .{};
    try testing.expect(!t.program.set("a\nb"));
    try testing.expect(t.program.set("ok"));
}

test "settings save and load" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [1024]u8 = undefined;
    const dir = path_buf[0..try tmp.dir.realPath(io, &path_buf)];
    var s: Settings = .{};
    _ = s.listen.set("127.0.0.1:9000");
    _ = s.program.set("cmd.exe /k");
    s.input = .none;
    try save(gpa, io, dir, &s);
    const l = load(gpa, io, dir);
    try testing.expectEqualStrings("127.0.0.1:9000", l.listen.get().?);
    try testing.expectEqualStrings("cmd.exe /k", l.program.get().?);
    try testing.expectEqual(keymap.Policy.none, l.input.?);
    // Missing file: empty settings.
    const none = load(gpa, io, "C:\\definitely\\not\\here");
    try testing.expect(none.program.get() == null);
}

test "splitCommand" {
    var buf: [256]u8 = undefined;
    var args: [max_args][]const u8 = undefined;
    const a = try splitCommand("  agent   --resume ", &buf, &args);
    try testing.expectEqual(@as(usize, 2), a.len);
    try testing.expectEqualStrings("agent", a[0]);
    try testing.expectEqualStrings("--resume", a[1]);
    const b = try splitCommand("\"C:\\Program Files\\x\\x.exe\" \"two words\" a\"b c\"d", &buf, &args);
    try testing.expectEqualStrings("C:\\Program Files\\x\\x.exe", b[0]);
    try testing.expectEqualStrings("two words", b[1]);
    try testing.expectEqualStrings("ab cd", b[2]);
    try testing.expectError(error.EmptyCommand, splitCommand("   ", &buf, &args));
    try testing.expectError(error.EmptyCommand, splitCommand("\"\" x", &buf, &args));
    try testing.expectError(error.UnterminatedQuote, splitCommand("\"abc", &buf, &args));
    var small: [3]u8 = undefined;
    try testing.expectError(error.CommandTooLong, splitCommand("abcd", &small, &args));
    const many: [2 * (max_args + 1)]u8 = @splat(' ');
    var many_buf = many;
    for (0..max_args + 1) |i| many_buf[2 * i] = 'a';
    try testing.expectError(error.TooManyArguments, splitCommand(&many_buf, &buf, &args));
}
