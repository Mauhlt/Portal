//! A fake session program for the convo group: run by Portal in a tab
//! (`portal-e2e --fake-agent`), it writes a synthetic agent
//! transcript where Portal looks for one (PORTAL_AGENT_PROJECTS, a
//! scratch folder: never the user's own), prints progress markers to the
//! terminal, reports OSC 7501 states, and waits for answer keys on its
//! console input, the way the real program would:
//!
//!   1. a prompt, a reply, two edits and a command (every text full of
//!      paths and the user's name, which Portal must scrub);
//!   2. an AskUserQuestion with two options; waits for 1 or 2;
//!   3. a command that needs permission (OSC 7501 kind=permission); waits
//!      for 1 (allow) or Esc (deny);
//!   4. a closing reply; then idles until its console closes.
//!
//! A tab whose folder's name contains "quiet" writes no transcript at all.
//!
//! Run as `claude.exe` (a copy of portal-e2e), so Portal treats it as
//! the agent and passes `--session-id <uuid>`: the transcript is then
//! `<uuid>.jsonl` and the terminal shows FAKE-SESSION-ID (never the id).
//! Before writing anything it waits for `e2e-go` in its folder, so the
//! test can put another session's transcript next to it first.
//!
//! The folder name follows the agent's rule (every byte that is not an
//! ASCII letter or digit becomes '-'), written independently of Portal's
//! own src/convo/transcript.zig so the e2e checks it.

const std = @import("std");

const HANDLE = *anyopaque;
const DWORD = u32;
const BOOL = c_int;
extern "kernel32" fn GetStdHandle(which: DWORD) callconv(.winapi) ?HANDLE;
extern "kernel32" fn SetConsoleMode(h: HANDLE, mode: DWORD) callconv(.winapi) BOOL;
extern "kernel32" fn ReadFile(h: HANDLE, buf: [*]u8, len: DWORD, read: ?*DWORD, overlapped: ?*anyopaque) callconv(.winapi) BOOL;
extern "kernel32" fn WriteFile(h: HANDLE, buf: [*]const u8, len: DWORD, written: ?*DWORD, overlapped: ?*anyopaque) callconv(.winapi) BOOL;
const STD_INPUT_HANDLE: DWORD = @bitCast(@as(i32, -10));
const STD_OUTPUT_HANDLE: DWORD = @bitCast(@as(i32, -11));
const ENABLE_VIRTUAL_TERMINAL_INPUT: DWORD = 0x0200;

var out_h: ?HANDLE = null;
var in_h: ?HANDLE = null;

fn say(s: []const u8) void {
    var n: DWORD = 0;
    if (out_h) |h| _ = WriteFile(h, s.ptr, @intCast(s.len), &n, null);
}

/// The next key byte from the console, or null at its end.
fn key() ?u8 {
    const h = in_h orelse return null;
    var b: [1]u8 = undefined;
    var n: DWORD = 0;
    while (true) {
        if (ReadFile(h, &b, 1, &n, null) == 0 or n == 0) return null;
        return b[0];
    }
}

const Transcript = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    cwd: []const u8,
    user: []const u8,

    fn append(t: *Transcript, line: []const u8) void {
        var f = std.Io.Dir.cwd().createFile(t.io, t.path, .{ .truncate = false }) catch return;
        defer f.close(t.io);
        const end = f.length(t.io) catch 0;
        f.writePositionalAll(t.io, line, end) catch {};
        f.writePositionalAll(t.io, "\n", end + line.len) catch {};
    }

    /// `fmt` with {c} = the working folder, {u} = the user's name, both
    /// JSON-escaped.
    fn rec(t: *Transcript, comptime fmt: []const u8) void {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(t.gpa);
        var i: usize = 0;
        while (i < fmt.len) : (i += 1) {
            if (fmt[i] == '{' and i + 2 < fmt.len and fmt[i + 2] == '}' and (fmt[i + 1] == 'c' or fmt[i + 1] == 'u')) {
                const v = if (fmt[i + 1] == 'c') t.cwd else t.user;
                for (v) |ch| {
                    if (ch == '\\' or ch == '"') out.append(t.gpa, '\\') catch return;
                    out.append(t.gpa, ch) catch return;
                }
                i += 2;
                continue;
            }
            out.append(t.gpa, fmt[i]) catch return;
        }
        t.append(out.items);
    }
};

fn validUuid(s: []const u8) bool {
    if (s.len != 36) return false;
    for (s, 0..) |c, i| switch (i) {
        8, 13, 18, 23 => if (c != '-') return false,
        else => if (!std.ascii.isHex(c)) return false,
    };
    return true;
}

pub fn main(gpa: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map, args: []const []const u8) u32 {
    var session_id: ?[]const u8 = null;
    for (args, 0..) |a, i| if (std.mem.eql(u8, a, "--session-id") and i + 1 < args.len) {
        session_id = args[i + 1];
    };
    out_h = GetStdHandle(STD_OUTPUT_HANDLE);
    in_h = GetStdHandle(STD_INPUT_HANDLE);
    if (in_h) |h| _ = SetConsoleMode(h, ENABLE_VIRTUAL_TERMINAL_INPUT);
    say("FAKE-START\r\n");
    const cwd = std.process.currentPathAlloc(io, gpa) catch return 2;
    if (session_id) |s| say(if (validUuid(s)) "FAKE-SESSION-ID\r\n" else "FAKE-BAD-SESSION-ID\r\n") else say("FAKE-NO-SESSION-ID\r\n");
    const quiet = std.mem.indexOf(u8, std.fs.path.basename(cwd), "quiet") != null;
    if (quiet) {
        say("FAKE-QUIET\r\n");
        while (key()) |_| {}
        return 0;
    }
    const projects = env.get("PORTAL_AGENT_PROJECTS") orelse {
        say("FAKE-NO-ROOT\r\n");
        while (key()) |_| {}
        return 3;
    };
    const folder = gpa.alloc(u8, cwd.len) catch return 2;
    for (cwd, folder) |c, *o| o.* = if (std.ascii.isAlphanumeric(c)) c else '-';
    const dir = std.fmt.allocPrint(gpa, "{s}\\{s}", .{ projects, folder }) catch return 2;
    std.Io.Dir.cwd().createDirPath(io, dir) catch return 4;
    // Tell the test (only) which id it got, so it can check that the id
    // never reaches a device.
    if (session_id) |s| {
        const sid = std.fmt.allocPrint(gpa, "{s}\\e2e-sid", .{cwd}) catch return 2;
        std.Io.Dir.cwd().writeFile(io, .{ .sub_path = sid, .data = s }) catch {};
    }
    // Wait for the test's go-ahead (test code: polling is fine here).
    const go = std.fmt.allocPrint(gpa, "{s}\\e2e-go", .{cwd}) catch return 2;
    var waited: u32 = 0;
    while (waited < 200) : (waited += 1) {
        std.Io.Dir.cwd().access(io, go, .{}) catch {
            io.sleep(.fromMilliseconds(50), .awake) catch {};
            continue;
        };
        break;
    }
    var rnd: [6]u8 = undefined;
    io.random(&rnd);
    const stem = if (session_id) |s| s else std.fmt.allocPrint(gpa, "e2e00000-0000-4000-8000-{x}", .{&rnd}) catch return 2;
    var t: Transcript = .{
        .gpa = gpa,
        .io = io,
        .path = std.fmt.allocPrint(gpa, "{s}\\{s}.jsonl", .{ dir, stem }) catch return 2,
        .cwd = cwd,
        .user = env.get("USERNAME") orelse "nobody",
    };

    // 1. A turn.
    t.rec("{\"type\":\"mode\",\"mode\":\"normal\",\"sessionId\":\"x\"}");
    t.rec("{\"parentUuid\":null,\"isSidechain\":false,\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"Please fix the build in {c}\\\\src and tell {u}\"},\"uuid\":\"u1\",\"timestamp\":\"2026-11-12T10:00:00.000Z\",\"cwd\":\"{c}\",\"sessionId\":\"x\",\"origin\":{\"kind\":\"human\"},\"promptSource\":\"typed\"}");
    t.rec("{\"type\":\"user\",\"isMeta\":true,\"message\":{\"role\":\"user\",\"content\":\"<system-reminder>injected {c}</system-reminder>\"},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m1\",\"role\":\"assistant\",\"content\":[{\"type\":\"thinking\",\"thinking\":\"THINKING-SECRET {c}\"}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m1\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"I will look at {c}\\\\build.zig and C:\\\\Users\\\\{u}\\\\notes.txt\"}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m1\",\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"Edit\",\"input\":{\"file_path\":\"{c}\\\\a.zig\",\"old_string\":\"ARG-SECRET\",\"new_string\":\"y\"}}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"tool_use_id\":\"t1\",\"type\":\"tool_result\",\"content\":\"RESULT-SECRET {c}\"}]},\"toolUseResult\":{\"filePath\":\"{c}\\\\a.zig\"},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m1\",\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"t2\",\"name\":\"Write\",\"input\":{\"file_path\":\"{c}\\\\b.zig\",\"content\":\"ARG-SECRET\"}}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m1\",\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"t3\",\"name\":\"Bash\",\"input\":{\"command\":\"dir {c} ARG-SECRET\"}}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"tool_use_id\":\"t3\",\"type\":\"tool_result\",\"content\":\"RESULT-SECRET\",\"is_error\":true}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"frame-link\",\"whatever\":{\"future\":[1,2,3]}}");
    t.rec("this line is not JSON {c}");

    // 2. A question.
    t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m2\",\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"q1\",\"name\":\"AskUserQuestion\",\"input\":{\"questions\":[{\"question\":\"Which fix should I apply in {c}?\",\"header\":\"Fix\",\"multiSelect\":false,\"options\":[{\"label\":\"Alpha\",\"description\":\"d\"},{\"label\":\"Beta in C:\\\\Windows\\\\x\",\"description\":\"d\"}]}]}}]},\"cwd\":\"{c}\"}");
    say("\x1b]7501;state=blocked:kind=question:app=fake\x07FAKE-ASKED\r\n");
    var choice: u8 = 0;
    while (key()) |k| if (k == '1' or k == '2') {
        choice = k;
        break;
    };
    if (choice == 0) return 0;
    t.rec("{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"tool_use_id\":\"q1\",\"type\":\"tool_result\",\"content\":\"answered\"}]},\"cwd\":\"{c}\"}");
    if (choice == '2') {
        t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m3\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"You chose Beta.\"}]},\"cwd\":\"{c}\"}");
    } else {
        t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m3\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"You chose Alpha.\"}]},\"cwd\":\"{c}\"}");
    }
    say("\x1b]7501;state=working\x07");
    say(if (choice == '2') "FAKE-GOT-2\r\n" else "FAKE-GOT-1\r\n");

    // 3. A permission prompt (the transcript has the tool call; the
    // prompt itself is only on screen and in the OSC 7501 state).
    t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m4\",\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"p1\",\"name\":\"Bash\",\"input\":{\"command\":\"del {c}\"}}]},\"cwd\":\"{c}\"}");
    say("\x1b]7501;state=blocked:kind=permission:app=fake\x07FAKE-PERMISSION\r\n");
    var allowed = false;
    while (key()) |k| {
        if (k == '1') {
            allowed = true;
            break;
        }
        if (k == 0x1b) break;
    }
    t.rec("{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"tool_use_id\":\"p1\",\"type\":\"tool_result\",\"content\":\"ok\"}]},\"cwd\":\"{c}\"}");
    say("\x1b]7501;state=working\x07");
    say(if (allowed) "FAKE-ALLOWED\r\n" else "FAKE-DENIED\r\n");

    // 4. Done.
    t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m5\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"All done.\"}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"system\",\"subtype\":\"turn_duration\",\"durationMs\":5,\"cwd\":\"{c}\"}");
    say("\x1b]7501;state=idle\x07FAKE-DONE\r\n");
    while (key()) |_| {}
    return 0;
}
