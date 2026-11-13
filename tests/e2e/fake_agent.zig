//! A fake session program for the convo group: run by Portal in a tab
//! (`portal-e2e --fake-agent`), it writes a synthetic agent
//! transcript where Portal looks for one (CLAUDE_CONFIG_DIR\projects, as
//! the agent does; the harness points Portal there too, a
//! scratch folder: never the user's own), prints progress markers to the
//! terminal, reports OSC 7501 states, and waits for answer keys on its
//! console input, the way the real program would:
//!
//!   1. a prompt, a reply, two edits and a command (every text full of
//!      paths and the user's name, which Portal must scrub); token usage
//!      on the replies (repeated on every record of one reply, as the agent
//!      does), and background work: two shells (one finishes at once
//!      through a queued task notification) and a monitor;
//!   2. an AskUserQuestion with two options; waits for 1 or 2 (Up/Down
//!      arriving meanwhile print FAKE-UP-ASKED / FAKE-DOWN-ASKED; at the
//!      idle prompt of step 5 FAKE-UP-IDLE, in a quiet tab FAKE-UP-QUIET);
//!   3. a command that needs permission (OSC 7501 kind=permission); waits
//!      for 1 (allow) or Esc (deny);
//!   4. the other shell's notification and a TaskStop for the monitor
//!      (nothing runs any more), a closing reply; then waits for 1;
//!   5. `/clear`: prints, then starts a second transcript (a new session
//!      id of its own, as the agent does); then idles until its
//!      console closes.
//!
//! Answers are read strictly (`answer`): a read that is exactly the key,
//! nothing else; any other input is reported as FAKE-STRAY. Every byte
//! read is logged to `e2e-input` in the working folder, so the e2e checks
//! that nothing but the answers sent ever reaches the program. (A visual
//! run once saw "unexplained" `1`s: that desk's console had been started
//! minimized with Start-Process, which activates it, so the owner's own
//! Numpad-1 presses meant for another window went to `portalctl run
//! --console`, which types its console's keys into the tab by design.
//! Start such consoles hidden or with SW_SHOWMINNOACTIVE.)
//!
//! A tab whose folder's name contains "quiet" writes no transcript at all.
//! A tab whose folder's name contains "probe" only does OSC 7501 feature
//! detection (`probe`; the probe group, tests/e2e/probe_tests.zig).
//! In a folder whose name contains "showcase" (manual visual checks only,
//! never the e2e suite) the reply carries a code block and the question a
//! third option. (Not a PORTAL_* variable: Portal keeps those from its
//! session programs, src/childenv.zig.)
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
extern "kernel32" fn CreateFileW(name: [*:0]const u16, access: DWORD, share: DWORD, sa: ?*anyopaque, disposition: DWORD, flags: DWORD, template: ?HANDLE) callconv(.winapi) HANDLE;
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

/// Every byte read from the console is appended to `e2e-input` in the
/// working folder, so a test sees exactly what reached the program.
var log_h: ?HANDLE = null;

/// One read of console input: what one key press (or one write by
/// Portal) delivered, logged; null at the input's end.
fn chunk(buf: []u8) ?[]const u8 {
    const h = in_h orelse return null;
    var n: DWORD = 0;
    if (ReadFile(h, buf.ptr, @intCast(buf.len), &n, null) == 0 or n == 0) return null;
    if (log_h) |l| {
        var wn: DWORD = 0;
        _ = WriteFile(l, buf.ptr, n, &wn, null);
    }
    return buf[0..n];
}

/// Strict, unlike a byte-at-a-time reader: an answer is a read that is
/// exactly one of `accept` (one whole key, as a person presses it).
/// Anything else (a stray key, a `1` inside a longer sequence such as a
/// terminal reply or a win32-input-mode record, two keys at once) answers
/// nothing and is reported on screen as FAKE-STRAY, which the e2e checks
/// never appears. Returns the index in `accept`; null at the input's end.
///
/// Up / Down (`ESC [ A` / `ESC [ B`, one read each) answer nothing either
/// but are reported as FAKE-UP-<tag> / FAKE-DOWN-<tag> (never FAKE-STRAY),
/// so a test sees exactly which arrows got through, and when.
fn answer(accept: []const []const u8, tag: []const u8) ?usize {
    var buf: [256]u8 = undefined;
    while (chunk(&buf)) |got| {
        for (accept, 0..) |a, i| if (std.mem.eql(u8, got, a)) return i;
        if (!arrow(got, tag)) say("FAKE-STRAY\r\n");
    }
    return null;
}

/// Reports an Up / Down read (see `answer`); false for anything else.
fn arrow(got: []const u8, tag: []const u8) bool {
    const up = std.mem.eql(u8, got, "\x1b[A");
    if (!up and !std.mem.eql(u8, got, "\x1b[B")) return false;
    say(if (up) "FAKE-UP-" else "FAKE-DOWN-");
    say(tag);
    say("\r\n");
    return true;
}

/// Reads and logs until the input ends; Up / Down are reported as in
/// `answer`.
fn drain(tag: []const u8) void {
    var buf: [256]u8 = undefined;
    while (chunk(&buf)) |got| _ = arrow(got, tag);
}

/// OSC 7501 feature detection as the agent does it (docs/protocol.md,
/// "Program status (OSC 7501)"): the query, then a primary device attributes request
/// (the agent's sentinel: whichever reply comes first decides). Reads
/// until Portal's reply has arrived, then prints FAKE-PROBE-REPLY and
/// which came first: FAKE-PROBE-REPLY-FIRST or FAKE-PROBE-DA-FIRST (under
/// ConPTY conhost answers DA1 itself, at once, so its reply comes first).
/// Then it reports a permission wait, as the agent does once it knows,
/// and reads (and logs) until its input ends.
fn probe() void {
    say("\x1b]7501;?\x07\x1b[c");
    const reply = "\x1b]7501;?\x07";
    var acc: [1024]u8 = undefined;
    var n: usize = 0;
    var buf: [256]u8 = undefined;
    while (std.mem.indexOf(u8, acc[0..n], reply) == null) {
        const got = chunk(&buf) orelse return;
        const k = @min(got.len, acc.len - n);
        @memcpy(acc[n..][0..k], got[0..k]);
        n += k;
        if (n == acc.len) return;
    }
    const at = std.mem.indexOf(u8, acc[0..n], reply).?;
    const da_first = std.mem.indexOf(u8, acc[0..at], "\x1b[?") != null;
    say(if (da_first) "FAKE-PROBE-DA-FIRST\r\n" else "FAKE-PROBE-REPLY-FIRST\r\n");
    say("FAKE-PROBE-REPLY\r\n");
    say("\x1b]7501;state=blocked:kind=permission:app=fake\x07FAKE-PROBE-BLOCKED\r\n");
    drain("PROBE");
}

/// Opens `e2e-input` in `cwd` for appending (shared: the test reads it
/// while the program runs).
fn openInputLog(gpa: std.mem.Allocator, cwd: []const u8) void {
    const path = std.fs.path.join(gpa, &.{ cwd, "e2e-input" }) catch return;
    const wide = std.unicode.utf8ToUtf16LeAllocZ(gpa, path) catch return;
    const FILE_APPEND_DATA: DWORD = 0x0004;
    const FILE_SHARE_ALL: DWORD = 0x7;
    const OPEN_ALWAYS: DWORD = 4;
    const h = CreateFileW(wide.ptr, FILE_APPEND_DATA, FILE_SHARE_ALL, null, OPEN_ALWAYS, 0x80, null);
    if (@intFromPtr(h) != std.math.maxInt(usize)) log_h = h;
}

const Transcript = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    cwd: []const u8,
    user: []const u8,
    /// Now, as a transcript timestamp ({t}).
    ts: []const u8 = "2026-11-12T10:00:00.000Z",

    fn append(t: *Transcript, line: []const u8) void {
        var f = std.Io.Dir.cwd().createFile(t.io, t.path, .{ .truncate = false }) catch return;
        defer f.close(t.io);
        const end = f.length(t.io) catch 0;
        f.writePositionalAll(t.io, line, end) catch {};
        f.writePositionalAll(t.io, "\n", end + line.len) catch {};
    }

    /// `fmt` with {c} = the working folder, {u} = the user's name, both
    /// JSON-escaped, {t} = now as a timestamp.
    fn rec(t: *Transcript, comptime fmt: []const u8) void {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(t.gpa);
        var i: usize = 0;
        while (i < fmt.len) : (i += 1) {
            if (fmt[i] == '{' and i + 2 < fmt.len and fmt[i + 2] == '}' and (fmt[i + 1] == 'c' or fmt[i + 1] == 'u' or fmt[i + 1] == 't')) {
                const v = switch (fmt[i + 1]) {
                    'c' => t.cwd,
                    'u' => t.user,
                    else => t.ts,
                };
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

/// Unix seconds as `YYYY-MM-DDTHH:MM:SS.000Z` (civil-from-days, written
/// here independently of Portal's parser).
fn isoTime(t: i64, buf: []u8) []const u8 {
    const days = @divFloor(t, 86400);
    const secs = @mod(t, 86400);
    const z = days + 719468;
    const era = @divFloor(z, 146097);
    const doe = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    const y = yoe + era * 400 + @as(i64, if (m <= 2) 1 else 0);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.000Z", .{ @as(u64, @intCast(y)), @as(u64, @intCast(m)), @as(u64, @intCast(d)), @as(u64, @intCast(@divFloor(secs, 3600))), @as(u64, @intCast(@divFloor(@mod(secs, 3600), 60))), @as(u64, @intCast(@mod(secs, 60))) }) catch "2026-11-12T10:00:00.000Z";
}

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
    openInputLog(gpa, cwd);
    if (session_id) |s| say(if (validUuid(s)) "FAKE-SESSION-ID\r\n" else "FAKE-BAD-SESSION-ID\r\n") else say("FAKE-NO-SESSION-ID\r\n");
    const quiet = std.mem.indexOf(u8, std.fs.path.basename(cwd), "quiet") != null;
    if (quiet) {
        say("FAKE-QUIET\r\n");
        drain("QUIET");
        return 0;
    }
    if (std.mem.indexOf(u8, std.fs.path.basename(cwd), "probe") != null) {
        probe();
        return 0;
    }
    const config = env.get("CLAUDE_CONFIG_DIR") orelse {
        say("FAKE-NO-ROOT\r\n");
        drain("END");
        return 3;
    };
    const projects = std.fmt.allocPrint(gpa, "{s}\\projects", .{config}) catch return 2;
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
    var ts_buf: [32]u8 = undefined;
    t.ts = isoTime(std.Io.Timestamp.now(io, .real).toSeconds(), &ts_buf);

    // 1. A turn.
    t.rec("{\"type\":\"mode\",\"mode\":\"normal\",\"sessionId\":\"x\"}");
    t.rec("{\"parentUuid\":null,\"isSidechain\":false,\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"Please fix the build in {c}\\\\src and tell {u}\"},\"uuid\":\"u1\",\"timestamp\":\"2026-11-12T10:00:00.000Z\",\"cwd\":\"{c}\",\"sessionId\":\"x\",\"origin\":{\"kind\":\"human\"},\"promptSource\":\"typed\"}");
    t.rec("{\"type\":\"user\",\"isMeta\":true,\"message\":{\"role\":\"user\",\"content\":\"<system-reminder>injected {c}</system-reminder>\"},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"assistant\",\"timestamp\":\"{t}\",\"message\":{\"model\":\"model-e2e-1\",\"id\":\"m1\",\"role\":\"assistant\",\"usage\":{\"input_tokens\":10,\"cache_creation_input_tokens\":40,\"cache_read_input_tokens\":300,\"output_tokens\":20,\"service_tier\":\"standard\"},\"content\":[{\"type\":\"thinking\",\"thinking\":\"THINKING-SECRET {c}\"}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"assistant\",\"timestamp\":\"{t}\",\"message\":{\"model\":\"model-e2e-1\",\"id\":\"m1\",\"role\":\"assistant\",\"usage\":{\"input_tokens\":10,\"cache_creation_input_tokens\":40,\"cache_read_input_tokens\":300,\"output_tokens\":20,\"service_tier\":\"standard\"},\"content\":[{\"type\":\"text\",\"text\":\"I will look at {c}\\\\build.zig and C:\\\\Users\\\\{u}\\\\notes.txt\"}]},\"cwd\":\"{c}\"}");
    const showcase = std.mem.indexOf(u8, std.fs.path.basename(cwd), "showcase") != null;
    if (showcase) t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m1\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"The build fails because two steps install the same artifact. The fix is small; this is the step that runs the tests afterwards:\\n\\n```zig\\nconst run = b.addRunArtifact(tests);\\ntest_step.dependOn(&run.step); // one step per artifact, never two installs of the same file\\n```\\n\\nI can apply it in one of three ways.\"}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m1\",\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"Edit\",\"input\":{\"file_path\":\"{c}\\\\a.zig\",\"old_string\":\"ARG-SECRET\",\"new_string\":\"y\"}}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"tool_use_id\":\"t1\",\"type\":\"tool_result\",\"content\":\"RESULT-SECRET {c}\"}]},\"toolUseResult\":{\"filePath\":\"{c}\\\\a.zig\"},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m1\",\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"t2\",\"name\":\"Write\",\"input\":{\"file_path\":\"{c}\\\\b.zig\",\"content\":\"ARG-SECRET\"}}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m1\",\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"t3\",\"name\":\"Bash\",\"input\":{\"command\":\"dir {c} ARG-SECRET\"}}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"tool_use_id\":\"t3\",\"type\":\"tool_result\",\"content\":\"RESULT-SECRET\",\"is_error\":true}]},\"cwd\":\"{c}\"}");
    // Background work: a shell that keeps running, a monitor, and a shell
    // that finishes at once (its notification queued while busy).
    t.rec("{\"type\":\"assistant\",\"timestamp\":\"{t}\",\"message\":{\"model\":\"model-e2e-1\",\"id\":\"m6\",\"role\":\"assistant\",\"usage\":{\"input_tokens\":1,\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":0,\"output_tokens\":2},\"content\":[{\"type\":\"tool_use\",\"id\":\"bg1\",\"name\":\"Bash\",\"input\":{\"command\":\"SECRET-CMD {c}\",\"description\":\"Run the tests in {c}\\\\src for {u}\",\"run_in_background\":true}}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"user\",\"timestamp\":\"{t}\",\"message\":{\"role\":\"user\",\"content\":[{\"tool_use_id\":\"bg1\",\"type\":\"tool_result\",\"content\":\"Command running in background with ID: bshell001. Output is being written to: {c}\\\\RESULT-SECRET.txt\"}]},\"toolUseResult\":{\"stdout\":\"\",\"stderr\":\"\",\"interrupted\":false,\"backgroundTaskId\":\"bshell001\",\"backgroundCwdHint\":\"{c}\"},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"assistant\",\"timestamp\":\"{t}\",\"message\":{\"model\":\"model-e2e-1\",\"id\":\"m6\",\"role\":\"assistant\",\"usage\":{\"input_tokens\":1,\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":0,\"output_tokens\":2},\"content\":[{\"type\":\"tool_use\",\"id\":\"mon1\",\"name\":\"Monitor\",\"input\":{\"command\":\"SECRET-CMD tail\",\"description\":\"Watch the build log\",\"timeout_ms\":3600000}}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"user\",\"timestamp\":\"{t}\",\"message\":{\"role\":\"user\",\"content\":[{\"tool_use_id\":\"mon1\",\"type\":\"tool_result\",\"content\":\"Monitor started\"}]},\"toolUseResult\":{\"taskId\":\"bmon00001\",\"timeoutMs\":3600000,\"persistent\":false},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"assistant\",\"timestamp\":\"{t}\",\"message\":{\"model\":\"model-e2e-1\",\"id\":\"m6\",\"role\":\"assistant\",\"usage\":{\"input_tokens\":1,\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":0,\"output_tokens\":2},\"content\":[{\"type\":\"tool_use\",\"id\":\"bg2\",\"name\":\"PowerShell\",\"input\":{\"command\":\"SECRET-CMD lint\",\"description\":\"Lint the docs\",\"run_in_background\":true}}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"user\",\"timestamp\":\"{t}\",\"message\":{\"role\":\"user\",\"content\":[{\"tool_use_id\":\"bg2\",\"type\":\"tool_result\",\"content\":\"Command running in background with ID: bshell002\"}]},\"toolUseResult\":{\"stdout\":\"\",\"backgroundTaskId\":\"bshell002\"},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"queue-operation\",\"operation\":\"enqueue\",\"timestamp\":\"{t}\",\"sessionId\":\"x\",\"content\":\"<task-notification>\\n<task-id>bshell002</task-id>\\n<tool-use-id>bg2</tool-use-id>\\n<output-file>{c}\\\\RESULT-SECRET.out</output-file>\\n<status>completed</status>\\n<summary>SUMMARY-SECRET {c}</summary>\\n</task-notification>\"}");
    t.rec("{\"type\":\"frame-link\",\"whatever\":{\"future\":[1,2,3]}}");
    t.rec("this line is not JSON {c}");

    // 2. A question.
    if (showcase)
        t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m2\",\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"q1\",\"name\":\"AskUserQuestion\",\"input\":{\"questions\":[{\"question\":\"Which fix should I apply in {c}?\",\"header\":\"Fix\",\"multiSelect\":false,\"options\":[{\"label\":\"Merge the two steps\",\"description\":\"d\"},{\"label\":\"Rename the second artifact\",\"description\":\"d\"},{\"label\":\"Explain first\",\"description\":\"d\"}]}]}}]},\"cwd\":\"{c}\"}")
    else
        t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m2\",\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"q1\",\"name\":\"AskUserQuestion\",\"input\":{\"questions\":[{\"question\":\"Which fix should I apply in {c}?\",\"header\":\"Fix\",\"multiSelect\":false,\"options\":[{\"label\":\"Alpha\",\"description\":\"d\"},{\"label\":\"Beta in C:\\\\Windows\\\\x\",\"description\":\"d\"}]}]}}]},\"cwd\":\"{c}\"}");
    say("\x1b]7501;state=blocked:kind=question:app=fake\x07FAKE-ASKED\r\n");
    const options: []const []const u8 = if (showcase) &.{ "1", "2", "3" } else &.{ "1", "2" };
    const choice: u8 = '1' + @as(u8, @intCast(answer(options, "ASKED") orelse return 0));
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
    // 1 allows, a lone Esc denies.
    const allowed = (answer(&.{ "1", "\x1b" }, "PERMISSION") orelse return 0) == 0;
    t.rec("{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"tool_use_id\":\"p1\",\"type\":\"tool_result\",\"content\":\"ok\"}]},\"cwd\":\"{c}\"}");
    say("\x1b]7501;state=working\x07");
    say(if (allowed) "FAKE-ALLOWED\r\n" else "FAKE-DENIED\r\n");

    // 4. Done: the first shell's notification (delivered as a prompt), and
    // the monitor stopped.
    t.rec("{\"type\":\"user\",\"timestamp\":\"{t}\",\"origin\":{\"kind\":\"task-notification\",\"producer\":\"session-task\"},\"message\":{\"role\":\"user\",\"content\":\"<task-notification>\\n<task-id>bshell001</task-id>\\n<status>completed</status>\\n<summary>SUMMARY-SECRET</summary>\\n</task-notification>\"},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"assistant\",\"timestamp\":\"{t}\",\"message\":{\"model\":\"model-e2e-1\",\"id\":\"m7\",\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"stop1\",\"name\":\"TaskStop\",\"input\":{\"task_id\":\"bmon00001\"}}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"user\",\"timestamp\":\"{t}\",\"message\":{\"role\":\"user\",\"content\":[{\"tool_use_id\":\"stop1\",\"type\":\"tool_result\",\"content\":\"stopped\"}]},\"toolUseResult\":{\"message\":\"stopped\",\"task_id\":\"bmon00001\",\"task_type\":\"local_bash\",\"command\":\"SECRET-CMD tail\"},\"cwd\":\"{c}\"}");
    // 4. Done.
    t.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m5\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"All done.\"}]},\"cwd\":\"{c}\"}");
    t.rec("{\"type\":\"system\",\"subtype\":\"turn_duration\",\"durationMs\":5,\"cwd\":\"{c}\"}");
    say("\x1b]7501;state=idle\x07FAKE-DONE\r\n");

    // 5. On 1: `/clear` as the agent does it: the screen first, then a
    // new session file (not the --session-id one) with the next prompt.
    _ = answer(&.{"1"}, "IDLE") orelse return 0;
    say("\x1b[2J\x1b[HFAKE-CLEARING\r\n");
    io.random(&rnd);
    var t2 = t;
    t2.path = std.fmt.allocPrint(gpa, "{s}\\e2e00000-0000-4000-8000-{x}.jsonl", .{ dir, &rnd }) catch return 2;
    t2.rec("{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"AFTER-CLEAR prompt\"},\"cwd\":\"{c}\",\"sessionId\":\"y\"}");
    t2.rec("{\"type\":\"assistant\",\"message\":{\"id\":\"m6\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"Fresh start.\"}]},\"cwd\":\"{c}\"}");
    say("FAKE-CLEARED\r\n");
    drain("END");
    return 0;
}
