//! The input line against a real server in its DEFAULT input mode (no
//! --input): what Send produces is decided by the clients' own input-line
//! logic (src/inputrules/send.zig, module "inputrules"), then sent over the
//! socket as a client would, and the native client's instruction line is
//! driven the way its window does. The child is `cmd.exe /k` (prompt
//! "E2E>"), so what reaches it shows on the prompt line.

const std = @import("std");
const net = @import("net.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;
const inputbox = @import("inputrules");
/// The native client's instruction line (client/src/inputline.zig).
const inputline = @import("client").inputline;

/// The native line's sender: frames go out on the test socket.
const LineSender = struct {
    v: *client.Viewer,
    pub fn send(s: LineSender, f: []const u8) bool {
        s.v.send(f);
        return true;
    }
};

/// Types `s` into the native line as the window delivers characters.
fn typeLine(l: *inputline.Line, s: []const u8) void {
    var it = std.unicode.Utf8View.initUnchecked(s).iterator();
    while (it.nextCodepoint()) |cp| _ = l.onChar(cp, .{});
}

/// The `reason` of the last {"t":"rejected"} the viewer got.
fn rejectedReason(v: *const client.Viewer, buf: []u8) []const u8 {
    const msg = v.rejected[0..v.rejected_len];
    const key = "\"reason\":\"";
    const i = std.mem.indexOf(u8, msg, key) orelse return "";
    const rest = msg[i + key.len ..];
    const j = std.mem.indexOfScalar(u8, rest, '"') orelse return "";
    const n = @min(j, buf.len);
    @memcpy(buf[0..n], rest[0..n]);
    return buf[0..n];
}

fn waitLine(v: *client.Viewer, want: []const u8, ms: u32) bool {
    const ok = v.pumpUntil(ms, want, struct {
        fn f(w: []const u8, vv: *client.Viewer) bool {
            return std.mem.eql(u8, vv.cursorLine(), w);
        }
    }.f);
    _ = v.settle(400, 2000);
    return ok and std.mem.eql(u8, v.cursorLine(), want);
}

/// Sends the frames for `d`. False if the decision was not to send.
fn sendDecision(v: *client.Viewer, d: inputbox.Decision) bool {
    var buf: [inputbox.max_frame]u8 = undefined;
    const frame = switch (d) {
        .nothing, .refuse => return false,
        .key => |k| std.fmt.bufPrint(&buf, "k:{s}", .{k}) catch return false,
        .line => |l| std.fmt.bufPrint(&buf, "l:{s}", .{l}) catch return false,
        .typed => |t| std.fmt.bufPrint(&buf, "t:{s}", .{t}) catch return false,
    };
    v.send(frame);
    if (d == .typed) v.send("k:enter");
    return true;
}

/// `text` through Send in `policy`; returns the decision.
fn box(v: *client.Viewer, policy: inputbox.Policy, text: []const u8, scratch: []u8) inputbox.Decision {
    const d = inputbox.decide(policy, text, scratch);
    _ = sendDecision(v, d);
    return d;
}

fn helloPolicy(v: *const client.Viewer) ?inputbox.Policy {
    const h = v.helloText();
    inline for (.{ "none", "keys", "instruct", "text" }) |name| {
        if (std.mem.indexOf(u8, h, "\"input\":\"" ++ name ++ "\"") != null) return @field(inputbox.Policy, name);
    }
    return null;
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    var dump_buf: [4096]u8 = undefined;
    var scratch: [inputbox.max_frame]u8 = undefined;

    // Default mode for a program that is not a shell is instruct; cmd.exe
    // is a shell, so this needs the explicit opt-in, but no --input.
    {
        const dir = try h.dataDir("webinput");
        const inst = try proc.Instance.start(h, dir, port, &.{ "--allow-remote-shell", "--project", "Web \"Demo\"", "--", "cmd.exe", "/k" });
        defer inst.kill();
        const creds = try client.pair(inst, "phone");
        const v = try client.Viewer.open(inst, creds.sessionCookie());
        defer v.deinit();

        const policy = helloPolicy(v) orelse .none;
        _ = r.check("default input mode is instruct", policy == .instruct, "{s}", .{v.helloText()});
        _ = r.check("hello carries the project name, escaped", std.mem.indexOf(u8, v.helloText(), "\"project\":\"Web \\\"Demo\\\"\"") != null, "{s}", .{v.helloText()});
        _ = r.check("cmd prompt visible", waitLine(v, "E2E>", 10_000), "{s}", .{v.dump(&dump_buf)});

        // A typed instruction (with a Shift+Enter line break, collapsed to
        // a space) is typed into the child and submitted.
        const d = box(v, policy, "echo BOX-%OS%\nOK", &scratch);
        _ = r.check("box text becomes an l: instruction line", d == .line and std.mem.eql(u8, d.line, "echo BOX-%OS% OK"), "{any}", .{d});
        _ = r.check("instruction line reaches the child", v.waitFor("BOX-Windows_NT OK", 5000), "{s}", .{v.dump(&dump_buf)});
        _ = waitLine(v, "E2E>", 5000);

        // Refused lines: the client refuses at once (and keeps the text);
        // the server, sent the raw line anyway, refuses with the same reason.
        const cases = [_]struct { text: []const u8, reason: []const u8, refusal: inputbox.Refusal }{
            .{ .text = "!echo WEB-ESCAPE", .reason = "ShellEscape", .refusal = .shell_escape },
            .{ .text = "/permissions", .reason = "SlashCommand", .refusal = .slash_command },
            .{ .text = "# remember WEB-ESCAPE", .reason = "MemoryShortcut", .refusal = .memory_shortcut },
        };
        for (cases) |c| {
            const cd = inputbox.decide(policy, c.text, &scratch);
            var name_buf: [96]u8 = undefined;
            _ = r.check(std.fmt.bufPrint(&name_buf, "client refuses '{s}'", .{c.text}) catch "client refuses", cd == .refuse and cd.refuse == c.refusal, "{any}", .{cd});
            const before = v.rejected_count;
            var raw: [128]u8 = undefined;
            v.send(std.fmt.bufPrint(&raw, "l:{s}", .{c.text}) catch unreachable);
            const got = v.pumpUntil(3000, before, struct {
                fn f(n: usize, vv: *client.Viewer) bool {
                    return vv.rejected_count > n;
                }
            }.f);
            const msg = v.rejected[0..v.rejected_len];
            const reason_ok = got and std.mem.indexOf(u8, msg, c.reason) != null;
            const same = reason_ok and inputbox.serverRefusal(c.reason).? == c.refusal;
            _ = r.check(std.fmt.bufPrint(&name_buf, "server rejects with a reason ({s})", .{c.reason}) catch "server rejects", same, "got={} '{s}'", .{ got, msg });
        }
        v.pump(600);
        _ = r.check("no refused line reached the child", v.g.find("WEB-ESCAPE") == null and std.mem.eql(u8, v.cursorLine(), "E2E>"), "'{s}'", .{v.cursorLine()});

        // Answer words, as dictation writes them, press keys.
        for ([_][]const u8{ "Four.", "two", "Yes!", "\u{FF2E}\u{FF4F}" }) |t| {
            const ad = box(v, policy, t, &scratch);
            _ = r.check("answer word maps to a key", ad == .key, "'{s}' -> {any}", .{ t, ad });
        }
        _ = r.check("answer words typed as keys (4 2 y n)", waitLine(v, "E2E>42yn", 5000), "'{s}'", .{v.cursorLine()});
        net.sleep(1100); // one Esc per second
        _ = box(v, policy, "Escape.", &scratch);
        _ = r.check("\"Escape.\" presses Esc (clears the line)", waitLine(v, "E2E>", 5000), "'{s}'", .{v.cursorLine()});
        _ = box(v, policy, "number five", &scratch);
        _ = waitLine(v, "E2E>5", 5000);
        _ = box(v, policy, "OK.", &scratch);
        _ = r.check("\"OK.\" presses Enter", v.waitFor("'5' is not recognized", 5000), "{s}", .{v.dump(&dump_buf)});
        _ = waitLine(v, "E2E>", 5000);

        // The native client's instruction line, fed keystrokes the way its
        // window does: the same features as above.
        {
            const line = try std.heap.page_allocator.create(inputline.Line);
            defer std.heap.page_allocator.destroy(line);
            line.* = .{};
            const sender: LineSender = .{ .v = v };
            typeLine(line, "echo NATIVE-%OS%");
            _ = line.onKey(.enter, .{}, sender);
            _ = r.check("native line: Enter sends an instruction line", v.waitFor("NATIVE-Windows_NT", 5000) and line.text().len == 0, "{s}", .{v.dump(&dump_buf)});
            _ = waitLine(v, "E2E>", 5000);
            typeLine(line, "!echo NATIVE-ESCAPE");
            _ = line.onKey(.enter, .{}, sender);
            _ = r.check("native line: a leading ! is refused locally, the text kept", std.mem.eql(u8, line.text(), "!echo NATIVE-ESCAPE") and std.mem.eql(u8, line.note(), inputbox.refusalText(.shell_escape)), "'{s}' '{s}'", .{ line.text(), line.note() });
            net.sleep(1100); // one Esc per second
            _ = line.onKey(.escape, .{}, sender); // clears the line, sends nothing
            _ = r.check("native line: Esc clears a non-empty line", line.text().len == 0, "'{s}'", .{line.text()});
            // A server refusal puts the last line back (the server is sent
            // a raw line the client would have refused).
            const before = v.rejected_count;
            v.send("l:#NATIVE-ESCAPE");
            const got = v.pumpUntil(3000, before, struct {
                fn f(n: usize, vv: *client.Viewer) bool {
                    return vv.rejected_count > n;
                }
            }.f);
            var why_buf: [32]u8 = undefined;
            if (got) line.rejected(rejectedReason(v, &why_buf));
            _ = r.check("native line: a rejection is explained and the line restored", got and std.mem.eql(u8, line.text(), "echo NATIVE-%OS%") and std.mem.eql(u8, line.note(), inputbox.refusalText(.memory_shortcut)), "got={} '{s}' '{s}'", .{ got, line.text(), line.note() });
            line.field.clear();
            // Answer words press keys; Enter on an empty line presses Enter.
            typeLine(line, "Three.");
            _ = line.onKey(.enter, .{}, sender);
            _ = r.check("native line: an answer word presses its key", waitLine(v, "E2E>3", 5000), "'{s}'", .{v.cursorLine()});
            _ = line.onKey(.enter, .{}, sender);
            _ = r.check("native line: Enter on an empty line presses Enter", v.waitFor("'3' is not recognized", 5000), "{s}", .{v.dump(&dump_buf)});
            _ = r.check("native line: nothing refused reached the child", v.g.find("NATIVE-ESCAPE") == null, "{s}", .{v.dump(&dump_buf)});
        }
        _ = r.check("every frame decoded strictly", v.bad == null, "{?t}", .{v.bad});
        _ = r.ok("portal still running", inst.alive() and client.alive(inst));
    }

    // Without the opt-in, the default drops to keys for a shell: answer
    // words still work, instruction lines are refused by the client and
    // dropped by the server.
    {
        const dir = try h.dataDir("webinput-shell");
        const inst = try proc.Instance.start(h, dir, port + 1, &.{ "--", "cmd.exe", "/k" });
        defer inst.kill();
        const creds = try client.pair(inst, "phone");
        const v = try client.Viewer.open(inst, creds.sessionCookie());
        defer v.deinit();
        const policy = helloPolicy(v) orelse .none;
        _ = r.check("default for a shell without --allow-remote-shell is keys", policy == .keys, "{s}", .{v.helloText()});
        _ = r.ok("the fallback is logged", inst.logHas("not for a shell"));
        _ = waitLine(v, "E2E>", 10_000);
        const d = box(v, policy, "echo NOPE", &scratch);
        _ = r.check("keys mode: client refuses a line (answers only)", d == .refuse and d.refuse == .answers_only, "{any}", .{d});
        v.send("l:echo NOPE-RAW");
        v.pump(800);
        _ = r.check("keys mode: server drops a raw l: line", v.g.find("NOPE-RAW") == null, "{s}", .{v.dump(&dump_buf)});
        _ = box(v, policy, "Three.", &scratch);
        _ = r.check("keys mode: answer words still press keys", waitLine(v, "E2E>3", 5000), "'{s}'", .{v.cursorLine()});
    }
}
