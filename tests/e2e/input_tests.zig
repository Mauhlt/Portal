//! Input policies, verified through what the child actually received: the
//! child is `cmd.exe /k` (prompt "E2E>"), so anything that reaches it is
//! echoed on the prompt line and shows up in the grid.

const std = @import("std");
const net = @import("net.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const Runner = @import("runner.zig").Runner;

const cmd_child = [_][]const u8{ "--", "cmd.exe", "/k" };

fn startShell(h: *proc.Harness, name: []const u8, port: u16, input: []const u8) !struct { inst: *proc.Instance, v: *client.Viewer } {
    const dir = try h.dataDir(name);
    const args = [_][]const u8{ "--input", input } ++ cmd_child;
    const inst = try proc.Instance.start(h, dir, port, &args);
    errdefer inst.kill();
    const creds = try client.pair(inst, "laptop");
    const v = try client.Viewer.open(inst, creds.sessionCookie());
    return .{ .inst = inst, .v = v };
}

/// Waits for an idle prompt on the cursor row.
fn waitPrompt(v: *client.Viewer, ms: u32) bool {
    const ok = v.pumpUntil(ms, {}, struct {
        fn f(_: void, vv: *client.Viewer) bool {
            return std.mem.eql(u8, vv.cursorLine(), "E2E>");
        }
    }.f);
    _ = v.settle(300, 2000);
    return ok;
}

/// Waits until the cursor line equals `want`.
fn waitLine(v: *client.Viewer, want: []const u8, ms: u32) bool {
    const ok = v.pumpUntil(ms, want, struct {
        fn f(w: []const u8, vv: *client.Viewer) bool {
            return std.mem.eql(u8, vv.cursorLine(), w);
        }
    }.f);
    // Anything that arrives later would show in the next check.
    _ = v.settle(400, 2000);
    return ok and std.mem.eql(u8, v.cursorLine(), want);
}

pub fn runKeys(h: *proc.Harness, r: *Runner, port: u16) !void {
    var dump_buf: [4096]u8 = undefined;
    {
        const s = try startShell(h, "keys", port, "keys");
        defer s.inst.kill();
        defer s.v.deinit();
        const v = s.v;
        _ = r.check("hello says keys", std.mem.indexOf(u8, v.helloText(), "\"keys\"") != null, "{s}", .{v.helloText()});
        _ = r.check("cmd prompt visible", waitPrompt(v, 10_000), "{s}", .{v.dump(&dump_buf)});
        const prompts0 = v.g.count("E2E>");

        // None of these may reach the child in keys mode.
        const blocked = [_][]const u8{
            "t:QQQ",    "k:tab",       "k:up",     "k:left",   "k:backspace", "k:ctrl-c",
            "k:delete", "k:shift-tab", "k:home",   "k:pageup", "k:down",      "k:right",
            "k:end",    "k:pagedown",  "i1",       "r",        "k:\x1b[A",    "k:ENTER",
            "k:",       "t:",          "k:enter ", "k:11",     "k:yes",
        };
        for (blocked) |m| v.send(m);
        v.send("k:4");
        v.send("k:2");
        _ = r.check("disallowed keys and text dropped; allowed digits typed", waitLine(v, "E2E>42", 5000), "cursor line '{s}'", .{v.cursorLine()});
        _ = r.check("no stray text, ^C or extra prompt from dropped input", v.g.find("QQQ") == null and v.g.find("^C") == null and
            v.g.count("E2E>") == prompts0, "{s}", .{v.dump(&dump_buf)});
        v.send("k:enter");
        _ = r.check("k:enter submits the line", v.waitFor("'42' is not recognized", 5000), "{s}", .{v.dump(&dump_buf)});
        _ = r.ok("back at an empty prompt", waitPrompt(v, 5000));

        v.send("k:y");
        v.send("k:n");
        v.send("k:0");
        _ = r.check("y, n and digits are allowed", waitLine(v, "E2E>yn0", 5000), "'{s}'", .{v.cursorLine()});
        // Esc clears cmd's input line. Only one Esc per second is passed on.
        net.sleep(1100);
        v.send("k:esc");
        v.send("k:7");
        v.send("k:esc");
        v.send("k:8");
        _ = r.check("first Esc passes, a second within 1 s is dropped", waitLine(v, "E2E>78", 5000), "'{s}'", .{v.cursorLine()});
        net.sleep(1100);
        v.send("k:esc");
        _ = r.check("Esc again after 1 s", waitLine(v, "E2E>", 5000), "'{s}'", .{v.cursorLine()});
        _ = r.check("every frame decoded strictly", v.bad == null, "{?t}", .{v.bad});
        _ = r.ok("portal still running", s.inst.alive() and client.alive(s.inst));
    }
    {
        const s = try startShell(h, "none", port + 1, "none");
        defer s.inst.kill();
        defer s.v.deinit();
        const v = s.v;
        _ = r.check("--input none: hello says none", std.mem.indexOf(u8, v.helloText(), "\"none\"") != null, "{s}", .{v.helloText()});
        _ = r.ok("--input none: prompt visible", waitPrompt(v, 10_000));
        for ([_][]const u8{ "k:1", "k:y", "t:abc", "k:enter" }) |m| v.send(m);
        v.pump(1500);
        _ = r.check("--input none: nothing reaches the child", std.mem.eql(u8, v.cursorLine(), "E2E>") and v.g.count("E2E>") == 1, "'{s}' {s}", .{ v.cursorLine(), v.dump(&dump_buf) });
    }
}

pub fn runText(h: *proc.Harness, r: *Runner, port: u16) !void {
    var dump_buf: [4096]u8 = undefined;
    const s = try startShell(h, "text", port, "text");
    defer s.inst.kill();
    defer s.v.deinit();
    const v = s.v;
    _ = r.check("hello says text", std.mem.indexOf(u8, v.helloText(), "\"text\"") != null, "{s}", .{v.helloText()});
    _ = r.check("cmd prompt visible", waitPrompt(v, 10_000), "{s}", .{v.dump(&dump_buf)});

    v.send("t:echo TXT-%OS%-OK");
    _ = r.check("t: text appears on the prompt line", waitLine(v, "E2E>echo TXT-%OS%-OK", 5000), "'{s}'", .{v.cursorLine()});
    v.send("k:enter");
    _ = r.check("typed command ran (output in grid)", v.waitFor("TXT-Windows_NT-OK", 5000), "{s}", .{v.dump(&dump_buf)});
    _ = waitPrompt(v, 5000);

    v.send("t:REM abcX");
    v.send("k:backspace");
    v.send("t:Y");
    _ = r.check("k:backspace works in text mode", waitLine(v, "E2E>REM abcY", 5000), "'{s}'", .{v.cursorLine()});
    v.send("k:left");
    v.send("k:left");
    v.send("t:-");
    _ = r.check("arrow keys work in text mode", waitLine(v, "E2E>REM ab-cY", 5000), "'{s}'", .{v.cursorLine()});
    v.send("k:esc");
    _ = r.ok("Esc clears the line", waitLine(v, "E2E>", 5000));

    // Control characters are stripped from typed text: no escape sequence
    // (and no Enter) can come from the web.
    v.send("t:A\x1b[31mB\x07C\rD\nE\u{9b}F");
    _ = r.check("control characters stripped from t: text", waitLine(v, "E2E>A[31mBCDEF", 5000), "'{s}'", .{v.cursorLine()});
    {
        const row = v.g.cursor_y;
        _ = r.check("...and no colour reached the terminal", !v.g.lines.items[row].styled, "", .{});
    }
    v.send("k:esc");
    _ = waitPrompt(v, 5000);
    {
        // Ctrl+C abandons the line being typed: cmd starts a new prompt.
        const prompts = v.g.count("E2E>");
        v.send("t:REM abandoned");
        _ = waitLine(v, "E2E>REM abandoned", 5000);
        v.send("k:ctrl-c");
        _ = r.check("k:ctrl-c reaches the child in text mode", waitPrompt(v, 5000) and v.g.count("E2E>") == prompts + 1 and v.g.find("E2E>REM abandoned") != null, "{s}", .{v.dump(&dump_buf)});
    }
    _ = waitPrompt(v, 5000);

    // Wide characters: the grid carries them once, taking two cells.
    v.send("t:echo \u{6F22}\u{5B57}-WIDE");
    v.send("k:enter");
    _ = r.check("wide (CJK) text round-trips through the grid", v.pumpUntil(5000, {}, struct {
        fn f(_: void, vv: *client.Viewer) bool {
            return vv.g.count("\u{6F22}\u{5B57}-WIDE") >= 2;
        }
    }.f), "{s}", .{v.dump(&dump_buf)});
    _ = waitPrompt(v, 5000);
    v.send("k:up");
    _ = r.check("k:up recalls history in text mode", waitLine(v, "E2E>echo \u{6F22}\u{5B57}-WIDE", 5000), "'{s}'", .{v.cursorLine()});
    v.send("k:esc");
    _ = waitLine(v, "E2E>", 3000);

    // Largest allowed input message (4096 bytes after the "t:" prefix is
    // over the limit; exactly 4096 bytes of frame payload is accepted).
    {
        var big: [4096]u8 = undefined;
        @memcpy(big[0..2], "t:");
        @memset(big[2..], 'x');
        v.send(&big);
        v.pump(1000);
        _ = r.check("4096-byte input message accepted", !v.closed and v.g.find("xxxxxxxxxxxxxxxxxxxx") != null, "closed={}", .{v.closed});
        v.send("k:esc");
        v.pump(500);
    }
    _ = r.check("every frame decoded strictly", v.bad == null, "{?t}", .{v.bad});
    _ = r.ok("portal still running", s.inst.alive() and client.alive(s.inst));
}
