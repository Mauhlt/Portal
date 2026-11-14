//! "For you" suggestions from the agent's last reply (docs/tabs-design.md,
//! "For you"): deterministic rules, no model call. Pure: the reply's texts
//! in, items without ids out (foryou_desk.zig gives them ids and keeps
//! them).
//!
//! The texts are the Conversation view's (convo/model.zig): already
//! cleaned and scrubbed of paths and the user's name (scrub.zig). A
//! command that held a path or a name (now `[path]`, `[home]`, `[user]`)
//! can't be run as written, so it is never suggested.
//!
//! Rules, in reply order:
//!   * a fenced code block in a shell language (`sh`, `bash`, `powershell`,
//!     `cmd`, ...; or no language and a known command word first) with
//!     exactly one command line (a leading `$ ` / `> ` / `PS> ` prompt
//!     dropped) -> `suggest_run`; several lines are a script, not one
//!     command (foryou.runnable allows one line), and are skipped;
//!   * an inline code span right after a run verb ("run `zig build`",
//!     "try `x`", "execute `y`"), or in a request to the owner ("please
//!     ...", "you'll need to ...", "can you ...", "you can ...") whose
//!     first word is a known command -> `suggest_run`;
//!   * a sentence that names an open tab or a startable project (not this
//!     tab) with a switch cue ("switch to", "move to", "go to", "over to",
//!     "belongs in", "... project") -> `suggest_goto`;
//!   * the reply's closing sentence, if it is a yes/no question (ends
//!     with `?`, does not start with a question word, offers no "or") ->
//!     `answer`.
//! A sentence that negates ("don't", "do not", "never", "avoid", "no need
//! to", "instead of", ...) suggests nothing; for a code block that is the
//! prose line just before it. A command with a backtick or a line break
//! is not runnable (foryou.runnable) and is skipped; duplicates once.

const std = @import("std");
const foryou = @import("shared").foryou;
const tabs_wire = @import("shared").tabs;

pub const Item = foryou.Item;

/// Names a reply may switch to: the open tabs and the startable projects,
/// minus the tab's own name.
pub const Names = struct {
    tabs: []const []const u8 = &.{},
    startable: []const []const u8 = &.{},
    own: []const u8 = "",
};

/// At most this many suggestions per reply (the desk caps the whole list
/// at foryou.max_items, waiting cards first).
pub const max_suggestions = foryou.max_items;

pub const Out = struct {
    items: [max_suggestions]Item = undefined,
    len: usize = 0,

    pub fn slice(o: *const Out) []const Item {
        return o.items[0..o.len];
    }

    fn add(o: *Out, it: Item) void {
        if (o.len == o.items.len or !it.valid()) return;
        for (o.slice()) |*have| if (have.kind == it.kind and
            std.mem.eql(u8, have.cmd(), it.cmd()) and std.mem.eql(u8, have.project(), it.project()) and
            (it.kind != .answer or std.mem.eql(u8, have.summary(), it.summary()))) return;
        o.items[o.len] = it;
        o.len += 1;
    }
};

/// The suggestions of a reply made of `texts` (its assistant items, in
/// order).
pub fn extract(texts: []const []const u8, names: Names, out: *Out) void {
    out.len = 0;
    for (texts) |t| scanText(t, names, out);
    if (texts.len > 0) if (closingQuestion(texts[texts.len - 1])) |q| {
        var it: Item = .{ .kind = .answer };
        it.setSummary(q);
        out.add(it);
    };
}

// ------------------------------------------------------------ the scan

const shell_langs = [_][]const u8{ "sh", "bash", "shell", "console", "terminal", "zsh", "fish", "powershell", "ps", "ps1", "pwsh", "cmd", "bat", "batch", "bat-file" };

/// First words that make an unlabeled code block or a request's span a
/// command.
const command_words = [_][]const u8{
    "zig",    "git",     "npm",    "npx",       "pnpm",   "yarn",   "node",   "cargo",  "go",
    "python", "python3", "py",     "pip",       "pip3",   "make",   "cmake",  "ninja",  "dotnet",
    "msbuild", "docker", "kubectl", "gh",       "curl",   "pwsh",   "powershell", "cmd", "bash",
    "sh",     "deno",    "bun",    "mvn",       "gradle", "ruby",   "bundle", "rake",   "rustc",
    "rustup", "portalctl", "portal", "winget",  "choco",  "scoop",  "uv",     "poetry", "pytest",
    "jest",   "vitest",  "tsc",    "eslint",    "prettier", "terraform", "helm", "ls", "dir",
    "cat",    "type",    "echo",   "cd",        "zvc",
};

const run_verbs = [_][]const u8{ "run", "rerun", "re-run", "execute", "try", "type", "running" };

const request_cues = [_][]const u8{ "please", "you'll need to", "you will need to", "you need to", "you'd need to", "can you", "could you", "you can", "you could", "you should", "you may want to", "you might want to", "make sure to" };

const negations = [_][]const u8{ "don't", "dont", "do not", "never", "avoid", "shouldn't", "should not", "must not", "mustn't", "no need to", "not to run", "without running", "instead of", "rather than", "won't", "will not", "cannot", "can't" };

const switch_cues = [_][]const u8{ "switch to", "switch over to", "move to", "move over to", "go to", "over to", "belongs in", "belong in", "continue in", "work in", "project" };

const question_words = [_][]const u8{ "what", "which", "where", "when", "why", "who", "whom", "whose", "how" };

const marks = [_][]const u8{ "[path]", "[home]", "[user]" };

fn scanText(text: []const u8, names: Names, out: *Out) void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var in_code = false;
    var lang: []const u8 = "";
    var code_lines: usize = 0;
    var code_line: []const u8 = "";
    var intro: []const u8 = "";
    var prose: []const u8 = "";
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (std.mem.startsWith(u8, line, "```")) {
            if (!in_code) {
                in_code = true;
                lang = std.mem.trim(u8, line[3..], " \t`");
                code_lines = 0;
                intro = prose;
            } else {
                in_code = false;
                if (code_lines == 1) codeBlock(lang, code_line, intro, out);
                prose = "";
            }
            continue;
        }
        if (in_code) {
            if (line.len > 0) {
                code_lines += 1;
                code_line = stripPrompt(line);
            }
            continue;
        }
        if (line.len == 0) continue;
        prose = line;
        var sentences: Sentences = .{ .s = line };
        while (sentences.next()) |sentence| {
            inlineCommands(sentence, out);
            projectSwitch(sentence, names, out);
        }
    }
}

fn codeBlock(lang: []const u8, line: []const u8, intro: []const u8, out: *Out) void {
    var shell = false;
    for (shell_langs) |l| shell = shell or std.ascii.eqlIgnoreCase(lang, l);
    if (!shell and !(lang.len == 0 and knownCommand(line))) return;
    if (negated(intro)) return;
    addRun(line, intro, out);
}

/// `$ zig build` -> `zig build` (and `> `, `PS> `, `PS x> `, `% `).
fn stripPrompt(line: []const u8) []const u8 {
    for ([_][]const u8{ "$ ", "> ", "% ", "PS> " }) |p| if (std.mem.startsWith(u8, line, p)) return std.mem.trim(u8, line[p.len..], " ");
    if (std.mem.startsWith(u8, line, "PS ")) if (std.mem.indexOf(u8, line, "> ")) |i| return std.mem.trim(u8, line[i + 2 ..], " ");
    return line;
}

fn knownCommand(cmd: []const u8) bool {
    const end = std.mem.indexOfAny(u8, cmd, " \t") orelse cmd.len;
    var first = cmd[0..end];
    if (std.mem.startsWith(u8, first, ".\\") or std.mem.startsWith(u8, first, "./")) return true;
    if (std.ascii.endsWithIgnoreCase(first, ".exe")) first = first[0 .. first.len - 4];
    for (command_words) |w| if (std.ascii.eqlIgnoreCase(first, w)) return true;
    return false;
}

fn addRun(cmd_raw: []const u8, why: []const u8, out: *Out) void {
    const cmd = std.mem.trim(u8, cmd_raw, " ");
    if (cmd.len < 2 or !foryou.runnable(cmd)) return;
    for (marks) |m| if (std.mem.indexOf(u8, cmd, m) != null) return;
    var it: Item = .{ .kind = .suggest_run };
    it.setCmd(cmd);
    var sb: [foryou.max_summary]u8 = undefined;
    it.setSummary(cutLine(cmd, &sb));
    setWhy(&it, why);
    out.add(it);
}

fn setWhy(it: *Item, why_raw: []const u8) void {
    var wb: [foryou.max_why]u8 = undefined;
    const why = cutLine(plain(why_raw, &wb), &wb);
    if (why.len > 0) it.setWhy(why);
}

/// Inline spans after a run verb, or in a request to the owner.
fn inlineCommands(sentence: []const u8, out: *Out) void {
    if (negated(sentence)) return;
    const request = startsWithAny(plainStart(sentence), &request_cues);
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, sentence, i, '`')) |a| {
        if (a + 1 < sentence.len and sentence[a + 1] == '`') {
            // ``...``: skip the double tick.
            i = a + 2;
            continue;
        }
        const b = std.mem.indexOfScalarPos(u8, sentence, a + 1, '`') orelse return;
        const span = sentence[a + 1 .. b];
        i = b + 1;
        const before = std.mem.trimEnd(u8, sentence[0..a], " :");
        const sp = std.mem.lastIndexOfAny(u8, before, " (") orelse 0;
        const word = std.mem.trim(u8, before[if (sp == 0) 0 else sp + 1 ..], " (\"'*_");
        var verb = false;
        for (run_verbs) |v| verb = verb or std.ascii.eqlIgnoreCase(word, v);
        if (verb or (request and knownCommand(span))) addRun(span, sentence, out);
    }
}

fn projectSwitch(sentence: []const u8, names: Names, out: *Out) void {
    if (negated(sentence)) return;
    var cue = false;
    for (switch_cues) |c| cue = cue or containsWord(sentence, c);
    if (!cue) return;
    for ([_][]const []const u8{ names.tabs, names.startable }) |list| for (list) |name| {
        if (name.len == 0 or std.ascii.eqlIgnoreCase(name, names.own) or !tabs_wire.validName(name)) continue;
        if (!containsWord(sentence, name)) continue;
        var it: Item = .{ .kind = .suggest_goto };
        it.setProject(name);
        var sb: [foryou.max_summary]u8 = undefined;
        it.setSummary(std.fmt.bufPrint(&sb, "Switch to {s}", .{name}) catch name);
        setWhy(&it, sentence);
        out.add(it);
    };
}

/// The last prose sentence of `text`, if it is a yes/no question.
pub fn closingQuestion(text: []const u8) ?[]const u8 {
    var last: []const u8 = "";
    var lines = std.mem.splitScalar(u8, text, '\n');
    var in_code = false;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (std.mem.startsWith(u8, line, "```")) {
            in_code = !in_code;
            last = "";
            continue;
        }
        if (in_code or line.len == 0) continue;
        var sentences: Sentences = .{ .s = line };
        while (sentences.next()) |s| last = s;
    }
    const q = std.mem.trim(u8, plainStart(last), " *_");
    if (q.len < 4 or q[q.len - 1] != '?' or q.len > foryou.max_summary) return null;
    if (std.mem.indexOfScalar(u8, q, '`') != null) return null;
    const first_end = std.mem.indexOfAny(u8, q, " ,?") orelse q.len;
    for (question_words) |w| if (std.ascii.eqlIgnoreCase(q[0..first_end], w)) return null;
    if (containsWord(q, "or")) return null;
    return q;
}

// ------------------------------------------------------------ helpers

/// Sentences of one line: ends at `.`, `?` or `!` followed by a space or
/// the end, never inside a code span.
const Sentences = struct {
    s: []const u8,
    i: usize = 0,

    fn next(it: *Sentences) ?[]const u8 {
        while (it.i < it.s.len and it.s[it.i] == ' ') it.i += 1;
        if (it.i >= it.s.len) return null;
        const start = it.i;
        var tick = false;
        var j = it.i;
        while (j < it.s.len) : (j += 1) {
            const c = it.s[j];
            if (c == '`') tick = !tick;
            if (tick) continue;
            if ((c == '.' or c == '?' or c == '!') and (j + 1 == it.s.len or it.s[j + 1] == ' ')) {
                it.i = j + 1;
                return it.s[start .. j + 1];
            }
        }
        it.i = it.s.len;
        return it.s[start..];
    }
};

fn negated(s: []const u8) bool {
    for (negations) |n| if (containsWord(s, n)) return true;
    return false;
}

fn startsWithAny(s: []const u8, list: []const []const u8) bool {
    for (list) |p| if (std.ascii.startsWithIgnoreCase(s, p) and (s.len == p.len or !std.ascii.isAlphanumeric(s[p.len]))) return true;
    return false;
}

/// Without a leading list marker, quote or heading mark.
fn plainStart(s: []const u8) []const u8 {
    var t = std.mem.trimStart(u8, s, " ");
    while (true) {
        const before = t.len;
        for ([_][]const u8{ "- ", "* ", "+ ", "> ", "#" }) |p| if (std.mem.startsWith(u8, t, p)) {
            t = std.mem.trimStart(u8, t[p.len..], " #");
        };
        t = std.mem.trimStart(u8, t, "*_");
        if (t.len == before) return t;
    }
}

/// `s` without Markdown emphasis marks (`**`, `__`), into `buf`.
fn plain(s: []const u8, buf: []u8) []const u8 {
    var n: usize = 0;
    var i: usize = 0;
    const t = plainStart(s);
    while (i < t.len and n < buf.len) : (i += 1) {
        if (i + 1 < t.len and ((t[i] == '*' and t[i + 1] == '*') or (t[i] == '_' and t[i + 1] == '_'))) {
            i += 1;
            continue;
        }
        buf[n] = t[i];
        n += 1;
    }
    return buf[0..n];
}

/// One line of at most `buf.len` bytes: cut at a UTF-8 boundary with
/// "..." when longer.
fn cutLine(s: []const u8, buf: []u8) []const u8 {
    var t = s;
    if (std.mem.indexOfAny(u8, t, "\n\t")) |k| t = t[0..k];
    if (t.len <= buf.len) {
        std.mem.copyForwards(u8, buf[0..t.len], t);
        return buf[0..t.len];
    }
    var n = buf.len - 3;
    while (n > 0 and (t[n] & 0xC0) == 0x80) n -= 1;
    std.mem.copyForwards(u8, buf[0..n], t[0..n]);
    @memcpy(buf[n..][0..3], "...");
    return buf[0 .. n + 3];
}

fn containsWord(s: []const u8, w: []const u8) bool {
    var from: usize = 0;
    while (from + w.len <= s.len) {
        const i = from + (std.ascii.findIgnoreCase(s[from..], w) orelse return false);
        const end = i + w.len;
        const before_ok = i == 0 or !(std.ascii.isAlphanumeric(s[i - 1]) or s[i - 1] == '_');
        const after_ok = end == s.len or !(std.ascii.isAlphanumeric(s[end]) or s[end] == '_');
        if (before_ok and after_ok) return true;
        from = i + 1;
    }
    return false;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn run(texts: []const []const u8, names: Names) Out {
    var o: Out = .{};
    extract(texts, names, &o);
    return o;
}

fn has(o: *const Out, kind: foryou.Kind, what: []const u8) bool {
    for (o.slice()) |*it| if (it.kind == kind and (std.mem.eql(u8, it.cmd(), what) or std.mem.eql(u8, it.project(), what) or std.mem.eql(u8, it.summary(), what))) return true;
    return false;
}

test "commands: fenced shell blocks and run verbs; negated mentions and scripts skipped" {
    const o = run(&.{
        \\The manifest test fails because `files 0` isn't rejected. I added the check.
        \\
        \\To check it:
        \\
        \\```sh
        \\$ zig build test -Dtest-filter=manifest
        \\```
        \\
        \\Then run `zig build e2e` once more. Don't run `zig build release` yet, and never run `git push --force`.
        \\
        \\Avoid this one:
        \\```powershell
        \\Remove-Item -Recurse zig-out
        \\```
        \\
        \\A script, not one command:
        \\```bash
        \\cd x
        \\make
        \\```
        \\
        \\```zig
        \\const x = 1;
        \\```
        \\
        \\```
        \\git status
        \\```
        \\
        \\Run `echo ``x`` y` and try `rm -rf [path]`.
    }, .{});
    try testing.expect(has(&o, .suggest_run, "zig build test -Dtest-filter=manifest"));
    try testing.expect(has(&o, .suggest_run, "zig build e2e"));
    try testing.expect(has(&o, .suggest_run, "git status"));
    try testing.expect(!has(&o, .suggest_run, "zig build release"));
    try testing.expect(!has(&o, .suggest_run, "git push --force"));
    try testing.expect(!has(&o, .suggest_run, "Remove-Item -Recurse zig-out"));
    try testing.expect(!has(&o, .suggest_run, "make"));
    try testing.expect(!has(&o, .suggest_run, "const x = 1;"));
    try testing.expect(!has(&o, .suggest_run, "files 0")); // a span, not after a run verb
    for (o.slice()) |*it| {
        try testing.expect(std.mem.indexOf(u8, it.cmd(), "[path]") == null);
        try testing.expect(std.mem.indexOfScalar(u8, it.cmd(), '`') == null);
        try testing.expect(it.valid());
    }
    // The why is the sentence (or the line before the block).
    for (o.slice()) |*it| if (std.mem.eql(u8, it.cmd(), "zig build e2e")) try testing.expectEqualStrings("Then run `zig build e2e` once more.", it.why());
}

test "requests to the owner: a known command in the span" {
    const o = run(&.{"Please `zig build run` when you get a chance. You'll need to `npm install` first. Can you check `README.md`? Please update `config.zig`."}, .{});
    try testing.expect(has(&o, .suggest_run, "zig build run"));
    try testing.expect(has(&o, .suggest_run, "npm install"));
    try testing.expect(!has(&o, .suggest_run, "README.md"));
    try testing.expect(!has(&o, .suggest_run, "config.zig"));
}

test "project switches: only open tabs and startable projects, not the tab itself" {
    const names: Names = .{ .tabs = &.{ "Portal", "WireGuard" }, .startable = &.{"SpeechToText"}, .own = "Portal" };
    const o = run(&.{"The next change belongs in the WireGuard project. After that, switch to SpeechToText. Portal itself is done. Switch to Elsewhere later. Don't move to WireGuard yet."}, names);
    try testing.expect(has(&o, .suggest_goto, "WireGuard"));
    try testing.expect(has(&o, .suggest_goto, "SpeechToText"));
    try testing.expect(!has(&o, .suggest_goto, "Portal"));
    try testing.expect(!has(&o, .suggest_goto, "Elsewhere"));
    var n: usize = 0;
    for (o.slice()) |*it| n += @intFromBool(it.kind == .suggest_goto);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expect(has(&o, .suggest_goto, "Switch to WireGuard"));
}

test "the closing question: yes/no only, the last sentence only" {
    try testing.expect(has(&run(&.{"I kept the port. Keep UDP 51820 for the tunnel?"}, .{}), .answer, "Keep UDP 51820 for the tunnel?"));
    try testing.expect(has(&run(&.{ "Shall I go on?", "Done. **Should I commit this?**" }, .{}), .answer, "Should I commit this?"));
    try testing.expectEqual(@as(usize, 0), run(&.{"Which port should I use?"}, .{}).len);
    try testing.expectEqual(@as(usize, 0), run(&.{"Should I use TCP or UDP?"}, .{}).len);
    try testing.expectEqual(@as(usize, 0), run(&.{"Is this right? I think so."}, .{}).len);
    try testing.expectEqual(@as(usize, 0), run(&.{"Shall I go on?\n```\nx?\n```"}, .{}).len);
    const long = "Should I " ++ comptime repeat("really ", 20) ++ "go on?";
    try testing.expectEqual(@as(usize, 0), run(&.{long}, .{}).len);
}

test "caps, duplicates and long commands" {
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    for (0..40) |i| try w.print("Run `zig build t{d}`. Run `zig build t{d}`.\n", .{ i, i });
    const o = run(&.{w.buffered()}, .{});
    try testing.expectEqual(@as(usize, max_suggestions), o.len);
    try testing.expectEqualStrings("zig build t1", o.items[1].cmd());
    const long_cmd = "zig build " ++ comptime repeat("-Dx=1 ", 30);
    const o2 = run(&.{"Run `" ++ long_cmd ++ "`."}, .{});
    try testing.expectEqual(@as(usize, 1), o2.len);
    try testing.expect(o2.items[0].summary().len <= foryou.max_summary);
    try testing.expect(std.mem.endsWith(u8, o2.items[0].summary(), "..."));
    try testing.expectEqualStrings(std.mem.trim(u8, long_cmd, " "), o2.items[0].cmd());
}

fn repeat(comptime s: []const u8, comptime n: usize) []const u8 {
    comptime var out: []const u8 = "";
    inline for (0..n) |_| out = out ++ s;
    return out;
}
