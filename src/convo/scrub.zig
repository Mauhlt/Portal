//! Path and user-name scrubbing for every Conversation view text
//! (docs/tabs-design.md, privacy rule 1: no paths, user names or data
//! folders leave the desktop). The grid is exempt; the conversation is
//! not, because it is sent as metadata-like text.
//!
//! One pass over the text, at each position, in this order:
//!   1. the tab's project folder (any case, `\` or `/`, doubled
//!      separators, `\\?\` prefixed, git-bash `/c/...`, WSL `/mnt/c/...`,
//!      URL-encoded `C%3A%5C...`) becomes the tab's name, so
//!      `C:\code\acme\src\x.zig` reads `acme\src\x.zig`;
//!   2. any other absolute path becomes `[path]`: drive paths (`C:\`,
//!      `c:/`, `C%3A%2F`), UNC and device paths (`\\server\share`,
//!      `\\?\`, `\\.\`, `//server/share`), `file://` URLs, POSIX paths with
//!      at least two components (`/home/bob`, `/c/Users`), and paths from
//!      the home folder or an environment variable (`~/x`, `%USERPROFILE%\x`,
//!      `$HOME/x`, `${HOME}/x`, `$env:LOCALAPPDATA\x`). A path that starts
//!      right after a quote runs to the closing quote (spaces included);
//!      otherwise to the next space or quote. Trailing sentence
//!      punctuation stays;
//!   3. a lone drive letter (`C:` before the end, a quote, `,`, `.`, `;`,
//!      `)` or `]`) is dropped;
//!   4. the user's name, as a whole word in any case, becomes `[user]`
//!      (this also catches pieces of a path cut by a line break).
//!
//! The home folder is an absolute path, so rule 2 removes it. No regular
//! expressions: a byte scanner, so the output is valid UTF-8 whenever the
//! input is (it only cuts at ASCII bytes).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Context = struct {
    /// The tab's project folder, absolute (`C:\code\acme`).
    root: []const u8 = "",
    /// The tab's display name (never a path).
    name: []const u8 = "Project",
    /// The user's name (%USERNAME%).
    user: ?[]const u8 = null,
};

pub const path_mark = "[path]";
pub const user_mark = "[user]";

/// Appends the scrubbed `in` to `out`.
pub fn scrub(gpa: Allocator, ctx: Context, in: []const u8, out: *std.ArrayList(u8)) Allocator.Error!void {
    var root = trimSeps(ctx.root);
    // A drive root ("C:\") as the project would turn every path on the
    // drive into a project path: treat it like any other path instead.
    if (root.len <= 3) root = "";
    const user: []const u8 = if (ctx.user) |u| (if (u.len >= 2) u else "") else "";
    var i: usize = 0;
    while (i < in.len) {
        const at_boundary = boundaryBefore(in, i);
        if (at_boundary and root.len > 0) {
            if (matchRoot(in, i, root)) |end| {
                try out.appendSlice(gpa, ctx.name);
                i = end;
                continue;
            }
        }
        if (at_boundary) {
            if (absolutePath(in, i)) |end| {
                try out.appendSlice(gpa, path_mark);
                i = end;
                continue;
            }
            if (loneDrive(in, i)) {
                i += 2;
                continue;
            }
        }
        if (user.len > 0 and wordAt(in, i, user)) {
            try out.appendSlice(gpa, user_mark);
            i += user.len;
            continue;
        }
        try out.append(gpa, in[i]);
        i += 1;
    }
}

fn trimSeps(p: []const u8) []const u8 {
    var s = p;
    while (s.len > 0 and isSep(s[s.len - 1])) s = s[0 .. s.len - 1];
    return s;
}

fn isSep(c: u8) bool {
    return c == '\\' or c == '/';
}

fn isAlnum(c: u8) bool {
    return std.ascii.isAlphanumeric(c);
}

/// A character that may be part of a path outside quotes.
fn pathChar(c: u8) bool {
    return switch (c) {
        0...0x20, 0x7f, '"', '\'', '`', '<', '>', '|', '*', '?' => false,
        else => true,
    };
}

/// The previous byte cannot continue a word or a path: a path or a name
/// may start at `i`.
fn boundaryBefore(s: []const u8, i: usize) bool {
    if (i == 0) return true;
    const p = s[i - 1];
    return !isAlnum(p) and p != '_' and p != '-' and p != '.' and p != '$' and p != '%' and p != '~';
}

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// `%XX` at `j` decoded, or null.
fn pctAt(s: []const u8, j: usize) ?u8 {
    if (j + 3 > s.len or s[j] != '%') return null;
    const hi = hexVal(s[j + 1]) orelse return null;
    const lo = hexVal(s[j + 2]) orelse return null;
    return hi << 4 | lo;
}

/// One character of `s` at `j` (itself or `%XX`-encoded): the byte and
/// its length.
fn charAt(s: []const u8, j: usize) ?struct { c: u8, len: usize } {
    if (j >= s.len) return null;
    if (pctAt(s, j)) |c| return .{ .c = c, .len = 3 };
    return .{ .c = s[j], .len = 1 };
}

/// A run of separators (`\`, `/`, `%5C`, `%2F`) at `j`: its end, or null.
fn sepRun(s: []const u8, j: usize) ?usize {
    var k = j;
    while (charAt(s, k)) |ch| {
        if (!isSep(ch.c)) break;
        k += ch.len;
    }
    return if (k > j) k else null;
}

/// `pat` at `s[j..]`, ignoring ASCII case, any separator run matching
/// any separator run, characters possibly `%XX`-encoded. Returns the end.
fn matchLoose(s: []const u8, j0: usize, pat: []const u8) ?usize {
    var j = j0;
    var k: usize = 0;
    while (k < pat.len) {
        if (isSep(pat[k])) {
            while (k < pat.len and isSep(pat[k])) k += 1;
            j = sepRun(s, j) orelse return null;
            continue;
        }
        const ch = charAt(s, j) orelse return null;
        if (std.ascii.toLower(ch.c) != std.ascii.toLower(pat[k])) return null;
        j += ch.len;
        k += 1;
    }
    return j;
}

/// The project folder at `i` in any of its spellings, ending at a
/// separator or the end of the path; returns the end (separator excluded).
fn matchRoot(s: []const u8, i: usize, root: []const u8) ?usize {
    var start = i;
    // \\?\C:\..., //?/C:/...
    for ([_][]const u8{ "\\\\?\\", "//?/", "\\\\.\\", "//./" }) |pre| {
        if (std.mem.startsWith(u8, s[i..], pre)) start = i + pre.len;
    }
    const end = blk: {
        if (matchLoose(s, start, root)) |e| break :blk e;
        // C:\rest as /c/rest, /mnt/c/rest, /cygdrive/c/rest.
        if (root.len >= 3 and root[1] == ':' and std.ascii.isAlphabetic(root[0]) and isSep(root[2])) {
            const rest = root[2..];
            for ([_][]const u8{ "/", "/mnt/", "/cygdrive/" }) |pre| {
                if (!std.mem.startsWith(u8, s[i..], pre)) continue;
                const d = i + pre.len;
                if (d >= s.len or std.ascii.toLower(s[d]) != std.ascii.toLower(root[0])) continue;
                if (matchLoose(s, d + 1, rest)) |e| break :blk e;
            }
        }
        return null;
    };
    // "C:\code\acme" must not match "C:\code\acme2".
    if (end < s.len) {
        const ch = charAt(s, end).?;
        if (!isSep(ch.c) and (isAlnum(ch.c) or ch.c == '_' or ch.c == '-' or ch.c >= 0x80)) return null;
    }
    return end;
}

/// The end of the absolute path starting at `i`, or null if none starts
/// there.
fn absolutePath(s: []const u8, i: usize) ?usize {
    const rest = s[i..];
    // file:// URLs, whatever follows.
    if (rest.len > 7 and std.ascii.startsWithIgnoreCase(rest, "file://")) return pathEnd(s, i, i + 7);
    // Device paths: \\?\..., \\.\...
    for ([_][]const u8{ "\\\\?\\", "//?/", "\\\\.\\", "//./" }) |pre| {
        if (std.mem.startsWith(u8, rest, pre)) return pathEnd(s, i, i + pre.len);
    }
    // Drive paths: C:\ c:/ C%3A%5C
    if (rest.len > 0 and std.ascii.isAlphabetic(rest[0])) {
        if (charAt(s, i + 1)) |colon| if (colon.c == ':') {
            if (sepRun(s, i + 1 + colon.len) != null) return pathEnd(s, i, i + 1 + colon.len);
        };
    }
    // UNC: \\server\share, //server/share (not a URL's "scheme://").
    if (rest.len >= 2 and isSep(rest[0]) and rest[1] == rest[0] and !(i > 0 and s[i - 1] == ':')) {
        if (components(s, i + 2) >= 2) return pathEnd(s, i, i + 2);
    }
    // POSIX: /a/b (two components at least, so "/clear" and "and/or" stay).
    if (rest.len >= 1 and rest[0] == '/' and !(i > 0 and (s[i - 1] == '/' or s[i - 1] == ':' or s[i - 1] == '\\'))) {
        if (components(s, i + 1) >= 2) return pathEnd(s, i, i + 1);
    }
    // ~/x, ~\x
    if (rest.len >= 3 and rest[0] == '~' and isSep(rest[1]) and components(s, i + 2) >= 1) return pathEnd(s, i, i + 2);
    // %VAR%\x, $VAR/x, ${VAR}/x, $env:VAR\x
    if (envPrefix(s, i)) |after| {
        if (sepRun(s, after) != null) return pathEnd(s, i, after);
    }
    return null;
}

/// `%NAME%`, `$NAME`, `${NAME}` or `$env:NAME` at `i`: the position after it.
fn envPrefix(s: []const u8, i: usize) ?usize {
    var j = i;
    if (j >= s.len) return null;
    if (s[j] == '%') {
        j += 1;
        const st = j;
        while (j < s.len and (isAlnum(s[j]) or s[j] == '_')) j += 1;
        if (j == st or j >= s.len or s[j] != '%') return null;
        return j + 1;
    }
    if (s[j] != '$') return null;
    j += 1;
    if (j < s.len and s[j] == '{') {
        j += 1;
        const st = j;
        while (j < s.len and (isAlnum(s[j]) or s[j] == '_')) j += 1;
        if (j == st or j >= s.len or s[j] != '}') return null;
        return j + 1;
    }
    if (std.ascii.startsWithIgnoreCase(s[j..], "env:")) j += 4;
    const st = j;
    while (j < s.len and (isAlnum(s[j]) or s[j] == '_')) j += 1;
    if (j == st) return null;
    return j;
}

/// How many non-empty components (separated by `\` or `/`) follow at `j`,
/// counting up to 2.
fn components(s: []const u8, j0: usize) usize {
    var j = j0;
    var n: usize = 0;
    while (n < 2) {
        const st = j;
        while (j < s.len and pathChar(s[j]) and !isSep(s[j])) j += 1;
        if (j == st) return n;
        n += 1;
        if (j >= s.len or !isSep(s[j])) return n;
        j += 1;
    }
    return n;
}

/// The end of a path that starts at `start` (its body from `body`): to the
/// closing quote if it starts right after one, else over path characters;
/// trailing punctuation is left out.
fn pathEnd(s: []const u8, start: usize, body: usize) usize {
    if (start > 0) {
        const q = s[start - 1];
        if (q == '"' or q == '\'' or q == '`') {
            var j = body;
            while (j < s.len and j - start < 1024 and s[j] != q and s[j] != '\n') j += 1;
            if (j < s.len and s[j] == q) return j;
        }
    }
    var j = body;
    while (j < s.len and pathChar(s[j])) j += 1;
    while (j > body and std.mem.indexOfScalar(u8, ".,;:!)]}>", s[j - 1]) != null) j -= 1;
    return j;
}

/// `X:` standing alone (a drive letter): before the end, a quote, a
/// separator-less punctuation mark.
fn loneDrive(s: []const u8, i: usize) bool {
    if (i + 2 > s.len or !std.ascii.isAlphabetic(s[i]) or s[i + 1] != ':') return false;
    if (i + 2 == s.len) return true;
    return std.mem.indexOfScalar(u8, "\"'`,.;)]", s[i + 2]) != null;
}

/// `word` at `i` as a whole word (ASCII case ignored).
fn wordAt(s: []const u8, i: usize, word: []const u8) bool {
    if (i + word.len > s.len) return false;
    if (!std.ascii.eqlIgnoreCase(s[i..][0..word.len], word)) return false;
    if (i > 0 and isAlnum(s[i - 1])) return false;
    const e = i + word.len;
    if (e < s.len and isAlnum(s[e])) return false;
    return true;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn check(ctx: Context, in: []const u8, want: []const u8) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try scrub(testing.allocator, ctx, in, &out);
    if (!std.mem.eql(u8, out.items, want)) {
        std.debug.print("\nin:   {s}\nwant: {s}\ngot:  {s}\n", .{ in, want, out.items });
        return error.TestUnexpectedResult;
    }
}

const acme: Context = .{ .root = "C:\\Users\\bob\\code\\acme-api", .name = "acme-api", .user = "bob" };

test "project folder becomes the tab name, in every spelling" {
    try check(acme, "Edited C:\\Users\\bob\\code\\acme-api\\src\\main.zig.", "Edited acme-api\\src\\main.zig.");
    try check(acme, "c:/users/BOB/Code/ACME-API/src/x.zig", "acme-api/src/x.zig");
    try check(acme, "C:\\\\Users\\\\bob\\\\code\\\\acme-api\\\\build.zig", "acme-api\\\\build.zig");
    try check(acme, "\\\\?\\C:\\Users\\bob\\code\\acme-api\\a", "acme-api\\a");
    try check(acme, "cd /c/Users/bob/code/acme-api/src && ls", "cd acme-api/src && ls");
    try check(acme, "/mnt/c/Users/bob/code/acme-api", "acme-api");
    try check(acme, "file C%3A%5CUsers%5Cbob%5Ccode%5Cacme-api%5Cx.txt", "file acme-api%5Cx.txt");
    try check(acme, "\"C:\\Users\\bob\\code\\acme-api\"", "\"acme-api\"");
    try check(acme, "(C:\\Users\\bob\\code\\acme-api)", "(acme-api)");
    // A sibling folder with the same prefix is not the project.
    try check(acme, "C:\\Users\\bob\\code\\acme-api2\\x", "[path]");
    try check(acme, "C:\\Users\\bob\\code\\acme-apiX", "[path]");
}

test "other absolute paths are removed" {
    const c: Context = .{ .root = "D:\\work\\proj", .name = "proj", .user = "alice" };
    try check(c, "see C:\\Windows\\System32\\drivers\\etc\\hosts.", "see [path].");
    try check(c, "C:/Program Files/Git/bin", "[path] Files/Git/bin");
    try check(c, "open \"C:\\Program Files\\My App\\x.exe\" now", "open \"[path]\" now");
    try check(c, "'C:\\Users\\alice\\My Documents\\a b.txt'", "'[path]'");
    try check(c, "`c:\\temp\\x`", "`[path]`");
    try check(c, "\\\\fileserver\\share\\team\\doc.txt", "[path]");
    try check(c, "//fileserver/share/doc", "[path]");
    try check(c, "\\\\?\\UNC\\srv\\share\\x", "[path]");
    try check(c, "\\\\.\\pipe\\portal-x", "[path]");
    try check(c, "at /home/alice/.config/x and /usr/bin", "at [path] and [path]");
    try check(c, "PATH=/usr/local/bin:/opt/x/bin", "PATH=[path]"); // one path list, one mark
    try check(c, "file:///C:/Users/alice/x.html", "[path]");
    try check(c, "file:///home/alice/x", "[path]");
    try check(c, "~/.claude/projects", "[path]");
    try check(c, "%LOCALAPPDATA%\\Portal\\portal.log", "[path]");
    try check(c, "%userprofile%/x", "[path]");
    try check(c, "$HOME/.ssh/id_ed25519", "[path]");
    try check(c, "${HOME}/x", "[path]");
    try check(c, "$env:USERPROFILE\\Downloads", "[path]");
    try check(c, "C%3A%5CUsers%5Calice%5Cx", "[path]");
    try check(c, "c%3a%2fusers%2fx", "[path]");
    try check(c, "D:\\work\\proj\\src and D:\\work\\other\\src", "proj\\src and [path]");
}

test "ordinary text stays" {
    const c: Context = .{ .root = "D:\\work\\proj", .name = "proj", .user = "alice" };
    const keep = [_][]const u8{
        "run /clear first",
        "and/or src/main.zig a/b/c",
        "see https://example.com/a/b?x=1",
        "1/2 of 3/4",
        "Option B: do it",
        "Note: x",
        "drive C: is full", // a drive letter before a space is kept
        "split on \"\\\\n\" then",
        "// comment here",
        "x = a / b / c",
        "100%",
        "$5 and $ 6",
        "~ is home",
        "src\\convo\\scrub.zig",
        "Alicex alicea",
    };
    for (keep) |k| try check(c, k, k);
}

test "lone drive letters go; the user name goes in any case" {
    const c: Context = .{ .root = "D:\\work\\proj", .name = "proj", .user = "alice" };
    try check(c, "copy to E:", "copy to ");
    try check(c, "on \"E:\" or (F:)", "on \"\" or ()");
    try check(c, "ask Alice or ALICE, alice's", "ask [user] or [user], [user]'s");
    // A wrapped path: the second line is relative, the name still goes.
    try check(c, "C:\\Users\\al\nice\\x and Users\\alice\\Docs", "[path]\nice\\x and Users\\[user]\\Docs");
    // A short user name is not scrubbed as a word (too many false hits).
    try check(.{ .user = "a" }, "a b", "a b");
}

test "a drive root as the project is not a prefix of everything" {
    try check(.{ .root = "C:\\", .name = "Project" }, "C:\\x\\y", "[path]");
}

test "utf-8 survives" {
    try check(acme, "日本 C:\\Users\\bob\\x 中文 ✓", "日本 [path] 中文 ✓");
    try check(acme, "C:\\Users\\bob\\code\\acme-api\\日本\\x", "acme-api\\日本\\x");
}

test "no input makes the scanner misbehave" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    const alphabet = "C:\\/%3A5c2fx ~$\"'`?.\nab{}eNv";
    var buf: [64]u8 = undefined;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    for (0..5000) |_| {
        const n = r.uintLessThan(usize, buf.len);
        for (buf[0..n]) |*b| b.* = alphabet[r.uintLessThan(usize, alphabet.len)];
        out.clearRetainingCapacity();
        try scrub(testing.allocator, acme, buf[0..n], &out);
        try testing.expect(out.items.len <= n * 6 + 8);
    }
}
