//! Path and user-name scrubbing for every Conversation view text
//! (docs/tabs-design.md, privacy rule 1: no paths, user names or data
//! folders leave the desktop). The grid is exempt; the conversation is
//! not, because it is sent as metadata-like text.
//!
//! One pass over the text, at each position, in this order:
//!   1. the tab's project folder (any case, `\` or `/`, doubled
//!      separators, `\\?\` prefixed, git-bash `/c/...`, WSL `/mnt/c/...`,
//!      URL-encoded `C%3A%5C...`, also doubly `C%253A...`) becomes the
//!      tab's name, so `C:\code\acme\src\x.zig` reads `acme\src\x.zig`;
//!   2. a home folder (%USERPROFILE%, its 8.3 short form, %OneDrive%; in
//!      the same spellings, spaces included) becomes `[home]`, so
//!      `C:\Users\Jo Ann\x.txt` reads `[home]\x.txt`;
//!   3. any other absolute path becomes `[path]`: drive paths (`C:\`,
//!      `c:/`, `C%3A%2F`, drive-relative `C:Users\x`), UNC and device
//!      paths (`\\server\share`, a bare `\\server`, `\\?\`, `\\.\`,
//!      `//server/share`), `file://` and `smb://` style URLs, root-relative
//!      Windows paths (`\Users\x`), POSIX paths with at least two
//!      components (`/home/bob`, `/c/Users`), and paths from the home
//!      folder or an environment variable (`~/x`, `%USERPROFILE%\x`,
//!      `$HOME/x`, `${HOME}/x`, `$env:LOCALAPPDATA\x`). A path that starts
//!      right after a quote runs to the closing quote (spaces included).
//!      Otherwise it runs to the next space or quote, except that a drive,
//!      UNC or device path keeps going past a space while the next word
//!      holds a separator (`C:\Program Files\Git\bin`). Trailing sentence
//!      punctuation stays;
//!   4. a lone drive letter (`C:` before the end, a quote, `,`, `.`, `;`,
//!      `)` or `]`) is dropped;
//!   5. the user's names (%USERNAME%, the home folder's name and its 8.3
//!      form, and each space-separated part of those), as whole words in
//!      any case (simple Unicode case folding), become `[user]` (this also
//!      catches pieces of a path cut by a line break).
//!
//! Paths of rules 1-3 start at a word boundary, except that drive paths
//! (and `\\?\`, `\\.\`, `file://`, `%VAR%\`) also match glued to the text
//! before them (`-LC:\x`, `x_C:\`, `a.C:\`); a glued `x://` is a URL
//! scheme, and the last letter of a longer word (`Result:` before an
//! escape) is not a drive letter either. No regular expressions: a byte
//! scanner, so the output is valid UTF-8 whenever the input is (it only
//! cuts at ASCII bytes or at whole UTF-8 sequences).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Context = struct {
    /// The tab's project folder, absolute (`C:\code\acme`).
    root: []const u8 = "",
    /// The tab's display name (never a path).
    name: []const u8 = "Project",
    /// The user's name (%USERNAME%).
    user: ?[]const u8 = null,
    /// More names of the user, scrubbed like `user` (see `Identity`).
    users: []const []const u8 = &.{},
    /// Home folders, absolute: become `[home]` (see `Identity`).
    homes: []const []const u8 = &.{},
};

pub const path_mark = "[path]";
pub const user_mark = "[user]";
pub const home_mark = "[home]";

/// Longest quoted path followed to its closing quote; a longer one is cut
/// there (all of it removed) rather than left to leak past a space.
const max_quoted = 64 * 1024;

/// The user's names and home folders, gathered once at startup from the
/// environment (main.zig) for every tab's `Context`.
pub const Identity = struct {
    users: []const []const u8 = &.{},
    homes: []const []const u8 = &.{},

    pub const Inputs = struct {
        /// %USERNAME%.
        user_name: ?[]const u8 = null,
        /// %USERPROFILE% and its 8.3 short form (GetShortPathNameW).
        profile: ?[]const u8 = null,
        profile_short: ?[]const u8 = null,
        /// %OneDrive%, %OneDriveConsumer%, %OneDriveCommercial% and their
        /// short forms; nulls are skipped.
        other_homes: []const ?[]const u8 = &.{},
    };

    /// Builds the lists (deduplicated; names longest first, each also
    /// split at spaces). Strings are copied into `arena`.
    pub fn init(arena: Allocator, in: Inputs) Allocator.Error!Identity {
        var users: std.ArrayList([]const u8) = .empty;
        var homes: std.ArrayList([]const u8) = .empty;
        const named = [_]?[]const u8{ in.user_name, if (in.profile) |p| baseName(p) else null, if (in.profile_short) |p| baseName(p) else null };
        for (named) |maybe| {
            const n = std.mem.trim(u8, maybe orelse continue, " ");
            try addWord(arena, &users, n);
            var parts = std.mem.tokenizeScalar(u8, n, ' ');
            while (parts.next()) |part| try addWord(arena, &users, part);
        }
        std.mem.sort([]const u8, users.items, {}, struct {
            fn longer(_: void, a: []const u8, b: []const u8) bool {
                return a.len > b.len;
            }
        }.longer);
        for ([_]?[]const u8{ in.profile, in.profile_short }) |h| try addHome(arena, &homes, h);
        for (in.other_homes) |h| try addHome(arena, &homes, h);
        return .{ .users = users.items, .homes = homes.items };
    }

    fn addWord(arena: Allocator, list: *std.ArrayList([]const u8), w: []const u8) !void {
        if (w.len < 2) return;
        for (list.items) |have| if (wordEnd(have, 0, w)) |e| if (e == have.len) return;
        try list.append(arena, try arena.dupe(u8, w));
    }

    fn addHome(arena: Allocator, list: *std.ArrayList([]const u8), maybe: ?[]const u8) !void {
        const h = trimSeps(std.mem.trim(u8, maybe orelse return, " "));
        if (h.len <= 3) return; // a drive root is not a home
        for (list.items) |have| if (std.ascii.eqlIgnoreCase(have, h)) return;
        try list.append(arena, try arena.dupe(u8, h));
    }

    fn baseName(p: []const u8) []const u8 {
        return std.fs.path.basenameWindows(trimSeps(p));
    }
};

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
        // Glued to the text before it: only the unmistakable kinds.
        const glued = !at_boundary and gluedStart(in, i);
        if (at_boundary or glued) {
            if (root.len > 0) if (matchRoot(in, i, root)) |end| {
                try out.appendSlice(gpa, ctx.name);
                i = end;
                continue;
            };
            if (matchHome(in, i, ctx.homes)) |end| {
                try out.appendSlice(gpa, home_mark);
                i = end;
                continue;
            }
            if (absolutePath(in, i, at_boundary)) |end| {
                try out.appendSlice(gpa, path_mark);
                i = end;
                continue;
            }
        }
        if (at_boundary and loneDrive(in, i)) {
            i += 2;
            continue;
        }
        if (userAt(in, i, user, ctx.users)) |end| {
            try out.appendSlice(gpa, user_mark);
            i = end;
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

/// Whether a path that may be glued to the previous text starts at `i`:
/// a drive (`X:` and a separator, but not a URL scheme's `x://`), a device
/// prefix, `file://`, or `%VAR%` and a separator.
fn gluedStart(s: []const u8, i: usize) bool {
    if (driveAt(s, i)) |after| {
        // A drive letter ends a word of one letter at most (`-LC:\x`);
        // `Result:\n` is a word and an escape, not a drive.
        var k = i;
        while (k > 0 and std.ascii.isAlphabetic(s[k - 1])) k -= 1;
        if (i - k > 1) return false;
        // "https://": a scheme glued to its name. A real drive path is
        // never written "C://" glued to a word.
        const first = charAt(s, after).?;
        if (first.c == '/') if (charAt(s, after + first.len)) |second| if (second.c == '/') return false;
        return true;
    }
    const rest = s[i..];
    for ([_][]const u8{ "\\\\?\\", "//?/", "\\\\.\\", "//./" }) |pre| if (std.mem.startsWith(u8, rest, pre)) return true;
    if (std.ascii.startsWithIgnoreCase(rest, "file://")) return true;
    if (rest.len > 0 and rest[0] == '%') if (envPrefix(s, i)) |after| return sepRun(s, after) != null;
    return false;
}

/// `X:` and a separator at `i` (the colon and separator possibly
/// `%XX`-encoded): the position after the colon.
fn driveAt(s: []const u8, i: usize) ?usize {
    if (i >= s.len or !std.ascii.isAlphabetic(s[i])) return null;
    const colon = charAt(s, i + 1) orelse return null;
    if (colon.c != ':') return null;
    const after = i + 1 + colon.len;
    _ = sepRun(s, after) orelse return null;
    return after;
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
    return (hi << 4) | lo;
}

/// One character of `s` at `j` (itself, `%XX`-encoded, or encoded twice
/// as `%25XX`): the byte and its length.
fn charAt(s: []const u8, j: usize) ?struct { c: u8, len: usize } {
    if (j >= s.len) return null;
    if (pctAt(s, j)) |c| {
        if (c == '%' and j + 5 <= s.len) if (hexVal(s[j + 3])) |hi| if (hexVal(s[j + 4])) |lo| return .{ .c = (hi << 4) | lo, .len = 5 };
        return .{ .c = c, .len = 3 };
    }
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

/// The folder `root` at `i` in any of its spellings, ending at a
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

/// The longest home folder at `i`: its end.
fn matchHome(s: []const u8, i: usize, homes: []const []const u8) ?usize {
    var best: ?usize = null;
    for (homes) |h| {
        const home = trimSeps(h);
        if (home.len <= 3) continue;
        if (matchRoot(s, i, home)) |e| {
            if (best == null or e > best.?) best = e;
        }
    }
    return best;
}

/// Top-level Windows folders that mark `\Name\...` as a path even with
/// one component.
const windows_roots = [_][]const u8{ "users", "documents and settings", "programdata", "program files", "program files (x86)", "windows", "onedrive" };

/// URL schemes whose URLs name files or shares: removed like paths.
const file_schemes = [_][]const u8{ "file://", "smb://", "cifs://", "nfs://", "afp://" };

/// The end of the absolute path starting at `i`, or null if none starts
/// there. Without `at_boundary` (glued to the text before), only drive
/// and device paths, file URLs and `%VAR%\` count.
fn absolutePath(s: []const u8, i: usize, at_boundary: bool) ?usize {
    const rest = s[i..];
    // file:// and share URLs, whatever follows.
    for (file_schemes) |scheme| {
        if (!at_boundary and !std.mem.eql(u8, scheme, "file://")) continue;
        if (rest.len > scheme.len and std.ascii.startsWithIgnoreCase(rest, scheme)) return pathEnd(s, i, i + scheme.len, true);
    }
    // Device paths: \\?\..., \\.\...
    for ([_][]const u8{ "\\\\?\\", "//?/", "\\\\.\\", "//./" }) |pre| {
        if (std.mem.startsWith(u8, rest, pre)) return pathEnd(s, i, i + pre.len, true);
    }
    // Drive paths: C:\ c:/ C%3A%5C
    if (driveAt(s, i)) |after| return pathEnd(s, i, after, true);
    // %VAR%\x
    if (rest.len > 0 and rest[0] == '%') if (envPrefix(s, i)) |after| {
        if (sepRun(s, after) != null) return pathEnd(s, i, after, false);
    };
    if (!at_boundary) return null;
    // Drive-relative: C:Users\x (a backslash in the word after the colon).
    if (rest.len >= 4 and std.ascii.isAlphabetic(rest[0]) and rest[1] == ':' and isAlnum(rest[2])) {
        var j = i + 2;
        while (j < s.len and pathChar(s[j]) and s[j] != '\\') j += 1;
        if (j < s.len and s[j] == '\\') return pathEnd(s, i, i + 2, true);
    }
    // UNC: \\server\share, //server/share (not a URL's "scheme://"), and
    // a bare \\server.
    if (rest.len >= 2 and isSep(rest[0]) and rest[1] == rest[0] and !(i > 0 and s[i - 1] == ':')) {
        if (components(s, i + 2) >= 2) return pathEnd(s, i, i + 2, true);
        if (rest[0] == '\\' and hostAt(s, i + 2)) return pathEnd(s, i, i + 2, true);
    }
    // Root-relative Windows paths: \Users\x, \Program Files\x.
    if (rest.len >= 3 and rest[0] == '\\' and rest[1] != '\\' and !(i > 0 and isSep(s[i - 1]))) {
        if (rootRelative(s, i + 1)) return pathEnd(s, i, i + 1, true);
    }
    // POSIX: /a/b (two components at least, so "/clear" and "and/or" stay).
    if (rest.len >= 1 and rest[0] == '/' and !(i > 0 and (s[i - 1] == '/' or s[i - 1] == ':' or s[i - 1] == '\\'))) {
        if (components(s, i + 1) >= 2) return pathEnd(s, i, i + 1, false);
    }
    // ~/x, ~\x
    if (rest.len >= 3 and rest[0] == '~' and isSep(rest[1]) and components(s, i + 2) >= 1) return pathEnd(s, i, i + 2, false);
    // $VAR/x, ${VAR}/x, $env:VAR\x
    if (envPrefix(s, i)) |after| {
        if (sepRun(s, after) != null) return pathEnd(s, i, after, false);
    }
    return null;
}

/// A host name of two characters or more at `j` (a bare `\\server`; one
/// letter would be an escape such as `\\n`).
fn hostAt(s: []const u8, j0: usize) bool {
    var j = j0;
    while (j < s.len and (isAlnum(s[j]) or s[j] == '-' or s[j] == '.' or s[j] == '_')) j += 1;
    if (j - j0 < 2 or !std.ascii.isAlphanumeric(s[j0])) return false;
    return j == s.len or !pathChar(s[j]) or isSep(s[j]) or std.mem.indexOfScalar(u8, ".,;:!)]}", s[j]) != null;
}

/// After a single leading `\` at `j`: a well-known top-level folder, or a
/// capitalised first component of two or more letters followed by another
/// component (so escapes such as `\n\t`, `\nDone\n` or `\x00\x01` stay).
fn rootRelative(s: []const u8, j: usize) bool {
    for (windows_roots) |r| {
        if (j + r.len > s.len or !std.ascii.eqlIgnoreCase(s[j..][0..r.len], r)) continue;
        const e = j + r.len;
        if (e == s.len or isSep(s[e]) or !pathChar(s[e])) return true;
    }
    if (j >= s.len or !std.ascii.isUpper(s[j])) return false;
    var k = j;
    while (k < s.len and std.ascii.isAlphabetic(s[k])) k += 1;
    if (k - j < 2 or k >= s.len or !isSep(s[k])) return false;
    return components(s, k + 1) >= 1;
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
/// closing quote if it starts right after one, else over path characters
/// (and, with `spaces`, on past a space while the next word holds a
/// separator); trailing punctuation is left out.
fn pathEnd(s: []const u8, start: usize, body: usize, spaces: bool) usize {
    if (start > 0) {
        const q = s[start - 1];
        if (q == '"' or q == '\'' or q == '`') {
            var j = body;
            while (j < s.len and s[j] != q and s[j] != '\n') : (j += 1) {
                // Too long to follow: remove all of it rather than leak
                // what lies past a space.
                if (j - start >= max_quoted) return j;
            }
            if (j < s.len and s[j] == q) return j;
        }
    }
    var j = body;
    while (true) {
        while (j < s.len and pathChar(s[j])) j += 1;
        if (!spaces or j >= s.len or s[j] != ' ') break;
        var k = j;
        while (k < s.len and s[k] == ' ') k += 1;
        var e = k;
        var sep = false;
        while (e < s.len and pathChar(s[e])) : (e += 1) sep = sep or isSep(s[e]);
        if (!sep) break;
        j = e;
    }
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

/// The longest of the user's names at `i` as a whole word: its end.
fn userAt(s: []const u8, i: usize, user: []const u8, users: []const []const u8) ?usize {
    var best: ?usize = null;
    if (user.len > 0) best = wordEnd(s, i, user);
    for (users) |u| {
        if (u.len < 2) continue;
        if (wordEnd(s, i, u)) |e| {
            if (best == null or e > best.?) best = e;
        }
    }
    return best;
}

/// One code point of `s` at `j` (an invalid byte stands for itself).
fn codePoint(s: []const u8, j: usize) struct { cp: u21, len: usize } {
    const n = std.unicode.utf8ByteSequenceLength(s[j]) catch return .{ .cp = s[j], .len = 1 };
    if (j + n > s.len) return .{ .cp = s[j], .len = 1 };
    const cp = std.unicode.utf8Decode(s[j..][0..n]) catch return .{ .cp = s[j], .len = 1 };
    return .{ .cp = cp, .len = n };
}

/// Simple case folding for the scripts names are commonly written in:
/// ASCII, Latin-1, Latin Extended-A, Greek and Cyrillic.
fn fold(c: u21) u21 {
    return switch (c) {
        'A'...'Z' => c + 32,
        0xC0...0xD6, 0xD8...0xDE => c + 32,
        0x130, 0x131 => 'i', // dotted capital I, dotless i
        0x178 => 0xFF,
        0x100...0x12F, 0x132...0x137, 0x14A...0x177 => c | 1,
        0x139...0x148, 0x179...0x17E => if (c & 1 == 1) c + 1 else c,
        0x386 => 0x3AC,
        0x388...0x38A => c + 37,
        0x38C => 0x3CC,
        0x38E, 0x38F => c + 63,
        0x391...0x3A1, 0x3A3...0x3AB => c + 32,
        0x3C2 => 0x3C3, // final sigma
        0x400...0x40F => c + 80,
        0x410...0x42F => c + 32,
        0x460...0x481, 0x48A...0x4BF, 0x4D0...0x52F => c | 1,
        else => c,
    };
}

/// `word` at `i` as a whole word (case folded): its end.
fn wordEnd(s: []const u8, i: usize, word: []const u8) ?usize {
    if (i > 0 and isAlnum(s[i - 1])) return null;
    var j = i;
    var k: usize = 0;
    while (k < word.len) {
        if (j >= s.len) return null;
        const a = codePoint(s, j);
        const b = codePoint(word, k);
        if (fold(a.cp) != fold(b.cp)) return null;
        j += a.len;
        k += b.len;
    }
    if (j < s.len and isAlnum(s[j])) return null;
    return j;
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
    try check(c, "C:/Program Files/Git/bin", "[path]");
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

test "unquoted paths with spaces: home folders and drive paths" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const id = try Identity.init(arena.allocator(), .{
        .user_name = "jann",
        .profile = "C:\\Users\\Jo Ann",
        .profile_short = "C:\\Users\\JOANN~1",
        .other_homes = &.{ "C:\\Users\\Jo Ann\\OneDrive - Contoso", null },
    });
    const c: Context = .{ .root = "D:\\work\\proj", .name = "proj", .user = "jann", .users = id.users, .homes = id.homes };
    try check(c, "open C:\\Users\\Jo Ann\\Documents\\plan.txt now", "open [home]\\Documents\\plan.txt now");
    try check(c, "c:/users/jo ann/x", "[home]/x");
    try check(c, "/c/Users/Jo Ann/Desktop", "[home]/Desktop");
    try check(c, "C%3A%5CUsers%5CJo%20Ann%5Cx", "[home]%5Cx");
    try check(c, "C:\\Users\\JOANN~1\\AppData", "[home]\\AppData");
    try check(c, "C:\\Users\\Jo Ann\\OneDrive - Contoso\\Q3 report.xlsx", "[home]\\Q3 report.xlsx");
    try check(c, "C:\\Users\\Jo Ann", "[home]");
    // Without a known home: the path goes on past a space while the next
    // word holds a separator.
    const bare: Context = .{ .root = "D:\\work\\proj", .name = "proj" };
    try check(bare, "C:\\Users\\Jo Ann\\Documents\\plan.txt now", "[path] now");
    try check(bare, "C:/Program Files/Git/bin", "[path]");
    try check(bare, "run C:\\Program Files\\My App\\x.exe, then", "run [path], then");
    try check(bare, "\\\\nas\\team share\\q3\\a.txt ok", "[path] ok");
    try check(bare, "see C:\\a\\b and src/main.zig", "see [path] and src/main.zig");
}

test "glued drive paths are removed too" {
    const c: Context = .{ .root = "D:\\work\\proj", .name = "proj", .user = "alice" };
    try check(c, "-LC:\\Users\\x\\lib", "-L[path]");
    try check(c, "x_C:\\tmp\\a", "x_[path]");
    try check(c, "a.C:\\tmp\\a", "a.[path]");
    try check(c, "--out=foo-C:/Users/x", "--out=foo-[path]");
    try check(c, "-I%USERPROFILE%\\inc", "-I[path]");
    try check(c, "-ID:\\work\\proj\\inc", "-Iproj\\inc");
    try check(acme, "-IC:\\Users\\bob\\code\\acme-api\\inc", "-Iacme-api\\inc");
    // A glued URL scheme is not a drive, nor is a word's last letter
    // before an escape.
    try check(c, "see https://example.com/a/b and ftp://h/x", "see https://example.com/a/b and ftp://h/x");
    try check(c, "print(\"Result:\\n\") and ERROR:\\t", "print(\"Result:\\n\") and ERROR:\\t");
    try check(c, "-Lc:\\x", "-L[path]");
}

test "every name of the user, in any case" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const id = try Identity.init(arena.allocator(), .{
        .user_name = "jsmith",
        .profile = "C:\\Users\\John Smith",
        .profile_short = "C:\\Users\\JOHNSM~1",
    });
    try testing.expectEqual(@as(usize, 5), id.users.len); // "John Smith", "JOHNSM~1", "jsmith", "Smith", "John"
    try testing.expectEqualStrings("John Smith", id.users[0]);
    const c: Context = .{ .user = "jsmith", .users = id.users, .homes = id.homes };
    try check(c, "John Smith, JOHN and smith; JOHNSM~1 or Jsmith", "[user], [user] and [user]; [user] or [user]");
    try check(c, "Johnny Smithers", "Johnny Smithers");
    // Unicode case folding.
    const u = try Identity.init(arena.allocator(), .{ .user_name = "Øyvind", .profile = "C:\\Users\\José Ángel" });
    const cu: Context = .{ .users = u.users };
    try check(cu, "ØYVIND and øyvind", "[user] and [user]");
    try check(cu, "josé ángel, JOSÉ, Ángel", "[user], [user], [user]");
    const cy = try Identity.init(arena.allocator(), .{ .user_name = "Иван", .profile = "C:\\Users\\Σοφία" });
    try check(.{ .users = cy.users }, "ИВАН иван ΣΟΦΊΑ", "[user] [user] [user]");
    // One-letter parts are not words of their own.
    const one = try Identity.init(arena.allocator(), .{ .profile = "C:\\Users\\J Doe" });
    try check(.{ .users = one.users }, "J went home, Doe", "J went home, [user]");
}

test "more path spellings" {
    const c: Context = .{ .root = "D:\\work\\proj", .name = "proj", .user = "alice" };
    try check(c, "C:Users\\alice\\x.txt", "[path]");
    try check(c, "cd \\Users\\alice\\Desktop", "cd [path]");
    try check(c, "\\Program Files\\App\\x.exe", "[path]");
    try check(c, "\\Windows\\System32", "[path]");
    try check(c, "\\Users", "[path]");
    try check(c, "at \\\\fileserver now", "at [path] now");
    try check(c, "\\\\fileserver\\", "[path]");
    try check(c, "smb://nas/share/x and nfs://h/e", "[path] and [path]");
    try check(c, "C%253A%255CUsers%255Calice", "[path]");
    try check(c, "D%253A%255Cwork%255Cproj%255Cx", "proj%255Cx");
    // Escapes and markup stay.
    try check(c, "use \\n\\t here and \\x00\\x01", "use \\n\\t here and \\x00\\x01");
    try check(c, "print(\"\\nDone\\n\")", "print(\"\\nDone\\n\")");
    try check(c, "cd \\Projects\\acme", "cd [path]");
    try check(c, "split on \\\\n", "split on \\\\n");
}

test "a quoted path longer than 1024 bytes is removed whole" {
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(testing.allocator);
    try in.appendSlice(testing.allocator, "open \"C:\\");
    for (0..300) |_| try in.appendSlice(testing.allocator, "my dir\\");
    try in.appendSlice(testing.allocator, "x.txt\" ok");
    try check(.{}, in.items, "open \"[path]\" ok");
    // Unclosed and too long to follow: all of it goes.
    var long: std.ArrayList(u8) = .empty;
    defer long.deinit(testing.allocator);
    try long.appendSlice(testing.allocator, "\"C:\\");
    for (0..max_quoted / 4) |_| try long.appendSlice(testing.allocator, "a b ");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try scrub(testing.allocator, .{}, long.items, &out);
    try testing.expect(out.items.len < 64);
}
