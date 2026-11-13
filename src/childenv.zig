//! The environment each tab's session program starts with: Portal's own
//! (the user's environment, plus the PATH prepend for portal-show,
//! main.zig prependOwnDirToPath) minus what leaks the context Portal was
//! launched from. Started from inside an agent session, Portal
//! inherits that session's markers (CLAUDECODE, CLAUDE_CODE_ENTRYPOINT,
//! CLAUDE_CODE_CHILD_SESSION, CLAUDE_CODE_SESSION_ID, its messaging socket
//! and token...). Passed on, they make the tab's agent a "child session"
//! of it: transcript saving off, the parent's permission mode, the
//! parent's messaging channel. Portal's own variables (PORTAL_*: the
//! launcher's, the build's and the tests') are not the session's either.
//!
//! Removed (names compare case-insensitively, as Windows does):
//!   * CLAUDECODE, AI_AGENT, and every name starting with CLAUDE_ (so
//!     CLAUDE_CODE_* too): what a running agent sets for the
//!     programs it starts;
//!   * every name starting with PORTAL_.
//! Kept although they match:
//!   * The agent's documented user configuration (`user_config`):
//!     CLAUDE_CONFIG_DIR, CLAUDE_CODE_GIT_BASH_PATH, the Bedrock / Vertex /
//!     Foundry switches, CLAUDE_CODE_OAUTH_TOKEN, client certificates,
//!     shell and output settings;
//!   * any CLAUDE name the user set persistently (their own or the
//!     system's environment in the registry: HKCU\Environment,
//!     HKLM\...\Session Manager\Environment): set on purpose, not by a
//!     parent session.
//! Everything else stays, ANTHROPIC_* included (API keys, base URL, model:
//! the user's configuration; the agent does not set them for its
//! children). Windows wants the block sorted by name, case-insensitively:
//! `build` sorts it.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Agent settings a user sets on purpose, kept even though they start with CLAUDE_.
pub const user_config = [_][]const u8{
    "CLAUDE_CONFIG_DIR",
    "CLAUDE_CODE_GIT_BASH_PATH",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_SKIP_BEDROCK_AUTH",
    "CLAUDE_CODE_SKIP_VERTEX_AUTH",
    "CLAUDE_CODE_SKIP_FOUNDRY_AUTH",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_API_KEY_HELPER_TTL_MS",
    "CLAUDE_CODE_CLIENT_CERT",
    "CLAUDE_CODE_CLIENT_KEY",
    "CLAUDE_CODE_CLIENT_KEY_PASSPHRASE",
    "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
    "CLAUDE_CODE_SUBAGENT_MODEL",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    "CLAUDE_CODE_DISABLE_TERMINAL_TITLE",
    "CLAUDE_CODE_SHELL",
    "CLAUDE_CODE_SHELL_PREFIX",
    "CLAUDE_CODE_TMPDIR",
    "CLAUDE_CODE_IDE_SKIP_AUTO_INSTALL",
};

/// Exact names (besides the prefixes) a parent agent session sets.
const markers = [_][]const u8{ "CLAUDECODE", "AI_AGENT" };

/// What to do with variable `name` (WTF-16, without `=value`).
pub const Verdict = enum {
    keep,
    /// Portal's own: always removed.
    drop,
    /// A launcher-context name: removed unless the user set it
    /// persistently (`build`'s `persistent` check).
    drop_unless_persistent,
};

fn upper(c: u16) u16 {
    return if (c >= 'a' and c <= 'z') c - 32 else c;
}

fn eqlAscii(name: []const u16, s: []const u8) bool {
    if (name.len != s.len) return false;
    for (name, s) |a, b| if (upper(a) != b) return false;
    return true;
}

fn startsAscii(name: []const u16, prefix: []const u8) bool {
    return name.len >= prefix.len and eqlAscii(name[0..prefix.len], prefix);
}

/// The filter, pure: see the file comment.
pub fn verdict(name: []const u16) Verdict {
    if (startsAscii(name, "PORTAL_")) return .drop;
    for (user_config) |k| if (eqlAscii(name, k)) return .keep;
    for (markers) |k| if (eqlAscii(name, k)) return .drop_unless_persistent;
    if (startsAscii(name, "CLAUDE_")) return .drop_unless_persistent;
    return .keep;
}

/// The name part of a block entry `NAME=value`. Entries for the per-drive
/// current directories start with '=' (`=C:=C:\x`): the name includes it.
pub fn entryName(entry: []const u16) []const u16 {
    const from: usize = if (entry.len > 0 and entry[0] == '=') 1 else 0;
    const eq = std.mem.indexOfScalarPos(u16, entry, from, '=') orelse entry.len;
    return entry[0..eq];
}

/// Windows' order for an environment block: by name, case-insensitively
/// (upper-cased code units; non-ASCII names, which Windows upper-cases
/// with its own table, are compared as they are).
pub fn nameLess(_: void, a: []const u16, b: []const u16) bool {
    const na = entryName(a);
    const nb = entryName(b);
    const n = @min(na.len, nb.len);
    for (na[0..n], nb[0..n]) |x, y| {
        const ux = upper(x);
        const uy = upper(y);
        if (ux != uy) return ux < uy;
    }
    return na.len < nb.len;
}

/// Asks whether the user set variable `name` persistently.
pub const Persistent = struct {
    ctx: ?*anyopaque = null,
    f: *const fn (ctx: ?*anyopaque, name: []const u16) bool,

    pub const never: Persistent = .{ .f = struct {
        fn f(_: ?*anyopaque, _: []const u16) bool {
            return false;
        }
    }.f };
};

/// The filtered, sorted copy of `source` (a block: `NAME=value` entries,
/// each NUL-terminated, then one more NUL), as a block for CreateProcessW
/// with CREATE_UNICODE_ENVIRONMENT. Caller frees.
pub fn build(gpa: Allocator, source: [*:0]const u16, persistent: Persistent) Allocator.Error![:0]u16 {
    var entries: std.ArrayList([]const u16) = .empty;
    defer entries.deinit(gpa);
    var i: usize = 0;
    var total: usize = 0;
    while (source[i] != 0) {
        const entry = std.mem.sliceTo(source[i..], 0);
        i += entry.len + 1;
        const keep = switch (verdict(entryName(entry))) {
            .keep => true,
            .drop => false,
            .drop_unless_persistent => persistent.f(persistent.ctx, entryName(entry)),
        };
        if (!keep) continue;
        try entries.append(gpa, entry);
        total += entry.len + 1;
    }
    std.mem.sort([]const u16, entries.items, {}, nameLess);
    // An empty block still needs two NULs.
    const out = try gpa.allocSentinel(u16, @max(total, 1), 0);
    var o: usize = 0;
    for (entries.items) |e| {
        @memcpy(out[o..][0..e.len], e);
        o += e.len;
        out[o] = 0;
        o += 1;
    }
    if (total == 0) out[0] = 0;
    return out;
}

// ------------------------------------------------------------ the process

const HKEY = *opaque {};
const HKEY_CURRENT_USER: HKEY = @ptrFromInt(0x80000001);
const HKEY_LOCAL_MACHINE: HKEY = @ptrFromInt(0x80000002);
const RRF_RT_ANY: u32 = 0x0000ffff;
const RRF_NOEXPAND: u32 = 0x10000000;
extern "advapi32" fn RegGetValueW(key: HKEY, sub: ?[*:0]const u16, value: ?[*:0]const u16, flags: u32, kind: ?*u32, data: ?*anyopaque, len: ?*u32) callconv(.winapi) i32;
extern "kernel32" fn GetEnvironmentStringsW() callconv(.winapi) ?[*:0]u16;
extern "kernel32" fn FreeEnvironmentStringsW(block: [*:0]u16) callconv(.winapi) c_int;

const user_env = std.unicode.utf8ToUtf16LeStringLiteral("Environment");
const system_env = std.unicode.utf8ToUtf16LeStringLiteral("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment");

/// The variable is in the user's or the system's persistent environment.
fn inRegistry(_: ?*anyopaque, name: []const u16) bool {
    var buf: [256:0]u16 = undefined;
    if (name.len == 0 or name.len >= buf.len) return false;
    @memcpy(buf[0..name.len], name);
    buf[name.len] = 0;
    const flags = RRF_RT_ANY | RRF_NOEXPAND;
    if (RegGetValueW(HKEY_CURRENT_USER, user_env, &buf, flags, null, null, null) == 0) return true;
    return RegGetValueW(HKEY_LOCAL_MACHINE, system_env, &buf, flags, null, null, null) == 0;
}

/// The block for a session program, from this process's environment as it
/// is now (with Portal's own changes, such as the PATH prepend). Caller
/// frees.
pub fn forSession(gpa: Allocator) error{ OutOfMemory, NoEnvironment }![:0]u16 {
    const src = GetEnvironmentStringsW() orelse return error.NoEnvironment;
    defer _ = FreeEnvironmentStringsW(src);
    return build(gpa, src, .{ .f = inRegistry });
}

// ------------------------------------------------------------------ tests

const testing = std.testing;
const L = std.unicode.utf8ToUtf16LeStringLiteral;

test "verdict: launcher markers and Portal's own go, user configuration stays" {
    @setEvalBranchQuota(1_000_000);
    for ([_][]const u16{
        L("CLAUDECODE"),             L("CLAUDE_X"),       L("CLAUDE_CODE_CHILD_SESSION"),
        L("CLAUDE_X"), L("CLAUDE_X"),         L("CLAUDE_X"),
        L("CLAUDE_X"),   L("CLAUDE_X"), L("CLAUDE_X"),
        L("CLAUDE_X"),          L("CLAUDE_X"),           L("CLAUDE_X"),
        L("AI_AGENT"),               L("claudecode"),                   L("Claude_Code_Child_Session"),
    }) |n| try testing.expectEqual(Verdict.drop_unless_persistent, verdict(n));
    for ([_][]const u16{ L("PORTAL_VIA_LAUNCHER"), L("PORTAL_AGENT_PROJECTS"), L("PORTAL_TESTING"), L("portal_releases_dir") }) |n|
        try testing.expectEqual(Verdict.drop, verdict(n));
    for ([_][]const u16{
        L("PATH"),              L("Path"),                      L("SystemRoot"),              L("USERPROFILE"),
        L("ANTHROPIC_X"), L("ANTHROPIC_X"),        L("ANTHROPIC_X"),         L("CLAUDE_CONFIG_DIR"),
        L("claude_config_dir"), L("CLAUDE_CODE_GIT_BASH_PATH"), L("CLAUDE_CODE_USE_BEDROCK"), L("CLAUDE_CODE_OAUTH_TOKEN"),
        L("CLAUDE"),            L("CLAUDEX"),                   L("PORTAL"),                  L("=C:"),
        L("AI_AGENTS"),         L(""),
    }) |n| try testing.expectEqual(Verdict.keep, verdict(n));
}

fn block(comptime entries: []const []const u8) [*:0]const u16 {
    @setEvalBranchQuota(1_000_000);
    comptime var s: []const u8 = "";
    inline for (entries) |e| s = s ++ e ++ "\x00";
    return L(s ++ "");
}

fn expectBlock(want: []const []const u8, got: [:0]const u16) !void {
    var i: usize = 0;
    for (want) |w| {
        const e = std.mem.sliceTo(got[i..], 0);
        var buf: [256]u8 = undefined;
        const n = std.unicode.wtf16LeToWtf8(&buf, e);
        try testing.expectEqualStrings(w, buf[0..n]);
        i += e.len + 1;
    }
    try testing.expectEqual(@as(u16, 0), got[i]);
    try testing.expectEqual(i, got.len);
}

test "build: filtered and sorted case-insensitively; persistent CLAUDE names kept" {
    @setEvalBranchQuota(1_000_000);
    const src = block(&.{
        "windir=C:\\Windows",
        "Path=C:\\portal;C:\\bin",
        "=C:=C:\\work",
        "CLAUDE_CODE_CHILD_SESSION=1",
        "ANTHROPIC_X=sk-x",
        "CLAUDECODE=1",
        "PORTAL_AGENT_PROJECTS=C:\\t",
        "CLAUDE_CONFIG_DIR=C:\\c",
        "apple=1",
        "CLAUDE_CODE_USE_VERTEX=1",
        "CLAUDE_MY_SETTING=persisted",
        "AI_AGENT=x",
        "SystemRoot=C:\\Windows",
        "PORTAL_VIA_LAUNCHER=1",
        "Zeta=z",
        "_under=1",
    });
    const Reg = struct {
        fn f(_: ?*anyopaque, name: []const u16) bool {
            return std.mem.eql(u16, name, L("CLAUDE_MY_SETTING"));
        }
    };
    const got = try build(testing.allocator, src, .{ .f = Reg.f });
    defer testing.allocator.free(got);
    try expectBlock(&.{
        "=C:=C:\\work",
        "ANTHROPIC_X=sk-x",
        "apple=1",
        "CLAUDE_CODE_USE_VERTEX=1",
        "CLAUDE_CONFIG_DIR=C:\\c",
        "CLAUDE_MY_SETTING=persisted",
        "Path=C:\\portal;C:\\bin",
        "SystemRoot=C:\\Windows",
        "windir=C:\\Windows",
        "Zeta=z",
        "_under=1",
    }, got);
    // Nothing persistent: the CLAUDE marker goes too.
    const none = try build(testing.allocator, src, .never);
    defer testing.allocator.free(none);
    var it = std.mem.splitScalar(u16, none, 0);
    while (it.next()) |e| try testing.expect(!std.mem.startsWith(u16, e, L("CLAUDE_MY")));
}

test "build: an empty result is still a valid block" {
    @setEvalBranchQuota(1_000_000);
    const got = try build(testing.allocator, block(&.{ "CLAUDECODE=1", "PORTAL_X=1" }), .never);
    defer testing.allocator.free(got);
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqual(@as(u16, 0), got[0]);
    try testing.expectEqual(@as(u16, 0), got[1]); // the sentinel: two NULs
}

test "forSession: this process's environment, markers removed, PATH kept" {
    @setEvalBranchQuota(1_000_000);
    const name = L("CLAUDE_CODE_CHILD_SESSION");
    const w = @import("win32.zig");
    var old: [64]u16 = undefined;
    const had = w.GetEnvironmentVariableW(name, &old, old.len);
    _ = w.SetEnvironmentVariableW(name, L("1"));
    _ = w.SetEnvironmentVariableW(L("PORTAL_CHILDENV_TEST"), L("1"));
    defer {
        _ = w.SetEnvironmentVariableW(name, if (had > 0 and had < old.len) blk: {
            old[had] = 0;
            break :blk old[0..had :0].ptr;
        } else null);
        _ = w.SetEnvironmentVariableW(L("PORTAL_CHILDENV_TEST"), null);
    }
    const got = try forSession(testing.allocator);
    defer testing.allocator.free(got);
    var path = false;
    var prev: ?[]const u16 = null;
    var it = std.mem.splitScalar(u16, got, 0);
    while (it.next()) |e| {
        if (e.len == 0) break;
        const n = entryName(e);
        try testing.expect(!eqlAscii(n, "CLAUDE_CODE_CHILD_SESSION") or inRegistry(null, n));
        try testing.expect(!eqlAscii(n, "PORTAL_CHILDENV_TEST"));
        if (eqlAscii(n, "PATH")) path = true;
        if (prev) |p| try testing.expect(!nameLess({}, e, p));
        prev = e;
    }
    try testing.expect(path);
}
