//! The admin-prompt guard's patterns (docs/tabs-design.md, "The
//! admin-prompt guard"): does a shell command the agent is about to run
//! (its Bash or PowerShell tool, PreToolUse) ask Windows for elevation, so
//! that an administrator prompt (UAC) would open on the desk? Pure: one
//! table, no allocation, no regular expressions; the hook process
//! (`portalctl hook`, hookpipe.zig) checks it, the desk never sees the
//! command.
//!
//! Deliberately broad: a false alarm costs a "needs desk" card (or, for a
//! session a device started, a denied command the agent is told it can
//! only run at the desk); a miss leaves a prompt nobody at the phone can
//! answer. It is a guard against a stuck session, not a sandbox: a command
//! built to hide its intent is not its business.
//!
//! Matching is ASCII case-insensitive. A `word` matches between word
//! boundaries (anything but a letter, digit or `_`; so `-Verb RunAs`,
//! `runas.exe` and `"sudo"` match, `gsudo` is not `sudo`, `runassist` is
//! not `runas`). A `write_under` rule needs both a mention of the place
//! (any of its spellings) and a write anywhere in the command: a write
//! verb (`write_verbs`; `reg add` etc., not `reg query`) or an output
//! redirection (`>`, `>>`, not `>&` or into `$null` / `nul`).

const std = @import("std");

pub const Place = enum { program_files, hklm };

pub const Pattern = union(enum) {
    /// The word itself.
    word: []const u8,
    /// A file name ending in this extension (`setup.msi`).
    extension: []const u8,
    /// An `.exe` whose name holds `setup` or `install` (`Setup.exe`,
    /// `vs_installer.exe`, `node-x64-setup.exe`, `uninstall.exe`).
    installer_exe,
    /// A write into the place.
    write_under: Place,
    /// The tool's word, then (anywhere after it) one of its subcommands
    /// as a word: `winget install`, `choco upgrade`.
    subcommand: struct { tool: []const u8, subs: []const []const u8 },
    /// `-Verb` whose value, without quotes, `+`, parentheses, backticks
    /// and spaces, spells RunAs: `-Verb ('Run'+'As')`.
    verb_runas,
};

pub const Rule = struct {
    /// What it is, for the log and the agent's reason (never the command).
    what: []const u8,
    pattern: Pattern,
};

/// The table.
pub const rules = [_]Rule{
    .{ .what = "runs a command as administrator (runas, -Verb RunAs)", .pattern = .{ .word = "runas" } },
    .{ .what = "uses sudo", .pattern = .{ .word = "sudo" } },
    .{ .what = "uses gsudo", .pattern = .{ .word = "gsudo" } },
    .{ .what = "runs Windows Installer (msiexec)", .pattern = .{ .word = "msiexec" } },
    .{ .what = "runs an installer package (.msi)", .pattern = .{ .extension = ".msi" } },
    .{ .what = "runs an installer patch (.msp)", .pattern = .{ .extension = ".msp" } },
    .{ .what = "runs an installer program", .pattern = .installer_exe },
    .{ .what = "runs a command as administrator (runas, -Verb RunAs)", .pattern = .verb_runas },
    .{ .what = "installs, upgrades or removes software with winget", .pattern = .{ .subcommand = .{ .tool = "winget", .subs = &.{ "install", "upgrade", "uninstall", "add", "update", "remove", "rm" } } } },
    .{ .what = "installs, upgrades or removes software with Chocolatey", .pattern = .{ .subcommand = .{ .tool = "choco", .subs = &.{ "install", "upgrade", "uninstall", "update" } } } },
    .{ .what = "adds or removes a Windows capability", .pattern = .{ .word = "add-windowscapability" } },
    .{ .what = "adds or removes a Windows capability", .pattern = .{ .word = "remove-windowscapability" } },
    .{ .what = "turns a Windows optional feature on or off", .pattern = .{ .word = "enable-windowsoptionalfeature" } },
    .{ .what = "turns a Windows optional feature on or off", .pattern = .{ .word = "disable-windowsoptionalfeature" } },
    .{ .what = "services the Windows image (dism)", .pattern = .{ .word = "dism" } },
    .{ .what = "changes the boot configuration (bcdedit)", .pattern = .{ .word = "bcdedit" } },
    .{ .what = "changes the PowerShell execution policy", .pattern = .{ .word = "set-executionpolicy" } },
    .{ .what = "writes under Program Files", .pattern = .{ .write_under = .program_files } },
    .{ .what = "writes to HKEY_LOCAL_MACHINE", .pattern = .{ .write_under = .hklm } },
};

/// The spellings of each place.
fn spellings(p: Place) []const []const u8 {
    return switch (p) {
        .program_files => &.{ "program files", "programfiles", "programw6432", "progra~1", "progra~2" },
        .hklm => &.{ "hklm:", "hklm\\", "hklm/", "hkey_local_machine" },
    };
}

/// Words that write files or registry keys (cmd, PowerShell, coreutils).
pub const write_verbs = [_][]const u8{
    "copy",          "cp",               "xcopy",                "robocopy",           "move",
    "mv",            "del",              "erase",                "rm",                 "rmdir",
    "rd",            "mkdir",            "md",                   "ren",                "rename",
    "new-item",      "ni",               "set-content",          "sc",                 "add-content",
    "ac",            "out-file",         "copy-item",            "cpi",                "move-item",
    "mi",            "remove-item",      "ri",                   "rename-item",        "rni",
    "set-item",      "si",               "set-itemproperty",     "sp",                 "new-itemproperty",
    "remove-itemproperty", "rp",         "clear-item",           "clear-itemproperty", "expand-archive",
    "tee",           "tee-object",       "install",              "icacls",             "takeown",
    "regedit",       "reg add",          "reg delete",           "reg import",         "reg copy",
    "reg restore",   "reg load",         "new-service",          "set-service",
};

pub const Match = struct { rule: *const Rule };

/// The first rule `cmd` matches, or null.
pub fn check(cmd: []const u8) ?Match {
    for (&rules) |*r| if (matches(r.pattern, cmd)) return .{ .rule = r };
    return null;
}

fn matches(p: Pattern, cmd: []const u8) bool {
    return switch (p) {
        .word => |w| hasWord(cmd, w),
        .extension => |e| hasExtension(cmd, e),
        .installer_exe => hasInstallerExe(cmd),
        .write_under => |place| blk: {
            var named = false;
            for (spellings(place)) |s| named = named or std.ascii.findIgnoreCase(cmd, s) != null;
            break :blk named and writes(cmd);
        },
        .subcommand => |sc| blk: {
            var from: usize = 0;
            while (wordAt(cmd, sc.tool, from)) |i| {
                from = i + sc.tool.len;
                for (sc.subs) |sub| if (wordAt(cmd, sub, from) != null) break :blk true;
            }
            break :blk false;
        },
        .verb_runas => hasVerbRunAs(cmd),
    };
}

/// `-Verb` followed by a value that spells RunAs once quotes, `+`,
/// parentheses, backticks, colons and spaces are left out.
fn hasVerbRunAs(s: []const u8) bool {
    var from: usize = 0;
    while (from < s.len) {
        const i = from + (std.ascii.findIgnoreCase(s[from..], "-verb") orelse return false);
        from = i + 1;
        var j = i + "-verb".len;
        if (j < s.len and wordChar(s[j])) continue;
        var got: [5]u8 = undefined;
        var n: usize = 0;
        while (j < s.len and n < got.len) : (j += 1) {
            const c = s[j];
            if (std.ascii.isAlphabetic(c)) {
                got[n] = std.ascii.toLower(c);
                n += 1;
            } else if (std.mem.indexOfScalar(u8, " \t'\"+()`:", c) == null) break;
        }
        if (n == got.len and std.mem.eql(u8, &got, "runas")) return true;
    }
    return false;
}

fn wordChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

/// `w` occurs in `s` between word boundaries (`-` counts as one, so
/// `-Verb RunAs` matches; but a hyphenated word like `new-item` is matched
/// whole).
pub fn hasWord(s: []const u8, w: []const u8) bool {
    return wordAt(s, w, 0) != null;
}

/// Where `w` first occurs as a word (hasWord) at or after `start`.
fn wordAt(s: []const u8, w: []const u8, start: usize) ?usize {
    var from = start;
    while (from + w.len <= s.len) {
        const i = from + (std.ascii.findIgnoreCase(s[from..], w) orelse return null);
        const before_ok = i == 0 or !(wordChar(s[i - 1]) or (s[i - 1] == '-' and i >= 2 and wordChar(s[i - 2])));
        const end = i + w.len;
        const after_ok = end == s.len or !(wordChar(s[end]) or (s[end] == '-' and end + 1 < s.len and wordChar(s[end + 1])));
        if (before_ok and after_ok) return i;
        from = i + 1;
    }
    return null;
}

/// A file name (letters before it) ending in `ext`, then a boundary.
fn hasExtension(s: []const u8, ext: []const u8) bool {
    var from: usize = 0;
    while (from + ext.len <= s.len) {
        const i = from + (std.ascii.findIgnoreCase(s[from..], ext) orelse return false);
        const end = i + ext.len;
        if (i > 0 and (wordChar(s[i - 1]) or s[i - 1] == '-') and (end == s.len or !wordChar(s[end]))) return true;
        from = i + 1;
    }
    return false;
}

fn hasInstallerExe(s: []const u8) bool {
    var from: usize = 0;
    while (from + 4 <= s.len) {
        const i = from + (std.ascii.findIgnoreCase(s[from..], ".exe") orelse return false);
        from = i + 1;
        const end = i + 4;
        if (end < s.len and wordChar(s[end])) continue;
        // The file name before it.
        var b = i;
        while (b > 0 and (wordChar(s[b - 1]) or s[b - 1] == '-' or s[b - 1] == '.')) b -= 1;
        const stem = s[b..i];
        if (std.ascii.findIgnoreCase(stem, "setup") != null or std.ascii.findIgnoreCase(stem, "install") != null) return true;
    }
    return false;
}

/// A write verb, or an output redirection that goes somewhere.
fn writes(s: []const u8) bool {
    for (write_verbs) |v| if (hasWord(s, v)) return true;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] != '>') continue;
        var j = i + 1;
        if (j < s.len and s[j] == '>') j += 1;
        if (j < s.len and s[j] == '&') {
            i = j;
            continue;
        }
        while (j < s.len and s[j] == ' ') j += 1;
        const rest = s[j..];
        const sink = std.ascii.startsWithIgnoreCase(rest, "$null") or
            (std.ascii.startsWithIgnoreCase(rest, "nul") and (rest.len == 3 or !wordChar(rest[3])));
        if (!sink) return true;
        i = j;
    }
    return false;
}

/// The reason the hook gives the agent when it denies a command
/// (PreToolUse `permissionDecisionReason`): fixed text and the rule's
/// `what`, never the command.
pub fn denyReason(m: Match, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "Portal blocked this command because it {s}, which opens an administrator prompt on the desktop. This session was started from a paired device, so nobody is at the desktop to answer it: commands that need elevation can only run at the desk. Tell the user what you wanted to run and why, and continue without it.", .{m.rule.what}) catch
        "Portal blocked this command because it needs elevation (an administrator prompt on the desktop). It can only run at the desk.";
}

/// The reason when the desk's `block_elevation_desk = on` denies it in a
/// session started at the desk.
pub fn deskDenyReason(m: Match, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "Portal blocked this command because it {s}, which opens an administrator prompt, and the desk's setting block_elevation_desk is on. Ask the user to run it at the desk themselves, and continue without it.", .{m.rule.what}) catch
        "Portal blocked this command because it needs elevation, and the desk blocks that. Ask the user to run it at the desk.";
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn what(cmd: []const u8) ?[]const u8 {
    return if (check(cmd)) |m| m.rule.what else null;
}

test "elevation: each rule, and what is not elevation" {
    const hits = [_]struct { cmd: []const u8, rule: []const u8 }{
        .{ .cmd = "Start-Process pwsh -Verb RunAs -ArgumentList '-c x'", .rule = "runas" },
        .{ .cmd = "start-process cmd -verb runas", .rule = "runas" },
        .{ .cmd = "runas /user:Administrator \"cmd /c x\"", .rule = "runas" },
        .{ .cmd = "C:\\Windows\\System32\\runas.exe /savecred x", .rule = "runas" },
        .{ .cmd = "sudo apt install x", .rule = "sudo" },
        .{ .cmd = "echo y | \"sudo\" make install", .rule = "sudo" },
        .{ .cmd = "gsudo choco install git", .rule = "gsudo" },
        .{ .cmd = "msiexec /i x.msi /qn", .rule = "msiexec" },
        .{ .cmd = "MSIEXEC.EXE /x {GUID}", .rule = "msiexec" },
        .{ .cmd = "& .\\build\\Portal-1.2.msi", .rule = ".msi" },
        .{ .cmd = "Start-Process fix.msp", .rule = ".msp" },
        .{ .cmd = ".\\Setup.exe /quiet", .rule = "installer" },
        .{ .cmd = "vs_installer.exe modify", .rule = "installer" },
        .{ .cmd = "node-v22-x64-setup.exe", .rule = "installer" },
        .{ .cmd = "& \"$env:TEMP\\uninstall.exe\"", .rule = "installer" },
        .{ .cmd = "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine", .rule = "execution policy" },
        .{ .cmd = "Copy-Item x.dll 'C:\\Program Files\\App\\'", .rule = "Program Files" },
        .{ .cmd = "cp x \"/c/Program Files/App/\"", .rule = "Program Files" },
        .{ .cmd = "New-Item -ItemType Directory \"$env:ProgramFiles\\Portal\"", .rule = "Program Files" },
        .{ .cmd = "echo x > \"%ProgramFiles%\\a.txt\"", .rule = "Program Files" },
        .{ .cmd = "Set-ItemProperty -Path HKLM:\\SOFTWARE\\X -Name A -Value 1", .rule = "HKEY_LOCAL_MACHINE" },
        .{ .cmd = "reg add HKLM\\Software\\X /v A /d 1 /f", .rule = "HKEY_LOCAL_MACHINE" },
        .{ .cmd = "reg import x.reg HKEY_LOCAL_MACHINE", .rule = "HKEY_LOCAL_MACHINE" },
        .{ .cmd = "winget install --id Git.Git -e", .rule = "winget" },
        .{ .cmd = "WinGet.exe upgrade --all", .rule = "winget" },
        .{ .cmd = "winget uninstall Foo", .rule = "winget" },
        .{ .cmd = "choco install nodejs -y", .rule = "Chocolatey" },
        .{ .cmd = "choco upgrade all", .rule = "Chocolatey" },
        .{ .cmd = "choco.exe uninstall x", .rule = "Chocolatey" },
        .{ .cmd = "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0", .rule = "capability" },
        .{ .cmd = "Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform", .rule = "optional feature" },
        .{ .cmd = "dism /online /enable-feature /featurename:x", .rule = "dism" },
        .{ .cmd = "DISM.exe /Online /Cleanup-Image", .rule = "dism" },
        .{ .cmd = "bcdedit /set testsigning on", .rule = "bcdedit" },
        .{ .cmd = "Start-Process pwsh -Verb ('Run'+'As')", .rule = "runas" },
        .{ .cmd = "start-process cmd -verb \"Ru\"+\"nAs\"", .rule = "runas" },
        .{ .cmd = "Start-Process x -Verb:`RunAs", .rule = "runas" },
    };
    for (hits) |h| {
        const got = what(h.cmd) orelse {
            std.debug.print("not caught: {s}\n", .{h.cmd});
            return error.TestUnexpectedResult;
        };
        if (std.ascii.findIgnoreCase(got, h.rule) == null) {
            std.debug.print("{s}: {s}\n", .{ h.cmd, got });
            return error.TestUnexpectedResult;
        }
    }
    const misses = [_][]const u8{
        "zig build test",
        "git status",
        "dir \"C:\\Program Files\"",
        "Get-ChildItem 'C:\\Program Files\\Git'",
        "Get-ItemProperty HKLM:\\SOFTWARE\\X",
        "Get-ItemProperty HKLM:\\SOFTWARE\\X 2>$null",
        "reg query HKLM\\Software\\X 2>&1",
        "Get-ExecutionPolicy",
        "echo runassist",
        "pseudocode --sudoku",
        "zig build -Dmsi=false",
        "cat notes.msix.txt",
        "setup-env.ps1",
        "python install_deps.py",
        "./configure && make",
        "Copy-Item a b",
        "echo hi > out.txt",
        "winget search git",
        "winget list",
        "choco list --local-only",
        "echo dismiss",
        "Start-Process notepad -Verb Open",
        "Start-Process x -Verbose",
    };
    for (misses) |cmd| if (what(cmd)) |got| {
        std.debug.print("false alarm: {s}: {s}\n", .{ cmd, got });
        return error.TestUnexpectedResult;
    };
}

test "elevation: the reasons never hold the command" {
    var buf: [600]u8 = undefined;
    const m = check("gsudo rm -rf C:\\secret-dir").?;
    const r = denyReason(m, &buf);
    try testing.expect(std.mem.indexOf(u8, r, "secret") == null);
    try testing.expect(std.mem.indexOf(u8, r, "only run at the desk") != null);
    try testing.expect(std.mem.indexOf(u8, deskDenyReason(m, &buf), "secret") == null);
}
