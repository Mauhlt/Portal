//! What the Portal window starts with when no arguments say otherwise
//! (double-click, Start menu): %LOCALAPPDATA%\Portal\settings.txt, written
//! by the window's first-run and Settings panels.
//!
//!   # Portal settings
//!   tunnel_port = 51820
//!   tunnel_endpoint = home.example.org:51820
//!   input = keys
//!   project = acme-api
//!   program = agent --some-flag
//!   cwd = C:\code\acme-api
//!   color = acme-api #3366cc
//!   system_monitor = on
//!
//! One `key = value` per line; blank lines and lines starting with '#' are
//! ignored, so are unknown keys and values that are too long. `program` is
//! a command line (split by splitCommand). Command-line options always win
//! over the file. There is deliberately no default program: if none is
//! configured, the window asks for one. `system_monitor` (`on` / `off`,
//! default off) shows the System button and lets the system monitor
//! sample while a System panel is open (sysmon.zig).
//!
//! Speech input (the Audio panel): `speech_model` is the stt model file
//! (default: speech.defaultModel, models\ggml-base.en.bin in the data
//! directory); `mic` is `auto` (headset first, the default) or the
//! endpoint id of the microphone chosen by hand. `speech.<name> = <n>`
//! sets one of the speech limits (src/speech/limits.zig Config: rates,
//! caps, clip lengths, sizes), clamped to its range; only the desk edits
//! this file (no device can), and the Audio panel's "Reload limits"
//! applies a change without a restart.

const std = @import("std");
const Io = std.Io;
const keymap = @import("keymap.zig");
const fsutil = @import("fsutil.zig");
const tabs_wire = @import("shared").tabs;
const speech_limits = @import("speech").limits;

pub const file_name = "settings.txt";

pub const max_port_text = 5;
pub const max_endpoint = @import("shared").pairqr.max_endpoint;
pub const max_project = 64;
pub const max_program = 1024;
pub const max_cwd = 1024;
pub const max_args = 64;
pub const max_model = 1024;
pub const max_mic = 256;
/// Tab colour choices (`color = NAME #rrggbb`, one line each).
pub const max_colors = 16;

pub const ColorEntry = struct {
    name: Str(max_project) = .{},
    color: u32 = 0,
};

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
    /// The desk's WireGuard UDP port (default 51820, tunnelnet).
    tunnel_port: Str(max_port_text) = .{},
    /// Where devices reach that port ("host:port": a public IP or DNS
    /// name), put into their pairing codes. Portal cannot know it.
    tunnel_endpoint: Str(max_endpoint) = .{},
    input: ?keymap.Policy = null,
    project: Str(max_project) = .{},
    program: Str(max_program) = .{},
    cwd: Str(max_cwd) = .{},
    /// "Show system monitor" (null: not set, i.e. off).
    system_monitor: ?bool = null,
    /// "Background art": the hero art, faint, behind the window's content
    /// (null: not set, i.e. on).
    background_art: ?bool = null,
    /// The speech model file (null: the default).
    speech_model: Str(max_model) = .{},
    /// The microphone chosen by hand (an endpoint id); null: automatic.
    mic: Str(max_mic) = .{},
    /// "Learn from my voice" (null: on).
    speech_learning: ?bool = null,
    /// `speech.*` lines this Portal doesn't know (a newer one wrote them, or
    /// a typo): kept as they are and written back, never dropped.
    speech_extra: [8]Str(160) = @splat(.{}),
    n_speech_extra: usize = 0,
    /// The desk's Instruct button (null: auto).
    instruct_mode: ?@import("portal_ui").shell.InstructMode = null,
    /// The speech limits (defaults unless set; always clamped).
    speech: speech_limits.Config = .{},
    /// Tab colours overriding the one derived from the name.
    colors: [max_colors]ColorEntry = undefined,
    n_colors: usize = 0,

    /// The colour choices for tabs.Hub (names point into `s`).
    pub fn colorChoices(s: *const Settings, buf: *[max_colors]@import("tabs.zig").Hub.ColorChoice) []const @import("tabs.zig").Hub.ColorChoice {
        for (s.colors[0..s.n_colors], 0..) |*c, i| buf[i] = .{ .name = c.name.get() orelse "", .color = c.color };
        return buf[0..s.n_colors];
    }

    /// The tunnel UDP port: the saved one, else the default.
    pub fn tunnelPort(s: *const Settings) u16 {
        return parsePort(s.tunnel_port.get() orelse "") orelse @import("shared").tunnelnet.default_udp_port;
    }

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
            if (std.mem.eql(u8, key, "tunnel_port")) {
                if (parsePort(val) != null) _ = s.tunnel_port.set(val);
            } else if (std.mem.eql(u8, key, "tunnel_endpoint")) {
                _ = s.tunnel_endpoint.set(val);
            } else if (std.mem.eql(u8, key, "input")) {
                s.input = keymap.Policy.parse(val);
            } else if (std.mem.eql(u8, key, "project")) {
                _ = s.project.set(val);
            } else if (std.mem.eql(u8, key, "program")) {
                _ = s.program.set(val);
            } else if (std.mem.eql(u8, key, "cwd")) {
                _ = s.cwd.set(val);
            } else if (std.mem.eql(u8, key, "system_monitor")) {
                if (std.ascii.eqlIgnoreCase(val, "on")) s.system_monitor = true else if (std.ascii.eqlIgnoreCase(val, "off")) s.system_monitor = false;
            } else if (std.mem.eql(u8, key, "background_art")) {
                if (std.ascii.eqlIgnoreCase(val, "on")) s.background_art = true else if (std.ascii.eqlIgnoreCase(val, "off")) s.background_art = false;
            } else if (std.mem.eql(u8, key, "speech_model")) {
                _ = s.speech_model.set(val);
            } else if (std.mem.eql(u8, key, "mic")) {
                if (!std.ascii.eqlIgnoreCase(val, "auto")) _ = s.mic.set(val);
            } else if (std.mem.eql(u8, key, "instruct_mode")) {
                s.instruct_mode = @import("portal_ui").shell.InstructMode.parse(val);
            } else if (std.mem.eql(u8, key, "speech_learning")) {
                if (std.ascii.eqlIgnoreCase(val, "on")) s.speech_learning = true else if (std.ascii.eqlIgnoreCase(val, "off")) s.speech_learning = false;
            } else if (std.mem.startsWith(u8, key, "speech.")) {
                const name = key["speech.".len..];
                if (!s.speech.set(name, val) and !removedSpeechKey(name) and s.n_speech_extra < s.speech_extra.len) {
                    if (s.speech_extra[s.n_speech_extra].set(line)) s.n_speech_extra += 1;
                }
            } else if (std.mem.eql(u8, key, "color")) {
                // NAME #rrggbb: the name may contain spaces.
                const sp = std.mem.lastIndexOfScalar(u8, val, ' ') orelse continue;
                const name = std.mem.trim(u8, val[0..sp], " \t");
                const c = tabs_wire.parseColor(val[sp + 1 ..]) orelse continue;
                if (name.len == 0 or s.n_colors == max_colors) continue;
                var e: ColorEntry = .{ .color = c };
                if (!e.name.set(name)) continue;
                s.colors[s.n_colors] = e;
                s.n_colors += 1;
            }
        }
        return s;
    }

    pub fn format(s: *const Settings, out: *Io.Writer) !void {
        try out.writeAll("# Portal settings (written by the Portal window; command-line options win)\r\n");
        if (s.tunnel_port.get()) |v| try out.print("tunnel_port = {s}\r\n", .{v});
        if (s.tunnel_endpoint.get()) |v| try out.print("tunnel_endpoint = {s}\r\n", .{v});
        if (s.input) |v| try out.print("input = {t}\r\n", .{v});
        if (s.project.get()) |v| try out.print("project = {s}\r\n", .{v});
        if (s.program.get()) |v| try out.print("program = {s}\r\n", .{v});
        if (s.cwd.get()) |v| try out.print("cwd = {s}\r\n", .{v});
        if (s.system_monitor) |v| try out.print("system_monitor = {s}\r\n", .{if (v) "on" else "off"});
        if (s.background_art) |v| try out.print("background_art = {s}\r\n", .{if (v) "on" else "off"});
        if (s.speech_model.get()) |v| try out.print("speech_model = {s}\r\n", .{v});
        if (s.mic.get()) |v| try out.print("mic = {s}\r\n", .{v});
        if (s.instruct_mode) |m| try out.print("instruct_mode = {s}\r\n", .{m.text()});
        if (s.speech_learning) |v| try out.print("speech_learning = {s}\r\n", .{if (v) "on" else "off"});
        try s.speech.format(out);
        for (s.speech_extra[0..s.n_speech_extra]) |*x| if (x.get()) |l| try out.print("{s}\r\n", .{l});
        for (s.colors[0..s.n_colors]) |*c| {
            const name = c.name.get() orelse continue;
            try out.print("color = {s} {s}\r\n", .{ name, &tabs_wire.colorHex(c.color) });
        }
    }
};

/// Speech limits that existed and were removed (2026-11-14 trim): ignored
/// on load and not written back, so the next save drops them.
const removed_speech_keys = [_][]const u8{
    "transcribe_per_hour",       "feedback_per_hour",         "global_feedback_per_hour",
    "global_kept_clips_per_day", "global_bundles_per_day",    "global_bundle_mib_per_day",
    "slot_max_hold_s",           "slot_idle_s",               "slot_cooldown_s",
    "malformed_strikes",         "malformed_window_min",      "bundles_per_day",
};

fn removedSpeechKey(name: []const u8) bool {
    for (removed_speech_keys) |k| if (std.mem.eql(u8, k, name)) return true;
    return false;
}

/// A UDP port 1-65535 as typed (digits only).
pub fn parsePort(text: []const u8) ?u16 {
    if (text.len == 0 or text.len > max_port_text) return null;
    for (text) |c| if (c < '0' or c > '9') return null;
    const p = std.fmt.parseInt(u16, text, 10) catch return null;
    return if (p == 0) null else p;
}

/// Reads `<dir>\settings.txt`; a missing or unreadable file is empty settings.
pub fn load(gpa: std.mem.Allocator, io: Io, dir: []const u8) Settings {
    const path = std.fs.path.join(gpa, &.{ dir, file_name }) catch return .{};
    defer gpa.free(path);
    const text = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 * 1024)) catch return .{};
    defer gpa.free(text);
    return Settings.parse(text);
}

/// Like `load`, but null when the file exists and can't be read (so a
/// caller merging one change into it doesn't overwrite it with defaults);
/// a missing file is empty settings.
pub fn loadOrNull(gpa: std.mem.Allocator, io: Io, dir: []const u8) ?Settings {
    const path = std.fs.path.join(gpa, &.{ dir, file_name }) catch return null;
    defer gpa.free(path);
    const text = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 * 1024)) catch |err| return switch (err) {
        error.FileNotFound => .{},
        else => null,
    };
    defer gpa.free(text);
    return Settings.parse(text);
}

/// Writes `<dir>\settings.txt` atomically (a temporary file renamed over it).
pub fn save(gpa: std.mem.Allocator, io: Io, dir: []const u8, s: *const Settings) !void {
    var buf: [8192]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try s.format(&out);
    const path = try std.fs.path.join(gpa, &.{ dir, file_name });
    defer gpa.free(path);
    try Io.Dir.cwd().createDirPath(io, dir);
    fsutil.writeAtomic(gpa, io, path, out.buffered()) catch |err| return switch (err) {
        error.ReplaceFailed => error.SettingsWriteFailed,
        else => err,
    };
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
        \\tunnel_port = 51900
        \\tunnel_endpoint = home.example.org:51900
        \\listen = 10.8.0.1:8420
        \\input=instruct
        \\
        \\project =  acme api
        \\program = "C:\Program Files\tool\tool.exe" --flag
        \\cwd = C:\code\acme
        \\color = acme api #3366CC
        \\color = bad
        \\unknown = whatever
        \\no equals sign
        \\input2 = text
    ;
    const s = Settings.parse(text);
    try testing.expectEqual(@as(u16, 51900), s.tunnelPort());
    try testing.expectEqualStrings("home.example.org:51900", s.tunnel_endpoint.get().?);
    try testing.expectEqual(@as(u16, 51820), Settings.parse("tunnel_port = 0").tunnelPort());
    try testing.expectEqual(keymap.Policy.instruct, s.input.?);
    try testing.expect(Settings.parse("system_monitor = ON\r\n").system_monitor.?);
    try testing.expect(!Settings.parse("system_monitor=off").system_monitor.?);
    try testing.expect(Settings.parse("system_monitor = maybe").system_monitor == null);
    try testing.expect(Settings.parse("").system_monitor == null);
    try testing.expectEqualStrings("acme api", s.project.get().?);
    try testing.expectEqualStrings("\"C:\\Program Files\\tool\\tool.exe\" --flag", s.program.get().?);
    try testing.expectEqualStrings("C:\\code\\acme", s.cwd.get().?);
    try testing.expectEqual(@as(usize, 1), s.n_colors);
    try testing.expectEqualStrings("acme api", s.colors[0].name.get().?);
    try testing.expectEqual(@as(u32, 0x3366CC), s.colors[0].color);

    var buf: [2048]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try s.format(&out);
    const again = Settings.parse(out.buffered());
    try testing.expectEqualStrings(s.tunnel_port.get().?, again.tunnel_port.get().?);
    try testing.expectEqualStrings(s.tunnel_endpoint.get().?, again.tunnel_endpoint.get().?);
    try testing.expectEqual(s.input, again.input);
    try testing.expectEqualStrings(s.project.get().?, again.project.get().?);
    try testing.expectEqualStrings(s.program.get().?, again.program.get().?);
    try testing.expectEqualStrings(s.cwd.get().?, again.cwd.get().?);
    try testing.expectEqual(@as(u32, 0x3366CC), again.colors[0].color);
}

test "settings: speech model and microphone" {
    const s = Settings.parse("speech_model = C:\\m\\ggml-base.en.bin\r\nmic = {0.0.1.00000000}.{abc}\r\n");
    try testing.expectEqualStrings("C:\\m\\ggml-base.en.bin", s.speech_model.get().?);
    try testing.expectEqualStrings("{0.0.1.00000000}.{abc}", s.mic.get().?);
    try testing.expect(Settings.parse("mic = Auto").mic.get() == null);
    var buf: [2048]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try s.format(&out);
    const again = Settings.parse(out.buffered());
    try testing.expectEqualStrings(s.mic.get().?, again.mic.get().?);
    try testing.expectEqualStrings(s.speech_model.get().?, again.speech_model.get().?);
}

test "settings: speech_learning; unknown speech.* lines survive a save" {
    const s = Settings.parse("speech_learning = off\r\nspeech.from_the_future = 7\r\nspeech.transcribe_per_day = 9\r\n");
    try testing.expect(!s.speech_learning.?);
    var buf: [2048]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try s.format(&out);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "speech.from_the_future = 7") != null);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "speech.transcribe_per_day = 9") != null);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "speech_learning = off") != null);
    try testing.expect(Settings.parse("").speech_learning == null);
}

test "settings: removed speech limits are ignored on load and dropped on save" {
    const s = Settings.parse("speech.slot_idle_s = 90\r\nspeech.global_feedback_per_hour = 5\r\nspeech.transcribe_per_hour = 9\r\nspeech.transcribe_per_day = 70\r\n");
    try testing.expectEqual(@as(u32, 70), s.speech.transcribe_per_day);
    try testing.expectEqual(@as(usize, 0), s.n_speech_extra);
    var buf: [1024]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try s.format(&out);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "slot_idle") == null);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "per_hour") == null);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "speech.transcribe_per_day = 70") != null);
}

test "settings: instruct_mode" {
    const ui_shell = @import("portal_ui").shell;
    try testing.expectEqual(ui_shell.InstructMode.typing, Settings.parse("instruct_mode = type").instruct_mode.?);
    try testing.expectEqual(ui_shell.InstructMode.record, Settings.parse("instruct_mode=Record").instruct_mode.?);
    try testing.expect(Settings.parse("instruct_mode = sometimes").instruct_mode == null);
    var s: Settings = .{ .instruct_mode = .record };
    var buf: [512]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try s.format(&out);
    try testing.expectEqual(ui_shell.InstructMode.record, Settings.parse(out.buffered()).instruct_mode.?);
}

test "settings: speech limits load clamped and round-trip" {
    const s = Settings.parse("speech.transcribe_per_day = 50\r\nspeech.clip_max_s = 9999\r\nspeech.feedback_burst = 0\r\nspeech.bogus = 3\r\n");
    try testing.expectEqual(@as(u32, 50), s.speech.transcribe_per_day);
    try testing.expectEqual(@as(u32, 120), s.speech.clip_max_s);
    try testing.expectEqual(@as(u32, 1), s.speech.feedback_burst);
    try testing.expectEqual(@as(u32, 2000), Settings.parse("").speech.transcribe_per_day);
    var buf: [2048]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try s.format(&out);
    const again = Settings.parse(out.buffered());
    try testing.expectEqual(s.speech, again.speech);
}

test "settings: bad values are ignored, nothing defaults" {
    const empty = Settings.parse("");
    try testing.expect(empty.tunnel_port.get() == null);
    try testing.expect(empty.input == null);
    try testing.expect(empty.program.get() == null); // no default program
    const long: [max_project + 1]u8 = @splat('p');
    const s = Settings.parse("input = everything\r\ntunnel_port = 99999\r\nproject = " ++ long ++ "\r\n");
    try testing.expect(s.input == null);
    try testing.expect(s.tunnel_port.get() == null);
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
    _ = s.tunnel_port.set("9000");
    _ = s.program.set("cmd.exe /k");
    s.input = .none;
    try save(gpa, io, dir, &s);
    const l = load(gpa, io, dir);
    try testing.expectEqualStrings("9000", l.tunnel_port.get().?);
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
