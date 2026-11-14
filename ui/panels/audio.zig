//! The Audio panel (docs/audio-design.md, "App UI"): the microphones with
//! their type, the Automatic toggle (headset first), a live input-level
//! meter (only while this panel is open: the glue captures for it exactly
//! then), "Test" (record 3 s, show the transcription) and the speech
//! model's path. A state machine with no drawing and no I/O, like the desk
//! panels: the glue feeds it the microphone thread's snapshot (`View`),
//! performs the `Action`s it returns and draws `panel()`.

const std = @import("std");
const frame = @import("../frame.zig");
const form = @import("../form.zig");
const input = @import("../input.zig");
const InstructMode = @import("../shell.zig").InstructMode;

/// Ids (clear of the other panels' and the shell's ranges).
pub const id = struct {
    pub const close: u32 = 1700;
    pub const test_clip: u32 = 1701;
    pub const save: u32 = 1702;
    pub const reload: u32 = 1703;
    /// field0 + index: Automatic (0), speech model (1), Instruct (2),
    /// Learn from my voice (3).
    pub const field0: u32 = 1710;
    /// dev0 + row: "Use" this microphone.
    pub const dev0: u32 = 1720;
};

pub const max_rows = 16;
pub const max_model = 1024;
/// How long Test records.
pub const test_ms: i64 = 3000;

pub const Action = union(enum) {
    none,
    /// The panel closed (the glue stops the meter).
    closed,
    /// Automatic on (true) or off: off pins the active microphone.
    set_auto: bool,
    /// "Learn from my voice" on / off (applies at once, saved).
    set_learning: bool,
    /// What the Instruct button does now (applies at once, saved).
    set_instruct_mode: InstructMode,
    /// Use row i's microphone (manual mode).
    use: usize,
    /// Record test_ms, then transcribe (the glue calls testRecorded /
    /// testResult as that progresses).
    test_clip,
    /// Save `model.text()` as the speech model.
    save_model,
    /// Read the clipboard and call `paste`.
    paste,
    /// Read the speech limits from the settings again and apply them.
    reload_limits,
};

/// One microphone as the panel lists it.
pub const Row = struct {
    name: []const u8,
    /// "Headset · USB".
    kind: []const u8,
    active: bool = false,
    default: bool = false,
};

/// What the glue knows this frame.
pub const View = struct {
    rows: []const Row = &.{},
    automatic: bool = true,
    /// Manual, but that microphone is gone: Automatic chose.
    fell_back: bool = false,
    /// 0..10 bars (the meter).
    level: u8 = 0,
    capturing: bool = false,
    /// Speech engine: "" ready, else its state ("Loading the speech
    /// model…", or why it can't run).
    speech: []const u8 = "",
    speech_bad: bool = false,
    /// The microphone thread's last error ("" none).
    mic_error: []const u8 = "",
};

pub const TestState = enum { idle, recording, transcribing, done, failed };

pub const Ui = struct {
    open_: bool = false,
    focus: form.Focus = .{},
    auto: bool = true,
    model: form.TextField(max_model) = .{},
    instruct_mode: InstructMode = .auto,
    /// "Learn from my voice" (default on).
    learning: bool = true,
    test_state: TestState = .idle,
    test_buf: [600]u8 = undefined,
    test_len: usize = 0,
    note_buf: [200]u8 = undefined,
    note_len: usize = 0,
    note_tone: frame.Tone = .muted,
    n_rows: u8 = 0,

    pub const Bufs = struct {
        rows: [max_rows]frame.PanelRow = undefined,
        row_text: [max_rows][200]u8 = undefined,
        lines: [4]frame.PanelText = undefined,
        line_text: [3][240]u8 = undefined,
        fields: [4]frame.PanelField = undefined,
        after: [1]frame.PanelText = undefined,
        buttons: [4]frame.PanelButton = undefined,
    };

    pub fn open(ui: *const Ui) bool {
        return ui.open_;
    }

    /// Opens the panel with the saved mode and model path.
    pub fn show(ui: *Ui, automatic: bool, model_path: []const u8, mode: InstructMode) void {
        ui.open_ = true;
        ui.auto = automatic;
        ui.instruct_mode = mode;
        ui.model.set(model_path);
        ui.note_len = 0;
        if (ui.test_state != .recording and ui.test_state != .transcribing) {
            ui.test_state = .idle;
            ui.test_len = 0;
        }
        ui.focus.reset(ui.focusCount(), 0);
    }

    pub fn close(ui: *Ui) Action {
        if (!ui.open_) return .none;
        ui.open_ = false;
        return .closed;
    }

    pub fn setNote(ui: *Ui, tone: frame.Tone, comptime fmt: []const u8, args: anytype) void {
        const s = std.fmt.bufPrint(&ui.note_buf, fmt, args) catch ui.note_buf[0..0];
        ui.note_len = s.len;
        ui.note_tone = tone;
    }

    // ------------------------------------------------------- test progress

    /// The 3 s are recorded; transcription runs.
    pub fn testRecorded(ui: *Ui) void {
        ui.test_state = .transcribing;
    }

    /// The test's transcript (or why it failed).
    pub fn testResult(ui: *Ui, text: []const u8, failed: bool) void {
        ui.test_state = if (failed) .failed else .done;
        const shown = if (!failed and std.mem.trim(u8, text, " ").len == 0) "(nothing heard)" else text;
        const n = @min(shown.len, ui.test_buf.len);
        @memcpy(ui.test_buf[0..n], shown[0..n]);
        ui.test_len = n;
    }

    // ------------------------------------------------------- focus

    /// Focus order: Automatic, the model field, Instruct, Learn, the rows,
    /// Test, Save, Reload limits, Close.
    const n_fields = 4;
    fn focusCount(ui: *const Ui) u8 {
        return n_fields + ui.n_rows + 4;
    }

    fn focusedRow(ui: *const Ui) ?usize {
        if (ui.focus.index < n_fields or ui.focus.index >= n_fields + ui.n_rows) return null;
        return ui.focus.index - n_fields;
    }

    fn focusedButton(ui: *const Ui) ?u32 {
        const b = ui.focus.index -| (n_fields + ui.n_rows);
        if (ui.focus.index < n_fields + ui.n_rows) return null;
        return switch (b) {
            0 => id.test_clip,
            1 => id.save,
            2 => id.reload,
            else => id.close,
        };
    }

    /// The glue's rows changed count (keeps the focus in range).
    fn sync(ui: *Ui, n: usize) void {
        const k: u8 = @intCast(@min(n, max_rows));
        if (k == ui.n_rows) return;
        ui.n_rows = k;
        ui.focus.reset(ui.focusCount(), ui.focus.index);
    }

    // ------------------------------------------------------- input

    pub fn key(ui: *Ui, k: input.Key, mods: input.Mods) Action {
        switch (k) {
            .escape => return ui.close(),
            .tab => if (mods.shift) ui.focus.prev() else ui.focus.next(),
            .up => ui.focus.prev(),
            .down => ui.focus.next(),
            .left, .right => if (ui.focus.index == 0) return ui.toggleAuto() else if (ui.focus.index == 2) return ui.cycleInstruct() else if (ui.focus.index == 3) return ui.toggleLearning(),
            .backspace => if (ui.focus.index == 1) ui.model.backspace(),
            .enter => return ui.activate(),
            else => {},
        }
        return .none;
    }

    pub fn char(ui: *Ui, cp: u21, mods: input.Mods) Action {
        if (mods.ctrl and !mods.alt and (cp == 'v' or cp == 'V')) return if (ui.focus.index == 1) .paste else .none;
        if (mods.ctrl or mods.alt) return .none;
        if (ui.focus.index == 1) {
            _ = ui.model.insert(cp);
            return .none;
        }
        if (cp == ' ') return ui.activate();
        return .none;
    }

    pub fn paste(ui: *Ui, text: []const u8) void {
        if (ui.focus.index == 1) _ = ui.model.insertText(text);
    }

    pub fn button(ui: *Ui, b: u32) Action {
        switch (b) {
            id.close => return ui.close(),
            id.test_clip => return ui.startTest(),
            id.save => return .save_model,
            id.reload => return .reload_limits,
            id.field0 => {
                ui.focus.index = 0;
                return ui.toggleAuto();
            },
            id.field0 + 1 => ui.focus.index = 1,
            id.field0 + 2 => {
                ui.focus.index = 2;
                return ui.cycleInstruct();
            },
            id.field0 + 3 => {
                ui.focus.index = 3;
                return ui.toggleLearning();
            },
            id.dev0...id.dev0 + max_rows - 1 => if (b - id.dev0 < ui.n_rows) {
                ui.auto = false;
                return .{ .use = b - id.dev0 };
            },
            else => {},
        }
        return .none;
    }

    fn toggleAuto(ui: *Ui) Action {
        ui.auto = !ui.auto;
        return .{ .set_auto = ui.auto };
    }

    fn toggleLearning(ui: *Ui) Action {
        ui.learning = !ui.learning;
        return .{ .set_learning = ui.learning };
    }

    fn cycleInstruct(ui: *Ui) Action {
        ui.instruct_mode = ui.instruct_mode.next();
        return .{ .set_instruct_mode = ui.instruct_mode };
    }

    fn startTest(ui: *Ui) Action {
        if (ui.test_state == .recording or ui.test_state == .transcribing) return .none;
        ui.test_state = .recording;
        ui.test_len = 0;
        return .test_clip;
    }

    fn activate(ui: *Ui) Action {
        if (ui.focus.index == 0) return ui.toggleAuto();
        if (ui.focus.index == 1) return .save_model;
        if (ui.focus.index == 2) return ui.cycleInstruct();
        if (ui.focus.index == 3) return ui.toggleLearning();
        if (ui.focusedRow()) |r| {
            ui.auto = false;
            return .{ .use = r };
        }
        return ui.button(ui.focusedButton() orelse return .none);
    }

    // ------------------------------------------------------- drawing

    pub fn panel(ui: *Ui, b: *Bufs, v: View) ?frame.Panel {
        if (!ui.open_) return null;
        ui.sync(v.rows.len);
        var nl: usize = 0;
        b.lines[nl] = if (v.speech.len == 0)
            .{ .text = "Speech: ready (desktop GPU)", .tone = .good }
        else
            .{ .text = v.speech, .tone = if (v.speech_bad) .bad else .warn };
        nl += 1;
        if (v.rows.len == 0) {
            b.lines[nl] = .{ .text = "No microphone found. Connect one; it shows up here.", .tone = .warn };
            nl += 1;
        } else if (v.fell_back) {
            b.lines[nl] = .{ .text = "The chosen microphone is not connected: Automatic picked one.", .tone = .warn };
            nl += 1;
        }
        if (v.mic_error.len > 0) {
            b.lines[nl] = .{ .text = v.mic_error, .tone = .bad };
            nl += 1;
        }
        // The meter: ten bars, live while this panel is open.
        var mb: std.Io.Writer = .fixed(&b.line_text[0]);
        mb.writeAll("Input level  ") catch {};
        for (0..10) |i| mb.writeAll(if (i < v.level) "\u{2588}" else "\u{2591}") catch {};
        if (!v.capturing) mb.writeAll("  (not capturing)") catch {};
        b.lines[nl] = .{ .text = mb.buffered(), .tone = if (v.capturing) .good else .muted };
        nl += 1;

        const n = @min(v.rows.len, max_rows);
        for (v.rows[0..n], 0..) |r, i| {
            const t = std.fmt.bufPrint(&b.row_text[i], "{s}{s}  \u{2014}  {s}{s}", .{
                if (r.active) "\u{1F3A4} " else "",
                r.name,
                r.kind,
                if (r.default) " \u{00B7} Windows default" else "",
            }) catch r.name;
            b.rows[i] = .{
                .text = t,
                .tone = if (r.active) .good else .normal,
                .selected = ui.focusedRow() == i,
                .button = if (r.active and !v.automatic) null else .{ .label = "Use", .id = id.dev0 + @as(u32, @intCast(i)), .focused = ui.focusedRow() == i },
            };
        }
        b.fields[0] = .{
            .label = "Microphone",
            .value = if (ui.auto) "Automatic (a headset first)" else "Manual (the one marked \u{1F3A4})",
            .id = id.field0,
            .focused = ui.focus.index == 0,
            .choice = true,
        };
        b.fields[1] = .{
            .label = "Speech model",
            .value = ui.model.text(),
            .hint = "path to a ggml model, e.g. ggml-base.en.bin",
            .id = id.field0 + 1,
            .focused = ui.focus.index == 1,
        };
        b.fields[2] = .{
            .label = "Instruct",
            .value = ui.instruct_mode.label(),
            .id = id.field0 + 2,
            .focused = ui.focus.index == 2,
            .choice = true,
        };
        b.fields[3] = .{
            .label = "Learn from my voice",
            .value = if (ui.learning) "On (corrections and clips train your model)" else "Off (transcribe only, nothing kept)",
            .id = id.field0 + 3,
            .focused = ui.focus.index == 3,
            .choice = true,
        };
        var na: usize = 0;
        switch (ui.test_state) {
            .idle => {},
            .recording => {
                b.after[0] = .{ .text = "\u{25CF} Recording 3 s\u{2026} say something.", .tone = .bad };
                na = 1;
            },
            .transcribing => {
                b.after[0] = .{ .text = "Transcribing\u{2026}", .tone = .warn };
                na = 1;
            },
            .done => {
                b.after[0] = .{ .text = ui.test_buf[0..ui.test_len], .tone = .normal, .bold = true };
                na = 1;
            },
            .failed => {
                b.after[0] = .{ .text = ui.test_buf[0..ui.test_len], .tone = .bad };
                na = 1;
            },
        }
        const fb = ui.focusedButton();
        b.buttons[0] = .{ .label = "Test (3 s)", .id = id.test_clip, .focused = fb == id.test_clip, .tone = .good };
        b.buttons[1] = .{ .label = "Save model", .id = id.save, .focused = fb == id.save };
        b.buttons[2] = .{ .label = "Reload limits", .id = id.reload, .focused = fb == id.reload };
        b.buttons[3] = .{ .label = "Close", .id = id.close, .focused = fb == id.close };
        return .{
            .title = "Audio",
            .lines = b.lines[0..nl],
            .rows = b.rows[0..n],
            .fields = &b.fields,
            .after = b.after[0..na],
            .note = .{ .text = ui.note_buf[0..ui.note_len], .tone = ui.note_tone },
            .buttons = &b.buttons,
        };
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "audio panel: rows, automatic toggle, use, test, close" {
    var ui: Ui = .{};
    ui.show(true, "C:\\models\\ggml-base.en.bin", .auto);
    var b: Ui.Bufs = .{};
    const rows = [_]Row{
        .{ .name = "Microphone Array", .kind = "Microphone \u{00B7} built-in", .default = true },
        .{ .name = "Jabra Evolve2", .kind = "Headset \u{00B7} USB", .active = true },
    };
    const p = ui.panel(&b, .{ .rows = &rows, .level = 4, .capturing = true }).?;
    try testing.expectEqualStrings("Audio", p.title);
    try testing.expectEqual(@as(usize, 2), p.rows.len);
    try testing.expect(std.mem.startsWith(u8, p.rows[1].text, "\u{1F3A4} Jabra"));
    try testing.expect(std.mem.indexOf(u8, p.lines[1].text, "\u{2588}\u{2588}\u{2588}\u{2588}\u{2591}") != null);
    try testing.expectEqualStrings("C:\\models\\ggml-base.en.bin", p.fields[1].value);
    // Automatic is focused first: Enter / Space / a click toggles it.
    const a = ui.key(.enter, .{});
    try testing.expect(a == .set_auto and !a.set_auto);
    try testing.expect(ui.button(id.field0).set_auto);
    // "Use" pins a microphone.
    const u = ui.button(id.dev0);
    try testing.expectEqual(@as(usize, 0), u.use);
    try testing.expect(!ui.auto);
    try testing.expect(ui.button(id.dev0 + 5) == .none); // no such row
    // Test: once at a time, then its transcript.
    try testing.expect(ui.button(id.test_clip) == .test_clip);
    try testing.expect(ui.button(id.test_clip) == .none);
    ui.testRecorded();
    ui.testResult(" Hello world.", false);
    const p2 = ui.panel(&b, .{ .rows = &rows }).?;
    try testing.expectEqualStrings(" Hello world.", p2.after[0].text);
    try testing.expect(std.mem.indexOf(u8, p2.lines[p2.lines.len - 1].text, "not capturing") != null);
    try testing.expect(ui.button(id.reload) == .reload_limits);
    try testing.expect(ui.key(.escape, .{}) == .closed);
    try testing.expect(!ui.open());
    try testing.expect(ui.panel(&b, .{}) == null);
}

test "audio panel: the Instruct choice cycles auto, type, record" {
    var ui: Ui = .{};
    ui.show(true, "", .auto);
    try testing.expectEqual(InstructMode.typing, ui.button(id.field0 + 2).set_instruct_mode);
    _ = ui.key(.right, .{});
    try testing.expectEqual(InstructMode.record, ui.instruct_mode);
    try testing.expectEqual(InstructMode.auto, ui.char(' ', .{}).set_instruct_mode);
    var b: Ui.Bufs = .{};
    const p = ui.panel(&b, .{}).?;
    try testing.expectEqualStrings("Instruct", p.fields[2].label);
}

test "audio panel: Learn from my voice, on by default, toggles" {
    var ui: Ui = .{};
    ui.show(true, "", .auto);
    try testing.expect(ui.learning);
    try testing.expect(!ui.button(id.field0 + 3).set_learning);
    try testing.expect(ui.key(.left, .{}).set_learning);
    var b: Ui.Bufs = .{};
    const p = ui.panel(&b, .{}).?;
    try testing.expectEqualStrings("Learn from my voice", p.fields[3].label);
}

test "audio panel: the model field takes text and Enter saves" {
    var ui: Ui = .{};
    ui.show(true, "", .auto);
    _ = ui.key(.tab, .{});
    for ("D:\\m.bin") |c| _ = ui.char(c, .{});
    try testing.expectEqualStrings("D:\\m.bin", ui.model.text());
    _ = ui.key(.backspace, .{});
    try testing.expectEqualStrings("D:\\m.bi", ui.model.text());
    try testing.expect(ui.char('v', .{ .ctrl = true }) == .paste);
    try testing.expect(ui.key(.enter, .{}) == .save_model);
    var b: Ui.Bufs = .{};
    const p = ui.panel(&b, .{ .speech = "Speech model not found: D:\\m.bi", .speech_bad = true }).?;
    try testing.expectEqual(frame.Tone.bad, p.lines[0].tone);
    try testing.expect(std.mem.indexOf(u8, p.lines[1].text, "No microphone") != null);
}
