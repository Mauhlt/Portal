//! One tab's Conversation view (docs/protocol.md section 3b): the items a
//! viewer draws instead of the terminal, built from the session program's
//! transcript (transcript.zig, read by follow.zig) and its OSC 7501 state
//! (a permission prompt or question it waits on).
//!
//! Rules (owner's decision, 2026-11-12):
//!   * the owner's prompts and the program's replies as readable text
//!     (Markdown code blocks kept); thinking never;
//!   * tool use as one-liners by tool and count ("Edited 2 files",
//!     "Ran 3 commands"; consecutive uses of the same kind merge into one
//!     line), never arguments, paths or results;
//!   * questions (AskUserQuestion) with their options as answer keys
//!     ("1".."9"); a permission prompt (OSC 7501 `kind=permission`) as
//!     Yes (`1`) / No (`esc`); other waits as a question without options;
//!   * API errors as one-line `error` items; compaction and interrupts as
//!     `status` items;
//!   * every text is cleaned (valid UTF-8, no controls or bidi overrides)
//!     and scrubbed of paths and the user's name (scrub.zig), then cut to
//!     `wire.max_text`.
//!
//! Bounded: at most `wire.max_items` items, `wire.max_total_text` bytes of
//! text and `wire.max_total_options` options; the oldest items go first.
//! Every change bumps `rev` and stamps the changed item with it, so a
//! viewer sends only what changed since its last `rev` (`writeSince`);
//! `epoch` changes when the conversation starts over (`reset`).
//!
//! Locking: the caller holds the hub's mutex (tabs.Hub.mutex) for every
//! call, as for the tab's screen.

const std = @import("std");
const Allocator = std.mem.Allocator;
const wire = @import("shared").convo;
const transcript = @import("transcript.zig");
const scrub = @import("scrub.zig");

pub const Kind = wire.Kind;

/// What the program waits for (OSC 7501, session.zig): nothing, a
/// permission prompt, or anything else (a question, sign-in...).
pub const Wait = enum { none, permission, other };

const Slot = struct {
    n: u32,
    kind: Kind,
    rev: u64,
    text: []u8,
    open: bool = false,
    multi: bool = false,
    options: []wire.Option = &.{},
    /// Questions: hash of the tool_use id that asked (0: none).
    tool_id: u64 = 0,
    /// Assistant text: hash of the reply's message id (merging).
    msg: u64 = 0,
    /// Removed (a question Portal asked that the transcript overtook):
    /// sent once as an empty `status` so viewers drop it, never in a
    /// snapshot.
    gone: bool = false,

    fn item(s: *const Slot) wire.Item {
        if (s.gone) return .{ .n = s.n, .kind = .status, .text = "" };
        return .{ .n = s.n, .kind = s.kind, .text = s.text, .open = s.open, .multi = s.multi, .options = s.options };
    }
};

const Pending = struct { id: u64, cat: transcript.Category, tool: [transcript.max_tool_name]u8, tool_len: u8 };

const Group = struct {
    n: u32 = 0,
    cat: transcript.Category = .other,
    tool: [transcript.max_tool_name]u8 = undefined,
    tool_len: u8 = 0,
    calls: u32 = 0,
    files: [32]u64 = undefined,
    n_files: u32 = 0,
    /// Distinct files counted beyond `files`.
    extra_files: u32 = 0,
};

pub const no_transcript_text = "No conversation to show yet: this tab's transcript has not appeared (the program may not keep one). The terminal shows everything.";

pub const Convo = struct {
    gpa: Allocator,
    /// How texts are scrubbed (the tab's folder, name, the user's name).
    /// Borrowed: the tab outlives its conversation.
    ctx: scrub.Context,

    slots: [wire.max_items]Slot = undefined,
    first: usize = 0,
    len: usize = 0,
    next_n: u32 = 1,
    rev: u64 = 1,
    epoch: u32 = 1,
    /// A transcript is being read.
    on: bool = false,
    text_bytes: usize = 0,
    option_count: usize = 0,
    group: Group = .{},
    pending: [8]Pending = undefined,
    n_pending: usize = 0,
    /// The open question Portal made from the program's state (0: none),
    /// and the tool it asks permission for (0: unknown).
    synthetic_n: u32 = 0,
    synthetic_tool: u64 = 0,
    /// Set while Portal adds its own question (askFromState).
    asking: bool = false,
    wait: Wait = .none,

    pub fn init(gpa: Allocator, ctx: scrub.Context) Convo {
        var c: Convo = .{ .gpa = gpa, .ctx = ctx };
        c.reset(false);
        return c;
    }

    pub fn deinit(c: *Convo) void {
        c.clear();
    }

    fn slotAt(c: *Convo, i: usize) *Slot {
        return &c.slots[(c.first + i) % wire.max_items];
    }

    /// The newest item still shown.
    fn last(c: *Convo) ?*Slot {
        var i = c.len;
        while (i > 0) {
            i -= 1;
            const s = c.slotAt(i);
            if (!s.gone) return s;
        }
        return null;
    }

    fn find(c: *Convo, n: u32) ?*Slot {
        for (0..c.len) |i| {
            const s = c.slotAt(i);
            if (s.n == n) return s;
        }
        return null;
    }

    fn freeSlot(c: *Convo, s: *Slot) void {
        c.text_bytes -= s.text.len;
        c.gpa.free(s.text);
        for (s.options) |o| c.gpa.free(o.label);
        c.option_count -= s.options.len;
        c.gpa.free(s.options);
        s.options = &.{};
    }

    fn dropOldest(c: *Convo) void {
        const s = c.slotAt(0);
        c.freeSlot(s);
        c.first = (c.first + 1) % wire.max_items;
        c.len -= 1;
    }

    fn clear(c: *Convo) void {
        while (c.len > 0) c.dropOldest();
        c.first = 0;
    }

    /// Starts over: a new transcript (`on`), or none to read. Viewers get
    /// a fresh snapshot.
    pub fn reset(c: *Convo, on: bool) void {
        c.clear();
        c.on = on;
        c.epoch +%= 1;
        if (c.epoch == 0) c.epoch = 1; // 0 is "never sent" to viewers
        c.rev +%= 1;
        c.group = .{};
        c.n_pending = 0;
        c.synthetic_n = 0;
        c.synthetic_tool = 0;
        if (!on) _ = c.pushStatic(.status, no_transcript_text) catch {};
        // The program may be waiting right now.
        c.programState(c.wait);
    }

    fn bump(c: *Convo, s: *Slot) void {
        c.rev +%= 1;
        s.rev = c.rev;
    }

    /// Makes room for `bytes` of text and `opts` options and one more item.
    fn makeRoom(c: *Convo, bytes: usize, opts: usize) void {
        while (c.len > 0 and (c.len >= wire.max_items or c.text_bytes + bytes > wire.max_total_text or c.option_count + opts > wire.max_total_options)) {
            const gone = c.slotAt(0).n;
            c.dropOldest();
            if (gone == c.synthetic_n) c.synthetic_n = 0;
            if (gone == c.group.n) c.group.n = 0;
        }
    }

    /// Before the transcript adds or extends an item: a question Portal
    /// asked from the program's state is taken away (refreshWait asks it
    /// again after the record, at the end, if the program still waits), so
    /// it never sits above what led to it.
    fn beforeAdd(c: *Convo) void {
        if (c.asking or c.synthetic_n == 0) return;
        if (c.find(c.synthetic_n)) |s| c.remove(s);
        c.synthetic_n = 0;
        c.synthetic_tool = 0;
    }

    fn remove(c: *Convo, s: *Slot) void {
        c.text_bytes -= s.text.len;
        c.gpa.free(s.text);
        s.text = &.{};
        for (s.options) |o| c.gpa.free(o.label);
        c.option_count -= s.options.len;
        c.gpa.free(s.options);
        s.options = &.{};
        s.open = false;
        s.gone = true;
        c.bump(s);
    }

    /// Appends an item that owns `text`.
    fn pushOwned(c: *Convo, kind: Kind, text: []u8) Allocator.Error!*Slot {
        c.beforeAdd();
        c.makeRoom(text.len, 0);
        // A tool line is extended only while it is the newest item.
        if (c.last()) |l| {
            if (l.n != c.group.n) c.group.n = 0;
        } else c.group.n = 0;
        const s = c.slotAt(c.len);
        c.len += 1;
        s.* = .{ .n = c.next_n, .kind = kind, .rev = 0, .text = text };
        c.next_n +%= 1;
        if (c.next_n == 0) c.next_n = 1;
        c.text_bytes += text.len;
        c.bump(s);
        return s;
    }

    /// Appends Portal's own text (not scrubbed: it holds no paths).
    fn pushStatic(c: *Convo, kind: Kind, text: []const u8) Allocator.Error!*Slot {
        const t = try c.gpa.dupe(u8, text);
        errdefer c.gpa.free(t);
        return c.pushOwned(kind, t);
    }

    /// Program text: cleaned, scrubbed and cut.
    fn prepare(c: *Convo, raw: []const u8, limit: usize) Allocator.Error![]u8 {
        var clean: std.ArrayList(u8) = .empty;
        defer clean.deinit(c.gpa);
        try cleanText(c.gpa, raw, &clean);
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(c.gpa);
        try scrub.scrub(c.gpa, c.ctx, std.mem.trim(u8, clean.items, " \t\n"), &out);
        cut(&out, limit);
        return out.toOwnedSlice(c.gpa);
    }

    fn setText(c: *Convo, s: *Slot, text: []u8) void {
        c.text_bytes -= s.text.len;
        c.gpa.free(s.text);
        s.text = text;
        c.text_bytes += text.len;
        c.bump(s);
    }

    fn setOptions(c: *Convo, s: *Slot, labels: []const []const u8) Allocator.Error!void {
        for (s.options) |o| c.gpa.free(o.label);
        c.option_count -= s.options.len;
        c.gpa.free(s.options);
        s.options = &.{};
        const n = @min(labels.len, 9);
        const opts = try c.gpa.alloc(wire.Option, n);
        var done: usize = 0;
        errdefer {
            for (opts[0..done]) |o| c.gpa.free(o.label);
            c.gpa.free(opts);
        }
        const keys = [_][]const u8{ "1", "2", "3", "4", "5", "6", "7", "8", "9" };
        for (labels[0..n], 0..) |l, i| {
            var label = try c.prepare(l, wire.max_label);
            if (std.mem.indexOfScalar(u8, label, '\n')) |nl| label = shrink(c.gpa, label, nl);
            if (label.len == 0) {
                c.gpa.free(label);
                label = try std.fmt.allocPrint(c.gpa, "Option {d}", .{i + 1});
            }
            opts[i] = .{ .label = label, .key = keys[i] };
            done += 1;
        }
        s.options = opts;
        c.option_count += n;
    }

    // ------------------------------------------------------- transcript

    /// Adds what one transcript record says.
    pub fn applyRecord(c: *Convo, rec: *const transcript.Record) Allocator.Error!void {
        if (rec.sidechain) return;
        switch (rec.rtype) {
            .user => try c.userRecord(rec),
            .assistant => try c.assistantRecord(rec),
            .system => {
                if (rec.compact_boundary) {
                    _ = try c.pushStatic(.status, "Conversation compacted");
                } else if (rec.level_error and rec.content.len > 0) {
                    try c.errorLine(rec.content);
                }
            },
            .other, .queue => return,
        }
        c.refreshWait();
    }

    /// The program still waits and nothing is open (its question was
    /// answered, or Portal's was taken away): ask from its state again.
    fn refreshWait(c: *Convo) void {
        if (c.wait == .none or c.synthetic_n != 0 or c.openQuestion()) return;
        c.askFromState(c.wait) catch {};
    }

    fn userRecord(c: *Convo, rec: *const transcript.Record) Allocator.Error!void {
        var prompt: std.ArrayList(u8) = .empty;
        defer prompt.deinit(c.gpa);
        var results = false;
        for (rec.blockSlice()) |*b| switch (b.kind) {
            .tool_result => {
                results = true;
                c.toolDone(b.id_hash);
            },
            .text => {
                if (prompt.items.len > 0) try prompt.appendSlice(c.gpa, "\n\n");
                try prompt.appendSlice(c.gpa, b.text);
            },
            .image => {
                if (prompt.items.len > 0) try prompt.append(c.gpa, '\n');
                try prompt.appendSlice(c.gpa, "[image]");
            },
            else => {},
        };
        if (results or rec.meta or rec.compact_summary or rec.not_human) return;
        if (prompt.items.len == 0 or transcript.taggedPrompt(prompt.items)) return;
        if (transcript.interruptPrompt(prompt.items)) {
            c.closeQuestions();
            _ = try c.pushStatic(.status, "Interrupted");
            return;
        }
        const text = try c.prepare(prompt.items, wire.max_text);
        errdefer c.gpa.free(text);
        if (text.len == 0) {
            c.gpa.free(text);
            return;
        }
        // A new prompt answers or ends whatever was asked.
        c.closeQuestions();
        _ = try c.pushOwned(.user, text);
    }

    fn assistantRecord(c: *Convo, rec: *const transcript.Record) Allocator.Error!void {
        if (rec.api_error) {
            for (rec.blockSlice()) |*b| if (b.kind == .text) return c.errorLine(b.text);
            return c.errorLine("The program reported an API error");
        }
        for (rec.blockSlice()) |*b| switch (b.kind) {
            .text => try c.assistantText(rec.msg_hash, b.text),
            .tool_use => {
                const cat = transcript.category(b.tool());
                c.addPending(b.id_hash, cat, b.tool());
                if (cat == .question and b.n_questions > 0) {
                    try c.questions(b);
                } else {
                    try c.toolUse(cat, b.tool(), b.file_hash);
                }
            },
            else => {},
        };
    }

    fn assistantText(c: *Convo, msg: u64, raw: []const u8) Allocator.Error!void {
        const text = try c.prepare(raw, wire.max_text);
        if (text.len == 0) {
            c.gpa.free(text);
            return;
        }
        c.beforeAdd();
        if (c.last()) |l| if (l.kind == .assistant and msg != 0 and l.msg == msg) {
            defer c.gpa.free(text);
            var joined: std.ArrayList(u8) = .empty;
            errdefer joined.deinit(c.gpa);
            try joined.appendSlice(c.gpa, l.text);
            try joined.appendSlice(c.gpa, "\n\n");
            try joined.appendSlice(c.gpa, text);
            cut(&joined, wire.max_text);
            const t = try joined.toOwnedSlice(c.gpa);
            c.makeRoom(t.len -| l.text.len, 0);
            c.setText(l, t);
            return;
        };
        errdefer c.gpa.free(text);
        const s = try c.pushOwned(.assistant, text);
        s.msg = msg;
    }

    fn errorLine(c: *Convo, raw: []const u8) Allocator.Error!void {
        const nl = std.mem.indexOfScalar(u8, raw, '\n') orelse raw.len;
        const text = try c.prepare(raw[0..nl], 300);
        errdefer c.gpa.free(text);
        if (text.len == 0) {
            c.gpa.free(text);
            return;
        }
        _ = try c.pushOwned(.@"error", text);
    }

    fn toolUse(c: *Convo, cat: transcript.Category, tool: []const u8, file: u64) Allocator.Error!void {
        var line: [96]u8 = undefined;
        c.beforeAdd();
        const g = &c.group;
        const same_tool = cat != .other or std.mem.eql(u8, g.tool[0..g.tool_len], tool[0..@min(tool.len, g.tool.len)]);
        if (g.n != 0 and c.last() != null and c.last().?.n == g.n and g.cat == cat and same_tool) {
            g.calls +|= 1;
            addFile(g, file);
            const s = c.last().?;
            const t = try c.gpa.dupe(u8, transcript.oneLiner(&line, cat, tool, g.calls, g.n_files + g.extra_files));
            c.setText(s, t);
            return;
        }
        g.* = .{ .cat = cat, .calls = 1 };
        const tl = @min(tool.len, g.tool.len);
        @memcpy(g.tool[0..tl], tool[0..tl]);
        g.tool_len = @intCast(tl);
        addFile(g, file);
        const s = try c.pushStatic(.tool, transcript.oneLiner(&line, cat, tool, 1, g.n_files));
        g.n = s.n;
    }

    fn addFile(g: *Group, file: u64) void {
        if (file == 0) return;
        for (g.files[0..g.n_files]) |f| if (f == file) return;
        if (g.n_files < g.files.len) {
            g.files[g.n_files] = file;
            g.n_files += 1;
        } else g.extra_files +|= 1;
    }

    fn questions(c: *Convo, b: *const transcript.Block) Allocator.Error!void {
        for (b.questions[0..b.n_questions]) |*q| {
            const text = try c.prepare(q.text, wire.max_text);
            errdefer c.gpa.free(text);
            var opts: usize = @min(q.n_labels, 9);
            if (c.option_count + opts > wire.max_total_options) opts = 0;
            const s = try c.pushOwned(.question, text);
            s.open = true;
            s.multi = q.multi;
            s.tool_id = b.id_hash;
            c.makeRoom(0, opts);
            try c.setOptions(s, q.labels[0..opts]);
            c.bump(s);
        }
    }

    fn addPending(c: *Convo, id: u64, cat: transcript.Category, tool: []const u8) void {
        if (id == 0) return;
        if (c.n_pending == c.pending.len) {
            std.mem.copyForwards(Pending, c.pending[0 .. c.pending.len - 1], c.pending[1..]);
            c.n_pending -= 1;
        }
        var p: Pending = .{ .id = id, .cat = cat, .tool = undefined, .tool_len = 0 };
        const tl = @min(tool.len, p.tool.len);
        @memcpy(p.tool[0..tl], tool[0..tl]);
        p.tool_len = @intCast(tl);
        c.pending[c.n_pending] = p;
        c.n_pending += 1;
    }

    /// A tool's result arrived: whatever it asked is answered.
    fn toolDone(c: *Convo, id: u64) void {
        if (id == 0) return;
        var i: usize = 0;
        while (i < c.n_pending) {
            if (c.pending[i].id == id) {
                std.mem.copyForwards(Pending, c.pending[i .. c.n_pending - 1], c.pending[i + 1 .. c.n_pending]);
                c.n_pending -= 1;
            } else i += 1;
        }
        for (0..c.len) |k| {
            const s = c.slotAt(k);
            if (s.kind == .question and s.open and s.tool_id == id) {
                s.open = false;
                c.bump(s);
            }
        }
        if (c.synthetic_n != 0 and c.synthetic_tool == id) c.closeSynthetic();
    }

    /// The program no longer waits: a permission question Portal asked
    /// stays, answered; a plain "waiting" note goes.
    fn closeSynthetic(c: *Convo) void {
        if (c.find(c.synthetic_n)) |s| {
            if (s.options.len == 0) {
                c.remove(s);
            } else if (s.open) {
                s.open = false;
                c.bump(s);
            }
        }
        c.synthetic_n = 0;
        c.synthetic_tool = 0;
    }

    fn closeQuestions(c: *Convo) void {
        if (c.synthetic_n != 0) c.closeSynthetic();
        for (0..c.len) |k| {
            const s = c.slotAt(k);
            if (s.kind == .question and s.open) {
                s.open = false;
                c.bump(s);
            }
        }
        c.synthetic_n = 0;
        c.synthetic_tool = 0;
    }

    fn openQuestion(c: *Convo) bool {
        for (0..c.len) |k| {
            const s = c.slotAt(k);
            if (s.kind == .question and s.open) return true;
        }
        return false;
    }

    // ---------------------------------------------------- program state

    /// The program's OSC 7501 state changed (session.zig). Waiting with
    /// nothing open asks the owner; anything else closes what Portal asked.
    pub fn programState(c: *Convo, wait: Wait) void {
        c.wait = wait;
        if (wait == .none) {
            if (c.synthetic_n != 0) c.closeSynthetic();
            return;
        }
        if (c.synthetic_n != 0 or c.openQuestion()) return;
        c.askFromState(wait) catch {};
    }

    fn askFromState(c: *Convo, kind: Wait) Allocator.Error!void {
        c.asking = true;
        defer c.asking = false;
        var buf: [160]u8 = undefined;
        if (kind == .permission) {
            const p: ?Pending = if (c.n_pending > 0) c.pending[c.n_pending - 1] else null;
            var pb: [96]u8 = undefined;
            const text = if (p) |pp|
                std.fmt.bufPrint(&buf, "Claude wants to {s}. Allow it?", .{transcript.permissionPhrase(&pb, pp.cat, pp.tool[0..pp.tool_len])}) catch "Claude needs your permission to continue."
            else
                "Claude needs your permission to continue.";
            c.makeRoom(text.len, 2);
            const s = try c.pushStatic(.question, text);
            s.open = true;
            const opts = try c.gpa.alloc(wire.Option, 2);
            opts[0] = .{ .label = c.gpa.dupe(u8, "Yes") catch {
                c.gpa.free(opts);
                return error.OutOfMemory;
            }, .key = "1" };
            opts[1] = .{ .label = c.gpa.dupe(u8, "No") catch {
                c.gpa.free(opts[0].label);
                c.gpa.free(opts);
                return error.OutOfMemory;
            }, .key = "esc" };
            s.options = opts;
            c.option_count += 2;
            c.synthetic_n = s.n;
            c.synthetic_tool = if (p) |pp| pp.id else 0;
            return;
        }
        const s = try c.pushStatic(.question, "Claude is waiting for your answer. The terminal shows the question.");
        s.open = true;
        c.synthetic_n = s.n;
        c.synthetic_tool = 0;
    }

    // ------------------------------------------------------------ wire

    /// The whole conversation as a `convo` message for tab `id`.
    pub fn writeSnapshot(c: *Convo, w: *std.Io.Writer, id: wire.Id) std.Io.Writer.Error!void {
        try wire.writeBegin(w, true, id, c.on);
        var first = true;
        for (0..c.len) |i| {
            const s = c.slotAt(i);
            if (s.gone) continue;
            if (!first) try w.writeByte(',');
            first = false;
            try wire.writeItem(w, s.item());
        }
        try wire.writeEnd(w);
    }

    /// Items changed after `since` as a `convo+` message; false (nothing
    /// written) if there are none.
    pub fn writeSince(c: *Convo, w: *std.Io.Writer, id: wire.Id, since: u64) std.Io.Writer.Error!bool {
        var any = false;
        for (0..c.len) |i| {
            const s = c.slotAt(i);
            if (s.rev <= since) continue;
            if (!any) try wire.writeBegin(w, false, id, c.on) else try w.writeByte(',');
            any = true;
            try wire.writeItem(w, s.item());
        }
        if (any) try wire.writeEnd(w);
        return any;
    }
};

/// Valid UTF-8 (invalid bytes become U+FFFD), line breaks as `\n`, no
/// control characters but `\n` and `\t`, no bidi or zero-width format
/// characters.
pub fn cleanText(gpa: Allocator, raw: []const u8, out: *std.ArrayList(u8)) Allocator.Error!void {
    var i: usize = 0;
    while (i < raw.len) {
        const c = raw[i];
        if (c < 0x80) {
            i += 1;
            switch (c) {
                '\r' => {
                    if (i < raw.len and raw[i] == '\n') continue;
                    try out.append(gpa, '\n');
                },
                '\n', '\t' => try out.append(gpa, c),
                0...8, 0x0b...0x0c, 0x0e...0x1f, 0x7f => {},
                else => try out.append(gpa, c),
            }
            continue;
        }
        const len = std.unicode.utf8ByteSequenceLength(c) catch {
            try out.appendSlice(gpa, "\u{FFFD}");
            i += 1;
            continue;
        };
        if (i + len > raw.len) {
            try out.appendSlice(gpa, "\u{FFFD}");
            i += 1;
            continue;
        }
        const cp = std.unicode.utf8Decode(raw[i..][0..len]) catch {
            try out.appendSlice(gpa, "\u{FFFD}");
            i += 1;
            continue;
        };
        switch (cp) {
            0x80...0x9f, 0x200b...0x200f, 0x202a...0x202e, 0x2060...0x2069, 0x061c, 0xfeff => {},
            0x2028, 0x2029 => try out.append(gpa, '\n'),
            else => try out.appendSlice(gpa, raw[i..][0..len]),
        }
        i += len;
    }
}

/// Cuts `out` to at most `limit` bytes at a character boundary, ending
/// with "…" when anything was cut.
fn cut(out: *std.ArrayList(u8), limit: usize) void {
    if (out.items.len <= limit) return;
    const ell = "\u{2026}";
    var n = limit - ell.len;
    while (n > 0 and (out.items[n] & 0xC0) == 0x80) n -= 1;
    out.items.len = n;
    out.appendSliceAssumeCapacity(ell);
}

/// `s` cut to `n` bytes (reallocated), freeing the rest.
fn shrink(gpa: Allocator, s: []u8, n: usize) []u8 {
    return gpa.realloc(s, n) catch s[0..n];
}

// ------------------------------------------------------------------ tests

const testing = std.testing;
const ctx_acme: scrub.Context = .{ .root = "C:\\Users\\bob\\code\\acme", .name = "acme", .user = "bob" };

const Fixture = struct {
    c: Convo,
    rec: *transcript.Record,

    fn init() !Fixture {
        return .{ .c = Convo.init(testing.allocator, ctx_acme), .rec = try testing.allocator.create(transcript.Record) };
    }

    fn deinit(f: *Fixture) void {
        f.c.deinit();
        testing.allocator.destroy(f.rec);
    }

    fn feed(f: *Fixture, line: []const u8) !void {
        try testing.expect(transcript.parseLine(testing.allocator, line, true, f.rec));
        try f.c.applyRecord(f.rec);
    }

    fn snapshot(f: *Fixture, buf: []u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try f.c.writeSnapshot(&w, @splat(7));
        return w.buffered();
    }

    fn texts(f: *Fixture, buf: []u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        for (0..f.c.len) |i| {
            const s = f.c.slotAt(i);
            if (s.gone) continue;
            try w.print("{s}:{s}{s}|", .{ @tagName(s.kind), s.text, if (s.kind == .question and s.open) "(open)" else "" });
        }
        return w.buffered();
    }
};

fn user(comptime text: []const u8) []const u8 {
    return "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"" ++ text ++ "\"},\"cwd\":\"C:\\\\Users\\\\bob\\\\code\\\\acme\",\"sessionId\":\"s\"}";
}

fn toolLine(comptime id: []const u8, comptime name: []const u8, comptime input: []const u8) []const u8 {
    return "{\"type\":\"assistant\",\"message\":{\"id\":\"m-" ++ id ++ "\",\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"" ++ id ++ "\",\"name\":\"" ++ name ++ "\",\"input\":" ++ input ++ "}]}}";
}

fn result(comptime id: []const u8) []const u8 {
    return "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"tool_use_id\":\"" ++ id ++ "\",\"type\":\"tool_result\",\"content\":\"C:\\\\Users\\\\bob\\\\secret.txt\"}]},\"toolUseResult\":{\"filePath\":\"C:\\\\Users\\\\bob\"}}";
}

fn say(comptime msg: []const u8, comptime text: []const u8) []const u8 {
    return "{\"type\":\"assistant\",\"message\":{\"id\":\"" ++ msg ++ "\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"" ++ text ++ "\"}]}}";
}

test "a turn: prompt, tools merged into one-liners, reply, no paths" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.feed(user("Fix C:\\\\Users\\\\bob\\\\code\\\\acme\\\\src\\\\a.zig please"));
    try f.feed("{\"type\":\"assistant\",\"message\":{\"id\":\"m1\",\"content\":[{\"type\":\"thinking\",\"thinking\":\"hmm C:\\\\secret\"}]}}");
    try f.feed(toolLine("t1", "Read", "{\"file_path\":\"C:\\\\Users\\\\bob\\\\code\\\\acme\\\\a.zig\"}"));
    try f.feed(result("t1"));
    try f.feed(toolLine("t2", "Edit", "{\"file_path\":\"C:\\\\Users\\\\bob\\\\code\\\\acme\\\\a.zig\",\"old_string\":\"C:\\\\x\"}"));
    try f.feed(toolLine("t3", "Edit", "{\"file_path\":\"C:\\\\Users\\\\bob\\\\code\\\\acme\\\\b.zig\"}"));
    try f.feed(toolLine("t4", "MultiEdit", "{\"file_path\":\"C:\\\\Users\\\\bob\\\\code\\\\acme\\\\a.zig\"}"));
    try f.feed(result("t2"));
    try f.feed(toolLine("t5", "Bash", "{\"command\":\"del C:\\\\Users\\\\bob\\\\x\"}"));
    try f.feed(toolLine("t6", "Bash", "{\"command\":\"zig build\"}"));
    try f.feed(toolLine("t7", "Grep", "{\"pattern\":\"x\",\"path\":\"C:\\\\Users\\\\bob\"}"));
    try f.feed(toolLine("t8", "WebFetch", "{\"url\":\"https://x\"}"));
    try f.feed(toolLine("t9", "mcp__srv__do_thing", "{}"));
    try f.feed(say("m9", "Done. I changed C:\\\\Users\\\\bob\\\\code\\\\acme\\\\a.zig:\\n```zig\\nconst a = 1;\\n```"));
    try f.feed(say("m9", "Anything else, Bob?"));
    var buf: [4096]u8 = undefined;
    try testing.expectEqualStrings(
        "status:" ++ no_transcript_text ++ "|user:Fix acme\\src\\a.zig please|tool:Read 1 file|tool:Edited 2 files|tool:Ran 2 commands|tool:Searched the project|tool:Looked something up|tool:Used do_thing|assistant:Done. I changed acme\\a.zig:\n```zig\nconst a = 1;\n```\n\nAnything else, [user]?|",
        try f.texts(&buf),
    );
    var sb: [8192]u8 = undefined;
    const snap = try f.snapshot(&sb);
    try testing.expect(std.mem.indexOf(u8, snap, "Users") == null);
    try testing.expect(std.mem.indexOf(u8, snap, "secret") == null);
    try testing.expect(std.mem.indexOf(u8, snap, "zig build") == null);
    // The snapshot parses with the shared parser.
    var pb: [8192]u8 = undefined;
    var scratch: wire.Scratch = .{ .text = &pb };
    const m = wire.parse(snap, &scratch).?;
    try testing.expectEqual(@as(usize, 9), m.items.len);
    try testing.expect(m.on == false); // reset(false) at init; the follower says when it reads one
}

test "injected and non-human prompts are not shown; interrupts and compaction are statuses" {
    var f = try Fixture.init();
    defer f.deinit();
    f.c.reset(true);
    try f.feed(user("<command-name>/clear</command-name>"));
    try f.feed(user("<local-command-stdout></local-command-stdout>"));
    try f.feed("{\"type\":\"user\",\"isMeta\":true,\"message\":{\"content\":\"Caveat\"}}");
    try f.feed("{\"type\":\"user\",\"origin\":{\"kind\":\"task-notification\"},\"message\":{\"content\":\"bg done\"}}");
    try f.feed("{\"type\":\"user\",\"isSidechain\":true,\"message\":{\"content\":\"sub\"}}");
    try f.feed("{\"type\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"[Request interrupted by user for tool use]\"}]}}");
    try f.feed("{\"type\":\"system\",\"subtype\":\"compact_boundary\",\"content\":\"x\"}");
    try f.feed("{\"type\":\"user\",\"isCompactSummary\":true,\"message\":{\"content\":\"summary\"}}");
    try f.feed("{\"type\":\"assistant\",\"isApiErrorMessage\":true,\"message\":{\"id\":\"e\",\"content\":[{\"type\":\"text\",\"text\":\"API Error: 529 at C:\\\\Users\\\\bob\\nsecond line\"}]}}");
    try f.feed("{\"type\":\"attachment\",\"attachment\":{\"type\":\"file\"}}");
    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("status:Interrupted|status:Conversation compacted|error:API Error: 529 at [path]|", try f.texts(&buf));
}

test "questions: options become answer keys; a result closes them" {
    var f = try Fixture.init();
    defer f.deinit();
    f.c.reset(true);
    try f.feed(toolLine("q1", "AskUserQuestion", "{\"questions\":[{\"question\":\"Which DB at C:\\\\Users\\\\bob?\",\"header\":\"DB\",\"multiSelect\":false,\"options\":[{\"label\":\"Postgres\",\"description\":\"d\"},{\"label\":\"SQLite\\nlite\",\"description\":\"d\"}]},{\"question\":\"Also?\",\"header\":\"x\",\"multiSelect\":true,\"options\":[{\"label\":\"A\"},{\"label\":\"B\"},{\"label\":\"C\"}]}]}"));
    var sb: [4096]u8 = undefined;
    var pb: [4096]u8 = undefined;
    var scratch: wire.Scratch = .{ .text = &pb };
    var m = wire.parse(try f.snapshot(&sb), &scratch).?;
    try testing.expectEqual(@as(usize, 2), m.items.len);
    try testing.expectEqualStrings("Which DB at [path]?", m.items[0].text);
    try testing.expect(m.items[0].open);
    try testing.expectEqual(@as(usize, 2), m.items[0].options.len);
    try testing.expectEqualStrings("SQLite", m.items[0].options[1].label);
    try testing.expectEqualStrings("2", m.items[0].options[1].key);
    try testing.expect(m.items[1].multi);
    try testing.expectEqual(@as(usize, 3), m.items[1].options.len);
    const rev = f.c.rev;
    try f.feed(result("q1"));
    var w: std.Io.Writer = .fixed(&sb);
    try testing.expect(try f.c.writeSince(&w, @splat(7), rev));
    m = wire.parse(w.buffered(), &scratch).?;
    try testing.expect(!m.snapshot);
    try testing.expectEqual(@as(usize, 2), m.items.len);
    try testing.expect(!m.items[0].open and !m.items[1].open);
    // Nothing changed since: nothing to send.
    var w2: std.Io.Writer = .fixed(&sb);
    try testing.expect(!try f.c.writeSince(&w2, @splat(7), f.c.rev));
}

test "program state: permission prompts become Yes/No, other waits a plain question" {
    var f = try Fixture.init();
    defer f.deinit();
    f.c.reset(true);
    try f.feed(toolLine("b1", "Bash", "{\"command\":\"rm -rf C:\\\\\"}"));
    f.c.programState(.permission);
    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("tool:Ran a command|question:Claude wants to run a command. Allow it?(open)|", try f.texts(&buf));
    const q = f.c.last().?;
    try testing.expectEqualStrings("1", q.options[0].key);
    try testing.expectEqualStrings("esc", q.options[1].key);
    f.c.programState(.permission); // no duplicate
    f.c.programState(.none);
    try testing.expectEqualStrings("tool:Ran a command|question:Claude wants to run a command. Allow it?|", try f.texts(&buf));
    // A generic wait; then the transcript's question takes its place
    // (the note is removed: viewers get it as an empty item).
    f.c.programState(.other);
    const n = f.c.last().?.n;
    try testing.expectEqualStrings("Claude is waiting for your answer. The terminal shows the question.", f.c.last().?.text);
    const rev = f.c.rev;
    try f.feed(toolLine("q2", "AskUserQuestion", "{\"questions\":[{\"question\":\"Go?\",\"options\":[{\"label\":\"Yes\"}]}]}"));
    try testing.expect(n != f.c.last().?.n);
    try testing.expectEqualStrings("Go?", f.c.last().?.text);
    try testing.expect(f.c.last().?.open);
    try testing.expect(f.c.find(n).?.gone);
    var sb: [2048]u8 = undefined;
    var sw: std.Io.Writer = .fixed(&sb);
    _ = try f.c.writeSince(&sw, @splat(7), rev);
    try testing.expect(std.mem.indexOf(u8, sw.buffered(), "\"k\":\"status\",\"text\":\"\"") != null);
    var snap_buf: [4096]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, try f.snapshot(&snap_buf), "waiting for your answer") == null);
    // Waiting while a transcript question is open adds nothing.
    const len = f.c.len;
    f.c.programState(.other);
    try testing.expectEqual(len, f.c.len);
    // A typed prompt closes it.
    try f.feed(user("never mind"));
    try testing.expect(!f.c.slotAt(f.c.len - 2).open);
}

test "the program's wait seen before the transcript catches up: Portal's question moves below" {
    var f = try Fixture.init();
    defer f.deinit();
    f.c.reset(true);
    // Portal's question is the only item, then taken away: nothing left
    // shown but the record's own item.
    f.c.programState(.other);
    try f.feed(user("go"));
    f.c.programState(.none);
    f.c.programState(.permission); // the record of the tool is not read yet
    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("user:go|question:Claude needs your permission to continue.(open)|", try f.texts(&buf));
    try f.feed(toolLine("b2", "Bash", "{\"command\":\"x\"}"));
    try testing.expectEqualStrings("user:go|tool:Ran a command|question:Claude wants to run a command. Allow it?(open)|", try f.texts(&buf));
    // A question still open from the transcript when the program says it
    // waits; its result arrives later: Portal asks then.
    f.c.programState(.none);
    try f.feed(toolLine("q3", "AskUserQuestion", "{\"questions\":[{\"question\":\"Pick\",\"options\":[{\"label\":\"A\"}]}]}"));
    f.c.programState(.permission);
    try f.feed(result("q3"));
    try f.feed(toolLine("b3", "Bash", "{\"command\":\"y\"}"));
    try testing.expect(f.c.last().?.open);
    try testing.expectEqualStrings("Claude wants to run a command. Allow it?", f.c.last().?.text);
}

test "bounded: items, bytes and options; oldest go first" {
    var f = try Fixture.init();
    defer f.deinit();
    f.c.reset(true);
    for (0..wire.max_items + 50) |_| try f.feed(user("hello"));
    try testing.expectEqual(@as(usize, wire.max_items), f.c.len);
    const big: [wire.max_text * 2]u8 = @splat('x');
    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(testing.allocator);
    try line.appendSlice(testing.allocator, "{\"type\":\"user\",\"message\":{\"content\":\"");
    try line.appendSlice(testing.allocator, &big);
    try line.appendSlice(testing.allocator, "\"}}");
    for (0..40) |_| try f.feed(line.items);
    try testing.expect(f.c.text_bytes <= wire.max_total_text);
    try testing.expectEqual(@as(usize, wire.max_text), f.c.last().?.text.len);
    try testing.expect(std.mem.endsWith(u8, f.c.last().?.text, "\u{2026}"));
    for (0..200) |_| try f.feed(toolLine("qq", "AskUserQuestion", "{\"questions\":[{\"question\":\"Q\",\"options\":[{\"label\":\"1\"},{\"label\":\"2\"},{\"label\":\"3\"},{\"label\":\"4\"},{\"label\":\"5\"},{\"label\":\"6\"},{\"label\":\"7\"},{\"label\":\"8\"},{\"label\":\"9\"},{\"label\":\"10\"}]}]}"));
    try testing.expect(f.c.option_count <= wire.max_total_options);
    // Whatever is kept fits one message.
    const buf = try testing.allocator.alloc(u8, wire.max_message);
    defer testing.allocator.free(buf);
    var w: std.Io.Writer = .fixed(buf);
    try f.c.writeSnapshot(&w, @splat(1));
}

test "cleanText" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try cleanText(testing.allocator, "a\r\nb\rc\x1b[31md\x00e\u{202e}f\u{2028}g\xffh\t", &out);
    try testing.expectEqualStrings("a\nb\nc[31mde" ++ "f\ng\u{FFFD}h\t", out.items);
}
