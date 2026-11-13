//! Agent transcripts (the session program's own record of a
//! conversation), read for the Conversation view. Only the structure is
//! relied on, never more than needed:
//!
//! * Location: `<projects>\<folder>\<sessionId>.jsonl`, where `<projects>`
//!   is `%CLAUDE_CONFIG_DIR%\projects` or `%USERPROFILE%\.claude\projects`
//!   and `<folder>` is the session's working directory with every UTF-16
//!   unit that is not an ASCII letter or digit replaced by `-`
//!   (`C:\code\acme` → `C--code-acme`; names over 200 characters are cut
//!   and get a hash suffix, matched by prefix). Subagent transcripts live
//!   in `<sessionId>\subagents\` (subagents.zig: each a sub-tab of its
//!   own, never mixed into the session's view).
//! * One JSON object per line, appended as the session goes. Records with
//!   `type` `user`, `assistant` or `system` carry `sessionId`, `cwd`,
//!   `timestamp`, `uuid`, `isSidechain`; other types (`mode`,
//!   `permission-mode`, `attachment`, `file-history-snapshot`,
//!   `queue-operation`, `last-prompt`, `ai-title`, `api-request*`, ...)
//!   are ignored, as is every field not listed here.
//! * `user`: `message.content` is a string (a typed prompt) or an array of
//!   blocks: `text`, `image`, or `tool_result` (`tool_use_id`, `is_error`,
//!   `content`); `isMeta` marks injected context, `isCompactSummary` the
//!   summary after compaction, `origin.kind` (`human`, `task-notification`,
//!   `peer`, ...) who sent it. Prompts that start with a tag such as
//!   `<command-name>` or `<task-notification>` are not typed by the owner.
//! * `assistant`: `message.id`, `message.content` blocks `text`,
//!   `thinking` (never shown) and `tool_use` (`id`, `name`, `input`);
//!   one block per record, records of one reply share `message.id`.
//!   `isApiErrorMessage` marks an API error shown as a reply.
//! * `system`: `subtype` (`compact_boundary`, `turn_duration`, ...),
//!   `level`, `content`.
//! * `AskUserQuestion` tool input: `questions[]` of `question`, `header`,
//!   `multiSelect`, `options[]` of `label`, `description`.
//! * `timestamp`: ISO 8601 UTC (`2026-11-12T10:00:00.000Z`).
//! * Token use (assistant records): `message.model` (a model id, or
//!   `<synthetic>` for the agent's own notes) and `message.usage` with
//!   `input_tokens`, `output_tokens`, `cache_read_input_tokens`,
//!   `cache_creation_input_tokens` (integers; further fields ignored). Every
//!   record of one reply repeats its usage: count each `message.id` once.
//! * Background work (activity.zig): a `Bash` / `PowerShell` tool_use with
//!   `input.run_in_background` true starts a shell; a `Monitor` tool_use
//!   starts a monitor (`input.timeout_ms`). Both have `input.description`.
//!   The tool_result's record has `toolUseResult.backgroundTaskId` (shell)
//!   or `toolUseResult.taskId` and `.persistent` (monitor): the task id.
//!   `TaskStop` (`input.task_id`) stops one. When a task ends (or a
//!   monitor reports an event) the agent queues a notification: a
//!   `queue-operation` record (`operation` `enqueue`, `content`) and, once
//!   delivered, a `user` record (`origin.kind` `task-notification`) whose
//!   content starts `<task-notification>` and holds `<task-id>` and, when
//!   the task ended, `<status>` (`completed`, `failed`, `killed`). Only the
//!   id and the status are read from it.
//!
//! Tool arguments are never kept: a tool's file argument (`file_path`,
//! `notebook_path`) is only hashed, to count distinct files.
//!
//! Parsing is streaming (std.json.Scanner) over one line, bounded: strings
//! are cut to their limits, unknown fields are skipped without allocating,
//! a line cut short (too long to buffer) yields what came before the cut.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Scanner = std.json.Scanner;
const wire = @import("shared").convo;

// ------------------------------------------------------- folder encoding

/// Longest folder name the agent uses before it cuts and adds a hash.
pub const max_folder = 200;

/// The transcript folder name for working directory `cwd` (UTF-8/WTF-8):
/// every UTF-16 code unit that is not [A-Za-z0-9] becomes '-'. Returns the
/// full name; when it is longer than `max_folder`, the agent's folder is
/// its first `max_folder` bytes, a '-' and a hash (match by prefix).
pub fn folderName(cwd: []const u8, out: []u8) error{NameTooLong}![]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < cwd.len) {
        const c = cwd[i];
        const len = std.unicode.utf8ByteSequenceLength(c) catch 1;
        const units: usize = if (len == 4 and i + 4 <= cwd.len) 2 else 1;
        if (len == 1 and std.ascii.isAlphanumeric(c)) {
            if (n >= out.len) return error.NameTooLong;
            out[n] = c;
            n += 1;
        } else for (0..units) |_| {
            if (n >= out.len) return error.NameTooLong;
            out[n] = '-';
            n += 1;
        }
        i += @min(len, cwd.len - i);
    }
    return out[0..n];
}

/// The working directory as the agent sees it: no trailing separator
/// (except a drive root).
pub fn normalizeCwd(cwd: []const u8) []const u8 {
    var s = cwd;
    while (s.len > 3 and (s[s.len - 1] == '\\' or s[s.len - 1] == '/')) s = s[0 .. s.len - 1];
    return s;
}

/// `cwd` (from a record) is `root` or a folder inside it (ASCII case and
/// separator style ignored).
pub fn cwdWithin(cwd: []const u8, root: []const u8) bool {
    const r = normalizeCwd(root);
    const c = normalizeCwd(cwd);
    if (c.len < r.len) return false;
    for (r, c[0..r.len]) |a, b| {
        const sa = a == '\\' or a == '/';
        const sb = b == '\\' or b == '/';
        if (sa != sb) return false;
        if (!sa and std.ascii.toLower(a) != std.ascii.toLower(b)) return false;
    }
    return c.len == r.len or c[r.len] == '\\' or c[r.len] == '/';
}

/// A session id / transcript stem: a UUID (8-4-4-4-12 hex).
pub fn isSessionStem(s: []const u8) bool {
    if (s.len != 36) return false;
    for (s, 0..) |c, i| switch (i) {
        8, 13, 18, 23 => if (c != '-') return false,
        else => if (!std.ascii.isHex(c)) return false,
    };
    return true;
}

// ------------------------------------------------------------- tools

pub const Category = enum {
    edit,
    read,
    command,
    search,
    web,
    todo,
    agent,
    question,
    other,
};

pub fn category(name: []const u8) Category {
    const map = [_]struct { []const u8, Category }{
        .{ "Edit", .edit },                .{ "Write", .edit },   .{ "MultiEdit", .edit },
        .{ "NotebookEdit", .edit },        .{ "Read", .read },    .{ "Bash", .command },
        .{ "PowerShell", .command },       .{ "Grep", .search },  .{ "Glob", .search },
        .{ "LS", .search },                .{ "WebFetch", .web }, .{ "WebSearch", .web },
        .{ "TodoWrite", .todo },           .{ "Agent", .agent },  .{ "Task", .agent },
        .{ "AskUserQuestion", .question },
    };
    for (map) |m| if (std.mem.eql(u8, name, m[0])) return m[1];
    return .other;
}

/// A tool name fit to show ("Used <name>"): the last part of an MCP tool
/// (`mcp__server__tool`), letters, digits, `_` and `-` only, at most 40
/// bytes; otherwise "a tool".
pub fn displayTool(name: []const u8) []const u8 {
    var n = name;
    if (std.mem.startsWith(u8, n, "mcp__")) {
        if (std.mem.lastIndexOf(u8, n, "__")) |k| n = n[k + 2 ..];
    }
    if (n.len == 0 or n.len > 40) return "a tool";
    for (n) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-') return "a tool";
    return n;
}

/// The one-liner for `calls` uses of a tool category touching `files`
/// distinct files. Never arguments or paths.
pub fn oneLiner(buf: []u8, cat: Category, tool: []const u8, calls: u32, files: u32) []const u8 {
    const f = @max(files, 1);
    const s = switch (cat) {
        .edit => if (f == 1) std.fmt.bufPrint(buf, "Edited 1 file", .{}) else std.fmt.bufPrint(buf, "Edited {d} files", .{f}),
        .read => if (f == 1) std.fmt.bufPrint(buf, "Read 1 file", .{}) else std.fmt.bufPrint(buf, "Read {d} files", .{f}),
        .command => if (calls <= 1) std.fmt.bufPrint(buf, "Ran a command", .{}) else std.fmt.bufPrint(buf, "Ran {d} commands", .{calls}),
        .search => if (calls <= 1) std.fmt.bufPrint(buf, "Searched the project", .{}) else std.fmt.bufPrint(buf, "Searched the project {d} times", .{calls}),
        .web => if (calls <= 1) std.fmt.bufPrint(buf, "Looked something up", .{}) else std.fmt.bufPrint(buf, "Looked {d} things up", .{calls}),
        .todo => std.fmt.bufPrint(buf, "Updated the to-do list", .{}),
        .agent => if (calls <= 1) std.fmt.bufPrint(buf, "Started a helper agent", .{}) else std.fmt.bufPrint(buf, "Started {d} helper agents", .{calls}),
        .question => std.fmt.bufPrint(buf, "Asked a question", .{}),
        .other => if (calls <= 1) std.fmt.bufPrint(buf, "Used {s}", .{displayTool(tool)}) else std.fmt.bufPrint(buf, "Used {s} {d} times", .{ displayTool(tool), calls }),
    };
    return s catch "Used a tool";
}

/// What the owner is asked to allow, for a permission prompt about a tool
/// of this category ("Claude wants to <phrase>.").
pub fn permissionPhrase(buf: []u8, cat: Category, tool: []const u8) []const u8 {
    return switch (cat) {
        .edit => "edit a file",
        .read => "read a file",
        .command => "run a command",
        .search => "search the project",
        .web => "look something up",
        .todo => "update its to-do list",
        .agent => "start a helper agent",
        .question => "ask you something",
        .other => std.fmt.bufPrint(buf, "use {s}", .{displayTool(tool)}) catch "use a tool",
    };
}

// ------------------------------------------------------------ records

pub const RecordType = enum { other, user, assistant, system, queue };

pub const BlockKind = enum { other, text, image, thinking, tool_use, tool_result };

pub const max_blocks = 16;
pub const max_questions = 4;
pub const max_question_options = 9;
pub const max_cwd = 1024;
pub const max_tool_name = 64;
/// Longest tool description kept (before scrubbing and cutting).
pub const max_desc = 512;
pub const max_model = 64;

pub const Usage = struct {
    input: u64 = 0,
    output: u64 = 0,
    cache_read: u64 = 0,
    cache_write: u64 = 0,
};
/// Text kept per record (all strings of it together).
pub const arena_size = 64 * 1024;

pub const Question = struct {
    text: []const u8 = "",
    header: []const u8 = "",
    multi: bool = false,
    labels: [max_question_options][]const u8 = undefined,
    n_labels: usize = 0,
};

pub const Block = struct {
    kind: BlockKind = .other,
    /// `text` blocks (and a string `content`): the text, cut to
    /// `wire.max_text` + 1 bytes (so a cut is visible).
    text: []const u8 = "",
    tool_buf: [max_tool_name]u8 = undefined,
    tool_len: u8 = 0,
    /// Hash of the tool_use `id` / tool_result `tool_use_id`.
    id_hash: u64 = 0,
    is_error: bool = false,
    /// Hash of the tool's file argument, 0 if none.
    file_hash: u64 = 0,
    /// tool_use input: `run_in_background` true.
    background: bool = false,
    /// tool_use input: `description` (cut to `max_desc`); scrubbed before
    /// it is shown anywhere.
    desc: []const u8 = "",
    /// tool_use input: `timeout_ms` (Monitor), 0 if none.
    timeout_ms: u64 = 0,
    /// tool_use input: hash of `task_id` (TaskStop), 0 if none.
    task_ref: u64 = 0,
    questions: [max_questions]Question = undefined,
    n_questions: usize = 0,

    pub fn tool(b: *const Block) []const u8 {
        return b.tool_buf[0..b.tool_len];
    }
};

pub const Record = struct {
    rtype: RecordType = .other,
    sidechain: bool = false,
    meta: bool = false,
    compact_summary: bool = false,
    api_error: bool = false,
    /// `origin.kind` present and not `human`.
    not_human: bool = false,
    compact_boundary: bool = false,
    level_error: bool = false,
    /// `system` records: `content`.
    content: []const u8 = "",
    session_buf: [64]u8 = undefined,
    session_len: u8 = 0,
    cwd_buf: [max_cwd]u8 = undefined,
    cwd_len: u16 = 0,
    cwd_cut: bool = false,
    msg_hash: u64 = 0,
    /// `timestamp` as Unix seconds, 0 if absent or malformed.
    timestamp: i64 = 0,
    /// `queue-operation` records: `operation` is `enqueue`.
    enqueue: bool = false,
    /// `message.model`.
    model_buf: [max_model]u8 = undefined,
    model_len: u8 = 0,
    /// `message.usage`, if present.
    usage: ?Usage = null,
    /// `toolUseResult.backgroundTaskId` or `.taskId`, hashed (0: none).
    result_task: u64 = 0,
    /// `toolUseResult.persistent` (a monitor without a timeout).
    result_persistent: bool = false,
    /// Set by the follower: the record was in the transcript before the
    /// tab started (an earlier run of the program).
    history: bool = false,
    blocks: [max_blocks]Block = undefined,
    n_blocks: usize = 0,
    arena: [arena_size]u8 = undefined,
    arena_len: usize = 0,

    pub fn sessionId(r: *const Record) []const u8 {
        return r.session_buf[0..r.session_len];
    }

    /// The record's `cwd`, or null if absent (or too long to keep).
    pub fn model(r: *const Record) []const u8 {
        return r.model_buf[0..r.model_len];
    }

    pub fn cwd(r: *const Record) ?[]const u8 {
        if (r.cwd_len == 0 or r.cwd_cut) return null;
        return r.cwd_buf[0..r.cwd_len];
    }

    pub fn reset(r: *Record) void {
        r.rtype = .other;
        r.sidechain = false;
        r.meta = false;
        r.compact_summary = false;
        r.api_error = false;
        r.not_human = false;
        r.compact_boundary = false;
        r.level_error = false;
        r.content = "";
        r.session_len = 0;
        r.cwd_len = 0;
        r.cwd_cut = false;
        r.msg_hash = 0;
        r.timestamp = 0;
        r.enqueue = false;
        r.model_len = 0;
        r.usage = null;
        r.result_task = 0;
        r.result_persistent = false;
        r.history = false;
        r.n_blocks = 0;
        r.arena_len = 0;
    }

    pub fn blockSlice(r: *const Record) []const Block {
        return r.blocks[0..r.n_blocks];
    }
};

pub fn hash(s: []const u8) u64 {
    const h = std.hash.Wyhash.hash(0x636f6e766f, s);
    return if (h == 0) 1 else h;
}

/// Parses one transcript line into `rec`. `complete` is false when the
/// line was cut short (only its first part is here): what came before the
/// cut is kept. Returns false if nothing usable was found (not JSON, not
/// an object).
pub fn parseLine(gpa: Allocator, line: []const u8, complete: bool, rec: *Record) bool {
    rec.reset();
    var sc = Scanner.initStreaming(gpa);
    defer sc.deinit();
    sc.feedInput(line);
    if (complete) sc.endInput();
    var p: P = .{ .sc = &sc, .rec = rec };
    p.top() catch |err| switch (err) {
        error.BufferUnderrun => return rec.rtype != .other or rec.n_blocks > 0,
        else => return false,
    };
    return true;
}

const Error = Scanner.NextError || error{UnexpectedToken};

const P = struct {
    sc: *Scanner,
    rec: *Record,

    /// Reads a string value (the next token must start one) into the
    /// record's arena, cut at `limit` bytes. Returns the kept part.
    fn str(p: *P, limit: usize) Error![]const u8 {
        const r = p.rec;
        const start = r.arena_len;
        var kept: usize = 0;
        while (true) {
            const t = try p.sc.next();
            const piece: []const u8 = switch (t) {
                .string => |s| s,
                .partial_string => |s| s,
                .partial_string_escaped_1 => |*b| b,
                .partial_string_escaped_2 => |*b| b,
                .partial_string_escaped_3 => |*b| b,
                .partial_string_escaped_4 => |*b| b,
                else => return error.UnexpectedToken,
            };
            const room = @min(limit - kept, arena_size - r.arena_len);
            const n = @min(room, piece.len);
            @memcpy(r.arena[r.arena_len..][0..n], piece[0..n]);
            r.arena_len += n;
            kept += n;
            if (t == .string) break;
        }
        return r.arena[start..r.arena_len];
    }

    /// A string into a small fixed buffer (keys, enum values, ids), cut.
    fn small(p: *P, buf: []u8) Error![]const u8 {
        var n: usize = 0;
        while (true) {
            const t = try p.sc.next();
            const piece: []const u8 = switch (t) {
                .string => |s| s,
                .partial_string => |s| s,
                .partial_string_escaped_1 => |*b| b,
                .partial_string_escaped_2 => |*b| b,
                .partial_string_escaped_3 => |*b| b,
                .partial_string_escaped_4 => |*b| b,
                else => return error.UnexpectedToken,
            };
            const k = @min(buf.len - n, piece.len);
            @memcpy(buf[n..][0..k], piece[0..k]);
            n += k;
            if (t == .string) return buf[0..n];
        }
    }

    /// The next value is a string: true, and `small` reads it. Anything
    /// else is skipped: false.
    fn isString(p: *P) Error!bool {
        const tt = try p.sc.peekNextTokenType();
        if (tt == .string) return true;
        try p.skip();
        return false;
    }

    fn boolean(p: *P) Error!bool {
        const tt = try p.sc.peekNextTokenType();
        if (tt == .true) {
            _ = try p.sc.next();
            return true;
        }
        if (tt == .false) {
            _ = try p.sc.next();
            return false;
        }
        try p.skip();
        return false;
    }

    fn skip(p: *P) Error!void {
        const h = p.sc.stackHeight();
        while (true) switch (try p.sc.next()) {
            .object_begin, .array_begin => return p.sc.skipUntilStackHeight(h),
            .partial_number, .partial_string, .partial_string_escaped_1, .partial_string_escaped_2, .partial_string_escaped_3, .partial_string_escaped_4 => continue,
            .object_end, .array_end, .end_of_document => return error.UnexpectedToken,
            else => return,
        };
    }

    /// Next key of the current object, or null at its end.
    fn key(p: *P, buf: []u8) Error!?[]const u8 {
        const tt = try p.sc.peekNextTokenType();
        if (tt == .object_end) {
            _ = try p.sc.next();
            return null;
        }
        return try p.small(buf);
    }

    fn expect(p: *P, comptime tag: std.meta.Tag(std.json.Token)) Error!bool {
        const tt = try p.sc.peekNextTokenType();
        if (@backingInt(tt) != @backingInt(tag)) {
            try p.skip();
            return false;
        }
        _ = try p.sc.next();
        return true;
    }

    fn top(p: *P) Error!void {
        if ((try p.sc.next()) != .object_begin) return error.UnexpectedToken;
        const r = p.rec;
        var kb: [32]u8 = undefined;
        var vb: [32]u8 = undefined;
        while (try p.key(&kb)) |k| {
            if (eq(k, "type")) {
                if (try p.isString()) {
                    const v = try p.small(&vb);
                    r.rtype = if (eq(v, "queue-operation")) .queue else if (eq(v, "queue")) .other else std.meta.stringToEnum(RecordType, v) orelse .other;
                }
            } else if (eq(k, "isSidechain")) {
                r.sidechain = try p.boolean();
            } else if (eq(k, "isMeta")) {
                r.meta = try p.boolean();
            } else if (eq(k, "isCompactSummary")) {
                r.compact_summary = try p.boolean();
            } else if (eq(k, "isApiErrorMessage")) {
                r.api_error = try p.boolean();
            } else if (eq(k, "sessionId")) {
                if (try p.isString()) {
                    const v = try p.small(&r.session_buf);
                    r.session_len = @intCast(v.len);
                }
            } else if (eq(k, "cwd")) {
                if (try p.isString()) {
                    var big: [max_cwd + 1]u8 = undefined;
                    const v = try p.small(&big);
                    if (v.len > max_cwd) {
                        r.cwd_cut = true;
                    } else {
                        @memcpy(r.cwd_buf[0..v.len], v);
                        r.cwd_len = @intCast(v.len);
                    }
                }
            } else if (eq(k, "timestamp")) {
                if (try p.isString()) r.timestamp = parseTimestamp(try p.small(&vb)) orelse 0;
            } else if (eq(k, "operation")) {
                if (try p.isString()) r.enqueue = eq(try p.small(&vb), "enqueue");
            } else if (eq(k, "toolUseResult")) {
                try p.toolUseResult();
            } else if (eq(k, "subtype")) {
                if (try p.isString()) r.compact_boundary = eq(try p.small(&vb), "compact_boundary");
            } else if (eq(k, "level")) {
                if (try p.isString()) r.level_error = eq(try p.small(&vb), "error");
            } else if (eq(k, "content")) {
                if (try p.isString()) r.content = try p.str(wire.max_text + 1);
            } else if (eq(k, "origin")) {
                if (try p.expect(.object_begin)) {
                    while (try p.key(&kb)) |ok| {
                        if (eq(ok, "kind") and try p.isString()) {
                            r.not_human = !eq(try p.small(&vb), "human");
                        } else try p.skip();
                    }
                }
            } else if (eq(k, "message")) {
                try p.message();
            } else try p.skip();
        }
    }

    fn message(p: *P) Error!void {
        if (!try p.expect(.object_begin)) return;
        const r = p.rec;
        var kb: [32]u8 = undefined;
        var ib: [128]u8 = undefined;
        while (try p.key(&kb)) |k| {
            if (eq(k, "id")) {
                if (try p.isString()) r.msg_hash = hash(try p.small(&ib));
            } else if (eq(k, "model")) {
                if (try p.isString()) {
                    const v = try p.small(&r.model_buf);
                    r.model_len = @intCast(v.len);
                }
            } else if (eq(k, "usage")) {
                try p.usage();
            } else if (eq(k, "content")) {
                const tt = try p.sc.peekNextTokenType();
                if (tt == .string) {
                    if (r.n_blocks < max_blocks) {
                        const b = &r.blocks[r.n_blocks];
                        b.* = .{ .kind = .text };
                        b.text = try p.str(wire.max_text + 1);
                        r.n_blocks += 1;
                    } else try p.skip();
                } else if (tt == .array_begin) {
                    _ = try p.sc.next();
                    while (true) {
                        if ((try p.sc.peekNextTokenType()) == .array_end) {
                            _ = try p.sc.next();
                            break;
                        }
                        try p.block();
                    }
                } else try p.skip();
            } else try p.skip();
        }
    }

    fn block(p: *P) Error!void {
        const r = p.rec;
        if (r.n_blocks >= max_blocks) return p.skip();
        if (!try p.expect(.object_begin)) return;
        const b = &r.blocks[r.n_blocks];
        b.* = .{};
        r.n_blocks += 1;
        var kb: [32]u8 = undefined;
        var vb: [32]u8 = undefined;
        var ib: [128]u8 = undefined;
        while (try p.key(&kb)) |k| {
            if (eq(k, "type")) {
                if (try p.isString()) b.kind = std.meta.stringToEnum(BlockKind, try p.small(&vb)) orelse .other;
            } else if (eq(k, "text")) {
                if (try p.isString()) b.text = try p.str(wire.max_text + 1);
            } else if (eq(k, "name")) {
                if (try p.isString()) {
                    const v = try p.small(&b.tool_buf);
                    b.tool_len = @intCast(v.len);
                }
            } else if (eq(k, "id") or eq(k, "tool_use_id")) {
                if (try p.isString()) b.id_hash = hash(try p.small(&ib));
            } else if (eq(k, "is_error")) {
                b.is_error = try p.boolean();
            } else if (eq(k, "input")) {
                try p.input(b);
            } else try p.skip();
        }
    }

    /// A tool_use `input`: only the file argument (hashed) and
    /// AskUserQuestion's questions.
    fn input(p: *P, b: *Block) Error!void {
        if (!try p.expect(.object_begin)) return;
        var kb: [32]u8 = undefined;
        var fb: [max_cwd]u8 = undefined;
        while (try p.key(&kb)) |k| {
            if (eq(k, "file_path") or eq(k, "notebook_path")) {
                if (try p.isString()) b.file_hash = hash(try p.small(&fb));
            } else if (eq(k, "run_in_background")) {
                b.background = try p.boolean();
            } else if (eq(k, "description")) {
                if (try p.isString()) b.desc = try p.str(max_desc);
            } else if (eq(k, "timeout_ms")) {
                b.timeout_ms = (try p.int()) orelse 0;
            } else if (eq(k, "task_id")) {
                if (try p.isString()) b.task_ref = hash(try p.small(&fb));
            } else if (eq(k, "questions")) {
                if (!try p.expect(.array_begin)) continue;
                while (true) {
                    if ((try p.sc.peekNextTokenType()) == .array_end) {
                        _ = try p.sc.next();
                        break;
                    }
                    if (b.n_questions >= max_questions) {
                        try p.skip();
                        continue;
                    }
                    if (try p.question(&b.questions[b.n_questions])) b.n_questions += 1;
                }
            } else try p.skip();
        }
    }

    /// A non-negative integer value (anything else is skipped: null).
    fn int(p: *P) Error!?u64 {
        const tt = try p.sc.peekNextTokenType();
        if (tt != .number) {
            try p.skip();
            return null;
        }
        var buf: [24]u8 = undefined;
        var n: usize = 0;
        var too_long = false;
        while (true) {
            const t = try p.sc.next();
            const piece: []const u8 = switch (t) {
                .number => |s| s,
                .partial_number => |s| s,
                else => return error.UnexpectedToken,
            };
            if (n + piece.len > buf.len) {
                too_long = true;
            } else {
                @memcpy(buf[n..][0..piece.len], piece);
                n += piece.len;
            }
            if (t == .number) break;
        }
        if (too_long) return null;
        return std.fmt.parseInt(u64, buf[0..n], 10) catch null;
    }

    /// `message.usage`: the four token counts.
    fn usage(p: *P) Error!void {
        if (!try p.expect(.object_begin)) return;
        var u: Usage = .{};
        var kb: [40]u8 = undefined;
        while (try p.key(&kb)) |k| {
            if (eq(k, "input_tokens")) {
                u.input = (try p.int()) orelse 0;
            } else if (eq(k, "output_tokens")) {
                u.output = (try p.int()) orelse 0;
            } else if (eq(k, "cache_read_input_tokens")) {
                u.cache_read = (try p.int()) orelse 0;
            } else if (eq(k, "cache_creation_input_tokens")) {
                u.cache_write = (try p.int()) orelse 0;
            } else try p.skip();
        }
        p.rec.usage = u;
    }

    /// The top-level `toolUseResult` (an object for most tools): only the
    /// background task's id.
    fn toolUseResult(p: *P) Error!void {
        if (!try p.expect(.object_begin)) return;
        const r = p.rec;
        var kb: [32]u8 = undefined;
        var ib: [128]u8 = undefined;
        while (try p.key(&kb)) |k| {
            if (eq(k, "backgroundTaskId") or eq(k, "taskId")) {
                if (try p.isString()) r.result_task = hash(try p.small(&ib));
            } else if (eq(k, "persistent")) {
                r.result_persistent = try p.boolean();
            } else try p.skip();
        }
    }

    fn question(p: *P, q: *Question) Error!bool {
        if (!try p.expect(.object_begin)) return false;
        q.* = .{};
        var kb: [32]u8 = undefined;
        while (try p.key(&kb)) |k| {
            if (eq(k, "question")) {
                if (try p.isString()) q.text = try p.str(2048);
            } else if (eq(k, "header")) {
                if (try p.isString()) q.header = try p.str(wire.max_label);
            } else if (eq(k, "multiSelect")) {
                q.multi = try p.boolean();
            } else if (eq(k, "options")) {
                if (!try p.expect(.array_begin)) continue;
                while (true) {
                    if ((try p.sc.peekNextTokenType()) == .array_end) {
                        _ = try p.sc.next();
                        break;
                    }
                    if (!try p.expect(.object_begin)) continue;
                    while (try p.key(&kb)) |ok| {
                        if (eq(ok, "label") and q.n_labels < max_question_options and try p.isString()) {
                            q.labels[q.n_labels] = try p.str(wire.max_label);
                            q.n_labels += 1;
                        } else try p.skip();
                    }
                }
            } else try p.skip();
        }
        return q.text.len > 0;
    }
};

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// A user prompt that the owner did not type: injected context and
/// command wrappers start with a tag such as `<command-name>`,
/// `<local-command-stdout>`, `<task-notification>`, `<system-reminder>`
/// (lower case, with a '-').
pub fn taggedPrompt(text: []const u8) bool {
    const t = std.mem.trimStart(u8, text, " \t\r\n");
    if (t.len < 3 or t[0] != '<') return false;
    var i: usize = 1;
    var dash = false;
    while (i < t.len and i < 48) : (i += 1) {
        const c = t[i];
        if (c == '>') return dash and i > 1;
        if (c == '-') dash = true else if (!(c >= 'a' and c <= 'z') and !(c >= '0' and c <= '9')) return false;
    }
    return false;
}

/// `2026-11-12T10:00:00.000Z` (fraction and offset optional; `Z` or
/// `+hh:mm`) as Unix seconds, or null.
pub fn parseTimestamp(s: []const u8) ?i64 {
    if (s.len < 19 or s[4] != '-' or s[7] != '-' or (s[10] != 'T' and s[10] != ' ') or s[13] != ':' or s[16] != ':') return null;
    const y = std.fmt.parseInt(i64, s[0..4], 10) catch return null;
    const mo = std.fmt.parseInt(u8, s[5..7], 10) catch return null;
    const d = std.fmt.parseInt(u8, s[8..10], 10) catch return null;
    const hh = std.fmt.parseInt(i64, s[11..13], 10) catch return null;
    const mi = std.fmt.parseInt(i64, s[14..16], 10) catch return null;
    const ss = std.fmt.parseInt(i64, s[17..19], 10) catch return null;
    if (mo < 1 or mo > 12 or d < 1 or d > 31 or hh > 23 or mi > 59 or ss > 60) return null;
    var i: usize = 19;
    if (i < s.len and s[i] == '.') {
        i += 1;
        while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
    }
    var off: i64 = 0;
    if (i < s.len) switch (s[i]) {
        'Z' => i += 1,
        '+', '-' => {
            if (i + 6 > s.len or s[i + 3] != ':') return null;
            const oh = std.fmt.parseInt(i64, s[i + 1 .. i + 3], 10) catch return null;
            const om = std.fmt.parseInt(i64, s[i + 4 .. i + 6], 10) catch return null;
            off = (oh * 60 + om) * 60;
            if (s[i] == '-') off = -off;
            i += 6;
        },
        else => return null,
    };
    if (i != s.len) return null;
    return daysFromCivil(y, mo, d) * 86400 + hh * 3600 + mi * 60 + ss - off;
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// algorithm).
pub fn daysFromCivil(y0: i64, m: u8, d: u8) i64 {
    const y = if (m <= 2) y0 - 1 else y0;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp: i64 = if (m > 2) m - 3 else m + 9;
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

pub const NoticeStatus = enum { completed, failed, killed };

/// What a task notification says: the task (hashed id) and, if it ended,
/// how. Nothing else of it is read.
pub const Notice = struct { task: u64, status: ?NoticeStatus };

/// A `<task-notification>` text (a queued or delivered notification), or
/// null for anything else.
pub fn taskNotice(text: []const u8) ?Notice {
    const t = std.mem.trimStart(u8, text, " \t\r\n");
    if (!std.mem.startsWith(u8, t, "<task-notification>")) return null;
    const id = tagValue(t, "task-id") orelse return null;
    if (id.len == 0 or id.len > 64) return null;
    var st: ?NoticeStatus = null;
    if (tagValue(t, "status")) |v| st = std.meta.stringToEnum(NoticeStatus, v);
    return .{ .task = hash(id), .status = st };
}

/// The text between `<name>` and `</name>` (the first pair), or null.
fn tagValue(t: []const u8, comptime name: []const u8) ?[]const u8 {
    const open = "<" ++ name ++ ">";
    const a = std.mem.indexOf(u8, t, open) orelse return null;
    const start = a + open.len;
    const b = std.mem.indexOfPos(u8, t, start, "</" ++ name ++ ">") orelse return null;
    return std.mem.trim(u8, t[start..b], " \t\r\n");
}

/// The owner interrupted the program (Esc): the agent records this as a
/// user text.
pub fn interruptPrompt(text: []const u8) bool {
    return std.mem.startsWith(u8, std.mem.trimStart(u8, text, " \t\r\n"), "[Request interrupted by user");
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn parsed(line: []const u8) !*Record {
    const r = try testing.allocator.create(Record);
    if (!parseLine(testing.allocator, line, true, r)) {
        testing.allocator.destroy(r);
        return error.NotParsed;
    }
    return r;
}

test "folder names follow the agent's encoding" {
    var buf: [400]u8 = undefined;
    try testing.expectEqualStrings("C--Users-bob-code-zig-Portal", try folderName("C:\\Users\\bob\\code\\zig\\Portal", &buf));
    try testing.expectEqualStrings("C--code-my-app-v1-2", try folderName("C:\\code\\my app\\v1.2", &buf));
    // One '-' per UTF-16 unit: two for a character outside the BMP.
    try testing.expectEqualStrings("C--x---y", try folderName("C:\\x\\é\\y", &buf));
    try testing.expectEqualStrings("C--x----y", try folderName("C:\\x\\😀\\y", &buf));
    try testing.expectEqualStrings("C--x", try folderName(normalizeCwd("C:\\x\\"), &buf));
    var tiny: [3]u8 = undefined;
    try testing.expectError(error.NameTooLong, folderName("C:\\abc", &tiny));
}

test "cwdWithin and session stems" {
    try testing.expect(cwdWithin("C:\\code\\acme", "c:/code/acme/"));
    try testing.expect(cwdWithin("C:\\code\\acme\\src", "C:\\code\\acme"));
    try testing.expect(!cwdWithin("C:\\code\\acme2", "C:\\code\\acme"));
    try testing.expect(!cwdWithin("C:\\code", "C:\\code\\acme"));
    try testing.expect(isSessionStem("584bcabc-a7ec-4bf2-a467-15f8757ea7e3"));
    try testing.expect(!isSessionStem("584bcabc-a7ec-4bf2-a467-15f8757ea7e"));
    try testing.expect(!isSessionStem("584bcabc_a7ec-4bf2-a467-15f8757ea7e3"));
}

test "one-liners never carry arguments" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("Edited 2 files", oneLiner(&buf, category("MultiEdit"), "MultiEdit", 3, 2));
    try testing.expectEqualStrings("Edited 1 file", oneLiner(&buf, category("Write"), "Write", 1, 0));
    try testing.expectEqualStrings("Read 3 files", oneLiner(&buf, category("Read"), "Read", 3, 3));
    try testing.expectEqualStrings("Ran a command", oneLiner(&buf, category("Bash"), "Bash", 1, 0));
    try testing.expectEqualStrings("Ran 4 commands", oneLiner(&buf, category("PowerShell"), "PowerShell", 4, 0));
    try testing.expectEqualStrings("Searched the project", oneLiner(&buf, category("Grep"), "Grep", 1, 0));
    try testing.expectEqualStrings("Looked something up", oneLiner(&buf, category("WebSearch"), "WebSearch", 1, 0));
    try testing.expectEqualStrings("Used SendMessage", oneLiner(&buf, category("SendMessage"), "SendMessage", 1, 0));
    try testing.expectEqualStrings("Used send_message 2 times", oneLiner(&buf, .other, "mcp__acme__send_message", 2, 0));
    try testing.expectEqualStrings("Used a tool", oneLiner(&buf, .other, "C:\\evil\\path", 1, 0));
    try testing.expectEqualStrings("Used a tool", oneLiner(&buf, .other, "mcp__x__", 1, 0));
}

test "user prompt as a string, and injected prompts" {
    const r = try parsed(
        \\{"parentUuid":null,"isSidechain":false,"type":"user","message":{"role":"user","content":"Fix \"the\" build\nplease"},"uuid":"u1","timestamp":"2026-11-12T10:00:00.000Z","cwd":"C:\\code\\acme","sessionId":"584bcabc-a7ec-4bf2-a467-15f8757ea7e3","origin":{"kind":"human"},"future":{"a":[1,2,{"b":null}]}}
    );
    defer testing.allocator.destroy(r);
    try testing.expectEqual(RecordType.user, r.rtype);
    try testing.expectEqualStrings("C:\\code\\acme", r.cwd().?);
    try testing.expectEqualStrings("584bcabc-a7ec-4bf2-a467-15f8757ea7e3", r.sessionId());
    try testing.expect(!r.not_human);
    try testing.expectEqual(@as(usize, 1), r.n_blocks);
    try testing.expectEqualStrings("Fix \"the\" build\nplease", r.blocks[0].text);
    try testing.expect(taggedPrompt("<command-name>/clear</command-name>"));
    try testing.expect(taggedPrompt("  <task-notification>\n..."));
    try testing.expect(!taggedPrompt("<div> is a tag"));
    try testing.expect(!taggedPrompt("a < b"));
    try testing.expect(interruptPrompt("[Request interrupted by user for tool use]"));
}

test "assistant blocks: text, thinking, tool_use with a file and questions" {
    const r = try parsed(
        \\{"isSidechain":false,"message":{"model":"m","id":"msg_1","type":"message","role":"assistant","content":[{"type":"thinking","thinking":"secret","signature":"x"},{"type":"text","text":"Here:\n```zig\nconst a = 1;\n```"},{"type":"tool_use","id":"toolu_1","name":"Edit","input":{"file_path":"C:\\code\\acme\\a.zig","old_string":"x","new_string":"y"}},{"type":"tool_use","id":"toolu_2","name":"AskUserQuestion","input":{"questions":[{"question":"Which one?","header":"Pick","multiSelect":false,"options":[{"label":"Alpha","description":"d"},{"label":"Beta","description":"d","preview":"p"}]}]}}],"stop_reason":"tool_use"},"type":"assistant","cwd":"C:\\code\\acme","sessionId":"s"}
    );
    defer testing.allocator.destroy(r);
    try testing.expectEqual(RecordType.assistant, r.rtype);
    try testing.expectEqual(hash("msg_1"), r.msg_hash);
    try testing.expectEqual(@as(usize, 4), r.n_blocks);
    try testing.expectEqual(BlockKind.thinking, r.blocks[0].kind);
    try testing.expectEqualStrings("", r.blocks[0].text); // thinking text is not kept
    try testing.expectEqualStrings("Here:\n```zig\nconst a = 1;\n```", r.blocks[1].text);
    try testing.expectEqualStrings("Edit", r.blocks[2].tool());
    try testing.expectEqual(hash("C:\\code\\acme\\a.zig"), r.blocks[2].file_hash);
    try testing.expectEqual(hash("toolu_1"), r.blocks[2].id_hash);
    const q = r.blocks[3].questions[0];
    try testing.expectEqual(@as(usize, 1), r.blocks[3].n_questions);
    try testing.expectEqualStrings("Which one?", q.text);
    try testing.expectEqualStrings("Pick", q.header);
    try testing.expectEqual(@as(usize, 2), q.n_labels);
    try testing.expectEqualStrings("Beta", q.labels[1]);
}

test "tool results, api errors, system records" {
    const r = try parsed(
        \\{"type":"user","message":{"role":"user","content":[{"tool_use_id":"toolu_1","type":"tool_result","content":[{"type":"text","text":"big output"}],"is_error":true}]},"toolUseResult":{"stdout":"x","filePath":"C:\\secret"}}
    );
    defer testing.allocator.destroy(r);
    try testing.expectEqual(BlockKind.tool_result, r.blocks[0].kind);
    try testing.expectEqual(hash("toolu_1"), r.blocks[0].id_hash);
    try testing.expect(r.blocks[0].is_error);
    try testing.expectEqualStrings("", r.blocks[0].text);

    const e = try parsed(
        \\{"type":"assistant","isApiErrorMessage":true,"error":"rate_limit","message":{"id":"m","role":"assistant","content":[{"type":"text","text":"API Error: 529 overloaded"}]}}
    );
    defer testing.allocator.destroy(e);
    try testing.expect(e.api_error);
    try testing.expectEqualStrings("API Error: 529 overloaded", e.blocks[0].text);

    const s = try parsed(
        \\{"type":"system","subtype":"compact_boundary","content":"Conversation compacted","level":"info","isMeta":false}
    );
    defer testing.allocator.destroy(s);
    try testing.expect(s.compact_boundary);
    try testing.expect(!s.level_error);
}

test "schema drift and damage: unknown types, wrong value types, cut lines" {
    const gpa = testing.allocator;
    const r = try gpa.create(Record);
    defer gpa.destroy(r);
    // Unknown record type: parsed, nothing to show.
    try testing.expect(parseLine(gpa, "{\"type\":\"frame-link\",\"x\":1}", true, r));
    try testing.expectEqual(RecordType.other, r.rtype);
    // Wrong types where strings or objects were expected are skipped.
    try testing.expect(parseLine(gpa, "{\"type\":\"user\",\"cwd\":7,\"isMeta\":\"yes\",\"message\":{\"content\":[1,\"x\",{\"type\":5,\"text\":[]}]},\"origin\":\"human\"}", true, r));
    try testing.expectEqual(RecordType.user, r.rtype);
    try testing.expect(r.cwd() == null);
    try testing.expect(!r.meta);
    // Not JSON / not an object.
    try testing.expect(!parseLine(gpa, "garbage", true, r));
    try testing.expect(!parseLine(gpa, "[1,2]", true, r));
    try testing.expect(!parseLine(gpa, "", true, r));
    // A line cut short keeps what came before the cut.
    const full = "{\"type\":\"assistant\",\"message\":{\"id\":\"m\",\"content\":[{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"Write\",\"input\":{\"file_path\":\"a.txt\",\"content\":\"xxxxxxxxxxxxxxxxxxxxxxxx";
    try testing.expect(parseLine(gpa, full, false, r));
    try testing.expectEqual(RecordType.assistant, r.rtype);
    try testing.expectEqual(@as(usize, 1), r.n_blocks);
    try testing.expectEqualStrings("Write", r.blocks[0].tool());
    try testing.expectEqual(hash("a.txt"), r.blocks[0].file_hash);
    // A truncated line marked complete is malformed: rejected.
    try testing.expect(!parseLine(gpa, full, true, r));
}

test "timestamps" {
    try testing.expectEqual(@as(?i64, 1_762_941_600), parseTimestamp("2025-11-12T10:00:00.000Z"));
    try testing.expectEqual(@as(?i64, 0), parseTimestamp("1970-01-01T00:00:00Z"));
    try testing.expectEqual(@as(?i64, 1_762_941_600 - 3600), parseTimestamp("2025-11-12T10:00:00+01:00"));
    try testing.expectEqual(@as(?i64, 951_782_400), parseTimestamp("2000-02-29T00:00:00"));
    try testing.expect(parseTimestamp("2025-13-12T10:00:00Z") == null);
    try testing.expect(parseTimestamp("yesterday") == null);
    try testing.expect(parseTimestamp("2025-11-12T10:00:00Zjunk") == null);
}

test "usage, model, background tasks, notifications" {
    const a = try parsed(
        \\{"type":"assistant","timestamp":"2025-11-12T10:00:00.000Z","message":{"model":"model-large-4-1","id":"msg_9","usage":{"input_tokens":3,"cache_creation_input_tokens":120,"cache_read_input_tokens":4500,"cache_creation":{"ephemeral_5m_input_tokens":0},"output_tokens":17,"service_tier":"standard","server_tool_use":{"web_search_requests":0}},"content":[{"type":"tool_use","id":"toolu_b","name":"Bash","input":{"command":"zig build test C:\\Users\\bob","description":"Run the tests","run_in_background":true,"timeout":600000}}]}}
    );
    defer testing.allocator.destroy(a);
    try testing.expectEqual(@as(i64, 1_762_941_600), a.timestamp);
    try testing.expectEqualStrings("model-large-4-1", a.model());
    try testing.expectEqual(@as(u64, 3), a.usage.?.input);
    try testing.expectEqual(@as(u64, 17), a.usage.?.output);
    try testing.expectEqual(@as(u64, 4500), a.usage.?.cache_read);
    try testing.expectEqual(@as(u64, 120), a.usage.?.cache_write);
    try testing.expect(a.blocks[0].background);
    try testing.expectEqualStrings("Run the tests", a.blocks[0].desc);
    const m = try parsed(
        \\{"type":"assistant","message":{"id":"m","content":[{"type":"tool_use","id":"toolu_m","name":"Monitor","input":{"command":"tail -f x","description":"Watch the log","timeout_ms":300000}}]}}
    );
    defer testing.allocator.destroy(m);
    try testing.expectEqual(@as(u64, 300000), m.blocks[0].timeout_ms);
    try testing.expect(m.usage == null);
    const r = try parsed(
        \\{"type":"user","message":{"content":[{"tool_use_id":"toolu_m","type":"tool_result","content":"Monitor started"}]},"toolUseResult":{"taskId":"b12345678","timeoutMs":300000,"persistent":false}}
    );
    defer testing.allocator.destroy(r);
    try testing.expectEqual(hash("b12345678"), r.result_task);
    try testing.expect(!r.result_persistent);
    const s = try parsed(
        \\{"type":"user","message":{"content":[{"tool_use_id":"toolu_b","type":"tool_result","content":"Command running in background"}]},"toolUseResult":{"stdout":"","stderr":"","interrupted":false,"backgroundTaskId":"bzzzz1234"}}
    );
    defer testing.allocator.destroy(s);
    try testing.expectEqual(hash("bzzzz1234"), s.result_task);
    const stop = try parsed(
        \\{"type":"assistant","message":{"id":"m2","content":[{"type":"tool_use","id":"toolu_s","name":"TaskStop","input":{"task_id":"bzzzz1234"}}]}}
    );
    defer testing.allocator.destroy(stop);
    try testing.expectEqual(hash("bzzzz1234"), stop.blocks[0].task_ref);
    const q = try parsed(
        \\{"type":"queue-operation","operation":"enqueue","timestamp":"2025-11-12T10:05:00.000Z","sessionId":"s","content":"<task-notification>\n<task-id>bzzzz1234</task-id>\n<tool-use-id>toolu_b</tool-use-id>\n<output-file>C:\\x</output-file>\n<status>failed</status>\n<summary>secret</summary>\n</task-notification>"}
    );
    defer testing.allocator.destroy(q);
    try testing.expectEqual(RecordType.queue, q.rtype);
    try testing.expect(q.enqueue);
    const n = taskNotice(q.content).?;
    try testing.expectEqual(hash("bzzzz1234"), n.task);
    try testing.expectEqual(NoticeStatus.failed, n.status.?);
    // A monitor's event: no status (still running).
    try testing.expect(taskNotice("<task-notification><task-id>b1</task-id><event>line</event></task-notification>").?.status == null);
    try testing.expect(taskNotice("no <task-notification>") == null);
    try testing.expect(taskNotice("<task-notification><status>completed</status></task-notification>") == null);
}

test "long strings are cut, not refused" {
    const gpa = testing.allocator;
    const r = try gpa.create(Record);
    defer gpa.destroy(r);
    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(gpa);
    try line.appendSlice(gpa, "{\"type\":\"user\",\"message\":{\"content\":\"");
    try line.appendNTimes(gpa, 'a', 100_000);
    try line.appendSlice(gpa, "\\n\"},\"cwd\":\"");
    try line.appendNTimes(gpa, 'c', 5000);
    try line.appendSlice(gpa, "\"}");
    try testing.expect(parseLine(gpa, line.items, true, r));
    try testing.expectEqual(@as(usize, wire.max_text + 1), r.blocks[0].text.len);
    try testing.expect(r.cwd() == null); // too long to trust
}
