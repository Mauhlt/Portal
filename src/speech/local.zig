//! The laptop's speech engine: stt-local (SpeechToText's program, a signed
//! sync package from the desk) as a child process, protocol 1: JSON lines
//! on its stdin and stdout (docs/stt-sync-contract.md). Every line it
//! writes is untrusted input: parsed strictly, sizes capped, unknown events
//! ignored.
//!
//! One `Engine` runs at most one stt-local. It starts on demand (the first
//! call after `configure`) and waits for the `ready` line; `stop` closes
//! its stdin (stt-local confirms what is pending and exits) and kills it if
//! it has not gone after `Timing.stop_ms`. When Portal itself exits, the
//! pipe closes and stt-local stops the same way.
//!
//! Calls are blocking and one at a time (the device's speech worker makes
//! them): each request carries a `rid`, and the caller sleeps on a
//! condition until the reader thread hands over the reply with that rid,
//! the program dies, or the call's deadline passes (then the program is
//! killed: a hang). Nothing polls: two reader threads per program block in
//! their reads (stdout: replies and events; stderr: its log, into std.log,
//! the last line kept for the user), the caller in its wait.
//!
//! Crashes: a program that exits without being asked to (or is killed for
//! a hang, a `backend_lost` reply or a broken line) fails the call in
//! flight; the next call starts a new one, but not before a backoff
//! (`backoff_ms`, doubling per crash in a row, at most `backoff_max_ms`; a
//! deadline the caller waits for). After `max_crashes` in a row the engine
//! gives up (error.GaveUp) until `configure` (a new package) or `retry`
//! (the user asks again). Any good reply resets the count.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const limits = @import("limits.zig");
const pecheck = @import("pecheck");

pub const proto = 1;
/// The longest line either way (stt-local's own limit).
pub const max_line = 8 << 20;
/// stt-local caps a bundle at this (its line must fit `max_line`).
pub const max_bundle_bytes = 5 << 20;
/// An update travels as one base64 line: above this it cannot fit.
pub const max_update_bytes = 6 << 20;
/// The program's file name in its package folder.
pub const exe_name = if (builtin.os.tag == .windows) "stt-local.exe" else "stt-local";

pub const Config = struct {
    /// stt-local in its (read-only) package folder; it runs from there.
    exe: []const u8,
    /// The stt-model package's model file.
    model: []const u8,
    /// The only folder stt-local writes (rules, vocabulary, samples, the
    /// adapter, the NPU's compiled graphs).
    profile: []const u8,
    /// The stt-adapter package's file (an update, or a raw adapter with
    /// `adapter_version`), if one is installed.
    adapter: ?[]const u8 = null,
    adapter_version: u32 = 0,
    /// Where the QNN runtime is (null: stt-local searches the driver's).
    qnn: ?[]const u8 = null,
    /// The source name on its training samples.
    device_name: []const u8 = "laptop",
};

/// Deadlines and the crash policy (tests shorten them).
pub const Timing = struct {
    /// The first start compiles the NPU graphs (cached afterwards).
    ready_ms: i64 = 300_000,
    call_ms: i64 = 60_000,
    /// 120 s of audio, on the slowest backend.
    transcribe_ms: i64 = 300_000,
    stop_ms: i64 = 5_000,
    backoff_ms: i64 = 1_000,
    backoff_max_ms: i64 = 60_000,
    max_crashes: u32 = 5,
};

pub const Error = error{
    /// No package paths yet (`configure`).
    NotConfigured,
    /// It exited before saying ready (the last stderr line says why).
    StartFailed,
    /// It exited (or was killed) during the call.
    Crashed,
    /// No reply in time: it was killed.
    Timeout,
    /// A reply that is not protocol 1 (it was killed).
    BadReply,
    /// The ready line names another protocol version.
    ProtocolMismatch,
    /// Crashed `max_crashes` times in a row.
    GaveUp,
    /// Too much to send in one line.
    TooLarge,
    // The program's own error codes.
    BadRequest,
    BadAudio,
    TooLong,
    Busy,
    BackendLost,
    UnknownId,
    NotFound,
    Internal,
    OutOfMemory,
};

pub const Result = struct { id: u64, text: []u8 };
pub const Bundle = struct { bytes: []u8, through: u32, count: u32 };
pub const Outcome = enum { learned, discarded };
pub const Status = struct { adapter_version: u32, profile_version: u32, learning: bool, pending_export: u32 };

/// Whether a delivered stt-local can run on this machine: the package has
/// no architecture of its own, and the desk builds it for the Snapdragon
/// (aarch64 Windows), so an x86_64 PC must not try it. Reads the PE header
/// (src/tools/pecheck.zig); off Windows, nothing delivered runs.
pub fn fitsThisMachine(io: Io, exe: []const u8) bool {
    if (builtin.os.tag != .windows) return false;
    const want: pecheck.Machine = switch (builtin.cpu.arch) {
        .x86_64 => .x86_64,
        .aarch64 => .aarch64,
        else => return false,
    };
    var buf: [4096]u8 = undefined;
    const f = Io.Dir.cwd().openFile(io, exe, .{}) catch return false;
    defer f.close(io);
    const n = f.readPositionalAll(io, &buf, 0) catch return false;
    const info = pecheck.parse(buf[0..n]) catch return false;
    return info.machine == want;
}

// ------------------------------------------------------------------ protocol

pub const Ready = struct { proto: u32, adapter_version: u32 };

/// What one stdout line is.
pub const Msg = union(enum) {
    ready: Ready,
    /// stt's next timed work (it runs it itself), null: none.
    wakeup: ?i64,
    /// A reply (its fields are in the parsed object).
    reply: u32,
    failure: struct { rid: u32, err: Error },
    /// An event this Portal does not know: ignored.
    other,
};

pub fn int(obj: std.json.ObjectMap, comptime T: type, key: []const u8) ?T {
    const v = obj.get(key) orelse return null;
    if (v != .integer) return null;
    return std.math.cast(T, v.integer);
}

pub fn str(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return if (v == .string) v.string else null;
}

pub fn boolean(obj: std.json.ObjectMap, key: []const u8) ?bool {
    const v = obj.get(key) orelse return null;
    return if (v == .bool) v.bool else null;
}

fn codeError(code: []const u8) Error {
    const map = .{
        .{ "bad_request", Error.BadRequest },   .{ "bad_audio", Error.BadAudio },
        .{ "too_long", Error.TooLong },         .{ "busy", Error.Busy },
        .{ "backend_lost", Error.BackendLost }, .{ "unknown_id", Error.UnknownId },
        .{ "not_found", Error.NotFound },       .{ "internal", Error.Internal },
    };
    inline for (map) |m| if (std.mem.eql(u8, code, m[0])) return m[1];
    return Error.Internal;
}

/// Classifies a parsed line; null: not a protocol line (no object, no rid
/// and no event).
pub fn classify(v: std.json.Value) ?Msg {
    if (v != .object) return null;
    const o = v.object;
    if (str(o, "event")) |ev| {
        if (std.mem.eql(u8, ev, "ready")) return .{ .ready = .{
            .proto = int(o, u32, "proto") orelse return null,
            .adapter_version = int(o, u32, "adapter_version") orelse 0,
        } };
        if (std.mem.eql(u8, ev, "wakeup")) {
            const d = o.get("deadline_unix_ms") orelse return null;
            return switch (d) {
                .null => .{ .wakeup = null },
                .integer => |n| .{ .wakeup = n },
                else => null,
            };
        }
        return .other;
    }
    const rid = int(o, u32, "rid") orelse return null;
    if (str(o, "error")) |code| return .{ .failure = .{ .rid = rid, .err = codeError(code) } };
    return .{ .reply = rid };
}

// ------------------------------------------------------------------ engine

const Parsed = std.json.Parsed(std.json.Value);

/// One running stt-local.
const Proc = struct {
    child: std.process.Child,
    stdin: ?Io.File,
    stdout: Io.File,
    stderr: Io.File,
    out_thread: ?std.Thread = null,
    err_thread: ?std.Thread = null,
    // ---- under Engine.mutex
    ready: ?Ready = null,
    /// Its stdout ended (it exited or is exiting).
    dead: bool = false,
    /// A line broke the protocol: it is killed by the caller.
    bad: bool = false,
    /// Asked to stop (not a crash when it goes).
    stopping: bool = false,
    want_rid: u32 = 0,
    reply: ?Parsed = null,
    failure: ?Error = null,
};

pub const Engine = struct {
    gpa: Allocator,
    io: Io,
    timing: Timing = .{},

    /// One call at a time (and start / stop between calls).
    call_lock: Io.Mutex = .init,
    mutex: Io.Mutex = .init,
    cond: Io.Condition = .init,
    // ---- under `mutex`
    cfg: ?Config = null,
    cfg_mem: []u8 = &.{},
    proc: ?*Proc = null,
    next_rid: u32 = 0,
    crashes: u32 = 0,
    /// Real-clock ms before which no new program starts (the backoff).
    retry_at_ms: i64 = 0,
    /// stt's next timed work, as its last wakeup said.
    stt_deadline: ?i64 = null,
    adapter_version: u32 = 0,
    last_err_buf: [200]u8 = undefined,
    last_err_len: usize = 0,

    pub fn init(gpa: Allocator, io: Io) Engine {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(e: *Engine) void {
        e.stop();
        e.gpa.free(e.cfg_mem);
        e.cfg_mem = &.{};
        e.cfg = null;
    }

    fn nowMs(e: *const Engine) i64 {
        return Io.Clock.real.now(e.io).toMilliseconds();
    }

    /// The paths of the next program (copied). A running one keeps its
    /// own until it is stopped. Clears a give-up.
    pub fn configure(e: *Engine, c: Config) !void {
        var total: usize = c.exe.len + c.model.len + c.profile.len + c.device_name.len;
        if (c.adapter) |a| total += a.len;
        if (c.qnn) |q| total += q.len;
        const mem = try e.gpa.alloc(u8, total);
        var at: usize = 0;
        const dup = struct {
            fn f(m: []u8, pos: *usize, s: []const u8) []const u8 {
                @memcpy(m[pos.*..][0..s.len], s);
                defer pos.* += s.len;
                return m[pos.*..][0..s.len];
            }
        }.f;
        var copy = c;
        copy.exe = dup(mem, &at, c.exe);
        copy.model = dup(mem, &at, c.model);
        copy.profile = dup(mem, &at, c.profile);
        copy.device_name = dup(mem, &at, c.device_name);
        if (c.adapter) |a| copy.adapter = dup(mem, &at, a);
        if (c.qnn) |q| copy.qnn = dup(mem, &at, q);
        e.mutex.lockUncancelable(e.io);
        defer e.mutex.unlock(e.io);
        e.gpa.free(e.cfg_mem);
        e.cfg_mem = mem;
        e.cfg = copy;
        e.crashes = 0;
        e.retry_at_ms = 0;
    }

    /// The user asks again after a give-up.
    pub fn retry(e: *Engine) void {
        e.mutex.lockUncancelable(e.io);
        defer e.mutex.unlock(e.io);
        if (e.crashes >= e.timing.max_crashes) {
            e.crashes = 0;
            e.retry_at_ms = 0;
        }
    }

    /// A program is up (it may still be loading).
    pub fn running(e: *Engine) bool {
        e.mutex.lockUncancelable(e.io);
        defer e.mutex.unlock(e.io);
        const p = e.proc orelse return false;
        return !p.dead and !p.bad;
    }

    pub fn gaveUp(e: *Engine) bool {
        e.mutex.lockUncancelable(e.io);
        defer e.mutex.unlock(e.io);
        return e.crashes >= e.timing.max_crashes;
    }

    /// The adapter version the program reported last (0: the base model).
    pub fn adapterVersion(e: *Engine) u32 {
        e.mutex.lockUncancelable(e.io);
        defer e.mutex.unlock(e.io);
        return e.adapter_version;
    }

    /// stt's next timed work while it runs (null: none, or not running).
    pub fn sttDeadline(e: *Engine) ?i64 {
        e.mutex.lockUncancelable(e.io);
        defer e.mutex.unlock(e.io);
        return if (e.proc != null) e.stt_deadline else null;
    }

    /// The last line stt-local wrote to stderr, or why it could not run.
    pub fn lastError(e: *Engine, buf: []u8) []const u8 {
        e.mutex.lockUncancelable(e.io);
        defer e.mutex.unlock(e.io);
        const n = @min(buf.len, e.last_err_len);
        @memcpy(buf[0..n], e.last_err_buf[0..n]);
        return buf[0..n];
    }

    /// Starts the program if it is not running (waits for ready).
    pub fn start(e: *Engine) Error!void {
        e.call_lock.lockUncancelable(e.io);
        defer e.call_lock.unlock(e.io);
        _ = try e.ensure();
    }

    /// Stops the program: stdin closed (it confirms what is pending and
    /// exits), killed if still there after `stop_ms`.
    pub fn stop(e: *Engine) void {
        e.call_lock.lockUncancelable(e.io);
        defer e.call_lock.unlock(e.io);
        e.mutex.lockUncancelable(e.io);
        const p = e.proc orelse {
            e.mutex.unlock(e.io);
            return;
        };
        e.proc = null;
        e.stt_deadline = null;
        p.stopping = true;
        e.mutex.unlock(e.io);
        e.finish(p);
    }

    // ------------------------------------------------------------ requests

    /// 16 kHz mono samples; `gpa` owns the text.
    pub fn transcribe(e: *Engine, gpa: Allocator, pcm: []const i16) Error!Result {
        if (pcm.len > limits.max_samples) return error.TooLong;
        comptime std.debug.assert(builtin.cpu.arch.endian() == .little);
        const raw = std.mem.sliceAsBytes(pcm);
        const enc = std.base64.standard.Encoder;
        const b64 = try e.gpa.alloc(u8, enc.calcSize(raw.len));
        defer e.gpa.free(b64);
        _ = enc.encode(b64, raw);
        var r = try e.call(.{ .op = "transcribe", .pcm_s16le_b64 = b64 }, e.timing.transcribe_ms);
        defer r.deinit();
        const o = r.value.object;
        const id = int(o, u64, "id") orelse return e.broken();
        const text = str(o, "text") orelse return e.broken();
        const kept = limits.capText(text, limits.max_text);
        return .{ .id = id, .text = try gpa.dupe(u8, kept) };
    }

    pub fn feedback(e: *Engine, id: u64, text: []const u8, ok: bool) Error!Outcome {
        var r = try e.call(.{ .op = "feedback", .id = id, .text = text, .ok = ok }, e.timing.call_ms);
        defer r.deinit();
        const out = str(r.value.object, "outcome") orelse return e.broken();
        if (std.mem.eql(u8, out, "learned")) return .learned;
        if (std.mem.eql(u8, out, "discarded")) return .discarded;
        return e.broken();
    }

    /// The next training bundle (owned by `gpa`), null: nothing waits.
    pub fn exportBundle(e: *Engine, gpa: Allocator, max_bytes: usize) Error!?Bundle {
        var r = try e.call(.{ .op = "export_bundle", .max_bytes = @min(max_bytes, max_bundle_bytes) }, e.timing.call_ms);
        defer r.deinit();
        const o = r.value.object;
        const v = o.get("b64") orelse return e.broken();
        if (v == .null) return null;
        if (v != .string) return e.broken();
        const through = int(o, u32, "through") orelse return e.broken();
        const count = int(o, u32, "count") orelse return e.broken();
        const dec = std.base64.standard.Decoder;
        const n = dec.calcSizeForSlice(v.string) catch return e.broken();
        if (n == 0 or n > max_bundle_bytes) return e.broken();
        const bytes = try gpa.alloc(u8, n);
        errdefer gpa.free(bytes);
        dec.decode(bytes, v.string) catch return e.broken();
        return .{ .bytes = bytes, .through = through, .count = count };
    }

    /// Samples home, the device's side of a sync pass: null with learning
    /// off (nothing leaves the device), and the program is started for it
    /// only when training samples wait in the profile.
    pub fn nextBundle(e: *Engine, gpa: Allocator, learning: bool, max_bytes: usize) Error!?Bundle {
        if (!learning) return null;
        if (!e.running() and !e.samplesWaiting()) return null;
        return e.exportBundle(gpa, max_bytes);
    }

    /// stt keeps a training sample as samples/<id>.wav in the profile and
    /// deletes it once the desk stored it.
    pub fn samplesWaiting(e: *Engine) bool {
        var pb: [1100]u8 = undefined;
        e.mutex.lockUncancelable(e.io);
        const c = e.cfg;
        const dir = if (c) |x| std.fmt.bufPrint(&pb, "{s}" ++ std.fs.path.sep_str ++ "samples", .{x.profile}) catch "" else "";
        e.mutex.unlock(e.io);
        if (dir.len == 0) return false;
        var d = Io.Dir.cwd().openDir(e.io, dir, .{ .iterate = true }) catch return false;
        defer d.close(e.io);
        var it = d.iterate();
        while (it.next(e.io) catch null) |ent| if (std.mem.endsWith(u8, ent.name, ".wav")) return true;
        return false;
    }

    /// The desk stored the bundle up to `through`: those samples go.
    pub fn commitExport(e: *Engine, through: u32) Error!void {
        var r = try e.call(.{ .op = "commit_export", .through = through }, e.timing.call_ms);
        r.deinit();
    }

    /// An adapter update, swapped into the running program at once.
    /// Returns the adapter version now in use.
    pub fn importUpdate(e: *Engine, bytes: []const u8) Error!u32 {
        if (bytes.len > max_update_bytes) return error.TooLarge;
        const enc = std.base64.standard.Encoder;
        const b64 = try e.gpa.alloc(u8, enc.calcSize(bytes.len));
        defer e.gpa.free(b64);
        _ = enc.encode(b64, bytes);
        var r = try e.call(.{ .op = "import_update", .b64 = b64 }, e.timing.call_ms);
        defer r.deinit();
        const o = r.value.object;
        const v = int(o, u32, "adapter_version") orelse int(o, u32, "version") orelse return e.broken();
        e.mutex.lockUncancelable(e.io);
        e.adapter_version = v;
        e.mutex.unlock(e.io);
        return v;
    }

    pub fn setLearning(e: *Engine, on: bool) Error!void {
        var r = try e.call(.{ .op = "set_learning", .on = on }, e.timing.call_ms);
        r.deinit();
    }

    pub fn status(e: *Engine) Error!Status {
        var r = try e.call(.{ .op = "status" }, e.timing.call_ms);
        defer r.deinit();
        const o = r.value.object;
        return .{
            .adapter_version = int(o, u32, "adapter_version") orelse return e.broken(),
            .profile_version = int(o, u32, "profile_version") orelse 0,
            .learning = boolean(o, "learning") orelse return e.broken(),
            .pending_export = int(o, u32, "pending_export") orelse 0,
        };
    }

    // ------------------------------------------------------------ inside

    /// A reply without the fields its request promises: the program is not
    /// what it claims; it is killed.
    fn broken(e: *Engine) Error {
        e.mutex.lockUncancelable(e.io);
        const p = e.proc;
        if (p) |x| x.bad = true;
        e.mutex.unlock(e.io);
        if (p) |x| e.kill(x);
        return error.BadReply;
    }

    fn waitUntil(e: *Engine, deadline_ms: i64) bool {
        const left = deadline_ms - e.nowMs();
        if (left <= 0) return false;
        e.cond.waitTimeout(e.io, &e.mutex, .{ .duration = .{ .raw = .fromMilliseconds(left), .clock = .real } }) catch {};
        return true;
    }

    /// One request and its reply (the caller deinits it).
    fn call(e: *Engine, req: anytype, timeout_ms: i64) Error!Parsed {
        e.call_lock.lockUncancelable(e.io);
        defer e.call_lock.unlock(e.io);
        const p = try e.ensure();
        e.mutex.lockUncancelable(e.io);
        e.next_rid +%= 1;
        if (e.next_rid == 0) e.next_rid = 1;
        const rid = e.next_rid;
        p.want_rid = rid;
        p.failure = null;
        e.mutex.unlock(e.io);

        // {"rid":N, then the request's own fields: one line.
        var aw: Io.Writer.Allocating = .init(e.gpa);
        defer aw.deinit();
        aw.writer.print("{{\"rid\":{d},", .{rid}) catch return error.OutOfMemory;
        const head = aw.written().len;
        std.json.Stringify.value(req, .{}, &aw.writer) catch return error.OutOfMemory;
        aw.writer.writeByte('\n') catch return error.OutOfMemory;
        const line = aw.written();
        std.mem.copyForwards(u8, line[head..], line[head + 1 ..]); // the request's '{'
        const bytes = line[0 .. line.len - 1];
        if (bytes.len > max_line) return error.TooLarge;
        p.stdin.?.writeStreamingAll(e.io, bytes) catch {
            e.kill(p);
            return error.Crashed;
        };

        const deadline = e.nowMs() + timeout_ms;
        e.mutex.lockUncancelable(e.io);
        while (p.reply == null and p.failure == null and !p.dead and !p.bad) {
            if (!e.waitUntil(deadline)) break;
        }
        const reply = p.reply;
        p.reply = null;
        const failure = p.failure;
        const dead = p.dead;
        const bad = p.bad;
        p.want_rid = 0;
        if (reply != null or (failure != null and failure.? != error.BackendLost)) e.crashes = 0;
        e.mutex.unlock(e.io);
        if (reply) |r| return r;
        if (failure) |f| {
            // The engine failed for good: the next call gets a new program.
            if (f == error.BackendLost) e.kill(p);
            return f;
        }
        if (bad) {
            e.kill(p);
            return error.BadReply;
        }
        if (dead) return error.Crashed;
        std.log.warn("speech: stt-local did not answer in {d} ms: stopped", .{timeout_ms});
        e.kill(p);
        return error.Timeout;
    }

    /// The running program, or a new one (after the backoff). Under
    /// call_lock.
    fn ensure(e: *Engine) Error!*Proc {
        e.mutex.lockUncancelable(e.io);
        if (e.proc) |p| {
            if (!p.dead and !p.bad) {
                e.mutex.unlock(e.io);
                return p;
            }
            e.proc = null;
            e.stt_deadline = null;
            e.mutex.unlock(e.io);
            e.finish(p);
            e.mutex.lockUncancelable(e.io);
        }
        defer e.mutex.unlock(e.io);
        const cfg = e.cfg orelse return error.NotConfigured;
        if (e.crashes >= e.timing.max_crashes) return error.GaveUp;
        // The backoff after a crash: a deadline, nothing else wakes it.
        while (e.waitUntil(e.retry_at_ms)) {}
        e.mutex.unlock(e.io);
        const p = e.spawn(cfg) catch |err| {
            e.mutex.lockUncancelable(e.io);
            e.crashed();
            const t = std.fmt.bufPrint(&e.last_err_buf, "stt-local could not be started ({t})", .{err}) catch "";
            e.last_err_len = t.len;
            std.log.warn("speech: {s}", .{t});
            return error.StartFailed;
        };
        e.mutex.lockUncancelable(e.io);
        const deadline = e.nowMs() + e.timing.ready_ms;
        while (p.ready == null and !p.dead and !p.bad) {
            if (!e.waitUntil(deadline)) break;
        }
        const ready = p.ready;
        const dead = p.dead;
        e.mutex.unlock(e.io);
        const r = ready orelse {
            if (!dead) {
                std.log.warn("speech: stt-local did not get ready in {d} ms: stopped", .{e.timing.ready_ms});
                e.kill(p);
            }
            e.finish(p);
            e.mutex.lockUncancelable(e.io);
            return if (dead) error.StartFailed else error.Timeout;
        };
        if (r.proto != proto) {
            std.log.warn("speech: stt-local speaks protocol {d}, Portal {d}: not used", .{ r.proto, proto });
            e.kill(p);
            e.finish(p);
            e.mutex.lockUncancelable(e.io);
            // A newer package fixes this, not a restart.
            e.crashes = e.timing.max_crashes;
            return error.ProtocolMismatch;
        }
        e.mutex.lockUncancelable(e.io);
        e.adapter_version = r.adapter_version;
        e.proc = p;
        return p;
    }

    /// Under `mutex`: one more crash in a row, and the backoff.
    fn crashed(e: *Engine) void {
        e.crashes +|= 1;
        const shift: u6 = @intCast(@min(e.crashes - 1, 20));
        const wait = @min(e.timing.backoff_ms << shift, e.timing.backoff_max_ms);
        e.retry_at_ms = e.nowMs() + wait;
    }

    fn spawn(e: *Engine, cfg: Config) !*Proc {
        var argv: [16][]const u8 = undefined;
        var n: usize = 0;
        var vb: [16]u8 = undefined;
        for ([_][]const u8{ cfg.exe, "--model", cfg.model, "--profile", cfg.profile, "--device-name", cfg.device_name }) |a| {
            argv[n] = a;
            n += 1;
        }
        if (cfg.adapter) |a| {
            argv[n..][0..4].* = .{ "--adapter", a, "--adapter-version", std.fmt.bufPrint(&vb, "{d}", .{cfg.adapter_version}) catch unreachable };
            n += 4;
        }
        if (cfg.qnn) |q| {
            argv[n..][0..2].* = .{ "--qnn", q };
            n += 2;
        }
        const p = try e.gpa.create(Proc);
        errdefer e.gpa.destroy(p);
        const child = try std.process.spawn(e.io, .{
            .argv = argv[0..n],
            .exe = .{ .path = Io.Dir.cwd() },
            // Its own read-only folder: a stray relative write fails.
            .cwd = .{ .path = std.fs.path.dirname(cfg.exe) orelse "." },
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .pipe,
            .create_no_window = true,
        });
        // The pipes are this side's to close (after the readers end), not
        // the child's cleanup (which would close them under a reader).
        p.* = .{ .child = child, .stdin = child.stdin, .stdout = child.stdout.?, .stderr = child.stderr.? };
        p.child.stdin = null;
        p.child.stdout = null;
        p.child.stderr = null;
        p.out_thread = std.Thread.spawn(.{}, readOut, .{ e, p }) catch null;
        p.err_thread = std.Thread.spawn(.{}, readErr, .{ e, p }) catch null;
        if (p.out_thread == null or p.err_thread == null) {
            p.stopping = true;
            e.kill(p);
            e.finish(p);
            return error.SystemResources;
        }
        return p;
    }

    /// Kills it (a hang, a broken line, a lost backend); its readers then
    /// see their pipes end.
    fn kill(e: *Engine, p: *Proc) void {
        e.mutex.lockUncancelable(e.io);
        const was_dead = p.dead;
        // Never used again, from now (its reader ends a moment later).
        p.bad = true;
        e.mutex.unlock(e.io);
        if (p.child.id != null) {
            if (!was_dead) std.log.warn("speech: stt-local stopped by force", .{});
            p.child.kill(e.io);
        }
    }

    /// Ends `p` (no longer e.proc): stdin closed, a wait for it to go,
    /// a kill past `stop_ms`, the readers joined, everything closed.
    fn finish(e: *Engine, p: *Proc) void {
        if (p.stdin) |f| f.close(e.io);
        p.stdin = null;
        const deadline = e.nowMs() + e.timing.stop_ms;
        e.mutex.lockUncancelable(e.io);
        while (!p.dead and p.out_thread != null) {
            if (!e.waitUntil(deadline)) break;
        }
        const dead = p.dead or p.out_thread == null;
        e.mutex.unlock(e.io);
        if (!dead) {
            std.log.warn("speech: stt-local did not stop in {d} ms", .{e.timing.stop_ms});
            e.kill(p);
        }
        if (p.out_thread) |t| t.join();
        if (p.err_thread) |t| t.join();
        if (p.child.id != null) _ = p.child.wait(e.io) catch p.child.kill(e.io);
        p.stdout.close(e.io);
        p.stderr.close(e.io);
        if (p.reply) |*r| r.deinit();
        e.gpa.destroy(p);
    }

    /// stdout: replies and events, until it ends.
    fn readOut(e: *Engine, p: *Proc) void {
        defer {
            e.mutex.lockUncancelable(e.io);
            p.dead = true;
            if (!p.stopping) e.crashed();
            e.mutex.unlock(e.io);
            e.cond.broadcast(e.io);
        }
        const buf = e.gpa.alloc(u8, max_line + 1) catch return;
        defer e.gpa.free(buf);
        var r = p.stdout.readerStreaming(e.io, buf);
        while (true) {
            const got = r.interface.takeDelimiter('\n') catch |err| {
                if (err == error.StreamTooLong) {
                    std.log.warn("speech: stt-local wrote a line over 8 MiB", .{});
                    e.mutex.lockUncancelable(e.io);
                    p.bad = true;
                    e.mutex.unlock(e.io);
                    e.cond.broadcast(e.io);
                }
                return;
            };
            const line = got orelse return;
            e.onLine(p, std.mem.trim(u8, line, " \t\r"));
        }
    }

    fn onLine(e: *Engine, p: *Proc, line: []const u8) void {
        if (line.len == 0) return;
        var parsed = std.json.parseFromSlice(std.json.Value, e.gpa, line, .{}) catch {
            std.log.warn("speech: stt-local wrote a line that is not JSON ({d} bytes): ignored", .{line.len});
            return;
        };
        const msg = classify(parsed.value) orelse {
            parsed.deinit();
            std.log.warn("speech: stt-local wrote a line that is not protocol 1: ignored", .{});
            return;
        };
        e.mutex.lockUncancelable(e.io);
        defer e.mutex.unlock(e.io);
        var keep = false;
        switch (msg) {
            .ready => |rd| if (p.ready == null) {
                p.ready = rd;
            },
            .wakeup => |d| e.stt_deadline = d,
            .other => {},
            .reply => |rid| if (rid == p.want_rid and rid != 0 and p.reply == null) {
                p.reply = parsed;
                keep = true;
            },
            // rid 0: stt-local could not read the request at all.
            .failure => |f| if (p.want_rid != 0 and (f.rid == p.want_rid or f.rid == 0)) {
                p.failure = f.err;
            },
        }
        if (!keep) parsed.deinit();
        e.cond.broadcast(e.io);
    }

    /// stderr: stt-local's log, into Portal's; the last line kept.
    fn readErr(e: *Engine, p: *Proc) void {
        var buf: [1024]u8 = undefined;
        var r = p.stderr.readerStreaming(e.io, &buf);
        while (true) {
            const got = r.interface.takeDelimiter('\n') catch |err| switch (err) {
                error.StreamTooLong => {
                    _ = r.interface.discardDelimiterInclusive('\n') catch return;
                    continue;
                },
                else => return,
            };
            const line = got orelse return;
            const t = std.mem.trim(u8, line, " \t\r");
            if (t.len == 0) continue;
            std.log.info("stt-local: {s}", .{t});
            e.mutex.lockUncancelable(e.io);
            const n = limits.capText(t, e.last_err_buf.len).len;
            @memcpy(e.last_err_buf[0..n], t[0..n]);
            e.last_err_len = n;
            e.mutex.unlock(e.io);
        }
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;
const options = @import("speech_options");

test "classify: events, replies, errors; anything else is not protocol" {
    const gpa = testing.allocator;
    const cases = .{
        .{ "{\"event\":\"ready\",\"proto\":1,\"version\":\"0.1.0\",\"backend\":\"htp\",\"model\":\"m\",\"adapter_version\":4}", Msg{ .ready = .{ .proto = 1, .adapter_version = 4 } } },
        .{ "{\"event\":\"wakeup\",\"deadline_unix_ms\":123}", Msg{ .wakeup = 123 } },
        .{ "{\"event\":\"wakeup\",\"deadline_unix_ms\":null}", Msg{ .wakeup = null } },
        .{ "{\"event\":\"later\"}", Msg.other },
        .{ "{\"rid\":7,\"id\":1,\"text\":\"x\"}", Msg{ .reply = 7 } },
        .{ "{\"rid\":3,\"error\":\"backend_lost\",\"message\":\"m\"}", Msg{ .failure = .{ .rid = 3, .err = error.BackendLost } } },
        .{ "{\"rid\":3,\"error\":\"what\"}", Msg{ .failure = .{ .rid = 3, .err = error.Internal } } },
    };
    inline for (cases) |c| {
        var p = try std.json.parseFromSlice(std.json.Value, gpa, c[0], .{});
        defer p.deinit();
        try testing.expectEqualDeep(@as(?Msg, c[1]), classify(p.value));
    }
    for ([_][]const u8{ "[1]", "{}", "{\"rid\":-1}", "{\"rid\":4294967296}", "{\"event\":\"ready\"}", "{\"event\":\"wakeup\",\"deadline_unix_ms\":\"x\"}", "{\"event\":\"ready\",\"proto\":\"1\"}" }) |t| {
        var p = try std.json.parseFromSlice(std.json.Value, gpa, t, .{});
        defer p.deinit();
        try testing.expect(classify(p.value) == null);
    }
}

/// A fake stt-local (fake_stt_local.zig, built by `zig build test`) with a
/// profile in a temporary folder; its model is the fake itself.
pub const TestFixture = struct {
    tmp: testing.TmpDir,
    profile_buf: [1024]u8 = undefined,
    profile: []const u8 = "",
    /// The fake's absolute path (it runs in its own folder).
    exe_buf: [1024]u8 = undefined,
    exe: []const u8 = "",
    engine: Engine,

    pub fn init(f: *TestFixture) !void {
        f.* = .{ .tmp = testing.tmpDir(.{}), .engine = .init(testing.allocator, testing.io) };
        f.profile = f.profile_buf[0..try f.tmp.dir.realPath(testing.io, &f.profile_buf)];
        f.exe = f.exe_buf[0..try Io.Dir.cwd().realPathFile(testing.io, options.fake_stt_local, &f.exe_buf)];
        f.engine.timing = .{ .ready_ms = 20_000, .call_ms = 20_000, .transcribe_ms = 20_000, .stop_ms = 5_000, .backoff_ms = 10, .backoff_max_ms = 40, .max_crashes = 3 };
        try f.engine.configure(.{ .exe = f.exe, .model = f.exe, .profile = f.profile });
    }

    pub fn deinit(f: *TestFixture) void {
        f.engine.deinit();
        f.tmp.cleanup();
    }
};

/// A clip whose first sample tells the fake what to do.
fn clip(first: i16) [64]i16 {
    var b: [64]i16 = @splat(100);
    b[0] = first;
    return b;
}

test "stt-local: ready, transcribe, feedback, export and commit, status, stop" {
    if (options.fake_stt_local.len == 0) return error.SkipZigTest;
    var f: TestFixture = undefined;
    try f.init();
    defer f.deinit();
    const e = &f.engine;
    try testing.expect(!e.running());
    const c = clip(1);
    const r = try e.transcribe(testing.allocator, &c);
    defer testing.allocator.free(r.text);
    try testing.expect(e.running());
    try testing.expectEqualStrings("heard 64 samples", r.text);
    try testing.expectEqual(@as(u64, 1), r.id);
    // No adapter file: version 0; the wakeup seen.
    try testing.expectEqual(@as(u32, 0), e.adapterVersion());
    try testing.expectEqual(@as(?i64, 4_000_000_000_000), e.sttDeadline());
    try testing.expectEqual(Outcome.learned, try e.feedback(r.id, "fixed \"text\"\n", true));
    try testing.expectError(error.UnknownId, e.feedback(99, "x", true));
    try testing.expectEqual(@as(u32, 1), (try e.status()).pending_export);
    const b = (try e.exportBundle(testing.allocator, 8 << 20)).?;
    defer testing.allocator.free(b.bytes);
    try testing.expectEqualStrings("BUNDLE 1", b.bytes);
    try testing.expectEqual(@as(u32, 1), b.through);
    try e.commitExport(b.through);
    try testing.expectEqual(@as(?Bundle, null), try e.exportBundle(testing.allocator, 8 << 20));
    try e.setLearning(false);
    try testing.expect(!(try e.status()).learning);
    const long = try testing.allocator.alloc(i16, limits.max_samples + 1);
    defer testing.allocator.free(long);
    try testing.expectError(error.TooLong, e.transcribe(testing.allocator, long));
    e.stop();
    try testing.expect(!e.running());
    try testing.expectEqual(@as(?i64, null), e.sttDeadline());
}

test "stt-local: the adapter at start, and import_update swapped into the running program" {
    if (options.fake_stt_local.len == 0) return error.SkipZigTest;
    var f: TestFixture = undefined;
    try f.init();
    defer f.deinit();
    const e = &f.engine;
    try f.tmp.dir.writeFile(testing.io, .{ .sub_path = "adapter.bin", .data = "raw" });
    var ab: [1100]u8 = undefined;
    const adapter = try std.fmt.bufPrint(&ab, "{s}/adapter.bin", .{f.profile});
    try e.configure(.{ .exe = f.exe, .model = f.exe, .profile = f.profile, .adapter = adapter, .adapter_version = 2 });
    try e.start();
    try testing.expectEqual(@as(u32, 2), e.adapterVersion());
    try testing.expectEqual(@as(u32, 5), try e.importUpdate("STTUPD015"));
    try testing.expectEqual(@as(u32, 5), (try e.status()).adapter_version);
    try testing.expectError(error.BadRequest, e.importUpdate("not an update"));
    try testing.expect(e.running());
    const big = try testing.allocator.alloc(u8, max_update_bytes + 1);
    defer testing.allocator.free(big);
    try testing.expectError(error.TooLarge, e.importUpdate(big));
}

test "stt-local: a crash fails the call, the next one restarts it; give-up after crashes in a row" {
    if (options.fake_stt_local.len == 0) return error.SkipZigTest;
    var f: TestFixture = undefined;
    try f.init();
    defer f.deinit();
    const e = &f.engine;
    const crash = clip(0x7777);
    try testing.expectError(error.Crashed, e.transcribe(testing.allocator, &crash));
    try testing.expect(!e.running());
    try testing.expectEqual(@as(u32, 1), e.crashes);
    // Restarted after the backoff; the fake crashes only once.
    const r = try e.transcribe(testing.allocator, &crash);
    testing.allocator.free(r.text);
    try testing.expect(e.running());
    try testing.expectEqual(@as(u32, 0), e.crashes);
    // backend_lost: stopped, and the next call gets a new program.
    const lost = clip(0x5555);
    try testing.expectError(error.BackendLost, e.transcribe(testing.allocator, &lost));
    try testing.expect(!e.running());
    const ok = clip(1);
    const r2 = try e.transcribe(testing.allocator, &ok);
    testing.allocator.free(r2.text);
    // A program that never starts: given up after max_crashes, until retry.
    var buf: [200]u8 = undefined;
    e.stop();
    try e.configure(.{ .exe = f.exe, .model = "no-such-model.bin", .profile = f.profile });
    for (0..3) |_| try testing.expectError(error.StartFailed, e.start());
    try testing.expectError(error.GaveUp, e.start());
    try testing.expect(e.gaveUp());
    try testing.expect(std.mem.indexOf(u8, e.lastError(&buf), "cannot start") != null);
    e.retry();
    try testing.expectError(error.StartFailed, e.start());
    // A missing program: a start failure too.
    try e.configure(.{ .exe = "no-such-stt-local.exe", .model = "m", .profile = f.profile });
    try testing.expectError(error.StartFailed, e.start());
    try testing.expect(std.mem.indexOf(u8, e.lastError(&buf), "could not be started") != null);
}

test "fitsThisMachine: the host's own program fits; anything else does not" {
    if (options.fake_stt_local.len == 0) return error.SkipZigTest;
    try testing.expectEqual(builtin.os.tag == .windows, fitsThisMachine(testing.io, options.fake_stt_local));
    try testing.expect(!fitsThisMachine(testing.io, "no-such-stt-local.exe"));
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "x.exe", .data = "MZ not really" });
    var pb: [1024]u8 = undefined;
    const dir = pb[0..try tmp.dir.realPath(testing.io, &pb)];
    var xb: [1100]u8 = undefined;
    try testing.expect(!fitsThisMachine(testing.io, try std.fmt.bufPrint(&xb, "{s}/x.exe", .{dir})));
}

test "stt-local: a hang is stopped at the deadline; the next call works" {
    if (options.fake_stt_local.len == 0) return error.SkipZigTest;
    var f: TestFixture = undefined;
    try f.init();
    defer f.deinit();
    const e = &f.engine;
    e.timing.transcribe_ms = 300;
    const hang = clip(0x6666);
    try testing.expectError(error.Timeout, e.transcribe(testing.allocator, &hang));
    try testing.expect(!e.running());
    const ok = clip(1);
    const r = try e.transcribe(testing.allocator, &ok);
    testing.allocator.free(r.text);
}

test "samples home: nothing with learning off; started only when samples wait; deleted only after the desk's 200" {
    if (options.fake_stt_local.len == 0) return error.SkipZigTest;
    var f: TestFixture = undefined;
    try f.init();
    defer f.deinit();
    const e = &f.engine;
    const gpa = testing.allocator;
    // Nothing waits: the program is not started for a sync pass.
    try testing.expectEqual(@as(?Bundle, null), try e.nextBundle(gpa, true, 2 << 20));
    try testing.expect(!e.running());
    // Two corrections learned, then the program went (idle).
    const c = clip(1);
    for (0..2) |_| {
        const r = try e.transcribe(gpa, &c);
        defer gpa.free(r.text);
        try testing.expectEqual(Outcome.learned, try e.feedback(r.id, "corrected", true));
    }
    e.stop();
    try testing.expect(e.samplesWaiting());
    // Learning off: nothing leaves, and nothing starts.
    try testing.expectEqual(@as(?Bundle, null), try e.nextBundle(gpa, false, 2 << 20));
    try testing.expect(!e.running());
    // The desk answers 503 (busy) and then 200: what connect.sendSamples
    // does with each answer (commit only after 200).
    for ([_]u16{ 503, 200 }) |code| {
        const b = (try e.nextBundle(gpa, true, 2 << 20)).?;
        defer gpa.free(b.bytes);
        try testing.expect(e.running());
        try testing.expectEqualStrings("BUNDLE 1 2", b.bytes);
        if (code == 200) try e.commitExport(b.through);
        e.stop();
        try testing.expectEqual(code != 200, e.samplesWaiting());
    }
    try testing.expectEqual(@as(?Bundle, null), try e.nextBundle(gpa, true, 2 << 20));
    try testing.expect(!e.running());
}
