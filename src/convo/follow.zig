//! Finds and follows a tab's transcript (transcript.zig) for its
//! Conversation view, event-driven; nothing is polled:
//!   * directory change notifications (ReadDirectoryChangesW) report new
//!     transcripts (`/clear`, `/resume`) and, where NTFS reports them,
//!     appends;
//!   * the tab's program producing output (or changing its OSC 7501 state,
//!     which is output too) pokes the follower (`Poke`), which then checks
//!     the followed transcript's size on its own handle. NTFS does not
//!     report size changes made through a handle the writer keeps open
//!     until its metadata is flushed, so notifications alone could lag;
//!     the program always prints while it writes its transcript. Pokes
//!     are coalesced: at most one size check per `poke_batch_ms` (the
//!     viewers' frame interval), and none while the program is quiet.
//!
//! Which transcript is the tab's: when Portal started the agent with
//! `--session-id <uuid>` (tabs.zig, cmdline.wantsSessionId), exactly
//! `<projects>\<encoded cwd>\<uuid>.jsonl`, waited for until it appears;
//! nothing else is considered before it. After it (and when no id could be
//! given, e.g. `--resume` in the configured command) the rules below decide,
//! so `/clear` and `/resume` inside the session are followed too.
//!
//! The tab's working directory names the folder (`<projects>\<encoded
//! cwd>`). When the tab starts, the sizes of
//! the transcripts already there are noted. A transcript then belongs to
//! the tab when it is new or has grown since (its program started or
//! resumed it after the tab did), its records' `cwd` is the tab's folder
//! (or inside it; folder names can collide, e.g. `a-b` and `a\b`), and no
//! other tab claimed it. When another one starts growing later (`/clear`
//! starts a new session file, `/resume` continues an old one), the view
//! moves to it and starts over.
//!
//! Without a transcript (none yet, the projects folder missing, or the
//! program not keeping one) the view says so; the terminal is unaffected.
//!
//! Memory: one line buffer of at most `max_line` bytes (a longer line is
//! cut, and what came before the cut is still read), one record
//! (transcript.Record), and the noted sizes. A transcript bigger than
//! `max_initial` when first read is read from its last `tail_read` bytes.

const std = @import("std");
const Allocator = std.mem.Allocator;
const w = @import("../win32.zig");
const fsutil = @import("../fsutil.zig");
const transcript = @import("transcript.zig");

/// Longest transcript line kept whole.
pub const max_line = 512 * 1024;
/// A transcript bigger than this when first read ...
pub const max_initial = 32 << 20;
/// ... is read from this far before its end (the view keeps only the
/// latest items anyway).
pub const tail_read = 8 << 20;
/// How much of a transcript's beginning is read to confirm whose it is.
const confirm_bytes = 256 * 1024;
/// Pokes closer together than this share one size check (web.zig's
/// frame interval: output is shown at most this often anyway).
pub const poke_batch_ms = 33;

/// "The tab's program printed something": wakes the follower to look at
/// its transcript's size. `poke` is cheap and never blocks (an atomic
/// flag; the event is set only on the first poke after a check).
pub const Poke = struct {
    ev: w.HANDLE,
    pending: std.atomic.Value(bool) = .init(false),

    /// An auto-reset event; null if it cannot be made (no pokes then).
    pub fn init() ?Poke {
        const ev = w.validHandle(w.CreateEventW(null, 0, 0, null)) orelse return null;
        return .{ .ev = ev };
    }

    pub fn deinit(p: *Poke) void {
        _ = w.CloseHandle(p.ev);
    }

    pub fn poke(p: *Poke) void {
        if (p.pending.swap(true, .acq_rel)) return;
        _ = w.SetEvent(p.ev);
    }
};

/// Where the follower delivers what it reads. Called on the follower's
/// thread; each call takes whatever lock the conversation needs.
pub const Sink = struct {
    ctx: *anyopaque,
    /// One record of the transcript followed.
    apply: *const fn (ctx: *anyopaque, rec: *const transcript.Record) void,
    /// The view starts over: a transcript is followed now (`on`), or none.
    reset: *const fn (ctx: *anyopaque, on: bool) void,
    /// Claims transcript `stem` for this tab; false if another tab has it.
    claim: *const fn (ctx: *anyopaque, stem: []const u8) bool,
};

/// ReadDirectoryChangesW on one directory, overlapped, so the waiting
/// thread can also wait for its stop event. Heap-allocated: the buffer
/// must not move while a read is pending.
pub const DirChanges = struct {
    gpa: Allocator,
    dir: w.HANDLE,
    ev: w.HANDLE,
    ov: w.OVERLAPPED = .{},
    filter: w.DWORD,
    pending: bool = false,
    buf: [32 * 1024]u8 align(8) = undefined,

    pub fn open(gpa: Allocator, path: []const u8, filter: w.DWORD) !*DirChanges {
        const pw = try fsutil.wide(gpa, path);
        defer gpa.free(pw);
        const dir = w.validHandle(w.CreateFileW(pw.ptr, w.FILE_LIST_DIRECTORY, w.FILE_SHARE_READ | w.FILE_SHARE_WRITE | w.FILE_SHARE_DELETE, null, w.OPEN_EXISTING, w.FILE_FLAG_BACKUP_SEMANTICS | w.FILE_FLAG_OVERLAPPED, null)) orelse return error.OpenFailed;
        errdefer _ = w.CloseHandle(dir);
        const ev = w.validHandle(w.CreateEventW(null, 1, 0, null)) orelse return error.OpenFailed;
        errdefer _ = w.CloseHandle(ev);
        const d = try gpa.create(DirChanges);
        d.* = .{ .gpa = gpa, .dir = dir, .ev = ev, .filter = filter };
        return d;
    }

    /// Starts the next read; changes made since the last one are already
    /// queued by the system, so none is lost between reads.
    pub fn arm(d: *DirChanges) !void {
        if (d.pending) return;
        _ = w.ResetEvent(d.ev);
        d.ov = .{ .hEvent = d.ev };
        if (w.ReadDirectoryChangesW(d.dir, &d.buf, d.buf.len, 0, d.filter, null, &d.ov, null) == 0) return error.WatchFailed;
        d.pending = true;
    }

    pub const Batch = struct {
        /// The system dropped changes (its buffer overflowed): look at
        /// everything again.
        overflow: bool,
        data: []const u8,

        /// Names (UTF-16) of the changed entries, in order.
        pub fn next(b: *Batch, out: []u8) ?[]const u8 {
            while (b.data.len >= @sizeOf(w.FILE_NOTIFY_INFORMATION)) {
                const info: *align(1) const w.FILE_NOTIFY_INFORMATION = @ptrCast(b.data.ptr);
                const name_len = info.FileNameLength;
                const hdr = @sizeOf(w.FILE_NOTIFY_INFORMATION);
                const rest = b.data;
                b.data = if (info.NextEntryOffset == 0 or info.NextEntryOffset > rest.len) rest[rest.len..] else rest[info.NextEntryOffset..];
                if (hdr + name_len > rest.len) return null;
                const raw = rest[hdr..][0..name_len];
                var units: [260]u16 = undefined;
                const n = @min(raw.len / 2, units.len);
                for (0..n) |i| units[i] = std.mem.readInt(u16, raw[2 * i ..][0..2], .little);
                const len = std.unicode.wtf16LeToWtf8(out, units[0..n]);
                return out[0..len];
            }
            return null;
        }
    };

    /// After `ev` was signalled: what changed. Error if the directory is
    /// gone or can no longer be watched.
    pub fn collect(d: *DirChanges) !Batch {
        var n: w.DWORD = 0;
        const ok = w.GetOverlappedResult(d.dir, &d.ov, &n, 0);
        if (ok == 0 and w.GetLastError() == w.ERROR_IO_INCOMPLETE) return .{ .overflow = false, .data = &.{} };
        d.pending = false;
        if (ok == 0) return error.WatchFailed;
        if (n == 0) return .{ .overflow = true, .data = &.{} };
        return .{ .overflow = false, .data = d.buf[0..@min(n, d.buf.len)] };
    }

    pub fn close(d: *DirChanges) void {
        if (d.pending) {
            _ = w.CancelIoEx(d.dir, &d.ov);
            var n: w.DWORD = 0;
            _ = w.GetOverlappedResult(d.dir, &d.ov, &n, 1);
        }
        _ = w.CloseHandle(d.dir);
        _ = w.CloseHandle(d.ev);
        d.gpa.destroy(d);
    }
};

const Current = struct {
    stem: [36]u8,
    offset: u64,
};

pub const Follower = struct {
    gpa: Allocator,
    sink: Sink,
    /// `<projects>`: the agent's projects folder.
    projects: []const u8,
    /// The tab's working directory (normalized).
    cwd: []const u8,
    /// `<projects>\<folder>` once it exists (owned).
    folder: ?[]u8 = null,
    /// Sizes of the transcripts there when the tab started (owned keys).
    start_sizes: std.StringHashMapUnmanaged(u64) = .empty,
    noted: bool = false,
    /// Transcripts whose `cwd` is not the tab's (owned keys).
    rejected: std.StringHashMapUnmanaged(void) = .empty,
    /// New transcripts not yet known to be the tab's (no `cwd` written
    /// yet): looked at again on every poke, since appends through a handle
    /// the program keeps open may never be reported.
    unsure: [8][36]u8 = undefined,
    n_unsure: usize = 0,
    cur: ?Current = null,
    /// The session id Portal gave the program (`--session-id`): its
    /// transcript is the tab's, and nothing else is until it appeared.
    expected: ?[36]u8 = null,
    expected_seen: bool = false,
    line: std.ArrayList(u8) = .empty,
    line_cut: bool = false,
    /// Reading started mid-file: the first line is partial, dropped.
    skip_partial: bool = false,
    rec: *transcript.Record,
    /// Wakes of the wait loop (tests and the log measure idle cost).
    wakes: u32 = 0,

    pub fn init(gpa: Allocator, sink: Sink, projects: []const u8, cwd: []const u8) !Follower {
        return .{
            .gpa = gpa,
            .sink = sink,
            .projects = projects,
            .cwd = transcript.normalizeCwd(cwd),
            .rec = try gpa.create(transcript.Record),
        };
    }

    pub fn deinit(f: *Follower) void {
        if (f.folder) |p| f.gpa.free(p);
        var it = f.start_sizes.keyIterator();
        while (it.next()) |k| f.gpa.free(k.*);
        f.start_sizes.deinit(f.gpa);
        var it2 = f.rejected.keyIterator();
        while (it2.next()) |k| f.gpa.free(k.*);
        f.rejected.deinit(f.gpa);
        f.line.deinit(f.gpa);
        f.gpa.destroy(f.rec);
    }

    /// Follows until `stop` is signalled. Never polls: it blocks on change
    /// notifications, `poke` (the program printed) and `stop` only.
    pub fn run(f: *Follower, stop: w.HANDLE, poke: ?*Poke) void {
        // No folder yet: nothing existed before the tab started, so the
        // first transcript to appear is new.
        f.resolveFolder() catch {};
        if (f.folder == null) f.noted = true;
        while (true) {
            if (f.folder == null) {
                f.resolveFolder() catch {};
                if (f.folder == null) {
                    if (f.waitForFolder(stop)) return;
                    continue;
                }
            }
            const dc = DirChanges.open(f.gpa, f.folder.?, w.FILE_NOTIFY_CHANGE_FILE_NAME | w.FILE_NOTIFY_CHANGE_SIZE | w.FILE_NOTIFY_CHANGE_LAST_WRITE) catch {
                f.lostFolder();
                if (f.waitForFolder(stop)) return;
                continue;
            };
            defer dc.close();
            dc.arm() catch {
                f.lostFolder();
                continue;
            };
            f.rescan();
            while (true) {
                const hs = [_]w.HANDLE{ stop, dc.ev, if (poke) |p| p.ev else stop };
                const r = w.WaitForMultipleObjects(if (poke != null) 3 else 2, &hs, 0, w.INFINITE);
                f.wakes +|= 1;
                if (r == w.WAIT_OBJECT_0 + 2) {
                    // The program printed: coalesce a burst of output into
                    // one look at the transcript's size.
                    if (w.WaitForSingleObject(stop, poke_batch_ms) == w.WAIT_OBJECT_0) return;
                    poke.?.pending.store(false, .release);
                    f.recheck();
                    continue;
                }
                if (r != w.WAIT_OBJECT_0 + 1) return; // stop, or the wait failed
                var batch = dc.collect() catch break;
                dc.arm() catch break;
                if (batch.overflow) {
                    f.rescan();
                    continue;
                }
                var nb: [1024]u8 = undefined;
                while (batch.next(&nb)) |name| f.changed(name);
            }
            f.lostFolder();
        }
    }

    fn lostFolder(f: *Follower) void {
        if (f.folder) |p| f.gpa.free(p);
        f.folder = null;
    }

    /// Blocks until something appears in the nearest existing ancestor of
    /// the folder (or `stop`). True if stopped.
    fn waitForFolder(f: *Follower, stop: w.HANDLE) bool {
        var name_buf: [1024]u8 = undefined;
        const name = transcript.folderName(f.cwd, &name_buf) catch return waitStop(stop);
        var pb: [2048]u8 = undefined;
        const want = fsutil.join(&pb, &.{ f.projects, name[0..@min(name.len, transcript.max_folder)] }) catch return waitStop(stop);
        var anc: []const u8 = want;
        while (!f.exists(anc)) anc = std.fs.path.dirnameWindows(anc) orelse return waitStop(stop);
        if (anc.len == want.len) return false; // there now
        var dw = fsutil.DirWatch.open(f.gpa, anc, .{ .dirs = true }) catch return waitStop(stop);
        defer dw.close();
        // It may have appeared while the watch was being set up.
        f.resolveFolder() catch {};
        if (f.folder != null) return false;
        const hs = [_]w.HANDLE{ stop, dw.h };
        const r = w.WaitForMultipleObjects(2, &hs, 0, w.INFINITE);
        f.wakes +|= 1;
        return r != w.WAIT_OBJECT_0 + 1;
    }

    fn waitStop(stop: w.HANDLE) bool {
        _ = w.WaitForSingleObject(stop, w.INFINITE);
        return true;
    }

    fn exists(f: *Follower, path: []const u8) bool {
        const pw = fsutil.wide(f.gpa, path) catch return false;
        defer f.gpa.free(pw);
        const a = w.GetFileAttributesW(pw.ptr);
        return a != w.INVALID_FILE_ATTRIBUTES and a & w.FILE_ATTRIBUTE_DIRECTORY != 0;
    }

    /// Sets `folder` if the transcript folder exists. Names over
    /// `max_folder` characters carry a hash suffix: matched by prefix.
    fn resolveFolder(f: *Follower) !void {
        if (f.folder != null) return;
        var name_buf: [1024]u8 = undefined;
        const name = try transcript.folderName(f.cwd, &name_buf);
        var pb: [2048]u8 = undefined;
        if (name.len <= transcript.max_folder) {
            const p = try fsutil.join(&pb, &.{ f.projects, name });
            if (f.exists(p)) f.folder = try f.gpa.dupe(u8, p);
            return;
        }
        var pat_buf: [2048]u8 = undefined;
        const pat = try std.fmt.bufPrint(&pat_buf, "{s}\\{s}-*", .{ f.projects, name[0..transcript.max_folder] });
        var it = try Find.open(f.gpa, pat);
        defer it.close();
        var nb: [1024]u8 = undefined;
        while (it.next(&nb)) |e| if (e.dir) {
            f.folder = try f.gpa.dupe(u8, try fsutil.join(&pb, &.{ f.projects, e.name }));
            return;
        };
    }

    /// Notes what is there (first time), or looks at every transcript
    /// again (after an overflow, or the folder (re)appearing): follows the
    /// newest one that belongs to the tab, then reads on.
    fn rescan(f: *Follower) void {
        const folder = f.folder orelse return;
        var pat_buf: [2048]u8 = undefined;
        const pat = std.fmt.bufPrint(&pat_buf, "{s}\\*.jsonl", .{folder}) catch return;
        var it = Find.open(f.gpa, pat) catch return;
        defer it.close();
        const first = !f.noted;
        f.noted = true;
        var best: ?struct { stem: [36]u8, time: u64 } = null;
        var nb: [1024]u8 = undefined;
        while (it.next(&nb)) |e| {
            if (e.dir) continue;
            const stem = stemOf(e.name) orelse continue;
            if (first) {
                const k = f.gpa.dupe(u8, stem) catch continue;
                f.start_sizes.put(f.gpa, k, e.size) catch f.gpa.free(k);
                continue;
            }
            if (f.cur) |c| if (std.mem.eql(u8, &c.stem, stem)) continue;
            if (!f.grown(stem, e.size)) continue;
            if (best == null or e.time > best.?.time) best = .{ .stem = stem[0..36].*, .time = e.time };
        }
        if (f.waitingExpected()) {
            const e = f.expected.?;
            if (f.fileSize(&e) != null) f.consider(&e);
        } else if (best) |b| f.consider(&b.stem);
        if (f.cur != null) f.readMore();
    }

    /// Portal gave the program a session id and its transcript has not
    /// appeared yet.
    fn waitingExpected(f: *const Follower) bool {
        return f.expected != null and !f.expected_seen;
    }

    fn isExpected(f: *const Follower, stem: []const u8) bool {
        const e = f.expected orelse return false;
        return std.mem.eql(u8, &e, stem);
    }

    /// New since the tab started, or bigger than it was then.
    fn grown(f: *Follower, stem: []const u8, size: u64) bool {
        if (f.isExpected(stem)) return true;
        if (f.rejected.contains(stem)) return false;
        const before = f.start_sizes.get(stem) orelse return true;
        return size > before;
    }

    /// The program printed: read what the followed transcript gained (its
    /// size on a fresh handle is current even when the directory entry is
    /// not), and look again at new transcripts not yet confirmed.
    fn recheck(f: *Follower) void {
        f.readMore();
        if (f.waitingExpected()) {
            const e = f.expected.?;
            f.changedStem(&e);
        }
        var list: [8][36]u8 = undefined;
        const n = f.n_unsure;
        @memcpy(list[0..n], f.unsure[0..n]);
        for (list[0..n]) |*stem| f.changedStem(stem);
    }

    fn addUnsure(f: *Follower, stem: []const u8) void {
        for (f.unsure[0..f.n_unsure]) |*u| if (std.mem.eql(u8, u, stem)) return;
        if (f.n_unsure == f.unsure.len) {
            std.mem.copyForwards([36]u8, f.unsure[0 .. f.unsure.len - 1], f.unsure[1..]);
            f.n_unsure -= 1;
        }
        f.unsure[f.n_unsure] = stem[0..36].*;
        f.n_unsure += 1;
    }

    fn dropUnsure(f: *Follower, stem: []const u8) void {
        var i: usize = 0;
        while (i < f.n_unsure) {
            if (std.mem.eql(u8, &f.unsure[i], stem)) {
                std.mem.copyForwards([36]u8, f.unsure[i .. f.n_unsure - 1], f.unsure[i + 1 .. f.n_unsure]);
                f.n_unsure -= 1;
            } else i += 1;
        }
    }

    /// An entry of the folder changed.
    fn changed(f: *Follower, name: []const u8) void {
        const stem = stemOf(name) orelse return;
        f.changedStem(stem);
    }

    fn changedStem(f: *Follower, stem: []const u8) void {
        if (f.cur) |c| if (std.mem.eql(u8, &c.stem, stem)) return f.readMore();
        const size = f.fileSize(stem) orelse return;
        if (!f.grown(stem, size)) return;
        f.consider(stem);
        if (f.cur) |c| if (std.mem.eql(u8, &c.stem, stem)) f.readMore();
    }

    /// Switches to transcript `stem` if it is the tab's.
    fn consider(f: *Follower, stem: []const u8) void {
        const expected = f.isExpected(stem);
        // Until the session Portal started has its transcript, nothing
        // else in the folder is the tab's (another session there, e.g. one
        // outside Portal, is not).
        if (f.waitingExpected() and !expected) return;
        if (!expected) switch (f.confirm(stem)) {
            .unknown => return f.addUnsure(stem), // no `cwd` yet: looked at again when it grows
            .no => {
                f.dropUnsure(stem);
                const k = f.gpa.dupe(u8, stem) catch return;
                f.rejected.put(f.gpa, k, {}) catch f.gpa.free(k);
                return;
            },
            .yes => {},
        };
        f.dropUnsure(stem);
        if (!f.sink.claim(f.sink.ctx, stem)) return;
        if (expected) f.expected_seen = true;
        const size = f.fileSize(stem) orelse 0;
        f.cur = .{ .stem = stem[0..36].*, .offset = if (size > max_initial) size - tail_read else 0 };
        f.line.clearRetainingCapacity();
        // Started mid-file: the first (partial) line is dropped.
        f.line_cut = size > max_initial;
        f.skip_partial = size > max_initial;
        f.sink.reset(f.sink.ctx, true);
    }

    const Confirm = enum { yes, no, unknown };

    /// Whose transcript: the first record with a `cwd` decides.
    fn confirm(f: *Follower, stem: []const u8) Confirm {
        var pb: [2048]u8 = undefined;
        const path = f.pathOf(&pb, stem) orelse return .unknown;
        const buf = f.gpa.alloc(u8, confirm_bytes) catch return .unknown;
        defer f.gpa.free(buf);
        const n = readAt(f.gpa, path, 0, buf) catch return .unknown;
        var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
        while (lines.next()) |line| {
            if (lines.index == null) break; // the last piece may be partial
            if (!transcript.parseLine(f.gpa, std.mem.trimEnd(u8, line, "\r"), true, f.rec)) continue;
            const cwd = f.rec.cwd() orelse continue;
            return if (transcript.cwdWithin(cwd, f.cwd)) .yes else .no;
        }
        return .unknown;
    }

    fn pathOf(f: *Follower, buf: []u8, stem: []const u8) ?[]const u8 {
        const folder = f.folder orelse return null;
        return std.fmt.bufPrint(buf, "{s}\\{s}.jsonl", .{ folder, stem }) catch null;
    }

    fn fileSize(f: *Follower, stem: []const u8) ?u64 {
        var pb: [2048]u8 = undefined;
        const path = f.pathOf(&pb, stem) orelse return null;
        return sizeOf(f.gpa, path);
    }

    /// Reads what was appended to the current transcript since last time.
    fn readMore(f: *Follower) void {
        const c = &(f.cur orelse return);
        var pb: [2048]u8 = undefined;
        const path = f.pathOf(&pb, &c.stem) orelse return;
        const size = sizeOf(f.gpa, path) orelse return;
        if (size < c.offset) {
            // Replaced or cut: read it again from the start.
            c.offset = 0;
            f.line.clearRetainingCapacity();
            f.line_cut = false;
            f.skip_partial = false;
            f.sink.reset(f.sink.ctx, true);
        }
        var chunk: [64 * 1024]u8 = undefined;
        while (c.offset < size) {
            const want: usize = @intCast(@min(chunk.len, size - c.offset));
            const n = readAt(f.gpa, path, c.offset, chunk[0..want]) catch return;
            if (n == 0) return;
            c.offset += n;
            f.feed(chunk[0..n]);
        }
    }

    /// Splits appended bytes into lines; a line still being written stays
    /// buffered (cut at `max_line`).
    pub fn feed(f: *Follower, data: []const u8) void {
        var rest = data;
        while (rest.len > 0) {
            const nl = std.mem.indexOfScalar(u8, rest, '\n');
            const piece = rest[0 .. nl orelse rest.len];
            const room = max_line - f.line.items.len;
            if (piece.len > room) f.line_cut = true;
            f.line.appendSlice(f.gpa, piece[0..@min(piece.len, room)]) catch {
                f.line_cut = true;
            };
            if (nl == null) return;
            rest = rest[nl.? + 1 ..];
            if (f.skip_partial) {
                f.skip_partial = false;
            } else {
                f.lineDone(std.mem.trimEnd(u8, f.line.items, "\r"), !f.line_cut);
            }
            f.line.clearRetainingCapacity();
            f.line_cut = false;
        }
    }

    fn lineDone(f: *Follower, line: []const u8, complete: bool) void {
        if (std.mem.trim(u8, line, " \t").len == 0) return;
        if (!transcript.parseLine(f.gpa, line, complete, f.rec)) return;
        f.sink.apply(f.sink.ctx, f.rec);
    }
};

/// `<uuid>.jsonl` → `<uuid>`, else null.
fn stemOf(name: []const u8) ?[]const u8 {
    if (!std.ascii.endsWithIgnoreCase(name, ".jsonl")) return null;
    const stem = name[0 .. name.len - ".jsonl".len];
    if (!transcript.isSessionStem(stem)) return null;
    return stem;
}

fn openRead(gpa: Allocator, path: []const u8) ?w.HANDLE {
    const pw = fsutil.wide(gpa, path) catch return null;
    defer gpa.free(pw);
    return w.validHandle(w.CreateFileW(pw.ptr, w.GENERIC_READ, w.FILE_SHARE_READ | w.FILE_SHARE_WRITE | w.FILE_SHARE_DELETE, null, w.OPEN_EXISTING, w.FILE_ATTRIBUTE_NORMAL, null));
}

fn sizeOf(gpa: Allocator, path: []const u8) ?u64 {
    const h = openRead(gpa, path) orelse return null;
    defer _ = w.CloseHandle(h);
    var size: i64 = 0;
    if (w.GetFileSizeEx(h, &size) == 0 or size < 0) return null;
    return @intCast(size);
}

/// Reads up to `buf.len` bytes at `offset`; the count read.
fn readAt(gpa: Allocator, path: []const u8, offset: u64, buf: []u8) !usize {
    const h = openRead(gpa, path) orelse return error.OpenFailed;
    defer _ = w.CloseHandle(h);
    if (w.SetFilePointerEx(h, @intCast(offset), null, w.FILE_BEGIN) == 0) return error.SeekFailed;
    var total: usize = 0;
    while (total < buf.len) {
        var n: w.DWORD = 0;
        const len: w.DWORD = @intCast(@min(buf.len - total, 1 << 30));
        if (w.ReadFile(h, buf[total..].ptr, len, &n, null) == 0) return error.ReadFailed;
        if (n == 0) break;
        total += n;
    }
    return total;
}

/// Directory listing (FindFirstFileW): names (UTF-8), sizes, last write
/// times.
const Find = struct {
    h: ?w.HANDLE,
    data: w.WIN32_FIND_DATAW = undefined,
    first: bool = true,

    const Entry = struct { name: []const u8, dir: bool, size: u64, time: u64 };

    fn open(gpa: Allocator, pattern: []const u8) !Find {
        const pw = try fsutil.wide(gpa, pattern);
        defer gpa.free(pw);
        var f: Find = .{ .h = null };
        f.h = w.validHandle(w.FindFirstFileW(pw.ptr, &f.data));
        return f;
    }

    fn next(f: *Find, out: []u8) ?Entry {
        const h = f.h orelse return null;
        while (true) {
            if (!f.first) {
                if (w.FindNextFileW(h, &f.data) == 0) return null;
            }
            f.first = false;
            const units = std.mem.sliceTo(&f.data.cFileName, 0);
            if (std.mem.eql(u16, units, &.{'.'}) or std.mem.eql(u16, units, &.{ '.', '.' })) continue;
            const len = std.unicode.wtf16LeToWtf8(out, units[0..@min(units.len, out.len / 3)]);
            return .{
                .name = out[0..len],
                .dir = f.data.dwFileAttributes & w.FILE_ATTRIBUTE_DIRECTORY != 0,
                .size = (@as(u64, f.data.nFileSizeHigh) << 32) | f.data.nFileSizeLow,
                .time = f.data.ftLastWriteTime.toU64(),
            };
        }
    }

    fn close(f: *Find) void {
        if (f.h) |h| _ = w.FindClose(h);
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;
const Convo = @import("model.zig").Convo;

/// A sink straight into a conversation, with claims shared by "tabs".
const TestSink = struct {
    convo: Convo,
    claimed: ?[36]u8 = null,
    others: []const [36]u8 = &.{},
    resets: u32 = 0,
    applied: std.atomic.Value(u32) = .init(0),

    fn sink(s: *TestSink) Sink {
        return .{ .ctx = s, .apply = apply, .reset = reset, .claim = claim };
    }
    fn apply(ctx: *anyopaque, rec: *const transcript.Record) void {
        const s: *TestSink = @ptrCast(@alignCast(ctx));
        s.convo.applyRecord(rec) catch {};
        _ = s.applied.fetchAdd(1, .release);
    }
    fn reset(ctx: *anyopaque, on: bool) void {
        const s: *TestSink = @ptrCast(@alignCast(ctx));
        s.convo.reset(on);
        s.resets += 1;
    }
    fn claim(ctx: *anyopaque, stem: []const u8) bool {
        const s: *TestSink = @ptrCast(@alignCast(ctx));
        for (s.others) |o| if (std.mem.eql(u8, &o, stem)) return false;
        s.claimed = stem[0..36].*;
        return true;
    }

    fn texts(s: *TestSink, buf: []u8) []const u8 {
        var wr: std.Io.Writer = .fixed(buf);
        for (0..s.convo.len) |i| {
            const it = s.convo.slots[(s.convo.first + i) % s.convo.slots.len];
            wr.print("{s}|", .{it.text}) catch {};
        }
        return wr.buffered();
    }
};

const Tmp = struct {
    tmp: testing.TmpDir,
    root: []u8,

    fn init() !Tmp {
        var t: Tmp = .{ .tmp = testing.tmpDir(.{}), .root = undefined };
        const cwd = try std.process.currentPathAlloc(testing.io, testing.allocator);
        defer testing.allocator.free(cwd);
        t.root = try std.fmt.allocPrint(testing.allocator, "{s}\\.zig-cache\\tmp\\{s}", .{ cwd, &t.tmp.sub_path });
        return t;
    }

    fn deinit(t: *Tmp) void {
        testing.allocator.free(t.root);
        t.tmp.cleanup();
    }

    fn path(t: *Tmp, buf: []u8, rel: []const u8) []const u8 {
        return std.fmt.bufPrint(buf, "{s}\\{s}", .{ t.root, rel }) catch unreachable;
    }

    fn append(t: *Tmp, rel: []const u8, data: []const u8) !void {
        var pb: [1024]u8 = undefined;
        const p = t.path(&pb, rel);
        const pw = try fsutil.wide(testing.allocator, p);
        defer testing.allocator.free(pw);
        const h = w.validHandle(w.CreateFileW(pw.ptr, w.FILE_APPEND_DATA, w.FILE_SHARE_READ | w.FILE_SHARE_WRITE | w.FILE_SHARE_DELETE, null, w.OPEN_ALWAYS, w.FILE_ATTRIBUTE_NORMAL, null)) orelse return error.OpenFailed;
        defer _ = w.CloseHandle(h);
        var n: w.DWORD = 0;
        if (w.WriteFile(h, data.ptr, @intCast(data.len), &n, null) == 0) return error.WriteFailed;
    }
};

const stem_a = "11111111-2222-3333-4444-555555555555";
const stem_b = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const stem_old = "00000000-0000-0000-0000-000000000000";

fn recLine(comptime kind: []const u8, comptime cwd: []const u8, comptime text: []const u8) []const u8 {
    if (comptime std.mem.eql(u8, kind, "user"))
        return "{\"type\":\"user\",\"cwd\":\"" ++ cwd ++ "\",\"sessionId\":\"s\",\"message\":{\"role\":\"user\",\"content\":\"" ++ text ++ "\"}}\n";
    return "{\"type\":\"assistant\",\"cwd\":\"" ++ cwd ++ "\",\"message\":{\"id\":\"m" ++ text ++ "\",\"content\":[{\"type\":\"text\",\"text\":\"" ++ text ++ "\"}]}}\n";
}

test "follower: notes old transcripts, picks the new one, reads appends and partial lines, moves on /clear" {
    var t = try Tmp.init();
    defer t.deinit();
    const gpa = testing.allocator;
    // The tab's folder C:\proj\acme as the agent names it.
    const cwd = "C:\\proj\\acme";
    try t.tmp.dir.createDirPath(testing.io, "projects\\C--proj-acme");
    try t.append("projects\\C--proj-acme\\" ++ stem_old ++ ".jsonl", recLine("user", "C:\\\\proj\\\\acme", "old one"));
    var pb: [1024]u8 = undefined;
    const projects = t.path(&pb, "projects");

    var ts: TestSink = .{ .convo = Convo.init(gpa, .{ .root = cwd, .name = "acme" }) };
    defer ts.convo.deinit();
    var f = try Follower.init(gpa, ts.sink(), projects, cwd);
    defer f.deinit();
    try f.resolveFolder();
    try testing.expect(f.folder != null);
    f.rescan(); // notes sizes; follows nothing yet
    try testing.expect(f.cur == null);
    try testing.expect(!ts.convo.on);

    // A new session file appears and is written to.
    try t.append("projects\\C--proj-acme\\" ++ stem_a ++ ".jsonl", "{\"type\":\"mode\",\"mode\":\"x\",\"sessionId\":\"" ++ stem_a ++ "\"}\n");
    f.changed(stem_a ++ ".jsonl");
    try testing.expect(f.cur == null); // no cwd yet: not confirmed
    try t.append("projects\\C--proj-acme\\" ++ stem_a ++ ".jsonl", recLine("user", "C:\\\\proj\\\\acme", "hello"));
    f.changed(stem_a ++ ".jsonl");
    try testing.expect(f.cur != null);
    try testing.expectEqualStrings(stem_a, &ts.claimed.?);
    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("hello|", ts.texts(&buf));
    try testing.expect(ts.convo.on);

    // A line written in two pieces is read once it is whole.
    const line = recLine("assistant", "C:\\\\proj\\\\acme", "hi there");
    try t.append("projects\\C--proj-acme\\" ++ stem_a ++ ".jsonl", line[0..20]);
    f.changed(stem_a ++ ".jsonl");
    try testing.expectEqualStrings("hello|", ts.texts(&buf));
    try t.append("projects\\C--proj-acme\\" ++ stem_a ++ ".jsonl", line[20..]);
    f.changed(stem_a ++ ".jsonl");
    try testing.expectEqualStrings("hello|hi there|", ts.texts(&buf));

    // Another transcript in the folder whose records name another
    // folder (names collide: C:\proj-acme and C:\proj\acme) is not the tab's.
    try t.append("projects\\C--proj-acme\\" ++ stem_b ++ ".jsonl", recLine("user", "C:\\\\proj-acme", "collision"));
    f.changed(stem_b ++ ".jsonl");
    try testing.expectEqualStrings(stem_a, &f.cur.?.stem);
    try testing.expect(f.rejected.contains(stem_b));

    // /clear: a new session file in the right folder takes over.
    const stem_c = "cccccccc-0000-0000-0000-000000000000";
    try t.append("projects\\C--proj-acme\\" ++ stem_c ++ ".jsonl", recLine("user", "C:\\\\proj\\\\acme", "fresh"));
    f.changed(stem_c ++ ".jsonl");
    try testing.expectEqualStrings(stem_c, &f.cur.?.stem);
    try testing.expectEqualStrings("fresh|", ts.texts(&buf));
}

test "follower: with a session id, only that transcript until it appears; then /clear is followed" {
    var t = try Tmp.init();
    defer t.deinit();
    const gpa = testing.allocator;
    try t.tmp.dir.createDirPath(testing.io, "projects\\C--p");
    var pb: [1024]u8 = undefined;
    const projects = t.path(&pb, "projects");
    var ts: TestSink = .{ .convo = Convo.init(gpa, .{ .root = "C:\\p", .name = "p" }) };
    defer ts.convo.deinit();
    var f = try Follower.init(gpa, ts.sink(), projects, "C:\\p");
    defer f.deinit();
    f.expected = stem_b.*;
    try f.resolveFolder();
    f.rescan();
    // Another session in the same folder (outside Portal), same cwd: ignored.
    try t.append("projects\\C--p\\" ++ stem_a ++ ".jsonl", recLine("user", "C:\\\\p", "outside"));
    f.changed(stem_a ++ ".jsonl");
    try testing.expect(f.cur == null);
    // Portal's session: followed at once, even before it names its cwd.
    try t.append("projects\\C--p\\" ++ stem_b ++ ".jsonl", "{\"type\":\"mode\"}\n");
    f.changed(stem_b ++ ".jsonl");
    try testing.expectEqualStrings(stem_b, &f.cur.?.stem);
    try t.append("projects\\C--p\\" ++ stem_b ++ ".jsonl", recLine("user", "C:\\\\p", "mine"));
    f.changed(stem_b ++ ".jsonl");
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("mine|", ts.texts(&buf));
    // /clear: a new session file with the tab's cwd takes over.
    const stem_c = "cccccccc-0000-0000-0000-000000000000";
    try t.append("projects\\C--p\\" ++ stem_c ++ ".jsonl", recLine("user", "C:\\\\p", "cleared"));
    f.changed(stem_c ++ ".jsonl");
    try testing.expectEqualStrings(stem_c, &f.cur.?.stem);
    try testing.expectEqualStrings("cleared|", ts.texts(&buf));
}

test "follower: a transcript claimed by another tab is left alone" {
    var t = try Tmp.init();
    defer t.deinit();
    const gpa = testing.allocator;
    try t.tmp.dir.createDirPath(testing.io, "projects\\C--p");
    var pb: [1024]u8 = undefined;
    const projects = t.path(&pb, "projects");
    const others = [_][36]u8{stem_a.*};
    var ts: TestSink = .{ .convo = Convo.init(gpa, .{ .root = "C:\\p", .name = "p" }), .others = &others };
    defer ts.convo.deinit();
    var f = try Follower.init(gpa, ts.sink(), projects, "C:\\p");
    defer f.deinit();
    try f.resolveFolder();
    f.rescan();
    try t.append("projects\\C--p\\" ++ stem_a ++ ".jsonl", recLine("user", "C:\\\\p", "theirs"));
    f.changed(stem_a ++ ".jsonl");
    try testing.expect(f.cur == null);
    try t.append("projects\\C--p\\" ++ stem_b ++ ".jsonl", recLine("user", "C:\\\\p", "mine"));
    f.changed(stem_b ++ ".jsonl");
    try testing.expectEqualStrings(stem_b, &f.cur.?.stem);
}

test "follower: overlong lines are cut, not kept whole" {
    const gpa = testing.allocator;
    var ts: TestSink = .{ .convo = Convo.init(gpa, .{ .root = "C:\\p", .name = "p" }) };
    defer ts.convo.deinit();
    var f = try Follower.init(gpa, ts.sink(), "C:\\nowhere", "C:\\p");
    defer f.deinit();
    ts.convo.reset(true);
    const head = "{\"type\":\"assistant\",\"message\":{\"id\":\"m\",\"content\":[{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"Write\",\"input\":{\"file_path\":\"x\",\"content\":\"";
    f.feed(head);
    const big = try gpa.alloc(u8, max_line);
    defer gpa.free(big);
    @memset(big, 'z');
    f.feed(big);
    f.feed(big);
    try testing.expect(f.line.items.len <= max_line);
    f.feed("\"}}]}}\n");
    try testing.expectEqual(@as(usize, 0), f.line.items.len);
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("Edited 1 file|", ts.texts(&buf));
}

test "DirChanges: a new transcript in the folder is reported by name" {
    var t = try Tmp.init();
    defer t.deinit();
    const gpa = testing.allocator;
    const dc = try DirChanges.open(gpa, t.root, w.FILE_NOTIFY_CHANGE_FILE_NAME | w.FILE_NOTIFY_CHANGE_SIZE | w.FILE_NOTIFY_CHANGE_LAST_WRITE);
    defer dc.close();
    try dc.arm();
    try testing.expectEqual(w.WAIT_TIMEOUT, w.WaitForSingleObject(dc.ev, 0));
    try t.append(stem_a ++ ".jsonl", "{}\n");
    try testing.expectEqual(w.WAIT_OBJECT_0, w.WaitForSingleObject(dc.ev, 5000));
    var b = try dc.collect();
    var nb: [256]u8 = undefined;
    try testing.expect(!b.overflow);
    try testing.expectEqualStrings(stem_a ++ ".jsonl", b.next(&nb).?);
}

test "follower: a poke (the program printed) picks up appends through a kept-open handle" {
    var t = try Tmp.init();
    defer t.deinit();
    const gpa = testing.allocator;
    const io = testing.io;
    try t.tmp.dir.createDirPath(io, "projects\\C--kept");
    var pb: [1024]u8 = undefined;
    const projects = t.path(&pb, "projects");
    var ts: TestSink = .{ .convo = Convo.init(gpa, .{ .root = "C:\\kept", .name = "kept" }) };
    defer ts.convo.deinit();
    var f = try Follower.init(gpa, ts.sink(), projects, "C:\\kept");
    defer f.deinit();
    // The folder is noted (empty) before the program starts.
    try f.resolveFolder();
    f.rescan();
    var poke = Poke.init().?;
    defer poke.deinit();
    const stop = w.validHandle(w.CreateEventW(null, 1, 0, null)).?;
    defer _ = w.CloseHandle(stop);
    const th = try std.Thread.spawn(.{}, Follower.run, .{ &f, stop, &poke });
    defer {
        _ = w.SetEvent(stop);
        th.join();
    }
    // The program creates its transcript and keeps the handle open: the
    // directory reports the new name (maybe while it is still empty);
    // what it appends later may never be reported.
    var fb: [1024]u8 = undefined;
    const fpath = t.path(&fb, "projects\\C--kept\\" ++ stem_a ++ ".jsonl");
    const pw = try fsutil.wide(gpa, fpath);
    defer gpa.free(pw);
    const h = w.validHandle(w.CreateFileW(pw.ptr, w.FILE_APPEND_DATA, w.FILE_SHARE_READ | w.FILE_SHARE_WRITE | w.FILE_SHARE_DELETE, null, w.OPEN_ALWAYS, w.FILE_ATTRIBUTE_NORMAL, null)).?;
    defer _ = w.CloseHandle(h);
    var n: w.DWORD = 0;
    const lines = [_][]const u8{ recLine("user", "C:\\\\kept", "one"), recLine("assistant", "C:\\\\kept", "two") };
    for (lines, 1..) |line, want| {
        _ = w.WriteFile(h, line.ptr, @intCast(line.len), &n, null);
        // It prints while it writes: Portal pokes the follower on output.
        var i: u32 = 0;
        while (ts.applied.load(.acquire) < want) : (i += 1) {
            if (i == 200) return error.AppendNotSeen;
            poke.poke();
            try io.sleep(.fromMilliseconds(10), .awake);
        }
    }
    try testing.expectEqual(@as(u32, 2), ts.applied.load(.acquire));
}

test "follower thread: stops on its event; waits for the folder to appear" {
    var t = try Tmp.init();
    defer t.deinit();
    const gpa = testing.allocator;
    const io = testing.io;
    try t.tmp.dir.createDirPath(io, "projects");
    var pb: [1024]u8 = undefined;
    const projects = t.path(&pb, "projects");
    var ts: TestSink = .{ .convo = Convo.init(gpa, .{ .root = "C:\\late", .name = "late" }) };
    defer ts.convo.deinit();
    var f = try Follower.init(gpa, ts.sink(), projects, "C:\\late");
    defer f.deinit();
    const stop = w.validHandle(w.CreateEventW(null, 1, 0, null)).?;
    defer _ = w.CloseHandle(stop);
    const th = try std.Thread.spawn(.{}, Follower.run, .{ &f, stop, null });
    // The folder appears after the follower started; then a transcript,
    // appended to until the follower has read it.
    try t.tmp.dir.createDirPath(io, "projects\\C--late");
    var tries: u32 = 0;
    while (ts.applied.load(.acquire) == 0) : (tries += 1) {
        if (tries > 100) {
            _ = w.SetEvent(stop);
            th.join();
            return error.TranscriptNotSeen;
        }
        try t.append("projects\\C--late\\" ++ stem_a ++ ".jsonl", recLine("user", "C:\\\\late", "made it"));
        try io.sleep(.fromMilliseconds(50), .awake);
    }
    _ = w.SetEvent(stop);
    th.join();
    var buf: [256]u8 = undefined;
    try testing.expect(std.mem.startsWith(u8, ts.texts(&buf), "made it|"));
    // It woke for changes only (no polling): a handful of times.
    try testing.expect(f.wakes < 3 * tries + 10);
}
