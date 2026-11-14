//! The microphone thread: which capture endpoint is active (mics.zig's
//! rules), and recording from it only while asked to.
//!
//! One thread per Portal window, in the multithreaded COM apartment (the
//! window's thread is single-threaded for the shell's dialogs). It sleeps
//! in one WaitForMultipleObjects on:
//!   * stop      the window is closing;
//!   * command   the window asked for something (record, stop, meter,
//!               mode);
//!   * changed   the backend saw a device change (IMMNotificationClient:
//!               added, removed, state, default device): the list is read
//!               again and the active endpoint chosen again; a recording
//!               moves to the new endpoint at once (a headset plugged in
//!               mid-sentence takes over);
//!   * ready     captured audio is waiting (WASAPI's event callback),
//!               only while capturing.
//! Nothing wakes on a timer.
//!
//! Capture runs only while a recording is wanted (the 🎤 is on) or the
//! level meter is (the Audio panel is open): never in the background. The
//! window learns of everything through `notify` (any thread: it only
//! wakes the window) and reads it with `snapshot`.
//!
//! The backend is an interface so tests use a fake one (no microphone);
//! the real one is wasapi.zig.

const std = @import("std");
const sys = @import("sys.zig");
const mics = @import("mics.zig");

/// 16 kHz mono signed 16-bit: what stt wants and what WASAPI is asked for.
const limits = @import("limits.zig");
pub const sample_rate = limits.sample_rate;
/// The longest recording (stt refuses more than 120 s).
pub const max_seconds = limits.max_seconds;
pub const max_samples = limits.max_samples;

/// Where a backend puts captured samples.
pub const Sink = struct {
    ctx: *anyopaque,
    put: *const fn (ctx: *anyopaque, samples: []const i16) void,
};

/// A capture backend. Every call is made on the microphone thread.
pub const Backend = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Once, first: set up (COM, the device enumerator) and signal
        /// `changed` whenever the capture endpoints change.
        open: *const fn (ctx: *anyopaque, changed: sys.HANDLE) anyerror!void,
        close: *const fn (ctx: *anyopaque) void,
        /// The active capture endpoints now.
        list: *const fn (ctx: *anyopaque, out: *mics.List) anyerror!void,
        /// Starts capturing `id` at 16 kHz mono s16le; `ready` is set
        /// whenever audio waits.
        start: *const fn (ctx: *anyopaque, id: []const u8, ready: sys.HANDLE) anyerror!void,
        /// Moves what waits into `sink`. error.DeviceLost: the endpoint went.
        read: *const fn (ctx: *anyopaque, sink: Sink) anyerror!void,
        stop: *const fn (ctx: *anyopaque) void,
    };
};

/// What the window reads (copies; `snapshot`).
pub const Snapshot = struct {
    list: mics.List = .{},
    /// Index into `list` of the endpoint in use, if any.
    active: ?usize = null,
    /// Manual mode, but that device is gone: Automatic chose.
    fell_back: bool = false,
    automatic: bool = true,
    recording: bool = false,
    /// The recording reached max_seconds: the window should stop it.
    full: bool = false,
    /// Capturing for the meter or a recording.
    capturing: bool = false,
    /// Peak level of the latest audio, 0..1 (a 10-step bar: `levelSteps`).
    level: f32 = 0,
    /// Bumped whenever `list` (or the active endpoint) changes.
    list_gen: u64 = 0,
    /// Why capture failed last ("" if it did not).
    err_buf: [96]u8 = undefined,
    err_len: usize = 0,

    pub fn err(s: *const Snapshot) []const u8 {
        return s.err_buf[0..s.err_len];
    }
    pub fn activeEndpoint(s: *const Snapshot) ?*const mics.Endpoint {
        const i = s.active orelse return null;
        return &s.list.items[i];
    }
};

/// The meter's resolution: the window redraws only when this changes.
pub fn levelSteps(level: f32) u8 {
    return @intFromFloat(@round(std.math.clamp(level, 0, 1) * 10));
}

/// Peak of |s| as 0..1 on a dB scale (-60 dBFS .. 0): what the meter shows.
pub fn peakLevel(samples: []const i16) f32 {
    var peak: u32 = 0;
    for (samples) |s| peak = @max(peak, @abs(@as(i32, s)));
    if (peak == 0) return 0;
    const db = 20 * std.math.log10(@as(f32, @floatFromInt(peak)) / 32768.0);
    return std.math.clamp((db + 60) / 60, 0, 1);
}

/// A finished recording, handed to the window (`takeRecording`).
pub const Recording = struct {
    samples: []i16,
    /// It hit max_seconds and was cut there.
    truncated: bool = false,
};

pub const Mic = struct {
    gpa: std.mem.Allocator,
    backend: Backend,
    notify_ctx: ?*anyopaque = null,
    notify_fn: ?*const fn (ctx: *anyopaque) void = null,

    stop_ev: sys.HANDLE = undefined,
    cmd_ev: sys.HANDLE = undefined,
    changed_ev: sys.HANDLE = undefined,
    ready_ev: sys.HANDLE = undefined,
    thread: ?std.Thread = null,

    lock: sys.Lock = .{},
    // ---- under `lock`: what the window wants
    want_record: bool = false,
    want_meter: bool = false,
    /// Bumped by startRecording; the thread begins a recording for each
    /// new value (so a start and stop that arrive together still hand
    /// over an, empty, recording).
    rec_seq: u32 = 0,
    automatic: bool = true,
    manual_id: mics.IdText = .{},
    // ---- under `lock`: what the thread reports
    snap: Snapshot = .{},
    /// The recording in progress (thread appends), and a finished one
    /// waiting for the window.
    /// Allocated once (`start`) at max_samples and never grown: capture
    /// stops when it is full.
    rec: []i16 = &.{},
    rec_len: usize = 0,
    rec_truncated: bool = false,
    /// The configured longest recording (limits.Config.clip_max_s), at
    /// most the buffer.
    cap_samples: usize = max_samples,
    done: ?Recording = null,
    shown_steps: u8 = 0,
    /// A headset came or went (the toast), until the window takes it.
    change_buf: [mics.max_name + 32]u8 = undefined,
    change_len: usize = 0,

    // ---- thread only
    capturing_id: mics.IdText = .{},
    capturing: bool = false,
    rec_seen: u32 = 0,

    /// Starts the thread. `mode` is the saved choice.
    pub fn start(m: *Mic) !void {
        m.rec = try m.gpa.alloc(i16, max_samples);
        errdefer m.gpa.free(m.rec);
        m.stop_ev = try sys.autoEvent();
        m.cmd_ev = try sys.autoEvent();
        m.changed_ev = try sys.autoEvent();
        m.ready_ev = try sys.autoEvent();
        m.thread = try std.Thread.spawn(.{}, run, .{m});
    }

    /// Stops the thread (and any capture) and frees everything.
    pub fn deinit(m: *Mic) void {
        if (m.thread) |t| {
            _ = sys.SetEvent(m.stop_ev);
            t.join();
            m.thread = null;
            for ([_]sys.HANDLE{ m.stop_ev, m.cmd_ev, m.changed_ev, m.ready_ev }) |h| _ = sys.CloseHandle(h);
        }
        m.gpa.free(m.rec);
        m.rec = &.{};
        if (m.done) |d| m.gpa.free(d.samples);
        m.done = null;
    }

    fn command(m: *Mic) void {
        _ = sys.SetEvent(m.cmd_ev);
    }

    fn notify(m: *Mic) void {
        if (m.notify_fn) |f| f(m.notify_ctx.?);
    }

    // ------------------------------------------------------------ window side

    /// Automatic, or a specific endpoint (falls back while it is missing).
    pub fn setMode(m: *Mic, mode: mics.Mode) void {
        m.lock.lock();
        switch (mode) {
            .automatic => m.automatic = true,
            .manual => |id| {
                m.automatic = false;
                m.manual_id.set(id);
            },
        }
        m.lock.unlock();
        // Choosing again needs the list: the same path as a device change.
        _ = sys.SetEvent(m.changed_ev);
    }

    /// The 🎤 went on: record from the active endpoint.
    pub fn startRecording(m: *Mic) void {
        m.lock.lock();
        m.want_record = true;
        m.rec_seq +%= 1;
        m.lock.unlock();
        m.command();
    }

    /// The 🎤 went off: the recording is finished on the thread (what is
    /// still buffered is read first) and handed over through
    /// `takeRecording` (the window is notified).
    pub fn stopRecording(m: *Mic) void {
        m.lock.lock();
        m.want_record = false;
        m.lock.unlock();
        m.command();
    }

    /// New limits (live): the longest recording.
    pub fn setLimits(m: *Mic, c: limits.Config) void {
        m.lock.lock();
        defer m.lock.unlock();
        m.cap_samples = @min(c.clamped().maxSamples(), max_samples);
    }

    /// The level meter (the Audio panel is open).
    pub fn setMeter(m: *Mic, on: bool) void {
        m.lock.lock();
        m.want_meter = on;
        m.lock.unlock();
        m.command();
    }

    pub fn snapshot(m: *Mic, out: *Snapshot) void {
        m.lock.lock();
        defer m.lock.unlock();
        out.* = m.snap;
    }

    /// A finished recording, if one waits (the caller frees `samples`).
    pub fn takeRecording(m: *Mic) ?Recording {
        m.lock.lock();
        defer m.lock.unlock();
        const d = m.done orelse return null;
        m.done = null;
        return d;
    }

    /// The latest headset change ("Headset connected: …"), once.
    pub fn takeChange(m: *Mic, buf: []u8) ?[]const u8 {
        m.lock.lock();
        defer m.lock.unlock();
        if (m.change_len == 0) return null;
        const n = @min(buf.len, m.change_len);
        @memcpy(buf[0..n], m.change_buf[0..n]);
        m.change_len = 0;
        return buf[0..n];
    }

    // ------------------------------------------------------------ thread

    fn run(m: *Mic) void {
        const b = m.backend;
        b.vtable.open(b.ctx, m.changed_ev) catch |err| {
            m.setError("Cannot use the audio devices: {t}", .{err});
            m.notify();
            // Without a backend, only stop matters.
            _ = sys.WaitForSingleObject(m.stop_ev, sys.INFINITE);
            return;
        };
        defer b.vtable.close(b.ctx);
        m.refresh(true);
        while (true) {
            var hs: [4]sys.HANDLE = .{ m.stop_ev, m.cmd_ev, m.changed_ev, m.ready_ev };
            const n: sys.DWORD = if (m.capturing) 4 else 3;
            const r = sys.WaitForMultipleObjects(n, &hs, 0, sys.INFINITE);
            switch (r) {
                0 => break,
                1 => m.reconcile(),
                2 => m.refresh(false),
                3 => m.readNow(),
                else => break,
            }
        }
        m.stopCapture();
        m.finishRecording();
    }

    fn setError(m: *Mic, comptime fmt: []const u8, args: anytype) void {
        m.lock.lock();
        defer m.lock.unlock();
        const s = std.fmt.bufPrint(&m.snap.err_buf, fmt, args) catch m.snap.err_buf[0..0];
        m.snap.err_len = s.len;
    }

    /// Reads the device list and chooses again; a capture follows the
    /// active endpoint.
    fn refresh(m: *Mic, first: bool) void {
        const b = m.backend;
        var l: mics.List = .{};
        b.vtable.list(b.ctx, &l) catch |err| m.setError("Cannot list the microphones: {t}", .{err});
        m.lock.lock();
        const old = m.snap.list;
        var id_buf: mics.IdText = m.manual_id;
        const mode: mics.Mode = if (m.automatic) .automatic else .{ .manual = id_buf.get() };
        const c = mics.choose(&l, mode);
        m.snap.list = l;
        m.snap.active = if (c) |x| x.index else null;
        m.snap.fell_back = if (c) |x| x.fell_back else false;
        m.snap.automatic = m.automatic;
        m.snap.list_gen += 1;
        if (!first) switch (mics.headsetChange(&old, &m.snap.list)) {
            .none => {},
            .headset_connected => |name| m.setChange("Headset connected: {s}", .{name}),
            .headset_disconnected => |name| m.setChange("Headset disconnected: {s}", .{name}),
        };
        m.lock.unlock();
        id_buf = .{};
        m.reconcile();
        m.notify();
    }

    fn setChange(m: *Mic, comptime fmt: []const u8, args: anytype) void {
        const s = std.fmt.bufPrint(&m.change_buf, fmt, args) catch m.change_buf[0..0];
        m.change_len = s.len;
    }

    /// Captures exactly while wanted, from the active endpoint.
    fn reconcile(m: *Mic) void {
        // What is buffered belongs to the state before this command (a
        // recording that is ending gets its last packets).
        m.readNow();
        m.lock.lock();
        // A new recording starts empty.
        if (m.rec_seq != m.rec_seen) {
            m.rec_seen = m.rec_seq;
            m.rec_len = 0;
            m.rec_truncated = false;
            m.snap.full = false;
            m.snap.recording = true;
        }
        const want = m.want_record or m.want_meter;
        var id: mics.IdText = .{};
        if (m.snap.activeEndpoint()) |e| id = e.id;
        const recording_ended = !m.want_record and m.snap.recording;
        m.lock.unlock();

        if (m.capturing and (!want or !m.capturing_id.eql(id.get()))) {
            // Whatever is buffered belongs to the recording before it ends.
            m.readNow();
            m.stopCapture();
        }
        if (recording_ended) m.finishRecording();
        if (want and !m.capturing and id.len > 0) {
            const b = m.backend;
            if (b.vtable.start(b.ctx, id.get(), m.ready_ev)) |_| {
                m.capturing = true;
                m.capturing_id = id;
                m.lock.lock();
                m.snap.err_len = 0;
                m.lock.unlock();
            } else |err| {
                m.setError("Cannot record from that microphone: {t}", .{err});
            }
        }
        m.lock.lock();
        m.snap.capturing = m.capturing;
        m.snap.recording = m.want_record;
        if (!m.capturing) m.snap.level = 0;
        m.lock.unlock();
        m.notify();
    }

    fn stopCapture(m: *Mic) void {
        if (!m.capturing) return;
        m.backend.vtable.stop(m.backend.ctx);
        m.capturing = false;
        m.capturing_id = .{};
    }

    /// Hands the recording (possibly empty) to the window.
    fn finishRecording(m: *Mic) void {
        m.lock.lock();
        defer m.lock.unlock();
        if (!m.snap.recording) return;
        // A copy of what was recorded (at most max_samples): the window's
        // one job; the capture buffer stays for the next recording.
        const samples: []i16 = m.gpa.dupe(i16, m.rec[0..m.rec_len]) catch &.{};
        if (m.done) |d| m.gpa.free(d.samples);
        m.done = .{ .samples = samples, .truncated = m.rec_truncated or m.snap.full };
        m.snap.recording = false;
    }

    fn put(ctx: *anyopaque, samples: []const i16) void {
        const m: *Mic = @ptrCast(@alignCast(ctx));
        m.lock.lock();
        defer m.lock.unlock();
        m.snap.level = peakLevel(samples);
        if (!m.snap.recording) return;
        const room = @min(m.cap_samples, m.rec.len) -| m.rec_len;
        const take = @min(room, samples.len);
        @memcpy(m.rec[m.rec_len..][0..take], samples[0..take]);
        m.rec_len += take;
        if (take < samples.len) m.rec_truncated = true;
        if (m.rec_len >= @min(m.cap_samples, m.rec.len)) m.snap.full = true;
    }

    fn readNow(m: *Mic) void {
        if (!m.capturing) return;
        const b = m.backend;
        b.vtable.read(b.ctx, .{ .ctx = m, .put = put }) catch |err| {
            // The endpoint went (unplugged): choose again; a recording
            // continues on the next one.
            m.stopCapture();
            m.setError("The microphone stopped: {t}", .{err});
            m.refresh(false);
            return;
        };
        m.lock.lock();
        const steps = levelSteps(m.snap.level);
        const changed = steps != m.shown_steps;
        m.shown_steps = steps;
        const full = m.snap.full and m.snap.recording;
        // At the cap the recording ends here: it is handed over and
        // capture stops (unless the meter wants it), whatever the window
        // does.
        if (full) m.want_record = false;
        m.lock.unlock();
        if (full) {
            m.finishRecording();
            _ = sys.SetEvent(m.cmd_ev);
        }
        // The meter redraws only when its bar changes.
        if (changed or full) m.notify();
    }
};

// ------------------------------------------------------------------ fake backend

/// A backend for tests: a fixed device list (`plug` replaces it and
/// signals a change) and samples fed by the test (`feed`).
pub const Fake = struct {
    lock: sys.Lock = .{},
    list: mics.List = .{},
    changed: ?sys.HANDLE = null,
    ready: ?sys.HANDLE = null,
    queue: std.ArrayList(i16) = .empty,
    gpa: std.mem.Allocator,
    started_id: mics.IdText = .{},
    starts: u32 = 0,
    stops: u32 = 0,
    lost: bool = false,

    pub fn backend(f: *Fake) Backend {
        return .{ .ctx = f, .vtable = &vt };
    }

    pub fn deinit(f: *Fake) void {
        f.queue.deinit(f.gpa);
    }

    pub fn plug(f: *Fake, l: mics.List) void {
        f.lock.lock();
        f.list = l;
        // The capturing endpoint went: the next read says so.
        if (f.ready != null and l.find(f.started_id.get()) == null) f.lost = true;
        const ev = f.changed;
        const rd = f.ready;
        f.lock.unlock();
        if (ev) |e| _ = sys.SetEvent(e);
        if (rd) |e| if (f.lost) {
            _ = sys.SetEvent(e);
        };
    }

    /// Audio "arrives" (only while capturing; dropped otherwise, like a mic).
    pub fn feed(f: *Fake, samples: []const i16) void {
        f.lock.lock();
        const rd = f.ready;
        if (rd != null) f.queue.appendSlice(f.gpa, samples) catch {};
        f.lock.unlock();
        if (rd) |e| _ = sys.SetEvent(e);
    }

    pub fn capturingId(f: *Fake, buf: []u8) ?[]const u8 {
        f.lock.lock();
        defer f.lock.unlock();
        if (f.ready == null) return null;
        const id = f.started_id.get();
        @memcpy(buf[0..id.len], id);
        return buf[0..id.len];
    }

    fn of(ctx: *anyopaque) *Fake {
        return @ptrCast(@alignCast(ctx));
    }
    fn open(ctx: *anyopaque, changed: sys.HANDLE) anyerror!void {
        const f = of(ctx);
        f.lock.lock();
        defer f.lock.unlock();
        f.changed = changed;
    }
    fn close(ctx: *anyopaque) void {
        const f = of(ctx);
        f.lock.lock();
        defer f.lock.unlock();
        f.changed = null;
    }
    fn listFn(ctx: *anyopaque, out: *mics.List) anyerror!void {
        const f = of(ctx);
        f.lock.lock();
        defer f.lock.unlock();
        out.* = f.list;
    }
    fn startFn(ctx: *anyopaque, id: []const u8, ready: sys.HANDLE) anyerror!void {
        const f = of(ctx);
        f.lock.lock();
        defer f.lock.unlock();
        if (f.list.find(id) == null) return error.DeviceLost;
        f.started_id.set(id);
        f.ready = ready;
        f.lost = false;
        f.starts += 1;
    }
    fn readFn(ctx: *anyopaque, sink: Sink) anyerror!void {
        const f = of(ctx);
        f.lock.lock();
        defer f.lock.unlock();
        if (f.lost) return error.DeviceLost;
        sink.put(sink.ctx, f.queue.items);
        f.queue.clearRetainingCapacity();
    }
    fn stopFn(ctx: *anyopaque) void {
        const f = of(ctx);
        f.lock.lock();
        defer f.lock.unlock();
        f.ready = null;
        f.queue.clearRetainingCapacity();
        f.stops += 1;
    }
    const vt: Backend.VTable = .{ .open = open, .close = close, .list = listFn, .start = startFn, .read = readFn, .stop = stopFn };
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

/// Wakes counted by the test: an event the test waits on (no sleeping).
const Waker = struct {
    ev: sys.HANDLE,
    fn notify(ctx: *anyopaque) void {
        const w: *Waker = @ptrCast(@alignCast(ctx));
        _ = sys.SetEvent(w.ev);
    }
    /// Waits for notifications until `cond` holds (5 s at most).
    fn until(w: *Waker, m: *Mic, cond: *const fn (*Mic) bool) !void {
        var tries: usize = 0;
        while (!cond(m)) : (tries += 1) {
            if (tries > 200) return error.TestTimeout;
            _ = sys.WaitForSingleObject(w.ev, 25);
        }
    }
};

fn twoMics() mics.List {
    var l: mics.List = .{};
    var a = mics.testEndpoint("{builtin}", "Microphone Array", .microphone, .builtin);
    a.default_console = true;
    a.default_comms = true;
    l.append(a);
    return l;
}

test "mic thread: records only while asked, from the chosen endpoint; headset hot-plug moves it" {
    const gpa = testing.allocator;
    var fake: Fake = .{ .gpa = gpa, .list = twoMics() };
    defer fake.deinit();
    var waker: Waker = .{ .ev = try sys.autoEvent() };
    defer _ = sys.CloseHandle(waker.ev);
    var m: Mic = .{ .gpa = gpa, .backend = fake.backend(), .notify_ctx = &waker, .notify_fn = Waker.notify };
    try m.start();
    defer m.deinit();

    const S = struct {
        fn listed(x: *Mic) bool {
            var s: Snapshot = .{};
            x.snapshot(&s);
            return s.list_gen > 0;
        }
        fn capturing(x: *Mic) bool {
            var s: Snapshot = .{};
            x.snapshot(&s);
            return s.capturing;
        }
        fn idle(x: *Mic) bool {
            return !capturing(x);
        }
        fn done(x: *Mic) bool {
            x.lock.lock();
            defer x.lock.unlock();
            return x.done != null;
        }
        fn headset(x: *Mic) bool {
            var s: Snapshot = .{};
            x.snapshot(&s);
            const e = s.activeEndpoint() orelse return false;
            return e.isHeadset() and s.capturing;
        }
    };
    try waker.until(&m, S.listed);
    // Nothing is captured until asked: audio arriving now is dropped.
    try testing.expectEqual(@as(u32, 0), fake.starts);
    fake.feed(&.{ 1, 2, 3 });

    m.startRecording();
    try waker.until(&m, S.capturing);
    var idb: [mics.max_id]u8 = undefined;
    try testing.expectEqualStrings("{builtin}", fake.capturingId(&idb).?);
    fake.feed(&.{ 10, 20, 30, 40 });

    // A headset arrives mid-recording: the recording moves to it, and the
    // window gets a toast.
    var with_headset = twoMics();
    with_headset.append(mics.testEndpoint("{jabra}", "Jabra Evolve2", .headset, .usb));
    fake.plug(with_headset);
    try waker.until(&m, S.headset);
    try testing.expectEqualStrings("{jabra}", fake.capturingId(&idb).?);
    var cb: [128]u8 = undefined;
    try testing.expectEqualStrings("Headset connected: Jabra Evolve2", m.takeChange(&cb).?);
    try testing.expect(m.takeChange(&cb) == null);
    fake.feed(&.{ 50, 60 });

    m.stopRecording();
    try waker.until(&m, S.done);
    try waker.until(&m, S.idle);
    const rec = m.takeRecording().?;
    defer gpa.free(rec.samples);
    // Every sample from both endpoints, in order, none from before.
    try testing.expectEqualSlices(i16, &.{ 10, 20, 30, 40, 50, 60 }, rec.samples);
    try testing.expect(!rec.truncated);
    try testing.expectEqual(fake.starts, fake.stops);

    // The headset is unplugged: Automatic goes back to the built-in mic.
    fake.plug(twoMics());
    const S2 = struct {
        fn builtin(x: *Mic) bool {
            var s: Snapshot = .{};
            x.snapshot(&s);
            const e = s.activeEndpoint() orelse return false;
            return e.id.eql("{builtin}");
        }
    };
    try waker.until(&m, S2.builtin);
    try waker.until(&m, struct {
        fn f(x: *Mic) bool {
            var b: [128]u8 = undefined;
            const c = x.takeChange(&b) orelse return false;
            return std.mem.eql(u8, c, "Headset disconnected: Jabra Evolve2");
        }
    }.f);
}

test "mic thread: the meter captures while the panel is open; manual mode falls back" {
    const gpa = testing.allocator;
    var fake: Fake = .{ .gpa = gpa, .list = twoMics() };
    defer fake.deinit();
    var l = twoMics();
    l.append(mics.testEndpoint("{usb}", "USB mic", .microphone, .usb));
    fake.list = l;
    var waker: Waker = .{ .ev = try sys.autoEvent() };
    defer _ = sys.CloseHandle(waker.ev);
    var m: Mic = .{ .gpa = gpa, .backend = fake.backend(), .notify_ctx = &waker, .notify_fn = Waker.notify };
    try m.start();
    defer m.deinit();

    m.setMode(.{ .manual = "{usb}" });
    try waker.until(&m, struct {
        fn f(x: *Mic) bool {
            var s: Snapshot = .{};
            x.snapshot(&s);
            const e = s.activeEndpoint() orelse return false;
            return e.id.eql("{usb}") and !s.automatic;
        }
    }.f);
    m.setMeter(true);
    try waker.until(&m, struct {
        fn f(x: *Mic) bool {
            var s: Snapshot = .{};
            x.snapshot(&s);
            return s.capturing and !s.recording;
        }
    }.f);
    fake.feed(&.{ 16384, -16384 });
    try waker.until(&m, struct {
        fn f(x: *Mic) bool {
            var s: Snapshot = .{};
            x.snapshot(&s);
            return levelSteps(s.level) >= 9;
        }
    }.f);
    // The manual device goes: Automatic picks, and says it fell back.
    fake.plug(twoMics());
    try waker.until(&m, struct {
        fn f(x: *Mic) bool {
            var s: Snapshot = .{};
            x.snapshot(&s);
            const e = s.activeEndpoint() orelse return false;
            return e.id.eql("{builtin}") and s.fell_back and s.capturing;
        }
    }.f);
    m.setMeter(false);
    try waker.until(&m, struct {
        fn f(x: *Mic) bool {
            var s: Snapshot = .{};
            x.snapshot(&s);
            return !s.capturing and s.level == 0;
        }
    }.f);
    // The meter alone never produces a recording.
    try testing.expect(m.takeRecording() == null);
}

test "mic thread: a recording stops at the cap by itself; the buffer is the one allocated at start" {
    const gpa = testing.allocator;
    var l: mics.List = .{};
    l.append(mics.testEndpoint("{m}", "Mic", .microphone, .builtin));
    var fake: Fake = .{ .gpa = gpa, .list = l };
    defer fake.deinit();
    var waker: Waker = .{ .ev = try sys.autoEvent() };
    defer _ = sys.CloseHandle(waker.ev);
    var m: Mic = .{ .gpa = gpa, .backend = fake.backend(), .notify_ctx = &waker, .notify_fn = Waker.notify };
    try m.start();
    defer m.deinit();
    const buf_ptr = m.rec.ptr;
    try testing.expectEqual(@as(usize, max_samples), m.rec.len);
    m.startRecording();
    try waker.until(&m, struct {
        fn f(x: *Mic) bool {
            var s: Snapshot = .{};
            x.snapshot(&s);
            return s.capturing;
        }
    }.f);
    // 121 s of audio arrives: only 120 s are kept, and the recording ends
    // without the window asking.
    const chunk = try gpa.alloc(i16, sample_rate);
    defer gpa.free(chunk);
    @memset(chunk, 7);
    for (0..max_seconds + 1) |_| fake.feed(chunk);
    try waker.until(&m, struct {
        fn f(x: *Mic) bool {
            x.lock.lock();
            defer x.lock.unlock();
            return x.done != null;
        }
    }.f);
    const rec = m.takeRecording().?;
    defer gpa.free(rec.samples);
    try testing.expectEqual(@as(usize, max_samples), rec.samples.len);
    try testing.expect(rec.truncated);
    try testing.expect(m.rec.ptr == buf_ptr and m.rec.len == max_samples);
    try waker.until(&m, struct {
        fn f(x: *Mic) bool {
            var s: Snapshot = .{};
            x.snapshot(&s);
            return !s.capturing and !s.recording;
        }
    }.f);
}

test "peakLevel" {
    try testing.expectEqual(@as(f32, 0), peakLevel(&.{ 0, 0 }));
    try testing.expect(peakLevel(&.{ 0, 32767 }) > 0.99);
    try testing.expect(peakLevel(&.{33}) < 0.05); // about -60 dBFS
}
