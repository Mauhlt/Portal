//! The optional system monitor (owner's request, 2026-11-12): the
//! desktop's CPU, memory and GPU load and each tab's process tree, for the
//! System panel on the desk and on devices (docs/protocol.md section 3d).
//!
//! Sampling is the one deliberate exception to Portal's event-driven rule
//! (there is no event for "the CPU got busier"), and it is scoped hard:
//!   * nothing at all while the desk's "Show system monitor" setting is
//!     off (the default): no sampler thread, no PDH query, no counters, no
//!     deadline, no job accounting read; `subscribe` refuses;
//!   * with it on, still nothing until a System panel is open somewhere
//!     (the desk's, or a viewer that sent `y:on`);
//!   * then one sample per second, each on a real deadline aligned to the
//!     next second boundary;
//!   * the last panel closing, or the setting turned off, stops the
//!     sampler at once: its thread ends and the backend (PDH query,
//!     libraries) is closed.
//! `Monitor` holds that rule and nothing platform-specific; the Windows
//! backend (`WinBackend`) does the measuring. Tests use a fake backend.
//!
//! Numbers only: tab ids (names are the tab list's), never process names,
//! command lines, paths or user names.

const std = @import("std");
const w = @import("win32.zig");
const wire = @import("shared").sysinfo;
const tabs = @import("tabs.zig");

/// What measures. Called on the sampler thread only, between `open` and
/// `close`.
pub const Backend = struct {
    ctx: *anyopaque,
    /// Starts measuring (PDH query, first counter values); false: nothing
    /// to sample with (the sampler then stops).
    open: *const fn (ctx: *anyopaque) bool,
    sample: *const fn (ctx: *anyopaque, out: *wire.Snapshot) void,
    close: *const fn (ctx: *anyopaque) void,
};

/// A plain lock (SRW) usable without an Io: the monitor is driven from the
/// window, the viewers' threads and its own sampler thread.
const Lock = struct {
    srw: ?*anyopaque = null,
    fn lock(l: *Lock) void {
        AcquireSRWLockExclusive(&l.srw);
    }
    fn unlock(l: *Lock) void {
        ReleaseSRWLockExclusive(&l.srw);
    }
};
extern "kernel32" fn AcquireSRWLockExclusive(l: *?*anyopaque) callconv(.winapi) void;
extern "kernel32" fn ReleaseSRWLockExclusive(l: *?*anyopaque) callconv(.winapi) void;

pub const Monitor = struct {
    backend: Backend,
    /// Milliseconds between samples (deadlines aligned to its multiples).
    period_ms: u32 = 1000,
    /// Called after every sample (any thread may read `latest` then).
    notify_ctx: ?*anyopaque = null,
    notify_fn: ?*const fn (ctx: *anyopaque) void = null,

    /// Guards enabled, subs, thread (control only; the sampler thread
    /// never takes it, so stopping can join under it).
    ctl: Lock = .{},
    enabled: bool = false,
    subs: u32 = 0,
    thread: ?std.Thread = null,
    stop_ev: ?w.HANDLE = null,

    snap_mutex: Lock = .{},
    snap: wire.Snapshot = .{},
    /// Bumped after every sample; 0: none yet.
    gen: std.atomic.Value(u64) = .init(0),
    /// Counters for tests and the log.
    samples: std.atomic.Value(u32) = .init(0),
    starts: std.atomic.Value(u32) = .init(0),

    /// The setting changed. Off stops the sampler now (panels stay
    /// subscribed but get nothing until it is on again).
    pub fn setEnabled(m: *Monitor, on: bool) void {
        m.ctl.lock();
        defer m.ctl.unlock();
        m.enabled = on;
        m.update();
    }

    pub fn isEnabled(m: *Monitor) bool {
        m.ctl.lock();
        defer m.ctl.unlock();
        return m.enabled;
    }

    /// A System panel opened. False (and nothing counted, nothing started)
    /// while the setting is off.
    pub fn subscribe(m: *Monitor) bool {
        m.ctl.lock();
        defer m.ctl.unlock();
        if (!m.enabled) return false;
        m.subs += 1;
        m.update();
        return true;
    }

    /// A System panel that `subscribe` accepted closed.
    pub fn unsubscribe(m: *Monitor) void {
        m.ctl.lock();
        defer m.ctl.unlock();
        m.subs -|= 1;
        m.update();
    }

    /// The sampler runs exactly while enabled with a subscriber.
    pub fn running(m: *Monitor) bool {
        m.ctl.lock();
        defer m.ctl.unlock();
        return m.thread != null;
    }

    /// Caller holds `ctl`.
    fn update(m: *Monitor) void {
        const want = m.enabled and m.subs > 0;
        if (want and m.thread == null) {
            const ev = w.validHandle(w.CreateEventW(null, 1, 0, null)) orelse return;
            m.stop_ev = ev;
            m.thread = std.Thread.spawn(.{}, run, .{m}) catch {
                _ = w.CloseHandle(ev);
                m.stop_ev = null;
                return;
            };
            _ = m.starts.fetchAdd(1, .monotonic);
        } else if (!want and m.thread != null) {
            _ = w.SetEvent(m.stop_ev.?);
            m.thread.?.join();
            m.thread = null;
            _ = w.CloseHandle(m.stop_ev.?);
            m.stop_ev = null;
            // Viewers keep the last numbers; nothing new comes.
        }
    }

    /// Stops the sampler for good (shutdown).
    pub fn deinit(m: *Monitor) void {
        m.ctl.lock();
        defer m.ctl.unlock();
        m.enabled = false;
        m.update();
    }

    /// The latest sample.
    pub fn latest(m: *Monitor, out: *wire.Snapshot) u64 {
        m.snap_mutex.lock();
        defer m.snap_mutex.unlock();
        out.* = m.snap;
        return m.gen.load(.acquire);
    }

    fn run(m: *Monitor) void {
        const b = m.backend;
        if (!b.open(b.ctx)) return;
        defer b.close(b.ctx);
        var tmp: wire.Snapshot = .{};
        while (true) {
            b.sample(b.ctx, &tmp);
            m.snap_mutex.lock();
            m.snap = tmp;
            m.snap_mutex.unlock();
            _ = m.gen.fetchAdd(1, .acq_rel);
            _ = m.samples.fetchAdd(1, .monotonic);
            if (m.notify_fn) |f| f(m.notify_ctx.?);
            if (w.WaitForSingleObject(m.stop_ev.?, untilNext(m.period_ms, nowMs())) == w.WAIT_OBJECT_0) return;
        }
    }
};

fn nowMs() i64 {
    var ft: w.FILETIME = undefined;
    w.GetSystemTimeAsFileTime(&ft);
    return @intCast(ft.toU64() / 10_000);
}

/// Milliseconds from `now` to the next multiple of `period`, at least half
/// a period (a sample just before a boundary waits for the one after).
pub fn untilNext(period: u32, now: i64) u32 {
    const p: i64 = period;
    var left = p - @mod(now, p);
    if (left < @divFloor(p, 2)) left += p;
    return @intCast(left);
}

/// CPU busy share in tenths of a percent from two readings of
/// (idle, kernel, user) times; kernel time includes idle time.
pub fn cpuTenths(idle0: u64, kernel0: u64, user0: u64, idle1: u64, kernel1: u64, user1: u64) u16 {
    const total = (kernel1 -% kernel0) +% (user1 -% user0);
    if (total == 0) return 0;
    const idle = idle1 -% idle0;
    const busy = total -| idle;
    return @intCast(@min(1000, busy * 1000 / total));
}

/// A tab's share of the whole machine in tenths of a percent: CPU time its
/// job used (100 ns units) over `wall` (100 ns) on `cpus` processors.
pub fn jobTenths(used: u64, wall: u64, cpus: u32) u16 {
    const cap = wall * @max(cpus, 1);
    if (cap == 0) return 0;
    return @intCast(@min(1000, used * 1000 / cap));
}

// ----------------------------------------------------------- Windows backend

const PDH_FMT_DOUBLE: u32 = 0x00000200;
const PDH_FMT_LARGE: u32 = 0x00000400;
const PDH_FMT_NOCAP100: u32 = 0x00008000;
const PDH_MORE_DATA: u32 = 0x800007D2;

const PdhValue = extern struct {
    status: u32,
    v: extern union { long: i32, double: f64, large: i64, ptr: ?*anyopaque },
};
const PdhItem = extern struct {
    name: [*:0]u16,
    value: PdhValue,
};

const PdhOpenQueryW = *const fn (?[*:0]const u16, usize, *?*anyopaque) callconv(.winapi) u32;
const PdhAddEnglishCounterW = *const fn (?*anyopaque, [*:0]const u16, usize, *?*anyopaque) callconv(.winapi) u32;
const PdhCollectQueryData = *const fn (?*anyopaque) callconv(.winapi) u32;
const PdhGetFormattedCounterArrayW = *const fn (?*anyopaque, u32, *u32, *u32, ?*anyopaque) callconv(.winapi) u32;
const PdhCloseQuery = *const fn (?*anyopaque) callconv(.winapi) u32;

const Guid = extern struct { a: u32, b: u16, c: u16, d: [8]u8 };
const iid_factory1: Guid = .{ .a = 0x770aae78, .b = 0xf26f, .c = 0x4dba, .d = .{ 0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87 } };
const CreateDXGIFactory1 = *const fn (*const Guid, *?*anyopaque) callconv(.winapi) i32;
const AdapterDesc1 = extern struct {
    description: [128]u16,
    vendor: u32,
    device: u32,
    subsys: u32,
    revision: u32,
    dedicated_video: usize,
    dedicated_system: usize,
    shared_system: usize,
    luid_low: u32,
    luid_high: i32,
    flags: u32,
};
const ComObj = extern struct { vtbl: [*]const ?*const anyopaque };

const MemoryStatusEx = extern struct {
    len: u32 = @sizeOf(MemoryStatusEx),
    load: u32 = 0,
    total_phys: u64 = 0,
    avail_phys: u64 = 0,
    total_page: u64 = 0,
    avail_page: u64 = 0,
    total_virtual: u64 = 0,
    avail_virtual: u64 = 0,
    avail_ext: u64 = 0,
};
const JobAccounting = extern struct {
    user: i64,
    kernel: i64,
    period_user: i64,
    period_kernel: i64,
    page_faults: u32,
    total_procs: u32,
    active_procs: u32,
    terminated: u32,
};
const JobPids = extern struct {
    assigned: u32,
    in_list: u32,
    pids: [256]usize,
};
const ProcessMemory = extern struct {
    cb: u32 = @sizeOf(ProcessMemory),
    faults: u32 = 0,
    peak_ws: usize = 0,
    ws: usize = 0,
    qpp_peak: usize = 0,
    qpp: usize = 0,
    qnp_peak: usize = 0,
    qnp: usize = 0,
    pagefile: usize = 0,
    pagefile_peak: usize = 0,
};

extern "kernel32" fn LoadLibraryW(name: [*:0]const u16) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn FreeLibrary(m: *anyopaque) callconv(.winapi) w.BOOL;
extern "kernel32" fn GetProcAddress(m: *anyopaque, name: [*:0]const u8) callconv(.winapi) ?*const anyopaque;
extern "kernel32" fn GetSystemTimes(idle: *w.FILETIME, kernel: *w.FILETIME, user: *w.FILETIME) callconv(.winapi) w.BOOL;
extern "kernel32" fn GlobalMemoryStatusEx(m: *MemoryStatusEx) callconv(.winapi) w.BOOL;
extern "kernel32" fn QueryInformationJobObject(job: w.HANDLE, class: c_int, info: *anyopaque, len: u32, ret: ?*u32) callconv(.winapi) w.BOOL;
extern "kernel32" fn K32GetProcessMemoryInfo(p: w.HANDLE, m: *ProcessMemory, cb: u32) callconv(.winapi) w.BOOL;
extern "kernel32" fn Sleep(ms: u32) callconv(.winapi) void;
extern "kernel32" fn GetActiveProcessorCount(group: u16) callconv(.winapi) u32;

const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const JobObjectBasicAccountingInformation: c_int = 1;
const JobObjectBasicProcessIdList: c_int = 3;

const Adapter = struct { luid: u64, total: u64, util: f64 = 0, used: u64 = 0 };

/// The Windows backend: GetSystemTimes, GlobalMemoryStatusEx, PDH's GPU
/// counters (vendor-neutral) with DXGI for the adapters' VRAM sizes, and
/// each tab's job object. pdh.dll and dxgi.dll are loaded in `open` and
/// freed in `close`: nothing of it exists while the sampler is stopped.
pub const WinBackend = struct {
    gpa: std.mem.Allocator,
    hub: *tabs.Hub,

    pdh: ?*anyopaque = null,
    query: ?*anyopaque = null,
    engine: ?*anyopaque = null,
    vram: ?*anyopaque = null,
    collect: ?PdhCollectQueryData = null,
    array: ?PdhGetFormattedCounterArrayW = null,
    close_query: ?PdhCloseQuery = null,
    adapters: [wire.max_gpus]Adapter = undefined,
    n_adapters: usize = 0,
    cpus: u32 = 1,
    sys0: [3]u64 = .{ 0, 0, 0 },
    wall0: u64 = 0,
    /// The previous job CPU time per tab (100 ns), matched by id.
    prev: [tabs.max_tabs]struct { id: tabs.Id, used: u64 } = undefined,
    n_prev: usize = 0,
    buf: std.ArrayList(u8) = .empty,

    pub fn backend(b: *WinBackend) Backend {
        return .{ .ctx = b, .open = openThunk, .sample = sampleThunk, .close = closeThunk };
    }

    fn of(ctx: *anyopaque) *WinBackend {
        return @ptrCast(@alignCast(ctx));
    }

    fn openThunk(ctx: *anyopaque) bool {
        const b = of(ctx);
        b.cpus = @max(1, GetActiveProcessorCount(0xFFFF));
        b.n_prev = 0;
        b.readAdapters();
        b.openPdh();
        _ = b.systemTimes();
        b.wall0 = wallNow();
        return true;
    }

    fn closeThunk(ctx: *anyopaque) void {
        const b = of(ctx);
        if (b.close_query) |f| if (b.query) |q| {
            _ = f(q);
        };
        b.query = null;
        b.engine = null;
        b.vram = null;
        if (b.pdh) |m| _ = FreeLibrary(m);
        b.pdh = null;
        b.collect = null;
        b.array = null;
        b.close_query = null;
        b.buf.deinit(b.gpa);
        b.buf = .empty;
    }

    fn wallNow() u64 {
        var ft: w.FILETIME = undefined;
        w.GetSystemTimeAsFileTime(&ft);
        return ft.toU64();
    }

    fn systemTimes(b: *WinBackend) [3]u64 {
        var i: w.FILETIME = undefined;
        var k: w.FILETIME = undefined;
        var u: w.FILETIME = undefined;
        if (GetSystemTimes(&i, &k, &u) == 0) return b.sys0;
        return .{ i.toU64(), k.toU64(), u.toU64() };
    }

    /// The hardware adapters (DXGI, software ones skipped) and their VRAM.
    fn readAdapters(b: *WinBackend) void {
        b.n_adapters = 0;
        const lib = LoadLibraryW(std.unicode.utf8ToUtf16LeStringLiteral("dxgi.dll")) orelse return;
        defer _ = FreeLibrary(lib);
        const create: CreateDXGIFactory1 = @ptrCast(GetProcAddress(lib, "CreateDXGIFactory1") orelse return);
        var fac: ?*anyopaque = null;
        if (create(&iid_factory1, &fac) < 0) return;
        const f: *ComObj = @ptrCast(@alignCast(fac orelse return));
        defer comRelease(f);
        const EnumAdapters1 = *const fn (*ComObj, u32, *?*anyopaque) callconv(.winapi) i32;
        const GetDesc1 = *const fn (*ComObj, *AdapterDesc1) callconv(.winapi) i32;
        const enumerate: EnumAdapters1 = @ptrCast(f.vtbl[12].?);
        var i: u32 = 0;
        while (b.n_adapters < wire.max_gpus and i < 16) : (i += 1) {
            var ad: ?*anyopaque = null;
            if (enumerate(f, i, &ad) < 0) break;
            const a: *ComObj = @ptrCast(@alignCast(ad orelse break));
            defer comRelease(a);
            const desc_fn: GetDesc1 = @ptrCast(a.vtbl[10].?);
            var d: AdapterDesc1 = undefined;
            if (desc_fn(a, &d) < 0) continue;
            if (d.flags & 2 != 0) continue; // DXGI_ADAPTER_FLAG_SOFTWARE
            const luid = (@as(u64, @as(u32, @bitCast(d.luid_high))) << 32) | d.luid_low;
            b.adapters[b.n_adapters] = .{ .luid = luid, .total = d.dedicated_video };
            b.n_adapters += 1;
        }
    }

    fn comRelease(o: *ComObj) void {
        const Release = *const fn (*ComObj) callconv(.winapi) u32;
        const r: Release = @ptrCast(o.vtbl[2].?);
        _ = r(o);
    }

    fn openPdh(b: *WinBackend) void {
        const lib = LoadLibraryW(std.unicode.utf8ToUtf16LeStringLiteral("pdh.dll")) orelse return;
        b.pdh = lib;
        const open: PdhOpenQueryW = @ptrCast(GetProcAddress(lib, "PdhOpenQueryW") orelse return);
        const add: PdhAddEnglishCounterW = @ptrCast(GetProcAddress(lib, "PdhAddEnglishCounterW") orelse return);
        b.collect = @ptrCast(GetProcAddress(lib, "PdhCollectQueryData") orelse return);
        b.array = @ptrCast(GetProcAddress(lib, "PdhGetFormattedCounterArrayW") orelse return);
        b.close_query = @ptrCast(GetProcAddress(lib, "PdhCloseQuery") orelse return);
        if (open(null, 0, &b.query) != 0) {
            b.query = null;
            return;
        }
        if (add(b.query, std.unicode.utf8ToUtf16LeStringLiteral("\\GPU Engine(*)\\Utilization Percentage"), 0, &b.engine) != 0) b.engine = null;
        if (add(b.query, std.unicode.utf8ToUtf16LeStringLiteral("\\GPU Adapter Memory(*)\\Dedicated Usage"), 0, &b.vram) != 0) b.vram = null;
        _ = b.collect.?(b.query); // rates need two collections
    }

    fn sampleThunk(ctx: *anyopaque, out: *wire.Snapshot) void {
        of(ctx).sample(out);
    }

    fn sample(b: *WinBackend, out: *wire.Snapshot) void {
        out.* = .{};
        const s1 = b.systemTimes();
        out.cpu = cpuTenths(b.sys0[0], b.sys0[1], b.sys0[2], s1[0], s1[1], s1[2]);
        b.sys0 = s1;
        var ms: MemoryStatusEx = .{};
        if (GlobalMemoryStatusEx(&ms) != 0) {
            out.mem_total = ms.total_phys;
            out.mem_used = ms.total_phys -| ms.avail_phys;
        }
        b.gpus(out);
        const wall1 = wallNow();
        const wall = wall1 -% b.wall0;
        b.wall0 = wall1;
        b.tabLoads(out, wall);
    }

    fn gpus(b: *WinBackend, out: *wire.Snapshot) void {
        for (b.adapters[0..b.n_adapters]) |*a| {
            a.util = 0;
            a.used = 0;
        }
        if (b.query != null and b.collect != null and b.collect.?(b.query) == 0) {
            // Utilisation: per adapter, the busiest engine type (summed
            // over processes), as Task Manager shows it.
            var types: [32]struct { luid: u64, eng: u64, sum: f64 } = undefined;
            var n_types: usize = 0;
            if (b.items(b.engine, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100)) |list| for (list) |it| {
                if (it.value.status > 1) continue;
                var nb: [256]u8 = undefined;
                const name = utf8(it.name, &nb);
                const luid = parseLuid(name) orelse continue;
                const eng = std.hash.Wyhash.hash(0, afterTag(name, "engtype_") orelse "");
                var found = false;
                for (types[0..n_types]) |*t| if (t.luid == luid and t.eng == eng) {
                    t.sum += it.value.v.double;
                    found = true;
                };
                if (!found and n_types < types.len) {
                    types[n_types] = .{ .luid = luid, .eng = eng, .sum = it.value.v.double };
                    n_types += 1;
                }
            };
            for (types[0..n_types]) |t| if (b.adapter(t.luid)) |a| {
                a.util = @max(a.util, t.sum);
            };
            if (b.items(b.vram, PDH_FMT_LARGE)) |list| for (list) |it| {
                if (it.value.status > 1) continue;
                var nb: [256]u8 = undefined;
                const luid = parseLuid(utf8(it.name, &nb)) orelse continue;
                if (b.adapter(luid)) |a| a.used +|= @intCast(@max(it.value.v.large, 0));
            };
        }
        for (b.adapters[0..b.n_adapters]) |a| {
            out.gpus[out.n_gpus] = .{ .util = @intFromFloat(@min(1000, @max(0, a.util * 10))), .used = a.used, .total = a.total };
            out.n_gpus += 1;
        }
    }

    fn adapter(b: *WinBackend, luid: u64) ?*Adapter {
        for (b.adapters[0..b.n_adapters]) |*a| if (a.luid == luid) return a;
        return null;
    }

    /// A counter's instances (in `buf`), or null.
    fn items(b: *WinBackend, counter: ?*anyopaque, fmt: u32) ?[]const PdhItem {
        const c = counter orelse return null;
        const f = b.array orelse return null;
        var size: u32 = 0;
        var count: u32 = 0;
        if (f(c, fmt, &size, &count, null) != PDH_MORE_DATA or size == 0) return null;
        b.buf.resize(b.gpa, size + @alignOf(PdhItem)) catch return null;
        const base = std.mem.alignForward(usize, @intFromPtr(b.buf.items.ptr), @alignOf(PdhItem));
        const ptr: [*]PdhItem = @ptrFromInt(base);
        if (f(c, fmt, &size, &count, ptr) != 0) return null;
        return ptr[0..count];
    }

    fn tabLoads(b: *WinBackend, out: *wire.Snapshot, wall: u64) void {
        var list: [tabs.max_tabs]*tabs.Tab = undefined;
        const open = b.hub.snapshot(&list);
        defer for (open) |t| t.release();
        var next: @TypeOf(b.prev) = undefined;
        var n_next: usize = 0;
        for (open) |t| {
            var l: wire.TabLoad = .{ .id = t.id };
            var acc: JobAccounting = undefined;
            if (QueryInformationJobObject(t.pty.job, JobObjectBasicAccountingInformation, &acc, @sizeOf(JobAccounting), null) != 0) {
                const used: u64 = @intCast(@max(0, acc.user) + @max(0, acc.kernel));
                l.procs = acc.active_procs;
                for (b.prev[0..b.n_prev]) |p| if (std.mem.eql(u8, &p.id, &t.id)) {
                    l.cpu = jobTenths(used -| p.used, wall, b.cpus);
                };
                next[n_next] = .{ .id = t.id, .used = used };
                n_next += 1;
            }
            var pids: JobPids = undefined;
            if (QueryInformationJobObject(t.pty.job, JobObjectBasicProcessIdList, &pids, @sizeOf(JobPids), null) != 0) {
                for (pids.pids[0..@min(pids.in_list, pids.pids.len)]) |pid| {
                    const h = w.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, @intCast(pid)) orelse continue;
                    defer _ = w.CloseHandle(h);
                    var pm: ProcessMemory = .{};
                    if (K32GetProcessMemoryInfo(h, &pm, @sizeOf(ProcessMemory)) != 0) l.mem +|= pm.ws;
                }
            }
            out.tabs[out.n_tabs] = l;
            out.n_tabs += 1;
        }
        b.prev = next;
        b.n_prev = n_next;
    }
};

fn utf8(name: [*:0]const u16, buf: []u8) []const u8 {
    const units = std.mem.sliceTo(name, 0);
    const n = std.unicode.wtf16LeToWtf8(buf, units[0..@min(units.len, buf.len / 3)]);
    return buf[0..n];
}

fn afterTag(s: []const u8, tag: []const u8) ?[]const u8 {
    const i = std.mem.indexOf(u8, s, tag) orelse return null;
    const rest = s[i + tag.len ..];
    const end = std.mem.indexOfScalar(u8, rest, '_') orelse rest.len;
    return rest[0..end];
}

/// `..._luid_0x00000000_0x0000D1B6_...` → the adapter LUID (high << 32 | low).
pub fn parseLuid(name: []const u8) ?u64 {
    const i = std.mem.indexOf(u8, name, "luid_0x") orelse return null;
    const s = name[i + "luid_0x".len ..];
    if (s.len < 8 + 3 + 8 or !std.mem.eql(u8, s[8..11], "_0x")) return null;
    const hi = std.fmt.parseInt(u32, s[0..8], 16) catch return null;
    const lo = std.fmt.parseInt(u32, s[11..19], 16) catch return null;
    return (@as(u64, hi) << 32) | lo;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

const Fake = struct {
    opens: std.atomic.Value(u32) = .init(0),
    closes: std.atomic.Value(u32) = .init(0),
    calls: std.atomic.Value(u32) = .init(0),

    fn backend(f: *Fake) Backend {
        return .{ .ctx = f, .open = open, .sample = sample, .close = close };
    }
    fn of(ctx: *anyopaque) *Fake {
        return @ptrCast(@alignCast(ctx));
    }
    fn open(ctx: *anyopaque) bool {
        _ = of(ctx).opens.fetchAdd(1, .monotonic);
        return true;
    }
    fn sample(ctx: *anyopaque, out: *wire.Snapshot) void {
        const n = of(ctx).calls.fetchAdd(1, .monotonic);
        out.* = .{ .cpu = @intCast(n % 1000) };
    }
    fn close(ctx: *anyopaque) void {
        _ = of(ctx).closes.fetchAdd(1, .monotonic);
    }
};

fn waitFor(v: *std.atomic.Value(u32), at_least: u32) bool {
    var i: u32 = 0;
    while (v.load(.acquire) < at_least) : (i += 1) {
        if (i > 500) return false;
        Sleep(10);
    }
    return true;
}

test "off (the default): subscribing samples nothing, opens nothing, arms no deadline" {
    var f: Fake = .{};
    var m: Monitor = .{ .backend = f.backend(), .period_ms = 20 };
    defer m.deinit();
    try testing.expect(!m.subscribe());
    try testing.expect(!m.subscribe());
    try testing.expect(!m.running());
    try testing.expect(m.stop_ev == null); // no deadline to wait on
    m.unsubscribe(); // harmless
    Sleep(60);
    try testing.expectEqual(@as(u32, 0), f.opens.load(.acquire));
    try testing.expectEqual(@as(u32, 0), f.calls.load(.acquire));
    try testing.expectEqual(@as(u32, 0), m.starts.load(.acquire));
    try testing.expectEqual(@as(u64, 0), m.gen.load(.acquire));
}

test "on: samples only while a panel is open; the last one closing stops it" {
    var f: Fake = .{};
    var m: Monitor = .{ .backend = f.backend(), .period_ms = 20 };
    defer m.deinit();
    m.setEnabled(true);
    try testing.expect(!m.running()); // on, but no panel open: nothing
    try testing.expectEqual(@as(u32, 0), f.opens.load(.acquire));
    try testing.expect(m.subscribe());
    try testing.expect(m.subscribe());
    try testing.expect(m.running());
    try testing.expect(waitFor(&f.calls, 3));
    var snap: wire.Snapshot = undefined;
    try testing.expect(m.latest(&snap) >= 3);
    m.unsubscribe();
    try testing.expect(m.running()); // one panel still open
    m.unsubscribe();
    try testing.expect(!m.running());
    try testing.expectEqual(@as(u32, 1), f.opens.load(.acquire));
    try testing.expectEqual(@as(u32, 1), f.closes.load(.acquire));
    const n = f.calls.load(.acquire);
    Sleep(80);
    try testing.expectEqual(n, f.calls.load(.acquire)); // stopped for real
}

test "turning the setting off stops at once; back on resumes for open panels" {
    var f: Fake = .{};
    var m: Monitor = .{ .backend = f.backend(), .period_ms = 20 };
    defer m.deinit();
    m.setEnabled(true);
    try testing.expect(m.subscribe());
    try testing.expect(waitFor(&f.calls, 1));
    m.setEnabled(false);
    try testing.expect(!m.running());
    try testing.expectEqual(@as(u32, 1), f.closes.load(.acquire));
    try testing.expect(!m.subscribe()); // refused while off
    m.setEnabled(true);
    try testing.expect(m.running()); // the panel still open
    try testing.expect(waitFor(&f.opens, 2));
}

test "deadlines align to the next period; CPU and job math" {
    try testing.expectEqual(@as(u32, 1000), untilNext(1000, 5000));
    try testing.expectEqual(@as(u32, 700), untilNext(1000, 5300));
    try testing.expectEqual(@as(u32, 1100), untilNext(1000, 5900)); // too close: the one after
    // 4 s total over the interval, 1 s idle: 75 %.
    try testing.expectEqual(@as(u16, 750), cpuTenths(100, 1000, 500, 1100, 4000, 1500));
    try testing.expectEqual(@as(u16, 0), cpuTenths(1, 2, 3, 1, 2, 3));
    // 0.5 s of CPU in 1 s on 4 processors: 12.5 % of the machine.
    try testing.expectEqual(@as(u16, 125), jobTenths(5_000_000, 10_000_000, 4));
    try testing.expectEqual(@as(u16, 1000), jobTenths(99_000_000, 10_000_000, 1));
    try testing.expectEqual(@as(?u64, 0x0000D1B6), parseLuid("pid_1234_luid_0x00000000_0x0000D1B6_phys_0_eng_0_engtype_3D"));
    try testing.expectEqual(@as(?u64, 0x1_0000_0002), parseLuid("luid_0x00000001_0x00000002_phys_0"));
    try testing.expect(parseLuid("luid_0xZZ") == null);
    try testing.expectEqualStrings("3D", afterTag("pid_1_luid_0x0_0x0_phys_0_eng_0_engtype_3D", "engtype_").?);
}
