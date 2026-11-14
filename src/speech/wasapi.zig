//! The Windows capture backend (capture.Backend) on the Core Audio APIs:
//!
//!   * IMMDeviceEnumerator lists the active capture endpoints with their
//!     friendly name, form factor (PKEY_AudioEndpoint_FormFactor) and bus
//!     (PKEY_Device_EnumeratorName), and the default communications /
//!     console capture devices;
//!   * an IMMNotificationClient registered with it signals the microphone
//!     thread's `changed` event on any add / remove / state / default
//!     change (the callbacks only SetEvent: COM forbids blocking there);
//!   * IAudioClient in shared mode with AUDCLNT_STREAMFLAGS_EVENTCALLBACK
//!     and AUTOCONVERTPCM delivers 16 kHz mono s16le, the audio engine
//!     doing the conversion; IAudioCaptureClient drains the packets each
//!     time the event fires. No polling.
//!
//! Every method runs on the microphone thread, which this backend puts in
//! the multithreaded apartment.

const std = @import("std");
const sys = @import("sys.zig");
const mics = @import("mics.zig");
const capture = @import("capture.zig");

const HRESULT = i32;
const GUID = extern struct { a: u32, b: u16, c: u16, d: [8]u8 };

fn guid(comptime s: []const u8) GUID {
    @setEvalBranchQuota(10000);
    const hex = struct {
        fn n(comptime t: []const u8) comptime_int {
            return std.fmt.parseInt(u64, t, 16) catch unreachable;
        }
    }.n;
    return .{
        .a = hex(s[0..8]),
        .b = hex(s[9..13]),
        .c = hex(s[14..18]),
        .d = .{ hex(s[19..21]), hex(s[21..23]), hex(s[24..26]), hex(s[26..28]), hex(s[28..30]), hex(s[30..32]), hex(s[32..34]), hex(s[34..36]) },
    };
}

const CLSID_MMDeviceEnumerator = guid("BCDE0395-E52F-467C-8E3D-C4579291692E");
const IID_IMMDeviceEnumerator = guid("A95664D2-9614-4F35-A746-DE8DB63617E6");
const IID_IAudioClient = guid("1CB9AD4C-DBFA-4C32-B178-C2F568A703B2");
const IID_IAudioCaptureClient = guid("C8ADBD64-E71E-48A0-A4DE-185C395CD317");
const IID_IMMNotificationClient = guid("7991EEC9-7E89-4D85-8390-6C703CEC60C0");
const IID_IUnknown = guid("00000000-0000-0000-C000-000000000046");

const PROPERTYKEY = extern struct { fmtid: GUID, pid: u32 };
const PKEY_Device_FriendlyName: PROPERTYKEY = .{ .fmtid = guid("A45C254E-DF1C-4EFD-8020-67D146A850E0"), .pid = 14 };
const PKEY_Device_EnumeratorName: PROPERTYKEY = .{ .fmtid = guid("A45C254E-DF1C-4EFD-8020-67D146A850E0"), .pid = 24 };
const PKEY_AudioEndpoint_FormFactor: PROPERTYKEY = .{ .fmtid = guid("1DA5D803-D492-4EDD-8C23-E0C0FFEE7F0E"), .pid = 0 };

const PROPVARIANT = extern struct {
    vt: u16 = 0,
    r1: u16 = 0,
    r2: u16 = 0,
    r3: u16 = 0,
    data: extern union {
        pwsz: ?[*:0]u16,
        ul: u32,
        pair: extern struct { a: usize, b: usize },
    } = .{ .pair = .{ .a = 0, .b = 0 } },
};
const VT_UI4: u16 = 19;
const VT_LPWSTR: u16 = 31;

const WAVEFORMATEX = extern struct {
    wFormatTag: u16,
    nChannels: u16,
    nSamplesPerSec: u32,
    nAvgBytesPerSec: u32,
    nBlockAlign: u16,
    wBitsPerSample: u16,
    cbSize: u16,
};

const eCapture: u32 = 1;
const eConsole: u32 = 0;
const eCommunications: u32 = 2;
const DEVICE_STATE_ACTIVE: u32 = 1;
const CLSCTX_ALL: u32 = 0x17;
const STGM_READ: u32 = 0;
const COINIT_MULTITHREADED: u32 = 0;
const AUDCLNT_SHAREMODE_SHARED: u32 = 0;
const AUDCLNT_STREAMFLAGS_EVENTCALLBACK: u32 = 0x00040000;
const AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM: u32 = 0x80000000;
const AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY: u32 = 0x08000000;
const AUDCLNT_BUFFERFLAGS_SILENT: u32 = 0x2;
const AUDCLNT_E_DEVICE_INVALIDATED: HRESULT = @bitCast(@as(u32, 0x88890004));
const E_NOINTERFACE: HRESULT = @bitCast(@as(u32, 0x80004002));
const E_ACCESSDENIED: HRESULT = @bitCast(@as(u32, 0x80070005));

extern "ole32" fn CoInitializeEx(reserved: ?*anyopaque, coinit: u32) callconv(.winapi) HRESULT;
extern "ole32" fn CoUninitialize() callconv(.winapi) void;
extern "ole32" fn CoCreateInstance(clsid: *const GUID, outer: ?*anyopaque, ctx: u32, iid: *const GUID, out: *?*anyopaque) callconv(.winapi) HRESULT;
extern "ole32" fn CoTaskMemFree(p: ?*anyopaque) callconv(.winapi) void;
extern "ole32" fn PropVariantClear(p: *PROPVARIANT) callconv(.winapi) HRESULT;

fn ok(hr: HRESULT) bool {
    return hr >= 0;
}

// ---- COM interfaces (vtables in declaration order, IUnknown first)

fn Unknown(comptime Self: type) type {
    return extern struct {
        QueryInterface: *const fn (*Self, *const GUID, *?*anyopaque) callconv(.winapi) HRESULT,
        AddRef: *const fn (*Self) callconv(.winapi) u32,
        Release: *const fn (*Self) callconv(.winapi) u32,
    };
}

const IMMDeviceEnumerator = extern struct {
    vt: *const extern struct {
        unk: Unknown(IMMDeviceEnumerator),
        EnumAudioEndpoints: *const fn (*IMMDeviceEnumerator, u32, u32, *?*IMMDeviceCollection) callconv(.winapi) HRESULT,
        GetDefaultAudioEndpoint: *const fn (*IMMDeviceEnumerator, u32, u32, *?*IMMDevice) callconv(.winapi) HRESULT,
        GetDevice: *const fn (*IMMDeviceEnumerator, [*:0]const u16, *?*IMMDevice) callconv(.winapi) HRESULT,
        RegisterEndpointNotificationCallback: *const fn (*IMMDeviceEnumerator, *NotificationClient) callconv(.winapi) HRESULT,
        UnregisterEndpointNotificationCallback: *const fn (*IMMDeviceEnumerator, *NotificationClient) callconv(.winapi) HRESULT,
    },
};

const IMMDeviceCollection = extern struct {
    vt: *const extern struct {
        unk: Unknown(IMMDeviceCollection),
        GetCount: *const fn (*IMMDeviceCollection, *u32) callconv(.winapi) HRESULT,
        Item: *const fn (*IMMDeviceCollection, u32, *?*IMMDevice) callconv(.winapi) HRESULT,
    },
};

const IMMDevice = extern struct {
    vt: *const extern struct {
        unk: Unknown(IMMDevice),
        Activate: *const fn (*IMMDevice, *const GUID, u32, ?*PROPVARIANT, *?*anyopaque) callconv(.winapi) HRESULT,
        OpenPropertyStore: *const fn (*IMMDevice, u32, *?*IPropertyStore) callconv(.winapi) HRESULT,
        GetId: *const fn (*IMMDevice, *?[*:0]u16) callconv(.winapi) HRESULT,
        GetState: *const fn (*IMMDevice, *u32) callconv(.winapi) HRESULT,
    },
};

const IPropertyStore = extern struct {
    vt: *const extern struct {
        unk: Unknown(IPropertyStore),
        GetCount: *const fn (*IPropertyStore, *u32) callconv(.winapi) HRESULT,
        GetAt: *const fn (*IPropertyStore, u32, *PROPERTYKEY) callconv(.winapi) HRESULT,
        GetValue: *const fn (*IPropertyStore, *const PROPERTYKEY, *PROPVARIANT) callconv(.winapi) HRESULT,
    },
};

const IAudioClient = extern struct {
    vt: *const extern struct {
        unk: Unknown(IAudioClient),
        Initialize: *const fn (*IAudioClient, u32, u32, i64, i64, *const WAVEFORMATEX, ?*const GUID) callconv(.winapi) HRESULT,
        GetBufferSize: *const fn (*IAudioClient, *u32) callconv(.winapi) HRESULT,
        GetStreamLatency: *const fn (*IAudioClient, *i64) callconv(.winapi) HRESULT,
        GetCurrentPadding: *const fn (*IAudioClient, *u32) callconv(.winapi) HRESULT,
        IsFormatSupported: *const fn (*IAudioClient, u32, *const WAVEFORMATEX, *?*WAVEFORMATEX) callconv(.winapi) HRESULT,
        GetMixFormat: *const fn (*IAudioClient, *?*WAVEFORMATEX) callconv(.winapi) HRESULT,
        GetDevicePeriod: *const fn (*IAudioClient, *i64, *i64) callconv(.winapi) HRESULT,
        Start: *const fn (*IAudioClient) callconv(.winapi) HRESULT,
        Stop: *const fn (*IAudioClient) callconv(.winapi) HRESULT,
        Reset: *const fn (*IAudioClient) callconv(.winapi) HRESULT,
        SetEventHandle: *const fn (*IAudioClient, sys.HANDLE) callconv(.winapi) HRESULT,
        GetService: *const fn (*IAudioClient, *const GUID, *?*anyopaque) callconv(.winapi) HRESULT,
    },
};

const IAudioCaptureClient = extern struct {
    vt: *const extern struct {
        unk: Unknown(IAudioCaptureClient),
        GetBuffer: *const fn (*IAudioCaptureClient, *?[*]u8, *u32, *u32, ?*u64, ?*u64) callconv(.winapi) HRESULT,
        ReleaseBuffer: *const fn (*IAudioCaptureClient, u32) callconv(.winapi) HRESULT,
        GetNextPacketSize: *const fn (*IAudioCaptureClient, *u32) callconv(.winapi) HRESULT,
    },
};

fn release(p: anytype) void {
    _ = p.vt.unk.Release(p);
}

/// Our IMMNotificationClient: every callback signals `changed` and
/// returns. Lives inside the backend (never freed while registered).
const NotificationClient = extern struct {
    vt: *const VTable = &vtable,
    changed: ?sys.HANDLE = null,

    const VTable = extern struct {
        unk: Unknown(NotificationClient),
        OnDeviceStateChanged: *const fn (*NotificationClient, ?[*:0]const u16, u32) callconv(.winapi) HRESULT,
        OnDeviceAdded: *const fn (*NotificationClient, ?[*:0]const u16) callconv(.winapi) HRESULT,
        OnDeviceRemoved: *const fn (*NotificationClient, ?[*:0]const u16) callconv(.winapi) HRESULT,
        OnDefaultDeviceChanged: *const fn (*NotificationClient, u32, u32, ?[*:0]const u16) callconv(.winapi) HRESULT,
        OnPropertyValueChanged: *const fn (*NotificationClient, ?[*:0]const u16, PROPERTYKEY) callconv(.winapi) HRESULT,
    };
    const vtable: VTable = .{
        .unk = .{ .QueryInterface = query, .AddRef = addRef, .Release = rel },
        .OnDeviceStateChanged = stateChanged,
        .OnDeviceAdded = added,
        .OnDeviceRemoved = added,
        .OnDefaultDeviceChanged = defaultChanged,
        .OnPropertyValueChanged = propertyChanged,
    };

    fn query(self: *NotificationClient, iid: *const GUID, out: *?*anyopaque) callconv(.winapi) HRESULT {
        if (std.mem.eql(u8, std.mem.asBytes(iid), std.mem.asBytes(&IID_IUnknown)) or
            std.mem.eql(u8, std.mem.asBytes(iid), std.mem.asBytes(&IID_IMMNotificationClient)))
        {
            out.* = self;
            return 0;
        }
        out.* = null;
        return E_NOINTERFACE;
    }
    // Owned by the backend, not reference counted.
    fn addRef(_: *NotificationClient) callconv(.winapi) u32 {
        return 1;
    }
    fn rel(_: *NotificationClient) callconv(.winapi) u32 {
        return 1;
    }
    fn signal(self: *NotificationClient) HRESULT {
        if (self.changed) |e| _ = sys.SetEvent(e);
        return 0;
    }
    fn stateChanged(self: *NotificationClient, _: ?[*:0]const u16, _: u32) callconv(.winapi) HRESULT {
        return self.signal();
    }
    fn added(self: *NotificationClient, _: ?[*:0]const u16) callconv(.winapi) HRESULT {
        return self.signal();
    }
    fn defaultChanged(self: *NotificationClient, flow: u32, _: u32, _: ?[*:0]const u16) callconv(.winapi) HRESULT {
        if (flow != eCapture) return 0;
        return self.signal();
    }
    fn propertyChanged(self: *NotificationClient, _: ?[*:0]const u16, key: PROPERTYKEY) callconv(.winapi) HRESULT {
        // A rename or a form factor change; volume and the like are ignored.
        if (std.mem.eql(u8, std.mem.asBytes(&key), std.mem.asBytes(&PKEY_Device_FriendlyName)) or
            std.mem.eql(u8, std.mem.asBytes(&key), std.mem.asBytes(&PKEY_AudioEndpoint_FormFactor)))
            return self.signal();
        return 0;
    }
};

pub const Wasapi = struct {
    enumerator: ?*IMMDeviceEnumerator = null,
    client: NotificationClient = .{},
    registered: bool = false,
    co_init: bool = false,
    audio: ?*IAudioClient = null,
    cap: ?*IAudioCaptureClient = null,
    /// One packet's worth of zeros for silent packets.
    zeros: [4096]i16 = @splat(0),

    pub fn backend(wb: *Wasapi) capture.Backend {
        return .{ .ctx = wb, .vtable = &vt };
    }

    fn of(ctx: *anyopaque) *Wasapi {
        return @ptrCast(@alignCast(ctx));
    }

    fn open(ctx: *anyopaque, changed: sys.HANDLE) anyerror!void {
        const wb = of(ctx);
        const hr = CoInitializeEx(null, COINIT_MULTITHREADED);
        wb.co_init = ok(hr); // S_OK or S_FALSE: balanced by CoUninitialize
        var p: ?*anyopaque = null;
        if (!ok(CoCreateInstance(&CLSID_MMDeviceEnumerator, null, CLSCTX_ALL, &IID_IMMDeviceEnumerator, &p))) return error.NoAudioDevices;
        const e: *IMMDeviceEnumerator = @ptrCast(@alignCast(p.?));
        wb.enumerator = e;
        wb.client.changed = changed;
        wb.registered = ok(e.vt.RegisterEndpointNotificationCallback(e, &wb.client));
    }

    fn close(ctx: *anyopaque) void {
        const wb = of(ctx);
        stopFn(ctx);
        if (wb.enumerator) |e| {
            if (wb.registered) _ = e.vt.UnregisterEndpointNotificationCallback(e, &wb.client);
            release(e);
        }
        wb.enumerator = null;
        wb.registered = false;
        if (wb.co_init) CoUninitialize();
        wb.co_init = false;
    }

    /// UTF-16 (NUL-terminated) -> `out` as UTF-8.
    fn utf8(w: [*:0]const u16, out: anytype) void {
        var buf: [mics.max_id * 2]u8 = undefined;
        const s = std.mem.span(w);
        const n = std.unicode.utf16LeToUtf8(&buf, s[0..@min(s.len, mics.max_id)]) catch 0;
        out.set(buf[0..n]);
    }

    fn defaultId(e: *IMMDeviceEnumerator, role: u32, out: *mics.IdText) void {
        var d: ?*IMMDevice = null;
        if (!ok(e.vt.GetDefaultAudioEndpoint(e, eCapture, role, &d))) return;
        const dev = d orelse return;
        defer release(dev);
        var id: ?[*:0]u16 = null;
        if (!ok(dev.vt.GetId(dev, &id))) return;
        defer CoTaskMemFree(id);
        utf8(id.?, out);
    }

    fn listFn(ctx: *anyopaque, out: *mics.List) anyerror!void {
        const wb = of(ctx);
        const e = wb.enumerator orelse return error.NoAudioDevices;
        var comms: mics.IdText = .{};
        var console: mics.IdText = .{};
        defaultId(e, eCommunications, &comms);
        defaultId(e, eConsole, &console);
        var col: ?*IMMDeviceCollection = null;
        if (!ok(e.vt.EnumAudioEndpoints(e, eCapture, DEVICE_STATE_ACTIVE, &col))) return error.EnumFailed;
        const c = col.?;
        defer release(c);
        var n: u32 = 0;
        _ = c.vt.GetCount(c, &n);
        var i: u32 = 0;
        while (i < n and out.len < mics.max_endpoints) : (i += 1) {
            var d: ?*IMMDevice = null;
            if (!ok(c.vt.Item(c, i, &d))) continue;
            const dev = d.?;
            defer release(dev);
            var ep: mics.Endpoint = .{};
            var id: ?[*:0]u16 = null;
            if (!ok(dev.vt.GetId(dev, &id))) continue;
            utf8(id.?, &ep.id);
            CoTaskMemFree(id);
            var st: ?*IPropertyStore = null;
            if (ok(dev.vt.OpenPropertyStore(dev, STGM_READ, &st))) {
                const ps = st.?;
                defer release(ps);
                var v: PROPVARIANT = .{};
                if (ok(ps.vt.GetValue(ps, &PKEY_Device_FriendlyName, &v))) {
                    if (v.vt == VT_LPWSTR) if (v.data.pwsz) |s| utf8(s, &ep.name);
                    _ = PropVariantClear(&v);
                }
                v = .{};
                if (ok(ps.vt.GetValue(ps, &PKEY_AudioEndpoint_FormFactor, &v))) {
                    if (v.vt == VT_UI4) ep.kind = mics.Kind.fromFormFactor(v.data.ul);
                    _ = PropVariantClear(&v);
                }
                v = .{};
                if (ok(ps.vt.GetValue(ps, &PKEY_Device_EnumeratorName, &v))) {
                    if (v.vt == VT_LPWSTR) if (v.data.pwsz) |s| {
                        var en: mics.NameText = .{};
                        utf8(s, &en);
                        ep.bus = mics.Bus.fromEnumerator(en.get());
                    };
                    _ = PropVariantClear(&v);
                }
            }
            if (ep.name.len == 0) ep.name.set("Microphone");
            ep.default_comms = ep.id.eql(comms.get());
            ep.default_console = ep.id.eql(console.get());
            out.append(ep);
        }
    }

    fn startFn(ctx: *anyopaque, id: []const u8, ready: sys.HANDLE) anyerror!void {
        const wb = of(ctx);
        const e = wb.enumerator orelse return error.NoAudioDevices;
        stopFn(ctx);
        var wid: [mics.max_id + 1]u16 = undefined;
        const n = std.unicode.utf8ToUtf16Le(wid[0..mics.max_id], id) catch return error.BadId;
        wid[n] = 0;
        var d: ?*IMMDevice = null;
        if (!ok(e.vt.GetDevice(e, wid[0..n :0], &d))) return error.DeviceLost;
        const dev = d.?;
        defer release(dev);
        var p: ?*anyopaque = null;
        if (!ok(dev.vt.Activate(dev, &IID_IAudioClient, CLSCTX_ALL, null, &p))) return error.DeviceLost;
        const ac: *IAudioClient = @ptrCast(@alignCast(p.?));
        errdefer release(ac);
        const fmt: WAVEFORMATEX = .{
            .wFormatTag = 1, // PCM
            .nChannels = 1,
            .nSamplesPerSec = capture.sample_rate,
            .nAvgBytesPerSec = capture.sample_rate * 2,
            .nBlockAlign = 2,
            .wBitsPerSample = 16,
            .cbSize = 0,
        };
        // 100 ms buffer; the engine converts rate, channels and format.
        const hr = ac.vt.Initialize(ac, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_EVENTCALLBACK | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY, 1_000_000, 0, &fmt, null);
        if (hr == E_ACCESSDENIED) return error.MicrophoneAccessDenied;
        if (!ok(hr)) return error.CannotOpenMicrophone;
        if (!ok(ac.vt.SetEventHandle(ac, ready))) return error.CannotOpenMicrophone;
        var cp: ?*anyopaque = null;
        if (!ok(ac.vt.GetService(ac, &IID_IAudioCaptureClient, &cp))) return error.CannotOpenMicrophone;
        const cc: *IAudioCaptureClient = @ptrCast(@alignCast(cp.?));
        if (!ok(ac.vt.Start(ac))) {
            release(cc);
            return error.CannotOpenMicrophone;
        }
        wb.audio = ac;
        wb.cap = cc;
    }

    fn readFn(ctx: *anyopaque, sink: capture.Sink) anyerror!void {
        const wb = of(ctx);
        const cc = wb.cap orelse return;
        while (true) {
            var next: u32 = 0;
            const hr = cc.vt.GetNextPacketSize(cc, &next);
            if (hr == AUDCLNT_E_DEVICE_INVALIDATED) return error.DeviceLost;
            if (!ok(hr) or next == 0) return;
            var data: ?[*]u8 = null;
            var frames: u32 = 0;
            var flags: u32 = 0;
            const g = cc.vt.GetBuffer(cc, &data, &frames, &flags, null, null);
            if (g == AUDCLNT_E_DEVICE_INVALIDATED) return error.DeviceLost;
            if (!ok(g)) return;
            if (frames > 0) {
                if (flags & AUDCLNT_BUFFERFLAGS_SILENT != 0 or data == null) {
                    var left: usize = frames;
                    while (left > 0) {
                        const k = @min(left, wb.zeros.len);
                        sink.put(sink.ctx, wb.zeros[0..k]);
                        left -= k;
                    }
                } else {
                    const samples: [*]align(1) const i16 = @ptrCast(data.?);
                    // The buffer is 16-bit PCM, 2-byte aligned by WASAPI.
                    const aligned: [*]const i16 = @alignCast(samples);
                    sink.put(sink.ctx, aligned[0..frames]);
                }
            }
            _ = cc.vt.ReleaseBuffer(cc, frames);
        }
    }

    fn stopFn(ctx: *anyopaque) void {
        const wb = of(ctx);
        if (wb.audio) |ac| _ = ac.vt.Stop(ac);
        if (wb.cap) |cc| release(cc);
        if (wb.audio) |ac| release(ac);
        wb.cap = null;
        wb.audio = null;
    }

    const vt: capture.Backend.VTable = .{ .open = open, .close = close, .list = listFn, .start = startFn, .read = readFn, .stop = stopFn };
};

test "guids and layouts" {
    const g = guid("BCDE0395-E52F-467C-8E3D-C4579291692E");
    try std.testing.expectEqual(@as(u32, 0xBCDE0395), g.a);
    try std.testing.expectEqual(@as(u8, 0x8E), g.d[0]);
    try std.testing.expectEqual(@as(u8, 0x2E), g.d[7]);
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(PROPERTYKEY));
    if (@sizeOf(usize) == 8) try std.testing.expectEqual(@as(usize, 24), @sizeOf(PROPVARIANT));
}
