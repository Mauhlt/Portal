//! Capture endpoints as Portal sees them, and which one to use
//! (docs/audio-design.md, "Microphone selection"):
//!
//!   * Automatic (the default): a connected headset microphone (form
//!     factor Headset / Headphones / Handset, a Bluetooth hands-free
//!     device, a USB headset); otherwise the default communications
//!     capture device; otherwise the default console capture device;
//!     otherwise the first one.
//!   * Manual: the endpoint stored by id; if it is gone, Automatic.
//!
//! Pure data and rules, no I/O: the platform backend (wasapi.zig) fills
//! `List`, the capture thread (capture.zig) calls `choose`.

const std = @import("std");

/// PKEY_AudioEndpoint_FormFactor, reduced to what the UI shows.
pub const Kind = enum {
    headset,
    headphones,
    handset,
    microphone,
    line_in,
    other,

    pub fn label(k: Kind) []const u8 {
        return switch (k) {
            .headset => "Headset",
            .headphones => "Headphones",
            .handset => "Handset",
            .microphone => "Microphone",
            .line_in => "Line in",
            .other => "Input",
        };
    }

    /// EndpointFormFactor (mmdeviceapi.h) -> Kind.
    pub fn fromFormFactor(ff: u32) Kind {
        return switch (ff) {
            5 => .headset,
            3 => .headphones,
            6 => .handset,
            4 => .microphone,
            2 => .line_in,
            else => .other,
        };
    }
};

/// How the endpoint is attached (PKEY_Device_EnumeratorName).
pub const Bus = enum {
    usb,
    bluetooth,
    builtin,
    other,

    pub fn label(b: Bus) []const u8 {
        return switch (b) {
            .usb => "USB",
            .bluetooth => "Bluetooth",
            .builtin => "built-in",
            .other => "",
        };
    }

    /// "USB", "BTHENUM", "BTHHFENUM", "BTHLEDEVICE", "HDAUDIO", "INTELAUDIO", …
    pub fn fromEnumerator(name: []const u8) Bus {
        if (std.ascii.eqlIgnoreCase(name, "USB")) return .usb;
        if (std.ascii.startsWithIgnoreCase(name, "BTH")) return .bluetooth;
        if (std.ascii.eqlIgnoreCase(name, "HDAUDIO") or std.ascii.eqlIgnoreCase(name, "INTELAUDIO") or
            std.ascii.eqlIgnoreCase(name, "ACPI") or std.ascii.startsWithIgnoreCase(name, "SW")) return .builtin;
        return .other;
    }
};

/// An Apple audio input port (AVAudioSessionPortDescription.portType) as
/// a Kind and Bus, so the iPhone picks its microphone with the same rule
/// as the desk (`choose`): a wired or Bluetooth headset before the
/// built-in microphone. The iPhone app fills a `List` from its session's
/// available inputs (client/src/ios/mic.zig).
pub const ApplePort = struct { kind: Kind, bus: Bus };

pub fn fromApplePort(port_type: []const u8) ApplePort {
    const eql = std.mem.eql;
    if (eql(u8, port_type, "MicrophoneWired")) return .{ .kind = .headset, .bus = .other };
    if (eql(u8, port_type, "BluetoothHFP")) return .{ .kind = .headset, .bus = .bluetooth };
    if (eql(u8, port_type, "USBAudio")) return .{ .kind = .microphone, .bus = .usb };
    if (eql(u8, port_type, "MicrophoneBuiltIn")) return .{ .kind = .microphone, .bus = .builtin };
    if (eql(u8, port_type, "LineIn")) return .{ .kind = .line_in, .bus = .other };
    if (eql(u8, port_type, "CarAudio")) return .{ .kind = .handset, .bus = .bluetooth };
    return .{ .kind = .other, .bus = .other };
}

pub const max_id = 256;
pub const max_name = 128;
pub const max_endpoints = 16;

fn Text(comptime cap: usize) type {
    return struct {
        const Self = @This();
        buf: [cap]u8 = undefined,
        len: usize = 0,

        pub fn get(s: *const Self) []const u8 {
            return s.buf[0..s.len];
        }
        /// Truncates at a UTF-8 boundary if `v` is too long.
        pub fn set(s: *Self, v: []const u8) void {
            var n = @min(v.len, cap);
            while (n > 0 and n < v.len and (v[n] & 0xC0) == 0x80) n -= 1;
            @memcpy(s.buf[0..n], v[0..n]);
            s.len = n;
        }
        pub fn eql(s: *const Self, v: []const u8) bool {
            return std.mem.eql(u8, s.get(), v);
        }
    };
}

pub const IdText = Text(max_id);
pub const NameText = Text(max_name);

pub const Endpoint = struct {
    /// The endpoint id (UTF-8 of IMMDevice::GetId): stable across runs.
    id: IdText = .{},
    /// Friendly name ("Headset Microphone (Jabra Evolve2 65)").
    name: NameText = .{},
    kind: Kind = .other,
    bus: Bus = .other,
    /// Windows' default capture device for that role.
    default_console: bool = false,
    default_comms: bool = false,

    /// A headset microphone: what Automatic prefers.
    pub fn isHeadset(e: *const Endpoint) bool {
        return switch (e.kind) {
            .headset, .headphones, .handset => true,
            else => e.bus == .bluetooth,
        };
    }

    /// "Headset · USB" (the type column of the device list).
    pub fn typeLabel(e: *const Endpoint, buf: []u8) []const u8 {
        const b = e.bus.label();
        if (b.len == 0) return e.kind.label();
        return std.fmt.bufPrint(buf, "{s} \u{00B7} {s}", .{ e.kind.label(), b }) catch e.kind.label();
    }
};

/// The active capture endpoints, in the backend's order.
pub const List = struct {
    items: [max_endpoints]Endpoint = undefined,
    len: usize = 0,

    pub fn slice(l: *const List) []const Endpoint {
        return l.items[0..l.len];
    }

    pub fn append(l: *List, e: Endpoint) void {
        if (l.len == max_endpoints) return;
        l.items[l.len] = e;
        l.len += 1;
    }

    pub fn find(l: *const List, id: []const u8) ?usize {
        for (l.slice(), 0..) |*e, i| if (e.id.eql(id)) return i;
        return null;
    }

    pub fn anyHeadset(l: *const List) bool {
        for (l.slice()) |*e| if (e.isHeadset()) return true;
        return false;
    }
};

pub const Mode = union(enum) {
    automatic,
    /// An endpoint id (falls back to Automatic while it is missing).
    manual: []const u8,
};

pub const Choice = struct {
    index: usize,
    /// Manual mode, but its device is missing: Automatic chose.
    fell_back: bool = false,
};

/// Which endpoint to capture from; null when there is none.
pub fn choose(l: *const List, mode: Mode) ?Choice {
    if (l.len == 0) return null;
    switch (mode) {
        .manual => |id| {
            if (l.find(id)) |i| return .{ .index = i };
            const c = chooseAuto(l);
            return .{ .index = c, .fell_back = true };
        },
        .automatic => return .{ .index = chooseAuto(l) },
    }
}

fn chooseAuto(l: *const List) usize {
    const items = l.slice();
    // A headset: the default communications one if it is a headset, else
    // the first headset.
    for (items, 0..) |*e, i| if (e.isHeadset() and e.default_comms) return i;
    for (items, 0..) |*e, i| if (e.isHeadset()) return i;
    for (items, 0..) |*e, i| if (e.default_comms) return i;
    for (items, 0..) |*e, i| if (e.default_console) return i;
    return 0;
}

/// What changed between two device lists, for the toast.
pub const Change = union(enum) {
    none,
    /// A headset microphone appeared (its name).
    headset_connected: []const u8,
    /// One went away (its name, from the old list).
    headset_disconnected: []const u8,
};

/// The first headset that appeared in `new`, else the first that left
/// `old`; strings point into the lists.
pub fn headsetChange(old: *const List, new: *const List) Change {
    for (new.slice()) |*e| if (e.isHeadset() and old.find(e.id.get()) == null) return .{ .headset_connected = e.name.get() };
    for (old.slice()) |*e| if (e.isHeadset() and new.find(e.id.get()) == null) return .{ .headset_disconnected = e.name.get() };
    return .none;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

pub fn testEndpoint(id: []const u8, name: []const u8, kind: Kind, bus: Bus) Endpoint {
    var e: Endpoint = .{ .kind = kind, .bus = bus };
    e.id.set(id);
    e.name.set(name);
    return e;
}

test "automatic: a headset first, then communications, then console" {
    var l: List = .{};
    try testing.expect(choose(&l, .automatic) == null);
    var builtin_mic = testEndpoint("{a}", "Microphone Array", .microphone, .builtin);
    builtin_mic.default_console = true;
    l.append(builtin_mic);
    try testing.expectEqual(@as(usize, 0), choose(&l, .automatic).?.index);
    var webcam = testEndpoint("{b}", "Webcam mic", .microphone, .usb);
    webcam.default_comms = true;
    l.append(webcam);
    try testing.expectEqual(@as(usize, 1), choose(&l, .automatic).?.index);
    l.append(testEndpoint("{c}", "Headset Microphone (Evolve)", .headset, .usb));
    try testing.expectEqual(@as(usize, 2), choose(&l, .automatic).?.index);
    // A Bluetooth hands-free device counts as a headset whatever its form factor.
    var bt = testEndpoint("{d}", "Headset (Shokz)", .other, .bluetooth);
    bt.default_comms = true;
    l.append(bt);
    l.items[1].default_comms = false;
    try testing.expectEqual(@as(usize, 3), choose(&l, .automatic).?.index);
}

test "manual: the stored id, else automatic with fell_back" {
    var l: List = .{};
    l.append(testEndpoint("{a}", "Mic", .microphone, .builtin));
    l.append(testEndpoint("{h}", "Headset", .headset, .usb));
    const m = choose(&l, .{ .manual = "{a}" }).?;
    try testing.expectEqual(@as(usize, 0), m.index);
    try testing.expect(!m.fell_back);
    const g = choose(&l, .{ .manual = "{gone}" }).?;
    try testing.expectEqual(@as(usize, 1), g.index);
    try testing.expect(g.fell_back);
}

test "headset changes and labels" {
    var a: List = .{};
    a.append(testEndpoint("{a}", "Mic", .microphone, .builtin));
    var b = a;
    b.append(testEndpoint("{h}", "Jabra", .headset, .usb));
    try testing.expectEqualStrings("Jabra", headsetChange(&a, &b).headset_connected);
    try testing.expectEqualStrings("Jabra", headsetChange(&b, &a).headset_disconnected);
    try testing.expect(headsetChange(&a, &a) == .none);
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("Headset \u{00B7} USB", b.items[1].typeLabel(&buf));
    try testing.expectEqual(Bus.bluetooth, Bus.fromEnumerator("BTHHFENUM"));
    try testing.expectEqual(Bus.usb, Bus.fromEnumerator("usb"));
    try testing.expectEqual(Kind.headset, Kind.fromFormFactor(5));
    var t: NameText = .{};
    var long: [200]u8 = undefined;
    for (0..100) |i| @memcpy(long[2 * i ..][0..2], "\u{00E9}");
    t.set(&long); // 200 bytes: cut at a code point boundary
    try testing.expect(t.len <= max_name and std.unicode.utf8ValidateSlice(t.get()));
}

test "iPhone ports: a headset (wired or Bluetooth) before the built-in microphone" {
    var l: List = .{};
    const ports = [_][]const u8{ "MicrophoneBuiltIn", "USBAudio", "BluetoothHFP" };
    for (ports, 0..) |p, i| {
        const a = fromApplePort(p);
        var e = testEndpoint(&.{@as(u8, '0') + @as(u8, @intCast(i))}, p, a.kind, a.bus);
        e.default_console = a.bus == .builtin;
        l.append(e);
    }
    try testing.expectEqual(@as(usize, 2), choose(&l, .automatic).?.index);
    l.len = 2; // the headset went: the built-in one (the session's default)
    try testing.expectEqual(@as(usize, 0), choose(&l, .automatic).?.index);
    try testing.expect(fromApplePort("MicrophoneWired").kind == .headset);
    try testing.expect(fromApplePort("Something new").kind == .other);
}
