//! Speech training bundles from paired devices, at the desk: the bulk
//! channel's `put bundle` (src/web.zig, shared/bulk.zig) hands each one
//! here, and it reaches stt.Home through the desk's engine
//! (home.Engine.importBundleWait). The device name always comes from the
//! connection's paired session, never from the request.
//!
//!   begin(device, declared, now)   before the body is read: gate.Gate's
//!       verdict (2 devices at once, the payload budget) and the body's
//!       read deadline. A refusal sends no body.
//!   store(ticket, device, bytes, now)   the per-device limits (bytes and
//!       clips a rolling day), then the import; blocks until stt holds it,
//!       so a "stored" answer means the device may delete those samples.
//!   end(ticket)   always.
//!
//! The desk's window attaches its engine (`attach`) when it starts one and
//! detaches it before stopping it; `detach` waits for imports in flight.
//! Without an engine (no NVIDIA GPU, not the x86_64 desk build, speech
//! still loading or failed) every bundle is `unavailable`, so the device
//! keeps its samples and tries again on its next sync.

const std = @import("std");
const options = @import("speech_options");
const gate_mod = @import("gate.zig");
const limits = @import("limits.zig");
const home = if (options.home) @import("home.zig") else struct {};

pub const Engine = if (options.home) home.Engine else void;

pub const Verdict = enum {
    /// Imported: the desk holds it.
    stored,
    /// Not a training bundle (or the import failed).
    bad,
    /// A per-device limit (bytes or clips a rolling day).
    limited,
    /// "Learn from my voice" is off at the desk: nothing comes in.
    learning_off,
    /// No speech engine at the desk right now.
    unavailable,
    /// The engine's one import slot is taken: try later.
    busy,
    too_large,

    /// The bulk reply code (shared/bulk.zig, `put bundle`).
    pub fn code(v: Verdict) u16 {
        return switch (v) {
            .stored => 200,
            .bad => 400,
            .learning_off => 403,
            .unavailable => 404,
            .too_large => 413,
            .limited => 429,
            .busy => 503,
        };
    }
};

pub const Inbox = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    drained: std.Io.Condition = .init,
    gate: gate_mod.Gate = .{},
    engine: ?*Engine = null,
    /// Imports in flight on `engine` (detach waits for none).
    users: u32 = 0,

    pub fn attach(ib: *Inbox, e: *Engine) void {
        ib.mutex.lockUncancelable(ib.io);
        defer ib.mutex.unlock(ib.io);
        ib.engine = e;
    }

    /// Before the engine stops: no new import starts on it, and the ones
    /// in flight finish first.
    pub fn detach(ib: *Inbox) void {
        ib.mutex.lockUncancelable(ib.io);
        defer ib.mutex.unlock(ib.io);
        ib.engine = null;
        while (ib.users > 0) ib.drained.waitUncancelable(ib.io, &ib.mutex);
    }

    /// The desk's settings changed (`speech.*`).
    pub fn setLimits(ib: *Inbox, c: limits.Config) void {
        ib.mutex.lockUncancelable(ib.io);
        defer ib.mutex.unlock(ib.io);
        ib.gate.setLimits(c);
    }

    /// The paired devices (when the device store changes).
    pub fn retain(ib: *Inbox, paired: []const []const u8) void {
        ib.mutex.lockUncancelable(ib.io);
        defer ib.mutex.unlock(ib.io);
        ib.gate.retain(paired);
    }

    /// Before reading a body of `declared` bytes (monotonic ms).
    pub fn begin(ib: *Inbox, device: []const u8, declared: u64, now: i64) gate_mod.Begin {
        ib.mutex.lockUncancelable(ib.io);
        defer ib.mutex.unlock(ib.io);
        if (declared > @as(u64, ib.gate.cfg.bundle_max_kib) * 1024) return .too_large;
        return ib.gate.begin(device, declared, now);
    }

    pub fn end(ib: *Inbox, t: gate_mod.Ticket) void {
        ib.mutex.lockUncancelable(ib.io);
        defer ib.mutex.unlock(ib.io);
        ib.gate.end(t);
    }

    /// Imports the bundle (takes ownership of `bytes`): blocks until the
    /// desk's engine answered.
    pub fn store(ib: *Inbox, gpa: std.mem.Allocator, device: []const u8, bytes: []u8, now: i64) Verdict {
        var owned = true;
        defer if (owned) gpa.free(bytes);
        const clips = bundleClips(bytes) orelse return .bad;
        const e = blk: {
            ib.mutex.lockUncancelable(ib.io);
            defer ib.mutex.unlock(ib.io);
            const e = ib.engine orelse return .unavailable;
            switch (ib.gate.bundle(device, bytes.len, clips, now)) {
                .ok => {},
                .refused => return .bad,
                else => return .limited,
            }
            ib.users += 1;
            break :blk e;
        };
        defer {
            ib.mutex.lockUncancelable(ib.io);
            ib.users -= 1;
            ib.mutex.unlock(ib.io);
            ib.drained.broadcast(ib.io);
        }
        if (!options.home) return .unavailable;
        owned = false;
        const ok = e.importBundleWait(device, bytes) catch |err| return switch (err) {
            error.Busy => .busy,
            error.TooLarge => .too_large,
            error.LearningOff => .learning_off,
            error.SpeechUnavailable => .unavailable,
            error.OutOfMemory => .busy,
        };
        return if (ok) .stored else .bad;
    }
};

/// The number of samples a bundle says it holds, from its header (stt's
/// sync format: "STTBUN01", u32 version, u32 + device name, u32 count,
/// little-endian), or null if it is not one. stt checks the rest when it
/// imports it; this is only for the per-device clip limit.
pub fn bundleClips(bytes: []const u8) ?u32 {
    if (bytes.len < 16 or !std.mem.eql(u8, bytes[0..8], "STTBUN01")) return null;
    const name_len = std.mem.readInt(u32, bytes[12..16], .little);
    if (name_len > limits.max_device_name * 4 or bytes.len < 16 + @as(usize, name_len) + 4) return null;
    const at = 16 + @as(usize, name_len);
    const n = std.mem.readInt(u32, bytes[at..][0..4], .little);
    return if (n == 0) null else n;
}

const testing = std.testing;

fn testBundle(buf: []u8, device: []const u8, count: u32) []u8 {
    @memcpy(buf[0..8], "STTBUN01");
    std.mem.writeInt(u32, buf[8..12], 3, .little);
    std.mem.writeInt(u32, buf[12..16], @intCast(device.len), .little);
    @memcpy(buf[16..][0..device.len], device);
    std.mem.writeInt(u32, buf[16 + device.len ..][0..4], count, .little);
    return buf[0 .. 20 + device.len];
}

test "bundle header: the clip count, or not a bundle" {
    var b: [64]u8 = undefined;
    try testing.expectEqual(@as(?u32, 4), bundleClips(testBundle(&b, "iphone", 4)));
    try testing.expectEqual(@as(?u32, null), bundleClips(testBundle(&b, "iphone", 0)));
    const ok = testBundle(&b, "iphone", 4);
    try testing.expectEqual(@as(?u32, null), bundleClips(ok[0 .. ok.len - 1]));
    try testing.expectEqual(@as(?u32, null), bundleClips("STTUPD01 not a bundle at all"));
    std.mem.writeInt(u32, b[12..16], 0xffff_fff0, .little);
    try testing.expectEqual(@as(?u32, null), bundleClips(b[0..30]));
}

test "inbox: no engine means unavailable (the device keeps its samples); limits apply first" {
    var ib: Inbox = .{ .io = testing.io };
    const t = ib.begin("iphone", 100, 0).ok;
    var b: [64]u8 = undefined;
    const body = try testing.allocator.dupe(u8, testBundle(&b, "iphone", 2));
    try testing.expectEqual(Verdict.unavailable, ib.store(testing.allocator, "iphone", body, 0));
    ib.end(t);
    try testing.expectEqual(Verdict.bad, ib.store(testing.allocator, "iphone", try testing.allocator.dupe(u8, "junk"), 0));
    // Over the bundle cap: refused before the body is read.
    try testing.expect(ib.begin("iphone", limits.bundle_max_kib * 1024 + 1, 0) == .too_large);
    // Two devices at once at most (concurrent_devices = 2).
    const a = ib.begin("laptop", 1, 0).ok;
    const c = ib.begin("iphone", 1, 0).ok;
    try testing.expect(ib.begin("surface", 1, 0) == .busy);
    ib.end(a);
    ib.end(c);
    ib.detach(); // nothing in flight: returns at once
    try testing.expectEqual(@as(u16, 503), Verdict.busy.code());
}
