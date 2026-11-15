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
//!   retain(paired)   on every device store change (main.zig StoreWatch,
//!       after each read): a device unpaired, or replaced by a new pairing
//!       under its name, loses its entry (limits) and its bundle still
//!       queued for import (it keeps those samples); a body being read
//!       for it is refused when it arrives.
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

/// A paired device as the device store has it: its name and its pairing's
/// identity (an opaque id issued at pairing; a new pairing under the same
/// name has another).
pub const Member = struct { name: []const u8, id: []const u8 };

pub const Inbox = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    drained: std.Io.Condition = .init,
    gate: gate_mod.Gate = .{},
    engine: ?*Engine = null,
    /// Imports in flight on `engine` (detach waits for none).
    users: u32 = 0,
    /// The paired devices at the last `retain` (a name and its pairing id,
    /// hashed): a name whose id changed was paired again.
    known_names: [limits.max_devices][limits.max_device_name]u8 = undefined,
    known_lens: [limits.max_devices]u8 = @splat(0),
    known_ids: [limits.max_devices]u64 = @splat(0),
    known_n: usize = 0,

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

    /// The paired devices, on every device store change: an unpaired or
    /// replaced device's entry goes, and its bundle still queued for
    /// import with it. Returns how many devices went.
    pub fn retain(ib: *Inbox, paired: []const Member) usize {
        ib.mutex.lockUncancelable(ib.io);
        defer ib.mutex.unlock(ib.io);
        var gone: usize = 0;
        for (0..ib.known_n) |k| {
            const name = ib.known_names[k][0..ib.known_lens[k]];
            const now_id: ?u64 = for (paired) |m| {
                if (std.mem.eql(u8, m.name, name)) break idHash(m.id);
            } else null;
            if (now_id == ib.known_ids[k]) continue;
            // Unpaired, or paired again (another device now): what the
            // old one left is dropped.
            ib.gate.drop(name);
            if (options.home) if (ib.engine) |e| {
                _ = e.dropImport(name);
            };
            gone += 1;
        }
        // Entries for names no longer paired at all (also ones the store
        // never listed while this ran).
        var names: [limits.max_devices][]const u8 = undefined;
        var n: usize = 0;
        ib.known_n = 0;
        for (paired) |m| {
            if (m.name.len == 0 or m.name.len > limits.max_device_name or n == names.len) continue;
            names[n] = m.name;
            n += 1;
            const k = ib.known_n;
            @memcpy(ib.known_names[k][0..m.name.len], m.name);
            ib.known_lens[k] = @intCast(m.name.len);
            ib.known_ids[k] = idHash(m.id);
            ib.known_n += 1;
        }
        ib.gate.retain(names[0..n]);
        return gone;
    }

    fn idHash(id: []const u8) u64 {
        return std.hash.Wyhash.hash(0, id);
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
            // Unpaired or replaced while its body was on the way.
            if (ib.gate.isStale(device)) return .unavailable;
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

test "retain: an unpaired or replaced device's entry goes; a body on the way for it is refused" {
    var ib: Inbox = .{ .io = testing.io };
    try testing.expectEqual(@as(usize, 0), ib.retain(&.{ .{ .name = "laptop", .id = "A" }, .{ .name = "iphone", .id = "B" } }));
    // Both have used their limits a little.
    ib.mutex.lockUncancelable(ib.io);
    for (0..limits.feedback_burst) |_| try testing.expect(ib.gate.feedback("laptop", 0) == .ok);
    try testing.expect(ib.gate.feedback("iphone", 0) == .ok);
    ib.mutex.unlock(ib.io);
    // The same store again: nothing goes.
    try testing.expectEqual(@as(usize, 0), ib.retain(&.{ .{ .name = "laptop", .id = "A" }, .{ .name = "iphone", .id = "B" } }));
    try testing.expect(ib.gate.feedback("laptop", 0) == .limited);
    // "laptop" paired again (a new id): its old entry goes, the new
    // device starts afresh.
    try testing.expectEqual(@as(usize, 1), ib.retain(&.{ .{ .name = "laptop", .id = "C" }, .{ .name = "iphone", .id = "B" } }));
    try testing.expect(ib.gate.feedback("laptop", 0) == .ok);
    // "iphone" sends a bundle, and is unpaired while its body is read.
    const t = ib.begin("iphone", 100, 0).ok;
    try testing.expectEqual(@as(usize, 1), ib.retain(&.{.{ .name = "laptop", .id = "C" }}));
    var b: [64]u8 = undefined;
    const body = try testing.allocator.dupe(u8, testBundle(&b, "iphone", 2));
    try testing.expectEqual(Verdict.unavailable, ib.store(testing.allocator, "iphone", body, 0));
    ib.end(t);
    // Its entry is gone once the request ended.
    try testing.expect(ib.gate.per_device.find("iphone") == null);
    // Names never paired with a request are freed too (the table never
    // fills with names of the past).
    var names: [limits.max_devices][8]u8 = undefined;
    ib.mutex.lockUncancelable(ib.io);
    for (0..limits.max_devices) |i| {
        const n = std.fmt.bufPrint(&names[i], "d{d}", .{i}) catch unreachable;
        _ = ib.gate.feedback(n, 0);
    }
    ib.mutex.unlock(ib.io);
    _ = ib.retain(&.{.{ .name = "laptop", .id = "C" }});
    try testing.expect(ib.begin("surface", 1, 0) == .ok);
}
