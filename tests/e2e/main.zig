//! Portal end-to-end tests: `zig build e2e`.
//!
//! Launches real `portal run` instances (hidden consoles, scratch
//! LOCALAPPDATA, ports 18420+) and drives them over raw sockets: pairing,
//! grid frames, input policies, and transport hardening. Prints a PASS/FAIL
//! line per check and a summary; exits nonzero if anything failed.
//!
//!   e2e <path-to-portal.exe> [group...]
//!
//! Groups: pairing, grid, keys, text, transport, privacy, images, instruct,
//! console, idle (default: all).

const std = @import("std");
const net = @import("net.zig");
const proc = @import("proc.zig");
const Runner = @import("runner.zig").Runner;

const pairing = @import("pairing.zig");
const grid_tests = @import("grid_tests.zig");
const input_tests = @import("input_tests.zig");
const transport = @import("transport.zig");
const privacy = @import("privacy.zig");
const console_tests = @import("console_tests.zig");
const images = @import("images.zig");
const idle = @import("idle.zig");

pub const base_port: u16 = 18420;

const Group = struct {
    name: []const u8,
    run: *const fn (*proc.Harness, *Runner, u16) anyerror!void,
    /// Ports base+port_offset .. +port_count-1 belong to this group.
    port_offset: u16,
};

const groups = [_]Group{
    .{ .name = "pairing", .run = pairing.run, .port_offset = 0 },
    .{ .name = "grid", .run = grid_tests.run, .port_offset = 10 },
    .{ .name = "keys", .run = input_tests.runKeys, .port_offset = 20 },
    .{ .name = "text", .run = input_tests.runText, .port_offset = 30 },
    .{ .name = "transport", .run = transport.run, .port_offset = 40 },
    .{ .name = "privacy", .run = privacy.run, .port_offset = 50 },
    .{ .name = "instruct", .run = input_tests.runInstruct, .port_offset = 70 },
    .{ .name = "console", .run = console_tests.run, .port_offset = 80 },
    .{ .name = "images", .run = images.run, .port_offset = 60 },
    .{ .name = "idle", .run = idle.run, .port_offset = 90 },
};

pub fn main(init: std.process.Init) !void {
    const gpa = std.heap.smp_allocator;
    const io = init.io;

    var args: std.ArrayList([]const u8) = .empty;
    var it: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    _ = it.next();
    while (it.next()) |a| try args.append(gpa, try gpa.dupe(u8, a));
    // Helper mode for the console group (see console_tests.inject).
    if (args.items.len >= 1 and std.mem.eql(u8, args.items[0], "--inject"))
        @import("win.zig").ExitProcess(console_tests.injectMain(args.items[1..]));
    if (args.items.len < 1) {
        std.debug.print("usage: e2e <portal.exe> [group...]\n", .{});
        std.process.exit(2);
    }
    const exe = args.items[0];
    const selected = args.items[1..];

    net.init();
    var h = try proc.Harness.init(gpa, io, init.environ_map, exe);
    var r: Runner = .{ .gpa = gpa };
    const t0 = net.now();
    std.debug.print("portal e2e: {s}\nscratch: {s}\n", .{ exe, h.root });

    for (groups) |g| {
        if (selected.len > 0) {
            var want = false;
            for (selected) |s| {
                if (std.mem.eql(u8, s, g.name)) want = true;
            }
            if (!want) continue;
        }
        r.group(g.name);
        g.run(&h, &r, base_port + g.port_offset) catch |err| r.abort(err);
        // Each group stops its own instances; this catches any left over.
        h.mutex.lock();
        const live = h.live.items;
        h.mutex.unlock();
        for (live) |inst| inst.kill();
        r.endGroup();
    }
    h.deinit();

    const secs = @as(f64, @floatFromInt(net.now() - t0)) / 1000.0;
    std.debug.print("\n{d}/{d} passed, {d} failed, {d} skipped in {d:.1}s\n", .{ r.passed, r.passed + r.failed, r.failed, r.skipped, secs });
    if (r.failed > 0) {
        std.debug.print("failures:\n", .{});
        for (r.failures.items) |f| std.debug.print("  {s}\n", .{f});
        std.process.exit(1);
    }
}

test {
    _ = @import("grid.zig");
}
