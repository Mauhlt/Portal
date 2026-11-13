//! Portal end-to-end tests: `zig build e2e`.
//!
//! Launches real `portalctl run --console` instances (hidden consoles,
//! scratch LOCALAPPDATA, a random block of ports) and drives them over raw sockets:
//! pairing, grid frames, input policies, and transport hardening. Prints a
//! PASS/FAIL line per check and a summary; exits nonzero if anything failed.
//!
//!   e2e <path-to-portalctl.exe> [--base-port N] [group...]
//!
//! portal-show.exe must sit next to portalctl.exe (the build arranges it).
//!
//! Groups: pairing, grid, keys, text, transport, privacy, images, instruct,
//! console, idle, tls, sync, webinput, ended, tabs, convo, status, probe,
//! hooks (default: all).

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
const tls_tests = @import("tls_tests.zig");
const webinput = @import("webinput.zig");
const sync_tests = @import("sync_tests.zig");
const ended = @import("ended.zig");
const tabs_tests = @import("tabs_tests.zig");
const convo_tests = @import("convo_tests.zig");
const status_tests = @import("status_tests.zig");
const probe_tests = @import("probe_tests.zig");
const hooks_tests = @import("hooks_tests.zig");
const subtabs_tests = @import("subtabs_tests.zig");

/// Each run picks its own base port (a multiple of 200 in 20000..59800),
/// so concurrent runs don't collide; `--base-port N` fixes it. Portal binds
/// exclusively, so a clash fails loudly instead of sharing a port.
const port_span: u16 = 200;

fn pickBasePort(io: std.Io) u16 {
    var rnd: [2]u8 = undefined;
    io.random(&rnd);
    const slots: u16 = (59800 - 20000) / port_span;
    return 20000 + (std.mem.readInt(u16, &rnd, .little) % slots) * port_span;
}

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
    .{ .name = "tls", .run = tls_tests.run, .port_offset = 100 },
    .{ .name = "sync", .run = sync_tests.run, .port_offset = 110 },
    .{ .name = "webinput", .run = webinput.run, .port_offset = 120 },
    .{ .name = "ended", .run = ended.run, .port_offset = 130 },
    .{ .name = "tabs", .run = tabs_tests.run, .port_offset = 140 },
    .{ .name = "convo", .run = convo_tests.run, .port_offset = 150 },
    .{ .name = "status", .run = status_tests.run, .port_offset = 160 },
    .{ .name = "probe", .run = probe_tests.run, .port_offset = 170 },
    .{ .name = "hooks", .run = hooks_tests.run, .port_offset = 180 },
    .{ .name = "subtabs", .run = subtabs_tests.run, .port_offset = 190 },
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
    // The fake session program of the convo group (see fake_agent.zig).
    if (args.items.len >= 1 and std.mem.eql(u8, args.items[0], "--fake-agent"))
        @import("win.zig").ExitProcess(@import("fake_agent.zig").main(gpa, io, init.environ_map, args.items[1..]));
    if (args.items.len < 1) {
        std.debug.print("usage: e2e <portalctl.exe> [--base-port N] [group...]\n", .{});
        std.process.exit(2);
    }
    const exe = args.items[0];
    var selected = args.items[1..];
    var base_port = pickBasePort(io);
    if (selected.len >= 2 and std.mem.eql(u8, selected[0], "--base-port")) {
        base_port = std.fmt.parseInt(u16, selected[1], 10) catch {
            std.debug.print("--base-port needs a port number\n", .{});
            std.process.exit(2);
        };
        if (base_port > 65535 - port_span) {
            std.debug.print("--base-port must leave room for {d} ports\n", .{port_span});
            std.process.exit(2);
        }
        selected = selected[2..];
    }

    net.init();
    var h = try proc.Harness.init(gpa, io, init.environ_map, exe);
    var r: Runner = .{ .gpa = gpa };
    const t0 = net.now();
    std.debug.print("portal e2e: {s}\nscratch: {s}\nports: {d}..{d}\n", .{ exe, h.root, base_port, base_port + port_span - 1 });

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
