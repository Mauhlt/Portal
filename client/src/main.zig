//! portal-client: native viewer for a Portal session, over WireGuard.
//! (Intended to become `portal connect`; see README.md.)
//!
//!   portal-client --server 10.8.0.1:8420     connect (pair on first use)
//!   portal-client --server ADDR --forget     delete this device's stored credential
//!
//! The device credential lives only in the OS credential store; the session
//! cookie only in memory. Nothing secret is accepted on the command line.

const std = @import("std");
const view = @import("view");
const TermView = view.TermView;
const client_mod = @import("net/client.zig");
const credstore = @import("credstore.zig");
const remote = @import("remote.zig");

const usage =
    \\usage: portal-client --server IP:PORT [--forget]
    \\
    \\  --server IP:PORT   Portal server address inside the WireGuard tunnel,
    \\                     e.g. 10.8.0.1:8420 (literal IP, no host names)
    \\  --forget           delete this device's stored credential and exit
    \\
    \\First run: on the desktop run `portal pair <name>`, then click Pair.
    \\
;

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("portal-client: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

const Host = struct {
    tv: *TermView,
    shared: *client_mod.Shared,
    client: *client_mod.Client,
    sink: remote.RemoteSink,
    drawn_version: u64 = std.math.maxInt(u64),
    title_status: ?client_mod.Status = null,

    /// Snapshot status under the lock, build the frame, then present.
    fn frame(h: *Host) void {
        const s = h.shared;
        const version = s.version.load(.acquire);
        var detail_buf: [160]u8 = undefined;
        s.mutex.lockUncancelable(h.client.io);
        const st = s.status;
        const mode = s.mode;
        const detail = detail_buf[0..s.detail_len];
        @memcpy(detail, s.detail());
        const o = remote.overlay(st, mode, detail, h.client.host(), s.grid.cols > 0);
        h.tv.build(&s.grid, o);
        s.mutex.unlock(h.client.io);
        h.tv.present();
        h.sink.mode = mode;
        h.sink.status = st;
        h.drawn_version = version;
        if (h.title_status != st) {
            h.title_status = st;
            var tbuf: [128]u8 = undefined;
            h.tv.setTitle(remote.title(st, h.client.host(), &tbuf));
        }
    }

    fn liveRedraw(ctx: *anyopaque) void {
        const h: *Host = @ptrCast(@alignCast(ctx));
        h.frame();
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();

    var server: ?[]const u8 = null;
    var forget = false;
    var it: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |a| {
        if (std.mem.eql(u8, a, "--server")) {
            server = it.next() orelse fatal("--server needs a value", .{});
        } else if (std.mem.eql(u8, a, "--forget")) {
            forget = true;
        } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            std.debug.print("{s}", .{usage});
            return;
        } else {
            std.debug.print("{s}", .{usage});
            fatal("unknown argument '{s}'", .{a});
        }
    }
    const server_arg = server orelse {
        std.debug.print("{s}", .{usage});
        std.process.exit(2);
    };

    const shared = try arena.create(client_mod.Shared);
    shared.* = .{};
    const client = try arena.create(client_mod.Client);
    client.* = client_mod.Client.init(gpa, io, shared, server_arg) catch
        fatal("bad --server '{s}' (want a literal IP:PORT such as 10.8.0.1:8420)", .{server_arg});

    if (forget) {
        credstore.delete(client.target()) catch |err| fatal("could not delete the credential: {t}", .{err});
        std.debug.print("portal-client: forgot the credential for {s}\n", .{client.host()});
        return;
    }

    const tv = TermView.init(gpa, io, .{ .title = "Portal" }) catch |err| fatal("cannot open the window: {t}", .{err});
    const host = try arena.create(Host);
    host.* = .{ .tv = tv, .shared = shared, .client = client, .sink = .{ .client = client } };
    tv.setLiveRedraw(host, Host.liveRedraw);
    shared.wake_ctx = tv;
    shared.wake_fn = struct {
        fn f(ctx: *anyopaque) void {
            const v: *TermView = @ptrCast(@alignCast(ctx));
            v.wake();
        }
    }.f;

    // The network thread runs for the life of the process (its socket reads
    // cannot be cancelled portably); exiting the process ends it.
    const thread = std.Thread.spawn(.{}, client_mod.Client.run, .{client}) catch fatal("cannot start the network thread", .{});
    thread.detach();

    while (tv.pollEvents(host.sink.sink())) {
        if (tv.needsRedraw() or shared.version.load(.acquire) != host.drawn_version) host.frame();
        tv.waitEvents(250);
    }
    tv.deinit();
    std.process.exit(0);
}

test {
    _ = @import("tests.zig");
}
