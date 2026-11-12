//! The remote viewer: `portal connect` (in Portal's own executable) and the
//! standalone `portal-client` both run `main` below. Module "client" in
//! Portal's root build; imports only std and "view".
//!
//!   connect --server 10.8.0.1:8420     connect (pair on first use)
//!   connect --server ADDR --forget     delete this device's stored credential
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
    \\usage: {s} --server IP:PORT [--forget]
    \\
    \\  --server IP:PORT   Portal server address inside the WireGuard tunnel,
    \\                     e.g. 10.8.0.1:8420 (literal IP, no host names)
    \\  --forget           delete this device's stored credential and exit
    \\
    \\First run: on the desktop run `portal pair <name>`, then click Pair.
    \\
;

fn fatal(prog: []const u8, comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("{s}: " ++ fmt ++ "\n", .{prog} ++ args);
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

/// Runs the remote viewer until its window is closed, then exits the
/// process (the network thread cannot be joined). `args` excludes the
/// program/subcommand name; `prog` is used in messages ("portal connect").
/// Objects live for the life of the process and are never freed.
pub fn main(gpa: std.mem.Allocator, io: std.Io, prog: []const u8, args: []const []const u8) noreturn {
    var server: ?[]const u8 = null;
    var forget = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--server")) {
            i += 1;
            if (i >= args.len) fatal(prog, "--server needs a value", .{});
            server = args[i];
        } else if (std.mem.eql(u8, a, "--forget")) {
            forget = true;
        } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            std.debug.print(usage, .{prog});
            std.process.exit(0);
        } else {
            std.debug.print(usage, .{prog});
            fatal(prog, "unknown argument '{s}'", .{a});
        }
    }
    const server_arg = server orelse {
        std.debug.print(usage, .{prog});
        std.process.exit(2);
    };

    const shared = gpa.create(client_mod.Shared) catch fatal(prog, "out of memory", .{});
    shared.* = .{};
    const client = gpa.create(client_mod.Client) catch fatal(prog, "out of memory", .{});
    client.* = client_mod.Client.init(gpa, io, shared, server_arg) catch
        fatal(prog, "bad --server '{s}' (want a literal IP:PORT such as 10.8.0.1:8420)", .{server_arg});

    if (forget) {
        credstore.delete(client.target()) catch |err| fatal(prog, "could not delete the credential: {t}", .{err});
        std.debug.print("{s}: forgot the credential for {s}\n", .{ prog, client.host() });
        std.process.exit(0);
    }

    const tv = TermView.init(gpa, io, .{ .title = "Portal" }) catch |err| fatal(prog, "cannot open the window: {t}", .{err});
    const host = gpa.create(Host) catch fatal(prog, "out of memory", .{});
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
    const thread = std.Thread.spawn(.{}, client_mod.Client.run, .{client}) catch fatal(prog, "cannot start the network thread", .{});
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
