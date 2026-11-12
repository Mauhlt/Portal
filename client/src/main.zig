//! portal-client: the standalone remote viewer. The same code runs as
//! `portal connect` inside Portal's own executable (src/connect.zig); this
//! wrapper exists so the client can be built and shipped on its own
//! (Linux and macOS laptops, which cannot run Portal's ConPTY server).
//!
//!   portal-client --server 10.8.0.1:8420     connect (pair on first use)
//!   portal-client --server ADDR --forget     delete this device's stored credential

const std = @import("std");
const connect = @import("connect.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    var args: std.ArrayList([]const u8) = .empty;
    var it: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    _ = it.next();
    while (it.next()) |a| try args.append(gpa, a);
    // Never returns; args and the iterator live until process exit.
    connect.main(gpa, init.io, "portal-client", args.items);
}

test {
    _ = connect;
}
