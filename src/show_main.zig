//! portal-show.exe: `portal-show <file.png> [--cols N] [--stdout]` shows a
//! PNG inline in the terminal (src/show.zig). A console program of its
//! own because it runs inside sessions, where the Portal window (a GUI
//! program) cannot write to the session's terminal. Portal puts its own
//! folder first on the session's PATH, so `portal-show` is always found.

const std = @import("std");
const show = @import("show.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(gpa);
    var it: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |a| try args.append(gpa, a);
    std.process.exit(show.main(gpa, init.io, args.items));
}

test {
    _ = show;
}
