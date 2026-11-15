//! `fetch_file URL SHA256 SIZE OUT`: downloads one file over HTTPS and
//! keeps it only if its size and SHA-256 are the pinned ones. Zig's
//! package fetcher takes archives and git repositories only, so a single
//! file (the iPhone app's speech model, src/speech/model_pin.zig) comes
//! through this build tool: run only by the steps that bundle it, cached
//! by the build system on its arguments, never in the repository.

const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer args.deinit();
    _ = args.next();
    const url = args.next() orelse return usage();
    const want_hex = args.next() orelse return usage();
    const size_text = args.next() orelse return usage();
    const out_path = args.next() orelse return usage();
    const want_size = std.fmt.parseInt(u64, size_text, 10) catch return usage();
    var want: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&want, want_hex) catch return usage();

    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    var file = try std.Io.Dir.cwd().createFile(io, out_path, .{});
    var ok = false;
    defer {
        file.close(io);
        if (!ok) std.Io.Dir.cwd().deleteFile(io, out_path) catch {};
    }
    var buf: [1 << 16]u8 = undefined;
    var fw = file.writer(io, &buf);
    var hw: Hashing = .{ .out = &fw.interface };
    std.debug.print("fetch_file: downloading {s}\n", .{url});
    const result = try client.fetch(.{ .location = .{ .url = url }, .response_writer = &hw.writer });
    try hw.writer.flush();
    try fw.interface.flush();
    if (result.status != .ok) {
        std.log.err("{s}: HTTP {d}", .{ url, @intFromEnum(result.status) });
        return error.HttpStatus;
    }
    var got: [32]u8 = undefined;
    hw.hash.final(&got);
    check(want, got, want_size, hw.n) catch |err| {
        switch (err) {
            error.WrongSize => std.log.err("{s}: downloaded {d} bytes, the pin says {d}", .{ url, hw.n, want_size }),
            error.WrongHash => std.log.err("{s}: SHA-256 {x} does not match the pinned {x}", .{ url, got, want }),
        }
        return err;
    };
    ok = true;
}

fn usage() error{Usage} {
    std.log.err("usage: fetch_file URL SHA256 SIZE OUT", .{});
    return error.Usage;
}

/// Size first (the clearer message), then the hash.
fn check(want: [32]u8, got: [32]u8, want_size: u64, got_size: u64) error{ WrongSize, WrongHash }!void {
    if (got_size != want_size) return error.WrongSize;
    if (!std.mem.eql(u8, &want, &got)) return error.WrongHash;
}

/// A writer that hashes and counts what passes through to `out`.
const Hashing = struct {
    out: *std.Io.Writer,
    hash: std.crypto.hash.sha2.Sha256 = .init(.{}),
    n: u64 = 0,
    writer: std.Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const h: *Hashing = @alignCast(@fieldParentPtr("writer", w));
        var total: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try h.put(d);
            total += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            try h.put(last);
            total += last.len;
        }
        return total;
    }

    fn put(h: *Hashing, d: []const u8) std.Io.Writer.Error!void {
        h.hash.update(d);
        h.n += d.len;
        try h.out.writeAll(d);
    }
};

test "pinned size and hash" {
    var out: [64]u8 = undefined;
    var fw: std.Io.Writer = .fixed(&out);
    var h: Hashing = .{ .out = &fw };
    try h.writer.writeAll("abc");
    try h.writer.splatByteAll('d', 2);
    try h.writer.flush();
    try std.testing.expectEqualStrings("abcdd", fw.buffered());
    var got: [32]u8 = undefined;
    h.hash.final(&got);
    var want: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("abcdd", &want, .{});
    try check(want, got, 5, h.n);
    try std.testing.expectError(error.WrongSize, check(want, got, 6, h.n));
    var bad = want;
    bad[0] ^= 1;
    try std.testing.expectError(error.WrongHash, check(bad, got, 5, h.n));
}
