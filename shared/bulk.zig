//! The bulk WebSocket (`/ws/bulk`): request/reply for large transfers, on
//! its own connection (priority `.bulk`, shared/transport.zig) so a sync
//! download never delays a keystroke on the interactive one. One request
//! at a time; the server answers each fully before reading the next.
//!
//!   client -> server   text   "get key" | "get index"
//!                             | "get manifest <pkg> <ver>"
//!                             | "get file <pkg> <ver> <n>"
//!                             | "put bundle <len>"
//!   server -> client   text   "ok <len> [<signature hex>]"   then the body
//!                             in binary messages of at most `chunk` bytes
//!                             each, exactly <len> bytes in all
//!                      text   "err <code>"  (404: unknown or not
//!                             subscribed, they look the same; 500: the
//!                             store is unavailable; 400: malformed)
//!
//! `put bundle` is the other direction: a device's speech training bundle
//! (stt's exportBundle, opaque here) going home. Two steps, so a refused
//! upload never sends its body: the server answers the header with
//! "ok 0" (send it) or "err <code>"; the client then sends exactly <len>
//! bytes in binary messages of at most `upload_chunk` bytes, and the
//! server answers "ok 0" once the desk stored it (only then may the
//! device delete those samples) or "err <code>". Codes: 400 malformed,
//! 403 learning is off at the desk, 404 no speech engine at the desk,
//! 413 too large, 429 over a per-device limit, 503 busy (try later).
//!
//! The body formats are the sync ones, unchanged (client/src/sync:
//! keypin for `key`, the signed manifest and the stored files): signatures,
//! rollback protection and path checks do not depend on the transport.

const std = @import("std");

/// Largest binary message of a reply body.
pub const chunk = 16 * 1024;
/// Largest request or reply header message.
pub const max_header = 256;
pub const max_body: u64 = 1 << 40;
/// Largest binary message of an upload (a client frame, shared/ws.zig).
pub const upload_chunk = @import("ws.zig").max_client_payload;
/// Largest upload a header may declare (a speech bundle: 5 MiB at most,
/// src/speech/limits.zig bundle_max_kib).
pub const max_upload: u64 = 5 << 20;

pub const Request = union(enum) {
    key,
    index,
    manifest: Pkg,
    file: struct { pkg: Pkg, n: u32 },
    /// A speech training bundle of `len` bytes for the desk (`put bundle`).
    put_bundle: u64,

    pub const Pkg = struct { id: []const u8, version: []const u8 };
};

pub fn formatRequest(buf: []u8, r: Request) ![]const u8 {
    return switch (r) {
        .key => "get key",
        .index => "get index",
        .manifest => |m| std.fmt.bufPrint(buf, "get manifest {s} {s}", .{ m.id, m.version }),
        .file => |f| std.fmt.bufPrint(buf, "get file {s} {s} {d}", .{ f.pkg.id, f.pkg.version, f.n }),
        .put_bundle => |n| std.fmt.bufPrint(buf, "put bundle {d}", .{n}),
    };
}

/// Splits a request; the caller validates package ids and versions with
/// the sync manifest's own checks. Null: malformed.
pub fn parseRequest(text: []const u8) ?Request {
    if (text.len > max_header) return null;
    var it = std.mem.splitScalar(u8, text, ' ');
    const verb = it.next() orelse return null;
    if (std.mem.eql(u8, verb, "put")) {
        if (!std.mem.eql(u8, it.next() orelse return null, "bundle")) return null;
        const nt = it.next() orelse return null;
        if (it.next() != null or nt.len == 0 or nt.len > 8 or (nt.len > 1 and nt[0] == '0')) return null;
        for (nt) |c| if (!std.ascii.isDigit(c)) return null;
        const n = std.fmt.parseInt(u64, nt, 10) catch return null;
        if (n == 0 or n > max_upload) return null;
        return .{ .put_bundle = n };
    }
    if (!std.mem.eql(u8, verb, "get")) return null;
    const what = it.next() orelse return null;
    var r: Request = undefined;
    if (std.mem.eql(u8, what, "key")) {
        r = .key;
    } else if (std.mem.eql(u8, what, "index")) {
        r = .index;
    } else if (std.mem.eql(u8, what, "manifest")) {
        r = .{ .manifest = .{ .id = it.next() orelse return null, .version = it.next() orelse return null } };
    } else if (std.mem.eql(u8, what, "file")) {
        const id = it.next() orelse return null;
        const ver = it.next() orelse return null;
        const nt = it.next() orelse return null;
        if (nt.len == 0 or nt.len > 4 or (nt.len > 1 and nt[0] == '0')) return null;
        const n = std.fmt.parseInt(u32, nt, 10) catch return null;
        r = .{ .file = .{ .pkg = .{ .id = id, .version = ver }, .n = n } };
    } else return null;
    if (it.next() != null) return null;
    return r;
}

pub const Reply = union(enum) {
    ok: struct { len: u64, sig: ?[]const u8 = null },
    err: u16,
};

pub fn formatReply(buf: []u8, r: Reply) ![]const u8 {
    return switch (r) {
        .ok => |o| if (o.sig) |s| std.fmt.bufPrint(buf, "ok {d} {s}", .{ o.len, s }) else std.fmt.bufPrint(buf, "ok {d}", .{o.len}),
        .err => |c| std.fmt.bufPrint(buf, "err {d}", .{c}),
    };
}

pub fn parseReply(text: []const u8) ?Reply {
    if (text.len > max_header) return null;
    var it = std.mem.splitScalar(u8, text, ' ');
    const kind = it.next() orelse return null;
    const a = it.next() orelse return null;
    if (std.mem.eql(u8, kind, "err")) {
        if (it.next() != null) return null;
        return .{ .err = std.fmt.parseInt(u16, a, 10) catch return null };
    }
    if (!std.mem.eql(u8, kind, "ok")) return null;
    const len = std.fmt.parseInt(u64, a, 10) catch return null;
    if (len > max_body) return null;
    const sig = it.next();
    if (it.next() != null) return null;
    if (sig) |s| for (s) |c| if (!std.ascii.isHex(c)) return null;
    return .{ .ok = .{ .len = len, .sig = sig } };
}

const testing = std.testing;

test "bulk requests and replies round trip; malformed ones are refused" {
    var b: [max_header]u8 = undefined;
    const reqs = [_]Request{ .key, .index, .{ .manifest = .{ .id = "voice", .version = "1.2" } }, .{ .file = .{ .pkg = .{ .id = "voice", .version = "1.2" }, .n = 7 } }, .{ .put_bundle = 1234 } };
    for (reqs) |r| {
        const t = try formatRequest(&b, r);
        const back = parseRequest(t).?;
        try testing.expectEqual(std.meta.activeTag(r), std.meta.activeTag(back));
    }
    try testing.expectEqual(@as(u32, 7), parseRequest("get file voice 1.2 7").?.file.n);
    try testing.expectEqual(@as(u64, 1234), parseRequest("put bundle 1234").?.put_bundle);
    try testing.expectEqual(max_upload, parseRequest("put bundle 5242880").?.put_bundle);
    for ([_][]const u8{ "", "get", "put key", "get key x", "get file a b 01", "get file a b 99999", "get manifest a", "get  key", "put bundle", "put bundle 0", "put bundle 01", "put bundle 5242881", "put bundle 1 2", "put bundle -1", "put bundle +1", "put file 1" }) |t|
        try testing.expect(parseRequest(t) == null);
    try testing.expectEqual(@as(u64, 5), parseReply(try formatReply(&b, .{ .ok = .{ .len = 5 } })).?.ok.len);
    try testing.expectEqualStrings("ab12", parseReply(try formatReply(&b, .{ .ok = .{ .len = 0, .sig = "ab12" } })).?.ok.sig.?);
    try testing.expectEqual(@as(u16, 404), parseReply(try formatReply(&b, .{ .err = 404 })).?.err);
    for ([_][]const u8{ "", "ok", "ok -1", "ok 1 zz", "ok 1 ab cd", "err", "err x", "huh 1" }) |t|
        try testing.expect(parseReply(t) == null);
}
