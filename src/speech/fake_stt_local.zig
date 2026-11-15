//! A stand-in for stt-local in the speech module's tests (local.zig): the
//! same command line and protocol 1 on stdin/stdout, with no model or NPU.
//! Built by build.zig for `zig build test` only, never shipped.
//!
//!   transcribe    "heard <n> samples", a new id, and a wakeup event first
//!                 (as stt reports its silence deadline). The first sample
//!                 picks a failure: 0x7777 exits at once (a crash) unless
//!                 <profile>/crashed exists (it is created first, so the
//!                 restarted program answers); 0x6666 never answers (a
//!                 hang); 0x5555 answers backend_lost.
//!   feedback      ok with text: "learned", one sample file in
//!                 <profile>/samples (with learning on); else "discarded".
//!   export_bundle every waiting sample in one bundle, "BUNDLE" + ids.
//!   commit_export deletes the samples up to `through`.
//!   import_update "STTUPD01<n>": adapter version n.
//!   set_learning, status.
//! A --model that does not exist: the start fails (exit 1, a line on stderr).

const std = @import("std");
const Io = std.Io;

const max_line = 8 << 20;

const State = struct {
    io: Io,
    gpa: std.mem.Allocator,
    profile: []const u8,
    out: *Io.Writer,
    next_id: u64 = 0,
    adapter_version: u32 = 0,
    learning: bool = true,

    fn line(s: *State, v: anytype) void {
        std.json.Stringify.value(v, .{}, s.out) catch return;
        s.out.writeByte('\n') catch return;
        s.out.flush() catch return;
    }

    fn fail(s: *State, rid: u32, code: []const u8) void {
        s.line(.{ .rid = rid, .@"error" = code, .message = code });
    }

    fn path(s: *State, buf: []u8, comptime fmt: []const u8, args: anytype) []const u8 {
        var nb: [64]u8 = undefined;
        const name = std.fmt.bufPrint(&nb, fmt, args) catch unreachable;
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ s.profile, name }) catch unreachable;
    }

    /// The waiting sample ids, ascending.
    fn samples(s: *State, out: []u64) usize {
        var pb: [1024]u8 = undefined;
        var d = Io.Dir.cwd().openDir(s.io, s.path(&pb, "samples", .{}), .{ .iterate = true }) catch return 0;
        defer d.close(s.io);
        var it = d.iterate();
        var n: usize = 0;
        while (it.next(s.io) catch null) |e| {
            if (!std.mem.endsWith(u8, e.name, ".wav") or n == out.len) continue;
            out[n] = std.fmt.parseInt(u64, e.name[0 .. e.name.len - 4], 10) catch continue;
            n += 1;
        }
        std.mem.sort(u64, out[0..n], {}, std.sort.asc(u64));
        return n;
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    var model: []const u8 = "";
    var profile: []const u8 = "";
    var adapter: ?[]const u8 = null;
    var adapter_version: u32 = 0;
    var i: usize = 1;
    while (i + 1 < argv.len) : (i += 2) {
        const a: []const u8 = argv[i];
        const v: []const u8 = argv[i + 1];
        if (std.mem.eql(u8, a, "--model")) model = v;
        if (std.mem.eql(u8, a, "--profile")) profile = v;
        if (std.mem.eql(u8, a, "--adapter")) adapter = v;
        if (std.mem.eql(u8, a, "--adapter-version")) adapter_version = try std.fmt.parseInt(u32, v, 10);
    }
    Io.Dir.cwd().access(io, model, .{}) catch {
        std.debug.print("stt-local: cannot start (FileNotFound)\n", .{});
        std.process.exit(1);
    };

    var out_buf: [64 << 10]u8 = undefined;
    var stdout_w = Io.File.Writer.init(.stdout(), io, &out_buf);
    var s: State = .{ .io = io, .gpa = gpa, .profile = profile, .out = &stdout_w.interface };
    var pb: [1024]u8 = undefined;
    try Io.Dir.cwd().createDirPath(io, s.path(&pb, "samples", .{}));
    // The profile's adapter version survives a restart, like stt's.
    var vb: [32]u8 = undefined;
    if (Io.Dir.cwd().readFile(io, s.path(&pb, "adapter_version", .{}), &vb)) |t| {
        s.adapter_version = std.fmt.parseInt(u32, t, 10) catch 0;
    } else |_| {}
    if (adapter) |p| {
        var ab: [64]u8 = undefined;
        const bytes = Io.Dir.cwd().readFile(io, p, &ab) catch "";
        const v = if (std.mem.startsWith(u8, bytes, "STTUPD01")) std.fmt.parseInt(u32, bytes[8..], 10) catch 0 else adapter_version;
        s.adapter_version = @max(s.adapter_version, v);
    }
    s.line(.{ .event = "ready", .proto = 1, .version = "0.1.0", .backend = "cpu", .model = std.fs.path.basename(model), .adapter_version = s.adapter_version });

    const in_buf = try gpa.alloc(u8, max_line + 1);
    defer gpa.free(in_buf);
    var stdin_r = Io.File.Reader.initStreaming(.stdin(), io, in_buf);
    while (stdin_r.interface.takeDelimiter('\n') catch null) |l| {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        handle(&s, arena.allocator(), l) catch s.fail(0, "internal");
    }
}

fn handle(s: *State, arena: std.mem.Allocator, l: []const u8) !void {
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, l, .{}) catch return s.fail(0, "bad_request");
    if (v != .object) return s.fail(0, "bad_request");
    const o = v.object;
    const rid: u32 = @intCast((o.get("rid") orelse return s.fail(0, "bad_request")).integer);
    const op = (o.get("op") orelse return s.fail(rid, "bad_request")).string;
    var pb: [1024]u8 = undefined;
    const cwd = Io.Dir.cwd();
    if (std.mem.eql(u8, op, "transcribe")) {
        const b64 = (o.get("pcm_s16le_b64") orelse return s.fail(rid, "bad_request")).string;
        const dec = std.base64.standard.Decoder;
        const bytes = try arena.alloc(u8, try dec.calcSizeForSlice(b64));
        try dec.decode(bytes, b64);
        const first: u16 = if (bytes.len >= 2) std.mem.readInt(u16, bytes[0..2], .little) else 0;
        switch (first) {
            0x7777 => {
                const marker = s.path(&pb, "crashed", .{});
                if (cwd.access(s.io, marker, .{})) |_| {} else |_| {
                    try cwd.writeFile(s.io, .{ .sub_path = marker, .data = "1" });
                    std.process.exit(3);
                }
            },
            0x6666 => {
                s.io.sleep(.fromSeconds(3600), .awake) catch {};
                return;
            },
            0x5555 => return s.fail(rid, "backend_lost"),
            else => {},
        }
        s.next_id += 1;
        s.line(.{ .event = "wakeup", .deadline_unix_ms = @as(?i64, 4_000_000_000_000) });
        const text = try std.fmt.allocPrint(arena, "heard {d} samples", .{bytes.len / 2});
        return s.line(.{ .rid = rid, .id = s.next_id, .text = text });
    }
    if (std.mem.eql(u8, op, "feedback")) {
        const id: u64 = @intCast((o.get("id") orelse return s.fail(rid, "bad_request")).integer);
        if (id == 0 or id > s.next_id) return s.fail(rid, "unknown_id");
        const ok = (o.get("ok") orelse return s.fail(rid, "bad_request")).bool;
        const text = if (o.get("text")) |t| t.string else "";
        if (!ok or text.len == 0) return s.line(.{ .rid = rid, .outcome = "discarded" });
        if (s.learning) try cwd.writeFile(s.io, .{ .sub_path = s.path(&pb, "samples/{d}.wav", .{id}), .data = text });
        return s.line(.{ .rid = rid, .outcome = "learned", .sample_id = id, .new_rules = 0, .new_words = 0 });
    }
    if (std.mem.eql(u8, op, "export_bundle")) {
        var ids: [64]u64 = undefined;
        const n = s.samples(&ids);
        if (n == 0) return s.line(.{ .rid = rid, .b64 = @as(?[]const u8, null), .through = 0, .count = 0, .version = 1 });
        var raw: std.ArrayList(u8) = .empty;
        try raw.appendSlice(arena, "BUNDLE");
        for (ids[0..n]) |id| try raw.print(arena, " {d}", .{id});
        const enc = std.base64.standard.Encoder;
        const b64 = try arena.alloc(u8, enc.calcSize(raw.items.len));
        _ = enc.encode(b64, raw.items);
        return s.line(.{ .rid = rid, .b64 = @as(?[]const u8, b64), .through = ids[n - 1], .count = n, .version = 1 });
    }
    if (std.mem.eql(u8, op, "commit_export")) {
        const through: u64 = @intCast((o.get("through") orelse return s.fail(rid, "bad_request")).integer);
        var ids: [64]u64 = undefined;
        const n = s.samples(&ids);
        for (ids[0..n]) |id| if (id <= through) cwd.deleteFile(s.io, s.path(&pb, "samples/{d}.wav", .{id})) catch {};
        return s.line(.{ .rid = rid, .ok = true });
    }
    if (std.mem.eql(u8, op, "import_update")) {
        const b64 = (o.get("b64") orelse return s.fail(rid, "bad_request")).string;
        const dec = std.base64.standard.Decoder;
        const bytes = try arena.alloc(u8, try dec.calcSizeForSlice(b64));
        try dec.decode(bytes, b64);
        if (!std.mem.startsWith(u8, bytes, "STTUPD01")) return s.fail(rid, "bad_request");
        s.adapter_version = std.fmt.parseInt(u32, bytes[8..], 10) catch return s.fail(rid, "bad_request");
        var vb: [16]u8 = undefined;
        try cwd.writeFile(s.io, .{ .sub_path = s.path(&pb, "adapter_version", .{}), .data = try std.fmt.bufPrint(&vb, "{d}", .{s.adapter_version}) });
        return s.line(.{ .rid = rid, .version = s.adapter_version, .adapter_version = s.adapter_version });
    }
    if (std.mem.eql(u8, op, "set_learning")) {
        s.learning = (o.get("on") orelse return s.fail(rid, "bad_request")).bool;
        return s.line(.{ .rid = rid, .ok = true });
    }
    if (std.mem.eql(u8, op, "status")) {
        var ids: [64]u64 = undefined;
        return s.line(.{ .rid = rid, .proto = 1, .version = "0.1.0", .backend = "cpu", .device = "laptop", .model = "m", .adapter_version = s.adapter_version, .profile_version = 1, .learning = s.learning, .pending_export = s.samples(&ids), .deadline_unix_ms = @as(?i64, null) });
    }
    return s.fail(rid, "bad_request");
}
