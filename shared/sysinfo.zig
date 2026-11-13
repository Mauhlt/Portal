//! The optional system monitor on the wire (docs/protocol.md section 3d):
//! the desktop's load and each tab's, numbers only. Sent only to viewers
//! that asked for it (`y:on`), only while the desk's "Show system monitor"
//! setting is on, about once a second while any System panel is open.
//!
//!   {"t":"sys","cpu":<tenths of %>,"mem":{"used":<bytes>,"total":<bytes>},
//!    "gpus":[{"util":<tenths of %>,"used":<bytes>,"total":<bytes>},...],
//!    "tabs":[{"id":"<32 hex>","cpu":<tenths of %>,"mem":<bytes>,
//!             "procs":<n>},...]}
//!
//! * `cpu`: all logical processors together, 0..1000 (100.0 %).
//! * `gpus`: per graphics adapter (no names): the busiest engine's
//!   utilisation and dedicated video memory; `total` 0 if unknown.
//! * `tabs`: each open tab's process tree (its program and everything it
//!   started, e.g. background shells): CPU (share of the whole machine)
//!   and memory (working sets), and how many processes. Never process
//!   names, command lines, paths or user names.
//!
//! Parsing is strict and bounded like the other shared parsers.

const std = @import("std");
const tabs = @import("tabs.zig");
const convo = @import("convo.zig");

pub const Id = tabs.Id;
pub const max_gpus = 8;

pub const Gpu = struct {
    util: u16 = 0,
    used: u64 = 0,
    total: u64 = 0,
};

pub const TabLoad = struct {
    id: Id = @splat(0),
    cpu: u16 = 0,
    mem: u64 = 0,
    procs: u32 = 0,
};

pub const Snapshot = struct {
    cpu: u16 = 0,
    mem_used: u64 = 0,
    mem_total: u64 = 0,
    gpus: [max_gpus]Gpu = undefined,
    n_gpus: usize = 0,
    tabs: [tabs.max_tabs]TabLoad = undefined,
    n_tabs: usize = 0,

    pub fn gpuSlice(s: *const Snapshot) []const Gpu {
        return s.gpus[0..s.n_gpus];
    }

    pub fn tabSlice(s: *const Snapshot) []const TabLoad {
        return s.tabs[0..s.n_tabs];
    }

    pub fn find(s: *const Snapshot, id: Id) ?*const TabLoad {
        for (s.tabs[0..s.n_tabs]) |*t| if (std.mem.eql(u8, &t.id, &id)) return t;
        return null;
    }
};

pub const max_message = 160 + max_gpus * 80 + tabs.max_tabs * 120;

fn c53(v: u64) u64 {
    return @min(v, 1 << 53);
}

pub fn write(w: *std.Io.Writer, s: *const Snapshot) !void {
    try w.print("{{\"t\":\"sys\",\"cpu\":{d},\"mem\":{{\"used\":{d},\"total\":{d}}},\"gpus\":[", .{ @min(s.cpu, 1000), c53(s.mem_used), c53(s.mem_total) });
    for (s.gpuSlice(), 0..) |g, i| {
        if (i > 0) try w.writeByte(',');
        try w.print("{{\"util\":{d},\"used\":{d},\"total\":{d}}}", .{ @min(g.util, 1000), c53(g.used), c53(g.total) });
    }
    try w.writeAll("],\"tabs\":[");
    for (s.tabSlice(), 0..) |t, i| {
        if (i > 0) try w.writeByte(',');
        try w.print("{{\"id\":\"{s}\",\"cpu\":{d},\"mem\":{d},\"procs\":{d}}}", .{ &tabs.idHex(t.id), @min(t.cpu, 1000), c53(t.mem), t.procs });
    }
    try w.writeAll("]}");
}

const Obj = struct {
    p: *convo.Parser,
    first: bool = true,

    /// The next key of the object (its `{` already eaten), null at `}`;
    /// error.Bad if malformed.
    fn next(o: *Obj) error{Bad}!?[]const u8 {
        const p = o.p;
        p.ws();
        if (p.eat('}')) return null;
        if (!o.first and !p.eat(',')) return error.Bad;
        o.first = false;
        p.ws();
        const k = p.string() orelse return error.Bad;
        p.ws();
        if (!p.eat(':')) return error.Bad;
        p.ws();
        return k;
    }
};

fn pct(p: *convo.Parser) error{Bad}!u16 {
    const v = p.number() orelse return error.Bad;
    if (v > 1000) return error.Bad;
    return @intCast(v);
}

/// Parses a `sys` message into `out`; false if it is not one or malformed.
pub fn parse(text: []const u8, out: *Snapshot) bool {
    return parseInner(text, out) catch false;
}

fn parseInner(text: []const u8, out: *Snapshot) error{Bad}!bool {
    if (text.len > max_message) return false;
    var sbuf: [max_message]u8 = undefined;
    var p: convo.Parser = .{ .s = text, .out = &sbuf };
    out.* = .{};
    var have_t = false;
    p.ws();
    if (!p.eat('{')) return false;
    var o: Obj = .{ .p = &p };
    while (try o.next()) |key| {
        if (eq(key, "t")) {
            if (!eq(p.string() orelse return false, "sys")) return false;
            have_t = true;
        } else if (eq(key, "cpu")) {
            out.cpu = try pct(&p);
        } else if (eq(key, "mem")) {
            if (!p.eat('{')) return false;
            var m: Obj = .{ .p = &p };
            while (try m.next()) |k| {
                if (eq(k, "used")) out.mem_used = p.number64() orelse return false else if (eq(k, "total")) out.mem_total = p.number64() orelse return false else if (!p.scalar()) return false;
            }
        } else if (eq(key, "gpus") or eq(key, "tabs")) {
            const gpus = eq(key, "gpus");
            if (!p.eat('[')) return false;
            p.ws();
            if (!p.eat(']')) while (true) {
                p.ws();
                if (!p.eat('{')) return false;
                var e: Obj = .{ .p = &p };
                if (gpus) {
                    if (out.n_gpus == max_gpus) return false;
                    var g: Gpu = .{};
                    while (try e.next()) |k| {
                        if (eq(k, "util")) g.util = try pct(&p) else if (eq(k, "used")) g.used = p.number64() orelse return false else if (eq(k, "total")) g.total = p.number64() orelse return false else if (!p.scalar()) return false;
                    }
                    out.gpus[out.n_gpus] = g;
                    out.n_gpus += 1;
                } else {
                    if (out.n_tabs == tabs.max_tabs) return false;
                    var t: TabLoad = .{};
                    var have_id = false;
                    while (try e.next()) |k| {
                        if (eq(k, "id")) {
                            t.id = tabs.parseId(p.string() orelse return false) orelse return false;
                            have_id = true;
                        } else if (eq(k, "cpu")) t.cpu = try pct(&p) else if (eq(k, "mem")) t.mem = p.number64() orelse return false else if (eq(k, "procs")) t.procs = p.number() orelse return false else if (!p.scalar()) return false;
                    }
                    if (!have_id) return false;
                    out.tabs[out.n_tabs] = t;
                    out.n_tabs += 1;
                }
                p.ws();
                if (p.eat(']')) break;
                if (!p.eat(',')) return false;
            };
        } else if (!p.scalar()) return false;
    }
    p.ws();
    return p.i == text.len and have_t;
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// "12.5 %" for tenths of a percent.
pub fn formatPct(tenths: u16, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d} %", .{ tenths / 10, tenths % 10 }) catch "";
}

/// "512 MB", "7.4 GB" (binary units, one decimal from 1 GB).
pub fn formatBytes(b: u64, buf: []u8) []const u8 {
    const gb: u64 = 1 << 30;
    const mb: u64 = 1 << 20;
    if (b >= gb) {
        const tenths = (b * 10 + gb / 2) / gb;
        return std.fmt.bufPrint(buf, "{d}.{d} GB", .{ tenths / 10, tenths % 10 }) catch "";
    }
    return std.fmt.bufPrint(buf, "{d} MB", .{(b + mb / 2) / mb}) catch "";
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "sys round trip and bounds" {
    var s: Snapshot = .{ .cpu = 125, .mem_used = 7 << 30, .mem_total = 32 << 30 };
    s.gpus[0] = .{ .util = 33, .used = 1 << 30, .total = 8 << 30 };
    s.n_gpus = 1;
    s.tabs[0] = .{ .id = @splat(0xcd), .cpu = 42, .mem = 350 << 20, .procs = 3 };
    s.n_tabs = 1;
    var buf: [max_message]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try write(&w, &s);
    var b: Snapshot = undefined;
    try testing.expect(parse(w.buffered(), &b));
    try testing.expectEqual(@as(u16, 125), b.cpu);
    try testing.expectEqual(@as(u64, 32 << 30), b.mem_total);
    try testing.expectEqual(@as(u64, 8 << 30), b.gpus[0].total);
    try testing.expectEqual(@as(u32, 3), b.find(@splat(0xcd)).?.procs);
    // The largest fits.
    var big: Snapshot = .{ .cpu = 1000, .mem_used = 1 << 53, .mem_total = 1 << 53, .n_gpus = max_gpus, .n_tabs = tabs.max_tabs };
    for (&big.gpus) |*g| g.* = .{ .util = 1000, .used = 1 << 53, .total = 1 << 53 };
    for (&big.tabs) |*t| t.* = .{ .cpu = 1000, .mem = 1 << 53, .procs = std.math.maxInt(u32) };
    var w2: std.Io.Writer = .fixed(&buf);
    try write(&w2, &big);
    try testing.expect(parse(w2.buffered(), &b));
    const bad = [_][]const u8{
        "{\"t\":\"sys\",\"cpu\":1001}",
        "{\"t\":\"sys\",\"cpu\":-1}",
        "{\"t\":\"sysx\"}",
        "{\"cpu\":1}",
        "{\"t\":\"sys\",\"tabs\":[{\"cpu\":1}]}",
        "{\"t\":\"sys\",\"tabs\":[{\"id\":\"x\"}]}",
        "{\"t\":\"sys\",\"gpus\":{}}",
        "{\"t\":\"sys\",\"name\":{\"x\":1}}",
    };
    for (bad) |x| try testing.expect(!parse(x, &b));
    try testing.expect(parse("{\"t\":\"sys\",\"later\":\"x\"}", &b));
    var fb: [32]u8 = undefined;
    try testing.expectEqualStrings("12.5 %", formatPct(125, &fb));
    try testing.expectEqualStrings("7.0 GB", formatBytes(7 << 30, &fb));
    try testing.expectEqualStrings("350 MB", formatBytes(350 << 20, &fb));
}
