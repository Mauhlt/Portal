//! Inline images for the display-only emulator (vt.zig): a subset of the
//! kitty graphics protocol, stored as compressed PNG bytes and placed on
//! cells. Nothing here decodes pixels; viewers do that (client/src/image).
//!
//! Commands arrive as `ESC _ G <keys> ; <base64> ESC \` (APC), or, because
//! Windows ConPTY drops APC strings but passes unknown OSC strings through
//! unchanged, as the same `G<keys>;<base64>` carried in `ESC ] 7070 ;` ...
//! `BEL` (or ST). `portal show` uses the OSC form inside a Portal session.
//!
//! Supported: a=t (transmit), a=T (transmit + place), a=p (place by i),
//! a=d (delete: d=a/A all on this screen, d=i/I by id and optional p);
//! f=100 (PNG) only, t=d (direct) only, no o= compression; chunking with
//! m=1 ... m=0; i, p, c, r, C (C=1: don't move the cursor), q (accepted;
//! Portal never answers anyway). Portal extensions: j / l = 0-based anchor
//! column / row (default: the cursor), used by `portal show` because under
//! ConPTY the cursor position at the moment the OSC arrives can't be
//! relied on. Anything else (other formats, t=f/t/s file or shared-memory
//! transmission, unknown actions) is consumed and ignored: no state is
//! corrupted, and nothing ever reads a file.
//!
//! Hard limits (enforced before anything is stored, never by decoding):
//! base64 per image <= 8 MiB, <= 64 images, <= 64 MiB stored (least
//! recently used images evicted), PNG structure and IHDR <= 8192 x 8192
//! and <= 32 Mpx (imgcheck.validate), <= 256 placements per screen. Never
//! panics; allocation failure drops the image being received.

const std = @import("std");
const Allocator = std.mem.Allocator;
const imgcheck = @import("imgcheck");

pub const max_b64_per_image: usize = 8 << 20;
pub const max_images: usize = 64;
pub const max_total_bytes: usize = 64 << 20;
pub const max_placements: usize = 256;
pub const max_ctrl: usize = 512;
/// The OSC number of the ConPTY-safe carrier.
pub const osc_number = "7070";
/// Cell size assumed when an image's cell footprint is computed from its
/// pixel size (no c= / r= given): a typical 10 x 20 px terminal cell.
pub const nominal_cell_w: u32 = 10;
pub const nominal_cell_h: u32 = 20;

/// A placement on one screen, in cells. `row` is the top row and goes
/// negative as the image scrolls off the top; viewers clip.
pub const Placement = struct {
    /// Portal's id for the image (unique for the emulator's lifetime, never
    /// reused; this is the id on the wire).
    image: u32,
    /// The program's own ids (kitty i= / p=), 0 if none.
    client_id: u32,
    pid: u32,
    col: u16,
    row: i32,
    cols: u16,
    rows: u16,

    fn coversRow(p: Placement, y: i64) bool {
        return y >= p.row and y < @as(i64, p.row) + p.rows;
    }
    fn overlaps(p: Placement, y: i64, x0: usize, x1: usize) bool {
        return p.coversRow(y) and p.col < x1 and x0 < @as(usize, p.col) + p.cols;
    }
};

pub const Stored = struct {
    image: u32,
    client_id: u32,
    png: []u8,
    width: u32,
    height: u32,
    used: u64,
};

/// Parsed control keys of one command chunk.
const Cmd = struct {
    a: u8 = 't',
    f: u32 = 32,
    t: u8 = 'd',
    o: u8 = 0,
    m: u32 = 0,
    i: u32 = 0,
    p: u32 = 0,
    c: u32 = 0,
    r: u32 = 0,
    C: u32 = 0,
    d: u8 = 'a',
    j: ?u32 = null,
    l: ?u32 = null,
    /// Only m= and q= present: a continuation chunk.
    only_m: bool = true,
    bad: bool = false,
};

fn parseCmd(s: []const u8) Cmd {
    var c: Cmd = .{};
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |kv| {
        if (kv.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse {
            c.bad = true;
            continue;
        };
        const k = kv[0..eq];
        const v = kv[eq + 1 ..];
        if (k.len != 1 or v.len == 0) {
            c.bad = true;
            continue;
        }
        const num: ?u32 = std.fmt.parseInt(u32, v, 10) catch null;
        const ch: u8 = if (v.len == 1) v[0] else 0;
        switch (k[0]) {
            'm' => c.m = num orelse 0,
            'q' => {},
            else => c.only_m = false,
        }
        switch (k[0]) {
            'a' => c.a = ch,
            'f' => c.f = num orelse 0,
            't' => c.t = ch,
            'o' => c.o = if (ch == 0) '?' else ch,
            'i' => c.i = num orelse 0,
            'p' => c.p = num orelse 0,
            'c' => c.c = num orelse 0,
            'r' => c.r = num orelse 0,
            'C' => c.C = num orelse 0,
            'd' => c.d = ch,
            'j' => c.j = num,
            'l' => c.l = num,
            else => {}, // s, v, x, y, w, h, X, Y, z, U, ...: not supported, ignored
        }
    }
    return c;
}

/// What the terminal must do after a command that placed an image.
pub const Placed = struct { col: u16, cols: u16, rows: u16, move_cursor: bool };

/// The terminal state a placement needs.
pub const Where = struct { cols: u16, rows: u16, x: u16, y: u16, alt: bool };

fn b64Value(c: u8) ?u8 {
    return switch (c) {
        'A'...'Z' => c - 'A',
        'a'...'z' => c - 'a' + 26,
        '0'...'9' => c - '0' + 52,
        '+' => 62,
        '/' => 63,
        else => null,
    };
}

pub const Graphics = struct {
    images: std.ArrayList(Stored) = .empty,
    total_bytes: usize = 0,
    next_image: u32 = 1,
    clock: u64 = 0,
    /// [0] main screen, [1] alternate screen.
    screens: [2]std.ArrayList(Placement) = .{ .empty, .empty },
    /// Bumped on every change to images or placements.
    gen: u64 = 0,

    // ---- current command string
    ctrl: [max_ctrl]u8 = undefined,
    ctrl_len: usize = 0,
    ctrl_over: bool = false,
    in_payload: bool = false,
    cmd: Cmd = .{},
    /// This chunk's payload goes into `pend`.
    accumulate: bool = false,

    // ---- transmission in progress (spans chunks)
    pend_active: bool = false,
    pend_failed: bool = false,
    pend_cmd: Cmd = .{},
    pend: std.ArrayList(u8) = .empty,
    pend_b64: usize = 0,
    quad: [4]u8 = undefined,
    quad_n: u8 = 0,
    pad_seen: bool = false,

    pub fn deinit(g: *Graphics, gpa: Allocator) void {
        for (g.images.items) |im| gpa.free(im.png);
        g.images.deinit(gpa);
        for (&g.screens) |*s| s.deinit(gpa);
        g.pend.deinit(gpa);
        g.* = .{};
    }

    fn changed(g: *Graphics) void {
        g.gen +%= 1;
    }

    pub fn placements(g: *const Graphics, alt: bool) []const Placement {
        return g.screens[@intFromBool(alt)].items;
    }

    pub fn find(g: *const Graphics, image: u32) ?*const Stored {
        for (g.images.items) |*im| if (im.image == image) return im;
        return null;
    }

    // ------------------------------------------------ string parsing

    /// A new `G...` string starts (after APC `_G` or OSC `7070;G`).
    pub fn begin(g: *Graphics) void {
        g.ctrl_len = 0;
        g.ctrl_over = false;
        g.in_payload = false;
        g.accumulate = false;
    }

    /// One byte of the string after the `G`.
    pub fn put(g: *Graphics, gpa: Allocator, b: u8) void {
        if (!g.in_payload) {
            if (b == ';') {
                g.in_payload = true;
                g.startChunk(gpa);
                return;
            }
            if (g.ctrl_len < g.ctrl.len) {
                g.ctrl[g.ctrl_len] = b;
                g.ctrl_len += 1;
            } else g.ctrl_over = true;
            return;
        }
        if (!g.accumulate) return;
        g.payloadByte(gpa, b);
    }

    /// The string was terminated (ST or BEL). Returns a placement the
    /// terminal must follow with a cursor move.
    pub fn end(g: *Graphics, gpa: Allocator, where: Where) ?Placed {
        if (!g.in_payload) g.startChunk(gpa);
        g.in_payload = false;
        return g.finishChunk(gpa, where);
    }

    /// CAN / SUB inside the string: drop it and any transmission.
    pub fn abort(g: *Graphics, gpa: Allocator) void {
        g.dropPending(gpa);
        g.in_payload = false;
        g.accumulate = false;
    }

    fn dropPending(g: *Graphics, gpa: Allocator) void {
        g.pend.clearAndFree(gpa);
        g.pend_active = false;
        g.pend_failed = false;
        g.pend_b64 = 0;
        g.quad_n = 0;
        g.pad_seen = false;
    }

    fn startChunk(g: *Graphics, gpa: Allocator) void {
        var c = parseCmd(g.ctrl[0..g.ctrl_len]);
        if (g.ctrl_over) c.bad = true;
        g.cmd = c;
        g.accumulate = false;
        if (g.pend_active and c.only_m and !c.bad) {
            g.accumulate = !g.pend_failed;
            return;
        }
        if (g.pend_active) g.dropPending(gpa); // a new command interrupts it
        if (c.bad) return;
        if (c.a == 't' or c.a == 'T') {
            g.pend_active = true;
            g.pend_cmd = c;
            g.pend_failed = !(c.f == 100 and c.t == 'd' and c.o == 0);
            g.accumulate = !g.pend_failed;
        }
    }

    fn payloadByte(g: *Graphics, gpa: Allocator, b: u8) void {
        g.pend_b64 += 1;
        if (g.pend_b64 > max_b64_per_image) return g.fail(gpa);
        if (b == '=') {
            // Padding ends a quad: "xx==" -> 1 byte, "xxx=" -> 2 bytes.
            if (g.quad_n < 2) {
                if (!g.pad_seen) return g.fail(gpa);
                return; // the second '=' of "xx=="
            }
            const n: u8 = g.quad_n - 1;
            g.emit(gpa, n);
            g.quad_n = 0;
            g.pad_seen = true;
            return;
        }
        const v = b64Value(b) orelse {
            if (b == '\n' or b == '\r' or b == ' ') return;
            return g.fail(gpa);
        };
        g.pad_seen = false;
        g.quad[g.quad_n] = v;
        g.quad_n += 1;
        if (g.quad_n == 4) {
            g.emit(gpa, 3);
            g.quad_n = 0;
        }
    }

    fn emit(g: *Graphics, gpa: Allocator, n: u8) void {
        if (g.quad_n < 4) @memset(g.quad[g.quad_n..], 0);
        const q = g.quad;
        const bytes = [3]u8{ (q[0] << 2) | (q[1] >> 4), (q[1] << 4) | (q[2] >> 2), (q[2] << 6) | q[3] };
        const cap = imgcheck.max_file_bytes;
        if (g.pend.items.len + n > cap) return g.fail(gpa);
        if (g.pend.unusedCapacitySlice().len < n) {
            const want = @min(cap, @max(64 << 10, g.pend.capacity * 2, g.pend.items.len + n));
            g.pend.ensureTotalCapacityPrecise(gpa, want) catch return g.fail(gpa);
        }
        g.pend.appendSliceAssumeCapacity(bytes[0..n]);
    }

    fn fail(g: *Graphics, gpa: Allocator) void {
        g.pend_failed = true;
        g.accumulate = false;
        g.pend.clearAndFree(gpa);
    }

    fn finishChunk(g: *Graphics, gpa: Allocator, where: Where) ?Placed {
        const c = g.cmd;
        if (c.bad) return null;
        if (g.pend_active and (c.only_m or c.a == 't' or c.a == 'T')) {
            if (c.m != 0) return null; // more chunks follow
            defer g.dropPending(gpa);
            if (g.pend_failed or g.quad_n != 0) return null;
            const pc = g.pend_cmd;
            const image = g.store(gpa) orelse return null;
            if (pc.a == 'T') return g.place(gpa, image, pc, where);
            return null;
        }
        switch (c.a) {
            'p' => {
                if (c.i == 0) return null;
                const im = g.byClientId(c.i) orelse return null;
                return g.place(gpa, im.image, c, where);
            },
            'd' => g.delete(gpa, c, where.alt),
            else => {}, // q (query) and anything unknown: no reply, no effect
        }
        return null;
    }

    fn byClientId(g: *Graphics, id: u32) ?*Stored {
        for (g.images.items) |*im| if (im.client_id == id) return im;
        return null;
    }

    /// Validates and keeps the received PNG (without its ancillary
    /// chunks: `stripAncillary`); returns its image id.
    fn store(g: *Graphics, gpa: Allocator) ?u32 {
        _ = imgcheck.validate(g.pend.items) catch return null;
        g.pend.items.len = stripAncillary(g.pend.items) orelse return null;
        const info = imgcheck.validate(g.pend.items) catch return null;
        const len = g.pend.items.len;
        if (len > max_total_bytes) return null;
        if (g.pend_cmd.i != 0) if (g.byClientId(g.pend_cmd.i)) |old| g.removeImage(gpa, old.image);
        while (g.images.items.len > 0 and (g.images.items.len >= max_images or g.total_bytes + len > max_total_bytes)) {
            var lru: usize = 0;
            for (g.images.items, 0..) |im, k| if (im.used < g.images.items[lru].used) {
                lru = k;
            };
            g.removeImage(gpa, g.images.items[lru].image);
        }
        g.images.ensureUnusedCapacity(gpa, 1) catch return null;
        const png = g.pend.toOwnedSlice(gpa) catch return null;
        const image = g.next_image;
        g.next_image +%= 1;
        if (g.next_image == 0) g.next_image = 1;
        g.clock += 1;
        g.images.appendAssumeCapacity(.{
            .image = image,
            .client_id = g.pend_cmd.i,
            .png = png,
            .width = info.width,
            .height = info.height,
            .used = g.clock,
        });
        g.total_bytes += len;
        g.changed();
        return image;
    }

    fn removeImage(g: *Graphics, gpa: Allocator, image: u32) void {
        for (g.images.items, 0..) |im, k| if (im.image == image) {
            g.total_bytes -|= im.png.len;
            gpa.free(im.png);
            _ = g.images.orderedRemove(k);
            break;
        };
        for (&g.screens) |*s| {
            var k: usize = 0;
            while (k < s.items.len) {
                if (s.items[k].image == image) _ = s.orderedRemove(k) else k += 1;
            }
        }
        g.changed();
    }

    fn place(g: *Graphics, gpa: Allocator, image: u32, c: Cmd, where: Where) ?Placed {
        const im = g.find(image) orelse return null;
        const scr_cols: u32 = @max(where.cols, 1);
        const scr_rows: u32 = @max(where.rows, 1);
        const col: u32 = @min(c.j orelse where.x, scr_cols - 1);
        const row: u32 = @min(c.l orelse where.y, scr_rows - 1);
        const max_c = scr_cols - col;
        var cols: u64 = c.c;
        var rows: u64 = c.r;
        const w: u64 = @max(im.width, 1);
        const h: u64 = @max(im.height, 1);
        if (cols == 0 and rows == 0) {
            cols = (w + nominal_cell_w - 1) / nominal_cell_w;
            rows = (h + nominal_cell_h - 1) / nominal_cell_h;
            // Fit the screen, keeping the aspect ratio.
            if (cols > max_c) {
                rows = @max(1, rows * max_c / cols);
                cols = max_c;
            }
            if (rows > scr_rows) {
                cols = @max(1, cols * scr_rows / rows);
                rows = scr_rows;
            }
        } else if (rows == 0) {
            rows = (@min(cols, 10000) * h * nominal_cell_w + w * nominal_cell_h - 1) / (w * nominal_cell_h);
        } else if (cols == 0) {
            cols = (@min(rows, 10000) * w * nominal_cell_h + h * nominal_cell_w - 1) / (h * nominal_cell_w);
        }
        cols = std.math.clamp(cols, 1, max_c);
        rows = std.math.clamp(rows, 1, scr_rows);

        const list = &g.screens[@intFromBool(where.alt)];
        if (c.i != 0 and c.p != 0) {
            var k: usize = 0;
            while (k < list.items.len) {
                const p = list.items[k];
                if (p.client_id == c.i and p.pid == c.p) _ = list.orderedRemove(k) else k += 1;
            }
        }
        if (list.items.len >= max_placements) _ = list.orderedRemove(0);
        list.append(gpa, .{
            .image = image,
            .client_id = im.client_id,
            .pid = c.p,
            .col = @intCast(col),
            .row = @intCast(row),
            .cols = @intCast(cols),
            .rows = @intCast(rows),
        }) catch return null;
        g.clock += 1;
        if (g.find(image)) |s| @constCast(s).used = g.clock;
        g.changed();
        return .{ .col = @intCast(col), .cols = @intCast(cols), .rows = @intCast(rows), .move_cursor = c.C == 0 };
    }

    fn delete(g: *Graphics, gpa: Allocator, c: Cmd, alt: bool) void {
        const list = &g.screens[@intFromBool(alt)];
        switch (c.d) {
            'a', 'A' => {
                list.clearRetainingCapacity();
                if (c.d == 'A') g.freeUnplaced(gpa);
            },
            'i', 'I' => {
                if (c.i == 0) return;
                var k: usize = 0;
                while (k < list.items.len) {
                    const p = list.items[k];
                    if (p.client_id == c.i and (c.p == 0 or p.pid == c.p)) _ = list.orderedRemove(k) else k += 1;
                }
                if (c.d == 'I') g.freeUnplaced(gpa);
            },
            else => return, // by position, z-index, ...: unsupported
        }
        g.changed();
    }

    fn freeUnplaced(g: *Graphics, gpa: Allocator) void {
        var k: usize = 0;
        while (k < g.images.items.len) {
            const id = g.images.items[k].image;
            var placed = false;
            for (g.screens) |s| for (s.items) |p| {
                if (p.image == id) placed = true;
            };
            if (placed) k += 1 else g.removeImage(gpa, id);
        }
    }

    // ------------------------------------------------ screen events

    /// Rows [top, bot] of a screen scrolled by `delta` (negative = up).
    pub fn scroll(g: *Graphics, alt: bool, top: u16, bot: u16, delta: i32) void {
        const list = &g.screens[@intFromBool(alt)];
        var any = false;
        var k: usize = 0;
        while (k < list.items.len) {
            const p = &list.items[k];
            const in_region = (p.row >= top or top == 0) and p.row <= bot;
            if (!in_region) {
                k += 1;
                continue;
            }
            any = true;
            p.row += delta;
            const gone = if (delta < 0)
                (if (top == 0) p.row + @as(i32, p.rows) <= 0 else p.row < top)
            else
                p.row > bot;
            if (gone) _ = list.orderedRemove(k) else k += 1;
        }
        if (any) g.changed();
    }

    /// Cells [x0, x1) of row y were erased or overwritten.
    pub fn erase(g: *Graphics, alt: bool, y: u16, x0: usize, x1: usize) void {
        const list = &g.screens[@intFromBool(alt)];
        var k: usize = 0;
        while (k < list.items.len) {
            if (list.items[k].overlaps(y, x0, x1)) {
                _ = list.orderedRemove(k);
                g.changed();
            } else k += 1;
        }
    }

    pub fn clearScreen(g: *Graphics, alt: bool) void {
        const list = &g.screens[@intFromBool(alt)];
        if (list.items.len == 0) return;
        list.clearRetainingCapacity();
        g.changed();
    }

    /// The screen became cols x rows (content anchored top-left).
    pub fn resize(g: *Graphics, cols: u16, rows: u16) void {
        for (&g.screens) |*list| {
            var k: usize = 0;
            while (k < list.items.len) {
                const p = list.items[k];
                if (p.col >= cols or p.row >= rows) {
                    _ = list.orderedRemove(k);
                    g.changed();
                } else k += 1;
            }
        }
    }

    /// RIS: everything goes.
    pub fn reset(g: *Graphics, gpa: Allocator) void {
        for (g.images.items) |im| gpa.free(im.png);
        g.images.clearRetainingCapacity();
        g.total_bytes = 0;
        for (&g.screens) |*s| s.clearRetainingCapacity();
        g.dropPending(gpa);
        g.changed();
    }
};

// ------------------------------------------------------------ wire format

/// 'I' frame: u8 'I', u32 image id, u32 length, PNG bytes (docs/protocol.md).
pub fn appendBlobFrame(out: *std.ArrayList(u8), gpa: Allocator, image: u32, png: []const u8) !void {
    try out.ensureUnusedCapacity(gpa, 9 + png.len);
    out.appendAssumeCapacity('I');
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, image, .little);
    out.appendSliceAssumeCapacity(&b);
    std.mem.writeInt(u32, &b, @intCast(png.len), .little);
    out.appendSliceAssumeCapacity(&b);
    out.appendSliceAssumeCapacity(png);
}

pub const placement_entry_len = 14;

/// Removes, in place, every ancillary chunk of PNG `png` but a well-formed
/// `tRNS` (transparency, which changes the picture): text (`tEXt`,
/// `zTXt`, `iTXt`), `eXIf`, `tIME`, colour profiles, APNG frames and any
/// other metadata the program put in never reach a viewer. Critical
/// chunks (IHDR, PLTE, IDAT, IEND) are kept as they are, with their CRCs.
/// Returns the new length, or null if the chunk structure is broken.
pub fn stripAncillary(png: []u8) ?usize {
    const sig_len = 8;
    if (png.len < sig_len) return null;
    var r: usize = sig_len;
    var w: usize = sig_len;
    var color_type: ?u8 = null;
    var palette_entries: usize = 0;
    while (r < png.len) {
        if (png.len - r < 12) return null;
        const len = std.mem.readInt(u32, png[r..][0..4], .big);
        if (len > png.len - r - 12) return null;
        const total = 12 + @as(usize, len);
        const kind = png[r + 4 ..][0..4];
        const data = png[r + 8 ..][0..len];
        const critical = kind[0] & 0x20 == 0;
        if (std.mem.eql(u8, kind, "IHDR") and len >= 10) color_type = data[9];
        if (std.mem.eql(u8, kind, "PLTE")) palette_entries = len / 3;
        const keep = critical or (std.mem.eql(u8, kind, "tRNS") and validTrns(color_type, palette_entries, len));
        if (keep) {
            std.mem.copyForwards(u8, png[w..][0..total], png[r..][0..total]);
            w += total;
        }
        r += total;
        if (std.mem.eql(u8, kind, "IEND")) break;
    }
    return w;
}

/// tRNS's fixed sizes: 2 bytes (grey), 6 (RGB), at most one per palette
/// entry (indexed); none for colour types with alpha.
fn validTrns(color_type: ?u8, palette_entries: usize, len: u32) bool {
    return switch (color_type orelse return false) {
        0 => len == 2,
        2 => len == 6,
        3 => len >= 1 and len <= palette_entries,
        else => false,
    };
}

test "stripAncillary keeps the picture and drops metadata" {
    const gpa = std.testing.allocator;
    const base = try imgcheck.testImage(gpa, 4, 3);
    defer gpa.free(base);
    // Insert tEXt, tIME and an over-long tRNS after IHDR (8 + 25 bytes).
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try buf.appendSlice(gpa, base[0..33]);
    try appendChunk(gpa, &buf, "tEXt", "Comment\x00C:\\Users\\someone\\secret.txt");
    try appendChunk(gpa, &buf, "tIME", "\x07\xea\x0b\x0d\x0c\x00\x00");
    try appendChunk(gpa, &buf, "tRNS", "\x00\x01\x02\x03\x04\x05\x06\x07");
    try buf.appendSlice(gpa, base[33..]);
    _ = try imgcheck.validate(buf.items);
    const n = stripAncillary(buf.items).?;
    try std.testing.expectEqualSlices(u8, base, buf.items[0..n]);
    // Already clean: unchanged.
    const again = try gpa.dupe(u8, base);
    defer gpa.free(again);
    try std.testing.expectEqual(base.len, stripAncillary(again).?);
    // Broken structure.
    try std.testing.expect(stripAncillary(again[0 .. base.len - 3]) == null);
}

fn appendChunk(gpa: Allocator, buf: *std.ArrayList(u8), kind: *const [4]u8, data: []const u8) !void {
    var lb: [4]u8 = undefined;
    std.mem.writeInt(u32, &lb, @intCast(data.len), .big);
    try buf.appendSlice(gpa, &lb);
    try buf.appendSlice(gpa, kind);
    try buf.appendSlice(gpa, data);
    var c = std.hash.Crc32.init();
    c.update(kind);
    c.update(data);
    std.mem.writeInt(u32, &lb, c.final(), .big);
    try buf.appendSlice(gpa, &lb);
}

/// 'P' frame: u8 'P', u16 n, then n x { u32 image, u16 col, i16 row,
/// u16 cols, u16 rows }. Only placements whose image `have(ctx, id)`
/// accepts are included.
pub fn appendPlacementFrame(out: *std.ArrayList(u8), gpa: Allocator, list: []const Placement, ctx: anytype, comptime have: fn (@TypeOf(ctx), u32) bool) !void {
    const start = out.items.len;
    errdefer out.shrinkRetainingCapacity(start);
    try out.append(gpa, 'P');
    try out.appendSlice(gpa, &.{ 0, 0 });
    var n: u16 = 0;
    for (list) |p| {
        if (!have(ctx, p.image)) continue;
        if (p.row < std.math.minInt(i16) or p.row > std.math.maxInt(i16)) continue;
        var e: [placement_entry_len]u8 = undefined;
        std.mem.writeInt(u32, e[0..4], p.image, .little);
        std.mem.writeInt(u16, e[4..6], p.col, .little);
        std.mem.writeInt(i16, e[6..8], @intCast(p.row), .little);
        std.mem.writeInt(u16, e[8..10], p.cols, .little);
        std.mem.writeInt(u16, e[10..12], p.rows, .little);
        e[12] = 0;
        e[13] = 0;
        try out.appendSlice(gpa, &e);
        n += 1;
    }
    std.mem.writeInt(u16, out.items[start + 1 ..][0..2], n, .little);
}
