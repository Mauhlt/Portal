//! Tests for inline images in the emulator (vt.zig + vt_gfx.zig): the kitty
//! graphics subset, placement / scroll / erase semantics, limits, fuzzing.

const std = @import("std");
const vt = @import("vt.zig");
const gfx = vt.gfx;
const imgcheck = @import("imgcheck");
const testing = std.testing;
const gpa = testing.allocator;

/// `ESC _ G <keys>;<base64> ESC \` for `png`, in chunks of `chunk` base64
/// characters (0: one chunk).
fn kitty(out: *std.ArrayList(u8), keys: []const u8, png: []const u8, chunk: usize, osc: bool) !void {
    const enc = std.base64.standard.Encoder;
    const b64 = try gpa.alloc(u8, enc.calcSize(png.len));
    defer gpa.free(b64);
    _ = enc.encode(b64, png);
    const step = if (chunk == 0) @max(b64.len, 1) else chunk;
    var i: usize = 0;
    var first = true;
    while (true) {
        const n = @min(step, b64.len - i);
        const more = i + n < b64.len;
        try out.appendSlice(gpa, if (osc) "\x1b]7070;G" else "\x1b_G");
        if (first) {
            try out.appendSlice(gpa, keys);
            try out.appendSlice(gpa, if (more) ",m=1" else ",m=0");
        } else try out.appendSlice(gpa, if (more) "m=1" else "m=0");
        try out.append(gpa, ';');
        try out.appendSlice(gpa, b64[i..][0..n]);
        try out.appendSlice(gpa, if (osc) "\x07" else "\x1b\\");
        first = false;
        i += n;
        if (!more) break;
    }
}

fn feedImage(t: *vt.Terminal, keys: []const u8, w: u32, h: u32, chunk: usize) !void {
    const png = try imgcheck.testImage(gpa, w, h);
    defer gpa.free(png);
    var seq: std.ArrayList(u8) = .empty;
    defer seq.deinit(gpa);
    try kitty(&seq, keys, png, chunk, false);
    t.feed(seq.items);
}

fn expectPlacement(t: *const vt.Terminal, i: usize, col: u16, row: i32, cols: u16, rows: u16) !void {
    const ps = t.placements();
    try testing.expect(i < ps.len);
    const p = ps[i];
    testing.expect(p.col == col and p.row == row and p.cols == cols and p.rows == rows) catch |e| {
        std.debug.print("placement {d}: got col={d} row={d} {d}x{d}, want col={d} row={d} {d}x{d}\n", .{ i, p.col, p.row, p.cols, p.rows, col, row, cols, rows });
        return e;
    };
}

test "a=T places at the cursor and moves the cursor like kitty" {
    var t = try vt.Terminal.init(gpa, 40, 12);
    defer t.deinit();
    t.feed("ab");
    // 40 x 40 px at the nominal 10 x 20 cell: 4 x 2 cells.
    try feedImage(&t, "a=T,f=100", 40, 40, 0);
    try testing.expectEqual(@as(usize, 1), t.placements().len);
    try expectPlacement(&t, 0, 2, 0, 4, 2);
    // Cursor: last row of the image, column after it.
    try testing.expectEqual(vt.Cursor{ .x = 6, .y = 1, .visible = true }, t.cursor());
    const png = t.imagePng(t.placements()[0].image).?;
    try testing.expect(std.mem.startsWith(u8, png, &imgcheck.signature));
    // Explicit c/r, chunked, C=1 keeps the cursor.
    try feedImage(&t, "a=T,f=100,c=10,r=3,C=1", 40, 40, 8);
    try expectPlacement(&t, 1, 6, 1, 10, 3);
    try testing.expectEqual(vt.Cursor{ .x = 6, .y = 1, .visible = true }, t.cursor());
    // Only c given: rows follow the aspect ratio (40x40 px, 10x20 cells).
    try feedImage(&t, "a=T,f=100,c=8,C=1", 40, 40, 0);
    try expectPlacement(&t, 2, 6, 1, 8, 4);
}

test "default size is clamped to the screen keeping aspect" {
    var t = try vt.Terminal.init(gpa, 20, 6);
    defer t.deinit();
    // 1000 x 200 px -> 100 x 10 cells, fitted to 20 columns: 20 x 2.
    try feedImage(&t, "a=T,f=100,C=1", 1000, 200, 0);
    try expectPlacement(&t, 0, 0, 0, 20, 2);
    // Huge explicit sizes are clamped to the screen.
    try feedImage(&t, "a=T,f=100,c=5000,r=5000,C=1", 4, 4, 0);
    try expectPlacement(&t, 1, 0, 0, 20, 6);
}

test "OSC 7070 carrier with Portal anchor keys" {
    var t = try vt.Terminal.init(gpa, 30, 10);
    defer t.deinit();
    const png = try imgcheck.testImage(gpa, 30, 30);
    defer gpa.free(png);
    var seq: std.ArrayList(u8) = .empty;
    defer seq.deinit(gpa);
    try kitty(&seq, "a=T,f=100,t=d,q=2,C=1,c=6,r=3,j=4,l=5,i=99", png, 16, true);
    t.feed(seq.items);
    try expectPlacement(&t, 0, 4, 5, 6, 3);
    try testing.expectEqual(vt.Cursor{ .x = 0, .y = 0, .visible = true }, t.cursor());
    // The OSC did not leak into the title or the grid.
    try testing.expectEqualStrings("", t.title());
    var cells: [30]vt.Terminal.VisibleCell = undefined;
    _ = t.visibleRow(0, &cells);
    for (cells) |c| try testing.expectEqual(@as(u21, ' '), c.cp);
}

test "transmit, place by id, delete" {
    var t = try vt.Terminal.init(gpa, 30, 10);
    defer t.deinit();
    try feedImage(&t, "a=t,f=100,i=7", 20, 20, 0);
    try testing.expectEqual(@as(usize, 0), t.placements().len);
    t.feed("\x1b_Ga=p,i=7,c=2,r=1,C=1\x1b\\");
    t.feed("\x1b[5;5H\x1b_Ga=p,i=7,p=3,c=2,r=1\x1b\\");
    try testing.expectEqual(@as(usize, 2), t.placements().len);
    try expectPlacement(&t, 1, 4, 4, 2, 1);
    // Same i + p replaces that placement.
    t.feed("\x1b[1;1H\x1b_Ga=p,i=7,p=3,c=3,r=1,C=1\x1b\\");
    try testing.expectEqual(@as(usize, 2), t.placements().len);
    try expectPlacement(&t, 1, 0, 0, 3, 1);
    // Unknown id: nothing.
    t.feed("\x1b_Ga=p,i=8\x1b\\");
    try testing.expectEqual(@as(usize, 2), t.placements().len);
    t.feed("\x1b_Ga=d,d=i,i=7,p=3\x1b\\");
    try testing.expectEqual(@as(usize, 1), t.placements().len);
    t.feed("\x1b_Ga=d,d=I,i=7\x1b\\");
    try testing.expectEqual(@as(usize, 0), t.placements().len);
    try testing.expectEqual(@as(usize, 0), t.images.images.items.len);
    // d=a clears placements, keeps the image; d=A frees it too.
    try feedImage(&t, "a=T,f=100,i=9,C=1", 20, 20, 0);
    t.feed("\x1b_Ga=d\x1b\\");
    try testing.expectEqual(@as(usize, 0), t.placements().len);
    try testing.expectEqual(@as(usize, 1), t.images.images.items.len);
    t.feed("\x1b_Ga=d,d=A\x1b\\");
    try testing.expectEqual(@as(usize, 0), t.images.images.items.len);
    try testing.expectEqual(@as(usize, 0), t.images.total_bytes);
    // Retransmitting an id replaces the image (new wire id), dropping its placements.
    try feedImage(&t, "a=T,f=100,i=5,C=1", 20, 20, 0);
    const first = t.placements()[0].image;
    try feedImage(&t, "a=t,f=100,i=5", 10, 10, 0);
    try testing.expectEqual(@as(usize, 0), t.placements().len);
    t.feed("\x1b_Ga=p,i=5,C=1\x1b\\");
    try testing.expect(t.placements()[0].image != first);
}

test "placements scroll with text and leave when fully off screen" {
    var t = try vt.Terminal.init(gpa, 20, 5);
    defer t.deinit();
    t.feed("\x1b[3;1H");
    try feedImage(&t, "a=T,f=100,c=4,r=2,C=1", 8, 8, 0);
    try expectPlacement(&t, 0, 0, 2, 4, 2);
    t.feed("\x1b[5;1H\n");
    try expectPlacement(&t, 0, 0, 1, 4, 2);
    t.feed("\n\n");
    try expectPlacement(&t, 0, 0, -1, 4, 2); // half off the top: kept
    t.feed("\n");
    try testing.expectEqual(@as(usize, 0), t.placements().len);
    // Reverse index at the top scrolls down.
    t.feed("\x1b[1;1H");
    try feedImage(&t, "a=T,f=100,c=4,r=2,C=1", 8, 8, 0);
    t.feed("\x1bM");
    try expectPlacement(&t, 0, 0, 1, 4, 2);
    // Scroll region (rows 2-4): an image inside moves; leaving the region
    // drops it (it would cover the fixed rows above).
    t.feed("\x1b[3;1H");
    try feedImage(&t, "a=T,f=100,c=4,r=1,C=1", 8, 8, 0);
    t.feed("\x1b[2;4r\x1b[4;1H\n");
    // The 4x2 image at the region's top row left it; the 4x1 one moved up.
    try testing.expectEqual(@as(usize, 1), t.placements().len);
    try expectPlacement(&t, 0, 0, 1, 4, 1);
    t.feed("\n");
    try testing.expectEqual(@as(usize, 0), t.placements().len);
    // Above the region: untouched by region scrolls.
    t.feed("\x1b[r\x1b[1;1H");
    try feedImage(&t, "a=T,f=100,c=4,r=1,C=1", 8, 8, 0);
    t.feed("\x1b[2;4r\x1b[4;1H\n\n\n");
    try expectPlacement(&t, 0, 0, 0, 4, 1);
}

test "kitty cursor advance scrolls the image with it" {
    var t = try vt.Terminal.init(gpa, 20, 5);
    defer t.deinit();
    t.feed("\x1b[4;1H");
    try feedImage(&t, "a=T,f=100,c=3,r=4", 8, 8, 0);
    // Placed at row 3; the cursor moved 3 rows down, scrolling twice.
    try expectPlacement(&t, 0, 0, 1, 3, 4);
    try testing.expectEqual(vt.Cursor{ .x = 3, .y = 4, .visible = true }, t.cursor());
}

test "erasing or overwriting cells removes intersecting placements" {
    var t = try vt.Terminal.init(gpa, 20, 8);
    defer t.deinit();
    const cases = [_][]const u8{
        "\x1b[2J", // ED 2
        "\x1b[3;1H\x1b[J", // ED 0 from above
        "\x1b[4;2H\x1b[K", // EL 0 inside
        "\x1b[3;9H\x1b[1K", // EL 1 reaching it
        "\x1b[4;3HX", // print over it
        "\x1b[3;1H\x1b[10X", // ECH
        "\x1b[4;1H\x1b[P", // DCH shifts it
        "\x1b[4;1H\x1b[@", // ICH shifts it
        "\x1bc", // RIS
        "\x1b#8", // DECALN
    };
    for (cases) |c| {
        t.feed("\x1b[3;2H");
        try feedImage(&t, "a=T,f=100,c=4,r=2,C=1", 8, 8, 0);
        try testing.expectEqual(@as(usize, 1), t.placements().len);
        t.feed(c);
        testing.expectEqual(@as(usize, 0), t.placements().len) catch |e| {
            std.debug.print("not removed by {any}\n", .{c});
            return e;
        };
        t.feed("\x1b[2J");
    }
    // Text and erases elsewhere leave it alone.
    t.feed("\x1b[3;2H");
    try feedImage(&t, "a=T,f=100,c=4,r=2,C=1", 8, 8, 0);
    t.feed("\x1b[1;1Hhello\x1b[K\x1b[6;1Hworld\x1b[J\x1b[3;10Hxyz\x1b[4;6H\x1b[K");
    try testing.expectEqual(@as(usize, 1), t.placements().len);
}

test "alternate screen has its own placements" {
    var t = try vt.Terminal.init(gpa, 20, 8);
    defer t.deinit();
    try feedImage(&t, "a=T,f=100,i=1,c=2,r=2,C=1", 8, 8, 0);
    const g0 = t.imagesGen();
    t.feed("\x1b[?1049h");
    try testing.expect(t.imagesGen() != g0);
    try testing.expectEqual(@as(usize, 0), t.placements().len);
    t.feed("\x1b_Ga=p,i=1,c=3,r=1,C=1\x1b\\");
    try testing.expectEqual(@as(usize, 1), t.placements().len);
    try expectPlacement(&t, 0, 0, 0, 3, 1);
    t.feed("\x1b[?1049l");
    try testing.expectEqual(@as(usize, 1), t.placements().len);
    try expectPlacement(&t, 0, 0, 0, 2, 2);
    // Re-entering clears the alternate screen, images included.
    t.feed("\x1b[?1049h");
    try testing.expectEqual(@as(usize, 0), t.placements().len);
}

test "resize drops placements anchored outside" {
    var t = try vt.Terminal.init(gpa, 20, 8);
    defer t.deinit();
    t.feed("\x1b[6;15H");
    try feedImage(&t, "a=T,f=100,c=2,r=1,C=1", 8, 8, 0);
    t.feed("\x1b[1;1H");
    try feedImage(&t, "a=T,f=100,c=2,r=1,C=1", 8, 8, 0);
    try t.resize(10, 4);
    try testing.expectEqual(@as(usize, 1), t.placements().len);
    try expectPlacement(&t, 0, 0, 0, 2, 1);
}

test "unsupported commands are consumed without side effects" {
    var t = try vt.Terminal.init(gpa, 20, 4);
    defer t.deinit();
    const png = try imgcheck.testImage(gpa, 8, 8);
    defer gpa.free(png);
    const bad_keys = [_][]const u8{
        "a=T,f=32,s=8,v=8", // raw RGBA
        "a=T,f=24", // raw RGB
        "a=T,f=100,t=f", // "read this file": never
        "a=T,f=100,t=t", // temp file
        "a=T,f=100,t=s", // shared memory
        "a=T,f=100,o=z", // zlib-compressed payload
        "a=T,f=100,bogus", // malformed key
        "a=T,f=100,xx=1", // multi-letter key
    };
    for (bad_keys) |k| {
        var seq: std.ArrayList(u8) = .empty;
        defer seq.deinit(gpa);
        try kitty(&seq, k, png, 12, false);
        try seq.appendSlice(gpa, "ok");
        t.feed("\x1b[1;1H");
        t.feed(seq.items);
        try testing.expectEqual(@as(usize, 0), t.images.images.items.len);
        try testing.expectEqual(@as(usize, 0), t.placements().len);
        var cells: [20]vt.Terminal.VisibleCell = undefined;
        _ = t.visibleRow(0, &cells);
        try testing.expectEqual(@as(u21, 'o'), cells[0].cp);
        try testing.expectEqual(@as(u21, 'k'), cells[1].cp);
    }
    // Not a PNG, bad base64, truncated PNG, padding inside, queries.
    t.feed("\x1b_Ga=T,f=100;AAAAAAAA\x1b\\");
    t.feed("\x1b_Ga=T,f=100;!!!!\x1b\\");
    const enc = std.base64.standard.Encoder;
    var b64: [256]u8 = undefined;
    const half = enc.encode(&b64, png[0 .. png.len / 2]);
    var seq: std.ArrayList(u8) = .empty;
    defer seq.deinit(gpa);
    try seq.print(gpa, "\x1b_Ga=T,f=100;{s}\x1b\\", .{half});
    t.feed(seq.items);
    t.feed("\x1b_Ga=q,i=1,f=100;AAAA\x1b\\\x1b_G\x1b\\\x1b_G;\x1b\\\x1b_Gm=0\x1b\\\x1b_Ga=p\x1b\\\x1b_Ga=d,d=z\x1b\\");
    // Other APC strings, SOS/PM are still discarded.
    t.feed("\x1b_Xjunk\x1b\\\x1b^pm\x1b\\\x1bXsos\x1b\\");
    try testing.expectEqual(@as(usize, 0), t.images.images.items.len);
    try testing.expectEqual(@as(usize, 0), t.placements().len);
}

test "CAN aborts and an interrupting command drops a chunked transmission" {
    var t = try vt.Terminal.init(gpa, 20, 4);
    defer t.deinit();
    const png = try imgcheck.testImage(gpa, 8, 8);
    defer gpa.free(png);
    var seq: std.ArrayList(u8) = .empty;
    defer seq.deinit(gpa);
    try kitty(&seq, "a=T,f=100,C=1", png, 16, false);
    // Cut after the first chunk, CAN, then the rest: nothing is stored.
    const cut = std.mem.indexOf(u8, seq.items, "\x1b\\").? + 2;
    t.feed(seq.items[0..cut]);
    t.feed("\x1b_Gm=1;AAAA\x18");
    t.feed(seq.items[cut..]);
    try testing.expectEqual(@as(usize, 0), t.images.images.items.len);
    // A new full command in the middle of a transmission replaces it.
    t.feed(seq.items[0..cut]);
    t.feed(seq.items);
    try testing.expectEqual(@as(usize, 1), t.images.images.items.len);
    try testing.expectEqual(@as(usize, 1), t.placements().len);
}

test "limits: payload size, image count, total bytes, IHDR" {
    var t = try vt.Terminal.init(gpa, 20, 4);
    defer t.deinit();
    // > 8 MiB of base64 is dropped (and never fully buffered).
    {
        const chunk: [4096]u8 = @splat(65);
        t.feed("\x1b_Ga=T,f=100,m=1;");
        t.feed(&chunk);
        t.feed("\x1b\\");
        var i: usize = 0;
        while (i < (gfx.max_b64_per_image / 4096) + 4) : (i += 1) {
            t.feed("\x1b_Gm=1;");
            t.feed(&chunk);
            t.feed("\x1b\\");
        }
        try testing.expect(t.images.pend.capacity <= imgcheck.max_file_bytes);
        t.feed("\x1b_Gm=0;\x1b\\");
        try testing.expectEqual(@as(usize, 0), t.images.images.items.len);
    }
    // At most 64 images; the oldest go first.
    for (0..70) |k| {
        var keys: [64]u8 = undefined;
        try feedImage(&t, try std.fmt.bufPrint(&keys, "a=t,f=100,i={d}", .{k + 1}), 4, 4, 0);
    }
    try testing.expectEqual(gfx.max_images, t.images.images.items.len);
    try testing.expectEqual(@as(u32, 7), t.images.images.items[0].client_id);
    var sum: usize = 0;
    for (t.images.images.items) |im| sum += im.png.len;
    try testing.expectEqual(sum, t.images.total_bytes);
    // Total bytes: 12 images of ~5.9 MiB can't all stay.
    t.feed("\x1b_Ga=d,d=A\x1b\\");
    const big = try imgcheck.testImage(gpa, 1250, 1180); // ~5.9 MB stored PNG
    defer gpa.free(big);
    try testing.expect(big.len <= imgcheck.max_file_bytes);
    var seq: std.ArrayList(u8) = .empty;
    defer seq.deinit(gpa);
    try kitty(&seq, "a=t,f=100", big, 4096, false);
    for (0..12) |_| t.feed(seq.items);
    try testing.expect(t.images.total_bytes <= gfx.max_total_bytes);
    try testing.expectEqual(gfx.max_total_bytes / big.len, t.images.images.items.len);
    // IHDR over the limits: refused before storing.
    const huge = try gpa.dupe(u8, big[0..@min(big.len, 4096)]);
    defer gpa.free(huge);
    const small = try imgcheck.testImage(gpa, 4, 4);
    defer gpa.free(small);
    const m = try gpa.dupe(u8, small);
    defer gpa.free(m);
    std.mem.writeInt(u32, m[16..20], 9000, .big);
    imgcheck.fixCrcs(m);
    t.feed("\x1b_Ga=d,d=A\x1b\\");
    seq.clearRetainingCapacity();
    try kitty(&seq, "a=T,f=100", m, 0, false);
    t.feed(seq.items);
    try testing.expectEqual(@as(usize, 0), t.images.images.items.len);
}

test "placements per screen are capped" {
    var t = try vt.Terminal.init(gpa, 20, 4);
    defer t.deinit();
    try feedImage(&t, "a=t,f=100,i=1", 4, 4, 0);
    for (0..gfx.max_placements + 50) |_| t.feed("\x1b_Ga=p,i=1,C=1\x1b\\");
    try testing.expectEqual(gfx.max_placements, t.placements().len);
}

fn checkInvariants(t: *const vt.Terminal) !void {
    const g = &t.images;
    try testing.expect(g.images.items.len <= gfx.max_images);
    try testing.expect(g.total_bytes <= gfx.max_total_bytes);
    var sum: usize = 0;
    for (g.images.items) |im| {
        sum += im.png.len;
        _ = try imgcheck.validate(im.png);
    }
    try testing.expectEqual(sum, g.total_bytes);
    for (g.screens) |s| {
        try testing.expect(s.items.len <= gfx.max_placements);
        for (s.items) |p| {
            try testing.expect(g.find(p.image) != null);
            try testing.expect(p.cols >= 1 and p.rows >= 1 and p.col < t.cols and p.row < t.rows);
            try testing.expect(p.row + @as(i32, p.rows) > 0);
        }
    }
    try testing.expect(g.pend.items.len <= imgcheck.max_file_bytes);
}

test "fuzz: random, truncated, oversized and interleaved graphics never panic" {
    var prng: std.Random.DefaultPrng = .init(0x9a7c);
    const rand = prng.random();
    var t = try vt.Terminal.init(gpa, 24, 8);
    defer t.deinit();
    const pngs = [_][]u8{
        try imgcheck.testImage(gpa, 5, 3),
        try imgcheck.testImage(gpa, 40, 25),
        try imgcheck.testImage(gpa, 1, 1),
    };
    defer for (pngs) |p| gpa.free(p);
    const pieces = [_][]const u8{
        "\x1b_G",      "\x1b]7070;G", "a=T,f=100", "a=t,f=100,i=3", "a=p,i=3", "a=d,d=a", "m=1",
        "m=0",         ";",           "AAAA",      "\x1b\\",        "\x07",    "\x18",    "\x1b[2J",
        "\x1b[?1049h", "\x1b[?1049l", "\n",        "\r\n",          "text",    "\x1b[5;5H", "=",
        "c=3,r=2",     "C=1",         ",",         "j=30,l=40",     "\x1bM",   "\x1b[3L", "\x1b[2M",
        "\x1b[S",      "\x1b[T",      "\xff\xfe",  "\x1b[K",        "\x1b_",   "\x1b]",   "i=4294967295",
    };
    var seq: std.ArrayList(u8) = .empty;
    defer seq.deinit(gpa);
    for (0..4000) |round| {
        seq.clearRetainingCapacity();
        for (0..rand.intRangeAtMost(usize, 1, 12)) |_| {
            switch (rand.uintLessThan(u8, 10)) {
                0...5 => try seq.appendSlice(gpa, pieces[rand.uintLessThan(usize, pieces.len)]),
                6, 7 => { // a valid image command, maybe chunked, maybe cut short
                    var one: std.ArrayList(u8) = .empty;
                    defer one.deinit(gpa);
                    const keys = ([_][]const u8{ "a=T,f=100", "a=t,f=100,i=3", "a=T,f=100,C=1,c=2", "a=T,f=100,i=4,p=1,j=3,l=2" })[rand.uintLessThan(usize, 4)];
                    try kitty(&one, keys, pngs[rand.uintLessThan(usize, pngs.len)], rand.uintAtMost(usize, 64), rand.boolean());
                    const n = if (rand.uintLessThan(u8, 4) == 0) rand.uintAtMost(usize, one.items.len) else one.items.len;
                    try seq.appendSlice(gpa, one.items[0..n]);
                },
                8 => {
                    var junk: [64]u8 = undefined;
                    rand.bytes(&junk);
                    try seq.appendSlice(gpa, junk[0..rand.uintAtMost(usize, junk.len)]);
                },
                else => if (round % 200 == 0) { // an oversized transmission
                    try seq.appendSlice(gpa, "\x1b_Ga=T,f=100,m=1;");
                    try seq.appendNTimes(gpa, 'B', 9 << 20);
                    try seq.appendSlice(gpa, "\x1b\\\x1b_Gm=0;\x1b\\");
                },
            }
        }
        // Feed in random splits: the parser is byte-at-a-time.
        var rest: []const u8 = seq.items;
        while (rest.len > 0) {
            const n = rand.intRangeAtMost(usize, 1, @max(1, rest.len));
            t.feed(rest[0..n]);
            rest = rest[n..];
        }
        if (round % 500 == 0) try t.resize(rand.intRangeAtMost(u16, 1, 40), rand.intRangeAtMost(u16, 1, 12));
        try checkInvariants(&t);
    }
}

test "byte-at-a-time feeding equals feeding all at once" {
    const png = try imgcheck.testImage(gpa, 30, 30);
    defer gpa.free(png);
    var seq: std.ArrayList(u8) = .empty;
    defer seq.deinit(gpa);
    try seq.appendSlice(gpa, "hi\r\n");
    try kitty(&seq, "a=T,f=100,i=2", png, 20, false);
    try seq.appendSlice(gpa, "\r\n\n");
    try kitty(&seq, "a=T,f=100,c=3,r=2,j=1,l=1,C=1", png, 0, true);
    var a = try vt.Terminal.init(gpa, 20, 6);
    defer a.deinit();
    var b = try vt.Terminal.init(gpa, 20, 6);
    defer b.deinit();
    a.feed(seq.items);
    for (seq.items) |c| b.feed(&.{c});
    try testing.expectEqual(a.placements().len, b.placements().len);
    try testing.expectEqual(@as(usize, 2), a.placements().len);
    for (a.placements(), b.placements()) |pa, pb| {
        try testing.expectEqual(pa.col, pb.col);
        try testing.expectEqual(pa.row, pb.row);
        try testing.expectEqual(pa.cols, pb.cols);
        try testing.expectEqual(pa.rows, pb.rows);
    }
    try testing.expectEqual(a.cursor(), b.cursor());
}

test "wire frames" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try gfx.appendBlobFrame(&out, gpa, 0x01020304, "PNGDATA");
    try testing.expectEqualSlices(u8, "I\x04\x03\x02\x01\x07\x00\x00\x00PNGDATA", out.items);
    out.clearRetainingCapacity();
    const list = [_]gfx.Placement{
        .{ .image = 5, .client_id = 0, .pid = 0, .col = 1, .row = -2, .cols = 3, .rows = 4 },
        .{ .image = 6, .client_id = 0, .pid = 0, .col = 0, .row = 0, .cols = 1, .rows = 1 },
    };
    const Have = struct {
        fn f(_: void, id: u32) bool {
            return id == 5;
        }
    };
    try gfx.appendPlacementFrame(&out, gpa, &list, {}, Have.f);
    try testing.expectEqualSlices(u8, "P\x01\x00\x05\x00\x00\x00\x01\x00\xfe\xff\x03\x00\x04\x00\x00\x00", out.items);
}
