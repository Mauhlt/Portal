//! Inline images end to end: a program in the session runs `portal-show`
//! (found on the session's PATH, which Portal starts with its own folder)
//! on a PNG this test writes; viewers must receive the blob ('I') and the
//! placement ('P') with the right geometry, strictly decoded; a viewer
//! without a session gets nothing.

const std = @import("std");
const Io = std.Io;
const net = @import("net.zig");
const proc = @import("proc.zig");
const client = @import("client.zig");
const ws = @import("ws.zig");
const pngcheck = @import("pngcheck");
const Runner = @import("runner.zig").Runner;

/// 80 x 40 px at `--cols 8`: 8 columns, and rows from the aspect ratio at
/// the nominal 10 x 20 px cell = 8 * 40 * 10 / (80 * 20) = 2.
const png_w = 80;
const png_h = 40;
const want_cols = 8;
const want_rows = 2;

fn hasPlacement(_: void, v: *client.Viewer) bool {
    return v.g.placements.items.len > 0 and v.g.find("IMG-SHOWN") != null;
}

pub fn run(h: *proc.Harness, r: *Runner, port: u16) !void {
    const dir = try h.dataDir("images");
    const png = try pngcheck.testImage(h.gpa, png_w, png_h);
    defer h.gpa.free(png);
    const png_path = try std.fmt.allocPrint(h.gpa, "{s}\\test.png", .{dir});
    try Io.Dir.cwd().writeFile(h.io, .{ .sub_path = png_path, .data = png });

    // The session program waits for the viewer to connect, shows the image,
    // then idles. Paths under the scratch root have no spaces.
    // `portal-show` by name: the session's PATH must lead to the one next
    // to portalctl.exe.
    const script = try std.fmt.allocPrint(h.gpa, "echo IMG-READY & ping -n 6 127.0.0.1 >nul & portal-show {s} --cols {d} & echo IMG-SHOWN & ping -n 600 127.0.0.1 >nul", .{ png_path, want_cols });
    const inst = try proc.Instance.start(h, dir, port, &.{ "--", "cmd.exe", "/c", script });
    defer inst.kill();

    // Nothing without a session: the WebSocket upgrade is refused.
    {
        var c = try ws.Client.connect(h.gpa, port, .{ .host = inst.host, .origin = inst.origin, .cookie = null });
        defer c.close();
        _ = r.check("no session: /ws refused", c.status == 401, "status {d}", .{c.status});
        var c2 = try ws.Client.connect(h.gpa, port, .{ .host = inst.host, .origin = inst.origin, .cookie = "portal_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" });
        defer c2.close();
        _ = r.check("bogus session: /ws refused", c2.status == 401, "status {d}", .{c2.status});
    }

    const creds = try client.pair(inst, "laptop");
    const sess = creds.sessionCookie();
    var dump_buf: [4096]u8 = undefined;
    const v = try client.Viewer.open(inst, sess);
    defer v.deinit();
    _ = r.check("session started", v.waitFor("IMG-READY", 10_000), "{s}", .{v.dump(&dump_buf)});
    const got = v.pumpUntil(20_000, {}, hasPlacement);
    _ = r.check("'P' placement arrives after portal show", got, "placements {d}, blobs {d}; {s}", .{ v.g.placements.items.len, v.g.blob_frames, v.dump(&dump_buf) });
    _ = r.check("every frame decoded strictly (G, I, P)", v.bad == null, "{?t}", .{v.bad});
    _ = r.check("no image frame before the first grid frame", v.g.early_image_frames == 0, "{d}", .{v.g.early_image_frames});
    if (!got) return;

    const p = v.g.placements.items[0];
    _ = r.check("exactly one blob and one placement", v.g.blob_frames == 1 and v.g.placements.items.len == 1, "blobs {d}, placements {d}", .{ v.g.blob_frames, v.g.placements.items.len });
    const blob = v.g.blob(p.id) orelse &.{};
    _ = r.check("'I' blob is the exact PNG", std.mem.eql(u8, blob, png), "{d} bytes vs {d}", .{ blob.len, png.len });
    _ = r.check("placement size from --cols and the aspect ratio", p.cols == want_cols and p.rows == want_rows and p.col == 0, "col {d} {d}x{d}", .{ p.col, p.cols, p.rows });
    const ready = v.g.find("IMG-READY") orelse 0;
    const shown = v.g.find("IMG-SHOWN") orelse 0;
    _ = r.check("image sits between the lines printed before and after it", p.row > ready and shown >= @as(usize, @intCast(@max(0, p.row))) + p.rows, "ready row {d}, image row {d}+{d}, shown row {d}", .{ ready, p.row, p.rows, shown });

    // A viewer connecting later gets the blob and the same placement.
    {
        const v2 = try client.Viewer.open(inst, sess);
        defer v2.deinit();
        const got2 = v2.pumpUntil(10_000, {}, hasPlacement);
        const p2: ?@TypeOf(p) = if (v2.g.placements.items.len > 0) v2.g.placements.items[0] else null;
        _ = r.check("late viewer gets blob + placement", got2 and v2.g.blob_frames == 1 and p2 != null and p2.?.row == p.row and p2.?.cols == p.cols, "blobs {d}", .{v2.g.blob_frames});
        _ = r.check("late viewer: frames strict", v2.bad == null, "{?t}", .{v2.bad});
    }
    // Quiet afterwards: no repeated blobs or placements.
    const blobs_before = v.g.blob_frames;
    const p_before = v.g.placement_frames;
    v.pump(2500);
    _ = r.check("no repeated 'I'/'P' while nothing changes", v.g.blob_frames == blobs_before and v.g.placement_frames == p_before, "I {d}->{d}, P {d}->{d}", .{ blobs_before, v.g.blob_frames, p_before, v.g.placement_frames });
}
