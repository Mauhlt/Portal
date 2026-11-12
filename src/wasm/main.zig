//! Portal's browser client, compiled to wasm32-freestanding.
//!
//! The whole viewer lives here: protocol decoding (proto.zig), connection
//! and reconnect policy (conn.zig), layout and hit testing (layout.zig),
//! key mapping (keys.zig), glyph rasterisation (glyphs.zig + font/) and
//! drawing (render.zig). src/web/app.js is only the unavoidable browser
//! glue: it instantiates this module, forwards DOM events to the exports
//! below and implements the `host` imports as one-line browser API calls.
//!
//! Data in: the bridge asks `in_alloc(n)` for a buffer, copies the bytes
//! (a WebSocket message, a key name, a URL path) there, then calls the
//! handler with the length. Pixels out: `present` hands the bridge a view
//! of the framebuffer for putImageData.

const std = @import("std");
const proto = @import("proto.zig");
const conn_mod = @import("conn.zig");
const layout = @import("layout.zig");
const keys = @import("keys.zig");
const glyphs = @import("glyphs.zig");
const render = @import("render.zig");

/// Host functions provided by src/web/app.js. This list is the entire
/// surface between the page and the client; web.zig's tests check the
/// compiled module imports exactly these.
const host = struct {
    extern "env" fn log(p: [*]const u8, n: usize) void;
    /// Writes `location.protocol + "//" + location.host` into p[0..cap].
    extern "env" fn get_origin(p: [*]u8, cap: usize) usize;
    extern "env" fn ws_open(p: [*]const u8, n: usize) void;
    extern "env" fn ws_send(p: [*]const u8, n: usize) void;
    extern "env" fn ws_close() void;
    extern "env" fn canvas_size(w: u32, h: u32) void;
    /// putImageData of rows y0..y1 of the w x h RGBA image at p.
    extern "env" fn present(p: [*]const u32, w: u32, h: u32, y0: u32, y1: u32) void;
    extern "env" fn request_frame() void;
    extern "env" fn set_timer(ms: u32) void;
    /// GET / (following redirects); answers with on_check.
    extern "env" fn check_session() void;
    extern "env" fn navigate_pair() void;
    /// slot 0 = status, 1 = mode; cls 0 neutral, 1 ok, 2 bad.
    extern "env" fn set_text(slot: u32, p: [*]const u8, n: usize, cls: u32) void;
};

pub const panic = std.debug.FullPanic(struct {
    fn f(msg: []const u8, _: ?usize) noreturn {
        host.log(msg.ptr, msg.len);
        @trap();
    }
}.f);

const gpa = std.heap.wasm_allocator;

/// Largest message the bridge may hand over (a full 1000x1000 grid frame
/// is well under this).
const max_input = 32 << 20;

const Drag = struct { x: i32, y: i32, pan: [2]i32 };

const App = struct {
    grid: proto.Grid = .{},
    conn: conn_mod.Conn = .{},
    policy: proto.Policy = .none,
    zoom: layout.Zoom = .{},
    touch: bool = false,
    css_w: f64 = 0,
    css_h: f64 = 0,
    dpr: f64 = 1,
    sized: bool = false,
    l: layout.Layout = .{},
    pan: [2]i32 = .{ 0, 0 },
    term: glyphs.Glyphs,
    ui: glyphs.Glyphs,
    r: render.Renderer = .{},
    /// Everything must be redrawn (layout, pan or mode changed).
    full: bool = true,
    bar_dirty: bool = true,
    frame_pending: bool = false,
    pressed: ?usize = null,
    drag: ?Drag = null,
    in_buf: []u8 = &.{},
    canvas_w: u32 = 0,
    canvas_h: u32 = 0,
};

var app: App = undefined;
var ready = false;

fn logMsg(comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch "log overflow";
    host.log(s.ptr, s.len);
}

fn setText(slot: u32, s: []const u8, cls: conn_mod.Status) void {
    host.set_text(slot, s.ptr, s.len, @intFromEnum(cls));
}

fn showStatus() void {
    var buf: [64]u8 = undefined;
    const st = app.conn.statusText(&buf);
    setText(0, st.text, st.kind);
}

fn schedule() void {
    if (app.frame_pending or !app.sized) return;
    app.frame_pending = true;
    host.request_frame();
}

fn relayout() void {
    if (!app.sized) return;
    app.l = layout.compute(.{
        .css_w = app.css_w,
        .css_h = app.css_h,
        .dpr = app.dpr,
        .touch = app.touch,
        .show_bar = app.policy != .none,
        .cols = app.grid.cols,
        .rows = app.grid.rows,
        .zoom = app.zoom,
        .m = app.term.metrics(),
    });
    app.r.fb.resize(gpa, app.l.w, app.l.h) catch {
        logMsg("out of memory for a {d}x{d} canvas", .{ app.l.w, app.l.h });
        app.sized = false;
        return;
    };
    if (app.l.w != app.canvas_w or app.l.h != app.canvas_h) {
        // Setting canvas.width clears it, so only on a real change.
        app.canvas_w = app.l.w;
        app.canvas_h = app.l.h;
        host.canvas_size(app.l.w, app.l.h);
    }
    app.term.setSize(app.l.cw, app.l.ch, app.l.em);
    app.ui.setEm(app.l.label_em);
    app.pan = app.l.clampPan(app.pan);
    app.full = true;
    app.bar_dirty = true;
    schedule();
}

fn perform(e: conn_mod.Effect) void {
    switch (e) {
        .none => {},
        .open => {
            var url: [512]u8 = undefined;
            const n = @min(host.get_origin(&url, url.len - 8), url.len - 8);
            const origin = url[0..n];
            // http://host → ws://host/ws, https://host → wss://host/ws.
            const colon = std.mem.indexOfScalar(u8, origin, ':') orelse return;
            const secure = std.mem.eql(u8, origin[0..colon], "https");
            var out: [520]u8 = undefined;
            const s = std.fmt.bufPrint(&out, "{s}{s}/ws", .{ if (secure) "wss" else "ws", origin[colon..] }) catch return;
            host.ws_open(s.ptr, s.len);
        },
        .timer => |ms| host.set_timer(ms),
        .check => host.check_session(),
        .leave => {
            host.ws_close();
            host.navigate_pair();
        },
    }
    showStatus();
}

fn send(action: keys.Action) void {
    if (app.policy == .none or app.conn.state != .live) return;
    var buf: [64]u8 = undefined;
    const f = keys.frame(&buf, action) orelse return;
    host.ws_send(f.ptr, f.len);
}

fn input(len: usize) ?[]const u8 {
    if (len > app.in_buf.len) return null;
    return app.in_buf[0..len];
}

// ------------------------------------------------------------------ exports

/// Called once after instantiation. `touch`: the page has a coarse pointer.
export fn init(touch: u32) void {
    const regular = @embedFile("font_regular");
    const bold = @embedFile("font_bold");
    const term = glyphs.Glyphs.init(gpa, regular, bold) catch {
        setText(0, "font failed to load", .bad);
        return;
    };
    const ui = glyphs.Glyphs.init(gpa, regular, bold) catch return;
    app = .{ .term = term, .ui = ui, .touch = touch != 0 };
    ready = true;
    perform(app.conn.start());
}

/// The bridge copies `n` bytes to the returned address before calling a
/// handler with length `n`. Returns 0 (copy nothing) if `n` is too large.
export fn in_alloc(n: usize) usize {
    if (!ready or n > max_input) return 0;
    if (n > app.in_buf.len or app.in_buf.len == 0) {
        const size = @max(n, 64 << 10);
        const b = gpa.alloc(u8, size) catch return 0;
        gpa.free(app.in_buf);
        app.in_buf = b;
    }
    return @intFromPtr(app.in_buf.ptr);
}

/// Canvas CSS size and devicePixelRatio (on load and every resize).
export fn resize(css_w: f64, css_h: f64, dpr: f64) void {
    if (!ready) return;
    app.css_w = css_w;
    app.css_h = css_h;
    app.dpr = dpr;
    app.sized = true;
    relayout();
}

/// requestAnimationFrame callback: draw what changed and present it.
export fn frame() void {
    if (!ready) return;
    app.frame_pending = false;
    if (!app.sized) return;
    const view: render.Renderer.View = .{ .l = app.l, .pan = app.pan, .show_cursor = app.policy != .none };
    if (app.full) app.r.clearTerm(app.l);
    var y: u16 = 0;
    while (y < app.grid.rows) : (y += 1) {
        if (app.full or app.grid.dirty[y]) app.r.drawRow(&app.grid, &app.term, view, y);
    }
    if (app.full or app.bar_dirty) app.r.drawBar(&app.ui, app.l, app.pressed);
    app.full = false;
    app.bar_dirty = false;
    if (app.r.takeDirty()) |band| host.present(app.r.fb.pixels.ptr, app.r.fb.w, app.r.fb.h, band[0], band[1]);
}

export fn on_ws_open() void {
    if (!ready) return;
    perform(app.conn.onOpen());
}

export fn on_ws_close() void {
    if (!ready) return;
    perform(app.conn.onClose());
}

/// A WebSocket message of `len` bytes is in the input buffer.
export fn on_ws_message(binary: u32, len: usize) void {
    if (!ready) return;
    const data = input(len) orelse return;
    if (binary == 0) {
        switch (proto.parseControl(data)) {
            .hello => |p| {
                app.policy = p;
                setText(1, conn_mod.modeText(p), .neutral);
                relayout();
            },
            .exit => |code| perform(app.conn.onExit(code)),
            .logout => perform(app.conn.onLogout()),
            .unknown => {},
        }
        return;
    }
    const old_y = app.grid.cursor_y;
    const res = proto.applyFrame(&app.grid, gpa, data) catch |err| blk: {
        logMsg("bad grid frame: {t}", .{err});
        break :blk proto.FrameResult{};
    };
    if (res.resized) {
        relayout();
    } else if (app.grid.rows > 0) {
        // The cursor overlay is drawn with its row: redraw where it was.
        if (old_y < app.grid.rows) app.grid.dirty[old_y] = true;
        app.grid.dirty[app.grid.cursor_y] = true;
    }
    schedule();
}

export fn on_timer() void {
    if (!ready) return;
    perform(app.conn.onTimer());
}

/// Result of check_session: final HTTP status (0 = network error) and the
/// final URL's path (in the input buffer).
export fn on_check(status: u32, len: usize) void {
    if (!ready) return;
    const path = input(len) orelse "";
    perform(app.conn.onCheck(.{ .status = status, .path = path }));
}

/// keydown: `KeyboardEvent.key` in the input buffer; mods 1 shift, 2 ctrl,
/// 4 alt, 8 meta. Returns 1 when handled (the bridge then prevents the
/// browser default).
export fn on_key(len: usize, mods: u32) u32 {
    if (!ready) return 0;
    const key = input(len) orelse return 0;
    const action = keys.fromKeyboard(app.policy, key, keys.Mods.fromBits(mods));
    if (action == .none) return 0;
    send(action);
    return 1;
}

/// Pointer events on the canvas, CSS pixels. kind: 0 down, 1 move, 2 up,
/// 3 cancel.
export fn on_pointer(kind: u32, x_css: f64, y_css: f64) void {
    if (!ready or !app.sized) return;
    const x = layout.toInt(x_css * app.l.dpr);
    const y = layout.toInt(y_css * app.l.dpr);
    switch (kind) {
        0 => {
            if (app.l.hitButton(x, y)) |i| {
                app.pressed = i;
                app.bar_dirty = true;
            } else if (app.l.term.contains(x, y)) {
                app.drag = .{ .x = x, .y = y, .pan = app.pan };
            }
        },
        1 => if (app.drag) |d| {
            const p = app.l.clampPan(.{ d.pan[0] - (x - d.x), d.pan[1] - (y - d.y) });
            if (p[0] != app.pan[0] or p[1] != app.pan[1]) {
                app.pan = p;
                app.full = true;
            }
        },
        else => {
            if (app.pressed) |i| {
                // A tap counts if it ends on the button it started on.
                if (kind == 2 and app.l.hitButton(x, y) == i) send(.{ .key = keys.answer_bar[i].name });
                app.pressed = null;
                app.bar_dirty = true;
            }
            app.drag = null;
        },
    }
    schedule();
}

/// Wheel / trackpad scrolling pans a zoomed-in view. mode: 0 pixels,
/// 1 lines, 2 pages. Returns 1 when it panned (prevent default).
export fn on_wheel(dx: f64, dy: f64, mode: u32) u32 {
    if (!ready or !app.sized) return 0;
    const unit: f64 = switch (mode) {
        0 => app.l.dpr,
        1 => @floatFromInt(app.l.ch),
        else => @floatFromInt(@max(1, app.l.term.h)),
    };
    const p = app.l.clampPan(.{ app.pan[0] + layout.toInt(dx * unit), app.pan[1] + layout.toInt(dy * unit) });
    if (p[0] == app.pan[0] and p[1] == app.pan[1]) return 0;
    app.pan = p;
    app.full = true;
    schedule();
    return 1;
}

/// Header buttons: 1 Fit, 2 A−, 3 A+.
export fn on_cmd(id: u32) void {
    if (!ready) return;
    switch (id) {
        1 => app.zoom = .{},
        2 => app.zoom = layout.zoomStep(app.zoom, app.l, -1),
        3 => app.zoom = layout.zoomStep(app.zoom, app.l, 1),
        else => return,
    }
    relayout();
}
