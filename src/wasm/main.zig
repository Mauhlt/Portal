//! Portal's browser client, compiled to wasm32-freestanding.
//!
//! The whole viewer lives here: protocol decoding (proto.zig), connection
//! and reconnect policy (conn.zig), the page's panes (panes.zig: terminal,
//! input box, button row, following the on-screen keyboard), the canvas
//! layout (layout.zig), key mapping (keys.zig), what Send does with the
//! input box's text (inputbox.zig), glyph rasterisation (glyphs.zig +
//! font/) and drawing (render.zig). src/web/app.js is only the unavoidable
//! browser glue: it instantiates this module, forwards DOM events and
//! values to the exports below and implements the `host` imports as
//! one-line browser API calls.
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
const panes = @import("panes.zig");
const inputbox = @import("inputbox.zig");

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
    /// slot 0 = status, 1 = mode, 2 = the note under the input box;
    /// cls 0 neutral, 1 ok, 2 bad.
    extern "env" fn set_text(slot: u32, p: [*]const u8, n: usize, cls: u32) void;
    /// The page's CSS variables (body style) and classes (body className).
    extern "env" fn set_layout(p: [*]const u8, n: usize) void;
    extern "env" fn set_class(p: [*]const u8, n: usize) void;
    /// Writes the input box's text (UTF-8) into p[0..cap]; returns the length.
    extern "env" fn box_read(p: [*]u8, cap: usize) usize;
    /// Replaces the input box's text; sets its placeholder.
    extern "env" fn box_write(p: [*]const u8, n: usize) void;
    extern "env" fn box_hint(p: [*]const u8, n: usize) void;
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

/// Most of the input box read per Send. Instruction lines are at most
/// 2000 bytes and text-mode frames 4096, so anything this long is refused
/// as too long whether or not it was cut off.
const box_cap = inputbox.max_frame + 4;

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
    r: render.Renderer = .{},
    /// Everything must be redrawn (layout, pan or mode changed).
    full: bool = true,
    frame_pending: bool = false,
    drag: ?Drag = null,
    in_buf: []u8 = &.{},
    canvas_w: u32 = 0,
    canvas_h: u32 = 0,
    /// Last viewport report (on_viewport) and what was sent to the page.
    vp: ?panes.Input = null,
    panes: ?panes.Panes = null,
    class_buf: [128]u8 = undefined,
    class_len: usize = 0,
    /// The last instruction line sent: put back if the server rejects it
    /// while the box is still empty.
    last_line: [inputbox.max_frame]u8 = undefined,
    last_line_len: usize = 0,
};

var app: App = undefined;
var ready = false;
var box_buf: [box_cap]u8 = undefined;

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
    app.pan = app.l.clampPan(app.pan);
    app.full = true;
    schedule();
}

/// Re-derives the panes from the last viewport report and the input mode,
/// and tells the page only what changed. The canvas's ResizeObserver then
/// reports the terminal pane's new size through `resize`.
fn relayoutPanes() void {
    var in = app.vp orelse return;
    in.touch = app.touch;
    in.input = app.policy != .none;
    const p = panes.compute(in);
    if (app.panes == null or !app.panes.?.eql(p)) {
        app.panes = p;
        var buf: [512]u8 = undefined;
        const s = panes.css(p, &buf);
        host.set_layout(s.ptr, s.len);
    }
    var buf: [128]u8 = undefined;
    const cls = std.fmt.bufPrint(&buf, "viewer mode-{t}{s}{s}{s}", .{
        app.policy,
        if (app.touch) " touch" else "",
        if (p.keyboard) " kb" else "",
        if (p.no_head) " nohead" else "",
    }) catch return;
    if (!std.mem.eql(u8, cls, app.class_buf[0..app.class_len])) {
        @memcpy(app.class_buf[0..cls.len], cls);
        app.class_len = cls.len;
        host.set_class(cls.ptr, cls.len);
    }
}

fn note(text: []const u8, tone: inputbox.Tone) void {
    host.set_text(2, text.ptr, text.len, @intFromEnum(tone));
}

fn readBox() []const u8 {
    const n = host.box_read(&box_buf, box_buf.len);
    return box_buf[0..@min(n, box_buf.len)];
}

fn writeBox(text: []const u8) void {
    host.box_write(text.ptr, text.len);
}

/// Shows what Send would do with the box's current text.
fn showPreview() void {
    var buf: [128]u8 = undefined;
    const n = inputbox.preview(app.policy, readBox(), app.touch, &buf);
    note(n.text, n.tone);
}

fn sendFrame(prefix: []const u8, body: []const u8) void {
    var buf: [inputbox.max_frame]u8 = undefined;
    if (prefix.len + body.len > buf.len) return;
    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..][0..body.len], body);
    host.ws_send(&buf, prefix.len + body.len);
}

fn pressed(k: []const u8) void {
    var buf: [32]u8 = undefined;
    note(std.fmt.bufPrint(&buf, "Pressed {s}.", .{inputbox.keyLabel(k)}) catch "", .ok);
}

/// Send (the button, or Enter in the box): an answer word presses its key,
/// anything else becomes an instruction line (inputbox.decide). The box is
/// cleared only once something was sent.
fn sendBox() void {
    if (app.policy == .none) return;
    var scratch: [box_cap]u8 = undefined;
    const d = inputbox.decide(app.policy, readBox(), &scratch);
    switch (d) {
        .nothing => return,
        .refuse => |r| return note(inputbox.refusalText(r), .bad),
        else => if (app.conn.state != .live) return note(inputbox.refusalText(.offline), .bad),
    }
    switch (d) {
        .nothing, .refuse => unreachable,
        .key => |k| {
            sendFrame("k:", k);
            pressed(k);
        },
        .line => |l| {
            @memcpy(app.last_line[0..l.len], l);
            app.last_line_len = l.len;
            sendFrame("l:", l);
            note("Sent.", .ok);
        },
        .typed => |t| {
            sendFrame("t:", t);
            sendFrame("k:", "enter");
            note("Sent.", .ok);
        },
    }
    writeBox("");
}

/// The server refused the last instruction line: say why, and put the
/// line back unless something new was typed meanwhile.
fn onRejected(reason: []const u8) void {
    if (std.mem.trim(u8, readBox(), " \t\r\n").len == 0 and app.last_line_len > 0)
        writeBox(app.last_line[0..app.last_line_len]);
    if (inputbox.serverRefusal(reason)) |r| {
        note(inputbox.refusalText(r), .bad);
    } else {
        note("The desktop refused that line.", .bad);
    }
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
    app = .{ .term = term, .touch = touch != 0 };
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

/// The visible viewport changed (load, resize, rotation, the on-screen
/// keyboard opening or closing, Safari scrolling to the caret). CSS
/// pixels: window.innerWidth/innerHeight, visualViewport width, height and
/// offsetTop, and the safe-area insets env(safe-area-inset-top/bottom).
export fn on_viewport(inner_w: f64, inner_h: f64, vv_w: f64, vv_h: f64, vv_top: f64, safe_top: f64, safe_bottom: f64) void {
    if (!ready) return;
    app.vp = .{
        .inner_w = inner_w,
        .inner_h = inner_h,
        .vv_w = vv_w,
        .vv_h = vv_h,
        .vv_top = vv_top,
        .safe_top = safe_top,
        .safe_bottom = safe_bottom,
        .touch = app.touch,
    };
    relayoutPanes();
}

/// requestAnimationFrame callback: draw what changed and present it.
export fn frame() void {
    if (!ready) return;
    app.frame_pending = false;
    if (!app.sized) return;
    // Inline images decode lazily, one per frame so a big one can't stall
    // several; the rows it covers redraw once it is ready.
    if (app.grid.images.decodeOne(gpa)) |id| {
        app.grid.markImage(id);
        if (app.grid.images.nextToDecode() != null) schedule();
    }
    const view: render.Renderer.View = .{ .l = app.l, .pan = app.pan, .show_cursor = app.policy != .none };
    if (app.full) app.r.clearTerm(app.l);
    var y: u16 = 0;
    while (y < app.grid.rows) : (y += 1) {
        if (app.full or app.grid.dirty[y]) app.r.drawRow(&app.grid, &app.term, view, y);
    }
    app.full = false;
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
            .hello => |h| {
                app.policy = h.policy;
                setText(1, conn_mod.modeText(h.policy), .neutral);
                const ph = inputbox.placeholder(h.policy);
                host.box_hint(ph.ptr, ph.len);
                relayoutPanes();
                showPreview();
                relayout();
            },
            .rejected => |reason| onRejected(reason),
            .exit => |code| perform(app.conn.onExit(code)),
            .logout => perform(app.conn.onLogout()),
            .unknown => {},
        }
        return;
    }
    const old_y = app.grid.cursor_y;
    // 'G' grid, 'I' image, 'P' placements; unknown types are ignored.
    const res = proto.applyBinary(&app.grid, gpa, data) catch |err| blk: {
        logMsg("bad {c} frame: {t}", .{ if (data.len > 0 and data[0] >= 0x20 and data[0] < 0x7f) data[0] else '?', err });
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

/// keydown outside the input box: `KeyboardEvent.key` in the input
/// buffer; mods 1 shift, 2 ctrl, 4 alt, 8 meta. Returns 1 when handled
/// (the bridge then prevents the browser default).
export fn on_key(len: usize, mods: u32) u32 {
    if (!ready) return 0;
    const key = input(len) orelse return 0;
    const action = keys.fromKeyboard(app.policy, key, keys.Mods.fromBits(mods));
    if (action == .none) return 0;
    send(action);
    return 1;
}

/// The input box's text changed (typing, dictation, paste).
export fn on_box_input() void {
    if (!ready) return;
    showPreview();
}

/// keydown in the input box: `KeyboardEvent.key` in the input buffer,
/// mods as on_key plus 16 = IME composing. Returns 1 when handled (the
/// bridge prevents the default: the newline of a sending Enter).
export fn on_box_key(len: usize, mods: u32) u32 {
    if (!ready) return 0;
    const key = input(len) orelse return 0;
    if (!inputbox.boxKeySends(key, mods)) return 0;
    sendBox();
    return 1;
}

/// The button row, by inputbox.Button: Yes No 1 2 3 Esc Enter Send.
export fn on_button(id: u32) void {
    if (!ready) return;
    const b = std.enums.fromInt(inputbox.Button, id) orelse return;
    switch (b) {
        .send => sendBox(),
        else => {
            if (app.policy == .none) return;
            if (app.conn.state != .live) return note(inputbox.refusalText(.offline), .bad);
            const k = inputbox.buttonKey(b).?;
            sendFrame("k:", k);
            pressed(k);
        },
    }
}

/// Pointer events on the canvas, CSS pixels: dragging pans a zoomed view.
/// kind: 0 down, 1 move, 2 up, 3 cancel.
export fn on_pointer(kind: u32, x_css: f64, y_css: f64) void {
    if (!ready or !app.sized) return;
    const x = layout.toInt(x_css * app.l.dpr);
    const y = layout.toInt(y_css * app.l.dpr);
    switch (kind) {
        0 => if (app.l.term.contains(x, y)) {
            app.drag = .{ .x = x, .y = y, .pan = app.pan };
        },
        1 => if (app.drag) |d| {
            const p = app.l.clampPan(.{ d.pan[0] - (x - d.x), d.pan[1] - (y - d.y) });
            if (p[0] != app.pan[0] or p[1] != app.pan[1]) {
                app.pan = p;
                app.full = true;
            }
        },
        else => app.drag = null,
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
