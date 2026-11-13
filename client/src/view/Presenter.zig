//! Presenter: a native window that shows the shared UI (module
//! "portal_ui"). Owns the window (the Renderer's Window module), the
//! Instanced2D renderer, the font set, the glyph atlas and the inline-image
//! layer, plus the UI's `Frame` (layout, draw list, hit-testing). Knows
//! nothing about what the UI shows: hosts hand it a grid and a
//! `portal_ui.Overlay` (from `portal_ui.Shell.overlay`), it builds the
//! frame's draw list and turns it into GPU instances; window input goes
//! through the frame's hit-testing to an `InputSink` (the shell's).
//!
//!     var p = try Presenter.init(gpa, io, .{ .title = "Portal" });
//!     defer p.deinit();
//!     while (p.pollEvents(shell.sink())) {
//!         lock(); p.build(&grid, shell.overlay(state)); unlock();  // CPU only
//!         p.present();                                             // GPU submit
//!         p.waitEvents(Presenter.forever);
//!     }

const std = @import("std");
const builtin = @import("builtin");
const Renderer = @import("Renderer");
const Instanced2D = Renderer.Instanced2D;
const Window = @import("Window");
const Font = @import("Font");
const ui = @import("portal_ui");
const wcwidth = Font.wcwidth;
const fontset = Font.fontset;
const Atlas = Font.atlas.Atlas;
const images = @import("images.zig");
const input = ui.input;
const draw = ui.draw;

/// The texture: glyph atlas in rows 0..2047, inline images below it.
const tex_w: u32 = 2048;
const tex_h: u32 = images.region_y + images.region_h;

const Presenter = @This();

pub const Options = struct {
    title: []const u8 = "Portal",
    width: u32 = 1000,
    height: u32 = 640,
    sizing: ui.frame.Sizing = .fit_grid,
};

gpa: std.mem.Allocator,
window: *Window.Window,
/// Null after releaseGpu().
renderer: ?*Instanced2D,
fonts: fontset.FontSet,
atlas: Atlas,
/// The shared UI's frame: layout, draw list, hits, zoom, capacity.
frame: ui.Frame,
instances: std.ArrayList(Instanced2D.Instance) = .empty,
atlas_full: bool = false,
dirty: bool = true,
live_ctx: ?*anyopaque = null,
live_fn: ?Window.LiveFn = null,
/// Inline images (decode, scale, pack into the texture's image region).
img: images.Layer,
/// Host events (keys, text, mouse, close) that arrived during a modal
/// move/size loop, kept for the next pollEvents instead of being dropped.
deferred: Window.Queue = .{},
/// The app is off screen (Window `.background`, iOS): nothing is drawn
/// until `.foreground` (a GPU submit in the background gets an iOS app
/// killed).
suspended: bool = false,
/// The id of the frame's text slot the native field last showed (focus
/// moves raise the keyboard).
native_id: ?u32 = null,
/// What the native field is known to contain (the last text exchanged
/// with it), to turn its edits into key presses for the host.
native_buf: [ui.frame.TextSlot.cap]u8 = undefined,
native_len: usize = 0,
/// False once the window said it has no native text field (desktops).
native_supported: bool = true,
/// Scroll notches not yet turned into whole grid rows.
scroll_acc: f32 = 0,

/// Grid rows per scroll notch: a notch is 16 pt of finger travel on a
/// touch screen, a wheel detent elsewhere.
const rows_per_notch: f32 = if (builtin.os.tag == .ios) 1 else 3;

pub fn init(gpa: std.mem.Allocator, io: std.Io, options: Options) !*Presenter {
    const self = try gpa.create(Presenter);
    errdefer gpa.destroy(self);
    var fonts = try fontset.FontSet.load(gpa, io);
    errdefer fonts.deinit();
    const window = try Window.Window.init(gpa, options.title, options.width, options.height);
    errdefer window.deinit();
    const fb = window.framebufferSize();
    const renderer = try Instanced2D.init(gpa, window.surfaceSource(), fb[0], fb[1], .{
        .app_name = "Portal",
        .texture_width = tex_w,
        .texture_height = tex_h,
    });
    errdefer renderer.deinit();
    var atlas = try Atlas.init(gpa, tex_w, 2048);
    atlas.tex_h = tex_h;
    self.* = .{
        .gpa = gpa,
        .window = window,
        .renderer = renderer,
        .fonts = fonts,
        .atlas = atlas,
        .frame = .init(gpa, options.sizing),
        .img = .init(gpa),
    };
    window.setLiveCallback(self, liveThunk);
    return self;
}

pub fn deinit(p: *Presenter) void {
    p.releaseGpu();
    p.window.deinit();
    p.atlas.deinit();
    p.img.deinit();
    p.fonts.deinit();
    p.frame.deinit();
    p.instances.deinit(p.gpa);
    p.gpa.destroy(p);
}

/// Called while the OS runs a modal resize loop (Win32); the host should
/// build + present from its current state.
pub fn setLiveRedraw(p: *Presenter, ctx: *anyopaque, f: Window.LiveFn) void {
    p.live_ctx = ctx;
    p.live_fn = f;
}

fn liveThunk(ctx: *anyopaque) void {
    const p: *Presenter = @ptrCast(@alignCast(ctx));
    while (p.window.pollQueued()) |e| p.liveEvent(e);
    if (p.live_fn) |f| f(p.live_ctx.?);
}

/// Inside a modal loop: apply view events now, keep host events for later.
fn liveEvent(p: *Presenter, e: Window.Event) void {
    switch (e) {
        .resize, .scale, .expose, .zoom, .scroll, .insets, .background, .foreground => p.handleViewEvent(e),
        .close, .key, .char, .mouse_down, .mouse_move, .mouse_up, .text_input => p.deferred.push(e),
    }
}

/// Next event: those deferred from a modal loop first, then the window's.
fn nextEvent(p: *Presenter) ?Window.Event {
    return p.deferred.pop() orelse p.window.pollEvent();
}

/// Thread-safe: wakes a waitEvents (e.g. after new data arrived).
pub fn wake(p: *Presenter) void {
    p.window.wake();
}

/// waitEvents timeout meaning "until an event or wake()" (no idle polling).
pub const forever = Window.forever;

/// Sleeps until window input, a wake() from any thread, or the timeout
/// (`forever`: no timeout). Returns at once if a redraw is pending.
pub fn waitEvents(p: *Presenter, timeout_ms: u32) void {
    p.window.waitEvents(if (p.dirty and !p.suspended) 0 else timeout_ms);
}

/// Tears down the swapchain and GPU device cleanly (waits for the GPU to go
/// idle) while the window stays valid; present() is a no-op afterwards.
/// For hosts about to exit the process. Main thread only.
pub fn releaseGpu(p: *Presenter) void {
    if (p.renderer) |r| r.deinit();
    p.renderer = null;
}

/// The native window handle (Win32 HWND), null elsewhere: for OS services
/// tied to the window (the touch keyboard).
pub fn nativeHandle(p: *const Presenter) ?*anyopaque {
    return switch (p.window.surfaceSource()) {
        .win32 => |w| w.hwnd,
        else => null,
    };
}

pub fn setTitle(p: *Presenter, title: []const u8) void {
    p.window.setTitle(title);
}

/// True if the view itself needs a redraw (input, resize, zoom). Never
/// while suspended.
pub fn needsRedraw(p: *const Presenter) bool {
    return p.dirty and !p.suspended;
}

/// True while the app is off screen (iOS background): hosts drop their
/// connection meanwhile (Client.setPaused); present() draws nothing.
pub fn isSuspended(p: *const Presenter) bool {
    return p.suspended;
}

/// The UI's key for a window key (same names).
pub fn key(k: Window.Key) input.Key {
    return switch (k) {
        inline else => |t| @field(input.Key, @tagName(t)),
    };
}

pub fn mods(m: Window.Mods) input.Mods {
    return .{ .ctrl = m.ctrl, .shift = m.shift, .alt = m.alt, .super = m.super };
}

fn button(b: Window.MouseButton) input.MouseButton {
    return switch (b) {
        inline else => |t| @field(input.MouseButton, @tagName(t)),
    };
}

/// Pumps window events into `sink` (through the last frame's hits).
/// Returns false once the user closed the window.
pub fn pollEvents(p: *Presenter, sink: input.InputSink) bool {
    var open = true;
    while (p.nextEvent()) |e| {
        switch (e) {
            .close => open = false,
            .key => |k| {
                p.frame.scroll_back = 0; // typing follows the cursor again
                sink.key(key(k.key), mods(k.mods));
            },
            .char => |c| {
                p.frame.scroll_back = 0;
                sink.char(c.cp, mods(c.mods));
            },
            .mouse_down => |m| p.frame.pointerDown(m.x, m.y, button(m.button), mods(m.mods), sink),
            .mouse_move => |m| p.frame.pointerMove(m.x, m.y, sink),
            .mouse_up => |m| p.frame.pointerUp(m.x, m.y, button(m.button), sink),
            // The native text field (iOS): its edits become the same key
            // presses a keyboard would make, so hosts need nothing new.
            .text_input => |t| {
                p.frame.scroll_back = 0;
                p.nativeTextChanged(sink);
                if (t == .submit) sink.key(.enter, .{});
            },
            else => p.handleViewEvent(e),
        }
        p.dirty = true;
    }
    p.reportCapacity(sink);
    return open;
}

/// Tells the sink if the cells that fit the window changed since the last
/// report. pollEvents calls it; hosts may also call it from a live redraw
/// (during a modal resize) so the PTY follows the drag.
pub fn reportCapacity(p: *Presenter, sink: input.InputSink) void {
    p.frame.reportCapacity(sink, p.window.framebufferSize());
}

fn handleViewEvent(p: *Presenter, e: Window.Event) void {
    p.dirty = true;
    switch (e) {
        .background => p.suspended = true,
        .foreground => p.suspended = false,
        // A drag on a touch screen (the iOS window turns it into scroll
        // notches) or the wheel: grid rows that do not fit.
        .scroll => |sc| {
            p.scroll_acc += sc.dy * rows_per_notch;
            const rows = @trunc(p.scroll_acc);
            if (rows == 0) return;
            p.scroll_acc -= rows;
            p.frame.scrollRows(@intFromFloat(rows));
        },
        .resize => |r| if (p.renderer) |ren| ren.resize(r.width, r.height),
        .zoom => |z| p.frame.zoom(switch (z) {
            .in => .in,
            .out => .out,
            .reset => .reset,
        }),
        else => {},
    }
}

// ------------------------------------------------------------ build

/// Builds the frame from `grid` and `overlay` (CPU only: hold the host's
/// lock around this, not around present()).
pub fn build(p: *Presenter, grid: *const ui.grid.Grid, overlay: ui.Overlay) void {
    // Lay out inside the window's insets (iOS safe area and keyboard; zero
    // on desktops).
    const ins = p.window.insets();
    p.frame.insets = .{ .left = ins.left, .top = ins.top, .right = ins.right, .bottom = ins.bottomClear() };
    p.frame.build(&p.fonts, p.window.framebufferSize(), p.window.scale(), grid, overlay);
    p.resolve();
    if (p.atlas_full or p.img.full) {
        // Out of atlas / image space: start over with only what is on
        // screen now.
        if (p.atlas_full) p.atlas.wipe();
        if (p.img.full) p.img.wipe();
        p.resolve();
    }
    // Images still waiting to be decoded: come back next frame.
    if (p.img.needs_more) p.dirty = true;
}

/// Uploads new glyphs and presents the last built frame.
pub fn present(p: *Presenter) void {
    if (p.suspended) return;
    const renderer = p.renderer orelse return;
    if (p.atlas.takeDirty()) |d| {
        renderer.updateTexture(d.x, d.y, d.w, d.h, d.bytes) catch |err| std.log.warn("atlas upload failed: {t}", .{err});
    }
    for (p.img.uploads.items) |u| {
        renderer.updateTexture(u.x, images.region_y + u.y, u.w, u.h, u.px) catch |err| std.log.warn("image upload failed: {t}", .{err});
    }
    p.img.clearUploads();
    const bg = p.frame.list.clear;
    renderer.drawFrame(.{
        @as(f32, @floatFromInt(bg[0])) / 255,
        @as(f32, @floatFromInt(bg[1])) / 255,
        @as(f32, @floatFromInt(bg[2])) / 255,
        1,
    }, p.instances.items) catch |err| std.log.warn("draw failed: {t}", .{err});
    p.dirty = false;
    p.syncNativeField();
}

// ------------------------------------------------------ native text field

/// Places (or hides) the platform's native text field over the focused
/// field of the frame just presented (Frame.text_slot), and pushes the
/// host's text into it when the host changed it (cleared after a send, a
/// refused line put back). Desktops have none: the first refusal turns
/// this off.
fn syncNativeField(p: *Presenter) void {
    if (!p.native_supported) return;
    const slot = if (p.frame.text_slot) |*t| t else {
        if (p.native_id != null) p.window.hideTextInput();
        p.native_id = null;
        return;
    };
    const moved = p.native_id != null and p.native_id.? != slot.id;
    if (!p.window.showTextInput(.{
        .x = slot.rect.x,
        .y = slot.rect.y,
        .w = slot.rect.w,
        .h = slot.rect.h,
        .font_px = slot.font_px,
        .fg = ui.theme.ui.text,
        .bg = ui.theme.ui.field,
        .focus = moved,
    })) {
        p.native_supported = false;
        return;
    }
    if (moved or p.native_id == null or !std.mem.eql(u8, slot.value(), p.native_buf[0..p.native_len])) {
        p.window.setTextInputText(slot.value());
        @memcpy(p.native_buf[0..slot.value_len], slot.value());
        p.native_len = slot.value_len;
    }
    p.native_id = slot.id;
}

/// The native field's text changed: hand the difference to the host as
/// Backspaces and characters (the input lines only edit at the end).
fn nativeTextChanged(p: *Presenter, sink: input.InputSink) void {
    var buf: [ui.frame.TextSlot.cap]u8 = undefined;
    const now = p.window.textInputText(&buf);
    const edit = ui.frame.textEdit(p.native_buf[0..p.native_len], now);
    for (0..edit.deletes) |_| sink.key(.backspace, .{});
    var it = (std.unicode.Utf8View.init(edit.insert) catch return).iterator();
    while (it.nextCodepoint()) |cp| {
        if (cp < 0x20 or cp == 0x7f) continue;
        sink.char(cp, .{});
    }
    @memcpy(p.native_buf[0..now.len], now);
    p.native_len = now.len;
}

// ------------------------------------------------------------ draw list

fn push(p: *Presenter, x: f32, y: f32, w: f32, h: f32, uv: [4]f32, c: draw.Rgba) void {
    p.instances.append(p.gpa, .{ .rect = .{ x, y, w, h }, .uv = uv, .color = c }) catch {};
}

fn glyph(p: *Presenter, cp: u21, style: fontset.Style, m: fontset.Metrics, cells: u32, x: f32, y: f32, c: draw.Rgba) void {
    const slot = p.atlas.get(&p.fonts, cp, style, m, cells) orelse {
        p.atlas_full = true;
        return;
    };
    p.push(x, y, @floatFromInt(slot.w), @floatFromInt(slot.h), p.atlas.uv(slot), c);
}

fn text(p: *Presenter, m: fontset.Metrics, x0: f32, y: f32, s: []const u8, c: draw.Rgba, bold: bool) void {
    var x = x0;
    var it = (std.unicode.Utf8View.init(s) catch return).iterator();
    while (it.nextCodepoint()) |cp| {
        const w = wcwidth.of(cp);
        if (w == 0) continue;
        if (cp != ' ' and cp >= 0x20) p.glyph(cp, .{ .bold = bold }, m, w, x, y, c);
        x += @floatFromInt(w * m.cell_w);
    }
}

/// Turns the frame's draw list into instances (atlas lookups, image
/// decodes and uploads).
fn resolve(p: *Presenter) void {
    p.atlas_full = false;
    p.instances.clearRetainingCapacity();
    // Image entries live while the draw list uses them.
    p.img.begin();
    defer p.img.end();
    const dl = &p.frame.list;
    const white = p.atlas.whiteUv();
    for (dl.cmds.items) |c| switch (c) {
        .rect => |r| p.push(r.x, r.y, r.w, r.h, white, r.color),
        .glyph => |g| p.glyph(g.cp, g.style, dl.fonts[g.font], g.cells, g.x, g.y, g.color),
        .text => |t| p.text(dl.fonts[t.font], t.x, t.y, dl.textOf(t), t.color, t.bold),
        .image => |im| switch (p.img.prepare(im.store, im.id, im.disp_w, im.disp_h, tex_w, tex_h)) {
            .image => |uv| if (images.clip(im.x, im.y, im.w, im.h, uv, im.clip[0], im.clip[1], im.clip[2], im.clip[3])) |cl| {
                p.push(cl.rect[0], cl.rect[1], cl.rect[2], cl.rect[3], cl.uv, .{ 255, 255, 255, 255 });
            },
            .placeholder => |dims| p.placeholder(dl.fonts[im.font], im, dims),
            .none => {},
        },
    };
}

/// A box with the image's pixel size, for images that can't be decoded.
fn placeholder(p: *Presenter, m: fontset.Metrics, im: draw.Image, dims: [2]u32) void {
    const x = im.x;
    const y = im.y;
    const w = im.w;
    const h = im.h;
    const cx0 = im.clip[0];
    const cy0 = im.clip[1];
    const cx1 = im.clip[2];
    const cy1 = im.clip[3];
    const c = im.placeholder;
    const s: f32 = @floatFromInt(@max(m.stroke, 1));
    const white = p.atlas.whiteUv();
    const edges = [_][4]f32{ .{ x, y, w, s }, .{ x, y + h - s, w, s }, .{ x, y, s, h }, .{ x + w - s, y, s, h } };
    for (edges) |e| if (images.clip(e[0], e[1], e[2], e[3], white, cx0, cy0, cx1, cy1)) |r| {
        p.push(r.rect[0], r.rect[1], r.rect[2], r.rect[3], r.uv, c);
    };
    var buf: [48]u8 = undefined;
    const label = if (dims[0] > 0)
        std.fmt.bufPrint(&buf, "image {d}\u{00D7}{d}", .{ dims[0], dims[1] }) catch "image"
    else
        "image";
    const lw = ui.frame.textWidth(m, label);
    const ch: f32 = @floatFromInt(m.cell_h);
    if (lw + 2 * s <= w and h >= ch and y >= cy0 and y + ch <= cy1 and x + lw < cx1) {
        p.text(m, x + @round((w - lw) / 2), y + @round((h - ch) / 2), label, c, false);
    }
}

test "window keys map to the UI's by name" {
    try std.testing.expectEqual(input.Key.page_down, key(.page_down));
    try std.testing.expectEqual(input.Key.f12, key(.f12));
    const m = mods(.{ .ctrl = true, .super = true });
    try std.testing.expect(m.ctrl and m.super and !m.shift and !m.alt);
}
