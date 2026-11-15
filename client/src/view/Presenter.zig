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
/// Instanced2D's shaders (shaders/quad_*.zig, compiled by the build).
const quad_vert align(4) = @embedFile("quad_vert.spv").*;
const quad_frag align(4) = @embedFile("quad_frag.spv").*;
const Window = @import("Window");
const Font = @import("Font");
const ui = @import("portal_ui");
const wcwidth = Font.wcwidth;
const fontset = Font.fontset;
const Atlas = Font.atlas.Atlas;
const images = @import("images.zig");
const imgdec = @import("imgdec");
const input = ui.input;
const theme = ui.theme;
const draw = ui.draw;

/// The texture: glyph atlas in rows 0..2047, inline images below it, the
/// background art below them.
const tex_w: u32 = 2048;
const art_y: u32 = images.region_y + images.region_h;
pub const art_side: u32 = 1024;
const tex_h: u32 = art_y + art_side;

/// The background art's strength: the hero mixed into the theme's
/// background at this share (a watermark; docs/brand/README.md has the
/// contrast numbers against its brightest pixels).
pub const art_alpha: f32 = 0.10;

const Presenter = @This();

pub const Options = struct {
    title: []const u8 = "Portal",
    width: u32 = 1000,
    height: u32 = 640,
    sizing: ui.frame.Sizing = .fit_grid,
};

gpa: std.mem.Allocator,
io: std.Io,
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
/// The start-up splash (beginSplash) while it shows.
splash: ?*Splash = null,
/// The background art (the hero, faint, behind the main content): shown
/// when on; its pixels (premixed into the background) wait in `art_px`
/// until present() uploads them once into the texture's art region.
art_on: bool = true,
art_px: ?[]u8 = null,
art_uploaded: bool = false,

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
        .vertex_spirv = &quad_vert,
        .fragment_spirv = &quad_frag,
        .texture_width = tex_w,
        .texture_height = tex_h,
    });
    errdefer renderer.deinit();
    var atlas = try Atlas.init(gpa, tex_w, 2048);
    atlas.tex_h = tex_h;
    self.* = .{
        .gpa = gpa,
        .io = io,
        .window = window,
        .renderer = renderer,
        .fonts = fonts,
        .atlas = atlas,
        .frame = touch_frame: {
            var f: ui.frame.Frame = .init(gpa, options.sizing);
            // iOS: one finger is the pointer; presses act on release and
            // drags scroll (Frame.touch).
            f.touch = builtin.os.tag == .ios;
            break :touch_frame f;
        },
        .img = .init(gpa),
    };
    window.setLiveCallback(self, liveThunk);
    // The window icon comes from the Renderer's window class (the exe's
    // icon resource 1, docs/brand/portal.ico linked by build.zig).
    return self;
}

pub fn deinit(p: *Presenter) void {
    p.endSplash();
    if (p.art_px) |px| p.gpa.free(px);
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
        .close, .key, .char, .mouse_down, .mouse_move, .mouse_up, .text_input, .media => p.deferred.push(e),
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
    var t = timeout_ms;
    if (p.splash) |sp| if (sp.deadline(p.nowMs())) |left| {
        t = @min(t, left);
    };
    p.window.waitEvents(if (p.dirty and !p.suspended) 0 else t);
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
    p.splashTick();
    while (p.nextEvent()) |e| {
        // Input during the splash ends it (and is not passed on: nothing
        // the user could aim at is on screen yet).
        if (p.splash != null) switch (e) {
            .key, .char, .mouse_down, .mouse_move, .mouse_up, .text_input => {
                if (e != .mouse_move) p.endSplash();
                p.dirty = true;
                continue;
            },
            else => {},
        };
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
            .mouse_down => |m| {
                // Long presses are measured between press and release.
                p.frame.now_ms = p.nowMs();
                p.frame.pointerDown(m.x, m.y, button(m.button), mods(m.mods), sink);
            },
            .mouse_move => |m| p.frame.pointerMove(m.x, m.y, sink),
            // Cancelled (iOS: the system took the touch): no tap, no swipe.
            .mouse_up => |m| {
                p.frame.now_ms = p.nowMs();
                if (m.cancelled) p.frame.pointerCancel(sink) else p.frame.pointerUp(m.x, m.y, button(m.button), sink);
            },
            // A headset's play / pause button (Win32 WM_APPCOMMAND): the
            // shell decides (dictation, only with a headset microphone).
            // Play, pause and stop alone are not toggles: ignored.
            .media => |m| if (m == .play_pause) sink.action(.media_play_pause),
            // The native text field (iOS): its edits become the same key
            // presses a keyboard would make, so hosts need nothing new.
            .text_input => |t| {
                p.frame.scroll_back = 0;
                p.nativeTextChanged(sink);
                if (t == .submit) sink.key(.enter, .{});
            },
            // The wheel scrolls a content view (the conversation) under the
            // pointer; elsewhere grid rows that do not fit (handleViewEvent).
            // (iOS drags arrive as the pointer: Frame.touch.)
            .scroll => |w| if (!p.frame.wheel(w.x, w.y, w.dy, sink)) p.handleViewEvent(e),
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
        // The wheel: grid rows that do not fit.
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
    // The splash replaces the frame's picture (its layout still counts:
    // capacity reports, the PTY size).
    if (p.splash) |sp| {
        p.buildSplash(sp);
        return;
    }
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
    if (p.art_px) |px| {
        // Once: the region is the art's alone.
        renderer.updateTexture(0, art_y, art_side, art_side, px) catch |err| std.log.warn("art upload failed: {t}", .{err});
        p.gpa.free(px);
        p.art_px = null;
        p.art_uploaded = true;
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

// ------------------------------------------------------------ splash

/// The start-up splash: the hero art (a PNG), centred and scaled to fit on
/// the theme's background, shown instead of the UI while the app starts.
///
/// Never blocks start-up: the PNG is decoded on its own thread (which
/// wakes the window when done); until then the frame is the bare
/// background. Event-driven: it is drawn when something asks for a frame
/// and has at most two real deadlines (below), no animation. It ends when
///   - the host calls `splashDone` (the app is ready) and the art has shown
///     for at least `splash_min_ms` (so it never just flickers),
///   - `splash_max_ms` after it began, whatever the host is doing,
///   - the user presses a key, clicks or touches,
///   - the PNG can't be decoded (it is skipped).
pub const Splash = struct {
    png: []const u8,
    thread: ?std.Thread = null,
    /// Written by the decode thread before `done` is set.
    decoded: ?imgdec.Rgba = null,
    done: std.atomic.Value(bool) = .init(false),
    window: *Window.Window,
    gpa: std.mem.Allocator,
    begun_ms: i64,
    /// When the art was first drawn (null: not yet).
    shown_ms: ?i64 = null,
    ready: bool = false,
    /// The side the art is uploaded at (0: not uploaded).
    side: u32 = 0,

    fn decode(sp: *Splash) void {
        sp.decoded = imgdec.decode(sp.gpa, sp.png, .{ .budget = 64 << 20, .max_side = 2048 }) catch null;
        sp.done.store(true, .release);
        sp.window.wake();
    }

    /// Milliseconds until the splash must be looked at again.
    fn deadline(sp: *const Splash, now: i64) ?u32 {
        var at = sp.begun_ms + splash_max_ms;
        if (sp.ready) if (sp.shown_ms) |t| {
            at = @min(at, t + splash_min_ms);
        };
        return @intCast(std.math.clamp(at - now, 0, splash_max_ms));
    }
};

pub const splash_min_ms: i64 = 900;
pub const splash_max_ms: i64 = 4000;

fn nowMs(p: *const Presenter) i64 {
    return std.Io.Clock.awake.now(p.io).toMilliseconds();
}

/// Starts the splash with `png` (which must outlive it: an embedded
/// file). Call right after init; the next frames show it.
pub fn beginSplash(p: *Presenter, png: []const u8) void {
    if (p.splash != null) return;
    const sp = p.gpa.create(Splash) catch return;
    sp.* = .{ .png = png, .window = p.window, .gpa = p.gpa, .begun_ms = p.nowMs() };
    sp.thread = std.Thread.spawn(.{}, Splash.decode, .{sp}) catch {
        p.gpa.destroy(sp);
        return;
    };
    p.splash = sp;
    p.dirty = true;
}

/// The host is ready (connected, the session started): the splash ends
/// once the art has shown for a moment.
pub fn splashDone(p: *Presenter) void {
    const sp = p.splash orelse return;
    if (sp.ready) return;
    sp.ready = true;
    p.splashTick();
}

/// Ends the splash now (e.g. before a screen the user must answer).
pub fn endSplash(p: *Presenter) void {
    const sp = p.splash orelse return;
    if (sp.thread) |t| t.join(); // a bounded decode
    if (sp.decoded) |*d| {
        // The same picture, faint, becomes the background art.
        if (!p.art_uploaded and p.art_px == null) p.art_px = premixArt(p.gpa, d.*);
        d.deinit(p.gpa);
    }
    p.gpa.destroy(sp);
    p.splash = null;
    // The image region's pixels at (0, 0) were the splash's.
    p.img.wipe();
    p.dirty = true;
}

/// Applies the splash's deadlines and the decode result.
fn splashTick(p: *Presenter) void {
    const sp = p.splash orelse return;
    const now = p.nowMs();
    const done = sp.done.load(.acquire);
    if (done and sp.decoded == null) return p.endSplash(); // undecodable: skip it
    if (now - sp.begun_ms >= splash_max_ms) return p.endSplash();
    if (sp.ready) {
        // Ready before the art showed: it still shows once decoded (the
        // decode thread wakes the window), bounded by splash_max_ms.
        const t = sp.shown_ms orelse return;
        if (now - t >= splash_min_ms) return p.endSplash();
    }
    if (done and sp.shown_ms == null) p.dirty = true;
}

/// The splash frame: the background, and the art once decoded.
fn buildSplash(p: *Presenter, sp: *Splash) void {
    p.instances.clearRetainingCapacity();
    p.frame.list.clear = theme.palette.bg;
    p.frame.text_slot = null;
    if (!sp.done.load(.acquire)) return;
    const src = sp.decoded orelse return;
    const fb = p.window.framebufferSize();
    const room = @min(fb[0], fb[1]);
    if (room < 16) return;
    const side: u32 = @min(@as(u32, @intFromFloat(@as(f32, @floatFromInt(room)) * 0.92)), images.region_w, images.region_h);
    if (side != sp.side) {
        const px = scaleArt(p.gpa, src, side) orelse return;
        p.img.clearUploads();
        p.img.uploads.append(p.gpa, .{ .x = 0, .y = 0, .w = side, .h = side, .px = px }) catch {
            p.gpa.free(px);
            return;
        };
        sp.side = side;
    }
    const fw: f32 = @floatFromInt(tex_w);
    const fh: f32 = @floatFromInt(tex_h);
    const sf: f32 = @floatFromInt(side);
    const x = @round((@as(f32, @floatFromInt(fb[0])) - sf) / 2);
    const y = @round((@as(f32, @floatFromInt(fb[1])) - sf) / 2);
    const ry: f32 = @floatFromInt(images.region_y);
    p.push(x, y, sf, sf, .{ 0, ry / fh, sf / fw, (ry + sf) / fh }, .{ 255, 255, 255, 255 });
    if (sp.shown_ms == null) sp.shown_ms = p.nowMs();
}

/// `src` scaled to `side x side` RGBA8: box-filtered down (imgdec.scale),
/// bilinear up (the texture sampler is nearest-neighbour). Null without
/// memory.
fn scaleArt(gpa: std.mem.Allocator, src: imgdec.Rgba, side: u32) ?[]u8 {
    if (side <= src.w and side <= src.h) {
        const r = imgdec.scale(gpa, src, side, side) catch return null;
        return r.px;
    }
    const out = gpa.alloc(u8, @as(usize, side) * side * 4) catch return null;
    const sx = @as(f32, @floatFromInt(src.w)) / @as(f32, @floatFromInt(side));
    const sy = @as(f32, @floatFromInt(src.h)) / @as(f32, @floatFromInt(side));
    for (0..side) |oy| {
        const fy = @max(0, (@as(f32, @floatFromInt(oy)) + 0.5) * sy - 0.5);
        const y0: usize = @min(@as(usize, @intFromFloat(fy)), src.h - 1);
        const y1 = @min(y0 + 1, src.h - 1);
        const ty = fy - @as(f32, @floatFromInt(y0));
        for (0..side) |ox| {
            const fx = @max(0, (@as(f32, @floatFromInt(ox)) + 0.5) * sx - 0.5);
            const x0: usize = @min(@as(usize, @intFromFloat(fx)), src.w - 1);
            const x1 = @min(x0 + 1, src.w - 1);
            const tx = fx - @as(f32, @floatFromInt(x0));
            const o = out[(oy * side + ox) * 4 ..][0..4];
            for (0..4) |k| {
                const a: f32 = @floatFromInt(src.px[(y0 * src.w + x0) * 4 + k]);
                const b: f32 = @floatFromInt(src.px[(y0 * src.w + x1) * 4 + k]);
                const c: f32 = @floatFromInt(src.px[(y1 * src.w + x0) * 4 + k]);
                const d: f32 = @floatFromInt(src.px[(y1 * src.w + x1) * 4 + k]);
                const top = a + (b - a) * tx;
                const bot = c + (d - c) * tx;
                o[k] = @intFromFloat(@round(top + (bot - top) * ty));
            }
        }
    }
    return out;
}

test "splash art scaling: down box, up bilinear" {
    const gpa = std.testing.allocator;
    var px: [2 * 2 * 4]u8 = .{ 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 255 };
    const src: imgdec.Rgba = .{ .w = 2, .h = 2, .px = &px };
    const up = scaleArt(gpa, src, 4).?;
    defer gpa.free(up);
    try std.testing.expectEqual(@as(u8, 0), up[0]);
    try std.testing.expect(up[4] > 0 and up[4] < 255); // blended
    try std.testing.expectEqual(@as(u8, 255), up[3 * 4]);
    const down = scaleArt(gpa, src, 1).?;
    defer gpa.free(down);
    try std.testing.expect(down[0] > 100 and down[0] < 155);
}

// ------------------------------------------------------ background art

/// Shows or hides the background art (Settings "Background art").
pub fn setBackgroundArt(p: *Presenter, on: bool) void {
    if (p.art_on == on) return;
    p.art_on = on;
    p.dirty = true;
}

/// One opaque quad under everything, covering the window (the art is
/// premixed into the background colour, so what the frame leaves
/// unpainted shows it faintly; bars, panels, cards and fields paint over
/// it with their own fills).
fn pushArt(p: *Presenter) void {
    if (!p.art_on or !(p.art_uploaded or p.art_px != null)) return;
    const fb = p.window.framebufferSize();
    const w: f32 = @floatFromInt(fb[0]);
    const h: f32 = @floatFromInt(fb[1]);
    const side = @max(w, h); // cover
    const fw: f32 = @floatFromInt(tex_w);
    const fh: f32 = @floatFromInt(tex_h);
    const y0: f32 = @floatFromInt(art_y);
    const sd: f32 = @floatFromInt(art_side);
    p.push(@round((w - side) / 2), @round((h - side) / 2), side, side, .{ 0, y0 / fh, sd / fw, (y0 + sd) / fh }, .{ 255, 255, 255, 255 });
}

/// The art at `art_side` square, mixed into the theme background at
/// `art_alpha` (opaque). Null without memory.
fn premixArt(gpa: std.mem.Allocator, src: imgdec.Rgba) ?[]u8 {
    const px = scaleArt(gpa, src, art_side) orelse return null;
    const bg = theme.palette.bg;
    var i: usize = 0;
    while (i < px.len) : (i += 4) {
        for (0..3) |k| {
            const a: f32 = @floatFromInt(px[i + k]);
            const b: f32 = @floatFromInt(bg[k]);
            px[i + k] = @intFromFloat(@round(b + (a - b) * art_alpha));
        }
        px[i + 3] = 255;
    }
    return px;
}

test "background art is premixed: never brighter than bg + alpha * (white - bg)" {
    const gpa = std.testing.allocator;
    var white: [2 * 2 * 4]u8 = @splat(255);
    const px = premixArt(gpa, .{ .w = 2, .h = 2, .px = &white }).?;
    defer gpa.free(px);
    const bg = theme.palette.bg;
    const want: u8 = @intFromFloat(@round(@as(f32, @floatFromInt(bg[0])) + (255 - @as(f32, @floatFromInt(bg[0]))) * art_alpha));
    try std.testing.expectEqual(want, px[0]);
    try std.testing.expectEqual(@as(u8, 255), px[3]);
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
    p.glyphClipped(cp, style, m, cells, x, y, c, null);
}

fn glyphClipped(p: *Presenter, cp: u21, style: fontset.Style, m: fontset.Metrics, cells: u32, x: f32, y: f32, c: draw.Rgba, clip: ?[4]f32) void {
    const slot = p.atlas.get(&p.fonts, cp, style, m, cells) orelse {
        p.atlas_full = true;
        return;
    };
    const w: f32 = @floatFromInt(slot.w);
    const h: f32 = @floatFromInt(slot.h);
    const cl = clip orelse return p.push(x, y, w, h, p.atlas.uv(slot), c);
    if (images.clip(x, y, w, h, p.atlas.uv(slot), cl[0], cl[1], cl[2], cl[3])) |r| p.push(r.rect[0], r.rect[1], r.rect[2], r.rect[3], r.uv, c);
}

fn text(p: *Presenter, m: fontset.Metrics, x0: f32, y: f32, s: []const u8, c: draw.Rgba, style: fontset.Style, clip: ?[4]f32) void {
    var x = x0;
    var it = (std.unicode.Utf8View.init(s) catch return).iterator();
    while (it.nextCodepoint()) |cp| {
        const w = wcwidth.of(cp);
        if (w == 0) continue;
        if (clip) |cl| if (x >= cl[2]) break;
        if (cp != ' ' and cp >= 0x20) p.glyphClipped(cp, style, m, w, x, y, c, clip);
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
    p.pushArt();
    for (dl.cmds.items) |c| switch (c) {
        .rect => |r| p.push(r.x, r.y, r.w, r.h, white, r.color),
        .glyph => |g| p.glyph(g.cp, g.style, dl.fonts[g.font], g.cells, g.x, g.y, g.color),
        .text => |t| p.text(dl.fonts[t.font], t.x, t.y, dl.textOf(t), t.color, .{ .bold = t.bold, .italic = t.italic }, t.clip),
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
        p.text(m, x + @round((w - lw) / 2), y + @round((h - ch) / 2), label, c, .{}, null);
    }
}

test "window keys map to the UI's by name" {
    try std.testing.expectEqual(input.Key.page_down, key(.page_down));
    try std.testing.expectEqual(input.Key.f12, key(.f12));
    const m = mods(.{ .ctrl = true, .super = true });
    try std.testing.expect(m.ctrl and m.super and !m.shift and !m.alt);
}
