//! Module "view": everything needed to show a terminal grid in a native
//! window with the owner's Vulkan Renderer, and nothing about networking.
//! Self-contained (imports only std and the "Renderer" module), so Portal's
//! root build can add it as a module for `portal run`'s local GUI terminal
//! as well as for the remote client (`portal connect`).
//!
//!   TermView   window + renderer + fonts + atlas + theme + fit/zoom + chrome
//!   grid       Grid/Cell snapshot model (mirrors src/vt.zig) and Theme
//!   input      Key/Mods/Event, InputSink interface, answer buttons
//!   platform   Window backends: Win32, X11 (dlopen), Cocoa (objc runtime)
//!   font       TrueType parser, rasteriser, system font set, glyph atlas
//!   wcwidth    cell widths (copy of Portal's src/vt_width.zig)

pub const TermView = @import("TermView.zig");
pub const grid = @import("grid.zig");
pub const images = @import("images.zig");
pub const input = @import("input.zig");
pub const platform = @import("platform/platform.zig");
pub const wcwidth = @import("wcwidth.zig");
pub const font = struct {
    pub const ttf = @import("font/ttf.zig");
    pub const raster = @import("font/raster.zig");
    pub const fontset = @import("font/fontset.zig");
    pub const atlas = @import("font/atlas.zig");
};

test {
    _ = TermView;
    _ = grid;
    _ = images;
    _ = wcwidth;
    _ = font.ttf;
    _ = font.raster;
    _ = font.fontset;
    _ = font.atlas;
}
