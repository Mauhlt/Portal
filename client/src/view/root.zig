//! Module "view": everything needed to show a terminal grid in a native
//! window with the owner's Vulkan Renderer, and nothing about networking.
//! Self-contained (imports only std, the Renderer's "Renderer" and "Font"
//! modules and "imgdec"), so Portal's
//! root build can add it as a module for `portal run`'s local GUI terminal
//! as well as for the remote client (`portal connect`).
//!
//!   TermView   window + renderer + fonts + atlas + theme + fit/zoom + chrome
//!   grid       Grid/Cell snapshot model (mirrors src/vt.zig) and Theme
//!   input      Key/Mods/Event, InputSink interface, answer buttons
//!   platform   Window backends: Win32, X11 (dlopen), Cocoa (objc runtime)
//!   font       the Renderer's Font module: TrueType parser, rasteriser,
//!              system font set, glyph atlas (re-exported)
//!   wcwidth    cell widths: the Font module's table, the same one the
//!              server's src/vt.zig and the browser client use

pub const TermView = @import("TermView.zig");
pub const grid = @import("grid.zig");
pub const form = @import("form.zig");
pub const images = @import("images.zig");
pub const input = @import("input.zig");
pub const platform = @import("platform/platform.zig");
pub const font = @import("Font");
pub const wcwidth = font.wcwidth;

test {
    _ = TermView;
    _ = grid;
    _ = form;
    _ = images;
    _ = platform;
}
