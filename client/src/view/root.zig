//! Module "view": the shared UI (module "portal_ui") on screen in a native
//! window with the owner's Vulkan Renderer, and nothing about networking or
//! what the UI shows. Imports only std, the Renderer's "Renderer", "Window"
//! and "Font" modules, "imgdec" and "portal_ui", so Portal's root build adds
//! it for the desk's window (`portal run`) as well as for the remote viewer
//! (`portal connect`).
//!
//!   Presenter  window + renderer + fonts + atlas + inline images; builds
//!              the UI's frame and draws its draw list; window input
//!              through the frame's hit-testing to an InputSink
//!   images     PNG decode / scale / pack into the texture's image region
//!   hero_png   the brand's hero art, embedded: the start-up splash
//!   Window     the Renderer's Window module (re-exported): one window API
//!              for Win32, Wayland and macOS
//!   font       the Renderer's Font module (re-exported)

pub const Presenter = @import("Presenter.zig");
pub const images = @import("images.zig");
pub const Window = @import("Window");
pub const font = @import("Font");
pub const wcwidth = font.wcwidth;
/// The UI's colours (shared/theme.zig), for hosts' native bits (the iOS
/// privacy cover).
pub const theme = @import("portal_ui").theme;
/// The hero art (docs/brand/portal-hero-768.png): the start-up splash
/// (Presenter.beginSplash).
pub const hero_png = @embedFile("portal_hero");

test {
    _ = Presenter;
    _ = images;
}
