//! Stand-in for the "Vulkan" module when the owner's Image package is
//! compiled for the browser client (wasm32-freestanding). Image's Info and
//! Image structs carry a `vk.Format` field; the PNG decoder needs nothing
//! else from Vulkan, so this is the only declaration provided, and the real
//! bindings (and their package) never enter the wasm build. Names match the
//! real enum for every value Image's `Info.fmtFor` returns.

pub const Format = enum(i32) {
    undefined = 0,
    r8_unorm = 9,
    r8_srgb = 15,
    r8g8_unorm = 16,
    r8g8_srgb = 22,
    r8g8b8_unorm = 23,
    r8g8b8_srgb = 29,
    b8g8r8_unorm = 30,
    b8g8r8_srgb = 36,
    r8g8b8a8_unorm = 37,
    r8g8b8a8_srgb = 43,
    b8g8r8a8_unorm = 44,
    b8g8r8a8_srgb = 50,
    r16_unorm = 70,
    _,
};
