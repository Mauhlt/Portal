//! Module "imgcheck": Portal's inline-image policy on top of the owner's
//! image checker, `Image.check` (module "ImageCheck": format detection and
//! strict, allocation-free structural validation for every format Image
//! knows, std only, also built for wasm32).
//!
//! This file holds only Portal's choices: which format is accepted and the
//! limits. Inline images are PNG (kitty graphics `f=100`), and every check
//! below is `Image.check.checkAs(.png, ...)` with `limits`.
//!
//! Used on both sides of the wire, always BEFORE any decoding:
//!   * src/vt_gfx.zig, when a program in the session finishes transmitting
//!     an image, so nothing malformed or oversized is stored or forwarded;
//!   * imgdec.zig, before handing bytes to Image's PNG decoder;
//!   * the browser client (src/wasm/proto.zig) and the view, for sizes.
//! Also re-exports the checker's PNG test fixtures (`testImage`, ...).

const std = @import("std");

/// The owner's checker (Image.check).
pub const check = @import("ImageCheck");
pub const Info = check.Info;
pub const Error = check.Error;

/// Largest width or height accepted.
pub const max_side: u32 = 8192;
/// Largest width * height accepted.
pub const max_pixels: u64 = 32 * 1024 * 1024;
/// Largest PNG file accepted. The base64 payload of one image is capped at
/// 8 MiB, which decodes to 6 MiB.
pub const max_file_bytes: usize = 6 * 1024 * 1024;

pub const limits: check.Limits = .{
    .max_bytes = max_file_bytes,
    .max_width = max_side,
    .max_height = max_side,
    .max_pixels = max_pixels,
    // A file of a million empty chunks is valid but only burns CPU.
    .max_chunks = 4096,
    // Decode memory is budgeted where decoding happens (imgdec.Options).
    .max_decode_bytes = std.math.maxInt(u64),
};

/// Whole-file check: signature, IHDR (limits applied there), every chunk's
/// bounds, tag and CRC, chunk order, IEND.
pub fn validate(png: []const u8) Error!Info {
    return check.checkAs(.png, png, limits);
}

/// Signature and IHDR only (CRC checked, limits applied): the size.
pub fn header(png: []const u8) Error!Info {
    return check.checkHeaderAs(.png, png, limits);
}

/// True for the errors that mean "over Portal's limits" (vs. malformed).
pub fn tooLarge(e: Error) bool {
    return switch (e) {
        error.FileTooLarge, error.ImageTooLarge, error.DecodeTooLarge, error.TooManyChunks => true,
        else => false,
    };
}

pub const signature = check.png.signature;
/// Test fixtures from the checker: a stored-deflate RGBA PNG writer, a
/// gradient test image, and a CRC fixer for mutated files.
pub const encodeStored = check.png.fixtures.encodeStored;
pub const testImage = check.png.fixtures.testImage;
pub const fixCrcs = check.png.fixtures.fixCrcs;

test "Portal's limits" {
    const gpa = std.testing.allocator;
    const png = try testImage(gpa, 20, 10);
    defer gpa.free(png);
    const info = try validate(png);
    try std.testing.expectEqual(@as(u32, 20), info.width);
    try std.testing.expectEqual(@as(u32, 10), (try header(png)).height);
    const m = try gpa.dupe(u8, png);
    defer gpa.free(m);
    std.mem.writeInt(u32, m[16..20], max_side + 1, .big);
    fixCrcs(m);
    try std.testing.expectError(error.ImageTooLarge, validate(m));
    try std.testing.expect(tooLarge(error.ImageTooLarge));
    // Other formats are not inline images.
    try std.testing.expectError(error.UnknownFormat, validate("qoif\x00\x00\x00\x01\x00\x00\x00\x01\x04\x00"));
}
