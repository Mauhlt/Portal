//! Native test root for the browser client's pure logic (`zig build test`
//! runs these on the host; main.zig itself only builds for wasm because it
//! declares the bridge's host imports).

test {
    _ = @import("proto.zig");
    _ = @import("keys.zig");
    _ = @import("conn.zig");
    _ = @import("layout.zig");
    _ = @import("slices.zig");
    _ = @import("data.zig");
    _ = @import("inputbox.zig");
    _ = @import("glyphs.zig");
    _ = @import("render.zig");
    _ = @import("font/ttf.zig");
    _ = @import("font/raster.zig");
}
