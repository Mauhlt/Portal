//! Unit test root for the client-specific code (the reusable view module
//! has its own test root, src/view/root.zig).
test {
    _ = @import("gframe.zig");
    _ = @import("keys.zig");
    _ = @import("credstore.zig");
    _ = @import("net/ws.zig");
    _ = @import("net/http.zig");
}
