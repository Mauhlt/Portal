//! Unit test root for the client-specific code (the reusable view module
//! has its own test root, src/view/root.zig).
test {
    _ = @import("gframe.zig");
    _ = @import("keys.zig");
    _ = @import("inputline.zig");
    _ = @import("credstore.zig");
    _ = @import("net/ws.zig");
    _ = @import("net/http.zig");
    _ = @import("net/x509check.zig");
    _ = @import("net/tlsconn.zig");
    _ = @import("net/watchdog.zig");
    _ = @import("net/pin.zig");
    _ = @import("net/client.zig");
    _ = @import("remote.zig");
    _ = @import("setup.zig");
    _ = @import("sync/root.zig");
}
