//! Unit test root for the client-specific code (the view module and the
//! shared UI, ../ui, have their own test roots).
test {
    _ = @import("gframe.zig");
    _ = @import("keys.zig");
    _ = @import("touchkbd.zig");
    _ = @import("credstore.zig");
    _ = @import("net/http.zig");
    _ = @import("net/x509check.zig");
    _ = @import("net/tlsconn.zig");
    _ = @import("net/watchdog.zig");
    _ = @import("net/pin.zig");
    _ = @import("net/client.zig");
    _ = @import("sync/root.zig");
    _ = @import("ios/wgkey.zig");
}
