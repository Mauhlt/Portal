//! Code shared by Portal's server, native client, browser client (wasm32-
//! freestanding) and e2e tests, so both ends of each protocol are one
//! implementation with one set of limits:
//!
//!   screen   'G' / 'I' / 'P' screen frames: validation, row/cell iteration,
//!            image blob and placement parsing, client-side image limits
//!
//! Zig analyses only what a build references, so the browser build only
//! compiles what it uses (it must stay wasm32-freestanding clean).

pub const screen = @import("screen.zig");

test {
    _ = screen;
}
