//! Code shared by Portal's server, native client, browser client (wasm32-
//! freestanding) and e2e tests, so both ends of each protocol are one
//! implementation with one set of limits:
//!
//!   screen   'G' / 'I' / 'P' screen frames: validation, row/cell iteration,
//!            image blob and placement parsing, client-side image limits
//!   ws       WebSocket (RFC 6455) framing in both directions, handshake
//!            key and accept values
//!   http     HTTP/1.1 syntax checks (head end, tokens, field values) and
//!            Portal's cookie names
//!   pki      DER reader/writer, X.509 reading, PEM, SHA-256 fingerprints
//!   tls13    TLS 1.3 suites, record protection, HKDF-Expand-Label and a
//!            bounds-checked byte cursor
//!   pairqr   the pairing QR code's text (desk shows it, iPhone scans it)
//!
//! Zig analyses only what a build references, so the browser build only
//! compiles what it uses (it must stay wasm32-freestanding clean).

pub const screen = @import("screen.zig");
pub const ws = @import("ws.zig");
pub const http = @import("http.zig");
pub const pki = @import("pki/root.zig");
pub const tls13 = @import("tls13.zig");
pub const pairqr = @import("pairqr.zig");

test {
    _ = screen;
    _ = ws;
    _ = http;
    _ = pki;
    _ = tls13;
    _ = pairqr;
}
