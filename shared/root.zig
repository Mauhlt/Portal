//! Code shared by Portal's server, native clients and e2e tests, so both
//! ends of each protocol are one
//! implementation with one set of limits:
//!
//!   screen   'G' / 'I' / 'P' screen frames: validation, row/cell iteration,
//!            image blob and placement parsing, client-side image limits
//!   ws       WebSocket (RFC 6455) framing in both directions, handshake
//!            key and accept values
//!   http     HTTP/1.1 syntax checks (head end, tokens, field values) and
//!            Portal's cookie names
//!   pki      DER reader/writer, X.509 reading, PEM, SHA-256 fingerprints
//!   tabs     project tabs (protocol v2): session ids, the session list in
//!            hello/tabs, tab colours, program state
//!   theme    Portal's colour scheme (the one place colours are defined):
//!            palette, ANSI colours, terminal defaults, tab accents, UI roles
//!   convo    the Conversation view (convo / convo+ messages): items,
//!            writer and strict parser
//!   tls13    TLS 1.3 suites, record protection, HKDF-Expand-Label and a
//!            bounds-checked byte cursor
//!   pairqr   the pairing QR code's text (desk shows it, iPhone scans it)
//!   activity background tasks and token usage per tab (activity message)
//!   sysinfo  the optional system monitor's numbers (sys message)
//!   subtabs  subagent sub-tabs of the tab watched (subtabs message, a: frame)
//!   transport the stream seam (OS sockets or the in-process tunnel) under
//!            the HTTPS/WSS server and client, and an in-memory network
//!            for tests
//!   tunnelnet the in-process tunnel's addresses and ports (one definition)

pub const screen = @import("screen.zig");
pub const ws = @import("ws.zig");
pub const http = @import("http.zig");
pub const pki = @import("pki/root.zig");
pub const tls13 = @import("tls13.zig");
pub const tabs = @import("tabs.zig");
pub const theme = @import("theme.zig");
pub const convo = @import("convo.zig");
pub const pairqr = @import("pairqr.zig");
pub const activity = @import("activity.zig");
pub const sysinfo = @import("sysinfo.zig");
pub const subtabs = @import("subtabs.zig");
pub const transport = @import("transport.zig");
pub const tunnelnet = @import("tunnelnet.zig");

test {
    _ = screen;
    _ = ws;
    _ = http;
    _ = pki;
    _ = tls13;
    _ = tabs;
    _ = theme;
    _ = convo;
    _ = pairqr;
    _ = activity;
    _ = sysinfo;
    _ = subtabs;
    _ = transport;
    _ = tunnelnet;
}
