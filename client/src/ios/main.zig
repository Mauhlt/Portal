//! The iPhone app's entry (root of the `zig build ios` executable).
//!
//! Device section only: it wires iOS behaviour into the SAME viewer the
//! desktops run (`connect.main`, module "client": pairing, CA pinning,
//! sign-in, the WebSocket stream, the shared view and input line) and then
//! hands the main thread to UIKit. Nothing here draws or speaks the
//! protocol.
//!
//!   main thread   Window.runApp -> UIApplicationMain (never returns)
//!   app thread    connect.main(...), the same event-driven loop as
//!                 `portal connect` (see the Renderer's Window/ios.zig,
//!                 "Inverted control")
//!
//! Owner decisions wired here (all on, nothing to configure): third-party
//! keyboards refused, UI covered while inactive and while the screen is
//! captured, Face ID before anything is shown at launch and after every
//! trip to the background, the connection dropped while in the background,
//! the credential in the Keychain behind Face ID (credstore.zig), QR
//! pairing (scan.zig), and the per-app tunnel when built with it
//! (tunnel.zig).

const std = @import("std");
const view = @import("view");
const connect = @import("client");
const device = @import("device.zig");

var gpa: std.mem.Allocator = undefined;
var io: std.Io = undefined;

pub fn main(init: std.process.Init) void {
    gpa = init.gpa;
    io = init.io;
    device.install(io);
    view.Window.runApp(.{
        .block_keyboard_extensions = true,
        .cover_when_inactive = true,
        .cover_when_captured = true,
        .lock_after_background = true,
        .cover_rgb = .{ 0x20, 0x23, 0x29 },
    }, entry, null);
}

/// App thread: the shared viewer, exactly as `portal connect` runs it
/// (no arguments: the last server, or the first-run screen).
fn entry(_: ?*anyopaque) void {
    // Face ID first: nothing is shown or fetched before it.
    device.waitUnlocked();
    connect.main(gpa, io, "Portal", &.{});
}

comptime {
    // `zig build ios-check` compiles an object, which std's start code
    // does not give a main: reference it so the whole app is analysed.
    _ = &main;
    _ = &device.tunnel.configure;
}

test {
    _ = device;
}
