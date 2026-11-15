//! The iPhone app's entry (root of the `zig build ios` executable).
//!
//! Device section only: it wires iOS behaviour into the SAME viewer the
//! desktops run (`connect.main`, module "client": pairing, CA pinning,
//! the tunnel, the WebSocket stream, the shared view and input line) and then
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

/// An iOS app has no terminal: std.log and the panic message go to the
/// system log (syslog, which iOS forwards to the unified log: Console.app
/// on a Mac, filtered by process "Portal").
pub const std_options: std.Options = .{ .logFn = systemLog };

pub const panic = std.debug.FullPanic(struct {
    fn f(msg: []const u8, first_trace_addr: ?usize) noreturn {
        logLine(log_crit, "panic: ", msg);
        std.debug.defaultPanic(msg, first_trace_addr);
    }
}.f);

pub fn main(init: std.process.Init) void {
    gpa = init.gpa;
    io = init.io;
    // Every message that ends the viewer (connect's fatal/report) reaches
    // the system log too, before the process exits.
    connect.report_fn = reportLine;
    device.install(io);
    view.Window.runApp(.{
        .block_keyboard_extensions = true,
        .cover_when_inactive = true,
        .cover_when_captured = true,
        .lock_after_background = true,
        // Locked before UIKit starts, so the first activation asks for
        // Face ID (device.zig).
        .start_locked = true,
        .lock_message = device.tap_to_unlock,
        .cover_rgb = view.theme.palette.bg,
    }, entry, null);
}

// syslog priorities (<sys/syslog.h>).
const log_crit: c_int = 2;
const log_err: c_int = 3;
const log_warning: c_int = 4;
const log_info: c_int = 6;
const log_debug: c_int = 7;

fn reportLine(text: []const u8) void {
    logLine(log_err, "", text);
}

fn systemLog(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    const prefix = if (scope == .default) "" else "(" ++ @tagName(scope) ++ ") ";
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    w.print(prefix ++ format, args) catch {}; // cut at the buffer's end
    logLine(switch (level) {
        .err => log_err,
        .warn => log_warning,
        .info => log_info,
        .debug => log_debug,
    }, "", w.buffered());
}

/// One syslog record, `prefix ++ text` (cut at 2 KiB), passed as a "%s"
/// argument so the text is never read as a format.
fn logLine(priority: c_int, prefix: []const u8, text: []const u8) void {
    var buf: [2048:0]u8 = undefined;
    const p = @min(prefix.len, buf.len);
    @memcpy(buf[0..p], prefix[0..p]);
    const n = @min(text.len, buf.len - p);
    @memcpy(buf[p..][0..n], text[0..n]);
    buf[p + n] = 0;
    std.c.syslog(priority, "%s", @as([*:0]const u8, &buf));
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
}

test {
    _ = device;
}
