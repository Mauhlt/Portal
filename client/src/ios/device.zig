//! The iPhone section's glue: the `connect.Platform` hooks and the app
//! lock. Device behaviour only (Face ID, camera, tunnel); the viewer's
//! logic stays in the shared code.
//!
//! Lock: the Renderer's iOS window keeps an opaque cover up while locked
//! (`lock_after_background`, and `lock()` at launch) and calls our unlock
//! handler whenever the app becomes active while locked, or the cover is
//! tapped. The handler asks for Face ID (LocalAuthentication); on success
//! the evaluated LAContext goes to credstore (so the Keychain read that
//! follows does not ask again) and the cover is lifted. The app thread
//! waits for that at launch (before the viewer starts) and after every
//! return from the background (before it reconnects and draws): an
//! `Io.Event`, no polling.

const std = @import("std");
const view = @import("view");
const connect = @import("client");
const credstore = connect.credstore_mod;
const ios = view.Window.ios;
const objc = ios.objc;
const Object = objc.Object;
const msgSend = objc.msgSend;
const sel = objc.sel;
pub const scan = @import("scan.zig");
pub const tunnel = @import("tunnel.zig");

/// LAPolicy values.
const policy_biometrics: objc.NSInteger = 1; // DeviceOwnerAuthenticationWithBiometrics
const policy_owner: objc.NSInteger = 2; // DeviceOwnerAuthentication (passcode fallback)

var io: std.Io = undefined;
/// Set while the user is authenticated (reset on every trip to the
/// background).
var unlocked: std.Io.Event = .unset;
var evaluating: std.atomic.Value(bool) = .init(false);
/// The LAContext being evaluated (+1), handed to the reply block.
var pending: std.atomic.Value(?*Object) = .init(null);

pub fn install(the_io: std.Io) void {
    io = the_io;
    connect.platform = .{
        // The iPhone installs no packages: no sync worker.
        .sync = false,
        .on_suspend = onSuspend,
        .on_resume = onResume,
        .scan_qr = scan.start,
        .take_scanned = scan.take,
    };
    ios.setUnlockHandler(requestUnlock);
    // Nothing is shown before the first Face ID.
    ios.lock();
    scan.init(io);
}

/// App thread, before the viewer starts.
pub fn waitUnlocked() void {
    unlocked.wait(io) catch {};
}

fn onSuspend() void {
    unlocked.reset();
    // Forget the authentication: the next Keychain read asks again.
    if (credstore.apple_auth_context.swap(null, .acq_rel)) |old| objc.release(@as(*Object, @ptrCast(old)));
    tunnel.stop();
}

/// App thread, back on screen: wait for Face ID (the cover stays up and
/// nothing reconnects until then), then bring the tunnel up.
fn onResume() void {
    waitUnlocked();
    tunnel.start();
}

/// Main thread (the window's unlock handler).
fn requestUnlock() void {
    if (evaluating.swap(true, .acq_rel)) return;
    const ctx = msgSend(?*Object, objc.lookUpClass("LAContext") orelse return done(), sel("new"), .{}) orelse return done();
    // Face ID; only a device without enrolled biometrics falls back to
    // the passcode (it cannot hold the Face ID-bound credential anyway,
    // so it cannot sign in: credstore says so).
    const policy = if (msgSend(objc.BOOL, ctx, sel("canEvaluatePolicy:error:"), .{ policy_biometrics, @as(?*?*Object, null) }) != 0) policy_biometrics else policy_owner;
    pending.store(ctx, .release);
    const reason = objc.newString("Unlock Portal");
    defer if (reason) |r| objc.release(r);
    msgSend(void, ctx, sel("evaluatePolicy:localizedReason:reply:"), .{ policy, reason, &reply_block });
}

fn done() void {
    evaluating.store(false, .release);
}

var reply_block: objc.Block = objc.Block.global(@ptrCast(&reply));

/// LocalAuthentication's reply (a private queue).
fn reply(_: *const objc.Block, success: objc.BOOL, _: ?*Object) callconv(.c) void {
    const ctx = pending.swap(null, .acq_rel);
    if (success != 0) {
        if (credstore.apple_auth_context.swap(@as(?*anyopaque, @ptrCast(ctx)), .acq_rel)) |old| objc.release(@as(*Object, @ptrCast(old)));
        ios.unlock();
        unlocked.set(io);
    } else if (ctx) |c| objc.release(c);
    done();
}

comptime {
    // Analyse the iOS-only paths in compile checks.
    _ = &waitUnlocked;
}
