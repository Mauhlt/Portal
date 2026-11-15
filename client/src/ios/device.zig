//! The iPhone section's glue: the `connect.Platform` hooks and the app
//! lock. Device behaviour only (Face ID, camera, tunnel); the viewer's
//! logic stays in the shared code.
//!
//! Lock: the Renderer's iOS window keeps an opaque cover up while locked
//! (`lock_after_background`, and `start_locked` at launch) and calls our
//! unlock handler once per activation while locked (so a cancelled Face ID
//! sheet does not loop) and on every tap on the cover; the cover's text
//! says what to do (`lockMessage`: tap to retry, or how to turn Face ID
//! on). The handler asks for Face ID (LocalAuthentication); on success
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
pub const speech = @import("speech.zig");
const mic = @import("mic.zig");

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
        // The iPhone takes one package from its desk, the personal speech
        // adapter (data, signed, never older), and sends its training
        // samples home on the same passes (speech.zig).
        .sync = .{ .only = speech.sync_packages },
        .speech_sync = speech.syncHooks(),
        .on_suspend = onSuspend,
        .on_resume = onResume,
        .scan_qr = scan.start,
        .take_scanned = scan.take,
        .take_scan_note = scan.takeNote,
        // With -Dios-tunnel the packet tunnel extension carries the
        // tunnel (tunnel.zig); without, configure says no and the
        // viewer runs the in-app tunnel.
        .system_tunnel = tunnel.configure,
        .note = tunnel.note,
        .speech = speech.hooks(),
    };
    tunnel.init(io);
    speech.init(io);
    ios.setUnlockHandler(requestUnlock);
    // Nothing is shown before the first Face ID: main.zig starts the
    // window locked (AppOptions.start_locked, applied before UIKit runs).
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
    // No recording off screen; the speech engine's memory goes back.
    speech.suspend_();
}

/// App thread, back on screen: wait for Face ID (the cover stays up and
/// nothing reconnects until then), then bring the tunnel up.
fn onResume() void {
    waitUnlocked();
    // Settings may have changed microphone access while off screen.
    _ = mic.refreshPermission();
    tunnel.start();
}

/// The lock cover's text (AppOptions.lock_message, and after a cancel).
pub const tap_to_unlock = "Portal is locked.\nTap to unlock with Face ID.";

/// LAError codes (LocalAuthentication/LAError.h).
const la_authentication_failed: objc.NSInteger = -1;
const la_passcode_not_set: objc.NSInteger = -5;
const la_biometry_not_available: objc.NSInteger = -6;
const la_biometry_not_enrolled: objc.NSInteger = -7;
const la_biometry_lockout: objc.NSInteger = -8;

/// What the lock cover says after LocalAuthentication answered `code`.
/// The credential stays bound to Face ID (credstore.zig,
/// biometryCurrentSet): without Face ID the device key cannot be read,
/// so the app stays locked and says how to fix it rather than unlocking
/// with the passcode and failing later on the Keychain read.
pub fn lockMessage(code: objc.NSInteger) []const u8 {
    return switch (code) {
        la_biometry_not_available => "Face ID is off for Portal.\n\nTurn it on in Settings > Portal > Face ID (or Settings > Face ID & Passcode > Other Apps), then come back.\n\nPortal keeps this device's key behind Face ID and does not open without it.",
        la_biometry_not_enrolled => "Face ID is not set up on this iPhone.\n\nSet it up in Settings > Face ID & Passcode, then come back.\n\nPortal keeps this device's key behind Face ID and does not open without it.",
        la_passcode_not_set => "This iPhone has no passcode.\n\nSet a passcode and Face ID in Settings > Face ID & Passcode, then come back.",
        la_biometry_lockout => "Face ID is locked after too many attempts.\nTap to unlock with your passcode.",
        la_authentication_failed => "Face ID did not recognise you.\nTap to try again.",
        // Cancelled (by the user, the system or a trip to the background).
        else => tap_to_unlock,
    };
}

fn errorCode(err: ?*Object) objc.NSInteger {
    return if (err) |e| msgSend(objc.NSInteger, e, sel("code"), .{}) else 0;
}

/// Main thread (the window's unlock handler: once per activation while
/// locked, and on every tap on the cover).
fn requestUnlock() void {
    if (evaluating.swap(true, .acq_rel)) return;
    const ctx = msgSend(?*Object, objc.lookUpClass("LAContext") orelse return done(), sel("new"), .{}) orelse return done();
    // Face ID. Only a lockout (too many failed tries) uses the passcode
    // policy: entering the passcode ends the lockout, and the Keychain
    // read then asks for Face ID itself. Face ID off for the app, not
    // enrolled, or no passcode: stay locked and say why.
    var err: ?*Object = null;
    const policy = if (msgSend(objc.BOOL, ctx, sel("canEvaluatePolicy:error:"), .{ policy_biometrics, &err }) != 0) policy_biometrics else blk: {
        const code = errorCode(err);
        if (code == la_biometry_lockout) break :blk policy_owner;
        std.log.warn("Face ID unavailable (LAError {d}): staying locked", .{code});
        ios.setLockMessage(lockMessage(code));
        objc.release(ctx);
        return done();
    };
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
fn reply(_: *const objc.Block, success: objc.BOOL, err: ?*Object) callconv(.c) void {
    const ctx = pending.swap(null, .acq_rel);
    if (success != 0) {
        if (credstore.apple_auth_context.swap(@as(?*anyopaque, @ptrCast(ctx)), .acq_rel)) |old| objc.release(@as(*Object, @ptrCast(old)));
        ios.setLockMessage(tap_to_unlock);
        ios.unlock();
        unlocked.set(io);
    } else {
        // Stays locked; a tap on the cover asks again (the window does
        // not re-ask on its own until the next return from background).
        const code = errorCode(err);
        if (code != -2 and code != -4 and code != -9) std.log.warn("Face ID failed (LAError {d})", .{code});
        ios.setLockMessage(lockMessage(code));
        if (ctx) |c| objc.release(c);
    }
    done();
}

comptime {
    // Analyse the iOS-only paths in compile checks.
    _ = &waitUnlocked;
}
