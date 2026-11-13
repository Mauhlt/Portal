//! QR pairing on the iPhone: a full-screen camera view (AVFoundation)
//! that reads the desk's pairing QR code (shared/pairqr.zig: the server
//! address and the CA's SHA-256, nothing secret). The shared first-run
//! screen (ui/panels/setup.zig) offers "Scan QR code" when this hook exists, and
//! takes the text through `take`; connect.zig then pins the CA exactly as
//! for typed values (download while pairing is open, SHA-256 must match).
//!
//! Main thread for all UIKit/AVFoundation calls; the session starts and
//! stops on one serial queue (startRunning blocks). The metadata delegate
//! runs on the main queue. A tap anywhere cancels. Camera permission is
//! checked first (authorizationStatusForMediaType; iOS asks on first use,
//! Info.plist NSCameraUsageDescription); when it is denied or the camera
//! cannot start, the setup screen gets a note (`takeNote`) instead.

const std = @import("std");
const view = @import("view");
const ios = view.Window.ios;
const objc = ios.objc;
const Object = objc.Object;
const Selector = objc.Selector;
const msgSend = objc.msgSend;
const sel = objc.sel;

// AVFoundation (link with -framework AVFoundation).
extern const AVMediaTypeVideo: ?*Object;
extern const AVMetadataObjectTypeQRCode: ?*Object;
extern const AVLayerVideoGravityResizeAspectFill: ?*Object;

const max_text = 256;

var io: std.Io = undefined;
var mutex: std.Io.Mutex = .init;
var text_buf: [max_text]u8 = undefined;
var text_len: usize = 0;
var have: bool = false;
/// Why scanning did not start (guarded by `mutex`), for the setup note.
var note_buf: [256]u8 = undefined;
var note_len: usize = 0;

// Main thread only.
var overlay: ?*Object = null;
var session: ?*Object = null;
/// startRunning and stopRunning go to this one serial queue, so a stop
/// never overtakes (or overlaps) the start it ends.
var session_queue: ?*anyopaque = null;

pub fn init(the_io: std.Io) void {
    io = the_io;
}

/// Runs `work(s)` on the session queue (created on first use; main thread).
fn onSessionQueue(s: *Object, work: objc.DispatchFn) void {
    if (session_queue == null) session_queue = objc.newSerialQueue("portal.scan.session");
    if (session_queue) |q| objc.onQueueAsync(q, s, work) else objc.onBackgroundAsync(s, work);
}

/// App thread (connect.Platform.scan_qr): open the camera view.
pub fn start() void {
    objc.onMainAsync(null, startMain);
}

/// App thread (connect.Platform.take_scanned): the scanned text, once.
pub fn take(buf: []u8) ?[]const u8 {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    if (!have) return null;
    have = false;
    const n = @min(buf.len, text_len);
    @memcpy(buf[0..n], text_buf[0..n]);
    return buf[0..n];
}

/// App thread (connect.Platform.take_scan_note): why the camera view did
/// not open (permission denied, no camera), once.
pub fn takeNote(buf: []u8) ?[]const u8 {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    if (note_len == 0) return null;
    const n = @min(buf.len, note_len);
    @memcpy(buf[0..n], note_buf[0..n]);
    note_len = 0;
    return buf[0..n];
}

/// Any thread: a note for the setup screen, and wake the app thread.
fn setNote(text: []const u8) void {
    std.log.warn("QR scan: {s}", .{text});
    mutex.lockUncancelable(io);
    const n = @min(text.len, note_buf.len);
    @memcpy(note_buf[0..n], text[0..n]);
    note_len = n;
    mutex.unlock(io);
    ios.postEvent(.expose);
}

const note_denied = "Portal may not use the camera. Allow it in Settings > Portal > Camera, or type the address and the SHA-256 the desk shows.";
const note_restricted = "The camera is restricted on this iPhone (Screen Time or a profile). Type the address and the SHA-256 the desk shows.";
const note_no_camera = "The camera could not be started. Type the address and the SHA-256 the desk shows.";

// AVAuthorizationStatus.
const av_not_determined: objc.NSInteger = 0;
const av_restricted: objc.NSInteger = 1;
const av_denied: objc.NSInteger = 2;

var access_block: objc.Block = objc.Block.global(@ptrCast(&accessAnswered));

/// requestAccessForMediaType's answer (an arbitrary queue): open the
/// camera view now, or say why not.
fn accessAnswered(_: *const objc.Block, granted: objc.BOOL) callconv(.c) void {
    if (granted != 0) objc.onMainAsync(null, startMain) else setNote(note_denied);
}

fn startMain(_: ?*anyopaque) callconv(.c) void {
    if (overlay != null) return;
    const root = ios.rootView() orelse return;
    const pool = objc.AutoreleasePool.push();
    defer pool.pop();
    // Camera permission first: iOS asks once (Info.plist
    // NSCameraUsageDescription); after a "Don't Allow" only Settings can
    // change it, so say so instead of opening a black view.
    const cls = objc.getClass("AVCaptureDevice");
    switch (msgSend(objc.NSInteger, cls, sel("authorizationStatusForMediaType:"), .{AVMediaTypeVideo})) {
        av_not_determined => return msgSend(void, cls, sel("requestAccessForMediaType:completionHandler:"), .{ AVMediaTypeVideo, &access_block }),
        av_restricted => return setNote(note_restricted),
        av_denied => return setNote(note_denied),
        else => {}, // authorized
    }
    const device = msgSend(?*Object, cls, sel("defaultDeviceWithMediaType:"), .{AVMediaTypeVideo}) orelse return setNote(note_no_camera);
    const input = msgSend(?*Object, objc.getClass("AVCaptureDeviceInput"), sel("deviceInputWithDevice:error:"), .{ device, @as(?*?*Object, null) }) orelse return setNote(note_no_camera);
    const s = msgSend(?*Object, objc.getClass("AVCaptureSession"), sel("new"), .{}) orelse return setNote(note_no_camera);
    if (msgSend(objc.BOOL, s, sel("canAddInput:"), .{input}) == 0) return objc.release(s);
    msgSend(void, s, sel("addInput:"), .{input});
    const output = msgSend(?*Object, objc.getClass("AVCaptureMetadataOutput"), sel("new"), .{}) orelse return objc.release(s);
    defer objc.release(output);
    if (msgSend(objc.BOOL, s, sel("canAddOutput:"), .{output}) == 0) return objc.release(s);
    msgSend(void, s, sel("addOutput:"), .{output});
    const del = msgSend(?*Object, delegateClass(), sel("new"), .{});
    msgSend(void, output, sel("setMetadataObjectsDelegate:queue:"), .{ del, objc.mainQueue() });
    const types = msgSend(?*Object, objc.getClass("NSArray"), sel("arrayWithObject:"), .{AVMetadataObjectTypeQRCode});
    msgSend(void, output, sel("setMetadataObjectTypes:"), .{types});

    // Full-screen view with the camera preview; a tap cancels.
    const bounds = msgSend(objc.CGRect, root, sel("bounds"), .{});
    const va = msgSend(?*Object, viewClass(), sel("alloc"), .{}) orelse return objc.release(s);
    const v = msgSend(?*Object, va, sel("initWithFrame:"), .{bounds}) orelse return objc.release(s);
    msgSend(void, v, sel("setAutoresizingMask:"), .{@as(objc.NSUInteger, 2 | 16)});
    msgSend(void, v, sel("setBackgroundColor:"), .{objc.color(.{ 0, 0, 0 })});
    const preview = msgSend(?*Object, objc.getClass("AVCaptureVideoPreviewLayer"), sel("layerWithSession:"), .{s});
    if (preview) |p| {
        msgSend(void, p, sel("setFrame:"), .{bounds});
        msgSend(void, p, sel("setVideoGravity:"), .{AVLayerVideoGravityResizeAspectFill});
        msgSend(void, msgSend(?*Object, v, sel("layer"), .{}), sel("addSublayer:"), .{p});
    }
    msgSend(void, root, sel("addSubview:"), .{v});
    overlay = v;
    session = s;
    // startRunning blocks until the camera is up: off the main thread.
    onSessionQueue(s, struct {
        fn f(ctx: ?*anyopaque) callconv(.c) void {
            msgSend(void, ctx, sel("startRunning"), .{});
        }
    }.f);
}

/// Main thread: close the camera view.
fn stop() void {
    if (session) |s| {
        onSessionQueue(s, struct {
            fn f(ctx: ?*anyopaque) callconv(.c) void {
                msgSend(void, ctx, sel("stopRunning"), .{});
                objc.release(@as(*Object, @ptrCast(ctx.?)));
            }
        }.f);
    }
    session = null;
    if (overlay) |v| {
        msgSend(void, v, sel("removeFromSuperview"), .{});
        objc.release(v);
    }
    overlay = null;
}

const Delegate = struct {
    /// captureOutput:didOutputMetadataObjects:fromConnection: (main queue).
    fn didOutput(_: *Object, _: *Selector, _: ?*Object, objects: ?*Object, _: ?*Object) callconv(.c) void {
        if (overlay == null) return;
        if (msgSend(objc.NSUInteger, objects, sel("count"), .{}) == 0) return;
        const first = msgSend(?*Object, objects, sel("objectAtIndex:"), .{@as(objc.NSUInteger, 0)});
        const s = objc.stringBytes(msgSend(?*Object, first, sel("stringValue"), .{}));
        if (s.len == 0 or s.len > max_text) return;
        mutex.lockUncancelable(io);
        @memcpy(text_buf[0..s.len], s);
        text_len = s.len;
        have = true;
        mutex.unlock(io);
        stop();
        // Wake the app thread: connect.zig runSetup reads it with `take`.
        ios.postEvent(.expose);
    }
};

const ScanView = struct {
    fn tapped(_: *Object, _: *Selector, _: ?*Object, _: ?*Object) callconv(.c) void {
        stop();
    }
};

fn delegateClass() *objc.Class {
    const name = "PortalScanDelegate";
    if (objc.lookUpClass(name)) |c| return c;
    const b = objc.ClassBuilder.begin(objc.getClass("NSObject"), name) orelse return objc.lookUpClass(name).?;
    b.addProtocol("AVCaptureMetadataOutputObjectsDelegate");
    b.addMethod("captureOutput:didOutputMetadataObjects:fromConnection:", &Delegate.didOutput, "v@:@@@");
    return b.register();
}

fn viewClass() *objc.Class {
    const name = "PortalScanView";
    if (objc.lookUpClass(name)) |c| return c;
    const b = objc.ClassBuilder.begin(objc.getClass("UIView"), name) orelse return objc.lookUpClass(name).?;
    b.addMethod("touchesEnded:withEvent:", &ScanView.tapped, "v@:@@");
    return b.register();
}

comptime {
    _ = &startMain;
}
