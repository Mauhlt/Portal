//! QR pairing on the iPhone: a full-screen camera view (AVFoundation)
//! that reads the desk's pairing QR code (shared/pairqr.zig: the server
//! address and the CA's SHA-256, nothing secret). The shared first-run
//! screen (ui/panels/setup.zig) offers "Scan QR code" when this hook exists, and
//! takes the text through `take`; connect.zig then pins the CA exactly as
//! for typed values (download while pairing is open, SHA-256 must match).
//!
//! Main thread for all UIKit/AVFoundation calls; the session starts on a
//! background queue (startRunning blocks). The metadata delegate runs on
//! the main queue. A tap anywhere cancels. Camera permission is asked by
//! iOS on first use (Info.plist NSCameraUsageDescription).

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

// Main thread only.
var overlay: ?*Object = null;
var session: ?*Object = null;

pub fn init(the_io: std.Io) void {
    io = the_io;
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

fn startMain(_: ?*anyopaque) callconv(.c) void {
    if (overlay != null) return;
    const root = ios.rootView() orelse return;
    const pool = objc.AutoreleasePool.push();
    defer pool.pop();
    const device = msgSend(?*Object, objc.getClass("AVCaptureDevice"), sel("defaultDeviceWithMediaType:"), .{AVMediaTypeVideo}) orelse return;
    const input = msgSend(?*Object, objc.getClass("AVCaptureDeviceInput"), sel("deviceInputWithDevice:error:"), .{ device, @as(?*?*Object, null) }) orelse return;
    const s = msgSend(?*Object, objc.getClass("AVCaptureSession"), sel("new"), .{}) orelse return;
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
    objc.onBackgroundAsync(s, struct {
        fn f(ctx: ?*anyopaque) callconv(.c) void {
            msgSend(void, ctx, sel("startRunning"), .{});
        }
    }.f);
}

/// Main thread: close the camera view.
fn stop() void {
    if (session) |s| {
        objc.onBackgroundAsync(s, struct {
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
