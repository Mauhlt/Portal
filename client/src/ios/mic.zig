//! The iPhone's microphone for dictation (speech.zig): AVAudioSession
//! and AVAudioEngine through the Objective-C runtime.
//!
//!   start   asks for microphone access once (Info.plist
//!           NSMicrophoneUsageDescription), sets the session to record
//!           (Bluetooth hands-free allowed, so a headset's mic is
//!           routable), picks the input with the desk's headset-first
//!           rule (src/speech/mics.zig `choose`, the iPhone's ports
//!           mapped by `mics.fromApplePort`), and installs a tap on the
//!           input node;
//!   tap     the engine's callback (its own thread) appends the first
//!           channel's f32 samples at the hardware rate; when the clip
//!           reaches stt's limit (120 s) it says so and wakes the window;
//!   stop    removes the tap, stops the engine, releases the session and
//!           hands back the clip as 16 kHz mono f32 (stt.audio.resample,
//!           the resampler stt uses for files).
//!
//! Event-driven: nothing runs between the tap's callbacks. Recording
//! happens only between start and stop (never in the background: the
//! device glue stops it on suspend).

const std = @import("std");
const view = @import("view");
const stt = @import("stt");
const speech = @import("speech");
const mics = speech.mics;
const ios = view.Window.ios;
const objc = ios.objc;
const Object = objc.Object;
const msgSend = objc.msgSend;
const sel = objc.sel;

/// What stt wants: 16 kHz mono f32, at most 120 s.
pub const sample_rate = stt.audio.target_rate;
pub const max_seconds = (stt.audio.Limits{}).max_seconds;

// AVFAudio (re-exported by AVFoundation).
extern const AVAudioSessionCategoryRecord: ?*Object;
extern const AVAudioSessionModeDefault: ?*Object;
/// AVAudioSessionCategoryOptionAllowBluetooth (hands-free profile: the
/// headset's microphone).
const option_allow_bluetooth: objc.NSUInteger = 0x4;
/// AVAudioSessionSetActiveOptionNotifyOthersOnDeactivation.
const option_notify_others: objc.NSUInteger = 1;

/// AVAudioApplicationRecordPermission (FourCC values).
const perm_undetermined: objc.NSInteger = 0x756e6474; // 'undt'
const perm_denied: objc.NSInteger = 0x64656e79; // 'deny'
const perm_granted: objc.NSInteger = 0x67726e74; // 'grnt'

pub const Permission = enum { granted, denied, undetermined };

pub const StartError = error{ NotAllowed, AskedForAccess, SessionFailed, NoInput, EngineFailed, OutOfMemory };

var io: std.Io = undefined;
var gpa: std.mem.Allocator = undefined;

/// Guards everything the tap touches.
var mutex: std.Io.Mutex = .init;
/// The clip at the hardware rate (allocated at the first start, for
/// max_seconds at that rate, and kept).
var buf: []f32 = &.{};
var len: usize = 0;
var rate: f64 = 48000;
var recording: bool = false;
var full: bool = false;
/// The input in use ("iPhone Microphone", a headset's name).
var name_buf: [mics.max_name]u8 = undefined;
var name_len: usize = 0;

/// Owned by start/stop (one caller: the app thread).
var engine: ?*Object = null;

pub fn init(the_io: std.Io, the_gpa: std.mem.Allocator) void {
    io = the_io;
    gpa = the_gpa;
}

fn session() ?*Object {
    return msgSend(?*Object, objc.lookUpClass("AVAudioSession") orelse return null, sel("sharedInstance"), .{});
}

/// Microphone access as iOS has it now (iOS 17: AVAudioApplication).
pub fn permission() Permission {
    const app = msgSend(?*Object, objc.lookUpClass("AVAudioApplication") orelse return .denied, sel("sharedInstance"), .{});
    return switch (msgSend(objc.NSInteger, app, sel("recordPermission"), .{})) {
        perm_granted => .granted,
        perm_undetermined => .undetermined,
        perm_denied => .denied,
        else => .denied,
    };
}

var access_block: objc.Block = objc.Block.global(@ptrCast(&accessAnswered));

/// requestRecordPermission's answer (any queue): the window redraws, so
/// the 🎤 shows the new state; the next tap records.
fn accessAnswered(_: *const objc.Block, _: objc.BOOL) callconv(.c) void {
    ios.postEvent(.expose);
}

/// The input in use while recording (copied).
pub fn inputName(out: []u8) []const u8 {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    const n = @min(out.len, name_len);
    @memcpy(out[0..n], name_buf[0..n]);
    return out[0..n];
}

/// The clip reached max_seconds (the caller stops).
pub fn isFull() bool {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    return full;
}

/// App thread: start recording.
pub fn start() StartError!void {
    switch (permission()) {
        .granted => {},
        .denied => return error.NotAllowed,
        .undetermined => {
            const cls = objc.lookUpClass("AVAudioApplication") orelse return error.NotAllowed;
            msgSend(void, cls, sel("requestRecordPermissionWithCompletionHandler:"), .{&access_block});
            return error.AskedForAccess;
        },
    }
    const pool = objc.AutoreleasePool.push();
    defer pool.pop();
    const s = session() orelse return error.SessionFailed;
    var err: ?*Object = null;
    if (msgSend(objc.BOOL, s, sel("setCategory:mode:options:error:"), .{ AVAudioSessionCategoryRecord, AVAudioSessionModeDefault, option_allow_bluetooth, &err }) == 0) return error.SessionFailed;
    if (msgSend(objc.BOOL, s, sel("setActive:error:"), .{ objc.YES, &err }) == 0) return error.SessionFailed;
    errdefer deactivate(s);
    choosePreferredInput(s);

    const e = engine orelse (msgSend(?*Object, objc.getClass("AVAudioEngine"), sel("new"), .{}) orelse return error.EngineFailed);
    engine = e;
    const input = msgSend(?*Object, e, sel("inputNode"), .{}) orelse return error.NoInput;
    const format = msgSend(?*Object, input, sel("outputFormatForBus:"), .{@as(objc.NSUInteger, 0)}) orelse return error.NoInput;
    const hw_rate = msgSend(f64, format, sel("sampleRate"), .{});
    if (!(hw_rate >= 8000 and hw_rate <= 192000)) return error.NoInput; // no input route (rate 0)

    const want: usize = @intFromFloat(hw_rate * @as(f64, @floatFromInt(max_seconds)));
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    if (buf.len < want) {
        if (buf.len > 0) gpa.free(buf);
        buf = &.{};
        buf = gpa.alloc(f32, want) catch return error.OutOfMemory;
    }
    len = 0;
    full = false;
    rate = hw_rate;
    recording = true;
    // The tap's format: nil = the bus's own (a different rate is not
    // allowed on the input node; stop() resamples).
    msgSend(void, input, sel("installTapOnBus:bufferSize:format:block:"), .{ @as(objc.NSUInteger, 0), @as(u32, 4096), @as(?*Object, null), &tap_block });
    msgSend(void, e, sel("prepare"), .{});
    if (msgSend(objc.BOOL, e, sel("startAndReturnError:"), .{&err}) == 0) {
        recording = false;
        msgSend(void, input, sel("removeTapOnBus:"), .{@as(objc.NSUInteger, 0)});
        return error.EngineFailed;
    }
}

/// App thread: stop recording; the clip as 16 kHz mono f32 (caller
/// frees), or null if nothing was recorded.
pub fn stop() ?[]f32 {
    const e = engine orelse return null;
    const pool = objc.AutoreleasePool.push();
    defer pool.pop();
    if (msgSend(?*Object, e, sel("inputNode"), .{})) |input| msgSend(void, input, sel("removeTapOnBus:"), .{@as(objc.NSUInteger, 0)});
    msgSend(void, e, sel("stop"), .{});
    if (session()) |s| deactivate(s);
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    const was = recording;
    recording = false;
    if (!was or len == 0) return null;
    const hz: u32 = @intFromFloat(@round(rate));
    return stt.audio.resample(gpa, buf[0..len], hz, sample_rate) catch null;
}

fn deactivate(s: *Object) void {
    _ = msgSend(objc.BOOL, s, sel("setActive:withOptions:error:"), .{ objc.NO, option_notify_others, @as(?*?*Object, null) });
}

/// The input the shared rule picks among the session's available ones
/// (a wired or Bluetooth headset before the built-in microphone).
fn choosePreferredInput(s: *Object) void {
    const inputs = msgSend(?*Object, s, sel("availableInputs"), .{}) orelse return;
    var list: mics.List = .{};
    const n = msgSend(objc.NSUInteger, inputs, sel("count"), .{});
    var i: objc.NSUInteger = 0;
    while (i < n and list.len < mics.max_endpoints) : (i += 1) {
        const port = msgSend(?*Object, inputs, sel("objectAtIndex:"), .{i});
        const p = mics.fromApplePort(objc.stringBytes(msgSend(?*Object, port, sel("portType"), .{})));
        var ep: mics.Endpoint = .{ .kind = p.kind, .bus = p.bus, .default_console = p.bus == .builtin };
        ep.id.set(objc.stringBytes(msgSend(?*Object, port, sel("UID"), .{})));
        ep.name.set(objc.stringBytes(msgSend(?*Object, port, sel("portName"), .{})));
        list.append(ep);
    }
    const c = mics.choose(&list, .automatic) orelse return;
    const port = msgSend(?*Object, inputs, sel("objectAtIndex:"), .{@as(objc.NSUInteger, c.index)});
    _ = msgSend(objc.BOOL, s, sel("setPreferredInput:error:"), .{ port, @as(?*?*Object, null) });
    const name = list.items[c.index].name.get();
    mutex.lockUncancelable(io);
    @memcpy(name_buf[0..name.len], name);
    name_len = name.len;
    mutex.unlock(io);
}

var tap_block: objc.Block = objc.Block.global(@ptrCast(&tapped));

/// The tap (AVAudioEngine's thread): the first channel of `pcm` (an
/// AVAudioPCMBuffer, deinterleaved f32) onto the clip.
fn tapped(_: *const objc.Block, pcm: ?*Object, _: ?*Object) callconv(.c) void {
    const frames = msgSend(u32, pcm, sel("frameLength"), .{});
    const channels = msgSend(?[*]const [*]const f32, pcm, sel("floatChannelData"), .{}) orelse return;
    const samples = channels[0][0..frames];
    var wake = false;
    mutex.lockUncancelable(io);
    if (recording and !full) {
        const n = @min(samples.len, buf.len - len);
        @memcpy(buf[len..][0..n], samples[0..n]);
        len += n;
        if (len == buf.len) {
            full = true;
            wake = true;
        }
    }
    mutex.unlock(io);
    if (wake) ios.postEvent(.expose);
}
