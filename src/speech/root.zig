//! Module "speech": Portal's side of speech input on Windows
//! (docs/audio-design.md, docs/stt-sync-contract.md).
//!
//!   limits    the abuse limits: clip length, one in flight, rates,
//!             text and WAV sizes, per-device feedback buckets
//!   mics      capture endpoints and the headset-first choice (pure rules)
//!   capture   the microphone thread: records only while asked, follows
//!             device changes; a backend interface (fake one for tests)
//!   wasapi    the real backend: IMMDeviceEnumerator, IMMNotificationClient,
//!             event-driven shared-mode capture at 16 kHz mono s16le
//!   home      the desktop engine: stt.Home on the GPU in-process, one
//!             deadline-driven waiter thread (x86_64 Windows builds only)
//!   local     the laptop engine: stt-local as a child process, protocol 1
//!
//! Portal does no audio-format work of its own: the WAV handed to stt is
//! encoded by ../Audio, and transcription is stt's.

const options = @import("speech_options");

pub const sys = @import("sys.zig");
/// Every speech limit (clip length, rates, sizes) in one place.
pub const limits = @import("limits.zig");
/// The desktop's gate for device speech traffic (future /sync routes).
pub const gate = @import("gate.zig");
pub const mics = @import("mics.zig");
pub const capture = @import("capture.zig");
pub const wasapi = @import("wasapi.zig");
pub const local = @import("local.zig");
/// stt.Home in-process: only where it is linked (the x86_64 desktop).
pub const has_home = options.home;
pub const home = if (options.home) @import("home.zig") else struct {};

test {
    _ = sys;
    _ = limits;
    _ = gate;
    _ = mics;
    _ = capture;
    _ = wasapi;
    _ = local;
    if (options.home) _ = @import("tests.zig");
}
