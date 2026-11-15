//! The speech base model, in one place. A personal adapter trained at home
//! only fits the exact base model it was trained on, so every device runs
//! the same file, byte for byte:
//!
//!   desk     stt.Home loads <data dir>/models/<file_name>
//!            (deskspeech.defaultModel; `speech_model` in settings.txt
//!            overrides it, and must then be this same file);
//!   iPhone   Portal.app bundles stt/<file_name>, downloaded by build.zig
//!            from `url` and kept only if its size and SHA-256 are these
//!            (src/tools/fetch_file.zig; -Dios-model=<path> bundles a local
//!            copy instead);
//!   laptop   the `stt-model` package the desk publishes, from the same file.
//!
//! The pin: the whisper.cpp project's ggml base.en on Hugging Face, at a
//! fixed commit of that repository (OpenAI's Whisper weights, MIT; the
//! notice is in docs/ios-licenses.txt). Imported by build.zig too, so a
//! change here is the only change.

pub const file_name = "ggml-base.en.bin";
pub const url = "https://huggingface.co/ggerganov/whisper.cpp/resolve/5359861c739e955e79d9a303bcbc70fb988958b1/" ++ file_name;
pub const sha256_hex = "a03779c86df3323075f5e796cb2ce5029f00ec8869eee3fdfb897afe36c6d002";
pub const size: u64 = 147964211;

test "the pin is well formed" {
    const std = @import("std");
    try std.testing.expectEqual(@as(usize, 64), sha256_hex.len);
    var b: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, sha256_hex);
    try std.testing.expect(std.mem.endsWith(u8, url, "/" ++ file_name));
}
