# Speech-to-text sync: contract on file (not implemented)

**Status:** parked. The owner will say when to integrate their `stt` module
(SpeechToText repo, formerly named TextToSpeech). Nothing in Portal implements this yet.

## Proposed Portal endpoints

All endpoints require a live session from a paired device. Payloads are
opaque to Portal.

| Endpoint | Body / reply |
|---|---|
| `POST /sync/bundle?device_version=N` | opaque bundle, Content-Length ≤ 8 MB (limit = max(cap, ~1.1 MB)); `200` only after a durable write (fsync) = ack; `400` on `error.BadBundle` / `error.Truncated` |
| `GET /sync/update?version=N` | `200` + opaque update (≤ 16 MB), or `204` if the device is current |

Pending bundles are stored per paired device name.

**Unpairing never deletes samples (owner's decision: "those will be used for
training").** On unpair, Portal *imports* that device's pending bundles with
`stt.sync.importBundle` rather than deleting them. Samples already at home are
never purged by Portal; stt manages its own storage cap (50 GB, see below).

## Thin client: the iPhone, for now (owner's decision)

Until the owner confirms the models can run on the iPhone, the iPhone only
records audio. The desktop transcribes it and learns from feedback, with no
bundle round trip: samples go straight into the home profile, tagged
`source=<device_name>`.

| Endpoint (suggested) | Body / reply |
|---|---|
| `POST /stt/transcribe` | body = WAV (≤ ~4 MB) → `{"id": <u64>, "text": "..."}`; `400` on `error.BadAudio`, `413` on `error.AudioTooLong` (> 120 s) |
| `POST /stt/feedback` | `{"id", "text", "success"}` → outcome `learned` / `discarded` / `unknown_id` / `no_profile` / `failed` |

Both need a live session from a paired device. `device_name` comes from the
session's device tag, never from the client. They're served over the same
hardened HTTP layer, with explicit body limits.

```zig
var svc = try stt.Service.init(gpa, io, &transcriber, &home_profile, .{}); // own stt.Transcriber; several can share one stt.Model
const r = try svc.transcribeWav(gpa, wav_bytes, device_name);              // Result{ id: u64, text: []u8 }; caller frees text; id 0 = empty transcript
_ = try svc.feedback(id, final_text, success);                              // fix = feedback(id, corrected, true)
svc.tick();                                                                 // ~once a second
svc.deinit();                                                               // confirms everything pending
```

* Thread-safe (requests are serialised), so it can be called from HTTP
  handlers. Transcription is slow, so keep it off the accept and supervisor
  paths and give it its own timeout budget.
* Feedback semantics:
  * **fix:** `feedback(id, corrected, true)`;
  * **silence** (no feedback within 60 s, or the id falls out of the
    64-entry window): auto-saved as correct;
  * **"nothing":** learning is off.
* **Audio format: WAV only.** RIFF; PCM 8/16/24/32-bit or float32; any sample
  rate or channel count, resampled internally. stt does **not** decode
  AAC/Opus/WebM (Safari's MediaRecorder output), so the wasm client must
  capture raw PCM and wrap it in a 44-byte WAV header itself. 16 kHz mono
  16-bit is ideal: 32 KB/s, so 120 s ≈ 3.8 MB.
* **Mic in Safari needs HTTPS** (branch `feat/tls`). Raw PCM capture needs
  browser audio APIs that only JS can reach (getUserMedia + AudioWorklet).
  That's a small addition to the JS bridge, which only passes Float32
  buffers to wasm; the WAV encoding is done in Zig.

## Home storage

stt caps home sample storage at 50 GB. Over the cap, `trainIfReady` folds
everything into the weights and deletes the oldest trained audio down to 80%,
keeping every 10th sample as a replay set. No Portal impact.

## stt API (module `stt`)

Device side, with `profile = try stt.Profile.load(gpa, io, dir)`:

```zig
stt.sync.exportBundle(gpa, &profile, device_name, max_bytes) !?stt.sync.Bundle // Bundle{ bytes, through, count }; null = nothing pending / learning off
stt.sync.commitExport(&profile, bundle.through) !void                         // only after 200; deletes those samples
profile.version: u32                                                            // sent as ?device_version=
stt.sync.importUpdate(gpa, &profile, bytes) !u32                               // used on next model load
```

Home side (the desktop):

```zig
stt.sync.importBundle(gpa, &home, bytes) !ImportReport
stt.sync.exportUpdate(gpa, &home, device_version) !?[]u8                         // null = 204
stt.sync.trainIfReady(gpa, io, model_path, &home, .{ .threshold = 20 }, progress) !?u32 // after the response; slow; own model copy
```

The device loops: `exportBundle` → `POST` → `commitExport`, until `exportBundle`
returns null. Then `GET /sync/update`, then `importUpdate`.

## Sizes

* **Sample:** at most ~1 MB (`stt.sync.max_sample_bytes`); typical 100–300 KB.
* **Bundle:** at most `max_bytes`, and always at least one sample.
  `stt.sync.default_bundle_bytes` is 8 MB.
* **Update:** about 1.1 MB (tiny model), 2.2 MB (base) or 6.5 MB (small).

## Open questions for the owner

* **Models on the iPhone:** the owner is checking whether they can run there
  at all. Until then the iPhone is a thin client (section above).
