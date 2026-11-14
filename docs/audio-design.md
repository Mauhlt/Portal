# Voice input: microphones, headset detection, the 🎤 path

**Owner decisions (2026-11-12, revised):**
* Voice fills the input box of the split layout, on every device.
* **iPhone:** speech stays on the phone. Apple keyboard dictation types into
  the input box, and only the resulting text goes up over HTTPS. Portal
  sends no audio from the iPhone.
* **Laptop (Snapdragon X):** the owner's own transformer runs locally on the
  NPU (`stt.Local` via QNN bindings from the TranslateNPU repo). The model,
  the adapter and the `stt-local` program are delivered by signed Portal
  sync when the laptop is paired, and need approval on the laptop. No audio
  leaves the laptop.
* **Desktop window:** `stt.Home` on the desktop GPU, which is also where
  training happens. Laptop corrections come home as bundles.
* **Mic default:** a headset mic when one is connected, otherwise the
  built-in mic, on the laptop and on the iPhone (iOS already routes
  dictation to AirPods or a wired headset).

## Flow (laptop and desktop)

1. **Capture:** Windows WASAPI from Zig, event-driven
   (`AUDCLNT_STREAMFLAGS_EVENTCALLBACK`, no polling). Capture is Portal's
   job; nothing else captures audio.
2. **16 kHz mono PCM:** ask WASAPI for it (`AUTOCONVERTPCM`). Any audio
   format work (resampling, WAV/QOA for the Test button) comes from the
   owner's `../Audio` library, never from code inside Portal; anything Audio
   lacks is added there. See `docs/stt-sync-contract.md` for who owns what.
3. **Transcribe locally:** `stt.Local.transcribe` on the laptop NPU, or
   `stt.Home.transcribe` on the desktop GPU.
4. The text fills the input box. The user edits and sends; edits become
   `feedback(id, corrected, true)`. Laptop feedback is exported as bundles
   and synced home for training.

## Microphone selection (Windows)

* **Enumeration:** list capture endpoints via IMMDeviceEnumerator, with
  friendly name, form factor (PKEY_AudioEndpoint_FormFactor: Headset,
  Headphones, Microphone, LineLevel, …) and bus (USB, Bluetooth, built-in).
* **Change notifications:** IMMNotificationClient for device
  added/removed/state changes and default-device changes. Event-driven
  re-selection.
* **Automatic mode (default):** prefer a connected headset mic (Headset /
  Bluetooth hands-free / USB headset), otherwise the default communications
  capture device, otherwise the default console capture device. Switch when
  a headset connects or disconnects, even mid-session, and show a toast in
  the app.
* **Manual mode:** pick a specific device, stored by endpoint id; fall back
  to Automatic if it disappears.
* **App UI** (Audio settings panel):
  * device list with type icons;
  * Automatic toggle;
  * live input-level meter;
  * "Test" (record 3 s, show the transcription);
  * the active mic shown next to 🎤.
* **Bluetooth note:** opening a Bluetooth headset mic switches it into the
  hands-free profile (lower playback quality) while recording, as in Teams
  or Zoom.

## iPhone

iOS chooses the route itself: AirPods or a wired headset automatically when
connected, otherwise the phone mic. That matches the owner's default.
Speech is Apple keyboard dictation into the input box, and the page shows
the active input where the platform reports it.

## Privacy

* Audio only flows while 🎤 is held or toggled on, with a visible recording
  indicator.
* No background capture.
* Laptop samples stay on the laptop until synced home as bundles. Home
  storage follows stt's rules (unpairing never deletes samples; the
  owner's decision).

## Built (desktop, 2026-11-14)

* `src/speech` (module "speech"): `mics.zig` (headset-first choice),
  `capture.zig` (the microphone thread: one WaitForMultipleObjects on
  stop / command / device change / audio ready; records only while the 🎤
  or the Audio panel's meter wants it), `wasapi.zig` (IMMDeviceEnumerator,
  IMMNotificationClient, shared-mode EVENTCALLBACK + AUTOCONVERTPCM at
  16 kHz mono s16le), `home.zig` (stt.Home on the GPU, the contract's one
  deadline-driven waiter), `limits.zig` + `gate.zig` (abuse limits).
* `src/deskspeech.zig`: the desk window's glue; `ui/panels/audio.zig` (the
  Audio panel, top bar "Audio", Ctrl+Shift+A); `ui/dictation.zig` (which
  stt feedback a dictated line becomes); the shell's 🎤 shows the active
  microphone; a toast when a headset connects or disconnects.
* Capture stays in Portal (owner, 2026-11-14): ../Audio does formats
  only, never capture.
* Instruct on the desk (setting `instruct_mode`, Audio panel, applied
  live): `auto` (default) opens the box and records when a microphone works
  and speech is ready, else just opens the box (the 🎤 says why); `type`
  only opens the box (record with the 🎤 or the headset key); `record` as
  auto, but says once why it can't record. "A microphone works" is
  re-evaluated on every device change (IMMNotificationClient), no polling.
  Devices are not affected.
* `zig build mic-check -- <seconds>` records from the real microphone and
  prints the transcript (manual check, never part of `test`).
* Not yet: the training banner, the laptop's stt-local client, the
  device-facing /sync bundle and update routes (they must call
  `speech.gate.Gate`, see below).

## Limits (src/speech/limits.zig `Config`; settings.txt `speech.<name>`)

Desk-only (no device can change them), clamped on load, applied live by
the Audio panel's "Reload limits". Every refusal names the limit and when
it frees up. Rolling windows are fixed slots (60 x 1 min, 24 x 1 h).

| name | default | range | meaning |
|---|---|---|---|
| clip_max_s | 120 | 1-120 | longest utterance (buffer allocated once for 120 s) |
| clip_min_ms | 250 | 50-5000 | shorter clips: no stt call |
| transcribe_burst / _refill_ms | 10 / 6000 | 1-100 / 100-3600000 | per-minute bucket (10/min) |
| transcribe_per_hour / _per_day | 300 / 2000 | 1-100000 / 1-1000000 | rolling caps |
| job_timeout_s | 60 | 5-600 | a transcription not back is dropped |
| feedback_burst / _refill_ms | 5 / 6000 | 1-100 / 100-3600000 | corrections bucket, per source |
| feedback_per_hour / _per_day | 120 / 1000 | 1-100000 / 1-1000000 | rolling caps, per source |
| text_max | 8192 | 256-8192 | transcript / correction bytes |
| feedback_queue | 16 | 1-64 | queued feedback calls (oldest dropped) |
| kept_clips_per_day | 500 | 1-100000 | clips kept as training samples per source |
| bundles_per_day | 50 | 1-10000 | training bundles per device |
| bundle_mib_per_day | 100 | 1-10240 | bundle MiB per device |
| bundle_max_kib | 5120 | 64-5120 | one bundle |
| concurrent_devices | 3 | 1-16 | devices doing speech traffic at once (desk mic not counted) |
| global_feedback_per_hour | 300 | 1-100000 | all devices together |
| global_kept_clips_per_day | 1000 | 1-1000000 | all devices together |
| global_bundles_per_day | 100 | 1-100000 | all devices together |
| global_bundle_mib_per_day | 250 | 1-102400 | all devices together |
| payload_budget_mib | 16 | 1-64 | device payloads in flight, summed |
| read_timeout_s | 30 | 1-300 | body read deadline (slow-loris) |
| malformed_strikes / _window_min | 3 / 10 | 1-100 / 1-60 | then the device's speech traffic closes until it reconnects |
| slot_max_hold_s | 300 | 10-3600 | longest hold on a speech slot |
| slot_idle_s | 60 | 5-600 | idle release |
| slot_cooldown_s | 30 | 1-600 | re-acquire wait after expiry while others wait |

Fixed: one transcription in flight (others Busy), one bundle import and
one update export queued at most, all on the engine's one thread (the
desk's transcription first); 64 pending feedback ids; 16 device names.
