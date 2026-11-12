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
   (`AUDCLNT_STREAMFLAGS_EVENTCALLBACK`, no polling).
2. **Encode in Zig:** 16 kHz mono PCM.
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
