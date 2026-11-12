# Voice input: microphones, headset detection, the 🎤 path

**Owner decisions (2026-11-12):**
* Voice fills the input box of the split layout.
* The laptop mic feeds the owner's own speech model, not Win+H. It runs on
  the desktop GPU over HTTPS now, and later on the laptop's NPU.
* Headphones are detected and their mic used automatically, with Zoom/Teams
  style device choice in the app.

## Flow

1. **Capture** on the device: Windows WASAPI from Zig, event-driven
   (`AUDCLNT_STREAMFLAGS_EVENTCALLBACK`, no polling). The iPhone uses
   getUserMedia + AudioWorklet through the JS bridge, which passes raw
   Float32 buffers only.
2. **Encode in Zig:** 16 kHz mono, WAV (or QOA).
3. **Transcribe:**
   * **now:** `POST /stt/transcribe` to the desktop, where `stt.Home` runs on
     the GPU;
   * **later on the laptop:** `stt.Local` on the Snapdragon NPU (QNN), same
     API.
4. The text fills the input box. The user edits it and sends; edits become
   `feedback(id, corrected, true)`, unchanged sends confirm.

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

iOS chooses the route itself (AirPods or a wired headset automatically when
connected). The page shows the active input label. Apple keyboard dictation
remains the default; 🎤 (own model) records over HTTPS.

## Privacy

* Audio only flows while 🎤 is held or toggled on, with a visible recording
  indicator.
* No background capture.
* Samples are stored by stt on the desktop per its rules (unpairing doesn't
  delete them; the owner's decision).
