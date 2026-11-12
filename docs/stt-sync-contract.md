# Speech-to-text: how Portal and stt fit together

**Status (2026-11-12):** the stt side exists (SpeechToText repo: `stt.Home`,
`stt.Local`, the `stt-local` program, proto 1). Portal's side is not built
yet; this is the contract it will implement. The owner says when.

## Who does what

Each project has one job, and no job is done twice:

| Piece | Owns | Never does |
|---|---|---|
| **Portal** | transport (HTTPS/WSS over WireGuard), pairing and auth, signed package sync, the window/UI on every device, mic capture (WASAPI), starting `stt-local` | speech recognition, training, audio file formats |
| **stt** (SpeechToText) | transcription, feedback, learning, training, bundles/updates as opaque blobs | sockets, servers, mic capture, UI, child processes |
| **Audio** (`../Audio`) | WAV / QOA / MP3 decode and encode, PCM sample handling | capture, playback |
| **TranslateNPU** (`../TranslateNPU`) | QNN bindings for the Snapdragon NPU (used by stt) | anything Portal-facing |

Portal has no audio-format code of its own: anything it needs to encode or
decode (e.g. a WAV for the "Test" button in the audio panel) comes from
`../Audio`. If something is missing there (resampling, for instance), it is
added to Audio, not to Portal.

## Per device

| Device | Speech | Runs where | Audio leaves the device? |
|---|---|---|---|
| **Desktop** (Portal's own window) | `stt.Home` linked into Portal, NVIDIA GPU; also trains | in-process | no |
| **Laptop** (Snapdragon X) | `stt-local` child process wrapping `stt.Local`, on the NPU (QNN) | delivered by signed sync, approved on the laptop | no; only training bundles go home |
| **iPhone** | Apple keyboard dictation into the input box | iOS | no; only the resulting text |

So no device uploads audio for transcription, and Portal has no
`/stt/transcribe` endpoint.

## Desktop: `stt.Home` (SpeechToText src/home.zig; thread-safe)

```zig
const home = try stt.Home.open(gpa, io, .{ .model_path = ..., .profile_dir = ... });
defer home.close();
const r = try home.transcribe(gpa, audio_bytes, "desk");   // WAV/MP3/QOA, any rate/channels -> Result{ id, text }; caller frees text
const o = try home.feedback(r.id, corrected_text, true);    // !Outcome; discard = (id, _, false); silence = no call
try home.setLearning(enabled);                              // !void
const rep = try home.importBundle(gpa, bundle_bytes);       // !sync.ImportReport (bundles from laptops)
const up = try home.exportUpdate(gpa, device_version);      // !?[]u8; null = device is current
const next: ?i64 = home.tick();                             // unix ms of the next timed work, null = none
const st = home.trainingStatus();                           // stt.schedule.Status
try home.trainNow(); home.cancelTraining(); home.setSchedule(cfg); home.setListener(listener);
home.setWakeup(.{ .ctx = portal, .onWakeup = onWakeup });   // fn (ctx, deadline_unix_ms: ?i64) void
```

* **Build:** stt depends on `../Audio` and `../TranslateNPU` (path
  dependencies, checked out next to SpeechToText).
* **Event-driven:** the only timed work is auto-confirming a transcript after
  60 s of silence and starting training when its window opens.
  * `onWakeup` fires whenever the deadline can move (transcribe, feedback,
    setLearning, importBundle, setSchedule, a run finishing). It may fire on
    the training thread: Portal only re-arms its wait there and never calls
    into Home from inside it.
  * Portal's loop: one waiter sleeps until the latest deadline, calls
    `tick()`, then sleeps until tick's return value (null = until the next
    event). Nothing wakes on a fixed interval.
* **Unpairing never deletes samples** (owner decision): pending bundles from
  an unpaired laptop are still imported.

## Laptop: `stt-local`, proto 1 (SpeechToText src/local_main.zig)

`stt-local` is a package delivered by signed sync (executable, approval
required), with `stt-model` and `stt-adapter` as data packages. Portal starts
it as a child process; see "Running delivered programs" in
`docs/sync-design.md`.

* **Framing:** JSON lines on stdin/stdout, at most 8 MiB per line; logs on
  stderr. The first line is
  `{"event":"ready","proto":1,"version":"…","backend":"htp|cpu|cuda","model":"…","adapter_version":N}`.
  Every request carries `rid` and its reply echoes it.
* **Requests:**
  * `transcribe` with `pcm_s16le_b64` (16 kHz mono, preferred) or `wav_b64`
    → `{"rid","id","text"}`. At most 120 s of audio (else `too_long`).
    `id 0` = nothing heard, so no feedback is possible.
  * `feedback` `{"id","text","ok"}` → `outcome` learned / discarded.
  * `export_bundle` `{"max_bytes"}` → `{"b64","through","count","version"}`
    (`b64` null when nothing is pending). stt-local caps a bundle at 5 MiB.
  * `commit_export` `{"through"}` — only after the desktop stored the bundle.
  * `import_update` `{"b64"}` → `{"version"}`.
  * `set_learning` `{"on"}`, `status`.
* **Errors:** `{"rid","error","message"}` with codes `bad_request`,
  `bad_audio`, `too_long`, `busy`, `backend_lost` (restart the process),
  `unknown_id`, `not_found`, `internal`.
* **Events:** `{"event":"wakeup","deadline_unix_ms":N|null}`; stt-local runs
  its own tick at that deadline. Portal stops it by closing stdin.
* **Sandbox:** no network, sockets or child processes; writes only under its
  `--profile` dir (`sync\data\stt-local\` in the per-desktop sync folder).
* **Capture:** Portal records 16 kHz mono s16le from WASAPI (event-driven,
  `AUDCLNT_STREAMFLAGS_EVENTCALLBACK`, with `AUTOCONVERTPCM` to get 16 kHz;
  any conversion Windows can't do goes into `../Audio`) and sends
  `pcm_s16le_b64`.

## Laptop → desktop: training data (proposed endpoints, not built)

All require a live session from a paired device; the device name comes from
the session, never from the request. Payloads are opaque to Portal.

| Endpoint | Body / reply |
|---|---|
| `POST /sync/bundle?device_version=N` | a bundle from `export_bundle`, ≤ 5 MiB; 200 only after `home.importBundle` returned and the data is durable, then the laptop sends `commit_export`; 400 bad bundle |
| `GET /sync/update?version=N` | 200 + update from `home.exportUpdate`, or 204 if current; the laptop passes it to `import_update` |

* **Order:** `export_bundle` → POST → `commit_export` (repeat while more is
  pending), then GET update → `import_update`. Event-driven: run on connect,
  after feedback, and when the desk signals a new adapter version; no timers.
* **Open item for the stt session:** updates travel as one base64 line, so
  an update above ~6 MiB raw can't fit `import_update`'s 8 MiB line. Either
  stt-local raises `max_line` or splits updates; until then Portal refuses
  updates over 6 MiB.

## Training status

* **Schedule:** training starts only inside a daily local-time window
  (default 02:00–06:00), once 20 new samples arrived since the last adapter.
  `trainNow()` ignores the window.
* **Status fields:** `state` idle | waiting_for_window | running;
  `pending_samples` / `min_new_samples`; `next_start_unix`; `started_unix`,
  `progress`, `eta_seconds`, `epoch`/`epochs`; `version`;
  `last_finished_unix`, `last_loss`, `last_samples`, `last_error`.
* **Events:** started, progress, finished, failed, canceled (each with a
  Status). started/progress fire on the training thread: keep handlers quick.
* **Portal UI:** a top-bar banner on every device while running ("Training on
  GPU — other GPU work may be slower (ETA …)"), cleared when it ends; the next
  start time while waiting. Train now / Cancel are desk-only. The status
  travels to devices as `{"t":"training",…}` on the WebSocket, sent only on
  change.
