# Speech-to-text integration: contract on file (not implemented)

**Status:** parked. The owner will say when to integrate their `stt` module
(SpeechToText repo). Nothing in Portal implements this yet.

## Owner decisions

* **stt is GPU-only, on the home desktop**, for both transcription and
  training. There is no CPU path.
* **stt's own transport is gone.** Portal is the only way in: no stt TCP
  server, no `stt.Client`, no stt mic capture or voice detection.
* **Devices are thin clients** (iPhone, laptops). They record audio and
  upload it through Portal; the desktop transcribes and learns.
* **Unpairing never deletes samples** ("those will be used for training").
  Pending bundles from an unpaired device are imported, not deleted.
* **Portal must show training status.** While training runs, warn that
  other GPU work, including transcription, may be slower.

## stt API: `stt.Home` (src/home.zig in SpeechToText; thread-safe)

```zig
const home = try stt.Home.open(gpa, io, .{ .model_path = ..., .profile_dir = ... });
defer home.close();
const r = try home.transcribe(gpa, audio_bytes, device_name); // WAV, MP3 or QOA, any rate/channels -> { id, text }; caller frees text
home.feedback(id, text, success);       // fix = (corrected, true); discard = (_, false); silence = no call (auto-confirmed after 60 s)
home.setLearning(enabled);              // "nothing": learning off
home.importBundle(gpa, bytes);          // device bundles (formats and caps unchanged)
home.exportUpdate(gpa, device_version); // null = device current
home.tick();                            // confirms silence, starts scheduled training, adopts a finished adapter
home.trainingStatus();                  // stt.schedule.Status
home.trainNow(); home.cancelTraining(); home.setSchedule(cfg); home.setListener(listener);
```

* **Build:** stt depends on `../Audio` (path dependency). The Audio repo must
  be checked out next to SpeechToText.
* **Event-driven (agreed, implemented in stt):**
  * `home.tick()` returns `?i64`: the unix-ms deadline of its next timed
    work, or null when nothing is pending. Timed work means auto-confirming
    a transcript after 60 s of silence, or starting training when the window
    opens. Calling it early is harmless.
  * `home.setWakeup(.{ .ctx, .onWakeup = fn (ctx, deadline_unix_ms: ?i64) void })`
    fires on set and whenever the deadline can move: transcribe, feedback,
    setLearning, importBundle, setSchedule, or a training run finishing. It
    may fire on the training thread, so Portal only re-arms its wait in it
    and never calls into Home from inside it.
  * Training completes on its own thread. That thread commits the version,
    merges the adapter, and fires finished/failed/canceled, then onWakeup.
  * **Portal's loop:** one waiter sleeps until the latest deadline (from
    onWakeup or tick's return), calls tick() at that deadline, and sleeps
    until tick's return value; null means wait for the next event. Nothing
    wakes on a fixed interval.

## Training schedule and status

* **Schedule:** training starts automatically only inside a daily local-time
  window (default 02:00–06:00), once 20 new samples have arrived since the
  last adapter version. `trainNow()` ignores the window. A run takes seconds
  to minutes.
* **Status fields:**
  * `state`: idle | waiting_for_window | running;
  * `pending_samples` / `min_new_samples`;
  * `next_start_unix` (when waiting);
  * `started_unix`, `progress` (0–1), `eta_seconds`, `epoch`/`epochs` (while
    running);
  * `version` (the adapter in use);
  * `last_finished_unix`, `last_loss`, `last_samples`, `last_error`.
* **Events:** started, progress, finished, failed and canceled, each with a
  Status.
  * `started` and `progress` fire on the training thread. Keep the handler
    quick and don't call back into Home from it.
  * `started` fires from whichever call started the run (tick or trainNow).
  * `finished`, `failed` and `canceled` fire from the training thread when
    the run ends, with no tick needed.
* **Portal UI:**
  * a top-bar banner on every viewer while running: "Training on GPU —
    other GPU work may be slower (ETA …)";
  * cleared on finished, failed or canceled;
  * when waiting, the next start time.
  * Train now / Cancel controls are **desk-only**.

## Proposed Portal endpoints

All endpoints require a live session from a paired device. `device_name`
comes from the session's device tag, never from the client. Payloads are
opaque, with explicit body limits.

| Endpoint | Body / reply |
|---|---|
| `POST /stt/transcribe` | audio (WAV/MP3/QOA, ≤ ~4 MB, ≤ 120 s) → `{"id", "text"}`; 400 bad audio, 413 too long |
| `POST /stt/feedback` | `{"id", "text", "success"}` |
| `POST /sync/bundle?device_version=N` | opaque bundle ≤ 8 MB; 200 only after a durable write; 400 on bad bundle |
| `GET /sync/update?version=N` | 200 + update ≤ 16 MB, or 204 if current |

Training status travels as a new text message on the existing WebSocket,
`{"t":"training", ...}`, sent only on change (event-driven).

## Audio capture on the iPhone

Safari records only AAC/Opus/WebM through MediaRecorder, and stt accepts WAV,
MP3 or QOA. So the wasm client captures raw PCM through the JS bridge's audio
callback and encodes WAV (or QOA) in Zig. The mic needs HTTPS, which Portal
now serves.
