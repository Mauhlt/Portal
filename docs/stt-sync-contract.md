# Speech-to-text: how Portal and stt fit together

**Status (2026-11-14):** both sides exist. The desk runs `stt.Home`
(src/speech/home.zig), the iPhone `stt.Local` on Core ML
(client/src/ios/speech.zig), and a Windows laptop or Surface runs the
delivered `stt-local` as a child process (src/speech/local.zig, the
protocol client and supervisor; src/devicespeech.zig, the 🎤 and the
samples home). The NPU path is compile-checked only until it runs on the
laptop.

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
| **iPhone** | `stt.Local` on Core ML (client/src/ios/speech.zig), home's adapter from the `stt-adapter` package | in-process | no; only training bundles go home (learning on) |

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
* **Unpairing never deletes samples** (owner decision): what the desk
  stored from an unpaired laptop stays in the profile. A bundle not stored
  yet (still queued for import, or its body on the way) when its device is
  unpaired or replaced by a new pairing under its name is refused instead
  (src/speech/inbox.zig `retain`, from the device store watch); the device
  never got its "ok", so it never deleted those samples.

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

### Portal's side on the laptop (built)

* **Packages:** full sync (`Platform.sync = .full`) installs `stt-local`
  (approved on the device), `stt-model` and `stt-adapter` into this
  desktop's sync folder. After every pass the speech glue
  (src/devicespeech.zig) gets their folders (`SpeechSync.packages`,
  `installed`, `checked`).
* **Which machine:** the package has no architecture of its own. The desk
  builds stt-local for aarch64 Windows, so the device reads the
  program's PE header first (`speech.local.fitsThisMachine`). On an
  x86_64 PC, or with no stt-local installed, the 🎤 says speech is
  unavailable on this device. No CPU fallback is offered.
* **Running it:** `speech.local.Engine` starts
  `stt-local --model <stt-model>\ggml-base.en.bin --profile
  <desktop folder>\data\stt-local --device-name laptop [--adapter <file>
  --adapter-version <n>]`. Its cwd is its own read-only folder. stt-local
  finds the QNN runtime the drivers installed (no `--qnn`). The program
  starts when a recording starts. For a sync pass it starts only when
  samples wait in `<profile>\samples`. It stops 60 s after the last
  dictation, or later if stt's silence deadline is later. On exit the
  pipe closes and it stops by itself.
* **Supervision:** one call at a time, each with a deadline: ready 300 s
  (the first NPU graph compile), transcribe 300 s, others 60 s. A hang is
  killed. A crash, a `backend_lost` reply or a broken line fails the call
  in flight. The next call starts a new program after a backoff (1 s,
  doubling, at most 60 s). After 5 crashes in a row it gives up until a
  new package or the next 🎤.
* **Adapter:** an `update.bin` is sent to the running program with
  `import_update` (a live swap). A raw `adapter.bin` is passed at the
  next start, and the program restarts at the next idle moment. The 🎤
  shows "your voice vN", the same text as on the iPhone
  (`ui.dictation.voiceLabel`).
* **Samples home:** with `speech_learning` on (the default):
  `export_bundle` → `put bundle` → `commit_export`, only after the desk's
  200 (`connect.sendSamples`). With it off, nothing is sent.

### Publishing the laptop's engine (automatic, with each desk release)

`zig build release` publishes the engine and the model by itself once the
desk's own release is promoted (src/tools/release.zig `publishVoice`):

1. The new release's `portalctl voice-publish --enabled` checks the Audio
   panel's **Publish the laptop speech engine** (settings.txt
   `speech_publish_engine = on|off`, default on). Off: nothing is built or
   published, and the release says so.
2. `zig build voice-packages --prefix <releases>\_voice`: stt-local for
   aarch64 Windows (fetches the QAIRT SDK, or `-Dsdk` / `QNN_SDK_ROOT`) and
   the pinned model (src/speech/model_pin.zig, size and SHA-256 checked).
3. `portalctl voice-publish <releases>\_voice\voice`: each package goes
   through `sync.publish` (what `portalctl publish` and the adapter's
   auto-publish run), signed by the desk's release key, **only when its
   content changed**: `sync.sameAsLatest` compares every file's path, size
   and SHA-256 with the newest published version's manifest, so a rebuilt
   but identical engine, or the same model, adds no version (and the laptop
   is not asked to approve one).
   * `stt-local` (executable): version `<Portal version>+<sequence>`, e.g.
     `0.1.0+4`.
   * `stt-model` (data): version `<first 16 hex of the pin's SHA-256>+<sequence>`.
   * The sequence only goes up and is never reused, so the names are unique
     and devices order versions by it. Only the newest 3 of each stay
     published (`sync.prune`).

A failure (the SDK fetch, the cross-build, the model download, no release
key) never fails the desk's release: it ends with a WARNING line saying the
laptop speech engine was NOT published, and devices keep what they have.
Each run's result is one line in `%LOCALAPPDATA%\Portal\voice-engine.txt`;
the desk logs it when it starts and shows it in the Audio panel (red when
nothing was published). With the PORTAL_RELEASES_DIR testing override
nothing is built or published.

**Subscriptions follow the platform.** Every paired device is subscribed to
`stt-adapter`. A device reports its platform after each hello
(`d:platform`, docs/protocol.md section 4; kept in memory,
web.PlatformTable); the first time this run that a device says
`windows-aarch64`, the desk subscribes it to `stt-local` and `stt-model`
too (main.zig `StoreWatch.platformReported`, sync.autoSubscribe). Until it
says, and on any other platform, it gets the adapter alone. Unsubscribing
(Devices panel or `portalctl sync unsubscribe`) records an opt-out that
automatic subscription never undoes.

## Device → desktop: training data

**Built (the iPhone uses it):** `put bundle <len>` on the bulk WebSocket
(docs/protocol.md section 7): a bundle from `exportBundle`, the desk's
"ok" only after `Home.importBundle` returned (home.Engine.importBundleWait,
behind src/speech/inbox.zig and gate.zig), then the device's
`commitExport`. Adapters come back as the signed `stt-adapter` package
(an update file or a raw adapter), not as a reply. The proposal below is
what it replaced.

**Adapters go out by themselves** (src/voiceshare.zig): when a training
run finishes (Home's `finished` event), when Home opens, and when the
desk switches "Share voice improvements with devices" on (Audio panel,
settings.txt `speech_share = on|off`, default on), the engine asks
`exportUpdate(<newest published version>)`; a newer adapter becomes the
next `stt-adapter` version (its number = the adapter version) through
`sync.publish`, the code `portalctl publish` runs: `update.bin` (the
update) and `adapter.bin` (the raw adapter from it). SyncWatch sees the
new version and sends `{"t":"updates"}` to every subscribed device; only
the newest 3 versions stay published (`sync.prune`). Logged, and shown in
the Audio panel ("Your voice v7 published to devices"). Off: nothing is
published.

### The earlier proposal

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
