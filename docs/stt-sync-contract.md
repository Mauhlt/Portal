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

Pending bundles are stored per paired device name. Unpairing deletes that
device's pending bundles. Whether to purge samples already imported is the
owner's decision.

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

* **iPhone:** running the model in wasm is unproven. The proposed thin-client
  alternative:
  * the iPhone records audio (file input, or the mic once HTTPS lands, see
    `feat/tls`);
  * it uploads the audio through Portal;
  * the desktop or a laptop transcribes it.
* **Purging:** should unpairing also purge samples already imported?
