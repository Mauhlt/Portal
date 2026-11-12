# portal-client

Native viewer for a Portal session (Windows, Linux, macOS), drawn with the
owner's Vulkan Renderer. Implements `docs/protocol.md`: device pairing,
rotating sign-in, the WebSocket grid stream and key-name input.

```
portal-client --server 10.8.0.1:8420          # connect; pair on first use
portal-client --server 10.8.0.1:8420 --forget # delete this device's credential
```

First run: at the desktop run `portal pair <name>`, then click **Pair** (or
press P) in the client within 2 minutes. After that the client signs in by
itself on every launch and reconnect.

## Build

```
zig build                                  # zig-out/bin/portal-client(.exe), portal-mock-server
zig build test                             # unit tests + compile checks (Debug, ReleaseSafe, mock)
zig build -Dtarget=x86_64-linux-gnu        # cross-compiles without any SDK
zig build -Dtarget=aarch64-macos
```

`build.zig.zon` points at the Renderer worktree (`../../Renderer-wt-portal`,
branch `portal-client`). After that branch is merged, change it to
`../../Renderer`.

## Layout

| Path | What |
|---|---|
| `src/view/` | **Module `view`**: reusable, no networking. `TermView` (window, Instanced2D drawing, fit/zoom, cursor, answer bar, status line), `grid.zig` (cell snapshot model mirroring `src/vt.zig`), `input.zig` (Key/Mods/Event, `InputSink`), `platform/` (Win32, X11, Cocoa), `font/` (TrueType parser, rasteriser, system fonts, atlas), `wcwidth.zig` (copy of `src/vt_width.zig`). Imports only `std` and `Renderer`. |
| `src/gframe.zig` | 'G' frame decoder into `view.grid.Grid` (remote grid source). |
| `src/keys.zig` | Protocol key names per `hello.input` mode. |
| `src/remote.zig` | `RemoteSink` (InputSink → protocol frames) and the overlay (pairing screen, status). |
| `src/net/` | `http.zig` (requests, strict response/Set-Cookie parsing), `ws.zig` (masked client frames, server frame parser), `client.zig` (connection thread). |
| `src/credstore.zig` | OS credential store: Windows Credential Manager; macOS Keychain and Linux Secret Service (libsecret) via dlopen. |
| `tools/mock_server.zig` | Mock Portal server for end-to-end tests. |

For `portal run`'s future local GUI: import `view`, fill a `Grid` from
`vt.Terminal` (same `Kind`/attrs/colour sentinels), implement an
`InputSink` that writes VT bytes to the PTY, and use `.sizing = .fixed_em`
so `InputSink.resized` reports the cols/rows to give the PTY.

## Security

* The device credential is stored only in the OS credential store under
  `Portal/<server host>`; the rotated value is saved before anything else is
  done with the response. The session cookie stays in memory. Nothing secret
  is accepted on the command line, written to files, or logged. A 401 from
  `/auth/refresh` deletes the stored credential.
* If the credential store is unavailable (e.g. Linux without a Secret
  Service), the client refuses to pair instead of falling back to a file.
* `--server` must be a literal IP:PORT (no DNS); Host and Origin are derived
  from its canonical form.
* WebSocket client frames are masked with keys from the OS CSPRNG; the
  Sec-WebSocket-Accept value is verified. Server frames must be unmasked,
  unfragmented, at most 8 MiB; anything else drops the connection.
* Grid frames, HTTP responses and font files are untrusted: bounded,
  validated, fuzz-tested, never panic. A malformed grid frame drops the
  connection (the reconnect brings a fresh snapshot).

## Testing

`tools/mock_server.zig` implements `/pair` (single-use window), `/auth/refresh`
(rotation, 10-minute grace for the previous secret, revocation on a stale
secret, source-address binding) and `/ws` (scripted snapshot, diffs, colours,
attributes, wide characters, a resize), and logs every client frame:

```
zig-out/bin/portal-mock-server --input keys --pair-window 120 --resize-after 8 --revoke-after 0
zig-out/bin/portal-client --server 127.0.0.1:18420
```

## Status

Tested on Windows 11 (NVIDIA): pairing, refresh/rotation across restarts,
revocation and logout back to the pairing screen, keys/text/answer-bar
input, grid resize, window resize, against both the mock server and the real
Portal server (`portal run` + `portal pair`).

Not yet tested:

* Linux (X11) and macOS (Cocoa/MoltenVK) backends, Keychain and libsecret:
  compile-checked by cross-compilation only, never run.
* Zoom keys (Ctrl+= / Ctrl+- / Ctrl+0) and HiDPI scaling > 100% were not
  exercised by the automated run.
* No IME/compose input on X11; no Wayland backend; macOS needs arm64.
* Connect timeouts: std's Io.Threaded panics on connect timeouts in this Zig
  version, so the OS default applies (about 21 s on Windows). No WebSocket
  keepalive ping: a silently dead peer is detected only by TCP.
