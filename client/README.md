# portal-client

Native viewer for a Portal session (Windows, Linux, macOS), drawn with the
owner's Vulkan Renderer. Implements `docs/protocol.md`: the device's own
WireGuard tunnel to the desk (in-process: no WireGuard app, adapter or
administrator right), TLS 1.3 with the Portal CA pinned, the interactive
WebSocket (grid stream, key-name input) and the bulk one (sync).

```
portal-client                        # the paired desktop, or the first-run screen
portal-client --key                  # print this device's tunnel key and check code
portal-client --pairing-code CODE    # pair with the code the desk showed
portal-client --forget               # forget the desktop, both ways
```

On Windows the same viewer is built into Portal itself as `portal connect`
(same arguments): `src/connect.zig` is shared by both.

First run (docs/pairing.md): the window shows this device's tunnel key and
its check code. At the desk, Pair a device with that key and compare the
check code; the desk then shows a pairing code, which you enter here (and
compare the desk key's check code it shows). After that the client
connects by itself on every launch.

The window opens on the **Conversation view** (the Terminal | Conversation
toggle is in the top bar; docs/layout-design.md). Device settings live in
`settings.txt` next to the pinned servers (e.g. `%APPDATA%\Portal\settings.txt`):

    # which way a swipe on a Yes/No card says Yes (default left-yes)
    swipe = left-yes

## TLS

The desk sends its Portal CA in its certificate chain. On the first
connection after pairing the client accepts it only if its SHA-256 is the
one in the pairing code, then pins it (`%APPDATA%\Portal\servers\`,
`~/Library/Application Support/Portal/servers/`,
`$XDG_CONFIG_HOME/portal/servers/`); never trust on first use.
`src/net/tlsconn.zig` holds back the server's encrypted handshake flight
until it has checked the certificate itself with bounds-checked code
(`src/net/x509check.zig`): signed by exactly the pinned CA, valid now,
subjectAltName = 10.8.0.1, ECDSA P-256 (this closes std's fallback to the
OS root store on Windows and its unchecked certificate parser).

## Build

```
zig build                                  # zig-out/bin/portal-client(.exe)
zig build test                             # unit tests + compile checks (Debug, ReleaseSafe)
zig build -Dtarget=x86_64-linux-gnu        # cross-compiles without any SDK
zig build -Dtarget=aarch64-macos
```

`build.zig.zon` pins the Renderer, Image and WireGuard commits on GitHub, the
same ones as Portal's root `build.zig.zon` (`zig build pin` at the root bumps
both). Local checkouts: `zig build --fork=../../Renderer --fork=../../Image`.

## Layout

| Path | What |
|---|---|
| `src/view/` | **Module `view`**: reusable, no networking. `TermView` (window, Instanced2D drawing, fit/zoom, cursor, answer bar, status line), `grid.zig` (cell snapshot model mirroring `src/vt.zig`), `input.zig` (`InputSink`; Key/Mods/Event re-exported from the Renderer's `Window` module, which provides the native window on Win32, Wayland and macOS), `font` / `wcwidth` (re-exports of the Renderer's `Font` module: TrueType parser, rasteriser, system fonts, atlas, cell widths). Imports only `std`, the Renderer's `Renderer`, `Window` and `Font` modules, and `imgdec`. |
| `src/connect.zig` | The viewer's main loop; module "client" in Portal's root build (`portal connect`), wrapped by `src/main.zig` here. |
| `src/gframe.zig` | Writes decoded 'G'/'I'/'P' frames into `view.grid.Grid` (remote grid source). |
| `src/keys.zig` | Protocol key names per `hello.input` mode. |
| `src/remote.zig` | `RemoteSink` (InputSink → protocol frames) and the overlay (pairing screen, status). |
| `src/net/` | `http.zig` (the upgrade request, strict response parsing), `wsclient.zig` (a WebSocket on either channel), `client.zig` (connection thread), `tlsconn.zig` (TLS over the tunnel stream, certificate gate), `x509check.zig` (bounds-checked certificate checks, PEM, fingerprints), `pin.zig` (per-server pinned CA files), `watchdog.zig` (deadlines). |
| `../shared/` | **Module `shared`** (a path dependency, also used by Portal's server and e2e tests): `screen.zig` (the 'G'/'I'/'P' frame decoder), `ws.zig` (WebSocket framing), `http.zig` (header syntax), `pki/` (DER, certificate reading, PEM, fingerprints), `tls13.zig` (TLS 1.3 record protection). |
| `src/credstore.zig` | OS credential store: Windows Credential Manager; the macOS Keychain (dlopen); on Linux a private file. |
| `src/tunnel/`, `src/devicelink.zig` | The in-process WireGuard tunnel (zwg + netstack behind the stream seam), this device's key, the pairing code. |

`portal run`'s local window (Portal's `src/gui.zig`) uses `view` too: it
fills a `Grid` from `vt.Terminal` (`src/localgrid.zig`), its `InputSink`
writes VT bytes to the PTY (`src/localinput.zig`), and `.sizing = .fixed_em`
makes `InputSink.resized` report the cols/rows for the PTY.

## Security

* This device's WireGuard private key is stored only in the OS credential
  store (`src/credstore.zig`): Windows Credential Manager, the macOS
  Keychain, on Linux a 0600 file in a 0700 directory checked on every load.
  It is wiped from memory once the tunnel has it, and never leaves the
  device. Nothing secret is accepted on the command line, written
  elsewhere, or logged.
* The device talks only to `10.8.0.1:8420` inside its own tunnel; its only
  peer is the desk, allowed only that address.
* WebSocket client frames are masked with keys from the OS CSPRNG; the
  Sec-WebSocket-Accept value is verified. Server frames must be unmasked,
  unfragmented, at most 8 MiB; anything else drops the connection.
* Grid frames, HTTP responses and font files are untrusted: bounded,
  validated, fuzz-tested, never panic. A malformed grid frame drops the
  connection (the reconnect brings a fresh snapshot).

## Testing

The client is tested against the real server: Portal's e2e suite
(`zig build e2e` at the repository root) pairs, signs in and streams over
HTTPS/WSS, and unit tests cover TLS with certificates Portal made
(`src/net/testdata/`).

## Status

Tested on Windows 11 (NVIDIA): pairing, refresh/rotation across restarts,
revocation and logout back to the pairing screen, keys/text/answer-bar
input, grid resize, window resize, against the real
Portal server (`portal run` + `portal pair`), over HTTPS/WSS with a pinned CA
(pin by file and by downloaded fingerprint, wrong CA refused, plain-HTTP
server refused without --insecure-plain-http, 80 s idle kept alive by pings).

Not yet tested:

* Linux (Wayland) and macOS (AppKit/MoltenVK) window backends (the
  Renderer's `Window` module), Keychain and libsecret: compile-checked by
  cross-compilation only (`zig build test` does it), never run.
* Zoom keys (Ctrl+= / Ctrl+- / Ctrl+0) and HiDPI scaling > 100% were not
  exercised by the automated run.
* No IME/compose input; no X11 (Wayland only, by choice); integer Wayland
  scales only.
* std's TLS client changes its write keys from the reading thread when a
  server sends KeyUpdate(update_requested) (Portal's server never does);
  a malicious, already-authenticated server could only break its own
  connection that way.
