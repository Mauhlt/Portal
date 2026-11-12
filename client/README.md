# portal-client

Native viewer for a Portal session (Windows, Linux, macOS), drawn with the
owner's Vulkan Renderer. Implements `docs/protocol.md`: device pairing,
rotating sign-in, the WebSocket grid stream and key-name input.

```
portal-client --server 10.8.0.1:8420 --ca portal-ca.pem   # first run: pin the server's CA
portal-client --server 10.8.0.1:8420 --ca-sha256 AB:CD:.. # or: fetch it while `portal pair` is open
portal-client --server 10.8.0.1:8420                      # later runs (CA pinned)
portal-client --server 10.8.0.1:8420 --forget             # delete credentials + pinned CA
portal-client --server 127.0.0.1:8420 --insecure-plain-http  # only for `portal run --no-tls`
```

On Windows the same viewer is built into Portal itself as `portal connect`
(same arguments): `src/connect.zig` is shared by both.

First run: at the desktop run `portal ca export` (it writes portal-ca.pem /
portal-ca.cer and prints the CA's SHA-256 fingerprint) and `portal pair
<name>`. Here, either copy portal-ca.pem over and pass `--ca portal-ca.pem`,
or pass `--ca-sha256 <fingerprint>` while the pairing window is open: the
client then downloads `/ca.cer` from the desktop's pairing-time page
(http://IP:PORT+1/), and pins it only if its SHA-256 matches. Then click
**Pair** (or press P) within 2 minutes. After that the client signs in by
itself on every launch and reconnect, with just `--server`.

## TLS

Portal serves HTTPS/WSS by default with a private CA name-constrained to the
tunnel addresses. The client pins that CA per server:

* The CA (public, not secret) is stored in the per-user config directory:
  `%APPDATA%\Portal\servers\<ip>_<port>.pem` (Windows),
  `~/Library/Application Support/Portal/servers/` (macOS),
  `$XDG_CONFIG_HOME/portal/servers/` or `~/.config/portal/servers/` (Linux).
  It is only ever written from an explicit `--ca FILE` (which must be a
  self-signed CA; `--ca-sha256` with it must match) or a download that
  matches `--ca-sha256`. Without a pin the client refuses to start: there is
  no trust on first use. A `--ca` with a different CA replaces the pin and
  says so. The pinned fingerprint is printed on every start.
* `std.crypto.tls.Client` (TLS 1.3) runs with `.host = .{ .explicit =
  "<bare IP>" }` and a CA bundle holding only the pinned CA. In front of it
  `src/net/tlsconn.zig` holds back the server's encrypted handshake flight
  until it has checked the certificate itself with bounds-checked code
  (`src/net/x509check.zig`): signed by exactly the pinned CA, valid now,
  subjectAltName = the server IP, ECDSA P-256. This closes two std gaps: on
  Windows std falls back to the OS root store when the pinned bundle has no
  issuer (so any Windows-trusted certificate, e.g. another Portal's CA a
  browser trusts, would pass), and std's certificate parser is not
  bounds-checked (a malformed certificate from an unauthenticated server
  could crash it). Only TLS_AES_128_GCM_SHA256 and
  TLS_CHACHA20_POLY1305_SHA256 are accepted (what Portal's server offers).
* Over HTTPS the client uses Origin `https://IP:PORT` and the `__Host-portal`
  / `__Host-portal_device` cookie names. A credential stored by an older
  client is sent only over HTTPS (under the `__Host-` name), never in
  cleartext.
* `--insecure-plain-http` (loud warning, never the default) talks plain HTTP
  to a `portal run --no-tls` server. It uses a separate credential
  (`Portal-plain/<host>`), so a credential obtained over TLS is never sent
  in cleartext.
* Liveness: connect + handshake 15 s, each request 15 s, and the stream is
  dropped after 60 s without data; a WebSocket ping goes out after 20 s of
  silence. Steps run as `std.Io` concurrent tasks that a watchdog cancels
  (`src/net/watchdog.zig`), since std cannot time out connects or reads.

## Build

```
zig build                                  # zig-out/bin/portal-client(.exe)
zig build test                             # unit tests + compile checks (Debug, ReleaseSafe)
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
| `src/connect.zig` | The viewer's main loop; module "client" in Portal's root build (`portal connect`), wrapped by `src/main.zig` here. |
| `src/gframe.zig` | Writes decoded 'G'/'I'/'P' frames into `view.grid.Grid` (remote grid source). |
| `src/keys.zig` | Protocol key names per `hello.input` mode. |
| `src/remote.zig` | `RemoteSink` (InputSink → protocol frames) and the overlay (pairing screen, status). |
| `src/net/` | `http.zig` (requests, strict response/Set-Cookie parsing), `client.zig` (connection thread), `tlsconn.zig` (TCP/TLS connection, certificate gate), `x509check.zig` (bounds-checked certificate checks, PEM, fingerprints), `pin.zig` (per-server pinned CA files), `watchdog.zig` (deadlines). |
| `../shared/` | **Module `shared`** (a path dependency, also used by Portal's server and browser client): `screen.zig` (the 'G'/'I'/'P' frame decoder), `ws.zig` (WebSocket framing), `http.zig` (header syntax, cookie names), `pki/` (DER, certificate reading, PEM, fingerprints), `tls13.zig` (TLS 1.3 record protection). |
| `src/credstore.zig` | OS credential store: Windows Credential Manager; macOS Keychain and Linux Secret Service (libsecret) via dlopen. |

`portal run`'s local window (Portal's `src/gui.zig`) uses `view` too: it
fills a `Grid` from `vt.Terminal` (`src/localgrid.zig`), its `InputSink`
writes VT bytes to the PTY (`src/localinput.zig`), and `.sizing = .fixed_em`
makes `InputSink.resized` report the cols/rows for the PTY.

## Security

* The device credential is stored only in the OS credential store under
  `Portal/<server host>` (`Portal-plain/<server host>` for
  `--insecure-plain-http`); the rotated value is saved before anything else is
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

* Linux (X11) and macOS (Cocoa/MoltenVK) backends, Keychain and libsecret:
  compile-checked by cross-compilation only, never run.
* Zoom keys (Ctrl+= / Ctrl+- / Ctrl+0) and HiDPI scaling > 100% were not
  exercised by the automated run.
* No IME/compose input on X11; no Wayland backend; macOS needs arm64.
* std's TLS client changes its write keys from the reading thread when a
  server sends KeyUpdate(update_requested) (Portal's server never does);
  a malicious, already-authenticated server could only break its own
  connection that way.
