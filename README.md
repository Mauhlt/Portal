# Portal

Watch a terminal session running on your Windows desktop (typically the agent
) from a browser on your laptop, and answer its prompts, while you are
away from home.

```
laptop browser ──WireGuard tunnel──▶ desktop 10.8.0.1:8420 ──▶ portal ──ConPTY──▶ claude
                 (encrypted, only                              │
                  your devices)                                └──▶ Portal's own window on the desktop
```

`portal run` opens its own terminal window (drawn with Vulkan by the shared
view module in `client/src/view`); the person at the desk types into it with
full control. `portal connect --server IP:PORT` is the native remote viewer
in the same executable.

## What the web side can and cannot do

| Can | Cannot |
|---|---|
| See the session started at the desk, live, with scrollback | Start a new session, process, or project |
| Send keystrokes into that session, filtered by `--input` | Choose a directory, read or upload files |
| Ask the program to repaint | Resize or kill the session |

`--input` policies:

* `keys` (default): digits, y/n, Enter, and a single Esc. Enough to answer
  numbered "1 / 2 / 3" prompts. Be aware that at an idle input prompt
  these keys are typed like any other text, so a device can submit a line
  made only of digits and y/n (for example "1", Enter) as a prompt to the
  session program. It cannot type letters other than y/n, slash commands
  or a `!`. Arrows and Backspace are deliberately excluded: at an empty
  prompt, Up+Enter would resubmit an older prompt from history. Web input
  is also rate limited per connection, and a key sent right after an Esc
  is held back 50 ms so the two can't be read as Alt+key.
* `none`: view only.
* `instruct`: answer keys **plus whole instruction lines**, which Portal checks before typing. A line is refused if it starts with `!` (the agent would run it in a shell), `/` (slash commands can change permissions or folders) or `#` (memory), or contains control characters or line breaks. The agent still asks permission before running anything; you answer with the buttons.
* `text`: **full remote control of the program.** Typed text is an agent
  prompt, slash commands and Shift+Tab change modes, Ctrl+C exits. A `!`
  typed by a device at the start of a line is dropped (best effort, because
  Portal can't see the agent's input box). Anyone holding a logged-in browser
  session could start new work. This contradicts "no new projects from the
  laptop", so it is opt-in and Portal warns loudly when you use it.

**No breaking out to a shell.** Portal runs the agent directly, not inside a
shell, so if the agent exits the session ends instead of dropping anyone at a
prompt. If the session program *is* a shell (cmd, PowerShell, pwsh, bash,
wsl…), `instruct` and `text` are refused at startup, because remote typing
into a shell is a remote shell. Only `keys`/`none` are allowed there, unless
you pass `--allow-remote-shell` deliberately. Devices never send raw bytes,
so escape sequences can't come from them either.

The Portal window shows `N REMOTE VIEWER(S) WATCHING` as an amber badge (and
`— N REMOTE VIEWER(S)` in its title bar) while anyone is watching
(`--console` mode: the console title), and every login attempt and viewer
connection is written to `%LOCALAPPDATA%\Portal\portal.log` (moved to
`portal.log.1` when it passes 10 MB; lines that a peer can cause before
signing in are rate limited, with counts of what was suppressed).

## Security layers

1. **Network**: Portal refuses to listen on `0.0.0.0` or any public address.
   Bind it to your WireGuard interface address. Only devices holding a
   WireGuard key can reach it; WireGuard encrypts everything.
2. **Device pairing, approved at the desk, no passwords**: each device is
   paired once (`portal pair <name>` opens a 2-minute window; tap "Pair
   this device"). Tapping only creates a *request*; `portal pair` shows it
   with the device's address and a request code that the device's page
   also shows, and only a request you approve with `y` gets a credential.
   Anyone else who reaches the port during the window (another WireGuard
   peer, the LAN, a local process) can't take the slot: their request just
   appears at the desk, and you deny it. Nothing is typed on the device.
   The device gets its own random 256-bit credential, which you never see:
   * stored only as a SHA-256 hash on the desktop, and in an HttpOnly cookie
     or the OS credential store on the device;
   * bound to the device's WireGuard address;
   * **rotated on every use**. Credentials issued in the last 10 minutes
     stay valid until their own expiry (so two tabs signing in at once
     don't lock the device out); if any older one is ever presented again
     (a copied cookie), the device is revoked and logged, and must be
     paired again;
   * revocable any time with `portal unpair <name>`, which also disconnects
     its open viewers at once.
3. **HTTPS (TLS 1.3) inside the tunnel**: Portal serves HTTPS itself (a
   small TLS 1.3 server built on Zig std's crypto: x25519, AES-128-GCM /
   ChaCha20-Poly1305, ECDSA P-256). Its certificate comes from a private
   CA created on this desktop. The CA can only vouch for the WireGuard
   subnet and loopback (X.509 name constraints), and its key is
   DPAPI-protected (see [HTTPS certificates](#https-certificates)). Cookies
   are `Secure` and `__Host-` prefixed. `--no-tls` (plain HTTP) exists for
   tests only.
4. **Sessions**: random, HttpOnly, SameSite=Strict, in memory only. A paired
   device silently starts a new one after a Portal restart.
5. **Browser hardening**: Host allowlist (blocks DNS rebinding), Origin checks
   on every POST and on the WebSocket upgrade (blocks CSRF and cross-site
   WebSocket hijacking), strict Content-Security-Policy, no framing.
6. **Robustness**: Portal parses HTTP and WebSocket itself, strictly, instead
   of using `std.http` (which had remotely reachable crashes). Every
   connection has read/idle/send timeouts, and unauthenticated connections
   are capped per address, so idle or slow connections can't lock out a
   real viewer.
7. **Process hygiene**: the child runs in a Windows job object, so if Portal
   dies, the agent and anything it spawned die too, leaving no unobserved
   session. Programs are resolved to absolute paths from PATH only, never
   the current directory.

## Setup

### 1. Build a release

```powershell
zig build release
```

This runs the tests, builds `ReleaseSafe` (runtime safety checks stay on), and
promotes the result. It also installs a small launcher as
`%LOCALAPPDATA%\Portal\bin\portal.exe` that always runs the current release.
Put `%LOCALAPPDATA%\Portal\bin` on your PATH once, then type `portal`.

### 2. WireGuard (free, open source)

See [docs/wireguard.md](docs/wireguard.md) for the full walk-through. In short:

1. Install WireGuard for Windows on the desktop and the laptop.
2. Desktop tunnel: `Address = 10.8.0.1/24`, `ListenPort = 51820`, and a
   `[Peer]` for the laptop with `AllowedIPs = 10.8.0.2/32`.
3. Laptop tunnel: `Address = 10.8.0.2/24`, and a `[Peer]` for the desktop with
   `Endpoint = <your home IP or DDNS name>:51820`, `AllowedIPs = 10.8.0.1/32`.
4. Router: forward **UDP 51820** to the desktop. Nothing else.

### 3. Run

On the desktop, in the project you want to work on:

```powershell
portal run --listen 10.8.0.1:8420 -- claude          # --input keys is the default
portal run --cwd C:\code\proj --listen 10.8.0.1:8420 # start somewhere else
portal run --console --listen 10.8.0.1:8420          # old mode: inside this console
```

This opens the Portal window; closing it ends the session (like the program
exiting). Started from a terminal, the session starts in that terminal's
directory and the terminal waits until the session ends; started without one
(double-click, shortcut) it starts in your home folder. In the window:
selection with the mouse, Ctrl+Shift+C / Ctrl+Shift+V or right-click to copy
/ paste (bracketed when the program asks for it), Ctrl+= / Ctrl+- / Ctrl+0
to zoom. Resizing the window resizes the session; remote viewers adapt.
There is no scrollback yet.

Portal is a console-subsystem program (so `portal pair`, `devices` etc.
print and return exit codes normally); `portal run` frees its console once
the window is up. Double-clicking it therefore shows a console window for a
moment; a shortcut set to "Run: Minimized" avoids that.

### 4. Pair each device once (at the desk)

With `portal run --listen 10.8.0.1:8420` running (the default listen
address, 127.0.0.1, is reachable from this desktop only), open a second
terminal:

```powershell
portal pair laptop          # or: portal pair iphone
```

It prints the Portal CA's SHA-256 fingerprint, whether `portal run` is
serving the certificate download, and then waits. Within 2 minutes, on
that device: turn the WireGuard tunnel **on**. If this device does not
trust the Portal CA yet, first open `http://10.8.0.1:8421/` (listen port
+ 1; served only while a pairing window is open), install the
certificate (see below) and check that its fingerprint matches the one
`portal pair` printed. Then open `https://10.8.0.1:8420/` and tap **Pair
this device**. The device shows a request code, and the desk asks:

```
Pair 'laptop' from 10.8.0.2 (request 7f3a)? [y/N]
```

Answer `y` only if the address and code match your device; anything else
denies that request and keeps the window open for the right one. The
device's page then signs in by itself. Pair through the WireGuard address
even at home, because that's the address the device will use when away
(browsers keep credentials per address). If your router can't reach its
own public IP from inside the house, put the phone on cellular for those
30 seconds.

If `portal pair` reports that the certificate download could not be
opened, another program may be holding that port: don't install a
certificate from it; use `portal ca export` instead.

From then on, opening `https://10.8.0.1:8420/` from anywhere with the tunnel on
just works. `portal devices` lists paired devices; `portal unpair <name>`
revokes one.

### HTTPS certificates

The first `portal run` creates a private CA, "Portal Local CA (xxxxxxxx)",
in `%LOCALAPPDATA%\Portal\tls\`. Its X.509 name constraints only allow
`10.8.0.0/24` and `127.0.0.1`, and no real DNS names, so even a stolen CA
key cannot impersonate other web sites to a device that trusts it. To
choose the subnets yourself, do this before the first run:
`portal ca init --permit 10.8.0.0/24 --permit 127.0.0.1/32 [--permit-dns name]`.
The private keys (`ca.key`, `leaf.key`) are encrypted with Windows DPAPI for
your account. The server certificate (397 days, IP SAN of the listen
address) is renewed automatically at startup.

Trust the CA once on each device:

```powershell
portal ca export            # writes portal-ca.cer / .pem / .mobileconfig, prints the SHA-256
```

* **iPhone / iPad**: during `portal pair`, open `http://10.8.0.1:8421/` and
  tap *install profile*, or AirDrop `portal-ca.mobileconfig`. Then
  Settings > General > VPN & Device Management > the Portal profile >
  **Install**. Then Settings > General > About > Certificate Trust Settings
  > **enable full trust** for "Portal Local CA". Check the fingerprint
  against the one `portal pair` (or `portal ca export`) prints: the
  download page is plain HTTP, so only that comparison proves it is
  Portal's.
* **Windows**: double-click `portal-ca.cer` > Install Certificate > Current
  User > Trusted Root Certification Authorities.
* **macOS**: open `portal-ca.mobileconfig` (or add the `.cer` in Keychain
  Access and set it to Always Trust).
* **Linux / Android**: import `portal-ca.pem` / `portal-ca.cer` as a CA.

`portal ca` shows the CA, its constraints and the server certificate.
`portal ca init --force` replaces the CA, and every device must then trust
the new one.

## The browser viewer (Zig → WebAssembly)

The page a browser (including iPhone Safari) shows is written in Zig and
compiled to `wasm32-freestanding` (`src/wasm/`): protocol decoding, layout
and fit-to-width, a TrueType parser and antialiasing rasteriser, drawing into
an RGBA framebuffer, the answer bar and its tap targets, key mapping and
reconnect logic. It embeds DejaVu Sans Mono (`src/web/fonts/`, Bitstream Vera
licence), because a phone page cannot use system fonts. `zig build` compiles
it and embeds the `.wasm` in `portal.exe`, served at `/static/app.wasm`.

Browsers can only start WebAssembly from JavaScript, so `src/web/app.js` is a
small bridge with no application logic: it instantiates the module, forwards
events to it and wraps a handful of browser APIs (WebSocket, putImageData,
timers). The CSP allows `'wasm-unsafe-eval'` for exactly this; see `web.zig`.

## Upgrading Zig safely

Each release lives in its own folder, outside the repo so `git clean` can't
delete it, with the exact source and Zig version that produced it:

```
%LOCALAPPDATA%\Portal\releases\
  20261111-185919_zig-0.18.0-dev.4+5a23bf4b2\  portal.exe  portal.pdb  BUILD-INFO.txt  source\
  current.txt      the release the launcher runs
  known-good.txt   the release you confirmed works end to end
  history.txt      every promotion
%LOCALAPPDATA%\Portal\bin\portal.exe   the launcher (put this folder on PATH)
```

```powershell
zig build release          # test, build, promote, install the launcher, prune
zig build mark-good        # current -> known-good, after testing from the laptop
zig build rollback         # current -> known-good (running it twice is harmless)
zig build release-status   # current, known-good, history, and their zig versions
```

* The binary you run never depends on the installed compiler, so upgrading Zig
  cannot break it. The launcher only reads `current.txt` (validated against
  the release id format) and runs that release's `portal.exe`, passing your
  arguments through and returning its exit code.
* `zig build release` promotes only if `zig build test` passes with the
  compiler running the build. That step runs the unit tests and also compiles
  the whole program in Debug and ReleaseSafe. The new binary must also run
  `portal version`. On any failure the current release is left untouched.
  Pointer files are replaced atomically.
* After testing a release from the laptop, run `zig build mark-good`.
  `zig build rollback` always returns to known-good. Pruning never removes
  current, known-good, or the newest build for each Zig version, and keeps the
  4 newest others. A release whose `portal.exe` is running or locked is
  skipped, and pruning problems never fail a release.
* The release tooling is Zig too: `src\tools\release.zig` (`portal-release`)
  and `src\tools\launcher.zig` (`portal-launcher`).
* For testing only, `PORTAL_RELEASES_DIR` (an absolute path) overrides the
  releases folder for both the tools and the launcher; the launcher is then
  installed into the `bin` folder next to it. Both print a note when it is set.
* `src\win32.zig` declares its own Win32 bindings, and `build.zig` tolerates the
  0.17 to 0.18 build API change, to reduce breakage from std churn.
* ZVC can vet new compilers against Portal before promoting them: add this
  folder to `test_projects` in ZVC's `src/main.zig`. Because `zig build test`
  compiles the full exe, a compiler that can't build Portal is rejected.

## Development

```powershell
zig build test     # unit tests
zig build          # debug build in zig-out\bin
```

The build needs the owner's Renderer next to this repo (`build.zig.zon`:
`../Renderer-wt-portal` for now, `../Renderer` once that branch is merged).
`client/` still builds the standalone `portal-client` on its own (for Linux
and macOS laptops); its `src/view` and `src/connect.zig` are also the
"view" and "client" modules of the root build.
