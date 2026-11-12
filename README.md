# Portal

Watch a terminal session running on your Windows desktop (typically the
agent CLI) from a browser or a laptop, and answer its prompts, while you
are away from home.

```
laptop browser ──WireGuard tunnel──▶ desktop 10.8.0.1:8420 ──▶ portal ──ConPTY──▶ the session program
portal connect   (encrypted, only                              │
                  your devices)                                └──▶ the Portal window on the desktop
```

Portal is one Vulkan window, and nothing else: no console, no second
window. On the desktop it runs the session and is where you type, pair
devices, list and unpair them, and export the certificate; on a laptop the
same program (`portal connect`) is the remote viewer. Text only ever goes
through that window.

| Program | Subsystem | What it is |
|---|---|---|
| `portal.exe` | Windows GUI | The Portal window (`portal`, `portal run ...`) and the remote viewer (`portal connect`). Never opens a console; a terminal that starts it gets its prompt back at once. Errors go to a message box. |
| `portalctl.exe` | console | Scripting and tests: `pair`, `devices`, `unpair`, `ca`, `show`, `version`, `run --console` (a session in that console), and Portal sync: `sync`, `publish`, `unpublish`, `sync-device`. |
| `portal-show.exe` | console | `portal-show picture.png`, run inside a session (see Inline images). |

All three are built from the same source (`zig build`); `portal.exe` and
`portalctl.exe` differ only in their entry dispatch.

## What the web side can and cannot do

| Can | Cannot |
|---|---|
| See the session started at the desk, live, with scrollback | Start a new session, process, or project |
| Send keystrokes into that session, filtered by the input mode | Choose a directory, read or upload files |
| Ask the program to repaint | Resize or kill the session |

Input modes (`--input`, or Remote input in the window's Settings):

* `instruct` (default): answer keys **plus whole instruction lines**,
  which Portal checks before typing. A line is refused if it starts with
  `!` (the session program would run it in a shell), `/` (slash commands
  can change permissions or folders) or `#` (memory), or contains control
  characters or line breaks. The program still asks permission before
  running anything; you answer with the buttons. If the session program is
  a shell, the default is `keys` instead (see below).
* `keys`: digits, y/n, Enter, and a single Esc. Enough to answer
  numbered "1 / 2 / 3" prompts. Be aware that at an idle input prompt
  these keys are typed like any other text, so a device can submit a line
  made only of digits and y/n (for example "1", Enter) as a prompt to the
  session program. It cannot type letters other than y/n, slash commands
  or a `!`. Arrows and Backspace are deliberately excluded: at an empty
  prompt, Up+Enter would resubmit an older prompt from history. Web input
  is also rate limited per connection, and a key sent right after an Esc
  is held back 50 ms so the two can't be read as Alt+key.
* `none`: view only.
* `text`: **full remote control of the program.** Typed text is a prompt
  for the session program, slash commands and Shift+Tab change modes,
  Ctrl+C exits. A `!` typed by a device at the start of a line is dropped
  (best effort, because Portal can't see the program's input box). Anyone
  holding a logged-in browser session could start new work. This
  contradicts "no new projects from the laptop", so it is opt-in and
  Portal warns loudly when you use it.

**No breaking out to a shell.** Portal runs the session program directly,
not inside a shell, so if it exits the session ends instead of dropping
anyone at a prompt. If the session program *is* a shell (cmd, PowerShell,
pwsh, bash, wsl…), a chosen `instruct` or `text` is refused at startup and
the default drops to `keys`, because remote
typing into a shell is a remote shell. Only `keys`/`none` are
allowed there, unless you pass `--allow-remote-shell` deliberately. Devices
never send raw bytes, so escape sequences can't come from them either.

The Portal window shows `N REMOTE VIEWER(S) WATCHING` as an amber badge (and
`— N REMOTE VIEWER(S)` in its title bar) while anyone is watching
(`portalctl run --console`: the console title), and every login attempt and
viewer connection is written to `%LOCALAPPDATA%\Portal\portal.log` (moved
to `portal.log.1` when it passes 10 MB; lines that a peer can cause before
signing in are rate limited, with counts of what was suppressed).

## Security layers

1. **Network**: Portal refuses to listen on `0.0.0.0` or any public address.
   Bind it to your WireGuard interface address. Only devices holding a
   WireGuard key can reach it; WireGuard encrypts everything.
2. **Device pairing, approved at the desk, no passwords**: each device is
   paired once (**Pair a device…** in the Portal window, or `portalctl
   pair <name>`, opens a 2-minute window). Pairing on the device only
   creates a *request*; the desk shows it with the device's address and a
   request code that the device also shows, and only a request you approve
   gets a credential. Anyone else who reaches the port during the window
   (another WireGuard peer, the LAN, a local process) can't take the slot:
   their request just appears at the desk, and you deny it. Nothing is
   typed on the device. The device gets its own random 256-bit credential,
   which you never see:
   * stored only as a SHA-256 hash on the desktop, and in an HttpOnly cookie
     or the OS credential store on the device;
   * bound to the device's WireGuard address;
   * **rotated on every use**. Credentials issued in the last 10 minutes
     stay valid until their own expiry (so two tabs signing in at once
     don't lock the device out); if any older one is ever presented again
     (a copied cookie), the device is revoked and logged, and must be
     paired again;
   * revocable any time (**Devices** in the window, or `portalctl unpair
     <name>`), which also disconnects its open viewers at once.
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
   dies, the session program and anything it spawned die too, leaving no
   unobserved session. Programs are resolved to absolute paths from PATH
   only, never the current directory. Portal refuses to run as
   administrator unless you pass `--allow-elevated`.

## Setup

### 1. Build a release

```powershell
zig build release
```

This runs the tests, builds `ReleaseSafe` (runtime safety checks stay on), and
promotes the result. It also installs launchers into
`%LOCALAPPDATA%\Portal\bin` that always run the current release:
`portal.exe` (a GUI-subsystem launcher, so it never opens a console either),
`portalctl.exe` and `portal-show.exe` (console launchers). Put
`%LOCALAPPDATA%\Portal\bin` on your PATH once, then type `portal`, or pin
`portal.exe` to Start.

### 2. WireGuard (free, open source)

See [docs/wireguard.md](docs/wireguard.md) for the full walk-through. In short:

1. Install WireGuard for Windows on the desktop and the laptop.
2. Desktop tunnel: `Address = 10.8.0.1/24`, `ListenPort = 51820`, and a
   `[Peer]` for the laptop with `AllowedIPs = 10.8.0.2/32`.
3. Laptop tunnel: `Address = 10.8.0.2/24`, and a `[Peer]` for the desktop with
   `Endpoint = <your home IP or DDNS name>:51820`, `AllowedIPs = 10.8.0.1/32`.
4. Router: forward **UDP 51820** to the desktop. Nothing else.

### 3. Run

Double-click `portal.exe` (or type `portal`). The first time, the window
asks what it should do, in plain text inside the window:

* **Listen address**: `127.0.0.1:8420` (this desktop only) or your
  WireGuard address, e.g. `10.8.0.1:8420`;
* **Program to run**: the session program and its arguments. There is no
  built-in default;
* **Project name** (optional, shown in the title) and **Remote input**
  (Left/Right to change).

Click **Start**: the answers are saved in
`%LOCALAPPDATA%\Portal\settings.txt` and the session starts. Later starts
use them without asking; **Settings** in the top bar changes them for the
next start. If the saved values can't be used (the port is taken, the
program is not found), the same screen comes back with the reason.

Command-line options override the saved settings for one run:

```powershell
portal run --listen 10.8.0.1:8420 -- agent --some-flag   # --input instruct is the default
portal run --cwd C:\code\proj                           # start somewhere else
portalctl run --console --listen 10.8.0.1:8420 -- agent  # a session in this console instead
```

Started from a terminal, `portal` returns the prompt at once (it is a GUI
program) and the session starts in that terminal's directory; started by a
double-click, the Start menu or a shortcut, it starts in your home folder
(or `cwd = ...` in settings.txt). Closing the window ends the session (like
the program exiting). In the window: selection with the mouse,
Ctrl+Shift+C / Ctrl+Shift+V or right-click to copy / paste (bracketed when
the program asks for it), Ctrl+= / Ctrl+- / Ctrl+0 to zoom. Resizing the
window resizes the session; remote viewers adapt. There is no scrollback
yet.

The desk's own tools are in the top bar, and on these keys (they never
reach the session):

| Key | Top bar | What |
|---|---|---|
| Ctrl+Shift+P | Pair a device… | open a 2-minute pairing window and approve or deny each request |
| Ctrl+Shift+D | Devices | paired devices with address and last use; Unpair |
| Ctrl+Shift+E | Export certificate… | write portal-ca.cer / .pem / .mobileconfig to a folder (default `%USERPROFILE%\Downloads\Portal-CA`) |
| Ctrl+Shift+S | Settings | listen address, program, project, input mode for the next start |

Panels are keyboard driven: Tab / arrows move, Enter activates, Esc closes.

**Inline images.** `portal-show picture.png [--cols N]`, run inside the
session (by you, or by the session program through its shell tool), shows a
PNG in the window, in `portal connect`, and for browser viewers. Portal puts
its own folder first on the session's PATH, so `portal-show` is always
found there (`portalctl show` does the same). Images scroll with the text
and disappear when their cells are erased or the screen is cleared.
Resizing the window also clears them, because ConPTY repaints the whole
screen. Programs can also use the kitty graphics protocol directly (PNG
only; see `src/vt_gfx.zig`). Limits: 6 MiB per PNG, 8192 px per side and
32 Mpx, 64 images and 64 MiB per session. Images only ever come from a
program in the session; viewers can't request files. The browser client
currently draws a labelled box instead of the pixels (see
`docs/image-decoder-findings.md`).

### 4. Pair each device once (at the desk)

With Portal running on your WireGuard address (the default, 127.0.0.1, is
reachable from this desktop only), click **Pair a device…** (Ctrl+Shift+P),
name the device (`laptop`, `iphone`) and click **Open pairing**. The panel
shows the Portal CA's SHA-256 fingerprint and whether the certificate
download is up. Within 2 minutes, on that device: turn the WireGuard tunnel
**on**, then

* **browser**: if this device does not trust the Portal CA yet, first open
  `http://10.8.0.1:8421/` (listen port + 1; served only while a pairing
  window is open), install the certificate (see below) and check that its
  fingerprint matches the one the desk shows. Then open
  `https://10.8.0.1:8420/` and tap **Pair this device**;
* **Portal on a laptop** (`portal connect`): enter `10.8.0.1:8420` and the
  certificate (the exported `portal-ca.pem`, or the SHA-256 the desk shows,
  to download it now), then click **Pair**.

The device shows a request code, and the Portal window asks:

```
Pair 'laptop' from 10.8.0.2, code 7f3a?      [Stop pairing] [Deny] [Approve]
```

Approve only if the address and code match your device (Deny has the
focus; `y` approves, `n` denies); a denied request keeps the window open for
the right one. The device then signs in by itself. Pair through the
WireGuard address even at home, because that's the address the device will
use when away (browsers keep credentials per address). If your router can't
reach its own public IP from inside the house, put the phone on cellular for
those 30 seconds.

`portalctl pair <name>` does the same from a terminal (`[y/N]` prompts),
for scripts. If either reports that the certificate download could not be
opened, another program may be holding that port: don't install a
certificate from it; use Export certificate instead.

From then on, opening `https://10.8.0.1:8420/` from anywhere with the tunnel on
just works. **Devices** (or `portalctl devices`) lists paired devices;
Unpair (or `portalctl unpair <name>`) revokes one.

### HTTPS certificates

Portal's first start creates a private CA, "Portal Local CA (xxxxxxxx)",
in `%LOCALAPPDATA%\Portal\tls\`. Its X.509 name constraints only allow
`10.8.0.0/24` and `127.0.0.1`, and no real DNS names, so even a stolen CA
key cannot impersonate other web sites to a device that trusts it. To
choose the subnets yourself, do this before the first start:
`portalctl ca init --permit 10.8.0.0/24 --permit 127.0.0.1/32 [--permit-dns name]`.
The private keys (`ca.key`, `leaf.key`) are encrypted with Windows DPAPI for
your account. The server certificate (397 days, IP SAN of the listen
address) is renewed automatically at startup.

Trust the CA once on each device: **Export certificate…** in the window
(or `portalctl ca export [--out DIR]`) writes `portal-ca.cer`, `.pem` and
`.mobileconfig` and shows the SHA-256.

* **iPhone / iPad**: while pairing is open, open `http://10.8.0.1:8421/` and
  tap *install profile*, or AirDrop `portal-ca.mobileconfig`. Then
  Settings > General > VPN & Device Management > the Portal profile >
  **Install**. Then Settings > General > About > Certificate Trust Settings
  > **enable full trust** for "Portal Local CA". Check the fingerprint
  against the one the desk shows: the download page is plain HTTP, so only
  that comparison proves it is Portal's.
* **Windows**: double-click `portal-ca.cer` > Install Certificate > Current
  User > Trusted Root Certification Authorities.
* **macOS**: open `portal-ca.mobileconfig` (or add the `.cer` in Keychain
  Access and set it to Always Trust).
* **Linux / Android**: import `portal-ca.pem` / `portal-ca.cer` as a CA.
* **Portal on a laptop** pins the CA per server instead (it never trusts on
  first use). A wrong or replaced certificate is shown in its window
  ("Cannot verify this Portal"), with the pinned fingerprint.

`portalctl ca` shows the CA, its constraints and the server certificate.
`portalctl ca init --force` replaces the CA, and every device must then
trust the new one.

## Portal sync: packages for your devices

The desktop can deliver the owner's own programs and data (the laptop's
speech model, adapter and NPU tools) to paired devices, signed with a
release key that each device pinned when it paired. Vendor runtimes (such
as Qualcomm's QNN DLLs) are never shipped. Design and rules:
[docs/sync-design.md](docs/sync-design.md); wire format: section 7 of
[docs/protocol.md](docs/protocol.md).

```powershell
portalctl sync key                                    # the release key's SHA-256
portalctl publish stt-model D:\models\stt --kind data    # signs a new version
portalctl publish npu-probe .\zig-out\bin --kind executable --version 0.2
portalctl publish --list
portalctl sync subscribe laptop stt-model             # or: Devices panel, P on a row
portalctl sync subscriptions
```

* **Release key**: Ed25519, DPAPI-protected in `%LOCALAPPDATA%\Portal\sync-key`,
  separate from the CA key; created when Portal first starts. `portalctl
  sync key init --force` replaces it, and every device must then be paired
  again before it accepts packages.
* **Delivery is event-driven**: a publish or a subscription change sends
  the subscribed devices `{"t":"updates"}` on their WebSocket; they fetch,
  verify (signature, SHA-256 and size of every file) and install into
  `%LOCALAPPDATA%\Portal\sync\packages\<package>\<version>\`, read-only.
  A running program is never overwritten: each version is a new folder.
* **On the device** (`portal connect`): data installs by itself; a program
  asks "Install <package> <version> from <desktop>?" with the publisher key
  and size, every new version. Right after pairing it asks "Install voice
  model?" for subscribed voice packages. Ctrl+Shift+K shows Packages
  (installed, waiting for approval, Roll back). Nothing is ever run
  automatically.
* Devices paired before this existed have no pinned release key: pair them
  again to turn sync on.

## The browser viewer (Zig → WebAssembly)

The page a browser (including iPhone Safari) shows is written in Zig and
compiled to `wasm32-freestanding` (`src/wasm/`): protocol decoding, layout
and fit-to-width, a TrueType parser and antialiasing rasteriser, drawing into
an RGBA framebuffer, key mapping, reconnect logic, the page layout and
what the input box sends. It embeds DejaVu Sans Mono (`src/web/fonts/`, Bitstream Vera
licence), because a phone page cannot use system fonts. `zig build` compiles
it and embeds the `.wasm` in `portal.exe`, served at `/static/app.wasm`.

Browsers can only start WebAssembly from JavaScript, so `src/web/app.js` is a
small bridge with no application logic: it instantiates the module, forwards
events to it and wraps a handful of browser APIs (WebSocket, putImageData,
timers). The CSP allows `'wasm-unsafe-eval'` for exactly this; see `web.zig`.

The page is made of **slices**, the same on every platform:

* **Terminal**: the live terminal (fit to width, A−/A+ zoom, drag or
  scroll to pan) under a status line: project name (`--project`), viewer
  state, input mode, and the session state (working / waiting for you /
  done; a placeholder until the program reports it, see
  `docs/protocol.md`).
* **Interaction**: the input box and buttons, described below.
* **Data**: what the session pushed, newest first. Today that is every
  inline image it showed (a card with its size; the browser build has no
  PNG decoder yet, so previews show only where pixels were decoded);
  tables and charts can be added as further kinds in `src/wasm/data.zig`.

On a phone (narrow) the interaction slice is pinned at the bottom and the
area above switches between Terminal and Data with a segmented control;
the Data tab shows a dot when something new arrives. From 900 px wide
(laptop, desktop, iPad landscape) Data is a right-hand column; drag the
divider to resize it. The interaction slice:

* **an input box**, a native `<textarea>`, so the iPhone keyboard's
   dictation mic fills it, and so does Win+H on Windows. Enter sends,
   Shift+Enter adds a line (sent as a space: an instruction is one line).
   If the text is an *answer word*, Send presses that key instead: "yes",
   "yeah", "yep", "y" → `y`; "no", "nope", "n" → `n`; "zero"…"nine" or
   "0"…"9" (also "option two", "number 3") → that digit; "escape", "esc",
   "cancel" → Esc; "enter", "ok", "okay" → Enter. Case, full-width forms
   and the punctuation dictation adds ("Yes.", "Two!") are ignored.
   Anything else is sent as an instruction line; if it would be refused
   the reason shows under the box and the text stays. In `keys` mode the
   box takes answer words only;
* **buttons**: Yes, No, 1, 2, 3, Esc, Enter, Send.

On the iPhone, voice is Apple's keyboard dictation into the input box;
Portal never records or sends audio from the phone.

The slices follow the visible viewport, so when the iPhone keyboard opens,
the box and buttons sit right above it (the header is hidden if space is
short) and the safe areas (notch, home indicator) are respected. The
layout math is `src/wasm/slices.zig`, the input decisions
`src/wasm/inputbox.zig`.

## Upgrading Zig safely

Each release lives in its own folder, outside the repo so `git clean` can't
delete it, with the exact source and Zig version that produced it:

```
%LOCALAPPDATA%\Portal\releases\
  20261111-185919_zig-0.18.0-dev.4+5a23bf4b2\  portal.exe  portalctl.exe  portal-show.exe  *.pdb  BUILD-INFO.txt  source\
  current.txt      the release the launchers run
  known-good.txt   the release you confirmed works end to end
  history.txt      every promotion
%LOCALAPPDATA%\Portal\bin\    the launchers portal.exe, portalctl.exe, portal-show.exe (put this folder on PATH)
```

```powershell
zig build release          # test, build, promote, install the launchers, prune
zig build mark-good        # current -> known-good, after testing from the laptop
zig build rollback         # current -> known-good (running it twice is harmless)
zig build release-status   # current, known-good, history, and their zig versions
```

* The binary you run never depends on the installed compiler, so upgrading Zig
  cannot break it. The launchers only read `current.txt` (validated against
  the release id format) and run that release's exe of the same name,
  passing your arguments through and returning its exit code.
* `zig build release` promotes only if `zig build test` passes with the
  compiler running the build. That step runs the unit tests and also compiles
  the whole program in Debug and ReleaseSafe. The new build must also run
  `portalctl version`. On any failure the current release is left untouched.
  Pointer files are replaced atomically.
* After testing a release from the laptop, run `zig build mark-good`.
  `zig build rollback` always returns to known-good. Pruning never removes
  current, known-good, or the newest build for each Zig version, and keeps the
  4 newest others. A release whose `portal.exe` is running or locked is
  skipped, and pruning problems never fail a release.
* The release tooling is Zig too: `src\tools\release.zig` (`portal-release`)
  and `src\tools\launcher.zig` (`portal-launcher`, built once as a GUI and
  once as a console program).
* For testing only, `PORTAL_RELEASES_DIR` (an absolute path) overrides the
  releases folder for both the tools and the launchers; the launchers are
  then installed into the `bin` folder next to it. Both print a note when
  it is set.
* `src\win32.zig` declares its own Win32 bindings, and `build.zig` tolerates the
  0.17 to 0.18 build API change, to reduce breakage from std churn.
* ZVC can vet new compilers against Portal before promoting them: add this
  folder to `test_projects` in ZVC's `src/main.zig`. Because `zig build test`
  compiles the full exes, a compiler that can't build Portal is rejected.

## Development

```powershell
zig build test     # unit tests (and full compiles of every exe)
zig build          # debug build in zig-out\bin: portal.exe, portalctl.exe, portal-show.exe
zig build e2e      # end-to-end tests against real portalctl processes (minutes)
```

The build needs the owner's Renderer next to this repo (`build.zig.zon`:
`../Renderer-wt-portal` for now, `../Renderer` once that branch is merged).
`client/` still builds the standalone `portal-client` on its own (for Linux
and macOS laptops); its `src/view` and `src/connect.zig` are also the
"view" and "client" modules of the root build.
