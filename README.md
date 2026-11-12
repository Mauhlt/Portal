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
  the agent's numbered "1 / 2 / 3" prompts and nothing else. Arrows and
  Backspace are deliberately excluded: at an empty prompt, Up+Enter would
  resubmit an older prompt from history.
* `none`: view only.
* `text`: **full remote control of the program.** Typed text is an agent
  prompt, `!` runs shell commands, slash commands and Shift+Tab change modes,
  Ctrl+C exits. Anyone holding a logged-in browser session could start new
  work. This contradicts "no new projects from the laptop", so it is opt-in
  and Portal warns loudly when you use it.

The Portal window shows `N REMOTE VIEWER(S) WATCHING` as an amber badge (and
`— N REMOTE VIEWER(S)` in its title bar) while anyone is watching
(`--console` mode: the console title), and every login attempt and viewer
connection is written to `%LOCALAPPDATA%\Portal\portal.log`.

## Security layers

1. **Network**: Portal refuses to listen on `0.0.0.0` or any public address.
   Bind it to your WireGuard interface address. Only devices holding a
   WireGuard key can reach it; WireGuard encrypts everything.
2. **Device pairing, no passwords**: each device is paired once at the
   desk (`portal pair <name>` opens a 2-minute window; tap "Pair this
   device"). It gets its own random 256-bit credential, which you never see:
   * stored only as a SHA-256 hash on the desktop, and in an HttpOnly cookie
     or the OS credential store on the device;
   * bound to the device's WireGuard address;
   * **rotated on every use**. If an older credential is ever presented
     again (a copied cookie), the device is revoked and logged, and must be
     paired again;
   * revocable any time with `portal unpair <name>`, which also disconnects
     its open viewers within seconds.
3. **Sessions**: random, HttpOnly, SameSite=Strict, in memory only. A paired
   device silently starts a new one after a Portal restart.
4. **Browser hardening**: Host allowlist (blocks DNS rebinding), Origin checks
   on every POST and on the WebSocket upgrade (blocks CSRF and cross-site
   WebSocket hijacking), strict Content-Security-Policy, no framing.
5. **Robustness**: Portal parses HTTP and WebSocket itself, strictly, instead
   of using `std.http` (which had remotely reachable crashes). Every
   connection has read/idle/send timeouts, and unauthenticated connections
   are capped per address, so idle or slow connections can't lock out a
   real viewer.
6. **Process hygiene**: the child runs in a Windows job object, so if Portal
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

**Inline images.** `portal show picture.png [--cols N]`, run inside the
session (by you, or by the session program through its shell tool), shows a
PNG in the window, in `portal connect`, and for browser viewers. Images
scroll with the text and disappear when their cells are erased or the
screen is cleared. Resizing the window also clears them, because ConPTY
repaints the whole screen. Programs can also use the kitty graphics
protocol directly (PNG only; see `src/vt_gfx.zig`). Limits: 6 MiB per PNG,
8192 px per side and 32 Mpx, 64 images and 64 MiB per session. Images
only ever come from a program in the session; viewers can't request
files. The browser client currently draws a labelled box instead of the
pixels (see `docs/image-decoder-findings.md`).

Portal is a console-subsystem program (so `portal pair`, `devices` etc.
print and return exit codes normally); `portal run` frees its console once
the window is up. Double-clicking it therefore shows a console window for a
moment; a shortcut set to "Run: Minimized" avoids that.

### 4. Pair each device once (at the desk)

```powershell
portal pair laptop          # or: portal pair iphone
```

Within 2 minutes, on that device: turn the WireGuard tunnel **on** and open
`http://10.8.0.1:8420/`, then tap **Pair this device**. Pair through the
WireGuard address even at home, because that's the address the device will
use when away (browsers keep credentials per address). If your router can't
reach its own public IP from inside the house, put the phone on cellular for
those 30 seconds.

From then on, opening `http://10.8.0.1:8420/` from anywhere with the tunnel on
just works. `portal devices` lists paired devices; `portal unpair <name>`
revokes one.

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
