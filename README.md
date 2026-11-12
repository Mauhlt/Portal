# Portal

Watch a terminal session running on your Windows desktop (typically the agent
) from a browser on your laptop, and answer its prompts, while you are
away from home.

```
laptop browser ──WireGuard tunnel──▶ desktop 10.8.0.1:8420 ──▶ portal ──ConPTY──▶ claude
                 (encrypted, only                              │
                  your devices)                                └──▶ your desktop console (still usable)
```

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

The desktop console title shows `N REMOTE VIEWER(S) CONNECTED` while anyone is
watching, and every login attempt and viewer connection is written to
`%LOCALAPPDATA%\Portal\portal.log`.

## Security layers

1. **Network**: Portal refuses to listen on `0.0.0.0` or any public address.
   Bind it to your WireGuard interface address. Only devices holding a
   WireGuard key can reach it; WireGuard encrypts everything.
2. **Token**: a 256-bit random access token, generated on the desktop. Only
   its SHA-256 is stored. Constant-time comparison; 5 failures in 15 minutes
   lock logins for 15 minutes.
3. **Session cookie**: random, HttpOnly, SameSite=Strict, 12 h idle / 7 day
   absolute lifetime, held in memory only (restarting Portal logs everyone
   out). Open WebSockets are closed within 5 s of sign-out or expiry.
4. **Browser hardening**: Host allowlist (blocks DNS rebinding), Origin checks
   on every POST and on the WebSocket upgrade (blocks CSRF and cross-site
   WebSocket hijacking), strict Content-Security-Policy, no framing.
5. **Process hygiene**: the child runs in a Windows job object, so if Portal
   dies, the agent and anything it spawned die too, leaving no unobserved
   session. Programs are resolved to absolute paths from PATH only, never
   the current directory.

## Setup

### 1. Build a release

```powershell
powershell -ExecutionPolicy Bypass -File scripts\release.ps1
```

This runs the tests, builds `ReleaseSafe` (runtime safety checks stay on), and
promotes the result. Put `bin\` on your PATH, or call `bin\portal.cmd`
directly.

### 2. Create the access token

In a plain terminal (**not** through the agent or any tool that records
output):

```powershell
portal token
cls
```

Store the printed token in your password manager. It is shown only once.
Portal refuses to print it when output is redirected. A running `portal run`
keeps accepting the old token until it is restarted.

### 3. WireGuard (free, open source)

See [docs/wireguard.md](docs/wireguard.md) for the full walk-through. In short:

1. Install WireGuard for Windows on the desktop and the laptop.
2. Desktop tunnel: `Address = 10.8.0.1/24`, `ListenPort = 51820`, and a
   `[Peer]` for the laptop with `AllowedIPs = 10.8.0.2/32`.
3. Laptop tunnel: `Address = 10.8.0.2/24`, and a `[Peer]` for the desktop with
   `Endpoint = <your home IP or DDNS name>:51820`, `AllowedIPs = 10.8.0.1/32`.
4. Router: forward **UDP 51820** to the desktop. Nothing else.

### 4. Run

On the desktop, in the project you want to work on:

```powershell
portal run --listen 10.8.0.1:8420 -- claude          # --input keys is the default
```

On the laptop, with the tunnel up, open `http://10.8.0.1:8420/` and sign in
with the token.

## Upgrading Zig safely

Each release lives in its own folder, outside the repo so `git clean` can't
delete it, with the exact source and Zig version that produced it:

```
%LOCALAPPDATA%\Portal\releases\
  20261111-185919_zig-0.18.0-dev.4+5a23bf4b2\  portal.exe  portal.pdb  BUILD-INFO.txt  source\
  current.txt      the release bin\portal.cmd runs
  known-good.txt   the release you confirmed works end to end
  history.txt      every promotion
```

* The binary you run never depends on the installed compiler, so upgrading Zig
  cannot break it.
* `release.ps1` promotes only if `zig build test` passes with the new compiler.
  That step runs the unit tests and also compiles the whole program in Debug
  and ReleaseSafe. On failure the current release is left untouched.
* After testing a release from the laptop, run `scripts\mark-good.ps1`.
  `scripts\rollback.ps1` always returns to known-good (running it twice is
  harmless). Known-good, and the newest build for each Zig version, are never
  pruned.
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
