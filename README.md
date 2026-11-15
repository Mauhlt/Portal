# Portal

<p align="center"><img src="docs/brand/portal-hero.jpg" alt="Portal: a neon ring opening onto a split moon and sun, a brain-shaped constellation above and a mountain meadow of neuroscience instruments below" width="480"></p>

Watch a terminal session running on your Windows desktop (typically the
agent CLI) from a laptop or an iPhone, and answer its prompts, while you
are away from home.

```
portal connect ──WireGuard tunnel──▶ desktop 10.8.0.1:8420 ──▶ portal ──ConPTY──▶ the session program
the iPhone app   (encrypted, only                              │
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
| See the session started at the desk, live, with scrollback | Start a process, or a project the desk did not allow |
| Send keystrokes into that session, filtered by the input mode | Choose a directory, read or upload files |
| Ask the program to repaint | Resize the session, or end one the desk started |
| Start a project the desk marked startable, by name, in the mode the desk chose (Projects, below) | Choose the folder, the program or its permission mode |

Input modes (`--input`, or Remote input in the window's Settings):

* `instruct` (default): answer keys **plus whole instruction lines**,
  which Portal checks before typing. A line is refused if it starts with
  `!` (the session program would run it in a shell), `/` (slash commands
  can change permissions or folders) or `#` (memory), or contains control
  characters or line breaks. The program still asks permission before
  running anything; you answer with the buttons. If the session program is
  a shell, the default is `keys` instead (see below).
  **Up/Down** (for arrow-select menus without numbers, such as the agent's
  folder-trust prompt) are accepted only while the shown tab's
  program waits for an answer: it reports OSC 7501 `state=blocked`, an
  agent hook reported a permission prompt (see "Claude Code
  integration" below), or its Conversation view has an open question. Otherwise Portal refuses them
  (`rejected` `NotWaiting`), because at an idle prompt Up recalls an older
  prompt from history (possibly a `!` shell command or a slash command
  typed at the desk) and Enter would submit it past the line checks.
  Devices show ↑/↓ only while they would be accepted (in the
  instruct panel). A program
  that never reports OSC 7501 and asks nothing in its transcript (no
  question open) never gets them; that includes the agent if it does not
  detect OSC 7501 support in Portal's terminal (it does not under ConPTY)
  and the integration below is not installed. Its folder-trust prompt
  comes before any transcript and any hook, so it can only be answered
  at the desk.
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
  holding a paired device's session could start new work. This
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
(`portalctl run --console`: the console title), and every pairing and
viewer connection is written to `%LOCALAPPDATA%\Portal\portal.log` (moved
to `portal.log.1` when it passes 10 MB; lines that a peer can cause are
rate limited, with counts of what was suppressed).

## The Conversation view

Devices show each tab as a conversation by default (prompts, replies,
one-line tool activity, questions with answer buttons; the terminal is a
toggle away), read from the agent's transcript on the desktop and
scrubbed of paths and your user name before it is sent. Portal starts
the agent with its own `--session-id` per tab (unless your configured
arguments already use `--session-id`, `--resume` or `--continue`), so each
tab follows exactly its own transcript. After `/clear` or `/resume` in a
tab, the tab moves to the new transcript only if that tab's terminal
printed within 2 seconds of it appearing or growing, and no other tab in
the same folder did; a transcript no tab printed near (an agent
session outside Portal) is never shown. Details: docs/protocol.md
section 3b.

### For you, recap and admin prompts

Under the latest reply each device shows **For you**: what the tab needs
from you (a permission prompt, amber) and what the agent's reply suggests
(a command to run, another project to switch to, its closing yes/no
question). Swipe a row (left = Yes by default) or tap it for the full
card. Yes on a suggestion only asks the agent ("Please run `zig build
e2e`."); it still asks its own permission. **↺ Recap** (or the line
`recap`) asks the agent for a short recap.

Commands that would open an administrator prompt (runas, sudo, msiexec,
installers, Set-ExecutionPolicy, writes under Program Files or HKLM) are
caught by a PreToolUse hook: in a session a device started they are
denied (nobody is at the desk to answer), in a desk session they run and
the tab shows "needs desk". `block_elevation_desk = on` in settings.txt
denies them at the desk too. Reinstall the hooks (Settings, "Claude Code
integration", or `portalctl hooks install`) to add the PreToolUse entry.
Details: docs/tabs-design.md, "For you".

## Security layers

1. **One network path: Portal's own WireGuard tunnel, in-process.** Portal
   runs the owner's Zig WireGuard and a userspace TCP/IP stack inside its
   own process (no adapter, no driver, no administrator rights). The desk
   listens only on its WireGuard UDP port (51820 by default); the session
   is reachable only at 10.8.0.1:8420 *inside* that tunnel. There is no
   other listener: no LAN or loopback port, no web page.
2. **A device is its WireGuard key, approved at the desk.** Each device
   makes its own key (the private half never leaves it: Windows
   Credential Manager, the macOS Keychain, or a 0600 file on Linux). You
   enter its public key at the desk (**Pair a device…**, or `portalctl
   pair <name> <key>`); the desk shows that key's check code
   (`ABCD-EFGH-JKMN-PQRS`, 80 bits) and you approve only if the device
   shows the same code. The desk then shows a pairing code for the device (its own
   key with its check code, where to reach it, the CA's SHA-256, the
   device's tunnel address). Only paired keys get into the tunnel, each
   only from its own address, so the address names the device: there are
   no cookies, passwords or sign-in. Unpair (**Devices**, or `portalctl
   unpair <name>`) ends its connections with a `logout` and removes its
   key at once; a device that forgets the desktop tells it, and its record
   goes too.
3. **TLS 1.3 inside the tunnel**, as defence in depth: Portal's own TLS
   1.3 server (Zig std's crypto: x25519, AES-128-GCM / ChaCha20-Poly1305,
   ECDSA P-256) with a certificate from a private CA created on this
   desktop, name-constrained to the tunnel subnet and loopback, its key
   DPAPI-protected. Devices pin that CA by the SHA-256 in their pairing
   code, never on first use.
4. **WebSocket only**: `/ws` (interactive: screen, input, conversation,
   status) and `/ws/bulk` (sync packages, in 16 KiB chunks, on its own
   connection with the stream's bulk priority, so a download never delays
   a keystroke). Every other request is a 404.
5. **Robustness**: Portal parses HTTP and WebSocket itself, strictly,
   instead of using `std.http` (which had remotely reachable crashes).
   Every connection has read/idle/send timeouts and the number of
   connections is capped.
6. **Signed packages** (Portal sync): Ed25519-signed manifests, the
   release key pinned at pairing, no downgrades or replays, executables
   only after approval on the device.
7. **Process hygiene**: the child runs in a Windows job object, so if Portal
   dies, the session program and anything it spawned die too, leaving no
   unobserved session. Programs are resolved to absolute paths from PATH
   only, never the current directory. Portal refuses to run as
   administrator unless you pass `--allow-elevated`.
8. **A clean environment for each session program** (`src/childenv.zig`):
   your environment (and Portal's folder first on PATH), without what
   would leak the context Portal itself was started from. Started from
   inside an agent session, Portal would otherwise hand that
   session's markers to every tab, and each tab's agent would run as its
   child (transcript saving off, its mode). Removed: `CLAUDECODE`,
   `AI_AGENT`, every `CLAUDE_*` / `CLAUDE_CODE_*` name, and every
   `PORTAL_*` name. Kept: everything else (PATH, SystemRoot, USERPROFILE,
   `ANTHROPIC_*` such as your API key or base URL...), the agent's
   documented user settings (`CLAUDE_CONFIG_DIR`,
   `CLAUDE_CODE_GIT_BASH_PATH`, `CLAUDE_CODE_USE_BEDROCK` / `_VERTEX` /
   `_FOUNDRY` and their `_SKIP_*_AUTH`, `CLAUDE_CODE_OAUTH_TOKEN`, client
   certificates, `CLAUDE_CODE_SHELL`, `CLAUDE_CODE_MAX_OUTPUT_TOKENS`,
   ...; the full list is `childenv.user_config`), and any `CLAUDE_*` name
   you set permanently (your user or the system environment variables).

## Sensitive data stays on the desk

Portal makes it practical to work on projects whose data must not leave
your desk (patient records, research data, anything confidential):

* **Devices never receive files or paths.** A laptop or phone sees only
  the scrubbed conversation, cards and the screen; the data itself stays
  on the desk.
* **The agent works inside the folders you approve.** Its permission
  settings and hooks keep it to those folders and ask before anything
  else, so you can steer feature work from anywhere without opening the
  rest of the desk.
* **Build remotely, process in person.** Keep the sensitive data folder
  outside the agent's approved folders, let the agent build and test the
  feature against sample or synthetic data, and run the real processing
  yourself at the desk.

One limit to keep in mind: whatever the agent reads becomes part of its
conversation with the model provider. Data that must stay private should
never be in a folder the agent may read; the boundary above is what keeps
it out.

## Setup

### 0. A new machine

Install the Zig version in `build.zig.zon`'s `minimum_zig_version`
(0.18.0-dev.1005+75d48dfff; the owner's ZVC installs a given version), then:

```powershell
git clone https://github.com/Mauhlt/Portal
cd Portal
zig build
```

Every other repo comes from GitHub at a pinned commit (see Development,
"Dependencies: pinned on GitHub"). The window needs a Vulkan driver: if there
is none, Portal says what to install.

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

For the other Windows devices, `zig build package` writes ready-to-copy
ReleaseSafe folders: `zig-out/portal-x86_64-windows` (the desktop) and
`zig-out/portal-aarch64-windows` (Snapdragon X laptops, the Surface).
Installing and pairing each device, in order:
[docs/pairing.md](docs/pairing.md).

### 2. Portal's tunnel (nothing to install)

Portal carries its own WireGuard (the owner's Zig WireGuard, in-process: no
WireGuard app, adapter, driver or administrator rights). See
[docs/wireguard.md](docs/wireguard.md). In short:

1. Router: forward **UDP 51820** to the desktop. Nothing else.
2. Firewall: one inbound rule for UDP 51820 (an administrator adds it once;
   [docs/wireguard.md](docs/wireguard.md), "Firewall").
3. Settings: **Tunnel endpoint** = where devices reach that port (your
   public IP or dynamic-DNS name, e.g. `home.example.org:51820`).
4. Pair each device ([docs/pairing.md](docs/pairing.md)).

### 3. Run

Double-click `portal.exe` (or type `portal`). The first time, the window
asks what it should do, in plain text inside the window:

* **Tunnel UDP port**: Portal's own WireGuard port (default 51820);
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
portal run -- agent --some-flag                         # --input instruct is the default
portal run --cwd C:\code\proj                           # start somewhere else
portalctl run --console -- agent                        # a session in this console instead
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

The keyboard types straight into the session. At the bottom there is only
**Instruct** (as on the paired devices): it opens the instruct panel, a
line with Send (it types the line and presses Enter, with no checks; an
answer word such as "yes" or "two" presses that key), Close, and a key
row: 1, 2, 3, ↑, ↓, Esc, Enter. A click on the terminal gives the
keyboard back to it while the panel stays open; Esc on an empty line,
Send or Close shuts the panel. Space always types a space here (it never
toggles dictation at the desk; the panel's mic button and a headset's
play / pause key do, once speech-to-text exists).

**Project tabs.** One Portal window holds several projects. Each is a tab
in the top bar, in a colour derived from its name (or `color = NAME
#rrggbb` lines in settings.txt), with its own program (the configured one,
started in that folder), its own pseudo console and its own screen. A tab
whose program waits for an answer (it reports OSC 7501 `state=blocked`, or
an agent hook said so) is outlined in amber with a dot. Only the desk opens and closes projects:
Ctrl+Shift+T or **+** (folder picker), `portal open <folder> [--name NAME]`
or `portalctl open <folder>` from a terminal (handed to the running Portal
through its data folder), Ctrl+Shift+W or a tab's **×** to close one (its
program is asked to exit, and ended after 10 s). Ctrl+Tab /
Ctrl+Shift+Tab or a click switches. When a tab's program exits the tab
goes; when the last one goes (or the window is closed) Portal ends as
before. A tab is named after its folder (the home folder is "Home"); paired
devices see that name and the colour, never a path, and can switch
between open tabs and answer. The one thing they can open is a project
the desk marked startable, and the one thing they can close is a session
a device started (below; docs/tabs-design.md). Every tab finds the
program on PATH again when it opens, so a project reopened after an
agent update runs the version installed now, even if the update
moved it.

**Starting projects from a device.** The desk's **Projects** panel
(Ctrl+Shift+J) lists the folders a paired device may start, at most 16:
Add folder… (or Add this tab's folder), Remove, and per project the mode
a device start runs in: **Ask** (the agent's `--permission-mode
default`: every edit and command needs approval) or **Plan** (`--permission-mode
plan`: read-only planning). Never a permissive mode. The same list from a
terminal:

```
portalctl startable add <folder> [--name NAME] [--mode ask|plan]
portalctl startable remove <name>
portalctl startable list
```

It is kept in settings.txt (`startable = NAME | MODE | FOLDER`); a
running Portal follows the file. On a device, **Projects** in the top bar
opens the list: each project's colour, name, Ask / Plan badge and state,
with Start, Open (it runs: show it) and Stop (only for a session a device
started). Devices see names only, never folders. Starts are refused while
the input mode is `none`, limited to 3 a minute per device (stops too),
and refused altogether when the program setting is not the agent or
carries a flag that skips or widens permission prompts
(`--dangerously-*`, `--permission-mode`, `--allowedTools`,
`--permission-prompt-tool`). A device-started tab says so on the desk
("acme · started by iPhone"), and the desk keeps the tab it shows.

The desk's own tools are in the top bar, and on these keys (they never
reach the session):

| Key | Top bar | What |
|---|---|---|
| Ctrl+Shift+T | + | open a project folder in a new tab |
| Ctrl+Shift+W | × on the tab | close the tab shown (its program is asked to exit) |
| Ctrl+Tab / Ctrl+Shift+Tab | click a tab | the next / previous tab |
| Ctrl+Shift+P | Pair a device… | pair a device by the key it shows (check its check code), then show the pairing code for it |
| Ctrl+Shift+D | Devices | paired devices with address and last use; Unpair |
| Ctrl+Shift+S | Settings | tunnel port and endpoint (with this desktop's tunnel key and its peers), program, project, input mode for the next start; system monitor, background art and the agent integration (these apply at once) |
| Ctrl+Shift+J | Projects | the projects paired devices may start, Ask or Plan each |

Panels are keyboard driven: Tab / arrows move, Enter activates, Esc closes.

**Claude Code integration (hooks).** The agent can't tell Portal its
state in-band under Windows' pseudo console (docs/protocol.md, "Program
status (OSC 7501)"), so Portal offers agent hooks instead. They are
off until you install them, once, either in Settings ("Claude Code
integration", Left/Right or a click: Install / Remove) or from a terminal:

```
portalctl hooks install      # adds Portal's hooks to the agent's settings.json
portalctl hooks status       # installed / not installed / partly
portalctl hooks uninstall    # removes exactly Portal's entries again
```

This edits `%USERPROFILE%\.claude\settings.json` (or
`%CLAUDE_CONFIG_DIR%\settings.json`): one entry each for
`UserPromptSubmit`, `PermissionRequest`, `Notification`
(`permission_prompt` and `idle_prompt` only), `Stop`, `StopFailure`,
`SessionEnd`, `SubagentStart` and `SubagentStop`, each running the installed
`%LOCALAPPDATA%\Portal\bin\portalctl.exe hook` (exec form, no shell).
Everything else in the file stays byte for byte; a file that isn't valid
JSON is refused with the reason; the previous file is kept next to it as
`settings.json.portal-backup-<date>-<time>`; the write is atomic; running
install again changes nothing. Every agent session then runs the
hook, but outside Portal it does nothing at all (no `PORTAL_TAB` in its
environment: it exits at once, prints nothing). In a Portal tab it tells
the running Portal, over a local pipe only your Windows account can open
(never the network, never a device), that the agent works (a prompt was
sent), waits for a permission answer (the tab is highlighted, devices get
"Claude wants to run a command. Allow it?" with Yes / No, and Up/Down
work), is done, failed (an API error) or idle. Only the event name, the
tool's name (to pick a fixed phrase; it is never shown) and the
notification type travel; prompts, tool input and paths don't. One hook
takes about 20 ms. Sessions started before the install normally pick it up
without a restart (the agent watches its settings).

**Plan usage.** A thin strip under the top bar, on the desk and every
device, shows how much of your plan's limits is used: "Week 62% ·
resets Mon" over a slim meter, whichever window (week or five hours) is
closer to its limit; amber from 75 %, red from 90 %, a one-time notice at
each step, a tap shows both windows. Portal gets the numbers from the agent's
status line in the sessions it starts: it passes `--settings
%LOCALAPPDATA%\Portal\agent-statusline.json` (a status line running
`portalctl statusline`, nothing else), so your own settings.json and its
status line are never touched and your hooks still run; with the hooks
installed, a rate-limit stop marks the limit as reached. Only percentages
and reset times reach devices. The agent reports them for claude.ai
Pro / Max plans only, after a session's first reply; with an API key
there is no strip.

**Hidden tabs (devices).** Long-press a tab (or right-click it, or
Ctrl+Shift+H for the tab shown) and choose "Hide this tab" to keep it out
of this device's tab bar; "⋯ N hidden" at the end of the bar lists them
(amber while one of them waits for you) with Show. Only this device's bar
changes: the desk and other devices still show every tab. The list is kept
in `hidden-tabs.txt` next to the device's settings.

**Inline images.** `portal-show picture.png [--cols N]`, run inside the
session (by you, or by the session program through its shell tool), shows a
PNG in the window, in `portal connect` and in the iPhone app. Portal puts
its own folder first on the session's PATH, so `portal-show` is always
found there (`portalctl show` does the same). Images scroll with the text
and disappear when their cells are erased or the screen is cleared.
Resizing the window also clears them, because ConPTY repaints the whole
screen. Programs can also use the kitty graphics protocol directly (PNG
only; see `src/vt_gfx.zig`). Limits: 6 MiB per PNG, 8192 px per side and
32 Mpx, 64 images and 64 MiB per session. Images only ever come from a
program in the session; viewers can't request files. Every image is checked
with the owner's `Image.check` before it is stored, sent or decoded (see
`docs/image-decoder-findings.md`).

### 4. Pair each device once (at the desk)

A device *is* its WireGuard key: there are no passwords, cookies or
sign-in. Full steps, per device: [docs/pairing.md](docs/pairing.md).

1. On the device, run `portal connect` (or open the iPhone app). It shows
   its tunnel key and the key's check code (`ABCD-EFGH-JKMN-PQRS`).
2. At the desk, **Pair a device…** (Ctrl+Shift+P): a name (`laptop`,
   `iphone`) and the key as the device shows it. **Check key** shows the
   check code of what you typed: approve only if it is the device's.
   (Console: `portalctl pair <name> <key>`, with a `[y/N]` prompt.)
3. The desk then shows the **pairing code** (text and QR). Enter it on the
   device (or scan the QR on the iPhone); the device shows the desk key's
   check code, and you connect only if it is the one Settings shows at the
   desk. The device brings its tunnel up and pins the Portal CA and the
   release key from the code.

From then on, the device connects from anywhere it can reach the tunnel
endpoint. **Devices** (or `portalctl devices`) lists paired devices;
Unpair (or `portalctl unpair <name>`) revokes one.

### HTTPS certificates

Portal's first start creates a private CA, "Portal Local CA (xxxxxxxx)",
in `%LOCALAPPDATA%\Portal\tls\`. Its X.509 name constraints only allow
`10.8.0.0/24` and `127.0.0.1`, and no real DNS names, so even a stolen CA
key cannot impersonate other web sites to a device that trusts it. To
choose the subnets yourself, do this before the first start:
`portalctl ca init --permit 10.8.0.0/24 --permit 127.0.0.1/32 [--permit-dns name]`.
The private keys (`ca.key`, `leaf.key`) are encrypted with Windows DPAPI for
your account. The server certificate (397 days, IP SAN 10.8.0.1) is renewed automatically at startup.

Devices need nothing installed: the desk sends its CA with its
certificate, and a device accepts it only if its SHA-256 is the one in the
pairing code it was given at the desk; from then on it pins it (it never
trusts on first use). A wrong or replaced certificate is shown in its
window ("Cannot verify this Portal"), with the pinned fingerprint.
`portalctl ca export [--out DIR]` still writes the CA (portal-ca.cer and
portal-ca.pem) if you want to check it elsewhere.

`portalctl ca` shows the CA, its constraints and the server certificate.
`portalctl ca init --force` replaces the CA, and every device must then
be paired again.

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
  that desktop's own folder,
  `%LOCALAPPDATA%\Portal\sync\desktops\<host>-<key>\packages\<package>\<version>\`,
  read-only, so two paired desktops can never overwrite each other.
  A running program is never overwritten: each version is a new folder.
* **On the device** (`portal connect`): data installs by itself; a program
  asks "Install <package> <version> from <desktop>?" with the publisher key
  and size, every new version. Right after pairing it asks "Install voice
  model?" for subscribed voice packages. Ctrl+Shift+K shows Packages
  (installed, waiting for approval, Roll back, Revoke a program's
  approval, Forget this desktop). There are no letter shortcuts and panels
  ignore input for their first 600 ms, so typing can't approve anything.
  Nothing is ever run automatically.
* Devices paired before this existed have no pinned release key: pair them
  again to turn sync on.

## Answer words

Every device sends from the same instruction line (`portal connect`, the
iPhone app and the desk's own window; see docs/layout-design.md). If the
text is an *answer word*, Enter presses that key instead: "yes", "yeah",
"yep", "y" → `y`; "no", "nope", "n" → `n`; "zero"…"nine" or "0"…"9" (also
"option two", "number 3") → that digit; "escape", "esc", "cancel" → Esc;
"enter", "ok", "okay" → Enter. Case, full-width forms and the punctuation
dictation adds ("Yes.", "Two!") are ignored. Anything else is sent as an
instruction line; if it would be refused the reason shows under the line
and the text stays. In `keys` mode the line takes answer words only. The
rules are `src/inputrules/send.zig`.

On the iPhone, voice is Apple's keyboard dictation into the line; Portal
never records or sends audio from the phone.

## Upgrading Zig safely

Each release lives in its own folder, outside the repo so `git clean` can't
delete it, with the exact source and Zig version that produced it:

```
%LOCALAPPDATA%\Portal\releases\
  20261114-104043_zig-0.18.0-dev.1005+75d48dfff\  portal.exe  portalctl.exe  portal-show.exe  *.pdb  BUILD-INFO.txt  source\
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
* For testing only, `PORTAL_AGENT_PROJECTS` points the Conversation view at
  a scratch transcript folder instead of the agent's own (the e2e harness
  sets it). Debug builds only: release (ReleaseSafe) builds ignore it.
  Like every `PORTAL_*` name, it never reaches a tab's program.
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

`client/` still builds the standalone `portal-client` on its own (for Linux
and macOS laptops); its `src/view` and `src/connect.zig` are also the
"view" and "client" modules of the root build.

### Dependencies: pinned on GitHub

A fresh clone builds with nothing else: `git clone
https://github.com/Mauhlt/Portal` then `zig build`. Zig's package manager
fetches every sibling repo at the commit `build.zig.zon` pins (and
`client/build.zig.zon`, which pins the same ones):

| dependency | repo (branch)                 | brings                                              |
|------------|-------------------------------|-----------------------------------------------------|
| Renderer   | Renderer (main)               | Vulkan, Windows, Wayland, MacOS                     |
| Image      | Image (neuro-formats)         | Vulkan (the same commit as the Renderer's)          |
| WireGuard  | Wireguard (master)            |                                                     |
| stt        | SpeechToText (zig-packages)   | Audio; TranslateNPU, lazily                          |

Vulkan's bindings are generated at build time by TranslateVulkan from the
Khronos registry (about 3 s once per zig cache). `shared` is a folder of this
repo. The QAIRT SDK (Qualcomm's NPU headers) is only needed for `zig build
stt-local -Dtarget=aarch64-windows`: pass `-Dsdk=<dir>` or set
`QNN_SDK_ROOT`. Nothing else downloads it.

**Building against local checkouts** (the siblings next to this repo):

```powershell
zig build --fork=../Renderer --fork=../Image test
zig build --fork=../Renderer --fork=../Image --fork=../Vulkan --fork=../TranslateVulkan test
zig build --fork=../SpeechToText test-speech   # also runs the GPU speech tests with ../SpeechToText/models
```

`--fork=<path>` replaces every package of that name in the dependency tree
with the checkout, whatever it pins, so a change in a sibling can be tried
here before it is pushed. `zig build --print-tree` shows what is used.

**Bumping a pin** after pushing a sibling change:

```powershell
zig build pin -Dpin=Renderer   # newest commit of the Renderer's branch, both build.zig.zon files
zig build pin                  # every sibling
zig build test                 # then commit build.zig.zon and client/build.zig.zon
```

A change deeper down is pinned bottom-up, pushing each repo before the next:
TranslateVulkan -> Vulkan (`zig build pin` there) -> Image and Renderer
(`zig fetch --save=Vulkan git+https://github.com/Mauhlt/Vulkan#<commit>`; keep
the two on the same Vulkan commit, so a program using both has one Vulkan
module) -> Portal (`zig build pin`).
