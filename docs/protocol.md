# Portal client protocol (v2: project tabs)

Used by every client: the native Zig + Vulkan clients for Windows, Linux,
macOS and the iPhone. Everything goes through Portal's own WireGuard
tunnel (docs/wireguard.md): the device dials `10.8.0.1:8420` inside it,
then TLS 1.3, then HTTP/1.1 only far enough to upgrade to a WebSocket (RFC
6455). The server certificate is issued by the desktop's private Portal
CA, which the server sends in its chain; clients pin it by the SHA-256 in
their pairing code and must offer TLS 1.3 with x25519 and
ecdsa_secp256r1_sha256.

## 1. Pairing: a device is its WireGuard key

There is no sign-in, cookie or credential. The tunnel lets in only the
keys of paired devices, each only from its own address, so the desktop
knows which device a connection is from its tunnel address alone.

1. The device generates its WireGuard key pair; the private key never
   leaves it. It shows the public key (44 base64 characters) and that
   key's **check code** (`shared/tunnelnet.zig checkCode`: 80 bits of a
   domain-separated SHA-256, as `ABCD-EFGH-JKMN-PQRS`).
2. At the desk the owner enters the device's name and public key (Pair a
   device, or `portalctl pair <name> <key>`). The desk shows the check
   code of what was entered; the owner approves only if both screens show
   the same code. The device is recorded (name, key, a tunnel address,
   a random id) and its key enters the tunnel's peer table at once.
3. The desk shows the **pairing code** (`shared/pairqr.zig`, version 2),
   as text and QR:

   ```
   portal-pair 2 10.8.0.1:8420 <CA SHA-256, 64 hex> <endpoint HOST:PORT> <desk public key> <device address>
   ```

   The device brings its tunnel up (the desk as its only peer, allowed
   only `10.8.0.1`, keepalive 25 s), shows the desk key's check code for
   the owner to compare with the desk, and connects. On that first TLS
   handshake it accepts the CA in the server's chain only if its SHA-256 is
   the one in the code, then pins it. Then it pins the release key
   (section 7).

Nothing crosses the network before the device's key is in the peer table.
Every value in the code is public; its authenticity is the owner carrying
it from the desk's screen and comparing the check code.

**Re-pairing** a name, or a key, already in use removes the old record
outright: its connections end with `logout` (reason `replaced`) and its
key leaves the tunnel; nothing of it is kept.

**Forget, from the device**: the text message `f:` on the interactive
WebSocket. The desktop removes that record (only it: a newer pairing under
the name stays), answers `{"t":"forgotten"}` and closes the connection;
the device then forgets the desktop (pairing code, CA pin, release-key
pin, sync folder). If the desktop can't be reached, the device forgets it
locally and says the desktop still lists it until the owner unpairs it.

**Unpair, at the desk**: open connections get
`{"t":"logout","reason":"unpaired"}` (the desk waits for them, a few
seconds at most, before the key leaves the tunnel); the device then
forgets the desktop. A device offline at that moment only finds the
desktop unreachable afterwards.

## 2. Open the stream

```
GET /ws HTTP/1.1
Host: 10.8.0.1:8420
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64 of 16 random bytes>
Sec-WebSocket-Version: 13
```

`101 Switching Protocols` on success; `403` means this desktop no longer
has the device (forget it). `GET /ws/bulk` opens the bulk channel
(section 7) the same way. Every other request is a `404` and the
connection closes. Client frames must be masked; no fragmentation; no
extensions. The interactive connection is dialed with the transport's
`.interactive` priority, the bulk one with `.bulk`.

## 3. Server → client

**Text frames** (JSON, one object):

| `t` | fields | meaning |
|---|---|---|
| `hello` | `v`: `2`; `input`: `"none"`, `"keys"`, `"instruct"` or `"text"`; `project`: the name of the tab shown (printable, at most 64 bytes, `"` and `\` escaped as `\"` and `\\`); `session`: its id; `sessions`: the open tabs (section 3a) | sent first; which input is accepted and what is open. `portal run` defaults to `instruct` (`keys` when the session program is a shell); clients must ignore fields they don't know |
| `tabs` | `sessions` | the open tabs changed: one opened or closed at the desk, renamed, or a program's state changed. The whole list, in bar order |
| `session` | `id` | the server now shows this tab (after `s:<id>`); its full snapshot follows. Clients drop cached image blobs of the previous tab |
| `nosession` | | the id asked for is not an open tab: closed, never existed and malformed all get exactly this. Input now goes nowhere until the viewer picks an open tab |
| `ended` | `id`, `code` | the tab shown ended (its program exited with `code`) while other tabs go on; it is already gone from the list (`tabs` came first). Input to it is dropped; the client picks another tab |
| `state` | `state`: `"working"`, `"waiting"` or `"done"` | **not sent**: the per-tab state is the `state` field of each session in `hello` / `tabs` |
| `exit` | `code` | the last tab's program exited (every tab has ended): Portal stops; stream ends |
| `logout` | `reason`: `"unpaired"` or `"replaced"` | this desktop no longer lets the device's key in: unpaired at the desk (`"unpaired"`), or its name was paired again under another key (`"replaced"`). Forget this desktop. |
| `forgotten` | (none) | the answer to `f:` (Forget this desktop): the record is gone |
| `updates` | | Portal sync: this device's package index changed (a publish, or a subscription changed at the desk). Fetch `GET /sync/index` (section 7). Devices also look on every connect |
| `rejected` | `reason` | an `l:` instruction line was refused (e.g. `ShellEscape`, `SlashCommand`, `MemoryShortcut`, `ControlCharacter`, `TooLong`, `Empty`), or a `k:up` / `k:down` in `instruct` mode while the program was not waiting for an answer (`NotWaiting`, section 4); nothing was typed |
| `convo` | `id`, `on`, `items` | the whole Conversation view of the tab watched (section 3b): after `hello` and every `session`, and whenever the server starts the conversation over. Replaces what the client had |
| `convo+` | `id`, `items` | new or changed items of that conversation (section 3b) |
| `activity` | `sysmon`, `tabs` | every open tab's background tasks and token usage (section 3c): after `hello`, then whenever any of it, the tab list or the desk's system-monitor setting changes |
| `subtabs` | `id`, `subs` | the subagent sub-tabs of the tab watched (section 3e): after every `session` (and after hello), and whenever they change |
| `sys` | `cpu`, `mem`, `gpus`, `tabs` | a system monitor sample (section 3d): only to a viewer whose System panel is open (`y:on`), only while the desk's setting is on, about once a second |
| `projects` | `list` | the projects this device may start (section 3f): after `hello`, and whenever the list or a project's running state changes |
| `project` | `op`, `result`, `name` | the answer to `p:start` / `p:stop` (section 3f) |
| `foryou` | `id`, `items` | the For-you cards of tab `id` (section 3g): for every open tab after `hello`, then whenever that tab's cards change |
| `item` | `op`, `result`, `id` | the answer to `i:yes` / `i:no` (section 3g) |
| `recap` | `op`, `result`, `id` | the answer to `r:recap` (section 4b) |
| `usage` | `week`, `five_hour`, `limit_reached` | the plan-usage bar (section 3h): on connect, at most every 5 minutes, at once on crossing 75 %, 90 % or the limit |

### 3a. Project tabs (sessions)

One Portal holds several projects ("tabs"), each with its own program and
screen. A session entry is

```
{"id":"<32 lower-case hex>","name":"<name>","color":"#rrggbb","state":"<state>"}
```

* `id`: random, 128 bits, never reused while the desktop runs; never an
  index or a path.
* `name`: desk-assigned (the folder's name or `--project`), printable,
  at most 64 bytes, escaped like `project`. Never a path.
* `color`: the tab colour.
* `state`: what the program reports through OSC 7501, or what the agent's
  hooks report (below), whichever changed last: `unknown`,
  `working`, `waiting` (it needs an answer: highlight the tab), `idle`,
  `done`, `error`. Untrusted (any program output can contain it, and the
  tab's program can run the hook): it only changes a highlight (and
  instruct's Up/Down gate, section 4).

At most 12 tabs. Grid, image and placement frames always belong to the tab
the viewer watches, which is the desk's tab at connect (`hello.session`)
and then whatever the viewer chose with `s:<id>` (answered by `session`,
then a full snapshot). Only the desk opens and closes tabs (the window,
`portal open <dir>`); no message a client sends can create, start, close
or reopen one, except `p:start` / `p:stop` for a project the desk marked
startable (section 3f). The shared parser and writer are `shared/tabs.zig`.

#### Program status (OSC 7501), desk side

Not a client message: how the desk learns `state`. The program reports
`ESC ] 7501 ; state=<s>[:kind=<k>][:app=<name>][:msg=<base64>]... ST`
(ST is `ESC \` or BEL), and may first ask whether the terminal supports it.
Sources: the spec, https://www.superlogical.com/rex/docs/build/program-status
(revision 0.4, 2026-10-10, sections Syntax and Feature detection), linked
from https://mitchellh.com/writing/program-status-osc7501; the agent
2.1.323 as shipped (read only for interoperability: its probe and the
reply it accepts).

* Query: `ESC ] 7501 ; ? ST`. The agent sends `ESC ] 7501 ; ? BEL`, then
  a primary device attributes request `ESC [ c` as its sentinel, and
  accepts any `OSC 7501` reply whose body starts with `?`.
* Reply: a supporting terminal MUST answer `OSC 7501 ; ? ST`; it MAY add
  `:states=â€¦:kinds=â€¦`, and a reply without them means exactly the states
  idle, working, done, blocked, error and the kinds permission, question,
  auth, which is what Portal understands. Portal answers exactly
  `ESC ] 7501 ; ? ` and the query's own terminator (BEL or `ESC \`),
  nothing else: fixed bytes, never anything from the stream.
* Where it goes: into that tab's PTY input, like the desk's own keys
  (`Session.writeInput`), never through a device's policy. Only a query in
  the program's own output triggers it (`src/vt.zig`, at most two replies
  per read of output); devices can't send the bytes themselves (`l:`
  rejects control characters, `k:` takes key names only). ConPTY's conhost
  turns on win32-input-mode (`ESC [ ? 9001 h`) and then drops an OSC in
  its input, so while that mode is on the reply is typed as
  win32-input-mode key records (`ESC [ 0 ; 0 ; <byte> ; 1|0 ; 0 ; 1 _`,
  key down and up per byte), which conhost hands to the program as the
  same bytes.
* **Limit, Windows-wide:** conhost answers the DA1 sentinel itself, at
  once, while the OSC 7501 query has to travel to the terminal and back.
  The DA reply therefore always arrives first, and the agent (2.1.323)
  settles "unsupported" on it and never reports its state, in Portal as in
  any ConPTY terminal. Portal's reply still arrives (the e2e `probe` group
  checks it); the agent takes the late reply as a terminal response (in
  the live check nothing of it reached its prompt or its dialogs).
  Until the agent waits for the OSC 7501 reply past its DA sentinel (or
  offers a way to say the terminal supports it), `state` stays `unknown`
  for agent tabs unless the hooks below are installed, and
  otherwise only the Conversation view's open questions make a tab
  "waiting".

#### Program status from agent hooks, desk side

Also not a client message. With the integration installed (`portalctl
hooks install`, or the desk's Settings; nothing installs it by itself),
the agent runs `portalctl hook` for six hook events.
Each tab's program has `PORTAL_TAB=<32 hex>` in its environment (random
per tab launch, not the tab's `id`, never sent to a device); the hook
sends that, the event and at most a tool name and a notification type
over a local named pipe that only the current Windows user can open and
that refuses remote clients. Mapping:

| hook event | `state` |
|---|---|
| `UserPromptSubmit` | `working` |
| `PermissionRequest` | `waiting`; the Conversation view's permission question (section 3b), its phrase picked by the tool's category (never the tool's name) |
| `Notification` with `notification_type` `permission_prompt` | `waiting` |
| `Notification` with `notification_type` `idle_prompt` | `idle` |
| `Stop` | `done` |
| `StopFailure` | `error` |
| `SessionEnd` | `idle` |
| `SubagentStart`, `SubagentStop` (`agent_id`) | no state: the tab's sub-tabs (section 3e) |

After a hook's permission wait, a tool result or an interrupt in the
tab's transcript ends it (`working`, `idle`): no hook fires then. A
message for no open tab changes nothing. Details, the pipe's security and
the settings.json entries: docs/tabs-design.md, "Detecting the agent is
waiting", fallback 2.

### 3b. The Conversation view (`convo`, `convo+`)

Devices show a tab as a conversation by default, not as a terminal: the
owner's prompts, the program's replies as readable text, tool use as
one-liners, questions with answer buttons. The terminal (the grid) stays
available behind a toggle. The desktop builds the conversation from the
session program's own transcript (the agent's JSONL, followed by change
notifications and by the program's output; `src/convo/`) and from its
OSC 7501 state.

Which transcript is a tab's: when the session program is the agent
(`claude`, `claude.exe`, `claude.cmd`) and its configured arguments pick no
session (`--session-id`, `--resume`/`-r`, `--continue`/`-c`), Portal starts
each tab's program with its own `--session-id <random v4 UUID>` and follows
exactly `<projects>\<encoded folder>\<uuid>.jsonl` (waiting for it to
appear); another session's transcript in the same folder is not the tab's.
After it, another transcript in that folder takes over (`/clear`,
`/resume` inside the session) only when all of these hold:

* it is new, or grows, after the tab started (a transcript once passed
  over must grow again to be looked at again);
* the tab's own program printed within 2 seconds (before or after) of
  the moment Portal first saw it new or growing. The agent redraws at
  once on `/clear` and `/resume` and prints on every turn; a session
  outside Portal writes while the tab is quiet. Two seconds covers late
  directory notifications, batched output checks and a slow `/resume`,
  and is far shorter than a human's turn;
* its records' `cwd` is the tab's folder (or inside it);
* no other tab follows it, and it is not another tab's own
  `--session-id` transcript;
* no other tab whose transcripts share the folder printed from the start
  of that window until the decision. Then whose it is is unclear: neither
  tab takes it, both keep their transcripts, and the desktop log notes it
  (at most once a minute per tab, without paths).

No timer is involved: a candidate is decided by comparing timestamps at
the next event Portal gets anyway (the tab's output, a change in the
folder); at most 8 wait at once. A transcript no tab takes is never
shown. Without an id (the arguments chose a session) only these rules
apply. The UUID never leaves the desktop: it is not logged with paths and
not sent; viewers only see Portal's own tab ids.

```
{"t":"convo","id":"<32 hex>","on":true,"items":[ITEM,...]}
{"t":"convo+","id":"<32 hex>","items":[ITEM,...]}

ITEM = {"n":<u32>,"k":"<kind>","text":"<text>"
        [,"open":true|false][,"multi":true]
        [,"options":[{"label":"<text>","key":"<answer key>"},...]]}
```

* Scoped like grid frames: only the tab the viewer watches, `id` naming
  it. A `convo` snapshot follows `hello` and every `session` (after the
  grid snapshot); clients drop messages for any other id.
* `convo` replaces the client's items. `on` is `false` while the tab has
  no transcript to read (none yet, or the program keeps none): the client
  says so (the server also sends a `status` item explaining it) and
  offers the terminal.
* `convo+`: an item whose `n` the client has replaces it; any other is
  appended (`n` only grows). An item with an empty `text` removes item
  `n` (a note the server took back, e.g. "waiting for your answer" once
  the transcript shows the real question).
* Kinds: `user` (the owner's prompt), `assistant` (the program's reply,
  plain text; Markdown code blocks kept), `tool` (a one-liner: "Edited 2
  files", "Read 3 files", "Ran a command", "Searched the project",
  "Looked something up", "Used <tool>"; consecutive uses of one kind
  merge into one line), `question` (`open` while the program waits for
  the answer), `error` (one line, e.g. an API error), `status` (a note:
  "Conversation compacted", "Interrupted", no transcript).
* Never sent: tool arguments, tool results, file contents, thinking,
  injected context. Subagents' conversations are never mixed in: each
  is its own read-only sub-tab (section 3e). Every text is scrubbed on the
  desktop: the tab's folder becomes the tab's name (`acme\src\a.zig`),
  the home folder (%USERPROFILE%, its 8.3 form, OneDrive) `[home]`, any
  other absolute path `[path]` (drive, also glued to a word or with
  spaces, drive-relative, UNC, `\\?\`, `\Users\`, POSIX, `file://`,
  `smb://`, `~/`, `%VAR%\`, `$HOME/`, URL-encoded once or twice), the
  user's names (%USERNAME%, the home folder's name, their parts; any
  case) `[user]` (docs/tabs-design.md, privacy rule 1).
* **Answering adds no input power.** An option's `key` is one of the
  answer keys (`0`…`9`, `y`, `n`, `enter`, `esc`); answering is sending
  `k:<key>` exactly as the answer buttons do, under the same input mode
  and rules (nothing in view-only `none` mode). Questions from the
  transcript (the agent's AskUserQuestion) number their options `1`…`9`
  (`multi`: each key toggles one, `enter` submits); a permission prompt
  (OSC 7501 `kind=permission`) is "Claude wants to <do something>. Allow
  it?" with Yes = `1`, No = `esc`; any other wait is a question without
  options (the terminal shows it). The terminal stays authoritative:
  options are best effort.
* Bounds: at most 200 items, 16 KiB of text per item (cut with "…"),
  256 KiB of text and 400 options per conversation; the oldest items go
  first. Every message is at most `max_message` bytes (about 720 KB).
* Strings escape `"`, `\`, line feeds (`\n`), tabs (`\t`) and other
  controls (`\u00XX`); texts are printable UTF-8 with line feeds and
  tabs. The shared writer and strict parser are `shared/convo.zig`: a
  malformed message (unknown kind, bad key, too many items or options,
  invalid UTF-8, controls) is rejected whole. Unknown scalar fields are
  ignored.

### 3c. Background tasks and usage (`activity`)

What each tab's session program runs in the background and what it has
used, for the tab badges, the status line and the Tasks / Usage panels.
Built on the desktop from the same transcript as the conversation
(`src/convo/activity.zig`); numbers and short descriptions only.

```
{"t":"activity","sysmon":<bool>,"tabs":[TAB,...]}
TAB   = {"id":"<32 hex>"[,"model":"<model id>"],"usage":USAGE,"today":USAGE,
         "tasks":[TASK,...]}
USAGE = {"in":<n>,"out":<n>,"cr":<n>,"cw":<n>}
TASK  = {"k":"shell"|"monitor","state":"<state>","since":<unix s>,"text":"<description>"}
```

* Not scoped to the tab watched: one message for every open tab, in bar
  order, so each tab's badge can show its count. Sent after `hello` and
  again whenever any tab's tasks or usage change, a tab opens or closes,
  or the desk changes "Show system monitor" (`sysmon`). Event-driven: it
  rides on the transcript follower's own wake-ups.
* Tasks: a `Bash` / `PowerShell` call with `run_in_background` is a
  `shell`, a `Monitor` call a `monitor`. `text` is the description the
  program gave (scrubbed like conversation texts: paths become the tab's
  name or `[path]`, the user's name `[user]`; one line, at most 120
  bytes); never the command, its output or its output file. `state`:
  `running`; `done` (the program's notification said `completed`, or a
  monitor's timeout passed); `failed`; `killed` (its notification, or
  `TaskStop`); `stale` (started in the transcript before the tab started,
  i.e. by an earlier run of the program: not known to run). A new
  transcript in the tab (`/clear`, `/resume`) keeps running tasks and
  drops finished ones; a tab that ends takes its tasks with it. At most
  16 per tab (finished ones go first), newest last; `since` is when it
  started (0: unknown).
* Usage: `usage` sums the replies of the transcript the tab follows now
  (input, output, cache read and cache write tokens, from
  `message.usage`; each reply counted once); `today` counts only replies
  dated today in the desktop's time zone. `model` is the latest reply's
  model id (`[A-Za-z0-9._:@[]-]`, at most 64 bytes), absent if unknown.
  Plan-limit percentages are not in transcripts: the desk's Usage panel
  offers "Open /usage", which types `/usage` + Enter into that tab at the
  desk; devices never get that button, and `l:/usage` stays rejected
  (`SlashCommand`, section 4).
* `sysmon`: the desk's "Show system monitor" setting; clients show the
  System button only while it is `true`.
* Strict parser and writer: `shared/activity.zig` (malformed, too many
  tabs or tasks, an unknown kind or state, a model id or text out of
  bounds: rejected whole; unknown scalar fields ignored).

### 3d. The system monitor (`sys`)

Optional, off by default: the desk's Settings panel "Show system monitor"
(`settings.txt`: `system_monitor = on`). While it is off nothing is
measured at all (no sampler thread, no performance counters, no timer)
and `y:on` is ignored (and logged at the desk, rate limited). While it is
on, the desktop samples once a second, on deadlines aligned to the
second, **only while at least one System panel is open** (the desk's, or
a viewer that sent `y:on`), and stops as soon as the last one closes or
the setting is turned off. This is Portal's one deliberate exception to
being event-driven, scoped to "a System panel is visible".

```
{"t":"sys","cpu":<tenths of %>,"mem":{"used":<bytes>,"total":<bytes>},
 "gpus":[{"util":<tenths of %>,"used":<bytes>,"total":<bytes>},...],
 "tabs":[{"id":"<32 hex>","cpu":<tenths of %>,"mem":<bytes>,"procs":<n>},...]}
```

* `cpu`: the whole machine, 0..1000. `mem`: physical memory in use.
* `gpus`: per hardware adapter, unnamed: the busiest engine type's
  utilisation (as Task Manager shows it) and dedicated video memory in
  use / its size (`total` 0 if unknown). From Windows performance
  counters (`GPU Engine`, `GPU Adapter Memory`) and DXGI; vendor-neutral.
* `tabs`: each open tab's process tree (its job object: the program and
  everything it started, e.g. background shells): CPU as a share of the
  whole machine, working-set memory, process count.
* Numbers and tab ids only: never process names, command lines, paths or
  user names. Sent only to viewers that asked (`y:on`) and only after a
  new sample. Strict parser and writer: `shared/sysinfo.zig`.

### 3e. Subagent sub-tabs (`subtabs`, `a:`)

When the session program in a tab (the agent) starts subagents, each
is shown as a read-only sub-tab under that tab: its own conversation,
built on the desktop exactly like the tab's (section 3b, the same
reader and model) from the subagent's own transcript, which the program
keeps next to the session's (`<session>\subagents\agent-<id>.jsonl`,
with `agent-<id>.meta.json` holding its description and, once it ended,
`finished`; docs/tabs-design.md, "Subagent sub-tabs"). Found by change
notifications on that folder (and the tab's output, as for the main
transcript), and by the `SubagentStart` / `SubagentStop` hooks when they
are installed (section 3a); nothing is polled.

```
{"t":"subtabs","id":"<tab, 32 hex>","subs":[SUB,...]}
SUB = {"id":"<32 hex>","name":"<description>","done":true|false}
```

* Scoped like `convo`: only the tab the viewer watches (`id`); sent after
  `hello`, after every `session`, and whenever the list changes. At most
  16 per tab, in the order they appeared.
* `id`: random, 128 bits, Portal's own: never the subagent's id in the
  program, never reused while the desktop runs.
* `name`: the description the session gave the subagent, scrubbed like
  conversation texts (the tab's folder becomes its name, other paths
  `[path]`, the user's name `[user]`), one printable line of at most 64
  bytes, escaped like tab names; `Subagent` until it is known.
* `done`: the subagent finished. A finished sub-tab stays, read-only,
  until the tab's conversation starts over (`/clear`, `/resume`: the
  list empties) or room is needed (the oldest finished one goes first;
  with 16 running, a new one gets no sub-tab). Subagents that had already
  finished when the tab took over an earlier session (`/resume`) get none.
* `a:<sub id>` (client → server, every input mode) shows that sub-tab's
  conversation: a `convo` snapshot with the sub-tab's `id`, then `convo+`
  for it. `a:` shows the tab's own again. An id that is not a current
  sub-tab of the tab watched is the same as `a:` (nothing echoed or told
  apart); `s:` always shows the new tab's own conversation. A sub-tab
  that goes while shown falls back the same way (a `convo` snapshot with
  the tab's id).
* **Read-only.** While a sub-tab is shown, `k:`, `t:` and `l:` from that
  viewer are dropped; clients show no Instruct and no answer controls
  there. Grid frames stay the tab's.
* Strict parser and writer: `shared/subtabs.zig`.

### 3f. Startable projects (`projects`, `p:`, `project`)

The desk may mark up to 16 projects as startable from a device. The list
carries names, colours and booleans only; a project's folder never leaves
the desktop.

```
{"t":"projects","list":[ENTRY,...]}
ENTRY = {"name":"<name>","color":"#rrggbb","mode":"ask"|"plan",
         "running":true|false,"stoppable":true|false}
{"t":"project","op":"start"|"stop","result":"<result>"[,"name":"<name>"]}
```

* `name`: a startable name: a tab name (section 3a) without `\`, `/`,
  `:`, `|` or `"`, not starting with `-`, `.` or a space, so it can never
  be read as a path, a drive, an option or a settings field.
* `mode`: how a device-started session runs, chosen at the desk: `ask`
  (the agent asks before every edit and command) or `plan` (read-only
  planning). Never a permissive mode; a device can't change it.
* `stoppable`: running and started from a device (only then may a device
  stop it; `stoppable` without `running` is malformed).
* `p:start <name>` / `p:stop <name>` (section 4a). Results: `started`,
  `stopped`, `switched` (already running: the device now shows it),
  `unknown` (no such project, or malformed), `refused` (input mode
  `none`), `rate_limited`, `unsafe_program` (the desk's program setting is
  not safe to start from a device), `not_device_started`, `not_running`,
  `too_many_tabs`, `failed`, `starting` (another request is starting it
  right now), `no_guard` (the desk could not set up the guard that holds
  a device start to its mode, docs/tabs-design.md).
* Strict parser and writer: `shared/projects.zig`.

### 3g. For you (`foryou`, `i:`, `item`)

Cards a device shows in its For-you list: what a tab needs from the owner,
or what the desk suggests, each answered with yes or no (a swipe or a
button). The desk builds them (from the agent's hooks and transcript),
keeps them and decides what an answer does; the device only shows them.

```
{"t":"foryou","id":"<tab, 32 hex>","items":[ITEM,...]}
ITEM = {"id":"<32 hex>","k":"<kind>","text":"<summary>"
        [,"cmd":"<command>"][,"why":"<why>"][,"project":"<name>"]}
{"t":"item","op":"yes"|"no","result":"<result>"[,"id":"<item id>"]}
```

* One message per tab, for **every** open tab (not only the one
  watched): after `hello`, and whenever that tab's cards change. It
  replaces the device's cards for that tab; `"items":[]` clears them. A
  tab gone from `tabs` takes its cards with it. A card's tab is the
  message's `id`.
* At most 16 cards per tab, in the desk's order (most urgent first).
* `id`: random, 128 bits, never reused. **The id is the card's
  version:** the desk gives a card a new id whenever anything in it
  changes, so an answer to a card that was replaced, answered elsewhere
  (another device, the desk) or is gone names no current id and is
  refused `stale`.
* `text`: a one-line summary, 1..120 bytes. `cmd`: a command (the
  permission prompt's, a suggested run), at most 1 KiB, printable, line
  feeds and tabs allowed. `why`: one line, at most 240 bytes. `project`:
  a project name (tab-name rules); the target of `suggest_goto`. Every
  text is scrubbed on the desk like conversation texts (paths, the user's
  name).
* Kinds and what an answer does (enforced by the desk; `Kind.effect`,
  `Effect.allowedIn`):

| `k` | yes | no | input mode needed |
|---|---|---|---|
| `waiting_permission` (only a hook's prompt whose first choice is a plain one-time yes; any other prompt is a `needs_desk` card) | allows the agent's permission prompt (`1`) | denies it (`esc`) | `keys`, `instruct`, `text` |
| `suggest_run` (has `cmd`, and `text` is exactly `cmd`: printable ASCII, at most 120 bytes, no backtick, no run of 3+ spaces, no `;`, pipe, `&`, `<`, `>`, `$(`, no `iex` / `Invoke-Expression` / encoded command, no shell interpreter as the command: `foryou.runnable`) | sends the agent ``Please run `<cmd>`.`` | dismisses | yes: `instruct`, `text`; no: any |
| `suggest_goto` (has `project`) | sends the agent `Please switch to the <project> project.` | dismisses | yes: `instruct`, `text`; no: any |
| `answer` (a yes/no question in `text`) | answers yes | answers no | `keys`, `instruct`, `text` |
| `needs_desk` | dismisses | dismisses | any |
| `long_running` | dismisses | dismisses | any |

* The messages are fixed templates (`foryou.runMessage`, `gotoMessage`)
  filled with the desk's own `cmd` / `project`, never the device's text,
  so a device can show exactly what will be sent. Dismissing removes the
  card for every device.
* `i:yes <id>` / `i:no <id>` (section 4a). Results: `sent` (it reached
  the agent; the card is gone), `dismissed` (the card is gone), `stale`
  (no current card has that id, or a malformed frame; nothing happened),
  `refused` (the input mode doesn't allow it), `rate_limited`, `failed`
  (the desk could not deliver it, e.g. the agent is not at its prompt;
  the card stays).
* **Needs desk (the admin-prompt guard).** A tab that waits for something
  only the desk can give (an administrator prompt, the folder-trust
  prompt, a sign-in) gets a `needs_desk` card; a command running long
  gets a `long_running` card. There is no separate "needs desk" flag in
  the tab list: a tab needs the desk while its `foryou` list holds a
  `needs_desk` card (`foryou.List.needsDesk`), and clients mark its tab
  from that. Why: `foryou` already reaches every device for every tab, so
  it is one source of truth with the reason attached; older clients'
  tab-entry parser rejects the whole list on a non-string field, so a
  boolean there would break them; and a new `state` value would mix with
  `waiting`, which gates Up/Down (section 4). The tab's `state` stays
  what the program reports.
* Strict parser and writer: `shared/foryou.zig` (too many cards, an
  unknown kind, a field out of bounds, a card its kind can't have, an id
  twice: rejected whole; unknown scalar fields ignored).

### 3h. The plan-usage bar (`usage`)

How much of the owner's plan limits is used, as the desk knows it:
percentages and reset times only (token counts are `activity`, 3c).

```
{"t":"usage"[,"week":WINDOW][,"five_hour":WINDOW][,"limit_reached":"week"|"five_hour"]}
WINDOW = {"pct":<0..100>[,"resets_at":<unix s>]}
```

* An absent window is unknown; an absent `resets_at` is unknown.
  `limit_reached` names the window whose limit is reached.
* The desk sends it to a device on connect (after `hello`, once anything
  is known), then at most once per 5 minutes, and at once when a window
  crosses 75 %, 90 % or 100 %, or `limit_reached` changes. The throttling
  is the desk's (`src/usage_desk.zig` Throttle: per viewer, timestamps and
  one deadline in the viewer's wait, no polling); each message replaces
  the last.
* Where the desk gets it: the agent's status line in the sessions Portal
  starts (`portalctl statusline`, passed with `--settings`; it reads only
  `rate_limits.five_hour` / `seven_day`: `used_percentage`, floored, and
  `resets_at`), and the `StopFailure` hook with `error` = `rate_limit`
  (docs/tabs-design.md, "The plan-usage bar"). `limit_reached` names the
  window closer to its limit then; a later finished turn (`Stop`), a new
  window or its reset time clears it. Windows appear only for claude.ai
  subscriptions: an API-key desk never sends `usage`.
* Strict parser and writer: `shared/planusage.zig` (a percentage over
  100, a field twice, an unknown window: rejected).

**Binary frames**: grid updates, always starting with `'G'`, little-endian:

```
u8  'G'
u16 cols
u16 rows
u16 cursor_x
u16 cursor_y
u8  cursor_visible        0 or 1
u16 n_rows                rows included in this frame
repeat n_rows:
    u16 row_index
    u16 n_runs
    repeat n_runs:
        u32 fg            0x00RRGGBB, or a sentinel below
        u32 bg
        u8  attrs         1 bold, 2 dim, 4 italic, 8 underline, 16 strikethrough
        u16 text_len
        text_len bytes    UTF-8, no control characters
```

* Colour sentinels: `0xFF000000` means "default" for whichever slot it is in
  (default foreground in `fg`, default background in `bg`). For inverse video
  with default colours: `0xFF000002` is the default background used as
  foreground, and `0xFF000003` the default foreground used as background.
  Clients pick the actual default colours (theme). The exact values are
  defined in `src/vt.zig`.
* A wide character (CJK, emoji) occupies two cells but appears once in the
  text; the following cell is skipped.
* Cells not covered by a row's runs are blank with default colours.
* The first grid frame after `hello` contains every row (a full snapshot).
  Later frames contain only changed rows. If `cols`/`rows` change, the next
  frame is a full snapshot.
* The server never sends terminal escape sequences; clients never interpret
  any.
* Binary frames are told apart by their first byte. **Clients must ignore
  binary frames whose first byte they don't know** (all current clients do),
  so new frame types can be added without breaking them.
* Both Portal clients decode these frames with one decoder
  (`shared/screen.zig`): a malformed frame (truncated, trailing bytes, a
  row index outside the grid, a size of 0 or over 1000, a cursor flag
  other than 0/1) is dropped whole, before anything is applied. Invalid
  UTF-8 and control characters in text are shown as U+FFFD.

### Inline images (`'I'` and `'P'` frames)

Images appear only because a program running in the session emitted them
(kitty graphics protocol, see `src/vt_gfx.zig`; `portal-show <file.png>`
does it from a shell or from the agent CLI's shell tool). There is no message or
route a client can use to request an image, a file, or anything from disk.

**Image blob**, sent at most once per image per viewer, always before the
first `'P'` frame that lists it:

```
u8  'I'
u32 image_id       server-assigned, never reused while the server runs
u32 len            PNG byte count (at most 6 MiB)
len bytes          a complete PNG file
```

**Placements** of the visible screen (main or alternate), sent whenever
that list changes:

```
u8  'P'
u16 n
repeat n:
    u32 image_id   always one this viewer has received in an 'I' frame
    u16 col        left column
    i16 row        top row; negative when the image has partly scrolled
                   off the top
    u16 cols       width in cells
    u16 rows       height in cells
    u16 reserved   0
```

* Draw each image scaled to `cols × rows` cells with its top-left cell at
  (`col`, `row`), clipped to the grid. Images go above cell backgrounds and
  below the cursor and selection. A placement replaces nothing in the grid:
  the cells under it are still sent in `'G'` frames (usually blank).
* The list is complete: placements missing from the latest `'P'` are gone
  (erased, overwritten, scrolled off, cleared, or the screen switched).
* **Cache rule.** After a `'P'` frame a client may discard every cached
  blob that frame doesn't list; the server assumes it did and sends a blob
  again if it is needed again later. A client therefore never needs more
  than the blobs of one screen: the server holds at most 64 images and
  64 MiB, and a screen at most 256 placements.
* Clients must validate before decoding and must not trust the server
  with their memory: drop blobs over 6 MiB, anything that is not a
  well-formed PNG, and images over 8192 px per side or 32 Mpx; decode with
  a bounded allocator; show a placeholder for images they can't decode.
  Unknown ids in `'P'` are skipped. Portal's clients keep at most what the
  server holds (64 blobs, 64 MiB, 256 placements), dropping the oldest
  blob first.
* Blobs are rate limited per viewer (8 MiB burst, 4 MiB/s) so images can't
  starve grid updates; a placement appears once its blob has been sent.
* Old clients that predate these frames ignore them and simply show no
  images.

## 4. Client → server

Text frames only, at most 4096 bytes. Each connection may send about 40
messages and 16 KiB per second (bursts of twice that); the excess is
dropped. A key sent within 50 ms of an `esc` is delayed until 50 ms have
passed, so the program can't read the pair as Alt+key.

| frame | meaning |
|---|---|
| `k:<name>` | press a key |
| `t:<utf8>` | type text (only when `input` is `"text"`; a `!` typed at the start of a line is dropped, where "start of a line" means after any key other than the character keys `0`…`9`, `y`, `n`: Enter, Esc, Ctrl+C, Backspace, the arrows, Home, End…) |
| `l:<line>` | an instruction line (`"instruct"` and `"text"`): Portal rejects a leading `!` (shell), `/` (slash command) or `#` (memory), control characters, line breaks and bidi controls, max 2000 bytes; otherwise it types the line (as a bracketed paste when the program enabled it) and presses Enter |
| `s:<id>` | watch the open tab `id` (32 hex digits; in every input mode, `none` included). Input sent after it goes to that tab. Answered by `session` (and a snapshot) or, for anything that is not an open tab, `nosession`; rejected ids are logged at the desk, rate limited, never echoed |
| `a:<sub id>`, `a:` | show that sub-tab of the tab watched (read-only), or the tab's own conversation again (section 3e; every input mode). While a sub-tab is shown, `k:`, `t:` and `l:` are dropped |
| `y:on`, `y:off` | this viewer's System panel opened / closed (section 3d; every input mode: it is read-only). While the desk's "Show system monitor" is off, `y:on` is ignored and logged at the desk. Closing the connection counts as `y:off` |
| `f:` | Forget this desktop (section 1): the desktop removes this device's record, answers `forgotten` and closes the connection (every input mode). Exactly `f:`: nothing may follow (section 4a) |
| `p:start <name>`, `p:stop <name>` | start / stop a startable project (section 3f); answered by `project` |
| `i:yes <id>`, `i:no <id>` | answer a For-you card (section 3g); answered by `item` |
| `r:recap <tab id>` | ask that tab's agent for a recap (section 4b); answered by `recap` |

`k:`, `t:` and `l:` go to the tab the viewer last chose with `s:` (at
first, the tab in `hello.session`); while that tab has ended or the last
`s:` named no open tab, they are dropped.

Key names. `keys` mode accepts only the first row, `instruct` the first
row plus `up` / `down` while the program waits; `text` mode accepts all
(`none` accepts nothing):

| mode | names |
|---|---|
| `keys`, `instruct` | `0` … `9`, `y`, `n`, `enter`, `esc` |
| `instruct`, only while the tab's program waits for an answer | `up`, `down` |
| `text` additionally | `backspace`, `tab`, `shift-tab`, `up`, `down`, `left`, `right`, `home`, `end`, `pageup`, `pagedown`, `delete`, `ctrl-c` |

"Waits for an answer" is decided by the server when the key arrives: the
tab's state is `waiting` (OSC 7501 `state=blocked`, or an agent
hook's permission prompt, section 3a), or its Conversation view has an
open question (section 3b). Working, idle, done or unknown
(no OSC 7501 seen) is not waiting, so `up` / `down` are refused, answered
with `{"t":"rejected","reason":"NotWaiting"}`; the first key after the
state leaves `waiting` is already refused. They exist for arrow-select
menus without numbers (the agent's folder-trust prompt, its permission
and question menus). The gate is there because at an idle prompt Up
recalls an older prompt from history (a `!` shell command or slash command
typed at the desk among them) and Enter would submit it, past every
instruction-line check. Residual risk: a program that reports `blocked`
while its input box is live, or a question left open in the transcript,
re-opens that window; a program that never reports OSC 7501 and writes no
question (including the agent, which does not detect OSC 7501 support
under ConPTY: see "Program status (OSC 7501)" in section 3a, unless its
hooks are installed; its folder-trust prompt comes before any transcript
and any hook)
never gets `up` / `down`, and must be answered at the desk. Clients show
Up/Down only while they would be accepted: in `instruct` mode while the
shown tab's `state` is `waiting` or its conversation has an open question
(in the instruct panel's key row, docs/layout-design.md).

The server maps names to the exact bytes the terminal expects, applies the
session's input policy, and silently drops anything not allowed (except the
`NotWaiting` case above). Clients should still hide controls the current
mode doesn't accept. Unknown frames are ignored. The tables are defined
once, in `src/inputrules/keys.zig`, which the server and both Portal
clients use; so is the clients' key rule: Ctrl, Alt and Meta combinations
send nothing (Ctrl+Enter is not Enter), except Ctrl+C in `text` mode;
Shift+Tab is `shift-tab`.

### 4a. Frame prefixes (the one list)

`shared/frames.zig` (`Prefix`, `classify`) is the one list of the
prefixes above; the desk's dispatch and every client use it, and a new
frame takes a new letter there. Rules:

* Every frame is `<letter>:<rest>`; a frame whose letter is not in the
  list is ignored.
* **`f:` is exactly those two bytes.** Desks before this list forget the
  device on *any* frame starting with `f`, so no other frame may ever
  start with `f` (that is why For-you answers are `i:`, not `f:`). A
  current desk ignores `f:` followed by anything.
* Request families are `<letter>:<verb> <argument>`, exactly one space,
  the verb lower case: `p:start <name>`, `p:stop <name>`, `i:yes <id>`,
  `i:no <id>`, `r:recap <tab id>` (`frames.verb`).
* Each request is answered by one message
  `{"t":"<family>","op":"<verb>","result":"<result>"[,"<ref>":"<value>"]}`
  (`frames.writeAnswer` / `parseAnswer`): `project` (ref `name`), `item`
  (ref `id`, the card), `recap` (ref `id`, the tab). `op` is the frame's
  verb; the reference is the desk's own value for a request it could
  match, never the device's text echoed back, and absent otherwise.
  `rate_limited` (too many requests from this device in the last minute)
  and `refused` (the desk's input mode doesn't allow it) mean the same in
  every family.

### 4b. Recap (`r:recap`, `recap`)

`r:recap <tab id>` asks that open tab's agent for a short recap. The
device sends only the tab; the desk types its own fixed instruction
(`shared/recap.zig` `prompt`) as an instruction line, under the line
rules of section 4. The recap arrives as the agent's reply in that tab's
conversation. Answer
`{"t":"recap","op":"recap","result":"<result>"[,"id":"<tab>"]}`:

| result | meaning |
|---|---|
| `ok` | the prompt was sent |
| `refused` | the desk's input mode is not `instruct` or `text`, or the tab's program is not the agent |
| `rate_limited` | too many requests from this device in the last minute |
| `unknown` | not an open tab, or a malformed frame |

The frame names its tab, so it works for any open tab, not only the one
watched; it is a request, not typing, so a shown sub-tab doesn't block it.

## 5. Behaviour clients should implement

* Reconnect with backoff (1 s doubling to 15 s). After `logout` or a `401`,
  go back to sign-in; after `logout` with reason `unpaired`, or a sign-in
  answered `X-Portal-Device: gone`, forget the desktop instead.
* Keep the window independent of the terminal size: scale the font, or scroll
  or pan, to fit `cols × rows`.
* Show the input mode clearly ("view only", "answer keys", "instructions",
  "typing allowed").
* Show the open tabs (names and colours, the shown one marked, `waiting`
  highlighted) even when there is only one, and let the user switch with
  `s:<id>`. After a reconnect, switch back to the tab the user had chosen
  if it is still open. After `nosession` or `ended`, pick the tab shown if
  it is still open, else the first.
* Portal clients send instruction lines from an input line (the field in
  the instruct panel) and map answer words to keys before sending
  ("Yes." → `k:y`, "two" → `k:2`, "OK" → `k:enter`; one shared table and
  `decide` in `src/inputrules/send.zig`). They check lines with the
  server's rules first, so a refusal is shown without a round trip;
  `rejected` still covers anything they missed, and the line comes back.
  The native
  remote viewers and the desk's own window (owner's decisions,
  2026-11-12) show only Instruct; its panel has Esc, Enter, ↑ ↓ while
  waiting and the question's number keys while no card shows them
  (`keys` mode: the whole answer set; the desk, not policy-limited:
  1–3, ↑ ↓, Esc, Enter always), docs/layout-design.md.

* **Hidden tabs are device-local.** A device may hide tabs from its own
  tab bar (and their For-you cards); it keeps that list itself, by tab
  name, and nothing about it is sent: there is no message for it, the
  desk doesn't know, and every tab stays open and visible at the desk and
  on other devices. A hidden tab still gets `activity`, `foryou` and every
  other message as usual.

## 7. Portal sync (signed packages for paired devices)

The design and the rules are in [sync-design.md](sync-design.md). Sync
runs on the **bulk WebSocket** (`GET /ws/bulk`), its own connection with
the transport's bulk priority, so a large download never delays a
keystroke on the interactive one (`shared/bulk.zig`, the one codec for
both ends). One request at a time; each is answered in full:

* client: a text message `get key` | `get index` |
  `get manifest <id> <version>` | `get file <id> <version> <n>`;
* server: a text message `ok <len> [<signature hex>]`, then the body in
  binary messages of at most 16 KiB, exactly `<len>` bytes in all; or
  `err <code>` (`404`: unknown or not subscribed, they look the same;
  `500`: the store is unavailable; `400`: malformed).

Only the connection's own device is served (the device is its tunnel
address). The bodies are unchanged:

| request | body |
|---|---|
| `get key` | `portal-sync-key-v1\n<64 hex>\n`: the desktop's Ed25519 release public key |
| `get index` | `portal-sync-index-v1\n`, then one line per subscribed package that has a published version, `pkg <id> <version> <sequence> <data\|executable> <total size> <manifest sha256 hex>\n`, then `end\n` |
| `get manifest <id> <version>` | the canonical manifest bytes; the reply header carries the Ed25519 signature over exactly those bytes |
| `get file <id> <version> <n>` | file `n` (0-based, in manifest order, decimal without leading zeros), exactly the manifest's size, streamed |

**Pinning.** On its first connection after pairing (once the CA is pinned
by the SHA-256 in the pairing code), the device asks `get key` and pins
the key for that desktop next to the CA pin. A different key later is
refused; only pairing again replaces the pin.

**Device rules.** The index is advisory. For each line the device fetches
the manifest, checks its SHA-256 against the line, verifies the signature
with the pinned key, parses it strictly, and checks that its package,
version, sequence, kind and size match the line. It installs only a
sequence above anything it ever installed for that package (no downgrade,
no replay), fetches files by index into a staging folder, bounded by and
checked against the manifest's size and SHA-256, and moves them into a new
read-only version folder. `executable` packages wait for approval on the
device, every version; nothing is ever run automatically.

## 6. Voice

iPhone voice = keyboard dictation into the input box; laptops transcribe
locally on their NPU. Portal never records or sends audio from the phone,
and the protocol has no audio messages or routes.
