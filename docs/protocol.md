# Portal client protocol (v2: project tabs)

Used by every client: the browser viewer, and the native Zig + Vulkan clients
for Windows, Linux and macOS. Transport is HTTP/1.1 + WebSocket (RFC 6455)
over the WireGuard tunnel, inside TLS 1.3 (HTTPS / WSS on the same port).
The server certificate is issued by the desktop's private Portal CA; clients
must trust that CA (Export certificate in the Portal window, or `portalctl
ca export`) or pin it, and must offer TLS 1.3
with x25519 and ecdsa_secp256r1_sha256 (ALPN, if sent, must include
`http/1.1`). `portal run --no-tls` (or `portalctl run --console --no-tls`) serves plain HTTP for tests; replace
`https`/`wss` with `http`/`ws` and drop the `__Host-` cookie names below.

## 1. Pairing and sign-in (no passwords)

Every POST needs `Host` on the server's allowlist and `Origin: https://<that
host>`, sent exactly; native clients must send both. POST bodies are empty
(`Content-Length: 0`).

**Pair (once per device), approved at the desk.** The owner chooses Pair a
device in the Portal window (or runs `portalctl pair <name>`), which opens
a 2-minute window and asks the owner about every device that requests
pairing. Nothing is typed on the device. The client sends:

```
POST /pair HTTP/1.1
Host: 10.8.0.1:8420
Origin: https://10.8.0.1:8420
Content-Length: 0
```

* Request registered: `303`, `Location: /pair/wait`, with
  `Set-Cookie: __Host-portal_pairreq=<43 chars>; Path=/; HttpOnly; SameSite=Strict; Max-Age=600; Secure`,
  the request token. No credential yet.
* No window open, or the window already approved a device: `303` to `/pair?e=closed`.
* Too many pending requests (8 per window, 2 per address): `303` to `/pair?e=busy`.
* This address was denied in this window: `303` to `/pair?e=denied`.

Then wait for the answer, from the same source address and with the
request cookie. `GET /pair/wait` is a long poll:

```
GET /pair/wait HTTP/1.1
Cookie: __Host-portal_pairreq=<43 chars>
```

* Waiting for the desk: `200`, an HTML page showing the 4-hex-digit
  request code that the desk also shows. The same code is in the header
  `X-Portal-Request-Code: 7f3a`, for native clients, which read only the
  response head. Show the code to the user.
  The first `GET /pair/wait` for a request token is answered at once.
  Every later one, while the request is still pending, is **held** by
  the server until the pairing window changes (a request answered, the
  window closed, replaced or expired, its `portalctl pair` gone) or 25 s
  pass, and is then answered exactly as described here (the same waiting
  page if still pending). Clients re-ask immediately after each answer:
  there is no poll interval. Allow at least 30 s for the response; back
  off only on network errors, and give up when the request's 10-minute
  lifetime is over. Browsers do the same without script: the waiting
  page has `<meta http-equiv="refresh" content="0">`, and the browser
  keeps showing it while the held reload is pending.
* Approved: `303`, `Location: /`, with three `Set-Cookie` headers:
  * `__Host-portal_device=<name>.<43 chars>; Path=/; HttpOnly; SameSite=Strict; Max-Age=7776000; Secure`
    is the device credential;
  * `__Host-portal=<43 chars>; ...; Secure` is a session;
  * the request cookie, cleared (`Max-Age=0`).
  This happens once; the request is then used up.
* Denied: `303` to `/pair?e=denied`. Expired, unknown, used, or asked from
  another address: `303` to `/pair?e=expired`. Both clear the request cookie.
* With `--no-tls` the names are `portal_device` / `portal_session` /
  `portal_pairreq`, without `Secure`.

**Sign in (every launch or reconnect).** Present the device credential:

* Browsers: `GET /` with the device cookie. Returns `303 /` with a
  rotated device cookie and a new session.
* Native clients: `POST /auth/refresh` with the device cookie.
  Returns `204` with the same two `Set-Cookie` headers, or `401` if the
  device is unknown or revoked. A `401` that also carries
  **`X-Portal-Device: gone`** means, unambiguously, that this desktop no
  longer has the device: it was unpaired at the desk (`portalctl unpair`,
  the Devices panel), forgot itself (`POST /device/forget`), was replaced
  by a re-pair, was revoked by theft detection, or presented a credential
  that matches no record. The device then **forgets this desktop** (its
  credential, CA pin, release-key pin and sync folder) and says why. Any
  other answer (a `401` without the header, a `5xx`, no answer) is never
  a reason to forget anything.

The device secret **rotates on every sign-in**, so clients must replace the
stored value immediately. Each superseded value stays valid for 10 minutes
from the sign-in that replaced it (the last 4 are remembered), which
survives a lost response and several tabs signing in at once; that window
is never extended. Presenting anything older or wrong revokes the device
(theft detection), and re-pairing is then required. A removed record's
secrets are remembered (as hashes, up to 32, for 90 days after its last
use): presenting one gets `X-Portal-Device: gone` and touches nothing, so
an old device cannot revoke a newer pairing under its name. Credentials
are bound to the device's source (WireGuard) address; a known credential
presented from another address gets `303 /pair`, or a `401` *without*
the gone header (it is not removed).
Native clients store the device credential only in the OS credential
store and keep the session in memory.

**Re-pairing** a name (or an address) already in use removes the old
record outright and ends every one of its sessions (WebSockets, input,
`/sync`) before the new credential is issued; nothing of it is kept.

`POST /device/forget` (Origin required, the session cookie; the device
is taken from the session, never from the request): the device's "Forget
this desktop". The desktop removes the record, ends all its sessions
(open WebSockets get `logout` with reason `unpaired`), logs it and
refreshes the desk's Devices panel. `204` (with `X-Portal-Device: gone`)
when done; `401` without a live session (sign in first; that answer may
already be `gone`); `500` if the device store is unavailable (nothing
was removed). Clients call it first and then forget locally whatever the
answer; if the desktop can't be reached they say that it still lists the
device until it next sees it (and answers `gone`) or the owner unpairs it.

`POST /logout` unpairs this device and ends its sessions. It uses the
session cookie, or, if the session has expired, the device credential
(checked like a sign-in). Success: `303 /pair?bye`; nothing to unpair:
`303 /pair`.

## 2. Open the stream

```
GET /ws HTTP/1.1
Host: 10.8.0.1:8420
Origin: https://10.8.0.1:8420
Cookie: __Host-portal=<value>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64 of 16 random bytes>
Sec-WebSocket-Version: 13
```

`101 Switching Protocols` on success; `401` means sign in again. Client
frames must be masked; no fragmentation; no extensions.

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
| `logout` | `reason` (optional): `"unpaired"` or `"replaced"` | the session ended. `"unpaired"`: the desktop removed this device (unpaired at the desk, forgotten, revoked): forget this desktop now. `"replaced"`: a re-pair under its name or address replaced it: sign in again, whose answer (`X-Portal-Device: gone` or not) decides. No reason (expired, logged out): sign in again |
| `updates` | | Portal sync: this device's package index changed (a publish, or a subscription changed at the desk). Fetch `GET /sync/index` (section 7). Devices also look on every connect |
| `rejected` | `reason` | an `l:` instruction line was refused (e.g. `ShellEscape`, `SlashCommand`, `MemoryShortcut`, `ControlCharacter`, `TooLong`, `Empty`); nothing was typed |
| `convo` | `id`, `on`, `items` | the whole Conversation view of the tab watched (section 3b): after `hello` and every `session`, and whenever the server starts the conversation over. Replaces what the client had |
| `convo+` | `id`, `items` | new or changed items of that conversation (section 3b) |

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
* `state`: what the program reports through OSC 7501: `unknown`,
  `working`, `waiting` (it needs an answer: highlight the tab), `idle`,
  `done`, `error`. Untrusted (any program output can contain it): it only
  changes a highlight.

At most 12 tabs. Grid, image and placement frames always belong to the tab
the viewer watches, which is the desk's tab at connect (`hello.session`)
and then whatever the viewer chose with `s:<id>` (answered by `session`,
then a full snapshot). Only the desk opens and closes tabs (the window,
`portal open <dir>`); no message a client sends can create, start, close
or reopen one. The shared parser and writer are `shared/tabs.zig`.

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
  injected context, subagent transcripts. Every text is scrubbed on the
  desktop: the tab's folder becomes the tab's name (`acme\src\a.zig`),
  any other absolute path becomes `[path]` (drive, UNC, `\\?\`, POSIX,
  `file://`, `~/`, `%VAR%\`, `$HOME/`, URL-encoded), the user's name
  `[user]` (docs/tabs-design.md, privacy rule 1).
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

`k:`, `t:` and `l:` go to the tab the viewer last chose with `s:` (at
first, the tab in `hello.session`); while that tab has ended or the last
`s:` named no open tab, they are dropped.

Key names. `keys` and `instruct` mode accept only the first row; `text`
mode accepts all (`none` accepts nothing):

| mode | names |
|---|---|
| `keys`, `instruct` | `0` … `9`, `y`, `n`, `enter`, `esc` |
| `text` additionally | `backspace`, `tab`, `shift-tab`, `up`, `down`, `left`, `right`, `home`, `end`, `pageup`, `pagedown`, `delete`, `ctrl-c` |

The server maps names to the exact bytes the terminal expects, applies the
session's input policy, and silently drops anything not allowed. Clients
should still hide controls the current mode doesn't accept. Unknown frames
are ignored. The tables are defined once, in `src/inputrules/keys.zig`,
which the server and both Portal clients use; so is the clients' key rule:
Ctrl, Alt and Meta combinations send nothing (Ctrl+Enter is not Enter),
except Ctrl+C in `text` mode; Shift+Tab is `shift-tab`.

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
* Both Portal clients send instruction lines from an input line (the
  browser's text box, so phone dictation works; the native client's field
  under the answer bar) and map answer words to keys before sending
  ("Yes." → `k:y`, "two" → `k:2`, "OK" → `k:enter`; one shared table and
  `decide` in `src/inputrules/send.zig`). They check lines with the
  server's rules first, so a refusal is shown without a round trip;
  `rejected` still covers anything they missed, and the line comes back.
  The answer buttons are the same on both: Yes, No, 1, 2, 3, Esc, Enter.

## 7. Portal sync (signed packages for paired devices)

The design and the rules are in [sync-design.md](sync-design.md). Every
route is `GET`, needs the session cookie (`401` without a live one), and
serves only the session's own device: packages it is not subscribed to,
and anything unknown, answer `404`. Responses carry `Content-Length`;
connection timeouts, slot limits and rate limits are the usual ones.

| route | body |
|---|---|
| `GET /sync/key` | `portal-sync-key-v1\n<64 hex>\n`: the desktop's Ed25519 release public key; header `x-portal-sync-key-fingerprint: AB:CD:...` (SHA-256 of the 32-byte key) |
| `GET /sync/index` | `portal-sync-index-v1\n`, then one line per subscribed package that has a published version, `pkg <id> <version> <sequence> <data\|executable> <total size> <manifest sha256 hex>\n`, then `end\n` |
| `GET /sync/pkg/<id>/<version>/manifest` | the canonical manifest bytes; header `x-portal-signature: <128 hex>`, Ed25519 over exactly those bytes |
| `GET /sync/pkg/<id>/<version>/file/<n>` | file `n` (0-based, in manifest order, decimal without leading zeros) as `application/octet-stream`, exactly the manifest's size, streamed |

**Pinning.** Right after pairing (the `/pair/wait` that returns the
credential), the device asks `GET /sync/key` with its new session, over the
CA-pinned TLS connection, and pins the key for that server next to the CA
pin (`<host>.sync-key` in the per-user config folder). A different key
later is refused; only pairing again replaces the pin.

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
