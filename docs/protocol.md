# Portal client protocol (v1)

Used by every client: the browser viewer, and the native Zig + Vulkan clients
for Windows, Linux and macOS. Transport is HTTP/1.1 + WebSocket (RFC 6455)
over the WireGuard tunnel, inside TLS 1.3 (HTTPS / WSS on the same port).
The server certificate is issued by the desktop's private Portal CA; clients
must trust that CA (`portal ca export`) or pin it, and must offer TLS 1.3
with x25519 and ecdsa_secp256r1_sha256 (ALPN, if sent, must include
`http/1.1`). `portal run --no-tls` serves plain HTTP for tests; replace
`https`/`wss` with `http`/`ws` and drop the `__Host-` cookie names below.

## 1. Pairing and sign-in (no passwords)

Every POST needs `Host` on the server's allowlist and `Origin: https://<that
host>`, sent exactly; native clients must send both. POST bodies are empty
(`Content-Length: 0`).

**Pair (once per device).** The owner runs `portal pair <name>` at the
desktop, which opens a 2-minute, single-use window. The client then sends:

```
POST /pair HTTP/1.1
Host: 10.8.0.1:8420
Origin: https://10.8.0.1:8420
Content-Length: 0
```

* Success: `303`, `Location: /`, with two `Set-Cookie` headers:
  * `__Host-portal_device=<name>.<43 chars>; Path=/; HttpOnly; SameSite=Strict; Max-Age=7776000; Secure`
    is the device credential;
  * `__Host-portal=<43 chars>; ...; Secure` is a session.
* No window open: `303` to `/pair?e=closed`.
* With `--no-tls` the names are `portal_device` / `portal_session`, without `Secure`.

**Sign in (every launch or reconnect).** Present the device credential:

* Browsers: `GET /` with the device cookie. Returns `303 /` with a
  rotated device cookie and a new session.
* Native clients: `POST /auth/refresh` with the device cookie.
  Returns `204` with the same two `Set-Cookie` headers, or `401` if the
  device is unknown or revoked.

The device secret **rotates on every sign-in**, so clients must replace the
stored value immediately. The previous value stays valid for 10 minutes to
survive a lost response. Presenting anything older or wrong revokes the
device (theft detection), and re-pairing is then required. Credentials are
bound to the device's source (WireGuard) address. Native clients store the
device credential only in the OS credential store and keep the session in
memory.

`POST /logout` with the session cookie unpairs this device and ends its
sessions.

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
| `hello` | `input`: `"none"`, `"keys"`, `"instruct"` or `"text"` | sent first; which input is accepted |
| `exit` | `code` | the session's program exited; stream ends |
| `logout` | | session revoked or expired; sign in again |
| `rejected` | `reason` | an `l:` instruction line was refused (e.g. `ShellEscape`, `SlashCommand`, `MemoryShortcut`, `ControlCharacter`, `TooLong`, `Empty`); nothing was typed |

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

### Inline images (`'I'` and `'P'` frames)

Images appear only because a program running in the session emitted them
(kitty graphics protocol, see `src/vt_gfx.zig`; `portal show <file.png>`
does it from a shell or from the agent's Bash tool). There is no message or
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
  Unknown ids in `'P'` are skipped.
* Blobs are rate limited per viewer (8 MiB burst, 4 MiB/s) so images can't
  starve grid updates; a placement appears once its blob has been sent.
* Old clients that predate these frames ignore them and simply show no
  images.

## 4. Client → server

Text frames only, at most 4096 bytes.

| frame | meaning |
|---|---|
| `k:<name>` | press a key |
| `t:<utf8>` | type text (only when `input` is `"text"`; a `!` typed at the start of a line is dropped) |
| `l:<line>` | an instruction line (`"instruct"` and `"text"`): Portal rejects a leading `!` (shell), `/` (slash command) or `#` (memory), control characters, line breaks and bidi controls, max 2000 bytes; otherwise it types the line (as a bracketed paste when the program enabled it) and presses Enter |

Key names. `keys` mode accepts only the first row; `text` mode accepts all:

| mode | names |
|---|---|
| `keys` | `0` … `9`, `y`, `n`, `enter`, `esc` |
| `text` additionally | `backspace`, `tab`, `shift-tab`, `up`, `down`, `left`, `right`, `home`, `end`, `pageup`, `pagedown`, `delete`, `ctrl-c` |

The server maps names to the exact bytes the terminal expects, applies the
session's input policy, and silently drops anything not allowed. Clients
should still hide controls the current mode doesn't accept. Unknown frames
are ignored.

## 5. Behaviour clients should implement

* Reconnect with backoff (1 s doubling to 15 s). After `logout` or a `401`,
  go back to sign-in.
* Keep the window independent of the terminal size: scale the font, or scroll
  or pan, to fit `cols × rows`.
* Show the input mode clearly ("view only", "answer keys", "typing allowed").
