# Portal client protocol (v1)

Used by every client: the browser viewer, and the native Zig + Vulkan clients
for Windows, Linux and macOS. Transport is HTTP/1.1 + WebSocket (RFC 6455)
over the WireGuard tunnel, plain HTTP inside the tunnel.

## 1. Sign in

```
POST /login HTTP/1.1
Host: 10.8.0.1:8420
Origin: http://10.8.0.1:8420
Content-Type: application/x-www-form-urlencoded
Content-Length: <n>

token=<access token>
```

* Success: `303 See Other`, `Location: /`, and
  `Set-Cookie: portal_session=<43 chars>; Path=/; HttpOnly; SameSite=Strict; Max-Age=...`
  (`__Host-portal` plus `Secure` when the server runs with `--https`).
* Failure: `303` to `/login?e=1`, or `/login?e=locked` after repeated failures.
  A correct token is always accepted.
* `Host` must match the server's allowlist and `Origin` must be
  `http://<that host>`. Native clients must send both exactly.
* Native clients keep the cookie value only in memory. They should never write
  the token to disk unless an OS credential store is used.

`POST /logout` with the cookie and the same `Origin` ends the session.

## 2. Open the stream

```
GET /ws HTTP/1.1
Host: 10.8.0.1:8420
Origin: http://10.8.0.1:8420
Cookie: portal_session=<value>
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
| `hello` | `input`: `"none"`, `"keys"` or `"text"` | sent first; which input is accepted |
| `exit` | `code` | the session's program exited; stream ends |
| `logout` | | session revoked or expired; sign in again |

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

## 4. Client → server

Text frames only, at most 4096 bytes.

| frame | meaning |
|---|---|
| `k:<name>` | press a key |
| `t:<utf8>` | type text (only when `input` is `"text"`) |

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
