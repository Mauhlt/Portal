# Project tabs: design notes

**Status (2026-11-12): implemented**, except the per-device recent list
and the hooks / terminal-bell fallbacks for "waiting". What exists:

* `src/tabs.zig`: the tab hub (one program, pseudo console and screen per
  tab, reference counted, random 128-bit ids, display names from the
  folder's basename, "Home" for the profile folder). Colours from the name
  (`shared/tabs.zig`, `colorFromName`) or `color = NAME #rrggbb` in
  settings.txt.
* Desk: Ctrl+Shift+T / "+" (folder picker), Ctrl+Shift+W / "×",
  Ctrl+Tab; `portal open <dir>` and `portalctl open <dir>`
  (`src/openreq.zig`: a request file in the data folder, answered by the
  running Portal).
* Protocol v2 (docs/protocol.md): `hello` lists the sessions, `tabs`,
  `session`, `nosession`, `ended`; `s:<id>` from viewers. Both clients
  (`portal connect`, the browser) draw the same top bar and switch tabs;
  neither can open or close one.
* OSC 7501 is parsed per session (`src/vt.zig`, `parseProgramState`) and
  only highlights a tab (`waiting` = `state=blocked`). Portal answers the
  feature-detection query (docs/protocol.md, "Program status (OSC
  7501)"), but the agent (2.1.323) still never reports its state inside
  ConPTY: conhost answers its DA1 sentinel before any terminal's reply can
  arrive. Checked live 2026-11-12: the probe arrived, Portal replied, no
  `state=` report followed. The hook below (Session.state / Hub.gen) is
  where a fallback would plug in. No agent settings were changed.
* Privacy rules 1, 2, 3, 5, 6 and 7 are covered by `tests/e2e/privacy.zig`
  and `tests/e2e/tabs_tests.zig` (no paths in hello/tabs/session/ended,
  unknown, malformed and closed ids all get the same `nosession`, rejected
  ids logged locally, no message opens or closes a tab). Rule 4 has
  nothing to test until the recent list exists.

## Goal

One Portal window holds several projects. Each project is a tab with a
coloured top bar showing the project name. The colour comes from the name and
can be overridden. When the agent in any tab needs an answer, that tab is
highlighted, so the owner knows which project is asking. Remote viewers
(laptop, iPhone) see the same tab bar and can switch tabs and answer, but can
never open or close projects. That stays desk-only: Ctrl+T folder picker, or
`portal open <dir>`.

## Detecting "The agent is waiting for you"

1. **Primary: in-band program status, OSC 7501.** The agent v2.1.295+
   reports whether each interactive session is working, waiting on the user,
   or done, if the terminal implements the OSC 7501 Program Status Protocol. Portal's own emulator (src/vt.zig) sees all output, so it can
   parse this per session with no agent settings changes.
   * The wire format is not in the vendor's docs. According to
     https://mitchellh.com/writing/program-status-osc7501 it is
     `ESC ] 7501 ; state=<s>[:kind=<k>][:app=<name>][:msg=<base64>] ST`.
   * States: idle, working, blocked (kind permission / question / auth),
     done, error.
   * The agent reports only after its capability probe (`ESC ] 7501 ; ?
     BEL`, then `ESC [ c` as a sentinel) got a reply; see docs/protocol.md,
     "Program status (OSC 7501)", for the format, Portal's reply and why it
     cannot win the race against conhost's own DA reply.
   * Treat the message as untrusted. Program output can contain anything, so
     a hostile file the agent prints could fake a status. It only changes a
     highlight; it never grants input.
2. **Fallback: agent hooks.** Hooks inherit the agent process environment, so Portal sets `PORTAL_SESSION_ID` per tab when spawning it. A `portal hook` command reads the hook JSON from stdin and tells
   the running Portal over a current-user-only local pipe.
   * `PermissionRequest` fires immediately when a permission prompt appears,
     so it marks the tab blocked.
   * `UserPromptSubmit` and `PreToolUse` mean working, so they clear the
     highlight.
   * `Stop` means the turn finished and the agent is waiting for the next prompt.
     It does not fire after an Esc or Ctrl+C interrupt.
   * `StopFailure` means an API error.
   * `Notification` (permission_prompt after ~6 s without typing,
     idle_prompt after ~60 s) is only a backstop.
   * The hook must print nothing to stdout and must return fast.
   * Configuring hooks means editing `~/.claude/settings.json`. **Only with the
     owner's explicit approval.**
3. **Last resort:** `preferredNotifChannel: "terminal_bell"`, which makes
   the agent ring BEL, and vt.zig counts BEL per session. Also a settings
   change, so it too needs the owner's approval.

## Recent projects per device (owner's decision, 2026-11-11)

* The desktop keeps a recent-projects list for each paired device: the
  projects that device viewed, with name, colour and last-used time. It is
  stored server-side alongside the device record, so the phone needs no
  browser storage (no extra JS) and the list survives cache clears.
* A device sees its own list. Projects that are currently open are jumpable
  (switch tab). Closed ones are shown greyed out as history only.
* **Devices never reopen or start projects** (owner chose "switch open tabs
  only"). Reopening a closed project is desk-only: Ctrl+T, `portal open
  <dir>`, or the desk's own recent list. No protocol message can create a
  session.
* Unpairing a device deletes its recent-projects list. It is metadata, not
  training data.

## Privacy rules (owner's requirement: nothing reveals closed projects or other folders)

These are hard requirements for the tabs and recent-projects work, enforced by
`tests/e2e/privacy.zig`. Extend those tests as features land.

1. **No paths leave the desktop.** Remote clients get only a display name (the
   folder's basename, or a desk-set name) and a colour. Full paths, drive
   letters, parent folders, the data directory and the user name never appear
   in any protocol message, header or page. The terminal grid itself is
   exempt; it is the session.
2. **No file-system API.** No route or message lists, opens, reads or browses
   folders or files. Routing stays exact-path; assets are compiled into the
   binary.
3. **Opaque, unguessable ids.** Sessions are addressed by random 128-bit ids
   that are never reused, not by index or path. A viewer may subscribe only
   to ids of **currently open** sessions; anything else gets the same "no such
   session" answer, so probing can't tell closed from never-existed.
4. **Per-device history.** A device sees only its own recent list. Closed
   entries carry name + colour + last-used time only (no id, no path), and
   can't be subscribed to. Closed sessions keep no screen buffer to replay.
   The Conversation view (protocol section 3b) is the one place program
   text leaves the grid as text, by the owner's decision (2026-11-12): it
   is scrubbed on the desktop first (src/convo/scrub.zig: the tab's
   folder becomes its name, other absolute paths `[path]`, the user's
   name `[user]`), and tool arguments, results and thinking are never
   sent. Covered by tests/e2e/convo_tests.zig and privacy.zig.
5. **Program-controlled strings stay in the grid.** Window titles set by
   programs (OSC 0/2, which the agent uses and which can contain paths) are
   not sent as metadata. Tab names are desk-assigned. Inline images are
   part of the session too. They exist only because a program in the
   session emitted them (kitty graphics, `portal show`), and they go only to
   viewers of that session ('I'/'P' frames). No route or message lets a
   client ask for an image or a file, and the server never reads one: kitty
   file and shared-memory transmission (t=f/t/s) are ignored.
6. **Nothing without a session.** Without a live session, every route except
   `/pair` and the static assets reveals nothing: 303 to `/pair` with an empty
   body, or 401.
7. **Logs stay local.** Rejected probes are logged on the desktop (rate
   limited) and never echoed back to the client.

## Protocol changes (v2) — implemented

* `hello` lists sessions: `{id, name, color, state}`. A new `tabs` message
  announces any change: open/close, rename, state.
* Grid and image frames are scoped to the session the viewer watches: the
  server announces a switch with `session` and sends a full snapshot right
  after it. A viewer subscribes to one session at a time (`s:<id>`), and
  input goes to the selected session. There is no message that opens or
  closes a session.
