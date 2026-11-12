# Project tabs: design notes (next step after the GUI terminal lands)

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
   * The capability probe is undocumented. **Capture real ConPTY output to
     confirm the format and whether the agent emits it unprompted** before
     relying on it.
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

## Protocol changes (v2)

* `hello` lists sessions: `{id, name, color, state}`. A new `tabs` message
  announces any change: open/close, rename, state.
* Grid frames carry a session id. A viewer subscribes to one session at a
  time (`s:<id>`), and input goes to the selected session. There is no
  message that opens or closes a session.
