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

## Protocol changes (v2)

* `hello` lists sessions: `{id, name, color, state}`. A new `tabs` message
  announces any change: open/close, rename, state.
* Grid frames carry a session id. A viewer subscribes to one session at a
  time (`s:<id>`), and input goes to the selected session. There is no
  message that opens or closes a session.
