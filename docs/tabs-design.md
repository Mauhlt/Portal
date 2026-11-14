# Project tabs: design notes

**Status (2026-11-12): implemented**, except the per-device recent list
and the terminal-bell fallback for "waiting". What exists:

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
  (`portal connect`, the iPhone app) draw the same top bar and switch tabs;
  neither can open or close one, except the projects the desk marked
  startable ("Starting projects from a device", below, 2026-11-14).
* OSC 7501 is parsed per session (`src/vt.zig`, `parseProgramState`) and
  only highlights a tab (`waiting` = `state=blocked`). Portal answers the
  feature-detection query (docs/protocol.md, "Program status (OSC
  7501)"), but the agent (2.1.323) still never reports its state inside
  ConPTY: conhost answers its DA1 sentinel before any terminal's reply can
  arrive. Checked live 2026-11-12: the probe arrived, Portal replied, no
  `state=` report followed.
* Agent hooks (fallback 2 below) are implemented, approved by the
  owner 2026-11-12, and installed only on request (`portalctl hooks
  install`, or the desk's Settings, "Claude Code integration"):
  `src/hookmsg.zig` (the message and the mapping), `src/hookpipe.zig`
  (the pipe and `portalctl hook`), `src/agenthooks.zig` (settings.json),
  `Session.setHookState` (the same Hub.gen / convo / notify paths as
  OSC 7501). Covered by unit tests and the e2e `hooks` group.
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
`portal open <dir>`. (Since 2026-11-14 with one exception: the projects
the desk marked startable, "Starting projects from a device" below.)

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
2. **Fallback: agent hooks (implemented).** Hooks inherit the agent process environment, so Portal sets `PORTAL_TAB=<32 hex>` for each tab's program:
   a random 128-bit value per tab launch, added after childenv.zig's
   filter (which still drops every inherited `PORTAL_*`, an inherited
   `PORTAL_TAB` included). It is not the tab's protocol id, and it is
   never logged or sent to a device. `portalctl hook` (console
   subsystem, so stdin is clean) reads the hook JSON from stdin (at most
   1 MiB), keeps `hook_event_name`, `tool_name` and `notification_type`
   (the common fields and the per-event ones), and sends `{tab, event, tool?, ntype?}` as a few text
   lines to the running Portal over a current-user-only local pipe. It
   never prints, always exits 0, never waits more than 200 ms for the
   pipe, and without `PORTAL_TAB` (any agent session outside
   Portal) it exits at once without even parsing.
   * Mapping (hookmsg.effect):
     | Event | Meaning | Tab |
     |---|---|---|
     | `UserPromptSubmit` | the user submitted a prompt | `working` |
     | `PermissionRequest` | a permission prompt is about to show (`tool_name`, `tool_input`) | `waiting`, the permission card "Claude wants to <phrase>. Allow it?" (Yes = `1`, No = `esc`); the phrase from `tool_name`'s category (transcript.category: Bash runs a command, Edit edits a file, ...), any other tool "use a tool": the name itself is never shown |
     | `Notification`, `notification_type` `permission_prompt` | the prompt has waited a few seconds | `waiting` (a backstop) |
     | `Notification`, `idle_prompt` | the session has been idle for about a minute | `idle` (not `waiting`: an idle prompt is not an answer menu, so Up/Down stay refused) |
     | `Stop` | the turn finished (not after a user interrupt) | `done` (then `idle` from idle_prompt) |
     | `StopFailure` | the turn ended with an API error (`error`: rate_limit, ...) | `error` |
     | `SessionEnd` | the session ended (`reason`: clear, logout, prompt_input_exit, ...) | `idle` |
     | `SubagentStart`, `SubagentStop` | a subagent started / ended (`agent_id`) | no state: the tab's sub-tabs ("Subagent sub-tabs" below) |
     Other notification types and every other event change nothing;
     settings.json's Notification entry has the matcher
     `permission_prompt|idle_prompt`, so the others don't even start it.
   * `PreToolUse` (and PostToolUse) are not used: they fire on every tool
     call. So after a permission answer no hook says "working again";
     instead the tab's transcript does: a tool result after a hook's
     permission wait means the prompt was answered (`working`), and
     the agent's interrupt record (`[Request interrupted by user`) means
     `idle` (no Stop follows an interrupt). Residual: a parallel tool's
     result arriving during the prompt ends the highlight early.
   * Precedence: whichever reported last wins. A hook's state stays until
     the program's own OSC 7501 state changes (Session.osc_state).
   * Untrusted: the message is parsed strictly (enumerated events, names
     `[A-Za-z0-9_-]{1,64}`, unknown keys ignored, anything else dropped);
     an id for no open tab changes nothing and is logged at most once a
     minute without the id. A program in the tab can read PORTAL_TAB and
     fake a state, exactly like faking OSC 7501: it only changes a
     highlight and, like a real permission prompt, opens instruct's
     Up/Down gate for that tab (docs/protocol.md section 4).
   * The pipe (hookpipe.zig): `\\.\pipe\portal-hook-<first 16 bytes of
     SHA-256(user SID, data folder)>`; a security descriptor whose owner
     and only ACE are the current user's SID (read/write; no one else,
     not SYSTEM, not Administrators); `PIPE_REJECT_REMOTE_CLIENTS`, so
     no SMB client, from another machine or from this one, and nothing
     a paired device can reach (devices only talk HTTP/WebSocket);
     `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a squatter makes Portal log and
     listen to nothing rather than share. The client opens it with
     `SECURITY_IDENTIFICATION` and sends only if the serving process runs
     as the same user (GetNamedPipeServerProcessId). The server thread
     blocks in an overlapped ConnectNamedPipe next to a stop event and
     reads each client with a 500 ms deadline; one listening instance
     always exists, so back-to-back hooks queue in order. No polling.
   * Installing means editing `~/.claude/settings.json`: approved by the
     owner (2026-11-12) as an explicit action only, `portalctl hooks
     install` or the Settings item; nothing installs it by itself.
     agenthooks.zig adds one matcher group per event in exec form
     (`"command": "<LOCALAPPDATA>\\Portal\\bin\\portalctl.exe", "args":
     ["hook"], "timeout": 10`: with `args` the command is spawned directly, so the Windows path needs no shell quoting),
     textually, keeping every other byte; uninstall cuts exactly those
     entries, so install + uninstall restores the file.
   * Latency: about 20 ms per hook end to end on the development machine
     (the e2e `hooks` group prints it).
3. **Last resort:** `preferredNotifChannel: "terminal_bell"`, which makes
   the agent ring BEL, and vt.zig counts BEL per session. Also a settings
   change, so it too needs the owner's approval.

## Subagent sub-tabs (implemented 2026-11-13)

When the program in a tab starts subagents, each becomes a read-only
sub-tab under that tab, on the desk and on devices: its own
Conversation view, labelled with the subagent's description, marked
done when it ends. Protocol: docs/protocol.md section 3e.

### Where the data is (checked 2026-11-13, structure only)

Inspected read-only on real sessions of this machine with a small
throw-away Zig tool that printed key paths, value types and whether a
value equals a known id; no message text was printed, copied or kept.

* Layout: next to `<projects>\<folder>\<session>.jsonl` the program
  creates a folder `<session>\` holding `subagents\` (and `tool-results\`,
  not read). `subagents\` has two files per subagent:
  `agent-<agentId>.jsonl` and `agent-<agentId>.meta.json` (`agentId`: 17
  characters, `a` and hex digits; nothing else was found there).
* `agent-<id>.jsonl`: the same record format as the session's transcript
  (`user`, `assistant`, `attachment`, `api-request*` records ...). Every
  record has `isSidechain: true`, `agentId` (string, equals the file's
  id), `sessionId` (string, equals the parent session's id), `cwd`,
  `uuid`, `parentUuid` (null on the first record), `timestamp`. The
  first `user` record is the task the session gave the subagent.
* `agent-<id>.meta.json`: one object. `agentType` (string, e.g.
  `general-purpose`, `fork`), `isBuiltIn` (bool), `description`
  (string: the description given to the Agent tool call),
  `toolUseId` (string: equals the parent's `tool_use` block `id` of the
  Agent call), `spawnDepth` (integer), `requestShape`, `pickedEffortModel`
  (strings), `requestNonInteractive`, `launchedWithDefaults` (bools);
  forks add `isFork`, `parentAgentId`, `model`. `finished: true` is
  added when the subagent ends; while it runs the key is absent (5 of
  43 meta files of a running session had none).
* The parent's transcript links the other way: the Agent `tool_use`
  block (`name` `Agent`, `input.description`, `input.subagent_type`),
  and its `tool_result` record's `toolUseResult.agentId` (string;
  `toolUseResult.status` `async_launched` for background ones,
  `canContinueAgent`, `resumedAgentId`, `revivedAgentId`).
* Only `description` and `finished` of the meta file and the sidechain
  records of the subagent's transcript are read; the description is
  scrubbed before it becomes the sub-tab's name.

### How

* Reading (`src/convo/subagents.zig`, a `Watcher` driven by the tab's
  transcript follower, follow.zig, on the same thread and wait): when the
  follower takes a transcript it points the watcher at
  `<folder>\<session>\subagents\`. If that folder does not exist yet, a
  change notification on its nearest existing ancestor waits for it;
  then ReadDirectoryChangesW on it reports new subagents, meta rewrites
  and appends, and the tab's output (the follower's poke) checks the
  sizes of running subagents' transcripts, as for the main one. No
  polling, no timer. The records go through the same parser
  (transcript.parseLine) and model (model.Convo, with `sidechain` set so
  only sidechain records count) as the tab's conversation.
* Model (`src/convo/subtabs.zig`, `Tab.subs`, under the hub's lock):
  at most 16 per tab; random 128-bit ids of Portal's own; the
  subagent's id stays on the desktop; a new transcript in the tab
  (`/clear`, `/resume`) empties the list; when the tab took over an
  earlier session, subagents already finished then are history and get
  no sub-tab.
* Hooks: `SubagentStart` / `SubagentStop` (`agent_id`) travel as
  `agent=<id>` in the hook message (hookmsg.zig) and reach
  `Tab.subagentEvent` (tabs.zig), the one seam: start gives the sub-tab
  at once, stop marks it done; both kick the watcher to look again. The
  files stay the source of the conversation. `portalctl hooks install`
  adds both events (they come from hookmsg.Event).
* Viewers: `subtabs` lists them for the tab watched; `a:<id>` shows one
  (web.zig sends its conversation instead of the tab's; the viewer's
  `k:`/`t:`/`l:` are dropped meanwhile), `a:` goes back. The desk copies
  the shown sub-tab's conversation through the same writer and parser
  into its own Conversation view (gui.zig).
* UI (ui/shell.zig): the shown tab's sub-tabs follow it in the top bar
  ("▸ <description>", "· done" when finished, the tab's
  colour, no close box). Shown, the main slice is its conversation, the
  bottom is empty (no Instruct), the status line says "subagent: <name>
  · read-only", and keys reach nothing; a click on the parent tab
  goes back.
* Privacy: names and texts are scrubbed on the desktop; no path, user
  name, subagent id, session id, tool argument or result leaves it
  (tests/e2e/subtabs_tests.zig checks every message).

## Recent projects per device (owner's decision, 2026-11-11)

* The desktop keeps a recent-projects list for each paired device: the
  projects that device viewed, with name, colour and last-used time. It is
  stored server-side alongside the device record, so the phone needs no
  storage of its own.
* A device sees its own list. Projects that are currently open are jumpable
  (switch tab). Closed ones are shown greyed out as history only.
* **Devices never reopen or start projects** (owner chose "switch open tabs
  only"). Reopening a closed project is desk-only: Ctrl+T, `portal open
  <dir>`, or the desk's own recent list. No protocol message can create a
  session. *Superseded in part (owner, 2026-11-14): a device may start a
  project the desk marked startable, nothing else; see "Starting projects
  from a device".*
* Unpairing a device deletes its recent-projects list. It is metadata, not
  training data.

## Starting projects from a device (owner's decision, 2026-11-14)

The owner approved (mockup, screen 3) that a paired device may start a
project, but only one the desk allowed, and only as safely as the desk
chose. What exists:

* **The list is the desk's.** settings.txt `startable = NAME | MODE |
  FOLDER`, at most 16 (src/settings.zig), edited in the desk's Projects
  panel (ui/panels/projects.zig, src/deskprojects.zig; Ctrl+Shift+J) or
  with `portalctl startable add | remove | list`. The file is the one
  source; the running Portal follows it (main.zig, SettingsWatch: a
  directory change notification, no polling) and devices get the new
  list at once.
* **Devices see names only.** `{"t":"projects"}` (docs/protocol.md 3f)
  carries each project's name, colour, mode and whether it runs and may
  be stopped; never a folder (privacy rule 1, checked by the e2e
  `projects` group with privacy.checkMessages). A name is a
  `startableName` (shared/projects.zig): a tab name without `\ / : | "`,
  not starting with `-`, `.` or a space, so it can never be read as a
  path, a drive, an option or a settings field.
* **A request is a name, nothing more.** `p:start <name>` / `p:stop
  <name>` (src/projects_ws.zig): the exact verb, then a name that must
  equal one of the desk's (case-sensitive). The folder, the program, its
  arguments and the permission mode all come from the desk; nothing of
  the request but the name is used, and answers carry the desk's own
  spelling, never the device's text.
* **Never a permissive session.** Portal itself adds `--permission-mode
  default` (Ask: every edit and command asks) or `--permission-mode plan`
  (Plan: read-only planning) to the launch (cmdline.launchArgs), and only
  for the agent: a device start is refused (`unsafe_program`) when the
  program setting is not the agent or its arguments hold a flag that
  skips, widens or pre-answers permission prompts, or picks the mode
  itself (`--dangerously-*`, `--allow-dangerously-*`, `--permission-mode`,
  `--allowedTools` / `--allowed-tools`, `--permission-prompt-tool`;
  cmdline.deviceStart). The program is found on PATH again for every tab
  (tabs.Program, Hub.open), so a reopened project runs the agent installed
  now even if an update moved it, and the check runs again on the program
  as found (cmdline.deviceStartResolved).
* **Bounded.** Refused in input mode `none`; at most 3 starts and 3 stops
  a minute per paired device, across its connections (timestamps only,
  no timer); a malformed or unknown name counts too, so probing is
  limited. An already running project is not started twice: the device
  is switched to it (`switched`).
* **Only what a device started can a device stop.** `p:stop` of a
  session started at the desk is `not_device_started`; a device-started
  one is asked to exit like the desk's ×, and ended after 10 s.
* **The desk sees it.** The tab reads "<name> · started by <device>"
  ("(plan)" for plan mode), then "stopped by <device>"; the desk's log
  names the device, the project and the permission mode. A device start
  does not take the desk's view away from the tab it shows. The device
  that started it is switched to the new tab.

Residual risks (accepted by design, or outside Portal's reach):

* **Ask is the agent's own guard.** `--permission-mode default` only
  makes the agent ask; what it asks and how it enforces the answer is
  the agent's. Its settings files (`~/.claude/settings.json`, a project's
  `.claude/settings.json` / `settings.local.json`) can pre-allow tools
  (`permissions.allow`) or hooks that then run without a question; Portal
  checks its own command line, not those files. Plan mode is likewise
  enforced by the agent.
* **Input mode `text` can leave Ask or Plan.** In `text` mode a device may
  send Shift+Tab, which cycles the agent's permission modes. `text` is
  full remote control by definition (README); `instruct` and `keys` can't.
* **A started session is driven by the same device rules as any tab.**
  Approving prompts from the device (keys, For you) is as strong as the
  input mode allows; a stolen paired device gains "start an allowed
  project" on top of what it could already do in open tabs, until it is
  unpaired.
* **PATH decides which `claude` runs.** Portal runs what PATH finds when
  the tab opens (never the current folder); a program planted earlier on
  PATH under the agent's name would run, exactly as for a desk start. The
  name check (deviceStartResolved) does not authenticate the binary.
* **settings.txt is the user's file.** Any process running as the user can
  add startable folders, the same trust as the program setting.
* **Any device can stop any device-started session**, not only its own;
  stopping asks the agent to exit, and Portal ends it 10 s later.
* **Rate limits are per device.** A re-paired device starts with a fresh
  window; 3 a minute bounds bursts, not slow abuse.

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
   folder becomes its name, the home folder `[home]`, other absolute
   paths `[path]`, the user's names `[user]`), and tool arguments, results and thinking are never
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
