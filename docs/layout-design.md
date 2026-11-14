# Layout: slices on every platform

**Owner decision (2026-11-12, revised the same day):** every device (the
desktop window, the laptop viewer `portal connect`, the iPhone app) uses
the same layout: three slices stacked **vertically**, under the
top bar.

```
┌────────────────────────────────────────────┐
│ usage strip (plan limits; hidden w/o data) │
│ top bar (project name, project tabs later) │
├────────────────────────────────────────────┤
│ ① terminal                                 │  the biggest share
│                                            │
├────────────────────────────────────────────┤
│ ③ Data · nothing yet          [Hide (F2)]  │  a thin strip while empty;
│   (images, newest first, left to right)    │  grows when there is data
├────────────────────────────────────────────┤
│ ② [🎤 Instruct]                            │  big enough to see and tap;
│                                            │  opens the instruct panel
├────────────────────────────────────────────┤
│ status line                                │  (native windows)
└────────────────────────────────────────────┘
```

## Slices

### ① Terminal

* The live terminal grid, rendered by Portal from its own emulator.
* A header that explains the session (the top bar; extended with project
  tabs separately, docs/tabs-design.md):
  * project name ("No project" by default);
  * the **session state**: working / waiting for you / done / error. It
    comes from the program's own status signal (OSC 7501, see
    docs/tabs-design.md), sent to viewers as `{"t":"state", ...}` on
    change. It is never derived from program-set titles (privacy rule);
  * the remote-viewer badge.
* Viewers fill the slice with the remote grid (see "Terminal scaling").

### ③ Data (between the terminal and the interaction slice)

* Visualizes data the session pushes. Nothing is fetched or browsed (privacy
  rules in docs/tabs-design.md).
* Kinds:
  * today: images (kitty graphics / `portal show`);
  * next: tables and charts from CSV/JSON (`portal show data.csv`), drawn in
    Zig.
* A small history per session, with bounded memory (module `datafeed`).
* **Size:** one rule on every device, `datafeed.sliceHeight`: a header strip
  ("Data · nothing yet") while empty or collapsed; with items, the header
  plus what the items would like (a caption line and the tallest image at up
  to 1 image pixel per logical / CSS pixel, no wider than the window), at
  most `datafeed.max_share` (38 %) of the height the terminal and the Data
  slice share. Clearing it shrinks it back to the strip.
* Items are laid out left to right, newest first, each a caption over its
  image fitted to the slice height.
* Header buttons: **Hide / Show** (also F2 in the native windows) collapses
  it to the strip, which then counts what is new ("· 2 new"); **Clear**
  empties it.

### ② Interaction (at the bottom)

* Native windows (the desk and the native remote viewers, owner decisions
  2026-11-12): only the **Instruct** button; it opens the **instruct
  panel** (the instruction line with Send, dictation, a compact key row;
  see "Only Instruct at the bottom" below). Typed, Apple
  dictation on the iPhone, or the local NPU transcriber later
  (docs/audio-design.md).
* Large enough to see and tap: native windows draw the buttons and the box
  with a 16 px font (`TermView.action_em`, the rest of the chrome is 13 px),
  the buttons all the same width.
* Send behaviour: answer words become keys; anything else is a checked
  instruction line (`l:`), using instruct mode, the default.
* **The desk matches the devices** (owner decision, 2026-11-12): its
  bottom is only Instruct too, which opens the same instruct panel. The
  keyboard types straight into the terminal as before whenever the panel's
  line does not have it: Instruct gives the line the keyboard, a click on
  the terminal gives it back (the panel stays open; a click on the line
  takes it again). The desk has full control, so its Send types the line
  and presses Enter with no line checks (inputline with `policy = text`);
  answer words ("yes", "two", "esc") still press their keys. Its key row
  is not policy-limited: 1, 2, 3 (more while a question offers more), ↑,
  ↓, Esc, Enter, always. Esc on an empty line, Send or Close shuts the
  panel (an Esc with the terminal focused is the terminal's). The Data
  strip, the status line and the top bar are unchanged.

## For you (devices and the desk; the owner's mockup, screen 1)

Under the latest reply the Conversation view draws the tab's **For you**
panel (ui/foryou.zig; the cards: docs/tabs-design.md, "For you"):

```
┌ FOR YOU ───────────────────── [↺ Recap] ┐  Recap: instruct / text only
│ Sent.                                    │  the last answer's result
│ ┌ waiting  Wants to run a command…   › ┐ │  amber: the agent is blocked
│ ┌ run      zig build e2e             › ┐ │
│ ┌ answer   Shall I commit this?      › ┐ │
│ Swipe a row to answer, or tap it to …    │
└──────────────────────────────────────────┘
```

* **Swipe a row** to answer it directly: the Yes side per the device's
  `swipe = left-yes | right-yes` (left by default). **Tap** a row to toggle
  its full card (what it waits for, the question, the command in a code
  box, why, which way is which); the card swipes the same way, and a tap
  or Esc folds it back.
* **One gesture.** Rows and cards use the Conversation view's swipe (its
  target is a question card or a For-you row): the same guard (not within
  600 ms of the row first appearing, past 40 % of its width), lean
  colours, spring-back and fly-off. The answer leaves as `i:yes <id>` /
  `i:no <id>`, never as a key.
* **Keys:** ←/→ answer the focused row (or its open card), ↑/↓ move the
  focus, Enter toggles, Esc folds.
* **Input mode `none`:** the rows are shown, not swipeable ("View only").
  A suggestion's yes in `keys` mode is refused on the device already.
* **One approval UI:** while the panel holds the tab's permission prompt,
  the conversation's own permission card is not drawn.
* **The desk too.** The desk window's top bar has a **Conversation**
  button (after the desk tools) that toggles its main slice between the
  terminal (the default: the desk keeps the terminal) and the tab's
  conversation, with the same panel under the latest reply: the same
  swipe, toggle and keys. It is fed from the desk's own For-you state
  (src/foryou_desk.zig) in process, with no network, and its answers take
  the one path device `i:` / `r:` frames take (foryou_ws.handle) as the
  desk: input mode `text` (the owner at the keyboard may do anything a
  `text`-mode device could), no rate limit, its lines and keys typed as
  the desk's own. A sub-tab's read-only conversation has no panel.

## Devices: the Conversation view, minimal by default

**Owner decisions (2026-11-12):** paired devices (`portal connect`, the
iPhone app) open on the **Conversation view** (ui/convoview.zig), not the
terminal; the top bar's Terminal | Conversation toggle switches. The desk
keeps the terminal. In the Conversation view the window is minimal:

```
┌────────────────────────────────────────────┐
│ tabs ...               [Terminal][Convers.]│
├────────────────────────────────────────────┤
│                       ┌──────────────────┐ │  the owner's prompt: bubble
│                       │ fix the tests    │ │
│                       └──────────────────┘ │
│ Assistant text, word-wrapped, full width;  │  `inline code` in the code
│ inline code in the code colour             │  colour, backticks hidden
│ ┌────────────────────────────────────────┐ │  ``` code: monospaced, panel
│ │ zig build test                         │ │  colour, clipped not wrapped
│ └────────────────────────────────────────┘ │
│ ▸ Edited 2 files                           │  tool one-liners: small, dim
│ ┏ Question · swipe left for Yes, right … ━┓ │  two options: a swipe card
│ ┃ Run npm test?                           ┃ │
│ ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ │
│             [↓ New messages]               │  only when scrolled up
├────────────────────────────────────────────┤
│ ③ Data · nothing yet                       │
├────────────────────────────────────────────┤
│ ② [🎤 Instruct]                            │  only Instruct (both views)
├────────────────────────────────────────────┤
│ status line                                │
└────────────────────────────────────────────┘
```

* **Questions carry their own controls.** A question with exactly **two
  options** is a **swipe card** and has no buttons at all. A Yes/No one
  (options reading yes / no; a permission prompt is Yes = `1`, No = `esc`)
  answers by default **left = Yes, right = No** (the
  owner is left-handed; one device setting, `swipe = left-yes | right-yes`
  in the device's settings.txt next to its pinned servers, e.g.
  `%APPDATA%\Portal\settings.txt`), with touch or a mouse drag; the Left /
  Right arrows follow the same mapping. Any other pair is a choice: the
  first option on the Yes side, the second on the other, the card's header
  says which ("swipe left: Postgres · right: SQLite"), and it tints towards
  the neutral `swipe_choice` blue on both sides. Pressed, the card is grabbed: it
  grows slightly (about 4.5 %, eased in over 120 ms) with a short decaying
  shake (three swings of 2 degrees over 180 ms) and a light haptic on the
  iPhone (`View.haptic`), and stays enlarged while held. Dragged, it
  follows the pointer with a slight tilt, its colour moving from the held
  yellow towards green on the Yes side and red on the No side, full at the
  threshold (theme roles `swipe_hold` / `swipe_yes` / `swipe_no`; colour
  only: no text stamp, no transparency). Released past the threshold it
  flies off (from its enlarged size) and the answer key goes out through
  the answer path (`k:<key>`); earlier it springs back to its place and
  size. Questions with **more than two options** show them as large
  numbered buttons (the answer bar's hit-target height); a multi-choice
  shows its options plus Done (Enter). Answered cards keep their text;
  their controls go. A question without options says to answer it in the
  Terminal view.
* **Swipe safety** (accidental approvals): only the newest open question;
  only past 40 % of the card width and at least 96 logical px; only when the
  horizontal movement dominates (twice the vertical; anything else scrolls
  the list); not within 600 ms of the card really reaching the screen
  (measured from the frame that showed it to the press, no timers; the
  grab feedback is not guarded, answering is); a tap that became a
  drag never presses a button (view buttons fire on release).
* **Only Instruct at the bottom, in both views** (owner decision,
  2026-11-12, for the native remote viewers: `portal connect` on a laptop
  or Surface, and the iPhone app; the desk got the same bottom later that
  day, see "② Interaction"): no answer
  bar, no Yes / No / 1 / 2 / 3 buttons, and the **instruction line is
  hidden**. **Instruct** opens the **instruct panel**
  (`Shell.instructBottom`): a row with Dictate / "● Listening…"
  (with speech-to-text) and **Close**, the instruction line with Send
  (it has the keyboard; the touch keyboard on a tablet), and a compact
  **key row** for what a line can't express (`Shell.keyRow`): **Esc** and
  **Enter** always; **↑ / ↓** only while the shown tab's program waits for
  an answer (the server's rule, docs/protocol.md §4: tab state `waiting`
  or an open question); the **number keys** only while the open question
  offers numbered options and no card shows them (the Terminal view, or a
  card answered here already: `convoview.View.questionKeys`). Opening it
  calls `Shell.startDictation`'s hook, where speech-to-text plugs in
  (iPhone: the native text field, Apple dictation one tap away; laptops:
  none until Portal's mic → stt pipeline exists). **Esc** on an empty
  line (in a non-empty one it clears the text first), **Send** or
  **Close** shuts the panel: back to Instruct only. In `keys` mode the
  panel has no line, its key row is the whole answer set (Yes, No, 1–3,
  Esc, Enter); view only shows nothing. Option labels on cards drop a
  scrubbed path or name and the joiner word before it ("Beta in [path]"
  reads "Beta", `convoview.shortLabel`).
* **Dictation toggles** (owner decision): press to start, press again to
  stop; the text lands in the instruction line for review, the user sends.
  `Shell.toggleDictation` (the input action `toggle_dictation`) calls the
  device's `Dictation.start` / `.stop` hook; while it runs the bottom row
  shows a red "● Listening…" (its button stops). On Windows devices Space
  toggles it only when no text field has the keyboard (in the line, Space
  types a space). On the desk Space never toggles it: with the panel's
  line unfocused the terminal has the keyboard and Space is typed there,
  so the desk toggles dictation only with the panel's mic button and the
  headset's media key. A headset's play / pause button (`media_play_pause`)
  toggles it only when `Shell.headsetMicPresent()` says a headset with a
  microphone is attached: a predicate hook for the audio work (../Audio,
  IMMDevice form factor), false until then. The Renderer's Win32 window
  delivers WM_APPCOMMAND's play / pause as `Event.media`; the Presenter
  maps it to `media_play_pause` (only while Portal's window has the
  keyboard focus; macOS / iOS remote commands are a later step).
* While the Conversation view is shown the keyboard does not reach the
  terminal (no stray answers): PageUp / PageDown / Home / End scroll, the
  arrows answer the swipe card.
* The **Terminal view** has the same bottom (only Instruct, the instruct
  panel on request); with the panel closed the keyboard goes to the
  terminal, filtered by the input mode as everywhere.
* Scrolling: wheel, vertical drag, PageUp / PageDown / Home / End. On the
  iPhone one finger is the pointer (the window reports touches as
  down / move / up, `Frame.touch`): a sideways drag swipes the card, a
  vertical one scrolls, a drag over the terminal scrolls its rows, and
  every button acts on release only (a drag or a cancelled touch never
  presses one). At the
  bottom the list follows new items; scrolled up it stays anchored on the
  item at the top and a pill offers the newest. A tab without a transcript
  shows "No conversation log for this tab — use Terminal".
* Event-driven: frames on conversation changes, input and resizes only; the
  grab feedback (≤ 180 ms) and a fly-off / spring-back (≤ 180 ms) set frame
  deadlines while they run.

## The usage strip (every screen)

A thin strip above the top bar, desk and devices alike: the window's first
line, on a phone directly under the system's clock and status line
(`ui/usage_strip.zig`, drawn by `frame.drawUsage`; owner-approved mockup,
2026-11-14). While it shows, the top bar is drawn that much lower; hidden
(no data), the top bar is the first line again and nothing moves.

```
┌────────────────────────────────────────────┐
│ Week 62% · resets Mon                      │  the usage strip: one line
│ ▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬───────────────│  and a slim meter
│ ● Portal  ● WireGuard          [⋯ 3 hidden]│  top bar (tabs)
├────────────────────────────────────────────┤
```

* It shows whichever plan window is closer to its limit (`planusage.higher`:
  the week or the five-hour window) with its reset: "resets 14:20" within a
  day, "resets Mon" further out, local time. At the limit: "5-hour limit
  reached · resets 14:20".
* Neutral below 75 %, amber (`yellow_warmer`) from 75 %, red from 90 % and
  at the limit (shared/theme.zig). A toast says once when a window passes
  75 % or 90 %, or the limit is reached (each window's steps start over
  when it resets); the toast's end is the glue's one deadline for it.
* A tap or click toggles the detail: both windows, each with its meter and
  reset day and time, and where the numbers come from.
* No data (API-key sessions, or nothing reported yet): no strip. Where the
  numbers come from and when devices get them: docs/protocol.md section
  3h, docs/tabs-design.md "The plan-usage bar".

## Hidden tabs (devices)

A device may hide tabs from its own tab bar (`ui/hidden_tabs.zig`;
docs/protocol.md section 5). A tidy-up of this device's bar, not a
security control: the desk and other devices still show every tab, and a
hidden tab still gets every message.

* Hide: a long press on a tab (held at least 500 ms, measured between
  press and release: no timer) or a right-click opens its menu: "Hide this
  tab", and "Close (desk only)" shown disabled. Ctrl+Shift+H hides the tab
  shown. Hiding the tab shown switches to the next visible one; a hidden
  tab that is shown (the desk's choice on a first connect) stays in the bar
  until the user switches away. Ctrl+Tab skips hidden tabs.
* The bar then ends in "⋯ N hidden" (the open tabs hidden). It turns
  amber with a dot while a hidden tab is waiting for an answer (the tab
  state `waiting`) or has For-you items that need the desk.
* It opens the sheet "Hidden on this device": each hidden tab's colour
  dot, name and state (waiting for your answer / working / idle) and
  Show, which puts the tab back and switches to it. Esc or Close closes it.
* The list is tab names, at most 64 (the oldest dropped), in
  `hidden-tabs.txt` next to the device's `settings.txt` (one name per line;
  client/src/net/pin.zig), so it survives reconnects and restarts. Names of
  projects that are closed may stay in it; a tab of that name that opens
  again starts hidden.

## Terminal scaling (viewers)

The remote grid's size is the desk's. A viewer picks its cell size from the
terminal slice and the grid's dimensions (`TermView.fitEm`):

* the cell size at which the **columns fill the slice width**;
* made smaller so every row fits too, but **not below a readable size**
  (12 logical / CSS px);
* if the rows still do not fit, the view shows the lowest rows with content,
  keeping the cursor in view (`followTop` / `followPan`);
* the grid is top-aligned and centred across: no empty band above it.

It is recomputed on every resize and every grid size change (event-driven).
The desk itself keeps a fixed font and sizes the PTY to its terminal slice.

## Implementation notes

* Native (desk and laptop): TermView's `Layout` (`regions`): top bar,
  the usage strip (`usage`, `Overlay.usage`), terminal, `data` (`Overlay.data`, a `DataSlice`), the bottom panes
  (`Overlay.bottom`: `.answers`, `.field` with its `send` button), status
  line; a modal panel layer over all of them; a single focus owner per host.
  The feed: `client/src/dataview.zig`, used by `portal connect` and the
  desk window (src/gui.zig).
* A modal panel taller than the window keeps its buttons at the bottom of
  the box and scrolls the rest (the wheel, a drag on a touch screen, a slim
  bar at its right edge); a newly focused field or chosen row is scrolled
  into view (`frame.panelScroll`).
* Text that does not fit is shortened with an ellipsis (`frame.fitText`):
  labels at their end, folder paths in a panel row in the middle so their
  end stays (`PanelRow.detail`). Short of room, tabs give up the longest
  labels first but keep three characters each; when even that does not
  fit, the bar shows the tabs around the active one with a "‹" / "›" that
  switches to the next tab out of view (`frame.fitTabs`). The status line
  never overlaps: the label, then the tab's tasks, then the right-hand
  text, then the extra get room, cut or dropped in that order
  (`frame.packStatus`).
* Data frames reuse the image path ('I'/'P'), plus later typed data frames
  with explicit size limits.
* Interaction is one manner on every device: the input policy, the key
  names, the answer buttons and what Send does are defined once
  (`src/inputrules`) and used by the server and all clients.
* Not yet: scrolling the Data history, a draggable splitter between the
  terminal and the Data slice, keyboard focus moving between slices.
