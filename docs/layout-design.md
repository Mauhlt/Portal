# Layout: slices on every platform

**Owner decision (2026-11-12, revised the same day):** every device (the
desktop window, the laptop viewer `portal connect`, the iPhone / browser
page) uses the same layout: three slices stacked **vertically**, under the
top bar.

```
┌────────────────────────────────────────────┐
│ top bar (project name, project tabs later) │
├────────────────────────────────────────────┤
│ ① terminal                                 │  the biggest share
│                                            │
├────────────────────────────────────────────┤
│ ③ Data · nothing yet          [Hide (F2)]  │  a thin strip while empty;
│   (images, newest first, left to right)    │  grows when there is data
├────────────────────────────────────────────┤
│ ② [Yes] [No] [1] [2] [3] [Esc] [Enter]     │  big enough to see and tap
│   [ input box ......................][Send]│
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

* Answer buttons (Yes, No, 1–3, Esc, Enter), the input box and Send: typed,
  Apple dictation on the iPhone, or the local NPU transcriber later
  (docs/audio-design.md).
* Large enough to see and tap: native windows draw the buttons and the box
  with a 16 px font (`TermView.action_em`, the rest of the chrome is 13 px),
  the buttons all the same width; the browser uses 52 px buttons on touch
  screens (two rows of four on phones narrower than ~400 px), 44 px with a
  mouse, and 18 px labels.
* Send behaviour: answer words become keys; anything else is a checked
  instruction line (`l:`), using instruct mode, the default.
* On the desk the slice exists too: typing goes to the terminal as before
  unless the input box has focus (click it; Esc on an empty box or a click
  on the terminal gives the keyboard back). The desk has full control, so
  its Send types the text and presses Enter (inputline with `policy =
  text`); the answer buttons press their keys.

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
│ Assistant text, word-wrapped, full width   │
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
  or Surface, and the iPhone app; the desk keeps its full bar, the browser
  its button row): no answer bar, no Yes / No / 1 / 2 / 3 buttons, and the
  **instruction line is hidden**. **Instruct** opens the **instruct
  panel** (`Shell.viewerBottom`): a row with Dictate / "● Listening…"
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
  types a space); a headset's play / pause button (`media_play_pause`)
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

## Terminal scaling (viewers)

The remote grid's size is the desk's. A viewer picks its cell size from the
terminal slice and the grid's dimensions (`TermView.fitEm`,
`src/wasm/layout.zig` fit):

* the cell size at which the **columns fill the slice width**;
* made smaller so every row fits too, but **not below a readable size**
  (12 logical / CSS px);
* if the rows still do not fit, the view shows the lowest rows with content,
  keeping the cursor in view (`followTop` / `followPan`); in the browser,
  panning by hand stops following until Fit;
* the grid is top-aligned and centred across: no empty band above it.

It is recomputed on every resize and every grid size change (event-driven).
The desk itself keeps a fixed font and sizes the PTY to its terminal slice.

## Implementation notes

* Native (desk and laptop): TermView's `Layout` (`regions`): top bar,
  terminal, `data` (`Overlay.data`, a `DataSlice`), the bottom panes
  (`Overlay.bottom`: `.answers`, `.field` with its `send` button), status
  line; a modal panel layer over all of them; a single focus owner per host.
  The feed: `client/src/dataview.zig`, used by `portal connect` and the
  desk window (src/gui.zig).
* Browser: `src/wasm/slices.zig` computes the four rects (header, terminal,
  data, interaction) from the visual viewport; on a short screen with the
  keyboard open it sheds the header and the Data slice first. The page
  (`src/web/index.html`, `app.css`) only places what wasm decides; `app.js`
  stays logic-free.
* Data frames reuse the image path ('I'/'P'), plus later typed data frames
  with explicit size limits.
* Interaction is one manner on every device: the input policy, the key
  names, the answer buttons and what Send does are defined once
  (`src/inputrules`) and used by the server and all clients.
* Not yet: scrolling the Data history, a draggable splitter between the
  terminal and the Data slice, keyboard focus moving between slices.
