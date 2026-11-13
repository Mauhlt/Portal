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
│ ┏ Question · swipe left for Yes … ━━━ [⋯] ┓ │  Yes/No: a swipe card
│ ┃ Run npm test?                           ┃ │
│ ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ │
│             [↓ New messages]               │  only when scrolled up
├────────────────────────────────────────────┤
│ ③ Data · nothing yet                       │
├────────────────────────────────────────────┤
│ ② [🎤 Instruct]  [Keys]                    │  one row
├────────────────────────────────────────────┤
│ status line                                │
└────────────────────────────────────────────┘
```

* **Questions carry their own controls.** A Yes/No question (exactly two
  options reading yes / no; a permission prompt is Yes = `1`, No = `esc`)
  is a **swipe card**: by default swipe **left = Yes, right = No** (the
  owner is left-handed; one device setting, `swipe = left-yes | right-yes`
  in the device's settings.txt next to its pinned servers, e.g.
  `%APPDATA%\Portal\settings.txt`), with touch or a mouse drag; the Left /
  Right arrows follow the same mapping. The card follows the pointer with a
  slight tilt, tints towards the side's colour and fades in a green YES or
  red NO stamp; released past the threshold it flies off and the answer key
  goes out through the answer path (`k:<key>`), earlier it springs back.
  Its "⋯" reveals explicit Yes / No buttons. Other questions show their
  options as large buttons (the answer bar's hit-target height). Answered
  cards keep their text; their controls go.
* **Swipe safety** (accidental approvals): only the newest open question;
  only past 40 % of the card width and at least 96 logical px; only when the
  horizontal movement dominates (twice the vertical; anything else scrolls
  the list); not within 600 ms of the card really reaching the screen
  (measured from the frame that showed it, no timers); a tap that became a
  drag never presses a button (view buttons fire on release).
* **The answer bar is hidden**; **Keys** shows it (Esc to interrupt,
  Enter). The **instruction line is hidden**; **Instruct** opens it with
  the keyboard (the touch keyboard on a tablet) and calls
  `Shell.startDictation`'s hook, where speech-to-text plugs in (iPhone: the
  native text field, Apple dictation one tap away; laptops: "speech coming
  soon" until Portal's mic → stt pipeline exists). Esc or a sent line
  closes it again. In `keys` mode only Keys is offered, in view-only mode
  neither.
* **Dictation toggles** (owner decision): press to start, press again to
  stop; the text lands in the instruction line for review, the user sends.
  `Shell.toggleDictation` (the input action `toggle_dictation`) calls the
  device's `Dictation.start` / `.stop` hook; while it runs the bottom row
  shows a red "● Listening…" (its button stops). On Windows devices Space
  toggles it only when no text field has the keyboard (in the line, Space
  types a space); a headset's play / pause button (`media_play_pause`)
  toggles it only when `Shell.headsetMicPresent()` says a headset with a
  microphone is attached: a predicate hook for the audio work (../Audio,
  IMMDevice form factor), false until then. (The Renderer's Win32 window
  does not deliver WM_APPCOMMAND yet: the glue has nothing to map.)
* While the Conversation view is shown the keyboard does not reach the
  terminal (no stray answers): PageUp / PageDown / Home / End scroll, the
  arrows answer the swipe card.
* The **Terminal view** keeps the full interaction slice (answer bar, and
  the instruction line in `instruct` mode).
* Scrolling: wheel, vertical drag, PageUp / PageDown / Home / End. At the
  bottom the list follows new items; scrolled up it stays anchored on the
  item at the top and a pill offers the newest. A tab without a transcript
  shows "No conversation log for this tab — use Terminal".
* Event-driven: frames on conversation changes, input and resizes only; a
  fly-off / spring-back (≤ 180 ms) sets a frame deadline while it runs.

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
