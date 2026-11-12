# Layout: slices on every platform

**Owner decision (2026-11-12):** each platform (desktop, laptop, iPhone) uses a
split-screen design:

1. **Terminal slice:** explains the current terminal.
2. **Interaction slice:** input box plus buttons.
3. **Room for a third slice:** visualizes any data.

The layout is the same on desktop and laptop. The iPhone gets a variant for
the small screen.

## Slices

### ① Terminal

* The live terminal grid, rendered by Portal from its own emulator.
* A header that explains the session:
  * project name ("No project" by default);
  * the **session state**: working / waiting for you / done / error. It
    comes from the program's own status signal (OSC 7501, see
    docs/tabs-design.md), sent to viewers as `{"t":"state", ...}` on
    change. It is never derived from program-set titles (privacy rule);
  * the remote-viewer badge.

### ② Interaction

* The input box: typed, Apple dictation on the iPhone, or the local NPU
  transcriber on the laptop (docs/audio-design.md).
* Answer buttons (Yes, No, 1–3, Esc, Enter), 🎤 where local speech exists,
  and Send.
* Send behaviour: answer words become keys; anything else is a checked
  instruction line (`l:`), using instruct mode, the default.

### ③ Data

* Visualizes data the session pushes. Nothing is fetched or browsed (privacy
  rules in docs/tabs-design.md).
* Kinds:
  * today: images (kitty graphics / `portal show`);
  * next: tables and charts from CSV/JSON (`portal show data.csv`), drawn in
    Zig.
* A small scrollable history per session, with bounded memory, and a badge
  when something new arrives while the slice is hidden.

## Per platform

**Desktop / laptop (Vulkan app):** editor-style splits.

```
┌──────────────── ① ──────────────┬────── ③ ──────┐
│ terminal (+ state header)        │ data          │
├──────────────── ② ──────────────┤ (resizable,   │
│ input box · buttons              │  collapsible) │
└──────────────────────────────────┴───────────────┘
```

* Splitters are draggable.
* Data collapses to a thin edge when empty.
* Focus moves between slices with keyboard shortcuts.

**iPhone (wasm page):** the interaction slice is pinned at the bottom, above
the on-screen keyboard. The top switches between **Terminal | Data** with a
segmented control (and swipe), with a badge on Data when new data arrives.

## Implementation notes

* The desktop and laptop share TermView's `Layout` (stackable bottom panes,
  modal panel layer, single focus owner), extended with a right-hand Data
  column.
* The browser client uses a slice model in `src/wasm/` with the same three
  slices.
* Data frames reuse the image path ('I'/'P'), plus later typed data frames
  with explicit size limits.
* Status (2026-11-12): both clients have the Data slice, on one shared
  model (`src/datafeed`: bounded history, the "new" badge). The native
  client draws it as a right-hand column (`TermView.DataColumn`,
  `client/src/dataview.zig`), shown when the window is at least 640
  logical px wide; F2 shows/hides it; while hidden, the status line counts
  new items. Not yet: a draggable splitter, scrolling the history, keyboard
  focus moving between slices.
* Interaction is one manner on every device: the input policy, the key
  names, the answer buttons and what Send does are defined once
  (`src/inputrules`) and used by the server and both clients.
