//! Module "portal_ui": the one Portal UI every native device runs (the
//! desk's window, `portal connect` on a laptop, the iPhone app). It turns
//! state into a draw list and input into actions; device code only binds
//! it to an OS (window, input source, credential store) and to the session
//! or connection behind it.
//!
//!   shell      the Portal screen: top bar + tabs (+ view toggle on
//!              devices), main slice (terminal | conversation), Data slice,
//!              interaction slice, status line; input routing and focus.
//!              Parameterised by `Device` (.desk, .viewer). Glue feeds a
//!              `shell.State` per frame and implements `shell.Host`.
//!   frame      layout, widgets and draw-list generation (Overlay: the
//!              description of one frame), hit-testing, cell mapping
//!   draw       the draw list: rects, glyphs, text runs, images
//!   panels     desk (setup, pairing, devices, export), projects (which
//!              folders devices may start), setup (a device's
//!              first run), sync (approvals, packages), status (background
//!              tasks, usage, system): state machines / builders that
//!              describe frame.Panels
//!   inputline  the interaction slice's input line (rules: "inputrules")
//!   dictation  what a dictated transcript in the line becomes (stt
//!              feedback: learn, discard, or nothing)
//!   dataview   the Data slice's state (model: "datafeed")
//!   convo      the conversation items a device keeps (shared/convo.zig)
//!   projects_sheet  a device's Projects sheet (start / open / stop the
//!              projects the desk allowed)
//!   convoview  the Conversation view (a frame.ContentView): the items as a
//!              scrollable list, question cards, Yes/No swipe cards
//!   foryou     the For-you panel under the latest reply (its rows swipe
//!              with convoview's gesture) and the device's store of cards
//!   grid       the terminal snapshot model the frame draws
//!   form       text fields and focus rings for panels
//!   qr         QR code encoder (the desk's pairing code, Panel.qr)
//!   input      keys, mods, pointer, InputSink, the answer buttons
//!   theme      the colour scheme (shared/theme.zig: one file)
//!
//! Imports: std, "Font" (metrics and cell widths, std only), "shared",
//! "inputrules", "datafeed". No window system, no GPU: the view module
//! (client/src/view, Presenter) draws `frame.Frame.list` with the Renderer's
//! Instanced2D on desk and laptop, and the iPhone app does the same through
//! MoltenVK.

pub const shell = @import("shell.zig");
pub const frame = @import("frame.zig");
pub const draw = @import("draw.zig");
pub const grid = @import("grid.zig");
pub const form = @import("form.zig");
pub const qr = @import("qr.zig");
pub const input = @import("input.zig");
pub const inputline = @import("inputline.zig");
pub const dataview = @import("dataview.zig");
pub const convo = @import("convo.zig");
pub const convoview = @import("convoview.zig");
pub const foryou = @import("foryou.zig");
pub const projects_sheet = @import("projects_sheet.zig");
pub const dictation = @import("dictation.zig");
pub const theme = @import("shared").theme;
pub const panels = struct {
    pub const desk = @import("panels/desk.zig");
    pub const setup = @import("panels/setup.zig");
    pub const sync = @import("panels/sync.zig");
    pub const status = @import("panels/status.zig");
    pub const audio = @import("panels/audio.zig");
    pub const projects = @import("panels/projects.zig");
};

pub const Shell = shell.Shell;
pub const Frame = frame.Frame;
pub const Overlay = frame.Overlay;
pub const DrawList = draw.DrawList;

test {
    _ = shell;
    _ = frame;
    _ = draw;
    _ = grid;
    _ = form;
    _ = qr;
    _ = inputline;
    _ = dataview;
    _ = convo;
    _ = convoview;
    _ = foryou;
    _ = projects_sheet;
    _ = panels.setup;
    _ = panels.desk;
    _ = panels.status;
    _ = panels.audio;
    _ = panels.projects;
    _ = dictation;
}
