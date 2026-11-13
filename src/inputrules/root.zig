//! Module "inputrules": what a paired device may send, and how every client
//! turns a key press or an input line into protocol frames
//! (docs/protocol.md §4). The one definition, used by the server
//! (src/keymap.zig), the native client (client/src) and the browser client
//! (src/wasm), so every device offers the same keys and the same instruction
//! line with the same checks. Pure logic, std only.
//!
//!   keys.zig  input policy, the allowed key names (and their bytes, for the
//!             server), the client-side key rule, instruction-line checks,
//!             the text-mode guard
//!   send.zig  the input line: answer words, what Send does (`decide`),
//!             answer buttons, refusal and help texts

pub const keys = @import("keys.zig");
pub const send = @import("send.zig");

// The policy and key names.
pub const Policy = keys.Policy;
pub const Key = keys.Key;
pub const answer_keys = keys.answer_keys;
pub const text_keys = keys.text_keys;
pub const menu_keys = keys.menu_keys;
pub const isMenuKey = keys.isMenuKey;
pub const lookup = keys.lookup;
pub const lookupAt = keys.lookupAt;
pub const keyBytes = keys.keyBytes;
pub const keyBytesAt = keys.keyBytesAt;
pub const KeyError = keys.KeyError;
pub const allowed = keys.allowed;
// Clients: key presses at the terminal.
pub const Mods = keys.Mods;
pub const Action = keys.Action;
pub const special = keys.special;
pub const specialAt = keys.specialAt;
pub const char = keys.char;
pub const printable = keys.printable;
pub const frame = keys.frame;
// Instruction lines and text mode (server checks; clients check first).
pub const max_line_bytes = keys.max_line_bytes;
pub const LineError = keys.LineError;
pub const validateLine = keys.validateLine;
pub const TextGuard = keys.TextGuard;
pub const sanitizeText = keys.sanitizeText;
// The input line.
pub const AnswerButton = send.AnswerButton;
pub const answer_buttons = send.answer_buttons;
pub const menu_buttons = send.menu_buttons;
pub const showMenuButtons = send.showMenuButtons;
pub const answerKey = send.answerKey;
pub const keyLabel = send.keyLabel;
pub const Refusal = send.Refusal;
pub const Decision = send.Decision;
pub const decide = send.decide;
pub const collapse = send.collapse;
pub const max_frame = send.max_frame;
pub const refusalText = send.refusalText;
pub const serverRefusal = send.serverRefusal;
pub const Tone = send.Tone;
pub const Note = send.Note;
pub const Device = send.Device;
pub const preview = send.preview;
pub const help = send.help;
pub const placeholder = send.placeholder;

test {
    _ = keys;
    _ = send;
}
