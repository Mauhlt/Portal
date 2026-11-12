//! The server's view of remote input: the policy, key name -> bytes, the
//! instruction-line checks and the text-mode guard. Defined once in the
//! shared module "inputrules" (src/inputrules/keys.zig), which the native
//! and browser clients use too, so all devices offer exactly what the server
//! accepts.

const rules = @import("inputrules");

pub const Policy = rules.Policy;
pub const keyBytes = rules.keyBytes;
pub const max_line_bytes = rules.max_line_bytes;
pub const LineError = rules.LineError;
pub const validateLine = rules.validateLine;
pub const TextGuard = rules.TextGuard;
pub const sanitizeText = rules.sanitizeText;
