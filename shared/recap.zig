//! Recap on the wire (docs/protocol.md section 4b): a device asks a tab's
//! agent for a short recap. The device sends only the tab; the desk types
//! its own fixed prompt (`prompt`), never text from the device.
//!
//!   device -> server
//!     r:recap <tab id, 32 hex>
//!   server -> device
//!     {"t":"recap","op":"recap","result":"<result>"[,"id":"<tab id>"]}
//!
//! The recap itself arrives as the agent's reply in the tab's Conversation
//! view (`convo+`), like any other reply.

const std = @import("std");
const tabs = @import("tabs.zig");
const frames = @import("frames.zig");

pub const Id = tabs.Id;

/// The one instruction the desk sends for `r:recap`, as an instruction
/// line (one line, no leading `!`, `/` or `#`: it passes the desk's own
/// line rules).
pub const prompt = "Please give me a short recap: what you have done so far, where things stand now, and what comes next.";

pub const Op = enum { recap };

/// "r:recap <32 hex>".
pub fn requestFrame(tab: Id) [8 + tabs.hex_len]u8 {
    var out: [8 + tabs.hex_len]u8 = undefined;
    out[0..8].* = "r:recap ".*;
    out[8..].* = tabs.idHex(tab);
    return out;
}

/// What follows "r:": exactly "recap " and a tab id, or null (answered
/// `unknown`).
pub fn parseRequest(rest: []const u8) ?Id {
    const v = frames.verb(Op, rest) orelse return null;
    return tabs.parseId(v.arg);
}

pub const Result = enum {
    /// The prompt went to the tab's agent; the recap follows in its
    /// conversation.
    ok,
    /// The desk's input mode for devices is not `instruct` or `text` (a
    /// recap is an instruction line), or the tab's program is not the
    /// agent.
    refused,
    /// Too many requests from this device in the last minute.
    rate_limited,
    /// Not an open tab (or a malformed frame).
    unknown,

    /// What a device shows.
    pub fn text(r: Result) []const u8 {
        return switch (r) {
            .ok => "Asked for a recap.",
            .refused => "This desk's input mode does not allow that.",
            .rate_limited => "Too many requests: wait a minute.",
            .unknown => "That tab is not open.",
        };
    }
};

/// The answer to `r:recap`. `tab` (an open tab's id) only for a known tab.
pub fn writeResult(w: *std.Io.Writer, result: Result, tab: ?Id) !void {
    const hex = if (tab) |t| tabs.idHex(t) else undefined;
    try frames.writeAnswer(w, "recap", "recap", @tagName(result), "id", if (tab != null) &hex else null);
}

pub const Answer = struct { result: Result, tab: ?Id };

/// A `recap` message, or null.
pub fn parseResult(text: []const u8) ?Answer {
    var s: frames.Scratch = undefined;
    const a = frames.parseAnswer(text, "recap", "id", &s) orelse return null;
    _ = std.meta.stringToEnum(Op, a.op) orelse return null;
    return .{
        .result = std.meta.stringToEnum(Result, a.result) orelse return null,
        .tab = if (a.ref) |r| tabs.parseId(r) orelse return null else null,
    };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "request frame round trip" {
    const id: Id = @splat(0xc3);
    const f = requestFrame(id);
    try testing.expectEqualStrings("r:recap c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3", &f);
    const fr = frames.classify(&f).?;
    try testing.expectEqual(frames.Prefix.recap, fr.prefix);
    try testing.expectEqual(id, parseRequest(fr.rest).?);
    for ([_][]const u8{ "recap", "recap ", "recap c3", "Recap c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3", "recap  c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3", "recap c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3 please", "summary c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3" }) |bad|
        try testing.expect(parseRequest(bad) == null);
}

test "results round trip" {
    var buf: [frames.max_answer]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeResult(&w, .ok, @splat(1));
    try testing.expectEqualStrings("{\"t\":\"recap\",\"op\":\"recap\",\"result\":\"ok\",\"id\":\"01010101010101010101010101010101\"}", w.buffered());
    const a = parseResult(w.buffered()).?;
    try testing.expect(a.result == .ok and a.tab.?[0] == 1);
    var w2: std.Io.Writer = .fixed(&buf);
    try writeResult(&w2, .unknown, null);
    try testing.expect(parseResult(w2.buffered()).?.tab == null);
    try testing.expect(parseResult("{\"t\":\"recap\",\"op\":\"recap\",\"result\":\"busy\"}") == null);
    try testing.expect(parseResult("{\"t\":\"recap\",\"op\":\"summary\",\"result\":\"ok\"}") == null);
}

test "the prompt is one plain instruction line" {
    try testing.expect(std.mem.indexOfAny(u8, prompt, "\r\n\t") == null);
    try testing.expect(prompt[0] != '!' and prompt[0] != '/' and prompt[0] != '#');
    try testing.expect(prompt.len <= 2000);
}
