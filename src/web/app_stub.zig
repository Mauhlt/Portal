//! TEMPORARY stand-in for the removed browser client (src/wasm). src/web.zig
//! still embeds "app_wasm" and its test checks the module's imports and
//! exports against src/web/app.js, until feat/inproc-tunnel drops the
//! browser routes. Then delete this file, `browserStub` in build.zig and
//! the rest of src/web/. Nothing here runs: the
//! externs are referenced only so that the module declares them.

extern "env" fn log() void;
extern "env" fn get_origin() void;
extern "env" fn ws_open() void;
extern "env" fn ws_send() void;
extern "env" fn ws_close() void;
extern "env" fn canvas_size() void;
extern "env" fn present() void;
extern "env" fn request_frame() void;
extern "env" fn set_timer() void;
extern "env" fn check_session() void;
extern "env" fn navigate_pair() void;
extern "env" fn set_text() void;
extern "env" fn set_layout() void;
extern "env" fn set_class() void;
extern "env" fn box_read() void;
extern "env" fn box_write() void;
extern "env" fn box_hint() void;
extern "env" fn set_tab() void;

/// Never true for a real caller (app.js passes 0 or 1).
export fn init(magic: u32) void {
    if (magic != 0x7f7f7f7f) return;
    inline for (.{ log, get_origin, ws_open, ws_send, ws_close, canvas_size, present, request_frame, set_timer, check_session, navigate_pair, set_text, set_layout, set_class, box_read, box_write, box_hint, set_tab }) |f| f();
}
export fn in_alloc() u32 {
    return 0;
}
export fn resize() void {}
export fn frame() void {}
export fn on_ws_open() void {}
export fn on_ws_close() void {}
export fn on_ws_message() void {}
export fn on_timer() void {}
export fn on_check() void {}
export fn on_key() void {}
export fn on_pointer() void {}
export fn on_wheel() void {}
export fn on_cmd() void {}
export fn on_viewport() void {}
export fn on_box_input() void {}
export fn on_box_key() void {}
export fn on_button() void {}
export fn on_ptab() void {}
