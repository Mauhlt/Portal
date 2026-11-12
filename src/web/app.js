// Portal browser bridge: UNAVOIDABLE BROWSER GLUE, NO APPLICATION LOGIC.
// The viewer is Zig compiled to WebAssembly (src/wasm/, served as
// /static/app.wasm). Browsers can only start WebAssembly from JavaScript,
// so this file (1) instantiates the module, (2) forwards DOM events into its
// exports and (3) implements its host imports, each a one-line wrapper
// around a browser API. Every decision (protocol, drawing, layout, key
// mapping, taps, reconnects, status text) is made in wasm. web.zig's tests
// check this file defines exactly the imports app.wasm declares.
'use strict';
(async () => {
  const cv = document.getElementById('screen'), ctx = cv.getContext('2d');
  const enc = new TextEncoder(), dec = new TextDecoder();
  let X = null, ws = null; // wasm exports; the one WebSocket
  const mem = () => new Uint8Array(X.memory.buffer); // re-made: memory can grow
  const str = (p, n) => dec.decode(mem().subarray(p, p + n));
  // Copy bytes into wasm's input buffer; returns the length for the handler.
  const put = (b) => { const p = X.in_alloc(b.length); if (p) mem().set(b, p); return b.length; };
  const env = {
    log: (p, n) => console.log('portal:', str(p, n)),
    get_origin: (p, cap) => enc.encodeInto(location.protocol + '//' + location.host, mem().subarray(p, p + cap)).written,
    ws_open: (p, n) => {
      const s = ws = new WebSocket(str(p, n));
      s.binaryType = 'arraybuffer';
      s.onopen = () => X.on_ws_open();
      s.onmessage = (e) => typeof e.data === 'string'
        ? X.on_ws_message(0, put(enc.encode(e.data))) : X.on_ws_message(1, put(new Uint8Array(e.data)));
      s.onclose = () => { if (ws === s) ws = null; X.on_ws_close(); };
    },
    ws_send: (p, n) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(str(p, n)); },
    ws_close: () => { if (ws) ws.close(); },
    canvas_size: (w, h) => { cv.width = w; cv.height = h; },
    present: (p, w, h, y0, y1) => ctx.putImageData(
      new ImageData(new Uint8ClampedArray(X.memory.buffer, p, w * h * 4), w, h), 0, 0, 0, y0, w, y1 - y0),
    request_frame: () => requestAnimationFrame(() => X.frame()),
    set_timer: (ms) => setTimeout(() => X.on_timer(), ms),
    check_session: () => fetch('/', { credentials: 'same-origin', cache: 'no-store' }).then(
      (r) => X.on_check(r.status, put(enc.encode(new URL(r.url).pathname))), () => X.on_check(0, 0)),
    navigate_pair: () => location.assign('/pair'),
    set_text: (slot, p, n, cls) => {
      const el = document.getElementById(slot ? 'mode' : 'status');
      el.textContent = str(p, n);
      el.className = el.id + ['', ' ok', ' bad'][cls];
    },
  };
  try {
    const { instance } = await WebAssembly.instantiateStreaming(fetch('/static/app.wasm'), { env });
    X = instance.exports;
  } catch (e) {
    document.getElementById('status').textContent = 'could not start the viewer: ' + e;
    return;
  }
  X.init(matchMedia('(pointer: coarse)').matches ? 1 : 0);
  // Size in CSS pixels + devicePixelRatio; wasm picks the backing size.
  const size = () => X.resize(cv.clientWidth, cv.clientHeight, window.devicePixelRatio || 1);
  new ResizeObserver(size).observe(cv);
  // devicePixelRatio changes alone (another monitor) resize nothing: watch it.
  const dpr = () => matchMedia('(resolution: ' + devicePixelRatio + 'dppx)').addEventListener('change', () => { size(); dpr(); }, { once: true });
  dpr();
  // Header buttons carry a command number for on_cmd (Fit / A− / A+).
  for (const b of document.querySelectorAll('[data-cmd]')) b.onclick = () => X.on_cmd(+b.dataset.cmd);
  addEventListener('keydown', (e) => {
    const mods = e.shiftKey | e.ctrlKey << 1 | e.altKey << 2 | e.metaKey << 3;
    if (X.on_key(put(enc.encode(e.key)), mods)) e.preventDefault();
  });
  ['pointerdown', 'pointermove', 'pointerup', 'pointercancel'].forEach((type, kind) =>
    cv.addEventListener(type, (e) => {
      if (!e.isPrimary) return;
      if (kind === 0) cv.setPointerCapture(e.pointerId);
      X.on_pointer(kind, e.offsetX, e.offsetY);
    }));
  cv.addEventListener('wheel', (e) => { if (X.on_wheel(e.deltaX, e.deltaY, e.deltaMode)) e.preventDefault(); },
    { passive: false });
})();
