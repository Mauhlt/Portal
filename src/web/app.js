// Portal browser bridge: UNAVOIDABLE BROWSER GLUE, NO APPLICATION LOGIC.
// The viewer is Zig compiled to WebAssembly (src/wasm/, served as
// /static/app.wasm). Browsers can only start WebAssembly from JavaScript,
// so this file (1) instantiates the module, (2) forwards DOM events and
// values into its exports and (3) implements its host imports, each a
// one-line wrapper around a browser API. Every decision (protocol, drawing,
// slice layout, key mapping, what Send does, reconnects, status text) is
// made in wasm. web.zig's tests check this file defines exactly the
// imports app.wasm declares.
'use strict';
(async () => {
  const $ = (id) => document.getElementById(id);
  const cvs = [$('screen'), $('data')], ctxs = cvs.map((c) => c.getContext('2d')); // Canvas order in main.zig
  const box = $('box'), safe = $('safe'), split = $('split');
  const enc = new TextEncoder(), dec = new TextDecoder();
  let X = null, ws = null; // wasm exports; the one WebSocket
  const mem = () => new Uint8Array(X.memory.buffer); // re-made: memory can grow
  const str = (p, n) => dec.decode(mem().subarray(p, p + n));
  // Copy bytes into wasm's input buffer; returns the length for the handler.
  const put = (b) => { const p = X.in_alloc(b.length); if (p) mem().set(b, p); return b.length; };
  const mods = (e) => e.shiftKey | e.ctrlKey << 1 | e.altKey << 2 | e.metaKey << 3 | e.isComposing << 4;
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
    canvas_size: (c, w, h) => { cvs[c].width = w; cvs[c].height = h; },
    present: (c, p, w, h, y0, y1) => ctxs[c].putImageData(
      new ImageData(new Uint8ClampedArray(X.memory.buffer, p, w * h * 4), w, h), 0, 0, 0, y0, w, y1 - y0),
    request_frame: () => requestAnimationFrame(() => X.frame()),
    set_timer: (ms) => setTimeout(() => X.on_timer(), ms),
    check_session: () => fetch('/', { credentials: 'same-origin', cache: 'no-store' }).then(
      (r) => X.on_check(r.status, put(enc.encode(new URL(r.url).pathname)), 0),
      () => X.on_check(0, 0, navigator.onLine === false ? 1 : 0)),
    navigate_pair: () => location.assign('/pair'),
    set_text: (slot, p, n, cls) => { // TextSlot order in main.zig
      const el = $(['status', 'mode', 'note', 'project', 'state'][slot]);
      el.textContent = str(p, n);
      el.className = el.id + ['', ' ok', ' bad'][cls];
    },
    set_layout: (p, n) => { document.body.style.cssText = str(p, n); },
    set_class: (p, n) => { document.body.className = str(p, n); },
    box_read: (p, cap) => enc.encodeInto(box.value, mem().subarray(p, p + cap)).written,
    box_write: (p, n) => { box.value = str(p, n); },
    box_hint: (p, n) => { box.placeholder = str(p, n); },
  };
  try {
    const { instance } = await WebAssembly.instantiateStreaming(fetch('/static/app.wasm'), { env });
    X = instance.exports;
  } catch (e) {
    $('status').textContent = 'could not start the viewer: ' + e;
    return;
  }
  X.init(matchMedia('(pointer: coarse)').matches ? 1 : 0);
  // The visible viewport (it shrinks when the on-screen keyboard opens).
  const vv = visualViewport, view = () => X.on_viewport(innerWidth, innerHeight,
    vv.width, vv.height, vv.offsetTop, safe.offsetHeight, safe.offsetWidth);
  ['resize', 'scroll'].forEach((t) => vv.addEventListener(t, view));
  addEventListener('resize', view);
  view();
  // Canvas sizes in CSS pixels + devicePixelRatio; wasm picks the backing size.
  const size = () => cvs.forEach((c, i) => X.resize(i, c.clientWidth, c.clientHeight, window.devicePixelRatio || 1));
  cvs.forEach((c) => new ResizeObserver(size).observe(c));
  // devicePixelRatio changes alone (another monitor) resize nothing: watch it.
  const dpr = () => matchMedia('(resolution: ' + devicePixelRatio + 'dppx)').addEventListener('change', () => { size(); dpr(); }, { once: true });
  dpr();
  // Buttons carry a number for wasm: data-cmd (Fit / A− / A+), data-tab
  // (slices.Tab), data-btn (inputbox.Button).
  for (const b of document.querySelectorAll('[data-cmd]')) b.onclick = () => X.on_cmd(+b.dataset.cmd);
  for (const b of document.querySelectorAll('[data-tab]')) b.onclick = () => X.on_tab(+b.dataset.tab);
  for (const b of document.querySelectorAll('[data-btn]')) {
    b.onclick = () => X.on_button(+b.dataset.btn);
    b.onpointerdown = (e) => e.preventDefault(); // keeps focus (and the keyboard) in the box
  }
  ['input', 'change'].forEach((t) => box.addEventListener(t, () => X.on_box_input()));
  box.addEventListener('keydown', (e) => {
    e.stopPropagation(); // typing in the box is not terminal keys
    if (X.on_box_key(put(enc.encode(e.key)), mods(e))) e.preventDefault();
  });
  addEventListener('keydown', (e) => { if (X.on_key(put(enc.encode(e.key)), mods(e))) e.preventDefault(); });
  ['pointerdown', 'pointermove', 'pointerup', 'pointercancel'].forEach((type, kind) => {
    cvs[0].addEventListener(type, (e) => {
      if (!e.isPrimary) return;
      if (kind === 0) cvs[0].setPointerCapture(e.pointerId);
      X.on_pointer(kind, e.offsetX, e.offsetY);
    });
    split.addEventListener(type, (e) => {
      if (kind === 0) split.setPointerCapture(e.pointerId);
      X.on_split(kind, e.clientX);
    });
  });
  cvs[0].addEventListener('wheel', (e) => { if (X.on_wheel(e.deltaX, e.deltaY, e.deltaMode)) e.preventDefault(); },
    { passive: false });
})();
