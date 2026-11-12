// Portal browser bridge. All terminal emulation happens in Zig on the
// desktop (src/vt.zig); this only draws the grid Portal sends and reports
// key *names* (docs/protocol.md). It interprets no escape sequences and
// sends no raw bytes, so nothing here is a security boundary.
(function () {
  'use strict';

  var statusEl = document.getElementById('status');
  var modeEl = document.getElementById('mode');
  var screenEl = document.getElementById('screen');
  var cursorEl = document.getElementById('cursor');
  var wrapEl = document.getElementById('wrap');
  var answersEl = document.getElementById('answers');
  var keysEl = document.getElementById('keys');

  var THEME_FG = '#d4d4d4', THEME_BG = '#0c0c0c';
  var DEFAULT = 0xFF000000, BG_AS_FG = 0xFF000002, FG_AS_BG = 0xFF000003;

  var cols = 0, rows = 0, rowEls = [], cur = { x: 0, y: 0, on: false };
  var ws = null, policy = 'none', finished = false, retryMs = 1000;
  var fit = true, fontPx = 14;
  try {
    fontPx = parseInt(localStorage.getItem('portal.fontPx') || '14', 10) || 14;
    fit = localStorage.getItem('portal.fit') !== '0';
  } catch (_) {}

  function hex(v) { return '#' + ('00000' + (v & 0xFFFFFF).toString(16)).slice(-6); }
  function fgColor(v) { return v === DEFAULT ? THEME_FG : v === BG_AS_FG ? THEME_BG : hex(v); }
  function bgColor(v) { return v === DEFAULT ? '' : v === FG_AS_BG ? THEME_FG : hex(v); }

  function setStatus(text, cls) { statusEl.textContent = text; statusEl.className = 'status ' + (cls || ''); }

  // ---- layout ---------------------------------------------------------
  var probe = document.createElement('span');
  probe.className = 'probe';
  probe.textContent = 'MMMMMMMMMM';
  screenEl.appendChild(probe);

  function cellWidthPer1px() {
    screenEl.style.fontSize = '100px';
    var w = probe.getBoundingClientRect().width / 1000; // per px of font size
    screenEl.style.fontSize = fontPx + 'px';
    return w || 0.6;
  }
  var perPx = cellWidthPer1px();

  function layout() {
    if (fit && cols > 0) {
      var avail = wrapEl.clientWidth - 8;
      fontPx = Math.max(5, Math.min(28, Math.floor(avail / (cols * perPx) * 10) / 10));
    }
    screenEl.style.fontSize = fontPx + 'px';
    screenEl.style.width = (cols * perPx * fontPx) + 'px';
    placeCursor();
  }

  function rebuild(c, r) {
    cols = c; rows = r;
    rowEls.forEach(function (el) { el.remove(); });
    rowEls = [];
    for (var i = 0; i < rows; i++) {
      var d = document.createElement('div');
      d.className = 'row';
      screenEl.insertBefore(d, cursorEl);
      rowEls.push(d);
    }
    layout();
  }

  function placeCursor() {
    cursorEl.hidden = !cur.on || policy === 'none';
    cursorEl.style.left = (cur.x * perPx * fontPx) + 'px';
    cursorEl.style.top = (cur.y * 1.2 * fontPx) + 'px';
    cursorEl.style.width = (perPx * fontPx) + 'px';
    cursorEl.style.height = (1.2 * fontPx) + 'px';
  }

  // ---- grid frames ('G', little-endian; docs/protocol.md section 3) ----
  var utf8 = new TextDecoder('utf-8');
  function applyFrame(buf) {
    var v = new DataView(buf), p = 0;
    function u8() { return v.getUint8(p++); }
    function u16() { var x = v.getUint16(p, true); p += 2; return x; }
    function u32() { var x = v.getUint32(p, true); p += 4; return x; }
    if (buf.byteLength < 12 || u8() !== 0x47) return;
    var c = u16(), r = u16();
    cur.x = u16(); cur.y = u16(); cur.on = u8() === 1;
    if (c !== cols || r !== rows) rebuild(c, r);
    var n = u16();
    for (var i = 0; i < n; i++) {
      var idx = u16(), runs = u16();
      var frag = document.createDocumentFragment();
      for (var j = 0; j < runs; j++) {
        var fg = u32(), bg = u32(), attrs = u8(), len = u16();
        var span = document.createElement('span');
        span.textContent = utf8.decode(new Uint8Array(buf, p, len));
        p += len;
        span.style.color = fgColor(fg);
        var b = bgColor(bg);
        if (b) span.style.backgroundColor = b;
        if (attrs) span.className = (attrs & 1 ? ' b' : '') + (attrs & 2 ? ' d' : '') +
          (attrs & 4 ? ' i' : '') + (attrs & 8 ? ' u' : '') + (attrs & 16 ? ' s' : '');
        frag.appendChild(span);
      }
      if (idx < rowEls.length) { rowEls[idx].textContent = ''; rowEls[idx].appendChild(frag); }
    }
    placeCursor();
  }

  // ---- input: key names only -------------------------------------------
  function send(msg) { if (ws && ws.readyState === WebSocket.OPEN && policy !== 'none') ws.send(msg); }
  function key(name) { send('k:' + name); }

  var answerKeys = { '0': 1, '1': 1, '2': 1, '3': 1, '4': 1, '5': 1, '6': 1, '7': 1, '8': 1, '9': 1, y: 1, n: 1 };
  var textKeys = { Backspace: 'backspace', Tab: 'tab', ArrowUp: 'up', ArrowDown: 'down', ArrowLeft: 'left',
    ArrowRight: 'right', Home: 'home', End: 'end', PageUp: 'pageup', PageDown: 'pagedown', Delete: 'delete' };

  document.addEventListener('keydown', function (e) {
    if (policy === 'none' || e.altKey || e.metaKey) return;
    var name = null;
    if (e.key === 'Enter') name = 'enter';
    else if (e.key === 'Escape') name = 'esc';
    else if (policy === 'text') {
      if (e.ctrlKey && (e.key === 'c' || e.key === 'C')) name = 'ctrl-c';
      else if (e.key === 'Tab' && e.shiftKey) name = 'shift-tab';
      else if (textKeys[e.key]) name = textKeys[e.key];
      else if (!e.ctrlKey && e.key.length === 1) { send('t:' + e.key); e.preventDefault(); return; }
    } else if (!e.ctrlKey && answerKeys[e.key.toLowerCase()]) name = e.key.toLowerCase();
    if (name) { key(name); e.preventDefault(); }
  });

  function onButtons(e) {
    var b = e.target.closest('button');
    if (b && b.dataset.key) key(b.dataset.key);
  }
  answersEl.addEventListener('click', onButtons);
  keysEl.addEventListener('click', onButtons);

  // ---- connection ---------------------------------------------------------
  function connect() {
    var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(proto + '//' + location.host + '/ws');
    ws.binaryType = 'arraybuffer';
    ws.onopen = function () { retryMs = 1000; setStatus('live', 'ok'); };
    ws.onmessage = function (ev) {
      if (typeof ev.data !== 'string') { applyFrame(ev.data); return; }
      var m;
      try { m = JSON.parse(ev.data); } catch (_) { return; }
      if (m.t === 'hello') {
        policy = m.input === 'keys' || m.input === 'text' ? m.input : 'none';
        modeEl.textContent = policy === 'none' ? 'view only' : policy === 'keys' ? 'answer keys' : 'typing allowed';
        answersEl.hidden = keysEl.hidden = policy === 'none';
      } else if (m.t === 'exit') {
        finished = true; setStatus('session ended (exit ' + m.code + ')', 'bad');
      } else if (m.t === 'logout') {
        finished = true; location.href = '/login';
      }
    };
    ws.onclose = function () {
      if (finished) return;
      setStatus('reconnecting…', 'bad');
      setTimeout(function () {
        fetch('/', { redirect: 'manual', credentials: 'same-origin' }).then(function (r) {
          if (r.type === 'opaqueredirect' || r.status === 303) location.href = '/login'; else connect();
        }).catch(connect);
      }, retryMs);
      retryMs = Math.min(retryMs * 2, 15000);
    };
  }

  // ---- view controls ------------------------------------------------------
  function save() { try { localStorage.setItem('portal.fontPx', String(fontPx)); localStorage.setItem('portal.fit', fit ? '1' : '0'); } catch (_) {} }
  document.getElementById('fit').onclick = function () { fit = true; layout(); save(); };
  document.getElementById('smaller').onclick = function () { fit = false; fontPx = Math.max(5, fontPx - 1); layout(); save(); };
  document.getElementById('bigger').onclick = function () { fit = false; fontPx = Math.min(28, fontPx + 1); layout(); save(); };
  window.addEventListener('resize', layout);

  connect();
})();
