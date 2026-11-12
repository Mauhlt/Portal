// Portal viewer. Renders the desktop terminal and, if the server's input
// policy allows, forwards keystrokes. The server filters input again; nothing
// here is a security boundary.
(function () {
  'use strict';

  const statusEl = document.getElementById('status');
  const modeEl = document.getElementById('mode');
  const keysEl = document.getElementById('keys');

  let fontSize = 14;
  try { fontSize = parseInt(localStorage.getItem('portal.fontSize') || '14', 10) || 14; } catch (_) {}

  const term = new Terminal({
    fontFamily: '"Cascadia Mono", Consolas, "DejaVu Sans Mono", monospace',
    fontSize: fontSize,
    scrollback: 5000,
    allowProposedApi: false,
    // Links in terminal output are not made clickable.
    linkHandler: null,
  });
  term.open(document.getElementById('term'));

  let ws = null;
  let inputPolicy = 'none';
  let finished = false;
  let retryMs = 1000;

  const keyMap = { up: '\x1b[A', down: '\x1b[B', enter: '\r', esc: '\x1b' };

  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = 'status ' + (cls || '');
  }

  function sendKeys(data) {
    if (inputPolicy === 'none' || !ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send('i' + data);
  }

  function connect() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(proto + '//' + location.host + '/ws');
    ws.binaryType = 'arraybuffer';

    ws.onopen = function () {
      retryMs = 1000;
      setStatus('live', 'ok');
    };

    ws.onmessage = function (ev) {
      if (typeof ev.data !== 'string') {
        term.write(new Uint8Array(ev.data));
        return;
      }
      let m;
      try { m = JSON.parse(ev.data); } catch (_) { return; }
      if (m.t === 'hello') {
        term.reset(); // the server replays scrollback after hello
        inputPolicy = m.input;
        modeEl.textContent = m.input === 'none' ? 'view only' : (m.input === 'keys' ? 'answer keys only' : 'typing allowed');
        keysEl.hidden = m.input === 'none';
        ws.send('r'); // ask for a repaint so the screen is complete
      } else if (m.t === 'size') {
        term.resize(m.cols, m.rows);
      } else if (m.t === 'exit') {
        finished = true;
        setStatus('session ended (exit ' + m.code + ')', 'bad');
      } else if (m.t === 'logout') {
        finished = true;
        location.href = '/login';
      }
    };

    ws.onclose = function () {
      if (finished) return;
      setStatus('disconnected, retrying…', 'bad');
      setTimeout(function () {
        // A failed upgrade may mean the session expired; check by reloading.
        fetch('/', { redirect: 'manual', credentials: 'same-origin' }).then(function (r) {
          if (r.type === 'opaqueredirect' || r.status === 303) location.href = '/login';
          else connect();
        }).catch(connect);
      }, retryMs);
      retryMs = Math.min(retryMs * 2, 15000);
    };
  }

  term.onData(sendKeys);

  keysEl.addEventListener('click', function (e) {
    const b = e.target.closest('button');
    if (!b) return;
    const k = b.dataset.key;
    sendKeys(keyMap[k] || k);
    term.focus();
  });

  function setFont(px) {
    fontSize = Math.max(8, Math.min(28, px));
    term.options.fontSize = fontSize;
    try { localStorage.setItem('portal.fontSize', String(fontSize)); } catch (_) {}
  }
  document.getElementById('smaller').onclick = function () { setFont(fontSize - 1); };
  document.getElementById('bigger').onclick = function () { setFont(fontSize + 1); };
  document.getElementById('redraw').onclick = function () {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send('r');
  };

  connect();
})();
