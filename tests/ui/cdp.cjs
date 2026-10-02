// Minimal Chrome DevTools Protocol client – no dependencies (Node >= 16).
// Starts a headless Chrome with a throwaway profile, connects to the page
// over a WebSocket (RFC 6455, implemented here) and sends real input events
// (Input.dispatchKeyEvent / dispatchMouseEvent), which the page receives as
// trusted user input – unlike element.click() or dispatchEvent().

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const CANDIDATES = [
  process.env.CHROME,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
  '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
].filter(Boolean);

function findChrome() {
  const found = CANDIDATES.find(p => fs.existsSync(p));
  if (!found) throw new Error('No Chrome/Chromium/Edge found – set CHROME to its executable.');
  return found;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
const live = new Set();   // kill functions of browsers still running (for timeouts)
const killAll = () => { for (const kill of live) kill('SIGKILL'); live.clear(); };

function httpJson(port, pathName) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: pathName }, res => {
      let body = '';
      res.on('data', d => { body += d; });
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
}

// ── WebSocket (client side, text frames only) ──────────────────────────────
function connectWs(url) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const key = crypto.randomBytes(16).toString('base64');
    const req = http.request({
      host: u.hostname, port: u.port, path: u.pathname,
      headers: { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Key': key, 'Sec-WebSocket-Version': '13' },
    });
    req.on('error', reject);
    req.on('upgrade', (_res, socket) => {
      const listeners = [];
      let buf = Buffer.alloc(0);
      let parts = [];
      socket.on('data', chunk => {
        buf = Buffer.concat([buf, chunk]);
        for (;;) {
          if (buf.length < 2) return;
          const fin = (buf[0] & 0x80) !== 0;
          const op = buf[0] & 0x0f;
          let len = buf[1] & 0x7f;
          let off = 2;
          if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
          else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
          if (buf.length < off + len) return;
          const payload = buf.subarray(off, off + len);
          buf = buf.subarray(off + len);
          if (op === 0x8) { socket.end(); return; }
          if (op === 0x9) continue;                 // ping: ignored (Chrome does not require pongs)
          parts.push(payload);
          if (fin) {
            const text = Buffer.concat(parts).toString('utf8');
            parts = [];
            for (const fn of listeners) fn(text);
          }
        }
      });
      resolve({
        onMessage: fn => listeners.push(fn),
        send(text) {
          const data = Buffer.from(text, 'utf8');
          const mask = crypto.randomBytes(4);
          const head = data.length < 126 ? Buffer.from([0x81, 0x80 | data.length])
            : data.length < 65536 ? Buffer.from([0x81, 0x80 | 126, data.length >> 8, data.length & 0xff])
              : Buffer.concat([Buffer.from([0x81, 0x80 | 127]), (() => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(data.length)); return b; })()]);
          const masked = Buffer.alloc(data.length);
          for (let i = 0; i < data.length; i++) masked[i] = data[i] ^ mask[i & 3];
          socket.write(Buffer.concat([head, mask, masked]));
        },
        close() { socket.destroy(); },
      });
    });
    req.end();
  });
}

// ── Browser + page session ──────────────────────────────────────────────────
async function launch({ width = 1280, height = 800, url = 'about:blank' } = {}) {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'km-ui-'));
  const chrome = findChrome();
  const proc = spawn(chrome, [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--disable-extensions',
    '--disable-background-networking', '--disable-sync', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
    `--window-size=${width},${height}`, '--lang=en-US', ...(process.platform === 'linux' ? ['--no-sandbox'] : []), url,
  ], { stdio: ['ignore', 'ignore', 'pipe'], detached: process.platform !== 'win32' });
  // Chrome starts helper processes: end the whole group, not just the main one
  const killTree = signal => {
    try {
      if (process.platform === 'win32') spawn('taskkill', ['/pid', String(proc.pid), '/T', '/F'], { stdio: 'ignore' });
      else process.kill(-proc.pid, signal);
    } catch { /* already gone */ }
  };
  live.add(killTree);
  proc.on('exit', () => live.delete(killTree));
  let stderr = '';
  proc.stderr.on('data', d => { stderr += d; });
  const portFile = path.join(profile, 'DevToolsActivePort');
  for (let i = 0; i < 100 && !fs.existsSync(portFile); i++) await sleep(100);
  if (!fs.existsSync(portFile)) { killTree('SIGKILL'); throw new Error(`Chrome did not start:\n${stderr.slice(-2000)}`); }
  const port = Number(fs.readFileSync(portFile, 'utf8').split('\n')[0]);
  let target;
  for (let i = 0; i < 50 && !target; i++) {
    target = (await httpJson(port, '/json/list')).find(t => t.type === 'page');
    if (!target) await sleep(100);
  }
  const ws = await connectWs(target.webSocketDebuggerUrl);
  const pending = new Map();
  const handlers = new Map();
  let id = 0;
  ws.onMessage(text => {
    const msg = JSON.parse(text);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject, method } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(`${method}: ${msg.error.message}`)); else resolve(msg.result);
    } else if (msg.method) {
      for (const fn of handlers.get(msg.method) || []) fn(msg.params);
    }
  });
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const n = ++id;
    pending.set(n, { resolve, reject, method });
    ws.send(JSON.stringify({ id: n, method, params }));
  });
  const on = (event, fn) => { if (!handlers.has(event)) handlers.set(event, []); handlers.get(event).push(fn); };
  return {
    send, on, stderr: () => stderr,
    kill() { killTree('SIGKILL'); },
    async close() {
      ws.close();
      killTree('SIGTERM');
      await sleep(200);
      try { fs.rmSync(profile, { recursive: true, force: true }); } catch { /* Windows may still hold files */ }
    },
  };
}

// Only pass trusted, static functions here. Values travel as CDP arguments,
// never concatenated into JavaScript source or embedded in HTML.
async function callPage(send, fn, ...values) {
  const global = await send('Runtime.evaluate', { expression: 'globalThis' });
  if (global.exceptionDetails || !global.result.objectId) throw new Error('No page execution context');
  const objectId = global.result.objectId;
  try {
    const r = await send('Runtime.callFunctionOn', {
      objectId, functionDeclaration: fn.toString(), arguments: values.map(value => ({ value })),
      awaitPromise: true, returnByValue: true,
    });
    if (r.exceptionDetails) throw new Error(`page: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}`);
    return r.result.value;
  } finally {
    // Navigation may have already destroyed the context; do not hide the result.
    await send('Runtime.releaseObject', { objectId }).catch(() => {});
  }
}

module.exports = { launch, findChrome, sleep, killAll, callPage };
