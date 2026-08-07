const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.PORT || '8888', 10);
const ROOMS = new Map();
const MAX_AGE = 30000; // 30s stale cleanup
const POLL_HOLD = 15000; // hold polls up to 15s

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function serveFile(res, filePath) {
  const ext = path.extname(filePath);
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('未找到');
      return;
    }
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try { resolve(JSON.parse(body)); } catch { resolve({}); }
    });
  });
}

function getRoom(roomId) {
  if (!roomId) return null;
  let r = ROOMS.get(roomId);
  if (!r) {
    r = { offer: null, answer: null, ice: [], offerWaiters: [], answerWaiters: [] };
    ROOMS.set(roomId, r);
  }
  r.ts = Date.now();
  return r;
}

// stale cleanup every 60s
setInterval(() => {
  const now = Date.now();
  for (const [id, r] of ROOMS) {
    if (now - r.ts > MAX_AGE) ROOMS.delete(id);
  }
}, 60000);

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  // --- Signaling API ---

  if (pathname === '/api/offer' && req.method === 'POST') {
    const { room, sdp } = await parseBody(req);
    const r = getRoom(room);
    r.offer = sdp;
    // notify waiters
    for (const w of r.offerWaiters) { w(sdp); }
    r.offerWaiters = [];
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (pathname === '/api/offer' && req.method === 'GET') {
    const roomId = url.searchParams.get('room');
    const r = getRoom(roomId);
    if (r.offer) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ sdp: r.offer }));
      return;
    }
    // long poll: wait for offer
    const timeout = setTimeout(() => {
      const idx = r.offerWaiters.indexOf(resolve);
      if (idx >= 0) r.offerWaiters.splice(idx, 1);
      if (!res.writableEnded) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sdp: null }));
      }
    }, POLL_HOLD);
    const resolve = (sdp) => {
      clearTimeout(timeout);
      if (!res.writableEnded) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sdp }));
      }
    };
    r.offerWaiters.push(resolve);
    return;
  }

  if (pathname === '/api/answer' && req.method === 'POST') {
    const { room, sdp } = await parseBody(req);
    const r = getRoom(room);
    r.answer = sdp;
    for (const w of r.answerWaiters) { w(sdp); }
    r.answerWaiters = [];
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (pathname === '/api/answer' && req.method === 'GET') {
    const roomId = url.searchParams.get('room');
    const r = getRoom(roomId);
    if (r.answer) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ sdp: r.answer }));
      return;
    }
    const timeout = setTimeout(() => {
      const idx = r.answerWaiters.indexOf(resolve);
      if (idx >= 0) r.answerWaiters.splice(idx, 1);
      if (!res.writableEnded) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sdp: null }));
      }
    }, POLL_HOLD);
    const resolve = (sdp) => {
      clearTimeout(timeout);
      if (!res.writableEnded) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sdp }));
      }
    };
    r.answerWaiters.push(resolve);
    return;
  }

  if (pathname === '/api/ice' && req.method === 'POST') {
    const { room, candidate } = await parseBody(req);
    const r = getRoom(room);
    if (candidate) r.ice.push(candidate);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (pathname === '/api/ice' && req.method === 'GET') {
    const roomId = url.searchParams.get('room');
    const since = parseInt(url.searchParams.get('since') || '0', 10);
    const r = getRoom(roomId);
    const fresh = r.ice.slice(since);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ candidates: fresh, total: r.ice.length }));
    return;
  }

  if (pathname === '/api/reset' && req.method === 'POST') {
    const roomId = url.searchParams.get('room');
    if (roomId) ROOMS.delete(roomId);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // --- Static files ---
  if (pathname === '/') {
    serveFile(res, path.join(__dirname, 'index.html'));
    return;
  }

  serveFile(res, path.join(__dirname, pathname));
});

server.listen(PORT, '0.0.0.0', () => {
  const ifaces = require('os').networkInterfaces();
  const addrs = [];
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        addrs.push(iface.address);
      }
    }
  }
  console.log(`Radmin Share 服务器已启动`);
  console.log(`端口: ${PORT}`);
  console.log(`本机 IP: ${addrs.join(', ') || '未找到'}`);
  console.log(`Radmin VPN IP 通常为 26.x.x.x`);
  console.log(`其他设备打开: http://<本机IP>:${PORT}`);
});
