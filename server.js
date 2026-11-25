'use strict';
/*
 * Шёпот — сервер мессенджера со сквозным шифрованием.
 *
 * Сервер ничего не может прочитать: он получает только зашифрованные
 * строки и пересылает их всем, кто подключён к той же комнате.
 * Ключ комнаты живёт в части ссылки после "#", а она никогда не
 * отправляется на сервер.
 *
 * Без зависимостей: только встроенные модули Node.js (нужен Node 18+).
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || '0.0.0.0';
// На Render (и подобных хостингах) все запросы приходят через их прокси —
// настоящий адрес клиента лежит в X-Forwarded-For. Иначе защита от флуда
// считала бы всех пользователей одним человеком.
const ON_HOSTING = Boolean(process.env.RENDER);
const TRUST_PROXY = process.env.TRUST_PROXY === '1' || ON_HOSTING;
const PUBLIC_DIR = path.join(__dirname, 'public');
const PFX_PATH = path.join(__dirname, 'cert', 'shepot.pfx');
const PASS_PATH = path.join(__dirname, 'cert', 'pass.txt');

const LIMITS = {
  bodyBytes: 2_000_000, // максимальный размер запроса (картинка ~700 КБ после шифрования)
  dataChars: 1_900_000, // максимальная длина зашифрованной строки
  historyPerRoom: 100, // сколько последних сообщений помнить
  historyTtlMs: 24 * 60 * 60 * 1000, // и не дольше суток
  historyBytesPerRoom: 20_000_000,
  rooms: 2000,
  subsPerRoom: 64,
  streamsPerIp: 16,
  postsPerWindow: 40,
  windowMs: 10_000,
};

// Уникальный номер запуска: после перезапуска старые номера сообщений недействительны.
const BOOT = crypto.randomBytes(4).toString('hex');

const ROOM_RE = /^[a-f0-9]{32}$/;
const DATA_RE = /^[A-Za-z0-9_-]+$/;

/** @type {Map<string, {subs:Set<import('http').ServerResponse>, history:{seq:number,data:string,ts:number}[], seq:number, bytes:number}>} */
const rooms = new Map();
const postCounters = new Map(); // ip -> {count, reset}
const streamCounters = new Map(); // ip -> число открытых потоков

const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
  '/favicon.svg': ['favicon.svg', 'image/svg+xml'],
};
const staticCache = new Map();
function loadStatic(name) {
  if (process.env.NODE_ENV !== 'production') return fs.readFileSync(path.join(PUBLIC_DIR, name));
  if (!staticCache.has(name)) staticCache.set(name, fs.readFileSync(path.join(PUBLIC_DIR, name)));
  return staticCache.get(name);
}

let useHttps = false;

function securityHeaders(res) {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; " +
      "connect-src 'self'; media-src 'self' blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
  res.setHeader('Cache-Control', 'no-store');
  if (useHttps) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
}

function clientIp(req) {
  if (TRUST_PROXY) {
    const fwd = req.headers['x-forwarded-for'];
    if (typeof fwd === 'string' && fwd) return fwd.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function sendJson(res, status, obj) {
  if (res.headersSent) return;
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

function getRoom(id, create) {
  let room = rooms.get(id);
  if (!room && create) {
    if (rooms.size >= LIMITS.rooms) return null;
    room = { subs: new Set(), history: [], seq: 0, bytes: 0 };
    rooms.set(id, room);
  }
  return room || null;
}

function sseWrite(res, event, data, id) {
  let chunk = '';
  if (id) chunk += `id: ${id}\n`;
  chunk += `event: ${event}\ndata: ${data}\n\n`;
  res.write(chunk);
}

function broadcastPresence(room) {
  const payload = JSON.stringify({ online: room.subs.size });
  for (const sub of room.subs) sseWrite(sub, 'presence', payload);
}

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // не браузер или тот же сайт без заголовка
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

function rateLimited(ip) {
  const now = Date.now();
  let c = postCounters.get(ip);
  if (!c || now > c.reset) {
    c = { count: 0, reset: now + LIMITS.windowMs };
    postCounters.set(ip, c);
  }
  c.count++;
  return c.count > LIMITS.postsPerWindow;
}

function handleEvents(req, res, url) {
  const roomId = url.searchParams.get('room') || '';
  if (!ROOM_RE.test(roomId)) return sendJson(res, 400, { error: 'bad room' });

  const ip = clientIp(req);
  const open = streamCounters.get(ip) || 0;
  if (open >= LIMITS.streamsPerIp) return sendJson(res, 429, { error: 'too many connections' });

  const room = getRoom(roomId, true);
  if (!room) return sendJson(res, 503, { error: 'server full' });
  if (room.subs.size >= LIMITS.subsPerRoom) return sendJson(res, 503, { error: 'room full' });

  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-store',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write('retry: 2000\n\n');

  // История: отдаём то, что клиент ещё не видел (после переподключения).
  let after = 0;
  const lastId = req.headers['last-event-id'];
  if (typeof lastId === 'string') {
    const [boot, seq] = lastId.split('-');
    if (boot === BOOT && /^\d+$/.test(seq || '')) after = Number(seq);
  }
  for (const m of room.history) {
    if (m.seq > after) sseWrite(res, 'msg', JSON.stringify({ data: m.data }), `${BOOT}-${m.seq}`);
  }
  sseWrite(res, 'ready', '{}');

  room.subs.add(res);
  streamCounters.set(ip, open + 1);
  broadcastPresence(room);

  const ping = setInterval(() => res.write(': ping\n\n'), 20_000);
  let closed = false;
  const cleanup = () => {
    if (closed) return;
    closed = true;
    clearInterval(ping);
    room.subs.delete(res);
    const n = (streamCounters.get(ip) || 1) - 1;
    if (n <= 0) streamCounters.delete(ip);
    else streamCounters.set(ip, n);
    broadcastPresence(room);
  };
  req.on('close', cleanup);
  res.on('close', cleanup);
  res.on('error', cleanup);
}

function handleSend(req, res) {
  if (!sameOrigin(req)) return sendJson(res, 403, { error: 'forbidden' });
  const ctype = String(req.headers['content-type'] || '');
  if (!ctype.startsWith('application/json')) return sendJson(res, 415, { error: 'json only' });
  if (rateLimited(clientIp(req))) return sendJson(res, 429, { error: 'slow down' });

  const declared = Number(req.headers['content-length'] || 0);
  if (declared > LIMITS.bodyBytes) {
    sendJson(res, 413, { error: 'too large' });
    req.resume();
    return;
  }

  const chunks = [];
  let size = 0;
  let aborted = false;
  req.on('data', (c) => {
    if (aborted) return;
    size += c.length;
    if (size > LIMITS.bodyBytes) {
      aborted = true;
      sendJson(res, 413, { error: 'too large' });
      return;
    }
    chunks.push(c);
  });
  req.on('end', () => {
    if (aborted) return;
    let body;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      return sendJson(res, 400, { error: 'bad json' });
    }
    if (!body || typeof body !== 'object') return sendJson(res, 400, { error: 'bad body' });
    const { room: roomId, data, store } = body;
    if (typeof roomId !== 'string' || !ROOM_RE.test(roomId)) return sendJson(res, 400, { error: 'bad room' });
    if (typeof data !== 'string' || data.length < 40 || data.length > LIMITS.dataChars || !DATA_RE.test(data)) {
      return sendJson(res, 400, { error: 'bad data' });
    }

    const room = getRoom(roomId, true);
    if (!room) return sendJson(res, 503, { error: 'server full' });

    const payload = JSON.stringify({ data });
    if (store === false) {
      // Эфемерное: «печатает…», исчезающие сообщения — не сохраняем.
      for (const sub of room.subs) sseWrite(sub, 'msg', payload);
    } else {
      const seq = ++room.seq;
      room.history.push({ seq, data, ts: Date.now() });
      room.bytes += data.length;
      while (room.history.length > LIMITS.historyPerRoom || room.bytes > LIMITS.historyBytesPerRoom) {
        room.bytes -= room.history.shift().data.length;
      }
      for (const sub of room.subs) sseWrite(sub, 'msg', payload, `${BOOT}-${seq}`);
    }
    sendJson(res, 200, { ok: true });
  });
  req.on('error', () => {
    aborted = true;
  });
}

function handler(req, res) {
  securityHeaders(res);
  let url;
  try {
    url = new URL(req.url || '/', 'http://local');
  } catch {
    return sendJson(res, 400, { error: 'bad url' });
  }

  if (url.pathname === '/api/events' && req.method === 'GET') return handleEvents(req, res, url);
  if (url.pathname === '/api/send' && req.method === 'POST') return handleSend(req, res);
  if (url.pathname === '/api/health' && req.method === 'GET') return sendJson(res, 200, { ok: true });
  if (url.pathname === '/api/info' && req.method === 'GET') {
    // Адреса в локальной сети — только для того, кто открыл сайт на самом компьютере-сервере.
    const ip = req.socket.remoteAddress || '';
    const local = !TRUST_PROXY && (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1');
    return sendJson(res, 200, { https: useHttps, lan: local ? lanUrls() : [] });
  }

  const entry = STATIC[url.pathname];
  if (entry && (req.method === 'GET' || req.method === 'HEAD')) {
    try {
      const body = loadStatic(entry[0]);
      res.writeHead(200, { 'Content-Type': entry[1], 'Content-Length': body.length });
      return res.end(req.method === 'HEAD' ? undefined : body);
    } catch {
      return sendJson(res, 500, { error: 'internal' });
    }
  }
  sendJson(res, 404, { error: 'not found' });
}

// Уборка: старые сообщения, пустые комнаты, счётчики.
setInterval(() => {
  const now = Date.now();
  for (const [id, room] of rooms) {
    while (room.history.length && now - room.history[0].ts > LIMITS.historyTtlMs) {
      room.bytes -= room.history.shift().data.length;
    }
    if (room.subs.size === 0 && room.history.length === 0) rooms.delete(id);
  }
  for (const [ip, c] of postCounters) if (now > c.reset) postCounters.delete(ip);
}, 60_000).unref();

function createServer() {
  if (process.env.NO_HTTPS !== '1' && fs.existsSync(PFX_PATH) && fs.existsSync(PASS_PATH)) {
    try {
      const server = https.createServer(
        { pfx: fs.readFileSync(PFX_PATH), passphrase: fs.readFileSync(PASS_PATH, 'utf8').trim() },
        handler
      );
      useHttps = true;
      return server;
    } catch (e) {
      console.error('Не удалось загрузить сертификат, запускаю без HTTPS:', e.message);
    }
  }
  return http.createServer(handler);
}

const server = createServer();
server.headersTimeout = 20_000;
server.requestTimeout = 60_000;
server.keepAliveTimeout = 5_000;
server.on('clientError', (err, socket) => {
  if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

function lanUrls() {
  const proto = useHttps ? 'https' : 'http';
  const port = server.address() ? server.address().port : PORT;
  // Сначала настоящий Wi-Fi/Ethernet, в конце — виртуальные адаптеры и VPN (VirtualBox, Radmin, Hamachi, WSL…).
  const virtualName = /virtual|vmware|vbox|hyper-v|vethernet|wsl|docker|radmin|hamachi|zerotier|tailscale|vpn/i;
  const virtualIp = /^(192\.168\.56\.|26\.|25\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|172\.(1[6-9]|2\d|3[01])\.)/;
  const rank = ({ name, ip }) =>
    virtualName.test(name) || virtualIp.test(ip) ? 3 : /wi-?fi|wlan|wireless|беспровод/i.test(name) ? 0 : ip.startsWith('192.168.') ? 1 : 2;
  const found = [];
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    for (const a of list || []) {
      if (a.family === 'IPv4' && !a.internal && !a.address.startsWith('169.254.')) found.push({ name, ip: a.address });
    }
  }
  return found.sort((a, b) => rank(a) - rank(b)).map(({ ip }) => `${proto}://${ip}:${port}`);
}

server.listen(PORT, HOST, () => {
  const proto = useHttps ? 'https' : 'http';
  console.log('\n  🤫  Шёпот запущен\n');
  console.log(`  На этом компьютере:  ${proto}://localhost:${PORT}`);
  for (const u of lanUrls()) console.log(`  С телефона (Wi-Fi):  ${u}`);
  if (!useHttps && !ON_HOSTING) {
    console.log('\n  ⚠  Без HTTPS шифрование в браузере работает только через localhost.');
    console.log('     Для друзей в сети запусти make-cert.ps1 и перезапусти сервер.');
  }
  console.log('\n  Сервер ничего не записывает в логи и не может читать сообщения.\n');
});

function shutdown() {
  for (const room of rooms.values()) for (const sub of room.subs) sub.end();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1500).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
