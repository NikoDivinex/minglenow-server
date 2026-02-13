const { WebSocketServer } = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Config ───
const PORT = process.env.PORT || 3001;
const HEARTBEAT_INTERVAL = 30000;
const REPORTS_TO_AUTO_BAN = 3;
const BAN_DATA_FILE = path.join(__dirname, 'bans.json');
const UNBAN_PRICE_CENTS = 799; // $7.99

// ═══════════════════════════════════════════
// BAN PERSISTENCE
// ═══════════════════════════════════════════
let banData = { bannedIPs: {}, banLog: [] };

function loadBans() {
  try {
    if (fs.existsSync(BAN_DATA_FILE)) {
      banData = JSON.parse(fs.readFileSync(BAN_DATA_FILE, 'utf8'));
      console.log(`[BANS] Loaded ${Object.keys(banData.bannedIPs).length} banned IPs`);
    }
  } catch (e) { console.error('[BANS] Load error:', e.message); }
}

function saveBans() {
  try { fs.writeFileSync(BAN_DATA_FILE, JSON.stringify(banData, null, 2)); }
  catch (e) { console.error('[BANS] Save error:', e.message); }
}

loadBans();

// ═══════════════════════════════════════════
// SLUR / HATE SPEECH FILTER
// ═══════════════════════════════════════════
const INSTANT_BAN_PATTERNS = [
  /n+[i1!|l]+[gq9]+[gq9]*[e3]*r+s?/i,
  /n+[i1!|l]+[gq9]+[gq9]*[aA@4]+s?/i,
  /n[i1!|l]gg+/i,
  /k+[i1!|l]+k+[e3]+s?/i,
  /sp+[i1!|l]+[ck]+s?/i,
  /ch+[i1!|l]+n+k+s?/i,
  /w+[e3]+tb+[a@4]+ck+s?/i,
  /g+[o0]+[o0]+k+s?/i,
  /r+[a@4]+g+h+[e3]+[a@4]+d+s?/i,
  /f+[a@4]+g+[o0]+t+s?/i,
  /f+[a@4]+g+s?\b/i,
  /d+[y]+k+[e3]+s?/i,
  /tr+[a@4]+n+n+[y1i]+[e3]*s?/i,
  /r+[e3]+t+[a@4]+r+d+/i,
];

const WARNING_PATTERNS = [
  /k+[i1!|l]+l+l?\s*(your|ur|u)?\s*s+[e3]+l+f+/i,
  /g+[o0]\s*d+[i1!|l]+[e3]/i,
  /h+[o0]+p+[e3]+\s*[yY]+[o0]+u+\s*d+[i1!|l]+[e3]/i,
];

function normalizeText(text) {
  return text
    .replace(/[\s.\-_*#@!$%^&()+=~`|\\/<>{}[\]]/g, '')
    .replace(/0/g, 'o').replace(/1/g, 'i').replace(/3/g, 'e')
    .replace(/4/g, 'a').replace(/5/g, 's').replace(/8/g, 'b')
    .replace(/@/g, 'a').replace(/\$/g, 's').toLowerCase();
}

function checkMessage(text) {
  const normalized = normalizeText(text);
  const lower = text.toLowerCase();
  for (const p of INSTANT_BAN_PATTERNS) {
    if (p.test(lower) || p.test(normalized)) return { action: 'ban', reason: 'Hate speech / racial slur' };
  }
  for (const p of WARNING_PATTERNS) {
    if (p.test(lower) || p.test(normalized)) return { action: 'warn', reason: 'Threatening / harmful language' };
  }
  return { action: 'ok' };
}

// ═══════════════════════════════════════════
// BAN MANAGEMENT
// ═══════════════════════════════════════════
function banIP(ip, reason) {
  const unbanToken = crypto.randomBytes(16).toString('hex');
  banData.bannedIPs[ip] = { reason, timestamp: new Date().toISOString(), unbanToken, paid: false };
  banData.banLog.push({ ip: ip.slice(0, 8) + '***', reason, timestamp: new Date().toISOString() });
  saveBans();
  console.log(`[BAN] ${ip.slice(0, 8)}***: ${reason}`);
  return unbanToken;
}

function isIPBanned(ip) {
  const ban = banData.bannedIPs[ip];
  return ban && !ban.paid;
}

function getBanInfo(ip) { return banData.bannedIPs[ip] || null; }

function unbanIP(ip) {
  if (banData.bannedIPs[ip]) {
    banData.bannedIPs[ip].paid = true;
    banData.bannedIPs[ip].unbannedAt = new Date().toISOString();
    saveBans();
    console.log(`[UNBAN] ${ip.slice(0, 8)}***`);
    return true;
  }
  return false;
}

const reportTracker = new Map();

function trackReport(reportedIP, reporterIP, reason) {
  if (!reportTracker.has(reportedIP)) reportTracker.set(reportedIP, { reporters: new Set(), count: 0 });
  const t = reportTracker.get(reportedIP);
  if (!t.reporters.has(reporterIP)) { t.reporters.add(reporterIP); t.count++; }
  if (t.count >= REPORTS_TO_AUTO_BAN && !isIPBanned(reportedIP)) {
    banIP(reportedIP, `Auto-banned: ${t.count} reports (${reason})`);
    return true;
  }
  return false;
}

const warningTracker = new Map();

function trackWarning(ip) {
  const count = (warningTracker.get(ip) || 0) + 1;
  warningTracker.set(ip, count);
  if (count >= 2) { banIP(ip, 'Repeated harmful language'); return true; }
  return false;
}

function getClientIP(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.headers['x-real-ip'] || req.socket.remoteAddress || 'unknown';
}

// ═══════════════════════════════════════════
// HTTP SERVER
// ═══════════════════════════════════════════
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // Health
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok', waiting: waitingQueue.length,
      connected: connectedPairs.size, online: clients.size,
      banned: Object.keys(banData.bannedIPs).filter(ip => !banData.bannedIPs[ip].paid).length,
    }));
    return;
  }

  // Check ban
  if (req.url === '/check-ban') {
    const ip = getClientIP(req);
    const banned = isIPBanned(ip);
    const info = getBanInfo(ip);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ banned, reason: banned ? info.reason : null, unbanToken: banned ? info.unbanToken : null }));
    return;
  }

  // Create Stripe checkout for unban
  if (req.url === '/create-unban-session' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const ip = getClientIP(req);
        const banInfo = getBanInfo(ip);
        if (!banInfo || banInfo.paid) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Not banned' }));
          return;
        }
        if (process.env.STRIPE_SECRET_KEY) {
          const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
          const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [{
              price_data: {
                currency: 'usd',
                product_data: { name: 'MingleNow Unban', description: 'Remove your ban and regain access' },
                unit_amount: UNBAN_PRICE_CENTS,
              },
              quantity: 1,
            }],
            mode: 'payment',
            success_url: `${req.headers.origin || 'https://your-site.vercel.app'}?unbanned=true`,
            cancel_url: `${req.headers.origin || 'https://your-site.vercel.app'}?unbanned=false`,
            metadata: { banned_ip: ip, unban_token: banInfo.unbanToken },
          });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ url: session.url }));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Stripe not configured', message: 'Set STRIPE_SECRET_KEY on Railway' }));
        }
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // Stripe webhook
  if (req.url === '/webhook/stripe' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const event = JSON.parse(body);
        if (event.type === 'checkout.session.completed') {
          const s = event.data.object;
          if (s.metadata?.banned_ip && s.metadata?.unban_token) {
            const info = getBanInfo(s.metadata.banned_ip);
            if (info && info.unbanToken === s.metadata.unban_token) unbanIP(s.metadata.banned_ip);
          }
        }
        res.writeHead(200); res.end('ok');
      } catch { res.writeHead(400); res.end('bad'); }
    });
    return;
  }

  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('MingleNow Signaling Server');
});

// ═══════════════════════════════════════════
// WEBSOCKET
// ═══════════════════════════════════════════
const wss = new WebSocketServer({ server });
const clients = new Map();
const waitingQueue = [];
const connectedPairs = new Set();
let nextId = 1;

function generateId() { return `user_${nextId++}_${Date.now().toString(36)}`; }

function calculateMatchScore(a, b) {
  if (!a.length || !b.length) return 0;
  const s = new Set(a.map(i => i.toLowerCase().trim()));
  let m = 0;
  for (const i of b) { if (s.has(i.toLowerCase().trim())) m++; }
  return m;
}

function findBestMatch(ws) {
  const d = clients.get(ws);
  if (!d) return null;
  let best = null, bestScore = -1;
  for (let i = 0; i < waitingQueue.length; i++) {
    const c = waitingQueue[i];
    if (c === ws || c.readyState !== 1) continue;
    const cd = clients.get(c);
    if (!cd || cd.partner) continue;
    const score = calculateMatchScore(d.interests, cd.interests);
    if (score > bestScore) { bestScore = score; best = { index: i, ws: c, score }; }
  }
  if (!best) {
    for (let i = 0; i < waitingQueue.length; i++) {
      const c = waitingQueue[i];
      if (c === ws || c.readyState !== 1) continue;
      const cd = clients.get(c);
      if (!cd || cd.partner) continue;
      best = { index: i, ws: c, score: 0 }; break;
    }
  }
  return best;
}

function pairUsers(ws1, ws2) {
  const d1 = clients.get(ws1), d2 = clients.get(ws2);
  if (!d1 || !d2) return;
  d1.partner = ws2; d2.partner = ws1;
  connectedPairs.add([d1.id, d2.id].sort().join(':'));
  removeFromQueue(ws1); removeFromQueue(ws2);
  const shared = [];
  if (d1.interests.length && d2.interests.length) {
    const s = new Set(d1.interests.map(i => i.toLowerCase().trim()));
    for (const i of d2.interests) { if (s.has(i.toLowerCase().trim())) shared.push(i); }
  }
  send(ws1, { type: 'matched', role: 'initiator', sharedInterests: shared, partnerId: d2.id });
  send(ws2, { type: 'matched', role: 'receiver', sharedInterests: shared, partnerId: d1.id });
  console.log(`[PAIR] ${d1.id} <-> ${d2.id}`);
}

function removeFromQueue(ws) { const i = waitingQueue.indexOf(ws); if (i !== -1) waitingQueue.splice(i, 1); }

function unpairUser(ws) {
  const d = clients.get(ws);
  if (!d || !d.partner) return;
  const pd = clients.get(d.partner);
  if (pd) { connectedPairs.delete([d.id, pd.id].sort().join(':')); pd.partner = null; send(d.partner, { type: 'partner_disconnected' }); }
  d.partner = null;
}

function send(ws, data) { if (ws.readyState === 1) ws.send(JSON.stringify(data)); }

function disconnectAndBan(ws, reason) {
  const d = clients.get(ws);
  if (!d) return;
  const token = banIP(d.ip, reason);
  send(ws, { type: 'banned', reason, unbanToken: token });
  unpairUser(ws);
  removeFromQueue(ws);
  setTimeout(() => ws.close(), 500);
}

// ─── Connection ───
wss.on('connection', (ws, req) => {
  const ip = getClientIP(req);
  const id = generateId();

  if (isIPBanned(ip)) {
    const info = getBanInfo(ip);
    send(ws, { type: 'banned', reason: info.reason, unbanToken: info.unbanToken });
    ws.close();
    console.log(`[BLOCKED] Banned IP tried to connect`);
    return;
  }

  clients.set(ws, { id, ip, interests: [], partner: null, alive: true, warnings: 0 });
  send(ws, { type: 'welcome', id, online: clients.size });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    const cd = clients.get(ws);
    if (!cd) return;

    if (isIPBanned(cd.ip)) {
      const info = getBanInfo(cd.ip);
      send(ws, { type: 'banned', reason: info.reason, unbanToken: info.unbanToken });
      ws.close(); return;
    }

    switch (msg.type) {
      case 'join_queue': {
        unpairUser(ws); removeFromQueue(ws);
        cd.interests = Array.isArray(msg.interests) ? msg.interests.slice(0, 10) : [];
        const m = findBestMatch(ws);
        if (m) pairUsers(ws, m.ws);
        else { waitingQueue.push(ws); send(ws, { type: 'waiting', position: waitingQueue.length }); }
        break;
      }
      case 'leave_queue': { removeFromQueue(ws); send(ws, { type: 'left_queue' }); break; }
      case 'rtc_offer': case 'rtc_answer': case 'rtc_ice_candidate': {
        if (cd.partner) send(cd.partner, msg); break;
      }
      case 'chat_message': {
        if (cd.partner && typeof msg.text === 'string') {
          const text = msg.text.slice(0, 500).trim();
          if (!text) break;
          const result = checkMessage(text);
          if (result.action === 'ban') { disconnectAndBan(ws, result.reason); break; }
          if (result.action === 'warn') {
            cd.warnings++;
            if (trackWarning(cd.ip)) { disconnectAndBan(ws, result.reason); break; }
            send(ws, { type: 'warning', message: `⚠️ Warning ${cd.warnings}/2: ${result.reason}. Next violation = ban.` });
            break;
          }
          send(cd.partner, { type: 'chat_message', text, from: 'stranger' });
        }
        break;
      }
      case 'skip': {
        unpairUser(ws);
        cd.interests = Array.isArray(msg.interests) ? msg.interests.slice(0, 10) : cd.interests;
        const m = findBestMatch(ws);
        if (m) pairUsers(ws, m.ws);
        else { waitingQueue.push(ws); send(ws, { type: 'waiting', position: waitingQueue.length }); }
        break;
      }
      case 'report': {
        if (cd.partner) {
          const pd = clients.get(cd.partner);
          if (pd) {
            const reason = typeof msg.reason === 'string' ? msg.reason.slice(0, 200) : 'No reason';
            console.log(`[REPORT] ${cd.id} reported ${pd.id}: ${reason}`);
            const wasBanned = trackReport(pd.ip, cd.ip, reason);
            if (wasBanned) {
              const info = getBanInfo(pd.ip);
              send(cd.partner, { type: 'banned', reason: `Multiple reports: ${reason}`, unbanToken: info.unbanToken });
              setTimeout(() => cd.partner?.close?.(), 500);
            }
            unpairUser(ws);
            send(ws, { type: 'report_confirmed' });
          }
        }
        break;
      }
      case 'pong': { cd.alive = true; break; }
    }
  });

  ws.on('close', () => {
    const d = clients.get(ws);
    unpairUser(ws); removeFromQueue(ws); clients.delete(ws);
  });
  ws.on('error', () => { unpairUser(ws); removeFromQueue(ws); clients.delete(ws); });
});

// ─── Heartbeat ───
setInterval(() => {
  wss.clients.forEach(ws => {
    const d = clients.get(ws);
    if (!d) return;
    if (!d.alive) { ws.terminate(); return; }
    d.alive = false; send(ws, { type: 'ping' });
  });
}, HEARTBEAT_INTERVAL);

// ─── Online count broadcast ───
setInterval(() => {
  const c = clients.size;
  wss.clients.forEach(ws => send(ws, { type: 'online_count', count: c }));
}, 5000);

// ─── Start ───
server.listen(PORT, () => {
  console.log(`MingleNow server on port ${PORT}`);
  console.log(`Active bans: ${Object.keys(banData.bannedIPs).filter(ip => !banData.bannedIPs[ip].paid).length}`);
});
